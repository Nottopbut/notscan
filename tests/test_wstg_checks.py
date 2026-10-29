"""
tests/test_wstg_checks.py — тесты WSTG-чеков каталога.

Покрытие:
  • checks/catalog.py — единый каталог: уникальность, валидные WSTG-ID,
    скорректированные маппинги, соответствие registry-классам, payload-файлы;
  • checks/passive_extra.py — 6 новых passive-чеков TP/FP на fake response;
  • checks/injections.py + scanner_core — matcher'ы ssi_injection / html_injection,
    MATCHERS/run_matcher, новые SQLI_TIME-пайлоады и DESTRUCTIVE-паттерны;
  • path_probe.run_probe_scan — 5 WSTG probe-чеков на локальном
    ThreadingHTTPServer (без внешней сети), soft-404 FP-фильтр и legacy-обёртка.

Все серверы — 127.0.0.1:0 внутри теста; наружу сеть не ходит.
"""

from __future__ import annotations

import html
import json
import re
import threading
from dataclasses import fields
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import pytest

import db
import path_probe
import scanner_core
from checks.base import CheckContext, ScanRequest, ScanResponse
from checks.catalog import (
    ACTIVE_CHECK_IDS,
    CATEGORIES,
    CHECK_CATALOG,
    CheckDef,
    KINDS,
    PASSIVE_CHECK_IDS,
    PROBE_CHECK_IDS,
    SEVERITIES,
    by_kind,
    get as catalog_get,
    payload_file_for,
    wstg_id_for,
)
from checks.injections import (
    SQLI_TIME_PAYLOADS,
    html_injection_indicator,
    ssi_indicator,
)
from checks.passive_extra import ALL_EXTRA_PASSIVE_CHECKS
from checks.registry import CheckRegistry
from checks.runner import WSTG_ID_MAP

PROJECT_ROOT = Path(__file__).resolve().parent.parent
PAYLOADS_DIR = PROJECT_ROOT / "payloads"

WSTG_ID_RE = re.compile(
    r"^WSTG-(INFO|CONF|IDNT|ATHN|ATHZ|SESS|INPV|INJT|ERRH|CRYP|BUSL|CLNT|APIT|WASM)"
    r"-\d{2}( \(v5\))?$"
)


# ══════════════════════════════════════════════════════════════════
#  Fixtures / helpers
# ══════════════════════════════════════════════════════════════════

@pytest.fixture()
def tmp_db(tmp_path):
    """Изолированная БД на время теста (не трогаем repo history.db)."""
    db_path = tmp_path / ".db"
    db.set_db_path(db_path)
    yield db_path
    # Уводим глобальный db из tmp: соседние/последующие тесты ставят свой путь.
    db.set_db_path(tmp_path / "-closed.db")
    for suffix in ("", "-wal", "-shm"):
        try:
            Path(str(db_path) + suffix).unlink(missing_ok=True)
        except OSError:
            pass


def _payload_lines(filename: str) -> list[str]:
    lines = (PAYLOADS_DIR / filename).read_text(encoding="utf-8").splitlines()
    return [line.strip() for line in lines if line.strip() and not line.startswith("#")]


def _run_passive(
    check_id: str,
    *,
    url: str = "https://example.test/",
    method: str = "GET",
    req_headers: dict | None = None,
    body: bytes = b"",
    resp_headers: dict | None = None,
    resp_text: str = "",
    resp_status: int = 200,
):
    """Запуск passive-чека на fake request/response через свежий registry."""
    check = CheckRegistry().get(check_id)
    assert check is not None, f"чек {check_id} не зарегистрирован"
    req = ScanRequest(
        method=method, url=url, headers=dict(req_headers or {}), body=body, raw_http="",
    )
    resp = ScanResponse(
        status_code=resp_status, headers=dict(resp_headers or {}),
        text=resp_text, elapsed_ms=0.0, error=None,
    )
    return check.check(req, resp, CheckContext()).findings


def _run_check_class(check_id: str, *, url="http://example.test/?q=1", payload="",
                     resp_text="", resp_headers=None, resp_status=200, baseline_text=""):
    check = CheckRegistry().get(check_id)
    assert check is not None, f"чек {check_id} не зарегистрирован"
    req = ScanRequest(method="GET", url=url, headers={}, body=b"", raw_http="")
    resp = ScanResponse(
        status_code=resp_status, headers=dict(resp_headers or {}),
        text=resp_text, elapsed_ms=0.0, error=None,
    )
    ctx = CheckContext(payload=payload, check_type=check_id, baseline_text=baseline_text)
    return check.check(req, resp, ctx).findings


# ── in-test HTTP-сервер для probe-чеков ──────────────────────────────

class _ProbeHandler(BaseHTTPRequestHandler):
    """Мини-цель с уязвимостями для всех 5 новых probe-чеков."""

    protocol_version = "HTTP/1.1"

    def _send(self, status: int, body: bytes = b"", headers: dict | None = None) -> None:
        self.send_response(status)
        for key, value in (headers or {}).items():
            self.send_header(key, value)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        if body:
            self.wfile.write(body)

    def do_GET(self):  # noqa: N802
        path = self.path.split("?", 1)[0]
        if path == "/.env":
            self._send(200, b"DB_PASSWORD=notscan-secret\n", {"Content-Type": "text/plain"})
        elif path == "/backup.sql":
            self._send(200, b"CREATE TABLE users (id INT);\n", {"Content-Type": "text/plain"})
        elif path == "/robots.txt":
            self._send(200, b"User-agent: *\nDisallow: /admin\n", {"Content-Type": "text/plain"})
        elif path == "/phpinfo.php":
            # WAF-заглушка: 200, но это не раскрытие файла (FP-фильтр probe).
            self._send(200, b"Access denied", {"Content-Type": "text/html"})
        elif path == "/crossdomain.xml":
            self._send(200, (
                b'<?xml version="1.0"?><cross-domain-policy>'
                b'<allow-access-from domain="*" to-ports="*"/></cross-domain-policy>'
            ), {"Content-Type": "application/xml"})
        elif path == "/cors-reflect":
            origin = self.headers.get("Origin") or "*"
            self._send(200, b'{"ok": true}', {
                "Content-Type": "application/json",
                "Access-Control-Allow-Origin": origin,
                "Access-Control-Allow-Credentials": "true",
            })
        elif path == "/":
            headers = {"Content-Type": "text/html; charset=utf-8"}
            origin = self.headers.get("Origin")
            if origin:
                headers["Access-Control-Allow-Origin"] = origin
                headers["Access-Control-Allow-Credentials"] = "true"
            self._send(200, b"<html><body>probe target</body></html>", headers)
        else:
            self._send(404, b"")

    def do_OPTIONS(self):  # noqa: N802
        self._send(200, b"", {"Allow": "GET, PUT, DELETE, TRACE, OPTIONS"})

    def do_TRACE(self):  # noqa: N802
        self._send(200, b"TRACE / HTTP/1.1\r\n", {"Content-Type": "text/plain"})

    def _drain_body(self) -> None:
        """Прочитать тело запроса, иначе keep-alive-соединение ломается."""
        try:
            length = int(self.headers.get("Content-Length") or 0)
        except (TypeError, ValueError):
            length = 0
        if length > 0:
            self.rfile.read(length)

    def do_PUT(self):  # noqa: N802
        self._drain_body()
        self._send(201, b"created")

    def do_DELETE(self):  # noqa: N802
        self._drain_body()
        self._send(204, b"")

    def log_message(self, *args):  # noqa: D401
        pass


class _SpaHandler(BaseHTTPRequestHandler):
    """Catch-all SPA: 200 на любой путь — проверка soft-404 FP-фильтра."""

    protocol_version = "HTTP/1.1"
    _BODY = b"<html><body>SPA index - not found page</body></html>"

    def do_GET(self):  # noqa: N802
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(self._BODY)))
        self.end_headers()
        self.wfile.write(self._BODY)

    def log_message(self, *args):
        pass


def _serve(handler_cls):
    server = ThreadingHTTPServer(("127.0.0.1", 0), handler_cls)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    base = f"http://127.0.0.1:{server.server_address[1]}"
    return server, thread, base


@pytest.fixture()
def probe_server():
    server, thread, base = _serve(_ProbeHandler)
    try:
        yield base
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)


@pytest.fixture()
def spa_server():
    server, thread, base = _serve(_SpaHandler)
    try:
        yield base
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)


def _probe_rows(probe_id: str) -> list[dict]:
    return [r for r in db.fetch_scan_results(limit=None) if r["check_type"] == probe_id]


# ══════════════════════════════════════════════════════════════════
#  1. Каталог чеков (checks/catalog.py)
# ══════════════════════════════════════════════════════════════════

def test_catalog_interface_is_stable():
    """Интерфейс: dataclass CheckDef + tuple CHECK_CATALOG (GUI импортирует)."""
    names = [f.name for f in fields(CheckDef)]
    assert names == [
        "check_id", "wstg_id", "name", "category", "severity",
        "cwe", "description", "kind", "payload_file", "enabled_default",
    ]
    assert isinstance(CHECK_CATALOG, tuple)
    assert all(isinstance(cd, CheckDef) for cd in CHECK_CATALOG)
    # frozen=True: каталог не должен мутироваться GUI
    with pytest.raises(Exception):
        CHECK_CATALOG[0].wstg_id = "WSTG-INFO-99"  # type: ignore[misc]


def test_catalog_complete_and_unique():
    """38 чеков: 24 существующих + pseudo info_disclosure_paths + 13 новых."""
    assert len(CHECK_CATALOG) == 38, f"ожидали 38 чеков, получили {len(CHECK_CATALOG)}"
    ids = [cd.check_id for cd in CHECK_CATALOG]
    assert len(ids) == len(set(ids)), "check_id в каталоге должны быть уникальны"
    assert len(by_kind("active")) == 16
    assert len(by_kind("passive")) == 16
    assert len(by_kind("probe")) == 6
    assert ACTIVE_CHECK_IDS == tuple(c.check_id for c in by_kind("active"))
    assert PASSIVE_CHECK_IDS == tuple(c.check_id for c in by_kind("passive"))
    assert PROBE_CHECK_IDS == tuple(c.check_id for c in by_kind("probe"))
    assert by_kind("unknown") == []


def test_catalog_new_check_ids_exact_set():
    """Ровно набор из: 6 passive + 2 active + 5 probe (+ legacy pseudo probe)."""
    expected_passive = {
        "cookies", "hsts", "csp", "cache_control", "insecure_login", "browser_storage",
    }
    expected_active = {"ssi_injection", "html_injection"}
    expected_probe = {"sensitive_files", "metafiles", "ria_policy", "http_methods", "cors"}
    ids = {cd.check_id for cd in CHECK_CATALOG}
    assert expected_passive <= ids
    assert expected_active <= ids
    assert expected_probe <= ids
    assert {"cookies", "hsts", "csp", "cache_control", "insecure_login",
            "browser_storage"} <= {cd.check_id for cd in by_kind("passive")}
    assert {"ssi_injection", "html_injection"} <= {cd.check_id for cd in by_kind("active")}
    assert {"sensitive_files", "metafiles", "ria_policy", "http_methods", "cors"} <= {
        cd.check_id for cd in by_kind("probe")
    }


def test_catalog_fields_valid():
    for cd in CHECK_CATALOG:
        assert cd.category in CATEGORIES, f"{cd.check_id}: category {cd.category!r}"
        assert cd.severity in SEVERITIES, f"{cd.check_id}: severity {cd.severity!r}"
        assert cd.kind in KINDS, f"{cd.check_id}: kind {cd.kind!r}"
        assert WSTG_ID_RE.match(cd.wstg_id), f"{cd.check_id}: WSTG-ID {cd.wstg_id!r}"
        assert re.match(r"^CWE-\d+$", cd.cwe), f"{cd.check_id}: cwe {cd.cwe!r}"
        assert cd.name.strip(), f"{cd.check_id}: пустое имя"
        assert cd.description.strip(), f"{cd.check_id}: пустое описание"


@pytest.mark.parametrize("check_id,expected", [
    # исправленные ошибки маппинга WSTG-ID
    ("csrf", "WSTG-SESS-05"),
    ("xss_reflected", "WSTG-INPV-01"),
    ("xss_dom", "WSTG-CLNT-01"),
    ("path_traversal", "WSTG-ATHZ-01"),
    ("clickjacking", "WSTG-CLNT-09"),
    ("security_headers", "WSTG-CONF-14 (v5)"),
    ("info_disclosure", "WSTG-INFO-05"),
    ("info_disclosure_paths", "WSTG-CONF-05"),
    ("jwt", "WSTG-SESS-10 (v5)"),
    ("deserialization", "WSTG-INJT-23 (v5)"),
    ("nosql_injection", "WSTG-INJT-05 (v5)"),
    ("file_upload", "WSTG-BUSL-09"),
    # не путать path_traversal и crlf
    ("crlf_injection", "WSTG-INPV-15"),
    # корректные (не менялись)
    ("sqli", "WSTG-INPV-05"),
    ("sqli_time", "WSTG-INPV-05"),
    ("cmdi", "WSTG-INPV-12"),
    ("ssti", "WSTG-INPV-18"),
    ("ldap_injection", "WSTG-INPV-06"),
    ("xpath_injection", "WSTG-INPV-09"),
    ("xxe", "WSTG-INPV-07"),
    ("ssrf", "WSTG-INPV-19"),
    ("open_redirect", "WSTG-CLNT-04"),
    ("idor", "WSTG-ATHZ-04"),
    # новые чеки
    ("cookies", "WSTG-SESS-02"),
    ("hsts", "WSTG-CONF-07"),
    ("csp", "WSTG-CONF-12 (v5)"),
    ("cache_control", "WSTG-ATHN-06"),
    ("insecure_login", "WSTG-ATHN-01"),
    ("browser_storage", "WSTG-CLNT-12"),
    ("ssi_injection", "WSTG-INPV-08"),
    ("html_injection", "WSTG-CLNT-03"),
    ("sensitive_files", "WSTG-CONF-03"),
    ("metafiles", "WSTG-INFO-03"),
    ("ria_policy", "WSTG-CONF-08"),
    ("http_methods", "WSTG-CONF-06"),
    ("cors", "WSTG-CLNT-07"),
])
def test_catalog_wstg_ids(check_id, expected):
    assert wstg_id_for(check_id) == expected
    assert catalog_get(check_id) is not None


def test_catalog_lookup_helpers():
    assert wstg_id_for("no_such_check") == ""
    assert payload_file_for("no_such_check") is None
    assert catalog_get("no_such_check") is None
    assert payload_file_for("cookies") is None
    assert payload_file_for("ssi_injection") == "ssi.txt"
    assert payload_file_for("html_injection") == "html_injection.txt"
    assert payload_file_for("sqli") == "sqli.txt"


def test_catalog_matches_registry_classes():
    """Каждый зарегистрированный чек есть в каталоге; name/severity/cwe совпадают."""
    reg = CheckRegistry()
    registered = {c.check_id: c for c in reg.all_checks()}
    catalog_checks = {cd.check_id: cd for cd in CHECK_CATALOG if cd.kind != "probe"}

    assert set(registered) == set(catalog_checks), (
        f"registry vs catalog: {sorted(set(registered) ^ set(catalog_checks))}"
    )
    for check_id, check in registered.items():
        cd = catalog_checks[check_id]
        assert cd.name == check.name, f"{check_id}: name"
        assert cd.severity == check.severity.value, f"{check_id}: severity"
        assert cd.cwe == check.cwe, f"{check_id}: cwe"
        if check.passive:
            assert cd.kind == "passive", f"{check_id}: passive-класс должен иметь kind=passive"
        else:
            assert cd.kind == "active", f"{check_id}: активный класс должен иметь kind=active"
    # probe-чеки живут только в path_probe (не в CheckRegistry)
    for probe_id in PROBE_CHECK_IDS:
        assert reg.get(probe_id) is None, f"{probe_id}: probe-чек не должен быть в registry"


def test_catalog_active_payload_files_exist():
    missing = []
    for cd in by_kind("active"):
        assert cd.payload_file, f"{cd.check_id}: active-чек без payload_file"
        path = PAYLOADS_DIR / cd.payload_file
        if not path.exists():
            if cd.check_id in ("ssi_injection", "html_injection"):
                pytest.skip(f"{cd.payload_file} ещё не создан агентом payloads")
            missing.append(cd.payload_file)
            continue
        assert path.stat().st_size > 0, f"{cd.payload_file}: пустой файл"
    assert not missing, f"нет payload-файлов: {missing}"


def test_catalog_new_payload_files_have_expected_markers():
    ssi_path = PAYLOADS_DIR / "ssi.txt"
    html_path = PAYLOADS_DIR / "html_injection.txt"
    if not ssi_path.exists() or not html_path.exists():
        pytest.skip("SSI/HTML payload-файлы ещё не созданы агентом payloads")
    ssi = _payload_lines("ssi.txt")
    html = _payload_lines("html_injection.txt")
    assert len(ssi) >= 15 and all("<!--#" in p for p in ssi)
    assert len(html) >= 25
    assert all(re.search(r"notscan\s*=\s*['\"]?\d+", p, re.I) for p in html)


def test_runner_wstg_map_is_catalog_derived():
    for cd in CHECK_CATALOG:
        assert WSTG_ID_MAP.get(cd.check_id) == cd.wstg_id
    # legacy-алиасы движка не сломаны
    assert WSTG_ID_MAP.get("xss") == "WSTG-INPV-01"


def test_catalog_categories_count():
    seen = {cd.category for cd in CHECK_CATALOG}
    assert seen <= set(CATEGORIES)
    # все 8 GUI-групп представлены (для дерева Checks/WSTG)
    assert seen == set(CATEGORIES)


def test_extra_passive_checks_registered():
    reg = CheckRegistry()
    for cls in ALL_EXTRA_PASSIVE_CHECKS:
        assert reg.get(cls.check_id) is not None, f"{cls.check_id} не в registry"
        assert cls.passive is True
        assert cls.requires_payload is False
    assert len(ALL_EXTRA_PASSIVE_CHECKS) == 6


# ══════════════════════════════════════════════════════════════════
#  2. Passive-чеки: TP/FP
# ══════════════════════════════════════════════════════════════════

# ── cookies (WSTG-SESS-02) ──

def test_cookies_tp_missing_flags():
    findings = _run_passive(
        "cookies",
        resp_headers={"set-cookie": "sessionid=abc123; Path=/"},
    )
    assert findings, "Set-Cookie без Secure/HttpOnly/SameSite должен быть находкой"
    assert findings[0].vuln_type == "cookies"
    assert "sessionid" in findings[0].evidence
    assert findings[0].severity.value == "HIGH"  # сессионная cookie


def test_cookies_fp_all_flags_present():
    findings = _run_passive(
        "cookies",
        resp_headers={"set-cookie": "sid=abc; Secure; HttpOnly; SameSite=Strict; Path=/"},
    )
    assert findings == []


def test_cookies_fp_http_secure_not_required():
    """На http:// отсутствие Secure — не находка (cookie всё равно не уйдёт)."""
    findings = _run_passive(
        "cookies",
        url="http://example.test/",
        resp_headers={"set-cookie": "sid=abc; HttpOnly; SameSite=Lax"},
    )
    assert findings == []


def test_cookies_fp_benign_cookie():
    findings = _run_passive(
        "cookies",
        resp_headers={"set-cookie": "theme=dark; Path=/"},
    )
    assert findings == []


def test_cookies_multiple_combined_header():
    findings = _run_passive(
        "cookies",
        resp_headers={"set-cookie": "a=1; HttpOnly; SameSite=Lax; Secure, sid=xyz; Path=/"},
    )
    assert len(findings) == 1
    assert "sid" in findings[0].evidence


# ── hsts (WSTG-CONF-07) ──

def test_hsts_tp_missing_header():
    findings = _run_passive("hsts", resp_headers={"content-type": "text/html"})
    assert len(findings) == 1
    assert "Strict-Transport-Security" in findings[0].evidence


def test_hsts_fp_present():
    findings = _run_passive(
        "hsts",
        resp_headers={"strict-transport-security": "max-age=31536000; includeSubDomains"},
    )
    assert findings == []


def test_hsts_tp_max_age_zero():
    findings = _run_passive(
        "hsts", resp_headers={"strict-transport-security": "max-age=0"}
    )
    assert len(findings) == 1


def test_hsts_skips_http():
    findings = _run_passive("hsts", url="http://example.test/")
    assert findings == []


# ── csp (WSTG-CONF-12 v5) ──

def test_csp_tp_missing():
    findings = _run_passive(
        "csp", resp_headers={"content-type": "text/html; charset=utf-8"}
    )
    assert len(findings) == 1
    assert "Content-Security-Policy" in findings[0].evidence


def test_csp_tp_unsafe_inline():
    findings = _run_passive(
        "csp",
        resp_headers={
            "content-type": "text/html",
            "content-security-policy": "default-src 'self'; script-src 'self' 'unsafe-inline'",
        },
    )
    assert findings
    assert any("unsafe-inline" in f.evidence for f in findings)


def test_csp_fp_strong_policy():
    findings = _run_passive(
        "csp",
        resp_headers={
            "content-type": "text/html",
            "content-security-policy": "default-src 'self'; script-src 'nonce-abc123'",
        },
    )
    assert findings == []


def test_csp_skips_json():
    findings = _run_passive(
        "csp", resp_headers={"content-type": "application/json"}
    )
    assert findings == []


# ── cache_control (WSTG-ATHN-06) ──

def test_cache_control_tp_sensitive_without_no_store():
    findings = _run_passive(
        "cache_control",
        resp_headers={"set-cookie": "sessionid=abc; Path=/", "content-type": "text/html"},
    )
    assert len(findings) == 1
    assert "Cache-Control" in findings[0].evidence


def test_cache_control_fp_no_store():
    findings = _run_passive(
        "cache_control",
        resp_headers={
            "set-cookie": "sessionid=abc; Path=/",
            "cache-control": "no-store, private",
        },
    )
    assert findings == []


def test_cache_control_fp_public_response():
    findings = _run_passive(
        "cache_control",
        resp_headers={"content-type": "text/html"},
        resp_text="<html><body>public page</body></html>",
    )
    assert findings == []


def test_cache_control_tp_authorization_request():
    findings = _run_passive(
        "cache_control",
        req_headers={"Authorization": "Bearer token"},
        resp_text='{"account": "secret"}',
    )
    assert len(findings) == 1


# ── insecure_login (WSTG-ATHN-01) ──

def test_insecure_login_tp_password_form_over_http():
    findings = _run_passive(
        "insecure_login",
        url="http://example.test/login",
        method="POST",
        body=b"username=alice&password=s3cr3t",
        resp_headers={"content-type": "text/html"},
        resp_text='<form action="/login"><input type="password" name="password"></form>',
    )
    assert len(findings) == 1
    assert "http://" in findings[0].evidence


def test_insecure_login_fp_https():
    findings = _run_passive(
        "insecure_login",
        url="https://example.test/login",
        method="POST",
        body=b"username=alice&password=s3cr3t",
        resp_headers={"content-type": "text/html"},
        resp_text='<input type="password">',
    )
    assert findings == []


def test_insecure_login_fp_plain_page():
    findings = _run_passive(
        "insecure_login",
        url="http://example.test/about",
        resp_headers={"content-type": "text/html"},
        resp_text="<html><body>about us</body></html>",
    )
    assert findings == []


def test_insecure_login_tp_authorization_header():
    findings = _run_passive(
        "insecure_login",
        url="http://example.test/api",
        req_headers={"Authorization": "Basic dXNlcjpwYXNz"},
    )
    assert len(findings) == 1


# ── browser_storage (WSTG-CLNT-12) ──

def test_browser_storage_tp_token():
    findings = _run_passive(
        "browser_storage",
        resp_headers={"content-type": "text/html"},
        resp_text=(
            "<html><script>"
            "localStorage.setItem('auth_token', 'eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.sig');"
            "</script></html>"
        ),
    )
    assert findings
    assert "auth_token" in findings[0].evidence


def test_browser_storage_fp_theme():
    findings = _run_passive(
        "browser_storage",
        resp_headers={"content-type": "text/html"},
        resp_text="<script>localStorage.setItem('theme', 'dark');</script>",
    )
    assert findings == []


def test_browser_storage_fp_no_storage():
    findings = _run_passive(
        "browser_storage",
        resp_headers={"content-type": "text/html"},
        resp_text="<html><body>no js storage here</body></html>",
    )
    assert findings == []


def test_browser_storage_tp_jwt_value_property():
    findings = _run_passive(
        "browser_storage",
        resp_headers={"content-type": "text/html"},
        resp_text=(
            "<script>window.sessionStorage.jwt = "
            "'eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJhZG1pbiJ9.sig';</script>"
        ),
    )
    assert findings


# ══════════════════════════════════════════════════════════════════
#  3. Active-чеки: HTML injection (WSTG-CLNT-03)
# ══════════════════════════════════════════════════════════════════

HTML_TP_PAYLOAD = '<h1 notscan=7>HTMLINJ_MARKER</h1>'
HTML_TP_RESPONSE = f"<html><body>{HTML_TP_PAYLOAD}</body></html>"
HTML_HEADERS = {"content-type": "text/html; charset=utf-8"}


def test_html_injection_check_tp():
    findings = _run_check_class(
        "html_injection", payload=HTML_TP_PAYLOAD,
        resp_text=HTML_TP_RESPONSE, resp_headers=HTML_HEADERS,
    )
    assert len(findings) == 1
    assert findings[0].vuln_type == "html_injection"
    assert "notscan" in findings[0].evidence


def test_html_injection_check_fp_escaped():
    escaped = HTML_TP_RESPONSE.replace("<", "&lt;").replace(">", "&gt;")
    findings = _run_check_class(
        "html_injection", payload=HTML_TP_PAYLOAD,
        resp_text=escaped, resp_headers=HTML_HEADERS,
    )
    assert findings == []


def test_html_injection_check_fp_json_response():
    findings = _run_check_class(
        "html_injection", payload=HTML_TP_PAYLOAD,
        resp_text=f'{{"q": "{HTML_TP_PAYLOAD}"}}',
        resp_headers={"content-type": "application/json"},
    )
    assert findings == []


def test_html_injection_check_fp_bare_tag():
    """«Голый» тег без атрибутов-маркеров — не HTML-инъекция (bare-tag правило)."""
    findings = _run_check_class(
        "html_injection", payload="<h1>",
        resp_text="<html><body><h1>Title</h1></body></html>",
        resp_headers=HTML_HEADERS,
    )
    assert findings == []


def test_html_injection_matcher_registered():
    assert scanner_core.run_matcher(
        "html_injection", HTML_TP_PAYLOAD, HTML_TP_RESPONSE, 200, HTML_HEADERS
    )
    assert scanner_core.run_matcher(
        "html_injection", HTML_TP_PAYLOAD, HTML_TP_RESPONSE, 200,
        {"content-type": "application/json"},
    ) is None


def test_html_injection_indicator_all_marker_variants():
    for payload in (
        '<h1 notscan=1>HTMLINJ_MARKER</h1>',
        '<div notscan="27">HTMLINJ_MARKER</div>',
        '<p NOTSCAN=28>HTMLINJ_MARKER</p>',
        '"><h2 notscan=5>HTMLINJ_MARKER</h2>',
    ):
        assert html_injection_indicator(payload, f"<html>{payload}</html>", HTML_HEADERS)
        escaped = f"<html>{payload.replace('<', '&lt;').replace('>', '&gt;')}</html>"
        assert html_injection_indicator(payload, escaped, HTML_HEADERS) is None


# ══════════════════════════════════════════════════════════════════
#  4. Active-чеки: SSI injection (WSTG-INPV-08)
# ══════════════════════════════════════════════════════════════════

SSI_TP_PAYLOAD = '<!--#echo var="DATE_LOCAL" -->'


def test_ssi_check_tp_error_signature():
    findings = _run_check_class(
        "ssi_injection", payload=SSI_TP_PAYLOAD,
        resp_text="<html>[an error occurred while processing this directive]</html>",
        resp_headers=HTML_HEADERS,
    )
    assert len(findings) == 1
    assert findings[0].vuln_type == "ssi_injection"


def test_ssi_check_tp_executed_date():
    findings = _run_check_class(
        "ssi_injection", payload=SSI_TP_PAYLOAD,
        resp_text="<html>Last modified: Monday, 29-Oct-2026 15:00:00</html>",
        resp_headers=HTML_HEADERS,
    )
    assert len(findings) == 1


def test_ssi_check_tp_reflected_unescaped_is_weak():
    findings = _run_check_class(
        "ssi_injection", payload=SSI_TP_PAYLOAD,
        resp_text=f"<html><body>{SSI_TP_PAYLOAD}</body></html>",
        resp_headers=HTML_HEADERS,
    )
    assert len(findings) == 1
    assert "needs manual verification" in findings[0].evidence
    assert findings[0].severity.value == "MEDIUM"


def test_ssi_check_fp_no_directive_processing():
    findings = _run_check_class(
        "ssi_injection", payload=SSI_TP_PAYLOAD,
        resp_text="<html><body>ordinary page without includes</body></html>",
        resp_headers=HTML_HEADERS,
    )
    assert findings == []


def test_ssi_check_fp_escaped_and_json():
    escaped = f"<html>&lt;!--#echo var=&quot;DATE_LOCAL&quot; --&gt;</html>"
    assert _run_check_class(
        "ssi_injection", payload=SSI_TP_PAYLOAD, resp_text=escaped,
        resp_headers=HTML_HEADERS,
    ) == []
    assert _run_check_class(
        "ssi_injection", payload=SSI_TP_PAYLOAD,
        resp_text=f'{{"q": "{SSI_TP_PAYLOAD}"}}',
        resp_headers={"content-type": "application/json"},
    ) == []


def _html_escape_echo(payload: str) -> str:
    """Эмуляция уязвимой/безопасной страницы с html.escape-эхом (как lab /search)."""
    return "<html><body>You searched: %s</body></html>" % html.escape(payload)


def test_ssi_check_fp_html_escaped_reflection_marker_payloads():
    """Bаг из QA: marker/payload в escaped-эхе НЕ должен давать strong-находку."""
    for payload in (
        '<!--#echo var="NOTSCAN_SSI_MARKER" -->',
        '<!--#exec cmd="echo NOTSCAN_SSI_MARKER" -->',
        '<!--#if expr="1=1" -->NOTSCAN_SSI_MARKER<!--#endif -->',
        '<!--#echo var="DATE_LOCAL" -->',
        '<!--#printenv -->',
        '<!--#exec cmd="id" -->',
    ):
        findings = _run_check_class(
            "ssi_injection", payload=payload,
            resp_text=_html_escape_echo(payload), resp_headers=HTML_HEADERS,
        )
        assert findings == [], f"{payload!r}: FP на html-escaped отражении"


def test_ssi_indicator_all_real_payloads_escaped_echo_none():
    """Все реальные SSI_TEMP payload'ы на html.escape-эхо: ни strong, ни weak."""
    payloads = _payload_lines("ssi.txt")
    assert payloads
    for payload in payloads:
        escaped = _html_escape_echo(payload)
        assert ssi_indicator(payload, escaped, HTML_HEADERS) is None, (
            f"{payload!r} -> {ssi_indicator(payload, escaped, HTML_HEADERS)!r}"
        )
        # JSON/plain Content-Type — тоже не находка
        json_body = json.dumps({"q": html.escape(payload)})
        assert ssi_indicator(payload, json_body,
                             {"content-type": "application/json"}) is None
        assert ssi_indicator(payload, escaped,
                             {"content-type": "text/plain"}) is None


def test_ssi_indicator_real_payloads_raw_echo_only_weak():
    """Сырое echo (без экранирования) — только weak-сигнал, не «executed»."""
    for payload in _payload_lines("ssi.txt"):
        evidence = ssi_indicator(payload, _html_escape_echo(payload).replace(
            html.escape(payload), payload), HTML_HEADERS)
        assert evidence, f"{payload!r}: weak-сигнал потерян"
        assert "needs manual verification" in evidence, evidence
        assert "executed" not in evidence.lower(), evidence


def test_ssi_check_tp_executed_outputs():
    """Реальный вывод SSI (маркер/date/uid) при НЕотражённой директиве — strong TP."""
    cases = [
        ('<!--#echo var="NOTSCAN_SSI_MARKER" -->',
         "<html><body>NOTSCAN_SSI_MARKER</body></html>"),
        ('<!--#echo var="DATE_LOCAL" -->',
         "<html><body>2026-10-29T15:00:00</body></html>"),
        ('<!--#exec cmd="id" -->',
         "<html><body>uid=0(root) gid=0(root)</body></html>"),
        ('<!--#printenv -->',
         "<html><body>DOCUMENT_ROOT=/var/www/html</body></html>"),
    ]
    for payload, response in cases:
        findings = _run_check_class(
            "ssi_injection", payload=payload, resp_text=response,
            resp_headers=HTML_HEADERS,
        )
        assert len(findings) == 1, f"{payload!r}: strong TP потерян"
        assert "executed" in findings[0].evidence.lower() or "output" in findings[0].evidence.lower()


def test_ssi_matcher_registered():
    assert scanner_core.run_matcher(
        "ssi_injection", SSI_TP_PAYLOAD,
        "<html>[an error occurred while processing this directive]</html>",
        200, HTML_HEADERS,
    )
    assert scanner_core.run_matcher(
        "ssi_injection", SSI_TP_PAYLOAD, "<html>nothing</html>", 200, HTML_HEADERS
    ) is None
    # engine-путь: escaped эхо маркера не должно давать strong (QA-баг)
    marker_payload = '<!--#echo var="NOTSCAN_SSI_MARKER" -->'
    assert scanner_core.run_matcher(
        "ssi_injection", marker_payload,
        _html_escape_echo(marker_payload), 200, HTML_HEADERS,
    ) is None


def test_ssi_indicator_execution_marker():
    """Исполнение #echo/#exec с маркером: директива заменена своим выводом."""
    payload = '<!--#echo var="NOTSCAN_SSI_MARKER" -->'
    assert ssi_indicator(payload, "<html>NOTSCAN_SSI_MARKER</html>", HTML_HEADERS)
    assert ssi_indicator(
        '<!--#exec cmd="echo NOTSCAN_SSI_MARKER" -->',
        "<pre>NOTSCAN_SSI_MARKER</pre>", HTML_HEADERS,
    )


def test_ssi_indicator_exec_variants():
    assert ssi_indicator('<!--#exec cmd="id" -->', "<pre>uid=0(root) gid=0(root)</pre>",
                         HTML_HEADERS)
    assert ssi_indicator('<!--#include file="/etc/passwd" -->',
                         "<pre>root:x:0:0:root:/root:/bin/bash</pre>", HTML_HEADERS)
    assert ssi_indicator('<!--#printenv -->', "<pre>DOCUMENT_ROOT=/var/www</pre>",
                         HTML_HEADERS)


# ══════════════════════════════════════════════════════════════════
#  5. scanner_core: payload'ы, planner, time-based, destructive
# ══════════════════════════════════════════════════════════════════

def test_load_payloads_uses_catalog():
    assert scanner_core.load_payloads("sqli")
    assert scanner_core.load_payloads("sqli_time")
    assert scanner_core.load_payloads("ssi_injection") == _payload_lines("ssi.txt")
    assert scanner_core.load_payloads("html_injection") == _payload_lines("html_injection.txt")
    # legacy payload-файлы file_upload/idor сохранены (каталог, kind=passive)
    assert scanner_core.load_payloads("file_upload") == _payload_lines("file_upload.txt")
    assert scanner_core.load_payloads("idor") == _payload_lines("idor.txt")
    # legacy-имя "xss" (не чек каталога) продолжает работать
    assert scanner_core.load_payloads("xss")
    assert scanner_core.load_payloads("no_such_check") == []


def test_build_scan_tasks_keeps_new_active_checks(tmp_db):
    """Planner не должен выкидывать ssi_injection/html_injection задачи."""
    history_id = db.insert_history(
        "GET", "http://127.0.0.1:9/api?name=test",
        {"Accept": "*/*"}, None, 200, {"content-type": "text/html"}, b"<html></html>",
    )
    tasks = scanner_core.build_scan_tasks(
        [history_id], ["ssi_injection", "html_injection"], safe_mode=False,
    )
    types = {t.check_type for t in tasks}
    assert types == {"ssi_injection", "html_injection"}
    expected = (len(scanner_core.load_payloads("ssi_injection"))
                + len(scanner_core.load_payloads("html_injection")))
    assert len(tasks) == expected, f"planner потерял задачи: {len(tasks)} != {expected}"


def test_new_active_checks_not_destructive_in_safe_mode():
    assert (
        scanner_core.load_payloads("ssi_injection", safe_mode=True)
        == scanner_core.load_payloads("ssi_injection", safe_mode=False)
    )
    assert (
        scanner_core.load_payloads("html_injection", safe_mode=True)
        == scanner_core.load_payloads("html_injection", safe_mode=False)
    )


def test_sqli_time_payloads_synced_with_payload_file():
    """Все SQLI_TIME_PAYLOADS должны посимвольно присутствовать в sqli_time.txt."""
    lines = _payload_lines("sqli_time.txt")
    assert len(SQLI_TIME_PAYLOADS) >= 23, "ожидались 4 старых + 19 новых time-based"
    missing = [p for _pid, p, _t, _db in SQLI_TIME_PAYLOADS if p not in lines]
    assert not missing, f"нет в sqli_time.txt: {missing[:5]}"
    # новые быстрые пороги 2–3 c
    new_thresholds = [t for _pid, _p, t, _db in SQLI_TIME_PAYLOADS[4:]]
    assert new_thresholds and all(2.0 <= t <= 3.0 for t in new_thresholds)


def test_sqli_time_detects_new_2s_payload():
    check = CheckRegistry().get("sqli_time")
    assert check is not None

    def run(elapsed_ms: float, payload: str, baseline_ms: float = 150.0):
        req = ScanRequest(method="GET", url="http://x/?id=1", headers={}, body=b"", raw_http="")
        resp = ScanResponse(status_code=200, headers={}, text="ok",
                            elapsed_ms=elapsed_ms, error=None)
        ctx = CheckContext(payload=payload, check_type="sqli_time",
                           baseline_ms=baseline_ms)
        return check.check(req, resp, ctx).findings

    payload = "' AND SLEEP(2)-- -"
    assert run(2400.0, payload), "задержка >= порога должна детектиться"
    assert run(300.0, payload) == [], "без задержки — не time-based"


def test_destructive_patterns_include_expect_wrapper():
    assert "expect://" in scanner_core.DESTRUCTIVE_PAYLOAD_PATTERNS
    assert scanner_core._is_destructive_payload(
        '<!DOCTYPE r [<!ENTITY x SYSTEM "expect://id">]><r>&x;</r>'
    )
    unsafe = scanner_core.load_payloads("xxe", safe_mode=False)
    safe = scanner_core.load_payloads("xxe", safe_mode=True)
    expected_safe = [p for p in unsafe if not scanner_core._is_destructive_payload(p)]
    assert safe == expected_safe


# ══════════════════════════════════════════════════════════════════
#  6. Probe-чеки (path_probe.run_probe_scan) на локальном сервере
# ══════════════════════════════════════════════════════════════════

def test_probe_public_api_and_ids():
    assert path_probe.run_info_disclosure_scan is not None
    assert set(path_probe.PROBE_IDS) == set(PROBE_CHECK_IDS)
    for probe_id in path_probe.PROBE_IDS:
        assert probe_id in path_probe._PROBE_HANDLERS


def test_probe_sensitive_files(probe_server, tmp_db):
    count = path_probe.run_probe_scan(
        [probe_server + "/home?x=1"], ["sensitive_files"], log_cb=lambda _m: None,
    )
    rows = _probe_rows("sensitive_files")
    assert count == len(rows) >= 2
    urls = {r["url"] for r in rows}
    assert f"{probe_server}/.env" in urls
    assert f"{probe_server}/backup.sql" in urls
    # 200-заглушка WAF ("Access denied") не считается раскрытием файла
    assert f"{probe_server}/phpinfo.php" not in urls
    meta = db.fetch_scan_meta_by_result(rows[0]["id"])
    assert meta and meta["detector"] == "probe"
    assert meta["severity"] == "HIGH"
    assert meta["fingerprint"], "scan_meta.fingerprint должен быть заполнен"


def test_probe_metafiles(probe_server, tmp_db):
    count = path_probe.run_probe_scan(
        [probe_server], ["metafiles"], log_cb=lambda _m: None,
    )
    rows = _probe_rows("metafiles")
    assert count == len(rows) >= 1
    assert any(r["url"].endswith("/robots.txt") for r in rows)


def test_probe_ria_policy(probe_server, tmp_db):
    count = path_probe.run_probe_scan(
        [probe_server], ["ria_policy"], log_cb=lambda _m: None,
    )
    rows = _probe_rows("ria_policy")
    assert count == len(rows) == 1
    assert "crossdomain.xml" in rows[0]["url"]
    assert "wildcard" in (rows[0]["evidence"] or "").lower()


def test_probe_http_methods(probe_server, tmp_db):
    count = path_probe.run_probe_scan(
        [probe_server], ["http_methods"], log_cb=lambda _m: None,
    )
    rows = _probe_rows("http_methods")
    assert count == len(rows) >= 2
    evidence = " ".join((r["evidence"] or "") for r in rows)
    assert "OPTIONS" in evidence or "TRACE" in evidence


def test_probe_cors(probe_server, tmp_db):
    count = path_probe.run_probe_scan(
        [probe_server], ["cors"], log_cb=lambda _m: None,
    )
    rows = _probe_rows("cors")
    assert count == len(rows) == 1
    assert "reflected" in rows[0]["evidence"].lower() or "Origin" in rows[0]["evidence"]
    meta = db.fetch_scan_meta_by_result(rows[0]["id"])
    assert meta["severity"] == "HIGH"


def test_probe_cors_checks_scan_paths(probe_server, tmp_db):
    """CORS-проба идёт и на конкретный путь из scan-list (как lab /cors-reflect)."""
    count = path_probe.run_probe_scan(
        [probe_server + "/cors-reflect?x=1"], ["cors"], log_cb=lambda _m: None,
    )
    rows = _probe_rows("cors")
    assert count == len(rows) == 1
    assert "/cors-reflect" in rows[0]["url"]


def test_probe_legacy_wrapper(probe_server, tmp_db):
    count = path_probe.run_info_disclosure_scan(
        [probe_server], log_cb=lambda _m: None,
    )
    rows = _probe_rows("info_disclosure_paths")
    assert count == len(rows) >= 1
    assert any(r["url"].endswith("/.env") for r in rows)


def test_probe_default_runs_all_ids(probe_server, tmp_db):
    logs: list[str] = []
    count = path_probe.run_probe_scan([probe_server], log_cb=logs.append)
    kinds = {r["check_type"] for r in db.fetch_scan_results(limit=None)}
    assert count >= 8, logs
    assert kinds <= set(path_probe.PROBE_IDS)
    assert {"sensitive_files", "metafiles", "ria_policy", "http_methods", "cors"} <= kinds, logs


def test_probe_unknown_ids_and_bad_urls(tmp_db):
    logs: list[str] = []
    assert path_probe.run_probe_scan(["http://127.0.0.1:9"], ["nope"], log_cb=logs.append) == 0
    assert any("No known probe ids" in line for line in logs)
    assert path_probe.run_probe_scan(["not-a-url"], ["cors"]) == 0


def test_probe_soft_404_suppressed(spa_server, tmp_db):
    """SPA, отдающий 200 на всё, не должен давать находок sensitive_files/metafiles."""
    assert path_probe.run_probe_scan(
        [spa_server], ["sensitive_files", "metafiles"], log_cb=lambda _m: None,
    ) == 0
