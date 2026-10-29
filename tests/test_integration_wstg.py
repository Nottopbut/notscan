"""
tests/test_integration_wstg.py — QA волна 2: интеграция новых WSTG-чеков.

Проверяется на локальной лабе (`tests/lab/`) и в headless-xvfb:
  • каталог `checks/catalog.py` (43 чека) ↔ payload-файлы ↔ GUI Checks/WSTG;
  • новые active-чеки (ssi_injection, html_injection) через реальный движок
    (`build_scan_tasks → ScannerRunner → scan_results`) — TP на уязвимых
    эндпоинтах и **0 FP** на /search (html.escape) и /safe;
  • новые passive-чеки (cookies/cache_control/insecure_login/browser_storage/csp)
    на реальных HTTP-ответах лабы через `run_checks_on_response(only_passive=True)`;
  • probe-чеки (`path_probe.run_probe_scan`: sensitive_files/metafiles/ria_policy/
    http_methods/cors) — находки с `detector="probe"` и 0 FP на «чистой» лабе;
    host_header_injection проверяется unit-тестами (tests/test_wstg_checks.py) на
    собственном ThreadingHTTPServer — лаба host-заголовки не отражает;
  • авто-жизненный цикл прокси: авто-старт при запуске App, освобождение порта
    после закрытия, fallback при занятом 8080, отсутствие кнопки Stop Proxy.

Тесты помечены ``@pytest.mark.integration`` (Makefile: ``make lab``). Payload'ы
в движковых сценариях урезаны (секунды); TP/FP с РЕАЛЬНЫМИ payload-файлами —
в `test_active_new_checks_no_fp_on_search_and_safe` (110 задач, ~1 c).
"""

from __future__ import annotations

import collections
import json
import os
import shutil
import socket
import subprocess
import sys
import textwrap
import time
from pathlib import Path

import pytest

import db
import path_probe
import scanner_core
from checks.registry import get_registry, reset_registry
from checks.runner import run_checks_on_response
from tests.lab import harness
from tests.lab.server import LabServer

pytestmark = pytest.mark.integration

PROJECT_DIR = Path(__file__).resolve().parent.parent
_RESULT_PREFIX = "RESULT_JSON "

NEW_PASSIVE_IDS = ("cookies", "cache_control", "insecure_login", "browser_storage", "csp")
NEW_ACTIVE_IDS = ("ssi_injection", "html_injection")
NEW_PROBE_IDS = ("sensitive_files", "metafiles", "ria_policy", "http_methods", "cors")

#: короткие наборы для быстрых движковых сценариев
SSI_PAYLOADS = [
    '<!--#echo var="NOTSCAN_SSI_MARKER" -->',
    '<!--#exec cmd="id" -->',
    '<!--#printenv -->',
    '<!--#echo var="DATE_LOCAL" -->',
    "plain-ssi-control",
]
HTML_PAYLOADS = [
    "<h1 notscan=1>HTMLINJ_MARKER</h1>",
    "<div notscan=2>HTMLINJ_MARKER</div>",
    "plain-html-control",
]


# ══════════════════════════════════════════════════════════════════
#  helpers
# ══════════════════════════════════════════════════════════════════


@pytest.fixture()
def lab(tmp_path):
    env = harness.Lab(tmp_path)
    try:
        yield env
    finally:
        env.close()


def _db_findings(url_contains: str | None = None) -> list[dict]:
    """Все evidence-строки (+ detector) из текущей БД."""
    rows = harness.sqlite_rows(
        "SELECT r.id, r.url, r.check_type, r.evidence, r.payload, m.detector "
        "FROM scan_results r LEFT JOIN scan_meta m ON m.scan_result_id = r.id "
        "WHERE r.evidence IS NOT NULL AND r.evidence != ''"
    )
    if url_contains is not None:
        rows = [r for r in rows if url_contains in (r["url"] or "")]
    return rows


def _run_passive(
    lab: harness.Lab,
    path: str,
    *,
    method: str = "GET",
    params: dict | None = None,
    headers: dict | None = None,
) -> list[dict]:
    """Снять реальный ответ лабы и прогнать passive-чеки через единый pipeline."""
    reset_registry()
    cap = lab.capture(method, path, params=params, headers=headers)
    run_checks_on_response(
        method=cap.method,
        url=cap.url,
        headers=dict(cap.request_headers),
        body=cap.request_body or b"",
        raw_http="",
        resp_status=cap.status,
        resp_headers=cap.response_headers,
        resp_text=cap.response_body.decode("utf-8", errors="replace"),
        resp_elapsed_ms=cap.elapsed_ms,
        resp_error=None,
        check_type="",
        payload="",
        mutation_point="",
        original_param="",
        history_id=None,
        registry=get_registry(),
        log_cb=lambda _msg: None,
        only_passive=True,
    )
    return _db_findings(url_contains=path)


def _by_type(rows: list[dict]) -> dict[str, list[dict]]:
    grouped: dict[str, list[dict]] = collections.defaultdict(list)
    for row in rows:
        grouped[(row["check_type"] or "").lower()].append(row)
    return grouped


# ── headless GUI helpers ────────────────────────────────────────────


def _xvfb_python() -> list[str]:
    xvfb_run = shutil.which("xvfb-run")
    if xvfb_run:
        return [xvfb_run, "-a", sys.executable]
    if os.environ.get("DISPLAY"):
        return [sys.executable]
    pytest.skip("нет ни xvfb-run, ни DISPLAY — GUI-тест невозможен")


def _copy_project(tmp_path: Path) -> Path:
    dst = tmp_path / "notscan_gui_copy"
    ignore = shutil.ignore_patterns(
        "__pycache__", "*.pyc", "*.pyo", ".git", "projects", "history.db",
        "history.db-*", ".venv", "venv", "reports", ".pytest_cache",
    )
    shutil.copytree(PROJECT_DIR, dst, ignore=ignore)
    return dst


def _run_gui_script(
    project: Path,
    code: str,
    *,
    disable_proxy_autostart: bool = True,
    timeout: int = 240,
) -> dict:
    env = dict(os.environ)
    if disable_proxy_autostart:
        env["NOTSCAN_DISABLE_PROXY_AUTOSTART"] = "1"
    else:
        env.pop("NOTSCAN_DISABLE_PROXY_AUTOSTART", None)
    proc = subprocess.run(
        [*_xvfb_python(), "-c", textwrap.dedent(code)],
        cwd=str(project),
        env=env,
        capture_output=True,
        text=True,
        timeout=timeout,
    )
    assert proc.returncode == 0, (
        f"GUI-скрипт упал (rc={proc.returncode}).\n"
        f"STDOUT:\n{proc.stdout[-3000:]}\nSTDERR:\n{proc.stderr[-3000:]}"
    )
    data = None
    for line in proc.stdout.splitlines():
        if line.startswith(_RESULT_PREFIX):
            data = json.loads(line[len(_RESULT_PREFIX):])
    assert data is not None, f"нет RESULT_JSON в stdout:\n{proc.stdout[-3000:]}"
    return data


_CATALOG_SCRIPT = r"""
import json, sys
sys.path.insert(0, ".")
import tkinter as tk
import tkinter.ttk as ttk
import notscan
import checks.catalog as catalog


def _walk(widget):
    stack = [widget]
    while stack:
        w = stack.pop()
        stack.extend(w.winfo_children())
        yield w


def _button_texts(root):
    texts = []
    for w in _walk(root):
        try:
            if isinstance(w, (tk.Button, ttk.Button)):
                texts.append(str(w.cget("text")))
        except Exception:
            pass
    return texts


app = notscan.App()
app.update()
tree_ids = list(app._chk_tree.get_children())
cfg = notscan.ScanConfigWindow(app)
app.update()
badges = sorted(cfg._badges.keys())
checkboxes = sorted(cfg._check_widgets.keys())
cfg.destroy()
app.update()
buttons = _button_texts(app)

result = {
    "catalog_count": len(catalog.CHECK_CATALOG),
    "catalog_ids": sorted(d.check_id for d in catalog.CHECK_CATALOG),
    "tree_ids": sorted(tree_ids),
    "uses_catalog": bool(getattr(app, "_uses_check_catalog", False)),
    "summary": app._chk_summary_lbl.cget("text"),
    "badges": badges,
    "checkboxes": checkboxes,
    "active_ids": sorted(d.check_id for d in catalog.by_kind("active")),
    "passive_ids": sorted(d.check_id for d in catalog.by_kind("passive")),
    "probe_ids": sorted(d.check_id for d in catalog.by_kind("probe")),
    "passive_helper": sorted(notscan.passive_check_ids()),
    "probe_helper": sorted(notscan.probe_check_ids()),
    "button_texts": buttons,
    "has_stop_proxy": any(
        ("stop" in t.lower() and "proxy" in t.lower()) for t in buttons
    ),
    "has_stop_scan": any("stop scan" in t.lower() for t in buttons),
    "has_proxy_settings": all(
        hasattr(app, name)
        for name in ("_proxy_autostart_var", "_proxy_stop_on_browser_exit_var",
                     "_proxy_idle_min_var")
    ),
    "has_lifecycle": all(
        hasattr(app, name)
        for name in ("_maybe_autostart_proxy", "_proxy_watchdog_tick",
                     "_check_browser_exit", "_check_idle_stop",
                     "_shutdown_proxy_sync")
    ),
}
print("RESULT_JSON " + json.dumps(result, ensure_ascii=False))
app.destroy()
"""


def _bindable(port: int, host: str = "127.0.0.1") -> bool:
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(1.0)
    try:
        sock.bind((host, port))
        return True
    except OSError:
        return False
    finally:
        sock.close()


# ══════════════════════════════════════════════════════════════════
#  1. Каталог ↔ payload-файлы ↔ matchers
# ══════════════════════════════════════════════════════════════════


def test_catalog_complete_with_payload_files_and_matchers():
    """43 чека: уникальные id, active с payload-файлами, matcher'ы новых чеков."""
    import checks.catalog as catalog

    defs = list(catalog.CHECK_CATALOG)
    assert len(defs) == 43, f"ожидалось 43 чека, в каталоге {len(defs)}"
    ids = [d.check_id for d in defs]
    assert len(set(ids)) == len(ids), "дубли check_id в каталоге"

    kinds = collections.Counter(d.kind for d in defs)
    assert kinds["active"] == 17 and kinds["passive"] == 19 and kinds["probe"] == 7, kinds

    # Все active-чеки имеют payload-файл, который реально грузится.
    active_payloads: dict[str, list[str]] = {}
    for defn in catalog.by_kind("active"):
        assert defn.payload_file, f"active {defn.check_id} без payload_file"
        path = PROJECT_DIR / "payloads" / defn.payload_file
        assert path.is_file(), f"нет payload-файла {path}"
        loaded = scanner_core.load_payloads(defn.check_id)
        assert loaded, f"load_payloads({defn.check_id!r}) пуст"
        active_payloads[defn.check_id] = loaded

    # Новые WSTG-чеки есть в каталоге, payload'ах и matcher-слое.
    new_active = [d for d in catalog.by_kind("active") if d.check_id in NEW_ACTIVE_IDS]
    assert {d.check_id for d in new_active} == set(NEW_ACTIVE_IDS)
    assert catalog.payload_file_for("ssi_injection") == "ssi.txt"
    assert catalog.payload_file_for("html_injection") == "html_injection.txt"
    for cid in NEW_ACTIVE_IDS:
        assert cid in scanner_core.MATCHERS, f"{cid} нет в scanner_core.MATCHERS"

    # WSTG-карта runner'а — из каталога.
    from checks.runner import WSTG_ID_MAP
    for defn in defs:
        assert WSTG_ID_MAP.get(defn.check_id) == defn.wstg_id, (
            f"WSTG_ID_MAP[{defn.check_id}]={WSTG_ID_MAP.get(defn.check_id)!r} "
            f"!= каталог {defn.wstg_id!r}"
        )

    # Active+passive зарегистрированы в CheckRegistry.
    registry = reset_registry()
    for defn in catalog.by_kind("active") + catalog.by_kind("passive"):
        assert registry.get(defn.check_id) is not None, f"{defn.check_id} не в registry"


def test_new_payload_files_format_and_safe_mode():
    """SSI/HTML payload-файлы подхватываются; safe_mode не ломает их."""
    ssi = scanner_core.load_payloads("ssi_injection")
    html_payloads = scanner_core.load_payloads("html_injection")
    assert len(ssi) >= 15, f"SSI payload'ов {len(ssi)}"
    assert len(html_payloads) >= 25, f"HTML payload'ов {len(html_payloads)}"
    assert all("<!--#" in p for p in ssi), "SSI payload без директивы"
    assert all("notscan=" in p.lower() for p in html_payloads), "HTML payload без маркера"

    # safe_mode для новых чеков ничего не отбрасывает (payload'ы не деструктивные).
    assert scanner_core.load_payloads("ssi_injection", safe_mode=True) == ssi
    assert scanner_core.load_payloads("html_injection", safe_mode=True) == html_payloads

    # Контроль: для sqli safe ⊆ all и safe_mode действительно фильтрует.
    sql_all = scanner_core.load_payloads("sqli", safe_mode=False)
    sql_safe = scanner_core.load_payloads("sqli", safe_mode=True)
    assert set(sql_safe) <= set(sql_all)
    assert len(sql_safe) <= len(sql_all)


# ══════════════════════════════════════════════════════════════════
#  2. Active-чеки через реальный движок (TP + FP)
# ══════════════════════════════════════════════════════════════════


def test_active_ssi_injection_tp_on_ssi_endpoint(lab):
    """SSI-директивы на /ssi исполняются → ssi_injection TP."""
    history_id = lab.add_get("/ssi", {"q": "hello"})
    result = lab.build_and_run(
        [history_id],
        checks=["ssi_injection"],
        payloads={"ssi_injection": SSI_PAYLOADS},
    )
    assert result.tasks_for_url("/ssi"), "planner выкинул ssi_injection-задачи"
    hits = result.findings(check_type="ssi_injection", url_contains="/ssi")
    assert hits, "SSI-инъекция на /ssi не обнаружена"
    evidence = " ".join((r.get("evidence") or "") for r in hits).lower()
    assert "ssi" in evidence and ("executed" in evidence or "output" in evidence or "error" in evidence)


def test_active_html_injection_tp_on_html_endpoint(lab):
    """Маркерный HTML-тег отражается сырым → html_injection TP."""
    history_id = lab.add_get("/html", {"q": "hello"})
    result = lab.build_and_run(
        [history_id],
        checks=["html_injection"],
        payloads={"html_injection": HTML_PAYLOADS},
    )
    assert result.tasks_for_url("/html"), "planner выкинул html_injection-задачи"
    hits = result.findings(check_type="html_injection", url_contains="/html")
    assert hits, "HTML-инъекция на /html не обнаружена"
    assert any("notscan" in (r.get("evidence") or "").lower() for r in hits), (
        f"evidence без маркера: {[r['evidence'] for r in hits]}"
    )


def test_active_new_checks_no_fp_on_search_and_safe(lab):
    """FP=0 (реальные payload-файлы): /search (escape) и /safe не дают SSI/HTML."""
    ids = [
        lab.add_get("/search", {"q": "hello"}),
        lab.add_get("/safe", {"q": "hello"}),
    ]
    # payloads=None → реальные ssi.txt (20) и html_injection.txt (35).
    result = lab.build_and_run(ids, checks=list(NEW_ACTIVE_IDS))
    assert len(result.tasks) >= 100, f"мало задач: {len(result.tasks)}"

    fp_rows = [
        r for r in result.evidence
        if (r.get("check_type") or "").lower() in NEW_ACTIVE_IDS
        and ("/search" in r["url"] or "/safe" in r["url"])
    ]
    assert fp_rows == [], (
        "FP новых active-чеков на /search и /safe (контракт): "
        f"{[(r['check_type'], r['url'], r['payload'], (r['evidence'] or '')[:80]) for r in fp_rows]}"
    )


def test_planner_keeps_new_active_checks(lab):
    """Планировщик build_scan_tasks не выкидывает ssi_injection/html_injection."""
    history_id = lab.add_get("/reflect", {"q": "hello"})
    tasks = lab.build_tasks(
        [history_id], checks=list(NEW_ACTIVE_IDS)
    )  # реальные payload-файлы
    by_check = collections.Counter(t.check_type for t in tasks)
    assert by_check["ssi_injection"] >= 15, by_check
    assert by_check["html_injection"] >= 25, by_check
    assert all(t.mutation_point == "query" for t in tasks)


# ══════════════════════════════════════════════════════════════════
#  3. Passive-чеки на реальных ответах лабы (TP + FP)
# ══════════════════════════════════════════════════════════════════


def test_passive_cookies_tp_and_fp(lab):
    """/cookie-nosecure → cookies TP (sessionid, benign theme не флагуется)."""
    rows = _run_passive(lab, "/cookie-nosecure")
    cookies = _by_type(rows).get("cookies", [])
    assert cookies, "cookie без флагов не найден"
    evidence = " ".join((r["evidence"] or "") for r in cookies).lower()
    assert "sessionid" in evidence
    assert "theme" not in evidence, "benign cookie 'theme' ошибочно флагуется"

    secure_rows = _run_passive(lab, "/cookie-secure")
    assert not _by_type(secure_rows).get("cookies"), "FP: cookie со всеми флагами"


def test_passive_cache_control_tp_and_fp(lab):
    """/cache-session → cache_control TP; /secure-page (no-store) — FP=0."""
    rows = _run_passive(lab, "/cache-session")
    assert _by_type(rows).get("cache_control"), "кэшируемый ответ без no-store не найден"
    secure_rows = _run_passive(lab, "/secure-page")
    assert not _by_type(secure_rows).get("cache_control"), "FP: Cache-Control: no-store"


def test_passive_insecure_login_tp_and_fp(lab):
    """HTTP-форма логина (пароль в теле ответа/запроса) → insecure_login TP."""
    rows = _run_passive(lab, "/form")
    assert _by_type(rows).get("insecure_login"), "http-логин не найден"
    safe_rows = _run_passive(lab, "/safe")
    assert not _by_type(safe_rows).get("insecure_login"), "FP: страница без креденшелов"


def test_passive_browser_storage_tp_and_fp(lab):
    """localStorage.setItem('auth_token', …) → browser_storage TP."""
    rows = _run_passive(lab, "/storage")
    storage = _by_type(rows).get("browser_storage", [])
    assert storage, "секрет в localStorage не найден"
    assert "auth_token" in " ".join((r["evidence"] or "") for r in storage)
    safe_rows = _run_passive(lab, "/safe")
    assert not _by_type(safe_rows).get("browser_storage"), "FP: нет storage в /safe"


def test_passive_csp_tp_and_fp(lab):
    """/search без CSP → csp TP; /secure-page с nonce-CSP — FP=0."""
    rows = _run_passive(lab, "/search")
    assert _by_type(rows).get("csp"), "отсутствие CSP не найдено"
    secure_rows = _run_passive(lab, "/secure-page")
    assert not _by_type(secure_rows).get("csp"), "FP: сильная CSP"


def test_new_passive_checks_no_fp_on_safe_page(lab):
    """На /safe нет ложных срабатываний новых passive-чеков."""
    rows = _run_passive(lab, "/safe")
    grouped = _by_type(rows)
    for check_id in ("cookies", "cache_control", "insecure_login", "browser_storage"):
        assert not grouped.get(check_id), (
            f"FP {check_id} на /safe: {grouped[check_id]}"
        )


# ══════════════════════════════════════════════════════════════════
#  4. Probe-чеки (WSTG: sensitive_files/metafiles/ria_policy/…)
# ══════════════════════════════════════════════════════════════════


def test_probe_checks_tp_on_lab(lab):
    """Все 5 новых probe-чеков находят свои уязвимости на лабе."""
    found = path_probe.run_probe_scan(
        [lab.base_url + "/cors-reflect"],
        probe_ids=list(NEW_PROBE_IDS),
        log_cb=lambda _msg: None,
    )
    assert found >= 5, f"probe-находок {found}"
    rows = _db_findings()
    by_type = _by_type(rows)
    for check_id in NEW_PROBE_IDS:
        assert by_type.get(check_id), f"probe {check_id} не дал находок"
    assert all((r.get("detector") or "") == "probe" for r in rows), (
        f"детектор probe не проставлен: {[(r['check_type'], r.get('detector')) for r in rows]}"
    )
    # Контракт: check_type = probe_id, запись в scan_results + scan_meta.
    assert by_type["sensitive_files"][0]["url"].endswith("/backup.sql")
    assert any("/robots.txt" in r["url"] for r in by_type["metafiles"])
    assert any("/crossdomain.xml" in r["url"] for r in by_type["ria_policy"])
    assert any(r["check_type"] == "http_methods" for r in rows)
    assert any("/cors-reflect" in r["url"] for r in by_type["cors"])


def test_probe_checks_no_fp_on_clean_lab(tmp_path):
    """probe_clean-лаба (404/без рискованных заголовков) → 0 probe-находок."""
    with LabServer(probe_clean=True) as server:
        db.set_db_path(tmp_path / "clean_probe.db")
        found = path_probe.run_probe_scan(
            [server.base_url + "/cors-reflect"],
            probe_ids=list(NEW_PROBE_IDS) + ["info_disclosure_paths"],
            log_cb=lambda _msg: None,
        )
    assert found == 0, f"probe FP на чистой лабе: {_db_findings()}"


# ══════════════════════════════════════════════════════════════════
#  5. GUI: каталог ↔ Checks/WSTG вкладка + кнопки/настройки прокси
# ══════════════════════════════════════════════════════════════════


def test_gui_checks_tree_and_badges_match_catalog(tmp_path):
    """Дерево Checks/WSTG строится из каталога; Stop Proxy отсутствует."""
    import checks.catalog as catalog

    project = _copy_project(tmp_path)
    data = _run_gui_script(project, _CATALOG_SCRIPT)

    assert data["uses_catalog"] is True, "GUI не использует checks/catalog.py"
    assert data["catalog_count"] == len(catalog.CHECK_CATALOG) == 43
    assert data["tree_ids"] == data["catalog_ids"], (
        f"строк GUI {len(data['tree_ids'])} != чеков каталога {len(data['catalog_ids'])}"
    )
    assert set(data["badges"]) == set(data["active_ids"]), "бейджи != active каталога"
    expected_checkboxes = set(data["passive_ids"]) | set(data["probe_ids"])
    assert set(data["checkboxes"]) == expected_checkboxes, "чекбоксы != passive+probe"
    assert data["passive_helper"] == data["passive_ids"]
    assert data["probe_helper"] == data["probe_ids"]
    assert "info_disclosure_paths" in data["probe_ids"]
    assert "43" in data["summary"], data["summary"]

    # Кнопки Stop Proxy больше нет; Stop Scan — остаётся.
    assert data["has_stop_proxy"] is False, (
        f"в UI осталась кнопка Stop Proxy: {data['button_texts']}"
    )
    assert data["has_stop_scan"] is True
    assert data["has_proxy_settings"] is True
    assert data["has_lifecycle"] is True


# ══════════════════════════════════════════════════════════════════
#  6. GUI-прокси lifecycle
# ══════════════════════════════════════════════════════════════════
# Покрыто в tests/test_gui_catalog.py: прокси не стартует сам, старт по кнопке,
# смена порта, fallback при занятом порте, освобождение порта при закрытии.


def test_proxy_lifecycle_helpers_acceptance():
    """Публичные helper'ы lifecycle: порты/idle/настройки/методы App."""
    import mitm_proxy
    import notscan

    # find_free_port / next_proxy_port на реально занятом порте.
    blocker = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    blocker.bind(("127.0.0.1", 0))
    blocker.listen(1)
    busy_port = blocker.getsockname()[1]
    try:
        assert mitm_proxy.port_is_free("127.0.0.1", busy_port) is False
        assert mitm_proxy.find_free_port("127.0.0.1", busy_port) > busy_port
        assert mitm_proxy.next_proxy_port("127.0.0.1", busy_port) > busy_port
        assert mitm_proxy.find_free_port("127.0.0.1", 65536) is None
    finally:
        blocker.close()
    assert mitm_proxy.port_is_free("127.0.0.1", busy_port) is True

    # idle-порог.
    assert mitm_proxy.should_idle_stop(now=1000.0, last_activity=0.0, minutes=15) is False
    assert mitm_proxy.should_idle_stop(now=1000.0, last_activity=990.0, minutes=15) is False
    assert mitm_proxy.should_idle_stop(now=1000.0, last_activity=1000 - 15 * 60, minutes=15) is True
    assert mitm_proxy.should_idle_stop(now=1e9, last_activity=1.0, minutes=0) is False

    # Настройки авто-прокси: дефолты и нормализация.
    defaults = mitm_proxy.proxy_settings({})
    assert defaults["proxy_autostart"] is False, "прокси не должен авто-стартовать"
    assert defaults["proxy_stop_on_browser_exit"] is True
    assert defaults["proxy_idle_stop_min"] == 15
    assert defaults["proxy_filter_noise"] is True
    tuned = mitm_proxy.proxy_settings(
        {"proxy_autostart": True, "proxy_idle_stop_min": -3, "junk": "x"}
    )
    assert tuned["proxy_autostart"] is True
    assert tuned["proxy_idle_stop_min"] == 0.0

    # ProxyRunner отдаёт активность для idle-автостопа.
    runner = mitm_proxy.ProxyRunner(log_callback=lambda _m: None)
    assert hasattr(runner, "last_activity_ts")
    assert runner.last_activity_ts == 0.0
    assert runner._stopped_event.is_set(), "новый runner должен быть «остановлен»"

    # App содержит lifecycle-методы (Stop-кнопки нет — проверено в GUI-тесте).
    for name in (
        "_maybe_autostart_proxy",
        "_proxy_watchdog_tick",
        "_check_browser_exit",
        "_check_idle_stop",
        "_shutdown_proxy_sync",
        "_on_closing",
    ):
        assert hasattr(notscan.App, name), f"нет App.{name}"
