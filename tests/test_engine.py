"""
tests/test_engine.py — async-движок скана (M1), scope-guard и matcher-fixes.

Покрывает :
  • ScannerRunner на asyncio: все задачи доходят до БД, wait()/stop() не вешают;
  • follow_redirects=False ВСЕГДА (302 не сопровождается — scope-guard);
  • build_scan_tasks(tamper_modes=[...]) → дополнительные закодированные задачи;
  • build_scan_tasks(csrf_token_provider=...) → один вызов на history record,
    свежий токен в мутациях, PLACEHOLDER сохранён;
  • match_xss: bare-tag/JSON-фильтры; match_sqli_time → None;
  • host calibration не обновляется для sqli_time.

Тесты быстрые: сеть — локальный ThreadingHTTPServer на 127.0.0.1:0,
payload-листы подменяются через monkeypatch scanner_core.load_payloads.
"""

from __future__ import annotations

import http.server
import json
import socketserver
import threading
import time
import urllib.parse
from pathlib import Path

import pytest

import db
import scanner_core
import templating


# ══════════════════════════════════════════════════════════════════
#  Тестовый сервер (ThreadingHTTPServer на 127.0.0.1:0)
# ══════════════════════════════════════════════════════════════════


class _StubHandler(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    # ── helpers ──
    def _count(self, path: str) -> None:
        with self.server.lock:  # type: ignore[attr-defined]
            self.server.counts[path] = self.server.counts.get(path, 0) + 1  # type: ignore[attr-defined]

    def _send(self, status: int, body: bytes, headers: dict | None = None) -> None:
        self.send_response(status)
        for key, value in (headers or {}).items():
            self.send_header(key, value)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    # ── routes ──
    def do_GET(self) -> None:  # noqa: N802
        parsed = urllib.parse.urlsplit(self.path)
        self._count(parsed.path)
        qs = urllib.parse.parse_qs(parsed.query)
        if parsed.path == "/redirect":
            self._send(302, b"", {"Location": "/followed-by-redirect"})
            return
        if parsed.path == "/followed-by-redirect":
            self._send(200, b"followed")
            return
        if parsed.path == "/slow":
            ms = float((qs.get("ms") or ["200"])[0])
            time.sleep(ms / 1000.0)
            self._send(200, f"slow {ms}".encode())
            return
        if parsed.path == "/reflect":
            q = (qs.get("q") or [""])[0]
            body = f"<html>{q}</html>".encode()
            self._send(200, body, {"Content-Type": "text/html"})
            return
        if parsed.path == "/auth":
            auth_header = self.headers.get("Authorization", "")
            if auth_header == "Bearer FRESH":
                self._count("/auth-ok")
                self._send(200, b"secret")
            else:
                self._count("/auth-denied")
                self._send(401, b"unauthorized")
            return
        self._send(200, b"ok")

    def do_POST(self) -> None:  # noqa: N802
        parsed = urllib.parse.urlsplit(self.path)
        self._count(parsed.path)
        length = int(self.headers.get("Content-Length") or 0)
        body = self.rfile.read(length) if length else b""
        with self.server.lock:  # type: ignore[attr-defined]
            self.server.post_bodies.setdefault(parsed.path, []).append(body)  # type: ignore[attr-defined]
        if parsed.path == "/form":
            fields = urllib.parse.parse_qs(body.decode("utf-8", errors="replace"))
            token = (fields.get("csrf_token") or [""])[0]
            if token == "T0KEN":
                self._send(200, b"accepted")
            else:
                self._send(403, b"bad csrf")
            return
        self._send(200, b"posted")

    def log_message(self, *args) -> None:  # noqa: D401 - тишина в тестах
        pass


class _StubServer(socketserver.ThreadingTCPServer):
    daemon_threads = True
    allow_reuse_address = True


@pytest.fixture()
def stub_server():
    server = _StubServer(("127.0.0.1", 0), _StubHandler)
    server.counts = {}  # type: ignore[attr-defined]
    server.post_bodies = {}  # type: ignore[attr-defined]
    server.lock = threading.Lock()  # type: ignore[attr-defined]
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    server.base_url = f"http://127.0.0.1:{server.server_address[1]}"  # type: ignore[attr-defined]
    try:
        yield server
    finally:
        server.shutdown()
        server.server_close()


@pytest.fixture()
def tmp_db(tmp_path: Path):
    """Изолированная БД на время теста; в конце — уводим global db из tmp.

    Не восстанавливаем прежний путь: соседние тестовые файлы сами ставят
    временные БД, а возврат к repo history.db мог бы её создать/тронуть.
    """
    db_path = tmp_path / "engine-test.db"
    db.set_db_path(db_path)
    yield db_path
    db.set_db_path(tmp_path / "engine-test-closed.db")
    for suffix in ("", "-wal", "-shm"):
        try:
            (Path(str(db_path) + suffix)).unlink(missing_ok=True)
        except OSError:
            pass


# ══════════════════════════════════════════════════════════════════
#  helpers
# ══════════════════════════════════════════════════════════════════

def _insert_history(
    method: str,
    url: str,
    *,
    headers: dict | None = None,
    body: bytes | None = None,
    resp_status: int = 200,
    resp_headers: dict | None = None,
    resp_body_preview: bytes = b"",
) -> int:
    return db.insert_history(
        method,
        url,
        headers or {},
        body,
        resp_status,
        resp_headers or {},
        resp_body_preview,
    )


def _fake_load_payloads(mapping: dict[str, list[str]]):
    normalized = {str(k).lower(): list(v) for k, v in mapping.items()}

    def _load(check_type: str, safe_mode: bool = True):  # noqa: ARG001
        return list(normalized.get(str(check_type or "").lower(), []))

    return _load


def _run_runner(tasks, *, workers: int = 4, allowlist=None):
    runner = scanner_core.ScannerRunner(
        tasks,
        workers=workers,
        log_callback=lambda _m: None,
        scope_allowlist=allowlist if allowlist is not None else ["127.0.0.1"],
    )
    runner.start()
    runner.wait()
    return runner


def _rows() -> list[dict]:
    return db.fetch_scan_results(limit=1000)


@pytest.fixture()
def no_redirect_follow(stub_server):
    """Гарантирует, что фикстура сервера видна тесту через base_url."""
    return stub_server


# ══════════════════════════════════════════════════════════════════
#  1. Async Runner: все задачи записаны в БД, wait() завершается
# ══════════════════════════════════════════════════════════════════

def test_async_runner_persists_all_tasks(stub_server, tmp_db, monkeypatch):
    monkeypatch.setattr(
        scanner_core,
        "load_payloads",
        _fake_load_payloads({"cmdi": ["p1", "p2", "p3", "p4", "p5"]}),
    )
    hid = _insert_history(
        "GET", f"{stub_server.base_url}/ok?id=1", resp_status=200, resp_body_preview=b"ok"
    )
    tasks = scanner_core.build_scan_tasks([hid], ["cmdi"])
    assert len(tasks) == 5, f"ожидали 5 задач, получили {len(tasks)}"

    runner = _run_runner(tasks, workers=4)

    rows = _rows()
    assert len(rows) == len(tasks), "не все задачи сохранены в scan_results"
    assert runner.tasks_remaining == 0
    assert all(r["status_code"] == 200 for r in rows)
    assert stub_server.counts.get("/ok", 0) >= len(tasks)
    # wait() вызвал stop(), поток-раннер должен быть уже мёртв
    assert not runner._threads


def test_async_runner_stop_does_not_hang(stub_server, tmp_db, monkeypatch):
    monkeypatch.setattr(
        scanner_core,
        "load_payloads",
        _fake_load_payloads({"cmdi": [f"p{i}" for i in range(10)]}),
    )
    hid = _insert_history(
        "GET",
        f"{stub_server.base_url}/slow?ms=800&id=1",
        resp_status=200,
        resp_body_preview=b"slow",
    )
    tasks = scanner_core.build_scan_tasks([hid], ["cmdi"])
    # 2 query-параметра (ms, id) × 10 payload'ов
    assert len(tasks) == 20

    runner = scanner_core.ScannerRunner(
        tasks, workers=4, log_callback=lambda _m: None, scope_allowlist=["127.0.0.1"]
    )
    runner.start()
    # Дождаться, пока хотя бы один запрос реально уйдёт в сервер.
    deadline = time.time() + 5.0
    while stub_server.counts.get("/slow", 0) == 0 and time.time() < deadline:
        time.sleep(0.01)

    started = time.perf_counter()
    runner.stop()
    elapsed = time.perf_counter() - started
    assert elapsed < 4.0, f"stop() занял {elapsed:.2f}s — похоже на зависание"
    assert not runner._threads
    assert runner.tasks_remaining <= len(tasks)


def test_async_runner_scope_guard_skips_private(stub_server, tmp_db, monkeypatch):
    """Без allowlist приватный хост отсекается, но задача учитывается как done."""
    monkeypatch.setattr(
        scanner_core, "load_payloads", _fake_load_payloads({"cmdi": ["p1"]})
    )
    hid = _insert_history("GET", f"{stub_server.base_url}/ok?id=1")
    tasks = scanner_core.build_scan_tasks([hid], ["cmdi"])
    assert len(tasks) == 1

    runner = scanner_core.ScannerRunner(
        tasks, workers=2, log_callback=lambda _m: None, scope_block_private=True
    )
    runner.start()
    runner.wait()
    assert runner.tasks_remaining == 0
    assert stub_server.counts.get("/ok", 0) == 0
    assert _rows() == []


# ══════════════════════════════════════════════════════════════════
#  2. follow_redirects=False — 302 не сопровождается (scope-guard)
# ══════════════════════════════════════════════════════════════════

def test_redirects_are_not_followed(stub_server, tmp_db, monkeypatch):
    # check_type=cmdi НЕ входит в старый whitelist редиректов — проверяем
    # глобальное поведение клиента, а не частный случай open_redirect.
    monkeypatch.setattr(
        scanner_core, "load_payloads", _fake_load_payloads({"cmdi": ["x"]})
    )
    hid = _insert_history(
        "GET",
        f"{stub_server.base_url}/redirect?url=/followed-by-redirect",
        resp_status=302,
        resp_headers={"Location": "/followed-by-redirect"},
    )
    tasks = scanner_core.build_scan_tasks([hid], ["cmdi"])
    assert tasks, "нет задач на /redirect"

    _run_runner(tasks)

    rows = _rows()
    assert len(rows) == len(tasks)
    assert all(r["status_code"] == 302 for r in rows), "редирект должен вернуться как 302"
    assert stub_server.counts.get("/redirect", 0) >= 1
    assert stub_server.counts.get("/followed-by-redirect", 0) == 0, (
        "client сопровождал 302-редирект (follow_redirects должен быть False)"
    )


# ══════════════════════════════════════════════════════════════════
#  3. tamper_modes: дополнительные закодированные задачи
# ══════════════════════════════════════════════════════════════════

pytestmark_api = pytest.mark.skipif(
    not hasattr(templating, "encode_payload"),
    reason="templating.encode_payload ещё не реализован (параллельная задача)",
)


@pytestmark_api
def test_build_scan_tasks_tamper_modes(stub_server, tmp_db, monkeypatch):
    payload = "' OR 1=1--"
    monkeypatch.setattr(
        scanner_core, "load_payloads", _fake_load_payloads({"sqli": [payload]})
    )
    hid = _insert_history("GET", f"{stub_server.base_url}/ok?id=1")

    base_tasks = scanner_core.build_scan_tasks([hid], ["sqli"])
    tampered_tasks = scanner_core.build_scan_tasks([hid], ["sqli"], tamper_modes=["url"])

    assert len(base_tasks) == 1
    assert len(tampered_tasks) == 2, "ожидали base + один tamper-вариант"

    encoded = templating.encode_payload(payload, "url")
    by_payload = {t.payload: t for t in tampered_tasks}
    assert payload in by_payload, "base-задача с исходным payload потерялась"
    assert encoded in by_payload, f"нет tamper-задачи с payload {encoded!r}"
    assert "tamper-url" in by_payload[encoded].template_id
    # base-задача: payload в URL закодирован один раз (старое поведение apply_payload);
    # tamper-задача: закодирован twice (encode_payload + quote внутри apply_payload).
    assert urllib.parse.quote(payload, safe="") in by_payload[payload].url
    assert urllib.parse.quote(encoded, safe="") in by_payload[encoded].url
    assert payload not in by_payload[encoded].url


@pytestmark_api
def test_build_scan_tasks_tamper_not_applied_to_xss(stub_server, tmp_db, monkeypatch):
    payload = "<script>alert(1)</script>"
    monkeypatch.setattr(
        scanner_core, "load_payloads", _fake_load_payloads({"xss": [payload]})
    )
    hid = _insert_history("GET", f"{stub_server.base_url}/reflect?q=1")
    tasks = scanner_core.build_scan_tasks([hid], ["xss"], tamper_modes=["url"])
    assert len(tasks) == 1, "для XSS tamper применяться не должен"
    assert tasks[0].payload == payload


# ══════════════════════════════════════════════════════════════════
#  4. CSRF: один вызов провайдера на history record + подстановка токена
# ══════════════════════════════════════════════════════════════════

pytestmark_csrf = pytest.mark.skipif(
    not hasattr(templating, "patch_csrf_token"),
    reason="templating.patch_csrf_token ещё не реализован (параллельная задача)",
)


@pytestmark_csrf
def test_build_scan_tasks_csrf_provider(stub_server, tmp_db, monkeypatch):
    monkeypatch.setattr(
        scanner_core, "load_payloads", _fake_load_payloads({"sqli": ["'"]})
    )
    form_url = f"{stub_server.base_url}/form"
    hid1 = _insert_history(
        "POST",
        form_url,
        headers={"Content-Type": "application/x-www-form-urlencoded"},
        body=b"username=alice&csrf_token=EXPIRED123",
        resp_status=200,
    )
    hid2 = _insert_history(
        "POST",
        form_url,
        headers={"Content-Type": "application/x-www-form-urlencoded"},
        body=b"username=bob&csrf_token=EXPIRED123",
        resp_status=200,
    )
    calls: list[int] = []

    def _provider() -> str:
        calls.append(1)
        return "T0KEN"

    tasks = scanner_core.build_scan_tasks(
        [hid1, hid2], ["sqli"], csrf_token_provider=_provider
    )
    assert len(calls) == 2, "csrf_token_provider должен вызываться один раз на history record"
    assert tasks

    username_tasks = [t for t in tasks if t.original_param == "username"]
    assert username_tasks, "нет задач с мутацией username"
    for task in username_tasks:
        body = task.body.decode("utf-8")
        assert "T0KEN" in body, "свежий CSRF-токен не подставлен"
        assert "username='" in body, "payload инъекции не подставлен в username"
        # raw_http — мутация ДО подстановки payload: токен уже свежий,
        # PLACEHOLDER инъекции сохранён.
        assert "T0KEN" in task.raw_http
        assert templating.PLACEHOLDER in task.raw_http, "PLACEHOLDER инъекции затёрт токеном"

    # Мутации самого CSRF-поля не отправляются (иначе гарантированный 403).
    assert all(t.original_param != "csrf_token" for t in tasks)


@pytestmark_csrf
def test_build_scan_tasks_csrf_without_provider_keeps_expired_token(
    stub_server, tmp_db, monkeypatch
):
    monkeypatch.setattr(
        scanner_core, "load_payloads", _fake_load_payloads({"sqli": ["'"]})
    )
    hid = _insert_history(
        "POST",
        f"{stub_server.base_url}/form",
        headers={"Content-Type": "application/x-www-form-urlencoded"},
        body=b"username=alice&csrf_token=EXPIRED123",
    )
    tasks = scanner_core.build_scan_tasks([hid], ["sqli"])
    assert tasks
    assert any(t.original_param == "csrf_token" for t in tasks), (
        "без провайдера CSRF-поле остаётся обычной точкой мутации (старое поведение)"
    )
    assert all(b"T0KEN" not in t.body for t in tasks)


# ══════════════════════════════════════════════════════════════════
#  5. matcher-слой: XSS FP-фильтры, sqli_time → None
# ══════════════════════════════════════════════════════════════════

class TestMatchXss:
    def test_bare_html_tag_not_xss(self):
        # <body> уже есть в HTML-скелете — отражение не доказывает инъекцию
        assert scanner_core.match_xss(
            "<body>", "<html><body>hello</body></html>", 200,
            {"content-type": "text/html"},
        ) is None
        assert scanner_core.match_xss("<body>", "<html><body>hello</body></html>") is None

    def test_json_response_not_xss(self):
        payload = "<script>alert(1)</script>"
        body = json.dumps({"echo": payload})
        assert scanner_core.match_xss(
            payload, body, 200, {"content-type": "application/json"}
        ) is None
        assert scanner_core.match_xss(
            payload, body, 200, {"Content-Type": "text/plain; charset=utf-8"}
        ) is None

    def test_html_reflection_is_xss(self):
        payload = "<script>alert(1)</script>"
        body = f"<html><div>{payload}</div></html>"
        evidence = scanner_core.match_xss(
            payload, body, 200, {"content-type": "text/html"}
        )
        assert evidence is not None
        assert "XSS" in evidence

    def test_run_matcher_passes_headers_for_xss(self):
        # через run_matcher заголовки тоже должны учитываться
        assert scanner_core.run_matcher(
            "xss", "<body>", "<html><body></body></html>", 200,
            {"content-type": "text/html"},
        ) is None
        assert scanner_core.run_matcher(
            "xss", "<script>alert(1)</script>",
            '{"x":"<script>alert(1)</script>"}', 200,
            {"content-type": "application/json"},
        ) is None
        assert scanner_core.run_matcher(
            "xss", "<script>alert(1)</script>",
            "<html><script>alert(1)</script></html>", 200,
            {"content-type": "text/html"},
        ) is not None


def test_match_sqli_time_returns_none():
    # time-based детекция живёт в checks-слое по задержке; error-эвристика удалена
    assert scanner_core.match_sqli_time(
        "' AND SLEEP(5)--",
        "you have an error in your sql syntax; sqlstate 42000",
        500,
    ) is None
    assert scanner_core.run_matcher(
        "sqli_time", "'", "Warning: mysql_fetch_assoc() expects parameter", 200
    ) is None


# ══════════════════════════════════════════════════════════════════
#  6. host calibration: не обновляется для sqli_time
# ══════════════════════════════════════════════════════════════════

def test_host_calibration_skips_sqli_time(stub_server, tmp_db, monkeypatch):
    host = "127.0.0.1"
    url = f"{stub_server.base_url}/ok?id=1"
    hid = _insert_history("GET", url, resp_status=200, resp_body_preview=b"ok")

    monkeypatch.setattr(
        scanner_core, "load_payloads", _fake_load_payloads({"sqli_time": ["'"]})
    )
    time_tasks = scanner_core.build_scan_tasks([hid], ["sqli_time"])
    assert time_tasks
    _run_runner(time_tasks)
    assert db.fetch_host_calibration(host) is None, (
        "sqli_time не должен обновлять baseline хоста (иначе time-based детекция ломается)"
    )

    monkeypatch.setattr(
        scanner_core, "load_payloads", _fake_load_payloads({"cmdi": ["x"]})
    )
    normal_tasks = scanner_core.build_scan_tasks([hid], ["cmdi"])
    assert normal_tasks
    _run_runner(normal_tasks)
    calibration = db.fetch_host_calibration(host)
    assert calibration is not None, "обычные чеки обязаны обновлять host calibration"
    assert float(calibration.get("baseline_ms_p50") or 0.0) > 0.0


# ══════════════════════════════════════════════════════════════════
#  7. RateLimiter: async-вариант существует и не блокирует loop
# ══════════════════════════════════════════════════════════════════

def test_rate_limiter_async_contract():
    limiter = scanner_core.RateLimiter(0)  # = без лимита
    assert hasattr(limiter, "acquire_async")

    async def _acquire():
        await limiter.acquire_async()
        await limiter.acquire_async()

    import asyncio

    asyncio.run(_acquire())  # не должно падать/блокироваться


# ══════════════════════════════════════════════════════════════════
#  8. auto-relogin на 401/403 (логика перенесена из sync _worker)
# ══════════════════════════════════════════════════════════════════


class _FakeTokenStore:
    def __init__(self) -> None:
        self.access_token: str | None = None
        self.refresh_token: str | None = None
        self.cookies: dict = {}

    def is_valid(self) -> bool:
        return bool(self.access_token)


class _FakeSessionManager:
    """login() при старте падает, при relogin — успешен (как после протухания)."""

    def __init__(self) -> None:
        import types

        self.auth_enabled = True
        self._relogin_count = 0
        self.token_store = _FakeTokenStore()
        self.auth = types.SimpleNamespace(
            token_header_name="Authorization",
            token_prefix="Bearer ",
            max_relogin_attempts=3,
        )
        self.login_calls = 0

    def login(self) -> bool:
        self.login_calls += 1
        if self.login_calls == 1:  # login в start() — «сессия ещё не готова»
            return False
        self.token_store.access_token = "FRESH"
        return True


def test_async_runner_relogin_on_401(stub_server, tmp_db, monkeypatch):
    monkeypatch.setattr(
        scanner_core, "load_payloads", _fake_load_payloads({"cmdi": ["x"]})
    )
    hid = _insert_history(
        "GET",
        f"{stub_server.base_url}/auth?id=1",
        resp_status=401,
        resp_body_preview=b"unauthorized",
    )
    tasks = scanner_core.build_scan_tasks([hid], ["cmdi"])
    assert tasks

    session = _FakeSessionManager()
    runner = scanner_core.ScannerRunner(
        tasks,
        workers=2,
        log_callback=lambda _m: None,
        session_manager=session,
        scope_allowlist=["127.0.0.1"],
    )
    runner.start()
    runner.wait()

    assert session.login_calls >= 2, "auto-relogin не был выполнен"
    assert stub_server.counts.get("/auth-denied", 0) >= 1, "первый запрос должен дать 401"
    rows = _rows()
    assert len(rows) == len(tasks)
    assert all(r["status_code"] == 200 for r in rows), (
        "после успешного re-login запрос должен быть повторён с новым токеном"
    )


# ══════════════════════════════════════════════════════════════════
#  9. matcher FP-фиксы из аудита:
#     • path_traversal: эхо payload'а в теле 200 — не раскрытие файла;
#     • open_redirect: относительный Location / эхо payload — не redirect.
# ══════════════════════════════════════════════════════════════════


class TestMatchPathTraversalEcho:
    def test_echoed_payload_is_not_traversal(self):
        # lab /api/user отдаёт JSON-эхо payload'а → 78 FP до фикса
        assert scanner_core.match_path_traversal(
            "../../../../etc/passwd", '{"name": "../../../../etc/passwd"}', 200
        ) is None
        assert scanner_core.match_path_traversal(
            "../../../../etc/passwd",
            '{"name": "../../../../etc/passwd", "echo": true}',
            200,
        ) is None

    def test_real_file_disclosure_still_detected(self):
        assert scanner_core.match_path_traversal(
            "../../etc/passwd", "root:x:0:0:root:/root:/bin/bash", 200
        ) is not None

    def test_html_page_without_paths_not_detected(self):
        assert scanner_core.match_path_traversal(
            "../../etc/passwd", "<html><head><title>Home</title></head></html>", 200
        ) is None


class TestMatchOpenRedirectRelative:
    def test_relative_location_echo_not_redirect(self):
        assert scanner_core.match_open_redirect(
            "/redirect", "", 302, {"Location": "/redirect"}
        ) is None

    def test_relative_location_with_path_query_not_redirect(self):
        assert scanner_core.match_open_redirect(
            "example.com", "", 302, {"Location": "/path?x=1"}
        ) is None
        assert scanner_core.match_open_redirect(
            "/home", "", 302, {"Location": "/home"}
        ) is None

    def test_absolute_external_location_with_payload_is_redirect(self):
        assert scanner_core.match_open_redirect(
            "http://evil.com", "", 302, {"Location": "http://evil.com/phish"}
        ) is not None

    def test_unrelated_external_location_not_redirect(self):
        assert scanner_core.match_open_redirect(
            "http://evil.com", "", 302, {"Location": "https://legit.com/r"}
        ) is None

    def test_bare_domain_payload_in_absolute_location(self):
        assert scanner_core.match_open_redirect(
            "evil.com", "", 302, {"Location": "http://evil.com/x"}
        ) is not None
        # bare-domain payload эхом в ОТНОСИТЕЛЬНОМ Location — не redirect
        assert scanner_core.match_open_redirect(
            "evil.com", "", 302, {"Location": "/evil.com"}
        ) is None

    def test_protocol_relative_location(self):
        assert scanner_core.match_open_redirect(
            "//evil.com/", "", 302, {"Location": "//evil.com/p"}
        ) is not None
        assert scanner_core.match_open_redirect(
            "//evil.com/", "", 302, {"Location": "/login"}
        ) is None


# ══════════════════════════════════════════════════════════════════
#  10. ScanTask: обратная совместимость после добавления pair_* полей
# ══════════════════════════════════════════════════════════════════

def test_scan_task_pair_fields_have_defaults():
    """sqli_blind добавил pair_payload/pair_url/pair_headers/pair_body — с дефолтами."""
    task = scanner_core.ScanTask(
        template_id="hist-1-sqli-query-id",
        check_type="sqli",
        payload="'",
        method="GET",
        url="http://example.test/item?id=%27",
        headers={"Host": "example.test"},
        body=b"",
        raw_http="",
        mutation_point="query",
        original_param="id",
        history_id=1,
    )
    assert task.pair_payload == ""
    assert task.pair_url == ""
    assert task.pair_headers == {}
    assert task.pair_body == b""
    assert task.is_pair is False
