"""Скан-запросы должны реально использовать Cookie/Authorization авто-логина.

Регресс: HTTP-запрос уходил с сессией, но scan_requests.raw_request строился из
исходных task.headers без Cookie → в Request detail выглядело, будто авторизация
из авто-логина не применяется.
"""

from __future__ import annotations

import http.server
import threading
import types

import pytest

import db
import scanner_core


class _AuthManager:
    """Минимальный SessionManager-совместимый объект для engine."""

    def __init__(self):
        self.auth_enabled = True
        self.auth = types.SimpleNamespace(
            token_header_name="Authorization", token_prefix="Bearer "
        )
        self.token_store = types.SimpleNamespace(
            cookies={"PHPSESSID": "session-cookie-123"},
            access_token=None,
        )

    def login(self) -> bool:
        return True


@pytest.fixture()
def tmp_db(tmp_path, monkeypatch):
    db.set_db_path(tmp_path / "history.db")
    db.init_db()
    yield db
    db.close_all_connections()


@pytest.fixture()
def cookie_server():
    seen: list[str] = []

    class Handler(http.server.BaseHTTPRequestHandler):
        def do_GET(self):
            cookie = self.headers.get("Cookie", "")
            seen.append(cookie)
            if self.path.startswith("/protected") and "PHPSESSID=session-cookie-123" not in cookie:
                self.send_response(302)
                self.send_header("Location", "/login.php")
                self.end_headers()
                return
            self.send_response(200)
            self.send_header("Content-Type", "text/plain")
            self.end_headers()
            self.wfile.write(b"ok")

        def log_message(self, *args):
            pass

    srv = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=srv.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{srv.server_address[1]}", seen
    finally:
        srv.shutdown()
        srv.server_close()


def _task(url: str) -> scanner_core.ScanTask:
    return scanner_core.ScanTask(
        template_id="t-auth-cookie",
        check_type="cmdi",
        payload="x",
        method="GET",
        url=url,
        headers={},
        body=b"",
        raw_http="",
        mutation_point="query",
        original_param="a",
        history_id=None,
    )


def test_scan_request_uses_session_cookie_and_stores_it(cookie_server, tmp_db):
    base_url, seen = cookie_server
    mgr = _AuthManager()
    runner = scanner_core.ScannerRunner(
        [_task(f"{base_url}/ok?a=1")],
        workers=1,
        log_callback=lambda _m: None,
        session_manager=mgr,
        scope_allowlist=["127.0.0.1"],
        scope_block_private=True,
    )
    runner.start()
    runner.wait()

    assert seen and "PHPSESSID=session-cookie-123" in seen[0], seen

    rows = db.fetch_scan_results(limit=10)
    assert rows
    stored_any = False
    for row in rows:
        stored = db.fetch_scan_request_by_result(row["id"])
        if not stored:
            continue
        stored_any = True
        raw = stored.get("raw_request") or ""
        # Cookie реально применён и попал в сохранённый запрос (значение redacted).
        assert "Cookie:" in raw, raw
        assert "***REDACTED***" in raw, raw
        assert "session-cookie-123" not in raw, raw
    assert stored_any, "ни один scan_request не сохранён"


def test_current_auth_headers_from_session_manager():
    import notscan

    app = notscan.App.__new__(notscan.App)
    app._session_manager = _AuthManager()
    assert notscan.App._current_auth_headers(app) == {
        "Cookie": "PHPSESSID=session-cookie-123"
    }


def test_merge_auth_headers_does_not_duplicate_session_cookie():
    import notscan

    merged = notscan.App._merge_auth_headers_for_request(
        {"Cookie": "security_level=0; PHPSESSID=OLD", "X-Test": "1"},
        {"Cookie": "PHPSESSID=NEW"},
    )
    assert merged["Cookie"] == "security_level=0; PHPSESSID=NEW"
    assert merged["X-Test"] == "1"


def test_preflight_uses_session_auth_headers(cookie_server, tmp_db):
    """Preflight не должен считать защищённую цель неавторизованной, если
    авто-логин уже дал Cookie (иначе ложный диалог «Continue anyway?»)."""
    import notscan

    base_url, seen = cookie_server
    hid = db.insert_history(
        method="GET", url=f"{base_url}/protected?x=1", req_headers={},
        req_body=None, resp_status=200, resp_headers={}, resp_body_preview=b"ok",
    )
    app = notscan.App.__new__(notscan.App)
    app._scan_list = {hid: db.fetch_history_by_id(hid)}
    app._session_manager = _AuthManager()
    app.log = lambda _m: None
    asked: list = []
    app._ask_yesno_threadsafe = lambda *a, **k: (asked.append(a), True)[1]

    assert notscan.App._preflight_auth(app, [hid]) is True
    assert seen and "PHPSESSID=session-cookie-123" in seen[-1], seen
    assert asked == [], "preflight не должен спрашивать при валидной сессии"
