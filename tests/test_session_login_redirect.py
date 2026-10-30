"""SessionManager: login-эндпоинт отвечает 302 + Set-Cookie (bWAPP-кейс).

До фикса httpx следовал редиректу, и Cookies из промежуточного 302 терялись:
сессия оставалась пустой → каждый запрос скана считался неавторизованным и
запускал лавину relogin (скан «висел» после нескольких запросов).
"""

import http.server
import threading

import pytest

from session_manager import AuthConfig, SessionManager


class _Login302Handler(http.server.BaseHTTPRequestHandler):
    def do_POST(self):  # noqa: N802
        length = int(self.headers.get("Content-Length") or 0)
        body = self.rfile.read(length).decode("utf-8", errors="replace")
        if self.path.startswith("/login") and "user=bee" in body and "pass=bug" in body:
            self.send_response(302)
            self.send_header("Set-Cookie", "session=ok; Path=/; HttpOnly")
            self.send_header("Location", "/portal")
            self.end_headers()
            return
        self.send_response(401)
        self.end_headers()

    def do_GET(self):  # noqa: N802
        cookie = self.headers.get("Cookie") or ""
        if "session=ok" in cookie:
            self.send_response(200)
            self.send_header("Content-Type", "text/plain")
            self.end_headers()
            self.wfile.write(b"authorized")
        else:
            self.send_response(302)
            self.send_header("Location", "/login")
            self.end_headers()

    def log_message(self, *_a):  # silence
        pass


@pytest.fixture()
def login_lab():
    srv = http.server.ThreadingHTTPServer(("127.0.0.1", 0), _Login302Handler)
    t = threading.Thread(target=srv.serve_forever, daemon=True)
    t.start()
    try:
        yield f"http://127.0.0.1:{srv.server_address[1]}"
    finally:
        srv.shutdown()
        srv.server_close()


def test_login_captures_cookie_from_302(login_lab):
    logs = []
    mgr = SessionManager(
        auth_config=AuthConfig(
            enabled=True,
            login_url=f"{login_lab}/login",
            method="POST",
            body={"user": "bee", "pass": "bug"},
            content_type="form",
            success_codes={200, 302, 303},
        ),
        log_callback=logs.append,
    )
    assert mgr.login() is True
    assert mgr.token_store.cookies.get("session") == "ok"
    r = mgr.request("GET", f"{login_lab}/private")
    assert r.status_code == 200
    assert r.text == "authorized"
