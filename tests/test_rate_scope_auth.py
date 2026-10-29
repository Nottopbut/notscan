"""
tests/test_rate_scope_auth.py — rate limiting, scope-guard и auth (OTP/relogin).

A) RateLimiter (task-25):
   • min/max RPS → интервал uniform(1/max, 1/min), фактический RPS в диапазоне;
   • только max → ровно 1/max; только min → ровно 1/min;
   • delay_ms → нижняя граница интервала;
   • acquire_async не блокирует loop; ScannerRunner прокидывает min/max/delay;
   • sqli_blind-пара: ОБА запроса проходят через limiter.
B) Scope guard:
   • allowlist = явная авторизация (private/local разрешены);
   • private вне allowlist блокируется;
   • вместо per-request спама — первые 5 подробно + агрегированный summary;
   • scope_stats() наружу.
B2) Auth-counters: 401/403/login-redirect → auth_failure_count/last_auth_status.
C) SessionManager OTP/2FA + auto-relogin (локальный ThreadingHTTPServer):
   • env NOTSCAN_OTP_STUB / AuthConfig.otp_test_stub / set_otp_provider;
   • неверный OTP → False без исключений; otp_attempts;
   • 401 → auto-relogin (с OTP) → повтор запроса с новым Cookie;
   • max_relogin_attempts → без бесконечного цикла.
"""

from __future__ import annotations

import http.server
import socketserver
import tempfile
import threading
import time
import urllib.parse
import uuid

import pytest

import db
import scanner_core
import session_manager


# ══════════════════════════════════════════════════════════════════
#  Общие хелперы
# ══════════════════════════════════════════════════════════════════


class FakeClock:
    """Управляемые часы + sleep для детерминированных тестов пейсинга."""

    def __init__(self, now: float = 1000.0):
        self.now = now

    def __call__(self) -> float:
        return self.now

    def sleep(self, seconds: float) -> None:
        self.now += max(0.0, float(seconds))


def _task(url: str, *, pair_url: str = "", check_type: str = "cmdi"):
    return scanner_core.ScanTask(
        template_id=f"t-{abs(hash(url))}-{time.time_ns()}",
        check_type=check_type,
        payload="x",
        method="GET",
        url=url,
        headers={},
        body=b"",
        raw_http="",
        mutation_point="query",
        original_param="x",
        history_id=None,
        pair_payload="y" if pair_url else "",
        pair_url=pair_url,
        pair_headers={},
        pair_body=b"",
    )


def _run(runner: scanner_core.ScannerRunner) -> None:
    runner.start()
    runner.wait()


class _StatusHandler(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def _record(self) -> None:
        with self.server.lock:  # type: ignore[attr-defined]
            self.server.paths.append(self.path)  # type: ignore[attr-defined]

    def _send(self, status: int, body: str = "", headers: dict | None = None) -> None:
        data = body.encode()
        self.send_response(status)
        for key, value in (headers or {}).items():
            self.send_header(key, value)
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def do_GET(self) -> None:  # noqa: N802
        self._record()
        parsed = urllib.parse.urlsplit(self.path)
        if parsed.path == "/unauth":
            self._send(401, "unauthorized")
        elif parsed.path == "/forbid":
            self._send(403, "forbidden")
        elif parsed.path == "/login-redirect":
            self._send(302, "", {"Location": "/login?next=/"})
        else:
            self._send(200, "ok")

    def log_message(self, *args) -> None:  # noqa: D401 - тишина
        pass


class _StatusServer(socketserver.ThreadingTCPServer):
    daemon_threads = True
    allow_reuse_address = True


@pytest.fixture()
def status_server():
    server = _StatusServer(("127.0.0.1", 0), _StatusHandler)
    server.paths = []  # type: ignore[attr-defined]
    server.lock = threading.Lock()  # type: ignore[attr-defined]
    threading.Thread(target=server.serve_forever, daemon=True).start()
    server.base_url = f"http://127.0.0.1:{server.server_address[1]}"  # type: ignore[attr-defined]
    try:
        yield server
    finally:
        server.shutdown()
        server.server_close()


@pytest.fixture()
def tmp_db(tmp_path):
    db_path = tmp_path / "rate-scope-auth.db"
    db.set_db_path(db_path)
    yield db_path
    db.set_db_path(tmp_path / "rate-scope-auth-closed.db")
    for suffix in ("", "-wal", "-shm"):
        try:
            type(db_path)(str(db_path) + suffix).unlink(missing_ok=True)
        except OSError:
            pass


# ══════════════════════════════════════════════════════════════════
#  A) RateLimiter: min/max/delay
# ══════════════════════════════════════════════════════════════════


class TestRateLimiterIntervals:
    def _measure_sync(self, limiter, clock, monkeypatch, n: int):
        monkeypatch.setattr(scanner_core.time, "sleep", clock.sleep)
        marks = []
        for _ in range(n):
            limiter.acquire()
            marks.append(clock.now)
        return [round(marks[i + 1] - marks[i], 6) for i in range(len(marks) - 1)]

    def test_disabled_limiter_is_noop(self, monkeypatch):
        clock = FakeClock()
        limiter = scanner_core.RateLimiter(0, clock=clock)
        monkeypatch.setattr(
            scanner_core.time, "sleep",
            lambda s: (_ for _ in ()).throw(AssertionError("sleep called")),
        )
        limiter.acquire()
        limiter.acquire()
        assert limiter.enabled is False
        assert limiter.total_acquires == 0  # выключенный limiter даже не резервирует слот

    def test_max_rps_only_interval(self, monkeypatch):
        clock = FakeClock()
        limiter = scanner_core.RateLimiter(max_rps=4, clock=clock)
        deltas = self._measure_sync(limiter, clock, monkeypatch, 5)
        assert all(abs(d - 0.25) < 1e-6 for d in deltas), deltas

    def test_min_rps_only_interval(self, monkeypatch):
        clock = FakeClock()
        limiter = scanner_core.RateLimiter(min_rps=2, clock=clock)
        deltas = self._measure_sync(limiter, clock, monkeypatch, 4)
        assert all(abs(d - 0.5) < 1e-6 for d in deltas), deltas

    def test_min_max_range(self, monkeypatch):
        clock = FakeClock()
        limiter = scanner_core.RateLimiter(max_rps=10, min_rps=5, clock=clock)
        deltas = self._measure_sync(limiter, clock, monkeypatch, 101)
        assert all(0.1 - 1e-9 <= d <= 0.2 + 1e-9 for d in deltas), deltas[:5]
        avg = sum(deltas) / len(deltas)
        assert 0.1 <= avg <= 0.2, avg
        # фактический RPS в [min, max] (плюс-минус погрешность выборки)
        rate = 1.0 / avg
        assert 4.9 <= rate <= 10.1, rate
        # интервалы действительно варьируются (uniform), а не константа
        assert len(set(deltas)) > 1

    def test_delay_ms_is_lower_bound(self, monkeypatch):
        clock = FakeClock()
        limiter = scanner_core.RateLimiter(max_rps=100, delay_ms=500, clock=clock)
        deltas = self._measure_sync(limiter, clock, monkeypatch, 3)
        assert all(abs(d - 0.5) < 1e-6 for d in deltas), deltas
        # delay больше выбранного по max интервала
        clock2 = FakeClock()
        limiter2 = scanner_core.RateLimiter(max_rps=2, delay_ms=100, clock=clock2)
        deltas2 = self._measure_sync(limiter2, clock2, monkeypatch, 3)
        assert all(abs(d - 0.5) < 1e-6 for d in deltas2), deltas2

    def test_async_acquire_uses_async_sleep(self, monkeypatch):
        import asyncio

        clock = FakeClock()
        limiter = scanner_core.RateLimiter(max_rps=4, clock=clock)

        async def fake_sleep(seconds):
            clock.sleep(seconds)

        monkeypatch.setattr(scanner_core.asyncio, "sleep", fake_sleep)

        async def run():
            marks = []
            for _ in range(4):
                await limiter.acquire_async()
                marks.append(clock.now)
            return [round(marks[i + 1] - marks[i], 6) for i in range(len(marks) - 1)]

        deltas = asyncio.run(run())
        assert all(abs(d - 0.25) < 1e-6 for d in deltas), deltas

    def test_scanner_runner_rate_kwargs(self):
        runner = scanner_core.ScannerRunner(
            [], workers=1,
            min_rps=5.0, max_rps=10.0, delay_ms=250.0,
        )
        assert runner.min_rps == 5.0
        assert runner.max_rps == 10.0
        assert runner.delay_ms == 250.0
        limiter = runner._rate_limiter
        assert limiter.enabled is True
        assert limiter.min_rps == 5.0 and limiter.max_rps == 10.0
        # delay_ms (250) доминирует над uniform(0.1..0.2)
        for _ in range(10):
            assert abs(limiter._pick_interval() - 0.25) < 1e-9


class _RecordingLimiter:
    def __init__(self):
        self.acquires = 0

    async def acquire_async(self):
        self.acquires += 1

    def acquire(self):
        self.acquires += 1


def test_blind_pair_both_requests_use_limiter(status_server, tmp_db):
    fake = _RecordingLimiter()
    pair = _task(
        f"{status_server.base_url}/ok?a=1",
        pair_url=f"{status_server.base_url}/ok?a=2",
        check_type="sqli_blind",
    )
    normal = _task(f"{status_server.base_url}/ok?b=1")
    runner = scanner_core.ScannerRunner(
        [pair, normal], workers=1, log_callback=lambda _m: None,
        scope_allowlist=["127.0.0.1"], scope_block_private=True,
    )
    runner._rate_limiter = fake
    _run(runner)
    # pair: true + false = 2 acquire; normal = 1 acquire
    assert fake.acquires == 3, fake.acquires
    assert len(status_server.paths) >= 3


# ══════════════════════════════════════════════════════════════════
#  B) Scope guard: allowlist + агрегированный лог
# ══════════════════════════════════════════════════════════════════


class TestScopeGuard:
    def test_classify_allowlist_overrides_private(self):
        assert scanner_core.classify_url_scope(
            "http://127.0.0.1:8080/x", ["127.0.0.1"], True
        ) == (True, scanner_core.SCOPE_REASON_ALLOWED)
        # allowlist c host:port
        assert scanner_core.is_url_in_scope(
            "http://127.0.0.1:8080/x", ["127.0.0.1:8080"], True
        ) is True
        assert scanner_core.is_url_in_scope(
            "http://10.10.10.5/login", ["10.10.10.5"], True
        ) is True

    def test_private_blocked_without_allowlist(self):
        assert scanner_core.classify_url_scope(
            "http://10.10.10.5/", None, True
        ) == (False, scanner_core.SCOPE_REASON_PRIVATE)
        assert scanner_core.classify_url_scope(
            "http://192.168.1.5/", [], True
        ) == (False, scanner_core.SCOPE_REASON_PRIVATE)
        assert scanner_core.classify_url_scope(
            "http://169.254.169.254/latest/meta-data", None, True
        ) == (False, scanner_core.SCOPE_REASON_PRIVATE)
        # блокировка выключена → private разрешён
        assert scanner_core.is_url_in_scope("http://10.0.0.1/", None, False) is True

    def test_allowlist_miss_reason(self):
        assert scanner_core.classify_url_scope(
            "http://evil.test/x", ["good.test"], True
        ) == (False, scanner_core.SCOPE_REASON_ALLOWLIST)

    def test_aggregated_scope_stats_and_capped_logs(self, status_server, tmp_db):
        logs: list[str] = []
        allowed = [
            _task(f"{status_server.base_url}/ok?a=1"),
            _task(f"{status_server.base_url}/ok?a=2"),
        ]
        blocked = [
            _task("http://10.0.0.1/x"),
            _task("http://10.0.0.2/x"),
            _task("http://192.168.1.5/x"),
            _task("http://169.254.169.254/latest/meta-data"),
            _task("http://evil-one.test/x"),
            _task("http://evil-two.test/x"),
            _task("http://evil-three.test/x"),
        ]
        runner = scanner_core.ScannerRunner(
            allowed + blocked, workers=3, log_callback=logs.append,
            scope_allowlist=["127.0.0.1"], scope_block_private=True,
        )
        _run(runner)

        stats = runner.scope_stats()
        assert stats["skipped"] == 7, stats
        assert stats["private"] == 4, stats
        assert stats["allowlist"] == 3, stats
        assert stats["details_logged"] == scanner_core.SCOPE_LOG_DETAIL_LIMIT
        # подробных логов ровно limit, без спама на каждую задачу
        detail_logs = [m for m in logs if "Skipping out-of-scope URL" in m]
        assert len(detail_logs) == scanner_core.SCOPE_LOG_DETAIL_LIMIT, detail_logs
        summary = [m for m in logs if "Skipped 7 requests outside scope" in m]
        assert len(summary) == 1, logs
        assert "private=4" in summary[0] and "allowlist=3" in summary[0]
        assert "examples:" in summary[0]

        rows = db.fetch_scan_results(limit=100)
        assert len(rows) == 2, "разрешённые (localhost+allowlist) задачи должны выполниться"

    def test_allowlist_localhost_targets_run_without_skip(self, status_server, tmp_db):
        logs: list[str] = []
        tasks = [_task(f"{status_server.base_url}/ok?a={i}") for i in range(2)]
        runner = scanner_core.ScannerRunner(
            tasks, workers=2, log_callback=logs.append,
            scope_allowlist=["127.0.0.1"], scope_block_private=True,
        )
        _run(runner)
        assert runner.scope_stats()["skipped"] == 0
        assert len(db.fetch_scan_results(limit=10)) == 2
        assert not any("Skipping out-of-scope" in m for m in logs)


# ══════════════════════════════════════════════════════════════════
#  B2) Auth-counters: 401/403/login-redirect
# ══════════════════════════════════════════════════════════════════


def test_auth_failure_counters(status_server, tmp_db):
    logs: list[str] = []
    tasks = [
        _task(f"{status_server.base_url}/ok"),
        _task(f"{status_server.base_url}/unauth"),
        _task(f"{status_server.base_url}/forbid"),
        _task(f"{status_server.base_url}/login-redirect"),
    ]
    runner = scanner_core.ScannerRunner(
        tasks, workers=1, log_callback=logs.append,
        scope_allowlist=["127.0.0.1"], scope_block_private=True,
    )
    _run(runner)
    stats = runner.auth_stats()
    assert runner.auth_failure_count == 3, stats
    assert runner.last_auth_status == 302, stats
    assert any("[AUTH] 3 responses" in m for m in logs), logs


# ══════════════════════════════════════════════════════════════════
#  C) SessionManager: OTP/2FA + auto-relogin
# ══════════════════════════════════════════════════════════════════


class _AuthHandler(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def _send(self, status: int, body: str = "", headers: dict | None = None) -> None:
        data = body.encode()
        self.send_response(status)
        for key, value in (headers or {}).items():
            self.send_header(key, value)
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def do_POST(self) -> None:  # noqa: N802
        server = self.server
        length = int(self.headers.get("Content-Length") or 0)
        raw = self.rfile.read(length).decode("utf-8", errors="replace")
        content_type = (self.headers.get("Content-Type") or "").lower()
        if "json" in content_type:
            import json

            try:
                body = json.loads(raw or "{}")
            except Exception:
                body = {}
        else:
            body = {
                k: v[0]
                for k, v in urllib.parse.parse_qs(raw, keep_blank_values=True).items()
            }
        with server.lock:  # type: ignore[attr-defined]
            server.login_requests.append(body)  # type: ignore[attr-defined]
        if self.path != "/login":
            self._send(404, "not found")
            return
        if body.get("username") != "admin" or body.get("password") != "secret":
            self._send(401, "bad credentials")
            return
        if "otp" not in body:
            self._send(401, "OTP required: enter 2FA verification code")
            return
        if str(body.get("otp")) != "000000":
            self._send(401, "Invalid one-time code")
            return
        token = uuid.uuid4().hex
        with server.lock:  # type: ignore[attr-defined]
            server.token = token  # type: ignore[attr-defined]
        self._send(
            200,
            '{"access_token": "%s"}' % token,
            {
                "Set-Cookie": f"session={token}; Path=/; HttpOnly",
                "Content-Type": "application/json",
            },
        )

    def do_GET(self) -> None:  # noqa: N802
        server = self.server
        if self.path.startswith("/protected"):
            token = getattr(server, "token", None)
            cookie = self.headers.get("Cookie") or ""
            if getattr(server, "always_unauth", False):
                self._send(401, "unauthorized")
                return
            if token and f"session={token}" in cookie:
                self._send(200, "secret data")
                if getattr(server, "rotate_after_get", False):
                    with server.lock:  # type: ignore[attr-defined]
                        server.token = uuid.uuid4().hex  # type: ignore[attr-defined]
                return
            self._send(401, "unauthorized")
            return
        self._send(200, "ok")

    def log_message(self, *args) -> None:  # noqa: D401 - тишина
        pass


class _AuthServer(socketserver.ThreadingTCPServer):
    daemon_threads = True
    allow_reuse_address = True


@pytest.fixture()
def auth_server():
    server = _AuthServer(("127.0.0.1", 0), _AuthHandler)
    server.lock = threading.Lock()  # type: ignore[attr-defined]
    server.login_requests = []  # type: ignore[attr-defined]
    server.token = None  # type: ignore[attr-defined]
    server.rotate_after_get = False  # type: ignore[attr-defined]
    server.always_unauth = False  # type: ignore[attr-defined]
    threading.Thread(target=server.serve_forever, daemon=True).start()
    server.base_url = f"http://127.0.0.1:{server.server_address[1]}"  # type: ignore[attr-defined]
    try:
        yield server
    finally:
        server.shutdown()
        server.server_close()


def _auth_config(base_url: str, **overrides) -> session_manager.AuthConfig:
    kwargs = dict(
        enabled=True,
        login_url=f"{base_url}/login",
        method="POST",
        body={"username": "admin", "password": "secret"},
        content_type="form",
        success_codes={200},
        token_json_path="access_token",
        max_relogin_attempts=2,
    )
    kwargs.update(overrides)
    return session_manager.AuthConfig(**kwargs)


@pytest.fixture()
def no_otp_env(monkeypatch):
    monkeypatch.delenv("NOTSCAN_OTP_STUB", raising=False)
    yield monkeypatch


class TestOtpLogin:
    def test_env_stub_login_success(self, auth_server, no_otp_env):
        no_otp_env.setenv("NOTSCAN_OTP_STUB", "000000")
        logs: list[str] = []
        manager = session_manager.SessionManager(
            _auth_config(auth_server.base_url), log_callback=logs.append
        )
        try:
            assert manager.login() is True
            assert manager.cookies.get("session")
            assert manager.access_token
            assert any("OTP" in m and "submitting code" in m for m in logs), logs
            assert any("OTP accepted" in m for m in logs)
            # 1-й login без OTP + 1 повтор с кодом
            assert len(auth_server.login_requests) == 2
        finally:
            manager.close()

    def test_provider_login_success(self, auth_server, no_otp_env):
        calls: list[int] = []
        manager = session_manager.SessionManager(
            _auth_config(auth_server.base_url), log_callback=lambda _m: None
        )
        manager.set_otp_provider(lambda: calls.append(1) or "000000")
        try:
            assert manager.login() is True
            assert calls, "OTP provider не был вызван"
            assert manager.cookies.get("session")
        finally:
            manager.close()

    def test_config_stub_login_success(self, auth_server, no_otp_env):
        manager = session_manager.SessionManager(
            _auth_config(auth_server.base_url, otp_test_stub="000000"),
            log_callback=lambda _m: None,
        )
        try:
            assert manager.login() is True
        finally:
            manager.close()

    def test_missing_provider_fails_without_exception(self, auth_server, no_otp_env):
        logs: list[str] = []
        manager = session_manager.SessionManager(
            _auth_config(auth_server.base_url), log_callback=logs.append
        )
        try:
            assert manager.login() is False
            assert any("[WARN]" in m and "OTP" in m for m in logs), logs
            # без провайдера OTP-запрос не отправлялся
            assert len(auth_server.login_requests) == 1
        finally:
            manager.close()

    def test_wrong_stub_fails_gracefully(self, auth_server, no_otp_env):
        no_otp_env.setenv("NOTSCAN_OTP_STUB", "111111")
        logs: list[str] = []
        manager = session_manager.SessionManager(
            _auth_config(auth_server.base_url), log_callback=logs.append
        )
        try:
            assert manager.login() is False
            assert manager.cookies.get("session") is None
            assert any(("rejected" in m) or ("OTP login failed" in m) for m in logs), logs
        finally:
            manager.close()

    def test_otp_attempts_with_provider_sequence(self, auth_server, no_otp_env):
        codes = iter(["111111", "000000"])
        manager = session_manager.SessionManager(
            _auth_config(auth_server.base_url, otp_attempts=2),
            log_callback=lambda _m: None,
        )
        manager.set_otp_provider(lambda: next(codes, None))
        try:
            assert manager.login() is True
            # initial login + 2 OTP-попытки
            assert len(auth_server.login_requests) == 3
        finally:
            manager.close()


class TestAutoRelogin:
    def test_request_auto_relogin_refreshes_cookie(self, auth_server, no_otp_env):
        no_otp_env.setenv("NOTSCAN_OTP_STUB", "000000")
        manager = session_manager.SessionManager(
            _auth_config(auth_server.base_url), log_callback=lambda _m: None
        )
        try:
            assert manager.login() is True
            first_cookie = manager.cookies.get("session")
            # Сервер «протухает» сессию: следующий запрос → 401.
            with auth_server.lock:  # type: ignore[attr-defined]
                auth_server.token = uuid.uuid4().hex  # type: ignore[attr-defined]
            resp = manager.request("GET", f"{auth_server.base_url}/protected")
            assert resp.status_code == 200, resp.text
            assert manager.cookies.get("session") != first_cookie
            # initial login + relogin
            assert len(auth_server.login_requests) >= 3
        finally:
            manager.close()

    def test_scanner_relogin_refreshes_session(self, auth_server, no_otp_env):
        no_otp_env.setenv("NOTSCAN_OTP_STUB", "000000")
        logs: list[str] = []
        manager = session_manager.SessionManager(
            _auth_config(auth_server.base_url), log_callback=logs.append
        )
        auth_server.rotate_after_get = True
        tasks = [
            _task(f"{auth_server.base_url}/protected?i={i}") for i in range(2)
        ]
        try:
            runner = scanner_core.ScannerRunner(
                tasks, workers=1, log_callback=logs.append,
                session_manager=manager, scope_allowlist=["127.0.0.1"],
                max_rps=100,
            )
            _run(runner)
            rows = db.fetch_scan_results(limit=100)
            assert len(rows) == 2
            assert all(r["status_code"] == 200 for r in rows), [
                (r["status_code"], r["error"]) for r in rows
            ]
            assert any("[SESSION] Retry after re-login: 200" in m for m in logs), logs
            stats = runner.auth_stats()
            assert stats["auth_failure_count"] >= 1, stats
        finally:
            manager.close()

    def test_max_relogin_attempts_no_infinite_loop(self, auth_server, no_otp_env):
        """Login перестал работать → релогin не крутится бесконечно (max attempts)."""
        no_otp_env.setenv("NOTSCAN_OTP_STUB", "000000")
        manager = session_manager.SessionManager(
            _auth_config(auth_server.base_url, max_relogin_attempts=1),
            log_callback=lambda _m: None,
        )
        auth_server.always_unauth = True   # любой запрос → 401 даже с валидной сессией
        tasks = [
            _task(f"{auth_server.base_url}/protected?i={i}") for i in range(3)
        ]
        runner = scanner_core.ScannerRunner(
            tasks, workers=1, log_callback=lambda _m: None,
            session_manager=manager, scope_allowlist=["127.0.0.1"],
            max_rps=100, stop_on_session_drift=False,
        )
        try:
            started = time.perf_counter()
            runner.start()          # initial login (успешен)
            # После старта ломаем пароль: последующие relogin будут неуспешны.
            manager.auth.body["password"] = "wrong-password"
            runner.wait()
            elapsed = time.perf_counter() - started
            assert elapsed < 15.0, f"скан завис: {elapsed:.1f}s"
            # initial login (2 запроса: без OTP + с OTP) + РОВНО 1 неуспешный relogin
            assert len(auth_server.login_requests) == 3, auth_server.login_requests
            assert runner.auth_failure_count >= 3
        finally:
            manager.close()
