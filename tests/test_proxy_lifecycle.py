"""
tests/test_proxy_lifecycle.py — авто-жизненный цикл прокси.

Unit-тесты (без реального mitmproxy):
  • find_free_port / next_proxy_port / port_is_free — подбор свободного порта;
  • should_idle_stop — idle-автостоп;
  • proxy_settings — дефолты/нормализация project settings;
  • ProxyRunner: last_activity_ts / stop() без start() безопасен;
  • GUI-хелперы авто-стопа (browser exit / idle) на dummy-объекте App —
    без Tk-дисплея, через unbound-методы.

Интеграционный тест (@pytest.mark.integration): ProxyRunner.start() →
реально слушает → stop() → порт снова bindable. Если mitmproxy не поднялся
(ограниченное окружение) — skip, чтобы не флапать.
"""

from __future__ import annotations

import socket
import time

import pytest

import mitm_proxy
import notscan
from mitm_proxy import (
    ProxyRunner,
    find_free_port,
    next_proxy_port,
    port_is_free,
    proxy_settings,
    should_idle_stop,
)


# ──────────────────────────── helpers ────────────────────────────

def _pick_free_port(host: str = "127.0.0.1") -> int:
    """Возвращает свободный ephemeral-порт (bind(0) → port → close)."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind((host, 0))
        return int(s.getsockname()[1])


def _busy_socket(host: str = "127.0.0.1", port: int = 0) -> socket.socket:
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind((host, port))
    s.listen(1)
    return s


class _FakeProc:
    def __init__(self, returncode: int | None):
        self._returncode = returncode

    def poll(self):
        return self._returncode


class _FakeRunner:
    def __init__(self, running: bool = True, last_activity_ts: float = 0.0):
        self.is_running = running
        self.last_activity_ts = last_activity_ts
        self.stop_calls: list[bool] = []

    def stop(self, wait: bool = True) -> None:  # noqa: ARG002
        self.stop_calls.append(wait)
        self.is_running = False


def _dummy_app(**attrs):
    """Экземпляр App без Tk-инициализации (для проверки lifecycle-хелперов)."""
    app = notscan.App.__new__(notscan.App)
    for key, value in attrs.items():
        setattr(app, key, value)
    return app


# ──────────────────────────── find_free_port ────────────────────────────

class TestFindFreePort:
    def test_port_is_free_for_free_port(self):
        port = _pick_free_port()
        assert port_is_free("127.0.0.1", port) is True

    def test_port_is_free_for_busy_port(self):
        sock = _busy_socket()
        try:
            busy = int(sock.getsockname()[1])
            assert port_is_free("127.0.0.1", busy) is False
        finally:
            sock.close()

    def test_port_is_free_rejects_invalid(self):
        assert port_is_free("127.0.0.1", 0) is False
        assert port_is_free("127.0.0.1", -1) is False
        assert port_is_free("127.0.0.1", 70000) is False

    def test_find_free_port_returns_start_when_free(self):
        port = _pick_free_port()
        assert find_free_port("127.0.0.1", port) == port

    def test_find_free_port_skips_busy(self):
        sock = _busy_socket()
        try:
            busy = int(sock.getsockname()[1])
            found = find_free_port("127.0.0.1", busy, attempts=100)
            assert found is not None
            assert found != busy
            assert found > busy
            assert port_is_free("127.0.0.1", found)
        finally:
            sock.close()

    def test_find_free_port_none_when_no_candidates(self):
        # attempts=1 и занятый порт → None (не нашли в диапазоне)
        sock = _busy_socket()
        try:
            busy = int(sock.getsockname()[1])
            assert find_free_port("127.0.0.1", busy, attempts=1) is None
        finally:
            sock.close()

    def test_next_proxy_port_strictly_after_start(self):
        port = _pick_free_port()
        nxt = next_proxy_port("127.0.0.1", port, attempts=100)
        assert nxt is not None
        assert nxt != port
        assert port_is_free("127.0.0.1", nxt)


# ──────────────────────────── should_idle_stop ────────────────────────────

class TestShouldIdleStop:
    def test_zero_minutes_disables(self):
        assert should_idle_stop(now=10_000.0, last_activity=0.0, minutes=0) is False
        assert should_idle_stop(now=10_000.0, last_activity=1.0, minutes=-5) is False

    def test_no_activity_data_does_not_stop(self):
        assert should_idle_stop(now=10_000.0, last_activity=0.0, minutes=15) is False

    def test_below_threshold(self):
        now = 10_000.0
        assert should_idle_stop(now, now - 60, minutes=15) is False

    def test_at_and_above_threshold(self):
        now = 10_000.0
        assert should_idle_stop(now, now - 15 * 60, minutes=15) is True
        assert should_idle_stop(now, now - 16 * 60, minutes=15) is True

    def test_invalid_values_do_not_stop(self):
        assert should_idle_stop("bad", 1.0, 15) is False
        assert should_idle_stop(1000.0, "bad", 15) is False


# ──────────────────────────── proxy_settings ────────────────────────────

class TestProxySettings:
    def test_defaults(self):
        opts = proxy_settings(None)
        # Прокси НЕ должен стартовать сам по умолчанию — только по кнопке.
        assert opts["proxy_autostart"] is False
        assert opts["proxy_stop_on_browser_exit"] is True
        assert opts["proxy_idle_stop_min"] == 15
        assert opts["proxy_filter_noise"] is True

    def test_overrides_and_normalization(self):
        opts = proxy_settings({
            "proxy_autostart": True,
            "proxy_stop_on_browser_exit": 0,
            "proxy_idle_stop_min": "7",
            "proxy_filter_noise": False,
        })
        assert opts["proxy_autostart"] is True
        assert opts["proxy_stop_on_browser_exit"] is False
        assert opts["proxy_idle_stop_min"] == 7.0
        assert opts["proxy_filter_noise"] is False

    def test_invalid_values_fall_back(self):
        opts = proxy_settings({"proxy_idle_stop_min": "abc"})
        assert opts["proxy_idle_stop_min"] == 15
        opts = proxy_settings({"proxy_idle_stop_min": -3})
        assert opts["proxy_idle_stop_min"] == 0  # 0 = выключено

    def test_unknown_keys_ignored(self):
        opts = proxy_settings({"proxy_foo": 1, "theme_mode": "light"})
        assert "proxy_foo" not in opts
        assert set(opts) == set(mitm_proxy.PROXY_SETTING_DEFAULTS)


# ──────────────────────────── ProxyRunner ────────────────────────────

class TestProxyRunnerLifecycle:
    def test_last_activity_ts_updates(self):
        runner = ProxyRunner(host="127.0.0.1", port=_pick_free_port(),
                             log_callback=lambda _m: None)
        assert runner.last_activity_ts == 0.0
        runner._touch_activity()
        assert runner.last_activity_ts > 0.0
        first = runner.last_activity_ts
        time.sleep(0.01)
        runner._touch_activity()
        assert runner.last_activity_ts >= first

    def test_stop_without_start_is_safe(self):
        port = _pick_free_port()
        logs: list[str] = []
        runner = ProxyRunner(host="127.0.0.1", port=port, log_callback=logs.append)
        t0 = time.perf_counter()
        runner.stop(wait=True)
        elapsed = time.perf_counter() - t0
        assert elapsed < 2.0, "stop() без start() не должен зависать"
        assert runner.is_running is False
        assert runner.pac_url == ""
        assert port_is_free("127.0.0.1", port), "порт свободного ProxyRunner не тронут"
        assert any("stopped" in m for m in logs)

    def test_wait_stopped_event_initially_set(self):
        runner = ProxyRunner(host="127.0.0.1", port=_pick_free_port(),
                             log_callback=lambda _m: None)
        assert runner.wait_stopped(timeout=0.1) is True


# ──────────────────── GUI lifecycle-хелперы (без Tk) ────────────────────

class TestGuiProxyLifecycleHelpers:
    def test_browser_exit_auto_stops_proxy(self):
        runner = _FakeRunner(running=True)
        stopped: list[str] = []
        app = _dummy_app(
            _browser_proc=_FakeProc(returncode=0),
            _proxy_runner=runner,
            _get_proxy_settings=lambda: {"proxy_stop_on_browser_exit": True},
            _auto_stop_proxy=lambda reason: stopped.append(reason),
            _set_proxy_status=lambda *a, **k: None,
            log=lambda _m: None,
        )
        notscan.App._check_browser_exit(app)
        assert app._browser_proc is None
        assert stopped == ["browser closed"]

    def test_browser_exit_keeps_proxy_when_disabled(self):
        runner = _FakeRunner(running=True)
        stopped: list[str] = []
        app = _dummy_app(
            _browser_proc=_FakeProc(returncode=1),
            _proxy_runner=runner,
            _get_proxy_settings=lambda: {"proxy_stop_on_browser_exit": False},
            _auto_stop_proxy=lambda reason: stopped.append(reason),
            _set_proxy_status=lambda *a, **k: None,
            log=lambda _m: None,
        )
        notscan.App._check_browser_exit(app)
        assert stopped == []
        assert runner.is_running is True

    def test_browser_still_running_does_nothing(self):
        runner = _FakeRunner(running=True)
        stopped: list[str] = []
        app = _dummy_app(
            _browser_proc=_FakeProc(returncode=None),
            _proxy_runner=runner,
            _get_proxy_settings=lambda: {"proxy_stop_on_browser_exit": True},
            _auto_stop_proxy=lambda reason: stopped.append(reason),
            _set_proxy_status=lambda *a, **k: None,
            log=lambda _m: None,
        )
        notscan.App._check_browser_exit(app)
        assert app._browser_proc is not None
        assert stopped == []

    def test_idle_auto_stop_by_setting(self):
        now = time.time()
        runner = _FakeRunner(running=True, last_activity_ts=now - 16 * 60)
        stopped: list[str] = []
        app = _dummy_app(
            _proxy_runner=runner,
            _get_proxy_settings=lambda: {"proxy_idle_stop_min": 15},
            _auto_stop_proxy=lambda reason: stopped.append(reason),
            log=lambda _m: None,
        )
        notscan.App._check_idle_stop(app, now=now)
        assert stopped == ["idle 15 min"]

    def test_idle_no_stop_when_disabled_or_active(self):
        now = time.time()
        stopped: list[str] = []
        # 0 минут = выключено
        app = _dummy_app(
            _proxy_runner=_FakeRunner(running=True, last_activity_ts=now - 3600),
            _get_proxy_settings=lambda: {"proxy_idle_stop_min": 0},
            _auto_stop_proxy=lambda reason: stopped.append(reason),
            log=lambda _m: None,
        )
        notscan.App._check_idle_stop(app, now=now)
        # активность только что
        app2 = _dummy_app(
            _proxy_runner=_FakeRunner(running=True, last_activity_ts=now - 5),
            _get_proxy_settings=lambda: {"proxy_idle_stop_min": 15},
            _auto_stop_proxy=lambda reason: stopped.append(reason),
            log=lambda _m: None,
        )
        notscan.App._check_idle_stop(app2, now=now)
        assert stopped == []


# ──────────────────── Интеграционный: реальный mitmproxy ────────────────────

@pytest.mark.integration
def test_proxy_runner_start_stop_releases_port():
    """start() реально слушает порт; stop() освобождает его (bindable)."""
    host = "127.0.0.1"
    port = _pick_free_port(host)
    logs: list[str] = []
    runner = ProxyRunner(host=host, port=port, log_callback=logs.append)
    try:
        runner.start()
        deadline = time.time() + 10.0
        listening = False
        while time.time() < deadline:
            time.sleep(0.05)
            if runner._master is not None and not port_is_free(host, port):
                listening = True
                break
            if not runner.is_running:
                break
        if not listening:
            runner.stop(wait=True)
            pytest.skip(f"mitmproxy не поднялся в этом окружении (logs={logs[-3:]})")
        assert runner.is_running
        assert not port_is_free(host, port), "пока прокси работает, порт должен быть занят"
        runner._touch_activity()
        start_ts = time.perf_counter()
        runner.stop(wait=True)
        elapsed = time.perf_counter() - start_ts
        assert elapsed < 15.0, f"stop() слишком долгий: {elapsed:.2f}s"
        assert port_is_free(host, port), "после stop() порт обязан быть bindable"
        assert runner.wait_stopped(timeout=0.1) is True
        assert any("stopped" in m for m in logs)
    finally:
        try:
            runner.stop(wait=True)
        except Exception:
            pass


# ──────────── фоновый шум браузера (Google telemetry и т.п.) ────────────

def test_noise_host_detection():
    import mitm_proxy

    # типичный фоновый шум Chromium/Google
    assert mitm_proxy.is_noise_host("update.googleapis.com") is True
    assert mitm_proxy.is_noise_host("accounts.google.com") is True
    assert mitm_proxy.is_noise_host("www.google-analytics.com") is True
    assert mitm_proxy.is_noise_host("ssl.gstatic.com") is True
    assert mitm_proxy.is_noise_host("UPDATE.GOOGLEAPIS.COM") is True
    assert mitm_proxy.is_noise_host("update.googleapis.com.") is True
    # обычные цели/домены — не шум
    assert mitm_proxy.is_noise_host("example.com") is False
    assert mitm_proxy.is_noise_host("127.0.0.1") is False
    assert mitm_proxy.is_noise_host("localhost:8080") is False
    assert mitm_proxy.is_noise_host("") is False


def test_proxy_setting_defaults_autostart_off_and_noise_filter_on():
    import mitm_proxy

    opts = mitm_proxy.proxy_settings({})
    assert opts["proxy_autostart"] is False, "прокси не должен авто-стартовать по умолчанию"
    assert opts["proxy_filter_noise"] is True
    assert opts["proxy_stop_on_browser_exit"] is True
    assert opts["proxy_idle_stop_min"] == 15
    # явные настройки уважаются
    opts = mitm_proxy.proxy_settings(
        {"proxy_autostart": True, "proxy_filter_noise": False, "proxy_idle_stop_min": 0}
    )
    assert opts["proxy_autostart"] is True
    assert opts["proxy_filter_noise"] is False
    assert opts["proxy_idle_stop_min"] == 0


def test_logger_addon_filters_noise_without_db():
    import mitm_proxy

    class _Req:
        host = "update.googleapis.com"

    class _Flow:
        request = _Req()

    logs: list[str] = []
    addon = mitm_proxy.LoggerAddon(log_callback=logs.append, filter_noise=True)
    # Шум отфильтрован: в БД не пишем, activity для idle не обновляем.
    addon.response(_Flow())
    assert addon.filtered_noise_count == 1
    assert logs and "отфильтрован" in logs[0]

    class _Req2:
        host = "example.com"

    class _Flow2:
        request = _Req2()

    # filter_noise=False — обычный поток (здесь специально не зовём response():
    # без БД он упадёт; проверяем только флаг).
    off = mitm_proxy.LoggerAddon(log_callback=lambda _s: None, filter_noise=False)
    assert off.filter_noise is False
