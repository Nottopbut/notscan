"""
tests/test_net_probe.py — liveness-проверка хостов перед сканом (net_probe.py).

Покрывает:
  • check_host_alive: HEAD 200; HEAD 405/501 → OPTIONS → GET fallback;
    любой HTTP-статус (<600) = жив; connection refused / timeout / DNS /
    invalid URL = мёртв; headers/User-Agent; redirect не сопровождается;
  • probe_host alias;
  • filter_alive_history_ids: группировка по scheme://host:port, ОДИН probe
    на хост (server counter), живые history_id в исходном порядке, отчёт по
    хостам, [ALIVE]-логи, битые/не-http URL — dead без сети.
"""

from __future__ import annotations

import http.server
import socketserver
import threading
import time
from pathlib import Path

import pytest

import db
import net_probe


# ══════════════════════════════════════════════════════════════════
#  Конфигурируемый тестовый HTTP-сервер
# ══════════════════════════════════════════════════════════════════


class _ProbeHandler(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def _handle(self) -> None:
        server = self.server
        method = self.command.upper()
        with server.lock:  # type: ignore[attr-defined]
            server.counts[method] = server.counts.get(method, 0) + 1  # type: ignore[attr-defined]
            server.paths.append(self.path)  # type: ignore[attr-defined]
            server.headers_seen.append(dict(self.headers))  # type: ignore[attr-defined]
        delay = server.delays.get(method, 0.0)  # type: ignore[attr-defined]
        if delay:
            time.sleep(delay)
        status = server.behavior.get(method, server.default_status)  # type: ignore[attr-defined]
        if callable(status):
            status = status(self)
        self.send_response(int(status))
        self.send_header("Content-Length", "0")
        location = getattr(server, "location", "")
        if location and 300 <= int(status) < 400:
            self.send_header("Location", location)
        self.end_headers()

    def do_HEAD(self) -> None:  # noqa: N802
        self._handle()

    def do_OPTIONS(self) -> None:  # noqa: N802
        self._handle()

    def do_GET(self) -> None:  # noqa: N802
        self._handle()

    def log_message(self, *args) -> None:  # noqa: D401 - тишина
        pass


class _ProbeServer(socketserver.ThreadingTCPServer):
    daemon_threads = True
    allow_reuse_address = True


@pytest.fixture()
def server_factory():
    servers: list[_ProbeServer] = []

    def make(default_status: int = 200, behavior: dict | None = None,
             delays: dict | None = None, location: str = "") -> _ProbeServer:
        server = _ProbeServer(("127.0.0.1", 0), _ProbeHandler)
        server.default_status = default_status  # type: ignore[attr-defined]
        server.behavior = dict(behavior or {})  # type: ignore[attr-defined]
        server.delays = dict(delays or {})  # type: ignore[attr-defined]
        server.counts = {}  # type: ignore[attr-defined]
        server.paths = []  # type: ignore[attr-defined]
        server.headers_seen = []  # type: ignore[attr-defined]
        server.lock = threading.Lock()  # type: ignore[attr-defined]
        server.location = location  # type: ignore[attr-defined]
        threading.Thread(target=server.serve_forever, daemon=True).start()
        server.base_url = f"http://127.0.0.1:{server.server_address[1]}"  # type: ignore[attr-defined]
        servers.append(server)
        return server

    try:
        yield make
    finally:
        for server in servers:
            try:
                server.shutdown()
                server.server_close()
            except Exception:
                pass


def _closed_port_url() -> str:
    """URL на порт, где точно никто не слушает (connection refused)."""
    import socket

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.bind(("127.0.0.1", 0))
    port = sock.getsockname()[1]
    sock.close()
    return f"http://127.0.0.1:{port}/"


@pytest.fixture()
def tmp_db(tmp_path: Path):
    prev = db.get_db_path()
    db_path = tmp_path / "net-probe.db"
    db.set_db_path(db_path)
    yield db_path
    db.set_db_path(tmp_path / "net-probe-closed.db")
    for suffix in ("", "-wal", "-shm"):
        try:
            Path(str(db_path) + suffix).unlink(missing_ok=True)
        except OSError:
            pass


# ══════════════════════════════════════════════════════════════════
#  check_host_alive
# ══════════════════════════════════════════════════════════════════


class TestCheckHostAlive:
    def test_head_200_alive(self, server_factory):
        server = server_factory(default_status=200)
        alive, detail = net_probe.check_host_alive(server.base_url + "/")
        assert alive is True
        assert detail == "HTTP 200 via HEAD"
        assert server.counts == {"HEAD": 1}

    def test_head_405_falls_back_to_options(self, server_factory):
        server = server_factory(behavior={"HEAD": 405, "OPTIONS": 200})
        alive, detail = net_probe.check_host_alive(server.base_url + "/login")
        assert alive is True
        assert detail == "HTTP 200 via OPTIONS"
        assert server.counts.get("HEAD") == 1
        assert server.counts.get("OPTIONS") == 1
        assert server.counts.get("GET") is None

    def test_head_and_options_405_fall_back_to_get(self, server_factory):
        server = server_factory(behavior={"HEAD": 405, "OPTIONS": 501, "GET": 200})
        alive, detail = net_probe.check_host_alive(server.base_url + "/api")
        assert alive is True
        assert detail == "HTTP 200 via GET"
        assert server.counts.get("GET") == 1

    def test_head_403_is_alive_and_falls_back(self, server_factory):
        server = server_factory(behavior={"HEAD": 403, "OPTIONS": 204})
        alive, detail = net_probe.check_host_alive(server.base_url + "/")
        assert alive is True
        assert detail == "HTTP 204 via OPTIONS"

    def test_any_http_status_means_alive(self, server_factory):
        server = server_factory(default_status=500)
        alive, detail = net_probe.check_host_alive(server.base_url + "/")
        assert alive is True
        assert detail == "HTTP 500 via HEAD"

    def test_redirect_not_followed(self, server_factory):
        server = server_factory(
            behavior={"HEAD": 302}, location="http://127.0.0.1:1/elsewhere"
        )
        alive, detail = net_probe.check_host_alive(server.base_url + "/")
        assert alive is True
        assert detail == "HTTP 302 via HEAD"
        assert server.counts == {"HEAD": 1}

    def test_connection_refused_dead(self):
        alive, detail = net_probe.check_host_alive(_closed_port_url(), timeout=1.0)
        assert alive is False
        assert detail, "должна быть причина"
        assert ("connect" in detail.lower()) or ("timeout" in detail.lower()), detail

    def test_timeout_dead(self, server_factory):
        server = server_factory(delays={"HEAD": 2.0})
        started = time.perf_counter()
        alive, detail = net_probe.check_host_alive(server.base_url + "/", timeout=0.25)
        elapsed = time.perf_counter() - started
        assert alive is False
        assert "timeout" in detail.lower(), detail
        assert elapsed < 1.5, f"liveness должен уважать timeout: {elapsed:.2f}s"

    @pytest.mark.parametrize(
        "url",
        ["", "not-a-url", "ftp://example.test/", "http://", "://bad"],
    )
    def test_invalid_urls_dead_without_network(self, url):
        alive, detail = net_probe.check_host_alive(url, timeout=0.5)
        assert alive is False
        assert "invalid" in detail.lower() or "unsupported" in detail.lower(), detail

    def test_headers_and_user_agent(self, server_factory):
        server = server_factory(default_status=200)
        net_probe.check_host_alive(
            server.base_url + "/", headers={"X-Probe": "yes", "X-Trace": "1"}
        )
        seen = server.headers_seen[0]
        headers_lower = {str(k).lower(): str(v) for k, v in seen.items()}
        assert headers_lower.get("x-probe") == "yes"
        assert headers_lower.get("x-trace") == "1"
        assert "notscan-liveness" in headers_lower.get("user-agent", "")

    def test_probe_host_alias(self, server_factory):
        server = server_factory(default_status=200)
        assert net_probe.probe_host(server.base_url + "/") == (True, "HTTP 200 via HEAD")


# ══════════════════════════════════════════════════════════════════
#  filter_alive_history_ids
# ══════════════════════════════════════════════════════════════════


class TestFilterAliveHistoryIds:
    def _insert(self, url: str) -> int:
        return db.insert_history("GET", url, {"User-Agent": "lab"}, None, 200, {}, b"ok")

    def test_filters_dead_and_probes_each_host_once(self, server_factory, tmp_db):
        alive_server = server_factory(default_status=200)
        logs: list[str] = []
        dead_url = _closed_port_url()
        h_alive_1 = self._insert(alive_server.base_url + "/a?x=1")
        h_dead = self._insert(dead_url)
        h_alive_2 = self._insert(alive_server.base_url + "/b?x=2")  # тот же хост
        h_invalid = self._insert("not-a-url")

        live_ids, report = net_probe.filter_alive_history_ids(
            [h_alive_1, h_dead, h_alive_2, h_invalid], timeout=1.0, log_cb=logs.append
        )

        assert live_ids == [h_alive_1, h_alive_2]
        host_key = net_probe._host_key(alive_server.base_url)
        assert report[host_key][0] is True
        assert report[net_probe._host_key(dead_url)][0] is False
        assert report["not-a-url"] == (False, "invalid URL")
        # Один хост проверяется РОВНО ОДИН раз, несмотря на 2 history-записи.
        assert alive_server.counts.get("HEAD", 0) == 1
        # Логи: OK и DEAD строки в формате [ALIVE] host — ...
        assert any("[ALIVE]" in m and "— OK" in m for m in logs), logs
        assert any("[ALIVE]" in m and "— DEAD" in m for m in logs), logs
        assert any("invalid URL" in m for m in logs)

    def test_empty_input(self, tmp_db):
        assert net_probe.filter_alive_history_ids([]) == ([], {})

    def test_missing_history_id_is_dead(self, tmp_db):
        logs: list[str] = []
        live_ids, report = net_probe.filter_alive_history_ids(
            [999999], timeout=0.5, log_cb=logs.append
        )
        assert live_ids == []
        assert report, "для отсутствующей записи должен быть отчёт"
        assert any("DEAD" in m for m in logs), logs

    def test_preserves_input_order_mixed(self, server_factory, tmp_db):
        server = server_factory(default_status=200)
        ids = [self._insert(server.base_url + f"/p{i}") for i in range(5)]
        dead_id = self._insert(_closed_port_url())
        live_ids, _report = net_probe.filter_alive_history_ids(
            [ids[3], dead_id, ids[0], ids[4], ids[1], ids[2]], timeout=1.0
        )
        assert live_ids == [ids[3], ids[0], ids[4], ids[1], ids[2]]
