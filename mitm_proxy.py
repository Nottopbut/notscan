"""
mitm_proxy.py — mitmproxy LoggerAddon + ProxyRunner.

Стратегия запуска:
  1. Python API через DumpMaster в собственном asyncio loop.
     DumpMaster создаётся ВНУТРИ корутины _run_master() — loop уже running.
  2. Fallback: subprocess mitmdump если Python API недоступен.

Исправления:
  - RuntimeError: Event loop is closed  → патчим mitmproxy logging handler
    чтобы ошибки в закрытый loop не крашили proxy server thread.
  - [Errno 98] address already in use   → SO_REUSEPORT через workaround;
    корректный async shutdown с ожиданием завершения потока.
"""

from __future__ import annotations

import asyncio
import logging
import logging.handlers
import socket
import subprocess
import sys
import threading
import time
from pathlib import Path
from typing import Any, Optional, Callable

logger = logging.getLogger(__name__)


# ─────────────────────── Monkey-patch mitmproxy log handler ──────────────────
# mitmproxy/log.py:221 делает master.event_loop.call_soon_threadsafe(...)
# Когда event loop уже закрыт (после shutdown) — это RuntimeError: Event loop is closed
# Патчим emit() чтобы проглатывать ошибку вместо краша.

def _patch_mitmproxy_log_handler() -> None:
    """
    Перехватывает mitmproxy.log.MitmLogHandler.emit() и добавляет
    защиту от 'Event loop is closed' / 'Event loop is not running'.
    Вызывается один раз при первом запуске прокси.
    """
    try:
        import mitmproxy.log as mlog
        handler_class = None
        for name in dir(mlog):
            obj = getattr(mlog, name)
            if isinstance(obj, type) and issubclass(obj, logging.Handler) and obj is not logging.Handler:
                handler_class = obj
                break

        if handler_class is None:
            return

        original_emit = handler_class.emit

        def safe_emit(self, record):
            try:
                original_emit(self, record)
            except RuntimeError as e:
                if "event loop" in str(e).lower() or "closed" in str(e).lower():
                    pass  # loop закрыт — игнорируем
                else:
                    raise
            except Exception:
                pass  # любые другие ошибки при shutdown — тихо игнорируем

        handler_class.emit = safe_emit
        logger.debug("[PROXY] mitmproxy log handler patched")
    except Exception as e:
        logger.debug("[PROXY] could not patch mitmproxy log handler: %s", e)


_LOG_PATCHED = False


# ─────────────────────── Настройки авто-жизненного цикла прокси ──────────────
# Хранятся в project settings (ui_theme.load_settings/save_settings).
# См..

# Фоновый «шум» браузера: телеметрия Chromium/Google, обновления компонентов,
# safe-browsing, connectivity-check и т.п. Такие запросы не нужны в History и
# только засоряют её (и могут случайно попасть в скан). Фильтруются на входе
# в прокси (LoggerAddon), настройка — proxy_filter_noise (по умолчанию вкл.).
NOISE_HOST_SUFFIXES: tuple[str, ...] = (
    # Google / Chromium telemetry & updates
    "accounts.google.com",
    "update.googleapis.com",
    "clients2.google.com",
    "clientservices.googleapis.com",
    "optimizationguide-pa.googleapis.com",
    "safebrowsing.googleapis.com",
    "chromewebstore.googleapis.com",
    "play.googleapis.com",
    "c2dm.googleapis.com",
    "android.clients.google.com",
    "mtalk.google.com",
    "time.google.com",
    "www.google.com",
    "www.gstatic.com",
    "fonts.googleapis.com",
    "fonts.gstatic.com",
    "ssl.gstatic.com",
    "connectivitycheck.gstatic.com",
    "google-analytics.com",
    "googletagmanager.com",
    "googlesyndication.com",
    "doubleclick.net",
    # Microsoft / Mozilla аналогичный фоновый шум
    "settings-win.data.microsoft.com",
    "v10.events.data.microsoft.com",
    "self.events.data.microsoft.com",
    "firefox.settings.services.mozilla.com",
    "incoming.telemetry.mozilla.org",
)


def is_noise_host(host: str) -> bool:
    """True, если хост — известный фоновый шум браузера (телеметрия/обновления)."""
    host_l = (host or "").strip().lower().rstrip(".")
    if not host_l:
        return False
    return any(host_l == suffix or host_l.endswith("." + suffix)
               for suffix in NOISE_HOST_SUFFIXES)


PROXY_SETTING_DEFAULTS: dict[str, Any] = {
    "proxy_autostart": False,            # авто-старт прокси при запуске App (по умолчанию ВЫКЛ)
    "proxy_stop_on_browser_exit": True,  # авто-стоп после закрытия браузера
    "proxy_idle_stop_min": 15,           # авто-стоп после N минут простоя (0 = off)
    "proxy_filter_noise": True,          # не писать в History фоновый шум браузера
}


def proxy_settings(settings: Optional[dict]) -> dict[str, Any]:
    """Настройки авто-прокси с дефолтами и нормализацией типов.

    Неизвестные ключи отбрасываются; значения приводятся к bool / float,
    idle minutes < 0 → 0 (0 = авто-стоп выключен).
    """
    out = dict(PROXY_SETTING_DEFAULTS)
    if not settings:
        return out
    for key, default in PROXY_SETTING_DEFAULTS.items():
        if key not in settings:
            continue
        value = settings.get(key)
        if key == "proxy_idle_stop_min":
            try:
                number = float(value)
            except (TypeError, ValueError):
                number = float(default)
            out[key] = max(0.0, number)
        else:
            out[key] = bool(value)
    return out


def port_is_free(host: str, port: int) -> bool:
    """True, если TCP-порт можно забиндить (нет активного LISTEN)."""
    try:
        port = int(port)
    except (TypeError, ValueError):
        return False
    if not (0 < port <= 65535):
        return False
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(1.0)
    try:
        sock.bind((host or "127.0.0.1", port))
        return True
    except OSError:
        return False
    finally:
        sock.close()


def find_free_port(host: str, start: int, attempts: int = 100) -> Optional[int]:
    """Первый свободный порт в диапазоне [start, start+attempts).

    Нужен для авто-подбора порта, когда дефолтный (8080) занят: вместо
    модалки-тупика GUI просто берёт следующий свободный. None — не нашли.
    """
    try:
        start_port = int(start)
        limit = max(1, int(attempts))
    except (TypeError, ValueError):
        return None
    for offset in range(limit):
        candidate = start_port + offset
        if candidate > 65535:
            break
        if port_is_free(host, candidate):
            return candidate
    return None


def next_proxy_port(host: str, start: int, attempts: int = 100) -> Optional[int]:
    """Следующий свободный порт СТРОГО после ``start`` (fallback при занятом).

    Возвращает None, если нашли/не нашли: GUI оставляет исходный порт, если
    free_port(host, start) вернул его же, и вызывает next_proxy_port только
    когда стартовый занят.
    """
    try:
        start_port = int(start)
    except (TypeError, ValueError):
        return None
    if start_port >= 65535:
        return None
    return find_free_port(host, start_port + 1, attempts)


def should_idle_stop(now: float, last_activity: float, minutes: float) -> bool:
    """Пора ли остановить прокси из-за простоя (idle-автостоп).

    minutes <= 0 → выключено; нетданных об активности (<=0) → не стоп.
    """
    try:
        minutes = float(minutes)
        now = float(now)
        last_activity = float(last_activity)
    except (TypeError, ValueError):
        return False
    if minutes <= 0 or last_activity <= 0:
        return False
    return (now - last_activity) >= minutes * 60.0



# ─────────────────────────── PAC server ──────────────────────────────────────
# Chromium/Chrome обходит прокси для loopback даже с --proxy-bypass-list=
# Единственный надёжный способ заставить браузер проксировать localhost —
# PAC-скрипт через --proxy-pac-url, где явно перечислено "PROXY host:port"
# без исключений для loopback.

class PacServer:
    """
    Минимальный HTTP-сервер, отдающий PAC-скрипт.
    PAC-скрипт направляет ВСЕ запросы (включая localhost/127.x.x.x) в прокси.

    Запускается на случайном свободном порту.
    URL: http://127.0.0.1:<pac_port>/proxy.pac
    """

    PAC_TEMPLATE = """function FindProxyForURL(url, host) {{
    // Направляем абсолютно всё через прокси — включая localhost
    return "PROXY {proxy_host}:{proxy_port}; DIRECT";
}}
"""

    def __init__(self, proxy_host: str, proxy_port: int):
        self.proxy_host = proxy_host
        self.proxy_port = proxy_port
        self._server: Optional[Any] = None
        self._thread: Optional[threading.Thread] = None
        self.pac_port: int = 0
        self.pac_url: str = ""

    def start(self) -> str:
        """Запускает PAC-сервер. Возвращает URL PAC-файла."""
        import http.server
        import socket

        pac_content = self.PAC_TEMPLATE.format(
            proxy_host=self.proxy_host,
            proxy_port=self.proxy_port,
        ).encode()

        class PacHandler(http.server.BaseHTTPRequestHandler):
            def do_GET(self):
                self.send_response(200)
                self.send_header("Content-Type", "application/x-ns-proxy-autoconfig")
                self.send_header("Content-Length", str(len(pac_content)))
                self.end_headers()
                self.wfile.write(pac_content)

            def log_message(self, fmt, *args):
                pass  # тихий режим

        # Выбираем свободный порт
        with socket.socket() as s:
            s.bind(("127.0.0.1", 0))
            self.pac_port = s.getsockname()[1]

        self._server = http.server.HTTPServer(("127.0.0.1", self.pac_port), PacHandler)
        self._server.socket.setsockopt(
            __import__("socket").SOL_SOCKET,
            __import__("socket").SO_REUSEADDR,
            1,
        )
        self._thread = threading.Thread(
            target=self._server.serve_forever,
            daemon=True,
            name="pac-server",
        )
        self._thread.start()
        self.pac_url = f"http://127.0.0.1:{self.pac_port}/proxy.pac"
        logger.debug("[PAC] server started: %s", self.pac_url)
        return self.pac_url

    def stop(self) -> None:
        server = self._server
        self._server = None
        if server is not None:
            try:
                server.shutdown()
            except Exception:
                pass
            try:
                server.server_close()  # освобождаем PAC-порт
            except Exception:
                pass
        thread = self._thread
        self._thread = None
        if thread is not None and thread.is_alive():
            thread.join(timeout=2.0)

# ──────────────────────────── LoggerAddon ────────────────────────────────────

class LoggerAddon:
    """mitmproxy addon: сохраняет каждый завершённый flow в SQLite."""

    BODY_PREVIEW_SIZE = 32_768  # 32 KB
    _db_initialized = False

    def __init__(
        self,
        log_callback: Optional[Callable[[str], None]] = None,
        on_activity: Optional[Callable[[], None]] = None,
        filter_noise: bool = True,
    ):
        self.log_cb = log_callback or (lambda s: None)
        # Колбэк «был перехвачен трафик» — нужен idle-автостопу ProxyRunner.
        self.on_activity = on_activity
        self.filter_noise = bool(filter_noise)
        self.filtered_noise_count = 0
        self._noise_lock = threading.Lock()

    def _is_noise(self, flow) -> bool:
        if not self.filter_noise:
            return False
        try:
            host = flow.request.host or ""
        except Exception:
            return False
        if not is_noise_host(host):
            return False
        with self._noise_lock:
            self.filtered_noise_count += 1
            count = self.filtered_noise_count
        # Логируем редко, чтобы не засорять лог.
        if count == 1 or count % 25 == 0:
            self.log_cb(
                f"[PROXY] фоновый шум браузера отфильтрован: {host} "
                f"(всего {count}; отключить — Settings → Proxy filter noise)"
            )
        return True

    def response(self, flow) -> None:  # type: ignore[override]
        try:
            if self._is_noise(flow):
                return
            if self.on_activity is not None:
                try:
                    self.on_activity()
                except Exception:
                    pass
            # Гарантируем создание таблиц до первой записи
            # (иначе при старте прокси до init_db будет "no such table: history").
            if not LoggerAddon._db_initialized:
                import db as _db
                _db.init_db()
                LoggerAddon._db_initialized = True
            from db import insert_history  # отложенный импорт

            req = flow.request
            resp = flow.response

            req_headers = dict(req.headers)
            # req.content автоматически декодирует gzip/br; raw_content — прямые байты.
            # Используем get_content() и fallback на raw_content чтобы не потерять JSON-тело.
            try:
                req_body: Optional[bytes] = req.get_content() or None
            except Exception:
                req_body = req.raw_content or None

            resp_status: Optional[int] = resp.status_code if resp else None
            resp_headers: Optional[dict] = dict(resp.headers) if resp else None
            resp_body: Optional[bytes] = (
                resp.content[: self.BODY_PREVIEW_SIZE] if resp and resp.content else None
            )

            row_id = insert_history(
                method=req.method,
                url=req.pretty_url,
                req_headers=req_headers,
                req_body=req_body,
                resp_status=resp_status,
                resp_headers=resp_headers,
                resp_body_preview=resp_body,
            )
            self.log_cb(
                f"[PROXY] {req.method} {req.pretty_url} → {resp_status}  (id={row_id})"
            )
        except Exception as exc:
            logger.exception("LoggerAddon.response error: %s", exc)
            self.log_cb(f"[PROXY][ERR] {exc}")


# ──────────────────────────── ProxyRunner ────────────────────────────────────

class ProxyRunner:
    """
    Запускает mitmproxy в отдельном потоке.

    Режим 1 (по умолчанию): Python API (DumpMaster внутри running loop).
    Режим 2 (fallback): subprocess mitmdump.
    """

    def __init__(
        self,
        host: str = "127.0.0.1",
        port: int = 8080,
        log_callback: Optional[Callable[[str], None]] = None,
        filter_noise: bool = True,
    ):
        self.host = host
        self.port = port
        self.log_cb = log_callback or print
        self.filter_noise = bool(filter_noise)

        # Python-API mode
        self._thread: Optional[threading.Thread] = None
        self._loop: Optional[asyncio.AbstractEventLoop] = None
        self._master = None
        self._stop_event = threading.Event()

        # Subprocess fallback mode
        self._process: Optional[subprocess.Popen] = None
        self._mode: str = "api"  # "api" | "subprocess"

        # PAC server (запускается вместе с прокси)
        self._pac_server: Optional[PacServer] = None
        self.pac_url: str = ""

        # Активность для idle-автостопа: обновляется при каждом перехваченном
        # запросе (LoggerAddon.on_activity / строки mitmdump в fallback-режиме).
        self.last_activity_ts: float = 0.0
        self._activity_lock = threading.Lock()
        # Устанавливается после фактического освобождения ресурсов в stop().
        self._stopped_event = threading.Event()
        self._stopped_event.set()

    # ── public ───────────────────────────────────────────────────────────────

    def _touch_activity(self) -> None:
        """Отметить активность прокси (для idle-автостопа)."""
        with self._activity_lock:
            self.last_activity_ts = time.time()

    def _wait_port_released(self, timeout: float = 2.0) -> bool:
        """Ждёт освобождения listen-порта (best-effort, для гарантий stop())."""
        deadline = time.time() + timeout
        while time.time() < deadline:
            if port_is_free(self.host, self.port):
                return True
            time.sleep(0.02)
        return port_is_free(self.host, self.port)

    @staticmethod
    def _stop_proxy_servers(master: Any, loop: Optional[asyncio.AbstractEventLoop]) -> None:
        """Явно закрыть listen-сокеты mitmproxy (иначе порт остаётся занятым).

        В mitmproxy 12 выход реализован через should_exit, а ProxyServer-аддон
        сам сервера не останавливает; модульный ctx держит master живым, поэтому
        сокеты не освобождаются GC. Останавливаем их через servers.update([]).
        """
        try:
            addons = getattr(master, "addons", None)
            proxyserver = addons.get("proxyserver") if addons is not None else None
            servers = getattr(proxyserver, "servers", None)
            if servers is None or len(servers) == 0:
                return
            if loop is None or loop.is_closed():
                return
            fut = asyncio.run_coroutine_threadsafe(servers.update([]), loop)
            fut.result(timeout=5)
        except Exception as exc:  # pragma: no cover - защитный путь
            logger.debug("could not stop proxy servers explicitly: %s", exc)

    def start(self) -> None:
        if self.is_running:
            self.log_cb("[PROXY] already running")
            return

        global _LOG_PATCHED
        if not _LOG_PATCHED:
            _patch_mitmproxy_log_handler()
            _LOG_PATCHED = True

        self._stop_event.clear()
        self._stopped_event.clear()
        self._touch_activity()
        self._mode = "api"

        # Запускаем PAC-сервер чтобы браузер проксировал localhost
        self._pac_server = PacServer(self.host, self.port)
        self.pac_url = self._pac_server.start()
        self.log_cb(f"[PROXY] PAC server: {self.pac_url}")

        self._thread = threading.Thread(
            target=self._run_in_thread, daemon=True, name="mitmproxy"
        )
        self._thread.start()
        self.log_cb(f"[PROXY] starting on {self.host}:{self.port} …")

    def wait_stopped(self, timeout: float = 8.0) -> bool:
        """Блокируется до фактического освобождения ресурсов (порт/PAC)."""
        return self._stopped_event.wait(timeout)

    def stop(self, wait: bool = True) -> None:
        """
        Останавливает прокси и ГАРАНТИРОВАННО освобождает порт (оба режима).

        wait=True (по умолчанию) — ждёт завершения потока/процесса и закрытия
        PAC-сервера. После выхода забиндить self.host:self.port снова можно.
        """
        self._stop_event.set()

        if self._mode == "api":
            master = self._master
            loop = self._loop
            thread = self._thread
            # Мастер может ещё не успеть создаться (start() только что вернул
            # управление) — даём ему короткий шанс появиться, иначе порт
            # остался бы занятым до принудительного loop.stop.
            deadline = time.time() + 2.0
            while (
                master is None
                and thread is not None
                and thread.is_alive()
                and time.time() < deadline
            ):
                time.sleep(0.02)
                master = self._master
            if master is not None:
                # mitmproxy 12 при выходе НЕ закрывает listen-сокеты сам
                # (глобальный ctx держит addon-manager) — останавливаем
                # proxyserver-сервера явно, иначе порт остаётся занятым.
                self._stop_proxy_servers(master, loop)
                try:
                    # В mitmproxy 12 Master.shutdown() — СИНХРОННЫЙ thread-safe
                    # метод: ставит should_exit через loop.call_soon_threadsafe.
                    master.shutdown()
                except Exception as exc:
                    self.log_cb(f"[PROXY] stop signal error: {exc}")
                finally:
                    self._master = None

            # Ждём завершения потока
            if wait and thread is not None and thread.is_alive():
                thread.join(timeout=8)

            # Принудительно закрываем loop если поток завис
            if loop is not None and not loop.is_closed():
                if thread is not None and thread.is_alive():
                    try:
                        loop.call_soon_threadsafe(loop.stop)
                    except Exception:
                        pass
            # Второй join: после loop.stop поток должен завершиться быстро.
            if wait and thread is not None and thread.is_alive():
                thread.join(timeout=3)
            self._thread = None

        else:
            process = self._process
            if process is not None:
                if process.poll() is None:
                    process.terminate()
                    try:
                        process.wait(timeout=5)
                    except subprocess.TimeoutExpired:
                        process.kill()
                        try:
                            process.wait(timeout=3)
                        except subprocess.TimeoutExpired:
                            pass
                self._process = None
            if self._thread is not None and self._thread.is_alive():
                self._thread.join(timeout=3)
            self._thread = None

        pac = self._pac_server
        self._pac_server = None
        self.pac_url = ""
        if pac is not None:
            pac.stop()

        # Гарантия освобождения порта: ждём короткое время, логируем, если нет.
        try:
            released = self._wait_port_released(timeout=2.0)
        except Exception:
            released = True
        if not released:
            self.log_cb(
                f"[PROXY][WARN] port {self.host}:{self.port} still busy after stop"
            )

        self._stopped_event.set()
        self.log_cb("[PROXY] stopped")

    @property
    def is_running(self) -> bool:
        if self._mode == "api":
            return bool(self._thread and self._thread.is_alive())
        else:
            return bool(self._process and self._process.poll() is None)

    # ── private: Python API mode ──────────────────────────────────────────────

    def _run_in_thread(self) -> None:
        """Точка входа потока: новый event loop → запуск _run_master()."""
        self._loop = asyncio.new_event_loop()
        asyncio.set_event_loop(self._loop)
        try:
            self._loop.run_until_complete(self._run_master())
        except Exception as exc:
            if not self._stop_event.is_set():
                # Настоящая ошибка — переключаемся на subprocess
                self.log_cb(f"[PROXY][ERR] Python API failed: {exc}")
                logger.warning("ProxyRunner API mode failed, switching to subprocess: %s", exc)
                self._start_subprocess_fallback()
        finally:
            # Закрываем loop только после завершения всех задач
            try:
                # Отмена оставшихся задач
                pending = asyncio.all_tasks(self._loop)
                if pending:
                    self._loop.run_until_complete(
                        asyncio.gather(*pending, return_exceptions=True)
                    )
            except Exception:
                pass
            try:
                self._loop.close()
            except Exception:
                pass

    async def _run_master(self) -> None:
        """
        Корутина внутри running loop:
        DumpMaster.__init__ найдёт активный loop через asyncio.get_running_loop().
        """
        from mitmproxy.tools.dump import DumpMaster
        from mitmproxy import options as mitm_options

        opts = mitm_options.Options(
            listen_host=self.host,
            listen_port=self.port,
        )
        # Создаём DumpMaster здесь — loop уже running
        self._master = DumpMaster(opts, with_termlog=False, with_dumper=False)
        self._master.addons.add(
            LoggerAddon(
                self.log_cb,
                on_activity=self._touch_activity,
                filter_noise=self.filter_noise,
            )
        )

        self._touch_activity()
        self.log_cb(f"[PROXY] listening on {self.host}:{self.port} (Python API)")
        await self._master.run()

    # ── private: subprocess fallback ─────────────────────────────────────────

    def _start_subprocess_fallback(self) -> None:
        """Запускает mitmdump как subprocess — надёжный fallback."""
        self._mode = "subprocess"

        mitmdump_bin = self._find_mitmdump()
        if not mitmdump_bin:
            self.log_cb("[PROXY][ERR] mitmdump not found — установите mitmproxy")
            return

        addon_path = Path(__file__).resolve()

        cmd = [
            mitmdump_bin,
            "-q",
            "--listen-host", self.host,
            "-p", str(self.port),
            "-s", str(addon_path),
        ]

        try:
            self._process = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
            )
            self._touch_activity()
            self.log_cb(
                f"[PROXY] listening on {self.host}:{self.port} "
                f"(subprocess mitmdump, pid={self._process.pid})"
            )
            self._thread = threading.Thread(
                target=self._pipe_reader, args=(self._process,), daemon=True
            )
            self._thread.start()
        except Exception as exc:
            self.log_cb(f"[PROXY][ERR] subprocess launch failed: {exc}")
            logger.exception("subprocess fallback failed: %s", exc)

    def _pipe_reader(self, proc: subprocess.Popen) -> None:
        """Читает stdout/stderr mitmdump в фоновом потоке."""
        try:
            assert proc.stdout is not None
            for line in proc.stdout:
                if self._stop_event.is_set():
                    break
                line = line.rstrip()
                if line:
                    self._touch_activity()
                    self.log_cb(f"[MITMDUMP] {line}")
        except Exception:
            pass

    @staticmethod
    def _find_mitmdump() -> Optional[str]:
        """Ищет бинарь mitmdump: venv рядом → venv интерпретатора → PATH."""
        here = Path(__file__).parent
        for candidate in [
            here / ".venv" / "bin" / "mitmdump",
            here / "venv" / "bin" / "mitmdump",
        ]:
            if candidate.exists():
                return str(candidate)

        venv_bin = Path(sys.executable).parent / "mitmdump"
        if venv_bin.exists():
            return str(venv_bin)

        result = subprocess.run(["which", "mitmdump"], capture_output=True, text=True)
        if result.returncode == 0:
            return result.stdout.strip()

        return None

# ─────────────────────────────── mitmdump addon registration ───────────────────────────────
# Когда mitm_proxy.py запускается через `mitmdump -s` (subprocess fallback),
# mitmproxy ищет модульную переменную `addons`.
# Без неё fallback перехватывал трафик, но не писал в history.
addons = [LoggerAddon(log_callback=print)]
