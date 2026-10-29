"""
tests/lab/server.py — локальная HTTP-лаба для интеграционных тестов notscan.

`LabServer` поднимает ``ThreadingHTTPServer`` на ``127.0.0.1:0`` (реальный порт
берётся из ``server.server_address[1]``) и реализует эндпоинты, на которых
проверяются ключевые детекторы/фиксы:

  GET  /reflect?q=   — сырой (без экранирования) echo параметра q;
  GET  /search?q=    — html.escape(q) + HTML-скелет (регресс FP XSS бага #4);
  GET  /sqli?id=     — SQL-error (500) при кавычке в id;
  GET  /redirect?url= — 302 c Location = url (open redirect / CRLF-инъекция);
  GET  /sleep?id=    — time.sleep(...) при time-based payload'е в id;
  GET  /slow?ms=     — time.sleep(ms/1000) (latency-bound замеры);
  GET  /safe         — статичная безопасная страница (HTML-скелет);
  GET  /form         — HTML-форма с <input name="csrf_token" value="TOKEN123">;
  POST /form         — принимает только csrf_token=TOKEN123, иначе 403;
  POST /api/user     — JSON: невалидный JSON → 400; "'" в name → 500 SQL-error.

WSTG-чеки (active / passive / probe):
  GET  /ssi?q=          — эмуляция SSI-движка: исполнение директив/SSI-ошибка;
  GET  /html?q=         — сырой echo HTML-маркеров (<h1 notscan=1>…);
  GET  /cookie-nosecure — Set-Cookie без Secure/HttpOnly/SameSite + benign cookie;
  GET  /cookie-secure   — Set-Cookie со всеми флагами (FP-контроль);
  GET  /cache-session   — сессионная cookie без Cache-Control (cache_control);
  GET  /secure-page     — CSP/no-store/all-flags cookie (FP-контроль);
  GET  /storage         — HTML с localStorage.setItem('auth_token', …);
  GET  /cors-reflect    — отражает Origin в ACAO + Allow-Credentials: true;
  GET  /backup.sql      — «дамп БД» (sensitive_files);
  GET  /robots.txt, /sitemap.xml — metafiles;
  GET  /crossdomain.xml — RIA-политика с wildcard domain="*";
  OPTIONS /             — Allow с рискованными PUT/DELETE/TRACE (http_methods).
  ``probe_clean=True`` — режим «чистого» сервера: probe-пути отдают 404/без
  рискованных заголовков (FP-контроль probe-чеков).

Все запросы пишутся в журнал (``LabServer.requests``) с методом/путём/телом/
статусом — это нужно интеграционным тестам для проверки «сервер получил
валидный JSON», «редирект не сопровождался», «CSRF-токен принят» и т.п.
Журнал потокобезопасен (ThreadingHTTPServer → один поток на запрос).

Запуск:
    server = LabServer().start()
    print(server.base_url)
    ...
    server.stop()
"""

from __future__ import annotations

import html
import json
import threading
import time
import urllib.parse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any, Optional

#: CSRF-токен, который лаба считает «свежим».
CSRF_TOKEN = "TOKEN123"

#: Тело ответа с SQL-ошибкой (сигнатура матчера/чека SQLi).
SQL_ERROR_TEXT = (
    "You have an error in your SQL syntax; check the manual that corresponds "
    "to your MySQL server version for the right syntax to use near ''' at line 1"
)

#: Маркеры time-based payload'ов — при их наличии /sleep реально спит.
SLEEP_PAYLOAD_MARKERS = ("sleep(", "pg_sleep", "waitfor", "randomblob")

#: Boolean-blind SQLi (/blind): FALSE-маркеры проверяются ПЕРВЫМИ, т.к. false-
#: payload может содержать и true-токен (пример: "1 AND 1=1 AND 2=3").
BLIND_FALSE_MARKERS = (
    "1=2", "2=3",
    "'1'='2", '"1"="2', "='b'", "like 'b'", "in (2)",
    "between 2 and 3", "ascii('a')=66", "length('abc')=4", "='other'",
    "('a'='b')", "cast(2", "is null", "=(select 2", "1)=2", "or 1=2",
)
BLIND_TRUE_MARKERS = (
    "1=1", "2=2",
    "'1'='1", '"1"="1', "='a'", "like 'a'", "in (1)",
    "between 1 and 1", "ascii('a')=65", "length('abc')=3", "='notscan'",
    "('a'='a')", "cast(1", "is not null", "=(select 1", "1)=1", "or 1=1",
)

_HTML_HEAD = "<html><head><title>{title}</title></head><body>"
_HTML_TAIL = "</body></html>"

#: Ответы эмуляции SSI-движка (см. GET /ssi) — покрывают все ветки ssi_indicator.
SSI_EXEC_OUTPUT = (
    "uid=0(root) gid=0(root) groups=0(root)\n"
    "root:x:0:0:root:/root:/bin/bash"
)
SSI_ENV_OUTPUT = (
    "DOCUMENT_ROOT=/var/www/html\n"
    "SERVER_SOFTWARE=Apache/2.4.58\n"
    "GATEWAY_INTERFACE=CGI/1.1"
)
SSI_ERROR_OUTPUT = "[an error occurred while processing this directive]"
SSI_MARKER_OUTPUT = "NOTSCAN_SSI_MARKER"

#: Статичные файлы probe-чеков (sensitive_files/metafiles/ria_policy).
BACKUP_SQL_BODY = (
    "-- MySQL dump 10.13  Distrib 8.0.36\n"
    "CREATE TABLE users (id INT PRIMARY KEY, login VARCHAR(64), password_hash CHAR(60));\n"
    "INSERT INTO users VALUES (1,'admin','$2y$10$abcdefghijklmnopqrstuv'),"
    "(2,'alice','$2y$10$zyxwvutsrqponmlkjihgfe');\n"
)
ROBOTS_TXT_BODY = (
    "User-agent: *\n"
    "Disallow: /admin/\n"
    "Disallow: /backup/\n"
    "Sitemap: /sitemap.xml\n"
)
SITEMAP_XML_BODY = (
    '<?xml version="1.0" encoding="UTF-8"?>\n'
    '<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">\n'
    "  <url><loc>/</loc></url>\n"
    "  <url><loc>/form</loc></url>\n"
    "</urlset>\n"
)
CROSSDOMAIN_XML_BODY = (
    '<?xml version="1.0"?>\n'
    '<!DOCTYPE cross-domain-policy SYSTEM "http://www.adobe.com/xml/dtds/cross-domain-policy.dtd">\n'
    "<cross-domain-policy>\n"
    '  <allow-access-from domain="*" to-ports="*" />\n'
    "</cross-domain-policy>\n"
)
STORAGE_HTML = (
    "<html><head><title>Dashboard</title></head><body>"
    "<h1>Dashboard</h1>"
    "<script>"
    "localStorage.setItem('auth_token', 'eyJhbGciOiJIUzI1NiJ9.secret.sig');"
    "sessionStorage.setItem('theme', 'dark');"
    "</script>"
    "</body></html>"
)
SECURE_PAGE_HEADERS = {
    "Content-Security-Policy": "default-src 'self'; script-src 'self' 'nonce-abc123'; frame-ancestors 'none'",
    "Cache-Control": "no-store, no-cache, must-revalidate",
    "X-Frame-Options": "DENY",
    "X-Content-Type-Options": "nosniff",
    "Referrer-Policy": "no-referrer",
}

_FORM_HTML = (
    "<html><head><title>Login form</title></head><body>"
    '<form method="post" action="/form">'
    '<input type="text" name="username" value="alice">'
    '<input type="password" name="password" value="">'
    '<input name="csrf_token" value="' + CSRF_TOKEN + '">'
    '<input type="submit" value="Login">'
    "</form>"
    "</body></html>"
)


def _first(query: dict[str, list[str]], name: str, default: str = "") -> str:
    values = query.get(name)
    return values[0] if values else default


def _ssi_render(param: str) -> str:
    """Эмуляция SSI-обработки: директивы исполняются, ошибки отдаются текстом.

    Покрывает все ветки checks.injections.ssi_indicator:
    marker-output, date, printenv, exec/include, SSI-error.
    """
    low = (param or "").lower()
    if "<!--#" not in low:
        return f"You searched: {html.escape(param)}"
    if "notscan_ssi_marker" in low:
        return SSI_MARKER_OUTPUT
    if "date_local" in low or "date_gmt" in low or "#if" in low or "<!--#set" in low:
        return time.strftime("%Y-%m-%dT%H:%M:%S")
    if "#printenv" in low:
        return SSI_ENV_OUTPUT
    if any(token in low for token in ("#exec", "#include", "#fsize", "#flastmod")):
        return SSI_EXEC_OUTPUT
    return SSI_ERROR_OUTPUT


class _LabHTTPServer(ThreadingHTTPServer):
    """ThreadingHTTPServer с увеличенным backlog'ом.

    Дефолтный ``request_queue_size=5`` на конкурентных сканах (10+ соединений
    разом) упирается в SYN-очередь: клиенты ретраят соединение и получают
    искусственную задержку ~1 c. Для замеров latency/time-based это давало
    искажения, поэтому поднимаем backlog.
    """

    request_queue_size = 128
    daemon_threads = True


class LabServer:
    """HTTP-лаба на 127.0.0.1 с журналом запросов и счётчиками по путям."""

    def __init__(
        self,
        host: str = "127.0.0.1",
        sleep_seconds: float = 4.0,
        probe_clean: bool = False,
    ):
        #: Сколько секунд спит /sleep по time-based payload'у (по контракту — 4.0).
        self.sleep_seconds = float(sleep_seconds)
        self.host = host
        #: True — «чистый» режим для FP-контроля probe-чеков: probe-пути отдают
        #: 404, OPTIONS не рекламирует рискованные методы, CORS не отражается.
        self.probe_clean = bool(probe_clean)

        self._lock = threading.Lock()
        self.requests: list[dict[str, Any]] = []
        self.form_accepted_tokens: list[str] = []
        self.json_bodies: list[Any] = []
        self.invalid_json_bodies: list[bytes] = []

        self._httpd = _LabHTTPServer((host, 0), _LabHandler)
        self._httpd.lab = self  # type: ignore[attr-defined]
        self._thread: Optional[threading.Thread] = None

    # ── жизненный цикл ──────────────────────────────────────────────

    @property
    def port(self) -> int:
        return int(self._httpd.server_address[1])

    @property
    def netloc(self) -> str:
        return f"{self.host}:{self.port}"

    @property
    def base_url(self) -> str:
        return f"http://{self.netloc}"

    def start(self) -> "LabServer":
        if self._thread is None or not self._thread.is_alive():
            self._thread = threading.Thread(
                target=self._httpd.serve_forever,
                kwargs={"poll_interval": 0.05},
                daemon=True,
                name="notscan-lab-server",
            )
            self._thread.start()
        return self

    def stop(self) -> None:
        if self._thread is not None:
            self._httpd.shutdown()
            self._thread.join(timeout=5)
            self._thread = None
        self._httpd.server_close()

    def __enter__(self) -> "LabServer":
        return self.start()

    def __exit__(self, *exc_info) -> None:
        self.stop()

    # ── журнал запросов ─────────────────────────────────────────────

    def _record(self, entry: dict[str, Any]) -> None:
        with self._lock:
            self.requests.append(entry)

    def reset_log(self) -> None:
        with self._lock:
            self.requests.clear()
            self.form_accepted_tokens.clear()
            self.json_bodies.clear()
            self.invalid_json_bodies.clear()

    def requests_for(self, path: str, method: Optional[str] = None) -> list[dict[str, Any]]:
        with self._lock:
            rows = list(self.requests)
        return [
            r for r in rows
            if r["path"] == path and (method is None or r["method"] == method)
        ]

    def count(self, path: Optional[str] = None, method: Optional[str] = None) -> int:
        with self._lock:
            rows = list(self.requests)
        return sum(
            1
            for r in rows
            if (path is None or r["path"] == path)
            and (method is None or r["method"] == method)
        )

    def paths(self) -> list[str]:
        with self._lock:
            return [r["path"] for r in self.requests]

    def statuses_for(self, path: str, method: Optional[str] = None) -> list[int]:
        return [r["status"] for r in self.requests_for(path, method)]

    def __repr__(self) -> str:
        return f"<LabServer {self.base_url} sleep={self.sleep_seconds}s>"


class _LabHandler(BaseHTTPRequestHandler):
    """Обработчик эндпоинтов лабы (маршрутизация в LabServer)."""

    protocol_version = "HTTP/1.1"
    server_version = "NotScanLab/1.0"
    sys_version = ""

    # ── инфраструктура ──────────────────────────────────────────────

    @property
    def lab(self) -> LabServer:
        return self.server.lab  # type: ignore[attr-defined]

    def log_message(self, fmt: str, *args: Any) -> None:  # noqa: A003
        """Тишина: журнал ведёт сам LabServer."""

    def _read_body(self) -> bytes:
        try:
            length = int(self.headers.get("Content-Length") or 0)
        except (TypeError, ValueError):
            length = 0
        return self.rfile.read(length) if length > 0 else b""

    def _send(
        self,
        status: int,
        body: bytes,
        content_type: str = "text/html; charset=utf-8",
        extra_headers: Optional[dict[str, str] | list[tuple[str, str]]] = None,
    ) -> None:
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        # dict — обычные заголовки; list[(name, value)] — для повторяющихся
        # (несколько Set-Cookie).
        if extra_headers is None:
            header_items: list[tuple[str, str]] = []
        elif isinstance(extra_headers, dict):
            header_items = list(extra_headers.items())
        else:
            header_items = list(extra_headers)
        for name, value in header_items:
            # Намеренно без санитизации CR/LF: /redirect должен позволять
            # CRLF-injection (payload с %0d%0a). HTTP/1.1-заголовки при этом
            # обязаны быть latin-1 — непечатаемые/не-latin1 payload'ы
            # экранируем, чтобы BaseHTTPRequestHandler не падал на них.
            try:
                value.encode("latin-1", "strict")
            except UnicodeEncodeError:
                value = value.encode("latin-1", "backslashreplace").decode("latin-1")
            self.send_header(name, value)
        self.end_headers()
        if body:
            self.wfile.write(body)

    def _finish(
        self,
        status: int,
        *,
        text: str = "",
        content_type: str = "text/html; charset=utf-8",
        extra_headers: Optional[dict[str, str] | list[tuple[str, str]]] = None,
        body: Optional[bytes] = None,
    ) -> None:
        method, path, query_raw, query, raw_body = self._pending
        self.lab._record(
            {
                "time": time.time(),
                "method": method,
                "path": path,
                "query": query,
                "query_raw": query_raw,
                "headers": dict(self.headers.items()),
                "body": raw_body,
                "status": status,
            }
        )
        payload = body if body is not None else text.encode("utf-8")
        self._send(status, payload, content_type=content_type, extra_headers=extra_headers)

    def _begin(self, method: str) -> tuple[str, dict[str, list[str]], bytes]:
        parsed = urllib.parse.urlsplit(self.path)
        query = urllib.parse.parse_qs(parsed.query, keep_blank_values=True)
        body = self._read_body()
        self._pending = (method, parsed.path, parsed.query, query, body)
        return parsed.path, query, body

    # ── GET ─────────────────────────────────────────────────────────

    def do_GET(self) -> None:  # noqa: N802
        path, query, _body = self._begin("GET")

        if path == "/reflect":
            q = _first(query, "q")
            self._finish(
                200,
                text=_HTML_HEAD.format(title="Reflect") + f"You searched: {q}" + _HTML_TAIL,
            )
        elif path == "/search":
            q = _first(query, "q")
            self._finish(
                200,
                text=(
                    _HTML_HEAD.format(title="Search")
                    + '<script src="/static/app.js"></script>'
                    + f"You searched: {html.escape(q)}"
                    + _HTML_TAIL
                ),
            )
        elif path == "/sqli":
            param = _first(query, "id")
            if "'" in param or '"' in param:
                self._finish(
                    500,
                    text=_HTML_HEAD.format(title="DB error") + SQL_ERROR_TEXT + _HTML_TAIL,
                )
            else:
                self._finish(
                    200,
                    text=_HTML_HEAD.format(title="Item") + f"Item id: {html.escape(param)}" + _HTML_TAIL,
                )
        elif path == "/blind":
            # Эмуляция boolean-based blind SQLi (см. FIX_CONTRACT round2/task-14):
            #   id=1               → 200 "User: admin"           (baseline)
            #   ... 1=1 / '1'='1   → 200 "User found: admin"     (TRUE)
            #   ... 1=2 / '1'='2   → 404 "User not found"        (FALSE)
            param = _first(query, "id")
            lowered = (param or "").lower()
            if any(marker in lowered for marker in BLIND_FALSE_MARKERS):
                self._finish(
                    404,
                    text=_HTML_HEAD.format(title="User")
                    + "<h1>User not found</h1>"
                    + _HTML_TAIL,
                )
            elif any(marker in lowered for marker in BLIND_TRUE_MARKERS):
                self._finish(
                    200,
                    text=_HTML_HEAD.format(title="User")
                    + "<h1>User found: admin</h1>"
                    + _HTML_TAIL,
                )
            else:
                self._finish(
                    200,
                    text=_HTML_HEAD.format(title="User")
                    + "<h1>User: admin</h1>"
                    + _HTML_TAIL,
                )
        elif path == "/redirect":
            target = _first(query, "url", "/safe")
            self._finish(302, text="", extra_headers={"Location": target})
        elif path == "/sleep":
            param = _first(query, "id")
            lowered = param.lower()
            if any(marker in lowered for marker in SLEEP_PAYLOAD_MARKERS):
                time.sleep(self.lab.sleep_seconds)
            self._finish(
                200,
                text=_HTML_HEAD.format(title="Sleep") + f"Item id: {html.escape(param)}" + _HTML_TAIL,
            )
        elif path == "/slow":
            try:
                ms = float(_first(query, "ms", "0"))
            except ValueError:
                ms = 0.0
            time.sleep(max(0.0, min(ms, 10_000.0)) / 1000.0)
            self._finish(200, text="slow ok", content_type="text/plain; charset=utf-8")
        elif path == "/safe":
            self._finish(
                200,
                text=(
                    _HTML_HEAD.format(title="Safe")
                    + "<h1>Safe page</h1><p>There is no reflection here.</p>"
                    + _HTML_TAIL
                ),
            )
        elif path == "/form":
            self._finish(200, text=_FORM_HTML)
        elif path == "/html":
            q = _first(query, "q")
            self._finish(
                200,
                text=_HTML_HEAD.format(title="HTML") + f"You searched: {q}" + _HTML_TAIL,
            )
        elif path == "/ssi":
            q = _first(query, "q")
            self._finish(
                200,
                text=_HTML_HEAD.format(title="SSI") + _ssi_render(q) + _HTML_TAIL,
            )
        elif path == "/cookie-nosecure":
            self._finish(
                200,
                text=_HTML_HEAD.format(title="Session")
                + "<p>session established</p>"
                + _HTML_TAIL,
                extra_headers=[
                    ("Set-Cookie", "sessionid=SECRET123; Path=/"),
                    ("Set-Cookie", "theme=dark; Path=/"),
                ],
            )
        elif path == "/cookie-secure":
            self._finish(
                200,
                text=_HTML_HEAD.format(title="Session")
                + "<p>session established</p>"
                + _HTML_TAIL,
                extra_headers=[
                    ("Set-Cookie",
                     "sessionid=abc; Path=/; Secure; HttpOnly; SameSite=Lax"),
                ],
            )
        elif path == "/cache-session":
            self._finish(
                200,
                text=_HTML_HEAD.format(title="Session")
                + "<p>session established</p>"
                + _HTML_TAIL,
                extra_headers=[
                    ("Set-Cookie", "sessionid=CACHEABLE123; Path=/; HttpOnly"),
                    ("Vary", "Accept-Encoding"),
                ],
            )
        elif path == "/secure-page":
            self._finish(
                200,
                text=_HTML_HEAD.format(title="Secure")
                + "<p>secured page</p>"
                + _HTML_TAIL,
                extra_headers=list(SECURE_PAGE_HEADERS.items())
                + [("Set-Cookie",
                    "sessionid=abc; Path=/; Secure; HttpOnly; SameSite=Strict")],
            )
        elif path == "/storage":
            self._finish(200, text=STORAGE_HTML)
        elif path == "/cors-reflect":
            origin = (self.headers.get("Origin") or "").strip()
            extra: dict[str, str] = {"Vary": "Origin"}
            if origin and not self.lab.probe_clean:
                extra["Access-Control-Allow-Origin"] = origin
                extra["Access-Control-Allow-Credentials"] = "true"
            body = json.dumps({"ok": True, "origin": origin or None})
            self._finish(200, text=body, content_type="application/json",
                         extra_headers=extra)
        elif path == "/backup.sql":
            if self.lab.probe_clean:
                self._finish(404, text="not found",
                             content_type="text/plain; charset=utf-8")
            else:
                self._finish(200, text=BACKUP_SQL_BODY,
                             content_type="application/sql; charset=utf-8")
        elif path == "/robots.txt":
            if self.lab.probe_clean:
                self._finish(404, text="not found",
                             content_type="text/plain; charset=utf-8")
            else:
                self._finish(200, text=ROBOTS_TXT_BODY,
                             content_type="text/plain; charset=utf-8")
        elif path == "/sitemap.xml":
            if self.lab.probe_clean:
                self._finish(404, text="not found",
                             content_type="text/plain; charset=utf-8")
            else:
                self._finish(200, text=SITEMAP_XML_BODY,
                             content_type="application/xml; charset=utf-8")
        elif path == "/crossdomain.xml":
            if self.lab.probe_clean:
                self._finish(404, text="not found",
                             content_type="text/plain; charset=utf-8")
            else:
                self._finish(200, text=CROSSDOMAIN_XML_BODY,
                             content_type="application/xml; charset=utf-8")
        elif path in ("/", "/index.html"):
            self._finish(
                200,
                text=(
                    _HTML_HEAD.format(title="NotScan lab")
                    + "<h1>NotScan test lab</h1>"
                    + '<p>Endpoints: /reflect /search /sqli /blind /redirect /sleep /slow /safe /form /api/user</p>'
                    + _HTML_TAIL
                ),
            )
        else:
            self._finish(404, text="not found", content_type="text/plain; charset=utf-8")

    def do_OPTIONS(self) -> None:  # noqa: N802
        self._begin("OPTIONS")
        allow = "GET, HEAD, OPTIONS"
        if not self.lab.probe_clean:
            allow = "GET, HEAD, OPTIONS, PUT, DELETE, TRACE"
        self._finish(200, text="", extra_headers={"Allow": allow})

    # ── POST ────────────────────────────────────────────────────────

    def do_POST(self) -> None:  # noqa: N802
        path, _query, body = self._begin("POST")

        if path == "/form":
            try:
                form = urllib.parse.parse_qs(body.decode("utf-8", errors="replace"), keep_blank_values=True)
            except Exception:
                form = {}
            token = (form.get("csrf_token") or [""])[0]
            if token != CSRF_TOKEN:
                self._finish(
                    403,
                    text="CSRF token missing or invalid",
                    content_type="text/plain; charset=utf-8",
                )
                return
            self.lab.form_accepted_tokens.append(token)
            username = (form.get("username") or [""])[0]
            self._finish(200, text=f"form accepted for user={username}")
            return

        if path == "/api/user":
            try:
                data = json.loads(body.decode("utf-8"))
            except (json.JSONDecodeError, UnicodeDecodeError):
                self.lab.invalid_json_bodies.append(body)
                self._finish(
                    400,
                    text="Bad Request: body is not valid JSON",
                    content_type="text/plain; charset=utf-8",
                )
                return
            self.lab.json_bodies.append(data)
            name = data.get("name", "") if isinstance(data, dict) else ""
            if isinstance(name, str) and "'" in name:
                self._finish(
                    500,
                    text=_HTML_HEAD.format(title="DB error") + SQL_ERROR_TEXT + _HTML_TAIL,
                )
                return
            self._finish(
                200,
                text=json.dumps({"ok": True, "received": data}),
                content_type="application/json",
            )
            return

        self._finish(404, text="not found", content_type="text/plain; charset=utf-8")

    def do_PUT(self) -> None:  # noqa: N802
        self._begin("PUT")
        self._finish(405, text="method not allowed", content_type="text/plain; charset=utf-8")

    do_PATCH = do_PUT  # noqa: N815
    do_DELETE = do_PUT  # noqa: N815
