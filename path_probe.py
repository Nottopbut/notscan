"""
path_probe.py — WSTG probe-чеки.

Публичный API:
    run_probe_scan(urls, probe_ids=None, log_cb=print, host_headers=None,
                   extra_headers=None) -> int
    run_info_disclosure_scan(urls, log_cb=print) -> int   # legacy-обёртка

`host_headers` — список заголовков для host-header-injection probe (None/пусто →
дефолт: Host, X-Forwarded-Host, X-Host, Forwarded).
`extra_headers` — дополнительные заголовки probe-клиента (например Cookie/Authorization
для аутентифицированных страниц): [(name, value), ...]; None = без них.

Probe-чеки (kind="probe" в checks/catalog.py, без payload-файлов):
  • sensitive_files       — WSTG-CONF-03/CONF-04: .env, .git/config, бэкапы
                            (*.bak/*.old/*.swp/~), config.php.bak, web.config,
                            phpinfo.php, .aws/credentials, SQL-дампы и т.п.;
  • metafiles             — WSTG-INFO-03: robots.txt, sitemap.xml, security.txt,
                            .well-known/security.txt, humans.txt;
  • ria_policy            — WSTG-CONF-08: crossdomain.xml/clientaccesspolicy.xml
                            с wildcard 'domain="*"';
  • http_methods          — WSTG-CONF-06: OPTIONS Allow (PUT/DELETE/TRACE), TRACE
                          200, PUT/DELETE на уникальном пути → 2xx/3xx;
  • cors                  — WSTG-CLNT-07: отражённый ACAO + Allow-Credentials:true
                            (или ACAO "*" + credentials);
  • host_header_injection — WSTG-INPV-17 (v5: WSTG-INJT-17): Host/X-Forwarded-Host/
                            X-Host/Forwarded с токеном evil-<rand>.notscan.invalid
                            отражается в body/Location/absolute-URL; пробуются пути
                            из scan-list (не статика) + корень хоста, метод GET;
  • info_disclosure_paths — legacy WSTG-CONF-05 (actuator/etcd/swagger/metrics).

Каждая находка пишется в БД: scan_results (check_type=probe_id) +
scan_meta (detector="probe", severity, fingerprint) + scan_requests (сырой ответ).

Сеть — только 127.0.0.1 в тестах; на реальных целях probe'ы делают обычные
GET/OPTIONS/TRACE/PUT/DELETE-запросы по base-URL из scan-list.
"""

from __future__ import annotations

import difflib
import hashlib
import random
import re
import string
from typing import Callable, Iterable, Optional
from urllib.parse import urlparse

import httpx

import db


# ══════════════════════════════════════════════════════════════════
#  Наборы путей
# ══════════════════════════════════════════════════════════════════

# Legacy-набор probe-чека info_disclosure_paths (WSTG-CONF-05): админ/дебаг
# интерфейсы и служебные эндпоинты. Оставлен без изменений для совместимости.
INFO_DISCLOSURE_PATHS = [
    # Spring Boot Actuator
    ("/actuator/env", "Spring Boot Actuator /env"),
    ("/actuator/health", "Spring Boot Actuator /health"),
    ("/actuator/beans", "Spring Boot Actuator /beans"),
    ("/actuator/mappings", "Spring Boot Actuator /mappings"),
    ("/actuator/heapdump", "Spring Boot Actuator /heapdump"),
    ("/actuator", "Spring Boot Actuator"),
    # etcd
    ("/v2/keys", "etcd v2 keys API"),
    ("/version", "etcd version"),
    # env / config
    ("/.env", ".env file"),
    ("/.git/config", ".git config"),
    ("/.git/HEAD", ".git HEAD"),
    ("/.aws/credentials", "AWS credentials file"),
    ("/.docker/config.json", "Docker config"),
    ("/.npmrc", ".npmrc"),
    # server info / status
    ("/phpinfo.php", "PHP info page"),
    ("/server-status", "Apache server-status"),
    ("/server-info", "Apache server-info"),
    # API docs
    ("/swagger-ui.html", "Swagger UI"),
    ("/swagger-ui/index.html", "Swagger UI"),
    ("/v2/api-docs", "Swagger API docs"),
    ("/openapi.json", "OpenAPI spec"),
    # observability
    ("/metrics", "Prometheus metrics"),
    ("/debug/pprof/", "Go pprof"),
    # app internals
    ("/WEB-INF/web.xml", "Java web.xml"),
    ("/web.config", "IIS web.config"),
]

# Backup / unreferenced files (WSTG-CONF-04) + sensitive extensions (CONF-03).
BACKUP_UNREFERENCED_PATHS = [
    # dotfiles / VCS / CI
    ("/.env.local", ".env.local file"),
    ("/.env.production", ".env.production file"),
    ("/.env.backup", ".env backup file"),
    ("/.env.bak", ".env backup file"),
    ("/.svn/entries", ".svn entries"),
    ("/.hg/", "Mercurial repository"),
    ("/.DS_Store", ".DS_Store file"),
    ("/.htaccess", ".htaccess file"),
    ("/.htpasswd", ".htpasswd file"),
    ("/.npmrc", ".npmrc"),
    ("/.aws/credentials", "AWS credentials file"),
    ("/.docker/config.json", "Docker config"),
    # config backups
    ("/config.php.bak", "config.php backup"),
    ("/config.php~", "config.php editor backup"),
    ("/config.old", "config.old backup"),
    ("/configuration.php.bak", "Joomla configuration backup"),
    ("/web.config.bak", "IIS web.config backup"),
    ("/appsettings.json", "ASP.NET appsettings.json"),
    ("/credentials.json", "credentials.json"),
    # DB dumps / site archives
    ("/backup.sql", "SQL dump backup"),
    ("/dump.sql", "SQL dump backup"),
    ("/database.sql", "SQL dump backup"),
    ("/db.sql", "SQL dump backup"),
    ("/backup.zip", "site backup archive"),
    ("/www.zip", "site backup archive"),
    ("/site.tar.gz", "site backup archive"),
    # editor temp / swap files
    ("/index.php~", "index.php editor backup"),
    ("/index.php.swp", "vim swap file"),
    ("/.index.php.swp", "vim swap file"),
    # phpinfo / debug
    ("/info.php", "PHP info page"),
]

# sensitive_files = legacy-набор + backup/unreferenced (дедуп по пути).
def _merge_paths(*groups: Iterable[tuple[str, str]]) -> list[tuple[str, str]]:
    seen: set[str] = set()
    merged: list[tuple[str, str]] = []
    for group in groups:
        for path, label in group:
            if path in seen:
                continue
            seen.add(path)
            merged.append((path, label))
    return merged


SENSITIVE_FILE_PATHS: list[tuple[str, str]] = _merge_paths(
    INFO_DISCLOSURE_PATHS, BACKUP_UNREFERENCED_PATHS
)

# WSTG-INFO-03: webserver metafiles.
METAFILE_PATHS = [
    ("/robots.txt", "robots.txt"),
    ("/sitemap.xml", "sitemap.xml"),
    ("/security.txt", "security.txt"),
    ("/.well-known/security.txt", "well-known security.txt"),
    ("/humans.txt", "humans.txt"),
]

# WSTG-CONF-08: RIA cross-domain policies (wildcard = находка).
RIA_POLICY_PATHS = [
    ("/crossdomain.xml", "Flash cross-domain policy"),
    ("/clientaccesspolicy.xml", "Silverlight client access policy"),
]

_RIA_WILDCARD_RE = re.compile(
    r"""<allow-access-from[^>]*\bdomain\s*=\s*["']\s*\*\s*["']"""
    r"""|<allow-from[^>]*\buri\s*=\s*["']\s*\*\s*["']""",
    re.IGNORECASE,
)

# ID probe-чеков (совпадают с check_id в checks/catalog.py, kind="probe").
PROBE_IDS: tuple[str, ...] = (
    "sensitive_files",
    "metafiles",
    "ria_policy",
    "http_methods",
    "cors",
    "info_disclosure_paths",
    "host_header_injection",
)

# Заголовки, подменяемые в host-header-injection probe (default; GUI может
# передать свой список через run_probe_scan(host_headers=...)).
DEFAULT_HOST_HEADERS: tuple[str, ...] = (
    "Host",
    "X-Forwarded-Host",
    "X-Host",
    "Forwarded",
)
_HOST_HEADER_TOKEN = f"evil-{{rand}}.notscan.invalid"
_HEADER_NAME_RE = re.compile(r"^[A-Za-z0-9!#$%&'*+\-.^_`|~]+$")


def _normalize_extra_headers(
    extra_headers: Optional[Iterable[tuple[str, str]]],
) -> dict[str, str]:
    """Нормализует extra_headers probe-клиента (Cookie-дубликаты — через '; ').

    • невалидные имена/значения (переводы строк) отбрасываются;
    • одинаковые имена (case-insensitive) объединяются: Cookie → '; ', остальные → ', ';
    • имена сохраняются в исходном регистре первого вхождения.
    """
    headers: dict[str, str] = {}
    lowered: dict[str, str] = {}
    for item in extra_headers or []:
        try:
            name, value = item
        except (TypeError, ValueError):
            continue
        name = str(name or "").strip()
        if not name or not _HEADER_NAME_RE.match(name):
            continue
        value = str(value or "").replace("\r", "").replace("\n", "").strip()
        if not value:
            continue
        key_low = name.lower()
        if key_low in lowered:
            real_name = lowered[key_low]
            sep = "; " if key_low == "cookie" else ", "
            headers[real_name] = f"{headers[real_name]}{sep}{value}"
        else:
            lowered[key_low] = name
            headers[name] = value
    return headers


def normalize_host_headers(host_headers: Optional[Iterable[str]]) -> list[str]:
    """Нормализует список заголовков для host-header probe (default при пустоте)."""
    if not host_headers:
        return list(DEFAULT_HOST_HEADERS)
    normalized: list[str] = []
    for raw in host_headers:
        name = str(raw or "").strip()
        if not name or not _HEADER_NAME_RE.match(name):
            continue
        if name.lower() in {h.lower() for h in normalized}:
            continue
        normalized.append(name)
        if len(normalized) >= 10:
            break
    return normalized or list(DEFAULT_HOST_HEADERS)

# Severity для scan_meta (грубая, для триажа в GUI).
_PROBE_SEVERITY = {
    "sensitive_files": "HIGH",
    "metafiles": "INFO",
    "ria_policy": "MEDIUM",
    "http_methods": "MEDIUM",
    "cors": "HIGH",
    "info_disclosure_paths": "MEDIUM",
    "host_header_injection": "HIGH",
}

_USER_AGENT = "notscan-path-probe/2.0 (+WSTG)"
_TRACE_MARKER_HEADER = "X-Notscan-Trace"


# ══════════════════════════════════════════════════════════════════
#  Helpers
# ══════════════════════════════════════════════════════════════════

def _base_url(url: str) -> str:
    p = urlparse(url or "")
    if not p.scheme or not p.netloc:
        return ""
    return f"{p.scheme}://{p.netloc}"


def _collect_base_urls(urls: Iterable[str]) -> list[str]:
    base_urls: list[str] = []
    for u in urls or []:
        b = _base_url(str(u))
        if b and b not in base_urls:
            base_urls.append(b)
    return base_urls


def _rand_token(n: int = 8) -> str:
    return "".join(random.choices(string.ascii_lowercase + string.digits, k=n))


def _fingerprint(url: str, probe_id: str, param: str = "") -> str:
    """Стабильный ключ дедупликации (как scanner_core._fingerprint_for_result)."""
    try:
        parsed = urlparse(url)
        host = (parsed.hostname or "").lower()
        path = (parsed.path or "/").lower()
    except Exception:
        host, path = "", ""
    raw = f"{host}|{path}|{probe_id.lower()}|{(param or '').lower()}"
    return hashlib.sha256(raw.encode("utf-8", errors="ignore")).hexdigest()[:24]


def _norm_body(body: str) -> str:
    return re.sub(r"\s+", " ", (body or "")).strip()[:4000]


def _is_soft_404(body: str, baseline_body: str) -> bool:
    """
    True, если ответ неотличим от ответа на заведомо несуществующий путь
    (SPA/nginx catch-all, отдающие 200 на всё) — это не находка.
    """
    if not baseline_body:
        return False
    if body == baseline_body:
        return True
    a, b = _norm_body(body), _norm_body(baseline_body)
    if not a or not b:
        return False
    return difflib.SequenceMatcher(None, a[:2000], b[:2000]).quick_ratio() > 0.9


# Короткое «вежливое» тело 200-ответа от WAF/фильтра — не раскрытие файла.
_DENIAL_RE = re.compile(
    r"(access\s+denied|forbidden|not\s+found|request\s+(?:rejected|blocked)|"
    r"blocked\s+by|page\s+not\s+available|403\s+forbidden|404\s+not\s+found|"
    r"unauthori[sz]ed)",
    re.IGNORECASE,
)


def _looks_like_denial(resp: httpx.Response, body: str) -> bool:
    """True для WAF/фильтр-заглушек: маленький 200-ответ с «access denied»."""
    if len(body) > 1024:
        return False
    return bool(_DENIAL_RE.search(body))


class _ProbeContext:
    """Состояние одного запуска probe-скана: клиент, базы, soft-404 baseline."""

    def __init__(self, client: httpx.Client, base_urls: list[str],
                 scan_urls: Optional[list[str]] = None,
                 host_headers: Optional[Iterable[str]] = None,
                 extra_headers: Optional[Iterable[tuple[str, str]]] = None,
                 log_cb: Callable[[str], None] = print):
        self.client = client
        self.base_urls = base_urls
        # Полные URL из scan-list (для проверок, привязанных к конкретному пути,
        # например CORS: Origin отправляем и на сам сканируемый эндпоинт).
        self.scan_urls = list(scan_urls or [])
        # Заголовки для host-header-injection probe (None → DEFAULT_HOST_HEADERS).
        self.host_headers = normalize_host_headers(host_headers)
        # Доп. заголовки probe-клиента (Cookie/Authorization для auth-страниц).
        self.extra_headers = _normalize_extra_headers(extra_headers)
        self.log_cb = log_cb
        self._baselines: dict[str, str] = {}
        self.found = 0

    # ── HTTP ──────────────────────────────────────────────────────
    def request(self, method: str, url: str, **kwargs) -> Optional[httpx.Response]:
        try:
            return self.client.request(method, url, **kwargs)
        except Exception as exc:
            self.log_cb(f"[PROBE][WARN] {method} {url[:90]}: {exc}")
            return None

    def baseline_body(self, base: str) -> str:
        """Тело ответа на заведомо несуществующий путь (soft-404 baseline)."""
        if base in self._baselines:
            return self._baselines[base]
        resp = self.request("GET", f"{base}/notscan-probe-{_rand_token(10)}")
        body = (resp.text or "") if resp is not None else ""
        self._baselines[base] = body
        return body

    # ── DB ────────────────────────────────────────────────────────
    def record(
        self,
        *,
        probe_id: str,
        url: str,
        method: str = "GET",
        path: str = "",
        status_code: int = 200,
        evidence: str = "",
        severity: Optional[str] = None,
        confidence: float = 0.55,
        exploitability: float = 0.2,
        resp_text: str = "",
        resp_headers: Optional[dict] = None,
        raw_request: str = "",
    ) -> bool:
        """Записать находку probe-чека в scan_results/scan_meta/scan_requests."""
        sev = severity or _PROBE_SEVERITY.get(probe_id, "MEDIUM")
        try:
            result_id = db.insert_scan_result(
                template_id=f"probe-{probe_id}-{url}",
                worker_id=0,
                method=method,
                url=url,
                status_code=status_code,
                error=None,
                check_type=probe_id,
                payload=path,
                evidence=evidence,
            )
            db.upsert_scan_meta(
                scan_result_id=result_id,
                payload_class=probe_id,
                detector="probe",
                confidence=confidence,
                severity=sev,
                exploitability=exploitability,
                fingerprint=_fingerprint(url, probe_id, path),
            )
            host = urlparse(url).netloc
            db.insert_scan_request(
                scan_result_id=result_id,
                raw_request=raw_request or f"{method} {path or '/'} HTTP/1.1\nHost: {host}\n\n",
                raw_response_preview=(resp_text or "")[:2048],
                resp_status=status_code,
                resp_headers=resp_headers or {},
            )
            self.found += 1
            self.log_cb(f"[PROBE][{sev}] {probe_id}: {evidence} | {url[:100]}")
            return True
        except Exception as exc:  # запись в БД не должна ронять скан
            self.log_cb(f"[PROBE][ERR] {probe_id} {url[:80]}: {exc}")
            return False


# ══════════════════════════════════════════════════════════════════
#  Probe 1/6: sensitive_files — WSTG-CONF-03 / CONF-04
# ══════════════════════════════════════════════════════════════════

# Пути, раскрытие которых особенно критично (весь файл целиком = секреты).
_HIGH_RISK_PATH_HINTS = (
    ".env", ".git/", ".aws/", ".docker/", ".npmrc", "credentials",
    ".sql", ".zip", ".tar.gz", "config.php", "web.config", "backup",
    "swagger", "actuator", "phpinfo",
)


def _probe_sensitive_files(ctx: _ProbeContext) -> int:
    for base in ctx.base_urls:
        baseline = ctx.baseline_body(base)
        for path, label in SENSITIVE_FILE_PATHS:
            url = base + path
            resp = ctx.request("GET", url)
            if resp is None or resp.status_code != 200:
                continue
            body = resp.text or ""
            if not body.strip():
                continue
            if _is_soft_404(body, baseline) or _looks_like_denial(resp, body):
                continue
            high = any(h in path.lower() for h in _HIGH_RISK_PATH_HINTS)
            ctx.record(
                probe_id="sensitive_files",
                url=url,
                path=path,
                status_code=resp.status_code,
                evidence=(f"[WSTG-CONF-03/04] {label} доступен по {path} "
                          f"(HTTP 200, {len(body)}B)"),
                severity="HIGH" if high else "MEDIUM",
                confidence=0.7 if high else 0.55,
                exploitability=0.6 if high else 0.3,
                resp_text=body,
                resp_headers=dict(resp.headers),
            )
    return ctx.found


# ══════════════════════════════════════════════════════════════════
#  Probe 2/6: metafiles — WSTG-INFO-03
# ══════════════════════════════════════════════════════════════════

def _probe_metafiles(ctx: _ProbeContext) -> int:
    for base in ctx.base_urls:
        baseline = ctx.baseline_body(base)
        for path, label in METAFILE_PATHS:
            url = base + path
            resp = ctx.request("GET", url)
            if resp is None or resp.status_code != 200:
                continue
            body = resp.text or ""
            if (not body.strip() or _is_soft_404(body, baseline)
                    or _looks_like_denial(resp, body)):
                continue
            snippet = body.strip().splitlines()[0][:120] if body.strip() else ""
            ctx.record(
                probe_id="metafiles",
                url=url,
                path=path,
                status_code=resp.status_code,
                evidence=f"[WSTG-INFO-03] {label} доступен: {snippet}",
                severity="INFO",
                confidence=0.5,
                exploitability=0.05,
                resp_text=body,
                resp_headers=dict(resp.headers),
            )
    return ctx.found


# ══════════════════════════════════════════════════════════════════
#  Probe 3/6: ria_policy — WSTG-CONF-08
# ══════════════════════════════════════════════════════════════════

def _probe_ria_policy(ctx: _ProbeContext) -> int:
    for base in ctx.base_urls:
        baseline = ctx.baseline_body(base)
        for path, label in RIA_POLICY_PATHS:
            url = base + path
            resp = ctx.request("GET", url)
            if resp is None or resp.status_code != 200:
                continue
            body = resp.text or ""
            if not body.strip() or _is_soft_404(body, baseline):
                continue
            m = _RIA_WILDCARD_RE.search(body)
            if not m:
                continue
            ctx.record(
                probe_id="ria_policy",
                url=url,
                path=path,
                status_code=resp.status_code,
                evidence=(f"[WSTG-CONF-08] {label} разрешает любой origin — "
                          f"wildcard: '{m.group()[:120]}'"),
                severity="MEDIUM",
                confidence=0.8,
                exploitability=0.4,
                resp_text=body,
                resp_headers=dict(resp.headers),
            )
    return ctx.found


# ══════════════════════════════════════════════════════════════════
#  Probe 4/6: http_methods — WSTG-CONF-06
# ══════════════════════════════════════════════════════════════════

_RISKY_METHODS = ("PUT", "DELETE", "TRACE", "PATCH", "CONNECT")


def _probe_http_methods(ctx: _ProbeContext) -> int:
    for base in ctx.base_urls:
        # 1) OPTIONS: какие методы сервер сам объявляет в Allow.
        resp = ctx.request("OPTIONS", base + "/")
        if resp is not None and resp.status_code < 500:
            allow = resp.headers.get("allow", "") or resp.headers.get("Allow", "")
            risky = [m for m in _RISKY_METHODS if m in allow.upper()]
            if risky:
                ctx.record(
                    probe_id="http_methods",
                    url=base + "/",
                    method="OPTIONS",
                    path="/",
                    status_code=resp.status_code,
                    evidence=(f"[WSTG-CONF-06] OPTIONS Allow содержит "
                              f"{', '.join(risky)} (Allow: {allow[:200]})"),
                    severity="MEDIUM",
                    confidence=0.7,
                    exploitability=0.35,
                    resp_text=resp.text or "",
                    resp_headers=dict(resp.headers),
                )

        # 2) TRACE: 200 = XST/Cross-Site Tracing возможен (безопасный запрос).
        token = _rand_token(12)
        resp = ctx.request(
            "TRACE", base + "/",
            headers={_TRACE_MARKER_HEADER: token},
        )
        if resp is not None and resp.status_code == 200:
            echoed = token in (resp.text or "")
            ctx.record(
                probe_id="http_methods",
                url=base + "/",
                method="TRACE",
                path="/",
                status_code=resp.status_code,
                evidence=("[WSTG-CONF-06] TRACE включён (HTTP 200"
                          + (", заголовки отражаются" if echoed else "") + ")"),
                severity="MEDIUM",
                confidence=0.75,
                exploitability=0.3,
                resp_text=resp.text or "",
                resp_headers=dict(resp.headers),
            )

        # 3) PUT/DELETE на УНИКАЛЬНОМ несуществующем пути: 2xx/3xx = метод
        #    реально выполняется. PUT выполняется раньше DELETE, поэтому если
        #    сервер создал файл, DELETE его же и уберёт (cleanup).
        probe_path = f"/notscan-method-{_rand_token(10)}.txt"
        for method in ("PUT", "DELETE"):
            url = base + probe_path
            # Тело нужно только PUT (проверка записи); DELETE — без body.
            # Connection: close — если сервер не прочитает тело, соединение не
            # останется «отравленным» для последующих probe-запросов.
            body = b"notscan-method-probe\n" if method == "PUT" else None
            resp = ctx.request(
                method, url, content=body, headers={"Connection": "close"},
            )
            if resp is None:
                continue
            if 200 <= resp.status_code < 400:
                ctx.record(
                    probe_id="http_methods",
                    url=url,
                    method=method,
                    path=probe_path,
                    status_code=resp.status_code,
                    evidence=(f"[WSTG-CONF-06] {method} на {probe_path} вернул "
                              f"HTTP {resp.status_code} — опасный HTTP-метод разрешён"),
                    severity="MEDIUM",
                    confidence=0.65,
                    exploitability=0.4,
                    resp_text=resp.text or "",
                    resp_headers=dict(resp.headers),
                )
    return ctx.found


# ══════════════════════════════════════════════════════════════════
#  Probe 5/6: cors — WSTG-CLNT-07
# ══════════════════════════════════════════════════════════════════

def _header_ci(headers, name: str) -> str:
    if not headers:
        return ""
    target = name.lower()
    for key, value in headers.items():
        if str(key).lower() == target:
            return str(value)
    return ""


def _path_candidate_urls(ctx: _ProbeContext, cap: int = 25) -> list[str]:
    """URL'ы для path/route-зависимых проб: сканируемые эндпоинты + корень хоста.

    CORS/host-header политика может отличаться per-route, поэтому проба идёт и
    на конкретные URL из scan-list (без фрагмента), и на base-URL. Ограничиваем
    число кандидатов, чтобы скан-list из сотен URL не раздувал probe.
    """
    candidates: list[str] = []
    seen: set[str] = set()

    def _add(url: str) -> None:
        url = (url or "").strip()
        if not url:
            return
        parsed = urlparse(url)
        if not parsed.scheme or not parsed.netloc:
            return
        # Без фрагмента; query сохраняем (эндпоинт может зависеть от параметров).
        key = f"{parsed.scheme}://{parsed.netloc}{parsed.path or '/'}?{parsed.query}"
        if key in seen:
            return
        seen.add(key)
        candidates.append(url.split("#", 1)[0])

    for url in ctx.scan_urls:
        _add(url)
        if len(candidates) >= cap:
            break
    for base in ctx.base_urls:
        _add(base + "/")
    return candidates


def _cors_candidate_urls(ctx: _ProbeContext) -> list[str]:
    """Backward-compatible alias для CORS-пробы."""
    return _path_candidate_urls(ctx)


# Статика: host-header пробовать бессмысленно (и шумно) — отфильтровываем.
_STATIC_PATH_EXTENSIONS = frozenset({
    ".css", ".js", ".mjs", ".map", ".png", ".jpg", ".jpeg", ".gif", ".svg",
    ".ico", ".webp", ".avif", ".bmp", ".woff", ".woff2", ".ttf", ".eot",
    ".otf", ".mp4", ".webm", ".mp3", ".pdf", ".swf", ".wasm",
})


def _is_static_path(path: str) -> bool:
    low = (path or "").lower().rstrip("/")
    return any(low.endswith(ext) for ext in _STATIC_PATH_EXTENSIONS)


def _host_header_candidate_urls(ctx: _ProbeContext, cap: int = 10) -> list[str]:
    """URL'ы для host-header probe: пути из scan-list (не статика) + корни хостов.

    bWAPP-кейс: отражение Host есть только в `hostheader_1.php` (при Cookie), а
    base-URL `/` отдаёт редирект без отражения — поэтому пробуем конкретные пути
    из scan-list. Метод всегда GET (даже если исходный запрос был POST); query
    сохраняем. Ограничение `cap` — чтобы не раздувать probe.
    """
    candidates: list[str] = []
    seen: set[tuple[str, str]] = set()

    def _add(url: str) -> bool:
        parsed = urlparse(url or "")
        if not parsed.scheme or not parsed.netloc:
            return False
        path = parsed.path or "/"
        key = (parsed.netloc.lower(), path.lower())
        if key in seen:
            return False
        seen.add(key)
        candidates.append(url.split("#", 1)[0])
        return True

    for url in ctx.scan_urls:
        parsed = urlparse(url or "")
        if not parsed.scheme or not parsed.netloc:
            continue
        path = parsed.path or "/"
        if path in ("", "/") or _is_static_path(path):
            continue
        if _add(url) and len(candidates) >= cap:
            break
    # Фолбэк: корень каждого хоста (часть целей отражает Host и там).
    for base in ctx.base_urls:
        if len(candidates) >= cap:
            break
        _add(base + "/")
    return candidates


def _probe_cors(ctx: _ProbeContext) -> int:
    tested_bases: set[str] = set()
    for url in _path_candidate_urls(ctx):
        origin = f"https://evil-{_rand_token(10)}.com"
        resp = ctx.request("GET", url, headers={"Origin": origin})
        if resp is None:
            continue
        acao = _header_ci(resp.headers, "access-control-allow-origin").strip()
        acac = _header_ci(resp.headers, "access-control-allow-credentials").strip().lower()
        if not acao:
            continue
        reflected = acao == origin
        wildcard = acao == "*"
        if acac != "true":
            # Контракт: находка — только credentials=true (иначе это не
            # даёт читать аутентифицированные данные; без креденшелов — шум).
            continue
        base = _base_url(url)
        if base in tested_bases:
            # На один хост — максимум одна CORS-находка (без дублей по путям).
            continue
        tested_bases.add(base)
        if reflected:
            ctx.record(
                probe_id="cors",
                url=url,
                method="GET",
                path=urlparse(url).path or "/",
                status_code=resp.status_code,
                evidence=(f"[WSTG-CLNT-07] CORS отражает произвольный Origin "
                          f"'{origin}' и разрешает credentials (ACAO + "
                          f"Access-Control-Allow-Credentials: true) на {url[:100]}"),
                severity="HIGH",
                confidence=0.85,
                exploitability=0.6,
                resp_text=resp.text or "",
                resp_headers=dict(resp.headers),
                raw_request=(f"GET {urlparse(url).path or '/'} HTTP/1.1\n"
                             f"Host: {urlparse(url).netloc}\nOrigin: {origin}\n\n"),
            )
        elif wildcard:
            ctx.record(
                probe_id="cors",
                url=url,
                method="GET",
                path=urlparse(url).path or "/",
                status_code=resp.status_code,
                evidence=("[WSTG-CLNT-07] CORS: Access-Control-Allow-Origin: * "
                          "вместе с Access-Control-Allow-Credentials: true"),
                severity="HIGH",
                confidence=0.8,
                exploitability=0.5,
                resp_text=resp.text or "",
                resp_headers=dict(resp.headers),
            )
    return ctx.found


# ══════════════════════════════════════════════════════════════════
#  Probe 6/6: info_disclosure_paths — WSTG-CONF-05 (legacy-набор)
# ══════════════════════════════════════════════════════════════════

def _probe_info_disclosure_paths(ctx: _ProbeContext) -> int:
    for base in ctx.base_urls:
        baseline = ctx.baseline_body(base)
        for path, label in INFO_DISCLOSURE_PATHS:
            url = base + path
            resp = ctx.request("GET", url)
            if resp is None or resp.status_code != 200:
                continue
            body = resp.text or ""
            if (not body.strip() or _is_soft_404(body, baseline)
                    or _looks_like_denial(resp, body)):
                continue
            ctx.record(
                probe_id="info_disclosure_paths",
                url=url,
                path=path,
                status_code=resp.status_code,
                evidence=f"[WSTG-CONF-05] {label} доступен по {path} (HTTP 200)",
                severity="MEDIUM",
                confidence=0.55,
                exploitability=0.2,
                resp_text=body,
                resp_headers=dict(resp.headers),
            )
    return ctx.found


# ══════════════════════════════════════════════════════════════════
#  Probe 7/7: host_header_injection — WSTG-INPV-17 / INJT-17 (v5)
# ══════════════════════════════════════════════════════════════════

_ABS_URL_TOKEN_RE_TMPL = r"(?:https?:)?//{token}"


def _probe_host_header_injection(ctx: _ProbeContext) -> int:
    """Host/X-Forwarded-Host/... → отражение токена в body/Location/absolute-URL.

    Один finding на host (дедуп по первому сработавшему заголовку).
    """
    found_hosts: set[str] = set()
    for candidate in _host_header_candidate_urls(ctx):
        base = _base_url(candidate)
        if not base or base in found_hosts:
            continue
        baseline = ctx.baseline_body(base)
        token = _HOST_HEADER_TOKEN.format(rand=_rand_token(10))
        abs_url_re = re.compile(_ABS_URL_TOKEN_RE_TMPL.format(
            token=re.escape(token)), re.IGNORECASE)
        for header_name in ctx.host_headers:
            resp = ctx.request("GET", candidate, headers={header_name: token})
            if resp is None:
                continue
            body = resp.text or ""
            # WAF/фильтр-заглушка и soft-404 (SPA catch-all) — не отражение.
            if _looks_like_denial(resp, body):
                continue
            if _is_soft_404(body, baseline):
                continue

            location = _header_ci(resp.headers, "location").strip()
            where: list[str] = []
            if token in body:
                where.append("body")
            if token in location:
                where.append("Location")
            if abs_url_re.search(body):
                where.append("absolute URL")
            if not where:
                continue

            parsed_candidate = urlparse(candidate)
            ctx.record(
                probe_id="host_header_injection",
                url=candidate,
                method="GET",
                path=parsed_candidate.path or "/",
                status_code=resp.status_code,
                evidence=(f"[WSTG-INPV-17] Заголовок '{header_name}' с токеном "
                          f"'{token}' отражается в {', '.join(where)} на "
                          f"{parsed_candidate.path or '/'} — возможна host-header "
                          f"injection (password-reset/cache poisoning)"),
                severity="HIGH",
                confidence=0.75,
                exploitability=0.55,
                resp_text=body,
                resp_headers=dict(resp.headers),
                raw_request=(f"GET {parsed_candidate.path or '/'} HTTP/1.1\n"
                             f"Host: {parsed_candidate.netloc}\n"
                             f"{header_name}: {token}\n\n"),
            )
            found_hosts.add(base)   # 1 finding на host
            break
    return ctx.found


_PROBE_HANDLERS: dict[str, Callable[[_ProbeContext], int]] = {
    "sensitive_files": _probe_sensitive_files,
    "metafiles": _probe_metafiles,
    "ria_policy": _probe_ria_policy,
    "http_methods": _probe_http_methods,
    "cors": _probe_cors,
    "info_disclosure_paths": _probe_info_disclosure_paths,
    "host_header_injection": _probe_host_header_injection,
}


# ══════════════════════════════════════════════════════════════════
#  Публичный API
# ══════════════════════════════════════════════════════════════════

def run_probe_scan(
    urls: list[str],
    probe_ids: Optional[Iterable[str]] = None,
    log_cb: Callable[[str], None] = print,
    host_headers: Optional[Iterable[str]] = None,
    extra_headers: Optional[Iterable[tuple[str, str]]] = None,
) -> int:
    """
    Запустить probe-чеки по base-URL сканируемых хостов.

    Args:
        urls: URL из scan-list (используется только scheme://host[:port]).
        probe_ids: какие probe-чеки запускать (по умолчанию — все PROBE_IDS).
        log_cb: callback для лога GUI.
        host_headers: заголовки для host-header-injection probe; None/пусто →
            DEFAULT_HOST_HEADERS (Host, X-Forwarded-Host, X-Host, Forwarded).
        extra_headers: дополнительные заголовки для всех probe-запросов
            (например [("Cookie", "PHPSESSID=...")]) — probe на auth-страницах.

    Returns:
        Количество находок (записей в scan_results).
    """
    base_urls = _collect_base_urls(urls)
    if not base_urls:
        log_cb("[PROBE] No valid URLs — path probe skipped")
        return 0

    if probe_ids is None:
        selected = list(PROBE_IDS)
    else:
        selected = []
        for pid in probe_ids:
            pid = str(pid or "").strip().lower()
            if pid and pid in _PROBE_HANDLERS and pid not in selected:
                selected.append(pid)
        if not selected:
            log_cb(f"[PROBE] No known probe ids in {list(probe_ids)!r} — skipped")
            return 0

    log_cb(f"[PROBE] Starting {', '.join(selected)} for {len(base_urls)} host(s)")
    client_headers: dict[str, str] = {"User-Agent": _USER_AGENT}
    extra = _normalize_extra_headers(extra_headers)
    for name, value in extra.items():
        if name.lower() == "user-agent":
            continue  # не перетираем UA probe-клиента
        client_headers[name] = value
    client = httpx.Client(
        verify=False,
        timeout=10.0,
        follow_redirects=False,
        headers=client_headers,
    )
    try:
        ctx = _ProbeContext(client, base_urls, scan_urls=list(urls or []),
                            host_headers=host_headers,
                            extra_headers=extra, log_cb=log_cb)
        for probe_id in selected:
            try:
                _PROBE_HANDLERS[probe_id](ctx)
            except Exception as exc:  # один probe не должен ломать остальные
                log_cb(f"[PROBE][ERR] {probe_id}: {exc}")
    finally:
        try:
            client.close()
        except Exception:
            pass

    log_cb(f"[PROBE] Done — {ctx.found} finding(s) across {len(base_urls)} "
           f"host(s) via {len(selected)} probe(s)")
    return ctx.found


def run_info_disclosure_scan(
    urls: list[str],
    log_cb: Callable[[str], None] = print,
) -> int:
    """Legacy-API: probe только по чувствительным путям (WSTG-CONF-05).

    Сохранён для старых вызовов/тестов; внутри — run_probe_scan.
    """
    return run_probe_scan(urls, probe_ids=["info_disclosure_paths"], log_cb=log_cb)
