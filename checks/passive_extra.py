"""
checks/passive_extra.py — Новые passive WSTG-чеки.

Все чеки работают только с уже полученным ответом (passive=True,
requires_payload=False) — новых сетевых запросов не делают.

  1. cookies        — WSTG-SESS-02: Set-Cookie без Secure/HttpOnly/SameSite
  2. hsts           — WSTG-CONF-07: HTTPS-ответ без Strict-Transport-Security/max-age
  3. csp            — WSTG-CONF-12 (v5): отсутствие/небезопасный Content-Security-Policy
  4. cache_control  — WSTG-ATHN-06: чувствительный ответ без Cache-Control: no-store/private
  5. insecure_login — WSTG-ATHN-01/CRYP-03: логин/пароль/Authorization по http://
  6. browser_storage— WSTG-CLNT-12: секреты/токены в localStorage/sessionStorage

Чеки регистрируются в checks/registry.CheckRegistry (см. ALL_EXTRA_PASSIVE_CHECKS).
"""

from __future__ import annotations

import re
from urllib.parse import urlparse

from .base import (
    BaseCheck, CheckContext, CheckResult,
    ScanRequest, ScanResponse, Severity, VulnCategory,
)
from .fp_rules import is_html_response


# ══════════════════════════════════════════════════════════════════
#  Общие helpers
# ══════════════════════════════════════════════════════════════════

# Имена cookie, которые почти всегда несут аутентификацию/сессию.
_SESSION_COOKIE_HINTS = (
    "sess", "sid", "auth", "token", "jwt", "login", "user", "csrf", "xsrf",
    "remember", "access", "refresh", "id_token", "jsessionid", "phpsessid",
    "asp.net_sessionid", "laravel_session", "ci_session", "connect.sid",
)
# Известные «безобидные» cookie (аналитика/тема/язык): их отсутствие флагов —
# шум, а не уязвимость. Не подавляем находки для сессионных имён.
_BENIGN_COOKIE_HINTS = (
    "theme", "lang", "locale", "consent", "cookie_consent", "gdpr",
    "_ga", "_gid", "_gat", "_fbp", "_gcl", "_hj", "_ym", "utm",
)


def _get_header(headers: dict | None, name: str) -> str:
    """Case-insensitive lookup значения заголовка ("" если нет)."""
    if not headers:
        return ""
    if name in headers:
        return str(headers[name])
    lowered = name.lower()
    for key, value in headers.items():
        if str(key).lower() == lowered:
            return str(value)
    return ""


def _has_header(headers: dict | None, name: str) -> bool:
    if not headers:
        return False
    lowered = name.lower()
    return any(str(k).lower() == lowered for k in headers.keys())


def _header_items(headers: dict | None, name: str) -> list[str]:
    """Все значения заголовка (учёт списков/склеенных значений)."""
    if not headers:
        return []
    lowered = name.lower()
    values: list[str] = []
    for key, value in headers.items():
        if str(key).lower() != lowered:
            continue
        if isinstance(value, (list, tuple)):
            values.extend(str(v) for v in value)
        else:
            values.append(str(value))
    return values


_SET_COOKIE_SPLIT_RE = re.compile(r",\s*(?=[A-Za-z0-9!#$%&'*+\-.^_`|~]+=)")


def _iter_raw_cookies(headers: dict | None) -> list[str]:
    """Разбивает (возможно склеенные) значения Set-Cookie на отдельные cookie."""
    chunks: list[str] = []
    for raw in _header_items(headers, "set-cookie"):
        chunks.extend(p for p in _SET_COOKIE_SPLIT_RE.split(raw) if p.strip())
    return chunks


class _Cookie:
    __slots__ = ("name", "flags", "raw")

    def __init__(self, name: str, flags: set[str], raw: str):
        self.name = name
        self.flags = flags
        self.raw = raw

    @property
    def secure(self) -> bool:
        return "secure" in self.flags

    @property
    def httponly(self) -> bool:
        return "httponly" in self.flags

    @property
    def samesite(self) -> str:
        for f in self.flags:
            if f.startswith("samesite="):
                return f.split("=", 1)[1].strip()
        return ""


def _parse_cookies(headers: dict | None) -> list[_Cookie]:
    parsed: list[_Cookie] = []
    for chunk in _iter_raw_cookies(headers):
        head = chunk.split(";", 1)[0].strip()
        name, sep, _value = head.partition("=")
        name = name.strip()
        if not sep or not name:
            continue
        flags = {a.strip().lower() for a in chunk.split(";")[1:] if a.strip()}
        parsed.append(_Cookie(name, flags, chunk.strip()))
    return parsed


def _is_benign_cookie(name: str) -> bool:
    low = (name or "").lower()
    return any(h in low for h in _BENIGN_COOKIE_HINTS)


def _is_session_cookie(name: str) -> bool:
    low = (name or "").lower()
    return any(h in low for h in _SESSION_COOKIE_HINTS)


def _body_text(resp: ScanResponse, limit: int = 200_000) -> str:
    return (resp.text or "")[:limit]


# ══════════════════════════════════════════════════════════════════
#  1. Cookie Attributes — WSTG-SESS-02
# ══════════════════════════════════════════════════════════════════

class CookiesCheck(BaseCheck):
    """Set-Cookie без Secure (на HTTPS) / HttpOnly / SameSite."""

    check_id = "cookies"
    vuln_type = "cookies"
    category = VulnCategory.AUTH
    severity = Severity.MEDIUM
    name = "Cookie Attributes (Secure/HttpOnly/SameSite)"
    description = "WSTG-SESS-02: cookie без Secure/HttpOnly/SameSite"
    cwe = "CWE-614"
    passive = True
    requires_payload = False

    MAX_FINDINGS = 5

    def check(self, req: ScanRequest, resp: ScanResponse, ctx: CheckContext) -> CheckResult:
        if not self.enabled:
            return self.skip()

        cookies = _parse_cookies(resp.headers)
        if not cookies:
            return self.ok()

        is_https = urlparse(req.url or "").scheme.lower() == "https"
        findings = []
        for cookie in cookies:
            if _is_benign_cookie(cookie.name):
                continue
            missing = []
            # Secure имеет смысл требовать только от HTTPS-ответа: на http
            # браузер всё равно не отправит Secure-cookie обратно.
            if is_https and not cookie.secure:
                missing.append("Secure")
            if not cookie.httponly:
                missing.append("HttpOnly")
            if not cookie.samesite:
                missing.append("SameSite")
            if not missing:
                continue

            high = _is_session_cookie(cookie.name) or cookie.name.startswith(("__Host-", "__Secure-"))
            findings.append(self.make_finding(
                f"Cookie '{cookie.name}' без атрибутов: {', '.join(missing)}",
                req, resp, ctx,
                severity=Severity.HIGH if high else Severity.MEDIUM,
                recommendation=(
                    "Установи Secure; HttpOnly; SameSite=Lax/Strict для сессионных "
                    "cookie и не храни в них секреты."
                ),
                cwe=self.cwe,
            ))
            if len(findings) >= self.MAX_FINDINGS:
                break

        if findings:
            return self.found(*findings)
        return self.ok()


# ══════════════════════════════════════════════════════════════════
#  2. HSTS — WSTG-CONF-07
# ══════════════════════════════════════════════════════════════════

class HSTSCheck(BaseCheck):
    """HTTPS-ответ без Strict-Transport-Security (или с max-age=0)."""

    check_id = "hsts"
    vuln_type = "hsts"
    category = VulnCategory.MISCONFIG
    severity = Severity.MEDIUM
    name = "Missing / Weak HSTS"
    description = "WSTG-CONF-07: HTTPS-ответ без HSTS/max-age"
    cwe = "CWE-319"
    passive = True
    requires_payload = False

    MIN_MAX_AGE = 86400  # сутки; меньше — слабая политика

    def check(self, req: ScanRequest, resp: ScanResponse, ctx: CheckContext) -> CheckResult:
        if not self.enabled:
            return self.skip()

        # HSTS применим только к HTTPS-ответам.
        if urlparse(req.url or "").scheme.lower() != "https":
            return self.skip()
        if resp.status_code and not (200 <= resp.status_code < 400):
            return self.skip()

        if not _has_header(resp.headers, "strict-transport-security"):
            return self.found(self.make_finding(
                "HTTPS-ответ без заголовка Strict-Transport-Security — "
                "возможен SSL-stripping / downgrade на http://",
                req, resp, ctx,
                recommendation="Strict-Transport-Security: max-age=31536000; includeSubDomains",
                cwe=self.cwe,
            ))

        hsts = _get_header(resp.headers, "strict-transport-security")
        m = re.search(r"max-age\s*=\s*\"?(\d+)", hsts, re.IGNORECASE)
        if not m:
            return self.found(self.make_finding(
                f"Strict-Transport-Security без max-age: '{hsts[:120]}'",
                req, resp, ctx,
                recommendation="Добавь max-age (>= 86400, лучше 31536000).",
                cwe=self.cwe,
            ))
        try:
            max_age = int(m.group(1))
        except ValueError:
            max_age = 0
        if max_age <= 0:
            return self.found(self.make_finding(
                f"HSTS отключён: max-age={max_age} ('{hsts[:120]}')",
                req, resp, ctx,
                recommendation="max-age=0 отключает HSTS — задай >= 31536000.",
                cwe=self.cwe,
            ))
        if max_age < self.MIN_MAX_AGE:
            return self.found(self.make_finding(
                f"Слишком короткий HSTS max-age={max_age} (< {self.MIN_MAX_AGE})",
                req, resp, ctx,
                severity=Severity.LOW,
                recommendation="Увеличь max-age до >= 31536000 секунд.",
                cwe=self.cwe,
            ))
        return self.ok()


# ══════════════════════════════════════════════════════════════════
#  3. CSP — WSTG-CONF-12 (v5)
# ══════════════════════════════════════════════════════════════════

class CSPCheck(BaseCheck):
    """Отсутствующий или небезопасный Content-Security-Policy."""

    check_id = "csp"
    vuln_type = "csp"
    category = VulnCategory.MISCONFIG
    severity = Severity.MEDIUM
    name = "Content Security Policy"
    description = "WSTG-CONF-12 (v5): отсутствие/слабость CSP"
    cwe = "CWE-693"
    passive = True
    requires_payload = False

    def check(self, req: ScanRequest, resp: ScanResponse, ctx: CheckContext) -> CheckResult:
        if not self.enabled:
            return self.skip()

        # CSP имеет смысл для HTML-документов.
        if not is_html_response(resp.headers):
            return self.skip()
        if resp.status_code and not (200 <= resp.status_code < 400):
            return self.skip()

        raw_csp = _get_header(resp.headers, "content-security-policy")
        if not raw_csp.strip():
            # CSP может приходить и в report-only варианте (метаданные), но
            # политика не применяется — это всё равно отсутствие защиты.
            return self.found(self.make_finding(
                "Отсутствует Content-Security-Policy — нет защиты от XSS/инъекций "
                "на уровне браузера",
                req, resp, ctx,
                recommendation="Content-Security-Policy: default-src 'self'; "
                               "script-src 'self' 'nonce-<random>'",
                cwe=self.cwe,
            ))

        csp = raw_csp.lower()
        has_nonce_or_hash = bool(
            re.search(r"'?(nonce-|sha256-|sha384-|sha512-)", csp)
        ) or "strict-dynamic" in csp
        findings = []

        if "unsafe-inline" in csp and not has_nonce_or_hash:
            findings.append(self.make_finding(
                "CSP содержит 'unsafe-inline' без nonce/hash/strict-dynamic — "
                "inline-скрипты не блокируются",
                req, resp, ctx,
                severity=Severity.LOW,
                recommendation="Замени 'unsafe-inline' на nonce/hash или 'strict-dynamic'.",
                cwe=self.cwe,
            ))
        if "unsafe-eval" in csp:
            findings.append(self.make_finding(
                "CSP содержит 'unsafe-eval' — разрешено eval()/Function()",
                req, resp, ctx,
                severity=Severity.LOW,
                recommendation="Убери 'unsafe-eval' из script-src.",
                cwe=self.cwe,
            ))
        if "default-src" not in csp and "script-src" not in csp:
            findings.append(self.make_finding(
                "CSP не задаёт default-src/script-src — политика не ограничивает скрипты",
                req, resp, ctx,
                severity=Severity.LOW,
                recommendation="Начни политику с default-src 'self'.",
                cwe=self.cwe,
            ))

        if findings:
            return self.found(*findings)
        return self.ok()


# ══════════════════════════════════════════════════════════════════
#  4. Cache-Control — WSTG-ATHN-06
# ══════════════════════════════════════════════════════════════════

class CacheControlCheck(BaseCheck):
    """Чувствительный ответ без Cache-Control: no-store/private."""

    check_id = "cache_control"
    vuln_type = "cache_control"
    category = VulnCategory.AUTH
    severity = Severity.MEDIUM
    name = "Sensitive Response Cacheable"
    description = "WSTG-ATHN-06: чувствительный ответ кэшируется"
    cwe = "CWE-525"
    passive = True
    requires_payload = False

    _PASSWORD_FIELD_RE = re.compile(
        r"<input[^>]+type\s*=\s*[\"']?password", re.IGNORECASE
    )
    _CACHEABLE_SAFE_TOKENS = ("no-store", "private", "no-cache")

    def _is_sensitive(self, req: ScanRequest, resp: ScanResponse) -> bool:
        # 1) Сессионная cookie в ответе.
        for cookie in _parse_cookies(resp.headers):
            if _is_session_cookie(cookie.name) and not _is_benign_cookie(cookie.name):
                return True
        # 2) Авторизация в запросе.
        if _get_header(req.headers, "authorization") or _get_header(req.headers, "proxy-authorization"):
            return True
        # 3) Пароль в теле запроса.
        body = (req.body or b"")[:100_000].decode("utf-8", errors="ignore").lower()
        if "password=" in body or '"password"' in body:
            return True
        # 4) Форма логина / пароль на странице ответа.
        if self._PASSWORD_FIELD_RE.search(_body_text(resp, 100_000)):
            return True
        return False

    def check(self, req: ScanRequest, resp: ScanResponse, ctx: CheckContext) -> CheckResult:
        if not self.enabled:
            return self.skip()

        if resp.status_code and not (200 <= resp.status_code < 400):
            return self.skip()
        if not self._is_sensitive(req, resp):
            return self.ok()

        cache_control = _get_header(resp.headers, "cache-control").lower()
        if any(tok in cache_control for tok in self._CACHEABLE_SAFE_TOKENS):
            return self.ok()

        return self.found(self.make_finding(
            "Чувствительный ответ (сессия/Authorization/пароль) без "
            f"Cache-Control: no-store/private (Cache-Control={cache_control or '<нет>'!r}) — "
            "страница может осесть в кэше браузера/прокси",
            req, resp, ctx,
            recommendation="Cache-Control: no-store, no-cache, must-revalidate; Pragma: no-cache",
            cwe=self.cwe,
        ))


# ══════════════════════════════════════════════════════════════════
#  5. Insecure Login — WSTG-ATHN-01 / CRYP-03
# ══════════════════════════════════════════════════════════════════

class InsecureLoginCheck(BaseCheck):
    """Логин/пароль/Authorization передаются по http://."""

    check_id = "insecure_login"
    vuln_type = "insecure_login"
    category = VulnCategory.AUTH
    severity = Severity.HIGH
    name = "Credentials over Cleartext Channel"
    description = "WSTG-ATHN-01/CRYP-03: учётные данные по http://"
    cwe = "CWE-319"
    passive = True
    requires_payload = False

    _PASSWORD_INPUT_RE = re.compile(r"<input[^>]+type\s*=\s*[\"']?password", re.IGNORECASE)
    _LOGIN_PATH_RE = re.compile(r"(login|signin|sign-in|auth|session|token)", re.IGNORECASE)

    def check(self, req: ScanRequest, resp: ScanResponse, ctx: CheckContext) -> CheckResult:
        if not self.enabled:
            return self.skip()

        # Только незашифрованный HTTP.
        if urlparse(req.url or "").scheme.lower() != "http":
            return self.skip()
        if resp.error:
            return self.skip()

        reasons = []
        if _get_header(req.headers, "authorization"):
            reasons.append("заголовок Authorization")
        body = (req.body or b"")[:100_000].decode("utf-8", errors="ignore").lower()
        if "password=" in body or "passwd=" in body or '"password"' in body:
            reasons.append("пароль в теле запроса")
        if self._PASSWORD_INPUT_RE.search(_body_text(resp, 100_000)):
            reasons.append("поле <input type=password>")
        try:
            path = urlparse(req.url or "").path or ""
        except Exception:
            path = ""
        if self._LOGIN_PATH_RE.search(path) and req.method.upper() in ("POST", "PUT"):
            reasons.append(f"POST на login-подобный путь {path[:60]}")

        if not reasons:
            return self.ok()

        return self.found(self.make_finding(
            "Учётные данные передаются по незашифрованному http:// "
            f"({'; '.join(reasons)}) — MitM/сниффинг перехватывает логин, пароль и токены",
            req, resp, ctx,
            recommendation="Только HTTPS + HSTS; редирект http→https на всём сайте "
                           "(включая формы логина и API-токены).",
            cwe=self.cwe,
        ))


# ══════════════════════════════════════════════════════════════════
#  6. Browser Storage — WSTG-CLNT-12
# ══════════════════════════════════════════════════════════════════

class BrowserStorageCheck(BaseCheck):
    """Секреты/токены, сохранённые в localStorage/sessionStorage."""

    check_id = "browser_storage"
    vuln_type = "browser_storage"
    category = VulnCategory.INJECTION_CLIENT
    severity = Severity.HIGH
    name = "Browser Storage of Secrets"
    description = "WSTG-CLNT-12: секреты в localStorage/sessionStorage"
    cwe = "CWE-922"
    passive = True
    requires_payload = False

    _SECRET_KEY_HINTS = (
        "token", "jwt", "auth", "session", "secret", "password", "passwd",
        "api_key", "apikey", "access", "refresh", "credential", "bearer",
        "id_token", "csrf", "private",
    )
    _JWT_RE = re.compile(r"eyJ[A-Za-z0-9_\-]{5,}\.[A-Za-z0-9_\-]{5,}\.[A-Za-z0-9_\-]*")

    _SETITEM_RE = re.compile(
        r"(?:localStorage|sessionStorage)\s*\.\s*setItem\s*\(\s*(['\"])(.*?)\1\s*,\s*([^)]{1,300})\)",
        re.IGNORECASE,
    )
    _PROP_RE = re.compile(
        r"(?:localStorage|sessionStorage)\s*\.\s*([A-Za-z_$][\w$]*)\s*=\s*([^;\n]{1,300})",
        re.IGNORECASE,
    )
    _INDEX_RE = re.compile(
        r"(?:localStorage|sessionStorage)\s*\[\s*(['\"])(.*?)\1\s*\]\s*=\s*([^;\n]{1,300})",
        re.IGNORECASE,
    )

    def _looks_secret(self, key: str, value: str) -> bool:
        key_low = (key or "").lower()
        val = (value or "").strip().strip("'\"").strip()
        if any(h in key_low for h in self._SECRET_KEY_HINTS):
            return True
        if self._JWT_RE.search(val):
            return True
        if re.search(r"(bearer\s+|basic\s+|aws_|ghp_|sk-[A-Za-z0-9]{16,}|AKIA[0-9A-Z]{16})", val, re.IGNORECASE):
            return True
        return False

    def check(self, req: ScanRequest, resp: ScanResponse, ctx: CheckContext) -> CheckResult:
        if not self.enabled:
            return self.skip()

        text = _body_text(resp)
        if "storage" not in text.lower():
            return self.ok()

        hits: list[tuple[str, str]] = []
        for regex in (self._SETITEM_RE, self._INDEX_RE):
            for m in regex.finditer(text):
                key, value = m.group(2), m.group(3)
                if self._looks_secret(key, value):
                    hits.append((key, m.group(0)))
        for m in self._PROP_RE.finditer(text):
            key, value = m.group(1), m.group(2)
            if self._looks_secret(key, value):
                hits.append((key, m.group(0)))

        if not hits:
            return self.ok()

        seen: set[str] = set()
        findings = []
        for key, snippet in hits[:5]:
            if key in seen:
                continue
            seen.add(key)
            findings.append(self.make_finding(
                f"Секрет '{key}' сохраняется в browser storage: {snippet.strip()[:140]}",
                req, resp, ctx,
                recommendation="Не храни токены/пароли в localStorage/sessionStorage — "
                               "любой XSS их прочитает. Используй HttpOnly Secure SameSite cookie.",
                cwe=self.cwe,
            ))
        if findings:
            return self.found(*findings)
        return self.ok()


# ══════════════════════════════════════════════════════════════════
#  Экспорт
# ══════════════════════════════════════════════════════════════════

ALL_EXTRA_PASSIVE_CHECKS: list[type[BaseCheck]] = [
    CookiesCheck,
    HSTSCheck,
    CSPCheck,
    CacheControlCheck,
    InsecureLoginCheck,
    BrowserStorageCheck,
]
