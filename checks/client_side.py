"""
checks/client_side.py — Клиентские уязвимости и пассивные проверки.

Реализованные чеки:
  • XSS              — Reflected, Stored (пассивный), DOM-based (эвристика)
  • CSRF             — отсутствие Anti-CSRF токенов
  • Open Redirect    — небезопасные редиректы
  • Clickjacking     — отсутствие X-Frame-Options / CSP frame-ancestors
  • Security Headers — Content-Security-Policy, HSTS, X-Content-Type-Options, …
  • Info Disclosure  — чувствительные данные в JS, stack traces, комментарии
  • Outdated Libs    — признаки устаревших JS-библиотек (jQuery < 3.x, Angular 1.x)
  • Third-party Scripts — inline скрипты без SRI
"""

from __future__ import annotations

import base64
import re
import urllib.parse
from typing import Optional

from .base import (
    BaseCheck, CheckContext, CheckResult, Finding,
    ScanRequest, ScanResponse, Severity, VulnCategory,
)
from .fp_rules import is_bare_html_tag, is_html_response, payload_in_baseline


# ══════════════════════════════════════════════════════════════════
#  1. XSS — Cross-Site Scripting
# ══════════════════════════════════════════════════════════════════

XSS_REFLECTION_PROBES = [
    "<script>", "onerror=", "onload=", "alert(", "confirm(",
    "javascript:", "data:text/html", "svg onload",
    "<img src=x", "</script>",
]


class XSSReflectedCheck(BaseCheck):
    check_id = "xss_reflected"
    vuln_type = "xss_reflected"
    category = VulnCategory.INJECTION_CLIENT
    severity = Severity.HIGH
    name = "XSS — Reflected"
    cwe = "CWE-79"

    def check(self, req: ScanRequest, resp: ScanResponse, ctx: CheckContext) -> CheckResult:
        if not self.enabled:
            return self.skip()
        if not ctx.payload:
            return self.skip()
        # Только payload, способные разорвать HTML-структуру (< > " ').
        if not any(c in ctx.payload for c in "<>\"'"):
            return self.ok()

        # ── FP-фильтры (баг #4) ──────────────────────────────────
        # 1) «Голый» HTML-тег (<body>, <script>, </svg>) уже присутствует в
        #    HTML-скелете любой страницы → не исполняемый вектор, не находка.
        if is_bare_html_tag(ctx.payload):
            return self.ok()
        # 2) Payload уже был в baseline-ответе без нашей мутации → сигнал не наш.
        if ctx.baseline_text and payload_in_baseline(ctx.payload, ctx.baseline_text):
            return self.ok()
        # 3) JSON/plain-ответ с отражением — не XSS (нужен HTML-контекст).
        if not is_html_response(resp.headers):
            return self.ok()

        # Direct reflection
        if ctx.payload in resp.text:
            return self.found(self.make_finding(
                f"XSS payload reflected verbatim: {ctx.payload[:80]}",
                req, resp, ctx,
                recommendation="Encode output contextually (HTML-encode, JS-encode).",
            ))

        # URL-encoded reflection (те же FP-проверки применены выше)
        encoded = urllib.parse.quote(ctx.payload, safe="")
        if encoded != ctx.payload and encoded in resp.text:
            return self.found(self.make_finding(
                f"XSS payload reflected URL-encoded: {encoded[:80]}",
                req, resp, ctx, severity=Severity.MEDIUM,
            ))

        # (partial-reflection heuristic removed: флагало "alert"/"<script" даже при HTML-кодировании)
        return self.ok()


class XSSDOMCheck(BaseCheck):
    """
    Эвристический DOM-XSS чек (пассивный):
    Ищет опасные sink'и в JS-коде ответа.
    """
    check_id = "xss_dom"
    vuln_type = "xss_dom"
    category = VulnCategory.INJECTION_CLIENT
    severity = Severity.MEDIUM
    name = "XSS — DOM-Based (Heuristic)"
    cwe = "CWE-79"
    passive = True
    requires_payload = False

    DOM_SINKS = [
        r"document\.write\s*\(",
        r"innerHTML\s*=",
        r"outerHTML\s*=",
        r"eval\s*\(",
        r"setTimeout\s*\([^,]+,",   # setTimeout with string arg
        r"setInterval\s*\([^,]+,",
        r"location\.href\s*=",
        r"document\.domain\s*=",
        r"\.src\s*=.*location",
        r"window\.open\s*\(",
    ]

    DOM_SOURCES = [
        r"location\.hash",
        r"location\.search",
        r"location\.href",
        r"document\.referrer",
        r"document\.cookie",
        r"window\.name",
        r"localStorage\[",
        r"sessionStorage\[",
    ]

    def check(self, req: ScanRequest, resp: ScanResponse, ctx: CheckContext) -> CheckResult:
        if not self.enabled:
            return self.skip()

        ct = resp.headers.get("content-type", "").lower()
        if "html" not in ct and "javascript" not in ct:
            return self.skip()

        found_sinks = []
        for pattern in self.DOM_SINKS:
            if re.search(pattern, resp.text, re.IGNORECASE):
                found_sinks.append(pattern.split(r"\s")[0].replace("\\", ""))

        found_sources = []
        for pattern in self.DOM_SOURCES:
            if re.search(pattern, resp.text, re.IGNORECASE):
                found_sources.append(pattern.split(r"\.")[1] if "." in pattern else pattern)

        if found_sinks and found_sources:
            return self.found(self.make_finding(
                f"Potential DOM-XSS: sinks={found_sinks[:3]}, sources={found_sources[:3]}",
                req, resp, ctx, severity=Severity.MEDIUM,
                recommendation="Avoid passing user-controlled values to DOM sinks.",
            ))
        return self.ok()


# ══════════════════════════════════════════════════════════════════
#  2. CSRF
# ══════════════════════════════════════════════════════════════════

CSRF_TOKEN_NAMES = [
    "csrf", "csrftoken", "_token", "xsrf", "authenticity_token",
    "__requestverificationtoken", "csrf_token", "_csrf",
]


class CSRFCheck(BaseCheck):
    """
    Пассивный чек: ищет unsafe методы без CSRF-токенов в форме/заголовках.
    """
    check_id = "csrf"
    vuln_type = "csrf"
    category = VulnCategory.INJECTION_CLIENT
    severity = Severity.MEDIUM
    name = "CSRF — Missing Anti-CSRF Token"
    cwe = "CWE-352"
    passive = True
    requires_payload = False

    def check(self, req: ScanRequest, resp: ScanResponse, ctx: CheckContext) -> CheckResult:
        if not self.enabled:
            return self.skip()

        # Only relevant for state-changing methods
        if req.method.upper() in ("GET", "HEAD", "OPTIONS"):
            return self.skip()

        # Check request for CSRF token presence
        body_text = req.body.decode("utf-8", errors="ignore").lower()
        headers_lower = {k.lower(): v.lower() for k, v in req.headers.items()}

        has_csrf_token = any(name in body_text for name in CSRF_TOKEN_NAMES)
        has_csrf_header = any(
            name in headers_lower
            for name in ["x-csrf-token", "x-xsrf-token", "x-requested-with"]
        )

        if has_csrf_token or has_csrf_header:
            return self.ok()

        # Check if SameSite cookie is set
        set_cookie = resp.headers.get("set-cookie", "").lower()
        if "samesite=strict" in set_cookie or "samesite=lax" in set_cookie:
            return self.ok()

        return self.found(self.make_finding(
            f"State-changing {req.method} request without CSRF token or SameSite cookie",
            req, resp, ctx,
            recommendation="Add anti-CSRF token or use SameSite=Strict/Lax cookies.",
        ))


# ══════════════════════════════════════════════════════════════════
#  3. Open Redirect
# ══════════════════════════════════════════════════════════════════

REDIRECT_PARAM_NAMES = [
    "redirect", "redirect_url", "redirect_uri", "return", "return_url",
    "returnto", "next", "url", "goto", "destination", "target",
    "continue", "forward",
]

REDIRECT_PAYLOAD_SIGS = [
    "http://", "https://", "//", "javascript:",
]


class OpenRedirectCheck(BaseCheck):
    check_id = "open_redirect"
    vuln_type = "open_redirect"
    category = VulnCategory.INJECTION_CLIENT
    severity = Severity.MEDIUM
    name = "Open Redirect"
    cwe = "CWE-601"

    def check(self, req: ScanRequest, resp: ScanResponse, ctx: CheckContext) -> CheckResult:
        if not self.enabled:
            return self.skip()

        # Check if payload looks like external redirect
        has_redirect_payload = any(
            sig.lower() in ctx.payload.lower() for sig in REDIRECT_PAYLOAD_SIGS
        )
        # Check if param name is redirect-like
        is_redirect_param = any(
            name in ctx.original_param.lower() for name in REDIRECT_PARAM_NAMES
        )

        if not (has_redirect_payload or is_redirect_param):
            return self.skip()

        # Check for redirect in response
        if resp.status_code in (301, 302, 303, 307, 308):
            location = resp.headers.get("location", "")
            if location and not _is_same_origin(req.url, location):
                if ctx.payload and ctx.payload[:20] in location:
                    return self.found(self.make_finding(
                        f"Open Redirect: Location header redirects to external URL '{location[:100]}'",
                        req, resp, ctx,
                        recommendation="Only allow relative paths or explicitly allowlisted domains.",
                    ))

        # Check for meta-refresh or JS redirect with payload
        meta_pattern = r'<meta[^>]+url=([^"\'>\s]+)'
        m = re.search(meta_pattern, resp.text, re.IGNORECASE)
        if m and ctx.payload[:20] in m.group(1):
            return self.found(self.make_finding(
                f"Possible Open Redirect via meta-refresh: '{m.group()[:100]}'",
                req, resp, ctx, severity=Severity.LOW,
            ))
        return self.ok()


def _is_same_origin(base_url: str, target_url: str) -> bool:
    try:
        base = urllib.parse.urlparse(base_url)
        target = urllib.parse.urlparse(target_url)
        if target.scheme == "" and target.netloc == "":
            return True  # relative
        return base.netloc == target.netloc
    except Exception:
        return True


# ══════════════════════════════════════════════════════════════════
#  4. Clickjacking
# ══════════════════════════════════════════════════════════════════

class ClickjackingCheck(BaseCheck):
    check_id = "clickjacking"
    vuln_type = "clickjacking"
    category = VulnCategory.MISCONFIG
    severity = Severity.LOW
    name = "Clickjacking — Missing X-Frame-Options / CSP"
    cwe = "CWE-1021"
    passive = True
    requires_payload = False

    def check(self, req: ScanRequest, resp: ScanResponse, ctx: CheckContext) -> CheckResult:
        if not self.enabled:
            return self.skip()

        ct = resp.headers.get("content-type", "").lower()
        if "html" not in ct:
            return self.skip()

        if resp.status_code not in range(200, 300):
            return self.skip()

        xfo = resp.headers.get("x-frame-options", "").lower()
        csp = resp.headers.get("content-security-policy", "").lower()

        has_xfo = bool(xfo) and xfo in ("deny", "sameorigin")
        has_csp_frame = "frame-ancestors" in csp

        if not has_xfo and not has_csp_frame:
            return self.found(self.make_finding(
                "Missing X-Frame-Options and CSP frame-ancestors — page embeddable in iframe",
                req, resp, ctx,
                recommendation="Set X-Frame-Options: DENY or Content-Security-Policy: frame-ancestors 'none'",
            ))
        return self.ok()


# ══════════════════════════════════════════════════════════════════
#  5. Security Headers (пассивный)
# ══════════════════════════════════════════════════════════════════

# Headers required on ALL responses (HTML and API alike)
REQUIRED_HEADERS_ALL = {
    "x-content-type-options": {
        "severity": Severity.LOW,
        "recommendation": "Add X-Content-Type-Options: nosniff",
        "cwe": "CWE-693",
    },
}

# Headers required on HTML responses
REQUIRED_HEADERS_HTML = {
    "strict-transport-security": {
        "severity": Severity.MEDIUM,
        "recommendation": "Add Strict-Transport-Security: max-age=31536000; includeSubDomains",
        "cwe": "CWE-319",
    },
    "content-security-policy": {
        "severity": Severity.MEDIUM,
        "recommendation": "Add Content-Security-Policy header to restrict resource loading",
        "cwe": "CWE-693",
    },
    "x-frame-options": {
        "severity": Severity.LOW,
        "recommendation": "Add X-Frame-Options: DENY or SAMEORIGIN",
        "cwe": "CWE-1021",
    },
    "referrer-policy": {
        "severity": Severity.INFO,
        "recommendation": "Add Referrer-Policy: strict-origin-when-cross-origin",
        "cwe": "CWE-116",
    },
    "permissions-policy": {
        "severity": Severity.INFO,
        "recommendation": "Consider adding Permissions-Policy to restrict browser features",
        "cwe": "CWE-693",
    },
}

# Keep legacy name pointing at the combined set for any external refs
REQUIRED_HEADERS = {**REQUIRED_HEADERS_ALL, **REQUIRED_HEADERS_HTML}


class SecurityHeadersCheck(BaseCheck):
    check_id = "security_headers"
    vuln_type = "security_headers"
    category = VulnCategory.MISCONFIG
    severity = Severity.LOW
    name = "Missing Security Headers"
    cwe = "CWE-693"
    passive = True
    requires_payload = False

    def check(self, req: ScanRequest, resp: ScanResponse, ctx: CheckContext) -> CheckResult:
        if not self.enabled:
            return self.skip()

        if resp.status_code not in range(200, 400):
            return self.skip()

        ct = resp.headers.get("content-type", "").lower()
        is_html = "html" in ct
        is_api  = any(x in ct for x in ("json", "xml", "application"))
        headers_lower = {k.lower(): v for k, v in resp.headers.items()}
        findings = []

        # ─ Headers required on all responses ────────────────────────────────────
        for header, meta in REQUIRED_HEADERS_ALL.items():
            if header not in headers_lower:
                findings.append(self.make_finding(
                    f"Missing security header: {header}",
                    req, resp, ctx,
                    severity=meta["severity"],
                    recommendation=meta["recommendation"],
                    cwe=meta["cwe"],
                    title=f"Missing {header}",
                ))

        # ─ Headers required on HTML responses ───────────────────────────────
        if is_html:
            for header, meta in REQUIRED_HEADERS_HTML.items():
                if header not in headers_lower:
                    findings.append(self.make_finding(
                        f"Missing security header: {header}",
                        req, resp, ctx,
                        severity=meta["severity"],
                        recommendation=meta["recommendation"],
                        cwe=meta["cwe"],
                        title=f"Missing {header}",
                    ))

        # ─ HSTS misconfiguration ─────────────────────────────────────────
        if req.url.startswith("https://"):
            hsts = headers_lower.get("strict-transport-security", "")
            if hsts and "max-age=0" in hsts:
                findings.append(self.make_finding(
                    "HSTS max-age=0 effectively disables HSTS",
                    req, resp, ctx, severity=Severity.MEDIUM,
                    cwe="CWE-319",
                ))

        # ─ CORS / Origin checks ─────────────────────────────────────────────
        acao = headers_lower.get("access-control-allow-origin", "")
        acac = headers_lower.get("access-control-allow-credentials", "").lower()
        acam = headers_lower.get("access-control-allow-methods", "")
        acah = headers_lower.get("access-control-allow-headers", "")

        if acao == "*":
            findings.append(self.make_finding(
                "CORS: Access-Control-Allow-Origin: * — wildcard allows any origin to read response",
                req, resp, ctx,
                severity=Severity.MEDIUM,
                recommendation="Restrict CORS to specific trusted origins instead of wildcard *",
                cwe="CWE-942",
                title="Overly permissive CORS (wildcard origin)",
            ))

        if acao == "*" and acac == "true":
            findings.append(self.make_finding(
                "CORS: wildcard origin combined with Allow-Credentials: true — "
                "browsers block this combination but misconfigured proxies/services may not",
                req, resp, ctx,
                severity=Severity.HIGH,
                recommendation="Never use Allow-Credentials: true with a wildcard origin",
                cwe="CWE-942",
                title="Dangerous CORS: wildcard + credentials",
            ))

        if acao and acao != "*" and acac == "true":
            # Reflect-origin misconfiguration: server echoes Origin header verbatim
            req_origin = req.headers.get("origin", req.headers.get("Origin", ""))
            if req_origin and acao == req_origin:
                findings.append(self.make_finding(
                    f"CORS: server reflects arbitrary Origin '{req_origin}' with Allow-Credentials: true — "
                    "any origin can read credentialed responses",
                    req, resp, ctx,
                    severity=Severity.HIGH,
                    recommendation="Validate Origin against a strict allowlist; never echo it verbatim",
                    cwe="CWE-942",
                    title="CORS: reflected origin with credentials",
                ))

        if acam and any(m.strip().upper() in ("PUT", "DELETE", "PATCH")
                        for m in acam.split(",")):
            if not acao:
                pass  # only flag if CORS is actually enabled
            elif acao:
                findings.append(self.make_finding(
                    f"CORS: dangerous methods allowed — Access-Control-Allow-Methods: {acam}",
                    req, resp, ctx,
                    severity=Severity.LOW,
                    recommendation="Only expose necessary HTTP methods in CORS policy",
                    cwe="CWE-942",
                    title="CORS: dangerous methods exposed",
                ))

        if findings:
            return self.found(*findings)
        return self.ok()


# ══════════════════════════════════════════════════════════════════
#  6. Information Disclosure
# ══════════════════════════════════════════════════════════════════

INFO_PATTERNS = [
    # Имя секрета может быть в кавычках (JSON-ключ вида "spring.datasource.password"),
    # поэтому кавычки вокруг имени опциональны. Минимальные длины значений сохранены:
    # password 4, secret 8, api_key/access_token 10.
    (r"[\"']?password[\"']?\s*[:=]\s*[\"'][^\"']{4,}", Severity.HIGH, "Password in response"),
    (r"[\"']?secret[\"']?\s*[:=]\s*[\"'][^\"']{8,}", Severity.HIGH, "Secret/key in response"),
    (r"[\"']?api[_\-]?key[\"']?\s*[:=]\s*[\"'][^\"']{10,}", Severity.HIGH, "API key in response"),
    (r"[\"']?access[_\-]?token[\"']?\s*[:=]\s*[\"'][^\"']{10,}", Severity.HIGH, "Access token in response"),
    (r"[A-Za-z0-9+/]{40,}={0,2}", Severity.INFO, "Possible base64-encoded secret"),
    (r"(?:traceback|stack trace|at [a-z]+\.[A-Z][a-zA-Z]+\.)", Severity.MEDIUM, "Stack trace in response"),
    (r"exception.*line \d+", Severity.MEDIUM, "Exception detail exposed"),
    (r"debug\s*=\s*true", Severity.MEDIUM, "Debug mode enabled"),
    (r"<!--.*?-->", Severity.INFO, "HTML comment (may contain sensitive info)"),
    (r"AKIA[0-9A-Z]{16}", Severity.CRITICAL, "AWS Access Key ID"),
    (r"ghp_[A-Za-z0-9]{36}", Severity.CRITICAL, "GitHub Personal Access Token"),
    (r"sk-[A-Za-z0-9]{48}", Severity.HIGH, "OpenAI API key"),
    (r"-----BEGIN (RSA |EC |OPENSSH )?PRIVATE KEY-----", Severity.CRITICAL, "Private key in response"),
]

#: label base64-эвристики (для неё матч валидируется, чтобы не флагать JWT).
BASE64_SECRET_LABEL = "Possible base64-encoded secret"

#: JWT: base64url(header).base64url(payload).signature; header JSON всегда начинается с "eyJ".
_JWT_RE = re.compile(r"eyJ[A-Za-z0-9_\-]*\.[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]*")


def _decode_base64_loose(value: str) -> Optional[bytes]:
    """b64decode без строгой валидации, с авто-добивкой padding (None при ошибке)."""
    try:
        return base64.b64decode(value + "=" * (-len(value) % 4), validate=False)
    except Exception:
        return None


def _is_token_like_base64(match: "re.Match[str]", text: str) -> bool:
    """
    True, если base64-совпадение — часть токена (JWT), а не утёкший секрет.

    JWT header/payload — это base64url-encoded JSON, поэтому совпадение
    считается токеном, если декодированное значение:
      • начинается с "{" или "[" (JSON); или
      • содержит "alg" (поле JWT-header);
    либо сам матч целиком лежит внутри JWT-строки "eyJ...".
    Такие base64-совпадения не являются info disclosure (FP на /jwt).
    """
    decoded = _decode_base64_loose(match.group())
    if decoded is not None:
        stripped = decoded.lstrip()
        if stripped[:1] in (b"{", b"["):
            return True
        if b"alg" in decoded.lower():
            return True
    for jwt_match in _JWT_RE.finditer(text):
        if jwt_match.start() <= match.start() and match.end() <= jwt_match.end():
            return True
    return False


def _find_base64_secret_match(pattern: str, text: str) -> Optional["re.Match[str]"]:
    """Первый base64-матч, не являющийся частью токена (JWT)."""
    for match in re.finditer(pattern, text, re.IGNORECASE | re.DOTALL):
        if not _is_token_like_base64(match, text):
            return match
    return None


class InfoDisclosureCheck(BaseCheck):
    check_id = "info_disclosure"
    vuln_type = "info_disclosure"
    category = VulnCategory.INFO_DISCLOSURE
    severity = Severity.MEDIUM
    name = "Sensitive Information Disclosure"
    cwe = "CWE-200"
    passive = True
    requires_payload = False

    def check(self, req: ScanRequest, resp: ScanResponse, ctx: CheckContext) -> CheckResult:
        if not self.enabled:
            return self.skip()

        findings = []
        for pattern, severity, label in INFO_PATTERNS:
            if label == BASE64_SECRET_LABEL:
                # FP-фильтр: JWT (base64url JSON) — это токен, не утёкший секрет.
                m = _find_base64_secret_match(pattern, resp.text)
            else:
                m = re.search(pattern, resp.text, re.IGNORECASE | re.DOTALL)
            if m:
                snippet = m.group()[:60]
                findings.append(self.make_finding(
                    f"{label}: '{snippet}'",
                    req, resp, ctx,
                    severity=severity,
                    title=label,
                    cwe=self.cwe,
                ))

        if findings:
            return self.found(*findings)
        return self.ok()


# ══════════════════════════════════════════════════════════════════
#  7. Outdated / Vulnerable JS Libraries
# ══════════════════════════════════════════════════════════════════

OUTDATED_LIB_PATTERNS = [
    (r"jquery[/-]([01]\.|2\.[0-2])", Severity.MEDIUM,
     "Outdated jQuery (< 3.x) — known XSS vulnerabilities"),
    (r"angular\.js/1\.", Severity.MEDIUM,
     "AngularJS 1.x — EOL since Dec 2021"),
    (r"bootstrap[/-]([0-2]\.|3\.[0-3])", Severity.LOW,
     "Outdated Bootstrap — may have XSS issues"),
    (r"underscore[/-]1\.[0-7]\.", Severity.LOW,
     "Outdated Underscore.js"),
    (r"moment\.js.*version.*\"([01]\.|2\.[0-1])", Severity.INFO,
     "Outdated Moment.js"),
    (r"prototype\.js/([0-1]\.)", Severity.HIGH,
     "Prototype.js is EOL and has known vulnerabilities"),
]


class OutdatedLibsCheck(BaseCheck):
    check_id = "outdated_libs"
    vuln_type = "outdated_libs"
    category = VulnCategory.INFO_DISCLOSURE
    severity = Severity.MEDIUM
    name = "Outdated/Vulnerable JS Libraries"
    cwe = "CWE-1035"
    passive = True
    requires_payload = False

    def check(self, req: ScanRequest, resp: ScanResponse, ctx: CheckContext) -> CheckResult:
        if not self.enabled:
            return self.skip()

        ct = resp.headers.get("content-type", "").lower()
        if "html" not in ct and "javascript" not in ct:
            return self.skip()

        findings = []
        for pattern, severity, label in OUTDATED_LIB_PATTERNS:
            m = re.search(pattern, resp.text, re.IGNORECASE)
            if m:
                findings.append(self.make_finding(
                    f"{label} — matched: '{m.group()[:60]}'",
                    req, resp, ctx, severity=severity, title=label,
                ))
        if findings:
            return self.found(*findings)
        return self.ok()


# ══════════════════════════════════════════════════════════════════
#  8. Third-party scripts without SRI
# ══════════════════════════════════════════════════════════════════

class ThirdPartyScriptCheck(BaseCheck):
    """
    Проверяет наличие <script src="..."> без атрибута integrity (SRI).
    TODO: расширить до полноценного CSP-аудита.
    """
    check_id = "third_party_scripts"
    vuln_type = "third_party_scripts"
    category = VulnCategory.MISCONFIG
    severity = Severity.LOW
    name = "Third-party Scripts Without SRI"
    cwe = "CWE-829"
    passive = True
    requires_payload = False

    EXTERNAL_SCRIPT_RE = re.compile(
        r'<script[^>]+src\s*=\s*["\']https?://(?!localhost|127\.|0\.0\.0\.0)([^"\']+)["\'][^>]*>',
        re.IGNORECASE,
    )

    def check(self, req: ScanRequest, resp: ScanResponse, ctx: CheckContext) -> CheckResult:
        if not self.enabled:
            return self.skip()

        ct = resp.headers.get("content-type", "").lower()
        if "html" not in ct:
            return self.skip()

        findings = []
        for m in self.EXTERNAL_SCRIPT_RE.finditer(resp.text):
            tag = m.group()
            if "integrity=" not in tag.lower():
                domain = m.group(1).split("/")[0]
                findings.append(self.make_finding(
                    f"External script from '{domain}' without SRI integrity attribute",
                    req, resp, ctx, severity=Severity.LOW,
                    recommendation="Add integrity='sha384-...' to all external scripts.",
                ))
            if len(findings) >= 5:  # Limit to 5 per page
                break

        if findings:
            return self.found(*findings)
        return self.ok()


# ══════════════════════════════════════════════════════════════════
#  Экспорт
# ══════════════════════════════════════════════════════════════════

ALL_CLIENT_CHECKS: list[type[BaseCheck]] = [
    XSSReflectedCheck,
    XSSDOMCheck,
    CSRFCheck,
    OpenRedirectCheck,
    ClickjackingCheck,
    SecurityHeadersCheck,
    InfoDisclosureCheck,
    OutdatedLibsCheck,
    ThirdPartyScriptCheck,
]
