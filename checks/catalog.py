"""
checks/catalog.py — Единый каталог чеков (WSTG-карта).

Единственный источник правды для:
  • GUI: вкладка Checks/WSTG (дерево чеков, группировка по category);
  • GUI: бейджи ScanConfigWindow (active/passive) и чекбоксы probe-чеков;
  • checks/runner.WSTG_ID_MAP (WSTG-ID для находок и логов);
  • scanner_core.load_payloads(check_type) — через payload_file_for();
  • GUI: PASSIVE_CHECK_IDS / набор probe-чеков (через by_kind).

Интерфейс менять нельзя — его импортирует GUI:
    from checks.catalog import CHECK_CATALOG

WSTG-ID сверены по:
  • OWASP WSTG v4.2 (stable): https://wstg.owasp.org/stable/
  • checklist v5-dev: https://raw.githubusercontent.com/OWASP/wstg/master/checklists/checklist.md
Для тестов, которых нет в v4.2, используется v5-ID с явной пометкой " (v5)".
Где в WSTG нет отдельного теста под класс уязвимости, в description указан
ближайший тест ("nearest"). v4.2 не содержит CONF-12..CONF-15, SESS-10,
INJT-*, поэтому такие ссылки помечены (v5).
"""

from __future__ import annotations

from dataclasses import dataclass


# GUI-группы (порядок = порядок групп на вкладке Checks/WSTG).
CATEGORIES: tuple[str, ...] = (
    "Information",
    "Config",
    "Injection",
    "File",
    "Client",
    "Session",
    "AuthN",
    "AuthZ",
)

SEVERITIES: tuple[str, ...] = ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO")
KINDS: tuple[str, ...] = ("active", "passive", "probe")


@dataclass(frozen=True)
class CheckDef:
    check_id: str
    wstg_id: str
    name: str
    category: str        # GUI-группа: "Information" | "Config" | "Injection" | "File"
                         #            | "Client" | "Session" | "AuthN" | "AuthZ"
    severity: str        # CRITICAL | HIGH | MEDIUM | LOW | INFO
    cwe: str             # "CWE-89"
    description: str
    kind: str            # "active" | "passive" | "probe"
    payload_file: str | None = None   # только для active, имя файла в payloads/
    enabled_default: bool = True


# ══════════════════════════════════════════════════════════════════
#  Каталог: 38 записей
#    24 существующих чека (14 active + 10 passive)
#    + 1 pseudo probe info_disclosure_paths
#    + 13 новых (2 active + 6 passive + 5 probe)
# ══════════════════════════════════════════════════════════════════

CHECK_CATALOG: tuple[CheckDef, ...] = (
    # ──────────────────────────── Information ────────────────────────────
    CheckDef(
        "info_disclosure", "WSTG-INFO-05", "Sensitive Information Disclosure",
        "Information", "MEDIUM", "CWE-200",
        "WSTG-INFO-05 Review Web Page Content for Information Leakage: "
        "secrets, tokens, stack traces, comments and private keys in responses.",
        "passive",
    ),
    CheckDef(
        "outdated_libs", "WSTG-INFO-08", "Outdated/Vulnerable JS Libraries",
        "Information", "MEDIUM", "CWE-1035",
        "WSTG-INFO-08 Fingerprint Web Application Framework (nearest: WSTG has no "
        "dedicated outdated-components test): jQuery/AngularJS/Bootstrap hints.",
        "passive",
    ),
    CheckDef(
        "third_party_scripts", "WSTG-INFO-09", "Third-party Scripts Without SRI",
        "Information", "LOW", "CWE-829",
        "WSTG-INFO-09 Fingerprint Web Application (nearest): external <script src> "
        "without Subresource Integrity allows supply-chain tampering.",
        "passive",
    ),
    CheckDef(
        "metafiles", "WSTG-INFO-03", "Webserver Metafiles Disclosure",
        "Information", "LOW", "CWE-200",
        "WSTG-INFO-03 Review Webserver Metafiles for Information Leakage: "
        "/robots.txt, /sitemap.xml, /security.txt, /.well-known/security.txt, /humans.txt.",
        "probe",
    ),

    # ────────────────────────────── Config ───────────────────────────────
    CheckDef(
        "security_headers", "WSTG-CONF-14 (v5)", "Missing Security Headers",
        "Config", "LOW", "CWE-693",
        "WSTG-CONF-14 (v5) Other HTTP Security Header Misconfigurations: missing "
        "X-Content-Type-Options, HSTS, CSP, X-Frame-Options, Referrer-Policy.",
        "passive",
    ),
    CheckDef(
        "clickjacking", "WSTG-CLNT-09", "Clickjacking — Missing X-Frame-Options / CSP",
        "Config", "LOW", "CWE-1021",
        "WSTG-CLNT-09 Test for Clickjacking: page embeddable because both "
        "X-Frame-Options and CSP frame-ancestors are missing.",
        "passive",
    ),
    CheckDef(
        "hsts", "WSTG-CONF-07", "Missing / Weak HSTS",
        "Config", "MEDIUM", "CWE-319",
        "WSTG-CONF-07 Test HTTP Strict Transport Security: HTTPS response without "
        "Strict-Transport-Security (or max-age too short).",
        "passive",
    ),
    CheckDef(
        "csp", "WSTG-CONF-12 (v5)", "Content Security Policy",
        "Config", "MEDIUM", "CWE-693",
        "WSTG-CONF-12 (v5) Content Security Policy: missing CSP or weak policy "
        "(unsafe-inline/unsafe-eval without nonce/hash/strict-dynamic).",
        "passive",
    ),
    CheckDef(
        "ria_policy", "WSTG-CONF-08", "RIA Cross-Domain Policy",
        "Config", "MEDIUM", "CWE-942",
        "WSTG-CONF-08 Test RIA Cross Domain Policy: /crossdomain.xml or "
        "/clientaccesspolicy.xml with wildcard 'allow-access-from domain=\"*\"'.",
        "probe",
    ),
    CheckDef(
        "http_methods", "WSTG-CONF-06", "HTTP Methods / TRACE",
        "Config", "MEDIUM", "CWE-650",
        "WSTG-CONF-06 Test HTTP Methods: OPTIONS advertises PUT/DELETE/TRACE, "
        "TRACE succeeds, or risky methods return 2xx/3xx.",
        "probe",
    ),
    CheckDef(
        "sensitive_files", "WSTG-CONF-03", "Sensitive Files / Backups Exposure",
        "Config", "HIGH", "CWE-538",
        "WSTG-CONF-03 File Extensions Handling for Sensitive Information "
        "(also WSTG-CONF-04 Review Old Backup and Unreferenced Files): .env, "
        ".git/config, *.bak/*.old/*.swp/*~, config.php.bak, web.config, phpinfo.php.",
        "probe",
    ),
    CheckDef(
        "info_disclosure_paths", "WSTG-CONF-05", "Admin / Debug Interface Exposure",
        "Config", "MEDIUM", "CWE-538",
        "WSTG-CONF-05 Enumerate Infrastructure and Application Admin Interfaces: "
        "Spring Actuator, etcd, swagger/openapi, metrics, pprof, server-status.",
        "probe",
    ),

    # ───────────────────────────── Injection ─────────────────────────────
    CheckDef(
        "sqli", "WSTG-INPV-05", "SQL Injection (Error-Based)",
        "Injection", "HIGH", "CWE-89",
        "WSTG-INPV-05 Testing for SQL Injection: DB error messages triggered by "
        "quote-based payloads (error-based detection).",
        "active", "sqli.txt",
    ),
    CheckDef(
        "sqli_time", "WSTG-INPV-05", "SQL Injection (Time-Based Blind)",
        "Injection", "HIGH", "CWE-89",
        "WSTG-INPV-05 Testing for SQL Injection (blind): response delay >= threshold "
        "for SLEEP/pg_sleep/WAITFOR payloads, relative to host baseline.",
        "active", "sqli_time.txt",
    ),
    CheckDef(
        "sqli_blind", "WSTG-INPV-05", "SQL Injection (Boolean-Based Blind)",
        "Injection", "HIGH", "CWE-89",
        "WSTG-INPV-05 Testing for SQL Injection (blind): true/false boolean payload "
        "pairs (AND 1=1 vs AND 1=2) compared by response status/length/similarity; "
        "false response must match the baseline.",
        "active", "sqli_blind.txt",
    ),
    CheckDef(
        "cmdi", "WSTG-INPV-12", "Command Injection (CMDi)",
        "Injection", "CRITICAL", "CWE-78",
        "WSTG-INPV-12 Testing for Command Injection: shell metacharacters executed "
        "server-side (shell errors / command output).",
        "active", "cmdi.txt",
    ),
    CheckDef(
        "ssti", "WSTG-INPV-18", "Server-Side Template Injection (SSTI)",
        "Injection", "CRITICAL", "CWE-94",
        "WSTG-INPV-18 Testing for Server-side Template Injection: template "
        "expressions ({{7*7}}) evaluated server-side.",
        "active", "ssti.txt",
    ),
    CheckDef(
        "ldap_injection", "WSTG-INPV-06", "LDAP Injection",
        "Injection", "HIGH", "CWE-90",
        "WSTG-INPV-06 Testing for LDAP Injection: LDAP filters built from user input "
        "(LDAP error/exception signatures).",
        "active", "ldapi.txt",
    ),
    CheckDef(
        "xpath_injection", "WSTG-INPV-09", "XPath/XML Injection",
        "Injection", "HIGH", "CWE-643",
        "WSTG-INPV-09 Testing for XPath Injection: XPath/XML parser errors after "
        "quote-based payloads.",
        "active", "xpath.txt",
    ),
    CheckDef(
        "nosql_injection", "WSTG-INJT-05 (v5)", "NoSQL Injection",
        "Injection", "HIGH", "CWE-943",
        "WSTG-INJT-05 (v5) SQL Injection (nearest: WSTG has no dedicated NoSQL test; "
        "NoSQL is sub-test 05.6 of SQL Injection, v4.2 WSTG-INPV-05): MongoDB-style "
        "operator injection ($gt/$ne/$where) and parser errors.",
        "active", "nosqli.txt",
    ),
    CheckDef(
        "xxe", "WSTG-INPV-07", "XML External Entity (XXE)",
        "Injection", "HIGH", "CWE-611",
        "WSTG-INPV-07 Testing for XML Injection (nearest XXE test): external entity "
        "expansion, local file disclosure via DOCTYPE.",
        "active", "xxe.txt",
    ),
    CheckDef(
        "deserialization", "WSTG-INJT-23 (v5)", "Insecure Deserialization",
        "Injection", "CRITICAL", "CWE-502",
        "WSTG-INJT-23 (v5) Insecure Deserialization: Java/PHP/Python serialized "
        "objects accepted and deserialized by the server.",
        "active", "deserialization.txt",
    ),
    CheckDef(
        "crlf_injection", "WSTG-INPV-15", "Header Injection / CRLF Injection",
        "Injection", "MEDIUM", "CWE-113",
        "WSTG-INPV-15 Testing for HTTP Splitting/Smuggling: CR/LF in user input "
        "injected into response headers (not to be confused with path traversal).",
        "active", "crlf.txt",
    ),
    CheckDef(
        "ssrf", "WSTG-INPV-19", "Server-Side Request Forgery (SSRF)",
        "Injection", "HIGH", "CWE-918",
        "WSTG-INPV-19 Testing for Server-Side Request Forgery: server fetches "
        "attacker-controlled URL (internal/metadata targets).",
        "active", "ssrf.txt",
    ),
    CheckDef(
        "ssi_injection", "WSTG-INPV-08", "Server-Side Includes (SSI) Injection",
        "Injection", "HIGH", "CWE-97",
        "WSTG-INPV-08 Testing for SSI Injection: <!--#echo/#exec/#include/#printenv "
        "processed server-side (SSI error or directive output).",
        "active", "ssi.txt",
    ),

    # ─────────────────────────────── File ────────────────────────────────
    CheckDef(
        "path_traversal", "WSTG-ATHZ-01", "Path Traversal / LFI / RFI",
        "File", "HIGH", "CWE-22",
        "WSTG-ATHZ-01 Testing Directory Traversal File Include: ../ sequences "
        "escape the web root and disclose/execute files.",
        "active", "path_traversal.txt",
    ),
    CheckDef(
        "file_upload", "WSTG-BUSL-09", "Dangerous File Upload",
        "File", "CRITICAL", "CWE-434",
        "WSTG-BUSL-09 Test Upload of Malicious Files (also WSTG-BUSL-08): multipart "
        "upload with executable extension / webshell content.",
        "passive", "file_upload.txt",
    ),

    # ────────────────────────────── Client ───────────────────────────────
    CheckDef(
        "xss_reflected", "WSTG-INPV-01", "XSS — Reflected",
        "Client", "HIGH", "CWE-79",
        "WSTG-INPV-01 Testing for Reflected Cross Site Scripting: payload reflected "
        "unencoded into an HTML response.",
        "active", "xss.txt",
    ),
    CheckDef(
        "xss_dom", "WSTG-CLNT-01", "XSS — DOM-Based (Heuristic)",
        "Client", "MEDIUM", "CWE-79",
        "WSTG-CLNT-01 Testing for DOM-based Cross Site Scripting: DOM sources "
        "(location/cookie) flow into dangerous sinks (innerHTML/document.write).",
        "passive",
    ),
    CheckDef(
        "open_redirect", "WSTG-CLNT-04", "Open Redirect",
        "Client", "MEDIUM", "CWE-601",
        "WSTG-CLNT-04 Testing for Client-side URL Redirect: Location header / "
        "meta-refresh redirects to an attacker-controlled external origin.",
        "active", "open_redirect.txt",
    ),
    CheckDef(
        "html_injection", "WSTG-CLNT-03", "HTML Injection",
        "Client", "MEDIUM", "CWE-80",
        "WSTG-CLNT-03 Testing for HTML Injection: marker tag (<h1 notscan=1>) "
        "reflected unescaped into HTML (no JS execution).",
        "active", "html_injection.txt",
    ),
    CheckDef(
        "browser_storage", "WSTG-CLNT-12", "Browser Storage of Secrets",
        "Client", "HIGH", "CWE-922",
        "WSTG-CLNT-12 Testing Browser Storage: tokens/secrets/passwords written to "
        "localStorage/sessionStorage and readable by any XSS.",
        "passive",
    ),
    CheckDef(
        "cors", "WSTG-CLNT-07", "Cross-Origin Resource Sharing (CORS)",
        "Client", "HIGH", "CWE-942",
        "WSTG-CLNT-07 Testing Cross Origin Resource Sharing: reflected "
        "Access-Control-Allow-Origin with credentials, or wildcard + credentials.",
        "probe",
    ),

    # ────────────────────────────── Session ──────────────────────────────
    CheckDef(
        "csrf", "WSTG-SESS-05", "CSRF — Missing Anti-CSRF Token",
        "Session", "MEDIUM", "CWE-352",
        "WSTG-SESS-05 Testing for Cross Site Request Forgery: state-changing request "
        "without anti-CSRF token or SameSite cookie.",
        "passive",
    ),
    CheckDef(
        "jwt", "WSTG-SESS-10 (v5)", "JWT Signature Verification",
        "Session", "HIGH", "CWE-347",
        "WSTG-SESS-10 (v5) JSON Web Tokens: alg=none accepted or token signed with a "
        "weak HMAC secret.",
        "passive",
    ),
    CheckDef(
        "cookies", "WSTG-SESS-02", "Cookie Attributes (Secure/HttpOnly/SameSite)",
        "Session", "MEDIUM", "CWE-614",
        "WSTG-SESS-02 Testing for Cookies Attributes: Set-Cookie without Secure / "
        "HttpOnly / SameSite protection.",
        "passive",
    ),

    # ─────────────────────────────── AuthN ───────────────────────────────
    CheckDef(
        "cache_control", "WSTG-ATHN-06", "Sensitive Response Cacheable",
        "AuthN", "MEDIUM", "CWE-525",
        "WSTG-ATHN-06 Testing for Browser Cache Weaknesses: authenticated/sensitive "
        "response without Cache-Control: no-store/private.",
        "passive",
    ),
    CheckDef(
        "insecure_login", "WSTG-ATHN-01", "Credentials over Cleartext Channel",
        "AuthN", "HIGH", "CWE-319",
        "WSTG-ATHN-01 Testing for Credentials Transported over an Encrypted Channel "
        "(also WSTG-CRYP-03): login form / password / Authorization over http://.",
        "passive",
    ),

    # ─────────────────────────────── AuthZ ───────────────────────────────
    CheckDef(
        "idor", "WSTG-ATHZ-04", "IDOR — Insecure Direct Object Reference",
        "AuthZ", "MEDIUM", "CWE-639",
        "WSTG-ATHZ-04 Testing for Insecure Direct Object References: numeric/GUID "
        "object identifiers in URL without object-level authorisation (heuristic).",
        "passive", "idor.txt",
    ),
)


# ══════════════════════════════════════════════════════════════════
#  Индексы и публичные функции (интерфейс из)
# ══════════════════════════════════════════════════════════════════

_CATALOG_BY_ID: dict[str, CheckDef] = {_c.check_id: _c for _c in CHECK_CATALOG}


def by_kind(kind: str) -> list[CheckDef]:
    """Все чеки указанного вида ("active" | "passive" | "probe"), в порядке каталога."""
    kind_l = (kind or "").strip().lower()
    return [_c for _c in CHECK_CATALOG if _c.kind == kind_l]


def wstg_id_for(check_id: str) -> str:
    """WSTG-ID для check_id; "" если чека нет в каталоге."""
    _c = _CATALOG_BY_ID.get((check_id or "").strip().lower())
    return _c.wstg_id if _c else ""


def payload_file_for(check_id: str) -> str | None:
    """Имя payload-файла в payloads/ для check_id (None — чек без payload'ов)."""
    _c = _CATALOG_BY_ID.get((check_id or "").strip().lower())
    return _c.payload_file if _c else None


def get(check_id: str) -> CheckDef | None:
    """CheckDef по check_id (дополнительный helper для GUI/тестов)."""
    return _CATALOG_BY_ID.get((check_id or "").strip().lower())


# Готовые списки ID (единый источник для GUI): порядок = порядок каталога.
ALL_CHECK_IDS: tuple[str, ...] = tuple(_c.check_id for _c in CHECK_CATALOG)
ACTIVE_CHECK_IDS: tuple[str, ...] = tuple(_c.check_id for _c in by_kind("active"))
PASSIVE_CHECK_IDS: tuple[str, ...] = tuple(_c.check_id for _c in by_kind("passive"))
PROBE_CHECK_IDS: tuple[str, ...] = tuple(_c.check_id for _c in by_kind("probe"))
