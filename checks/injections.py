"""
checks/injections.py — Серверные инъекции и server-side уязвимости.

Реализованные чеки:
  • SQLi         — error-based + boolean/time-based
  • CMDi         — reflection + shell errors
  • SSTI         — Server-Side Template Injection (Jinja2, Twig, Freemarker, …)
  • LDAPi        — LDAP Injection
  • XMLi         — XML/XPath Injection
  • NoSQLi       — NoSQL Injection (MongoDB-style)
  • XXE          — XML External Entity
  • Deserial     — Insecure Deserialization (signature-based)
  • PathTraversal — Path Traversal / LFI / RFI
  • HeaderInj    — Header Injection / CRLF
  • SSRF         — Server-Side Request Forgery
  • FileUpload   — опасные загрузки файлов
  • IDOR         — Insecure Direct Object Reference (пассивный)
  • SSI          — Server-Side Includes Injection (WSTG-INPV-08)
  • HTMLi        — HTML Injection по маркерному тегу (WSTG-CLNT-03)
"""

from __future__ import annotations

import html
import re
import time
import urllib.parse
from typing import Optional

from .base import (
    BaseCheck, CheckContext, CheckResult, Finding,
    ScanRequest, ScanResponse, Severity, VulnCategory,
)
from .fp_rules import is_bare_html_tag, is_html_response


# ══════════════════════════════════════════════════════════════════
#  1. SQL Injection
# ══════════════════════════════════════════════════════════════════

SQLI_ERRORS = [
    r"you have an error in your sql syntax",
    r"warning: mysql_",
    r"unclosed quotation mark after the character string",
    r"quoted string not properly terminated",
    r"pg::syntaxerror",
    r"ora-\d{5}",
    r"microsoft ole db provider for sql server",
    r"sqlite3\.operationalerror",
    r"pdoexception",
    r"syntax error or access violation",
    r"sqlstate\[",
    r"invalid column name",
    r"column count doesn't match",
    r"division by zero",
    r"supplied argument is not a valid mysql",
    r"error in your sql syntax",
    r"db2 sql error",
    r"java\.sql\.sqlexception",
    r"sybase.*server message",
]

SQLI_TIME_PAYLOADS = [
    ("sleep_mysql",  "' AND SLEEP(5)-- -",    5.0, "MySQL"),
    ("sleep_pg",     "'; SELECT pg_sleep(5);--", 5.0, "PostgreSQL"),
    ("sleep_mssql",  "'; WAITFOR DELAY '0:0:5'--", 5.0, "MSSQL"),
    ("sleep_sqlite", "' AND randomblob(500000000/1)--", 4.0, "SQLite"),
    # ── Быстрые 2–3-секундные payload'ы (см. payloads/README.md) ──────────
    # Быстрые 2–2.5–3-секундные payload'ы; строки посимвольно совпадают со
    # строками payloads/sqli_time.txt (чек ищет вхождение в ctx.payload).
    ("sleep2_mysql",          "' AND SLEEP(2)-- -",    2.0, "MySQL"),
    ("sleep25_mysql",         "' AND SLEEP(2.5)-- -",  2.5, "MySQL"),
    ("sleep3_mysql",          "' AND SLEEP(3)-- -",    3.0, "MySQL"),
    ("sleep2_mysql_dquote",   '" AND SLEEP(2)-- -',    2.0, "MySQL"),
    ("sleep2_mysql_numeric",  "1 AND SLEEP(2)-- -",    2.0, "MySQL"),
    ("sleep3_mysql_paren",    "1) AND SLEEP(3)-- -",   3.0, "MySQL"),
    ("sleep2_mysql_qparen",   "') AND SLEEP(2)-- -",   2.0, "MySQL"),
    ("sleep2_mysql_stacked",  "'; SELECT SLEEP(2)-- -", 2.0, "MySQL"),
    ("sleep3_mysql_or",       "' OR SLEEP(3)-- -",     3.0, "MySQL"),
    ("sleep2_mysql_sub",      "' AND (SELECT SLEEP(2))-- -", 2.0, "MySQL"),
    ("sleep3_mysql_derived",  "' AND (SELECT * FROM (SELECT(SLEEP(3)))notscan)-- -", 3.0, "MySQL"),
    ("sleep2_pg",             "'; SELECT pg_sleep(2);--", 2.0, "PostgreSQL"),
    ("sleep3_pg",             "'; SELECT pg_sleep(3)-- -", 3.0, "PostgreSQL"),
    ("sleep25_pg",            "'; SELECT pg_sleep(2.5);--", 2.5, "PostgreSQL"),
    ("waitfor2_mssql",        "'; WAITFOR DELAY '0:0:2'-- -", 2.0, "MSSQL"),
    ("waitfor3_mssql",        "'; WAITFOR DELAY '0:0:3'--", 3.0, "MSSQL"),
    ("waitfor2_mssql_numeric", "1; WAITFOR DELAY '0:0:2'--", 2.0, "MSSQL"),
    ("oracle_pipe3",          "'; SELECT dbms_pipe.receive_message(('notscan'),3) FROM dual--", 3.0, "Oracle"),
    ("oracle_lock2",          "' AND dbms_lock.sleep(2)=1-- -", 2.0, "Oracle"),
]

SQLI_BOOL_PAIRS = [
    ("' AND 1=1--", "' AND 1=2--"),
]


class SQLiErrorCheck(BaseCheck):
    check_id = "sqli"
    vuln_type = "sqli"
    category = VulnCategory.INJECTION_SERVER
    severity = Severity.HIGH
    name = "SQL Injection (Error-Based)"
    cwe = "CWE-89"

    def check(self, req: ScanRequest, resp: ScanResponse, ctx: CheckContext) -> CheckResult:
        if not self.enabled:
            return self.skip()
        lower = resp.text.lower()
        for pattern in SQLI_ERRORS:
            m = re.search(pattern, lower)
            if m:
                return self.found(self.make_finding(
                    f"SQL error pattern matched: '{m.group()}'",
                    req, resp, ctx,
                    recommendation="Use parameterised queries / prepared statements.",
                ))
        return self.ok()


class SQLiTimeCheck(BaseCheck):
    """
    Time-based blind SQLi — детекция ТОЛЬКО по задержке ответа (M5).

    Порог относительный: max(threshold_sec*1000, baseline_ms*3 + 1000).
    Если baseline_ms <= 0 (калибровки нет) — только абсолютный порог threshold_sec.
    Никаких error-сигнатур: SQL-ошибка в теле — это error-based (SQLiErrorCheck),
    а не доказательство time-based инъекции.
    """
    check_id = "sqli_time"
    vuln_type = "sqli_time"   # M5: отличимо от error-based "sqli"
    category = VulnCategory.INJECTION_SERVER
    severity = Severity.HIGH
    name = "SQL Injection (Time-Based Blind)"
    cwe = "CWE-89"

    THRESHOLD = 4.5  # seconds

    def required_delay_ms(self, threshold_sec: float, baseline_ms: float) -> float:
        """Минимальная задержка (мс) для вывода о time-based SQLi."""
        absolute = threshold_sec * 1000.0
        if baseline_ms and baseline_ms > 0:
            return max(absolute, baseline_ms * 3.0 + 1000.0)
        return absolute

    def check(self, req: ScanRequest, resp: ScanResponse, ctx: CheckContext) -> CheckResult:
        if not self.enabled:
            return self.skip()
        for _pid, payload, threshold, dbtype in SQLI_TIME_PAYLOADS:
            if payload.lower() not in ctx.payload.lower():
                continue
            required_ms = self.required_delay_ms(threshold, getattr(ctx, "baseline_ms", 0.0) or 0.0)
            if resp.elapsed_ms >= required_ms:
                return self.found(self.make_finding(
                    f"Response delayed {resp.elapsed_ms:.0f}ms \u2265 required {required_ms:.0f}ms "
                    f"(absolute {threshold:.1f}s, baseline {getattr(ctx, 'baseline_ms', 0.0) or 0.0:.0f}ms) "
                    f"\u2014 possible {dbtype} time-based blind SQLi",
                    req, resp, ctx,
                    recommendation="Use parameterised queries.",
                ))
        return self.ok()


# ══════════════════════════════════════════════════════════════════
#  2. Command Injection (CMDi)
# ══════════════════════════════════════════════════════════════════

CMDI_ERRORS = [
    r"sh:\s*\d+:", r"bash:\s*line", r"syntax error near unexpected token",
    r"command not found", r"sh:\s+can't open", r"/bin/sh:", r"/bin/bash:",
    r"permission denied", r"ambiguous redirect", r"bad substitution",
    r"no such file or directory",
    r"uid=\d+\(", r"gid=\d+\(",   # id output
    r"root:x:0:0",                  # /etc/passwd
    r"win32_operatingsystem",       # Windows WMI
]

CMDI_REFLECTION_MARKERS = ["pwned", "vulntest_cmdi_marker"]


class CMDiCheck(BaseCheck):
    check_id = "cmdi"
    vuln_type = "cmdi"
    category = VulnCategory.INJECTION_SERVER
    severity = Severity.CRITICAL
    name = "Command Injection (CMDi)"
    cwe = "CWE-78"

    def check(self, req: ScanRequest, resp: ScanResponse, ctx: CheckContext) -> CheckResult:
        if not self.enabled:
            return self.skip()
        lower = resp.text.lower()
        # Только реальные ошибки/вывод шелла, а не отражение payload.
        for pattern in CMDI_ERRORS:
            m = re.search(pattern, lower)
            if m:
                return self.found(self.make_finding(
                    f"Shell error/output: '{m.group()[:80]}'",
                    req, resp, ctx, severity=Severity.CRITICAL,
                ))
        return self.ok()


# ══════════════════════════════════════════════════════════════════
#  3. SSTI — Server-Side Template Injection
# ══════════════════════════════════════════════════════════════════

SSTI_PROBES = [
    ("{{7*7}}",       "49",    "Jinja2/Twig/generic"),
    ("${7*7}",        "49",    "FreeMarker/Velocity"),
    ("#{7*7}",        "49",    "Pebble/Thymeleaf"),
    ("<%= 7*7 %>",    "49",    "ERB/EJS"),
    ("{{7*'7'}}",     "7777777", "Jinja2 (string mult)"),
    ("a{*comment*}b", "ab",   "Smarty"),
    ("${{7*7}}",      "49",    "Groovy/Spring"),
]

SSTI_ERROR_SIGS = [
    r"jinja2\.exceptions",
    r"org\.springframework\.expression",
    r"thymeleaf\.exceptions",
    r"pebble\.error",
    r"velocity error",
    r"smarty error",
    r"templateexception",
]


class SSTICheck(BaseCheck):
    check_id = "ssti"
    vuln_type = "ssti"
    category = VulnCategory.INJECTION_SERVER
    severity = Severity.CRITICAL
    name = "Server-Side Template Injection (SSTI)"
    cwe = "CWE-94"

    def check(self, req: ScanRequest, resp: ScanResponse, ctx: CheckContext) -> CheckResult:
        if not self.enabled:
            return self.skip()
        # Arithmetic result check
        for probe, expected, engine in SSTI_PROBES:
            if probe in ctx.payload and expected in resp.text:
                return self.found(self.make_finding(
                    f"SSTI: arithmetic result '{expected}' found in response "
                    f"(engine hint: {engine})",
                    req, resp, ctx, severity=Severity.CRITICAL,
                    recommendation="Never pass user input to template engines.",
                ))
        # Error signatures
        lower = resp.text.lower()
        for pattern in SSTI_ERROR_SIGS:
            m = re.search(pattern, lower)
            if m:
                return self.found(self.make_finding(
                    f"Template engine error: '{m.group()[:80]}'",
                    req, resp, ctx, severity=Severity.HIGH,
                ))
        return self.ok()


# ══════════════════════════════════════════════════════════════════
#  4. LDAP Injection
# ══════════════════════════════════════════════════════════════════

LDAP_ERRORS = [
    r"ldap_bind\(\)", r"ldap error", r"javax\.naming\.namingexception",
    r"com\.sun\.jndi\.ldap", r"invalid dn syntax", r"ldap:.*error",
    r"activedirectory.*exception",
]


class LDAPInjectionCheck(BaseCheck):
    check_id = "ldap_injection"
    vuln_type = "ldap_injection"
    category = VulnCategory.INJECTION_SERVER
    severity = Severity.HIGH
    name = "LDAP Injection"
    cwe = "CWE-90"

    def check(self, req: ScanRequest, resp: ScanResponse, ctx: CheckContext) -> CheckResult:
        if not self.enabled:
            return self.skip()
        lower = resp.text.lower()
        for pattern in LDAP_ERRORS:
            m = re.search(pattern, lower)
            if m:
                return self.found(self.make_finding(
                    f"LDAP error/exception: '{m.group()[:80]}'",
                    req, resp, ctx,
                    recommendation="Escape LDAP special chars in user input.",
                ))
        return self.ok()


# ══════════════════════════════════════════════════════════════════
#  5. XML/XPath Injection
# ══════════════════════════════════════════════════════════════════

XML_XPATH_ERRORS = [
    r"xpath.*error", r"invalid xpath", r"xpathexception",
    r"xmlparseerror", r"sax parse exception",
    r"org\.xml\.sax", r"javax\.xml\.xpath",
    r"system\.xml\.xpath",
    r"unterminated string literal.*xpath",
]


class XPathInjectionCheck(BaseCheck):
    check_id = "xpath_injection"
    vuln_type = "xpath_injection"
    category = VulnCategory.INJECTION_SERVER
    severity = Severity.HIGH
    name = "XPath/XML Injection"
    cwe = "CWE-643"

    def check(self, req: ScanRequest, resp: ScanResponse, ctx: CheckContext) -> CheckResult:
        if not self.enabled:
            return self.skip()
        lower = resp.text.lower()
        for pattern in XML_XPATH_ERRORS:
            m = re.search(pattern, lower)
            if m:
                return self.found(self.make_finding(
                    f"XPath/XML error: '{m.group()[:80]}'",
                    req, resp, ctx,
                    recommendation="Validate and escape XML/XPath input.",
                ))
        return self.ok()


# ══════════════════════════════════════════════════════════════════
#  6. NoSQL Injection
# ══════════════════════════════════════════════════════════════════

NOSQL_ERRORS = [
    r"mongoparseerror", r"bson\.errors", r"mongoerror",
    r"castError", r"mongoose.*validationerror",
    r"couchdb.*error", r"elasticsearch.*exception",
    r"com\.mongodb",
]

NOSQL_BYPASS_MARKERS = [
    ("$gt", r"\$gt"),
    ("$ne", r"\$ne"),
    ("$where", r"\$where"),
]


class NoSQLInjectionCheck(BaseCheck):
    check_id = "nosql_injection"
    vuln_type = "nosql_injection"
    category = VulnCategory.INJECTION_SERVER
    severity = Severity.HIGH
    name = "NoSQL Injection"
    cwe = "CWE-943"

    def check(self, req: ScanRequest, resp: ScanResponse, ctx: CheckContext) -> CheckResult:
        if not self.enabled:
            return self.skip()
        lower = resp.text.lower()
        for pattern in NOSQL_ERRORS:
            m = re.search(pattern, lower)
            if m:
                return self.found(self.make_finding(
                    f"NoSQL error: '{m.group()[:80]}'",
                    req, resp, ctx,
                    recommendation="Sanitize NoSQL operator injection ($gt, $ne, $where).",
                ))
        # (auth-bypass heuristic "200 + оператор в payload" убрана — это не доказательство)
        return self.ok()


# ══════════════════════════════════════════════════════════════════
#  7. XXE — XML External Entity
# ══════════════════════════════════════════════════════════════════

XXE_INDICATORS = [
    r"root:x:0:0",              # /etc/passwd leaked
    r"\[boot loader\]",         # win.ini
    r"file:///",                # file URI reflected
    r"<!entity",                # entity declaration echoed
    r"doctype.*system",
    r"external entity",
    r"xmlreader.*error",
]

XXE_PAYLOADS_SIGNATURES = ["<!DOCTYPE", "<!ENTITY", "SYSTEM", "file:///"]


class XXECheck(BaseCheck):
    check_id = "xxe"
    vuln_type = "xxe"
    category = VulnCategory.INJECTION_SERVER
    severity = Severity.HIGH
    name = "XML External Entity (XXE)"
    cwe = "CWE-611"

    def check(self, req: ScanRequest, resp: ScanResponse, ctx: CheckContext) -> CheckResult:
        if not self.enabled:
            return self.skip()
        # Only relevant if payload or body contains XML markers
        payload_upper = ctx.payload.upper()
        has_xml_payload = any(sig.upper() in payload_upper for sig in XXE_PAYLOADS_SIGNATURES)
        body_upper = req.body.decode("utf-8", errors="ignore").upper()
        has_xml_body = "<" in body_upper and ">" in body_upper

        if not (has_xml_payload or has_xml_body):
            return self.skip()

        lower = resp.text.lower()
        for pattern in XXE_INDICATORS:
            m = re.search(pattern, lower)
            if m:
                return self.found(self.make_finding(
                    f"XXE indicator: '{m.group()[:80]}'",
                    req, resp, ctx, severity=Severity.HIGH,
                    recommendation="Disable external entity processing in XML parser.",
                ))
        return self.ok()


# ══════════════════════════════════════════════════════════════════
#  8. Insecure Deserialization
# ══════════════════════════════════════════════════════════════════

DESERIAL_MARKERS = [
    r"unserialize\(\)",
    r"java\.io\.objectinputstream",
    r"classnotfoundexception",
    r"java\.lang\.runtime",
    r"ysoserial",
    r"pickle\.loads",
    r"php unserialize",
    r"unmarshaller",
    r"deserialization.*error",
    r"gadget chain",
]

DESERIAL_PAYLOAD_SIGS = [
    b"\xac\xed\x00\x05",  # Java serialized object magic bytes
    b"rO0AB",             # Base64 Java serial
    b"O:4:",              # PHP serialize O:<len>
    b"a:1:",              # PHP array serialize
]


class DeserializationCheck(BaseCheck):
    check_id = "deserialization"
    vuln_type = "deserialization"
    category = VulnCategory.DESERIALIZATION
    severity = Severity.CRITICAL
    name = "Insecure Deserialization"
    cwe = "CWE-502"

    def check(self, req: ScanRequest, resp: ScanResponse, ctx: CheckContext) -> CheckResult:
        if not self.enabled:
            return self.skip()

        # Check if payload/body looks like serialized data
        body_bytes = req.body
        has_serial_sig = any(sig in body_bytes for sig in DESERIAL_PAYLOAD_SIGS)

        # Check for serialized cookies
        cookie_header = req.headers.get("Cookie", req.headers.get("cookie", ""))
        cookie_has_serial = any(
            sig.decode("utf-8", errors="ignore") in cookie_header
            for sig in [b"rO0AB", b"O:4:"]
        )

        if not (has_serial_sig or cookie_has_serial or "rO0AB" in ctx.payload):
            return self.skip()

        lower = resp.text.lower()
        for pattern in DESERIAL_MARKERS:
            m = re.search(pattern, lower)
            if m:
                return self.found(self.make_finding(
                    f"Deserialization error/marker: '{m.group()[:80]}'",
                    req, resp, ctx, severity=Severity.CRITICAL,
                    recommendation="Never deserialize untrusted data. Use safe formats (JSON).",
                ))

        # If server returned 500 with serialized payload — suspicious
        if resp.status_code == 500 and has_serial_sig:
            return self.found(self.make_finding(
                "Server returned 500 when receiving serialized payload — possible deserialization issue",
                req, resp, ctx, severity=Severity.MEDIUM,
            ))
        return self.ok()


# ══════════════════════════════════════════════════════════════════
#  9. Path Traversal / LFI / RFI
# ══════════════════════════════════════════════════════════════════

PATH_TRAV_INDICATORS = [
    r"root:x:0:0",
    r"\[boot loader\]",
    r"for 16-bit app support",
    r"\[fonts\]",
    r"/etc/passwd",
    r"c:\\windows\\",
    r"<\?php",
    r"php warning.*include",
    r"failed to open stream",
    r"no such file or directory",
    r"include_path",
]

PATH_TRAV_PAYLOAD_SIGS = ["../", "..\\", "%2e%2e", "%252e%252e", "....//"]


class PathTraversalCheck(BaseCheck):
    check_id = "path_traversal"
    vuln_type = "path_traversal"
    category = VulnCategory.FILE
    severity = Severity.HIGH
    name = "Path Traversal / LFI / RFI"
    cwe = "CWE-22"

    def check(self, req: ScanRequest, resp: ScanResponse, ctx: CheckContext) -> CheckResult:
        if not self.enabled:
            return self.skip()

        has_trav_payload = any(
            sig.lower() in ctx.payload.lower() for sig in PATH_TRAV_PAYLOAD_SIGS
        )
        if not has_trav_payload:
            return self.skip()

        lower = resp.text.lower()
        for pattern in PATH_TRAV_INDICATORS:
            m = re.search(pattern, lower)
            if m:
                return self.found(self.make_finding(
                    f"Path traversal indicator: '{m.group()[:80]}'",
                    req, resp, ctx,
                    recommendation="Canonicalise paths, use allowlists for file access.",
                ))
        return self.ok()


# ══════════════════════════════════════════════════════════════════
#  10. Header Injection / CRLF Injection
# ══════════════════════════════════════════════════════════════════

CRLF_PAYLOAD_SIGS = ["\r\n", "%0d%0a", "%0D%0A", "\\r\\n"]
CRLF_INJECTED_HEADER = "X-VulnScanner-CRLF-Test"

# Заголовки, которые легитимно присутствуют почти в любом ответе — их наличие
# само по себе НЕ является признаком CRLF-инъекции.
CRLF_BENIGN_HEADERS = {
    "host", "content-type", "content-length", "connection", "date", "server",
    "location", "set-cookie", "x-powered-by", "cache-control", "pragma",
    "expires", "keep-alive", "accept-ranges", "transfer-encoding",
    "content-encoding", "vary", "etag", "last-modified",
    "x-content-type-options", "x-frame-options", "strict-transport-security",
    "content-security-policy", "referrer-policy", "permissions-policy",
    "access-control-allow-origin",
}


def _payload_injected_header_names(payload: str) -> set[str]:
    """Извлекает имена заголовков, которые payload пытается инъектировать (CRLF)."""
    decoded = payload or ""
    for enc, ch in (
        ("%0d%0a", "\r\n"), ("%0a", "\n"), ("%0d", "\r"),
        ("%0D%0A", "\r\n"), ("%0A", "\n"), ("%0D", "\r"),
        ("\\r\\n", "\r\n"), ("\\n", "\n"), ("\\r", "\r"),
    ):
        decoded = decoded.replace(enc, ch)
    names: set[str] = set()
    for m in re.finditer(r'(?:^|[\r\n])([A-Za-z0-9_-]+)\s*:', decoded):
        names.add(m.group(1).lower())
    return names


class HeaderCRLFInjectionCheck(BaseCheck):
    check_id = "crlf_injection"
    vuln_type = "crlf_injection"
    category = VulnCategory.INJECTION_SERVER
    severity = Severity.MEDIUM
    name = "Header Injection / CRLF Injection"
    cwe = "CWE-113"

    def check(self, req: ScanRequest, resp: ScanResponse, ctx: CheckContext) -> CheckResult:
        if not self.enabled:
            return self.skip()

        has_crlf = any(sig.lower() in ctx.payload.lower() for sig in CRLF_PAYLOAD_SIGS)
        if not has_crlf:
            return self.skip()

        resp_names = {k.lower() for k in resp.headers.keys()}

        # 1. Unambiguous marker header injected by the payload
        if CRLF_INJECTED_HEADER.lower() in resp_names:
            return self.found(self.make_finding(
                f"CRLF-injected header '{CRLF_INJECTED_HEADER}' found in response",
                req, resp, ctx,
                recommendation="Strip \\r\\n from all user-controlled header values.",
            ))

        # 2. Non-standard header name the payload attempts to inject appears
        for name in _payload_injected_header_names(ctx.payload):
            if name in resp_names and name not in CRLF_BENIGN_HEADERS:
                return self.found(self.make_finding(
                    f"CRLF: injected header '{name}' in response",
                    req, resp, ctx,
                ))
        return self.ok()


# ══════════════════════════════════════════════════════════════════
#  11. SSRF — Server-Side Request Forgery
# ══════════════════════════════════════════════════════════════════

SSRF_PAYLOAD_SIGS = [
    "127.0.0.1", "localhost", "169.254.169.254",
    "file://", "dict://", "gopher://", "ftp://",
    "http://169.254", "http://metadata",
]

SSRF_INDICATORS = [
    r"aws.*metadata",
    r"169\.254\.169\.254",
    r"metadata\.google\.internal",
    r"connection refused.*localhost",
    r"failed to connect.*127\.",
    r"ec2.*metadata",
    r"connection to.*internal",
]


class SSRFCheck(BaseCheck):
    check_id = "ssrf"
    vuln_type = "ssrf"
    category = VulnCategory.SSRF
    severity = Severity.HIGH
    name = "Server-Side Request Forgery (SSRF)"
    cwe = "CWE-918"

    def check(self, req: ScanRequest, resp: ScanResponse, ctx: CheckContext) -> CheckResult:
        if not self.enabled:
            return self.skip()

        has_ssrf_payload = any(
            sig.lower() in ctx.payload.lower() for sig in SSRF_PAYLOAD_SIGS
        )
        if not has_ssrf_payload:
            return self.skip()

        lower = resp.text.lower()
        for pattern in SSRF_INDICATORS:
            m = re.search(pattern, lower)
            if m:
                return self.found(self.make_finding(
                    f"SSRF indicator in response: '{m.group()[:80]}'",
                    req, resp, ctx, severity=Severity.HIGH,
                    recommendation="Validate and restrict URLs to an allowlist.",
                ))

        # DNS/connection time anomaly (basic heuristic: > 8s)
        if resp.elapsed_ms > 8000 and any(s in ctx.payload for s in ["localhost", "127.0.0.1"]):
            return self.found(self.make_finding(
                f"Long response time ({resp.elapsed_ms:.0f}ms) with SSRF payload — possible blind SSRF",
                req, resp, ctx, severity=Severity.MEDIUM,
            ))
        return self.ok()


# ══════════════════════════════════════════════════════════════════
#  12. File Upload
# ══════════════════════════════════════════════════════════════════

DANGEROUS_EXTENSIONS = [
    ".php", ".php3", ".php4", ".php5", ".phtml", ".phar",
    ".asp", ".aspx", ".jsp", ".jspx", ".cfm",
    ".py", ".pl", ".rb", ".sh", ".bash",
    ".exe", ".bat", ".cmd",
    ".htaccess", ".htpasswd",
]

WEBSHELL_MARKERS = [
    r"<\?php.*\$_",          # PHP webshell
    r"eval\s*\(.*base64",    # eval(base64_decode
    r"system\s*\(",           # system() call
    r"exec\s*\(",
    r"passthru\s*\(",
    r"shell_exec\s*\(",
    r"popen\s*\(",
]


class FileUploadCheck(BaseCheck):
    """Пассивный чек: анализирует, были ли загружены опасные файлы."""
    check_id = "file_upload"
    vuln_type = "file_upload"
    category = VulnCategory.FILE
    severity = Severity.CRITICAL
    name = "Dangerous File Upload"
    cwe = "CWE-434"
    passive = True
    requires_payload = False

    def check(self, req: ScanRequest, resp: ScanResponse, ctx: CheckContext) -> CheckResult:
        if not self.enabled:
            return self.skip()

        # Only relevant for multipart requests
        ct = req.headers.get("Content-Type", req.headers.get("content-type", "")).lower()
        if "multipart/form-data" not in ct:
            return self.skip()

        body_text = req.body.decode("utf-8", errors="ignore").lower()

        # Check for dangerous extensions in filename
        for ext in DANGEROUS_EXTENSIONS:
            if f'filename="' in body_text and ext in body_text:
                return self.found(self.make_finding(
                    f"Upload attempt with dangerous extension '{ext}'",
                    req, resp, ctx, severity=Severity.CRITICAL,
                    recommendation="Validate file type by content (magic bytes), not extension.",
                ))

        # Check if server response contains webshell markers
        for pattern in WEBSHELL_MARKERS:
            m = re.search(pattern, resp.text, re.IGNORECASE)
            if m:
                return self.found(self.make_finding(
                    f"Possible webshell content in response: '{m.group()[:80]}'",
                    req, resp, ctx, severity=Severity.CRITICAL,
                ))
        return self.ok()


# ══════════════════════════════════════════════════════════════════
#  13. IDOR — Insecure Direct Object Reference (пассивный)
# ══════════════════════════════════════════════════════════════════

IDOR_ID_PATTERNS = [
    r"[?&](id|user_id|account|order|invoice|file|doc|item|product)=(\d+)",
    r"/(\d{3,})[/?$]",
    r"[?&](uuid|guid)=([a-f0-9\-]{20,})",
]


class IDORCheck(BaseCheck):
    """
    Пассивный чек: обнаруживает числовые/GUID-идентификаторы в URL.
    Не выполняет замену — только помечает потенциальные точки IDOR.

    TODO: активная версия — замена ID на соседние значения и сравнение ответов.
    """
    check_id = "idor"
    vuln_type = "idor"
    category = VulnCategory.BUSINESS_LOGIC
    severity = Severity.MEDIUM
    name = "IDOR — Insecure Direct Object Reference"
    cwe = "CWE-639"
    passive = True
    requires_payload = False

    def check(self, req: ScanRequest, resp: ScanResponse, ctx: CheckContext) -> CheckResult:
        if not self.enabled:
            return self.skip()

        for pattern in IDOR_ID_PATTERNS:
            m = re.search(pattern, req.url, re.IGNORECASE)
            if m and resp.status_code == 200:
                param = m.group(1) if m.lastindex and m.lastindex >= 1 else "id"
                value = m.group(2) if m.lastindex and m.lastindex >= 2 else m.group()
                return self.found(self.make_finding(
                    f"Numeric/GUID identifier '{param}={value}' in URL — "
                    f"potential IDOR. Verify access controls.",
                    req, resp, ctx, severity=Severity.LOW,
                    recommendation="Implement object-level authorisation checks.",
                    vuln_type="idor",
                ))
        return self.ok()


# ══════════════════════════════════════════════════════════════════
#  14. SSI Injection — WSTG-INPV-08
# ══════════════════════════════════════════════════════════════════
#
# Payload'ы SSI живут в payloads/ssi.txt (создаёт агент payloads).
# Матчер общий с scanner_core.match_ssi (engine использует ssi_indicator()).

SSI_PAYLOAD_SIGS = ("<!--#", "#echo", "#exec", "#include", "#printenv",
                    "#config", "#fsize", "#flastmod")

# Классическое сообщение Apache SSI и типовые ошибки обработки директив.
SSI_ERROR_INDICATORS = (
    "[an error occurred while processing this directive]",
    "error processing ssi",
    "ssi processing error",
    "ssi: warning",
    "ssi error:",
    "ssi directive error",
)

# Вывод SSI: дата (<!--#echo var="DATE_LOCAL" -->).
SSI_DATE_RE = re.compile(
    r"(?:Monday|Tuesday|Wednesday|Thursday|Friday|Saturday|Sunday),?\s+"
    r"\d{1,2}[-\s](?:Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)[-\s]\d{4}"
    r"|\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}",
    re.IGNORECASE,
)
# Вывод <!--#printenv -->: CGI-переменные сервера.
SSI_ENV_RE = re.compile(
    r"\b(DOCUMENT_ROOT|SERVER_SOFTWARE|GATEWAY_INTERFACE|HTTP_HOST|"
    r"SERVER_NAME|SERVER_PORT|REMOTE_ADDR|SCRIPT_NAME|REQUEST_METHOD)\b"
)
# Вывод <!--#exec cmd="id" --> / <!--#include virtual="/etc/passwd" -->.
SSI_EXEC_RE = re.compile(r"\b(uid=\d+(?:\(\w+\))?|gid=\d+|root:x:0:0)\b")
# Сырая (необработанная) SSI-директива в payload'е.
_SSI_RAW_DIRECTIVE_RE = re.compile(r"<!--#\s*[A-Za-z_]+[^>]*-->", re.IGNORECASE)


def _ssi_escaped_payload_forms(payload: str) -> list[str]:
    """Формы payload'а при HTML/URL-экранировании (не исполнение директивы)."""
    forms: list[str] = []
    for escaped in (
        html.escape(payload),                              # < > & " '  (html.escape(q))
        html.escape(payload, quote=False),                 # < > &
        payload.replace("<", "&lt;").replace(">", "&gt;"),  # кавычки не экранируются
    ):
        if escaped and escaped != payload and escaped not in forms:
            forms.append(escaped)
    quoted = urllib.parse.quote(payload, safe="")
    if quoted != payload and quoted not in forms:
        forms.append(quoted)
    return forms


def _ssi_is_reflected(payload: str, response_text: str) -> bool:
    """True, если payload отразился как есть, HTML-escaped или URL-encoded.

    Исполненная SSI-директива заменяется своим выводом и НЕ отражается, поэтому
    любая форма отражения отменяет strong-сигналы «directive executed» (иначе
    html.escape-эхо даёт ложное срабатывание на строке-маркере).
    """
    if payload in response_text:
        return True
    return any(form in response_text for form in _ssi_escaped_payload_forms(payload))


def ssi_indicator(
    payload: str,
    response_text: str,
    response_headers: Optional[dict] = None,
) -> Optional[str]:
    """
    Evidence-строка, если ответ демонстрирует SSI-инъекцию.

    Уровни доказательства:
      1) SSI-ошибки (Apache: "[an error occurred while processing this directive]");
      2) исполнение директивы — вывод date/printenv/exec/маркер (директива НЕ
         отразилась ни в одной форме, т.е. её реально обработал SSI-движок);
      3) слабый сигнал — директива из payload'а отразилась в HTML-ответе
         НЕэкранированной (возможна SSI-инъекция в SSI-обрабатываемом шаблоне;
         требует ручной проверки — помечается в evidence).

    Выполненная директива заменяется выводом, а не отражается; поэтому
    HTML-escaped/URL-encoded эхо (``&lt;!--#echo ... --&gt;``) — НЕ находка.
    """
    if not payload or not response_text:
        return None
    payload_l = payload.lower()
    if not any(sig.lower() in payload_l for sig in SSI_PAYLOAD_SIGS):
        return None

    text_l = response_text.lower()
    # SSI-ошибка — это ответ сервера, а не эхо payload'а: проверяем всегда.
    for sig in SSI_ERROR_INDICATORS:
        if sig in text_l:
            return f"SSI error signature in response: '{sig}'"

    # Отражение payload'а (raw/escaped/url-encoded) — не исполнение директивы.
    reflected = _ssi_is_reflected(payload, response_text)
    html_ok = is_html_response(response_headers) if response_headers is not None else True
    if not reflected and html_ok:
        # Маркер, который SSI-движок выводит при исполнении директивы
        # (#echo var="NOTSCAN_SSI_MARKER" / #exec cmd="echo NOTSCAN_SSI_MARKER").
        if "notscan_ssi_marker" in payload_l and "notscan_ssi_marker" in text_l:
            return ("SSI directive executed — marker output 'NOTSCAN_SSI_MARKER' "
                    "(directive replaced by its output)")
        if "#echo" in payload_l and ("date_local" in payload_l or "date_gmt" in payload_l):
            m = SSI_DATE_RE.search(response_text)
            if m:
                return f"SSI directive executed — date output '{m.group()[:48]}'"
        if "#printenv" in payload_l:
            m = SSI_ENV_RE.search(response_text)
            if m:
                return f"SSI printenv output — server variable '{m.group(1)}'"
        if any(k in payload_l for k in ("#exec", "#include", "#fsize", "#flastmod", "#config")):
            m = SSI_EXEC_RE.search(response_text)
            if m:
                return f"SSI directive output — command/file data '{m.group(1)}'"

    # Слабый сигнал: неэкранированная SSI-директива в HTML-ответе.
    directive = _SSI_RAW_DIRECTIVE_RE.search(payload)
    if directive:
        if not html_ok:
            return None
        if directive.group(0) in response_text:
            return ("SSI directive reflected unescaped into HTML response — "
                    f"possible SSI injection (needs manual verification): "
                    f"'{directive.group(0)[:100]}'")
    return None


class SSIInjectionCheck(BaseCheck):
    """Server-Side Includes injection (WSTG-INPV-08)."""

    check_id = "ssi_injection"
    vuln_type = "ssi_injection"
    category = VulnCategory.INJECTION_SERVER
    severity = Severity.HIGH
    name = "Server-Side Includes (SSI) Injection"
    description = "WSTG-INPV-08: исполнение SSI-директив (<!--#echo/#exec/#include)."
    cwe = "CWE-97"

    def check(self, req: ScanRequest, resp: ScanResponse, ctx: CheckContext) -> CheckResult:
        if not self.enabled:
            return self.skip()
        evidence = ssi_indicator(ctx.payload or "", resp.text or "", resp.headers)
        if evidence:
            # Отражённая (но не обработанная) директива — слабый сигнал: нужно
            # подтверждение вручную, поэтому severity ниже.
            weak = "needs manual verification" in evidence
            if ctx.baseline_text and ctx.payload and ctx.payload in ctx.baseline_text:
                return self.ok()  # payload уже был в baseline — не наш сигнал
            return self.found(self.make_finding(
                evidence, req, resp, ctx,
                severity=Severity.MEDIUM if weak else Severity.HIGH,
                recommendation="Не отдавай пользовательский ввод в SSI-обрабатываемые "
                               "страницы; экранируй '<!--#' и отключи SSI там, где он не нужен.",
                cwe=self.cwe,
            ))
        return self.ok()


# ══════════════════════════════════════════════════════════════════
#  15. HTML Injection — WSTG-CLNT-03
# ══════════════════════════════════════════════════════════════════
#
# Payload'ы — маркерные теги вида "<h1 notscan=1>PWNED</h1>" (html_injection.txt,
# создаёт агент payloads). Матчер общий с scanner_core.match_html_injection.
# Это НЕ XSS: находка = маркерный тег отразился НЕэкранированным.

HTML_MARKER_ATTR = "notscan"
_HTML_MARKER_RE = re.compile(
    r"<\s*([A-Za-z][A-Za-z0-9]*)\b[^>]*?\b" + HTML_MARKER_ATTR + r"\s*=\s*['\"]?(\d+)['\"]?[^>]*>",
    re.IGNORECASE,
)


def html_injection_indicator(
    payload: str,
    response_text: str,
    response_headers: Optional[dict] = None,
) -> Optional[str]:
    """
    Evidence-строка, если маркерный HTML-тег из payload'а отразился
    неэкранированным в HTML-ответе.

    • «голые» теги без атрибутов игнорируются (bare-tag правило fp_rules);
    • отражение в JSON/plain-ответе — не HTML-инъекция (is_html_response);
    • экранированные формы (&lt;h1 notscan=1&gt;) не считаются находкой.
    """
    if not payload or not response_text:
        return None
    if is_bare_html_tag(payload):
        return None
    if HTML_MARKER_ATTR not in payload.lower():
        return None
    if response_headers is not None:
        try:
            from .fp_rules import is_html_response
            if not is_html_response(response_headers):
                return None
        except Exception:
            pass

    m = _HTML_MARKER_RE.search(payload)
    if m:
        tag, num = m.group(1), m.group(2)
        marker_re = re.compile(
            r"<\s*" + re.escape(tag) + r"\b[^>]*?\b" + HTML_MARKER_ATTR
            + r"\s*=\s*['\"]?" + re.escape(num) + r"['\"]?[^>]*>",
            re.IGNORECASE,
        )
        found = marker_re.search(response_text)
        if found:
            return (f"HTML-маркер отражён неэкранированным: "
                    f"'{found.group()[:120]}' (HTML injection, без JS-исполнения)")
        return None

    # Fallback: payload с маркером отразился целиком/частично.
    if payload in response_text:
        return f"HTML-payload с маркером отражён verbatim: '{payload[:120]}'"
    return None


class HTMLInjectionCheck(BaseCheck):
    """HTML Injection (WSTG-CLNT-03) — маркерный тег отразился неэкранированным."""

    check_id = "html_injection"
    vuln_type = "html_injection"
    category = VulnCategory.INJECTION_CLIENT
    severity = Severity.MEDIUM
    name = "HTML Injection"
    description = "WSTG-CLNT-03: неэкранированный HTML-маркер в ответе."
    cwe = "CWE-80"

    def check(self, req: ScanRequest, resp: ScanResponse, ctx: CheckContext) -> CheckResult:
        if not self.enabled:
            return self.skip()
        evidence = html_injection_indicator(
            ctx.payload or "", resp.text or "", resp.headers
        )
        if evidence:
            return self.found(self.make_finding(
                evidence, req, resp, ctx,
                recommendation="HTML-encode пользовательский вывод (<, >, &, \"); "
                               "используй контекстное экранирование шаблонизатора.",
                cwe=self.cwe,
            ))
        return self.ok()


# ══════════════════════════════════════════════════════════════════
#  Экспорт всех injection-чеков
# ══════════════════════════════════════════════════════════════════

ALL_INJECTION_CHECKS: list[type[BaseCheck]] = [
    SQLiErrorCheck,
    SQLiTimeCheck,
    CMDiCheck,
    SSTICheck,
    LDAPInjectionCheck,
    XPathInjectionCheck,
    NoSQLInjectionCheck,
    XXECheck,
    DeserializationCheck,
    PathTraversalCheck,
    HeaderCRLFInjectionCheck,
    SSRFCheck,
    FileUploadCheck,
    IDORCheck,
    SSIInjectionCheck,
    HTMLInjectionCheck,
]
