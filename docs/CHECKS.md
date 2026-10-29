# WSTG check catalog

`notscan` ships **43 checks**: 17 active (mutation-based), 19 passive (response analysis)
and 7 probe (dedicated HTTP requests). The catalog lives in [`checks/catalog.py`](../checks/catalog.py)
and is the single source of truth for the GUI (Checks/WSTG tab, scan-config badges), the
WSTG mapping of findings (`checks/runner.py::WSTG_ID_MAP`) and payload files
(`scanner_core.load_payloads`).

WSTG identifiers follow the OWASP Web Security Testing Guide **v4.2**
([stable](https://wstg.owasp.org/stable/)). Tests that do not exist in v4.2 are cited from
the v5 checklist with an explicit `(v5)` marker. For vulnerability classes without a
dedicated WSTG test (e.g. NoSQL injection) the closest WSTG test is referenced and noted in
the check description.

## Active checks (17)

Mutation-based checks: payloads are injected into captured requests and the response is
analyzed (signatures, reflection with context checks, delay measurement).

| Check | WSTG | Severity | CWE | Description |
|---|---|---|---|---|
| `sqli` | WSTG-INPV-05 | HIGH | CWE-89 | SQL Injection (error-based) |
| `sqli_time` | WSTG-INPV-05 | HIGH | CWE-89 | SQL Injection (time-based blind) — delay relative to host baseline |
| `sqli_blind` | WSTG-INPV-05 | HIGH | CWE-89 | SQL Injection (boolean-based blind) — true/false payload pairs compared by status/length/similarity, false must match baseline |
| `cmdi` | WSTG-INPV-12 | CRITICAL | CWE-78 | Command Injection |
| `ssti` | WSTG-INPV-18 | CRITICAL | CWE-94 | Server-Side Template Injection |
| `ldap_injection` | WSTG-INPV-06 | HIGH | CWE-90 | LDAP Injection |
| `xpath_injection` | WSTG-INPV-09 | HIGH | CWE-643 | XPath / XML Injection |
| `nosql_injection` | WSTG-INJT-05 (v5) | HIGH | CWE-943 | NoSQL Injection (nearest WSTG test) |
| `xxe` | WSTG-INPV-07 | HIGH | CWE-611 | XML External Entity |
| `deserialization` | WSTG-INJT-23 (v5) | CRITICAL | CWE-502 | Insecure Deserialization |
| `crlf_injection` | WSTG-INPV-15 | MEDIUM | CWE-113 | Header / CRLF Injection |
| `ssrf` | WSTG-INPV-19 | HIGH | CWE-918 | Server-Side Request Forgery |
| `ssi_injection` | WSTG-INPV-08 | HIGH | CWE-97 | Server-Side Includes Injection |
| `path_traversal` | WSTG-ATHZ-01 | HIGH | CWE-22 | Path Traversal / LFI / RFI |
| `xss_reflected` | WSTG-INPV-01 | HIGH | CWE-79 | Reflected XSS |
| `html_injection` | WSTG-CLNT-03 | MEDIUM | CWE-80 | HTML Injection |
| `open_redirect` | WSTG-CLNT-04 | MEDIUM | CWE-601 | Open Redirect |

## Passive checks (19)

Analyze responses captured by the proxy (no additional payloads are sent by these checks).

| Check | WSTG | Severity | CWE | Description |
|---|---|---|---|---|
| `info_disclosure` | WSTG-INFO-05 | MEDIUM | CWE-200 | Sensitive information disclosure (secrets, stack traces, keys, comments) |
| `outdated_libs` | WSTG-INFO-08 | MEDIUM | CWE-1035 | Outdated / vulnerable JS libraries |
| `third_party_scripts` | WSTG-INFO-09 | LOW | CWE-829 | Third-party scripts without SRI |
| `security_headers` | WSTG-CONF-14 (v5) | LOW | CWE-693 | Missing security headers |
| `clickjacking` | WSTG-CLNT-09 | LOW | CWE-1021 | Missing X-Frame-Options / CSP frame-ancestors |
| `hsts` | WSTG-CONF-07 | MEDIUM | CWE-319 | Missing / weak HSTS |
| `csp` | WSTG-CONF-12 (v5) | MEDIUM | CWE-693 | Content Security Policy issues |
| `file_upload` | WSTG-BUSL-09 | CRITICAL | CWE-434 | Dangerous file upload heuristics |
| `xss_dom` | WSTG-CLNT-01 | MEDIUM | CWE-79 | DOM-based XSS sinks (heuristic) |
| `browser_storage` | WSTG-CLNT-12 | HIGH | CWE-922 | Secrets in browser storage |
| `csrf` | WSTG-SESS-05 | MEDIUM | CWE-352 | Missing anti-CSRF token |
| `jwt` | WSTG-SESS-10 (v5) | HIGH | CWE-347 | JWT signature verification |
| `cookies` | WSTG-SESS-02 | MEDIUM | CWE-614 | Cookie attributes (Secure / HttpOnly / SameSite) |
| `cache_control` | WSTG-ATHN-06 | MEDIUM | CWE-525 | Cacheable sensitive responses |
| `insecure_login` | WSTG-ATHN-01 | HIGH | CWE-319 | Credentials over cleartext channel |
| `idor` | WSTG-ATHZ-04 | MEDIUM | CWE-639 | Insecure Direct Object Reference |
| `server_fingerprint` | WSTG-INFO-02 | LOW | CWE-200 | Server / X-Powered-By / framework cookies / `<meta generator>` fingerprint |
| `errh` | WSTG-ERRH-01 | MEDIUM | CWE-209 | Verbose errors / stack traces / DEBUG pages (also WSTG-ERRH-02) |
| `session_in_url` | WSTG-SESS-04 | MEDIUM | CWE-598 | Session tokens in URL query/path, Referer, Location redirects |

## Probe checks (7)

Dedicated requests issued against the target base URL (no mutation of captured requests).

| Check | WSTG | Severity | CWE | Description |
|---|---|---|---|---|
| `metafiles` | WSTG-INFO-03 | LOW | CWE-200 | Webserver metafiles disclosure (robots.txt, sitemap.xml, security.txt) |
| `ria_policy` | WSTG-CONF-08 | MEDIUM | CWE-942 | RIA cross-domain policy (crossdomain.xml / clientaccesspolicy.xml) |
| `http_methods` | WSTG-CONF-06 | MEDIUM | CWE-650 | HTTP methods / TRACE / dangerous verbs |
| `sensitive_files` | WSTG-CONF-03 | HIGH | CWE-538 | Sensitive files / backups exposure |
| `info_disclosure_paths` | WSTG-CONF-05 | MEDIUM | CWE-538 | Admin / debug interface exposure |
| `cors` | WSTG-CLNT-07 | HIGH | CWE-942 | CORS misconfiguration (reflected origin + credentials) |
| `host_header_injection` | WSTG-INPV-17 | HIGH | CWE-644 | Host / X-Forwarded-Host / X-Host / Forwarded reflection in body, Location or absolute URLs |

## Notes

- **Active checks** require payload files under `payloads/` (see
  [`payloads/README.md`](../payloads/README.md)); missing files are reported in the log and
  the check is skipped.
- **sqli_blind** uses paired payloads (`payloads/sqli_blind.txt`, one pair per line:
  `true_payload ||| false_payload`): the engine sends both requests (same endpoint/headers,
  only the payload differs) and treats a significant status/length/similarity difference as
  a finding only when the other response matches the baseline (no baseline → status-diff only).
- **XXE / deserialization reachability:** raw/XML request bodies (XML, SOAP,
  PHP-serialized, protobuf/octet-stream) get a dedicated `body_raw` mutation point
  (whole body replaced by the payload); it is allowed only for `xxe` (XML/SOAP
  Content-Type) and `deserialization` — other checks never generate `body_raw` tasks.
- **Safe Mode** filters destructive payloads before task generation
  (`DESTRUCTIVE_PAYLOAD_PATTERNS` in `scanner_core.py`).
- **Tamper/WAF-bypass** encoders (`url`, `unicode`, `hex`, `double-url`) apply only to
  server-side injection checks.
- **Probes** perform real `OPTIONS`/`TRACE`/`PUT`/`DELETE` requests and file lookups: enable
  them only on targets you are authorized to test.
- Probe client accepts `host_headers` (hosts to spoof for `host_header_injection`;
  default `Host, X-Forwarded-Host, X-Host, Forwarded`) and `extra_headers`
  (e.g. `Cookie`/`Authorization` for authenticated probe requests). GUI exposes them
  as "Injection headers" / "Extra probe headers" settings.
- Findings are stored with their WSTG ID (`scan_meta`/reports), so a report can be mapped
  directly to WSTG coverage.
