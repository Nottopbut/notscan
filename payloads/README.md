# Payload sets

Each `*.txt` file contains one payload per line. Lines starting with `#` are comments
(headers/total counters/sections) and are ignored by the loader. URL-encoded forms are kept
as-is where the target expects encoded input (CRLF set); the engine applies URL quoting to
payloads inserted into query parameters.

| File | Payloads | Used by | Notes |
|---|---:|---|---|
| `sqli.txt` | 666 | `sqli` | Error-based SQL injection (multi-DBMS error signatures are matched by the check). |
| `sqli_time.txt` | 143 | `sqli_time` | Time-based blind SQLi. Only payloads registered in `checks/injections.py::SQLI_TIME_PAYLOADS` are treated as delay probes (threshold 2–5 s); the rest are sent as generic mutations. |
| `xss.txt` | 164 | `xss_reflected` | Reflected XSS vectors (tag/attribute breakouts, event handlers, polyglots). |
| `cmdi.txt` | 543 | `cmdi` | OS command injection (`;`, `|`, `&&`, `$()`, `%0a`, Windows/PowerShell variants). |
| `ssti.txt` | 139 | `ssti` | Server-side template injection (Jinja2, Twig, Freemarker, Velocity, Smarty, ERB, …). |
| `xxe.txt` | 89 | `xxe` | XML external entity / parameter entity / OOB / SOAP payloads. |
| `ssrf.txt` | 77 | `ssrf` | Cloud metadata endpoints, loopback/private ranges, `gopher://`, `dict://`, decimal/IPv6 tricks. |
| `nosqli.txt` | 61 | `nosql_injection` | MongoDB operator/JSON injection, `$where`, arrays. |
| `ldapi.txt` | 54 | `ldap_injection` | LDAP filter injection and blind/AD variants. |
| `xpath.txt` | 43 | `xpath_injection` | XPath 1.0/2.0 boolean and error-based vectors. |
| `html_injection.txt` | 35 | `html_injection` | Non-XSS HTML injection markers: each payload carries a `notscan=<n>` attribute and `HTMLINJ_MARKER` text so the check can prove the raw markup was reflected unescaped. |
| `file_upload.txt` | 34 | `file_upload` | Filename/extension/content-type bypass probes (no local file writing). |
| `crlf.txt` | 31 | `crlf_injection` | Header injection / response splitting, stored percent-encoded (normalized before use). |
| `open_redirect.txt` | 285 | `open_redirect` | Absolute/protocol-relative URL payloads; only absolute external `Location` values are flagged. |
| `path_traversal.txt` | 837 | `path_traversal` | Traversal/LFI/RFI incl. encoding tricks. |
| `idor.txt` | 28 | `idor` | Numeric/UUID object identifiers (read-only probes). |
| `ssi.txt` | 20 | `ssi_injection` | Server-Side Includes directives (`#echo`, `#exec`, `#include`, `#printenv`, …). |
| `deserialization.txt` | 16 | `deserialization` | Java (ysoserial-style), PHP, Python pickle, .NET, Node.js payload markers. |

Total: **3266 payloads** across 18 sets. Sets are intentionally curated (deduplicated, one
vector per line) rather than bulk copies; extra payloads can be added freely by appending
lines to the corresponding file — the loader picks them up automatically.

## Safe Mode

With **Safe Mode** enabled (default in the GUI), payloads containing destructive patterns
(`DROP TABLE`, `xp_cmdshell`, `INTO OUTFILE`, `load_file`, file-write/exec patterns, …) are
filtered out before task generation. See `DESTRUCTIVE_PAYLOAD_PATTERNS` in
`scanner_core.py`. The payload files themselves do not write files, delete data or open
reverse shells — they are only HTTP request payloads.

## Adding payloads

1. Append one payload per line to the relevant `payloads/*.txt`.
2. Keep the `# Total: N payloads` header roughly in sync (used by tests/documentation).
3. If the payload is a time-based probe, register it in
   `checks/injections.py::SQLI_TIME_PAYLOADS` with its expected delay so detection knows
   the threshold.
4. Run `python -m pytest tests/test_payloads_quality.py tests/test_hardening.py -q`.

Sources: [PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings),
OWASP WSTG test descriptions, PortSwigger Web Security Academy, HackTricks, vendor docs.
Only use these payloads against systems you are authorized to test.
