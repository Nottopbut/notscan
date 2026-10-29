# Payload sets

Each `*.txt` file contains one payload per line. Lines starting with `#` are comments
(headers/total counters/sections) and are ignored by the loader. URL-encoded forms are kept
as-is where the target expects encoded input (CRLF set); the engine applies URL quoting to
payloads inserted into query parameters.

WAF-bypass variants are embedded in the existing sets (sections `# --- WAF bypass ---`) so
the loader and the checks use them automatically — see [WAF_BYPASS.md](WAF_BYPASS.md) for
the strategies, affected sets and the non-destructive policy.

| File | Payloads | Used by | Notes |
|---|---:|---|---|
| `sqli.txt` | 703 | `sqli` | Error-based SQL injection (multi-DBMS error signatures are matched by the check). Includes case/comment/`%XX`-encoded WAF-bypass variants. |
| `sqli_time.txt` | 143 | `sqli_time` | Time-based blind SQLi. Only payloads registered in `checks/injections.py::SQLI_TIME_PAYLOADS` are treated as delay probes (threshold 2–5 s); the rest are sent as generic mutations. |
| `sqli_blind.txt` | 32 | `sqli_blind` | Boolean-based blind SQLi. Each line is a **pair** `true_payload ||| false_payload`; the engine sends both requests and flags a finding when the responses differ significantly (status/length/similarity) and the false response matches the baseline (boolean conditions only — no destructive statements). |
| `xss.txt` | 195 | `xss_reflected` | Reflected XSS vectors (tag/attribute breakouts, event handlers, polyglots, mXSS fragmentation, HTML-entity/JS-escape and `javascript:` obfuscation). |
| `cmdi.txt` | 578 | `cmdi` | OS command injection (`;`, `|`, `&&`, `$()`, `%0a`, Windows/PowerShell variants). WAF-bypass: `${IFS}`, `$@`, encoded separators/newlines, `c^m^d`/`who^ami` obfuscation, base64-echo probes. |
| `ssti.txt` | 167 | `ssti` | Server-side template injection (Jinja2, Twig, Freemarker, Velocity, Smarty, ERB, …). WAF-bypass: alternate delimiters (`%7B%7B`, `{%%7B`, `#{`, `${{`), `attr()`/filter bypasses. |
| `xxe.txt` | 103 | `xxe` | XML external entity / parameter entity / OOB / SOAP payloads, XInclude, encoding and entity-nesting variants. |
| `ssrf.txt` | 97 | `ssrf` | Cloud metadata endpoints, loopback/private ranges, `gopher://`, `dict://`, decimal/octal/hex IP and IPv4-mapped IPv6 tricks, DNS-rebinding domains, `user@host` obfuscation. |
| `nosqli.txt` | 74 | `nosql_injection` | MongoDB operator/JSON injection, `$where`, arrays. WAF variants: `$expr`, `$nor`, `$elemMatch`, `$regex`+`$options`. |
| `ldapi.txt` | 63 | `ldap_injection` | LDAP filter injection and blind/AD variants, encoded filter operators (`%2a`, `\2a`) and modern `objectClass` filters. |
| `xpath.txt` | 52 | `xpath_injection` | XPath 1.0/2.0 boolean and error-based vectors, percent-encoded and union-style WAF variants. |
| `html_injection.txt` | 35 | `html_injection` | Non-XSS HTML injection markers: each payload carries a `notscan=<n>` attribute and `HTMLINJ_MARKER` text so the check can prove the raw markup was reflected unescaped. |
| `file_upload.txt` | 47 | `file_upload` | Filename/extension/content-type bypass probes (no local file writing): double extensions, `%00`/`;`/`/` tricks, Windows ADS (`::$DATA`), `.user.ini`. |
| `crlf.txt` | 46 | `crlf_injection` | Header injection / response splitting, stored percent-encoded (normalized before use); encoded/unencoded CRLF, unicode line separators, header-name obfuscation. |
| `open_redirect.txt` | 317 | `open_redirect` | Absolute/protocol-relative URL payloads; only absolute external `Location` values are flagged. WAF variants: backslash/protocol-relative tricks, `@`-confusion, percent/unicode-encoded hosts. |
| `path_traversal.txt` | 857 | `path_traversal` | Traversal/LFI/RFI incl. encoding tricks: overlong UTF-8 (`%c0%af`), double encoding, `..;/`, path normalization and backslash variants. |
| `idor.txt` | 46 | `idor` | Numeric/UUID object identifiers (read-only probes), plus parser-evasion ids (`null`, `0x1f`) and base64-encoded UUIDs. |
| `ssi.txt` | 20 | `ssi_injection` | Server-Side Includes directives (`#echo`, `#exec`, `#include`, `#printenv`, …). |
| `deserialization.txt` | 26 | `deserialization` | Java (ysoserial-style), PHP, Python pickle, .NET, Node.js payload markers; WAF variants add non-destructive marker gadgets (PHP/Java/.NET/pickle/JSON.NET/XML). |

Total: **3601 payloads** across 19 sets (was 3298 before the WAF-bypass expansion; +303).
Sets are intentionally curated (deduplicated, one vector per line) rather than bulk copies;
extra payloads can be added freely by appending lines to the corresponding file — the loader
picks them up automatically.

## WAF bypass probes

Each key set has a `# --- WAF bypass ---` section at the end with obfuscated variants of the
same probes (case mixing, SQL comments `/**/`/`/*!50000...*/`, percent/unicode encoding,
HTML entities/JS escapes, path normalization, alternate IP forms, `@`-userinfo, template
delimiter variants, parser-evasion identifiers). They are ordinary payload lines — the
loader and checks consume them without any configuration. Full details:
[WAF_BYPASS.md](WAF_BYPASS.md).

## Safe Mode

With **Safe Mode** enabled (default in the GUI), payloads containing destructive patterns
(`DROP TABLE`, `xp_cmdshell`, `INTO OUTFILE`, `load_file`, file-write/exec patterns, …) are
filtered out before task generation. See `DESTRUCTIVE_PAYLOAD_PATTERNS` in
`scanner_core.py`. The payload files themselves do not write files, delete data or open
reverse shells — they are only HTTP request payloads. WAF-bypass additions are strictly
read-only probes and pass Safe Mode.

## Adding payloads

1. Append one payload per line to the relevant `payloads/*.txt` (WAF-bypass variants go under
   the existing `# --- WAF bypass ---` marker; keep the file deduplicated).
2. Keep the `# Total: N payloads` header in sync (counted by tests/documentation).
3. If the payload is a time-based probe, register it in
   `checks/injections.py::SQLI_TIME_PAYLOADS` with its expected delay so detection knows
   the threshold.
4. Raise `MIN_PAYLOAD_COUNTS` in `tests/test_payloads_quality.py` when growing a set.
5. Run `python -m pytest tests/test_payloads_quality.py tests/test_hardening.py -q`.
6. Boolean-blind pairs (`sqli_blind.txt`) must keep the `true ||| false` format and stay
   non-destructive: both halves are injected as-is into the vulnerable parameter.
7. A payload that itself starts with `#` cannot be stored bare (the loader treats `#` lines
   as comments): keep one leading space — the loader `strip()`s the line (e.g. SSTI `#{7*7}`).

Sources: [PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings),
OWASP WSTG test descriptions, PortSwigger Web Security Academy, HackTricks, vendor docs.
Only use these payloads against systems you are authorized to test.
