# notscan

**notscan** is a desktop web-vulnerability scanner with a Tkinter GUI: it intercepts
HTTP(S) traffic through a built-in proxy, turns captured requests into mutation-based
security tests, runs them with an async scan engine and stores findings with evidence
and reports.

> ⚠️ **Authorization required.** Use notscan only against applications you own or have
> explicit written permission to test. The authors are not responsible for misuse.

🇷🇺 [Русская версия README](README.md)

![python](https://img.shields.io/badge/python-3.10%2B-blue)
![platform](https://img.shields.io/badge/platform-Linux%20%7C%20Windows-lightgrey)
![WSTG](https://img.shields.io/badge/OWASP-WSTG%20v4.2%2Fv5-orange)
![checks](https://img.shields.io/badge/checks-43%20(17%20active%20%2F%2019%20passive%20%2F%207%20probe)-informational)
![license](https://img.shields.io/badge/license-MIT-green)

---

## Features

- **Intercepting proxy** — mitmproxy-based local proxy writes method, URL, headers, body
  and response preview into a per-project SQLite database. One click starts the proxy and
  a preconfigured Chromium/Burp Browser (PAC + certificate bypass for the isolated profile).
  The proxy never starts by itself: it is started explicitly with **▶ Start Proxy + Browser**
  (auto-start is available in Settings, off by default). Background browser noise — Google
  telemetry, component updates, safe-browsing and connectivity checks — is filtered out of
  History by default (`proxy_filter_noise` in Settings).
- **Mutation scan engine** — builds tasks from captured requests over query parameters,
  `application/x-www-form-urlencoded` bodies, JSON bodies and (optionally) headers.
  Async engine (`asyncio` + `httpx.AsyncClient`) with configurable concurrency, RPS limit
  and scope guard; redirects are **never followed** (a payload-controlled redirect must not
  turn a scan into an outbound request).
- **WSTG check catalog (43 checks)** — a single catalog (`checks/catalog.py`) drives the GUI
  Checks/WSTG tab, the scan-config badges, the WSTG map of findings and payload files:
  **17 active + 19 passive + 7 probe**. WSTG IDs are aligned with OWASP WSTG v4.2 and the
  v5 checklist (tests missing from v4.2 are marked `(v5)`). Full table:
  [`docs/CHECKS.md`](docs/CHECKS.md).
  - Active: SQLi (error-based, time-based blind and boolean-based blind with response
    status/body differentials), CMDi, SSTI, LDAP/XPath/NoSQL injection,
    XXE, insecure deserialization, CRLF/header injection, SSRF, SSI injection,
    path traversal, reflected XSS, HTML injection, open redirect.
  - Passive: sensitive info disclosure, outdated JS libs, missing SRI, security headers,
    HSTS, CSP, cookie attributes, cacheable sensitive responses, cleartext credentials,
    browser storage of secrets, CSRF token presence, JWT signature, clickjacking,
    file upload heuristics, DOM-XSS heuristic, IDOR.
  - Probe: sensitive files/backups, webserver metafiles, RIA cross-domain policy,
    HTTP methods/TRACE, admin/debug interface exposure, CORS misconfiguration.
- **False-positive controls** — bare-tag/XSS content-type/baseline-aware rules,
  reflection-aware path-traversal and open-redirect matchers, soft-404 and WAF-page
  filters for probes, host-timing calibration for time-based SQLi
  (relative threshold `max(payload_delay, 3×baseline_p50 + 1s)`).
- **Tamper / WAF-bypass encoders** — `url`, `unicode`, `hex`, `double-url`
  (optional, applied only to server-side injection checks).
- **Stateful scanning (optional)** — reuse captured login requests, retry on 401/403 with
  refresh/relogin, and inject a fresh CSRF token into every mutation
  (`templating.patch_csrf_token` + `SessionManager.csrf_token_provider`).
- **Triage & evidence** — severity/confidence/exploitability, dedup by stable fingerprint,
  raw HTTP request/response, unified diff snippets, manual confirm flow
  (baseline / benign / suspicious replay), paginated results.
- **Reports** — Markdown, JSON, HTML, SARIF, DOCX; the full result set is exported by
  default (no silent truncation).
- **Raw/XML body mutations** — XML/SOAP/PHP-serialized and other raw bodies get a
  `body_raw` mutation point, so **XXE** and **insecure deserialization** checks actually
  generate requests (previously declarative-only).
- **Multi-boundary mutations** — injections are tested in **query parameters, form bodies,
  JSON, cookies, URL path segments, multipart/form-data text fields, headers and raw bodies**
  (XML/SOAP/PHP-serialized). Each boundary can be toggled in Scan Config → Advanced →
  Mutation points; `Only parameters` also accepts cookie names, `path[0]`… and form field
  names. File parts of multipart requests are preserved byte-for-byte (not mutated).
- **Postman import with environments** — History → ⬆ Import understands Postman collections;
  if a collection uses `{{variables}}`, notscan lists the missing ones, offers to load a
  Postman environment/globals file (**⬆ Import environment**), resolves collection
  variables + environment values in URLs/headers/bodies and only then imports. The env is
  kept in memory for the session (values are not logged).
- **Rate limiting** — next to Workers in Advanced: **Min RPS**, **Max RPS** and
  **Delay (ms)**. Min+Max produce random pacing between 1/max and 1/min; Delay is a
  fixed pause; 0 disables the limit. A global async rate limiter is used (sqli_blind
  pairs included).
- **Local/private targets & scope** — hosts from the Scan list are automatically put into
  the allowlist (explicit authorization), so localhost/private targets are not blocked;
  a private target gets a one-time confirmation. Instead of per-request
  “Skipping out-of-scope…” spam, the log shows the first 5 examples plus one aggregate
  `[SCOPE] Skipped N…` summary.
- **Auth after Postman import** — Cookie/Authorization from the collection and env are
  automatically applied to imported requests and probes; if a login request is detected,
  notscan offers auto-login (SessionManager). A preflight check runs before scanning:
  401/403/login redirect → “looks unauthenticated” warning with Continue/Cancel; after
  the scan a 401/403 warning is shown. The Auth tab has an **OTP / 2FA code** field
  (test stub `000000`, env `NOTSCAN_OTP_STUB`); auto-relogin re-submits OTP when the
  session expires.
- **RU/EN interface** — the whole GUI (tabs, buttons, dialogs, tutorial, check names/descriptions,
  statuses) is available in **English and Russian**; **Russian is the default**, switch in
  Settings → Language (applies after restart; `NOTSCAN_UI_LANGUAGE` env override). Reports (MD/HTML/DOCX) are localised too; technical log lines
  (`[SCAN]/[PROXY]/…`) stay in English.
- **Simple scan profiles** — the scan window opens with a **Scan profile** choice:
  *Quick* (safe passive+probe recon), *Standard* (recommended active checks + passive/probe),
  *Full* (all checks, with a warning) or *Custom*. The 43-check wall and advanced options
  (workers, safe mode, tamper, mutation points, injection targets, ROE) are hidden behind
  «Customize checks» / «Advanced options» toggles.
- **Injection targets** — in the scan window you can choose which headers host-header
  injection tests (`inject_headers`), limit mutations to specific parameter names
  (`only_params`), and add extra probe headers such as `Cookie: PHPSESSID=...` for
  authenticated probe checks (`probe_extra_headers`).
- **Payload sets** — ~3.6k payloads across 19 sets with dedicated **WAF-bypass
  variants** (case/comment obfuscation, encoding/HTML-entity/unicode tricks, IP
  representations) in every injection set (SQLi incl. boolean-blind true/false
  pairs, XSS, SSTI, SSRF, XXE, NoSQLi,
  LDAP, XPath, CRLF, CMDi, path traversal, open redirect, file upload, IDOR,
  deserialization, SSI, HTML injection, time-based SQLi). Safe Mode filters destructive
  payloads. See [`payloads/README.md`](payloads/README.md).
- **Projects** — every launch works in its own project directory with its own DB, settings
  and reports; switch between projects via **Project → Sessions / Projects…**. Project
  switching is blocked while a scan is running.
- **Extra tools** — reverse-shell command generator (generates commands only, never
  executes them), endpoint contract inference, auth-boundary (anonymous vs authenticated)
  comparison, collection import/export (raw HTTP, HAR, Postman).

## Install

```bash
git clone https://github.com/Nottopbut/notscan.git
cd notscan
python -m pip install -r requirements.txt
```

Requirements: Python 3.10+ (tested on 3.13), Tkinter (`python3-tk` on Debian/Ubuntu),
mitmproxy, httpx, ttkbootstrap, python-docx. Details and troubleshooting:
[`docs/INSTALL.md`](docs/INSTALL.md).

## Quick start

```bash
python notscan.py
```

1. Press **▶ Start Proxy + Browser**: the proxy starts on `127.0.0.1:8080` (if the port is
   busy, the next free port is chosen automatically — check the status label) and an isolated
   Chromium opens with the proxy already configured. The proxy does **not** start on its own;
   auto-start is an opt-in setting in Settings.
2. Browse the target application and exercise its features.
3. In the **History** tab select the requests of interest (double-click also adds them),
   press **＋ Add to Scan list**, then **▶ Run Scan**.
4. In the scan-config window pick checks (active / passive / probe), mutation points and
   ROE options (concurrency, RPS, scope allowlist, Safe Mode, tamper), then **Start Scan**.
   **All checks are disabled by default** (the window shows `0 / 43 checks enabled`): enable
   the ones you need or press **All ON**; badges show ☐/☑ state.
5. Review findings in **Scan Results** (severity, evidence, raw HTTP, diff, confirm flow)
   and export a report (MD / JSON / HTML / SARIF / DOCX).

You can change the port at any time: edit the **Port** field and press the same
**▶ Start Proxy + Browser** button — the proxy restarts on the new port and the browser
opens (if a browser was already running, notscan asks for confirmation and closes it
before restarting the proxy).

The proxy stops automatically when the browser it launched is closed, after an idle timeout
(`proxy_idle_stop_min`, default 15 min) and on application exit — the port is always
released. Lifecycle settings are persisted per project:
`proxy_autostart`, `proxy_stop_on_browser_exit`, `proxy_idle_stop_min`.

## Testing

```bash
make test     # full pytest suite
make lab      # integration tests against the local HTTP lab (needs xvfb for GUI parts)
make smoke    # headless GUI smoke test in xvfb on a temp copy of the project
```

The repository ships a self-contained HTTP lab (`tests/lab/`) with intentionally vulnerable
endpoints (reflected XSS, escaped reflection, SQL errors, redirects, delayed responses,
CSRF-protected form, JSON API, cookie/CORS/SSRF/SSI cases, sensitive files/metafiles) used
by 560 unit and integration tests. Proxy-lifecycle integration tests are skipped
automatically when mitmproxy or a display is unavailable.

## Project structure

```
notscan.py            Tkinter GUI (proxy, scan, results, auth, revshell, checks/WSTG tabs)
scanner_core.py       async scan engine, task builder, matchers, scope guard, ROE
checks/               check catalog, active/passive checks, WSTG map, FP rules, runner
templating.py         raw-HTTP parsing/mutation, JSON payload escaping, tamper, CSRF patch
session_manager.py    login/refresh/relogin sessions, CSRF token provider
db.py                 per-project SQLite storage (WAL, per-thread connections)
report_export.py      MD / JSON / HTML / SARIF / DOCX reports
mitm_proxy.py         mitmproxy-based intercepting proxy + PAC server
path_probe.py         probe checks (sensitive files, metafiles, CORS, HTTP methods, …)
payloads/             payload sets (one payload per line) + payload docs
tests/                unit + integration tests and the local HTTP lab
docs/                 install, functional overview, WSTG check table
```

## Documentation

- [`docs/INSTALL.md`](docs/INSTALL.md) — requirements, installation, troubleshooting
- [`docs/FUNCTIONAL_OVERVIEW.md`](docs/FUNCTIONAL_OVERVIEW.md) — architecture and features
- [`docs/CHECKS.md`](docs/CHECKS.md) — full WSTG check catalog
- [`payloads/README.md`](payloads/README.md) — payload sets and how to extend them
- [`README.md`](README.md) — Russian README (primary)

## Known limitations

- No crawler/endpoint discovery: scan targets are the requests you captured through the
  proxy (or imported from a collection). Adding a lightweight crawler is on the roadmap.
- Some passive checks need the captured proxy response to be meaningful; HSTS is meaningful
  for HTTPS targets only (unit-tested, not exercised by the HTTP lab).
- Probe checks issue real `OPTIONS`/`TRACE`/`PUT`/`DELETE` requests — enable them only on
  targets you are allowed to test.
- This is a learning/practical tool, not a replacement for Burp Suite/ZAP/Nuclei.
  No CI is configured yet; run `make test` locally.

## License

MIT — see [`LICENSE`](LICENSE).

Credits: [OWASP WSTG](https://owasp.org/www-project-web-security-testing-guide/),
[PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings),
[mitmproxy](https://mitmproxy.org/), [httpx](https://www.python-httpx.org/),
[ttkbootstrap](https://github.com/israel-dryer/ttkbootstrap).
