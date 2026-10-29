# COVERAGE_GAPS — анализ покрытия уязвимостей (WSTG и вне WSTG)


> **Апдейт (2026-10-30):** 4 quick-win чека из §5.1 уже реализованы
> (`server_fingerprint`, `errh`, `session_in_url`, `host_header_injection`),
> каталог 43 чека; `body_raw` mutation-тип также реализован (XXE/deserialization
> стали reachable). Счётчики из снимка ниже — на момент HEAD 9b0d075.

**Репозиторий:** `notscan`, снимок HEAD `9b0d075` (на момент снятия инвентаризации рабочее дерево
было clean; другие агенты могут менять код параллельно).
**Дата:** 2026-10-29. **Тип документа:** read-only аналитика; код/тесты/payload'ы не менялись.
**Единственный артефакт:** этот файл.

**Источники:**
- код: `checks/catalog.py`, `checks/injections.py`, `checks/client_side.py`, `checks/other.py`,
  `checks/passive_extra.py`, `checks/runner.py`, `scanner_core.py`, `templating.py`,
  `path_probe.py`, `notscan.py`, `docs/CHECKS.md`, `docs/FUNCTIONAL_OVERVIEW.md`,
  `payloads/README.md`, `tests/lab/server.py`;
- OWASP WSTG v4.2 (stable): <https://wstg.owasp.org/stable/> и тег `v4.2` репозитория
  <https://github.com/OWASP/wstg> — **97 тестов** (без вводного `BUSL-00`);
- OWASP WSTG v5-dev checklist:
  <https://raw.githubusercontent.com/OWASP/wstg/master/checklists/checklist.md> — **115 тестов**
  (снято 2026-10-29).

**Легенда:**
- статус: ✅ покрыто чеком каталога · 🟡 частично (смежный чек/эвристика/декларативно) · ❌ нет покрытия;
- `auto`: `passive` (анализ захваченного ответа) · `probe` (отдельный запрос) · `active` (payload-мутация) ·
  `engine` (нужна доработка движка: mutation-тип/парные запросы/raw-сокеты) · `manual` (ручной тест);
- сложность `S` ≤ 1–2 дня, `M` 3–5 дней, `L` ≥ недели (1 разработчик, включая тесты);
- ценность для «лёгкой лиги» — частота на реальных целях × образовательная ценность.

---

## 0. TL;DR

- Каталог: **39 чеков** = 17 active + 16 passive + 6 probe (`checks/catalog.py:66`); 19 payload-файлов,
  **3298 payload'ов** на снимке HEAD, Safe Mode, tamper-кодировщики, baseline/FP-фильтры.
- WSTG v4.2: **32/97 (33%)** покрыто по маппингу каталога, **15** частично, **50** без покрытия;
  из 32 покрытых 4 — с ограниченной/декларативной детекцией (см. §3). WSTG v5: 35/115 (30%) полных,
  16 частичных, 64 без покрытия.
- Значительная часть непокрытого — **manual-only по природе** (IDNT, BUSL, OAuth, WebSockets,
  client-side JS, session-таймауты). Реально автоматизируемых «дыр» — около **35** тестов v4.2
  плюс ~15 v5-дополнений.
- Внутри «покрытого» есть **декларативные/ограниченные** чеки: XXE и deserialization фактически
  не достижимы для raw/XML-тел (нет mutation-типа), file_upload — только passive, IDOR/DOM-XSS — эвристики
  (см. §3). Это важнее, чем простое число «39 чеков».
- Quick wins (S/M без новой инфраструктуры): **17** (8×S + 9×M) — см. §5.
- Требует инфраструктуры: **~10 классов** (краулер, OOB-коллаборатор, login/stateful, raw-socket
  smuggling, WebSockets, DNS, CVE-база) — см. §5–6.
- Manual-only: **~30 тестов** — честно не автоматизируем (см. §5.3).

### Топ-10 непокрытых классов (по ценности для лёгкой лиги)

| # | Класс | WSTG | Почему важно | Реализуемость |
|---|---|---|---|---|
| 1 | Stored XSS | INJT-02 (INPV-02) | самый частый реальный XSS; в лабе/сканере не проверяется | L: нужен краулер/2-й проход |
| 2 | Host Header Injection | INJT-17 (INPV-17) | password-reset poisoning, cache-poisoning; дешёвый probe | **M quick win** |
| 3 | Blind SSRF/XXE/RCE (OOB) | INPV-19/07, INJT-12 | сейчас только in-band сигнатуры; слепые варианты не видны | L: OOB-коллаборатор |
| 4 | HTTP Request Smuggling | INJT-16 | критично на прокси/CDN, сейчас не проверяется | L: raw-сокеты |
| 5 | Mass Assignment | INJT-20 | массово в REST/JSON API, дёшево в текущем движке (JSON) | **M quick win** |
| 6 | GraphQL introspection | APIT-99 / APIT-01(v4.2) | GraphQL есть почти в каждом современном API; introspection = быстрый признак | **M quick win** |
| 7 | Excessive Data Exposure | APIT-03 (v5) | пассивно ловится в JSON-ответах, высокий TP на реальных API | **M quick win** |
| 8 | Parameter Pollution (HPP) | INJT-04 | рассинхрон валидации/бэкенда; нужен mutation-тип duplicate | M quick win |
| 9 | Weak TLS / crypto | CRYP-01 / CRYP-04 | self-signed/TLS1.0/истёкший серт — частые находки, дёшево | **M quick win** |
| 10 | CVE/outdated components | вне WSTG (OWASP A06) | уже заявленный next-step `cve_lookup`; высокий спрос | M/L: база CVE + fingerprint |

Плюс: **Reverse Tabnabbing**, **CSS injection**, **verbose error handling (ERRH)**, **session в URL**,
**weak password policy**, **WAF fingerprint** — дешёвые S-чеки (§5).

---

## 1. Инвентаризация текущего покрытия

Каталог — единственный источник (`checks/catalog.py:66`); WSTG-карта находок строится из него
(`checks/runner.py:25`), payload-файлы — `scanner_core.load_payloads` (`scanner_core.py:370`).

### 1.1. Слои детекции

| Слой | Где | Объём | Роль |
|---|---|---|---|
| Matcher-сигнатуры | `scanner_core.py:1661` (`MATCHERS`) | 15 рабочих сигнатур + legacy-алиас `xss`; `match_sqli_time` — заглушка (`:1392`), `sqli_blind` — движок | быстрая проверка каждого ответа + baseline-suppress |
| Checks active | `checks/injections.py`, `checks/client_side.py` | **17** | payload-мутации, дифференциальная детекция |
| Checks passive | `checks/client_side.py`, `checks/other.py`, `checks/passive_extra.py` | **16** | анализ захваченных прокси ответов |
| Probe | `path_probe.py:689` | **6** | отдельные запросы по base-URL |
| Blind-pair engine | `scanner_core.py:438` (`parse_blind_payload`), `:496` (`evaluate_blind_pair`) | только `sqli_blind` | 2 запроса true/false + сравнение status/len/similarity + baseline |

### 1.2. Что умеет движок (влияет на покрытие)

- **Mutation points** (`templating.py:352`): query (`:141`), urlencoded body (`:178`),
  JSON body (`:227`, payload экранируется как JSON-строка), headers (`:322`; только
  `User-Agent, Referer, X-Forwarded-For, X-Custom-Header, Cookie`, `templating.py:313`).
  **Нет**: raw/XML тела, multipart, path-сегментов, добавления новых JSON-полей, дублирования параметров.
- **Tamper/WAF-bypass** (`TAMPER_MODES`, `templating.py:26`): url/unicode/hex/double-url — только для
  серверных инъекционных чеков (`TAMPERABLE_CHECKS`, `scanner_core.py:113`); XSS/redirect — намеренно нет.
- **Baseline/FP**: baseline-suppress matcher'ов, калибровка таймингов, soft-404/WAF-заглушки в probe.
- **Stateful**: `session_manager` (login/refresh/relogin), CSRF-подстановка (`templating.py:581`),
  авторизация из перехваченного login-запроса; **один пользователь/роль** (нет multi-user).
- **ROE/scope**: allowlist, блокировка private/metadata, RPS-лимитер (защита сканера, не тест цели),
  дедуп, confirm-flow. Повторяющихся запросов для rate-limit-тестов нет.
- Payload'ы: 19 файлов / 3298 payload'ов (снимок HEAD); safe-mode фильтр (`DESTRUCTIVE_PAYLOAD_PATTERNS`,
  `scanner_core.py:333`).

### 1.3. Покрытие по видам чеков

| Вид | Кол-во | Чеки |
|---|---|---|
| active (payload) | 17 | `sqli`, `sqli_time`, `sqli_blind`, `cmdi`, `ssti`, `ldap_injection`, `xpath_injection`, `nosql_injection`, `xxe`, `deserialization`, `crlf_injection`, `ssrf`, `ssi_injection`, `path_traversal`, `xss_reflected`, `html_injection`, `open_redirect` |
| passive | 16 | `info_disclosure`, `outdated_libs`, `third_party_scripts`, `security_headers`, `clickjacking`, `hsts`, `csp`, `file_upload`, `xss_dom`, `browser_storage`, `csrf`, `jwt`, `cookies`, `cache_control`, `insecure_login`, `idor` |
| probe | 6 | `metafiles`, `ria_policy`, `http_methods`, `sensitive_files`, `info_disclosure_paths`, `cors` |

Полная таблица WSTG/CWE/severity — `docs/CHECKS.md`; сводная таблица 39 чеков — §7 этого файла.

---

## 2. WSTG-матрица: что не покрыто и почему

### 2.0. Сводка по категориям (WSTG v4.2, 97 тестов)

| Категория | Тестов | ✅ покрыто | 🟡 частично | ❌ нет | Ключевые пробелы |
|---|---:|---:|---:|---:|---|
| INFO | 10 | 4 | 1 | 5 | fingerprint, attack surface, entry points (краулер) |
| CONF | 11 | 5 | 2 | 4 | subdomain takeover, cloud storage, TLS-конфиг, platform config |
| IDNT | 5 | 0 | 0 | 5 | всё manual (enumeration — с login-flow) |
| ATHN | 10 | 2 | 0 | 8 | default creds, lockout, weak password policy, remember-me |
| ATHZ | 4 | 2 | 0 | 2 | bypass authz / privilege escalation (stateful) |
| SESS | 9 | 2 | 2 | 5 | fixation/logout/timeout (stateful), session в URL |
| INPV/INJT | 19 | 10 | 2 | 7 | stored XSS, HPP, host header, smuggling, mass assignment |
| ERRH | 2 | 0 | 2 | 0 | dedicated error-handling чека нет |
| CRYP | 4 | 0 | 2 | 2 | TLS-конфиг, padding oracle, weak crypto |
| BUSL | 9 | 1 | 1 | 7 | business logic — manual; rate-limit — с инфраструктурой |
| CLNT | 13 | 6 | 2 | 5 | CSS injection, XSSI, WebSockets, reverse tabnabbing |
| APIT | 1 | 0 | 1 | 0 | GraphQL (v4.2); v5 API-тесты — отдельно ниже |
| **Итого** | **97** | **32 (33%)** | **15** | **50** | |

«Покрыто» = в каталоге есть чек с этим WSTG-ID. Из 32 таких тестов 4 закрыты с ограниченной
детекцией и отдельно разобраны в §3: `xxe` (INPV-07), `idor` (ATHZ-04), `xss_dom` (CLNT-01),
`file_upload` (BUSL-09) — «доказательное» покрытие ближе к 28 тестам. Статус 🟡 в §3/§7
для этих чеков счётчик «покрыто по маппингу» не уменьшает.

WSTG v5 (115 тестов): 35 покрыто, 16 частично, 64 нет. Дополнительные v5-тесты, которых нет в v4.2:
`CONF-12/13/14/15`, `ATHN-11`, `ATHZ-05`, `SESS-10/11`, `INJT-15…23`, `CLNT-14/15`,
`APIT-01…04/99`, `WASM-01`. Из них покрыты: `CONF-12` (csp), `CONF-14` (security_headers),
`SESS-10` (jwt), `INJT-05` (nosql, nearest), `INJT-15` (crlf/response splitting),
`INJT-23` (deserialization).

Ниже — только непокрытые/частичные тесты (для покрытых см. `docs/CHECKS.md`).

### 2.1. INFO — Information Gathering

| WSTG | Тест | auto | Ценность | S/M/L | Что нужно |
|---|---|---|---|---|---|
| INFO-02 | Fingerprint Web Server | passive | средняя | S | новый passive-чек `server_fingerprint`: `Server`, `X-Powered-By`, `X-AspNet-Version`, cookie-имена, HTML-метки (быстрый quick win) |
| INFO-04 | Enumerate Applications / Attack Surface | probe | средняя | M | probe уже смотрит типовые пути; нужны vhost/subdomain-энумерация (DNS) и/или краулер |
| INFO-06 | Identify Application Entry Points | engine | высокая | L | краулер + сбор форм/JS/параметров (сейчас — только перехваченные запросы) |
| INFO-07 | Map Execution Paths | manual | средняя | M | ручной обход; частично помогает `contract_inference` |
| INFO-10 | Map Application Architecture | manual | низкая | M | ручной/полу-ручной; `auth_boundary` + contract inference |
| INFO-01 | Search Engine Discovery | manual | низкая | — | внешние поисковики, вне сканера (manual-only) |

### 2.2. CONF — Configuration and Deployment

| WSTG | Тест | auto | Ценность | S/M/L | Что нужно |
|---|---|---|---|---|---|
| CONF-02 | Application Platform Configuration | passive/probe | средняя | M | усилить `security_headers` + probe default-страниц (ниже приоритет) |
| CONF-04 | Old Backup / Unreferenced Files | probe | высокая | — | 🟡 уже покрыт тем же `sensitive_files` (в каталоге primary = CONF-03, в описании «also CONF-04»); можно добавить второй WSTG-ID в отчётность |
| CONF-10 | Subdomain Takeover | probe | средняя | M | DNS-резолв + fingerprints «висящих» CNAME (AWS/GitHub/Heroku/…); внешняя сеть/DNS |
| CONF-11 | Cloud Storage | probe | средняя | M | bucket-имена из host (`<host>.s3.amazonaws.com`, `storage.googleapis.com/<host>`, `blob.core.windows.net`) → public listing (quick win) |
| CONF-01 | Network Infrastructure Configuration | manual | низкая | — | вне scope веб-сканера |
| CONF-13 (v5) | Path Confusion | probe | низкая | M | probe нормализации путей (`/admin/..;/`, `%2e%2e`, `//`) — нишево |
| CONF-15 (v5) | Feature Flag Security Bypass | manual | средняя | M | ручной/stateful, зависит от приложения |
| CONF-09 | File Permissions | manual | низкая | — | требует доступа к ФС, вне scope |

### 2.3. IDNT — Identity Management

Все 5 тестов — manual/stateful: `IDNT-01` role definitions, `IDNT-02` registration process,
`IDNT-03` provisioning, `IDNT-04` account enumeration, `IDNT-05` username policy.
Единственный реально автоматизируемый фрагмент — **IDNT-04** (oracle по разнице ответов login/register)
→ `M`, требует login-flow и двух тестовых аккаунтов (инфраструктура §5).
`IDNT-02/05` частично закрываются passive-чеком «weak password policy» (см. ATHN-07/quick wins).

### 2.4. ATHN — Authentication

| WSTG | Тест | auto | Ценность | S/M/L | Что нужно |
|---|---|---|---|---|---|
| ATHN-02 | Default Credentials | active | высокая | M | login-flow: парсинг формы, список пар (admin/admin, admin/password, …), низкий RPS, не блокировать аккаунт |
| ATHN-03 | Weak Lock Out Mechanism | active | средняя | M | повторные попытки → 429/lockout; **opt-in**, риск блокировки аккаунта |
| ATHN-04 | Bypassing Authentication Schema | manual/active | средняя | M | обход через verb/param/path — набор ручных/эвристических кейсов |
| ATHN-05 | Vulnerable Remember Password | passive | средняя | M | анализ remember-me cookie (base64(user:pass), постоянный токен без ротации) |
| ATHN-07 | Weak Password Policy | passive | средняя | **S** | `weak_password_policy`: registration/change-password формы без `minlength/pattern`, `autocomplete` — quick win |
| ATHN-08 | Security Question Answer | manual | низкая | — | manual-only |
| ATHN-09 | Password Change/Reset | manual | высокая | M/L | ручной сценарий (reset-token, host header poisoning — см. INJT-17) |
| ATHN-10 | Weaker Auth in Alternative Channel | manual | низкая | — | manual-only |
| ATHN-11 (v5) | MFA | manual | средняя | M | ручной; эвристика наличия MFA-страницы малополезна |

### 2.5. ATHZ — Authorization

| WSTG | Тест | auto | Ценность | S/M/L | Что нужно |
|---|---|---|---|---|---|
| ATHZ-02 | Bypassing Authorization Schema | active | высокая | M/L | stateful: 2 роли/пользователя + replay с чужими объектами; фундамент (`session_manager`, `auth_boundary`) уже есть |
| ATHZ-03 | Privilege Escalation | active | высокая | M/L | то же + поля ролей (пересекается с mass assignment) |
| ATHZ-05 (v5) | OAuth Weaknesses | manual | средняя | M/L | redirect_uri/open redirect chain, `state` — частично probe, в основном manual |

🟡 `ATHZ-04 IDOR` покрыт эвристикой (`idor` — numeric/GUID в URL, passive), активной подстановки
соседних ID нет; `auth_boundary` — ручной инструмент сравнения «аноним vs с сессией».

### 2.6. SESS — Session Management

| WSTG | Тест | auto | Ценность | S/M/L | Что нужно |
|---|---|---|---|---|---|
| SESS-01 | Session Management Schema | passive | средняя | **S** | 🟡 частично: добавить `weak_sid`-эвристику (длина/энтропия session cookie) |
| SESS-04 | Exposed Session Variables | passive | средняя | **S** | `session_in_url`: session-like значения в query/path/Referer — quick win |
| SESS-03 | Session Fixation | active | высокая | M | login-flow: сравнить ID до/после логина |
| SESS-06 | Logout Functionality | active | средняя | M | login-flow: после logout старый cookie не должен работать |
| SESS-07 | Session Timeout | active | низкая | L | требует ожидания (минуты) — в лёгкой лиге неприемлемо, manual |
| SESS-08 | Session Puzzling | manual | средняя | — | manual-only |
| SESS-09 | Session Hijacking | manual | низкая | — | manual-only (нужен MitM/браузер) |
| SESS-11 (v5) | Concurrent Sessions | active | низкая | M | login-flow, повторный вход тем же пользователем |

✅ `SESS-02` cookies, `SESS-05` csrf; `SESS-10` jwt (в v4.2 отсутствует).

### 2.7. INPV (v4.2) / INJT (v5) — Injection

| WSTG | Тест | auto | Ценность | S/M/L | Что нужно |
|---|---|---|---|---|---|
| INPV-02/INJT-02 | Stored XSS | active | **высокая** | L | краулер/2-й проход: отправить маркер, найти его в сохранённых страницах; без discovery невозможен |
| INPV-03/INJT-03 | HTTP Verb Tampering | engine | средняя | M | replay перехваченного запроса с другим глаголом + сравнение auth-поведения (сейчас probe `http_methods` лишь перечисляет Allow/TRACE) |
| INPV-04/INJT-04 | HTTP Parameter Pollution | engine | средняя | M | новый mutation-тип «дублирование параметра» (`a=1&a=<payload>`), differential-детекция |
| INPV-10/INJT-10 | IMAP/SMTP Injection | active | низкая | S | payload-чек для email-параметров (`%0d%0a` в поля письма), сигнатуры ошибок MTA |
| INPV-13/INJT-13 | Format String Injection | active | низкая | S | payload'ы `%s%n%p` + ошибки/креши (`format string`, `%n`) |
| INPV-14/INJT-14 | Incubated Vulnerability | active | средняя | L | second-order: требует хранилища + повторного обхода (краулер) |
| INPV-17/INJT-17 | Host Header Injection | probe/active | **высокая** | M | `Host`/`X-Forwarded-Host: evil-<rand>` → отражение в body/Location/absolute-URL (quick win) |
| INPV-16 | HTTP Incoming Requests | manual | низкая | — | убран в v5, вне scope |
| INJT-16 (v5) | HTTP Request Smuggling | engine | высокая | L | raw-сокеты + CL/TE-тайминги; отдельный под-движок, риск для цели |
| INJT-20 (v5) | Mass Assignment | engine | **высокая** | M | JSON-поля «добавить, а не заменить» (`role`, `is_admin`, `status`) + сравнение ответов (quick win) |
| INJT-21 (v5) | CSV Injection | active/passive | средняя | M | payload `=HYPERLINK(...)`, `@SUM(...)` в поля; детект — только при выгрузке/Stored → без краулера слабо |
| INJT-22 (v5) | Prototype Pollution | active | средняя | M | JSON `__proto__`/`constructor.prototype`, серверный детект по ответу/поведению (клиентский — manual) |

✅ `INPV-01` reflected XSS, `05` SQLi (error/time/blind), `06` LDAP, `07` XXE (см. §3 — декларативно),
`08` SSI, `09` XPath, `11` code injection частично (LFI/RFI — `path_traversal`, exec — `ssti`/`cmdi`/`deserialization`),
`12` CMDi, `15` response splitting (`crlf_injection`; request smuggling — нет), `18` SSTI,
`19` SSRF (in-band; слепой — нет), `23` deserialization (декларативно).

### 2.8. ERRH — Error Handling

| WSTG | Тест | auto | Ценность | S/M/L | Что нужно |
|---|---|---|---|---|---|
| ERRH-01 | Improper Error Handling | passive | средняя | **S** | 🟡 частично ловится `info_disclosure` (stack trace/exception) и SQL/CMDi-сигнатурами; нужен отдельный `errh`-чек (WSTG-маппинг + паттерны PHP Warning/Java stack/DEBUG-страницы) — quick win |
| ERRH-02 | Stack Traces | passive | средняя | **S** | то же; вынести в отдельный чек для чистого WSTG-ID |

### 2.9. CRYP — Weak Cryptography

| WSTG | Тест | auto | Ценность | S/M/L | Что нужно |
|---|---|---|---|---|---|
| CRYP-01 | Weak Transport Layer Security | probe | **высокая** | M | `tls_config`: TLS<1.2, weak ciphers, self-signed/истёкший серт, отсутствие HSTS-редиректа (quick win) |
| CRYP-02 | Padding Oracle | manual | средняя | — | manual-only |
| CRYP-03 | Sensitive Info via Unencrypted Channels | passive | средняя | — | 🟡 покрыт `insecure_login` (логин/пароль/Authorization по http) |
| CRYP-04 | Weak Encryption | passive | средняя | M | 🟡 частично `info_disclosure` (base64/ключи) + `jwt` (слабый HMAC); отдельный чек/расширение — M |

### 2.10. BUSL — Business Logic

| WSTG | Тест | auto | Ценность | S/M/L | Что нужно |
|---|---|---|---|---|---|
| BUSL-07 | Defenses Against Application Misuse | probe | средняя | M | `rate_limit` probe (N запросов → 429/замедление); **opt-in**, риск lockout (quick win-кандидат) |
| BUSL-04 | Process Timing | active | низкая | M | тайминговые аномалии, сильно зависит от приложения |
| BUSL-01…03, 05, 06, 10 | — | manual | средняя | — | бизнес-логика не автоматизируется без модели приложения; `BUSL-10 Payment` — вне scope |
| BUSL-08 | Upload of Unexpected File Types | passive/active | средняя | M | 🟡 `file_upload` ловит опасные расширения в перехваченном multipart; активной загрузки/обхода MIME нет (§3) |

### 2.11. CLNT — Client-side

| WSTG | Тест | auto | Ценность | S/M/L | Что нужно |
|---|---|---|---|---|---|
| CLNT-01 | DOM-based XSS | passive | средняя | M | 🟡 `xss_dom` — эвристика sources/sinks без исполнения; полноценно — browserless DOM-taint или headless-браузер (L) |
| CLNT-02 | JavaScript Execution | manual | низкая | — | дублирует XSS-проверки, нужен JS-движок — manual |
| CLNT-05 | CSS Injection | active | низкая | **S** | `css_injection`: payload `</style><div notscan=...>`, маркер-reflect matcher (по образцу html_injection) — quick win |
| CLNT-06 | Client-side Resource Manipulation | passive | средняя | M | 🟡 `third_party_scripts` лишь SRI; нужен статический анализ JS (sink/source) |
| CLNT-08 | Cross Site Flashing | manual | — | — | deprecated, вне scope (нет в v5) |
| CLNT-10 | WebSockets | engine | средняя | L | нужен WS-клиент и перехват сообщений (mitm_proxy сейчас хранит только HTTP-обмен) |
| CLNT-11 | Web Messaging | manual | низкая | — | postMessage-анализ требует JS/браузера — manual |
| CLNT-13 | Cross Site Script Inclusion | probe/active | средняя | M | `xssi_jsonp`: поиск JSONP-эндпоинтов + детект отражения `callback` и чувствительных JSON |
| CLNT-14 (v5) | Reverse Tabnabbing | passive | низкая | **S** | `reverse_tabnabbing`: `<a target="_blank">` без `rel="noopener/noreferrer"` — quick win |
| CLNT-15 (v5) | Client-side Template Injection | manual | средняя | M | статическая эвристика (`{{...}}` в тексте без серверного исполнения) — FP-риск, лучше manual |

### 2.12. APIT — API Testing

| WSTG | Тест | auto | Ценность | S/M/L | Что нужно |
|---|---|---|---|---|---|
| APIT-01 (v4.2) / APIT-99 (v5) | GraphQL | probe | **высокая** | M | `graphql_introspection`: POST `{__schema{types{name}}}`, детект `__schema` (quick win) |
| APIT-01 (v5) | API Reconnaissance | passive/engine | средняя | M | 🟡 `contract_inference` + импорт коллекций; полный — краулер L |
| APIT-02 (v5) | API BOLA | active | высокая | M/L | 🟡 `idor`-эвристика + `auth_boundary` manual; активная подмена объектов — stateful (инфра) |
| APIT-03 (v5) | Excessive Data Exposure | passive | **высокая** | M | `excessive_data_exposure`: JSON-ответы с `password_hash`, `token`, `email`, `ssn`, `card` полями (quick win) |
| APIT-04 (v5) | Broken Function Level Auth | active | средняя | M/L | stateful-роли (инфра) |
| WASM-01 (v5) | WebAssembly Recon | manual | низкая | — | вне scope |

---

## 3. Важное: «декларативное» покрытие (чеки есть, но достижимость ограничена)

Это честный аудит: наличие чека в каталоге ≠ полноценная проверка класса.

| Чек | Фактическая детекция | Ограничение / следствие |
|---|---|---|
| `xxe` (INPV-07) | ошибки/признаки XML в ответе | **нет mutation-типа для raw/XML-тела**: `get_mutations` (`templating.py:352`) умеет только query/form/JSON/headers; для запроса с `Content-Type: application/xml` и XML-телом задач не строится (planner требует `xml` + body, но body не парсится). На лабе нет XML-эндпоинта. Фактическое покрытие реальных XML API ≈ 0; OOB-XXE нет. **Quick win M: mutation-тип `body_raw`.** |
| `deserialization` (INJT-23) | маркеры ошибок/500 + `rO0AB` в payload | payload подставляется строкой в параметр/JSON; сырое сериализованное тело не отправляется → на практике ловится только error-marker на серверах, которые десериализуют параметр. Тот же `body_raw`-mutation закроет. |
| `file_upload` (BUSL-09/08) | passive: опасные расширения в перехваченном multipart | активной загрузки/обхода MIME нет (нет multipart-mutation); webshell-маркеры — только если сервер их отразил. |
| `idor` (ATHZ-04) | passive эвристика: numeric/GUID в URL/200 | активной подстановки соседних ID нет; FP-риск и низкая доказательность. |
| `xss_dom` (CLNT-01) | пассивный поиск sources+sinks в HTML/JS | без исполнения JS; подтверждать вручную. |
| `csrf` (SESS-05) | пассивная эвристика (unsafe method без токена/SameSite) | без replay; состояния/сессии не учитывает. |
| `jwt` (SESS-10) | alg=none + перебор слабых HMAC-секретов | нет alg-confusion, kid/jku/x5u, exp/nbf; см. §5 `jwt_advanced`. |
| `sqli_time` (INPV-05) | задержка только по payload'ам из `SQLI_TIME_PAYLOADS` (~23) | из `sqli_time.txt` (143) измеряются ~23; остальные идут как обычные мутации без тайминг-детекции. |
| `xss_reflected` (INPV-01) | checks-слой (`XSSReflectedCheck`) | в `MATCHERS` нет ключа `xss_reflected` (`scanner_core.py:1661` — только legacy `xss`), т.е. matcher-слой для каталожного ID не работает; в GUI legacy-список `xss` плюс каталожный `xss_reflected` (`notscan.py:1060`) → возможен двойной расход payload'ов. |
| `security_headers`/`csp`/`hsts` | passive | нормально, но частично дублируют друг друга (одна и та же находка может попасть в 2-3 чека). |

**Вывод:** реальная матрица покрытия ближе к 28–32 тестам v4.2 «с доказательной детекцией», а не 32
«по маппингу». Приоритет №1 для качества — `body_raw` mutation (XXE/deserialization) и активный IDOR.

---

## 4. Классы вне текущего покрытия (включая non-WSTG)

`WSTG` — есть ли тест в WSTG (v4.2/v5); остальные — внешние классы, важные для лёгкой лиги.

| Класс | WSTG | auto | Ценность | S/M/L | Чем закрывать |
|---|---|---|---|---|---|
| Stored XSS | INJT-02/INPV-02 | active | высокая | L | краулер/2-проход + маркерный payload |
| Blind SSRF / XXE / RCE (OOB) | INPV-19/07, INJT-12 | active | высокая | L | OOB-коллаборатор (HTTP callback/DNS), уникальный маркер на задачу |
| HTTP Response Splitting | INJT-15/INPV-15 | ✅ | — | — | покрыт `crlf_injection` |
| HTTP Request Smuggling / desync | INJT-16 | engine | высокая | L | raw-сокеты, CL/TE, тайминги; отдельный под-движок |
| Host Header Injection | INJT-17 | probe | высокая | M | quick win (см. §5) |
| HPP | INJT-04 | engine | средняя | M | duplicate-param mutation |
| Mass Assignment | INJT-20 | engine | высокая | M | JSON field-add mutation |
| Prototype Pollution | INJT-22 | active | средняя | M | JSON `__proto__` mutation + серверный детект |
| CSV / Formula Injection | INJT-21 | active | средняя | M | payload'ы `=...`, `@...`; детект только при выгрузке → лучше со stored/crawler |
| Email / IMAP-SMTP Injection | INJT-10 | active | низкая | S | payload-чек для email-полей |
| Format String | INJT-13 | active | низкая | S | payload-чек `%s%n%p` |
| Incubated / second-order | INJT-14 | active | средняя | L | хранилище + краулер |
| GraphQL | APIT-01/99 | probe | высокая | M | introspection quick win |
| JWT-атаки шире alg=none/weak secret | SESS-10 v5 | active/probe | средняя | M | alg-confusion, kid path traversal, jku/x5u, нет exp |
| OAuth weaknesses | ATHZ-05 v5 | manual/probe | средняя | M/L | redirect_uri/open redirect, state, token leakage |
| Subdomain Takeover | CONF-10 | probe | средняя | M | DNS + fingerprints |
| Cloud Storage | CONF-11 | probe | средняя | M | bucket-имена из host |
| TLS/crypto-конфиг | CRYP-01/04 | probe | высокая | M | ssl-сокет: версии/шифры/серт; слабые примитивы |
| Rate limiting / brute-force | BUSL-07 | probe | средняя | M | opt-in probe, риск lockout |
| Session fixation/timeout/logout | SESS-03/06/07 | active | средняя | M | login-flow (session_manager уже есть) |
| Business logic | BUSL-01…06,10 | manual | средняя | — | manual-only без модели приложения |
| `cve_lookup` — Vulnerable & Outdated Components | вне WSTG (OWASP A06) | passive/probe | высокая | M/L | fingerprint версий → CVE-база (NVD/OSV), §6 |
| Crawler / discovery | INFO-04/06/07/10 | engine | высокая | L | §6 |
| WAF fingerprint | вне WSTG | passive | средняя | S | заголовки/cookies/403-страницы (Cloudflare/Akamai/Sucuri/ModSecurity) — подсказывает tamper |
| Web cache poisoning / deception | вне WSTG | probe | средняя | M | `X-Forwarded-Host`/`Host` + cache-заголовки; риск, opt-in |
| HTTP/2-specific (h2c, pseudo-headers) | вне WSTG | engine | низкая | L | отдельный транспорт |
| WASM-анализ | WASM-01 v5 | manual | низкая | — | вне scope |

---

## 5. Приоритизированный roadmap

### 5.1. Quick wins — 17 штук (S/M, без новой инфраструктуры)

Реализуются в текущей архитектуре: passive-чек в `checks/passive_extra.py` / `client_side.py`,
payload-чек в `checks/injections.py` + файл в `payloads/`, probe в `path_probe.py`,
mutation-тип в `templating.py` + planner. Каждый требует тестов в существующих test-файлах и WSTG-ID в каталоге.

| # | Предлагаемый ID | WSTG | тип | S/M | Что нужно | Ценность |
|---|---|---|---|---|---:|---|
| 1 | `server_fingerprint` | INFO-02 | passive | S | Server/X-Powered-By/cookie/HTML-метки | средняя |
| 2 | `errh` (или `error_handling`) | ERRH-01/02 | passive | S | паттерны stack trace/PHP Warning/DEBUG-страниц; переиспользовать каркас `info_disclosure` | средняя |
| 3 | `session_in_url` | SESS-04 | passive | S | session-like токены в query/path/Referer | средняя |
| 4 | `weak_password_policy` | ATHN-07 | passive | S | формы регистрации/смены пароля: нет `minlength/pattern/autocomplete` | средняя |
| 5 | `weak_sid` | SESS-01 | passive | S | длина/энтропия session-cookie (осторожно с FP) | средняя |
| 6 | `reverse_tabnabbing` | CLNT-14 (v5) | passive | S | `<a target=_blank>` без `rel=noopener` | низкая |
| 7 | `css_injection` | CLNT-05 | active | S | `payloads/css.txt` + маркерный matcher (по образцу html_injection) | низкая |
| 8 | `waf_fingerprint` | — (non-WSTG) | passive | S | заголовки/cookies/403-страницы WAF | средняя |
| 9 | `host_header_injection` | INJT-17 | probe | M | `Host`/`X-Forwarded-Host` с случайным доменом → отражение в body/Location | высокая |
| 10 | `tls_config` | CRYP-01 | probe | M | ssl-сокет: TLS<1.2, weak ciphers, self-signed/expired cert | высокая |
| 11 | `graphql_introspection` | APIT-99/APIT-01 | probe | M | POST `{__schema{types{name}}}`, детект `__schema` | высокая |
| 12 | `cloud_storage` | CONF-11 | probe | M | bucket-имена из host → public listing | средняя |
| 13 | `excessive_data_exposure` | APIT-03 (v5) | passive | M | JSON: `password_hash/token/email/ssn/card`-поля + baseline-suppress | высокая |
| 14 | `jwt_advanced` | SESS-10 (v5) | active/probe | M | alg-confusion, `kid` path traversal, `jku/x5u`, отсутствие `exp` | средняя |
| 15 | `body_raw` mutation + XXE/deser | INPV-07 / INJT-23 | engine | M | mutation-тип «сырое тело» + плейсхолдер; закрывает декларативный XXE/deserialization (§3) | высокая |
| 16 | `mass_assignment` | INJT-20 (v5) | engine | M | JSON field-add mutation (`role/is_admin/verified`), сравнение ответов | высокая |
| 17 | `hpp` | INJT-04 | engine | M | duplicate-param mutation + differential-детекция | средняя |

Дополнительно «дешёвые, но низкая ценность» (по желанию, +3): `format_string` (INJT-13, S),
`imap_smtp` (INJT-10, S), `csv_injection` (INJT-21, M — без stored/crawler почти не детектится).

### 5.2. Требует инфраструктуры

| Инфраструктура | Что закрывает | S/M/L | Замечания |
|---|---|---|---|
| **Краулер / discovery** | INFO-04/06/07/10, INJT-02 stored XSS, INJT-14, CLNT-13 (поиск JSONP), APIT-01, IDNT-... | L | обход `<a href>/<form>/<script src>`, очередь запросов через прокси/дедуп по паттернам; `contract_inference` уже даёт базу |
| **OOB-коллаборатор** | blind SSRF (INPV-19), blind XXE (INPV-07), blind RCE (CMDi/SSTI/deser), stored XSS-callback | L | нужен публично доступный HTTP/DNS-приёмник + уникальный маркер на задачу; минимум — локальный для лабы |
| **Login/stateful-слой** | ATHN-02/03/04/05, ATHZ-02/03, SESS-03/06/11, IDNT-04, APIT-02/04 | M | многопользовательский режим (2 аккаунта/роли), replay-подмена объектов, безопасный режим против lockout; `session_manager` уже есть |
| **Raw-socket под-движок** | INJT-16 smuggling, advanced response splitting/desync | L | отдельный клиент (не httpx), CL/TE-эксперименты, строгий scope-guard |
| **WebSockets-клиент** | CLNT-10 | L | mitm_proxy хранит только HTTP; нужен перехват WS-сообщений |
| **DNS-хелперы** | CONF-10 subdomain takeover, INFO-04 vhosts | M | резолв CNAME/A + fingerprints «висящих» сервисов |
| **CVE-база** | `cve_lookup` (Vulnerable & Outdated Components) | M/L | §6 |

### 5.3. Manual-only (честно не автоматизируем)

`IDNT-01/02/03/05`, `ATHN-08/09/10/11`, `ATHZ-05` (в основном), `SESS-08/09`, `CRYP-02`,
`BUSL-01/02/03/04/05/06/10`, `CONF-01/09/15`, `CLNT-02/11/15`, `APIT-04` (без ролей),
`WASM-01`, `INFO-01`, бизнес-логика и second-order без краулера.
Всего ≈ **30 тестов** + классы business logic/cache-poisoning в части ручных сценариев.

### 5.4. Предлагаемый порядок (3 итерации)

1. **Итерация 1 (S, быстрые очки):** `server_fingerprint`, `errh`, `session_in_url`,
   `weak_password_policy`, `reverse_tabnabbing`, `waf_fingerprint` + `tls_config`/`host_header_injection`
   (M) — «+8–9 WSTG-тестов» почти без риска для текущего поведения.
2. **Итерация 2 (M, движок):** `body_raw` mutation (XXE/deser), `mass_assignment`, `hpp`,
   `excessive_data_exposure`, `jwt_advanced`, `graphql_introspection`, `cloud_storage`.
3. **Итерация 3 (L, инфраструктура):** краулер → stored XSS/JSONP/discovery; login-flow →
   default creds/IDOR-BOLA/fixation; OOB → blind SSRF/XXE/RCE; далее smuggling/WebSockets/CVE.

---

## 6. Место `cve_lookup` и краулера в анализе

- **CVE-проверка (`cve_lookup`)** — **вне WSTG-матрицы** (WSTG не тестирует «уязвимые компоненты»),
  но закрывает OWASP A06 «Vulnerable & Outdated Components» и текущие «прокси-чеки»
  `outdated_libs` (WSTG-INFO-08, nearest) / `third_party_scripts` (INFO-09, nearest).
  Реализуемость `M/L`: (а) fingerprint версий из HTML/JS/headers (уже частично есть в `outdated_libs`
  и будущем `server_fingerprint`), (б) офлайн CVE-база (NVD/OSV JSON) или OSV API (сеть, кэш),
  (в) маппинг «продукт+версия → CVE» с порогом severity. Без OOB/краулера; WSTG-ID в каталоге:
  пустой или `WSTG-INFO-08 (nearest)` — рекомендуется отдельная колонка «вне WSTG» в GUI.
- **Краулер** — **инфраструктурный next-step**, а не чек: закрывает discovery-тесты
  (INFO-04/06/07/10), даёт вход для stored XSS (INJT-02), second-order (INJT-14), JSONP/XSSI
  (CLNT-13), API-recon (APIT-01) и частично IDNT-04. Требует: обход HTML/JS/форм, дедуп по
  нормализованному паттерну (`contract_inference.normalize_url_pattern` уже есть), ограничение
  глубины/scope. После краулера `stored XSS` становится реалистичным M-чеком (payload → crawl → проверка
  отражения в сохранённых страницах).

---

## 7. Финальная таблица покрытия: 39 текущих чеков

Все чеки присутствуют в каталоге и registry (status = ✅ есть). `matcher` = детекция matcher-слоем
(с baseline-suppress), `check` = checks-слой, `engine` = парные запросы, `—` = не применимо.

| # | check_id | WSTG-ID | CWE | kind | Детекция | Статус |
|---:|---|---|---|---|---|---|
| 1 | `info_disclosure` | WSTG-INFO-05 | CWE-200 | passive | check | ✅ |
| 2 | `outdated_libs` | WSTG-INFO-08 | CWE-1035 | passive | check | ✅ (nearest) |
| 3 | `third_party_scripts` | WSTG-INFO-09 | CWE-829 | passive | check | ✅ (nearest) |
| 4 | `metafiles` | WSTG-INFO-03 | CWE-200 | probe | probe | ✅ |
| 5 | `security_headers` | WSTG-CONF-14 (v5) | CWE-693 | passive | check | ✅ |
| 6 | `clickjacking` | WSTG-CLNT-09 | CWE-1021 | passive | check | ✅ |
| 7 | `hsts` | WSTG-CONF-07 | CWE-319 | passive | check | ✅ |
| 8 | `csp` | WSTG-CONF-12 (v5) | CWE-693 | passive | check | ✅ |
| 9 | `ria_policy` | WSTG-CONF-08 | CWE-942 | probe | probe | ✅ |
| 10 | `http_methods` | WSTG-CONF-06 | CWE-650 | probe | probe | ✅ |
| 11 | `sensitive_files` | WSTG-CONF-03 (+CONF-04) | CWE-538 | probe | probe | ✅ |
| 12 | `info_disclosure_paths` | WSTG-CONF-05 | CWE-538 | probe | probe | ✅ |
| 13 | `sqli` | WSTG-INPV-05 | CWE-89 | active | matcher+check | ✅ |
| 14 | `sqli_time` | WSTG-INPV-05 | CWE-89 | active | check | ✅ (≈23 payload'а с порогом) |
| 15 | `sqli_blind` | WSTG-INPV-05 | CWE-89 | active | engine (pair) | ✅ |
| 16 | `cmdi` | WSTG-INPV-12 | CWE-78 | active | matcher+check | ✅ |
| 17 | `ssti` | WSTG-INPV-18 | CWE-94 | active | matcher+check | ✅ |
| 18 | `ldap_injection` | WSTG-INPV-06 | CWE-90 | active | matcher+check | ✅ |
| 19 | `xpath_injection` | WSTG-INPV-09 | CWE-643 | active | matcher+check | ✅ |
| 20 | `nosql_injection` | WSTG-INJT-05 (v5) | CWE-943 | active | matcher+check | ✅ (nearest) |
| 21 | `xxe` | WSTG-INPV-07 | CWE-611 | active | matcher+check | 🟡 декларативно (§3) |
| 22 | `deserialization` | WSTG-INJT-23 (v5) | CWE-502 | active | matcher+check | 🟡 декларативно (§3) |
| 23 | `crlf_injection` | WSTG-INPV-15 | CWE-113 | active | matcher+check | ✅ |
| 24 | `ssrf` | WSTG-INPV-19 | CWE-918 | active | matcher+check | ✅ (in-band) |
| 25 | `ssi_injection` | WSTG-INPV-08 | CWE-97 | active | matcher+check | ✅ |
| 26 | `path_traversal` | WSTG-ATHZ-01 | CWE-22 | active | matcher+check | ✅ |
| 27 | `xss_reflected` | WSTG-INPV-01 | CWE-79 | active | check | ✅ (matcher только legacy `xss`) |
| 28 | `html_injection` | WSTG-CLNT-03 | CWE-80 | active | matcher+check | ✅ |
| 29 | `open_redirect` | WSTG-CLNT-04 | CWE-601 | active | matcher+check | ✅ |
| 30 | `file_upload` | WSTG-BUSL-09 | CWE-434 | passive | check | 🟡 passive-only (§3) |
| 31 | `xss_dom` | WSTG-CLNT-01 | CWE-79 | passive | check | 🟡 эвристика |
| 32 | `browser_storage` | WSTG-CLNT-12 | CWE-922 | passive | check | ✅ |
| 33 | `cors` | WSTG-CLNT-07 | CWE-942 | probe | probe | ✅ |
| 34 | `csrf` | WSTG-SESS-05 | CWE-352 | passive | check | ✅ (эвристика) |
| 35 | `jwt` | WSTG-SESS-10 (v5) | CWE-347 | passive | check | ✅ (alg=none + weak secret) |
| 36 | `cookies` | WSTG-SESS-02 | CWE-614 | passive | check | ✅ |
| 37 | `cache_control` | WSTG-ATHN-06 | CWE-525 | passive | check | ✅ |
| 38 | `insecure_login` | WSTG-ATHN-01 | CWE-319 | passive | check | ✅ |
| 39 | `idor` | WSTG-ATHZ-04 | CWE-639 | passive | check | 🟡 эвристика (нет активной подстановки) |

---

## 8. Методика, допущения, ограничения

1. **WSTG v4.2 = 97 тестов**: `BUSL-00` (вводный) исключён; под-тесты `INPV-05.1…05.8`
   (Oracle/MySQL/MSSQL/PostgreSQL/NoSQL/ORM/…) отнесены к `WSTG-INPV-05`.
2. **v5-dev ≠ v4.2 по нумерации**: `INPV-*` → `INJT-*` (1–14 и 17–19 совпадают; `INPV-15`
   разделён на `INJT-15` response splitting + `INJT-16` request smuggling); v5 добавил `INJT-20…23`,
   `CONF-12…15`, `ATHN-11`, `ATHZ-05`, `SESS-10/11`, `CLNT-14/15`, `APIT`, `WASM` и убрал `CLNT-08`.
3. **«Nearest»-маппинг** (NoSQL → `INJT-05`, XXE → `INPV-07`, outdated libs/3rd-party → INFO-08/09,
   file upload → BUSL-09) отмечен в каталоге/`docs/CHECKS.md`; при подсчёте «покрыто» я включал
   такие тесты, но в §3 они охарактеризованы отдельно.
4. **Статусы 39 чеков** — по коду/каталогу, без запуска сканов (документ read-only; рантайм-поведение
   на реальных целях не измерялось).
5. **Оценки S/M/L и ценности** — экспертные, для лёгкой лиги (API/приложение, 1 разработчик,
   без внешней инфраструктуры по умолчанию); порядок в roadmap можно менять по продукту.
6. **Риски-предупреждения**: `http_methods`-probe и будущие PUT/DELETE/rate-limit/smuggling-тесты
   имеют побочные эффекты на цели — держать opt-in/Safe-mode; OOB и smuggling требуют отдельного
   согласия (ROE).
7. Документ не меняет поведение сканера; предложения по чекам/движку — материал для следующих
   задач (планирование делает Lead).

---

## Приложение A. WSTG v4.2 — разбивка по статусам (97 тестов)

**❌ Не покрыто (50):**
`INFO-01, INFO-02, INFO-06, INFO-07, INFO-10; CONF-01, CONF-09, CONF-10, CONF-11;
IDNT-01, IDNT-02, IDNT-03, IDNT-04, IDNT-05; ATHN-02, ATHN-03, ATHN-04, ATHN-05, ATHN-07,
ATHN-08, ATHN-09, ATHN-10; ATHZ-02, ATHZ-03; SESS-03, SESS-06, SESS-07, SESS-08, SESS-09;
INPV-02, INPV-04, INPV-10, INPV-13, INPV-14, INPV-16, INPV-17;
CRYP-01, CRYP-02; BUSL-01, BUSL-02, BUSL-03, BUSL-04, BUSL-05, BUSL-06, BUSL-07;
CLNT-05, CLNT-08, CLNT-10, CLNT-11, CLNT-13`.

**🟡 Частично (15):** `INFO-04` (probe типовых путей), `CONF-02` (headers+probes),
`CONF-04` (тот же `sensitive_files`), `SESS-01` (cookies), `SESS-04` (info_disclosure частично),
`INPV-03` (`http_methods` probe), `INPV-11` (LFI/RFI через `path_traversal`), `ERRH-01`, `ERRH-02`
(паттерны в `info_disclosure`), `CRYP-03` (`insecure_login`), `CRYP-04` (`info_disclosure` + `jwt`),
`BUSL-08` (`file_upload` расширения), `CLNT-02` (`xss_reflected`), `CLNT-06` (`third_party_scripts`),
`APIT-01` (`contract_inference`).

**✅ По маппингу (32, из них 4 ограничены — §3):** `INFO-03/05/08/09`, `CONF-03/05/06/07/08`,
`INPV-01/05/06/07/08/09/12/15/18/19`, `ATHZ-01/04`, `SESS-02/05`, `ATHN-01/06`,
`CLNT-01/03/04/07/09/12`, `BUSL-09`.

## Приложение B. WSTG v5-дополнения (нет в v4.2) и их статус

| v5-ID | Тест | Статус | Комментарий |
|---|---|---|---|
| CONF-12 | Content Security Policy | ✅ | `csp` |
| CONF-13 | Path Confusion | ❌ | probe нормализации путей (M, нишево) |
| CONF-14 | Other HTTP Security Header Misconfig | ✅ | `security_headers` |
| CONF-15 | Feature Flag Security Bypass | ❌ | manual |
| ATHN-11 | MFA | ❌ | manual |
| ATHZ-05 | OAuth Weaknesses | ❌ | manual/probe (M/L, инфра) |
| SESS-10 | JSON Web Tokens | ✅ | `jwt` (базовые атаки; расширение — `jwt_advanced`) |
| SESS-11 | Concurrent Sessions | ❌ | login-flow (M) |
| INJT-15 | HTTP Response Splitting | ✅ | `crlf_injection` |
| INJT-16 | HTTP Request Smuggling | ❌ | raw-сокеты (L) |
| INJT-17 | Host Header Injection | ❌ | quick win (M) |
| INJT-20 | Mass Assignment | ❌ | quick win (M) |
| INJT-21 | CSV Injection | ❌ | M (слабо без stored) |
| INJT-22 | Prototype Pollution | ❌ | M |
| INJT-23 | Insecure Deserialization | 🟡 | `deserialization` (декларативно, §3) |
| CLNT-14 | Reverse Tabnabbing | ❌ | quick win (S) |
| CLNT-15 | Client-side Template Injection | ❌ | manual/M |
| APIT-01 | API Reconnaissance | 🟡 | `contract_inference`/коллекции |
| APIT-02 | API BOLA | 🟡 | `idor` + `auth_boundary` manual |
| APIT-03 | Excessive Data Exposure | ❌ | quick win (M) |
| APIT-04 | API Broken Function Level Auth | ❌ | stateful (M/L) |
| APIT-99 | GraphQL | ❌ | quick win (M) |
| WASM-01 | WebAssembly Recon | ❌ | вне scope |
