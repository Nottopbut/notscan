# Обзор функционала и архитектуры

## Слои приложения

```
GUI (notscan.py, Tkinter/ttkbootstrap)
  ├─ Proxy/Scan    — управление прокси, история, scan-list, запуск скана
  ├─ Scan Results  — триаж находок, evidence, пагинация, экспорт
  ├─ Auth          — login-сессии, токены, CSRF
  ├─ RevShell      — генератор reverse-shell команд (не выполняет)
  └─ Checks/WSTG   — каталог чеков, включение/выключение, WSTG-карта
        │
        ├─ mitm_proxy.py   — перехватывающий прокси (mitmproxy) + PAC-сервер
        ├─ db.py           — SQLite per-project (WAL, per-thread соединения)
        ├─ scanner_core.py — async-движок, построение задач, матчеры, scope-guard, ROE
        ├─ checks/         — каталог + active/passive проверки + FP-правила + runner
        ├─ templating.py   — парсинг/мутации raw HTTP, JSON-экранирование, tamper, CSRF
        ├─ session_manager.py — login/refresh/relogin, CSRF token provider
        ├─ path_probe.py   — probe-чеки (файлы, metafiles, CORS, HTTP-методы, …)
        └─ report_export.py— отчёты MD/JSON/HTML/SARIF/DOCX
```

## Проекты и данные

Каждый запуск создаёт отдельный проект `projects/<project_YYYYMMDD_HHMMSS>/`:

- `history.db` — SQLite: `history`, `scan_results`, `scan_meta`, `scan_requests`,
  `scan_confirmations`, `endpoint_contracts`, `auth_boundary_results`, `host_calibration`,
  `scan_links`, `evidence_snippets`;
- `settings.json` — настройки проекта (тема, жизненный цикл прокси);
- `reports/` — отчёты.

Смена проекта — **Project → Sessions / Projects…**; смена блокируется во время активного
скана (иначе закрылись бы соединения БД, которые используют воркеры).

## Перехват (History)

- Локальный прокси пишет метод, URL, заголовки, тело запроса, статус/заголовки/превью
  ответа.
- `history` — источник задач для мутационного скана и baseline-ответов для
  differential/FP-проверок.
- Прокси запускается автоматически; статус и порт — в верхней панели. Кнопка
  **Start Proxy + Browser** поднимает изолированный браузер с PAC и флагами обхода
  сертификатов.

## Мутационный скан

Для выбранных записей `history` строятся задачи по точкам мутации:

- query-параметры;
- `application/x-www-form-urlencoded` тела;
- JSON-тела (payload экранируется как JSON-строка — тело остаётся валидным JSON);
- заголовки (опционально).

**Движок** — `asyncio` + `httpx.AsyncClient`: `workers` = конкурентность, персистентность
через `asyncio.to_thread`, RPS-лимитер, корректный `stop()`. Редиректы **не сопровождаются**
(scope-guard: payload-редирект не должен уводить сканер на чужие хосты).

**ROE/scope:** allowlist целей (приоритет над block-private), блокировка private/metadata,
Safe Mode (фильтр деструктивных payload'ов), конкурентность/RPS, safe-обёртки
(`/loopback`-адреса можно явно разрешить allowlist'ом).

**Планировщик** отсекает заведомо неприменимые пары «чек × параметр» (типы параметров из
inferred-контрактов: int/url/json/email/…).

## Детекция

Два слоя, работающих на одном ответе:

1. **Matcher-слой** (`scanner_core.match_*`) — быстрые сигнатурные проверки
   (SQL-ошибки, отражение XSS с контекстными правилами, заголовки CRLF, Location и т.д.),
   с baseline-suppress: если сигнал есть и в baseline-ответе, он подавляется.
2. **Checks-пайплайн** (`checks/`) — 38 чеков из каталога:
   - **active** (16): payload-проверки (SQLi error/time, CMDi, SSTI, LDAP/XPath/NoSQL,
     XXE, deserialization, CRLF, SSRF, SSI, path traversal, reflected XSS, HTML injection,
     open redirect);
   - **passive** (16): анализ ответов (info disclosure, headers/HSTS/CSP, cookies,
     cache-control, креды по HTTP, browser storage, CSRF, JWT, clickjacking, file upload,
     DOM-XSS, IDOR и др.);
   - **probe** (6): отдельные запросы (sensitive files/backups, metafiles, RIA-policy,
     HTTP-методы/TRACE, admin/debug paths, CORS).

Полный каталог с WSTG-ID/CWE/severity — [`CHECKS.md`](CHECKS.md); источник —
`checks/catalog.py`.

**Контроль FP:** bare-tag/Content-Type/baseline-правила XSS; reflection-aware path
traversal и open redirect; soft-404/WAF-заглушки для probe; калибровка таймингов хоста
для time-based SQLi (`max(delay, 3×baseline_p50 + 1s)`); suppression по baseline в
checks-слое.

## Payloads, tamper, stateful

- Payload-наборы — 18 файлов, ~3.2k payload'ов (`payloads/`), один payload в строке;
  Safe Mode фильтрует деструктивные. Документация — [`../payloads/README.md`](../payloads/README.md).
- **Tamper/WAF-bypass**: кодировщики `url`, `unicode`, `hex`, `double-url` (только
  серверные инъекционные чеки, включается в конфигурации скана).
- **Auth/CSRF**: можно переиспользовать перехваченный login-запрос как шаблон сессии;
  на 401/403 воркер делает refresh/relogin; перед мутациями подставляется свежий
  CSRF-токен из формы/meta (`templating.patch_csrf_token`).

## Результаты, триаж, отчёты

- `scan_results` (+ `scan_meta`: severity/confidence/exploitability/fingerprint);
  `scan_requests` — сырой HTTP; `evidence_snippets` — unified diff.
- Дедуп по стабильному fingerprint (`host|path|check|param`), счётчик `occurrences`.
- Confirm-flow: baseline / benign / suspicious replay с diff — повышает confidence.
- GUI: пагинация Results («Load more», счётчик «показано / всего»), фильтры, detail-window.
- Отчёты: **MD / JSON / HTML / SARIF / DOCX**; по умолчанию выгружается полный набор
  результатов (без обрезки лимитом).

## Дополнительные инструменты

- **Endpoint contract inference** — офлайн-построение контрактов из history
  (нормализованный URL-pattern, типы/обязательность параметров, ожидаемые коды).
- **Auth boundary** — сравнение ответов «анонимно vs с сессией» (diff/sequence similarity).
- **RevShell** — генератор команд reverse shell (генерирует текст, никогда не выполняет).
- **Collections** — импорт/экспорт raw HTTP / HAR / Postman.

## Тестовая лаба

`tests/lab/` — самодостаточный `ThreadingHTTPServer` с намеренно уязвимыми эндпоинтами:
reflected XSS, escaped reflection, SQL-ошибки, редиректы, задержки (time-based), форма с
CSRF-токеном, JSON API, cookie/CORS/SSRF/SSI-кейсы, чувствительные файлы, metafiles,
HTTP-методы. Используется unit- и интеграционными тестами (`make test`, `make lab`).

## Ограничения

- Нет краулера/дискавери: цели — перехваченные запросы или импортированные коллекции.
- HSTS осмыслен только для HTTPS-целей (юнит-тесты; HTTP-лаба его не проверяет).
- Probe-чеки шлют реальные `OPTIONS`/`TRACE`/`PUT`/`DELETE` — только на разрешённых целях.
- Инструмент учебно-практический: не заменяет Burp Suite/ZAP/Nuclei.
