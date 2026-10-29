# notscan

**notscan** — настольный сканер веб-уязвимостей с графическим интерфейсом (Tkinter):
локальный перехватывающий прокси пишет историю запросов, из неё строятся
мутационные проверки, асинхронный движок прогоняет их и сохраняет находки
с доказательствами и отчётами.

> ⚠️ **Только для авторизованного тестирования.** Используй notscan лишь против
> приложений, которые тебе принадлежат или на тестирование которых есть письменное
> разрешение. Авторы не несут ответственности за неправомерное использование.

🇬🇧 [English README](README.md)

---

## Возможности

- **Перехват трафика** — локальный прокси на базе mitmproxy пишет метод, URL, заголовки,
  тело запроса и превью ответа в SQLite-базу проекта. Одна кнопка запускает прокси и
  преднастроенный браузер (PAC-скрипт + изолированный профиль с обходом сертификатов).
  Сам прокси не запускается: только по кнопке **▶ Start Proxy + Browser** (авто-старт —
  опция в Settings, по умолчанию выключена). Фоновый шум браузера (телеметрия Google,
  обновления компонентов, safe-browsing, connectivity-check) по умолчанию не пишется
  в History (`proxy_filter_noise` в Settings).
- **Мутационный скан** — задачи строятся по query-параметрам, form-urlencoded телам,
  JSON-телам и (опционально) заголовкам. Асинхронный движок (`asyncio` + `httpx.AsyncClient`),
  настраиваемая конкурентность, RPS-лимит, scope-guard; редиректы **не сопровождаются**
  (payload-редирект не должен превращать сканер в источник внешних запросов).
- **Каталог WSTG-чеков (43)** — единый источник (`checks/catalog.py`) для вкладки
  Checks/WSTG, бейджей конфигурации скана, WSTG-карты находок и payload-файлов:
  **17 active + 19 passive + 7 probe**. WSTG-ID сверены с OWASP WSTG v4.2 и checklist v5
  (тесты, которых нет в v4.2, помечены `(v5)`). Полная таблица —
  [`docs/CHECKS.md`](docs/CHECKS.md).
  - Active: SQLi (error-based, time-based и boolean-based blind по разнице кодов/тел
    ответов), CMDi, SSTI, LDAP/XPath/NoSQL, XXE, deserialization,
    CRLF, SSRF, SSI, path traversal, reflected XSS, HTML injection, open redirect.
  - Passive: info disclosure, устаревшие JS-библиотеки, SRI, security headers, HSTS, CSP,
    атрибуты cookie, кэширование чувствительных ответов, креды по открытому каналу,
    секреты в browser storage, CSRF-токены, JWT, clickjacking, file upload, DOM-XSS, IDOR.
  - Probe: чувствительные файлы/бэкапы, metafiles, RIA-политика, HTTP-методы/TRACE,
    админ/дебаг-интерфейсы, CORS.
- **Контроль ложных срабатываний** — правила bare-tag/Content-Type/baseline для XSS,
  reflection-aware проверки path traversal и open redirect, soft-404/WAF-фильтры для probe,
  калибровка таймингов хоста для time-based SQLi (относительный порог
  `max(задержка_payload, 3×baseline_p50 + 1 c)`).
- **Tamper / WAF-bypass** — кодировщики `url`, `unicode`, `hex`, `double-url`
  (опционально, только для серверных инъекционных чеков).
- **Stateful-скан (опционально)** — переиспользование сохранённого login-запроса,
  авто-relogin на 401/403, подстановка свежего CSRF-токена в каждую мутацию
  (`templating.patch_csrf_token` + `SessionManager.csrf_token_provider`).
- **Триаж и доказательства** — severity/confidence/exploitability, дедуп по стабильному
  fingerprint, сырые HTTP-запрос/ответ, unified diff, ручной confirm-flow
  (baseline / benign / suspicious replay), пагинация результатов.
- **Отчёты** — Markdown, JSON, HTML, SARIF, DOCX; по умолчанию выгружается полный набор
  результатов (без молчаливой обрезки).
- **Raw/XML mutation-тип** — для XML/SOAP/PHP-serialized и прочих «сырых» тел добавлена
  мутация `body_raw`, поэтому чеки **XXE** и **insecure deserialization** реально
  генерируют запросы (раньше были декларативными).
- **Multi-boundary мутации** — инъекции проверяются в **query-параметрах, form-теле,
  JSON, cookie, сегментах URL-пути, текстовых полях multipart/form-data, заголовках и
  сырых телах** (XML/SOAP/PHP-serialized). Каждую границу можно выключить в
  Scan Config → Advanced → Mutation points; `Only parameters` принимает также имена
  cookie, `path[0]`… и имена form-полей. Файловые части multipart сохраняются
  байт-в-байт (не мутируются).
- **Импорт Postman с окружением** — History → ⬆ Import понимает Postman-коллекции;
  если в коллекции есть `{{переменные}}`, notscan покажет список недостающих и предложит
  загрузить env/globals-файл (**⬆ Import environment**), подставит переменные коллекции и
  окружения в URL/headers/body и только затем импортирует. Env хранится в памяти сессии
  (значения не логируются).
- **Русский/английский интерфейс** — весь GUI (вкладки, кнопки, диалоги, tutorial,
  названия/описания чеков, статусы) доступен на **русском и английском**; переключатель —
  Settings → Language (применяется после перезапуска). Отчёты (MD/HTML/DOCX) тоже
  локализуются; технические строки лога (`[SCAN]/[PROXY]/…`) остаются на английском.
- **Простые профили скана** — окно скана открывается с выбором **Scan profile**:
  *Quick* (безопасная разведка passive+probe), *Standard* (рекомендуемые активные чеки
  + passive/probe), *Full* (все чеки, с предупреждением) или *Custom*. Стена из 43 чеков
  и advanced-опции (workers, safe mode, tamper, мутации, injection targets, ROE) спрятаны
  под «Customize checks» / «Advanced options».
- **Выбор цели инъекции** — в окне скана можно указать, какие заголовки проверяет
  host-header injection (`inject_headers`), ограничить мутации конкретными
  параметрами (`only_params`) и добавить extra-заголовки probe-чеков, например
  `Cookie: PHPSESSID=...`, для проверок под авторизацией (`probe_extra_headers`).
- **Payload-наборы** — ~3.6 тыс. payload'ов в 19 наборах с отдельными
  **WAF-bypass-вариантами** (обфускация регистром/комментариями, encoding/HTML-entity/
  unicode-трюки, IP-представления) в каждом инъекционном наборе (включая true/false
  пары для boolean-blind SQLi); Safe Mode фильтрует
  деструктивные. См. [`payloads/README.md`](payloads/README.md).
- **Проекты** — каждый запуск работает в своём каталоге проекта со своей БД, настройками
  и отчётами; переключение — **Project → Sessions / Projects…**. Смена проекта блокируется
  во время активного скана.
- **Доп. инструменты** — генератор reverse-shell команд (только генерирует, не выполняет),
  inference контрактов эндпоинтов, сравнение «анонимно vs с сессией», импорт/экспорт
  коллекций (raw HTTP, HAR, Postman).

## Установка

```bash
git clone https://github.com/Nottopbut/notscan.git
cd notscan
python -m pip install -r requirements.txt
```

Требования: Python 3.10+ (проверено на 3.13), Tkinter (`python3-tk` в Debian/Ubuntu),
mitmproxy, httpx, ttkbootstrap, python-docx. Подробности и troubleshooting —
[`docs/INSTALL.md`](docs/INSTALL.md).

## Быстрый старт

```bash
python notscan.py
```

1. Нажми **▶ Start Proxy + Browser** — прокси стартует на `127.0.0.1:8080` (если порт
   занят — автоматически выбирается следующий свободный; смотри статус-лейбл) и
   открывается изолированный Chromium с уже настроенным прокси. Сам прокси не
   запускается: авто-старт — опция в Settings (по умолчанию выключена).
2. Пройди по функционалу целевого приложения.
3. Во вкладке **History** выдели нужные запросы (двойной клик тоже добавляет),
   нажми **＋ Add to Scan list**, затем **▶ Run Scan**.
4. В окне конфигурации выбери чеки (active/passive/probe), точки мутации и ROE-опции
   (конкурентность, RPS, scope allowlist, Safe Mode, tamper) → **Start Scan**.
   **По умолчанию все чеки выключены** (`0 / 43 checks enabled`): выбери **Scan profile**
   (Quick/Standard/Full) или раскрой **Customize checks** и нажми **All ON**:
   включи нужные или нажми **All ON**; бейджи показывают состояние ☐/☑.
5. Смотри находки в **Scan Results** (severity, evidence, сырой HTTP, diff, confirm-flow)
   и экспортируй отчёт (MD / JSON / HTML / SARIF / DOCX).

Порт можно изменить в любой момент: впиши новый в поле **Port** и нажми ту же кнопку
**▶ Start Proxy + Browser** — прокси перезапустится на новом порту и откроется браузер
(если браузер уже был открыт, приложение спросит подтверждение и закроет его перед
перезапуском прокси).

Прокси останавливается сам при закрытии запущенного им браузера, по idle-таймауту
(`proxy_idle_stop_min`, по умолчанию 15 мин) и при выходе из приложения — порт всегда
освобождается. Настройки жизненного цикла хранятся в проекте:
`proxy_autostart`, `proxy_stop_on_browser_exit`, `proxy_idle_stop_min`.

## Тесты

```bash
make test     # весь pytest-набор
make lab      # интеграционные тесты на локальной HTTP-лабе (GUI-часть — под xvfb)
make smoke    # headless GUI-смоук в xvfb на временной копии проекта
```

В репозитории есть самодостаточная HTTP-лаба (`tests/lab/`) с намеренно уязвимыми
эндпоинтами (reflected XSS, escaped reflection, SQL-ошибки, редиректы, задержки,
CSRF-форма, JSON API, cookie/CORS/SSRF/SSI-кейсы, чувствительные файлы/metafiles) —
её используют 526 unit- и интеграционных тестов. Интеграционные тесты прокси
пропускаются автоматически, если mitmproxy или дисплей недоступны.

## Структура проекта

```
notscan.py            Tkinter GUI (proxy, scan, results, auth, revshell, checks/WSTG)
scanner_core.py       async-движок, построение задач, матчеры, scope guard, ROE
checks/               каталог чеков, active/passive проверки, WSTG-карта, FP-правила
templating.py         парсинг/мутации raw HTTP, JSON-экранирование, tamper, CSRF
session_manager.py    login/refresh/relogin, CSRF token provider
db.py                 SQLite per-project (WAL, per-thread соединения)
report_export.py      отчёты MD / JSON / HTML / SARIF / DOCX
mitm_proxy.py         перехватывающий прокси на mitmproxy + PAC-сервер
path_probe.py         probe-чеки (файлы, metafiles, CORS, HTTP-методы, …)
payloads/             payload-наборы (один payload в строке) + документация
tests/                unit- и интеграционные тесты + локальная HTTP-лаба
docs/                 установка, обзор функционала, таблица WSTG-чеков
```

## Документация

- [`docs/INSTALL.md`](docs/INSTALL.md) — требования, установка, troubleshooting
- [`docs/FUNCTIONAL_OVERVIEW.md`](docs/FUNCTIONAL_OVERVIEW.md) — архитектура и функционал
- [`docs/CHECKS.md`](docs/CHECKS.md) — полный каталог WSTG-чеков
- [`payloads/README.md`](payloads/README.md) — payload-наборы и как их расширять
- [`README.md`](README.md) — English README

## Известные ограничения

- Нет краулера/дискавери: цели скана — перехваченные прокси запросы (или импортированные
  из коллекции). Лёгкий краулер — в планах.
- Часть passive-чеков имеет смысл только при наличии сохранённого ответа прокси; HSTS
  проверяется только для HTTPS (юнит-тесты, не лаба).
- Probe-чеки делают реальные `OPTIONS`/`TRACE`/`PUT`/`DELETE` — включай только на целях,
  которые разрешено тестировать.
- Это учебно-практический инструмент, а не замена Burp Suite/ZAP/Nuclei. CI пока не
  настроен; запускай `make test` локально.

## Лицензия

MIT — см. [`LICENSE`](LICENSE).

Благодарности: [OWASP WSTG](https://owasp.org/www-project-web-security-testing-guide/),
[PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings),
[mitmproxy](https://mitmproxy.org/), [httpx](https://www.python-httpx.org/),
[ttkbootstrap](https://github.com/israel-dryer/ttkbootstrap).
