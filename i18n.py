"""
i18n.py — Minimal RU/EN internationalization for the notscan GUI.

The GUI sources are historically mixed EN/RU, so the catalog stores pairs
(english, russian) and translation is done **by source string**:

  • language "en": any RU source string from the catalog maps to its EN form;
  • language "ru": any EN source string maps to its RU form;
  • unknown strings fall back to the source string (nothing breaks).

Public API:
  set_language(lang), get_language(), available_languages()
  tr(text, **fmt)              — translate + optional str.format(**fmt)
  tr_en(text, **fmt), tr_ru(text, **fmt) — force a language
  translate_widget_tree(root)  — recursively translate tk/ttk widgets:
                                 text, Notebook tabs, Treeview headings
  install_messagebox_hooks()   — translate tkinter.messagebox title/message
                                 (idempotent; call once at startup)

Technical log lines ([SCAN]/[PROXY]/...) are intentionally NOT translated.
"""

from __future__ import annotations

import tkinter
import tkinter.messagebox as _tk_messagebox

DEFAULT_LANGUAGE = "en"
LANGUAGES: tuple[str, ...] = ("en", "ru")
LANGUAGE_LABELS: dict[str, str] = {"en": "English", "ru": "Русский"}

_current_language = DEFAULT_LANGUAGE

# (english, russian) pairs. Both sides must be non-empty and unique within
# their language; tests in tests/test_i18n.py enforce this.
_RAW_MESSAGES: tuple[tuple[str, str], ...] = (
    # ─────────────────────────── Tutorial / help ───────────────────────────
    ("Welcome to Notscan", "Добро пожаловать в Notscan"),
    (
        "Notscan intercepts your HTTP traffic through a proxy, then mutates requests "
        "and looks for vulnerabilities (SQLi, XSS, SSRF, XXE, JWT, etc.).\n\n"
        "Complete 7 steps and you can use it on your own.",
        "Notscan перехватывает твой HTTP-трафик через прокси, затем мутирует запросы "
        "и ищет уязвимости (SQLi, XSS, SSRF, XXE, JWT и др.).\n\n"
        "Пройди 7 шагов — и сможешь пользоваться им сам.",
    ),
    ("Step 1/7: Start the proxy and open the browser", "Шаг 1/7: Запусти прокси и открой браузер"),
    (
        "The proxy does NOT start by itself when the app launches: press the button "
        "below or «▶ Start Proxy + Browser» on the Proxy/Scan tab — the proxy starts "
        "and opens a browser; all requests go to History.\n\n"
        "The proxy stops automatically: when you close the browser, after idle time "
        "(Settings) or when the app exits.",
        "Прокси НЕ запускается сам при старте приложения: нажми кнопку ниже или "
        "«▶ Start Proxy + Browser» на вкладке Proxy/Scan — прокси поднимется и откроет "
        "браузер, все запросы попадут в History.\n\n"
        "Прокси остановится сам: когда закроешь браузер, после простоя (Settings) или "
        "при закрытии приложения.",
    ),
    (
        "Panel «Proxy» → button «▶ Start Proxy + Browser». There is no separate Stop "
        "button — everything is automatic.",
        "Панель «Proxy» → кнопка «▶ Start Proxy + Browser». Отдельной кнопки Stop нет — "
        "всё автоматически.",
    ),
    ("▶ Open browser via proxy", "▶ Открыть браузер через прокси"),
    ("Step 2/7: Browse the target site", "Шаг 2/7: Полазь по целевому сайту"),
    (
        "In the opened browser, visit the target site and click around: forms, links, "
        "buttons. All requests will appear in History automatically.",
        "В открывшемся браузере зайди на целевой сайт и покликай: формы, ссылки, кнопки. "
        "Все запросы появятся в History автоматически.",
    ),
    ("Just use the browser as usual.", "Просто пользуйся браузером как обычно."),
    ("Step 3/7: Add requests to the Scan list", "Шаг 3/7: Добавь запросы в Scan list"),
    (
        "In History select the requests of interest (Ctrl+click for several) and press "
        "«＋ Add to Scan list».",
        "В History выдели интересные запросы (Ctrl+клик для нескольких) и нажми "
        "«＋ Add to Scan list».",
    ),
    ("Panel «History» → button «＋ Add to Scan list».", "Панель «History» → кнопка «＋ Add to Scan list»."),
    ("Step 4/7: Configure the scan", "Шаг 4/7: Настрой сканирование"),
    (
        "Press «▶ Run Scan» — the scan window opens with check selection (SQLi, XSS, "
        "SSRF, JWT, etc.), mutation points and workers. Press «▶ Start Scan» inside.\n\n"
        "The «Smart mutation planner» option uses contract inference: the scanner "
        "analyses past requests (the «Contract Inference» button on the History panel) "
        "and determines parameter types (id→int, email, url, uuid, slug…) so that "
        "irrelevant payloads are not sent (e.g. open_redirect into a numeric id). "
        "To enable: History → «Contract Inference» → tick «Use contracts» + the "
        "planner checkbox.",
        "Нажми «▶ Run Scan» — откроется окно с выбором проверок (SQLi, XSS, SSRF, JWT и "
        "т.д.), mutation points и workers. Внутри нажми «▶ Start Scan».\n\n"
        "Опция «Smart mutation planner» использует contract inference: сканер анализирует "
        "прошлые запросы (кнопка «Contract Inference» на панели History) и определяет "
        "типы параметров (id→int, email, url, uuid, slug…), чтобы не слать нерелевантные "
        "пейлоады (например, open_redirect в числовой id). Для включения: History → "
        "«Contract Inference» → отметь «Use contracts» + чекбокс планировщика.",
    ),
    (
        "Panel «Scan» → «▶ Run Scan». Contract inference — on the History panel.",
        "Панель «Scan» → «▶ Run Scan». Contract inference — на панели History.",
    ),
    ("⚙ Open scan settings", "⚙ Открыть настройки скана"),
    ("Step 5/7: Review results", "Шаг 5/7: Смотри результаты"),
    (
        "Results appear on the Results tab automatically. Red rows are vulnerabilities, "
        "yellow rows are suspicious 4xx/5xx.",
        "Результаты появятся во вкладке Results автоматически. Красные строки — "
        "уязвимости, жёлтые — подозрительные 4xx/5xx.",
    ),
    ("Tab «Scan Results» (top).", "Вкладка «Scan Results» (сверху)."),
    ("Open the Results tab", "Открыть вкладку Results"),
    ("Step 6/7: Export a report", "Шаг 6/7: Экспортируй отчёт"),
    (
        "On the Results tab you can export a report to MD / JSON / DOCX with "
        "recommendations and a True/False matrix.",
        "На вкладке Results можно выгрузить отчёт в MD / JSON / DOCX с рекомендациями и "
        "матрицей True/False.",
    ),
    (
        "Buttons «Export MD/JSON/DOCX…» on the Results toolbar.",
        "Кнопки «Export MD/JSON/DOCX…» на панели Results.",
    ),
    ("Step 7/7: Projects", "Шаг 7/7: Проекты"),
    (
        "Every launch creates a separate project (its own DB and settings) in the "
        "projects/ folder. Switch projects via the Project menu.",
        "Каждый запуск создаёт отдельный проект (своя БД и настройки) в папке projects/. "
        "Менять проекты — через меню Project.",
    ),
    ("Menu «Project» at the top.", "Меню «Project» сверху."),
    ("Done!", "Готово!"),
    (
        "Now you can: intercept traffic, run a scan and read reports.\n\n"
        "⚠ For local targets (localhost/127.x/10.x) disable «Block private/metadata "
        "targets» in Settings.",
        "Теперь ты умеешь: перехватывать трафик, запускать скан и читать отчёты.\n\n"
        "⚠ Для локальных целей (localhost/127.x/10.x) отключи «Block private/metadata "
        "targets» в Settings.",
    ),
    ("Tutorial — Notscan", "Обучение — Notscan"),
    ("‹ Back", "‹ Назад"),
    ("Next ›", "Дальше ›"),
    ("Close", "Закрыть"),
    ("Tutorial", "Обучение"),

    # ─────────────────────────── Window / dialog titles ───────────────────────────
    ("Notscan — missing dependencies", "Notscan — не хватает зависимостей"),
    ("Endpoint contracts", "Контракты эндпоинтов"),
    ("Auth Boundary results", "Результаты Auth Boundary"),
    ("Sessions / Projects", "Сессии / Проекты"),
    ("Payload dictionaries", "Словари payload"),
    ("Scan configuration", "Настройка скана"),
    ("Sessions", "Сессии"),
    ("Project", "Проект"),
    ("Proxy", "Прокси"),
    ("Import", "Импорт"),
    ("Export", "Экспорт"),
    ("Confirm", "Подтвердить"),
    ("Auth Boundary", "Auth Boundary"),
    ("Auth", "Авторизация"),

    # ─────────────────────────── Main tab / proxy bar ───────────────────────────
    ("Proxy / Scan", "Прокси / Скан"),
    ("Scan Results", "Результаты скана"),
    ("Settings", "Настройки"),
    (
        "Proxy  (авто-старт · авто-стоп; отдельной кнопки Stop нет)",
        "Proxy  (auto-start · auto-stop; no separate Stop button)",
    ),
    ("Host:", "Хост:"),
    ("Port:", "Порт:"),
    ("▶ Start Proxy + Browser", "▶ Запустить прокси + браузер"),
    ("● STOPPED", "● ОСТАНОВЛЕН"),
    ("📂 Sessions", "📂 Сессии"),
    ("Contract Inference", "Вывод контрактов"),
    ("Use contracts", "Использовать контракты"),
    ("＋ Add to Scan list", "＋ В список скана"),
    ("🗑 Clear history", "🗑 Очистить историю"),
    ("🧹 Clear browser noise", "🧹 Очистить шум браузера"),
    ("⬇ Load more history", "⬇ Загрузить ещё историю"),
    ("History: 0 / 0", "История: 0 / 0"),
    ("🔍 Host/URL:", "🔍 Хост/URL:"),
    ("✕ Clear", "✕ Очистить"),
    ("⬆ Import", "⬆ Импорт"),
    ("⬇ Export", "⬇ Экспорт"),

    # ─────────────────────────── Scan list ───────────────────────────
    ("Scan list", "Список скана"),
    ("✕ Remove selected", "✕ Удалить выбранные"),
    ("✕ Clear all", "✕ Очистить всё"),
    ("Hist ID", "ID ист."),
    ("Scan", "Скан"),
    ("▶ Run Scan", "▶ Запустить скан"),
    ("⚙ Settings", "⚙ Настройки"),
    ("■ Stop Scan", "■ Остановить скан"),
    ("Log", "Лог"),

    # ─────────────────────────── Results tab ───────────────────────────
    ("Export MD…", "Экспорт MD…"),
    ("Export JSON…", "Экспорт JSON…"),
    ("Export DOCX…", "Экспорт DOCX…"),
    ("🗑 Clear all results", "🗑 Очистить результаты"),
    ("Only evidence", "Только с evidence"),
    ("Group duplicates", "Группировать дубликаты"),
    ("Method:", "Метод:"),
    ("Sev:", "Крит.:"),
    ("Check:", "Проверка:"),
    ("Host/URL:", "Хост/URL:"),
    ("Apply", "Применить"),
    ("Clear", "Очистить"),
    ("⏬ Load more", "⏬ Загрузить ещё"),
    ("Results: 0 / 0", "Результаты: 0 / 0"),
    ("● VULN", "● УЯЗВ."),
    ("● WARN 4xx/5xx", "● WARN 4xx/5xx"),
    ("● OK", "● OK"),

    # ─────────────────────────── Column headings ───────────────────────────
    ("Time", "Время"),
    ("Method", "Метод"),
    ("Sev", "Крит."),
    ("Conf", "Увер."),
    ("Expl", "Экспл."),
    ("Check", "Проверка"),
    ("Code", "Код"),
    ("Evidence", "Доказательство"),
    ("Name", "Имя"),
    ("Value", "Значение"),
    ("Samples", "Сэмплы"),
    ("Modified", "Изменён"),
    ("Open", "Открыть"),
    ("Category", "Категория"),
    ("Severity", "Критичность"),
    ("Kind", "Тип"),
    ("Description", "Описание"),
    ("URL pattern", "URL-шаблон"),
    ("Detected fields", "Найденные поля"),

    # ─────────────────────────── Settings tab ───────────────────────────
    ("Appearance", "Внешний вид"),
    ("Theme:", "Тема:"),
    ("Dark", "Тёмная"),
    ("Light", "Светлая"),
    ("Language / Язык:", "Language / Язык:"),
    ("applies after restart", "применяется после перезапуска"),
    ("Language changed — restart the application to apply it.", "Язык изменён — перезапусти приложение, чтобы применить."),
    ("Burp Browser settings", "Настройки браузера Burp"),
    ("Burp Browser binary path:", "Путь к бинарю Burp Browser:"),
    ("Browser profile dir:", "Каталог профиля браузера:"),
    ("Proxy auto-lifecycle", "Авто-жизненный цикл прокси"),
    (
        "Auto-start proxy when app launches (default OFF — start it with the «▶ Start "
        "Proxy + Browser» button)",
        "Авто-старт прокси при запуске приложения (по умолчанию ВЫКЛ — запускай кнопкой "
        "«▶ Запустить прокси + браузер»)",
    ),
    (
        "Filter browser background noise from History (Google telemetry/updates, "
        "safe-browsing, connectivity checks)",
        "Фильтровать фоновый шум браузера в History (телеметрия/обновления Google, "
        "safe-browsing, проверки связи)",
    ),
    ("Stop proxy when the launched browser is closed", "Останавливать прокси при закрытии запущенного браузера"),
    ("Idle auto-stop (minutes; 0 = off):", "Авто-стоп по простою (минуты; 0 = выкл):"),
    ("Scan scope", "Область скана"),
    (
        "Scope allowlist (comma-separated hosts/URLs; empty = no restriction):",
        "Allowlist scope (хосты/URL через запятую; пусто = без ограничений):",
    ),
    (
        "Block private/metadata targets (localhost, 127.x, 10.x, 192.168.x, 169.254.169.254)",
        "Блокировать приватные/metadata-цели (localhost, 127.x, 10.x, 192.168.x, 169.254.169.254)",
    ),
    ("ROE / rate limiting", "ROE / ограничение частоты"),
    ("Max requests/sec (0 = unlimited):", "Макс. запросов/сек (0 = без ограничений):"),
    (
        "Block check types (comma-separated; applied before task build):",
        "Блокировать типы чеков (через запятую; применяется до построения задач):",
    ),
    (
        "Stop scan on session drift (401/403, redirect to login, login-page content)",
        "Останавливать скан при дрейфе сессии (401/403, редирект на логин, контент "
        "логин-страницы)",
    ),
    ("Payload files (relative to app dir)", "Payload-файлы (относительно каталога приложения)"),
    ("👁 View payloads", "👁 Просмотр payload"),
    ("📂 Open payloads folder", "📂 Открыть папку payload"),
    ("Custom: drop <check>.txt into payloads/custom/", "Свои: положи <check>.txt в payloads/custom/"),
    ("Dictionary:", "Словарь:"),

    # ─────────────────────────── Scan configuration ───────────────────────────
    ("Scan profile", "Профиль скана"),
    ("Quick", "Быстрый"),
    ("Standard", "Стандартный"),
    ("Full", "Полный"),
    ("Custom", "Свой"),
    (
        "Quick: safe reconnaissance — all passive + probe checks, no active payload checks.",
        "Быстрый: безопасная разведка — все passive + probe чеки, без активных payload-чеков.",
    ),
    (
        "Standard: recommended active checks (SQLi, XSS, CMDi, SSRF, path traversal, "
        "open redirect, CRLF) + all passive/probe checks.",
        "Стандартный: рекомендованные активные чеки (SQLi, XSS, CMDi, SSRF, path traversal, "
        "open redirect, CRLF) + все passive/probe чеки.",
    ),
    (
        "Full: all checks enabled — noisy and slow; use only on authorized targets.",
        "Полный: включены все чеки — шумно и медленно; только для авторизованных целей.",
    ),
    (
        "Custom: keep the current check selection (nothing is changed).",
        "Свой: оставить текущий выбор чеков (ничего не меняется).",
    ),
    ("Customize checks", "Настроить чеки вручную"),
    ("Advanced options", "Расширенные настройки"),
    ("Server-side checks", "Серверные проверки"),
    ("Client-side checks", "Клиентские проверки"),
    ("Other", "Прочее"),
    ("Quick select:", "Быстрый выбор:"),
    ("All ON", "Все вкл"),
    ("All OFF", "Все выкл"),
    ("Server only", "Только серверные"),
    ("Client only", "Только клиентские"),
    ("Mutation points", "Точки мутации"),
    ("Query params", "Query-параметры"),
    ("Body form", "Тело формы"),
    ("Body JSON", "Тело JSON"),
    ("Headers", "Заголовки"),
    ("Injection targets (advanced)", "Цели инъекций (расширенно)"),
    (
        "Injection headers (comma-separated; empty = default):",
        "Заголовки для инъекций (через запятую; пусто = по умолчанию):",
    ),
    (
        "Only parameters (comma-separated; empty = all):",
        "Только параметры (через запятую; пусто = все):",
    ),
    (
        "Extra probe headers (for probes; e.g. Cookie: PHPSESSID=...; one per line):",
        "Доп. заголовки для probe (напр. Cookie: PHPSESSID=...; по одному в строке):",
    ),
    (
        "  default: {headers}  ·  used by host-header-injection probe",
        "  default: {headers}  ·  используется host-header-injection probe",
    ),
    (
        "  e.g. id, q, username — other parameters are not mutated (empty = all)",
        "  напр. id, q, username — остальные параметры не мутируются (пусто = все)",
    ),
    (
        "  sent only to probe checks (sensitive files/metafiles/host-header/CORS/…), not to mutations",
        "  отправляется только probe-чекам (sensitive files/metafiles/host-header/CORS/…), не в мутации",
    ),
    ("Workers:", "Потоки:"),
    (
        "Safe mode (exclude destructive payloads: DROP/INSERT/UPDATE/exec)",
        "Безопасный режим (исключить деструктивные payload: DROP/INSERT/UPDATE/exec)",
    ),
    (
        "Tamper/WAF-bypass (payload encoders: url / unicode / hex / double-url)",
        "Tamper/WAF-bypass (кодирование payload: url / unicode / hex / double-url)",
    ),
    (
        "Smart mutation planner (reduce noise / skip inapplicable combos)",
        "Умный планировщик мутаций (меньше шума / пропуск неприменимых комбинаций)",
    ),
    ("▶ Start Scan", "▶ Начать скан"),
    ("Cancel", "Отмена"),
    (
        "Full scan: all checks are enabled — this can be slow and noisy. Continue?",
        "Полный скан: включены все чеки — это может быть медленно и шумно. Продолжить?",
    ),
    ("Full scan", "Полный скан"),

    # ─────────────────────────── Detail window ───────────────────────────
    ("Result not found", "Результат не найден"),
    ("Summary", "Сводка"),
    ("Confirm (baseline/benign/suspicious)…", "Подтвердить (baseline/benign/suspicious)…"),
    ("Refresh confirmations", "Обновить подтверждения"),
    ("Baseline request", "Baseline-запрос"),
    ("Mutated request", "Мутированный запрос"),
    ("Response preview", "Превью ответа"),
    ("Confirmations", "Подтверждения"),
    ("No mutated raw request saved for this result.", "Для этого результата не сохранён мутированный raw-запрос."),
    ("Confirm error", "Ошибка подтверждения"),
    ("Confirm completed. Verdict:", "Подтверждение завершено. Вердикт:"),
    ("📋 Copy request", "📋 Копировать запрос"),
    ("📋 Copy response", "📋 Копировать ответ"),
    ("✕ Close", "✕ Закрыть"),
    ("Payload Request", "Запрос с payload"),
    ("Finding", "Находка"),
    ("Request", "Запрос"),
    ("Response", "Ответ"),

    # ─────────────────────────── Contracts / auth boundary ───────────────────────────
    ("Use inferred contracts in planner", "Использовать выведенные контракты в планировщике"),
    ("↻ Refresh", "↻ Обновить"),
    ("Export findings (JSON)", "Экспорт находок (JSON)"),
    ("No accessible_anon=1 findings to export.", "Нет находок accessible_anon=1 для экспорта."),

    # ─────────────────────────── Auth tab ───────────────────────────
    ("Login Requests", "Запросы логина"),
    ("↻ Refresh from History", "↻ Обновить из History"),
    ("Unauth codes:", "Коды неавторизации:"),
    ("Max re-logins:", "Макс. перелогинов:"),
    (
        "Captured Login Requests  (auto-detected from Proxy History)",
        "Перехваченные запросы логина  (автоопределение из истории прокси)",
    ),
    ("Request body:", "Тело запроса:"),
    ("▶ Use as Login Template", "▶ Использовать как шаблон логина"),
    ("✕ Clear session", "✕ Очистить сессию"),
    ("Live Session State", "Состояние сессии"),
    ("● INACTIVE", "● НЕАКТИВНА"),
    ("Active login template:", "Активный шаблон логина:"),
    ("Cookies / Token:", "Cookies / токен:"),
    ("Auth log:", "Лог авторизации:"),
    ("● NOT AUTHENTICATED", "● НЕ АУТЕНТИФИЦИРОВАН"),
    ("● EXPIRED", "● ИСТЕКЛА"),
    ("● ACTIVE (token)", "● АКТИВНА (токен)"),
    ("● ACTIVE (cookies)", "● АКТИВНА (cookies)"),
    ("Select a login request from the list first", "Сначала выбери запрос логина из списка"),

    # ─────────────────────────── RevShell / checks tab ───────────────────────────
    ("Reverse Shell Generator", "Генератор reverse shell"),
    ("⚠ Commands are generated ONLY — not executed locally.", "⚠ Команды только ГЕНЕРИРУЮТСЯ — не выполняются локально."),
    ("OS target:", "Целевая ОС:"),
    ("⚡ Generate suggestions", "⚡ Сгенерировать варианты"),
    ("🔍 Show full command", "🔍 Показать полную команду"),
    ("Checks / WSTG", "Проверки / WSTG"),
    ("↻ Reload", "↻ Обновить"),
    ("Toggle ON/OFF", "Переключить ВКЛ/ВЫКЛ"),
    ("✓ All ON", "✓ Все вкл"),
    ("✗ All OFF", "✗ Все выкл"),
    ("Category:", "Категория:"),

    # ─────────────────────────── Sessions picker ───────────────────────────
    ("Сессии (проекты):", "Sessions (projects):"),
    ("🆕 New project", "🆕 Новый проект"),
    ("History", "История"),
    ("Results", "Результаты"),

    # ─────────────────────────── Dialogs / confirmations ───────────────────────────
    ("Error", "Ошибка"),
    ("Not found", "Не найдено"),
    ("Invalid proxy port", "Некорректный порт прокси"),
    ("Invalid proxy port (1-65535)", "Некорректный порт прокси (1-65535)"),
    ("Некорректный host/port прокси", "Invalid proxy host/port"),
    ("Browser not found", "Браузер не найден"),
    ("Browser launch error", "Ошибка запуска браузера"),
    ("Clear browser noise", "Очистка шума браузера"),
    (
        "Фоновые запросы браузера не найдены",
        "No browser background requests found",
    ),
    ("Clear history", "Очистка истории"),
    ("Удалить всю историю запросов?", "Delete all request history?"),
    ("Clear scan results", "Очистка результатов скана"),
    (
        "Удалить ВСЕ результаты сканирования?\n\nЭто действие необратимо — scan_results, "
        "scan_requests,\nscan_meta, confirmations и evidence snippets будут удалены.",
        "Delete ALL scan results?\n\nThis cannot be undone — scan_results, scan_requests, "
        "scan_meta, confirmations and evidence snippets will be removed.",
    ),
    ("Delete result", "Удалить результат"),
    ("Contract inference error", "Ошибка вывода контрактов"),
    (
        "Select History rows (or add requests to Scan list) first",
        "Сначала выбери строки History (или добавь запросы в список скана)",
    ),
    (
        "No active session headers detected (Auth tab disabled / not logged in).\n"
        "Run boundary scan anyway (anonymous vs anonymous)?",
        "Активные заголовки сессии не найдены (Auth tab выключен / нет логина).\n"
        "Запустить boundary-скан всё равно (анонимно vs анонимно)?",
    ),
    ("Auth Boundary error", "Ошибка Auth Boundary"),
    ("No requests found in the file", "В файле не найдено запросов"),
    ("Select requests in History first", "Сначала выбери запросы в History"),
    ("No valid requests selected", "Не выбрано валидных запросов"),
    ("Select rows in History first", "Сначала выбери строки в History"),
    (
        "Scan list is empty — добавь запросы из History",
        "Scan list is empty — add requests from History",
    ),
    (
        "Scan list is empty — add requests from History first",
        "Список скана пуст — сначала добавь запросы из History",
    ),
    (
        "Не выбрано ни одной проверки — включи хотя бы один чек (☐ → ☑) в окне скана",
        "No checks selected — enable at least one check (☐ → ☑) in the scan window",
    ),
    ("Active mode", "Активный режим"),
    (
        "Active mode may send destructive payloads (DROP, INSERT, UPDATE, exec, etc.). "
        "Use only on authorized targets. Continue?",
        "Активный режим может отправлять деструктивные payload (DROP, INSERT, UPDATE, "
        "exec и т.п.). Используй только на авторизованных целях. Продолжить?",
    ),
    (
        "Сканирование выполняется — дождись завершения или останови скан (Stop) перед "
        "сменой проекта.",
        "A scan is running — wait until it finishes or stop it before switching projects.",
    ),
    ("Export error", "Ошибка экспорта"),
    ("Stopping…", "Останавливаем…"),
    ("Done", "Готово"),
    ("No free port", "нет свободного порта"),
    ("start failed", "ошибка запуска"),
    ("restart failed", "ошибка перезапуска"),
    ("browser closed", "браузер закрыт"),

    # ─────────────────────────── Dynamic templates (format via kwargs) ───────────────────────────
    ("History: {shown} / {total}", "История: {shown} / {total}"),
    ("Results: {shown} / {total}", "Результаты: {shown} / {total}"),
    (
        "Checks: {on}/{total}  ·  Workers: {workers}  ·  Safe: {safe}  ·  Tamper: {tamper}",
        "Чеки: {on}/{total}  ·  Потоки: {workers}  ·  Безопасный: {safe}  ·  Tamper: {tamper}",
    ),
    ("ON", "ВКЛ"),
    ("OFF", "ВЫКЛ"),
    ("{enabled} / {total} checks enabled", "{enabled} / {total} чеков включено"),
    (
        "{enabled} / {total} checks enabled (catalog: {catalog})",
        "{enabled} / {total} чеков включено (каталог: {catalog})",
    ),
    ("● RUNNING :{port}", "● РАБОТАЕТ :{port}"),
    ("● RESTARTING → :{port}", "● ПЕРЕЗАПУСК → :{port}"),
    ("● STOPPED ({reason}){suffix}", "● ОСТАНОВЛЕН ({reason}){suffix}"),
    ("● STOPPED (browser closed)", "● ОСТАНОВЛЕН (браузер закрыт)"),
    ("● STOPPED (no free port)", "● ОСТАНОВЛЕН (нет свободного порта)"),
    ("● STOPPED (start failed)", "● ОСТАНОВЛЕН (ошибка запуска)"),
    ("● STOPPED (restart failed)", "● ОСТАНОВЛЕН (ошибка перезапуска)"),
    ("  ● INACTIVE  ", "  ● НЕАКТИВНА  "),
    ("  ● NOT AUTHENTICATED  ", "  ● НЕ АУТЕНТИФИЦИРОВАН  "),
    ("  ● EXPIRED  ", "  ● ИСТЕКЛА  "),
    ("  ● ACTIVE (token)  ", "  ● АКТИВНА (токен)  "),
    ("  ● ACTIVE (cookies)  ", "  ● АКТИВНА (cookies)  "),
    ("Re-logins: 0", "Перелогинов: 0"),
    ("Re-logins: {count}", "Перелогинов: {count}"),
    ("{done}/{total} tasks", "{done}/{total} задач"),
    ("History: {shown} / {total} requests", "История: {shown} / {total} запросов"),
    # ─────────────────────────── App welcome / menus / misc ───────────────────────────
    (
        "Добро пожаловать! Как пользоваться:\n"
        "  1) Прокси не запускается сам — нажми «▶ Start Proxy + Browser» (статус в панели Proxy)\n"
        "  2) «▶ Start Proxy + Browser» — открыть браузер через прокси\n"
        "  3) В History выдели запросы → «＋ Add to Scan list»\n"
        "  4) «▶ Run Scan» — результаты во вкладке Results\n"
        "  ⚠ Прокси останавливается автоматически: браузер закрыт,\n"
        "    простой (Settings) или закрытие приложения.\n"
        "  ⚠ Для локальных целей (localhost/127.x/10.x/192.168.x)\n"
        "    отключи «Block private/metadata targets» в Settings.",
        "Welcome! How to use:\n"
        "  1) The proxy does not start by itself — press «▶ Start Proxy + Browser» (status in the Proxy panel)\n"
        "  2) «▶ Start Proxy + Browser» — open a browser through the proxy\n"
        "  3) In History select requests → «＋ Add to Scan list»\n"
        "  4) «▶ Run Scan» — results on the Results tab\n"
        "  ⚠ The proxy stops automatically: browser closed,\n"
        "    idle (Settings) or app exit.\n"
        "  ⚠ For local targets (localhost/127.x/10.x/192.168.x)\n"
        "    disable «Block private/metadata targets» in Settings.",
    ),
    ("Step {n} of {total}", "Шаг {n} из {total}"),
    ("▶ Run", "▶ Выполнить"),
    (" — port :{port} free", " — порт :{port} свободен"),
    ("idle {minutes} min", "простой {minutes} мин"),
    ("Sessions / Projects...", "Сессии / Проекты..."),
    ("New Project", "Новый проект"),
    ("Open Project...", "Открыть проект..."),
    ("Open Project Folder", "Открыть папку проекта"),
    ("Help", "Справка"),
    (
        "Найдены фоновые запросы браузера (Google/обновления и т.п.). Удалить их из History?",
        "Browser background requests found (Google/updates, etc.). Delete them from History?",
    ),
    (
        "Удаление идёт пачками и продолжается, пока находится шум — так очищаются и "
        "записи старше последних 10000. Удалить их из History?",
        "Deletion goes in batches and continues while noise is found — this also clears "
        "records older than the last 10000. Delete them from History?",
    ),
    # ─────────────────────────── Check catalog names / categories ───────────────────────────
    ("Sensitive Information Disclosure", "Раскрытие чувствительной информации"),
    ("Outdated/Vulnerable JS Libraries", "Устаревшие/уязвимые JS-библиотеки"),
    ("Third-party Scripts Without SRI", "Сторонние скрипты без SRI"),
    ("Webserver Metafiles Disclosure", "Раскрытие метафайлов веб-сервера"),
    ("Web Server / Framework Fingerprint", "Фингерпринт веб-сервера/фреймворка"),
    ("Verbose Error Handling / Stack Traces", "Подробные ошибки / stack traces"),
    ("Missing Security Headers", "Отсутствуют security-заголовки"),
    ("Clickjacking — Missing X-Frame-Options / CSP", "Clickjacking — нет X-Frame-Options / CSP"),
    ("Missing / Weak HSTS", "Отсутствует/слабый HSTS"),
    ("Content Security Policy", "Content Security Policy (CSP)"),
    ("RIA Cross-Domain Policy", "Cross-domain политика RIA"),
    ("HTTP Methods / TRACE", "HTTP-методы / TRACE"),
    ("Sensitive Files / Backups Exposure", "Доступ к чувствительным файлам/бэкапам"),
    ("Admin / Debug Interface Exposure", "Доступ к admin/debug-интерфейсам"),
    ("SQL Injection (Error-Based)", "SQL-инъекция (error-based)"),
    ("SQL Injection (Time-Based Blind)", "SQL-инъекция (time-based blind)"),
    ("SQL Injection (Boolean-Based Blind)", "SQL-инъекция (boolean-based blind)"),
    ("Command Injection (CMDi)", "Инъекция команд (CMDi)"),
    ("Server-Side Template Injection (SSTI)", "Инъекция в серверные шаблоны (SSTI)"),
    ("LDAP Injection", "LDAP-инъекция"),
    ("XPath/XML Injection", "XPath/XML-инъекция"),
    ("NoSQL Injection", "NoSQL-инъекция"),
    ("XML External Entity (XXE)", "XML External Entity (XXE)"),
    ("Insecure Deserialization", "Небезопасная десериализация"),
    ("Header Injection / CRLF Injection", "Инъекция заголовков / CRLF"),
    ("Server-Side Request Forgery (SSRF)", "SSRF (подделка серверных запросов)"),
    ("Server-Side Includes (SSI) Injection", "Инъекция Server-Side Includes (SSI)"),
    ("Host Header Injection", "Инъекция Host-заголовка"),
    ("Path Traversal / LFI / RFI", "Path Traversal / LFI / RFI"),
    ("Dangerous File Upload", "Опасная загрузка файлов"),
    ("XSS — Reflected", "XSS — отражённый"),
    ("XSS — DOM-Based (Heuristic)", "XSS — DOM-based (эвристика)"),
    ("Open Redirect", "Open Redirect"),
    ("HTML Injection", "HTML-инъекция"),
    ("Browser Storage of Secrets", "Секреты в Browser Storage"),
    ("Cross-Origin Resource Sharing (CORS)", "Cross-Origin Resource Sharing (CORS)"),
    ("CSRF — Missing Anti-CSRF Token", "CSRF — нет анти-CSRF токена"),
    ("JWT Signature Verification", "Проверка подписи JWT"),
    ("Cookie Attributes (Secure/HttpOnly/SameSite)", "Атрибуты cookie (Secure/HttpOnly/SameSite)"),
    ("Session Token in URL", "Токен сессии в URL"),
    ("Sensitive Response Cacheable", "Кэшируемые чувствительные ответы"),
    ("Credentials over Cleartext Channel", "Учётные данные по открытому каналу"),
    ("IDOR — Insecure Direct Object Reference", "IDOR — небезопасная прямая ссылка на объект"),
    # Короткие подписи бейджей (BADGE_LABELS в notscan.py)
    ("Deserial", "Десериал."),
    ("CRLF/Header", "CRLF/Заголовки"),
    ("File Upload", "Загрузка файлов"),
    ("XSS Reflected", "Отражённый XSS"),
    ("XSS DOM", "DOM XSS"),
    ("Sec Headers", "Security-заголовки"),
    ("Info Leak", "Утечка инфо"),
    ("Outdated Libs", "Устаревшие либы"),
    ("3rd-party JS", "Сторонний JS"),
    ("JWT Signature", "Подпись JWT"),
    ("Info Disclosure (paths)", "Info Disclosure (пути)"),
    # Категории / секции / колонки WSTG
    ("Information", "Информация"),
    ("Config", "Конфигурация"),
    ("Injection", "Инъекции"),
    ("File", "Файлы"),
    ("Client", "Клиент"),
    ("Session", "Сессия"),
    ("AuthN", "Аутентификация"),
    ("AuthZ", "Авторизация"),
    ("Server-side active checks", "Серверные активные проверки"),
    ("Client-side active checks", "Клиентские активные проверки"),
    ("Passive checks (analyze captured responses)", "Passive-проверки (анализ сохранённых ответов)"),
    ("Probe checks (extra paths/requests)", "Probe-проверки (доп. пути/запросы)"),
    ("Check details", "Детали проверки"),
    ("active", "активный"),
    ("passive", "пассивный"),
    ("probe", "probe"),
    ("Server-side checks", "Серверные проверки"),
    ("Client-side checks", "Клиентские проверки"),
    ("Other", "Прочее"),
    # ─────────────────────────── Badges (short) / RevShell / misc ───────────────────────────
    ("Metafiles", "Метафайлы"),
    ("Fingerprint", "Фингерпринт"),
    ("Verbose Errors", "Подробные ошибки"),
    ("RIA Policy", "RIA-политика"),
    ("HTTP Methods", "HTTP-методы"),
    ("Sensitive Files", "Файлы/бэкапы"),
    ("SQLi Blind", "SQLi Blind"),
    ("Browser Storage", "Browser Storage"),
    ("Cookie Attrs", "Cookie-атрибуты"),
    ("Token in URL", "Токен в URL"),
    ("Response Cache", "Кэш ответа"),
    ("Cleartext Login", "Логин без TLS"),
    ("Admin Debug", "Admin/debug"),
    ("Deserialization", "Десериализация"),
    ("OS", "ОС"),
    ("Requires", "Требуется"),
    ("Command (truncated)", "Команда (усечено)"),
    ("Proxy / Scan", "Прокси / Скан"),
    ("Scan Results", "Результаты скана"),
    ("Proxy", "Прокси"),
    ("Vuln type (hint):", "Тип уязвимости (подсказка):"),
    ("payloads", "payload'ов"),
    ("Browser Storage", "Хранилище браузера"),
    ("Notscan Scan Report", "Отчёт сканирования Notscan"),
    ("Recommendations", "Рекомендации"),
    ("Detection Matrix (True/False)", "Матрица детекции (True/False)"),
    ("Detection Matrix", "Матрица детекции"),
    ("Findings", "Находки"),
    ("Generated", "Сформирован"),
    ("Total results", "Всего результатов"),
    ("Unique findings", "Уникальных находок"),
    ("raw", "сырых"),
    ("Count", "Количество"),
    ("Recommendation", "Рекомендация"),
    ("Detected", "Обнаружено"),
    ("Max Severity", "Макс. критичность"),
    ("True", "Да"),
    ("False", "Нет"),
    ("No findings", "Находок нет"),
)

import re as _re

_CYRILLIC_RE = _re.compile(r"[А-Яа-яЁё]")



def _has_cyrillic(text: str) -> bool:
    return bool(_CYRILLIC_RE.search(text or ""))


def _normalize_source_pairs(pairs) -> tuple[tuple[str, str], ...]:
    """Нормализует пары (en, ru): направление, trim, без identity/дублей.

    Исходники GUI смешаны, поэтому часть пар записана как (ru_source, en_target) —
    здесь они разворачиваются; пары с отступами/identity отбрасываются (для
    краевых пробелов есть _tr_preserve_padding).
    """
    result: list[tuple[str, str]] = []
    seen_en: set[str] = set()
    for first, second in pairs:
        en, ru = str(first), str(second)
        if not en.strip() or not ru.strip():
            continue
        if en != en.strip() or ru != ru.strip():
            continue  # padded-пары не нужны (_tr_preserve_padding)
        if en == ru:
            continue  # identity-пары не нужны
        if _has_cyrillic(en) and not _has_cyrillic(ru):
            en, ru = ru, en  # развернуть (ru_source, en_target)
        if en in seen_en:
            continue
        seen_en.add(en)
        result.append((en, ru))
    return tuple(result)


MESSAGES: tuple[tuple[str, str], ...] = _normalize_source_pairs(_RAW_MESSAGES)


def _build_indexes() -> tuple[dict[str, str], dict[str, str]]:
    """Return (map_ru_from_en, map_en_from_ru). First pair wins on collisions."""
    ru_from_en: dict[str, str] = {}
    en_from_ru: dict[str, str] = {}
    for en, ru in MESSAGES:
        ru_from_en.setdefault(en, ru)
        en_from_ru.setdefault(ru, en)
    return ru_from_en, en_from_ru


_RU_FROM_EN, _EN_FROM_RU = _build_indexes()


def available_languages() -> tuple[str, ...]:
    """Supported UI languages."""
    return LANGUAGES


def language_label(lang: str | None = None) -> str:
    """Human label for a language code ("en" -> "English")."""
    return LANGUAGE_LABELS.get(lang or get_language(), lang or "")


def normalize_language(value) -> str:
    """Map arbitrary settings value to a supported language (default en)."""
    raw = str(value or "").strip().lower()
    if raw in LANGUAGES:
        return raw
    if raw in ("eng", "english", "en-us", "en_us"):
        return "en"
    if raw in ("rus", "russian", "ru-ru", "ru_ru"):
        return "ru"
    return DEFAULT_LANGUAGE


def set_language(lang: str) -> str:
    """Set current UI language; returns the applied language."""
    global _current_language
    _current_language = normalize_language(lang)
    return _current_language


def get_language() -> str:
    """Current UI language code."""
    return _current_language


def _translate(lang: str, text, **fmt) -> str:
    """Translate a single string to `lang` (fallback = source string)."""
    if text is None:
        return ""
    source = str(text)
    if lang == "ru":
        result = _RU_FROM_EN.get(source, source)
    else:
        result = _EN_FROM_RU.get(source, source)
    if fmt:
        try:
            result = result.format(**fmt)
        except (KeyError, IndexError, ValueError):
            pass
    return result


def tr(text, **fmt) -> str:
    """Translate `text` to the current language (with optional str.format kwargs)."""
    return _translate(_current_language, text, **fmt)


def tr_en(text, **fmt) -> str:
    """Force English translation."""
    return _translate("en", text, **fmt)


def tr_ru(text, **fmt) -> str:
    """Force Russian translation."""
    return _translate("ru", text, **fmt)


def catalog(lang: str) -> dict[str, str]:
    """Canonical-key translation catalog for a language (for tests/debug)."""
    if normalize_language(lang) == "ru":
        return {en: ru for en, ru in MESSAGES}
    return {en: en for en, _ru in MESSAGES}


# ─────────────────────────── Widget tree translation ───────────────────────────

def _translate_heading(widget, col: str) -> None:
    try:
        current = widget.heading(col).get("text", "")
    except Exception:
        return
    if not current:
        return
    new = tr(current)
    if new != current:
        try:
            widget.heading(col, text=new)
        except Exception:
            pass


def _tr_preserve_padding(text) -> str:
    """Перевести строку, сохранив ведущие/хвостовые пробелы (Notebook tabs, status)."""
    if not text:
        return text
    core = str(text).strip()
    if not core:
        return text
    translated = tr(core)
    if translated == core:
        return text
    lead = str(text)[: len(str(text)) - len(str(text).lstrip())]
    trail = str(text)[len(str(text).rstrip()):]
    return f"{lead}{translated}{trail}"


def translate_widget_tree(root, lang: str | None = None) -> None:
    """Recursively translate visible static texts of a Tk widget tree.

    Handles: tk/ttk widgets with a `text` option, ttk.Notebook tab labels,
    ttk.Treeview column headings, window titles. Dynamic texts (already
    formatted by tr() in code) are left as-is if unknown to the catalog.
    """
    previous = get_language()
    if lang is not None:
        set_language(lang)
    try:
        _translate_tree(root)
    finally:
        if lang is not None:
            set_language(previous)


def _translate_tree(widget) -> None:
    # window title (Tk / Toplevel only)
    if isinstance(widget, (tkinter.Tk, tkinter.Toplevel)):
        try:
            title = widget.title()
            new_title = tr(title)
            if new_title != title:
                widget.title(new_title)
        except Exception:
            pass

    # generic `text` option (Label/Button/Checkbutton/LabelFrame/...)
    try:
        keys = widget.keys()
    except Exception:
        keys = ()
    if "text" in keys:
        try:
            current = widget.cget("text")
            new = _tr_preserve_padding(current)
            if new != current:
                widget.configure(text=new)
        except Exception:
            pass

    try:
        import tkinter.ttk as _ttk
    except Exception:  # pragma: no cover
        _ttk = None

    if isinstance(widget, tkinter.Menu):
        try:
            last = widget.index("end")
        except Exception:
            last = None
        if last is not None:
            for i in range(int(last) + 1):
                try:
                    label = widget.entrycget(i, "label")
                except Exception:
                    label = ""
                if label:
                    new_label = tr(label)
                    if new_label != label:
                        try:
                            widget.entryconfigure(i, label=new_label)
                        except Exception:
                            pass
                try:
                    submenu = widget.entrycget(i, "menu")
                except Exception:
                    submenu = None
                if submenu:
                    try:
                        _translate_tree(widget.nametowidget(submenu))
                    except Exception:
                        pass

    if _ttk is not None and isinstance(widget, _ttk.Notebook):
        for tab_id in widget.tabs():
            try:
                label = widget.tab(tab_id, "text")
                new_label = _tr_preserve_padding(label)
                if new_label != label:
                    widget.tab(tab_id, text=new_label)
            except Exception:
                pass

    if _ttk is not None and isinstance(widget, _ttk.Treeview):
        try:
            columns = list(widget["columns"])
        except Exception:
            columns = []
        for col in columns:
            _translate_heading(widget, col)

    try:
        children = widget.winfo_children()
    except Exception:
        children = []
    for child in children:
        _translate_tree(child)


# ─────────────────────────── messagebox hooks ───────────────────────────

_HOOK_MARKER = "_notscan_i18n_hooked"
_MESSAGEBOX_FUNCS = (
    "showinfo",
    "showwarning",
    "showerror",
    "askyesno",
    "askokcancel",
    "askretrycancel",
    "askquestion",
)


def install_messagebox_hooks(mb_module=None) -> None:
    """Wrap tkinter.messagebox functions to translate title/message.

    Idempotent: already hooked functions are skipped. Tests may pass a fake
    module object with the same function names.
    """
    module = mb_module or _tk_messagebox
    for name in _MESSAGEBOX_FUNCS:
        original = getattr(module, name, None)
        if not callable(original) or getattr(original, _HOOK_MARKER, False):
            continue

        def _make_hook(func):
            def _hook(title=None, message=None, *args, **kwargs):
                return func(tr(title), tr(message), *args, **kwargs)

            setattr(_hook, _HOOK_MARKER, True)
            setattr(_hook, "__wrapped__", func)
            return _hook

        setattr(module, name, _make_hook(original))
