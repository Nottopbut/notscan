# Установка и запуск

## Требования

- Python **3.10+** (проект разрабатывается и тестируется на 3.13)
- Linux / macOS / Windows 10/11
- Tkinter (Debian/Ubuntu: `sudo apt install python3-tk`; Windows/macOS — обычно в комплекте с Python)
- Для GUI-смоука и headless-тестов под Linux: `xvfb` (`sudo apt install xvfb`)

## Установка зависимостей

Из корня репозитория:

```bash
python -m pip install -r requirements.txt
```

`requirements.txt` фиксирует проверенные версии: `mitmproxy==12.2.3`, `httpx==0.28.1`,
`ttkbootstrap==2.2.3`, `python-docx==1.2.0`.

## Запуск

```bash
python notscan.py
```

При старте создаётся **отдельный проект** в `projects/<project_YYYYMMDD_HHMMSS>/` со своей
БД `history.db`, файлом настроек и папкой `reports/`. Прошлые проекты открываются через
**Project → Sessions / Projects…** (там же создание нового проекта).

## Прокси и браузер

- Прокси **не запускается сам**: старт — только по кнопке **▶ Start Proxy + Browser**
  (порт по умолчанию `127.0.0.1:8080`; если занят — автоматически выбирается следующий
  свободный, порт и статус видны в верхней панели). В Settings есть необязательный
  авто-старт (`proxy_autostart`, по умолчанию **выключен**).
- Кнопка **▶ Start Proxy + Browser** запускает изолированный Chromium/Burp Browser
  с уже настроенным прокси и PAC-скриптом. Профиль браузера отдельный, флаги
  `--ignore-certificate-errors` включены — ручная установка CA-сертификата для
  этого профиля не требуется.
- Уже накопившийся шум можно удалить кнопкой **🧹 Clear browser noise** в панели
  History (удаляет только известные фоновые домены, остальные записи не трогает).
- **Фильтр фонового шума:** телеметрия Google/Chromium, обновления компонентов,
  safe-browsing и connectivity-check по умолчанию **не попадают в History**
  (`proxy_filter_noise` в Settings; отфильтрованные запросы только считаются в логе).
- Прокси останавливается сам:
  - когда закрывается запущенный им браузер (`proxy_stop_on_browser_exit`);
  - по idle-таймауту (`proxy_idle_stop_min`, по умолчанию 15 минут; `0` — выключить);
  - при выходе из приложения (включая SIGINT/SIGTERM) — порт всегда освобождается.
- Порт можно изменить в любой момент: впиши новый в поле **Port** и нажми
  **▶ Start Proxy + Browser** — если прокси уже запущен, он перезапустится на новом
  порту и откроется браузер (если браузер был открыт — приложение спросит подтверждение
  и закроет его, чтобы перезапустить прокси на новом порту).
- Кнопки «Stop Proxy» нет по дизайну: жизненный цикл автоматический. Настройки хранятся
  в `settings.json` проекта (`proxy_autostart`, `proxy_stop_on_browser_exit`,
  `proxy_idle_stop_min`).

Если нужен собственный браузер: укажи в нём HTTP-прокси `127.0.0.1:<port>` и разреши
его CA-сертификат (mitmproxy), либо используй запуск браузера из приложения.

## Типовой сценарий работы

1. Запустить приложение → **▶ Start Proxy + Browser** (по умолчанию прокси НЕ
   стартует сам; авто-старт включается в Settings).
2. Пройти по функционалу целевого приложения через браузер — запросы появятся в **History**.
3. Выделить нужные запросы (двойной клик добавляет в scan-list) → **＋ Add to Scan list**
   → **▶ Run Scan**.
4. В окне конфигурации: чеки (active/passive/probe), точки мутации (query/form/json/headers),
   Safe Mode, tamper, Smart planner, ROE (конкурентность, RPS, scope allowlist,
   block private/metadata) → **Start Scan**. **Все чеки по умолчанию выключены**
   (`0 / 39 checks enabled`): включи нужные или нажми **All ON**; бейджи показывают ☐/☑.
5. Результаты — во вкладке **Scan Results** (severity/confidence, evidence, raw HTTP, diff,
   confirm-flow, пагинация). Экспорт: **Export MD / JSON / HTML / SARIF / DOCX**
   (выгружается полный набор результатов).

## Тесты и headless-проверки

```bash
make test     # весь pytest-набор
make lab      # интеграционные тесты на локальной HTTP-лабе (GUI-часть — под xvfb)
make smoke    # GUI-смоук в xvfb на временной копии проекта
```

Ручной GUI-смоук (обязательно на **копии** проекта — App() создаёт `projects/`):

```bash
tmp=$(mktemp -d) && rsync -a --exclude=.git --exclude=projects --exclude='*.db' ./ "$tmp/" \
  && (cd "$tmp" && xvfb-run -a python -c "import notscan; a=notscan.App(); a.update(); a.destroy(); print('SMOKE_OK')")
```

Интеграционные тесты прокси/браузера автоматически пропускаются, если mitmproxy или
дисплей недоступны.

## Troubleshooting

| Проблема | Решение |
|---|---|
| `ModuleNotFoundError: tkinter` | `sudo apt install python3-tk` (Debian/Ubuntu) |
| Порт прокси занят | Это не блокирует запуск: приложение само возьмёт следующий свободный порт. Старый процесс можно найти: `ss -ltnp \| grep <port>` |
| Браузер не найден | Укажи путь к Chromium/Burp Browser во вкладке **Settings** |
| TLS-ошибки в своём браузере | Установи CA-сертификат mitmproxy или используй кнопку запуска браузера из приложения |
| GUI-тесты падают без дисплея | Запускай через `xvfb-run -a …` или `make lab` |
| Отчёты DOCX не создаются | `pip install python-docx` (уже в requirements) |

## Опционально

- **OWASP ZAP**: импорт alerts через вкладку Settings (пакет `python-owasp-zap-v2.4`).
- **Penelope**: `git clone https://github.com/brightio/penelope && pip install penelope`
  для shell-хендлера.
