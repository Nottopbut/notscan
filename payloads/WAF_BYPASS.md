# WAF-bypass probes

Наборы в этом каталоге содержат не только «канонические» инъекции, но и
WAF-bypass варианты — обфусцированные формы тех же проб, которые чаще проходят
сквозь сигнатурные WAF/фильтры. Варианты **встроены в существующие файлы**
(а не лежат отдельным файлом) в секциях `# --- WAF bypass ---`, поэтому их
автоматически читает `scanner_core.load_payloads` и используют текущие чеки.
Отдельный неиспользуемый файл намеренно не создавался.

## Стратегии обхода

| Стратегия | Что делаем | Примеры (файл) |
|---|---|---|
| Case-mix | Меняем регистр ключевых слов | `UnIoN SeLeCt` (`sqli.txt`), `JaVaScRiPt:` (`xss.txt`) |
| Комментарии/инлайн-мусор | Вставляем `/**/`, `/*!50000...*/` между токенами | `UN/**/ION`, `/*!50000UNION*/`, `AND/**/1=1` (`sqli.txt`) |
| Keyword splitting | Разрываем слова комментариями/кодированием | `' UN/**/ION SEL/**/ECT 1,2,3-- -` (`sqli.txt`) |
| Percent/hex-кодирование | Кодируем символы `%XX`, `%uXXXX`, `0x..` | `%55nion %53elect` (`sqli.txt`), `%c0%af` (`path_traversal.txt`), `%u000d%u000a` (`crlf.txt`) |
| HTML-entity/JS-escape | Сущности и escape-последовательности вместо символов | `&#x3c;script&#x3e;`, `\u003cscript\u003e`, `\x3cscript\x3e` (`xss.txt`) |
| Path normalization | Двойные точки/слэши, overlong-UTF-8, `..;/`, backslash | `....//`, `%252e%252e`, `%c0%af`, `..;/` (`path_traversal.txt`) |
| IP-представления | decimal/octal/hex/int IP, IPv4-mapped IPv6 | `2130706433`, `0x7f.0.0.1`, `017700000001`, `[::ffff:127.0.0.1]` (`ssrf.txt`) |
| Userinfo `@`-обфускация | Маскируем хост через `user@host` | `127.0.0.1@evil.com`, `trusted.com@evil.com` (`ssrf.txt`, `open_redirect.txt`) |
| Schema/template-альтернативы | Альтернативные разделители и обёртки | `${{7*7}}`, `%7B%7B7*7%7D%7D`, `{{7*7|abs}}`, `|attr('__mul__')` (`ssti.txt`) |
| Parser evasion | Двойные расширения, ADS/encoded-идентификаторы | `x.php%00.png`, `x.pHp5`, `null`, base64-UUID (`file_upload.txt`, `idor.txt`) |

## Какие наборы затронуты

Счётчики «до → после» (payload-строки, без комментариев):

| Файл | До | После | Добавлено |
|---|---:|---:|---:|
| `sqli.txt` | 666 | 703 | +37 |
| `xss.txt` | 165 | 195 | +30 |
| `cmdi.txt` | 543 | 578 | +35 |
| `path_traversal.txt` | 837 | 857 | +20 |
| `ssrf.txt` | 77 | 97 | +20 |
| `xxe.txt` | 89 | 103 | +14 |
| `open_redirect.txt` | 285 | 317 | +32 |
| `crlf.txt` | 31 | 46 | +15 |
| `ssti.txt` | 139 | 167 | +28 |
| `nosqli.txt` | 61 | 74 | +13 |
| `ldapi.txt` | 54 | 63 | +9 |
| `xpath.txt` | 43 | 52 | +9 |
| `deserialization.txt` | 16 | 26 | +10 |
| `file_upload.txt` | 34 | 47 | +13 |
| `idor.txt` | 28 | 46 | +18 |

Добавленные в `idor.txt` идентификаторы — безопасные значения (`null`, `0x1f`,
числовые/нумерованные id, base64-представления UUID), без SQL-строк.

Итого в каталоге: **3601 payload** (было 3298), 19 наборов. `sqli_time.txt`,
`sqli_blind.txt`, `ssi.txt`, `html_injection.txt` не расширялись: их формат жёстко
связан с таймингами/парами/маркерами детекторов.

## Чего мы НЕ делаем (non-destructive policy)

- Никаких разрушающих SQL-операций: `DROP`, `INSERT`, `UPDATE`, `DELETE`,
  `INTO OUTFILE`, `load_file`, `xp_cmdshell` — такие строки в файлах есть только
  как legacy-примеры и отсекаются Safe Mode (`DESTRUCTIVE_PAYLOAD_PATTERNS`).
- В WAF-секции добавлены только read-only пробы: `id`, `whoami`, `ls`, `echo`,
  `base64 -d`, чтение файлов (`/etc/passwd`, `win.ini`), запросы к localhost.
  Никаких записи файлов, изменения системы, reverse shell, выполнения
  деструктивных команд.
- Payload'ы — это **только HTTP-строки**. Сканер подставляет их в запрос и
  анализирует ответ; локально они не исполняются.
- WAF-bypass варианты не являются эксплойтами: они проверяют, доходит ли та же
  проба до приложения при включённом фильтре. Использовать только на
  авторизованных стендах (см. Safe Mode / ROE в корневом README).

## Runtime-кодировщики (Tamper)

Помимо статических WAF-вариантов в файлах, движок умеет кодировать payload
«на лету» — параметр `tamper_modes` в `scanner_core.build_scan_tasks`:

| Режим | Реализация | Пример `alert(1)` |
|---|---|---|
| `url` | `urllib.parse.quote(payload, safe="")` | `alert%281%29` |
| `unicode` | каждый символ → `%uXXXX` (IIS/ASP стиль) | `%u0061%u006C...` |
| `hex` | каждый байт UTF-8 → `%XX` (включая alnum) | `%61%6C%65%72%74...` |
| `double-url` | двойное URL-кодирование | `alert%25281%2529` |

Включение: галочка **Tamper/WAF-bypass** в GUI (список режимов берётся из
`templating.TAMPER_MODES`), либо программно:

```python
tasks = scanner_core.build_scan_tasks(
    history_ids=[hid],
    enabled_checks=["sqli", "cmdi"],
    tamper_modes=["url", "unicode", "hex", "double-url"],  # None = выключено
)
```

Tamper применяется только к серверным инъекционным чекам (`TAMPERABLE_CHECKS` в
`scanner_core.py`); XSS/passive/redirect не кодируются. Статические WAF-варианты
из файлов при этом загружаются всегда и работают независимо от Tamper.

## Как добавить/проверить

1. Один payload = одна строка; комментарии начинаются с `#`
   (payload, который сам начинается с `#`, храните с ведущим пробелом —
   `loader` делает `strip()`; пример — SSTI `#{7*7}`).
2. Новые WAF-варианты — в конец файла под маркер `# --- WAF bypass ---`,
   без дубликатов и деструктивных операций.
3. Обновите `# Total: N payloads` в шапке файла (считаются только payload-строки).
4. Обновите `MIN_PAYLOAD_COUNTS` в `tests/test_payloads_quality.py`.
5. Прогон: `python -m pytest tests/test_payloads_quality.py tests/test_hardening.py -q`.
