"""
report_export.py — Экспорт результатов скана в JSON, Markdown, DOCX, HTML и SARIF.

MD / JSON / DOCX содержат:
  • сводку по severity;
  • рекомендации «на что обратить внимание» (по типам находок);
  • матрицу детекции True/False (какой тип проверки сработал, а какой нет).
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

import db

# python-docx нужен только для DOCX-экспорта; импортируем лениво-безопасно,
# чтобы остальные форматы работали даже без установленного python-docx.
try:  # pragma: no cover - зависит от окружения
    from docx.enum.table import WD_TABLE_ALIGNMENT
    from docx.oxml import OxmlElement
    from docx.oxml.ns import qn
    from docx.shared import Cm, Inches, Pt
    _DOCX_IMPORT_ERROR: Exception | None = None
except Exception as _exc:  # noqa: BLE001
    WD_TABLE_ALIGNMENT = None  # type: ignore[assignment]
    OxmlElement = None  # type: ignore[assignment]
    qn = None  # type: ignore[assignment]
    Cm = Inches = Pt = None  # type: ignore[assignment]
    _DOCX_IMPORT_ERROR = _exc


def _require_docx() -> None:
    if _DOCX_IMPORT_ERROR is not None:
        raise RuntimeError(
            "python-docx не установлен. Выполни: pip install python-docx"
        ) from _DOCX_IMPORT_ERROR


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def _t(text: str, **fmt) -> str:
    """Перевод видимых строк отчёта по текущему языку GUI (fallback — исходник)."""
    try:
        import i18n
        return i18n.tr(text, **fmt)
    except Exception:
        try:
            return str(text).format(**fmt) if fmt else str(text)
        except Exception:
            return str(text)


def _report_lang() -> str:
    try:
        import i18n
        return i18n.get_language()
    except Exception:
        return "en"


def _catalog_severity_map() -> dict:
    """check_id → severity из единого каталога чеков (если доступен)."""
    try:
        from checks.catalog import CHECK_CATALOG  # локальный импорт: каталог лёгкий
        return {d.check_id.lower(): str(d.severity).upper() for d in CHECK_CATALOG}
    except Exception:
        return {}


_CATALOG_SEVERITY = _catalog_severity_map()


def _row_severity(r: dict) -> str:
    """Severity из scan_meta (CRITICAL/HIGH/MEDIUM/LOW/INFO) с фолбэком по check_type."""
    sev = (r.get("severity") or "").strip().upper()
    if sev:
        return sev
    ct = (r.get("check_type") or "").lower()
    if ct in _CATALOG_SEVERITY:
        return _CATALOG_SEVERITY[ct]
    if ct in ("cmdi", "ssti", "deserialization", "file_upload",
              "sqli", "sqli_time", "sqli_blind", "ssi_injection", "xxe", "ssrf",
              "path_traversal"):
        return "HIGH"
    if ct in ("xss", "xss_reflected", "xss_dom", "open_redirect", "crlf_injection",
              "html_injection", "nosql_injection", "ldap_injection",
              "xpath_injection", "idor", "cors", "ria_policy", "http_methods"):
        return "MEDIUM"
    if ct in ("csrf", "clickjacking", "security_headers",
              "info_disclosure", "outdated_libs", "third_party_scripts", "metafiles",
              "cookies", "hsts", "csp", "cache_control"):
        return "LOW"
    return "INFO"


def _sarif_level(sev: str) -> str:
    if sev in ("CRITICAL", "HIGH"):
        return "error"
    if sev in ("MEDIUM", "LOW"):
        return "warning"
    return "note"


# ──────────────────────────── Рекомендации ────────────────────────────

RECOMMENDATIONS_EN = {
    "sqli": "Use parameterized queries (prepared statements). Never concatenate user input into SQL.",
    "sqli_time": "Parameterized queries + DB timeouts. Validate and strictly type input.",
    "sqli_blind": "Parameterized queries. Do not concatenate input; keep response behavior consistent for boolean conditions.",
    "cmdi": "Never pass user input to shell/exec. Allowlist commands and separate arguments.",
    "ssti": "Do not eval user input in templates. Use sandboxing and an expression allowlist.",
    "xss": "Context-aware output encoding (HTML/JS/attribute). Add CSP and HttpOnly cookies.",
    "xss_reflected": "Escape reflected output + CSP. Never render user input without encoding.",
    "xss_dom": "Use safe DOM APIs (textContent instead of innerHTML). Avoid eval/document.write/innerHTML sinks.",
    "path_traversal": "Canonicalize paths + allowlist. Never accept raw paths from clients.",
    "xxe": "Disable external entity/DTD processing in the XML parser.",
    "ssrf": "Allowlist outbound destinations. Block metadata endpoints (169.254.169.254) and validate URLs.",
    "nosql_injection": "Validate and type input for NoSQL. Never pass raw objects into queries.",
    "ldap_injection": "Escape LDAP metacharacters or use safe APIs with filters.",
    "xpath_injection": "Use parameterized XPath expressions instead of string concatenation.",
    "deserialization": "Never deserialize untrusted data. Allowlist classes and use signatures.",
    "crlf_injection": "Sanitize CR/LF in headers. Never insert user input into response headers.",
    "open_redirect": "Allowlist redirect URLs. Never trust next/return/url parameters without validation.",
    "file_upload": "Validate content type by content (not extension). Store uploads outside the webroot.",
    "idor": "Enforce object-level authorization. Never trust IDs from URLs.",
    "jwt": "Verify JWT signatures server-side. Reject alg=none. Use a long random HMAC secret or RS256.",
    "info_disclosure_paths": "Restrict sensitive paths (actuator, .env, .git, swagger, metrics) or require authorization.",
    "sqli_confirmed": "Use parameterized queries (prepared statements).",
    "ssi_injection": "Do not process user input with SSI; encode directives or disable SSI for user data.",
    "html_injection": "Context-aware HTML output encoding. Never inject user input into HTML unencoded.",
    "cookies": "Set Secure, HttpOnly and SameSite=Lax/Strict on session cookies; never store secrets in cookies.",
    "hsts": "Add Strict-Transport-Security (max-age >= 31536000, includeSubDomains) to HTTPS responses.",
    "csp": "Configure Content-Security-Policy without unsafe-inline/unsafe-eval; use nonces/hashes.",
    "cache_control": "Use Cache-Control: no-store/private and Pragma: no-cache for session/secret responses.",
    "insecure_login": "Send credentials only over HTTPS; never submit login forms or Authorization over HTTP.",
    "browser_storage": "Do not store tokens/secrets in localStorage/sessionStorage; use HttpOnly cookies.",
    "metafiles": "Review robots.txt/sitemap.xml/security.txt for internal path leaks and remove unnecessary entries.",
    "ria_policy": "Remove wildcards from crossdomain.xml/clientaccesspolicy.xml; allowlist explicit domains.",
    "http_methods": "Disable unnecessary HTTP methods (TRACE/PUT/DELETE); keep only those required.",
    "sensitive_files": "Block access to backups, .env/.git and service files; keep them outside the webroot.",
    "cors": "Do not reflect arbitrary Origin; never combine Access-Control-Allow-Credentials with wildcard; use an allowlist.",
    "csrf": "Use CSRF tokens + SameSite cookies. Validate Origin/Referer.",
    "clickjacking": "Send X-Frame-Options / CSP frame-ancestors.",
    "security_headers": "Add missing security headers (HSTS, X-Content-Type-Options, CSP, etc.).",
    "info_disclosure": "Hide versions, internal paths and stack traces in production.",
    "outdated_libs": "Update outdated JS libraries/frameworks.",
    "third_party_scripts": "Restrict third-party scripts (SRI, domain allowlist).",
    "server_fingerprint": "Remove/obfuscate technology version headers (Server, X-Powered-By, X-AspNet-Version) and framework cookies; keep software patched.",
    "errh": "Show generic error pages in production; keep details in server logs. Disable debug mode and stack traces.",
    "session_in_url": "Never put session identifiers in URLs; use Secure/HttpOnly/SameSite cookies and regenerate session IDs on login.",
    "host_header_injection": "Validate/allowlist the Host header and never use it for absolute URLs, password-reset links or cache keys; set a canonical host.",
}

GENERIC_RECOMMENDATION_EN = "Verify manually and fix according to the OWASP Testing Guide / CWE."

RECOMMENDATIONS = {
    "sqli": "Параметризованные запросы (prepared statements). Не конкатенируй пользовательский ввод в SQL.",
    "sqli_time": "Параметризованные запросы + таймауты БД. Валидация и строгая типизация ввода.",
    "cmdi": "Не передавай пользовательский ввод в shell/exec. Allowlist команд и разделение аргументов.",
    "ssti": "Не используй eval пользовательского ввода в шаблонах. Sandbox и allowlist выражений.",
    "xss": "Контекстное экранирование вывода (HTML/JS/attribute). CSP и HttpOnly cookies.",
    "xss_reflected": "Экранируй отражённый вывод + CSP. Не выводи пользовательский ввод без фильтрации.",
    "xss_dom": "Безопасные DOM-API (textContent вместо innerHTML). Избегай sinks: eval, document.write, innerHTML.",
    "path_traversal": "Канонизация путей + allowlist. Не принимай пути напрямую от клиента.",
    "xxe": "Отключи обработку внешних сущностей (DTD/ENTITY) в XML-парсере.",
    "ssrf": "Allowlist исходящих адресов. Блокируй metadata-эндпоинты (169.254.169.254). Валидируй URL.",
    "nosql_injection": "Валидация и типизация ввода для NoSQL. Не подставляй объекты в запросы напрямую.",
    "ldap_injection": "Экранируй спецсимволы LDAP или используй безопасные API с фильтрами.",
    "xpath_injection": "Параметризованные XPath-запросы (переменные, а не конкатенация).",
    "deserialization": "Не десериализуй недоверенные данные. Allowlist классов + подписи.",
    "crlf_injection": "Санитизируй CR/LF в заголовках. Не вставляй пользовательский ввод в заголовки ответа.",
    "open_redirect": "Allowlist URL для редиректов. Не доверяй параметрам next/return/url без проверки.",
    "file_upload": "Валидация типа по содержимому (не по расширению). Храни загрузки вне webroot.",
    "idor": "Проверка прав на уровне объекта (object-level authorization). Не доверяй ID из URL.",
    "jwt": "Валидируй подпись JWT на сервере. Отклоняй alg=none. Используй длинный случайный HMAC-секрет или RS256.",
    "info_disclosure_paths": "Закрой доступ к чувствительным путям (actuator, .env, .git, swagger, metrics и т.п.) или ограничь их авторизацией.",
    "sqli_blind": "Параметризованные запросы (prepared statements). Не конкатенируй пользовательский ввод в SQL; следи за одинаковым поведением ответа на булевы условия.",
    "ssi_injection": "Не обрабатывай пользовательский ввод SSI-движком; экранируй директивы или отключи SSI для пользовательских данных.",
    "html_injection": "Контекстное HTML-экранирование вывода. Не вставляй пользовательский ввод в HTML без кодирования.",
    "cookies": "Установи Secure, HttpOnly и SameSite=Lax/Strict для сессионных cookie; не храни секреты в cookie.",
    "hsts": "Добавь Strict-Transport-Security (max-age >= 31536000, includeSubDomains) для HTTPS-ответов.",
    "csp": "Настрой Content-Security-Policy без unsafe-inline/unsafe-eval; используй nonce/hash и строгий script-src.",
    "cache_control": "Для ответов с сессией/секретами используй Cache-Control: no-store, private и Pragma: no-cache.",
    "insecure_login": "Передавай креды только по HTTPS; не используй формы логина и Authorization на HTTP.",
    "browser_storage": "Не храни токены/секреты в localStorage/sessionStorage; используй HttpOnly-cookie с защитой от XSS.",
    "metafiles": "Проверь robots.txt/sitemap.xml/security.txt на утечку внутренних путей и удали лишние записи.",
    "ria_policy": "Убери wildcard из crossdomain.xml/clientaccesspolicy.xml; ограничь домены явным allowlist.",
    "http_methods": "Отключи ненужные HTTP-методы (TRACE/PUT/DELETE), оставь только необходимые; ограничь через прокси/сервер.",
    "sensitive_files": "Закрой доступ к бэкапам, .env/.git и служебным файлам; храни их вне webroot.",
    "cors": "Не отражай произвольный Origin и не используй Access-Control-Allow-Credentials вместе с wildcard; веди allowlist origin.",
    "csrf": "CSRF-токены + SameSite cookies. Проверяй Origin/Referer.",
    "clickjacking": "Заголовки X-Frame-Options / CSP frame-ancestors.",
    "security_headers": "Добавь недостающие security-заголовки (HSTS, X-Content-Type-Options, CSP и др.).",
    "info_disclosure": "Скрывай версии, внутренние пути и stack traces в продакшене.",
    "outdated_libs": "Обнови устаревшие JS-библиотеки/фреймворки.",
    "third_party_scripts": "Ограничь сторонние скрипты (SRI, allowlist доменов).",
    "server_fingerprint": "Скрой версии/технологии: убери заголовки Server/X-Powered-By/"
                          "X-AspNet-Version, переименуй framework-cookie, удали meta generator.",
    "errh": "Показывай пользователю общее сообщение об ошибке; stack traces, DEBUG-страницы "
            "и SQL-ошибки — только в серверный лог (production).",
    "session_in_url": "Не передавай session-id/токены в URL и Referer; используй "
                      "HttpOnly-cookie (Secure, SameSite) или заголовок Authorization.",
    "host_header_injection": "Валидируй Host/X-Forwarded-Host/Forwarded по allowlist и не "
                             "используй их для генерации ссылок/редиректов (password-reset, "
                             "cache poisoning).",
}

GENERIC_RECOMMENDATION = "Проверь вручную и устрани в соответствии с OWASP Testing Guide / CWE."


def _recommendation_for(check_type: str) -> str:
    ct = (check_type or "").lower()
    if _report_lang() == "en":
        return RECOMMENDATIONS_EN.get(ct, GENERIC_RECOMMENDATION_EN)
    return RECOMMENDATIONS.get(ct, GENERIC_RECOMMENDATION)


# ──────────────────────────── Данные отчёта ────────────────────────────

_SEVERITY_ORDER = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]


def _sev_rank(sev: str) -> int:
    try:
        return _SEVERITY_ORDER.index(sev)
    except ValueError:
        return len(_SEVERITY_ORDER)


def _dedup_findings(findings: list[dict]) -> list[dict]:
    """
    Сворачивает дубликаты находок по стабильному fingerprint (или fallback
    check_type|url), повторяя поведение Results-вью «Group duplicates».
    Оставляет представителя группы с максимальной severity и добавляет
    поле `occurrences` (сколько находок представляет данная запись).
    """
    reps: dict[str, dict] = {}
    order: list[str] = []
    counts: dict[str, int] = {}
    for r in findings:
        fp = r.get("fingerprint")
        key = fp if fp else f"{r.get('check_type')}|{r.get('url')}"
        if key not in reps:
            reps[key] = r
            order.append(key)
            counts[key] = 1
        else:
            counts[key] += 1
            if _sev_rank(r.get("severity")) < _sev_rank(reps[key].get("severity")):
                reps[key] = r
    out: list[dict] = []
    for k in order:
        r = dict(reps[k])
        r["occurrences"] = counts[k]
        out.append(r)
    return out


def _enriched_findings(rows: list[dict]) -> list[dict]:
    """Enrich evidence-bearing rows with severity + recommendation."""
    findings = [r for r in rows if r.get("evidence")]
    return [
        {
            **r,
            "severity": _row_severity(r),
            "recommendation": _recommendation_for(r.get("check_type")),
        }
        for r in findings
    ]


def _build_report_data(limit: int | None = None, deduplicate: bool = True) -> dict:
    rows = db.fetch_scan_results_with_meta(limit=limit)
    findings_raw = _enriched_findings(rows)
    findings = _dedup_findings(findings_raw) if deduplicate else findings_raw

    sev_counts = {s: 0 for s in _SEVERITY_ORDER}
    by_type: dict[str, dict] = {}

    for r in findings:
        sev = _row_severity(r)
        sev_counts[sev] = sev_counts.get(sev, 0) + 1
        ct = (r.get("check_type") or "unknown").lower()
        d = by_type.setdefault(ct, {"count": 0, "max_severity": "INFO", "rank": len(_SEVERITY_ORDER)})
        d["count"] += 1
        if _sev_rank(sev) < d["rank"]:
            d["rank"] = _sev_rank(sev)
            d["max_severity"] = sev

    recommendations = sorted(
        [
            {
                "check_type": ct,
                "count": d["count"],
                "max_severity": d["max_severity"],
                "recommendation": _recommendation_for(ct),
            }
            for ct, d in by_type.items()
        ],
        key=lambda x: (-x["count"], _sev_rank(x["max_severity"])),
    )

    all_types = sorted({(r.get("check_type") or "unknown").lower() for r in rows})
    matrix = []
    for ct in all_types:
        d = by_type.get(ct)
        matrix.append({
            "check_type": ct,
            "detected": ct in by_type,
            "count": d["count"] if d else 0,
            "max_severity": d["max_severity"] if d else "",
        })

    return {
        "total": len(rows),
        "findings_count": len(findings),
        "findings_raw_count": len(findings_raw),
        "deduplicated": deduplicate,
        "severity_counts": sev_counts,
        "findings": findings,
        "recommendations": recommendations,
        "matrix": matrix,
    }


def _md_escape(s) -> str:
    return (s or "").replace("|", "\\|").replace("\n", " ").replace("\r", " ")


# ──────────────────────────── JSON ────────────────────────────

def export_json(filepath: str | Path, limit: int | None = None, deduplicate: bool = True) -> int:
    data = _build_report_data(limit, deduplicate)
    out = {
        "export_time": _now_iso(),
        "source": "notscan",
        "summary": {
            "total": data["total"],
            "findings": data["findings_count"],
            "findings_raw": data["findings_raw_count"],
            "deduplicated": data["deduplicated"],
            "severity_counts": data["severity_counts"],
        },
        "recommendations": data["recommendations"],
        "detection_matrix": data["matrix"],
        "results": [
            {
                "id": f["id"],
                "time": f["time"],
                "method": f["method"],
                "url": f["url"],
                "status_code": f["status_code"],
                "check_type": f["check_type"],
                "payload": f["payload"],
                "evidence": f["evidence"],
                "severity": f["severity"],
                "confidence": f.get("confidence"),
                "occurrences": f.get("occurrences", 1),
                "recommendation": f["recommendation"],
            }
            for f in data["findings"]
        ],
    }
    path = Path(filepath)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(out, ensure_ascii=False, indent=2), encoding="utf-8")
    return len(data["findings"])


# ──────────────────────────── Markdown ────────────────────────────

def export_md(filepath: str | Path, limit: int | None = None, deduplicate: bool = True) -> int:
    data = _build_report_data(limit, deduplicate)
    L: list[str] = []
    L.append(f"# {_t('Notscan Scan Report')}")
    L.append("")
    dedup_note = (
        f"  |  {_t('Unique findings')}: {data['findings_count']} ({_t('raw')}: {data['findings_raw_count']})"
        if data.get("deduplicated") else ""
    )
    L.append(
        f"> {_t('Generated')}: {_now_iso()}  |  {_t('Total results')}: {data['total']}  |  "
        f"{_t('Findings')}: {data['findings_count']}{dedup_note}"
    )
    L.append("")

    L.append(f"## {_t('Summary')}")
    L.append("")
    L.append(f"| {_t('Severity')} | {_t('Count')} |")
    L.append("|----------|-------|")
    for sev in _SEVERITY_ORDER:
        L.append(f"| {sev.title()} | {data['severity_counts'].get(sev, 0)} |")
    L.append("")

    L.append(f"## {_t('Recommendations')}")
    L.append("")
    L.append(f"| {_t('Check')} | {_t('Severity')} | {_t('Count')} | {_t('Recommendation')} |")
    L.append("|-------|----------|-------|----------------|")
    for rec in data["recommendations"]:
        L.append(
            f"| {rec['check_type']} | {rec['max_severity'].title()} | {rec['count']} | {rec['recommendation']} |"
        )
    L.append("")

    L.append(f"## {_t('Detection Matrix (True/False)')}")
    L.append("")
    L.append(f"| {_t('Check')} | {_t('Detected')} | {_t('Count')} | {_t('Max Severity')} |")
    L.append("|-------|----------|-------|--------------|")
    for m in data["matrix"]:
        det = _t("True") if m["detected"] else _t("False")
        mx = m["max_severity"].title() if m["max_severity"] else "—"
        L.append(f"| {m['check_type']} | {det} | {m['count']} | {mx} |")
    L.append("")

    L.append(f"## {_t('Findings')}")
    L.append("")
    L.append(f"| ID | {_t('Check')} | {_t('Severity')} | {_t('Method')} | {_t('Count')} | URL | {_t('Evidence')} |")
    L.append("|----|-------|----------|--------|-------|-----|----------|")
    for f in data["findings"]:
        cnt = f.get("occurrences", 1)
        L.append(
            f"| {f['id']} | {f.get('check_type')} | {f['severity'].title()} | "
            f"{f.get('method')} | {cnt} | {_md_escape(f.get('url', ''))} | "
            f"{_md_escape((f.get('evidence') or '')[:200])} |"
        )
    L.append("")

    Path(filepath).write_text("\n".join(L), encoding="utf-8")
    return len(data["findings"])


# ──────────────────────────── DOCX ────────────────────────────

def _soft_break_text(text: str, every: int = 40) -> str:
    _require_docx()
    """Вставляет zero-width-space, чтобы длинные URL/токены переносились в Word.

    Без этого Word не рвёт длинные URL/evidence-строки и таблица «разъезжается».
    """
    text = str(text or "")
    if not text:
        return ""
    # сначала пробуем рвать по естественным разделителям URL/пути
    for ch in ("/", "?", "&", "=", ";", ":", ",", "-", "_", "."):
        text = text.replace(ch, ch + "\u200b")
    # страховка для совсем длинных слитных токенов
    out = []
    for chunk_start in range(0, len(text), every):
        out.append(text[chunk_start:chunk_start + every])
    return "\u200b".join(out)


def _docx_set_cell_text(cell, value: str, *, bold: bool = False,
                        size_pt: float = 8.0, soft: bool = True) -> None:
    """Записывает текст в ячейку с шрифтом/переносами и без лишних отступов."""
    p = cell.paragraphs[0]
    p.paragraph_format.space_before = Pt(0)
    p.paragraph_format.space_after = Pt(0)
    run = p.add_run(_soft_break_text(value) if soft else str(value or ""))
    run.bold = bold
    run.font.size = Pt(size_pt)
    run.font.name = "Calibri"
    # узкие поля ячейки, чтобы больше текста помещалось
    tcPr = cell._tc.get_or_add_tcPr()
    mar = OxmlElement("w:tcMar")
    for side in ("top", "bottom", "start", "end"):
        node = OxmlElement(f"w:{side}")
        node.set(qn("w:w"), "40" if side in ("top", "bottom") else "70")
        node.set(qn("w:type"), "dxa")
        mar.append(node)
    tcPr.append(mar)


def _docx_table(doc, headers: list[str], rows: list[list[str]],
                widths_in: list[float] | None = None,
                font_size: float = 8.0,
                header_fill: str = "D9E2F3") -> None:
    """Таблица с фиксированной шириной колонок и читаемыми переносами."""
    table = doc.add_table(rows=1, cols=len(headers))
    try:
        table.style = "Table Grid"
    except Exception:
        pass
    table.alignment = WD_TABLE_ALIGNMENT.CENTER
    table.autofit = False
    # фиксированная раскладка: Word не будет сам сжимать колонки
    tblPr = table._tbl.tblPr
    layout = OxmlElement("w:tblLayout")
    layout.set(qn("w:type"), "fixed")
    tblPr.append(layout)

    n = len(headers)
    if widths_in and len(widths_in) == n:
        widths = [Inches(w) for w in widths_in]
    else:
        total = 10.5
        widths = [Inches(total / max(1, n))] * n

    header_cells = table.rows[0].cells
    for i, h in enumerate(headers):
        header_cells[i].width = widths[i]
        _docx_set_cell_text(header_cells[i], str(h), bold=True,
                            size_pt=font_size + 0.5, soft=False)
        # фон заголовка
        tcPr = header_cells[i]._tc.get_or_add_tcPr()
        shd = OxmlElement("w:shd")
        shd.set(qn("w:val"), "clear")
        shd.set(qn("w:color"), "auto")
        shd.set(qn("w:fill"), header_fill)
        tcPr.append(shd)
    # повторять заголовок на каждой странице
    trPr = table.rows[0]._tr.get_or_add_trPr()
    tbl_header = OxmlElement("w:tblHeader")
    tbl_header.set(qn("w:val"), "true")
    trPr.append(tbl_header)

    for row in rows:
        cells = table.add_row().cells
        for i, v in enumerate(row):
            cells[i].width = widths[i]
            _docx_set_cell_text(cells[i], str(v), size_pt=font_size)


def export_docx(filepath: str | Path, limit: int | None = None) -> int:
    _require_docx()
    try:
        from docx import Document
        from docx.enum.section import WD_ORIENT
    except ImportError as exc:
        raise RuntimeError("python-docx не установлен. Выполни: pip install python-docx") from exc

    data = _build_report_data(limit)
    doc = Document()

    # A4 landscape + узкие поля: таблица находок из 7 колонок становится читаемой
    section = doc.sections[0]
    section.orientation = WD_ORIENT.LANDSCAPE
    section.page_width, section.page_height = section.page_height, section.page_width
    section.left_margin = section.right_margin = Cm(1.5)
    section.top_margin = section.bottom_margin = Cm(1.5)

    try:
        styles = doc.styles
        normal = styles["Normal"]
        normal.font.name = "Calibri"
        normal.font.size = Pt(9)
    except Exception:
        pass

    doc.add_heading(_t("Notscan Scan Report"), 0)
    dedup_txt = (
        f"   |   {_t('Unique findings')}: {data['findings_count']} ({_t('raw')}: {data['findings_raw_count']})"
        if data.get("deduplicated") else ""
    )
    doc.add_paragraph(
        f"{_t('Generated')}: {_now_iso()}   |   {_t('Total results')}: {data['total']}   |   "
        f"{_t('Findings')}: {data['findings_count']}{dedup_txt}"
    )

    doc.add_heading(_t("Summary"), level=1)
    _docx_table(
        doc,
        [_t("Severity"), _t("Count")],
        [[sev.title(), str(data["severity_counts"].get(sev, 0))] for sev in _SEVERITY_ORDER],
        widths_in=[2.2, 1.2],
        font_size=9,
    )

    doc.add_heading(_t("Recommendations"), level=1)
    _docx_table(
        doc,
        [_t("Check"), _t("Severity"), _t("Count"), _t("Recommendation")],
        [
            [rec["check_type"], rec["max_severity"].title(), str(rec["count"]), rec["recommendation"]]
            for rec in data["recommendations"]
        ],
        widths_in=[1.35, 0.95, 0.7, 7.5],
        font_size=8.5,
    )

    doc.add_heading(_t("Detection Matrix (True/False)"), level=1)
    _docx_table(
        doc,
        [_t("Check"), _t("Detected"), _t("Count"), _t("Max Severity")],
        [
            [m["check_type"], _t("True") if m["detected"] else _t("False"), str(m["count"]),
             m["max_severity"].title() if m["max_severity"] else "—"]
            for m in data["matrix"]
        ],
        widths_in=[1.7, 1.1, 0.9, 1.3],
        font_size=8.5,
    )

    doc.add_heading(_t("Findings"), level=1)
    findings = data["findings"][:2000]
    _docx_table(
        doc,
        ["ID", _t("Check"), _t("Severity"), _t("Method"), _t("Count"), "URL", _t("Evidence")],
        [
            [str(f["id"]), str(f.get("check_type")), f["severity"].title(),
             str(f.get("method")), str(f.get("occurrences", 1)),
             str(f.get("url", "")), (f.get("evidence") or "")[:300]]
            for f in findings
        ],
        widths_in=[0.55, 1.05, 0.75, 0.6, 0.5, 3.25, 3.8],
        font_size=7.5,
    )

    doc.save(filepath)
    return len(data["findings"])


# ──────────────────────────── HTML ────────────────────────────

def export_html(filepath: str | Path, limit: int | None = None, deduplicate: bool = True) -> int:
    rows = db.fetch_scan_results_with_meta(limit=limit)
    path = Path(filepath)
    path.parent.mkdir(parents=True, exist_ok=True)

    findings = _enriched_findings(rows)
    raw_count = len(findings)
    vuln_rows = _dedup_findings(findings) if deduplicate else findings
    html_parts = [
        "<!DOCTYPE html><html><head><meta charset='utf-8'>",
        f"<title>{_t('Notscan Scan Report')}</title>",
        "<style>"
        "body{font-family:Segoe UI,sans-serif;background:#1e1e2e;color:#cdd6f4;margin:20px;}",
        "h1{color:#89b4fa;} .meta{color:#a6adc8;margin-bottom:20px;}",
        "table{border-collapse:collapse;width:100%;margin-bottom:20px;}",
        "th,td{border:1px solid #45475a;padding:8px;text-align:left;}",
        "th{background:#313244;color:#89b4fa;}",
        ".sev-error{color:#f38ba8;} .sev-warning{color:#f9e2af;} .sev-note{color:#a6adc8;}",
        "pre{overflow-x:auto;font-size:12px;}",
        "</style></head><body>",
        f"<h1>{_t('Notscan Scan Report')}</h1>",
        f"<p class='meta'>{_t('Export')}: {_now_iso()} | {_t('Total results')}: {len(rows)} | "
        f"{_t('Unique findings')}: {len(vuln_rows)} ({_t('raw')}: {raw_count})</p>",
        "<table><thead><tr>",
        f"<th>ID</th><th>{_t('Time')}</th><th>{_t('Check')}</th><th>{_t('Severity')}</th><th>{_t('Method')}</th><th>{_t('Count')}</th><th>URL</th>",
        f"<th>Payload</th><th>{_t('Evidence')}</th>",
        "</tr></thead><tbody>",
    ]
    for r in vuln_rows:
        sev = _row_severity(r)
        level = _sarif_level(sev)
        ts = datetime.fromtimestamp(r["time"]).strftime("%Y-%m-%d %H:%M:%S") if r.get("time") else ""
        html_parts.append(
            f"<tr class='sev-{level}'>"
            f"<td>{r['id']}</td><td>{ts}</td><td>{r.get('check_type', '')}</td>"
            f"<td class='sev-{level}'>{sev}</td><td>{r.get('method', '')}</td>"
            f"<td>{r.get('occurrences', 1)}</td><td>{r.get('url', '')}</td>"
            f"<td><pre>{json.dumps(r.get('payload') or '', ensure_ascii=False)[:200]}</pre></td>"
            f"<td><pre>{json.dumps(r.get('evidence') or '', ensure_ascii=False)[:500]}</pre></td>"
            "</tr>"
        )
    html_parts.append("</tbody></table></body></html>")
    path.write_text("".join(html_parts), encoding="utf-8")
    return len(vuln_rows)


# ──────────────────────────── SARIF ────────────────────────────

def export_sarif(filepath: str | Path, limit: int | None = None, deduplicate: bool = True) -> int:
    rows = db.fetch_scan_results_with_meta(limit=limit)
    findings = _enriched_findings(rows)
    vuln_rows = _dedup_findings(findings) if deduplicate else findings
    path = Path(filepath)
    path.parent.mkdir(parents=True, exist_ok=True)

    results_sarif = []
    for r in vuln_rows:
        sev = _row_severity(r)
        rule_id = (r.get("check_type") or "unknown").replace(" ", "_")
        occ = r.get("occurrences", 1)
        msg = (r.get("evidence") or "")[:1000]
        if occ > 1:
            msg = f"[×{occ}] {msg}"
        results_sarif.append({
            "ruleId": rule_id,
            "level": _sarif_level(sev),
            "message": {"text": msg},
            "locations": [{
                "physicalLocation": {
                    "artifactLocation": {"uri": r.get("url") or ""},
                    "region": {"startLine": 1},
                }
            }],
            "partialFingerprints": {
                "notscan/result": r.get("fingerprint") or str(r.get("id", "")),
            },
        })

    rules_seen = {r.get("check_type") or "unknown" for r in vuln_rows}
    rules = [
        {"id": rid, "name": rid, "shortDescription": {"text": rid}}
        for rid in rules_seen
    ]

    sarif = {
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {
                "driver": {
                    "name": "notscan",
                    "version": "1.0",
                    "informationUri": "https://github.com/Nottopbut/notscan",
                    "rules": rules,
                }
            },
            "results": results_sarif,
        }]
    }
    path.write_text(json.dumps(sarif, ensure_ascii=False, indent=2), encoding="utf-8")
    return len(vuln_rows)
