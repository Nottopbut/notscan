"""
checks/fp_rules.py — Правила подавления ложных срабатываний (FP) для XSS.

Баг #4: проверки XSS флагали:
  • «голые» HTML-теги (`<body>`, `<script>`) — они уже есть в HTML-скелете
    любой страницы и не являются исполняемым вектором без содержимого/атрибутов;
  • отражение payload в JSON/plain-ответах — это не XSS;
  • значения, которые присутствовали в baseline-ответе ещё без нашего payload.

Модуль общий: его импортирует и checks-слой (XSSReflectedCheck), и matcher-слой
(scanner_core.match_xss). Публичные имена стабильны.
"""

from __future__ import annotations

import re
import urllib.parse

# Один «голый» HTML-тег без атрибутов: <body>, </html>, <br/>, <svg >.
_BARE_TAG_RE = re.compile(r"</?[A-Za-z][A-Za-z0-9-]*\s*/?>")

# MIME-типы, в которых отражение payload может быть исполняемым (HTML/XML).
_HTML_MIME_TYPES = frozenset({
    "text/html",
    "application/xhtml+xml",
    "text/xml",
})


def is_bare_html_tag(payload: str) -> bool:
    """
    True, если payload после strip — ровно ОДИН «голый» HTML-тег без атрибутов.

    Примеры True:  "<body>", "<script>", "<img>", "<svg>", "</html>", "<title>", "<br/>"
    Примеры False: "<script>alert(1)</script>", "<img src=x onerror=alert(1)>",
                   "<body onload=alert(1)>", "<input type=text>", "text<body>".
    """
    if not payload:
        return False
    return _BARE_TAG_RE.fullmatch(payload.strip()) is not None


def _get_header(headers: dict | None, name: str) -> str | None:
    """Case-insensitive lookup значения заголовка."""
    if not headers:
        return None
    if name in headers:
        return headers[name]
    lowered = name.lower()
    for key, value in headers.items():
        if str(key).lower() == lowered:
            return value
    return None


def is_html_response(headers: dict | None) -> bool:
    """
    True, если Content-Type ответа подразумевает HTML/XML-документ.

    • Content-Type отсутствует → True (не сужаем старые сценарии/тесты);
    • text/html, application/xhtml+xml, text/xml → True;
    • application/json, text/plain и прочие → False.
    """
    content_type = _get_header(headers, "content-type")
    if content_type is None:
        return True
    mime = str(content_type).split(";", 1)[0].strip().lower()
    if not mime:
        return True
    return mime in _HTML_MIME_TYPES


def payload_in_baseline(payload: str, baseline_text: str) -> bool:
    """
    True, если payload (или его URL-encoded форма) уже был в baseline-ответе.

    Такой сигнал не является следствием нашей инъекции → подавляем находку.
    """
    if not payload or not baseline_text:
        return False
    if payload in baseline_text:
        return True
    encoded = urllib.parse.quote(payload, safe="")
    if encoded != payload and encoded in baseline_text:
        return True
    return False
