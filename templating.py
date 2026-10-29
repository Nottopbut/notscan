"""
templating.py — Разбор и мутация raw HTTP-запросов.

Умеет:
  • парсить raw HTTP → (method, url, headers, body)
  • строить raw HTTP из компонентов
  • мутировать:
      - query-параметры
      - application/x-www-form-urlencoded body
      - JSON body
      - заголовки (кастомные)
"""

from __future__ import annotations

import json
import re
import urllib.parse
from dataclasses import dataclass, field, replace
from typing import Any, Optional

PLACEHOLDER = "{{payload}}"

# Режимы WAF-обхода (tamper): будут задействованы движком через
# encode_payload()/apply_payload(..., encoder=mode). Порядок стабилен.
TAMPER_MODES: tuple[str, ...] = ("url", "unicode", "hex", "double-url")


# ──────────────────────────── Data structures ────────────────────────────

@dataclass
class ParsedRequest:
    method: str
    url: str
    http_version: str
    headers: dict[str, str]
    body: bytes

    # Derived helpers
    @property
    def host(self) -> str:
        return self.headers.get("host", self.headers.get("Host", ""))

    @property
    def content_type(self) -> str:
        return self.headers.get("content-type", self.headers.get("Content-Type", ""))


@dataclass
class MutatedRequest:
    """Один мутированный вариант исходного запроса."""
    method: str
    url: str
    headers: dict[str, str]
    body: bytes
    mutation_point: str   # "query" | "body_form" | "body_json" | "header:<name>"
    original_param: str
    raw_http: str = field(default="", repr=False)


# ──────────────────────────── Raw HTTP parser ────────────────────────────

def build_raw_http(
    method: str,
    url: str,
    headers: dict,
    body: Optional[bytes] = None,
) -> str:
    """Сборка raw HTTP из компонентов (без Content-Length — httpx добавит сам)."""
    parsed = urllib.parse.urlparse(url)
    path = parsed.path or "/"
    if parsed.query:
        path += "?" + parsed.query
    lines = [f"{method} {path} HTTP/1.1"]
    # ensure Host header first
    host = headers.get("host", headers.get("Host", parsed.netloc))
    lines.append(f"Host: {host}")
    for k, v in headers.items():
        if k.lower() in ("host", "content-length"):
            continue
        lines.append(f"{k}: {v}")
    lines.append("")
    raw = "\r\n".join(lines) + "\r\n"
    if body:
        try:
            raw += body.decode("utf-8", errors="replace")
        except Exception:
            raw += "<binary body>"
    return raw


def parse_raw_http(raw: str, base_url: str = "") -> ParsedRequest:
    """Разбирает raw HTTP-строку (как сохраняется в history) обратно в объект."""
    # Split head / body
    if "\r\n\r\n" in raw:
        head, _, body_text = raw.partition("\r\n\r\n")
    elif "\n\n" in raw:
        head, _, body_text = raw.partition("\n\n")
    else:
        head = raw
        body_text = ""

    lines = head.splitlines()
    request_line = lines[0] if lines else "GET / HTTP/1.1"
    parts = request_line.split(" ", 2)
    method = parts[0] if len(parts) > 0 else "GET"
    path = parts[1] if len(parts) > 1 else "/"
    http_version = parts[2] if len(parts) > 2 else "HTTP/1.1"

    headers: dict[str, str] = {}
    for line in lines[1:]:
        if ":" in line:
            k, _, v = line.partition(":")
            headers[k.strip()] = v.strip()

    host = headers.get("host", headers.get("Host", ""))

    # Build full URL
    if path.startswith("http://") or path.startswith("https://"):
        url = path
    elif base_url:
        url = base_url.rstrip("/") + path
    elif host:
        scheme = "https" if "443" in host else "http"
        url = f"{scheme}://{host}{path}"
    else:
        url = path

    body_bytes = body_text.encode("utf-8") if body_text else b""
    return ParsedRequest(
        method=method,
        url=url,
        http_version=http_version,
        headers=headers,
        body=body_bytes,
    )


# ──────────────────────────── Mutation functions ────────────────────────────

def mutate_query_params(req: ParsedRequest) -> list[MutatedRequest]:
    """Подставляет PLACEHOLDER в каждый query-параметр по отдельности.

    Важно: PLACEHOLDER хранится в URL в незакодированном виде,
    чтобы apply_payload мог его найти при str.replace.
    При отправке запроса через httpx URL будет перекодирован корректно.
    """
    parsed = urllib.parse.urlparse(req.url)
    params = urllib.parse.parse_qs(parsed.query, keep_blank_values=True)
    if not params:
        return []

    results = []
    for param_name in params:
        new_params = dict(params)
        new_params[param_name] = [PLACEHOLDER]
        # urlencode с quote_via=str чтобы PLACEHOLDER НЕ кодировался
        new_query = urllib.parse.urlencode(new_params, doseq=True, quote_via=lambda s, *a, **kw: s)
        new_url = urllib.parse.urlunparse(
            parsed._replace(query=new_query)
        )
        headers = {k: v for k, v in req.headers.items() if k.lower() != "content-length"}
        raw = build_raw_http(req.method, new_url, headers, req.body)
        results.append(
            MutatedRequest(
                method=req.method,
                url=new_url,
                headers=headers,
                body=req.body,
                mutation_point="query",
                original_param=param_name,
                raw_http=raw,
            )
        )
    return results


def mutate_body_form(req: ParsedRequest) -> list[MutatedRequest]:
    """Подставляет PLACEHOLDER в каждый параметр urlencoded-тела."""
    if not req.body:
        return []
    ct = req.content_type.lower()
    # Никогда не парсим JSON как form
    body_start = req.body.lstrip()[:1]
    if body_start in (b"{", b"["):
        return []
    if "application/x-www-form-urlencoded" not in ct:
        # Попробуем всё равно, если тело похоже на form
        if not re.search(rb"[^=&]+=", req.body):
            return []

    if not req.body:
        return []

    try:
        body_str = req.body.decode("utf-8")
    except UnicodeDecodeError:
        return []

    params = urllib.parse.parse_qs(body_str, keep_blank_values=True)
    if not params:
        return []

    results = []
    for param_name in params:
        new_params = dict(params)
        new_params[param_name] = [PLACEHOLDER]
        # quote_via=str: PLACEHOLDER НЕ кодируется, apply_payload подставит payload в сыром виде
        new_body_str = urllib.parse.urlencode(new_params, doseq=True, quote_via=lambda s, *a, **kw: s)
        new_body = new_body_str.encode("utf-8")
        headers = {k: v for k, v in req.headers.items() if k.lower() != "content-length"}
        raw = build_raw_http(req.method, req.url, headers, new_body)
        results.append(
            MutatedRequest(
                method=req.method,
                url=req.url,
                headers=headers,
                body=new_body,
                mutation_point="body_form",
                original_param=param_name,
                raw_http=raw,
            )
        )
    return results


def mutate_body_json(req: ParsedRequest) -> list[MutatedRequest]:
    """Рекурсивно подставляет PLACEHOLDER в строковые поля JSON-тела."""
    if not req.body:
        return []
    ct = req.content_type.lower()
    # Принимаем JSON если:
    #   a) Content-Type содержит 'json', ИЛИ
    #   b) тело начинается с '{' или '[' (автоопределение)
    body_start = req.body.lstrip()[:1]
    looks_like_json = body_start in (b"{", b"[")
    if "json" not in ct and not looks_like_json:
        return []

    try:
        data = json.loads(req.body.decode("utf-8"))
    except (json.JSONDecodeError, UnicodeDecodeError):
        return []

    def _walk(obj, path=""):
        """Yield (path, mutated_copy)."""
        if isinstance(obj, dict):
            for k, v in obj.items():
                yield from _walk(v, f"{path}.{k}" if path else k)
        elif isinstance(obj, list):
            for i, v in enumerate(obj):
                yield from _walk(v, f"{path}[{i}]")
        elif isinstance(obj, str):
            yield path, obj

    results = []
    for field_path, _original in _walk(data):
        mutated_data = _deep_replace(data, field_path, PLACEHOLDER)
        new_body = json.dumps(mutated_data).encode("utf-8")
        headers = {k: v for k, v in req.headers.items() if k.lower() != "content-length"}
        raw = build_raw_http(req.method, req.url, headers, new_body)
        results.append(
            MutatedRequest(
                method=req.method,
                url=req.url,
                headers=headers,
                body=new_body,
                mutation_point="body_json",
                original_param=field_path,
                raw_http=raw,
            )
        )
    return results


def _deep_replace(obj, path: str, value):
    """Возвращает глубокую копию obj с заменой по пути path."""
    parts = _split_path(path)

    def _replace(node, remaining):
        if not remaining:
            return value
        key = remaining[0]
        rest = remaining[1:]
        if isinstance(node, dict) and key in node:
            copy = dict(node)
            copy[key] = _replace(node[key], rest)
            return copy
        if isinstance(node, list):
            try:
                idx = int(key.strip("[]"))
                copy = list(node)
                copy[idx] = _replace(node[idx], rest)
                return copy
            except (ValueError, IndexError):
                pass
        return node  # unchanged

    return _replace(obj, parts)


def _split_path(path: str) -> list[str]:
    """'a.b[0].c' → ['a', 'b', '[0]', 'c']"""
    parts = []
    for segment in re.split(r"\.", path):
        sub = re.split(r"(\[\d+\])", segment)
        for s in sub:
            if s:
                parts.append(s)
    return parts


INJECTABLE_HEADERS = [
    "User-Agent",
    "Referer",
    "X-Forwarded-For",
    "X-Custom-Header",
    "Cookie",
]


def mutate_headers(req: ParsedRequest) -> list[MutatedRequest]:
    """Подставляет PLACEHOLDER в значения каждого «интересного» заголовка."""
    results = []
    for header_name in INJECTABLE_HEADERS:
        # Check case-insensitive
        matched = None
        for k in req.headers:
            if k.lower() == header_name.lower():
                matched = k
                break
        if matched is None:
            continue

        new_headers = {k: v for k, v in req.headers.items() if k.lower() != "content-length"}
        new_headers[matched] = PLACEHOLDER
        raw = build_raw_http(req.method, req.url, new_headers, req.body)
        results.append(
            MutatedRequest(
                method=req.method,
                url=req.url,
                headers=new_headers,
                body=req.body,
                mutation_point=f"header:{matched}",
                original_param=matched,
                raw_http=raw,
            )
        )
    return results


def get_mutations(
    req: ParsedRequest,
    do_query: bool = True,
    do_body_form: bool = True,
    do_body_json: bool = True,
    do_headers: bool = False,
) -> list[MutatedRequest]:
    """Возвращает все мутации по выбранным точкам."""
    result = []
    if do_query:
        result.extend(mutate_query_params(req))
    if do_body_form:
        result.extend(mutate_body_form(req))
    if do_body_json:
        result.extend(mutate_body_json(req))
    if do_headers:
        result.extend(mutate_headers(req))
    return result


# ──────────────────────────── Tamper / WAF-bypass encoders ────────────────────────────

def encode_payload(payload: str, mode: str) -> str:
    """
    Кодирует payload для обхода WAF (tamper).

    Режимы (стиль задокументирован и покрыт тестами):
      • "url"        — обычное URL-кодирование (urllib.parse.quote, safe=""):
                       "<script>" → "%3Cscript%3E".
      • "unicode"    — каждый символ → "%uXXXX" (uppercase-HEX, стиль IIS/ASP):
                       "<" → "%u003C". Для символов вне BMP — пара суррогатов.
      • "hex"        — каждый БАЙТ UTF-8 → "%XX" (в отличие от "url" кодируются
                       и буквы/цифры): "AB" → "%41%42".
      • "double-url" — двойное URL-кодирование: "%3C" → "%253C".

    Неизвестный mode → ValueError.
    """
    if mode == "url":
        return urllib.parse.quote(payload, safe="")
    if mode == "unicode":
        out = []
        for ch in payload:
            cp = ord(ch)
            if cp <= 0xFFFF:
                out.append(f"%u{cp:04X}")
            else:
                # surrogate pair (UTF-16) для символов вне BMP
                cp -= 0x10000
                out.append(f"%u{0xD800 + (cp >> 10):04X}%u{0xDC00 + (cp & 0x3FF):04X}")
        return "".join(out)
    if mode == "hex":
        return "".join(f"%{b:02X}" for b in payload.encode("utf-8"))
    if mode == "double-url":
        return urllib.parse.quote(urllib.parse.quote(payload, safe=""), safe="")
    raise ValueError(
        f"unknown tamper mode {mode!r}; expected one of {TAMPER_MODES}"
    )


def apply_payload(
    mutation: MutatedRequest,
    payload: str,
    *,
    encoder: Optional[str] = None,
) -> tuple[str, dict, bytes]:
    """Подставляет payload вместо PLACEHOLDER. Возвращает (url, headers, body).

    В URL payload кодируется через urllib.parse.quote (safe=''),
    в headers и body — подставляется как есть (строка).

    ``encoder``: сначала payload прогоняется через encode_payload(payload, encoder),
    затем подставляется (tamper/WAF-bypass, см. TAMPER_MODES).

    Баг #3: для mutation_point == "body_json" payload экранируется как
    JSON-строка (json.dumps(sub)[1:-1]), поэтому тело остаётся валидным JSON
    даже для payload с кавычками/бэкслешами/переводами строк.
    """
    sub = encode_payload(payload, encoder) if encoder else payload

    # URL: PLACEHOLDER хранится в незакодированном виде → кодируем payload перед заменой
    url = mutation.url.replace(PLACEHOLDER, urllib.parse.quote(sub, safe=""))
    # Headers: plain replacement
    headers = {k: v.replace(PLACEHOLDER, sub) for k, v in mutation.headers.items()}
    # Body: для JSON-мутации подстановка должна быть JSON-escaped, иначе ломается
    # структура тела (баг #3). Для form/plain body — как раньше.
    body_sub = json.dumps(sub)[1:-1] if mutation.mutation_point == "body_json" else sub
    try:
        body_str = mutation.body.decode("utf-8")
        body = body_str.replace(PLACEHOLDER, body_sub).encode("utf-8")
    except UnicodeDecodeError:
        body = mutation.body
    return url, headers, body


# ──────────────────────────── CSRF-токены ────────────────────────────

CSRF_FIELD_NAMES: tuple[str, ...] = (
    "csrf",
    "csrf_token",
    "_csrf",
    "csrftoken",
    "_token",
    "xsrf_token",
    "authenticity_token",
    "__requestverificationtoken",
)

# Имена CSRF-заголовков (для patch_csrf_token).
CSRF_HEADER_NAMES: tuple[str, ...] = ("x-csrf-token", "x-xsrf-token", "x-csrftoken")

_CSRF_NAMES_NORMALIZED = frozenset(n.replace("-", "_") for n in CSRF_FIELD_NAMES)
_CSRF_HEADERS_NORMALIZED = frozenset(n.replace("-", "_") for n in CSRF_HEADER_NAMES)

_ATTR_RE = re.compile(
    r"""([A-Za-z_:][-A-Za-z0-9_:.]*)\s*=\s*(?:"([^"]*)"|'([^']*)'|([^\s"'=<>`]+))"""
)
_INPUT_TAG_RE = re.compile(r"<input\b[^>]*>", re.IGNORECASE | re.DOTALL)
_META_TAG_RE = re.compile(r"<meta\b[^>]*>", re.IGNORECASE | re.DOTALL)


def _normalize_csrf_name(name: str) -> str:
    """csrf-token / CSRF_TOKEN / csrfToken → csrf_token."""
    return (name or "").strip().lower().replace("-", "_")


def _is_csrf_field_name(name: str) -> bool:
    return _normalize_csrf_name(name) in _CSRF_NAMES_NORMALIZED


def _parse_tag_attributes(tag: str) -> dict[str, str]:
    """Атрибуты HTML-тега → dict (имена в lower-case, порядок не важен)."""
    attrs: dict[str, str] = {}
    for m in _ATTR_RE.finditer(tag):
        key = m.group(1).lower()
        value = m.group(2)
        if value is None:
            value = m.group(3)
        if value is None:
            value = m.group(4)
        attrs.setdefault(key, value or "")
    return attrs


def extract_csrf_token(html: str) -> Optional[str]:
    """
    Извлекает CSRF-токен из HTML страницы.

    Поддерживает:
      • <input ... name="<field>" ... value="..."> (порядок атрибутов любой,
        кавычки одинарные/двойные/без них, имя в любом регистре);
      • <meta name="csrf-token" content="...">;
      • имена из CSRF_FIELD_NAMES (csrf, _token, authenticity_token, …).

    Возвращает None, если токен не найден.
    """
    if not html:
        return None
    for tag in _INPUT_TAG_RE.findall(html):
        attrs = _parse_tag_attributes(tag)
        if _is_csrf_field_name(attrs.get("name", "")):
            token = attrs.get("value", "")
            if token:
                return token
    for tag in _META_TAG_RE.findall(html):
        attrs = _parse_tag_attributes(tag)
        if _is_csrf_field_name(attrs.get("name", "")):
            token = attrs.get("content", "")
            if token:
                return token
    return None


def _csrf_name_alternation() -> str:
    """Regex-альтернатива имён CSRF-полей (включая вариант с дефисом)."""
    aliases: set[str] = set()
    for name in CSRF_FIELD_NAMES:
        aliases.add(name)
        aliases.add(name.replace("_", "-"))
    return "|".join(re.escape(a) for a in sorted(aliases, key=len, reverse=True))


_CSRF_PAIR_RE = re.compile(
    r"(?P<lead>^|&)(?P<name>" + _csrf_name_alternation() + r")(?P<eq>=)(?P<value>[^&]*)",
    re.IGNORECASE,
)


def _replace_csrf_in_pairs(pairs: str, token: str) -> tuple[str, bool]:
    """Заменяет значение csrf-параметра в urlencoded-строке (query или form body)."""
    found = False

    def _sub(m: re.Match) -> str:
        nonlocal found
        found = True
        quoted = urllib.parse.quote(token, safe="")
        return f"{m.group('lead')}{m.group('name')}{m.group('eq')}{quoted}"

    return _CSRF_PAIR_RE.sub(_sub, pairs), found


def _set_csrf_in_json(obj: Any, token: str) -> tuple[Any, bool]:
    """Рекурсивно заменяет строковые значения CSRF-полей в JSON-структуре."""
    if isinstance(obj, dict):
        changed = False
        out: dict = {}
        for key, value in obj.items():
            if (
                isinstance(key, str)
                and _is_csrf_field_name(key)
                and isinstance(value, str)
            ):
                out[key] = token
                changed = True
            else:
                new_value, child_changed = _set_csrf_in_json(value, token)
                out[key] = new_value
                changed = changed or child_changed
        return out, changed
    if isinstance(obj, list):
        changed = False
        out_list: list = []
        for item in obj:
            new_item, child_changed = _set_csrf_in_json(item, token)
            out_list.append(new_item)
            changed = changed or child_changed
        return out_list, changed
    return obj, False


def patch_csrf_token(mutation: MutatedRequest, token: str) -> MutatedRequest:
    """
    Возвращает КОПИЮ mutation с актуальным CSRF-токеном (сохраняя PLACEHOLDER).

    • body_form — меняется только значение csrf-поля в urlencoded-теле;
    • body_json — заменяется строковое значение csrf-поля (JSON остаётся валидным);
    • headers   — X-CSRF-Token / X-XSRF-TOKEN (если есть);
    • query     — csrf-параметр.

    PLACEHOLDER в ДРУГИХ полях не трогается. Если сама мутация нацелена на
    CSRF-поле, его значение тоже заменяется на token (запрос остаётся валидным
    с точки зрения CSRF; подстановка payload в это поле смысла не имеет).
    """
    url = mutation.url
    headers = dict(mutation.headers)
    body = mutation.body

    point = (mutation.mutation_point or "").lower()
    if point == "body_form":
        try:
            body_str = body.decode("utf-8")
        except UnicodeDecodeError:
            body_str = ""
        if body_str:
            new_body_str, _found = _replace_csrf_in_pairs(body_str, token)
            body = new_body_str.encode("utf-8")
    elif point == "body_json":
        try:
            payload_obj = json.loads(body.decode("utf-8"))
        except (json.JSONDecodeError, UnicodeDecodeError):
            payload_obj = None
        if payload_obj is not None:
            patched, _found = _set_csrf_in_json(payload_obj, token)
            body = json.dumps(patched).encode("utf-8")

    # Заголовки (X-CSRF-Token / X-XSRF-TOKEN) — если присутствуют.
    for key in list(headers):
        if _normalize_csrf_name(key) in _CSRF_HEADERS_NORMALIZED:
            headers[key] = token

    # Query-параметр, если он есть.
    try:
        split = urllib.parse.urlsplit(url)
        if split.query:
            new_query, found = _replace_csrf_in_pairs(split.query, token)
            if found:
                url = urllib.parse.urlunsplit(split._replace(query=new_query))
    except ValueError:
        pass

    raw_http = build_raw_http(mutation.method, url, headers, body)
    return replace(
        mutation,
        url=url,
        headers=headers,
        body=body,
        raw_http=raw_http,
    )
