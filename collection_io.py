"""
collection_io.py — импорт/экспорт коллекций HTTP-запросов.

Поддерживаемые форматы:
  • Raw HTTP (.http / .txt) — запросы, разделённые строкой "###"
  • HAR 1.2 (.har)          — экспорт браузера / Burp / DevTools
  • Postman v2.1 (.json)    — коллекции Postman

Внутренний формат записи (для вставки в history):
  {"method": str, "url": str, "headers": dict, "body": bytes}

Формат raw-HTTP коллекции:
    ### METHOD https://host/path          ← комментарий несёт полный URL (схему)
    POST /path HTTP/1.1
    Host: host
    Header: value

    body

Схема (http/https) восстанавливается из комментария-разделителя,
т.к. сам raw-request хранит только Host без схемы.
"""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Optional
from urllib.parse import urlencode

from templating import parse_raw_http, build_raw_http

_URL_RE = re.compile(r"https?://\S+")


# ──────────────────────────── Export ────────────────────────────

def _norm_headers(r: dict) -> dict:
    h = r.get("headers", r.get("req_headers")) or {}
    if isinstance(h, str):
        try:
            h = json.loads(h)
        except Exception:
            h = {}
    return h if isinstance(h, dict) else {}


def _norm_body(r: dict) -> bytes:
    b = r.get("body", r.get("req_body")) or b""
    if isinstance(b, str):
        return b.encode("utf-8", errors="replace")
    return b


def export_raw_http(records: list[dict], filepath) -> int:
    """Экспортирует список записей в raw-HTTP коллекцию. Возвращает кол-во записанных."""
    blocks: list[str] = []
    for r in records:
        method = (r.get("method") or "GET").upper()
        url = r.get("url") or ""
        if not url:
            continue
        headers = _norm_headers(r)
        body = _norm_body(r)
        block = build_raw_http(method, url, headers, body).replace("\r\n", "\n").rstrip()
        blocks.append(f"### {method} {url}\n{block}")
    text = "\n\n".join(blocks) + "\n"
    Path(filepath).write_text(text, encoding="utf-8")
    return len(blocks)


def _postman_url(url: str) -> dict:
    """Разбирает URL в структуру Postman url (host/path/query/port)."""
    from urllib.parse import urlparse, parse_qsl
    p = urlparse(url)
    host = p.hostname or ""
    out = {
        "raw": url,
        "protocol": p.scheme or "http",
        "host": host.split(".") if host else [],
        "path": [seg for seg in (p.path or "").split("/") if seg],
    }
    if p.port:
        out["port"] = str(p.port)
    query = [{"key": k, "value": v} for k, v in parse_qsl(p.query, keep_blank_values=True)]
    if query:
        out["query"] = query
    return out


def export_postman(records: list[dict], filepath) -> int:
    """Экспортирует записи в Postman Collection v2.1. Возвращает кол-во записанных."""
    items: list[dict] = []
    for r in records:
        method = (r.get("method") or "GET").upper()
        url = r.get("url") or ""
        if not url:
            continue
        headers = _norm_headers(r)
        body = _norm_body(r)

        item = {
            "name": f"{method} {url}",
            "request": {
                "method": method,
                "header": [{"key": k, "value": str(v)} for k, v in headers.items()],
                "url": _postman_url(url),
            },
        }
        if body:
            ct = ""
            for k, v in headers.items():
                if k.lower() == "content-type":
                    ct = str(v).lower()
                    break
            item["request"]["body"] = {
                "mode": "raw",
                "raw": body.decode("utf-8", errors="replace"),
                "options": {"raw": {"language": "json" if "json" in ct else "text"}},
            }
        items.append(item)

    data = {
        "info": {
            "name": "notscan export",
            "schema": "https://schema.getpostman.com/json/collection/v2.1.0/collection.json",
        },
        "item": items,
    }
    Path(filepath).write_text(json.dumps(data, indent=2, ensure_ascii=False), encoding="utf-8")
    return len(items)


# ──────────────────────────── Import ────────────────────────────

def parse_raw_http_collection(text: str) -> list[dict]:
    """Разбирает raw-HTTP коллекцию (разделитель '###') в список записей.

    Схема URL восстанавливается из комментария '### METHOD <full_url>'
    (если он есть); иначе — из Host-заголовка (http по умолчанию).
    """
    records: list[dict] = []
    lines = text.splitlines()
    current: list[str] = []
    url_hint: Optional[str] = None

    def _flush() -> None:
        nonlocal current, url_hint
        if not current:
            current = []
            url_hint = None
            return
        block = "\n".join(current).strip()
        current = []
        hint = url_hint
        url_hint = None
        if not block:
            return
        try:
            parsed = parse_raw_http(block)
        except Exception:
            return
        url = parsed.url or ""
        if hint and "://" in hint:
            url = hint  # полный URL из комментария (сохраняет схему)
        if not url or "://" not in url:
            return
        records.append({
            "method": parsed.method.upper(),
            "url": url,
            "headers": parsed.headers,
            "body": parsed.body,
        })

    for line in lines:
        if line.strip().startswith("###"):
            _flush()
            comment = line.strip()[3:].strip()
            m = _URL_RE.search(comment)
            url_hint = m.group(0) if m else None
        else:
            current.append(line)
    _flush()
    return records


def parse_har(path) -> list[dict]:
    data = json.loads(Path(path).read_text(encoding="utf-8", errors="replace"))
    records: list[dict] = []
    entries = (data.get("log") or {}).get("entries") or []
    for e in entries:
        req = e.get("request") or {}
        method = (req.get("method") or "GET").upper()
        url = req.get("url") or ""
        if not url or "://" not in url:
            continue
        headers: dict[str, str] = {}
        for h in (req.get("headers") or []):
            name = h.get("name")
            value = h.get("value")
            if name:
                headers[str(name)] = str(value or "")
        body = b""
        post = req.get("postData") or {}
        if post.get("text"):
            body = str(post["text"]).encode("utf-8", errors="replace")
        records.append({"method": method, "url": url, "headers": headers, "body": body})
    return records


_VAR_RE = re.compile(r"\{\{\s*([^{}]+?)\s*\}\}")


def _extract_vars(text: str) -> set[str]:
    return {m.group(1).strip() for m in _VAR_RE.finditer(text or "") if m.group(1).strip()}


def _resolve_text(text: str, variables: dict, depth: int = 5) -> str:
    """Подставляет {{var}} из variables (повторно до depth, если значения ссылаются друг на друга)."""
    if not text or not variables:
        return text
    out = str(text)
    for _ in range(max(1, depth)):
        def _sub(m: re.Match) -> str:
            name = m.group(1).strip()
            if name in variables and variables[name] is not None:
                return str(variables[name])
            return m.group(0)
        new = _VAR_RE.sub(_sub, out)
        if new == out:
            break
        out = new
    return out


def _resolve_record(rec: dict, variables: dict) -> dict:
    """Возвращает копию записи с подставленными {{var}} в url/headers/body."""
    if not variables:
        return rec
    headers = {k: _resolve_text(v, variables) for k, v in (rec.get("headers") or {}).items()}
    body = rec.get("body") or b""
    if isinstance(body, bytes):
        try:
            body = _resolve_text(body.decode("utf-8", errors="replace"), variables).encode("utf-8")
        except Exception:
            pass
    return {
        "method": rec.get("method") or "GET",
        "url": _resolve_text(rec.get("url") or "", variables),
        "headers": headers,
        "body": body,
    }


def _postman_variable_list(data: dict) -> list:
    """Переменные коллекции Postman (data['variable']) в едином виде."""
    out = []
    for item in (data.get("variable") or []):
        if isinstance(item, dict):
            key = item.get("key") or item.get("id")
            if key:
                out.append({"key": str(key), "value": item.get("value"),
                            "enabled": not bool(item.get("disabled"))})
    return out


def postman_collection_variables(path) -> dict:
    """Переменные, объявленные внутри Postman-коллекции (data.variable)."""
    data = json.loads(Path(path).read_text(encoding="utf-8", errors="replace"))
    if not isinstance(data, dict) or "item" not in data:
        return {}
    out: dict[str, str] = {}
    for v in _postman_variable_list(data):
        if v.get("enabled") and v.get("value") is not None:
            out[str(v["key"])] = str(v["value"])
    return out


def postman_environment(path) -> dict:
    """Читает Postman environment/globals JSON и возвращает {key: value}.

    Поддерживает:
      • Postman environment/globals: {"values": [{"key","value","enabled"}]};
      • плоский dict {"baseUrl": "http://..."};
      • {"environment": {...}}.
    Отключённые (enabled=false/disabled=true) переменные пропускаются.
    """
    data = json.loads(Path(path).read_text(encoding="utf-8", errors="replace"))
    if not isinstance(data, dict):
        raise ValueError("Not a Postman environment file")
    values = data.get("values")
    if values is None and isinstance(data.get("environment"), dict):
        values = data["environment"]
    out: dict[str, str] = {}
    if isinstance(values, list):
        for item in values:
            if not isinstance(item, dict):
                continue
            key = item.get("key") or item.get("id")
            if not key:
                continue
            if item.get("enabled") is False or item.get("disabled") is True:
                continue
            value = item.get("value")
            if value is not None:
                out[str(key)] = str(value)
    elif isinstance(values, dict):
        for key, value in values.items():
            if value is not None:
                out[str(key)] = str(value)
    elif "values" not in data:
        # плоский словарь переменных
        for key, value in data.items():
            if isinstance(value, (str, int, float, bool)):
                out[str(key)] = str(value)
    return out


def _all_postman_strings(data: dict) -> list[str]:
    """Все строки коллекции, где могут встречаться {{переменные}}."""
    found: list[str] = []

    def _walk(item) -> None:
        if isinstance(item, str):
            found.append(item)
        elif isinstance(item, dict):
            for k, v in item.items():
                if k in ("response", "auth", "script", "event"):
                    continue
                _walk(v)
        elif isinstance(item, list):
            for v in item:
                _walk(v)

    _walk(data.get("item") or [])
    return found


def postman_missing_variables(path, environment=None) -> list[str]:
    """Неразрешённые переменные {{...}} коллекции с учётом collection-vars/окружения.

    environment: dict | path к Postman environment JSON | None.
    Возвращает отсортированный список имён; [] — окружение не требуется.
    """
    data = json.loads(Path(path).read_text(encoding="utf-8", errors="replace"))
    if not isinstance(data, dict) or "item" not in data:
        return []
    env_vars: dict[str, str] = {}
    if environment:
        try:
            env_vars = (
                dict(environment) if isinstance(environment, dict)
                else postman_environment(environment)
            )
        except Exception:
            env_vars = {}
    known: dict[str, str] = {}
    for v in _postman_variable_list(data):
        if v.get("enabled") and v.get("value") is not None:
            known[str(v["key"])] = str(v["value"])
    known.update({str(k): str(v) for k, v in env_vars.items() if v is not None})
    missing: set[str] = set()
    for text in _all_postman_strings(data):
        for name in _extract_vars(text):
            # переменная, объявленная в env/collection (возможно пустая) — не missing
            if name not in known:
                missing.add(name)
    return sorted(missing)


def parse_postman(path, variables: Optional[dict] = None) -> list[dict]:
    data = json.loads(Path(path).read_text(encoding="utf-8", errors="replace"))
    records: list[dict] = []
    collection_vars: dict[str, str] = {}
    for v in _postman_variable_list(data):
        if v.get("enabled") and v.get("value") is not None:
            collection_vars[str(v["key"])] = str(v["value"])
    resolve_vars: dict[str, str] = dict(collection_vars)
    if variables:
        resolve_vars.update({str(k): str(v) for k, v in variables.items() if v is not None})

    def _postman_request(req: dict) -> dict:
        method = (req.get("method") or "GET").upper()
        url_obj = req.get("url") or {}
        url = url_obj.get("raw") or ""
        if not url:
            host = url_obj.get("host") or []
            if host and isinstance(host, list):
                url = "http://" + ".".join(host)
                path = url_obj.get("path") or []
                if path:
                    url += "/" + "/".join(str(p) for p in path)
                query = url_obj.get("query") or []
                if query:
                    url += "?" + urlencode([(q.get("key", ""), q.get("value", "")) for q in query])
            else:
                url = ""
        headers: dict[str, str] = {}
        for h in (req.get("header") or []):
            k = h.get("key")
            v = h.get("value")
            if k:
                headers[str(k)] = str(v or "")
        body = b""
        b_obj = req.get("body") or {}
        mode = b_obj.get("mode")
        if mode == "raw" and b_obj.get("raw"):
            body = str(b_obj["raw"]).encode("utf-8", errors="replace")
        elif mode == "urlencoded":
            pairs = [(f.get("key", ""), f.get("value", "")) for f in (b_obj.get("urlencoded") or [])]
            body = urlencode(pairs).encode("utf-8", errors="replace")
        return {"method": method, "url": url, "headers": headers, "body": body}

    def _walk(items):
        for it in items or []:
            req = it.get("request")
            if req:
                rec = _postman_request(req)
                if rec["url"]:
                    records.append(_resolve_record(rec, resolve_vars))
            _walk(it.get("item") or [])

    _walk(data.get("item") or [])
    return records


def import_collection(path, variables: Optional[dict] = None) -> list[dict]:
    """Автоопределение формата по расширению/содержимому.

    variables: значения Postman-окружения для подстановки {{var}} (только Postman).
    """
    p = Path(path)
    ext = p.suffix.lower()
    text = p.read_text(encoding="utf-8", errors="replace")

    if ext == ".har":
        return parse_har(p)
    if ext == ".json":
        try:
            data = json.loads(text)
        except Exception:
            return []
        if isinstance(data, dict) and "item" in data:
            return parse_postman(p, variables=variables)
        if isinstance(data, dict) and "log" in data:
            return parse_har(p)
        return []
    # default: raw HTTP
    return parse_raw_http_collection(text)
