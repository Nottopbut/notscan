import json
import re
from urllib.parse import urlsplit, parse_qsl

import db


_UUID_RE = re.compile(
    r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$"
)
_B64_RE = re.compile(r"^[A-Za-z0-9+/]+={0,2}$")
_SLUG_RE = re.compile(r"^[a-z0-9]+(?:-[a-z0-9]+){0,10}$", re.IGNORECASE)
_EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")


def normalize_url_pattern(url: str) -> str:
    """
    Normalize URL into a stable path pattern:
    - strips scheme/host and query string (keeps only path)
    - replaces path segments that look like ids with placeholders
    """
    try:
        parts = urlsplit(url)
        path = parts.path or "/"
    except Exception:
        path = url.split("?", 1)[0] or "/"

    segments = [s for s in path.split("/") if s != ""]
    out: list[str] = []
    for seg in segments:
        if seg.isdigit():
            out.append("{int}")
            continue
        if _UUID_RE.match(seg):
            out.append("{uuid}")
            continue
        if len(seg) >= 12 and all(c in "0123456789abcdefABCDEF" for c in seg):
            out.append("{hex}")
            continue
        # Slugs are usually hyphenated; avoid turning stable path segments (api/users) into placeholders.
        if "-" in seg and _SLUG_RE.match(seg) and not seg.isdigit() and len(seg) >= 3:
            out.append("{slug}")
            continue
        out.append(seg)
    return "/" + "/".join(out) if out else "/"


def infer_param_type(name: str, value: str) -> str:
    v = (value or "").strip()
    if v == "":
        return "str"

    low = v.lower()
    if low in ("true", "false", "0", "1") and name.lower() in ("enabled", "active", "disabled", "admin", "debug"):
        return "bool"
    if low in ("true", "false"):
        return "bool"

    if v.isdigit() or (v.startswith("-") and v[1:].isdigit()):
        return "int"
    try:
        float(v)
        if "." in v:
            return "float"
    except Exception:
        pass

    if _UUID_RE.match(v):
        return "uuid"
    if _EMAIL_RE.match(v):
        return "email"
    if low.startswith(("http://", "https://")):
        return "url"
    if "/" in v and not low.startswith(("http://", "https://")) and len(v) <= 200:
        return "path"

    if (v.startswith("{") and v.endswith("}")) or (v.startswith("[") and v.endswith("]")):
        try:
            json.loads(v)
            return "json"
        except Exception:
            pass

    if len(v) >= 16 and len(v) % 4 == 0 and _B64_RE.match(v):
        return "base64"

    return "str"


def extract_json_schema(data, depth: int = 0, max_depth: int = 3):
    if depth >= max_depth:
        return "…"

    if data is None:
        return "null"
    if isinstance(data, bool):
        return "bool"
    if isinstance(data, int) and not isinstance(data, bool):
        return "int"
    if isinstance(data, float):
        return "float"
    if isinstance(data, str):
        return infer_param_type("", data)

    if isinstance(data, list):
        if not data:
            return ["unknown"]
        return [extract_json_schema(data[0], depth + 1, max_depth)]

    if isinstance(data, dict):
        out: dict = {}
        for k, v in list(data.items())[:200]:
            out[str(k)] = extract_json_schema(v, depth + 1, max_depth)
        return out

    return "unknown"


def _merge_schema(a, b):
    if a == b:
        return a
    if isinstance(a, dict) and isinstance(b, dict):
        out = dict(a)
        for k, v in b.items():
            if k in out:
                out[k] = _merge_schema(out[k], v)
            else:
                out[k] = v
        return out
    if isinstance(a, list) and isinstance(b, list) and a and b:
        return [_merge_schema(a[0], b[0])]
    if isinstance(a, list) and isinstance(b, list):
        return a or b
    # fall back to union marker
    return "mixed"


def build_contract_from_rows(rows: list[dict]) -> dict:
    if not rows:
        raise ValueError("rows is empty")

    method = rows[0].get("method") or ""
    url_pattern = normalize_url_pattern(rows[0].get("url") or "")

    param_type_votes: dict[str, dict[str, int]] = {}
    param_presence: dict[str, int] = {}
    expected_codes: set[int] = set()
    content_type = ""
    merged_schema = {}

    for r in rows:
        if r.get("resp_status") is not None:
            try:
                expected_codes.add(int(r["resp_status"]))
            except Exception:
                pass

        rh = r.get("resp_headers") or ""
        if not content_type and "content-type" in rh.lower():
            # resp_headers stored as raw text/json-ish; best-effort extraction
            m = re.search(r"content-type\s*:\s*([^\r\n;]+)", rh, flags=re.IGNORECASE)
            if m:
                content_type = m.group(1).strip()

        url = r.get("url") or ""
        try:
            q = dict(parse_qsl(urlsplit(url).query, keep_blank_values=True))
        except Exception:
            q = {}
        for k, v in q.items():
            param_presence[k] = param_presence.get(k, 0) + 1
            t = infer_param_type(k, v)
            param_type_votes.setdefault(k, {})
            param_type_votes[k][t] = param_type_votes[k].get(t, 0) + 1

        body = r.get("req_body")
        if body is not None:
            try:
                if isinstance(body, (bytes, bytearray)):
                    body_text = body.decode("utf-8", errors="ignore")
                else:
                    body_text = str(body)
                if body_text.strip().startswith(("{", "[")):
                    parsed = json.loads(body_text)
                    if isinstance(parsed, dict):
                        for k, v in parsed.items():
                            param_presence[k] = param_presence.get(k, 0) + 1
                            t = infer_param_type(str(k), str(v))
                            param_type_votes.setdefault(str(k), {})
                            param_type_votes[str(k)][t] = param_type_votes[str(k)].get(t, 0) + 1
            except Exception:
                pass

        resp_preview = r.get("resp_body_preview")
        if resp_preview is not None:
            try:
                if isinstance(resp_preview, (bytes, bytearray)):
                    resp_text = resp_preview.decode("utf-8", errors="ignore")
                else:
                    resp_text = str(resp_preview)
                resp_text_s = resp_text.strip()
                if resp_text_s.startswith(("{", "[")):
                    parsed = json.loads(resp_text_s)
                    merged_schema = _merge_schema(merged_schema, extract_json_schema(parsed))
            except Exception:
                pass

    param_types: dict[str, str] = {}
    for k, votes in param_type_votes.items():
        best = sorted(votes.items(), key=lambda x: (-x[1], x[0]))[0][0]
        param_types[k] = best

    required_params = sorted([k for k, c in param_presence.items() if c >= max(2, int(0.8 * len(rows)))])

    return {
        "method": method,
        "url_pattern": url_pattern,
        "param_types": param_types,
        "required_params": required_params,
        "expected_codes": sorted(list(expected_codes)),
        "resp_schema": merged_schema if merged_schema else {},
        "content_type": content_type,
        "sample_count": len(rows),
    }


def infer_all_contracts(log_cb=None, limit: int = 5000) -> int:
    rows = db.fetch_history(limit=limit)
    groups: dict[tuple[str, str], list[dict]] = {}

    for r in rows:
        method = r.get("method") or ""
        pat = normalize_url_pattern(r.get("url") or "")
        groups.setdefault((method, pat), []).append(r)

    upserted = 0
    for (method, pat), rs in sorted(groups.items(), key=lambda x: (-len(x[1]), x[0][0], x[0][1])):
        try:
            c = build_contract_from_rows(rs)
            db.upsert_endpoint_contract(
                method=method,
                url_pattern=pat,
                param_types=c["param_types"],
                required_params=c["required_params"],
                expected_codes=c["expected_codes"],
                resp_schema=c["resp_schema"],
                content_type=c["content_type"],
                sample_count=c["sample_count"],
            )
            upserted += 1
            if log_cb:
                log_cb(f"[CONTRACT] {method} {pat} samples={c['sample_count']}")
        except Exception as e:
            if log_cb:
                log_cb(f"[CONTRACT] skip {method} {pat}: {e}")
    return upserted

