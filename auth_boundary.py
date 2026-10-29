from __future__ import annotations

import difflib
import json
import threading
from difflib import SequenceMatcher
from typing import Callable

import httpx

import db


def _make_client(proxy_url: str | None) -> httpx.Client:
    mounts_cfg: dict | None = None
    if proxy_url:
        _t = httpx.HTTPTransport(proxy=proxy_url, verify=False)
        mounts_cfg = {
            "http://":          _t,
            "https://":         _t,
            "http://localhost": _t,
            "https://localhost":_t,
            "http://127.0.0.1": _t,
            "https://127.0.0.1":_t,
        }
    return httpx.Client(
        **(dict(mounts=mounts_cfg) if mounts_cfg else {}),
        verify=False,
        follow_redirects=False,
        timeout=10.0,
        headers={"User-Agent": "notsca-auth-boundary/0.1"},
    )


def _preview_bytes(b: bytes | None, limit: int = 6000) -> str:
    if not b:
        return ""
    try:
        s = b.decode("utf-8", errors="ignore")
    except Exception:
        s = str(b)
    s = s.strip()
    if len(s) > limit:
        return s[:limit] + "\n... (truncated) ..."
    return s


def _diff(a: str, b: str, max_lines: int = 140) -> str:
    a_lines = (a or "").splitlines()
    b_lines = (b or "").splitlines()
    diff = difflib.unified_diff(a_lines, b_lines, fromfile="anon", tofile="auth", lineterm="", n=2)
    out: list[str] = []
    for i, line in enumerate(diff):
        if i >= max_lines:
            out.append("... (diff truncated) ...")
            break
        out.append(line)
    return "\n".join(out).strip()


def check_auth_boundary_single(
    history_row: dict,
    session_headers: dict,
    proxy_url: str | None = None,
) -> dict:
    method = (history_row.get("method") or "GET").upper()
    url = history_row.get("url") or ""

    try:
        base_headers = json.loads(history_row.get("req_headers") or "{}") or {}
    except Exception:
        base_headers = {}
    if not isinstance(base_headers, dict):
        base_headers = {}

    body = history_row.get("req_body") or b""
    if isinstance(body, str):
        body = body.encode("utf-8", errors="ignore")

    # Auth request = base + session (session wins)
    auth_headers = {str(k): str(v) for k, v in base_headers.items()}
    for k, v in (session_headers or {}).items():
        if v is None:
            continue
        auth_headers[str(k)] = str(v)

    # Anon request = base without obvious auth headers
    anon_headers = {str(k): str(v) for k, v in base_headers.items()}
    for k in list(anon_headers.keys()):
        if k.lower() in ("authorization", "cookie"):
            anon_headers.pop(k, None)

    anon_status = None
    auth_status = None
    anon_text = ""
    auth_text = ""
    note = ""

    with _make_client(proxy_url) as client:
        try:
            r_anon = client.request(method, url, headers=anon_headers, content=body)
            anon_status = r_anon.status_code
            anon_text = _preview_bytes(r_anon.content)
        except Exception as e:
            note += f"anon_error={e}; "

        try:
            r_auth = client.request(method, url, headers=auth_headers, content=body)
            auth_status = r_auth.status_code
            auth_text = _preview_bytes(r_auth.content)
        except Exception as e:
            note += f"auth_error={e}; "

    sim = 0.0
    try:
        sim = SequenceMatcher(None, auth_text, anon_text).ratio()
    except Exception:
        sim = 0.0

    accessible_anon = bool((anon_status in (200, 201, 204)) and (sim >= 0.6))
    diff_snippet = _diff(anon_text, auth_text)
    if accessible_anon and not note:
        note = "anon looks similar to auth"
    return {
        "method": method,
        "url": url,
        "anon_status": anon_status,
        "auth_status": auth_status,
        "similarity": float(sim),
        "accessible_anon": 1 if accessible_anon else 0,
        "diff_snippet": diff_snippet,
        "note": note.strip(),
    }


def run_auth_boundary_scan(
    history_ids: list[int],
    session_headers: dict,
    proxy_url: str | None,
    log_cb: Callable[[str], None],
    stop_event: threading.Event,
) -> None:
    for hid in history_ids:
        if stop_event.is_set():
            return
        row = db.fetch_history_by_id(hid)
        if not row:
            log_cb(f"[AUTH] missing history_id={hid}")
            continue
        try:
            res = check_auth_boundary_single(row, session_headers=session_headers, proxy_url=proxy_url)
            db.insert_auth_boundary_result(
                history_id=hid,
                method=res["method"],
                url=res["url"],
                anon_status=res["anon_status"],
                auth_status=res["auth_status"],
                similarity=res["similarity"],
                accessible_anon=bool(res["accessible_anon"]),
                diff_snippet=res["diff_snippet"],
                note=res.get("note") or "",
            )
            log_cb(
                f"[AUTH] BOUNDARY {res['method']} {res['url']} "
                f"anon={res['anon_status']} auth={res['auth_status']} sim={res['similarity']:.2f} "
                f"accessible_anon={res['accessible_anon']}"
            )
        except Exception as e:
            log_cb(f"[AUTH] error history_id={hid}: {e}")

