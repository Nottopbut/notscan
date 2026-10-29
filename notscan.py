"""
notscan.py — Главный GUI-файл приложения (tkinter).

Запуск:
    python notscan.py
"""

from __future__ import annotations

import atexit
import json
import os
import subprocess
import sys
import threading
import time
import tkinter as tk
import tkinter.messagebox as mb
import tkinter.ttk as ttk
from datetime import datetime
from pathlib import Path
from typing import Optional


def _check_deps() -> None:
    """Проверяет обязательные зависимости и показывает понятное сообщение."""
    import importlib.util
    missing = [m for m in ("ttkbootstrap", "httpx", "mitmproxy")
               if importlib.util.find_spec(m) is None]
    if not missing:
        return
    msg = (
        "Не хватает зависимостей:\n  " + ", ".join(missing) + "\n\n"
        "Установи командой:\n  pip install -r requirements.txt"
    )
    print("[notscan] " + msg, file=sys.stderr)
    try:
        root = tk.Tk()
        root.withdraw()
        mb.showerror("Notscan — missing dependencies", msg)
        root.destroy()
    except Exception:
        pass
    sys.exit(1)


_check_deps()

import ttkbootstrap as tb

import db
import contract_inference
import auth_boundary
import report_export
import scanner_core
import path_probe
from mitm_proxy import (
    ProxyRunner,
    is_noise_host,
    find_free_port,
    port_is_free,
    proxy_settings,
    should_idle_stop,
)
from tkinter import filedialog
import httpx
from templating import parse_raw_http, build_raw_http
import ui_theme


# ──────────────────────────── Helpers ────────────────────────────

def ts_to_str(ts: float) -> str:
    try:
        return datetime.fromtimestamp(ts).strftime("%H:%M:%S")
    except Exception:
        return str(ts)


def _truncate(s: Optional[str], n: int = 60) -> str:
    if not s:
        return ""
    return s[:n] + ("…" if len(s) > n else "")


def _baseline_for_result(result_id: int, method: str, url: str) -> Optional[dict]:
    """
    Возвращает baseline-запись history для результата скана.
    Сначала по scan_meta.history_id (надёжно), затем парсингом template_id
    "hist-{id}-…", и лишь в конце — точным совпадением method+url.
    """
    try:
        meta = db.fetch_scan_meta_by_result(result_id)
        if meta and meta.get("history_id"):
            row = db.fetch_history_by_id(meta["history_id"])
            if row:
                return row
    except Exception:
        pass
    try:
        res = db.fetch_scan_result_by_id(result_id)
        tmpl = (res or {}).get("template_id", "")
        if tmpl.startswith("hist-"):
            hid = int(tmpl.split("-")[1])
            row = db.fetch_history_by_id(hid)
            if row:
                return row
    except Exception:
        pass
    return db.fetch_history_baseline(method, url)


# ──────────────────────────── Detail window ────────────────────────────

class DetailWindow(tk.Toplevel):
    """Окно с детальной информацией о результате скана."""

    def __init__(self, parent, result_id: int):
        super().__init__(parent)
        self._parent_app = parent
        self._tokens = getattr(parent, "_tokens", ui_theme.get_tokens("dark"))
        self.title(f"Scan result #{result_id}")
        self.geometry("900x700")
        self.configure(bg=self._tokens.app_bg)
        self._build(result_id)

    def _build(self, result_id: int) -> None:
        result = db.fetch_scan_result_by_id(result_id)
        if not result:
            tk.Label(self, text="Result not found", fg="red", bg=self._tokens.app_bg).pack()
            return

        scan_req = db.fetch_scan_request_by_result(result_id)
        baseline = _baseline_for_result(result_id, result["method"], result["url"])
        evidence_snip = db.fetch_evidence_snippet(result_id)

        nb = ttk.Notebook(self)
        nb.pack(fill=tk.BOTH, expand=True, padx=6, pady=6)

        # ── Tab 1: Summary ──
        tab_sum = ttk.Frame(nb)
        nb.add(tab_sum, text="Summary")

        # Resolve WSTG ID for this finding
        try:
            from checks.runner import WSTG_ID_MAP as _WSTG_MAP
            _wstg_id = _WSTG_MAP.get((result.get("check_type") or "").lower(), "—")
        except Exception:
            _wstg_id = "—"

        info_lines = [
            ("ID", result["id"]),
            ("Time", ts_to_str(result["time"])),
            ("Template", result["template_id"]),
            ("Check type", result["check_type"]),
            ("WSTG ref", _wstg_id),
            ("Payload", result["payload"]),
            ("Method", result["method"]),
            ("URL", result["url"]),
            ("Status", result["status_code"]),
            ("Error", result["error"] or "—"),
            ("Evidence", result["evidence"] or "—"),
        ]
        for i, (label, value) in enumerate(info_lines):
            ttk.Label(tab_sum, text=f"{label}:", anchor="w", width=14).grid(
                row=i, column=0, sticky="w", padx=8, pady=2
            )
            ttk.Label(tab_sum, text=str(value), anchor="w", wraplength=700, justify="left").grid(
                row=i, column=1, sticky="w", padx=4, pady=2)

        btns = ttk.Frame(tab_sum)
        btns.grid(row=len(info_lines), column=0, columnspan=2, sticky="w", padx=8, pady=(10, 2))
        ttk.Button(
            btns,
            text="Confirm (baseline/benign/suspicious)…",
            command=lambda: self._confirm_flow(result_id),
        ).pack(side=tk.LEFT, padx=2)
        ttk.Button(
            btns,
            text="Refresh confirmations",
            command=lambda: self._refresh_confirmations(result_id),
        ).pack(side=tk.LEFT, padx=6)

        # ── Tab 2: Baseline request ──
        tab_base = ttk.Frame(nb)
        nb.add(tab_base, text="Baseline request")
        self._add_text_area(tab_base, self._format_baseline(baseline))

        # ── Tab 3: Mutated request ──
        tab_mut = ttk.Frame(nb)
        nb.add(tab_mut, text="Mutated request")
        self._add_text_area(tab_mut, scan_req["raw_request"] if scan_req else "(none)")

        # ── Tab 4: Response preview ──
        tab_resp = ttk.Frame(nb)
        nb.add(tab_resp, text="Response preview")
        self._add_text_area(tab_resp, self._build_full_response(result_id, scan_req))

        # ── Tab 5: Diff (baseline vs mutated response) ──
        tab_diff = ttk.Frame(nb)
        nb.add(tab_diff, text="Diff")
        diff_text = (evidence_snip or {}).get("diff_snippet") if evidence_snip else ""
        if not diff_text:
            diff_text = "(no diff snippet saved yet — run scan with evidence or use Confirm)"
        self._add_text_area(tab_diff, diff_text)

        # ── Tab 6: Confirmations ──
        tab_conf = ttk.Frame(nb)
        nb.add(tab_conf, text="Confirmations")
        self._conf_text = tk.Text(
            tab_conf,
            font=("Courier New", 10), wrap=tk.NONE,
        )
        ui_theme.apply_text_theme(self._conf_text, self._tokens)
        sb_y = ttk.Scrollbar(tab_conf, orient=tk.VERTICAL, command=self._conf_text.yview)
        self._conf_text.configure(yscrollcommand=sb_y.set)
        sb_y.pack(side=tk.RIGHT, fill=tk.Y)
        self._conf_text.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        self._conf_text.insert("1.0", self._format_confirmations(result_id))
        self._conf_text.configure(state=tk.DISABLED)

    def _add_text_area(self, parent, content: str) -> None:
        txt = tk.Text(parent, font=("Courier New", 10), wrap=tk.NONE)
        ui_theme.apply_text_theme(txt, self._tokens)
        sb_y = ttk.Scrollbar(parent, orient=tk.VERTICAL, command=txt.yview)
        sb_x = ttk.Scrollbar(parent, orient=tk.HORIZONTAL, command=txt.xview)
        txt.configure(yscrollcommand=sb_y.set, xscrollcommand=sb_x.set)
        sb_y.pack(side=tk.RIGHT, fill=tk.Y)
        sb_x.pack(side=tk.BOTTOM, fill=tk.X)
        txt.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        txt.insert("1.0", content or "(empty)")
        txt.configure(state=tk.DISABLED)

    def _build_full_response(self, result_id: int, scan_req: Optional[dict]) -> str:
        """
        Returns the full HTTP response text (status + headers + body).

        Priority:
          1. raw_response_preview from scan_requests — if it already starts with
             'HTTP/' the active scanner stored the full response there already.
          2. resp_status + resp_headers columns from scan_requests (added in v6)
             combined with the body from raw_response_preview.
          3. scan_meta.history_id → history table (headers of the original request,
             used as fallback for passive checks from older runs).
          4. Parse hist-{id}-... from template_id as last resort.
        """
        raw_preview = ""
        if scan_req and scan_req.get("raw_response_preview"):
            rp = scan_req["raw_response_preview"]
            if isinstance(rp, bytes):
                rp = rp.decode("utf-8", errors="replace")
            raw_preview = rp

        # Case 1: already a full HTTP response (scanner_core stores it this way)
        if raw_preview.startswith("HTTP/"):
            return raw_preview

        # Case 2: scan_requests has resp_status + resp_headers columns
        if scan_req and scan_req.get("resp_status"):
            try:
                resp_hdrs = json.loads(scan_req.get("resp_headers") or "{}")
            except Exception:
                resp_hdrs = {}
            lines = [f"HTTP/1.1 {scan_req['resp_status']}"]
            for k, v in resp_hdrs.items():
                lines.append(f"{k}: {v}")
            lines.append("")
            lines.append(raw_preview)
            return "\n".join(lines)

        # Case 3 / 4: look up history row
        history_row = None
        try:
            meta = db.fetch_scan_meta_by_result(result_id)
            if meta and meta.get("history_id"):
                history_row = db.fetch_history_by_id(meta["history_id"])
        except Exception:
            pass
        if history_row is None:
            try:
                _res = db.fetch_scan_result_by_id(result_id)
                tmpl = (_res or {}).get("template_id", "")
                if tmpl.startswith("hist-"):
                    hid = int(tmpl.split("-")[1])
                    history_row = db.fetch_history_by_id(hid)
            except Exception:
                pass

        if history_row is not None:
            lines = []
            status = history_row.get("resp_status") or "?"
            lines.append(f"HTTP/1.1 {status}")
            try:
                resp_hdrs = json.loads(history_row.get("resp_headers") or "{}")
            except Exception:
                resp_hdrs = {}
            for k, v in resp_hdrs.items():
                lines.append(f"{k}: {v}")
            lines.append("")
            if raw_preview:
                lines.append(raw_preview)
            else:
                rb = history_row.get("resp_body_preview")
                if rb:
                    lines.append(rb.decode("utf-8", errors="replace") if isinstance(rb, bytes) else str(rb))
                else:
                    lines.append("(no body preview)")
            return "\n".join(lines)

        if raw_preview:
            return "(status/headers not available — body only)\n\n" + raw_preview
        return "(no response preview saved)"

    def _format_baseline(self, row: Optional[dict]) -> str:
        if not row:
            return "(no baseline in history)"
        try:
            headers = json.loads(row["req_headers"])
        except Exception:
            headers = {}
        body = b""
        if row.get("req_body"):
            try:
                body = row["req_body"]
            except Exception:
                body = b""
        from templating import build_raw_http
        return build_raw_http(row["method"], row["url"], headers, body)

    def _format_confirmations(self, result_id: int) -> str:
        rows = db.fetch_confirmations(result_id, limit=50)
        if not rows:
            return "(no confirmations yet)"
        out = []
        for r in reversed(rows):
            elapsed = r.get("elapsed_ms") or 0.0
            out.append(
                f"[{ts_to_str(r.get('time', 0))}] kind={r.get('kind')} "
                f"status={r.get('status_code')} elapsed_ms={elapsed:.0f} "
                f"ok={r.get('ok')} note={r.get('note') or ''}"
            )
            if r.get("diff_snippet"):
                out.append(r["diff_snippet"])
                out.append("")
        return "\n".join(out).strip()

    def _refresh_confirmations(self, result_id: int) -> None:
        if not hasattr(self, "_conf_text"):
            return
        self._conf_text.configure(state=tk.NORMAL)
        self._conf_text.delete("1.0", tk.END)
        self._conf_text.insert("1.0", self._format_confirmations(result_id))
        self._conf_text.configure(state=tk.DISABLED)

    def _confirm_flow(self, result_id: int) -> None:
        """
        Offline confirm flow:
          baseline (from history baseline), benign (same mutated but payload replaced), suspicious (replay mutated).
        Stores confirmations + updates confidence heuristically.
        """
        res = db.fetch_scan_result_by_id(result_id)
        if not res:
            return
        scan_req = db.fetch_scan_request_by_result(result_id) or {}
        raw_mut = scan_req.get("raw_request") or ""
        if not raw_mut:
            mb.showwarning("Confirm", "No mutated raw request saved for this result.")
            return

        payload = res.get("payload") or ""
        evidence = (res.get("evidence") or "").strip()

        def _run():
            client = None
            try:
                proxy_url = None
                if hasattr(self._parent_app, "_proxy_runner") and self._parent_app._proxy_runner and self._parent_app._proxy_runner.is_running:
                    host = getattr(self._parent_app, "_proxy_host", None).get() if getattr(self._parent_app, "_proxy_host", None) else "127.0.0.1"
                    port = int(getattr(self._parent_app, "_proxy_port", None).get()) if getattr(self._parent_app, "_proxy_port", None) else 8080
                    proxy_url = f"http://{host}:{port}"

                mounts_cfg = None
                if proxy_url:
                    tr = httpx.HTTPTransport(proxy=proxy_url, verify=False)
                    mounts_cfg = {"http://": tr, "https://": tr, "http://localhost": tr, "https://localhost": tr, "http://127.0.0.1": tr, "https://127.0.0.1": tr}

                client = httpx.Client(verify=False, timeout=20.0, follow_redirects=True, **(({"mounts": mounts_cfg}) if mounts_cfg else {}))

                # Baseline request from history baseline
                base_row = _baseline_for_result(result_id, res["method"], res["url"])
                base_raw = self._format_baseline(base_row) if base_row else ""
                base_req = parse_raw_http(base_raw) if base_raw else None

                mut_req = parse_raw_http(raw_mut)

                def _send(req_obj):
                    if req_obj is None:
                        return None, 0.0, ""
                    start = time.time()
                    resp = client.request(method=req_obj.method, url=req_obj.url, headers=req_obj.headers, content=req_obj.body if req_obj.body else None)
                    elapsed_ms = (time.time() - start) * 1000.0
                    text = resp.text[:8192]
                    return resp.status_code, elapsed_ms, text

                # baseline
                b_code, b_ms, b_text = _send(base_req)
                db.insert_confirmation(scan_result_id=result_id, kind="baseline", status_code=b_code, elapsed_ms=b_ms, resp_preview=b_text)

                # benign (payload replaced)
                benign_marker = "NOTSCA_BENIGN"
                benign_raw = raw_mut.replace(payload, benign_marker) if payload else raw_mut
                benign_req = parse_raw_http(benign_raw)
                bn_code, bn_ms, bn_text = _send(benign_req)
                db.insert_confirmation(scan_result_id=result_id, kind="benign", status_code=bn_code, elapsed_ms=bn_ms, resp_preview=bn_text)

                # suspicious (replay mutated)
                s_code, s_ms, s_text = _send(mut_req)
                diff_snip = scanner_core.build_unified_diff_snippet(b_text or "", s_text or "", context_lines=2, max_lines=120)

                ok = False
                note = ""
                if evidence and (evidence in (s_text or "")) and (evidence not in (bn_text or "")):
                    ok = True
                    note = "evidence appears only in suspicious"
                elif (len(s_text or "") != len(b_text or "")) and (len(bn_text or "") == len(b_text or "")):
                    ok = True
                    note = "suspicious response differs; benign matches baseline length"
                else:
                    note = "inconclusive (manual review recommended)"

                db.insert_confirmation(
                    scan_result_id=result_id,
                    kind="suspicious",
                    status_code=s_code,
                    elapsed_ms=s_ms,
                    resp_preview=s_text,
                    diff_snippet=diff_snip,
                    ok=ok,
                    note=note,
                )

                # Update confidence based on confirm
                try:
                    # exploitability: higher when confirm is OK and evidence diff exists
                    db.upsert_scan_meta(
                        scan_result_id=result_id,
                        confidence=0.9 if ok else 0.4,
                        exploitability=0.85 if ok else 0.25,
                    )
                except Exception:
                    pass

                self.after(0, lambda: self._refresh_confirmations(result_id))
                mb.showinfo("Confirm", f"Confirm completed. Verdict: {'OK' if ok else 'INCONCLUSIVE'}")
            except Exception as exc:
                self.after(0, lambda: mb.showerror("Confirm error", str(exc)))
            finally:
                # Bug #2: клиент должен закрываться при любом исходе.
                if client is not None:
                    try:
                        client.close()
                    except Exception:
                        pass

        threading.Thread(target=_run, daemon=True).start()



# ──────────────────────────── Contract/Auth windows ────────────────────────────

class ContractWindow(tk.Toplevel):
    def __init__(self, parent: "App"):
        super().__init__(parent)
        self._app = parent
        self._tokens = getattr(parent, "_tokens", ui_theme.get_tokens("dark"))
        self.title("Endpoint contracts")
        self.geometry("980x640")
        self.configure(bg=self._tokens.app_bg)
        self._build()
        self.refresh()

    def _build(self) -> None:
        top = ttk.Frame(self)
        top.pack(fill=tk.X, padx=8, pady=6)

        self._use_var = getattr(self._app, "_use_contracts_var", tk.BooleanVar(value=False))
        ttk.Checkbutton(top, text="Use inferred contracts in planner", variable=self._use_var).pack(side=tk.LEFT)
        ttk.Button(top, text="↻ Refresh", command=self.refresh).pack(side=tk.LEFT, padx=6)

        body = ttk.PanedWindow(self, orient=tk.HORIZONTAL)
        body.pack(fill=tk.BOTH, expand=True, padx=8, pady=6)

        left = ttk.Frame(body)
        right = ttk.Frame(body)
        body.add(left, weight=2)
        body.add(right, weight=3)

        self._tree = ttk.Treeview(left, columns=("method", "pattern", "samples"), show="headings")
        self._tree.heading("method", text="Method")
        self._tree.heading("pattern", text="URL pattern")
        self._tree.heading("samples", text="Samples")
        self._tree.column("method", width=70, anchor="w")
        self._tree.column("pattern", width=520, anchor="w")
        self._tree.column("samples", width=70, anchor="e")
        sb = ttk.Scrollbar(left, orient=tk.VERTICAL, command=self._tree.yview)
        self._tree.configure(yscrollcommand=sb.set)
        self._tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        sb.pack(side=tk.RIGHT, fill=tk.Y)
        self._tree.bind("<<TreeviewSelect>>", lambda e: self._render_selected())

        self._detail = tk.Text(
            right,
            font=("Courier New", 10),
            wrap=tk.NONE,
        )
        ui_theme.apply_text_theme(self._detail, self._tokens)
        sb_y = ttk.Scrollbar(right, orient=tk.VERTICAL, command=self._detail.yview)
        sb_x = ttk.Scrollbar(right, orient=tk.HORIZONTAL, command=self._detail.xview)
        self._detail.configure(yscrollcommand=sb_y.set, xscrollcommand=sb_x.set)
        sb_y.pack(side=tk.RIGHT, fill=tk.Y)
        sb_x.pack(side=tk.BOTTOM, fill=tk.X)
        self._detail.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        self._detail.insert("1.0", "(select a contract)")
        self._detail.configure(state=tk.DISABLED)

    def refresh(self) -> None:
        for iid in self._tree.get_children():
            self._tree.delete(iid)
        rows = db.fetch_endpoint_contracts(limit=2000)
        for r in rows:
            iid = str(r["id"])
            self._tree.insert(
                "",
                tk.END,
                iid=iid,
                values=(r.get("method") or "", r.get("url_pattern") or "", r.get("sample_count") or 0),
            )
        self._app.log(f"[CONTRACT] Loaded {len(rows)} contract(s)")

    def _render_selected(self) -> None:
        sel = self._tree.selection()
        if not sel:
            return
        rid = int(sel[0])
        rows = db.fetch_endpoint_contracts(limit=2000)
        row = next((r for r in rows if int(r["id"]) == rid), None)
        if not row:
            return

        def _loads(s, default):
            try:
                return json.loads(s) if s else default
            except Exception:
                return default

        payload = {
            "method": row.get("method"),
            "url_pattern": row.get("url_pattern"),
            "sample_count": row.get("sample_count"),
            "content_type": row.get("content_type"),
            "param_types": _loads(row.get("param_types"), {}),
            "required_params": _loads(row.get("required_params"), []),
            "expected_codes": _loads(row.get("expected_codes"), []),
            "resp_schema": _loads(row.get("resp_schema"), {}),
        }

        self._detail.configure(state=tk.NORMAL)
        self._detail.delete("1.0", tk.END)
        self._detail.insert("1.0", json.dumps(payload, ensure_ascii=False, indent=2))
        self._detail.configure(state=tk.DISABLED)


class AuthBoundaryResultsWindow(tk.Toplevel):
    def __init__(self, parent: "App"):
        super().__init__(parent)
        self._app = parent
        self._tokens = getattr(parent, "_tokens", ui_theme.get_tokens("dark"))
        self.title("Auth Boundary results")
        self.geometry("1050x650")
        self.configure(bg=self._tokens.app_bg)
        self._build()
        self.refresh()

    def _build(self) -> None:
        top = ttk.Frame(self)
        top.pack(fill=tk.X, padx=8, pady=6)
        ttk.Button(top, text="↻ Refresh", command=self.refresh).pack(side=tk.LEFT)
        ttk.Button(top, text="Export findings (JSON)", command=self._export_findings).pack(side=tk.LEFT, padx=6)

        body = ttk.PanedWindow(self, orient=tk.VERTICAL)
        body.pack(fill=tk.BOTH, expand=True, padx=8, pady=6)
        upper = ttk.Frame(body)
        lower = ttk.Frame(body)
        body.add(upper, weight=3)
        body.add(lower, weight=2)

        self._tree = ttk.Treeview(
            upper,
            columns=("method", "url", "anon", "auth", "sim", "flag"),
            show="headings",
        )
        for k, h in [
            ("method", "Method"),
            ("url", "URL"),
            ("anon", "Anon"),
            ("auth", "Auth"),
            ("sim", "Similarity"),
            ("flag", "Accessible anon"),
        ]:
            self._tree.heading(k, text=h)
        self._tree.column("method", width=70, anchor="w")
        self._tree.column("url", width=720, anchor="w")
        self._tree.column("anon", width=70, anchor="e")
        self._tree.column("auth", width=70, anchor="e")
        self._tree.column("sim", width=80, anchor="e")
        self._tree.column("flag", width=110, anchor="center")
        self._tree.tag_configure("danger", foreground="#f38ba8")
        self._tree.tag_configure("ok", foreground="#a6e3a1")
        sb = ttk.Scrollbar(upper, orient=tk.VERTICAL, command=self._tree.yview)
        self._tree.configure(yscrollcommand=sb.set)
        self._tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        sb.pack(side=tk.RIGHT, fill=tk.Y)
        self._tree.bind("<<TreeviewSelect>>", lambda e: self._render_selected())

        self._diff = tk.Text(
            lower,
            font=("Courier New", 10),
            wrap=tk.NONE,
        )
        ui_theme.apply_text_theme(self._diff, self._tokens)
        sb_y = ttk.Scrollbar(lower, orient=tk.VERTICAL, command=self._diff.yview)
        sb_x = ttk.Scrollbar(lower, orient=tk.HORIZONTAL, command=self._diff.xview)
        self._diff.configure(yscrollcommand=sb_y.set, xscrollcommand=sb_x.set)
        sb_y.pack(side=tk.RIGHT, fill=tk.Y)
        sb_x.pack(side=tk.BOTTOM, fill=tk.X)
        self._diff.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        self._diff.insert("1.0", "(select a row)")
        self._diff.configure(state=tk.DISABLED)

    def refresh(self) -> None:
        for iid in self._tree.get_children():
            self._tree.delete(iid)
        rows = db.fetch_auth_boundary_results(limit=1000)
        for r in rows:
            iid = str(r["id"])
            flag = int(r.get("accessible_anon") or 0)
            tags = ("danger",) if flag else ("ok",)
            self._tree.insert(
                "",
                tk.END,
                iid=iid,
                values=(
                    r.get("method") or "",
                    _truncate(r.get("url") or "", 200),
                    r.get("anon_status") if r.get("anon_status") is not None else "—",
                    r.get("auth_status") if r.get("auth_status") is not None else "—",
                    f"{float(r.get('similarity') or 0.0):.2f}",
                    "YES" if flag else "NO",
                ),
                tags=tags,
            )
        self._app.log(f"[AUTH] Loaded {len(rows)} auth-boundary rows")

    def _selected_row(self) -> dict | None:
        sel = self._tree.selection()
        if not sel:
            return None
        rid = int(sel[0])
        rows = db.fetch_auth_boundary_results(limit=1000)
        return next((r for r in rows if int(r["id"]) == rid), None)

    def _render_selected(self) -> None:
        row = self._selected_row()
        if not row:
            return
        diff = row.get("diff_snippet") or "(no diff)"
        self._diff.configure(state=tk.NORMAL)
        self._diff.delete("1.0", tk.END)
        self._diff.insert("1.0", diff)
        self._diff.configure(state=tk.DISABLED)

    def _export_findings(self) -> None:
        rows = db.fetch_auth_boundary_results(limit=5000)
        findings = [r for r in rows if int(r.get("accessible_anon") or 0) == 1]
        if not findings:
            mb.showinfo("Export", "No accessible_anon=1 findings to export.")
            return
        path = filedialog.asksaveasfilename(
            defaultextension=".json",
            filetypes=[("JSON", "*.json"), ("All files", "*.*")],
            title="Export Auth Boundary findings",
        )
        if not path:
            return
        with open(path, "w", encoding="utf-8") as f:
            json.dump(findings, f, ensure_ascii=False, indent=2)
        mb.showinfo("Export", f"Exported {len(findings)} findings to\n{path}")

# ──────────────────────── RawViewWindow ──────────────────────────────────────

class RawViewWindow(tk.Toplevel):
    """
    Окно просмотра сырого HTTP-запроса и ответа для записи из History.
    Вызывается через ПКМ → Просмотр запроса/ответа.
    """

    def __init__(self, parent, record: dict):
        super().__init__(parent)
        self._tokens = getattr(parent, "_tokens", ui_theme.get_tokens("dark"))
        hist_id = record.get("id", "?")
        self.title(f"Raw view — History #{hist_id}")
        self.geometry("1000x720")
        self.configure(bg=self._tokens.app_bg)
        self._build(record)

    def _build(self, record: dict) -> None:
        nb = ttk.Notebook(self)
        nb.pack(fill=tk.BOTH, expand=True, padx=6, pady=6)

        # ── Tab 1: Raw Request ─────────────────────────────────────
        tab_req = ttk.Frame(nb)
        nb.add(tab_req, text="  Request  ")
        self._add_text_area(tab_req, self._build_raw_request(record))

        # ── Tab 2: Response ────────────────────────────────────────
        tab_resp = ttk.Frame(nb)
        nb.add(tab_resp, text="  Response  ")
        self._add_text_area(tab_resp, self._build_raw_response(record))

        # ── Tab 3: Summary ─────────────────────────────────────────
        tab_sum = ttk.Frame(nb)
        nb.add(tab_sum, text="  Summary  ")
        lines = [
            ("ID",       record.get("id")),
            ("Time",     ts_to_str(record.get("time", 0))),
            ("Method",   record.get("method")),
            ("URL",      record.get("url")),
            ("Status",   record.get("resp_status") or "—"),
        ]
        for i, (lbl, val) in enumerate(lines):
            ttk.Label(tab_sum, text=f"{lbl}:", anchor="w", width=10).grid(
                row=i, column=0, sticky="w", padx=10, pady=3
            )
            ttk.Label(tab_sum, text=str(val or ""), anchor="w", wraplength=820, justify="left").grid(
                row=i, column=1, sticky="w", padx=4, pady=3)

        # Copy buttons
        btn_frame = ttk.Frame(self)
        btn_frame.pack(fill=tk.X, padx=6, pady=(0, 6))
        raw_req = self._build_raw_request(record)
        raw_resp = self._build_raw_response(record)
        ttk.Button(btn_frame, text="📋 Copy request",
                   command=lambda: self._copy(raw_req)).pack(side=tk.LEFT, padx=4)
        ttk.Button(btn_frame, text="📋 Copy response",
                   command=lambda: self._copy(raw_resp)).pack(side=tk.LEFT, padx=4)
        ttk.Button(btn_frame, text="✕ Close",
                   command=self.destroy).pack(side=tk.RIGHT, padx=4)

    def _build_raw_request(self, record: dict) -> str:
        try:
            headers = json.loads(record.get("req_headers") or "{}")
        except Exception:
            headers = {}
        body = b""
        raw_body = record.get("req_body")
        if raw_body:
            body = raw_body if isinstance(raw_body, bytes) else raw_body.encode()
        from templating import build_raw_http
        return build_raw_http(record.get("method", "GET"), record.get("url", ""), headers, body)

    def _build_raw_response(self, record: dict) -> str:
        lines = []
        status = record.get("resp_status")
        lines.append(f"HTTP/1.1 {status or '?'}")
        try:
            resp_headers = json.loads(record.get("resp_headers") or "{}")
        except Exception:
            resp_headers = {}
        for k, v in resp_headers.items():
            lines.append(f"{k}: {v}")
        lines.append("")
        body_raw = record.get("resp_body_preview")
        if body_raw:
            if isinstance(body_raw, bytes):
                try:
                    lines.append(body_raw.decode("utf-8", errors="replace"))
                except Exception:
                    lines.append(repr(body_raw))
            else:
                lines.append(str(body_raw))
        else:
            lines.append("(no body preview)")
        return "\n".join(lines)

    def _add_text_area(self, parent, content: str) -> None:
        txt = tk.Text(parent, font=("Courier New", 10), wrap=tk.NONE)
        ui_theme.apply_text_theme(txt, self._tokens)
        sb_y = ttk.Scrollbar(parent, orient=tk.VERTICAL, command=txt.yview)
        sb_x = ttk.Scrollbar(parent, orient=tk.HORIZONTAL, command=txt.xview)
        txt.configure(yscrollcommand=sb_y.set, xscrollcommand=sb_x.set)
        sb_y.pack(side=tk.RIGHT, fill=tk.Y)
        sb_x.pack(side=tk.BOTTOM, fill=tk.X)
        txt.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        txt.insert("1.0", content or "(empty)")
        txt.configure(state=tk.DISABLED)

    def _copy(self, text: str) -> None:
        self.clipboard_clear()
        self.clipboard_append(text)


# ──────────────────────── ScanRawViewWindow ──────────────────────────────────

class ScanRawViewWindow(tk.Toplevel):
    """
    Окно просмотра raw payload-запроса и ответа для результата скана.
    Вызывается через ПКМ → Raw запрос (payload) / ответ.
    """

    def __init__(self, parent, result: dict, scan_req: Optional[dict]):
        super().__init__(parent)
        self._tokens = getattr(parent, "_tokens", ui_theme.get_tokens("dark"))
        res_id = result.get("id", "?")
        check  = result.get("check_type", "?")
        self.title(f"Scan raw #{res_id} — {check}")
        self.geometry("1000x720")
        self.configure(bg=self._tokens.app_bg)
        self._build(result, scan_req)

    def _build(self, result: dict, scan_req: Optional[dict]) -> None:
        nb = ttk.Notebook(self)
        nb.pack(fill=tk.BOTH, expand=True, padx=6, pady=6)

        raw_req  = (scan_req or {}).get("raw_request") or "(not saved)"
        raw_resp = self._build_full_response(result, scan_req)

        # ── Tab 1: Mutated Request (with payload) ──────────────────
        tab_req = ttk.Frame(nb)
        nb.add(tab_req, text="  Payload Request  ")
        self._add_text_area(tab_req, raw_req)

        # ── Tab 2: Response ────────────────────────────────────────
        tab_resp = ttk.Frame(nb)
        nb.add(tab_resp, text="  Response  ")
        self._add_text_area(tab_resp, raw_resp)

        # ── Tab 3: Finding summary ─────────────────────────────────
        tab_sum = ttk.Frame(nb)
        nb.add(tab_sum, text="  Finding  ")
        try:
            from checks.runner import WSTG_ID_MAP as _WM
            _raw_wstg = _WM.get((result.get("check_type") or "").lower(), "—")
        except Exception:
            _raw_wstg = "—"
        lines = [
            ("Result ID",   result.get("id")),
            ("Time",        ts_to_str(result.get("time", 0))),
            ("Check",       result.get("check_type")),
            ("WSTG ref",    _raw_wstg),
            ("Payload",     result.get("payload")),
            ("Method",      result.get("method")),
            ("URL",         result.get("url")),
            ("Status",      result.get("status_code") or "—"),
            ("Evidence",    result.get("evidence") or "—"),
            ("Error",       result.get("error") or "—"),
        ]
        for i, (lbl, val) in enumerate(lines):
            ttk.Label(tab_sum, text=f"{lbl}:", anchor="w", width=12).grid(
                row=i, column=0, sticky="w", padx=10, pady=3
            )
            ttk.Label(tab_sum, text=str(val or ""), anchor="w", wraplength=820, justify="left").grid(
                row=i, column=1, sticky="w", padx=4, pady=3)
        tab_sum.columnconfigure(1, weight=1)

        # Copy buttons
        btn_frame = ttk.Frame(self)
        btn_frame.pack(fill=tk.X, padx=6, pady=(0, 6))
        ttk.Button(btn_frame, text="📋 Copy request",
                   command=lambda: self._copy(raw_req)).pack(side=tk.LEFT, padx=4)
        ttk.Button(btn_frame, text="📋 Copy response",
                   command=lambda: self._copy(raw_resp)).pack(side=tk.LEFT, padx=4)
        ttk.Button(btn_frame, text="✕ Close",
                   command=self.destroy).pack(side=tk.RIGHT, padx=4)

    def _add_text_area(self, parent, content: str) -> None:
        txt = tk.Text(parent, font=("Courier New", 10), wrap=tk.NONE)
        ui_theme.apply_text_theme(txt, self._tokens)
        sb_y = ttk.Scrollbar(parent, orient=tk.VERTICAL, command=txt.yview)
        sb_x = ttk.Scrollbar(parent, orient=tk.HORIZONTAL, command=txt.xview)
        txt.configure(yscrollcommand=sb_y.set, xscrollcommand=sb_x.set)
        sb_y.pack(side=tk.RIGHT, fill=tk.Y)
        sb_x.pack(side=tk.BOTTOM, fill=tk.X)
        txt.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        txt.insert("1.0", content or "(empty)")
        txt.configure(state=tk.DISABLED)


    def _build_full_response(self, result: dict, scan_req) -> str:
        """Returns the full HTTP response (status + headers + body)."""
        raw_preview = ""
        if scan_req and scan_req.get("raw_response_preview"):
            rp = scan_req["raw_response_preview"]
            if isinstance(rp, bytes):
                rp = rp.decode("utf-8", errors="replace")
            raw_preview = rp

        # Case 1: already a full HTTP response stored by scanner_core
        if raw_preview.startswith("HTTP/"):
            return raw_preview

        # Case 2: resp_status + resp_headers columns in scan_requests (v6+)
        if scan_req and scan_req.get("resp_status"):
            try:
                resp_hdrs = json.loads(scan_req.get("resp_headers") or "{}")
            except Exception:
                resp_hdrs = {}
            lines = [f"HTTP/1.1 {scan_req['resp_status']}"]
            for k, v in resp_hdrs.items():
                lines.append(f"{k}: {v}")
            lines.append("")
            lines.append(raw_preview)
            return "\n".join(lines)

        # Case 3 / 4: look up history row via scan_meta or template_id
        history_row = None
        result_id = (result or {}).get("id")
        if result_id:
            try:
                meta = db.fetch_scan_meta_by_result(result_id)
                if meta and meta.get("history_id"):
                    history_row = db.fetch_history_by_id(meta["history_id"])
            except Exception:
                pass
        if history_row is None:
            try:
                tmpl = (result or {}).get("template_id", "")
                if tmpl.startswith("hist-"):
                    hid = int(tmpl.split("-")[1])
                    history_row = db.fetch_history_by_id(hid)
            except Exception:
                pass

        if history_row is not None:
            out = [f"HTTP/1.1 {history_row.get('resp_status') or '?'}"]
            try:
                resp_hdrs = json.loads(history_row.get("resp_headers") or "{}")
            except Exception:
                resp_hdrs = {}
            for k, v in resp_hdrs.items():
                out.append(f"{k}: {v}")
            out.append("")
            if raw_preview:
                out.append(raw_preview)
            else:
                rb = history_row.get("resp_body_preview")
                if rb:
                    out.append(rb.decode("utf-8", errors="replace") if isinstance(rb, bytes) else str(rb))
                else:
                    out.append("(no body preview)")
            return "\n".join(out)

        if raw_preview:
            return "(status/headers not available — body only)\n\n" + raw_preview
        return "(not saved)"

    def _copy(self, text: str) -> None:
        self.clipboard_clear()
        self.clipboard_append(text)

# ──────────────────────────── Main App ────────────────────────────

# ──────────────────────────── Scan config (popup) ────────────────────────────

BADGE_COLORS = {
    "sqli": ("#f38ba8", "#11111b"),
    "sqli_time": ("#eba0ac", "#11111b"),
    "cmdi": ("#fab387", "#11111b"),
    "ssti": ("#f9e2af", "#11111b"),
    "path_traversal": ("#a6e3a1", "#11111b"),
    "xxe": ("#94e2d5", "#11111b"),
    "ssrf": ("#89dceb", "#11111b"),
    "deserialization": ("#89b4fa", "#11111b"),
    "nosql_injection": ("#b4befe", "#11111b"),
    "ldap_injection": ("#cba6f7", "#11111b"),
    "xpath_injection": ("#d20f39", "#cdd6f4"),
    "crlf_injection": ("#fe640b", "#11111b"),
    "file_upload": ("#df8e1d", "#11111b"),
    "idor": ("#179299", "#cdd6f4"),
    "xss_reflected": ("#f38ba8", "#11111b"),
    "xss_dom": ("#eba0ac", "#11111b"),
    "csrf": ("#fab387", "#11111b"),
    "open_redirect": ("#f9e2af", "#11111b"),
    "clickjacking": ("#a6e3a1", "#11111b"),
    "security_headers": ("#94e2d5", "#11111b"),
    "info_disclosure": ("#89dceb", "#11111b"),
    "outdated_libs": ("#89b4fa", "#11111b"),
    "third_party_scripts": ("#b4befe", "#11111b"),
    "jwt": ("#f5c2e7", "#11111b"),
    "info_disclosure_paths": ("#cba6f7", "#11111b"),
}

SERVER_BADGES = [
    ("sqli", "SQLi Error", True),
    ("sqli_time", "SQLi Time", True),
    ("cmdi", "CMDi", True),
    ("ssti", "SSTI", True),
    ("xxe", "XXE", True),
    ("ssrf", "SSRF", True),
    ("nosql_injection", "NoSQLi", True),
    ("ldap_injection", "LDAPi", True),
    ("xpath_injection", "XPathi", True),
    ("deserialization", "Deserial", True),
    ("path_traversal", "Path Traversal", True),
    ("crlf_injection", "CRLF/Header", True),
    ("file_upload", "File Upload", True),
    ("idor", "IDOR", True),
]

CLIENT_BADGES = [
    ("xss_reflected", "XSS Reflected", True),
    ("xss_dom", "XSS DOM", True),
    ("csrf", "CSRF", True),
    ("open_redirect", "Open Redirect", True),
    ("clickjacking", "Clickjacking", True),
    ("security_headers", "Sec Headers", True),
    ("info_disclosure", "Info Leak", True),
    ("outdated_libs", "Outdated Libs", True),
    ("third_party_scripts", "3rd-party JS", True),
]

OTHER_BADGES = [
    ("jwt", "JWT Signature", True),
    ("info_disclosure_paths", "Info Disclosure (paths)", True),
]


# ─────────────────────── Центральный каталог чеков ──────────────────
# Источник GUI-строк/бейджей — checks/catalog.py.
# Файл пишет другой агент параллельно, поэтому импорт мягкий: пока каталога
# нет — работаем на прежних hardcoded-списках (не падаем).

try:
    from checks.catalog import CHECK_CATALOG as _CHECK_CATALOG  # type: ignore
    _CATALOG_AVAILABLE = True
except Exception:  # ImportError или временно битый параллельный модуль
    _CHECK_CATALOG = ()
    _CATALOG_AVAILABLE = False

BADGE_LABELS: dict[str, str] = {
    cid: lbl for cid, lbl, _on in SERVER_BADGES + CLIENT_BADGES + OTHER_BADGES
}

# Старые наборы — fallback, пока каталог не готов (сохраняем 163 старых теста).
_LEGACY_PASSIVE_CHECK_IDS = {
    "security_headers", "csrf", "clickjacking", "info_disclosure",
    "outdated_libs", "third_party_scripts", "xss_dom", "idor",
    "file_upload", "jwt",
}
_LEGACY_PROBE_CHECK_IDS = ["info_disclosure_paths"]
_LEGACY_PAYLOAD_CHECK_IDS = [
    # server-side active
    "cmdi", "sqli", "sqli_time", "xss", "ssti", "path_traversal",
    "xxe", "ssrf", "nosql_injection", "ldap_injection", "xpath_injection",
    "deserialization", "crlf_injection", "open_redirect", "file_upload",
    "idor",
    # client-side active (have payload files)
    "xss_reflected",
]


def catalog_available() -> bool:
    """True, если удалось загрузить checks/catalog.py."""
    return bool(_CATALOG_AVAILABLE and _CHECK_CATALOG)


def _def_attr(defn, name: str, default=None):
    try:
        return getattr(defn, name)
    except Exception:
        return default


def catalog_defs() -> list:
    """Все CheckDef из каталога (или пустой список в fallback-режиме)."""
    return list(_CHECK_CATALOG)


def catalog_by_kind(kind: str) -> list:
    return [d for d in _CHECK_CATALOG if str(_def_attr(d, "kind", "")) == kind]


def catalog_check_ids() -> list[str]:
    return [
        str(_def_attr(d, "check_id", ""))
        for d in _CHECK_CATALOG
        if _def_attr(d, "check_id", "")
    ]


def catalog_categories() -> list[str]:
    """Категории для группировки/кнопок фильтра (порядок — стабильный)."""
    preferred = ["Information", "Config", "Injection", "File", "Client",
                 "Session", "AuthN", "AuthZ"]
    seen: list[str] = []
    for d in _CHECK_CATALOG:
        cat = str(_def_attr(d, "category", "Other") or "Other")
        if cat not in seen:
            seen.append(cat)
    return [c for c in preferred if c in seen] + [c for c in seen if c not in preferred]


def _badge_label_for(defn) -> str:
    """Короткая подпись бейджа: существующие короткие — как были, новые — из name."""
    cid = str(_def_attr(defn, "check_id", ""))
    if cid in BADGE_LABELS:
        return BADGE_LABELS[cid]
    name = str(_def_attr(defn, "name", "") or cid)
    return name if len(name) <= 22 else name[:21] + "…"


def catalog_badge_lists() -> dict[str, list[tuple[str, str]]]:
    """Бейджи ScanConfigWindow по группам из каталога.

    server/client — active-чеки (kind="active"), passive — kind="passive",
    probe — kind="probe" (включая info_disclosure_paths).
    """
    if not catalog_available():
        return {}
    groups: dict[str, list[tuple[str, str]]] = {
        "server": [], "client": [], "passive": [], "probe": [],
    }
    for d in _CHECK_CATALOG:
        cid = str(_def_attr(d, "check_id", ""))
        if not cid:
            continue
        kind = str(_def_attr(d, "kind", "active"))
        if kind == "active":
            cat = str(_def_attr(d, "category", "") or "")
            group = "client" if cat.lower() == "client" else "server"
        elif kind == "passive":
            group = "passive"
        elif kind == "probe":
            group = "probe"
        else:
            continue
        groups[group].append((cid, _badge_label_for(d)))
    return groups


def check_var_defs() -> list[tuple[str, bool]]:
    """(check_id, enabled_default) для инициализации чекбоксов/бейджей."""
    if catalog_available():
        out: list[tuple[str, bool]] = []
        for d in _CHECK_CATALOG:
            cid = str(_def_attr(d, "check_id", ""))
            if not cid:
                continue
            out.append((cid, bool(_def_attr(d, "enabled_default", True))))
        return out
    return [(cid, on) for cid, _lbl, on in SERVER_BADGES + CLIENT_BADGES + OTHER_BADGES]


def passive_check_ids() -> list[str]:
    """Passive-чеки для ветки «analyze stored responses» (из каталога)."""
    if catalog_available():
        return [str(_def_attr(d, "check_id")) for d in catalog_by_kind("passive")]
    return sorted(_LEGACY_PASSIVE_CHECK_IDS)


def probe_check_ids() -> list[str]:
    """Probe-чеки (path_probe.run_probe_scan) — из каталога."""
    if catalog_available():
        return [str(_def_attr(d, "check_id")) for d in catalog_by_kind("probe")]
    return list(_LEGACY_PROBE_CHECK_IDS)


def payload_check_ids() -> list[str]:
    """Active-чеки с payload-файлами для build_scan_tasks (из каталога)."""
    ids: list[str] = []
    if catalog_available():
        for d in catalog_by_kind("active"):
            cid = str(_def_attr(d, "check_id", ""))
            if cid and _def_attr(d, "payload_file", None):
                ids.append(cid)
    for cid in _LEGACY_PAYLOAD_CHECK_IDS:
        if cid not in ids:
            ids.append(cid)
    return ids


def registry_check_ids() -> list[str]:
    """id, у которых надо синхронизировать enabled-флаг CheckRegistry с GUI."""
    ids: list[str] = []
    if catalog_available():
        ids.extend(catalog_check_ids())
    for cid in (
        "sqli", "sqli_time", "cmdi", "ssti", "xxe", "ssrf",
        "nosql_injection", "ldap_injection", "xpath_injection",
        "deserialization", "path_traversal", "crlf_injection",
        "file_upload", "idor", "jwt", "xss_reflected", "xss_dom", "csrf",
        "open_redirect", "clickjacking", "security_headers", "info_disclosure",
        "outdated_libs", "third_party_scripts",
    ):
        if cid not in ids:
            ids.append(cid)
    return ids


class ScanConfigWindow(tk.Toplevel):
    """Всплывающее окно настройки параметров скана."""

    def __init__(self, parent: "App", on_start=None):
        super().__init__(parent)
        self._parent = parent
        self._on_start = on_start
        self._badges: dict[str, tk.Label] = {}
        self._check_widgets: dict[str, ttk.Checkbutton] = {}
        tokens = getattr(parent, "_tokens", None) or ui_theme.get_tokens("dark")
        self.configure(bg=tokens.app_bg)
        self.title("Scan configuration")
        self.geometry("900x760")
        self.transient(parent)
        self._build()
        try:
            self.grab_set()
        except Exception:
            pass

    def _badge(self, frame, cid, label, row, col):
        var = self._parent._check_vars.get(cid)
        if var is None:
            var = tk.BooleanVar(value=True)
            self._parent._check_vars[cid] = var
        on_bg, on_fg = BADGE_COLORS.get(cid, ("#585b70", "#cdd6f4"))
        off_bg, off_fg = "#313244", "#585b70"
        badge = tk.Label(
            frame, text=label, font=("Segoe UI", 9, "bold"),
            padx=8, pady=4, relief="flat", cursor="hand2",
            bg=on_bg if var.get() else off_bg,
            fg=on_fg if var.get() else off_fg,
        )
        def _toggle(_e=None):
            val = not var.get()
            var.set(val)
            badge.configure(bg=on_bg if val else off_bg, fg=on_fg if val else off_fg)
        badge.bind("<Button-1>", _toggle)
        badge.grid(row=row, column=col, padx=3, pady=3, sticky="ew")
        self._badges[cid] = badge

    def _set_all(self, value: bool):
        for cid, var in self._parent._check_vars.items():
            var.set(value)
            b = self._badges.get(cid)
            if b:
                on_bg, on_fg = BADGE_COLORS.get(cid, ("#585b70", "#cdd6f4"))
                b.configure(bg=on_bg if value else "#313244", fg=on_fg if value else "#585b70")

    def _only(self, ids):
        self._set_all(False)
        for cid in ids:
            var = self._parent._check_vars.get(cid)
            if var is not None:
                var.set(True)
            b = self._badges.get(cid)
            if b:
                on_bg, on_fg = BADGE_COLORS.get(cid, ("#585b70", "#cdd6f4"))
                b.configure(bg=on_bg, fg=on_fg)

    def _badge_section(self, title: str, items, cols: int = 5) -> None:
        """Секция кликабельных бейджей (active-чеки из каталога)."""
        lf = ttk.LabelFrame(self, text=title)
        lf.pack(fill=tk.X, padx=8, pady=2)
        for i, (cid, lbl) in enumerate(items):
            self._badge(lf, cid, lbl, i // cols, i % cols)
        for c in range(max(1, cols)):
            lf.columnconfigure(c, weight=1)

    def _check_section(self, title: str, items, cols: int = 4) -> None:
        """Секция чекбоксов (passive/probe-чеки из каталога)."""
        lf = ttk.LabelFrame(self, text=title)
        lf.pack(fill=tk.X, padx=8, pady=2)
        for i, (cid, lbl) in enumerate(items):
            var = self._parent._check_vars.get(cid)
            if var is None:
                var = tk.BooleanVar(value=True)
                self._parent._check_vars[cid] = var
            cb = ttk.Checkbutton(lf, text=lbl, variable=var)
            cb.grid(row=i // cols, column=i % cols, sticky="w", padx=4, pady=2)
            self._check_widgets[cid] = cb
        for c in range(max(1, cols)):
            lf.columnconfigure(c, weight=1)

    def _build(self):
        p = self._parent

        groups = catalog_badge_lists()
        if groups:
            # Данные из checks/catalog.py: active/passive/probe.
            self._badge_section("Server-side active checks", groups.get("server", []), cols=5)
            self._badge_section("Client-side active checks", groups.get("client", []), cols=5)
            self._check_section("Passive checks (analyze captured responses)",
                                groups.get("passive", []), cols=4)
            self._check_section("Probe checks (extra paths/requests)",
                                groups.get("probe", []), cols=4)
            server_ids = [cid for cid, _ in groups.get("server", [])]
            client_ids = [cid for cid, _ in groups.get("client", [])]
        else:
            # Fallback: прежние hardcoded-списки (пока каталога нет).
            server_lf = ttk.LabelFrame(self, text="Server-side checks")
            server_lf.pack(fill=tk.X, padx=8, pady=(8, 2))
            for i, (cid, lbl, _on) in enumerate(SERVER_BADGES):
                self._badge(server_lf, cid, lbl, i // 5, i % 5)
            for c in range(5):
                server_lf.columnconfigure(c, weight=1)

            client_lf = ttk.LabelFrame(self, text="Client-side checks")
            client_lf.pack(fill=tk.X, padx=8, pady=2)
            for i, (cid, lbl, _on) in enumerate(CLIENT_BADGES):
                self._badge(client_lf, cid, lbl, 0, i)
            for c in range(len(CLIENT_BADGES)):
                client_lf.columnconfigure(c, weight=1)

            other_lf = ttk.LabelFrame(self, text="Other")
            other_lf.pack(fill=tk.X, padx=8, pady=2)
            for i, (cid, lbl, _on) in enumerate(OTHER_BADGES):
                self._badge(other_lf, cid, lbl, 0, i)
            for c in range(len(OTHER_BADGES)):
                other_lf.columnconfigure(c, weight=1)
            server_ids = [c[0] for c in SERVER_BADGES]
            client_ids = [c[0] for c in CLIENT_BADGES]

        qsel = ttk.Frame(self)
        qsel.pack(fill=tk.X, padx=8, pady=4)
        ttk.Label(qsel, text="Quick select:").pack(side=tk.LEFT, padx=(0, 6))
        ttk.Button(qsel, text="All ON", command=lambda: self._set_all(True), width=8).pack(side=tk.LEFT, padx=2)
        ttk.Button(qsel, text="All OFF", command=lambda: self._set_all(False), width=8).pack(side=tk.LEFT, padx=2)
        ttk.Button(qsel, text="Server only", command=lambda: self._only(server_ids), width=11).pack(side=tk.LEFT, padx=2)
        ttk.Button(qsel, text="Client only", command=lambda: self._only(client_ids), width=11).pack(side=tk.LEFT, padx=2)

        mut_lf = ttk.LabelFrame(self, text="Mutation points")
        mut_lf.pack(fill=tk.X, padx=8, pady=2)
        for text, var in [
            ("Query params", p._mut_query),
            ("Body form", p._mut_form),
            ("Body JSON", p._mut_json),
            ("Headers", p._mut_headers),
        ]:
            ttk.Checkbutton(mut_lf, text=text, variable=var).pack(side=tk.LEFT, padx=6, pady=4)

        opt = ttk.Frame(self)
        opt.pack(fill=tk.X, padx=8, pady=2)
        ttk.Label(opt, text="Workers:").pack(side=tk.LEFT, padx=(0, 4))
        ttk.Spinbox(opt, from_=1, to=50, width=6, textvariable=p._workers_var).pack(side=tk.LEFT)

        ttk.Checkbutton(self, text="Safe mode (exclude destructive payloads: DROP/INSERT/UPDATE/exec)",
                        variable=p._safe_mode_var).pack(anchor="w", padx=10, pady=2)
        ttk.Checkbutton(self, text="Tamper/WAF-bypass (payload encoders: url / unicode / hex / double-url)",
                        variable=p._tamper_var).pack(anchor="w", padx=10, pady=2)
        ttk.Checkbutton(self, text="Smart mutation planner (reduce noise / skip inapplicable combos)",
                        variable=p._planner_var).pack(anchor="w", padx=10, pady=2)

        btns = ttk.Frame(self)
        btns.pack(fill=tk.X, padx=8, pady=(6, 10))
        ttk.Button(btns, text="▶ Start Scan", style="Success.TButton", command=self._start).pack(side=tk.RIGHT, padx=4)
        ttk.Button(btns, text="Cancel", command=self.destroy).pack(side=tk.RIGHT, padx=4)

    def _start(self):
        cb = self._on_start
        self.destroy()
        if cb:
            cb()


# ──────────────────────────── Tutorial (обучение) ────────────────────────────

TUTORIAL_STEPS = [
    {
        "title": "Добро пожаловать в Notscan",
        "text": "Notscan перехватывает твой HTTP-трафик через прокси, затем мутирует запросы и ищет уязвимости (SQLi, XSS, SSRF, XXE, JWT и др.).\n\nПройди 7 шагов — и сможешь пользоваться им сам.",
    },
    {
        "title": "Шаг 1/7: Открой браузер (прокси уже работает)",
        "text": "Прокси запускается автоматически при старте приложения и перехватывает трафик браузера — все запросы попадают в History. Нажми кнопку ниже или «▶ Start Proxy + Browser» на вкладке Proxy/Scan, чтобы открыть браузер.\n\nПрокси остановится сам: когда закроешь браузер, после простоя (Settings) или при закрытии приложения.",
        "hint": "Панель «Proxy» → кнопка «▶ Start Proxy + Browser». Отдельной кнопки Stop нет — всё автоматически.",
        "action": "_start_proxy_and_browser",
        "action_label": "▶ Открыть браузер через прокси",
    },
    {
        "title": "Шаг 2/7: Полазь по целевому сайту",
        "text": "В открывшемся браузере зайди на целевой сайт и покликай: формы, ссылки, кнопки. Все запросы появятся в History автоматически.",
        "hint": "Просто пользуйся браузером как обычно.",
    },
    {
        "title": "Шаг 3/7: Добавь запросы в Scan list",
        "text": "В History выдели интересные запросы (Ctrl+клик для нескольких) и нажми «＋ Add to Scan list».",
        "hint": "Панель «History» → кнопка «＋ Add to Scan list».",
    },
    {
        "title": "Шаг 4/7: Настрой сканирование",
        "text": "Нажми «▶ Run Scan» — откроется окно с выбором проверок (SQLi, XSS, SSRF, JWT и т.д.), mutation points и workers. Внутри нажми «▶ Start Scan».\n\nОпция «Smart mutation planner» использует contract inference: сканер анализирует прошлые запросы (кнопка «Contract Inference» на панели History) и определяет типы параметров (id→int, email, url, uuid, slug…), чтобы не слать нерелевантные пейлоады (например, open_redirect в числовой id). Для включения: History → «Contract Inference» → отметь «Use contracts» + чекбокс планировщика.",
        "hint": "Панель «Scan» → «▶ Run Scan». Contract inference — на панели History.",
        "action": "_open_scan_config",
        "action_label": "⚙ Открыть настройки скана",
    },
    {
        "title": "Шаг 5/7: Смотри результаты",
        "text": "Результаты появятся во вкладке Results автоматически. Красные строки — уязвимости, жёлтые — подозрительные 4xx/5xx.",
        "hint": "Вкладка «Scan Results» (сверху).",
        "action": "_goto_results_tab",
        "action_label": "Открыть вкладку Results",
    },
    {
        "title": "Шаг 6/7: Экспортируй отчёт",
        "text": "На вкладке Results можно выгрузить отчёт в MD / JSON / DOCX с рекомендациями и матрицей True/False.",
        "hint": "Кнопки «Export MD/JSON/DOCX…» на панели Results.",
    },
    {
        "title": "Шаг 7/7: Проекты",
        "text": "Каждый запуск создаёт отдельный проект (своя БД и настройки) в папке projects/. Менять проекты — через меню Project.",
        "hint": "Меню «Project» сверху.",
    },
    {
        "title": "Готово!",
        "text": "Теперь ты умеешь: перехватывать трафик, запускать скан и читать отчёты.\n\n⚠ Для локальных целей (localhost/127.x/10.x) отключи «Block private/metadata targets» в Settings.",
    },
]


class TutorialWindow(tk.Toplevel):
    """Интерактивный пошаговый туториал."""

    def __init__(self, parent: "App"):
        super().__init__(parent)
        self._parent = parent
        self._step = 0
        tokens = getattr(parent, "_tokens", None) or ui_theme.get_tokens("dark")
        self.configure(bg=tokens.app_bg)
        self.title("Обучение — Notscan")
        self.geometry("680x480")
        self.transient(parent)

        self._title_lbl = tk.Label(self, text="", font=("Segoe UI", 13, "bold"),
                                   bg=tokens.app_bg, fg="#89b4fa", wraplength=640, justify="left")
        self._title_lbl.pack(anchor="w", padx=16, pady=(16, 2))

        self._progress_lbl = tk.Label(self, text="", bg=tokens.app_bg, fg="#a6adc8", font=("Segoe UI", 9))
        self._progress_lbl.pack(anchor="w", padx=16)

        self._text = tk.Text(self, height=9, font=("Segoe UI", 10), wrap="word", relief="flat", borderwidth=0)
        ui_theme.apply_text_theme(self._text, tokens)
        self._text.pack(fill=tk.BOTH, expand=True, padx=16, pady=8)

        self._hint_lbl = tk.Label(self, text="", bg=tokens.app_bg, fg="#f9e2af",
                                  wraplength=640, justify="left", font=("Segoe UI", 9))

        self._action_btn = ttk.Button(self, text="", command=self._do_action)

        nav = ttk.Frame(self)
        nav.pack(fill=tk.X, padx=16, pady=(8, 12))
        self._back_btn = ttk.Button(nav, text="‹ Назад", command=self._back)
        self._back_btn.pack(side=tk.LEFT)
        self._next_btn = ttk.Button(nav, text="Дальше ›", command=self._next)
        self._next_btn.pack(side=tk.LEFT, padx=6)
        ttk.Button(nav, text="Закрыть", command=self.destroy).pack(side=tk.RIGHT)

        self._render()

    def _render(self):
        step = TUTORIAL_STEPS[self._step]
        self._title_lbl.configure(text=step["title"])
        self._progress_lbl.configure(text=f"Шаг {self._step + 1} из {len(TUTORIAL_STEPS)}")
        self._text.configure(state=tk.NORMAL)
        self._text.delete("1.0", tk.END)
        self._text.insert("1.0", step["text"])
        self._text.configure(state=tk.DISABLED)

        self._hint_lbl.pack_forget()
        hint = step.get("hint")
        if hint:
            self._hint_lbl.configure(text="» " + hint)
            self._hint_lbl.pack(anchor="w", padx=16, pady=(4, 2))

        self._action_btn.pack_forget()
        action = step.get("action")
        if action:
            self._action_btn.configure(text=step.get("action_label", "▶ Выполнить"))
            self._action_btn.pack(anchor="w", padx=16, pady=4)

        self._back_btn.configure(state=tk.NORMAL if self._step > 0 else tk.DISABLED)
        self._next_btn.configure(state=tk.DISABLED if self._step == len(TUTORIAL_STEPS) - 1 else tk.NORMAL)

    def _next(self):
        if self._step < len(TUTORIAL_STEPS) - 1:
            self._step += 1
            self._render()

    def _back(self):
        if self._step > 0:
            self._step -= 1
            self._render()

    def _do_action(self):
        step = TUTORIAL_STEPS[self._step]
        action = step.get("action")
        if not action:
            return
        try:
            getattr(self._parent, action)()
        except Exception as exc:
            mb.showerror("Обучение", f"Не удалось выполнить: {exc}")


# ──────────────────────────── Session picker (old projects) ────────────────────────────

class SessionPickerWindow(tk.Toplevel):
    """Окно выбора старой сессии (проекта) для открытия."""

    def __init__(self, parent: "App"):
        super().__init__(parent)
        self._app = parent
        self._tokens = getattr(parent, "_tokens", ui_theme.get_tokens("dark"))
        self._proj_by_iid: dict[str, Path] = {}
        self.title("Sessions / Projects")
        self.geometry("760x480")
        self.configure(bg=self._tokens.app_bg)
        self.transient(parent)
        self._build()
        self.refresh()

    def _build(self) -> None:
        top = ttk.Frame(self)
        top.pack(fill=tk.X, padx=8, pady=6)
        ttk.Label(top, text="Сессии (проекты):", font=("Segoe UI", 11, "bold"),
                  foreground="#89b4fa").pack(side=tk.LEFT)
        ttk.Button(top, text="↻ Refresh", command=self.refresh).pack(side=tk.LEFT, padx=6)
        ttk.Button(top, text="🆕 New project", command=self._new_project).pack(side=tk.LEFT, padx=6)

        body = ttk.Frame(self)
        body.pack(fill=tk.BOTH, expand=True, padx=8, pady=(0, 6))
        body.rowconfigure(0, weight=1)
        body.columnconfigure(0, weight=1)

        cols = ("name", "history", "results", "modified")
        self._tree = ttk.Treeview(body, columns=cols, show="headings", selectmode="browse")
        self._tree.heading("name", text="Project")
        self._tree.heading("history", text="History")
        self._tree.heading("results", text="Results")
        self._tree.heading("modified", text="Modified")
        self._tree.column("name", width=300, anchor="w")
        self._tree.column("history", width=90, anchor="e")
        self._tree.column("results", width=90, anchor="e")
        self._tree.column("modified", width=160, anchor="w")
        sb = ttk.Scrollbar(body, orient=tk.VERTICAL, command=self._tree.yview)
        self._tree.configure(yscrollcommand=sb.set)
        self._tree.grid(row=0, column=0, sticky="nsew")
        sb.grid(row=0, column=1, sticky="ns")
        self._tree.bind("<Double-1>", lambda e: self._open_selected())
        self._tree.tag_configure("current", foreground="#a6e3a1", font=("Segoe UI", 10, "bold"))

        btns = ttk.Frame(self)
        btns.pack(fill=tk.X, padx=8, pady=(0, 10))
        ttk.Button(btns, text="Open", style="Success.TButton", command=self._open_selected).pack(side=tk.RIGHT)
        ttk.Button(btns, text="Close", command=self.destroy).pack(side=tk.RIGHT, padx=6)

    def _counts(self, proj: Path) -> tuple[int, int]:
        """(history_rows, results_rows) для проекта, без блокировки (read-only)."""
        dbp = proj / "history.db"
        if not dbp.exists():
            return 0, 0
        try:
            import sqlite3
            conn = sqlite3.connect(f"file:{dbp}?mode=ro", uri=True)
            try:
                h = conn.execute("SELECT COUNT(*) FROM history").fetchone()[0]
                r = conn.execute("SELECT COUNT(*) FROM scan_results").fetchone()[0]
                return int(h), int(r)
            finally:
                conn.close()
        except Exception:
            return 0, 0

    def refresh(self) -> None:
        import project_manager as _pm
        for iid in self._tree.get_children():
            self._tree.delete(iid)
        self._proj_by_iid.clear()
        current = getattr(self._app, "_project_dir", None)
        try:
            projects = _pm.list_projects()
        except Exception:
            projects = []
        for proj in projects:
            iid = str(proj)
            self._proj_by_iid[iid] = proj
            h, r = self._counts(proj)
            name = proj.name
            if proj == current:
                name = "▶ " + name
            try:
                mtime = datetime.fromtimestamp(proj.stat().st_mtime).strftime("%Y-%m-%d %H:%M")
            except Exception:
                mtime = ""
            tags = ("current",) if proj == current else ()
            self._tree.insert("", tk.END, iid=iid, values=(name, h, r, mtime), tags=tags)
        if current is not None and str(current) in self._proj_by_iid:
            self._tree.selection_set(str(current))
            self._tree.focus(str(current))

    def _open_selected(self) -> None:
        sel = self._tree.selection()
        if not sel:
            return
        proj = self._proj_by_iid.get(sel[0])
        if proj is None:
            return
        try:
            self._app._switch_project(proj)
        except Exception as exc:
            mb.showerror("Sessions", f"Не удалось открыть сессию: {exc}")
            return
        self.destroy()

    def _new_project(self) -> None:
        import project_manager as _pm
        try:
            proj = _pm.create_project()
            self._app._switch_project(proj)
        except Exception as exc:
            mb.showerror("Sessions", f"Не удалось создать проект: {exc}")
            return
        self.destroy()


class App(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("Notscan")
        self.geometry("1280x850")

        # State
        self._scan_list: dict[int, dict] = {}   # history_id → record
        self._proxy_runner: Optional[ProxyRunner] = None
        # Авто-жизненный цикл прокси
        self._browser_proc: Optional[subprocess.Popen] = None
        self._proxy_watchdog_id = None
        self._idle_watchdog_ticks = 0
        self._proxy_confirmed_port: Optional[int] = None
        self._proxy_confirmed_host: str = ""
        self._proxy_starting = False
        self._restart_thread: Optional[threading.Thread] = None
        self._proxy_shutdown_done = False
        self._scan_runner: Optional[scanner_core.ScannerRunner] = None
        # Фоновый поток построения/запуска задач и вспомогательные потоки скана
        # (passive-проверки, info-disclosure probe) — нужны guard'у смены проекта.
        self._scan_thread: Optional[threading.Thread] = None
        self._aux_scan_threads: list[threading.Thread] = []
        self._session_manager: Optional[object] = None  # set by Auth tab patch
        self._use_contracts_var = tk.BooleanVar(value=False)
        self._contracts_map: dict[tuple[str, str], dict] | None = None

        # Scan config state (persistent, edited in the scan popup)
        # Каталог чеков — единый источник (checks/catalog.py); fallback — старые списки.
        self._check_vars: dict[str, tk.BooleanVar] = {}
        for _cid, _on in check_var_defs():
            self._check_vars[_cid] = tk.BooleanVar(value=_on)
        self._workers_var = tk.StringVar(value="10")
        self._mut_query = tk.BooleanVar(value=True)
        self._mut_form = tk.BooleanVar(value=True)
        self._mut_json = tk.BooleanVar(value=True)
        self._mut_headers = tk.BooleanVar(value=False)
        self._safe_mode_var = tk.BooleanVar(value=True)
        self._planner_var = tk.BooleanVar(value=True)
        # Tamper/WAF-bypass: payload-кодирование (TAMPER_MODES из templating).
        self._tamper_var = tk.BooleanVar(value=False)

        # Results-пагинация (M2): сколько строк уже загружено из БД / размер страницы.
        self._results_offset = 0
        self._results_page = 1000

        # Theme
        self._app_dir = Path(__file__).parent
        # Project separation: a new project folder is created on every launch.
        import project_manager as _pm
        self._projects_root = _pm.get_projects_root()
        self._project_dir = _pm.create_project()
        db.set_db_path(self._project_dir / "history.db")  # also calls init_db()
        self._settings: dict = ui_theme.load_settings(self._project_dir)
        self._theme_mode = (self._settings.get("theme_mode") or "dark").lower()
        self._tokens = ui_theme.get_tokens(self._theme_mode)
        self.configure(bg=self._tokens.app_bg)
        self._setup_style()

        self._build_ui()
        self._build_menubar()
        self._update_project_title()
        # Build Auth / RevShell / Checks tabs directly (not via monkey-patch)
        try:
            _patch_app_with_auth_and_revshell(self)
        except Exception as _e:
            import traceback, sys
            print(f"[PATCH ERROR] Extra tabs failed: {_e}", file=sys.stderr)
            traceback.print_exc()
        self.protocol("WM_DELETE_WINDOW", self._on_closing)

        # ── Авто-жизненный цикл прокси ─────────────────────
        # Прокси стартует сам при запуске App (если settings proxy_autostart),
        # watchdog следит за браузером/idle, _shutdown_proxy_sync освобождает
        # порт на закрытии (в т.ч. при SIGINT/SIGTERM/atexit).
        try:
            atexit.register(self._shutdown_proxy_sync)
        except Exception:
            pass
        try:
            self.after(300, self._maybe_autostart_proxy)
            self._proxy_watchdog_id = self.after(2000, self._proxy_watchdog_tick)
        except Exception:
            pass

        # Auto-refresh: списки обновляются сами при новых данных (без кнопки Refresh)
        self._last_hist_id = -1
        self._last_res_id = -1
        self._refresh_history()
        self._refresh_results()
        self.after(1000, self._auto_refresh_loop)

        self.log(
            "Добро пожаловать! Как пользоваться:\n"
            "  1) Прокси запускается автоматически (статус в панели Proxy)\n"
            "  2) «▶ Start Proxy + Browser» — открыть браузер через прокси\n"
            "  3) В History выдели запросы → «＋ Add to Scan list»\n"
            "  4) «▶ Run Scan» — результаты во вкладке Results\n"
            "  ⚠ Прокси останавливается автоматически: браузер закрыт,\n"
            "    простой (Settings) или закрытие приложения.\n"
            "  ⚠ Для локальных целей (localhost/127.x/10.x/192.168.x)\n"
            "    отключи «Block private/metadata targets» в Settings."
        )

        # Global hotkeys
        self.bind_all("<Control-Return>", lambda e: self._run_scan())
        self.bind_all("<Control-Shift-S>", lambda e: self._stop_scan())
        self.bind_all("<Control-e>", lambda e: self._export_report("json"))

    # ──────────────────────────── Project management ────────────────────────────

    def _update_project_title(self) -> None:
        try:
            self.title(f"Notscan — {self._project_dir.name}")
        except Exception:
            pass

    def _build_menubar(self) -> None:
        menubar = tk.Menu(self)
        proj_menu = tk.Menu(menubar, tearoff=0)
        proj_menu.add_command(label="Sessions / Projects...", command=self._open_session_picker)
        proj_menu.add_command(label="New Project", command=self._new_project)
        proj_menu.add_command(label="Open Project...", command=self._open_project)
        proj_menu.add_separator()
        proj_menu.add_command(label="Open Project Folder", command=self._open_project_folder)
        menubar.add_cascade(label="Project", menu=proj_menu)

        help_menu = tk.Menu(menubar, tearoff=0)
        help_menu.add_command(label="Обучение", command=self._open_tutorial)
        menubar.add_cascade(label="Help", menu=help_menu)
        try:
            self.config(menu=menubar)
        except Exception:
            pass

    def _scan_in_progress(self) -> bool:
        """Идёт ли скан: построение задач, воркеры или passive/info-disclosure потоки.

        Нужно для guard'а смены проекта: db.set_db_path() закрывает соединения
        живых потоков, и воркеры, создавшие их, получили бы ProgrammingError
        (часть результатов скана потерялась бы).
        """
        thread = getattr(self, "_scan_thread", None)
        if thread is not None and thread.is_alive():
            return True
        for aux in getattr(self, "_aux_scan_threads", ()) or ():
            if aux is not None and aux.is_alive():
                return True
        runner = getattr(self, "_scan_runner", None)
        if runner is None:
            return False
        try:
            return int(runner.tasks_remaining) > 0
        except Exception:
            return False

    def _warn_scan_in_progress(self) -> None:
        mb.showwarning(
            "Project",
            "Сканирование выполняется — дождись завершения или останови "
            "скан (Stop) перед сменой проекта.",
        )

    def _start_aux_scan_thread(self, target, **kwargs) -> None:
        """Запускает вспомогательный поток скана и запоминает его для guard'а."""
        self._aux_scan_threads = [t for t in self._aux_scan_threads if t.is_alive()]
        thread = threading.Thread(target=target, kwargs=kwargs, daemon=True)
        self._aux_scan_threads.append(thread)
        thread.start()

    def _run_probe_scan(self, urls: list[str], probe_ids: list[str]) -> int:
        """Probe-чеки (WSTG): run_probe_scan из path_probe с fallback на старый API.

         добавляет path_probe.run_probe_scan(urls, probe_ids, log_cb=…);
        пока его нет — работает прежний run_info_disclosure_scan.
        """
        runner = getattr(path_probe, "run_probe_scan", None)
        if runner is not None:
            try:
                return runner(urls, probe_ids, log_cb=self.log)
            except TypeError:
                try:
                    return runner(urls=urls, probe_ids=probe_ids, log_cb=self.log)
                except Exception as exc:
                    self.log(f"[PROBE][WARN] run_probe_scan failed: {exc} — fallback")
            except Exception as exc:
                self.log(f"[PROBE][ERR] {exc}")
                return 0
        legacy = getattr(path_probe, "run_info_disclosure_scan", None)
        if legacy is None:
            self.log("[PROBE][ERR] path_probe: нет run_probe_scan/run_info_disclosure_scan")
            return 0
        return legacy(urls=urls, log_cb=self.log)

    def _switch_project(self, proj_dir) -> None:
        # Guard: смена проекта во время скана закрыла бы соединения БД, которые
        # используют воркеры (ProgrammingError → потеря результатов).
        if self._scan_in_progress():
            self._warn_scan_in_progress()
            return
        proj_dir = Path(proj_dir)
        proj_dir.mkdir(parents=True, exist_ok=True)
        (proj_dir / "reports").mkdir(exist_ok=True)
        self._project_dir = proj_dir
        db.set_db_path(proj_dir / "history.db")
        self._settings = ui_theme.load_settings(proj_dir)
        self._scan_list.clear()
        self._contracts_map = None
        if getattr(self, "_session_manager", None):
            try:
                self._session_manager.logout()
            except Exception:
                pass
            self._session_manager = None
        self._update_project_title()
        self._refresh_history()
        self._refresh_scanlist()
        self._refresh_results()
        self.log(f"[PROJECT] Switched to {proj_dir.name}")

    def _new_project(self) -> None:
        if self._scan_in_progress():
            self._warn_scan_in_progress()
            return
        import project_manager as _pm
        proj = _pm.create_project()
        self._switch_project(proj)
        self.log(f"[PROJECT] New project created: {proj.name}")

    def _open_project(self) -> None:
        if self._scan_in_progress():
            self._warn_scan_in_progress()
            return
        import project_manager as _pm
        start = str(_pm.get_projects_root())
        chosen = filedialog.askdirectory(title="Open project folder", initialdir=start)
        if not chosen:
            return
        self._switch_project(Path(chosen))

    def _open_session_picker(self) -> None:
        SessionPickerWindow(self)

    def _open_project_folder(self) -> None:
        try:
            if os.name == "nt":
                os.startfile(str(self._project_dir))  # type: ignore[attr-defined]
            else:
                subprocess.Popen(["xdg-open", str(self._project_dir)])
        except Exception as exc:
            mb.showerror("Error", f"Could not open folder: {exc}")

    # ──────────────────────────── Style ────────────────────────────

    def _setup_style(self) -> None:
        theme = ui_theme.get_ttkbootstrap_theme(self._theme_mode)
        self._tb_style = tb.Style(theme=theme)
        style = self._tb_style

        # Store tokens for non-ttk widgets (tk.Text) and toplevel backgrounds
        self._style_bg = self._tokens.app_bg

        # Global font (Windows-first)
        try:
            style.configure(".", font=("Segoe UI", 10))
        except Exception:
            pass

        # Make data-dense tables readable
        try:
            style.configure("Treeview", rowheight=22)
            style.configure("Treeview.Heading", font=("Segoe UI", 10, "bold"))
        except Exception:
            pass

        # Notebook tab density (lighter, less chunky)
        try:
            style.configure("TNotebook.Tab", padding=(10, 6))
        except Exception:
            pass

        # Compatibility for existing code that uses style="Success.TButton"/"Danger.TButton"
        try:
            style.configure("Success.TButton")
            style.configure("Danger.TButton")
        except Exception:
            pass

        # Fix: ttkbootstrap "darkly" не задаёт fieldbackground для Spinbox —
        # поле остаётся белым, а текст белым → ничего не видно. Задаём явно.
        try:
            _fb = self._tokens.mono_bg
            _fg = self._tokens.app_fg
            _ins = self._tokens.insert_fg
            for _wname in ("TSpinbox", "TCombobox", "TEntry"):
                style.configure(_wname, fieldbackground=_fb, foreground=_fg, insertcolor=_ins)
        except Exception:
            pass

    def _set_theme_mode(self, mode: str) -> None:
        mode = (mode or "dark").lower()
        if mode not in ("light", "dark"):
            mode = "dark"
        if mode == getattr(self, "_theme_mode", "dark"):
            return
        self._theme_mode = mode
        self._tokens = ui_theme.get_tokens(self._theme_mode)
        self.configure(bg=self._tokens.app_bg)
        self._settings["theme_mode"] = self._theme_mode
        try:
            ui_theme.save_settings(self._project_dir, self._settings)
        except Exception:
            pass
        # Recreate style to apply new ttkbootstrap theme
        self._setup_style()
        self._apply_text_theme_everywhere()

    def _apply_text_theme_everywhere(self) -> None:
        for attr in ("_log_text",):
            w = getattr(self, attr, None)
            if w is not None:
                ui_theme.apply_text_theme(w, self._tokens)

    # ──────────────────────────── UI Builder ────────────────────────────

    def _build_ui(self) -> None:
        nb = ttk.Notebook(self)
        nb.pack(fill=tk.BOTH, expand=True, padx=6, pady=6)
        self._notebook = nb  # saved for patch access

        # Tabs
        self._tab_main = ttk.Frame(nb)
        self._tab_results = ttk.Frame(nb)
        self._tab_settings = ttk.Frame(nb)

        nb.add(self._tab_main, text="  Proxy / Scan  ")
        nb.add(self._tab_results, text="  Scan Results  ")
        nb.add(self._tab_settings, text="  Settings  ")

        self._build_main_tab()
        self._build_results_tab()
        self._build_settings_tab()

    # ──────────────────────────── Main tab ────────────────────────────

    def _build_main_tab(self) -> None:
        tab = self._tab_main
        tab.columnconfigure(0, weight=1)
        tab.columnconfigure(1, weight=1)
        tab.rowconfigure(0, weight=2)
        tab.rowconfigure(1, weight=1)
        tab.rowconfigure(2, weight=2)

        # ── Proxy controls (top bar) ──
        proxy_bar = ttk.LabelFrame(tab, text="Proxy  (авто-старт · авто-стоп; отдельной кнопки Stop нет)")
        proxy_bar.grid(row=0, column=0, columnspan=2, sticky="ew", padx=6, pady=(6, 2))
        proxy_bar.columnconfigure(4, weight=1)

        ttk.Label(proxy_bar, text="Host:").grid(row=0, column=0, padx=4, pady=4)
        self._proxy_host = ttk.Entry(proxy_bar, width=14)
        self._proxy_host.insert(0, "127.0.0.1")
        self._proxy_host.grid(row=0, column=1, padx=2)

        ttk.Label(proxy_bar, text="Port:").grid(row=0, column=2, padx=4)
        self._proxy_port = ttk.Spinbox(proxy_bar, from_=1, to=65535, width=7)
        self._proxy_port.set(8080)
        self._proxy_port.grid(row=0, column=3, padx=2)

        self._btn_start_proxy = ttk.Button(
            proxy_bar, text="▶ Start Proxy + Browser", style="Success.TButton",
            command=self._start_proxy_and_browser)
        self._btn_start_proxy.grid(row=0, column=4, padx=8, sticky="w")

        # Единый индикатор состояния (заменяет отдельную кнопку Stop).
        self._proxy_status_lbl = ttk.Label(proxy_bar, text="● STOPPED", foreground="#f38ba8")
        self._proxy_status_lbl.grid(row=0, column=5, padx=8)

        self._btn_sessions = ttk.Button(proxy_bar, text="📂 Sessions", command=self._open_session_picker)
        self._btn_sessions.grid(row=0, column=6, padx=(12, 4))

        # ── History (left) ──
        hist_frame = ttk.LabelFrame(tab, text="History")
        hist_frame.grid(row=1, column=0, sticky="nsew", padx=(6, 2), pady=2)
        hist_frame.rowconfigure(2, weight=1)
        hist_frame.columnconfigure(0, weight=1)

        hist_toolbar = ttk.Frame(hist_frame)
        hist_toolbar.grid(row=0, column=0, sticky="ew", pady=2)
        ttk.Button(hist_toolbar, text="Contract Inference", command=self._run_contract_inference).pack(side=tk.LEFT, padx=4)
        ttk.Button(hist_toolbar, text="Auth Boundary", command=self._run_auth_boundary).pack(side=tk.LEFT, padx=4)
        ttk.Checkbutton(hist_toolbar, text="Use contracts", variable=self._use_contracts_var).pack(side=tk.LEFT, padx=8)
        ttk.Button(hist_toolbar, text="＋ Add to Scan list", command=self._add_selected_to_scan).pack(side=tk.LEFT, padx=4)
        ttk.Button(hist_toolbar, text="🗑 Clear history", command=self._clear_history).pack(side=tk.LEFT, padx=4)
        ttk.Button(hist_toolbar, text="🧹 Clear browser noise",
                   command=self._clear_browser_noise).pack(side=tk.LEFT, padx=4)

        # Host/URL search — quick endpoint lookup by host/substring
        hist_search = ttk.Frame(hist_frame)
        hist_search.grid(row=1, column=0, sticky="ew", pady=2)
        ttk.Label(hist_search, text="🔍 Host/URL:").pack(side=tk.LEFT, padx=(4, 2))
        self._history_filter = ttk.Entry(hist_search)
        self._history_filter.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=2)
        self._history_filter.bind("<KeyRelease>", lambda e: self._refresh_history())
        ttk.Button(hist_search, text="✕ Clear", command=self._clear_history_filter).pack(side=tk.LEFT, padx=2)
        ttk.Button(hist_search, text="⬆ Import", command=self._import_collection).pack(side=tk.LEFT, padx=(8, 2))
        ttk.Button(hist_search, text="⬇ Export", command=self._export_collection).pack(side=tk.LEFT, padx=2)

        self._history_tree = self._make_tree(
            hist_frame,
            columns=("id", "time", "method", "code", "url"),
            headings=("ID", "Time", "Method", "Code", "URL"),
            widths=(50, 70, 60, 50, 400),
            row=2,
        )
        self._history_tree.bind("<Double-1>", lambda e: self._add_selected_to_scan())
        self._history_tree.bind("<Button-3>", self._on_history_right_click)

        # ── Scan list (right) ──
        scan_list_frame = ttk.LabelFrame(tab, text="Scan list")
        scan_list_frame.grid(row=1, column=1, sticky="nsew", padx=(2, 6), pady=2)
        scan_list_frame.rowconfigure(1, weight=1)
        scan_list_frame.columnconfigure(0, weight=1)

        sl_toolbar = ttk.Frame(scan_list_frame)
        sl_toolbar.grid(row=0, column=0, sticky="ew", pady=2)
        ttk.Button(sl_toolbar, text="✕ Remove selected", command=self._remove_from_scan).pack(side=tk.LEFT, padx=4)
        ttk.Button(sl_toolbar, text="✕ Clear all", command=self._clear_scan_list).pack(side=tk.LEFT, padx=4)
        ttk.Label(sl_toolbar, text="🔍 Host/URL:").pack(side=tk.LEFT, padx=(8, 2))
        self._scanlist_filter = ttk.Entry(sl_toolbar, width=20)
        self._scanlist_filter.pack(side=tk.LEFT, padx=2)
        self._scanlist_filter.bind("<KeyRelease>", lambda e: self._refresh_scanlist())

        self._scanlist_tree = self._make_tree(
            scan_list_frame,
            columns=("hist_id", "method", "url"),
            headings=("Hist ID", "Method", "URL"),
            widths=(60, 60, 400),
            row=1,
        )

        # ── Scan controls (compact; settings open in a popup) ──
        scan_bar = ttk.LabelFrame(tab, text="Scan")
        scan_bar.grid(row=2, column=0, sticky="nsew", padx=(6, 2), pady=(2, 6))

        self._btn_run_scan = ttk.Button(
            scan_bar, text="▶ Run Scan", style="Success.TButton",
            command=lambda: self._open_scan_config(require_scan_list=True))
        self._btn_run_scan.pack(side=tk.LEFT, padx=6, pady=6)

        ttk.Button(scan_bar, text="⚙ Settings",
                   command=lambda: self._open_scan_config(require_scan_list=False)).pack(side=tk.LEFT, padx=2)
        ttk.Button(scan_bar, text="Обучение",
                   command=self._open_tutorial).pack(side=tk.LEFT, padx=2)

        self._btn_stop_scan = ttk.Button(
            scan_bar, text="■ Stop Scan", style="Danger.TButton",
            command=self._stop_scan, state=tk.DISABLED)
        self._btn_stop_scan.pack(side=tk.LEFT, padx=6)

        self._scan_progress = ttk.Label(scan_bar, text="")
        self._scan_progress.pack(side=tk.LEFT, padx=8)

        self._scan_summary_lbl = ttk.Label(scan_bar, text="", foreground="#a6adc8")
        self._scan_summary_lbl.pack(side=tk.LEFT, padx=8)

        self._update_scan_summary()

        # ── Log (bottom right) ──
        log_frame = ttk.LabelFrame(tab, text="Log")
        log_frame.grid(row=2, column=1, sticky="nsew", padx=(2, 6), pady=(2, 6))
        log_frame.rowconfigure(0, weight=1)
        log_frame.columnconfigure(0, weight=1)

        self._log_text = tk.Text(
            log_frame,
            height=10,
            font=("Courier New", 9),
            state=tk.DISABLED,
            wrap=tk.NONE,
        )
        ui_theme.apply_text_theme(self._log_text, self._tokens)
        sb = ttk.Scrollbar(log_frame, orient=tk.VERTICAL, command=self._log_text.yview)
        self._log_text.configure(yscrollcommand=sb.set)
        sb.grid(row=0, column=1, sticky="ns")
        self._log_text.grid(row=0, column=0, sticky="nsew")

        # Configure row/col weights for main tab
        tab.rowconfigure(1, weight=3)
        tab.rowconfigure(2, weight=2)

    # ──────────────────────────── Results tab ────────────────────────────

    def _build_results_tab(self) -> None:
        tab = self._tab_results
        tab.rowconfigure(1, weight=1)
        tab.columnconfigure(0, weight=1)

        toolbar = ttk.Frame(tab)
        toolbar.grid(row=0, column=0, sticky="ew", padx=6, pady=4)
        ttk.Button(toolbar, text="Export MD…", command=lambda: self._export_report("md")).pack(side=tk.LEFT, padx=2)
        ttk.Button(toolbar, text="Export JSON…", command=lambda: self._export_report("json")).pack(side=tk.LEFT, padx=2)
        ttk.Button(toolbar, text="Export DOCX…", command=lambda: self._export_report("docx")).pack(side=tk.LEFT, padx=2)
        ttk.Separator(toolbar, orient=tk.VERTICAL).pack(side=tk.LEFT, fill=tk.Y, padx=6)
        ttk.Button(
            toolbar, text="🗑 Clear all results",
            command=self._clear_scan_results,
        ).pack(side=tk.LEFT, padx=4)
        ttk.Separator(toolbar, orient=tk.VERTICAL).pack(side=tk.LEFT, fill=tk.Y, padx=6)

        # Filters (local)
        self._filter_only_evidence = tk.BooleanVar(value=False)
        ttk.Checkbutton(toolbar, text="Only evidence", variable=self._filter_only_evidence).pack(side=tk.LEFT, padx=4)
        self._group_duplicates = tk.BooleanVar(value=True)
        ttk.Checkbutton(toolbar, text="Group duplicates", variable=self._group_duplicates,
                        command=self._refresh_results).pack(side=tk.LEFT, padx=4)

        ttk.Label(toolbar, text="Method:").pack(side=tk.LEFT, padx=(8, 2))
        self._filter_method = ttk.Combobox(
            toolbar, width=8, state="readonly",
            values=("", "GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS", "HEAD"),
        )
        self._filter_method.pack(side=tk.LEFT, padx=2)
        self._filter_method.bind("<<ComboboxSelected>>", lambda e: self._refresh_results())

        ttk.Label(toolbar, text="Sev:").pack(side=tk.LEFT, padx=(6, 2))
        self._filter_severity = ttk.Combobox(
            toolbar, width=9, state="readonly",
            values=("", "Critical", "High", "Medium", "Low", "Info"),
        )
        self._filter_severity.pack(side=tk.LEFT, padx=2)
        self._filter_severity.bind("<<ComboboxSelected>>", lambda e: self._refresh_results())

        ttk.Label(toolbar, text="Check:").pack(side=tk.LEFT, padx=(6, 2))
        self._filter_check = ttk.Entry(toolbar, width=14)
        self._filter_check.insert(0, "")
        self._filter_check.pack(side=tk.LEFT, padx=2)

        ttk.Label(toolbar, text="Host/URL:").pack(side=tk.LEFT, padx=(6, 2))
        self._filter_url = ttk.Entry(toolbar, width=20)
        self._filter_url.insert(0, "")
        self._filter_url.pack(side=tk.LEFT, padx=2)

        ttk.Button(toolbar, text="Apply", command=self._refresh_results).pack(side=tk.LEFT, padx=2)
        ttk.Button(toolbar, text="Clear", command=self._clear_results_filters).pack(side=tk.LEFT, padx=2)
        # M2: пагинация — кнопка догрузки и счётчик «показано / всего».
        self._btn_load_more = ttk.Button(toolbar, text="⏬ Load more", command=self._load_more_results)
        self._btn_load_more.pack(side=tk.RIGHT, padx=4)
        self._results_count_lbl = ttk.Label(toolbar, text="Results: 0 / 0", foreground="#a6adc8")
        self._results_count_lbl.pack(side=tk.RIGHT, padx=8)
        # Legend
        tk.Label(
            toolbar, text="  ● VULN", fg="#f38ba8",
            bg=self._style_bg, font=("Segoe UI", 9, "bold"),
        ).pack(side=tk.LEFT, padx=2)
        tk.Label(
            toolbar, text="● WARN 4xx/5xx", fg="#f9e2af",
            bg=self._style_bg, font=("Segoe UI", 9),
        ).pack(side=tk.LEFT, padx=2)
        tk.Label(
            toolbar, text="● OK", fg="#a6e3a1",
            bg=self._style_bg, font=("Segoe UI", 9),
        ).pack(side=tk.LEFT, padx=2)

        self._results_tree = self._make_tree(
            tab,
            columns=("id", "time", "method", "sev", "conf", "expl", "check", "payload", "code", "evidence", "url"),
            headings=("ID", "Time", "Method", "Sev", "Conf", "Expl", "Check", "Payload", "Code", "Evidence", "URL"),
            widths=(50, 70, 55, 60, 55, 55, 70, 140, 50, 220, 350),
            row=1,
        )
        self._results_tree.bind("<Double-1>", self._on_result_double_click)
        self._results_tree.bind("<Button-3>", self._on_result_right_click)

        # Tag for found vulns (red = evidence present)
        self._results_tree.tag_configure("vuln", foreground="#f38ba8", font=("Segoe UI", 10, "bold"))
        # Tag for non-200 responses without evidence (yellow = worth inspecting)
        self._results_tree.tag_configure("warn", foreground="#f9e2af")
        # Tag for errors / no response
        self._results_tree.tag_configure("err", foreground="#a6adc8")

        # Hotkeys (Results)
        self.bind_all("<F5>", lambda e: self._refresh_results())

    def _clear_results_filters(self) -> None:
        try:
            self._filter_only_evidence.set(False)
            self._filter_check.delete(0, tk.END)
            self._filter_url.delete(0, tk.END)
            self._filter_method.set("")
            self._filter_severity.set("")
        except Exception:
            pass
        self._refresh_results()

    # ──────────────────────────── Settings tab ────────────────────────────

    def _build_settings_tab(self) -> None:
        tab = self._tab_settings
        tab.columnconfigure(1, weight=1)

        row = 0

        def labeled_entry(label: str, default: str, width: int = 30) -> ttk.Entry:
            nonlocal row
            ttk.Label(tab, text=label).grid(row=row, column=0, sticky="w", padx=12, pady=5)
            e = ttk.Entry(tab, width=width)
            e.insert(0, default)
            e.grid(row=row, column=1, sticky="ew", padx=6)
            row += 1
            return e

        # ── Appearance ────────────────────────────────────────────────────────
        ttk.Label(
            tab,
            text="Appearance",
            font=("Segoe UI", 11, "bold"),
            foreground="#89b4fa",
        ).grid(row=row, column=0, columnspan=2, sticky="w", padx=12, pady=(12, 4))
        row += 1

        self._theme_mode_var = tk.StringVar(value=getattr(self, "_theme_mode", "dark"))
        theme_row = ttk.Frame(tab)
        theme_row.grid(row=row, column=0, columnspan=2, sticky="w", padx=12, pady=2)
        ttk.Label(theme_row, text="Theme:").pack(side=tk.LEFT, padx=(0, 8))
        ttk.Radiobutton(
            theme_row,
            text="Dark",
            value="dark",
            variable=self._theme_mode_var,
            command=lambda: self._set_theme_mode(self._theme_mode_var.get()),
        ).pack(side=tk.LEFT, padx=4)
        ttk.Radiobutton(
            theme_row,
            text="Light",
            value="light",
            variable=self._theme_mode_var,
            command=lambda: self._set_theme_mode(self._theme_mode_var.get()),
        ).pack(side=tk.LEFT, padx=4)
        row += 1

        ttk.Label(tab, text="Burp Browser settings",
                  font=("Segoe UI", 11, "bold"), foreground="#89b4fa").grid(
            row=row, column=0, columnspan=2, sticky="w", padx=12, pady=(12, 4))
        row += 1

        default_burp = "/usr/share/burpsuite/burpbrowser/chrome"
        try:
            if os.name == "nt":
                default_burp = str(Path(os.environ.get("ProgramFiles", "C:\\Program Files")) / "BurpSuiteCommunity" / "BurpSuiteCommunity.exe")
        except Exception:
            pass
        self._burp_browser_path = labeled_entry(
            "Burp Browser binary path:",
            default_burp,
            width=60,
        )
        self._burp_browser_profile = labeled_entry(
            "Browser profile dir:",
            str(Path.home() / ".BurpSuite" / "pre-wired-browser"),
        )

        # ── Авто-жизненный цикл прокси ─────────────────────────────
        ttk.Label(tab, text="Proxy auto-lifecycle",
                  font=("Segoe UI", 11, "bold"), foreground="#89b4fa").grid(
            row=row, column=0, columnspan=2, sticky="w", padx=12, pady=(12, 4))
        row += 1

        _popts = self._get_proxy_settings()
        self._proxy_autostart_var = tk.BooleanVar(
            value=bool(_popts.get("proxy_autostart", False)))
        ttk.Checkbutton(
            tab,
            text="Auto-start proxy when app launches (default OFF — start it with the "
                 "«▶ Start Proxy + Browser» button)",
            variable=self._proxy_autostart_var,
            command=self._save_proxy_settings,
        ).grid(row=row, column=0, columnspan=2, sticky="w", padx=12, pady=2)
        row += 1

        self._proxy_filter_noise_var = tk.BooleanVar(
            value=bool(_popts.get("proxy_filter_noise", True)))
        ttk.Checkbutton(
            tab,
            text="Filter browser background noise from History (Google telemetry/updates, "
                 "safe-browsing, connectivity checks)",
            variable=self._proxy_filter_noise_var,
            command=self._save_proxy_settings,
        ).grid(row=row, column=0, columnspan=2, sticky="w", padx=12, pady=2)
        row += 1

        self._proxy_stop_on_browser_exit_var = tk.BooleanVar(
            value=bool(_popts.get("proxy_stop_on_browser_exit", True)))
        ttk.Checkbutton(
            tab,
            text="Stop proxy when the launched browser is closed",
            variable=self._proxy_stop_on_browser_exit_var,
            command=self._save_proxy_settings,
        ).grid(row=row, column=0, columnspan=2, sticky="w", padx=12, pady=2)
        row += 1

        _idle_min = _popts.get("proxy_idle_stop_min", 15)
        try:
            _idle_str = str(int(float(_idle_min)))
        except (TypeError, ValueError):
            _idle_str = "15"
        idle_row = ttk.Frame(tab)
        idle_row.grid(row=row, column=0, columnspan=2, sticky="w", padx=12, pady=2)
        ttk.Label(idle_row, text="Idle auto-stop (minutes; 0 = off):").pack(side=tk.LEFT)
        self._proxy_idle_min_var = tk.StringVar(value=_idle_str)
        _idle_spin = ttk.Spinbox(
            idle_row, from_=0, to=1440, width=6,
            textvariable=self._proxy_idle_min_var, command=self._save_proxy_settings,
        )
        _idle_spin.pack(side=tk.LEFT, padx=6)
        _idle_spin.bind("<FocusOut>", lambda _e: self._save_proxy_settings())
        row += 1

        ttk.Label(tab, text="Scan scope",
                  font=("Segoe UI", 11, "bold"), foreground="#89b4fa").grid(
            row=row, column=0, columnspan=2, sticky="w", padx=12, pady=(12, 4))
        row += 1
        self._scope_allowlist_entry = labeled_entry(
            "Scope allowlist (comma-separated hosts/URLs; empty = no restriction):",
            "", width=55,
        )
        self._scope_block_private_var = tk.BooleanVar(value=True)
        ttk.Checkbutton(
            tab,
            text="Block private/metadata targets (localhost, 127.x, 10.x, 192.168.x, 169.254.169.254)",
            variable=self._scope_block_private_var,
        ).grid(row=row, column=0, columnspan=2, sticky="w", padx=12, pady=2)
        row += 1

        ttk.Label(tab, text="ROE / rate limiting",
                  font=("Segoe UI", 11, "bold"), foreground="#89b4fa").grid(
            row=row, column=0, columnspan=2, sticky="w", padx=12, pady=(12, 4))
        row += 1
        self._roe_max_rps_entry = labeled_entry("Max requests/sec (0 = unlimited):", "0", width=10)
        self._roe_block_checks_entry = labeled_entry(
            "Block check types (comma-separated; applied before task build):",
            "file_upload,ssrf,xxe,deserialization",
            width=55,
        )
        self._roe_stop_on_session_drift = tk.BooleanVar(value=True)
        ttk.Checkbutton(
            tab,
            text="Stop scan on session drift (401/403, redirect to login, login-page content)",
            variable=self._roe_stop_on_session_drift,
        ).grid(row=row, column=0, columnspan=2, sticky="w", padx=12, pady=2)
        row += 1

        ttk.Separator(tab, orient=tk.HORIZONTAL).grid(
            row=row, column=0, columnspan=2, sticky="ew", padx=12, pady=10)
        row += 1

        ttk.Label(tab, text="Payload files (relative to app dir)",
                  font=("Segoe UI", 11, "bold"), foreground="#89b4fa").grid(
            row=row, column=0, columnspan=2, sticky="w", padx=12, pady=(4, 4))
        row += 1

        payload_btn_row = ttk.Frame(tab)
        payload_btn_row.grid(row=row, column=0, columnspan=2, sticky="w", padx=12, pady=(0, 4))
        ttk.Button(payload_btn_row, text="👁 View payloads", command=self._open_payload_viewer).pack(side=tk.LEFT, padx=2)
        ttk.Button(payload_btn_row, text="📂 Open payloads folder", command=self._open_payloads_folder).pack(side=tk.LEFT, padx=2)
        ttk.Label(payload_btn_row, text="Custom: drop <check>.txt into payloads/custom/",
                  foreground="#a6adc8").pack(side=tk.LEFT, padx=10)
        row += 1

        PAYLOAD_FILES = [
            ("CMDI",         "cmdi.txt"),
            ("SQLi Error",   "sqli.txt"),
            ("SQLi Time",    "sqli_time.txt"),
            ("XSS",          "xss.txt"),
            ("SSTI",         "ssti.txt"),
            ("Path Traversal","path_traversal.txt"),
            ("XXE",          "xxe.txt"),
            ("SSRF",         "ssrf.txt"),
            ("NoSQLi",       "nosqli.txt"),
            ("LDAPi",        "ldapi.txt"),
            ("XPathi",       "xpath.txt"),
            ("Deserialization","deserialization.txt"),
            ("CRLF/Header",  "crlf.txt"),
            ("Open Redirect","open_redirect.txt"),
            ("File Upload",  "file_upload.txt"),
        ]
        for pname, fname in PAYLOAD_FILES:
            p = Path(__file__).parent / "payloads" / fname
            if not p.exists():
                p = Path(__file__).parent / fname
            exists = "✓" if p.exists() else "✗"
            color = "#a6e3a1" if p.exists() else "#f38ba8"
            text = p.read_text(encoding="utf-8", errors="replace") if p.exists() else ""
            lines = len(text.splitlines()) if p.exists() else 0
            non_comment = sum(1 for l in (text.splitlines() if p.exists() else [])
                              if l.strip() and not l.strip().startswith("#"))
            ttk.Label(tab, text=f"{pname}:").grid(row=row, column=0, sticky="w", padx=12, pady=1)
            ttk.Label(tab, text=f"{exists} {fname}  ({non_comment} payloads)", foreground=color).grid(
                row=row, column=1, sticky="w", padx=6)
            row += 1

    def _open_payload_viewer(self) -> None:
        """Окно просмотра состава словарей (payloads/*.txt)."""
        win = tk.Toplevel(self)
        win.title("Payload dictionaries")
        win.geometry("760x580")
        tokens = getattr(self, "_tokens", ui_theme.get_tokens("dark"))
        win.configure(bg=tokens.app_bg)

        payload_dir = Path(__file__).parent / "payloads"
        files = sorted(payload_dir.glob("*.txt")) if payload_dir.exists() else []
        labels = [f.name for f in files]

        top = ttk.Frame(win)
        top.pack(fill=tk.X, padx=8, pady=6)
        ttk.Label(top, text="Dictionary:").pack(side=tk.LEFT)
        combo = ttk.Combobox(top, values=labels, state="readonly", width=28)
        combo.pack(side=tk.LEFT, padx=6)

        info = ttk.Label(win, text="", foreground="#a6adc8")
        info.pack(anchor="w", padx=10)

        txt = tk.Text(win, font=("Courier New", 9), wrap=tk.NONE)
        ui_theme.apply_text_theme(txt, tokens)
        sb = ttk.Scrollbar(win, orient=tk.VERTICAL, command=txt.yview)
        txt.configure(yscrollcommand=sb.set)
        sb.pack(side=tk.RIGHT, fill=tk.Y, pady=4)
        txt.pack(fill=tk.BOTH, expand=True, padx=(8, 0), pady=4)

        def _load(_=None):
            name = combo.get()
            if not name:
                return
            p = payload_dir / name
            if not p.exists():
                return
            content = p.read_text(encoding="utf-8", errors="replace")
            lines = [l.strip() for l in content.splitlines() if l.strip() and not l.startswith("#")]
            info.configure(text=f"{name}: {len(lines)} payloads")
            txt.configure(state=tk.NORMAL)
            txt.delete("1.0", tk.END)
            txt.insert("1.0", "\n".join(lines))
            txt.configure(state=tk.DISABLED)

        combo.bind("<<ComboboxSelected>>", _load)
        if labels:
            combo.set(labels[0])
            _load()

    def _open_payloads_folder(self) -> None:
        payload_dir = Path(__file__).parent / "payloads"
        payload_dir.mkdir(parents=True, exist_ok=True)
        try:
            if os.name == "nt":
                os.startfile(str(payload_dir))  # type: ignore[attr-defined]
            else:
                subprocess.Popen(["xdg-open", str(payload_dir)])
            self.log(f"[PAYLOADS] Opened folder: {payload_dir}")
        except Exception as exc:
            mb.showerror("Error", f"Could not open folder: {exc}")

    # ──────────────────────────── Treeview factory ────────────────────────────

    def _make_tree(
        self,
        parent,
        columns: tuple,
        headings: tuple,
        widths: tuple,
        row: int,
    ) -> ttk.Treeview:
        frame = ttk.Frame(parent)
        frame.grid(row=row, column=0, sticky="nsew", padx=4, pady=2)
        frame.rowconfigure(0, weight=1)
        frame.columnconfigure(0, weight=1)

        tree = ttk.Treeview(frame, columns=columns, show="headings", selectmode="extended")
        vsb = ttk.Scrollbar(frame, orient=tk.VERTICAL, command=tree.yview)
        hsb = ttk.Scrollbar(frame, orient=tk.HORIZONTAL, command=tree.xview)
        tree.configure(yscrollcommand=vsb.set, xscrollcommand=hsb.set)

        for col, heading, width in zip(columns, headings, widths):
            tree.heading(col, text=heading, anchor="w")
            tree.column(col, width=width, anchor="w", stretch=(col == columns[-1]))

        vsb.grid(row=0, column=1, sticky="ns")
        hsb.grid(row=1, column=0, sticky="ew")
        tree.grid(row=0, column=0, sticky="nsew")

        return tree

    # ──────────────────────────── Log ────────────────────────────

    def log(self, msg: str) -> None:
        """Thread-safe log append (безопасно после destroy/в atexit)."""
        def _do():
            try:
                self._log_text.configure(state=tk.NORMAL)
                ts = datetime.now().strftime("%H:%M:%S")
                self._log_text.insert(tk.END, f"[{ts}] {msg}\n")
                self._log_text.see(tk.END)
                self._log_text.configure(state=tk.DISABLED)
            except Exception:
                pass
        try:
            self.after(0, _do)
        except (tk.TclError, RuntimeError):
            # окно уже уничтожено ИЛИ вызвали из потока без mainloop
            try:
                print(msg)
            except Exception:
                pass

    # ──────────────────────────── Proxy controls ────────────────────────────

    def _port_in_use(self, host: str, port: int) -> bool:
        import socket as _socket
        s = _socket.socket(_socket.AF_INET, _socket.SOCK_STREAM)
        s.settimeout(1.0)
        try:
            s.bind((host, port))
            return False
        except OSError:
            return True
        finally:
            s.close()

    # ── Авто-жизненный цикл прокси ────────────

    def _get_proxy_settings(self) -> dict:
        """Текущие настройки авто-прокси: settings + живые значения Settings tab."""
        opts = proxy_settings(getattr(self, "_settings", {}) or {})
        try:
            var = getattr(self, "_proxy_autostart_var", None)
            if var is not None:
                opts["proxy_autostart"] = bool(var.get())
            var = getattr(self, "_proxy_stop_on_browser_exit_var", None)
            if var is not None:
                opts["proxy_stop_on_browser_exit"] = bool(var.get())
            var = getattr(self, "_proxy_filter_noise_var", None)
            if var is not None:
                opts["proxy_filter_noise"] = bool(var.get())
            var = getattr(self, "_proxy_idle_min_var", None)
            if var is not None:
                try:
                    opts["proxy_idle_stop_min"] = max(0.0, float(var.get() or 0))
                except (TypeError, ValueError):
                    pass
        except Exception:
            pass
        return opts

    def _save_proxy_settings(self) -> None:
        try:
            self._settings.update(self._get_proxy_settings())
            ui_theme.save_settings(self._project_dir, self._settings)
        except Exception:
            pass

    def _set_proxy_status(self, text: str, running: bool = False) -> None:
        try:
            self._proxy_status_lbl.configure(
                text=text, foreground="#a6e3a1" if running else "#f38ba8"
            )
        except Exception:
            pass

    def _start_proxy(self, auto: bool = False) -> bool:
        """Запуск прокси. При занятом порте — авто-подбор, БЕЗ модалки-тупика."""
        if self._proxy_starting:
            return False
        host = (self._proxy_host.get() or "").strip() or "127.0.0.1"
        try:
            port = int(self._proxy_port.get())
        except (TypeError, ValueError):
            if auto:
                port = 8080
                try:
                    self._proxy_port.set(port)
                except Exception:
                    pass
            else:
                mb.showerror("Error", "Invalid proxy port")
                return False

        if self._proxy_runner is not None and self._proxy_runner.is_running:
            return True

        # ── Port busy → следующий свободный (не блокируем запуск App) ──
        if not port_is_free(host, port):
            free = find_free_port(host, port, attempts=100)
            if free is None:
                self.log(f"[PROXY][ERR] port {host}:{port} busy — свободных портов не найдено")
                self._set_proxy_status("● STOPPED (no free port)", running=False)
                return False
            self.log(f"[PROXY] port {port} busy → using {free}")
            port = free
            try:
                self._proxy_port.set(port)
            except Exception:
                pass

        if self._proxy_runner is not None:
            try:
                self._proxy_runner.stop(wait=True)
            except Exception:
                pass

        self._proxy_starting = True
        try:
            self._proxy_runner = ProxyRunner(
                host=host,
                port=port,
                log_callback=self.log,
                filter_noise=bool(self._get_proxy_settings().get("proxy_filter_noise", True)),
            )
            try:
                self._proxy_runner.start()
            except Exception as exc:
                self.log(f"[PROXY][ERR] failed to start proxy: {exc}")
                self._set_proxy_status("● STOPPED (start failed)", running=False)
                return False

            self._proxy_confirmed_port = port
            self._proxy_confirmed_host = host
            self._set_proxy_status(f"● RUNNING :{port}", running=True)
            # Start-кнопка всегда доступна: если прокси уже запущен, она открывает
            # браузер (а при изменённом порте — перезапускает прокси на новом порту).
            try:
                self._btn_start_proxy.configure(state=tk.NORMAL)
            except Exception:
                pass
            return True
        finally:
            self._proxy_starting = False

    def _maybe_autostart_proxy(self) -> None:
        """after(300): авто-старт прокси при запуске App (settings proxy_autostart)."""
        if os.environ.get("NOTSCAN_DISABLE_PROXY_AUTOSTART") == "1":
            self.log("[PROXY] auto-start disabled (NOTSCAN_DISABLE_PROXY_AUTOSTART=1)")
            return
        try:
            if not self._get_proxy_settings().get("proxy_autostart", False):
                self.log(
                    "[PROXY] Прокси не запущен (авто-старт выключен). Нажми "
                    "«▶ Start Proxy + Browser», чтобы запустить прокси и открыть браузер."
                )
                return
        except Exception:
            pass
        if self._proxy_runner is not None and self._proxy_runner.is_running:
            return
        self.log("[PROXY] auto-starting proxy…")
        ok = self._start_proxy(auto=True)
        if ok:
            self.log(
                "[PROXY] Прокси запущен автоматически. Нажми «▶ Start Proxy + Browser», "
                "чтобы открыть браузер; порт можно изменить в поле Port и нажать ту же кнопку."
            )
        else:
            self.log(
                "[PROXY][ERR] Авто-старт прокси не удался — нажми «▶ Start Proxy + Browser» для повтора."
            )

    def _start_proxy_and_browser(self) -> None:
        """One-click: прокси (запуск/перезапуск при смене порта) + открыть браузер.

        Кнопка никогда не блокируется: если прокси уже запущен на том же
        endpoint — просто открываем браузер; если пользователь изменил
        host/port — перезапускаем прокси на новом порту и открываем браузер.
        """
        try:
            host = (self._proxy_host.get() or "").strip() or "127.0.0.1"
            port = int(self._proxy_port.get())
            if not (1 <= port <= 65535):
                raise ValueError
        except (TypeError, ValueError):
            mb.showerror("Proxy", "Некорректный host/port прокси")
            return

        running = bool(self._proxy_runner and self._proxy_runner.is_running)
        if not running:
            if not self._start_proxy(auto=False):
                return
            # дать прокси подняться до запуска браузера (без блокировки UI)
            self.after(700, self._open_burp_browser)
            return

        current_host = self._proxy_confirmed_host or host
        current_port = self._proxy_confirmed_port
        endpoint_changed = bool(current_port) and (host, port) != (current_host, current_port)
        if not endpoint_changed:
            self.log(f"[PROXY] already running on {host}:{port} — launching browser only")
            self._open_burp_browser()
            return

        if self._browser_proc is not None and self._browser_proc.poll() is None:
            if not mb.askyesno(
                "Proxy",
                f"Прокси уже запущен на {current_host}:{current_port}.\n"
                f"Закрыть браузер и перезапустить прокси на {host}:{port}?",
            ):
                # вернуть поля к фактическому endpoint, чтобы не путать
                try:
                    self._proxy_host.delete(0, tk.END)
                    self._proxy_host.insert(0, current_host)
                    self._proxy_port.set(current_port)
                except Exception:
                    pass
                return
            self._terminate_browser()

        self.log(f"[PROXY] switching {current_host}:{current_port} → {host}:{port} (restart)")
        self._set_proxy_status(f"● RESTARTING → :{port}", running=False)
        try:
            self._btn_start_proxy.configure(state=tk.DISABLED)
        except Exception:
            pass

        # Останавливаем прокси в фоне (сеть/сокеты), затем стартуем на новом
        # endpoint УЖЕ В GUI-ПОТОКЕ (Tkinter не потокобезопасен).
        runner = self._proxy_runner
        self._restart_thread = threading.Thread(
            target=self._stop_for_restart, args=(runner,), daemon=True,
            name="proxy-restart-stop",
        )
        self._restart_thread.start()
        self.after(100, self._wait_restart)

    def _stop_for_restart(self, runner) -> None:
        try:
            if runner is not None:
                runner.stop(wait=True)
        except Exception:
            pass

    def _wait_restart(self) -> None:
        thread = getattr(self, "_restart_thread", None)
        if thread is not None and thread.is_alive():
            self.after(100, self._wait_restart)
            return
        ok = self._start_proxy(auto=False)
        self._restart_done(ok)

    def _restart_done(self, ok: bool) -> None:
        try:
            self._btn_start_proxy.configure(state=tk.NORMAL)
        except Exception:
            pass
        if ok:
            self.after(700, self._open_burp_browser)
        else:
            self._set_proxy_status("● STOPPED (restart failed)", running=False)
            self.log("[PROXY][ERR] restart failed — проверь host/port и попробуй ещё раз")

    def _terminate_browser(self) -> None:
        """Закрыть браузер, запущенный приложением (для смены порта прокси)."""
        proc = self._browser_proc
        self._browser_proc = None
        if proc is None or proc.poll() is not None:
            return
        try:
            proc.terminate()
            try:
                proc.wait(timeout=3)
            except Exception:
                proc.kill()
            self.log("[BROWSER] closed for proxy restart")
        except Exception as exc:
            logger.debug("browser terminate failed: %s", exc)

    def _stop_proxy(self, reason: str = "manual") -> None:
        """Приватная остановка (кнопки Stop в UI больше нет)."""
        runner = self._proxy_runner
        port = self._proxy_confirmed_port
        if runner is not None:
            threading.Thread(
                target=runner.stop, kwargs={"wait": True}, daemon=True
            ).start()
        try:
            self._btn_start_proxy.configure(state=tk.NORMAL)
        except Exception:
            pass
        if reason == "manual":
            self._set_proxy_status("● STOPPED", running=False)
        else:
            suffix = f" — port :{port} free" if port else ""
            self._set_proxy_status(f"● STOPPED ({reason}){suffix}", running=False)

    def _auto_stop_proxy(self, reason: str) -> None:
        """Авто-стоп по жизненному циклу (браузер закрыт / idle)."""
        runner = self._proxy_runner
        port = self._proxy_confirmed_port
        if runner is not None:
            threading.Thread(
                target=runner.stop, kwargs={"wait": True}, daemon=True
            ).start()
        try:
            self._btn_start_proxy.configure(state=tk.NORMAL)
        except Exception:
            pass
        suffix = f" — port :{port} free" if port else ""
        self._set_proxy_status(f"● STOPPED ({reason}){suffix}", running=False)

    def _check_browser_exit(self) -> None:
        """Watchdog каждые 2с: браузер закрыт → авто-стоп прокси."""
        proc = self._browser_proc
        if proc is None:
            return
        if proc.poll() is None:
            return
        self._browser_proc = None
        try:
            stop_on_exit = bool(
                self._get_proxy_settings().get("proxy_stop_on_browser_exit", True)
            )
        except Exception:
            stop_on_exit = True
        if not stop_on_exit:
            self.log("[BROWSER] closed — proxy kept running (setting disabled)")
            return
        if self._proxy_runner is not None and self._proxy_runner.is_running:
            self.log("[PROXY] browser closed — stopping proxy automatically")
            self._auto_stop_proxy("browser closed")
        else:
            self._set_proxy_status("● STOPPED (browser closed)", running=False)

    def _check_idle_stop(self, now: Optional[float] = None) -> None:
        """Idle-автостоп: простой >= proxy_idle_stop_min минут → стоп."""
        runner = self._proxy_runner
        if runner is None or not runner.is_running:
            return
        try:
            minutes = float(self._get_proxy_settings().get("proxy_idle_stop_min", 15) or 0)
        except (TypeError, ValueError):
            minutes = 15.0
        if minutes <= 0:
            return
        last_activity = float(getattr(runner, "last_activity_ts", 0.0) or 0.0)
        check_now = float(now if now is not None else time.time())
        if should_idle_stop(check_now, last_activity, minutes):
            idle_label = int(minutes) if minutes == int(minutes) else minutes
            self.log(f"[PROXY] idle for ≥{idle_label} min — stopping proxy automatically")
            self._auto_stop_proxy(f"idle {idle_label} min")

    def _proxy_watchdog_tick(self) -> None:
        """Периодический watchdog: браузер (2с) и idle (60с)."""
        try:
            self._check_browser_exit()
            self._idle_watchdog_ticks += 1
            if self._idle_watchdog_ticks >= 30:
                self._idle_watchdog_ticks = 0
                self._check_idle_stop()
        except Exception:
            logger.debug("proxy watchdog error", exc_info=True)
        if getattr(self, "_proxy_shutdown_done", False):
            return
        try:
            self._proxy_watchdog_id = self.after(2000, self._proxy_watchdog_tick)
        except tk.TclError:
            pass

    def _shutdown_proxy_sync(self) -> None:
        """СИНХРОННО освободить порт: ProxyRunner.stop(wait=True) + PAC (+subprocess).

        Вызывается из _on_closing, atexit и обработчиков SIGINT/SIGTERM/SIGHUP.
        Идемпотентна (повторные вызовы ничего не делают).
        """
        if getattr(self, "_proxy_shutdown_done", False):
            return
        self._proxy_shutdown_done = True
        watchdog_id = getattr(self, "_proxy_watchdog_id", None)
        if watchdog_id is not None:
            try:
                self.after_cancel(watchdog_id)
            except Exception:
                pass
            self._proxy_watchdog_id = None
        runner = getattr(self, "_proxy_runner", None)
        port = getattr(self, "_proxy_confirmed_port", None)
        host = "127.0.0.1"
        try:
            host = (self._proxy_host.get() or "").strip() or host
        except Exception:
            pass
        if runner is not None:
            try:
                self.log("[APP] Stopping proxy before exit…")
            except Exception:
                pass
            try:
                runner.stop(wait=True)
            except Exception as exc:
                logger.warning("proxy shutdown error: %s", exc)
        self._proxy_runner = None
        # Контроль: порт должен быть свободен (best-effort, т.к. stop уже join'ил).
        try:
            if port and not port_is_free(host, port):
                logger.warning("proxy port %s:%s still busy after stop", host, port)
        except Exception:
            pass
        self._set_proxy_status("● STOPPED", running=False)

    def _get_pac_port(self) -> int:
        """Возвращает порт PAC-сервера если прокси запущен, иначе fallback на прокси-порт."""
        if self._proxy_runner and self._proxy_runner.pac_url:
            try:
                from urllib.parse import urlparse
                return urlparse(self._proxy_runner.pac_url).port or 18080
            except Exception:
                pass
        # PAC не запущен — отдаём URL вида "DIRECT" (через fallback pac на том же порту)
        try:
            return int(self._proxy_port.get()) + 10000  # запасной
        except Exception:
            return 18080

    def _open_burp_browser(self) -> None:
        host = self._proxy_host.get().strip() or "127.0.0.1"
        try:
            port = int(self._proxy_port.get())
        except ValueError:
            port = 8080
        proxy = f"{host}:{port}"

        # ── Найти бинарь ────────────────────────────────────────────────────
        browser_path = self._burp_browser_path.get().strip()
        executable = Path(browser_path)

        # Автопоиск стандартного Burp Browser
        if not executable.exists():
            burp_search = [
                Path("/usr/share/burpsuite/burpbrowser/140.0.7339.80/chrome"),
                Path("/usr/share/burpsuite/burpbrowser").glob("*/chrome")
                    if Path("/usr/share/burpsuite/burpbrowser").exists() else iter([]),
            ]
            # glob yields
            for candidate in [
                "/usr/share/burpsuite/burpbrowser/140.0.7339.80/chrome",
                "/usr/share/burpsuite/burpbrowser/chrome",
            ]:
                p = Path(candidate)
                if p.exists():
                    executable = p
                    self.log(f"[BROWSER] Found Burp Browser at: {p}")
                    break
            else:
                # Try glob for any version
                base = Path("/usr/share/burpsuite/burpbrowser")
                if base.exists():
                    for p in base.glob("*/chrome"):
                        executable = p
                        self.log(f"[BROWSER] Found Burp Browser (auto): {p}")
                        break

        # Fallback: системный Chromium / Chrome
        if not executable.exists():
            for candidate in ["chromium", "chromium-browser", "google-chrome", "google-chrome-stable"]:
                result = subprocess.run(["which", candidate], capture_output=True, text=True)
                if result.returncode == 0:
                    executable = Path(result.stdout.strip())
                    self.log(f"[BROWSER] Burp Browser not found, falling back to: {executable}")
                    break
            else:
                mb.showerror(
                    "Browser not found",
                    f"Cannot find browser.\n"
                    f"Expected: {browser_path}\n\n"
                    "Update the path in Settings tab.",
                )
                self.log(f"[BROWSER][ERR] No browser found at {browser_path}")
                return

        # ── Пути профиля и расширения ────────────────────────────────────────
        profile_dir = Path(self._burp_browser_profile.get().strip())
        profile_dir.mkdir(parents=True, exist_ok=True)

        extension_dir = Path.home() / ".BurpSuite" / "burp-chromium-extension"

        # ── Аргументы ─────────────────────────────────────────────────────────
        args = [
            str(executable),
            # PAC-скрипт — направляет ВСЕ запросы (включая localhost) через прокси.
            # Обычный --proxy-server + --proxy-bypass-list= НЕ работают для loopback.
            # PAC — единственный надёжный способ.
            f"--proxy-pac-url=http://127.0.0.1:{self._get_pac_port()}/proxy.pac",
            # Игнорировать самоподписанные / Burp CA сертификаты
            "--ignore-certificate-errors",
            "--ignore-ssl-errors",
            "--allow-insecure-localhost",
            # Изолированный профиль
            f"--user-data-dir={profile_dir}",
            # Обязательно для root / контейнеров
            "--no-sandbox",
            "--disable-setuid-sandbox",
            # GPU — отключить во избежание gbm_wrapper / dma_buf ошибок
            "--disable-gpu",
            "--disable-gpu-sandbox",
            "--disable-software-rasterizer",
            "--disable-dev-shm-usage",
            "--disable-accelerated-2d-canvas",
            # X11/Wayland: авто-определение
            "--ozone-platform-hint=auto",
            # Базовые Chromium флаги
            "--no-first-run",
            "--no-default-browser-check",
            "--no-pings",
            "--no-service-autorun",
            "--disable-background-networking",
            "--disable-breakpad",
            "--disable-crash-reporter",
            "--disable-default-apps",
            "--disable-ipc-flooding-protection",
            "--disable-notifications",
            # минимизация фонового сетевого шума Chromium
            "--disable-component-update",
            "--disable-domain-reliability",
            "--disable-client-side-phishing-detection",
            "--disable-sync",
            "--disable-component-extensions-with-background-pages",
            "--disable-speech-api",
            "--disable-permissions-api",
            "--disk-cache-size=0",
            "--media-cache-size=0",
            "--disable-features=ChromeWhatsNewUI,HttpsUpgrades,"
            "TrackingProtection3pcd,LensOverlay,"
            "OptimizationHints,MediaRouter,Translate,AutofillServerCommunication,"
            "CertificateTransparencyComponentUpdater,InterestFeedContentSuggestions,"
            "NetworkTimeServiceQuerying",
            "--user-agent=Mozilla/5.0 (X11; Linux x86_64) "
            "AppleWebKit/537.36 (KHTML, like Gecko) "
            "Chrome/120.0.0.0 Safari/537.36",
        ]

        # Подключить расширение Burp если каталог существует
        if extension_dir.exists():
            args.append(f"--load-extension={extension_dir}")

        args.append("about:blank")

        try:
            # Popen сохраняем: watchdog каждые 2с проверит, не закрылся ли
            # браузер, и авто-остановит прокси (settings proxy_stop_on_browser_exit).
            self._browser_proc = subprocess.Popen(args)
            self.log(f"[BROWSER] Launched: {executable.name} → proxy={proxy}")
            self.log(f"[BROWSER] Profile: {profile_dir}")
            self.log("[BROWSER] При закрытии браузера прокси остановится автоматически")
        except Exception as exc:
            self._browser_proc = None
            mb.showerror("Browser launch error", str(exc))
            self.log(f"[BROWSER][ERR] {exc}")

    # ──────────────────────────── History ────────────────────────────

    def _on_closing(self) -> None:
        """Корректное закрытие: синхронно освобождаем порт прокси и выходим."""
        try:
            self._shutdown_proxy_sync()
        except Exception as exc:
            logger.warning("Error stopping proxy on exit: %s", exc)
        try:
            self._browser_proc = None
        except Exception:
            pass
        self.destroy()

    def destroy(self) -> None:  # noqa: D401 - override Tk.destroy
        """Гарантированно освободить порт, даже если закрыли через destroy()."""
        try:
            self._shutdown_proxy_sync()
        except Exception:
            pass
        try:
            super().destroy()
        except tk.TclError:
            pass

    def _clear_browser_noise(self) -> None:
        """Удаляет из History фоновый шум браузера (Google telemetry/updates и т.п.).

        Нужно для проектов, в историю которых шум попал ДО включения фильтра
        proxy_filter_noise (новые такие запросы в History не пишутся).
        """
        try:
            rows = db.fetch_history(limit=10000)
        except Exception as exc:
            mb.showerror("Clear browser noise", str(exc))
            return
        noise_ids = []
        for row in rows:
            try:
                host = urlparse(row.get("url") or "").hostname or ""
            except Exception:
                host = ""
            if host and is_noise_host(host):
                noise_ids.append(int(row["id"]))
        if not noise_ids:
            self.log("[HISTORY] Фонового шума браузера в History не найдено")
            return
        if not mb.askyesno(
            "Clear browser noise",
            f"Найдено фоновых запросов браузера (Google/обновления и т.п.): "
            f"{len(noise_ids)}.\nУдалить их из History?",
        ):
            return
        deleted = db.delete_history_ids(noise_ids)
        self._refresh_history()
        self.log(f"[HISTORY] Удалено фоновых запросов: {deleted}")

    def _clear_history(self) -> None:
        if not mb.askyesno("Clear history", "Удалить всю историю запросов?"):
            return
        deleted = db.clear_history()
        for row in self._history_tree.get_children():
            self._history_tree.delete(row)
        # Также очищаем scan list если в нём есть элементы из истории
        self._scan_list.clear()
        for row in self._scanlist_tree.get_children():
            self._scanlist_tree.delete(row)
        self.log(f"[HISTORY] Cleared {deleted} records")

    def _clear_scan_results(self) -> None:
        """Очищает все результаты сканирования (с подтверждением)."""
        if not mb.askyesno(
            "Clear scan results",
            "Удалить ВСЕ результаты сканирования?\n\n"
            "Это действие необратимо — scan_results, scan_requests,\n"
            "scan_meta, confirmations и evidence snippets будут удалены.",
        ):
            return
        deleted = db.clear_scan_results()
        for row in self._results_tree.get_children():
            self._results_tree.delete(row)
        self._results_offset = 0
        self._update_results_counter()
        self.log(f"[RESULTS] Cleared {deleted} scan results")

    def _delete_scan_result(self, result_id: int) -> None:
        """Удаляет одну запись из результатов сканирования."""
        if not mb.askyesno(
            "Delete result",
            f"Удалить результат #{result_id}?",
        ):
            return
        try:
            db.delete_scan_result(result_id)
            if self._results_tree.exists(str(result_id)):
                self._results_tree.delete(str(result_id))
            self._update_results_counter()
            self.log(f"[RESULTS] Deleted result #{result_id}")
        except Exception as exc:
            mb.showerror("Error", f"Failed to delete result #{result_id}: {exc}")

    # ── Right-click context menus ──────────────────────────────────────────────

    def _on_history_right_click(self, event) -> None:
        """ПКМ в History tree — контекстное меню."""
        iid = self._history_tree.identify_row(event.y)
        if not iid:
            return
        self._history_tree.selection_set(iid)
        menu = tk.Menu(self, tearoff=0, bg="#313244", fg="#cdd6f4",
                       activebackground="#45475a", activeforeground="#cdd6f4",
                       relief="flat")
        menu.add_command(label="📋  Просмотр запроса / ответа",
                         command=lambda: self._show_history_raw(int(iid)))
        menu.add_command(label="＋  Добавить в Scan list",
                         command=self._add_selected_to_scan)
        menu.tk_popup(event.x_root, event.y_root)

    def _show_history_raw(self, history_id: int) -> None:
        """Открывает окно с raw request/response для записи истории."""
        record = db.fetch_history_by_id(history_id)
        if not record:
            mb.showerror("Not found", f"History #{history_id} not found")
            return
        RawViewWindow(self, record)

    def _on_result_right_click(self, event) -> None:
        """ПКМ в Scan Results tree — контекстное меню."""
        iid = self._results_tree.identify_row(event.y)
        if not iid:
            return
        self._results_tree.selection_set(iid)
        menu = tk.Menu(self, tearoff=0, bg="#313244", fg="#cdd6f4",
                       activebackground="#45475a", activeforeground="#cdd6f4",
                       relief="flat")
        menu.add_command(label="🔍  Подробная информация",
                         command=lambda: DetailWindow(self, int(iid)))
        menu.add_command(label="📋  Raw запрос (payload) / ответ",
                         command=lambda: self._show_scan_raw(int(iid)))
        menu.add_separator()
        menu.add_command(label="🗑  Удалить эту запись",
                         command=lambda: self._delete_scan_result(int(iid)))
        menu.tk_popup(event.x_root, event.y_root)

    def _show_scan_raw(self, result_id: int) -> None:
        """Открывает окно с raw mutated request / response для результата скана."""
        scan_req = db.fetch_scan_request_by_result(result_id)
        result   = db.fetch_scan_result_by_id(result_id)
        if not result:
            mb.showerror("Not found", f"Scan result #{result_id} not found")
            return
        ScanRawViewWindow(self, result, scan_req)

    def _load_contracts_cache(self) -> None:
        rows = db.fetch_endpoint_contracts(limit=5000)
        out: dict[tuple[str, str], dict] = {}

        def _loads(s, default):
            try:
                return json.loads(s) if s else default
            except Exception:
                return default

        for r in rows:
            method = (r.get("method") or "").upper()
            pat = r.get("url_pattern") or ""
            out[(method, pat)] = {
                "method": method,
                "url_pattern": pat,
                "param_types": _loads(r.get("param_types"), {}),
                "required_params": _loads(r.get("required_params"), []),
                "expected_codes": _loads(r.get("expected_codes"), []),
                "resp_schema": _loads(r.get("resp_schema"), {}),
                "content_type": r.get("content_type") or "",
                "sample_count": int(r.get("sample_count") or 0),
            }
        self._contracts_map = out

    def _run_contract_inference(self) -> None:
        def _bg():
            try:
                self.log("[CONTRACT] Inference started…")
                n = contract_inference.infer_all_contracts(log_cb=self.log, limit=5000)
                self._load_contracts_cache()
                self.log(f"[CONTRACT] Upserted {n} contract(s)")
                self.after(0, lambda: ContractWindow(self))
            except Exception as e:
                self.log(f"[CONTRACT][ERR] {e}")
                self.after(0, lambda: mb.showerror("Contract inference error", str(e)))
        threading.Thread(target=_bg, daemon=True).start()

    def _session_headers_for_boundary(self) -> dict:
        mgr = getattr(self, "_session_manager", None)
        if not mgr or not getattr(mgr, "auth_enabled", False):
            return {}
        headers: dict[str, str] = {}
        try:
            token = getattr(mgr, "access_token", None)
            if token:
                prefix = ""
                try:
                    prefix = getattr(getattr(mgr, "auth", None), "token_prefix", "Bearer ")
                except Exception:
                    prefix = "Bearer "
                headers["Authorization"] = f"{prefix}{token}"
        except Exception:
            pass
        try:
            cookies = getattr(mgr, "cookies", {}) or {}
            if cookies:
                headers["Cookie"] = "; ".join([f"{k}={v}" for k, v in cookies.items()])
        except Exception:
            pass
        return headers

    def _proxy_url_for_requests(self) -> Optional[str]:
        if self._proxy_runner and self._proxy_runner.is_running:
            host = self._proxy_host.get().strip() or "127.0.0.1"
            try:
                port = int(self._proxy_port.get())
            except Exception:
                port = 8080
            return f"http://{host}:{port}"
        return None

    def _run_auth_boundary(self) -> None:
        sel = list(self._history_tree.selection())
        if sel:
            ids = [int(x) for x in sel]
        elif self._scan_list:
            ids = list(self._scan_list.keys())
        else:
            mb.showinfo("Auth Boundary", "Select History rows (or add requests to Scan list) first")
            return

        session_headers = self._session_headers_for_boundary()
        if not session_headers:
            ok = mb.askyesno(
                "Auth Boundary",
                "No active session headers detected (Auth tab disabled / not logged in).\n"
                "Run boundary scan anyway (anonymous vs anonymous)?",
                icon="warning",
            )
            if not ok:
                return

        stop_event = threading.Event()

        def _bg():
            try:
                self.log(f"[AUTH] Boundary scan started for {len(ids)} request(s)…")
                auth_boundary.run_auth_boundary_scan(
                    history_ids=ids,
                    session_headers=session_headers,
                    proxy_url=self._proxy_url_for_requests(),
                    log_cb=self.log,
                    stop_event=stop_event,
                )
                self.after(0, lambda: AuthBoundaryResultsWindow(self))
            except Exception as e:
                self.log(f"[AUTH][ERR] {e}")
                self.after(0, lambda: mb.showerror("Auth Boundary error", str(e)))

        threading.Thread(target=_bg, daemon=True).start()

    def _refresh_history(self) -> None:
        selected = set(self._history_tree.selection())
        for row in self._history_tree.get_children():
            self._history_tree.delete(row)
        try:
            flt = (getattr(self, "_history_filter", None).get() or "").strip().lower()
        except Exception:
            flt = ""
        records = db.fetch_history(limit=500)
        for r in records:
            url = r.get("url") or ""
            if flt and flt not in url.lower():
                continue
            self._history_tree.insert(
                "", tk.END, iid=str(r["id"]),
                values=(
                    r["id"],
                    ts_to_str(r["time"]),
                    r["method"],
                    r["resp_status"] or "—",
                    _truncate(url, 120),
                ),
            )
        for iid in selected:
            try:
                if self._history_tree.exists(iid):
                    self._history_tree.selection_add(iid)
            except Exception:
                pass
        try:
            self._last_hist_id = db.latest_history_id()
        except Exception:
            pass

    def _auto_refresh_loop(self) -> None:
        """Фоновое автообновление History и Results (без кнопки Refresh)."""
        try:
            h = db.latest_history_id()
            if h != getattr(self, "_last_hist_id", -1):
                self._last_hist_id = h
                self._refresh_history()
            r = db.latest_scan_result_id()
            if r != getattr(self, "_last_res_id", -1):
                self._last_res_id = r
                self._refresh_results()
        except Exception:
            pass
        try:
            self.after(1000, self._auto_refresh_loop)
        except tk.TclError:
            pass  # окно закрыто

    def _clear_history_filter(self) -> None:
        try:
            self._history_filter.delete(0, tk.END)
        except Exception:
            pass
        self._refresh_history()

    def _import_collection(self) -> None:
        """Импорт коллекции (raw HTTP / HAR / Postman) в History."""
        path = filedialog.askopenfilename(
            title="Import collection",
            filetypes=[
                ("HTTP collections", "*.http *.txt *.har *.json"),
                ("Raw HTTP", "*.http *.txt"),
                ("HAR", "*.har"),
                ("Postman JSON", "*.json"),
                ("All files", "*.*"),
            ],
        )
        if not path:
            return
        try:
            import collection_io
            records = collection_io.import_collection(path)
        except Exception as e:
            self.log(f"[IMPORT][ERR] {e}")
            mb.showerror("Import", f"Failed to import: {e}")
            return
        if not records:
            mb.showwarning("Import", "No requests found in the file")
            return
        imported = 0
        for rec in records:
            try:
                db.insert_history(
                    method=rec["method"],
                    url=rec["url"],
                    req_headers=rec.get("headers") or {},
                    req_body=rec.get("body") or None,
                    resp_status=None,
                    resp_headers=None,
                    resp_body_preview=None,
                )
                imported += 1
            except Exception as e:
                self.log(f"[IMPORT][ERR] {rec.get('url', '?')}: {e}")
        self._refresh_history()
        self.log(f"[IMPORT] Imported {imported} request(s) from {Path(path).name}")
        mb.showinfo("Import", f"Imported {imported} request(s)")

    def _export_collection(self) -> None:
        """Экспорт выбранных запросов History в коллекцию (Postman или raw HTTP)."""
        sel = self._history_tree.selection()
        if not sel:
            mb.showinfo("Export", "Select requests in History first")
            return
        records = []
        for iid in sel:
            try:
                rec = db.fetch_history_by_id(int(iid))
            except Exception:
                rec = None
            if rec:
                records.append(rec)
        if not records:
            mb.showinfo("Export", "No valid requests selected")
            return
        path = filedialog.asksaveasfilename(
            defaultextension=".json",
            filetypes=[
                ("Postman JSON", "*.json"),
                ("Raw HTTP collection", "*.http *.txt"),
                ("All files", "*.*"),
            ],
            title="Export selected requests",
        )
        if not path:
            return
        try:
            import collection_io
            ext = Path(path).suffix.lower()
            if ext == ".json":
                n = collection_io.export_postman(records, path)
            else:
                n = collection_io.export_raw_http(records, path)
        except Exception as e:
            self.log(f"[EXPORT][ERR] {e}")
            mb.showerror("Export", f"Failed: {e}")
            return
        self.log(f"[EXPORT] Exported {n} request(s) to {path}")
        mb.showinfo("Export", f"Exported {n} request(s)")

    def _add_selected_to_scan(self) -> None:
        sel = self._history_tree.selection()
        if not sel:
            mb.showinfo("Scan list", "Select rows in History first")
            return
        added = 0
        for iid in sel:
            history_id = int(iid)
            if history_id not in self._scan_list:
                record = db.fetch_history_by_id(history_id)
                if record:
                    self._scan_list[history_id] = record
                    added += 1
        if added:
            self._refresh_scanlist()
        self.log(f"[SCAN LIST] Added {added} item(s), total: {len(self._scan_list)}")

    def _refresh_scanlist(self) -> None:
        """Перерисовывает Scan list из self._scan_list с учётом фильтра по host/URL."""
        try:
            flt = (getattr(self, "_scanlist_filter", None).get() or "").strip().lower()
        except Exception:
            flt = ""
        for item in self._scanlist_tree.get_children():
            self._scanlist_tree.delete(item)
        for history_id, record in self._scan_list.items():
            url = record.get("url") or ""
            if flt and flt not in url.lower():
                continue
            self._scanlist_tree.insert(
                "", tk.END, iid=str(history_id),
                values=(history_id, record.get("method"), _truncate(url, 100)),
            )

    def _remove_from_scan(self) -> None:
        sel = self._scanlist_tree.selection()
        for iid in sel:
            history_id = int(iid)
            self._scan_list.pop(history_id, None)
            self._scanlist_tree.delete(iid)
        self.log(f"[SCAN LIST] Removed {len(sel)} item(s)")

    def _clear_scan_list(self) -> None:
        self._scan_list.clear()
        for item in self._scanlist_tree.get_children():
            self._scanlist_tree.delete(item)
        self.log("[SCAN LIST] Cleared")

    # ──────────────────────────── Scan ────────────────────────────

    def _update_scan_summary(self) -> None:
        try:
            total = len(self._check_vars)
            on = sum(1 for v in self._check_vars.values() if v.get())
            workers = self._workers_var.get()
            safe = "ON" if self._safe_mode_var.get() else "OFF"
            tamper = "ON" if getattr(self, "_tamper_var", tk.BooleanVar(value=False)).get() else "OFF"
            self._scan_summary_lbl.configure(
                text=f"Checks: {on}/{total}  ·  Workers: {workers}  ·  Safe: {safe}  ·  Tamper: {tamper}"
            )
        except Exception:
            pass

    def _open_scan_config(self, require_scan_list: bool = False) -> None:
        """Открывает окно настройки скана. Скан стартует только после подтверждения внутри."""
        if require_scan_list and not self._scan_list:
            mb.showinfo("Scan", "Scan list is empty — добавь запросы из History")
            return
        self._update_scan_summary()
        win = ScanConfigWindow(self, on_start=self._run_scan)
        self.wait_window(win)
        self._update_scan_summary()

    def _open_tutorial(self) -> None:
        TutorialWindow(self)

    def _goto_results_tab(self) -> None:
        try:
            self._notebook.select(self._tab_results)
        except Exception:
            pass

    def _run_scan(self) -> None:
        if not self._scan_list:
            mb.showinfo("Scan", "Scan list is empty — add requests from History first")
            return

        history_ids = list(self._scan_list.keys())

        # ── Payload-file checks (legacy scanner_core) ──────────────────────────
        enabled_checks = []
        if self._check_vars.get("legacy_cmdi", tk.BooleanVar()).get():
            enabled_checks.append("cmdi")
        if self._check_vars.get("legacy_xss", tk.BooleanVar()).get():
            enabled_checks.append("xss")
        if self._check_vars.get("legacy_sqli", tk.BooleanVar()).get():
            enabled_checks.append("sqli")

        # ── Sync CheckRegistry with badge states (ids — из каталога/fallback) ──
        try:
            from checks.registry import get_registry
            reg = get_registry()
            for check_id in registry_check_ids():
                var = self._check_vars.get(check_id)
                if var is not None:
                    chk = reg.get(check_id)
                    if chk:
                        chk.enabled = var.get()
            enabled_registry = [c.check_id for c in reg.enabled_checks()]
            self.log(f"[SCAN] Registry checks active: {len(enabled_registry)}")
        except Exception as exc:
            self.log(f"[SCAN][WARN] Could not sync CheckRegistry: {exc}")

        if not enabled_checks and not any(
            self._check_vars.get(cid, tk.BooleanVar(value=False)).get()
            for cid in self._check_vars
        ):
            mb.showinfo("Scan", "No checks selected — toggle at least one badge ON")
            return

        try:
            workers = int(self._workers_var.get())
        except ValueError:
            workers = 10

        safe_mode = self._safe_mode_var.get()
        if not safe_mode:
            ok = mb.askyesno(
                "Active mode",
                "Active mode may send destructive payloads (DROP, INSERT, UPDATE, exec, etc.). "
                "Use only on authorized targets. Continue?",
                icon="warning",
            )
            if not ok:
                self.log("[SCAN] Cancelled — Active mode not confirmed")
                return

        # ── Добавляем в enabled_checks все активные badge-чеки, у которых есть
        # payload-файлы (id — из каталога, fallback — старый список) ──
        for cid in payload_check_ids():
            # Берём из badge-vars напрямую (не из legacy_* префикса)
            var = self._check_vars.get(cid)
            if var and var.get() and cid not in enabled_checks:
                enabled_checks.append(cid)

        # ROE: blocked check types (prevents task generation)
        blocked = set()
        try:
            raw_block = (getattr(self, "_roe_block_checks_entry", None).get() or "").strip()
            if raw_block:
                blocked = {s.strip().lower() for s in raw_block.split(",") if s.strip()}
        except Exception:
            blocked = set()
        if blocked:
            before = list(enabled_checks)
            enabled_checks = [c for c in enabled_checks if c.lower() not in blocked]
            removed = set(before) - set(enabled_checks)
            if removed:
                self.log(f"[ROE] Blocked checks removed: {sorted(removed)}")

        self.log(f"[SCAN] Building tasks for {len(history_ids)} request(s), checks: {enabled_checks}")

        # Build tasks in background to avoid freezing GUI
        def _build_and_run():
            # Диагностика тела запросов перед построением задач
            for hid in history_ids:
                rec = db.fetch_history_by_id(hid)
                if rec:
                    body = rec.get("req_body")
                    ct   = ""
                    try:
                        import json as _json
                        hdrs = _json.loads(rec.get("req_headers") or "{}")
                        ct = hdrs.get("content-type", hdrs.get("Content-Type", ""))
                    except Exception:
                        pass
                    self.log(
                        f"[SCAN] hist#{hid} {rec['method']} body={len(body) if body else 0}B "
                        f"ct={ct!r}"
                    )

            if self._use_contracts_var.get() and not self._contracts_map:
                try:
                    self._load_contracts_cache()
                    self.log(f"[CONTRACT] Loaded contracts for planner: {len(self._contracts_map or {})}")
                except Exception as exc:
                    self.log(f"[CONTRACT][WARN] Could not load contracts: {exc}")

            try:
                # Tamper/WAF-bypass + CSRF (contract/§3.5). Новые kwargs
                # пробрасываем только если scanner_core их уже принимает — так GUI
                # не падает, пока engine-dev/ не смержены.
                try:
                    import inspect as _inspect
                    _build_params = set(
                        _inspect.signature(scanner_core.build_scan_tasks).parameters
                    )
                except (TypeError, ValueError):
                    _build_params = set()

                _build_kwargs = dict(
                    history_ids=history_ids,
                    enabled_checks=enabled_checks,
                    do_query=self._mut_query.get(),
                    do_body_form=self._mut_form.get(),
                    do_body_json=self._mut_json.get(),
                    do_headers=self._mut_headers.get(),
                    safe_mode=safe_mode,  # from outer scope (confirmed on main thread if Active)
                    planner_enabled=getattr(self, "_planner_var", tk.BooleanVar(value=True)).get(),
                    contracts=(self._contracts_map if self._use_contracts_var.get() else None),
                )
                if "tamper_modes" in _build_params:
                    _tamper_modes = None
                    if getattr(self, "_tamper_var", tk.BooleanVar(value=False)).get():
                        try:
                            import templating as _templating
                            _tamper_modes = list(_templating.TAMPER_MODES)
                            self.log(f"[SCAN] Tamper/WAF-bypass ON: {_tamper_modes}")
                        except Exception as _te:
                            self.log(f"[SCAN][WARN] Tamper недоступен: {_te}")
                    _build_kwargs["tamper_modes"] = _tamper_modes
                if "csrf_token_provider" in _build_params:
                    _csrf_provider = None
                    try:
                        _sm = getattr(self, "_session_manager", None)
                        if _sm is not None:
                            _csrf_provider = _sm.csrf_token_provider  # bound method
                    except AttributeError:
                        _csrf_provider = None
                    _build_kwargs["csrf_token_provider"] = _csrf_provider
                tasks = scanner_core.build_scan_tasks(**_build_kwargs)
            except Exception as _exc:
                import traceback as _tb
                self.log(f"[SCAN][ERR] Не удалось построить задачи: {_exc}")
                _tb.print_exc()
                self.after(0, self._scan_finished)
                return

            # ── Passive checks: use STORED proxy response — no new network request ──
            # This avoids SSL timeouts entirely: the proxy already captured the response.
            # Набор passive-чеков — из каталога (fallback: прежний hardcoded set).
            PASSIVE_CHECK_IDS = set(passive_check_ids())
            active_passive = [
                cid for cid in PASSIVE_CHECK_IDS
                if self._check_vars.get(cid, tk.BooleanVar(value=False)).get()
            ]
            if active_passive:
                def _run_passive_checks():
                    try:
                        from checks.registry import get_registry
                        from checks.runner import run_checks_on_response
                        import json as _json
                        import templating as _templating
                        _reg = get_registry()
                        for _cid in PASSIVE_CHECK_IDS:
                            _chk = _reg.get(_cid)
                            if _chk:
                                _chk.enabled = _cid in active_passive

                        self.log(f"[PASSIVE] Analyzing stored responses for {active_passive} — {len(history_ids)} request(s)")
                        for _hid in history_ids:
                            _rec = db.fetch_history_by_id(_hid)
                            if not _rec:
                                continue
                            _method = _rec["method"]
                            _url    = _rec["url"]
                            # Use stored response captured by proxy — no new network call
                            _resp_status = _rec.get("resp_status") or 0
                            try:
                                _resp_hdrs = _json.loads(_rec.get("resp_headers") or "{}")
                            except Exception:
                                _resp_hdrs = {}
                            _resp_body = _rec.get("resp_body_preview") or b""
                            try:
                                _resp_text = _resp_body.decode("utf-8", errors="replace")
                            except Exception:
                                _resp_text = ""
                            try:
                                _req_hdrs = _json.loads(_rec.get("req_headers") or "{}")
                            except Exception:
                                _req_hdrs = {}
                            # ── Auto-inject random Origin if absent (needed for CORS passive checks)
                            # We use a random evil domain so that if the server reflects it
                            # verbatim we know it trusts arbitrary origins (real vulnerability).
                            if "origin" not in {k.lower() for k in _req_hdrs}:
                                try:
                                    import random as _random
                                    import string as _string
                                    _rand_suffix = "".join(_random.choices(_string.ascii_lowercase + _string.digits, k=8))
                                    _req_hdrs = dict(_req_hdrs)  # don't mutate original
                                    _req_hdrs["Origin"] = f"https://evil-{_rand_suffix}.com"
                                except Exception:
                                    pass
                            _body = _rec.get("req_body") or b""
                            _raw_req = _templating.build_raw_http(_method, _url, _req_hdrs, _body)
                            try:
                                run_checks_on_response(
                                    method=_method, url=_url,
                                    headers=_req_hdrs,
                                    body=_body,
                                    raw_http=_raw_req,
                                    resp_status=_resp_status,
                                    resp_headers=_resp_hdrs,
                                    resp_text=_resp_text,
                                    resp_elapsed_ms=0.0,
                                    resp_error=None,
                                    check_type="passive",
                                    payload="",
                                    mutation_point="",
                                    original_param="",
                                    history_id=_hid,
                                    registry=_reg,
                                    log_cb=self.log,
                                )
                                self.log(f"[PASSIVE] analyzed hist#{_hid} {_method} {_url[:60]} ({_resp_status})")
                            except Exception as _pe:
                                self.log(f"[PASSIVE][ERR] {_url}: {_pe}")
                        self.log("[PASSIVE] Done — refresh Results tab")
                    except Exception as _exc:
                        self.log(f"[PASSIVE][ERR] {_exc}")

                self._start_aux_scan_thread(_run_passive_checks)

            # ── Probe-чеки (WSTG): отдельные сетевые проверки путей/метафайлов.
            # Набор — из каталога (kind="probe"), включая info_disclosure_paths.
            # Запускаем ДО проверки "нет задач": иначе при выборе только probe
            # (без payload-чеков) ранний return обрывал проверку.
            enabled_probes = [
                cid for cid in probe_check_ids()
                if self._check_vars.get(cid, tk.BooleanVar(value=False)).get()
            ]
            run_infodisc = bool(enabled_probes)
            if run_infodisc:
                probe_urls = [self._scan_list[hid]["url"] for hid in history_ids]
                self._start_aux_scan_thread(
                    self._run_probe_scan, urls=probe_urls, probe_ids=enabled_probes,
                )
                self.log(
                    f"[PROBE] Starting path probe for {len(probe_urls)} URL(s), "
                    f"checks: {enabled_probes}"
                )

            if not tasks:
                if not active_passive and not run_infodisc:
                    self.log("[SCAN] No tasks generated — проверь:")
                    self.log("  • хотя бы один чек включён (бейдж активен)?")
                    self.log("  • у запроса есть query-параметры или тело?")
                    self.log("  • мутации Query/JSON/Form включены?")
                    self.log("  • тело запроса не пустое (смотри диагностику выше)?")
                    self.after(0, self._scan_finished)
                return

            self.log(f"[SCAN] {len(tasks)} tasks generated, starting {workers} workers …")

            # Передаём proxy_url чтобы httpx тоже проксировал localhost-запросы
            _proxy_url: Optional[str] = None
            if self._proxy_runner and self._proxy_runner.is_running:
                host = self._proxy_host.get().strip() or "127.0.0.1"
                try:
                    port = int(self._proxy_port.get())
                except Exception:
                    port = 8080
                _proxy_url = f"http://{host}:{port}"

            scope_allowlist_str = getattr(
                self, "_scope_allowlist_entry", None
            )
            scope_allowlist = []
            if scope_allowlist_str and getattr(scope_allowlist_str, "get", None):
                raw = (scope_allowlist_str.get() or "").strip()
                if raw:
                    scope_allowlist = [s.strip() for s in raw.split(",") if s.strip()]
            scope_block_private = getattr(
                self, "_scope_block_private_var", tk.BooleanVar(value=True)
            ).get()

            try:
                self._scan_runner = scanner_core.ScannerRunner(
                    tasks=tasks,
                    workers=workers,
                    log_callback=self.log,
                    proxy_url=_proxy_url,
                    session_manager=getattr(self, "_session_manager", None),
                    scope_allowlist=scope_allowlist if scope_allowlist else None,
                    scope_block_private=scope_block_private,
                    max_rps=float((getattr(self, "_roe_max_rps_entry", None).get() or "0").strip() or 0.0),
                    stop_on_session_drift=getattr(self, "_roe_stop_on_session_drift", tk.BooleanVar(value=True)).get(),
                )
                self._scan_runner.start()
            except Exception as _start_exc:
                self.log(f"[SCAN][ERR] Не удалось запустить скан: {_start_exc}")
                self.after(0, self._scan_finished)
                return

            self.after(0, lambda: self._btn_run_scan.configure(state=tk.DISABLED))
            self.after(0, lambda: self._btn_stop_scan.configure(state=tk.NORMAL))

            # Poll progress
            def _poll():
                runner = self._scan_runner
                if runner is None:
                    return
                remaining = runner.tasks_remaining
                total = len(tasks)
                done = total - remaining
                self.after(0, lambda: self._scan_progress.configure(
                    text=f"{done}/{total} tasks"
                ))
                if remaining > 0 and not runner._stop.is_set():
                    threading.Timer(1.0, _poll).start()
                elif not runner._stop.is_set():
                    self.after(0, self._scan_finished)
                # else: идёт остановка — финализацию сделает _stop_scan

            _poll()

        self._scan_thread = threading.Thread(target=_build_and_run, daemon=True)
        self._scan_thread.start()

    def _stop_scan(self) -> None:
        runner = self._scan_runner
        if runner is None:
            self._scan_finished()
            return
        # Не сбрасываем runner сразу: пока воркеры не завершились, смена проекта
        # всё ещё опасна (guard _scan_in_progress держит остаток задач > 0).
        self._btn_run_scan.configure(state=tk.DISABLED)
        self._scan_progress.configure(text="Stopping…")
        self.log("[SCAN] Stopping…")

        def _stop_then_finish():
            try:
                runner.stop()          # блокируется, пока воркеры не завершатся
            except Exception as exc:
                self.log(f"[SCAN][WARN] stop error: {exc}")
            self.after(0, self._scan_finished)

        threading.Thread(target=_stop_then_finish, daemon=True).start()

    def _scan_finished(self) -> None:
        # Скан завершён/остановлен: сбрасываем runner, иначе guard смены проекта
        # остался бы заблокированным (после Stop tasks_remaining может быть > 0).
        self._scan_runner = None
        self._scan_thread = None
        self._btn_run_scan.configure(state=tk.NORMAL)
        self._btn_stop_scan.configure(state=tk.DISABLED)
        self._scan_progress.configure(text="Done")
        self.log("[SCAN] Finished — refresh Results tab to see findings")
        # M2: новый скан — сброс пагинации Results на первую страницу.
        try:
            self._refresh_results(reset=True)
        except Exception:
            pass

    # ──────────────────────────── Results ────────────────────────────

    def _export_report(self, fmt: str) -> None:
        ext = {"json": ".json", "md": ".md", "docx": ".docx", "html": ".html", "sarif": ".sarif"}.get(fmt, ".json")
        try:
            report_dir = self._project_dir / "reports"
            report_dir.mkdir(parents=True, exist_ok=True)
            initialdir = str(report_dir)
        except Exception:
            initialdir = str(Path(__file__).parent)
        path = filedialog.asksaveasfilename(
            defaultextension=ext,
            filetypes=[(fmt.upper(), f"*{ext}"), ("All files", "*.*")],
            title=f"Export report as {fmt.upper()}",
            initialdir=initialdir,
        )
        if not path:
            return
        try:
            if fmt == "json":
                n = report_export.export_json(path)
            elif fmt == "md":
                n = report_export.export_md(path)
            elif fmt == "docx":
                n = report_export.export_docx(path)
            elif fmt == "html":
                n = report_export.export_html(path)
            elif fmt == "sarif":
                n = report_export.export_sarif(path)
            else:
                self.log(f"[EXPORT] Unknown format: {fmt}")
                return
            self.log(f"[EXPORT] Saved {n} findings to {path}")
            mb.showinfo("Export", f"Exported {n} findings to\n{path}")
        except Exception as e:
            self.log(f"[EXPORT][ERR] {e}")
            mb.showerror("Export error", str(e))

    def _refresh_results(self, reset: bool = True) -> None:
        """Перерисовывает Results. reset=True — сброс на первую страницу (M2)."""
        if getattr(self, "_results_tree", None) is None:
            return
        if reset:
            self._results_offset = 0
        selected = set(self._results_tree.selection())
        for row in self._results_tree.get_children():
            self._results_tree.delete(row)
        # M2: показываем уже загруженное окно (offset + страница), а не LIMIT 5000
        # без учёта фильтра evidence — иначе находки за пределами лимита терялись.
        loaded_limit = (
            getattr(self, "_results_offset", 0) + getattr(self, "_results_page", 1000)
        )
        records = db.fetch_scan_results_with_meta(limit=loaded_limit, offset=0)
        vuln_count = 0
        warn_count = 0

        def _text(attr: str) -> str:
            w = getattr(self, attr, None)
            try:
                return (w.get() or "").strip() if w is not None else ""
            except Exception:
                return ""

        def _sev_rank(sev):
            return {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}.get((sev or "").upper(), 5)

        try:
            only_ev = bool(getattr(self, "_filter_only_evidence", tk.BooleanVar(value=False)).get())
        except Exception:
            only_ev = False
        check_filter = _text("_filter_check").lower()
        url_filter = _text("_filter_url").lower()
        method_filter = _text("_filter_method").upper()
        sev_filter = _text("_filter_severity").lower()
        try:
            group_on = bool(getattr(self, "_group_duplicates", tk.BooleanVar(value=True)).get())
        except Exception:
            group_on = True

        # ── Дедупликация: сворачиваем находки по fingerprint ──
        if group_on:
            reps = {}
            order = []
            counts = {}
            for r in records:
                if not r.get("evidence"):
                    key = f"__single_{r['id']}"
                else:
                    key = r.get("fingerprint") or f"{r.get('check_type')}|{r.get('url')}"
                if key not in reps:
                    reps[key] = r
                    order.append(key)
                    counts[key] = 1
                else:
                    counts[key] += 1
                    if _sev_rank(r.get("severity")) < _sev_rank(reps[key].get("severity")):
                        reps[key] = r
            view = [reps[k] for k in order]
        else:
            view = records
            counts = {}

        for r in view:
            code = r["status_code"]
            evidence = r["evidence"]
            if only_ev and not evidence:
                continue
            if check_filter and check_filter not in (r.get("check_type") or "").lower():
                continue
            if method_filter and method_filter != (r.get("method") or "").upper():
                continue
            if sev_filter and sev_filter != (r.get("severity") or "").lower():
                continue
            if url_filter and url_filter not in (r.get("url") or "").lower():
                continue
            if evidence:
                tags = ("vuln",)
                vuln_count += 1
            elif code is None or str(code) == "ERR":
                tags = ("err",)
            elif isinstance(code, int) and code not in (200, 201, 204, 301, 302, 304):
                # 4xx / 5xx without evidence → yellow warning
                tags = ("warn",)
                warn_count += 1
            else:
                tags = ()

            evidence_val = _truncate(evidence, 80) or "—"
            if group_on and evidence:
                key = r.get("fingerprint") or f"{r.get('check_type')}|{r.get('url')}"
                n = counts.get(key, 1)
                if n > 1:
                    evidence_val = f"×{n} {evidence_val}"

            self._results_tree.insert(
                "", tk.END, iid=str(r["id"]),
                values=(
                    r["id"],
                    ts_to_str(r["time"]),
                    (r.get("method") or "—").upper(),
                    (r.get("severity") or "").title(),
                    f"{float(r.get('confidence') or 0.0):.2f}",
                    f"{float(r.get('exploitability') or 0.0):.2f}",
                    (r.get("check_type") or "").upper(),
                    _truncate(r.get("payload") or "", 40),
                    code or "ERR",
                    evidence_val,
                    _truncate(r.get("url") or "", 120),
                ),
                tags=tags,
            )
        for iid in selected:
            try:
                if self._results_tree.exists(iid):
                    self._results_tree.selection_add(iid)
            except Exception:
                pass
        try:
            self._last_res_id = db.latest_scan_result_id()
        except Exception:
            pass
        self._update_results_counter()

    def _load_more_results(self) -> None:
        """M2: догружает следующую страницу Results (offset += page)."""
        page = getattr(self, "_results_page", 1000)
        offset = getattr(self, "_results_offset", 0)
        try:
            total = db.count_scan_results()
        except Exception:
            return
        if offset + page >= total:
            self._update_results_counter()
            return
        self._results_offset = offset + page
        self._refresh_results(reset=False)

    def _update_results_counter(self) -> None:
        """Заголовок Results: «показано / всего» + доступность Load more."""
        try:
            shown = len(self._results_tree.get_children())
        except Exception:
            shown = 0
        try:
            total = db.count_scan_results()
        except Exception:
            total = 0
        try:
            self._results_count_lbl.configure(text=f"Results: {shown} / {total}")
        except Exception:
            pass
        try:
            loaded = getattr(self, "_results_offset", 0) + getattr(self, "_results_page", 1000)
            self._btn_load_more.configure(
                state=(tk.DISABLED if loaded >= total else tk.NORMAL)
            )
        except Exception:
            pass

    def _on_result_double_click(self, event) -> None:
        sel = self._results_tree.selection()
        if not sel:
            return
        result_id = int(sel[0])
        DetailWindow(self, result_id)


# ──────────────────────────── Entry point ────────────────────────────

# ══════════════════════════════════════════════════════════════════
#  Auth tab (вставляется как дополнительная вкладка в App._build_ui)
#  Patch: добавить вкладку Auth и RevShell в существующий App
# ══════════════════════════════════════════════════════════════════

def _patch_app_with_auth_and_revshell(app: "App") -> None:
    """
    Патчит экземпляр App: добавляет вкладки Auth и RevShell.
    Вызывается в конце __init__ после _build_ui().
    """
    # Use saved reference set in _build_ui; fall back to winfo_children scan
    nb = getattr(app, "_notebook", None)
    if nb is None:
        for child in app.winfo_children():
            if isinstance(child, ttk.Notebook):
                nb = child
                break
    if nb is None:
        return

    # ── Auth tab ──────────────────────────────────────────────────
    # Shows login requests captured from proxy history.
    # User selects one → it becomes the re-login template.
    # On 401 during scan the session manager replays that request.
    auth_tab = ttk.Frame(nb)
    nb.add(auth_tab, text="  Auth  ")
    auth_tab.columnconfigure(0, weight=1)
    auth_tab.columnconfigure(1, weight=1)
    auth_tab.rowconfigure(1, weight=1)

    # ── Header row ───────────────────────────────────────────────
    hdr = ttk.Frame(auth_tab)
    hdr.grid(row=0, column=0, columnspan=2, sticky="ew", padx=8, pady=(8, 4))

    ttk.Label(hdr, text="Login Requests",
              font=("Segoe UI", 11, "bold"), foreground="#89b4fa").pack(side=tk.LEFT)

    ttk.Button(hdr, text="↻ Refresh from History",
               command=lambda: _reload_login_requests()).pack(side=tk.LEFT, padx=8)

    _unauth_codes_var = tk.StringVar(value="401,403")
    ttk.Label(hdr, text="  Unauth codes:").pack(side=tk.LEFT, padx=(10, 2))
    _unauth_entry = ttk.Entry(hdr, textvariable=_unauth_codes_var, width=10)
    _unauth_entry.pack(side=tk.LEFT, padx=2)
    app._unauth_codes_entry = _unauth_entry

    _max_relogin_var = tk.StringVar(value="3")
    ttk.Label(hdr, text="  Max re-logins:").pack(side=tk.LEFT, padx=(8, 2))
    _relogin_spin = ttk.Entry(hdr, textvariable=_max_relogin_var, width=4)
    _relogin_spin.pack(side=tk.LEFT, padx=2)
    app._max_relogin_entry = _relogin_spin

    # ── Left pane: captured login requests ───────────────────────
    left_pane = ttk.LabelFrame(auth_tab, text="Captured Login Requests  (auto-detected from Proxy History)", padding=6)
    left_pane.grid(row=1, column=0, sticky="nsew", padx=(8, 3), pady=(0, 8))
    left_pane.columnconfigure(0, weight=1)
    left_pane.rowconfigure(1, weight=1)

    # Treeview of login candidates
    _login_cols = ("id", "time", "method", "url", "status", "hint")
    _login_tree = ttk.Treeview(left_pane, columns=_login_cols, show="headings", height=10)
    _login_tree.heading("id",     text="ID",     anchor="w")
    _login_tree.heading("time",   text="Time",   anchor="w")
    _login_tree.heading("method", text="Method", anchor="w")
    _login_tree.heading("url",    text="URL",    anchor="w")
    _login_tree.heading("status", text="Code",   anchor="w")
    _login_tree.heading("hint",   text="Detected fields", anchor="w")
    _login_tree.column("id",     width=40,  stretch=False)
    _login_tree.column("time",   width=70,  stretch=False)
    _login_tree.column("method", width=55,  stretch=False)
    _login_tree.column("url",    width=320, stretch=True)
    _login_tree.column("status", width=50,  stretch=False)
    _login_tree.column("hint",   width=180, stretch=True)

    _login_sb = ttk.Scrollbar(left_pane, orient=tk.VERTICAL, command=_login_tree.yview)
    _login_tree.configure(yscrollcommand=_login_sb.set)
    _login_sb.grid(row=1, column=1, sticky="ns")
    _login_tree.grid(row=1, column=0, sticky="nsew")

    # Request body preview below the tree
    ttk.Label(left_pane, text="Request body:", foreground="#a6adc8").grid(
        row=2, column=0, sticky="w", pady=(6, 2))
    _body_text = tk.Text(left_pane, height=5, font=("Consolas", 9), wrap=tk.WORD, state=tk.DISABLED)
    try:
        tokens_theme = getattr(app, "_tokens", None)
        if tokens_theme:
            import ui_theme as _uit
            _uit.apply_text_theme(_body_text, tokens_theme)
    except Exception:
        pass
    _body_sb = ttk.Scrollbar(left_pane, orient=tk.VERTICAL, command=_body_text.yview)
    _body_text.configure(yscrollcommand=_body_sb.set)
    _body_sb.grid(row=3, column=1, sticky="ns")
    _body_text.grid(row=3, column=0, sticky="ew", pady=2)

    btn_row = ttk.Frame(left_pane)
    btn_row.grid(row=4, column=0, columnspan=2, sticky="w", pady=(4, 0))
    ttk.Button(btn_row, text="▶ Use as Login Template",
               style="Success.TButton",
               command=lambda: _use_selected_as_login()).pack(side=tk.LEFT, padx=4)
    ttk.Button(btn_row, text="✕ Clear session",
               style="Danger.TButton",
               command=lambda: _clear_session()).pack(side=tk.LEFT, padx=4)

    # ── Right pane: live session state ───────────────────────────
    right_pane = ttk.LabelFrame(auth_tab, text="Live Session State", padding=8)
    right_pane.grid(row=1, column=1, sticky="nsew", padx=(3, 8), pady=(0, 8))
    right_pane.columnconfigure(0, weight=1)
    right_pane.rowconfigure(3, weight=1)

    status_row = ttk.Frame(right_pane)
    status_row.grid(row=0, column=0, sticky="ew", pady=(0, 6))
    _auth_status_badge = tk.Label(
        status_row, text="  ● INACTIVE  ",
        bg="#313244", fg="#a6adc8",
        font=("Segoe UI", 10, "bold"), relief="flat", padx=6, pady=2,
    )
    _auth_status_badge.pack(side=tk.LEFT, padx=(0, 8))
    _relogin_lbl = ttk.Label(status_row, text="Re-logins: 0", foreground="#a6adc8")
    _relogin_lbl.pack(side=tk.LEFT, padx=4)

    ttk.Label(right_pane, text="Active login template:", foreground="#a6adc8").grid(
        row=1, column=0, sticky="w", pady=(4, 0))
    _tpl_lbl = ttk.Label(right_pane, text="—", foreground="#cdd6f4", wraplength=380)
    _tpl_lbl.grid(row=2, column=0, sticky="ew")

    ttk.Label(right_pane, text="Cookies / Token:", foreground="#a6adc8").grid(
        row=3, column=0, sticky="w", pady=(8, 2))
    cookie_tree_frame = ttk.Frame(right_pane)
    cookie_tree_frame.grid(row=4, column=0, sticky="nsew")
    cookie_tree_frame.rowconfigure(0, weight=1)
    cookie_tree_frame.columnconfigure(0, weight=1)
    right_pane.rowconfigure(4, weight=1)

    _cookie_tree = ttk.Treeview(cookie_tree_frame,
                                 columns=("name", "value"), show="headings", height=6)
    _cookie_tree.heading("name",  text="Name",  anchor="w")
    _cookie_tree.heading("value", text="Value", anchor="w")
    _cookie_tree.column("name",  width=160, anchor="w")
    _cookie_tree.column("value", width=280, anchor="w")
    _csb = ttk.Scrollbar(cookie_tree_frame, orient=tk.VERTICAL, command=_cookie_tree.yview)
    _cookie_tree.configure(yscrollcommand=_csb.set)
    _csb.grid(row=0, column=1, sticky="ns")
    _cookie_tree.grid(row=0, column=0, sticky="nsew")

    # Auth log
    ttk.Label(right_pane, text="Auth log:", foreground="#a6adc8").grid(
        row=5, column=0, sticky="w", pady=(8, 2))
    right_pane.rowconfigure(6, weight=1)
    auth_log_frame = ttk.Frame(right_pane)
    auth_log_frame.grid(row=6, column=0, sticky="nsew")
    auth_log_frame.rowconfigure(0, weight=1)
    auth_log_frame.columnconfigure(0, weight=1)
    _auth_log_text = tk.Text(auth_log_frame, height=6, font=("Consolas", 9), wrap=tk.WORD,
                              state=tk.DISABLED)
    try:
        tokens_theme = getattr(app, "_tokens", None)
        if tokens_theme:
            import ui_theme as _uit
            _uit.apply_text_theme(_auth_log_text, tokens_theme)
    except Exception:
        pass
    _auth_log_sb2 = ttk.Scrollbar(auth_log_frame, orient=tk.VERTICAL, command=_auth_log_text.yview)
    _auth_log_text.configure(yscrollcommand=_auth_log_sb2.set)
    _auth_log_sb2.grid(row=0, column=1, sticky="ns")
    _auth_log_text.grid(row=0, column=0, sticky="nsew")

    # ── Helper: detect credential fields in request body ─────────
    CRED_FIELD_HINTS = [
        "username", "user", "login", "email", "mail", "phone",
        "password", "passwd", "pass", "pwd", "secret", "token",
        "credential", "cred",
    ]
    LOGIN_SUCCESS_CODES = {200, 201, 302, 303}

    def _detect_creds(body_bytes: bytes, content_type: str) -> list[str]:
        """Return list of detected credential field names from request body."""
        found = []
        if not body_bytes:
            return found
        try:
            text = body_bytes.decode("utf-8", errors="replace")
        except Exception:
            return found
        import urllib.parse as _up
        ct = (content_type or "").lower()
        if "json" in ct:
            try:
                import json as _j
                d = _j.loads(text)
                if isinstance(d, dict):
                    for k in d:
                        if any(h in k.lower() for h in CRED_FIELD_HINTS):
                            found.append(k)
            except Exception:
                pass
        else:  # form / raw
            try:
                pairs = _up.parse_qsl(text, keep_blank_values=True)
                for k, _ in pairs:
                    if any(h in k.lower() for h in CRED_FIELD_HINTS):
                        found.append(k)
            except Exception:
                pass
            if not found:
                # plain text heuristic
                for h in CRED_FIELD_HINTS:
                    if h in text.lower():
                        found.append(h)
        return found

    def _ts(ts_float):
        from datetime import datetime
        try:
            return datetime.fromtimestamp(ts_float).strftime("%H:%M:%S")
        except Exception:
            return str(ts_float)

    def _reload_login_requests():
        """Scan history for requests that look like login POSTs."""
        for row in _login_tree.get_children():
            _login_tree.delete(row)
        try:
            rows = db.fetch_history(limit=500)
        except Exception as e:
            app.log(f"[AUTH] history error: {e}")
            return
        import json as _j
        count = 0
        for rec in rows:
            if rec["method"] not in ("POST", "PUT"):
                continue
            status = rec.get("resp_status") or 0
            if status not in LOGIN_SUCCESS_CODES and status not in (400, 401, 422):
                # include 400/422 too — sometimes login fails with bad creds
                continue
            body = rec.get("req_body") or b""
            if not body:
                continue
            try:
                hdrs = _j.loads(rec.get("req_headers") or "{}")
            except Exception:
                hdrs = {}
            ct = hdrs.get("content-type", hdrs.get("Content-Type", "")).lower()
            creds = _detect_creds(body, ct)
            if not creds:
                continue
            hint = ", ".join(creds[:4])
            _login_tree.insert("", tk.END, iid=str(rec["id"]), values=(
                rec["id"],
                _ts(rec.get("time", 0)),
                rec["method"],
                rec["url"][:80],
                status,
                hint,
            ))
            count += 1
        app.log(f"[AUTH] Found {count} login request candidate(s)")

    def _auth_log(msg: str) -> None:
        app.log(msg)
        try:
            _auth_log_text.configure(state=tk.NORMAL)
            _auth_log_text.insert(tk.END, msg + "\n")
            _auth_log_text.see(tk.END)
            _auth_log_text.configure(state=tk.DISABLED)
        except tk.TclError:
            pass

    def _refresh_session_view() -> None:
        mgr = getattr(app, "_session_manager", None)
        if mgr is None or not getattr(mgr, "auth_enabled", False):
            _auth_status_badge.configure(text="  ● INACTIVE  ", bg="#313244", fg="#a6adc8")
            for row_id in _cookie_tree.get_children():
                _cookie_tree.delete(row_id)
            return
        store = getattr(mgr, "token_store", None)
        if store is None:
            _auth_status_badge.configure(text="  ● NOT AUTHENTICATED  ", bg="#3a2a1e", fg="#f9e2af")
            return
        token = getattr(store, "access_token", None)
        cookies = dict(getattr(store, "cookies", {}) or {})
        expired  = getattr(store, "is_expired", lambda: False)()
        relogins = getattr(mgr, "_relogin_count", 0)
        _relogin_lbl.configure(text=f"Re-logins: {relogins}")
        if token:
            if expired:
                _auth_status_badge.configure(text="  ● EXPIRED  ", bg="#3a1e1e", fg="#f38ba8")
            else:
                _auth_status_badge.configure(text="  ● ACTIVE (token)  ", bg="#1e3a2f", fg="#a6e3a1")
        elif cookies:
            _auth_status_badge.configure(text="  ● ACTIVE (cookies)  ", bg="#1e3a2f", fg="#a6e3a1")
        else:
            _auth_status_badge.configure(text="  ● NOT AUTHENTICATED  ", bg="#3a2a1e", fg="#f9e2af")
        # Refresh cookie tree
        for row_id in _cookie_tree.get_children():
            _cookie_tree.delete(row_id)
        if token:
            _cookie_tree.insert("", tk.END, values=("Bearer token", str(token)[:80]))
        for name, val in cookies.items():
            _cookie_tree.insert("", tk.END, values=(name, str(val)[:80]))

    def _show_body_preview(hist_id: int) -> None:
        """Show raw body of selected history row in preview widget."""
        import json as _j
        rec = db.fetch_history_by_id(hist_id)
        if not rec:
            return
        body = rec.get("req_body") or b""
        try:
            text = body.decode("utf-8", errors="replace")
        except Exception:
            text = repr(body)
        _body_text.configure(state=tk.NORMAL)
        _body_text.delete("1.0", tk.END)
        _body_text.insert("1.0", text)
        _body_text.configure(state=tk.DISABLED)

    def _on_login_select(event=None):
        sel = _login_tree.selection()
        if not sel:
            return
        try:
            hist_id = int(sel[0])
            _show_body_preview(hist_id)
        except Exception:
            pass

    _login_tree.bind("<<TreeviewSelect>>", _on_login_select)

    def _auth_file() -> Path:
        """Файл автосохранённых кредов текущего проекта."""
        return Path(app._project_dir) / "auth_session.json"

    def _activate_login_record(rec, *, save: bool = True) -> bool:
        """Build a SessionManager from a captured history record and activate it.
        Optionally persist the auth config to disk (autosave of creds)."""
        import json as _j
        import urllib.parse as _up
        try:
            hdrs = _j.loads(rec.get("req_headers") or "{}")
        except Exception:
            hdrs = {}
        ct_raw = hdrs.get("content-type", hdrs.get("Content-Type", "")).lower()
        content_type = "json" if "json" in ct_raw else "form"

        body_bytes = rec.get("req_body") or b""
        body_dict: dict = {}
        if content_type == "json":
            try:
                body_dict = _j.loads(body_bytes.decode("utf-8", errors="replace"))
            except Exception:
                body_dict = {}
        else:
            try:
                body_dict = dict(_up.parse_qsl(body_bytes.decode("utf-8", errors="replace"), keep_blank_values=True))
            except Exception:
                body_dict = {}

        # Guard: не активируем пустой/шаблонный боди без реальных кредов
        has_real_creds = any(
            isinstance(v, str) and v.strip()
            for k, v in body_dict.items()
            if any(h in k.lower() for h in CRED_FIELD_HINTS)
        )
        if not has_real_creds:
            _auth_log(f"[AUTH] Skip — no non-empty credential values in {rec['url'][:60]}")
            return False

        try:
            unauth = {int(c.strip()) for c in _unauth_codes_var.get().split(",") if c.strip()}
        except ValueError:
            unauth = {401, 403}
        try:
            max_rel = int(_max_relogin_var.get().strip() or "3")
        except ValueError:
            max_rel = 3

        from session_manager import AuthConfig, SessionManager, save_auth_config
        cfg = AuthConfig(
            enabled=True,
            login_url=rec["url"],
            method=rec["method"],
            body=body_dict,
            content_type=content_type,
            extra_headers={k: v for k, v in hdrs.items()
                           if k.lower() not in ("host", "content-length", "cookie",
                                                "transfer-encoding", "connection")},
            unauth_codes=unauth,
            max_relogin_attempts=max_rel,
        )
        mgr = SessionManager(auth_config=cfg, log_callback=_auth_log)
        app._session_manager = mgr
        _tpl_lbl.configure(text=f"{rec['method']} {rec['url'][:60]}")
        _auth_log(f"[AUTH] Login template set: {rec['method']} {rec['url']}")

        if save:
            try:
                save_auth_config(cfg, _auth_file())
                _auth_log(f"[AUTH] Credentials auto-saved to {_auth_file().name}")
            except Exception as exc:
                _auth_log(f"[AUTH][WARN] Could not save credentials: {exc}")

        import threading as _thr
        def _do_first_login():
            ok = mgr.login()
            app.log(f"[AUTH] {'Login OK ✓' if ok else 'Login FAILED ✗'}  {mgr}")
            app.after(0, _refresh_session_view)
        _thr.Thread(target=_do_first_login, daemon=True).start()
        return True

    def _use_selected_as_login():
        """Build SessionManager from the selected history row and activate it."""
        sel = _login_tree.selection()
        if not sel:
            mb.showinfo("Auth", "Select a login request from the list first")
            return
        try:
            hist_id = int(sel[0])
        except Exception:
            return
        rec = db.fetch_history_by_id(hist_id)
        if not rec:
            return
        _activate_login_record(rec, save=True)

    def _auto_activate_login():
        """Автоматически активирует лучший login-запрос из history
        (без участия юзера). Работает только когда активной сессии нет."""
        mgr = getattr(app, "_session_manager", None)
        if mgr is not None and getattr(mgr, "auth_enabled", False):
            return
        import json as _j
        try:
            rows = db.fetch_history(limit=500)
        except Exception:
            return
        best = None
        best_ts = -1.0
        for rec in rows:
            if rec["method"] not in ("POST", "PUT"):
                continue
            status = rec.get("resp_status") or 0
            if status not in LOGIN_SUCCESS_CODES and status not in (400, 401, 422):
                continue
            body = rec.get("req_body") or b""
            if not body:
                continue
            try:
                hdrs = _j.loads(rec.get("req_headers") or "{}")
            except Exception:
                hdrs = {}
            ct = hdrs.get("content-type", hdrs.get("Content-Type", "")).lower()
            creds = _detect_creds(body, ct)
            if not creds:
                continue
            ts = rec.get("time", 0) or 0
            if ts >= best_ts:
                best_ts = ts
                best = rec
        if best is None:
            return
        tried = getattr(app, "_auto_login_tried", None)
        if tried == best["url"]:
            return
        app._auto_login_tried = best["url"]
        if _activate_login_record(best, save=True):
            _auth_log("[AUTH] Auto-activated login from captured request")

    def _clear_session():
        if getattr(app, "_session_manager", None):
            try:
                app._session_manager.logout()
            except Exception:
                pass
        app._session_manager = None
        _tpl_lbl.configure(text="—")
        app.log("[AUTH] Session cleared")
        app.after(0, _refresh_session_view)

    app._refresh_session_view = _refresh_session_view

    # Expose for worker auto-relogin log
    def _poll_session():
        try:
            _auto_activate_login()
            _refresh_session_view()
        except Exception:
            pass
        try:
            app.after(2000, _poll_session)
        except tk.TclError:
            return  # widget destroyed

    def _restore_saved_auth():
        """Восстанавливает автосохранённые креды при старте (без участия юзера)."""
        try:
            from session_manager import SessionManager, load_auth_config
            cfg = load_auth_config(_auth_file())
            if cfg is not None and cfg.enabled and cfg.login_url:
                mgr = SessionManager(auth_config=cfg, log_callback=_auth_log)
                app._session_manager = mgr
                _tpl_lbl.configure(text=f"{cfg.method} {cfg.login_url[:60]}")
                _auth_log(f"[AUTH] Restored auto-saved credentials: {cfg.login_url}")
                import threading as _thr
                def _do_login():
                    ok = mgr.login()
                    app.log(f"[AUTH] {'Login OK ✓' if ok else 'Login FAILED ✗'}  {mgr}")
                    app.after(0, _refresh_session_view)
                _thr.Thread(target=_do_login, daemon=True).start()
        except Exception as exc:
            app.log(f"[AUTH] Could not restore saved session: {exc}")

    # Auto-load on tab open
    _reload_login_requests()
    app.after(500, _restore_saved_auth)
    app.after(2000, _poll_session)

    # ── RevShell tab ──────────────────────────────────────────────
    rs_tab = ttk.Frame(nb)
    nb.add(rs_tab, text="  RevShell  ")
    rs_tab.columnconfigure(1, weight=1)

    rs_row = 0

    def rs_lbl_entry(label, default="", width=20):
        nonlocal rs_row
        ttk.Label(rs_tab, text=label).grid(row=rs_row, column=0, sticky="w", padx=10, pady=3)
        e = ttk.Entry(rs_tab, width=width)
        e.insert(0, default)
        e.grid(row=rs_row, column=1, sticky="w", padx=6)
        rs_row += 1
        return e

    ttk.Label(rs_tab, text="Reverse Shell Generator",
              font=("Segoe UI", 11, "bold"), foreground="#89b4fa").grid(
        row=rs_row, column=0, columnspan=3, sticky="w", padx=10, pady=(10, 4))
    rs_row += 1

    ttk.Label(rs_tab, text="⚠ Commands are generated ONLY — not executed locally.",
              foreground="#f9e2af").grid(
        row=rs_row, column=0, columnspan=3, sticky="w", padx=10, pady=2)
    rs_row += 1

    lhost_entry = rs_lbl_entry("LHOST:", "10.10.10.10")
    lport_entry = rs_lbl_entry("LPORT:", "4444")

    # OS filter
    ttk.Label(rs_tab, text="OS target:").grid(row=rs_row, column=0, sticky="w", padx=10)
    os_filter_var = tk.StringVar(value="linux")
    ttk.Combobox(rs_tab, textvariable=os_filter_var,
                 values=["linux", "windows", "any"], width=10, state="readonly").grid(
        row=rs_row, column=1, sticky="w", padx=6)
    rs_row += 1

    # Vuln type for suggestions
    vuln_type_entry = rs_lbl_entry("Vuln type (hint):", "cmdi")
    app._rs_lhost = lhost_entry
    app._rs_lport = lport_entry
    app._rs_os_filter = os_filter_var
    app._rs_vuln_type = vuln_type_entry

    # Buttons
    rs_btn_frame = ttk.Frame(rs_tab)
    rs_btn_frame.grid(row=rs_row, column=0, columnspan=3, sticky="w", padx=10, pady=6)
    rs_row += 1

    def _generate_shells():
        from revshell.manager import ReverseShellManager
        mgr = ReverseShellManager(
            default_lhost=lhost_entry.get().strip(),
            default_lport=int(lport_entry.get().strip() or "4444"),
        )
        vuln_type = vuln_type_entry.get().strip() or "cmdi"
        options = mgr.suggest_revshell(
            vuln_type=vuln_type,
            lhost=lhost_entry.get().strip(),
            lport=int(lport_entry.get().strip() or "4444"),
            os_hint=os_filter_var.get(),
            max_suggestions=8,
        )
        # Clear and populate treeview
        for item in rs_tree.get_children():
            rs_tree.delete(item)
        for opt in options:
            cmd = opt.build(lhost_entry.get().strip(), int(lport_entry.get().strip() or "4444"))
            rs_tree.insert("", tk.END, iid=opt.id, values=(
                opt.name, opt.os_hint,
                ", ".join(opt.requires) or "—",
                _truncate(cmd, 80),
            ))
        app.log(f"[REVSHELL] Generated {len(options)} suggestions for {vuln_type}")

    def _show_full_command():
        sel = rs_tree.selection()
        if not sel:
            return
        shell_id = sel[0]
        from revshell.manager import ReverseShellManager
        mgr = ReverseShellManager()
        opt = mgr.get_option(shell_id)
        if not opt:
            return
        lhost = lhost_entry.get().strip()
        lport = int(lport_entry.get().strip() or "4444")
        cmd = opt.build(lhost, lport)

        # Show in popup
        popup = tk.Toplevel(app)
        popup.title(f"RevShell: {opt.name}")
        popup.geometry("800x300")
        tokens = getattr(app, "_tokens", ui_theme.get_tokens("dark"))
        popup.configure(bg=tokens.app_bg)
        ttk.Label(popup, text=f"Name: {opt.name}  |  OS: {opt.os_hint}",
                  foreground="#89b4fa").pack(anchor="w", padx=8, pady=4)
        ttk.Label(popup, text=f"Description: {opt.description}",
                  foreground="#a6adc8").pack(anchor="w", padx=8)
        txt = tk.Text(popup, height=6, font=("Courier New", 10), wrap=tk.WORD)
        ui_theme.apply_text_theme(txt, tokens)
        txt.pack(fill=tk.BOTH, expand=True, padx=8, pady=6)
        txt.insert("1.0", cmd)
        txt.configure(state=tk.DISABLED)

        nc_hint = f"\n\nListener: nc -lvnp {lport}"
        ttk.Label(popup, text=nc_hint, foreground="#f9e2af").pack(anchor="w", padx=8)
        app.log(f"[REVSHELL] Command for {opt.name}: {cmd[:80]}")

    ttk.Button(rs_btn_frame, text="⚡ Generate suggestions",
               command=_generate_shells).pack(side=tk.LEFT, padx=4)
    ttk.Button(rs_btn_frame, text="🔍 Show full command",
               command=_show_full_command).pack(side=tk.LEFT, padx=4)
    # RevShell treeview
    rs_tree_frame = ttk.Frame(rs_tab)
    rs_tree_frame.grid(row=rs_row, column=0, columnspan=3, sticky="nsew", padx=8, pady=4)
    rs_tree_frame.rowconfigure(0, weight=1)
    rs_tree_frame.columnconfigure(0, weight=1)
    rs_tab.rowconfigure(rs_row, weight=1)

    rs_tree = ttk.Treeview(
        rs_tree_frame,
        columns=("name", "os", "requires", "cmd"),
        show="headings", selectmode="browse",
    )
    for col, heading, width in zip(
        ("name", "os", "requires", "cmd"),
        ("Name", "OS", "Requires", "Command (truncated)"),
        (150, 70, 100, 500),
    ):
        rs_tree.heading(col, text=heading, anchor="w")
        rs_tree.column(col, width=width, anchor="w", stretch=(col == "cmd"))
    sb = ttk.Scrollbar(rs_tree_frame, orient=tk.VERTICAL, command=rs_tree.yview)
    rs_tree.configure(yscrollcommand=sb.set)
    sb.grid(row=0, column=1, sticky="ns")
    rs_tree.grid(row=0, column=0, sticky="nsew")
    rs_tree.bind("<Double-1>", lambda _: _show_full_command())
    app._rs_tree = rs_tree

    # ── CheckRegistry / WSTG tab ──────────────────────────────────
    chk_tab = ttk.Frame(nb)
    nb.add(chk_tab, text="  Checks / WSTG  ")
    chk_tab.rowconfigure(1, weight=1)
    chk_tab.columnconfigure(0, weight=1)

    # ── Checks / WSTG tab: данные из checks/catalog.py ──────────
    # Fallback — прежний hardcoded-список (пока каталог не готов параллельно).
    # (check_id, WSTG_ID, name, category_label, severity, cwe, description)
    _FALLBACK_WSTG_CHECKS = [
        # ─ OTG-INFO ─ Information Gathering
        ("info_disclosure",  "WSTG-INFO-01", "Conduct Search Engine Discovery",          "Information", "LOW",    "CWE-200", "Search engines, cached pages, metadata leakage"),
        ("outdated_libs",    "WSTG-INFO-08", "Fingerprint Web Application Framework",     "Information", "LOW",    "CWE-1035","Outdated/vulnerable JS libraries, framework hints"),
        ("third_party_scripts","WSTG-INFO-09","Fingerprint Web Application",             "Information", "LOW",    "CWE-829", "Third-party scripts without SRI"),
        # ─ OTG-CONF ─ Configuration & Deployment
        ("security_headers", "WSTG-CONF-05", "Enumerate Infrastructure & App Admin Interfaces","Config","MEDIUM","CWE-693", "Missing security headers: CSP, HSTS, X-Frame-Options, etc."),
        ("clickjacking",     "WSTG-CONF-09", "Test for Clickjacking",                    "Config",  "MEDIUM",   "CWE-1021","Missing X-Frame-Options / CSP frame-ancestors"),
        # ─ OTG-IDENT ─ Identity Management (placeholder, passive)
        # ─ OTG-AUTHN ─ Authentication
        ("sqli",             "WSTG-INPV-05", "Test for SQL Injection",                   "Injection", "HIGH",   "CWE-89",  "Error-based SQL injection, DB error messages exposed"),
        ("sqli_time",        "WSTG-INPV-05", "Test for SQL Injection (Blind/Time)",      "Injection", "HIGH",   "CWE-89",  "Time-based blind SQL injection via SLEEP/pg_sleep"),
        ("nosql_injection",  "WSTG-INPV-01", "Test for NoSQL Injection",                 "Injection", "HIGH",   "CWE-943", "MongoDB/CouchDB operator injection, auth bypass"),
        ("ldap_injection",   "WSTG-INPV-06", "Test for LDAP Injection",                  "Injection", "HIGH",   "CWE-90",  "LDAP filter injection, directory dump"),
        ("xpath_injection",  "WSTG-INPV-09", "Test for XPath Injection",                 "Injection", "MEDIUM", "CWE-643", "XPath filter injection, XML data disclosure"),
        ("cmdi",             "WSTG-INPV-12", "Test for Command Injection",               "Injection", "CRITICAL","CWE-78", "OS command injection via shell metacharacters"),
        ("ssti",             "WSTG-INPV-18", "Test for Server-Side Template Injection",  "Injection", "CRITICAL","CWE-94", "Jinja2/Twig/Smarty template evaluation, RCE"),
        ("xxe",              "WSTG-INPV-07", "Test for XML Injection / XXE",             "Injection", "HIGH",   "CWE-611", "XML external entity, file read, SSRF via XML"),
        ("ssrf",             "WSTG-INPV-19", "Test for Server-Side Request Forgery",     "Injection", "HIGH",   "CWE-918", "Internal network access, metadata endpoint leakage"),
        ("deserialization",  "WSTG-INPV-17", "Test for Deserialization",                 "Injection", "CRITICAL","CWE-502","Insecure object deserialization, RCE via gadget chains"),
        ("path_traversal",   "WSTG-INPV-15", "Test for Path Traversal",                  "File",      "HIGH",   "CWE-22",  "Directory traversal, LFI/RFI, arbitrary file read"),
        ("file_upload",      "WSTG-INPV-22", "Test for Unrestricted File Upload",        "File",      "HIGH",   "CWE-434", "Dangerous file upload, webshell, path traversal in filename"),
        ("crlf_injection",   "WSTG-INPV-15", "Test for HTTP Splitting/Header Injection", "Injection", "MEDIUM", "CWE-113", "CRLF header injection, response splitting, cookie injection"),
        # ─ OTG-CLNT ─ Client-Side Testing
        ("xss_reflected",    "WSTG-CLNT-01", "Test for Reflected XSS",                   "Client",    "HIGH",   "CWE-79",  "Reflected cross-site scripting via user input in response"),
        ("xss_dom",          "WSTG-CLNT-01", "Test for DOM-Based XSS",                   "Client",    "HIGH",   "CWE-79",  "DOM-based XSS via innerHTML/document.write"),
        ("csrf",             "WSTG-CLNT-09", "Test for CSRF",                            "Client",    "MEDIUM", "CWE-352", "Missing anti-CSRF token on state-changing forms"),
        ("open_redirect",    "WSTG-CLNT-04", "Test for Client-Side URL Redirect",        "Client",    "MEDIUM", "CWE-601", "Open redirect to external domain via Location header"),
        # ─ OTG-AUTHZ ─ Authorization
        ("idor",             "WSTG-ATHZ-04", "Test for IDOR",                            "AuthZ",     "HIGH",   "CWE-639", "Insecure direct object reference, BOLA"),
    ]

    # Severity color map
    _SEV_COLORS = {
        "CRITICAL": "#f38ba8",
        "HIGH":     "#fab387",
        "MEDIUM":   "#f9e2af",
        "LOW":      "#a6e3a1",
        "INFO":     "#89b4fa",
    }

    chk_toolbar = ttk.Frame(chk_tab)
    chk_toolbar.grid(row=0, column=0, sticky="ew", padx=6, pady=4)

    _catalog_rows = catalog_defs()  # [] → fallback-режим
    _use_catalog = bool(_catalog_rows)

    def _row_enabled(check_id: str, default: bool = True) -> bool:
        """Текущее enabled-состояние: registry → GUI-чекбокс → default."""
        try:
            from checks.registry import get_registry
            chk = get_registry().get(check_id)
            if chk is not None:
                return bool(chk.enabled)
        except Exception:
            pass
        var = app._check_vars.get(check_id)
        if var is not None:
            try:
                return bool(var.get())
            except Exception:
                return default
        return default

    def _catalog_values(defn) -> tuple:
        cid = str(_def_attr(defn, "check_id", ""))
        severity = str(_def_attr(defn, "severity", "INFO") or "INFO")
        enabled = _row_enabled(cid, bool(_def_attr(defn, "enabled_default", True)))
        return (
            str(_def_attr(defn, "wstg_id", "—") or "—"),
            cid,
            str(_def_attr(defn, "name", "") or ""),
            str(_def_attr(defn, "category", "") or ""),
            severity,
            str(_def_attr(defn, "kind", "") or ""),
            "✓" if enabled else "✗",
            str(_def_attr(defn, "cwe", "") or "—"),
            str(_def_attr(defn, "description", "") or "")[:90],
        )

    def _fallback_values(entry) -> tuple:
        cid = entry[0]
        enabled = _row_enabled(cid, True)
        if cid == "info_disclosure_paths":
            kind = "probe"
        elif cid in _LEGACY_PASSIVE_CHECK_IDS:
            kind = "passive"
        else:
            kind = "active"
        return (entry[1], cid, entry[2], entry[3], entry[4], kind,
                "✓" if enabled else "✗", entry[5], entry[6][:90])

    def _load_checks_tree():
        for item in chk_tree.get_children():
            chk_tree.delete(item)
        if _use_catalog:
            # Группировка по category: сортируем, порядок категорий — из каталога.
            cat_order = {c: i for i, c in enumerate(catalog_categories())}
            defs = sorted(
                _catalog_rows,
                key=lambda d: (
                    cat_order.get(str(_def_attr(d, "category", "") or ""), 99),
                    str(_def_attr(d, "check_id", "")),
                ),
            )
            for defn in defs:
                cid = str(_def_attr(defn, "check_id", ""))
                values = _catalog_values(defn)
                severity = values[4].lower()
                tag = severity if values[6] == "✓" else "off"
                kind_tag = f"kind_{values[5]}"
                chk_tree.insert("", tk.END, iid=cid, tags=(tag, kind_tag), values=values)
            enabled_count = sum(
                1 for d in _catalog_rows
                if _row_enabled(
                    str(_def_attr(d, "check_id", "")),
                    bool(_def_attr(d, "enabled_default", True)),
                )
            )
            _chk_summary_lbl.configure(
                text=f"{enabled_count} / {len(_catalog_rows)} checks enabled "
                     f"(catalog: {len(_catalog_rows)})"
            )
        else:
            for entry in sorted(_FALLBACK_WSTG_CHECKS, key=lambda e: (e[3], e[0])):
                values = _fallback_values(entry)
                tag = values[4].lower() if values[6] == "✓" else "off"
                chk_tree.insert("", tk.END, iid=values[1], tags=(tag,), values=values)
            enabled_count = sum(
                1 for e in _FALLBACK_WSTG_CHECKS if _row_enabled(e[0], True)
            )
            _chk_summary_lbl.configure(
                text=f"{enabled_count} / {len(_FALLBACK_WSTG_CHECKS)} checks enabled"
            )

    def _toggle_check():
        try:
            from checks.registry import get_registry
            reg = get_registry()
        except Exception:
            reg = None
        for iid in chk_tree.selection():
            new_value = None
            chk = reg.get(iid) if reg is not None else None
            if chk is not None:
                chk.enabled = not chk.enabled
                new_value = bool(chk.enabled)
            var = app._check_vars.get(iid)
            if var is not None:
                if new_value is None:
                    new_value = not bool(var.get())
                var.set(new_value)
        _load_checks_tree()

    def _enable_by_cat(cat_label: str, enabled: bool):
        """Enable/disable checks matching a WSTG category label (из каталога)."""
        try:
            from checks.registry import get_registry
            reg = get_registry()
        except Exception:
            reg = None
        if _use_catalog:
            cat_ids = [
                str(_def_attr(d, "check_id", ""))
                for d in _catalog_rows
                if str(_def_attr(d, "category", "")) == cat_label
            ]
        else:
            cat_ids = [entry[0] for entry in _FALLBACK_WSTG_CHECKS if entry[3] == cat_label]
        for cid in cat_ids:
            chk = reg.get(cid) if reg is not None else None
            if chk is not None:
                chk.enabled = enabled
            var = app._check_vars.get(cid)
            if var is not None:
                var.set(enabled)
        _load_checks_tree()

    def _set_all_checks(enabled: bool):
        try:
            from checks.registry import get_registry
            reg = get_registry()
            if enabled:
                reg.enable_all()
            else:
                reg.disable_all()
        except Exception:
            pass
        for var in app._check_vars.values():
            try:
                var.set(enabled)
            except Exception:
                pass
        _load_checks_tree()

    # Toolbar buttons (Reload / Toggle / All ON / All OFF сохранены)
    ttk.Button(chk_toolbar, text="↻ Reload", command=_load_checks_tree).pack(side=tk.LEFT, padx=4)
    ttk.Button(chk_toolbar, text="Toggle ON/OFF", command=_toggle_check).pack(side=tk.LEFT, padx=4)
    ttk.Button(chk_toolbar, text="✓ All ON",
               command=lambda: _set_all_checks(True)).pack(side=tk.LEFT, padx=4)
    ttk.Button(chk_toolbar, text="✗ All OFF",
               command=lambda: _set_all_checks(False)).pack(side=tk.LEFT, padx=4)

    # Category quick-filter buttons (категории — из каталога, fallback — старые)
    ttk.Separator(chk_toolbar, orient=tk.VERTICAL).pack(side=tk.LEFT, padx=6, fill=tk.Y)
    ttk.Label(chk_toolbar, text="Category:", foreground="#a6adc8").pack(side=tk.LEFT, padx=4)
    _CATS = catalog_categories() if _use_catalog else [
        "Injection", "File", "Client", "Config", "Information", "AuthZ",
    ]
    for _cat in _CATS:
        ttk.Button(
            chk_toolbar, text=_cat,
            command=lambda c=_cat: _enable_by_cat(c, True),
        ).pack(side=tk.LEFT, padx=2)

    _chk_summary_lbl = ttk.Label(chk_toolbar, text="", foreground="#a6e3a1")
    _chk_summary_lbl.pack(side=tk.RIGHT, padx=8)

    # Main treeview
    chk_tree_frame = ttk.Frame(chk_tab)
    chk_tree_frame.grid(row=1, column=0, sticky="nsew", padx=6, pady=4)
    chk_tree_frame.rowconfigure(0, weight=1)
    chk_tree_frame.columnconfigure(0, weight=1)

    _CHK_COLS     = ("wstg",  "id",    "name",   "category", "severity", "kind",  "on",     "cwe",  "desc")
    _CHK_HEADS    = ("WSTG",  "ID",    "Name",   "Category", "Severity", "Kind",  "✓/✗",    "CWE",  "Description")
    _CHK_WIDTHS   = (150,     140,     240,      95,         70,         60,       36,       70,     330)
    _CHK_STRETCH  = (False,   False,   False,    False,      False,      False,    False,    False,  True)

    chk_tree = ttk.Treeview(
        chk_tree_frame,
        columns=_CHK_COLS,
        show="headings", selectmode="extended",
    )
    for col, head, width, stretch in zip(_CHK_COLS, _CHK_HEADS, _CHK_WIDTHS, _CHK_STRETCH):
        chk_tree.heading(col, text=head, anchor="w")
        chk_tree.column(col, width=width, anchor="w", stretch=stretch)

    # Severity colour tags
    chk_tree.tag_configure("off",      foreground="#585b70")
    chk_tree.tag_configure("critical", foreground="#f38ba8")
    chk_tree.tag_configure("high",     foreground="#fab387")
    chk_tree.tag_configure("medium",   foreground="#f9e2af")
    chk_tree.tag_configure("low",      foreground="#a6e3a1")
    chk_tree.tag_configure("info",     foreground="#89b4fa")

    # Double-click toggles on/off
    chk_tree.bind("<Double-1>", lambda _e: _toggle_check())

    sb2 = ttk.Scrollbar(chk_tree_frame, orient=tk.VERTICAL, command=chk_tree.yview)
    chk_tree.configure(yscrollcommand=sb2.set)
    sb2.grid(row=0, column=1, sticky="ns")
    chk_tree.grid(row=0, column=0, sticky="nsew")

    # Detail panel at bottom
    chk_tab.rowconfigure(2, weight=0)
    _detail_frame = ttk.LabelFrame(chk_tab, text="Check details", padding=6)
    _detail_frame.grid(row=2, column=0, sticky="ew", padx=6, pady=(0, 6))
    _detail_frame.columnconfigure(0, weight=1)
    _detail_text = tk.Text(_detail_frame, height=4, font=("Consolas", 9), wrap=tk.WORD,
                           state=tk.DISABLED)
    try:
        _t2 = getattr(app, "_tokens", None)
        if _t2:
            import ui_theme as _uit2; _uit2.apply_text_theme(_detail_text, _t2)
    except Exception:
        pass
    _detail_text.pack(fill=tk.BOTH, expand=True)

    def _on_chk_select(event):
        sel = chk_tree.selection()
        if not sel:
            return
        iid = sel[0]
        if _use_catalog:
            defn = next(
                (d for d in _catalog_rows if str(_def_attr(d, "check_id", "")) == iid),
                None,
            )
            if defn is not None:
                txt = (
                    f"WSTG ID:     {_def_attr(defn, 'wstg_id', '—')}\n"
                    f"Name:        {_def_attr(defn, 'name', '')}\n"
                    f"Category:    {_def_attr(defn, 'category', '')}   "
                    f"Severity: {_def_attr(defn, 'severity', '')}   "
                    f"CWE: {_def_attr(defn, 'cwe', '')}   "
                    f"Kind: {_def_attr(defn, 'kind', '')}\n"
                    f"Description: {_def_attr(defn, 'description', '')}\n"
                )
                _detail_text.configure(state=tk.NORMAL)
                _detail_text.delete("1.0", tk.END)
                _detail_text.insert("1.0", txt)
                _detail_text.configure(state=tk.DISABLED)
                return
        # Fallback: старый WSTG-список, затем CheckRegistry
        wstg_map2 = {entry[0]: entry for entry in _FALLBACK_WSTG_CHECKS}
        entry = wstg_map2.get(iid)
        if entry:
            txt = (
                f"WSTG ID:     {entry[1]}\n"
                f"Name:        {entry[2]}\n"
                f"Category:    {entry[3]}   Severity: {entry[4]}   CWE: {entry[5]}\n"
                f"Description: {entry[6]}\n"
            )
        else:
            try:
                from checks.registry import get_registry
                c = get_registry().get(iid)
            except Exception:
                c = None
            txt = f"ID: {iid}\nName: {c.name if c else '?'}\nCWE: {c.cwe if c else '?'}" if c else f"ID: {iid}"
        _detail_text.configure(state=tk.NORMAL)
        _detail_text.delete("1.0", tk.END)
        _detail_text.insert("1.0", txt)
        _detail_text.configure(state=tk.DISABLED)

    chk_tree.bind("<<TreeviewSelect>>", _on_chk_select)
    _load_checks_tree()

    # Экспорт в App: тесты/интеграция проверяют строки дерева и каталог.
    app._chk_tree = chk_tree
    app._chk_tab = chk_tab
    app._chk_summary_lbl = _chk_summary_lbl
    app._load_checks_tree = _load_checks_tree
    app._uses_check_catalog = bool(_use_catalog)
    app._check_catalog_count = len(_catalog_rows)
    app._check_catalog_ids = [str(_def_attr(d, "check_id", "")) for d in _catalog_rows]

    # Kind-теги (active/passive/probe) для подсветки колонки Kind.
    chk_tree.tag_configure("kind_active", foreground="#f5c2e7")


# NOTE: _patch_app_with_auth_and_revshell is called directly inside App.__init__
# after _build_ui(), so no monkey-patch is needed here.


if __name__ == "__main__":
    import logging
    import signal
    import traceback
    logging.basicConfig(level=logging.WARNING)
    try:
        app = App()

        # Гарантированное освобождение порта прокси: atexit + SIGINT/SIGTERM/SIGHUP
        atexit.register(app._shutdown_proxy_sync)

        def _handle_signal(signum, frame):  # noqa: ANN001
            try:
                print(f"[notscan] signal {signum}: shutting down proxy…", file=sys.stderr)
            except Exception:
                pass
            try:
                app._shutdown_proxy_sync()
            finally:
                try:
                    app.quit()
                except Exception:
                    pass

        for _sig_name in ("SIGINT", "SIGTERM", "SIGHUP"):
            _sig = getattr(signal, _sig_name, None)
            if _sig is None:
                continue
            try:
                signal.signal(_sig, _handle_signal)
            except Exception:
                pass

        app.mainloop()
    except Exception as e:
        print(f"[notscan] Fatal error: {e}", file=sys.stderr)
        traceback.print_exc()
        try:
            root = tk.Tk()
            root.withdraw()
            mb.showerror(
                "Notscan — error",
                f"Произошла ошибка при запуске:\n\n{e}\n\n"
                "Подробности смотри в консоли.",
            )
            root.destroy()
        except Exception:
            pass
