"""
checks/runner.py — Интеграция CheckRegistry с ScannerRunner.

Этот модуль связывает:
  • scanner_core.ScanTask (мутированный запрос + payload)
  • httpx ответ
  • CheckRegistry (все активные чеки)
  • db.insert_scan_result / insert_scan_request
  • Finding → лог + GUI callback

Используется из scanner_core.py как drop-in дополнение.
"""

from __future__ import annotations

# ─── WSTG mapping: check_id → WSTG test ID ───────────────────────────────────
# ЕДИНЫЙ ИСТОЧНИК — checks/catalog.py. WSTG-ID сверены
# по OWASP WSTG v4.2 (stable) и checklist v5-dev; для тестов вне v4.2 — ID с
# пометкой " (v5)". GUI (Checks/WSTG tab) берёт данные из того же каталога.
try:  # pragma: no cover - каталог всегда есть в репозитории
    from checks.catalog import CHECK_CATALOG as _CATALOG
except Exception:  # pragma: no cover - защита переходного состояния
    _CATALOG = ()

WSTG_ID_MAP: dict[str, str] = {cd.check_id: cd.wstg_id for cd in _CATALOG}

# Legacy/алиасы check_type, которые движок исторически принимает в payload-файлах
# (например load_payloads("xss") / MATCHERS["xss"]), но которые не являются
# отдельными чеками каталога.
_LEGACY_WSTG_ALIASES: dict[str, str] = {
    "xss": "xss_reflected",
    "sqli_time_blind": "sqli_time",
    "xxe_ssrf": "xxe",
    "file_upload_exec": "file_upload",
    "path_traversal_exec": "path_traversal",
}
for _alias, _target in _LEGACY_WSTG_ALIASES.items():
    if _target in WSTG_ID_MAP:
        WSTG_ID_MAP.setdefault(_alias, WSTG_ID_MAP[_target])

import hashlib
import logging
import time
from typing import Callable, Optional
from urllib.parse import urlparse

import db
from checks.base import (
    CheckContext, ScanRequest, ScanResponse, Finding,
)
from checks.registry import get_registry, CheckRegistry

logger = logging.getLogger(__name__)


def _result_fingerprint(url: str, check_type: str, param: str) -> str:
    """Стабильный ключ дедупликации (совпадает с scanner_core._fingerprint_for_result)."""
    try:
        parsed = urlparse(url)
        host = (parsed.hostname or "").lower()
        path = (parsed.path or "/").lower()
    except Exception:
        host, path = "", ""
    raw = f"{host}|{path}|{check_type.lower()}|{(param or '').lower()}"
    return hashlib.sha256(raw.encode("utf-8", errors="ignore")).hexdigest()[:24]


def run_checks_on_response(
    *,
    method: str,
    url: str,
    headers: dict,
    body: bytes,
    raw_http: str,
    resp_status: int,
    resp_headers: dict,
    resp_text: str,
    resp_elapsed_ms: float,
    resp_error: Optional[str],
    check_type: str,
    payload: str,
    mutation_point: str,
    original_param: str,
    history_id: Optional[int],
    registry: Optional[CheckRegistry] = None,
    log_cb: Callable[[str], None] = print,
    only_active: bool = False,
    only_passive: bool = False,
    baseline_ms: float = 0.0,
    baseline_text: str = "",
) -> list[Finding]:
    """
    Запускает все активные чеки из registry против данного запроса/ответа.
    Сохраняет каждую находку в scan_results/scan_requests.
    Возвращает список Finding.

    ``baseline_ms`` / ``baseline_text`` — baseline-метрики хоста (p50 латентности
    и тело baseline-ответа); движок передаёт их для относительного time-based
    порога и FP-подавления. Старые вызовы без этих kwargs работают как раньше.
    """
    reg = registry or get_registry()

    request = ScanRequest(
        method=method,
        url=url,
        headers=headers,
        body=body,
        raw_http=raw_http,
    )
    response = ScanResponse(
        status_code=resp_status,
        headers=resp_headers,
        text=resp_text,
        elapsed_ms=resp_elapsed_ms,
        error=resp_error,
    )
    context = CheckContext(
        history_id=history_id,
        mutation_point=mutation_point,
        original_param=original_param,
        payload=payload,
        check_type=check_type,
        baseline_ms=baseline_ms,
        baseline_text=baseline_text,
    )

    findings = reg.run_all(
        request, response, context,
        only_active=only_active,
        only_passive=only_passive,
        match_check_type=(check_type if only_active else None),
    )

    for finding in findings:
        # Populate WSTG ID from the static map; fall back to check_type lookup
        if not finding.wstg_id:
            finding.wstg_id = (
                WSTG_ID_MAP.get(finding.vuln_type)
                or WSTG_ID_MAP.get(check_type)
                or ""
            )
        try:
            # Build template_id: embed history_id when available so the detail
            # view can later reconstruct the full HTTP response from history.
            if history_id is not None:
                tmpl_id = f"hist-{history_id}-check-{finding.vuln_type}-{original_param}"
            else:
                tmpl_id = f"check-{finding.vuln_type}-{original_param}"

            result_id = db.insert_scan_result(
                template_id=tmpl_id,
                worker_id=0,
                method=method,
                url=url,
                status_code=resp_status,
                error=resp_error,
                check_type=finding.vuln_type,
                payload=payload,
                evidence=finding.evidence,
            )
            # Build full raw response string (status + headers + body)
            _raw_resp_lines = [f"HTTP/1.1 {resp_status}"]
            for _hk, _hv in resp_headers.items():
                _raw_resp_lines.append(f"{_hk}: {_hv}")
            _raw_resp_lines.append("")
            _raw_resp_lines.append(resp_text[:8192])
            _raw_resp_full = "\r\n".join(_raw_resp_lines)

            db.insert_scan_request(
                scan_result_id=result_id,
                raw_request=raw_http,
                raw_response_preview=_raw_resp_full,
                resp_status=resp_status,
                resp_headers=resp_headers,
            )
            # Save scan_meta so _build_full_response can look up history row
            db.upsert_scan_meta(
                scan_result_id=result_id,
                history_id=history_id,
                mutation_point=mutation_point or "passive",
                original_param=original_param,
                payload_class=finding.vuln_type,
                detector="checks",
                severity=finding.severity.value if hasattr(finding.severity, "value") else str(finding.severity),
                fingerprint=_result_fingerprint(url, finding.vuln_type, original_param),
            )
            wstg_tag = f"[{finding.wstg_id}] " if finding.wstg_id else ""
            log_cb(
                f"[CHECK][{finding.severity.value}][{finding.vuln_type.upper()}] "
                f"{wstg_tag}{finding.title} — {finding.evidence[:80]} | {url[:60]}"
            )
        except Exception as exc:
            logger.exception("run_checks_on_response DB error: %s", exc)

    return findings
