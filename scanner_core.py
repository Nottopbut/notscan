"""
scanner_core.py — Построение задач скана, пул воркеров, матчеры уязвимостей.
"""

from __future__ import annotations

import asyncio
import contextlib
import json
import difflib
import hashlib
import logging
import random
import re
import threading
import time
import urllib.parse
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable, List, Optional
from urllib.parse import urlparse

import httpx

import db
import templating

logger = logging.getLogger(__name__)

try:
    from checks.runner import run_checks_on_response, WSTG_ID_MAP
    from checks.registry import get_registry
    _CHECKS_AVAILABLE = True
except ImportError:
    WSTG_ID_MAP: dict[str, str] = {}
    _CHECKS_AVAILABLE = False

# Единый каталог чеков — источник payload-файлов.
# Мягкий импорт: если каталог недоступен, load_payloads использует legacy-карту.
try:
    from checks.catalog import payload_file_for as _catalog_payload_file_for
    _CATALOG_AVAILABLE = True
except ImportError:  # pragma: no cover - каталог всегда есть в репозитории
    _catalog_payload_file_for = None
    _CATALOG_AVAILABLE = False

# Матчеры SSI/HTML-injection (новые чеки,). Логика живёт
# в checks/injections.py (общая с check-классами), здесь — тонкие обёртки
# под общий интерфейс MATCHERS.
try:
    from checks.injections import (
        html_injection_indicator as _html_injection_indicator,
        ssi_indicator as _ssi_indicator,
    )
    _NEW_MATCHERS_AVAILABLE = True
except ImportError:  # pragma: no cover
    _html_injection_indicator = None
    _ssi_indicator = None
    _NEW_MATCHERS_AVAILABLE = False

# FP-правила для XSS (checks/fp_rules.py). Модуль общий для checks-слоя и matcher-слоя;
# мягкий импорт с локальным fallback, чтобы движок и его тесты работали, даже
# если файл ещё не создан/переписывается параллельно.
try:
    from checks.fp_rules import (  # type: ignore[import-not-found]
        is_bare_html_tag as _fp_is_bare_html_tag,
        is_html_response as _fp_is_html_response,
        payload_in_baseline as _fp_payload_in_baseline,
    )
    _FP_RULES_AVAILABLE = True
except ImportError:  # pragma: no cover - fallback только для промежуточного состояния
    _FP_RULES_AVAILABLE = False
    _BARE_TAG_RE = re.compile(r"</?[A-Za-z][A-Za-z0-9-]*\s*/?>")
    _HTML_MIME_TYPES = frozenset({"text/html", "application/xhtml+xml", "text/xml"})

    def _fp_is_bare_html_tag(payload: str) -> bool:
        return bool(payload) and _BARE_TAG_RE.fullmatch((payload or "").strip()) is not None

    def _fp_is_html_response(headers: Optional[dict]) -> bool:
        if not headers:
            return True
        ct = ""
        for k, v in headers.items():
            if str(k).lower() == "content-type":
                ct = str(v)
                break
        if not ct:
            return True
        return ct.split(";", 1)[0].strip().lower() in _HTML_MIME_TYPES

    def _fp_payload_in_baseline(payload: str, baseline_text: str) -> bool:
        if not payload or not baseline_text:
            return False
        if payload in baseline_text:
            return True
        enc = urllib.parse.quote(payload, safe="")
        return enc != payload and enc in baseline_text


# Новые kwargs появились у run_checks_on_response. Определяем один
# раз: пока в runner.py их нет — вызываем старую сигнатуру (без падения).
try:
    import inspect as _inspect

    _RUN_CHECKS_HAS_BASELINE = "baseline_ms" in _inspect.signature(
        run_checks_on_response
    ).parameters
except Exception:  # pragma: no cover
    _RUN_CHECKS_HAS_BASELINE = False


# Чеки, для которых разрешена raw-мутация тела (mutation_point="body_raw"):
# их payload'ы — целые документы/объекты (XML для XXE, serialized-объект для
# deserialization), а не значения отдельных параметров.
# Для остальных чеков body_raw запрещён явно (не плодим шум), независимо от
# значения planner_enabled.
BODY_RAW_CHECKS = frozenset({"xxe", "deserialization"})


# Проверки, к которым применяется tamper/WAF-bypass кодирование:
# только серверные инъекционные. XSS/passive/редиректы — не кодируем.
TAMPERABLE_CHECKS = frozenset({
    "sqli", "sqli_time", "cmdi", "ssti", "ldap_injection", "xpath_injection",
    "nosql_injection", "xxe", "deserialization", "path_traversal",
    "crlf_injection", "ssrf", "file_upload", "idor",
})


# ──────────────────────────── Evidence diff ────────────────────────────

def build_unified_diff_snippet(
    baseline_text: str,
    mutated_text: str,
    *,
    context_lines: int = 2,
    max_lines: int = 120,
) -> str:
    """
    Build a compact unified diff snippet for evidence/triage.
    Returns at most max_lines lines.
    """
    base_lines = (baseline_text or "").splitlines()
    mut_lines = (mutated_text or "").splitlines()
    diff = difflib.unified_diff(
        base_lines,
        mut_lines,
        fromfile="baseline",
        tofile="mutated",
        lineterm="",
        n=context_lines,
    )
    out: list[str] = []
    for i, line in enumerate(diff):
        if i >= max_lines:
            out.append("... (diff truncated) ...")
            break
        out.append(line)
    return "\n".join(out).strip()


def redact_raw_http(raw: str) -> str:
    """
    Redact secrets in raw HTTP for local storage (offline):
    - Authorization/Bearer
    - Cookie / Set-Cookie values
    - X-Api-Key like headers
    """
    if not raw:
        return raw
    lines = raw.splitlines()
    out: list[str] = []
    for line in lines:
        lower = line.lower()
        if lower.startswith("authorization:"):
            out.append("Authorization: ***REDACTED***")
        elif lower.startswith("cookie:"):
            out.append("Cookie: ***REDACTED***")
        elif lower.startswith("set-cookie:"):
            out.append("Set-Cookie: ***REDACTED***")
        elif lower.startswith("x-api-key:") or lower.startswith("x-apikey:") or lower.startswith("api-key:"):
            k = line.split(":", 1)[0]
            out.append(f"{k}: ***REDACTED***")
        else:
            out.append(line)
    return "\n".join(out)


def _fingerprint_for_result(url: str, check_type: str, original_param: str) -> str:
    """
    Stable key for dedup/correlation (offline).
    """
    try:
        parsed = urlparse(url)
        host = (parsed.hostname or "").lower()
        path = (parsed.path or "/").lower()
    except Exception:
        host, path = "", ""
    raw = f"{host}|{path}|{check_type.lower()}|{(original_param or '').lower()}"
    return hashlib.sha256(raw.encode("utf-8", errors="ignore")).hexdigest()[:24]


def _severity_guess(check_type: str) -> str:
    ct = (check_type or "").lower()
    if ct in ("cmdi", "ssti", "deserialization", "file_upload", "ssi_injection"):
        return "HIGH"
    if ct in ("sqli", "sqli_time", "sqli_blind", "xxe", "ssrf", "path_traversal"):
        return "HIGH"
    if ct in ("xss", "xss_reflected", "xss_dom", "open_redirect", "crlf_injection",
              "html_injection", "cors", "ria_policy", "http_methods"):
        return "MEDIUM"
    if ct in ("csrf", "clickjacking", "security_headers", "info_disclosure",
              "outdated_libs", "third_party_scripts", "metafiles"):
        return "LOW"
    return "INFO"


# ──────────────────────────── ROE: Rate limiting ────────────────────────────

class RateLimiter:
    """Глобальный пейсер запросов (интервал между запросами, все воркеры).

    Семантика (FIX_CONTRACT task-25):
      • max_rps > 0 и min_rps > 0 (min <= max):
            интервал = uniform(1/max, 1/min) на каждый acquire —
            фактический RPS в диапазоне [min, max];
      • только max_rps > 0:      интервал = 1/max (предсказуемый пейсинг);
      • только min_rps > 0:      интервал = 1/min;
      • delay_ms > 0:            интервал = max(delay_ms/1000, интервал);
      • всё выключено (0/None):  acquire мгновенный.

    Интервал соблюдается ГЛОБАЛЬНО: слоты резервируются под lock через
    next_allowed, поэтому суммарная скорость всех воркеров ограничена.
    Первый запрос выполняется сразу, дальнейшие — не чаще выбранного интервала.
    ``acquire`` спит через time.sleep, ``acquire_async`` — через asyncio.sleep
    (event loop не блокируется). ``clock`` — точка расширения для тестов.
    """

    def __init__(
        self,
        max_rps: float | None = None,
        min_rps: float | None = None,
        delay_ms: float = 0.0,
        *,
        clock: Optional[Callable[[], float]] = None,
    ):
        self.max_rps = float(max_rps or 0.0)
        self.min_rps = float(min_rps or 0.0)
        self.delay_ms = float(delay_ms or 0.0)
        self._clock = clock or time.time
        self._lock = threading.Lock()
        self._next_allowed: float = 0.0
        # Диагностика (для тестов/отчётов): сколько всего слотов и сколько ждали.
        self.total_acquires = 0
        self.total_wait_s = 0.0
        self.last_interval_s = 0.0

    @property
    def enabled(self) -> bool:
        return self.max_rps > 0 or self.min_rps > 0 or self.delay_ms > 0

    def _pick_interval(self) -> float:
        """Интервал (сек) для следующего слота по настройкам min/max/delay."""
        max_rps = self.max_rps
        min_rps = self.min_rps
        interval = 0.0
        if max_rps > 0 and min_rps > 0 and min_rps <= max_rps:
            interval = random.uniform(1.0 / max_rps, 1.0 / min_rps)
        elif max_rps > 0:
            interval = 1.0 / max_rps
        elif min_rps > 0:
            interval = 1.0 / min_rps
        if self.delay_ms > 0:
            interval = max(interval, self.delay_ms / 1000.0)
        return interval

    def _reserve(self) -> float:
        """Резервирует слот; возвращает 0 (можно слать) либо сколько ещё ждать."""
        with self._lock:
            now = self._clock()
            wait = self._next_allowed - now
            if wait <= 0:
                interval = self._pick_interval()
                self._next_allowed = now + interval if interval > 0 else now
                self.last_interval_s = interval
                self.total_acquires += 1
                return 0.0
            self.total_wait_s += wait
            return wait

    def acquire(self) -> None:
        """Синхронный acquire: time.sleep до разрешённого слота."""
        while self.enabled:
            wait = self._reserve()
            if wait <= 0:
                return
            time.sleep(wait)

    async def acquire_async(self) -> None:
        """Async acquire: asyncio.sleep, event loop не блокируется."""
        while self.enabled:
            wait = self._reserve()
            if wait <= 0:
                return
            await asyncio.sleep(wait)


# ──────────────────────────── Scope guard ────────────────────────────

#: Сколько первых out-of-scope URL логировать подробно (дальше — только счётчики).
SCOPE_LOG_DETAIL_LIMIT = 5


def _is_private_or_metadata_host(host: str) -> bool:
    """True if host is private IP range or cloud metadata."""
    if not host:
        return True
    host_lower = host.lower()
    if host_lower in ("localhost", "::1", "0.0.0.0"):
        return True
    if host == "169.254.169.254":  # cloud metadata
        return True
    # Simple IPv4 private ranges (no full CIDR)
    parts = host.split(".")
    if len(parts) == 4:
        try:
            a, b, c, d = (int(p) for p in parts)
            if a == 10:
                return True
            if a == 172 and 16 <= b <= 31:
                return True
            if a == 192 and b == 168:
                return True
            if a == 127:
                return True
        except ValueError:
            pass
    return False


#: Причина отказа scope-guard (для агрегированной статистики).
SCOPE_REASON_ALLOWED = "allowed"
SCOPE_REASON_ALLOWLIST = "allowlist"
SCOPE_REASON_PRIVATE = "private"
SCOPE_REASON_OTHER = "other"


def _allowlist_matches(url: str, allowlist: Optional[List[str]]) -> bool:
    """True, если URL матчится хотя бы одним элементом allowlist.

    Матчинг (как раньше + host:port): URL-префикс (http...), hostname
    (exact / суффикс / подстрока), а также netloc ``host:port``.
    """
    if not allowlist:
        return False
    try:
        parsed = urlparse(url)
        host = (parsed.hostname or "").strip().lower()
        netloc = (parsed.netloc or "").strip().lower()
    except Exception:
        return False
    url_lower = url.lower()
    for raw_entry in allowlist:
        entry = (raw_entry or "").strip().lower()
        if not entry:
            continue
        if entry.startswith("http") and url_lower.startswith(entry):
            return True
        entry_no_port = entry.split("://", 1)[-1].split("/", 1)[0]
        if entry_no_port == netloc:  # host:port
            return True
        if host and (
            host == entry_no_port
            or host.endswith("." + entry_no_port)
            or entry_no_port in host
        ):
            return True
    return False


def classify_url_scope(
    url: str,
    allowlist: Optional[List[str]] = None,
    block_private: bool = True,
) -> tuple[bool, str]:
    """(allowed, reason) для scope-guard.

    Allowlist — явная авторизация: разрешает и private/localhost хосты.
    Без allowlist private/metadata блокируются при block_private=True.
    reason ∈ {allowed, allowlist, private, other}.
    """
    try:
        parsed = urlparse(url)
        host = (parsed.hostname or "").strip()
    except Exception:
        return False, SCOPE_REASON_OTHER
    if not host:
        return False, SCOPE_REASON_OTHER

    if allowlist:
        if _allowlist_matches(url, allowlist):
            return True, SCOPE_REASON_ALLOWED
        # Для статистики различаем «private вне allowlist» и «чужой хост»:
        # private-причина приоритетнее, если контретный хост private/metadata.
        if block_private and _is_private_or_metadata_host(host):
            return False, SCOPE_REASON_PRIVATE
        return False, SCOPE_REASON_ALLOWLIST

    if block_private and _is_private_or_metadata_host(host):
        return False, SCOPE_REASON_PRIVATE
    return True, SCOPE_REASON_ALLOWED


def is_url_in_scope(
    url: str,
    allowlist: Optional[List[str]] = None,
    block_private: bool = True,
) -> bool:
    """
    True if URL is allowed for scanning.
    - allowlist (если задан) — явная авторизация: разрешает даже private/local
      (localhost-цели разрешены, если хост в allowlist);
    - block_private=True без allowlist: отклоняет localhost, 127.x, 10.x,
      172.16-31.x, 192.168.x, 169.254.169.254.
    Матчинг allowlist: hostname / host:port / URL-префикс / суффикс домена.
    """
    allowed, _reason = classify_url_scope(url, allowlist, block_private)
    return allowed

_PAYLOADS_SUBDIR = Path(__file__).parent / "payloads"
PAYLOADS_DIR = _PAYLOADS_SUBDIR if _PAYLOADS_SUBDIR.exists() else Path(__file__).parent


# ──────────────────────────── Payload loading ────────────────────────────

# Substrings (case-insensitive) that mark a payload as destructive. Safe mode excludes these.
DESTRUCTIVE_PAYLOAD_PATTERNS = [
    "drop table", "drop database", "drop schema", "truncate table",
    "insert into", "update ", "delete from", "delete *",
    "xp_cmdshell", "exec master..xp_", "execute immediate",
    "grant ", "revoke ", "alter table", "create table",
    "; shutdown", "shutdown--", "bulk insert",
    "into outfile", "into dumpfile", "load_file",
    "writetofile", "writefile", "copy to",
    "expect://",  # PHP expect:// wrapper = RCE-канал (см. payloads/README.md)
]

def _is_destructive_payload(payload: str) -> bool:
    """True if payload contains destructive patterns (write/exec/drop/etc)."""
    lower = payload.lower().strip()
    for pat in DESTRUCTIVE_PAYLOAD_PATTERNS:
        if pat in lower:
            return True
    return False


def _normalize_crlf_payload(payload: str) -> str:
    """
    CRLF-пейлоады в crlf.txt хранятся в закодированном виде (%0d%0a, \\r\\n).
    apply_payload ещё раз URL-кодирует payload, из-за чего %0d%0a превращается в
    %250d%250a и CRLF так и не доезжает до сервера. Здесь декодируем формы в реальные
    CR/LF, чтобы apply_payload закодировал их ровно один раз.
    """
    p = payload
    # percent-encoded (порядок важен: сначала пары, потом одиночные)
    p = p.replace("%0d%0a", "\r\n").replace("%0D%0A", "\r\n")
    p = p.replace("%0d", "\r").replace("%0D", "\r")
    p = p.replace("%0a", "\n").replace("%0A", "\n")
    # backslash-escaped литералы
    p = p.replace("\\r\\n", "\r\n").replace("\\n", "\n").replace("\\r", "\r")
    return p


def load_payloads(check_type: str, safe_mode: bool = True) -> list[str]:
    # Единый источник имён payload-файлов — checks/catalog.py (§1 контракта).
    # Legacy-карта ниже нужна только для старых check_type, которых нет в
    # каталоге (например "xss"), и как fallback переходного состояния.
    filename_map = {
        # Legacy payload-file checks (не отдельные чеки каталога)
        "xss":             "xss.txt",
    }
    key = (check_type or "").strip().lower()
    fname = _catalog_payload_file_for(key) if _CATALOG_AVAILABLE else None
    if not fname:
        fname = filename_map.get(key)
    if not fname:
        return []
    path = PAYLOADS_DIR / fname
    payloads: list[str] = []
    if path.exists():
        lines = path.read_text(encoding="utf-8").splitlines()
        payloads = [l.strip() for l in lines if l.strip() and not l.startswith("#")]
    else:
        logger.warning("Payload file not found: %s", path)

    if key == "crlf_injection":
        payloads = [_normalize_crlf_payload(p) for p in payloads]

    # Merge user-supplied custom payloads: payloads/custom/<check_type>.txt
    try:
        custom_path = PAYLOADS_DIR / "custom" / f"{key}.txt"
        if custom_path.exists():
            clines = custom_path.read_text(encoding="utf-8").splitlines()
            custom = [l.strip() for l in clines if l.strip() and not l.startswith("#")]
            if custom:
                payloads.extend(custom)
                logger.info("Loaded %d custom payloads for %s", len(custom), check_type)
    except Exception as exc:
        logger.debug("custom payload load failed for %s: %s", check_type, exc)

    if safe_mode:
        before = len(payloads)
        payloads = [p for p in payloads if not _is_destructive_payload(p)]
        if before != len(payloads):
            logger.info("Safe mode: filtered %d destructive payloads for %s", before - len(payloads), check_type)
    return payloads


# ──────────────────────────── Boolean-blind SQLi helpers ────────────────────────────
#
# sqli_blind: каждая строка payload-файла — ПАРА «true_payload ||| false_payload».
# Движок отправляет оба запроса и сравнивает ответы (status / length / similarity),
# а false-ответ дополнительно сверяет с baseline из history.
# Детекция — engine-side: checks/injections.SQLiBlindCheck нужен только для
# консистентности каталог ↔ registry.

BLIND_SQLI_CHECK = "sqli_blind"
BLIND_PAYLOAD_DELIMITER = "|||"
BLIND_TEXT_LIMIT = 65_536        # сравниваем не больше 64 KB тела
BLIND_NORM_LIMIT = 4_096         # срез для SequenceMatcher (скорость)
BLIND_SIM_DIFF = 0.97            # ниже — ответы значимо различаются
BLIND_LEN_MIN_DIFF = 20
BLIND_LEN_REL_DIFF = 0.03
BLIND_MIN_BASELINE_SIM = 0.90
BLIND_BASELINE_SIM_MARGIN = 0.05
BLIND_FLOATING_SIM_EPS = 0.02
# Статусы «шлюзов» (WAF/auth/rate-limit). Их разница с обычным 200 — это, как
# правило, блокировка или дрейф сессии, а не boolean-blind SQLi (FP-guard).
BLIND_GATE_STATUSES = frozenset({401, 403, 406, 418, 429})


def parse_blind_payload(pair_line: str) -> Optional[tuple[str, str]]:
    """Парсит строку payload-файла sqli_blind: `true_payload ||| false_payload`."""
    line = (pair_line or "").strip()
    if not line or BLIND_PAYLOAD_DELIMITER not in line:
        return None
    true_payload, _sep, false_payload = line.partition(BLIND_PAYLOAD_DELIMITER)
    true_payload = true_payload.strip()
    false_payload = false_payload.strip()
    if not true_payload or not false_payload:
        return None
    if true_payload == false_payload:
        return None
    return true_payload, false_payload


def normalize_blind_text(text: str) -> str:
    """Нормализация тела ответа: collapse whitespace, нижний регистр, срез."""
    if not text:
        return ""
    return re.sub(r"\s+", " ", text).strip().lower()[:BLIND_NORM_LIMIT]


def _blind_echo_mask(text: str, payload: str) -> str:
    """Удаляет из текста эхо payload'а (raw / URL-encoded / JSON-escaped формы).

    Отражённый payload сам по себе не должен выглядеть как различие ответов:
    иначе любой echo-эндпоинт даёт FP на blind-детекции.
    """
    if not text or not payload:
        return text
    masked = text
    variants = {
        payload,
        urllib.parse.quote(payload, safe=""),
        json.dumps(payload)[1:-1],
        urllib.parse.quote(payload, safe="").replace("%", "%25"),
    }
    for variant in sorted((v for v in variants if v), key=len, reverse=True):
        masked = masked.replace(variant, "")
    return masked


def _blind_similarity(first: str, second: str) -> float:
    """similarity двух нормализованных текстов (0..1), безопасно для пустых."""
    if not first and not second:
        return 1.0
    return difflib.SequenceMatcher(None, first, second).ratio()


@dataclass
class BlindResult:
    """Результат сравнения true/false пары для boolean-blind SQLi."""

    evidence: str
    confidence: float
    status_diff: bool


def evaluate_blind_pair(
    *,
    true_status: Optional[int],
    true_text: str,
    false_status: Optional[int],
    false_text: str,
    payload_true: str = "",
    payload_false: str = "",
    baseline_text: str = "",
    baseline_status: Optional[int] = None,
) -> Optional[BlindResult]:
    """Решает, является ли разница true/false ответов boolean-blind SQLi.

    Критерии (FIX_CONTRACT/task-14):
      • оба запроса без transport error (status задан);
      • ответы значимо различаются: status_diff ИЛИ len_diff >= max(20, 3%) ИЛИ
        similarity < 0.97 (после маскировки эха payload'ов);
      • нет baseline → принимаем ТОЛЬКО status_diff (body-diff без baseline — FP);
      • есть baseline → similarity(false, baseline) >= max(similarity(true,
        baseline)+0.05, 0.90) ИЛИ (status_false == baseline_status и
        status_true != baseline_status); «плавающие» одинаково похожие ответы не
        флагаем;
      • одинаковые 4xx/5xx (WAF/error) — не сигнал.

    Возвращает BlindResult (evidence + confidence 0.7 при status-diff / 0.55 при
    body-diff) или None.
    """
    if true_status is None or false_status is None:
        return None

    true_text = (true_text or "")[:BLIND_TEXT_LIMIT]
    false_text = (false_text or "")[:BLIND_TEXT_LIMIT]
    base_text = (baseline_text or "")[:BLIND_TEXT_LIMIT]

    masked_true = _blind_echo_mask(true_text, payload_true)
    masked_false = _blind_echo_mask(false_text, payload_false)

    len_true, len_false = len(true_text), len(false_text)
    status_diff = true_status != false_status
    len_diff = abs(len_true - len_false) >= max(
        BLIND_LEN_MIN_DIFF, BLIND_LEN_REL_DIFF * max(len_true, len_false)
    )
    sim_true_false = _blind_similarity(
        normalize_blind_text(masked_true), normalize_blind_text(masked_false)
    )
    differ = status_diff or len_diff or (sim_true_false < BLIND_SIM_DIFF)
    if not differ:
        return None

    has_baseline = bool(base_text) or baseline_status is not None

    # Оба ответа — ошибки (4xx/5xx): WAF/upstream/таймауты, не boolean-сигнал.
    if true_status >= 400 and false_status >= 400:
        return None
    # Серверная ошибка (>=500) на стороне, не совпадающей с baseline, — это
    # WAF/апстрим/сбой, а не булева разница. (При baseline такого поведения нет.)
    if has_baseline and baseline_status is not None:
        for _st in (true_status, false_status):
            if _st >= 500 and _st != baseline_status:
                return None

    # WAF/auth/rate-limit gate: 200 vs 401/403/406/418/429 — обычно блокировка
    # запроса (WAF) или истёкшая сессия, а не boolean-инъекция. Не флагуем, если
    # «шлюзовый» статус есть на стороне, отличной от baseline (baseline сам
    # может быть gate-статусом — тогда это ожидаемое поведение).
    if status_diff:
        gate_side = (
            true_status if true_status in BLIND_GATE_STATUSES
            else false_status if false_status in BLIND_GATE_STATUSES
            else None
        )
        if gate_side is not None and gate_side != baseline_status:
            return None

    baseline_note = ""
    if has_baseline:
        masked_base = _blind_echo_mask(base_text, payload_true)
        norm_true_base = normalize_blind_text(masked_true)
        norm_false_base = normalize_blind_text(masked_false)
        norm_base = normalize_blind_text(masked_base)
        sim_false_base = _blind_similarity(norm_false_base, norm_base) if (base_text and norm_base) else 0.0
        sim_true_base = _blind_similarity(norm_true_base, norm_base) if (base_text and norm_base) else 0.0
        # Baseline может соответствовать как true-, так и false-состоянию
        # (уязвимый параметр часто отдаёт «нормальную» страницу = true). Поэтому
        # требуем, чтобы ОДНА сторона пары заметно сильнее походила на baseline,
        # и/или чтобы статус одной стороны совпал с baseline, а другой — нет.
        status_false_match = (
            baseline_status is not None
            and false_status == baseline_status
            and true_status != baseline_status
        )
        status_true_match = (
            baseline_status is not None
            and true_status == baseline_status
            and false_status != baseline_status
        )
        status_match = status_false_match or status_true_match
        sim_ok = False
        similar_side = "false" if status_false_match else "true"
        best_sim = 0.0
        sim_diff = abs(sim_true_base - sim_false_base)
        if base_text and norm_base:
            best_is_false = sim_false_base >= sim_true_base
            best_sim = sim_false_base if best_is_false else sim_true_base
            other_sim = sim_true_base if best_is_false else sim_false_base
            similar_side = "false" if best_is_false else "true"
            sim_ok = best_sim >= max(
                other_sim + BLIND_BASELINE_SIM_MARGIN, BLIND_MIN_BASELINE_SIM
            )
        if not (sim_ok or status_match):
            return None
        if base_text and norm_base and not status_match:
            # «Плавающий» ответ: true и false почти одинаково похожи на baseline.
            if sim_diff < max(BLIND_FLOATING_SIM_EPS, BLIND_BASELINE_SIM_MARGIN):
                return None
        if base_text and norm_base:
            baseline_note = (
                f"; {similar_side} matches baseline "
                f"(status {false_status if similar_side == 'false' else true_status}/"
                f"{baseline_status}, sim {best_sim:.2f})"
            )
        else:
            baseline_note = (
                f"; {similar_side} matches baseline (status "
                f"{false_status if similar_side == 'false' else true_status}/"
                f"{baseline_status})"
            )
    else:
        # Без baseline body-diff не считается находкой (FP-контроль): только status-diff.
        if not status_diff:
            return None
        baseline_note = "; no baseline: status-diff only"

    confidence = 0.7 if status_diff else 0.55
    evidence = (
        "Blind SQLi (boolean): true/false responses differ "
        f"(status {true_status} vs {false_status}; len {len_true} vs {len_false}; "
        f"sim {sim_true_false:.2f}){baseline_note}"
    )
    return BlindResult(evidence=evidence, confidence=confidence, status_diff=status_diff)


# ──────────────────────────── Task dataclass ────────────────────────────

@dataclass
class ScanTask:
    template_id: str        # e.g. "hist-42-xss-query.param"
    check_type: str         # "cmdi" | "xss" | "sqli" | "zap"
    payload: str
    method: str
    url: str
    headers: dict[str, str]
    body: bytes
    raw_http: str           # мутированный raw (до подстановки payload)
    mutation_point: str
    original_param: str
    history_id: Optional[int] = None  # for checks runner / scope

    # ── Boolean-blind SQLi (sqli_blind): готовый второй запрос пары ──
    # Поля с дефолтами — обратная совместимость: старые конструкторы/тесты
    # и все остальные чеки работают без изменений.
    pair_payload: str = ""                    # false-payload (payload — true-payload)
    pair_url: str = ""                        # готовый URL для false-запроса
    pair_headers: dict[str, str] = field(default_factory=dict)
    pair_body: bytes = b""

    @property
    def is_pair(self) -> bool:
        """True, если задача — пара для boolean-blind сравнения ответов."""
        return bool(self.pair_payload and self.pair_url)


# ──────────────────────────── Tamper helpers ────────────────────────────

def _encode_payload_safe(payload: str, mode: str) -> Optional[str]:
    """templating.encode_payload с защитой от переходного состояния templating."""
    encoder = getattr(templating, "encode_payload", None)
    if encoder is None:
        return None
    try:
        return encoder(payload, mode)
    except Exception as exc:
        logger.warning("tamper encode failed (mode=%s): %s", mode, exc)
        return None


def _apply_payload_with_encoder(
    mutation: "templating.MutatedRequest",
    payload: str,
    encoder: Optional[str] = None,
) -> tuple[str, dict, bytes]:
    """templating.apply_payload(..., encoder=…) c fallback на старую сигнатуру."""
    if encoder is None:
        return templating.apply_payload(mutation, payload)
    try:
        return templating.apply_payload(mutation, payload, encoder=encoder)
    except TypeError:
        # templating ещё не знает encoder= (параллельная правка ):
        # кодируем вручную и подставляем старым способом.
        encoded = _encode_payload_safe(payload, encoder)
        return templating.apply_payload(mutation, encoded if encoded is not None else payload)


# ──────────────────────────── Task builder ────────────────────────────

def build_scan_tasks(
    history_ids: list[int],
    enabled_checks: list[str],
    do_query: bool = True,
    do_body_form: bool = True,
    do_body_json: bool = True,
    do_headers: bool = False,
    safe_mode: bool = True,
    planner_enabled: bool = True,
    contracts: dict[tuple[str, str], dict] | None = None,
    tamper_modes: list[str] | None = None,
    csrf_token_provider: Callable[[], str | None] | None = None,
    do_body_raw: bool = True,
    only_params: list[str] | None = None,
    do_cookies: bool = True,
    do_path: bool = True,
    do_body_multipart: bool = True,
) -> list[ScanTask]:
    """
    Для каждого history_id × check_type × mutation_point × payload
    строит ScanTask.

    tamper_modes: список режимов templating.encode_payload ("url", "unicode",
        "hex", "double-url"). Для каждого base-(check_type, mutation, payload)
        добавляется вариант с закодированным payload (URL/body — через
        templating.apply_payload(..., encoder=mode)). Применяется только к
        серверным инъекционным чекам (TAMPERABLE_CHECKS); XSS/passive — нет.

    csrf_token_provider: вызывается ОДИН раз на history record; если вернул
        токен — он патчится в каждую мутацию (templating.patch_csrf_token) до
        генерации задач, а мутации самого CSRF-поля не отправляются.

    do_body_raw: включить raw-мутацию тела (XML/SOAP/PHP-serialized/сырые
        тела). Такие задачи создаются ТОЛЬКО для BODY_RAW_CHECKS (xxe при
        XML/SOAP Content-Type и deserialization), для остальных чеков
        отсекаются.

    only_params: если задан список имён — оставляем только мутации, у которых
        ``mutation.original_param`` входит в список (case-insensitive). Для
        raw-тела имя — "body". Пустой/None = без фильтра.

    do_cookies / do_path / do_body_multipart (multi-boundary, default True):
        мутации значений cookie (``cookie:<name>``), path-сегментов URL (``path``)
        и текстовых полей multipart/form-data (``body_multipart``). Для XXE
        новые точки не используются (только XML/raw тело); body_raw-gate не
        меняется.
    """
    tasks: list[ScanTask] = []

    def _is_type_ok(check_type: str, mutation_point: str, param_name: str, content_type: str, contract: dict | None) -> bool:
        if not contract:
            return True
        try:
            pt = (contract.get("param_types") or {}).get(param_name)
        except Exception:
            pt = None
        if not pt:
            return True
        ct = (check_type or "").lower()
        mp = (mutation_point or "").lower()

        # int params: focus IDOR-ish or numeric injections; deprioritize open_redirect/ssrf
        if pt == "int" and ct in ("open_redirect", "ssrf"):
            return False

        # url params: focus ssrf/open_redirect; deprioritize sql/cmd/ssti unless explicitly allowed
        if pt == "url" and ct in ("ssrf", "open_redirect"):
            return mp == "query"
        if pt == "url" and ct in ("sqli", "sqli_time", "sqli_blind", "cmdi", "ssti", "xxe"):
            return False

        # json-like params: prefer NoSQLi/deserialization, avoid open_redirect
        if pt == "json" and ct in ("nosql_injection", "deserialization"):
            return mp in ("body_json", "body_form", "query", "body_raw", "body_multipart")
        if pt == "json" and ct in ("open_redirect",):
            return False

        # email params: avoid SSRF/open_redirect noise
        if pt == "email" and ct in ("ssrf", "open_redirect"):
            return False

        # xml-related: allow xxe only if body and content-type hints xml;
        # raw body (целый XML-документ) — основной путь для XXE.
        if ct == "xxe":
            return ("xml" in (content_type or "")) and (
                mp in ("body_form", "body_json", "body_raw")
            )

        return True

    for history_id in history_ids:
        record = db.fetch_history_by_id(history_id)
        if not record:
            logger.warning("history id=%s not found, skipping", history_id)
            continue

        method = record["method"]
        url = record["url"]

        try:
            req_headers: dict = json.loads(record["req_headers"])
        except (json.JSONDecodeError, TypeError):
            req_headers = {}
        content_type = ""
        try:
            content_type = (req_headers.get("content-type") or req_headers.get("Content-Type") or "").lower()
        except Exception:
            content_type = ""

        req_body: Optional[bytes] = record["req_body"]
        body_bytes = req_body if req_body else b""

        parsed_req = templating.ParsedRequest(
            method=method,
            url=url,
            http_version="HTTP/1.1",
            headers=req_headers,
            body=body_bytes,
        )

        # Get mutation points
        mutations = templating.get_mutations(
            parsed_req,
            do_query=do_query,
            do_body_form=do_body_form,
            do_body_json=do_body_json,
            do_headers=do_headers,
            do_body_raw=do_body_raw,
            do_cookies=do_cookies,
            do_path=do_path,
            do_body_multipart=do_body_multipart,
        )

        # only_params: GUI-выбор «в какой параметр инъектить». Для raw-тела
        # original_param == "body". Сравнение case-insensitive.
        if only_params:
            _allowed_params = {
                str(_p).strip().lower()
                for _p in only_params
                if str(_p or "").strip()
            }
            if _allowed_params:
                _before = len(mutations)
                mutations = [
                    _m for _m in mutations
                    if str(getattr(_m, "original_param", "") or "").strip().lower()
                    in _allowed_params
                ]
                logger.info(
                    "only_params=%s: %d/%d mutations kept for history_id=%s",
                    sorted(_allowed_params), len(mutations), _before, history_id,
                )

        if not mutations:
            logger.info("No mutation points for history_id=%s, skipping", history_id)
            continue

        # ── CSRF (M3): ОДИН вызов провайдера на history record ──────────────
        # Свежий токен подставляется в каждую мутацию до генерации payload-задач.
        # Если провайдера нет/он вернул None/упал — мутации остаются как есть.
        csrf_token: Optional[str] = None
        if csrf_token_provider is not None:
            try:
                _tok = csrf_token_provider()
                if _tok:
                    csrf_token = str(_tok)
            except Exception as csrf_exc:
                logger.debug(
                    "csrf_token_provider failed for history_id=%s: %s", history_id, csrf_exc
                )
        if csrf_token:
            # Мутации, нацеленные на САМО CSRF-поле/заголовок, при наличии
            # свежего токена не отправляем: подстановка payload гарантированно
            # ломает токен и сервер отвечает 403 (шум, не инъекция). Сами чеки
            # CSRF живут в checks-слое, а инъекционные точки — в остальных полях.
            _csrf_fields = {
                str(n).lower().replace("-", "_")
                for n in getattr(templating, "CSRF_FIELD_NAMES", ()) or ()
            }
            _csrf_headers = {
                str(n).lower().replace("-", "_")
                for n in getattr(templating, "CSRF_HEADER_NAMES", ()) or ()
            }

            def _is_csrf_target(mutation) -> bool:  # noqa: ANN001
                param = str(getattr(mutation, "original_param", "") or "").lower()
                point = str(getattr(mutation, "mutation_point", "") or "").lower()
                normalized = param.replace("-", "_")
                if point.startswith("header:"):
                    return normalized in _csrf_headers
                return normalized in _csrf_fields

            before_filter = len(mutations)
            mutations = [m for m in mutations if not _is_csrf_target(m)]
            if len(mutations) != before_filter:
                logger.debug(
                    "CSRF: skipped %d token-target mutations for history_id=%s",
                    before_filter - len(mutations),
                    history_id,
                )
            if not mutations:
                logger.info(
                    "Only CSRF-token mutations for history_id=%s, skipping", history_id
                )
                continue

            _patcher = getattr(templating, "patch_csrf_token", None)
            if _patcher is not None:
                patched_mutations = []
                for mutation in mutations:
                    try:
                        patched_mutations.append(_patcher(mutation, csrf_token))
                    except Exception as patch_exc:
                        logger.debug("patch_csrf_token failed: %s", patch_exc)
                        patched_mutations.append(mutation)
                mutations = patched_mutations

        for check_type in enabled_checks:
            payloads = load_payloads(check_type, safe_mode=safe_mode)
            if not payloads:
                logger.warning("No payloads for check_type=%s", check_type)
                continue

            # tamper/WAF-bypass: только для серверных инъекционных чеков.
            check_type_lower = (check_type or "").lower()
            tamper_for_check: list[str] = []
            if tamper_modes and check_type_lower in TAMPERABLE_CHECKS:
                tamper_for_check = [str(m) for m in tamper_modes if m]

            for mutation in mutations:
                # ── body_raw reachability gate (FIX: XXE/deserialization) ──
                # raw-мутация тела разрешена только BODY_RAW_CHECKS: для XXE —
                # при XML/SOAP Content-Type, для deserialization — всегда.
                # Остальным чекам body_raw задач не создаёт (даже planner_enabled=False).
                if (mutation.mutation_point or "").lower() == "body_raw":
                    if check_type_lower not in BODY_RAW_CHECKS:
                        continue
                    if check_type_lower == "xxe" and "xml" not in content_type:
                        continue

                contract = None
                if contracts:
                    try:
                        from contract_inference import normalize_url_pattern
                        pat = normalize_url_pattern(url)
                        contract = contracts.get((method, pat))
                    except Exception:
                        contract = None

                # Mutation planner: skip obviously inapplicable combinations to reduce noise
                if planner_enabled:
                    mp = (mutation.mutation_point or "").lower()
                    p = (mutation.original_param or "").lower()
                    ct = (check_type or "").lower()

                    # File upload only makes sense for form/body and file-ish params
                    if ct == "file_upload" and mp not in ("body_form",):
                        continue
                    if ct == "file_upload" and p and not any(k in p for k in ("file", "upload", "avatar", "image", "attachment")):
                        continue

                    # Open redirect / SSRF: prefer query params with url-like names
                    if ct in ("open_redirect", "ssrf") and mp != "query":
                        continue
                    if ct in ("open_redirect", "ssrf") and p and not any(k in p for k in ("url", "uri", "next", "return", "redirect", "dest", "callback", "continue", "to")):
                        continue

                    # XXE only when content-type suggests xml and mutation is body
                    if ct == "xxe" and "xml" not in content_type:
                        continue
                    if ct == "xxe" and mp not in ("body_form", "body_json", "body_raw"):
                        continue

                    # SQLi/CMDi/SSTI: mostly query or body, rarely headers
                    if ct in ("sqli", "sqli_time", "sqli_blind", "cmdi", "ssti") and mp == "headers":
                        continue

                    # Path traversal: prefer file/path-ish parameter names
                    if ct == "path_traversal" and p and not any(k in p for k in ("file", "path", "dir", "folder", "name", "page", "template", "doc")):
                        # allow if no param name info
                        continue

                for payload in payloads:
                    if not _is_type_ok(check_type, mutation.mutation_point, mutation.original_param, content_type, contract):
                        continue

                    # ── Boolean-blind SQLi (sqli_blind): payload — это ПАРА ──
                    # Строка файла: "true_payload ||| false_payload". Готовим ОБА
                    # запроса здесь (url/headers/body), чтобы false-запрос точно
                    # совпадал с true по методу/эндпоинту/заголовкам и отличался
                    # только подставленным payload'ом (в т.ч. URL-encoded/JSON-
                    # escaped формах — apply_payload делает это корректно).
                    if check_type_lower == BLIND_SQLI_CHECK:
                        blind_pair = parse_blind_payload(payload)
                        if blind_pair is None:
                            logger.debug(
                                "sqli_blind: пропущена некорректная пара %r", payload
                            )
                            continue
                        true_payload, false_payload = blind_pair
                        if safe_mode and (
                            _is_destructive_payload(true_payload)
                            or _is_destructive_payload(false_payload)
                        ):
                            continue  # safe mode: только булевы условия
                        (
                            final_url_true,
                            final_headers_true,
                            final_body_true,
                        ) = _apply_payload_with_encoder(mutation, true_payload)
                        (
                            final_url_false,
                            final_headers_false,
                            final_body_false,
                        ) = _apply_payload_with_encoder(mutation, false_payload)
                        final_headers_true = {
                            k: v
                            for k, v in final_headers_true.items()
                            if k.lower() != "content-length"
                        }
                        final_headers_false = {
                            k: v
                            for k, v in final_headers_false.items()
                            if k.lower() != "content-length"
                        }
                        tasks.append(
                            ScanTask(
                                template_id=(
                                    f"hist-{history_id}-{check_type}"
                                    f"-{mutation.mutation_point}-{mutation.original_param}"
                                ),
                                check_type=check_type,
                                payload=true_payload,
                                method=method,
                                url=final_url_true,
                                headers=final_headers_true,
                                body=final_body_true,
                                raw_http=mutation.raw_http,
                                mutation_point=mutation.mutation_point,
                                original_param=mutation.original_param,
                                history_id=history_id,
                                pair_payload=false_payload,
                                pair_url=final_url_false,
                                pair_headers=final_headers_false,
                                pair_body=final_body_false,
                            )
                        )
                        continue

                    # (payload_used, encoder_mode): base-задача + tamper-варианты
                    variants: list[tuple[str, Optional[str]]] = [(payload, None)]
                    for mode in tamper_for_check:
                        encoded = _encode_payload_safe(payload, mode)
                        if encoded is not None:
                            variants.append((encoded, mode))
                    for task_payload, mode in variants:
                        final_url, final_headers, final_body = _apply_payload_with_encoder(
                            mutation, payload, mode
                        )
                        # Remove Content-Length — httpx will compute it
                        final_headers = {
                            k: v
                            for k, v in final_headers.items()
                            if k.lower() != "content-length"
                        }
                        template_id = (
                            f"hist-{history_id}-{check_type}"
                            f"-{mutation.mutation_point}-{mutation.original_param}"
                        )
                        if mode:
                            template_id += f"-tamper-{mode}"
                        tasks.append(
                            ScanTask(
                                template_id=template_id,
                                check_type=check_type,
                                payload=task_payload,
                                method=method,
                                url=final_url,
                                headers=final_headers,
                                body=final_body,
                                raw_http=mutation.raw_http,
                                mutation_point=mutation.mutation_point,
                                original_param=mutation.original_param,
                                history_id=history_id,
                            )
                        )

    return tasks


# ──────────────────────────── Matchers ────────────────────────────

# ── CMDi ──
CMDI_ERROR_SIGS = [
    "sh: 1:",
    "sh: 2:",
    "bash: line",
    "syntax error near unexpected token",
    "command not found",
    "sh: can't open",
    "/bin/sh:",
    "/bin/bash:",
    "/usr/bin/sh:",
    "no such file or directory",
    "permission denied",
    "ambiguous redirect",
    "bad substitution",
    "operation not permitted",
    "cannot execute",
    "is not recognized as an internal or external command",  # Windows
    "'cmd' is not recognized",
    "access is denied",
    "the system cannot find",
]

# Shell command output keywords that suggest successful execution
CMDI_OUTPUT_SIGS = [
    "root:",
    "daemon:",
    "nobody:",
    "uid=0",
    "uid=",
    "gid=",
    "groups=",
    "linux",
    "darwin",
    "windows_nt",
    "/etc/passwd",
    "/etc/shadow",
    "/var/www",
    "www-data",
]

# ── SQLi ──
SQLI_ERROR_SIGS = [
    "you have an error in your sql syntax",
    "warning: mysql",
    "unclosed quotation mark after the character string",
    "quoted string not properly terminated",
    "sqlstate",
    "ora-01756",
    "ora-00907",
    "ora-00933",
    "ora-00921",
    "microsoft ole db provider for sql server",
    "microsoft jet database engine",
    "sqlite3.operationalerror",
    "sqlite3.warning",
    "pg::syntaxerror",
    "psycopg2.errors",
    "pdoexception",
    "syntax error or access violation",
    "division by zero",
    "invalid column name",
    "column count doesn't match",
    "supplied argument is not a valid mysql result",
    "error in your sql syntax",
    "unexpected end of sql command",
    "mysql_fetch",
    "valid mysql result",
    "[microsoft][odbc",
    "[ibm][cli driver",
    "[sql server]",
    "org.postgresql.util",
    "com.mysql.jdbc.exceptions",
    "java.sql.sqlexception",
    "unterminated string literal",
    "invalid use of group function",
]

# ── SSTI ──
SSTI_ERROR_SIGS = [
    "jinja2.exceptions",
    "templatesyntaxerror",
    "templatenotfound",
    "undefined error",
    "flask/templating",
    "twig\\runtimeerror",
    "velocity error",
    "org.apache.velocity",
    "thymeleaferror",
    "tornadotemplate",
    "mako.exceptions",
    "cannotcallmethodon",
    "pebble template",
    "groovy.lang.missingmethodexception",
]

# ── XXE ──
XXE_ERROR_SIGS = [
    "libxml2",
    "xml parse error",
    "xml syntax error",
    "entity",
    "dtd not allowed",
    "reference to undeclared namespace prefix",
    "not well-formed",
    "content is not allowed in prolog",
    "root:x:0",
    "/etc/passwd",
    "xmleofexception",
    "system entity",
    "javax.xml.parsers",
    "org.xml.sax",
    "xml.etree",
    "lxml",
    "xmlparseexception",
]

# ── SSRF ──
SSRF_ERROR_SIGS = [
    "connection refused",
    "failed to connect",
    "could not connect to server",
    "no route to host",
    "network unreachable",
    "requests.exceptions",
    "urllib.error",
    "socket error",
    "169.254.169.254",
    "metadata.google.internal",
]
SSRF_REDIRECT_SIGS = [
    "169.254.169.254",
    "metadata.google.internal",
    "instance-data",
    "http://127.",
    "http://localhost",
    "http://[::1]",
    "file:///",
    "dict://",
    "gopher://",
]

# ── Path Traversal ──
PATH_TRAVERSAL_SIGS = [
    "root:x:0:0",
    "root:!:",
    "daemon:x:",
    "/bin/bash",
    "/bin/sh",
    "/usr/bin",
    "[extensions]",  # php.ini / windows.ini
    "[boot loader]",
    "[operating systems]",
    "[fonts]",
    "windows\\system32",
    "autoexec.bat",
    "win.ini",
    "c:\\windows",
    "/etc/hosts",
    "/proc/self/",
    "www-data",
    "web.config",
    "web.xml",
    "application.properties",
    "app.config",
    "database.yml",
    "settings.py",
    "config.php",
    "no such file",
    "permission denied",
    "path traversal",
]

# ── NoSQLi ──
NOSQLI_ERROR_SIGS = [
    "bsontype",
    "mongoerror",
    "mongodberror",
    "couchdb",
    "rethinkdb",
    "cassandraexception",
    "nosql injection",
    "document validation failed",
]

# ── LDAP Injection ──
LDAPI_ERROR_SIGS = [
    "ldap",
    "ldap_bind",
    "ldap_search",
    "ldap error",
    "namingexception",
    "dircontext",
    "ldapexception",
    "javax.naming.ldap",
    "com.sun.jndi.ldap",
    "invalid dn syntax",
    "ldap_conn_timeout",
    "distinguished name",
    "invalid filter",
    "invalid search filter",
]

# ── XPath Injection ──
XPATH_ERROR_SIGS = [
    "xpath",
    "xpathexception",
    "invalid expression",
    "syntax error in xpath",
    "xpathfunctionexception",
    "org.w3c.dom",
    "javax.xml.xpath",
    "unterminated string",
    "expecting )",
    "expecting ]",
    "invalid xpath",
    "bad xpath expression",
    "lxml.etree.xpatherror",
    "elementtree",
]

# ── Deserialization ──
DESERIAL_ERROR_SIGS = [
    "deserializ",
    "java.io.invalidclassexception",
    "java.lang.classnotfoundexception",
    "pickle",
    "unpicklingerror",
    "objectinputstream",
    "serialversionuid",
    "could not deserialize",
    "php unserialize",
    "unserialize() expects",
    "yaml.constructor.constructorerror",
    "yaml::node",
    "marshal.loads",
    "remoteobject",
    "jndi",
    "ysoserial",
]

# ── CRLF Injection ──
# Unambiguous injected-header markers: a real server never emits these on its
# own, so their presence in the response headers is a reliable CRLF signal.
CRLF_MARKER_HEADERS = [
    "x-vulnscanner-crlf-test",
    "x-crlf-injected",
    "x-injected",
]

# Headers that legitimately appear on almost any response. Their presence alone
# is NOT evidence of header injection (this was the source of ~25 false positives
# on redirect endpoints that reflect the URL into Location).
CRLF_BENIGN_HEADERS = {
    "host", "content-type", "content-length", "connection", "date", "server",
    "location", "set-cookie", "x-powered-by", "cache-control", "pragma",
    "expires", "keep-alive", "accept-ranges", "transfer-encoding",
    "content-encoding", "vary", "etag", "last-modified",
    "x-content-type-options", "x-frame-options", "strict-transport-security",
    "content-security-policy", "referrer-policy", "permissions-policy",
    "access-control-allow-origin",
}


def _payload_injected_header_names(payload: str) -> set[str]:
    """
    Extract header names a CRLF/header-injection payload tries to inject.
    Handles %0d%0a / %0a / %0d and \\r\\n / \\n / \\r encodings.
    """
    decoded = payload or ""
    for enc, ch in (
        ("%0d%0a", "\r\n"), ("%0a", "\n"), ("%0d", "\r"),
        ("%0D%0A", "\r\n"), ("%0A", "\n"), ("%0D", "\r"),
        ("\\r\\n", "\r\n"), ("\\n", "\n"), ("\\r", "\r"),
    ):
        decoded = decoded.replace(enc, ch)
    names: set[str] = set()
    for m in re.finditer(r'(?:^|[\r\n])([A-Za-z0-9_-]+)\s*:', decoded):
        names.add(m.group(1).lower())
    return names

# ── Open Redirect ──
OPEN_REDIRECT_SIGS = [
    "moved permanently",
    "moved temporarily",
    "found",
    "temporary redirect",
    "permanent redirect",
]

# ── File Upload ──
FILEUPLOAD_ERROR_SIGS = [
    "<?php",
    "<script",
    "file uploaded",
    "upload successful",
    "uploaded successfully",
    "upload complete",
    "shell",
    "webshell",
    "cmd=",
    "exec(",
    "system(",
    "application/x-php",
    "application/x-httpd-php",
    "image/php",
    "file type is not allowed",  # info: blocked
    "invalid file",              # info: blocked
]


# ─────────────────────────────────────────────────────────────────
# Matcher functions
# Each returns a short evidence string on match, or None.
# The worker always saves the result regardless; evidence=None → "—"
# in the GUI, but the row is still visible (all response codes shown).
# ─────────────────────────────────────────────────────────────────

def _reflect(payload: str, text: str, label: str) -> Optional[str]:
    """Return evidence string if payload (or url-encoded form) appears in text."""
    if payload in text:
        return f"{label}: payload reflected ({payload[:60]})"
    encoded = urllib.parse.quote(payload)
    if encoded != payload and encoded in text:
        return f"{label}: payload reflected url-enc ({encoded[:60]})"
    return None


def _sig_match(text: str, sigs: list[str], label: str) -> Optional[str]:
    """Return evidence string on first signature hit."""
    lower = text.lower()
    for sig in sigs:
        if sig.lower() in lower:
            return f"{label}: '{sig}'"
    return None


def match_cmdi(payload: str, response_text: str, status_code: int = 0) -> Optional[str]:
    # CMDi требует ошибку/вывод шелла, а НЕ отражение payload
    # (отражение команды само по себе не доказывает её выполнение).
    # (вывод вида "root:"/"uid=" часто просто отражается из payload — убрано)
    return _sig_match(response_text, CMDI_ERROR_SIGS, "Shell error")


def match_xss(
    payload: str,
    response_text: str,
    status_code: int = 0,
    response_headers: Optional[dict] = None,
) -> Optional[str]:
    # Reflected XSS: payload должен реально отразиться И уметь разорвать HTML-структуру.
    # Голые "javascript:...", "alert(1)", "[a](...)" в тексте тела — инертный текст, не XSS.
    #
    # FP-фильтры (баг #4, ):
    #  • «голый» HTML-тег (<body>, <script>) — это скелет любой HTML-страницы,
    #    его отражение не доказывает инъекцию;
    #  • отражение в JSON/plain-ответе не исполняется браузером как HTML;
    #  • payload, уже присутствовавший в baseline-ответе, — не наш сигнал.
    if not payload:
        return None
    try:
        if _fp_is_bare_html_tag(payload):
            return None
    except Exception:
        pass
    if response_headers is not None:
        try:
            if not _fp_is_html_response(response_headers):
                return None
        except Exception:
            pass
    if any(c in payload for c in "<>\"'"):
        return _reflect(payload, response_text, "XSS reflection")
    return None


def match_sqli(payload: str, response_text: str, status_code: int = 0) -> Optional[str]:
    return _sig_match(response_text, SQLI_ERROR_SIGS, "SQL error")


def match_sqli_time(payload: str, response_text: str, status_code: int = 0) -> Optional[str]:
    # Time-based SQLi НЕ детектируется по телу ответа: задержку измеряет
    # checks/injections.SQLiTimeCheck (сравнение с baseline_ms). Прежняя
    # эвристика по error-сигнатурам давала fake-детекции и удалена (M5).
    return None


def match_ssti(payload: str, response_text: str, status_code: int = 0) -> Optional[str]:
    # Check if the payload's expected arithmetic result appears (e.g. {{7*7}} → 49)
    import re
    # Extract arithmetic from payload: look for {{ N*N }} / ${{ N*N }}
    arith = re.findall(r'\{+\s*(\d+)\s*\*\s*(\d+)\s*\}+|\$\{\s*(\d+)\s*\*\s*(\d+)\s*\}', payload)
    for m in arith:
        a = int(m[0] or m[2])
        b = int(m[1] or m[3])
        result = str(a * b)
        if result in response_text:
            return f"SSTI: expression {a}*{b}={result} evaluated in response"
    ev = _sig_match(response_text, SSTI_ERROR_SIGS, "Template error")
    if ev:
        return ev
    return None


def match_path_traversal(payload: str, response_text: str, status_code: int = 0) -> Optional[str]:
    ev = _sig_match(response_text, PATH_TRAVERSAL_SIGS, "Path traversal")
    if ev:
        return ev
    # Heuristic: характерные пути в теле 200-ответа. Это слабый сигнал, поэтому
    # подавляем FP-эхо: если сервер просто отразил наш payload (например JSON
    # {"name": "../../../../etc/passwd"}), а найденный sig — часть payload'а,
    # то это не раскрытие файла, а эхо инъекции.
    if status_code in (200,) and len(response_text) > 20:
        payload_lower = (payload or "").lower()
        response_lower = (response_text or "").lower()
        reflected = bool(payload_lower) and payload_lower in response_lower
        if not reflected and payload:
            _encoded = urllib.parse.quote(payload, safe="").lower()
            reflected = _encoded != payload_lower and _encoded in response_lower
        # Check for file-like content patterns
        for sig in ["/home/", "/var/", "/etc/", "C:\\Users", "C:\\Windows"]:
            if sig not in response_text:
                continue
            if reflected and sig.lower() in payload_lower:
                # sig пришёл из нашего payload'а — это отражение, не disclosure
                continue
            return f"Path traversal: file path in response '{sig}'"
    return None


def match_xxe(payload: str, response_text: str, status_code: int = 0) -> Optional[str]:
    """XXE без OOB: доказуемо только раскрытие файла.

    Парсер-ошибки/эхо payload'а («entity», «file:///», «doctype … system»)
    НЕ являются доказательством XXE: так выглядит и заблокированная попытка,
    и обычный echo в debug-странице. Поэтому матчим только содержимое файлов
    (с OOB-коллаборатором blind-XXE появится отдельно).
    """
    text = response_text or ""
    low = text.lower()
    for sig in ("root:x:0", "root:!:", "daemon:x:", "[boot loader]",
                "for 16-bit app support", "[extensions]", "[fonts]"):
        if sig in low:
            return f"XXE: file content disclosed '{sig}'"
    return None


def match_ssrf(payload: str, response_text: str, status_code: int = 0) -> Optional[str]:
    # Check if any internal/redirect indicators appear.
    # (bare "status 500" was too weak — removed to reduce false positives)
    ev = _sig_match(response_text, SSRF_REDIRECT_SIGS, "SSRF target")
    if ev:
        return ev
    ev = _sig_match(response_text, SSRF_ERROR_SIGS, "SSRF indicator")
    if ev:
        return ev
    return None


def match_nosql_injection(payload: str, response_text: str, status_code: int = 0) -> Optional[str]:
    ev = _sig_match(response_text, NOSQLI_ERROR_SIGS, "NoSQLi error")
    if ev:
        return ev
    return None


def match_ldap_injection(payload: str, response_text: str, status_code: int = 0) -> Optional[str]:
    ev = _sig_match(response_text, LDAPI_ERROR_SIGS, "LDAP error")
    if ev:
        return ev
    return None


def match_xpath_injection(payload: str, response_text: str, status_code: int = 0) -> Optional[str]:
    return _sig_match(response_text, XPATH_ERROR_SIGS, "XPath error")


def match_deserialization(payload: str, response_text: str, status_code: int = 0) -> Optional[str]:
    # Require a deserialization-specific error signature; bare 500 was too noisy.
    return _sig_match(response_text, DESERIAL_ERROR_SIGS, "Deserialization error")


def match_crlf_injection(
    payload: str, response_text: str, status_code: int = 0,
    response_headers: Optional[dict] = None,
) -> Optional[str]:
    if not response_headers:
        return None
    resp_names = {k.lower() for k in response_headers.keys()}

    # 1. Unambiguous marker header injected by the payload
    for sig in CRLF_MARKER_HEADERS:
        if sig in resp_names:
            return f"CRLF: injected header '{sig}' in response"

    # 2. A non-standard header name the payload attempts to inject appears
    for name in _payload_injected_header_names(payload):
        if name in resp_names and name not in CRLF_BENIGN_HEADERS:
            return f"CRLF: injected header '{name}' in response"
    return None


# Bare-domain payload без схемы: "evil.com", "sub.evil.com" — только домен
# (точки разрешены, пробелы/спецсимволы — нет).
_BARE_DOMAIN_RE = re.compile(r"[a-z0-9-]+(?:\.[a-z0-9-]+)+")


def match_open_redirect(
    payload: str, response_text: str, status_code: int = 0,
    response_headers: Optional[dict] = None,
) -> Optional[str]:
    if status_code not in (301, 302, 303, 307, 308):
        return None
    loc = ""
    if response_headers:
        loc = response_headers.get("location", response_headers.get("Location", ""))
    if not loc:
        # Try to find Location: in the raw response text
        for line in response_text.splitlines():
            if line.lower().startswith("location:"):
                loc = line.split(":", 1)[1].strip()
                break
    if not loc:
        return None

    loc_stripped = loc.strip()
    loc_lower = loc_stripped.lower()

    # FP-фикс (аудит): open redirect — только АБСОЛЮТНЫЙ внешний Location
    # (http://, https://, protocol-relative //). Относительные пути вида
    # "/redirect" или "/path?x=1" (в т.ч. эхо payload в Location) — не
    # open redirect, раньше они флаугались почти на любом payload.
    if not loc_lower.startswith(("http://", "https://", "//")):
        return None

    payload_stripped = (payload or "").strip()
    if not payload_stripped:
        return None

    # 1) payload со схемой: http://host/… — host должен попасть в Location.
    m = re.search(r"https?://([^/\s?#]+)", payload_stripped, flags=re.IGNORECASE)
    if m:
        host = m.group(1).lower().rstrip("/")
        if host and host in loc_lower:
            return f"Open redirect: Location → {loc_stripped[:100]}"
        return None

    # 2) protocol-relative payload: //host/…
    if payload_stripped.startswith("//"):
        host = payload_stripped[2:].split("/", 1)[0].split("?", 1)[0].split("#", 1)[0]
        host = host.strip().lower()
        if host and host in loc_lower:
            return f"Open redirect: Location → {loc_stripped[:100]}"
        return None

    # 3) bare-domain payload без схемы ("evil.com"): только если это
    # действительно домен (точка, без пробелов/спецсимволов) и он есть в Location.
    bare_domain = payload_stripped.lower().strip("/")
    if bare_domain and _BARE_DOMAIN_RE.fullmatch(bare_domain) and bare_domain in loc_lower:
        return f"Open redirect: Location → {loc_stripped[:100]}"
    return None


def match_file_upload(payload: str, response_text: str, status_code: int = 0) -> Optional[str]:
    ev = _sig_match(response_text, FILEUPLOAD_ERROR_SIGS, "File upload")
    if ev:
        return ev
    if status_code == 200:
        for sig in ["upload", "uploaded", "file saved", "stored", "filename"]:
            if sig in response_text.lower():
                return f"File upload: success indicator '{sig}' in response"
    return None


def match_ssi(
    payload: str,
    response_text: str,
    status_code: int = 0,
    response_headers: Optional[dict] = None,
) -> Optional[str]:
    """
    WSTG-INPV-08 SSI injection: исполнение/ошибка SSI-директивы.

    Логика — checks/injections.ssi_indicator (общая с SSIInjectionCheck):
    error-сигнатуры Apache SSI + вывод date/printenv/exec + слабый сигнал
    «неэкранированная директива в HTML». Content-Type учитывается.
    """
    if not _NEW_MATCHERS_AVAILABLE:
        return None
    try:
        return _ssi_indicator(payload, response_text, response_headers)
    except TypeError:
        try:
            return _ssi_indicator(payload, response_text)
        except Exception:
            return None
    except Exception:
        return None


def match_html_injection(
    payload: str,
    response_text: str,
    status_code: int = 0,
    response_headers: Optional[dict] = None,
) -> Optional[str]:
    """
    WSTG-CLNT-03 HTML injection: маркерный тег (<h1 notscan=1>) отразился
    НЕэкранированным в HTML-ответе (не XSS: без JS-исполнения).

    Логика — checks/injections.html_injection_indicator (общая с чеком);
    учитывает bare-tag правила и Content-Type (JSON/plain ≠ HTML).
    """
    if not _NEW_MATCHERS_AVAILABLE:
        return None
    try:
        return _html_injection_indicator(payload, response_text, response_headers)
    except Exception:
        return None


# Worker calls this wrapper so all matchers get status_code + headers
def run_matcher(
    check_type: str,
    payload: str,
    response_text: str,
    status_code: int = 0,
    response_headers: Optional[dict] = None,
) -> Optional[str]:
    fn = MATCHERS.get(check_type.lower())
    if fn is None:
        return None
    # Функции, которым нужны заголовки ответа (Location/Content-Type/инъекция).
    if check_type.lower() in ("crlf_injection", "open_redirect", "xss",
                              "html_injection", "ssi_injection"):
        return fn(payload, response_text, status_code, response_headers)  # type: ignore[call-arg]
    return fn(payload, response_text, status_code)


MATCHERS: dict[str, Callable] = {
    "cmdi":             match_cmdi,
    "xss":              match_xss,
    "sqli":             match_sqli,
    "sqli_time":        match_sqli_time,
    "ssti":             match_ssti,
    "path_traversal":   match_path_traversal,
    "xxe":              match_xxe,
    "ssrf":             match_ssrf,
    "nosql_injection":  match_nosql_injection,
    "ldap_injection":   match_ldap_injection,
    "xpath_injection":  match_xpath_injection,
    "deserialization":  match_deserialization,
    "crlf_injection":   match_crlf_injection,
    "open_redirect":    match_open_redirect,
    "file_upload":      match_file_upload,
    # Новые active-чеки (WSTG-INPV-08 / WSTG-CLNT-03),.
    "ssi_injection":    match_ssi,
    "html_injection":   match_html_injection,
}


# ──────────────────────────── Async worker core ────────────────────────────
#
# M1: движок скана переписан на asyncio.
#   • ScannerRunner.start() поднимает ОДИН фоновый поток с asyncio.run();
#   • внутри — asyncio.Queue задач и N корутин-консьюмеров (workers = конкурентность);
#   • у каждого консьюмера свой httpx.AsyncClient(verify=False, timeout=15,
#     follow_redirects=False ВСЕГДА — scope-guard против payload-редиректов);
#   • синхронные db.* / session_manager вызовы уходят в asyncio.to_thread,
#     чтобы не блокировать event loop;
#   • stop() отменяет корутины и закрывает клиенты, wait() не вешает процесс.

RESP_PREVIEW_SIZE = 32_768  # 32 KB

# Sentinel для завершения корутин-консьюмеров (все реальные задачи взяты).
_QUEUE_SENTINEL: object = object()


def _build_async_client(proxy_url: Optional[str]) -> httpx.AsyncClient:
    """AsyncClient для одного консьюмера (свой пул соединений).

    follow_redirects=False — ЖЕЛЕЗНОЕ требование (scope-guard):
    payload-редирект не должен уводить сканер на чужой хост вне scope.
    """
    # httpx >= 0.28 убрал `proxies=`; используем `mounts=` с HTTPTransport.
    # Явно прописываем loopback-адреса, т.к. httpx по умолчанию их НЕ проксирует.
    kwargs: dict = {
        "verify": False,
        "timeout": 15.0,
        "follow_redirects": False,
        "limits": httpx.Limits(max_connections=20, max_keepalive_connections=10),
    }
    if proxy_url:
        _proxy_transport = httpx.HTTPTransport(proxy=proxy_url, verify=False)
        kwargs["mounts"] = {
            "http://":             _proxy_transport,
            "https://":            _proxy_transport,
            "http://localhost":    _proxy_transport,
            "https://localhost":   _proxy_transport,
            "http://127.0.0.1":    _proxy_transport,
            "https://127.0.0.1":   _proxy_transport,
        }
    return httpx.AsyncClient(**kwargs)


def _merge_cookie_headers(existing: str, fresh: str) -> str:
    """Объединяет Cookie: свежие session-cookies перетирают одноимённые старые.

    Простое склеивание "old; new" оставляло ДУБЛИ PHPSESSID/JSESSIONID: сервер
    брал первый (устаревший) — и каждый запрос скана получал 302/relogin-шторм.
    """
    merged: dict[str, str] = {}
    for chunk in (existing or "").split(";"):
        chunk = chunk.strip()
        if not chunk or "=" not in chunk:
            continue
        name, _sep, value = chunk.partition("=")
        name = name.strip()
        if name:
            merged[name] = value.strip()
    for chunk in (fresh or "").split(";"):
        chunk = chunk.strip()
        if not chunk or "=" not in chunk:
            continue
        name, _sep, value = chunk.partition("=")
        name = name.strip()
        if name:
            merged[name] = value.strip()
    return "; ".join(f"{k}={v}" for k, v in merged.items())


def _merge_session_headers(
    task_headers: dict, session_headers: Optional[dict]
) -> dict:
    """Merge session auth (cookies, Authorization) into request headers."""
    headers = dict(task_headers)
    if session_headers:
        for k, v in session_headers.items():
            if v and k.lower() not in ("content-length",):
                if k.lower() == "cookie":
                    old_cookie = headers.get("Cookie", headers.get("cookie", ""))
                    headers["Cookie"] = _merge_cookie_headers(old_cookie, str(v))
                else:
                    headers[k] = v
    return headers


def _build_raw_response_preview(resp: httpx.Response, resp_text: str) -> str:
    raw = (
        f"HTTP/1.1 {resp.status_code}\r\n"
        + "\r\n".join(f"{k}: {v}" for k, v in resp.headers.items())
        + "\r\n\r\n"
        + resp_text
    )
    return redact_raw_http(raw)


def _is_auth_error_response(
    status_code: Optional[int],
    response_headers: Optional[dict],
    resp_text: str,
) -> bool:
    """Session-drift эвристика из старого _worker (401/403/redirect на login)."""
    if status_code in (401, 403):
        return True
    loc = ""
    if response_headers:
        loc = response_headers.get("Location", "") or response_headers.get("location", "")
    loc_low = str(loc).lower()
    if loc_low and any(
        marker in loc_low for marker in
        ("login", "signin", "sign-in", "signon", "sso", "auth/")
    ):
        return True
    # Login-страница: только форма с password, а НЕ любое слово "login" в теле
    # (иначе каждая страница bWAPP с меню/ссылкой Login вызывала relogin-шторм).
    text = (resp_text or "").lower()
    if ("type=\"password\"" in text or "type='password'" in text) and "<form" in text:
        return True
    return False


def _relogin_and_get_headers(
    worker_id: int,
    status_code: Optional[int],
    url: str,
    session_manager: object,
    session_headers: Optional[dict],
    log_cb: Callable[[str], None],
    session_drift_stop: bool,
    request_stop: Callable[[], None],
) -> Optional[dict]:
    """Sync-часть auto-relogin на 401/403 (вызывается через asyncio.to_thread).

    Возвращает НОВЫЕ session_headers, если re-login удался (тогда запрос надо
    повторить), иначе None. Логика перенесена из старого синхронного _worker.
    """
    auth_enabled = getattr(session_manager, "auth_enabled", False)
    max_attempts = getattr(
        getattr(session_manager, "auth", None), "max_relogin_attempts", 3
    ) or 3
    relogin_count = getattr(session_manager, "_relogin_count", 0)

    if auth_enabled and relogin_count < max_attempts:
        # Cooldown: при массовых 401/302 не устраиваем «шторм» логинов из всех
        # воркеров — один login на 3 секунды, остальные переиспользуют cookies.
        now = time.time()
        try:
            last_attempt = float(getattr(session_manager, "_last_relogin_attempt", 0.0) or 0.0)
        except Exception:
            last_attempt = 0.0
        if now - last_attempt < 3.0:
            store = getattr(session_manager, "token_store", None)
            new_headers = {}
            if store is not None:
                if getattr(store, "access_token", None):
                    auth_obj = getattr(session_manager, "auth", None)
                    new_headers[
                        getattr(auth_obj, "token_header_name", "Authorization")
                    ] = (
                        getattr(auth_obj, "token_prefix", "Bearer ")
                        + str(store.access_token)
                    ).strip()
                if getattr(store, "cookies", None):
                    new_headers["Cookie"] = "; ".join(
                        f"{k}={v}" for k, v in store.cookies.items()
                    )
            if new_headers:
                return new_headers
        try:
            session_manager._last_relogin_attempt = now  # noqa: SLF001
        except Exception:
            pass
        # Сразу увеличиваем счётчик попыток, иначе каждый 401 в воркере снова
        # дёргал бы login() бесконечно. Успешный login() сам сбрасывает его в 0.
        try:
            session_manager._relogin_count = relogin_count + 1  # noqa: SLF001
        except Exception:
            pass
        log_cb(
            f"[SESSION] Worker-{worker_id}: {status_code} on {url[:60]} "
            f"— auto re-login (attempt {relogin_count + 1}/{max_attempts})"
        )
        # Try refresh first, then full login
        reauthed = False
        store = getattr(session_manager, "token_store", None)
        if store and getattr(store, "refresh_token", None) and not store.is_valid():
            reauthed = getattr(session_manager, "refresh", lambda: False)()
        if not reauthed:
            reauthed = getattr(session_manager, "login", lambda: False)()
        if reauthed:
            # Rebuild session_headers from updated store
            new_headers = dict(session_headers or {})
            new_store = getattr(session_manager, "token_store", None)
            auth_obj = getattr(session_manager, "auth", None)
            tok_header = getattr(auth_obj, "token_header_name", "Authorization")
            tok_prefix = getattr(auth_obj, "token_prefix", "Bearer ")
            if new_store:
                if getattr(new_store, "access_token", None):
                    new_headers[tok_header] = (tok_prefix + new_store.access_token).strip()
                if getattr(new_store, "cookies", None):
                    new_headers["Cookie"] = "; ".join(
                        f"{k}={v}" for k, v in new_store.cookies.items()
                    )
            return new_headers
        log_cb(f"[SESSION] Re-login failed for worker-{worker_id}")
        return None

    if auth_enabled and relogin_count >= max_attempts:
        log_cb("[SESSION] Max re-login attempts reached — marking as drift")
        if session_drift_stop:
            request_stop()
        return None

    # auth выключен — старое поведение: ничего не делаем (даже при drift stop).
    return None


def _persist_task_result(
    task: ScanTask,
    worker_id: int,
    status_code: Optional[int],
    error: Optional[str],
    evidence: Optional[str],
    resp_text: str,
    raw_response_preview: str,
    elapsed_ms_obs: float,
    baseline_text: str,
    baseline_row: Optional[dict],
    log_cb: Callable[[str], None],
    detector: str = "matcher",
    confidence: Optional[float] = None,
) -> None:
    """Все синхронные записи по одной задаче (вызывается через asyncio.to_thread).

    Сохранён полный набор записей старого движка: scan_results, scan_meta,
    duplicate-связи (scan_links), host_calibration, scan_requests,
    evidence snippets. Порядок записей сохранён.

    host_calibration НЕ обновляется для check_type="sqli_time": time-based
    детекция сравнивает задержку с baseline, поэтому «медленные» sleep-запросы
    не должны раздувать baseline хоста.
    """
    result_id = db.insert_scan_result(
        template_id=task.template_id,
        worker_id=worker_id,
        method=task.method,
        url=task.url,
        status_code=status_code,
        error=error,
        check_type=task.check_type,
        payload=task.payload,
        evidence=evidence,
    )
    # Store lineage/meta for correlation/triage
    try:
        fp = _fingerprint_for_result(task.url, task.check_type, task.original_param)
        # exploitability heuristic (without confirm): higher for RCE-like classes and when evidence exists
        ct = (task.check_type or "").lower()
        base_expl = 0.1
        if ct in ("cmdi", "ssti", "deserialization", "file_upload"):
            base_expl = 0.7
        elif ct in ("sqli", "sqli_time", "sqli_blind", "xxe", "ssrf", "path_traversal"):
            base_expl = 0.6
        elif ct in ("xss", "xss_reflected", "xss_dom", "open_redirect", "crlf_injection"):
            base_expl = 0.4
        expl = min(0.95, base_expl + (0.15 if evidence else 0.0))
        if confidence is None:
            confidence = 0.65 if evidence else 0.15
        db.upsert_scan_meta(
            scan_result_id=result_id,
            history_id=task.history_id,
            mutation_point=task.mutation_point,
            original_param=task.original_param,
            payload_class=task.check_type,
            detector=detector,
            confidence=confidence,
            severity=_severity_guess(task.check_type),
            exploitability=expl,
            fingerprint=fp,
        )

        # Correlation: mark duplicates by fingerprint when evidence exists
        if evidence:
            dup_id = db.find_duplicate_by_fingerprint(fp, exclude_result_id=result_id)
            if dup_id:
                db.insert_scan_link(
                    kind="duplicate",
                    src_result_id=result_id,
                    dst_result_id=dup_id,
                    fingerprint=fp,
                    note=f"{task.check_type}:{task.original_param}",
                )
                log_cb(f"[DEDUP] result#{result_id} duplicates result#{dup_id} fp={fp}")
    except Exception as meta_exc:
        logger.debug("scan_meta write failed: %s", meta_exc)

    # Self-calibration: update per-host baseline timing and typical 5xx rate
    # (кроме time-based sqli: его задержки — искусственные).
    try:
        if (task.check_type or "").lower() not in ("sqli_time", "sqli_blind"):
            host = urlparse(task.url).hostname or ""
            if host:
                prev = db.fetch_host_calibration(host) or {}
                p50 = float(prev.get("baseline_ms_p50") or 0.0)
                p95 = float(prev.get("baseline_ms_p95") or 0.0)
                rate5xx = float(prev.get("typical_5xx_rate") or 0.0)

                # Exponential moving averages; conservative p95 proxy
                alpha = 0.1
                if elapsed_ms_obs > 0:
                    p50 = (p50 * (1 - alpha) + elapsed_ms_obs * alpha) if p50 > 0 else elapsed_ms_obs
                    p95_candidate = max(elapsed_ms_obs, p50 * 1.8)
                    p95 = (p95 * (1 - alpha) + p95_candidate * alpha) if p95 > 0 else p95_candidate

                is5xx = 1.0 if (isinstance(status_code, int) and 500 <= status_code <= 599) else 0.0
                rate5xx = (rate5xx * (1 - alpha) + is5xx * alpha) if rate5xx > 0 else is5xx

                db.upsert_host_calibration(
                    host=host,
                    baseline_ms_p50=p50,
                    baseline_ms_p95=p95,
                    typical_5xx_rate=rate5xx,
                    notes="ema",
                )
    except Exception as cal_exc:
        logger.debug("host calibration update failed: %s", cal_exc)

    # Build raw request string
    raw_request = templating.build_raw_http(
        task.method, task.url, task.headers, task.body
    )
    raw_request = redact_raw_http(raw_request)
    db.insert_scan_request(
        scan_result_id=result_id,
        raw_request=raw_request,
        raw_response_preview=raw_response_preview,
    )

    # Evidence diff snippet (baseline history vs mutated response)
    if evidence:
        try:
            diff_snip = build_unified_diff_snippet(baseline_text, resp_text)
            if diff_snip:
                db.insert_evidence_snippet(
                    scan_result_id=result_id,
                    diff_snippet=diff_snip,
                    snippet_type="unified_diff",
                    baseline_ref=f"history:{baseline_row.get('id') if baseline_row else ''}",
                    mutated_ref=f"scan_result:{result_id}",
                )
        except Exception as diff_exc:
            logger.debug("evidence diff failed: %s", diff_exc)

    if evidence:
        _wstg = WSTG_ID_MAP.get(task.check_type.lower(), "")
        _wstg_tag = f"[{_wstg}] " if _wstg else ""
        log_cb(
            f"[VULN][{task.check_type.upper()}] {_wstg_tag}{task.url} | "
            f"param={task.original_param} | evidence={evidence[:120]}"
        )
    else:
        log_cb(
            f"[SCAN][{task.check_type.upper()}] worker={worker_id} "
            f"status={status_code or 'ERR'} "
            f"url={task.url[:60]} "
            f"payload={task.payload[:30]!r}"
        )


# ──────────────────────────── Worker pool ────────────────────────────

class ScannerRunner:
    """Async-движок: один поток с asyncio.run + N корутин-консьюмеров.

    Публичный контракт сохранён:
      • start()                — запустить скан в фоне;
      • wait()                 — блокироваться до завершения всех задач;
      • stop()                 — остановить (отменить задачи, закрыть клиенты);
      • start_and_wait_async() — start() + поток-waiter с wait();
      • tasks_remaining        — сколько задач ещё не завершено.

    ``workers`` — конкурентность (число корутин-консьюмеров), а не потоки.
    """

    def __init__(
        self,
        tasks: list[ScanTask],
        workers: int = 10,
        log_callback: Callable[[str], None] = print,
        proxy_url: Optional[str] = None,
        session_manager: Optional[object] = None,
        scope_allowlist: Optional[List[str]] = None,
        scope_block_private: bool = True,
        max_rps: float | None = None,
        stop_on_session_drift: bool = False,
        min_rps: float | None = None,
        delay_ms: float = 0.0,
    ):
        self.tasks = tasks
        self.workers = workers
        self.log_cb = log_callback
        self.proxy_url = proxy_url
        self.session_manager = session_manager
        self.scope_allowlist = scope_allowlist or []
        self.scope_block_private = scope_block_private
        self.max_rps = max_rps
        self.min_rps = min_rps
        self.delay_ms = float(delay_ms or 0.0)
        self._rate_limiter = RateLimiter(
            max_rps=max_rps, min_rps=min_rps, delay_ms=self.delay_ms
        )
        self.stop_on_session_drift = stop_on_session_drift

        # ── Scope-guard статистика (вместо спама per-request в GUI-лог) ──
        self._scope_lock = threading.Lock()
        self._scope_skipped = 0
        self._scope_skipped_private = 0
        self._scope_skipped_allowlist = 0
        self._scope_skipped_other = 0
        self._scope_details_logged = 0
        self._scope_examples: list[str] = []

        # ── Auth preflight counters (GUI предупреждает после скана) ──
        self._auth_lock = threading.Lock()
        self.auth_failure_count = 0
        self.auth_redirect_count = 0
        self.last_auth_status: Optional[int] = None
        self._tasks_total = len(tasks)
        self._completed = 0
        self._in_flight = 0
        # GUI-совместимость: _poll() читает self._scan_runner._stop.is_set().
        self._stop = threading.Event()
        self._threads: list[threading.Thread] = []
        self._done = threading.Event()
        self._loop: Optional[asyncio.AbstractEventLoop] = None
        self._async_q: Optional[asyncio.Queue] = None
        self._consumer_tasks: list[asyncio.Task] = []
        self._is_async = True

    # ── публичный контракт ──────────────────────────────────────────

    def start(self) -> None:
        if self._threads:
            self.log_cb("[SCAN] already running")
            return

        session_headers = self._login_session()

        total = self._tasks_total
        concurrency = max(1, int(self.workers or 1))
        self.log_cb(f"[SCAN] Queuing {total} tasks across {concurrency} workers …")

        self._stop.clear()
        self._done.clear()
        self._completed = 0
        self._in_flight = 0
        runner_thread = threading.Thread(
            target=self._thread_main,
            args=(session_headers,),
            daemon=True,
            name="scanner-async-runner",
        )
        self._threads = [runner_thread]
        runner_thread.start()

    def stop(self) -> None:
        """Остановить скан: отменить корутины, закрыть клиенты, join потока."""
        self._stop.set()
        loop = self._loop
        if loop is not None and not loop.is_closed():
            try:
                loop.call_soon_threadsafe(self._hard_cancel_consumers)
            except RuntimeError:
                pass
        runner_thread = self._threads[0] if self._threads else None
        if runner_thread is not None and runner_thread is not threading.current_thread():
            runner_thread.join(timeout=5.0)
            if runner_thread.is_alive():
                # Корутины, застрявшие в сети, отменяем повторно (клиенты
                # закроются в finally _async_main).
                loop = self._loop
                if loop is not None and not loop.is_closed():
                    try:
                        loop.call_soon_threadsafe(self._hard_cancel_consumers)
                    except RuntimeError:
                        pass
                runner_thread.join(timeout=5.0)
        self._threads.clear()
        self.log_cb("[SCAN] stopped")

    def wait(self) -> None:
        """Block until all tasks are done (or stop() called)."""
        self._done.wait()
        self.stop()
        self.log_cb("[SCAN] finished")

    def start_and_wait_async(self) -> threading.Thread:
        """Non-blocking: start scan in background thread, call log_cb when done."""
        self.start()
        waiter = threading.Thread(target=self.wait, daemon=True, name="scan-waiter")
        waiter.start()
        return waiter

    @property
    def tasks_remaining(self) -> int:
        remaining = self._tasks_total - self._completed
        return remaining if remaining > 0 else 0

    # ── внутреннее ──────────────────────────────────────────────────

    # ── Scope-guard: агрегированные счётчики вместо per-request лога ──

    def _record_scope_skip(self, reason: str, url: str) -> None:
        host = ""
        try:
            host = (urlparse(url).hostname or "").lower()
        except Exception:
            host = ""
        with self._scope_lock:
            self._scope_skipped += 1
            if reason == SCOPE_REASON_PRIVATE:
                self._scope_skipped_private += 1
            elif reason == SCOPE_REASON_ALLOWLIST:
                self._scope_skipped_allowlist += 1
            else:
                self._scope_skipped_other += 1
            if self._scope_details_logged < SCOPE_LOG_DETAIL_LIMIT:
                self._scope_details_logged += 1
                detail = True
            else:
                detail = False
            if host and host not in self._scope_examples and len(self._scope_examples) < 10:
                self._scope_examples.append(host)
        if detail:
            self.log_cb(
                f"[SCOPE] Skipping out-of-scope URL ({reason}): {url[:100]}"
            )

    def scope_stats(self) -> dict:
        """Снимок статистики scope-guard (для GUI/тестов/отчёта)."""
        with self._scope_lock:
            return {
                "skipped": self._scope_skipped,
                "private": self._scope_skipped_private,
                "allowlist": self._scope_skipped_allowlist,
                "other": self._scope_skipped_other,
                "details_logged": self._scope_details_logged,
                "examples": list(self._scope_examples),
            }

    def _log_scope_summary(self) -> None:
        with self._scope_lock:
            skipped = self._scope_skipped
            private = self._scope_skipped_private
            allowlist = self._scope_skipped_allowlist
            other = self._scope_skipped_other
            examples = list(self._scope_examples)
        if skipped:
            suffix = f"; examples: {', '.join(examples[:5])}" if examples else ""
            self.log_cb(
                f"[SCOPE] Skipped {skipped} requests outside scope "
                f"(private={private}, allowlist={allowlist}, other={other}){suffix}"
            )

    # ── Auth-ответы: агрегированные счётчики (401/403/login-redirect) ──

    def _record_auth_observation(
        self,
        status_code: Optional[int],
        response_headers: Optional[dict] = None,
    ) -> None:
        """Считает 401/403 и редиректы на login; поведение скана не меняет."""
        if status_code is None:
            return
        auth_failure = status_code in (401, 403)
        is_login_redirect = False
        if not auth_failure and 300 <= int(status_code) < 400 and response_headers:
            location = (
                response_headers.get("Location")
                or response_headers.get("location")
                or ""
            )
            is_login_redirect = "login" in str(location).lower()
        if not auth_failure and not is_login_redirect:
            return
        with self._auth_lock:
            # 401/403 — реальные признаки отсутствия авторизации. Редирект на
            # login часто просто поведение конкретного мутированного URL
            # (path-мутация) и не должен пугать пользователя.
            if auth_failure:
                self.auth_failure_count += 1
            else:
                self.auth_redirect_count += 1
            self.last_auth_status = int(status_code)

    def auth_stats(self) -> dict:
        """Снимок auth-counters (GUI предупреждает о 401/403 после скана)."""
        with self._auth_lock:
            return {
                "auth_failure_count": self.auth_failure_count,
                "auth_redirect_count": self.auth_redirect_count,
                "last_auth_status": self.last_auth_status,
            }

    def _log_auth_summary(self) -> None:
        stats = self.auth_stats()
        if stats["auth_failure_count"]:
            self.log_cb(
                f"[AUTH] {stats['auth_failure_count']} responses with 401/403 "
                f"(last status={stats['last_auth_status']}) — проверь "
                f"Cookie/OTP/авто-логин"
            )
        elif stats.get("auth_redirect_count"):
            self.log_cb(
                f"[AUTH] {stats['auth_redirect_count']} login-redirects during scan "
                f"(informational; часто это поведение мутированных URL)"
            )

    def _login_session(self) -> Optional[dict]:
        """Sync-логин сессии в start() (как в старом движке; поток не event loop)."""
        session_headers: Optional[dict] = None
        if self.session_manager is None:
            return None
        auth_enabled = getattr(self.session_manager, "auth_enabled", False)
        if not auth_enabled:
            return None
        if not getattr(self.session_manager, "login", None):
            self.log_cb("[SCAN] Session manager has no login(), skipping auth")
            return None
        ok = self.session_manager.login()
        if not ok:
            return None
        store = getattr(self.session_manager, "token_store", None)
        token_header = getattr(
            getattr(self.session_manager, "auth", None),
            "token_header_name",
            "Authorization",
        )
        token_prefix = getattr(
            getattr(self.session_manager, "auth", None),
            "token_prefix",
            "Bearer ",
        )
        if store:
            session_headers = {}
            if getattr(store, "access_token", None):
                session_headers[token_header] = (
                    token_prefix + (store.access_token or "")
                ).strip()
            if getattr(store, "cookies", None) and store.cookies:
                session_headers["Cookie"] = "; ".join(
                    f"{k}={v}" for k, v in store.cookies.items()
                )
        self.log_cb("[SCAN] Session auth applied for workers")
        return session_headers

    def _thread_main(self, session_headers: Optional[dict]) -> None:
        """Точка входа фонового потока: один asyncio.run на весь скан."""
        try:
            asyncio.run(self._async_main(session_headers))
        except asyncio.CancelledError:  # pragma: no cover - защитный путь
            pass
        except Exception:
            logger.exception("Async scanner runner crashed")
        finally:
            self._loop = None
            self._done.set()

    async def _async_main(self, session_headers: Optional[dict]) -> None:
        self._loop = asyncio.get_running_loop()
        self._async_q = asyncio.Queue()
        for task in self.tasks:
            self._async_q.put_nowait(task)

        concurrency = max(1, int(self.workers or 1))
        for _ in range(concurrency):
            self._async_q.put_nowait(_QUEUE_SENTINEL)

        clients: list[httpx.AsyncClient] = []
        consumers: list[asyncio.Task] = []
        try:
            for worker_id in range(concurrency):
                client = _build_async_client(self.proxy_url)
                clients.append(client)
                consumers.append(
                    asyncio.create_task(
                        self._async_consumer(worker_id, session_headers, client),
                        name=f"scanner-async-{worker_id}",
                    )
                )
            self._consumer_tasks = consumers
            if self._stop.is_set():
                # stop() успел раньше, чем создались корутины.
                for consumer in consumers:
                    consumer.cancel()
            await asyncio.gather(*consumers, return_exceptions=True)
        finally:
            for consumer in consumers:
                consumer.cancel()
            with contextlib.suppress(Exception):
                await asyncio.gather(*consumers, return_exceptions=True)
            self._consumer_tasks = []
            for client in clients:
                with contextlib.suppress(Exception):
                    await client.aclose()
            # Один агрегированный итог по scope/auth вместо per-request логов.
            with contextlib.suppress(Exception):
                self._log_scope_summary()
            with contextlib.suppress(Exception):
                self._log_auth_summary()

    async def _async_consumer(
        self,
        worker_id: int,
        session_headers: Optional[dict],
        client: httpx.AsyncClient,
    ) -> None:
        """Корутина-консьюмер: берёт задачи из asyncio.Queue и обрабатывает."""
        local_session_headers = session_headers
        while not self._stop.is_set():
            task = await self._async_q.get()
            if task is _QUEUE_SENTINEL:
                break
            self._in_flight += 1
            try:
                local_session_headers = await self._process_task(
                    worker_id, task, local_session_headers, client
                )
            except asyncio.CancelledError:
                raise
            except Exception:
                logger.exception(
                    "Async worker %d failed on task %s",
                    worker_id,
                    getattr(task, "template_id", "?"),
                )
            finally:
                self._completed += 1
                self._in_flight -= 1

    def _hard_cancel_consumers(self) -> None:
        """Выполняется в loop-потоке (через call_soon_threadsafe)."""
        for consumer in list(self._consumer_tasks):
            consumer.cancel()

    async def _process_task(
        self,
        worker_id: int,
        task: ScanTask,
        session_headers: Optional[dict],
        client: httpx.AsyncClient,
    ) -> Optional[dict]:
        """Обработка одной задачи: запрос → matchers → checks → persist."""
        # Scope guard: allowlist — явная авторизация (разрешает private/local);
        # блокируем private/metadata только ВНЕ allowlist. Подробно логируем
        # первые SCOPE_LOG_DETAIL_LIMIT записей, дальше — агрегированные счётчики.
        allowed, scope_reason = classify_url_scope(
            task.url,
            self.scope_allowlist if self.scope_allowlist else None,
            self.scope_block_private,
        )
        if not allowed:
            self._record_scope_skip(scope_reason, task.url)
            return session_headers

        headers = _merge_session_headers(task.headers, session_headers)

        status_code: Optional[int] = None
        error: Optional[str] = None
        evidence: Optional[str] = None
        resp_text = ""
        raw_response_preview = ""
        elapsed_ms_obs = 0.0
        baseline_text = ""
        baseline_status: Optional[int] = None
        baseline_row: Optional[dict] = None
        resp: Optional[httpx.Response] = None
        # sqli_blind: детектор/уверенность для scan_meta (matcher по умолчанию).
        blind_detector = "matcher"
        blind_confidence: Optional[float] = None

        try:
            if self._rate_limiter is not None:
                await self._rate_limiter.acquire_async()
            start_ts = time.perf_counter()
            resp = await client.request(
                method=task.method,
                url=task.url,
                headers=headers,
                content=task.body if task.body else None,
                # scope-guard: редиректы НЕ сопровождаем НИКОГДА.
                follow_redirects=False,
            )
            status_code = resp.status_code
            elapsed_ms_obs = (time.perf_counter() - start_ts) * 1000.0
            resp_text = resp.text[:RESP_PREVIEW_SIZE]
            raw_response_preview = _build_raw_response_preview(resp, resp_text)
            self._record_auth_observation(status_code, dict(resp.headers))

            # ── Session drift monitor + auto-relogin on 401/403 ──
            if _is_auth_error_response(status_code, dict(resp.headers), resp_text):
                if self.session_manager is not None:
                    new_headers = await asyncio.to_thread(
                        _relogin_and_get_headers,
                        worker_id,
                        status_code,
                        task.url,
                        self.session_manager,
                        session_headers,
                        self.log_cb,
                        self.stop_on_session_drift,
                        self._stop.set,
                    )
                    if new_headers is not None:
                        session_headers = new_headers
                        # Retry the same request with new headers
                        retry_headers = _merge_session_headers(
                            task.headers, session_headers
                        )
                        try:
                            resp = await client.request(
                                method=task.method,
                                url=task.url,
                                headers=retry_headers,
                                content=task.body if task.body else None,
                                follow_redirects=False,
                            )
                            status_code = resp.status_code
                            resp_text = resp.text[:RESP_PREVIEW_SIZE]
                            raw_response_preview = _build_raw_response_preview(
                                resp, resp_text
                            )
                            self._record_auth_observation(
                                status_code, dict(resp.headers)
                            )
                            self.log_cb(
                                f"[SESSION] Retry after re-login: {status_code} "
                                f"for {task.url[:60]}"
                            )
                        except Exception as retry_exc:
                            self.log_cb(f"[SESSION] Retry request failed: {retry_exc}")
                elif self.stop_on_session_drift:
                    self.log_cb(
                        "[SESSION] Drift detected (no session manager) — stopping scan"
                    )
                    self._stop.set()

            # ── Baseline-aware detection (differential analysis) ──
            try:
                if task.history_id is not None:
                    baseline_row = await asyncio.to_thread(
                        db.fetch_history_by_id, task.history_id
                    )
                    if baseline_row:
                        baseline_status = baseline_row.get("resp_status")
                        bb = baseline_row.get("resp_body_preview")
                        if bb:
                            baseline_text = (
                                bb.decode("utf-8", errors="replace")
                                if isinstance(bb, bytes)
                                else str(bb)
                            )
            except Exception:
                baseline_row = None

            # ── Boolean-blind SQLi (sqli_blind): второй (false) запрос пары ──
            # Второй запрос идёт тем же AsyncClient, с теми же method/headers и
            # follow_redirects=False; отличается только подставленный payload.
            if task.check_type.lower() == BLIND_SQLI_CHECK and task.is_pair:
                false_status: Optional[int] = None
                false_text = ""
                false_headers = _merge_session_headers(
                    task.pair_headers or task.headers, session_headers
                )
                try:
                    if self._rate_limiter is not None:
                        await self._rate_limiter.acquire_async()
                    false_resp = await client.request(
                        method=task.method,
                        url=task.pair_url,
                        headers=false_headers,
                        content=task.pair_body if task.pair_body else None,
                        follow_redirects=False,
                    )
                    false_status = false_resp.status_code
                    false_text = false_resp.text[:BLIND_TEXT_LIMIT]
                    self._record_auth_observation(
                        false_status, dict(false_resp.headers)
                    )
                except asyncio.CancelledError:
                    raise
                except Exception as pair_exc:
                    # Ошибка/таймаут второго запроса — пару не считаем.
                    logger.debug("sqli_blind: false-запрос не выполнен: %s", pair_exc)
                    self.log_cb(
                        f"[BLIND][WARN] false-запрос пары не выполнен "
                        f"({task.url[:60]}): {pair_exc}"
                    )
                if false_status is not None:
                    blind_result = evaluate_blind_pair(
                        true_status=status_code,
                        true_text=resp_text,
                        false_status=false_status,
                        false_text=false_text,
                        payload_true=task.payload,
                        payload_false=task.pair_payload,
                        baseline_text=baseline_text,
                        baseline_status=baseline_status,
                    )
                    if blind_result is not None:
                        evidence = blind_result.evidence
                        blind_detector = "blind"
                        blind_confidence = blind_result.confidence
                        self.log_cb(
                            f"[BLIND] {task.original_param} @ {task.url[:80]} | "
                            f"{blind_result.evidence[:140]}"
                        )
                    else:
                        logger.debug(
                            "sqli_blind: пара неразличима (status %s/%s, url=%s)",
                            status_code, false_status, task.url[:80],
                        )

            if evidence is None:
                evidence = run_matcher(
                    task.check_type,
                    task.payload,
                    resp_text,
                    status_code=status_code or 0,
                    response_headers=dict(resp.headers),
                )

            # Подавление ложных срабатываний: если тот же матчер срабатывает и на
            # baseline-ответе (без мутации), значит сигнал не вызван нашим payload.
            # (blind-детекция уже baseline-aware — её не подавляем повторно.)
            if evidence and blind_detector != "blind" and baseline_text:
                try:
                    _baseline_headers = None
                    if baseline_row:
                        try:
                            _bh = baseline_row.get("resp_headers") or "{}"
                            _baseline_headers = (
                                json.loads(_bh) if isinstance(_bh, str) else _bh
                            )
                        except Exception:
                            _baseline_headers = None
                    baseline_evidence = run_matcher(
                        task.check_type,
                        task.payload,
                        baseline_text,
                        status_code=baseline_status or 0,
                        response_headers=_baseline_headers,
                    )
                    if baseline_evidence:
                        self.log_cb(
                            f"[FP-SUPPRESS] {task.check_type} {task.url[:60]} — "
                            f"signal also present in baseline"
                        )
                        evidence = None
                except Exception:
                    pass

            # ── host calibration: p50 → baseline_ms для checks-слоя ──
            # (для sqli_time baseline тоже нужен, но сама калибровка им не
            # обновляется — см. _persist_task_result)
            baseline_ms = 0.0
            host = urlparse(task.url).hostname or ""
            if host:
                try:
                    calibration = await asyncio.to_thread(
                        db.fetch_host_calibration, host
                    )
                    if calibration:
                        baseline_ms = float(
                            calibration.get("baseline_ms_p50") or 0.0
                        )
                except Exception:
                    baseline_ms = 0.0

            # ── Unified pipeline: CheckRegistry (passive + active) ──
            if _CHECKS_AVAILABLE:
                await self._run_checks_layer(
                    task, resp, status_code, resp_text, error,
                    baseline_text, baseline_ms,
                )

        except asyncio.CancelledError:
            raise
        except Exception as exc:
            error = str(exc)
            logger.debug("Worker %d request error: %s", worker_id, exc)
            elapsed_ms_obs = 0.0

        # Persist (всегда, даже при ошибке запроса — как в старом движке)
        try:
            await asyncio.to_thread(
                _persist_task_result,
                task,
                worker_id,
                status_code,
                error,
                evidence,
                resp_text,
                raw_response_preview,
                elapsed_ms_obs,
                baseline_text,
                baseline_row,
                self.log_cb,
                detector=blind_detector,
                confidence=blind_confidence,
            )
        except asyncio.CancelledError:
            raise
        except Exception as exc:
            logger.exception("Worker %d DB write error: %s", worker_id, exc)

        return session_headers

    async def _run_checks_layer(
        self,
        task: ScanTask,
        resp: Optional[httpx.Response],
        status_code: Optional[int],
        resp_text: str,
        error: Optional[str],
        baseline_text: str,
        baseline_ms: float,
    ) -> None:
        """CheckRegistry в отдельном потоке (внутри — синхронные db-записи)."""

        def _call() -> None:
            elapsed = getattr(resp, "elapsed", None)
            elapsed_ms = (elapsed.total_seconds() * 1000.0) if elapsed else 0.0
            raw_req = templating.build_raw_http(
                task.method, task.url, task.headers, task.body
            )
            check_kwargs: dict = {
                "method": task.method,
                "url": task.url,
                "headers": task.headers,
                "body": task.body or b"",
                "raw_http": raw_req,
                "resp_status": status_code,
                "resp_headers": dict(resp.headers) if resp is not None else {},
                "resp_text": resp_text,
                "resp_elapsed_ms": elapsed_ms,
                "resp_error": error,
                "check_type": task.check_type,
                "payload": task.payload,
                "mutation_point": task.mutation_point,
                "original_param": task.original_param,
                "history_id": task.history_id,
                "registry": get_registry(),
                "log_cb": self.log_cb,
                "only_active": True,
            }
            # M5/FP: контракт run_checks_on_response с baseline-параметрами.
            if _RUN_CHECKS_HAS_BASELINE:
                check_kwargs["baseline_ms"] = baseline_ms
                check_kwargs["baseline_text"] = baseline_text
            run_checks_on_response(**check_kwargs)

        try:
            await asyncio.to_thread(_call)
        except asyncio.CancelledError:
            raise
        except Exception as check_exc:
            logger.debug("checks runner error: %s", check_exc)
