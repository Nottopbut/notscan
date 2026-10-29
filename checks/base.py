"""
checks/base.py — Базовый интерфейс системы чеков уязвимостей.

Каждый тип уязвимости реализует BaseCheck.
Единый вызов: check(request, response, context) → list[Finding]

Finding содержит всё необходимое для:
  • отображения в GUI
  • сохранения в БД (scan_results)
  • интерактивного предложения reverse shell
"""

from __future__ import annotations

import time
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Optional


# ══════════════════════════════════════════════════════════════════
#  Enumerations
# ══════════════════════════════════════════════════════════════════

class Severity(str, Enum):
    """CVSS-подобная шкала серьёзности."""
    CRITICAL  = "CRITICAL"
    HIGH      = "HIGH"
    MEDIUM    = "MEDIUM"
    LOW       = "LOW"
    INFO      = "INFO"


class VulnCategory(str, Enum):
    """Категория уязвимости для группировки в GUI и отчёте."""
    INJECTION_SERVER  = "injection_server"   # SQLi, CMDi, SSTI, XXE, …
    INJECTION_CLIENT  = "injection_client"   # XSS, CSRF, Open Redirect, …
    AUTH              = "auth"               # Auth bypass, IDOR, session
    CRYPTO            = "crypto"             # Weak TLS, cleartext, …
    MISCONFIG         = "misconfig"          # Security headers, Clickjacking, …
    INFO_DISCLOSURE   = "info_disclosure"    # Secrets in JS, stack traces, …
    BUSINESS_LOGIC    = "business_logic"     # IDOR, price manipulation, …
    FILE              = "file"               # File upload, path traversal, LFI/RFI
    SSRF              = "ssrf"
    DESERIALIZATION   = "deserialization"
    OTHER             = "other"


# RCE-подобные типы уязвимостей (триггеры для предложения reverse shell)
RCE_VULN_TYPES = frozenset({
    "cmdi", "ssti", "deserialization", "xxe_ssrf", "rce",
    "file_upload_exec", "path_traversal_exec",
})


# ══════════════════════════════════════════════════════════════════
#  Data structures
# ══════════════════════════════════════════════════════════════════

@dataclass
class CheckContext:
    """
    Контекст, передаваемый каждому чеку.
    Может расширяться без изменения интерфейса check().
    """
    history_id: Optional[int] = None          # ID из таблицы history
    scan_result_id: Optional[int] = None      # ID из scan_results (после записи)
    mutation_point: str = ""                  # "query" | "body_form" | …
    original_param: str = ""                  # имя параметра
    payload: str = ""                         # применённый payload
    check_type: str = ""                      # id текущего чека
    # Baseline-метрики хоста (передаёт движок; 0.0/"" = неизвестно):
    baseline_ms: float = 0.0                  # p50 латентности хоста до скана
    baseline_text: str = ""                   # тело baseline-ответа для FP-suppress
    extra: dict[str, Any] = field(default_factory=dict)


@dataclass
class ScanRequest:
    """Упрощённое представление HTTP-запроса, передаваемое в check()."""
    method: str
    url: str
    headers: dict[str, str]
    body: bytes
    raw_http: str = ""


@dataclass
class ScanResponse:
    """Упрощённое представление HTTP-ответа."""
    status_code: int
    headers: dict[str, str]
    text: str                                 # тело (первые N KB)
    elapsed_ms: float = 0.0
    error: Optional[str] = None


@dataclass
class Finding:
    """
    Одна найденная уязвимость.

    Пишется в scan_results и отображается в GUI.
    """
    vuln_type: str                            # "sqli", "cmdi", "xss", …
    category: VulnCategory
    severity: Severity
    title: str
    evidence: str                             # что именно указывает на уязвимость
    url: str
    method: str
    param: str = ""
    payload: str = ""
    mutation_point: str = ""
    recommendation: str = ""
    cwe: str = ""                             # e.g. "CWE-89"
    wstg_id: str = ""                         # e.g. "WSTG-INPV-05"
    cvss_score: Optional[float] = None
    raw_request: str = ""
    raw_response_preview: str = ""
    timestamp: float = field(default_factory=time.time)
    extra: dict[str, Any] = field(default_factory=dict)

    @property
    def is_rce_like(self) -> bool:
        """True — стоит предложить reverse shell."""
        return self.vuln_type.lower() in RCE_VULN_TYPES


@dataclass
class CheckResult:
    """Возвращается из BaseCheck.check()."""
    findings: list[Finding] = field(default_factory=list)
    checked: bool = True                      # False если чек пропущен (disabled/N/A)
    error: Optional[str] = None


# ══════════════════════════════════════════════════════════════════
#  BaseCheck
# ══════════════════════════════════════════════════════════════════

class BaseCheck(ABC):
    """
    Абстрактный базовый класс для всех чеков уязвимостей.

    Минимальный контракт:
        check_id   : str   — уникальный идентификатор (e.g. "sqli")
        vuln_type  : str   — тип (e.g. "sqli")
        category   : VulnCategory
        severity   : Severity
        name       : str   — человекочитаемое название
        enabled    : bool  — можно выключить в GUI

    Каждый чек ДОЛЖЕН реализовать check().
    """

    # ── Обязательные атрибуты класса ─────────────────────────────
    check_id: str   = "base"
    vuln_type: str  = "unknown"
    category: VulnCategory = VulnCategory.OTHER
    severity: Severity = Severity.MEDIUM
    name: str       = "Base Check"
    description: str = ""
    cwe: str        = ""
    enabled: bool   = True

    # ── Настройки поведения ───────────────────────────────────────
    requires_payload: bool = True   # False для пассивных чеков (CSRF, headers)
    passive: bool = False           # True — не отправляет доп. запросов

    @abstractmethod
    def check(
        self,
        request: ScanRequest,
        response: ScanResponse,
        context: CheckContext,
    ) -> CheckResult:
        """
        Анализирует request+response, возвращает CheckResult.

        Активный чек может отправлять доп. запросы через self.session.
        Пассивный — работает только с переданными request/response.
        """

    # ── Вспомогательные методы ────────────────────────────────────

    def make_finding(
        self,
        evidence: str,
        request: ScanRequest,
        response: ScanResponse,
        context: CheckContext,
        **kwargs,
    ) -> Finding:
        """Фабричный метод для создания Finding с заполненными полями."""
        return Finding(
            vuln_type=kwargs.get("vuln_type", self.vuln_type),
            category=kwargs.get("category", self.category),
            severity=kwargs.get("severity", self.severity),
            title=kwargs.get("title", self.name),
            evidence=evidence,
            url=request.url,
            method=request.method,
            param=context.original_param,
            payload=context.payload,
            mutation_point=context.mutation_point,
            recommendation=kwargs.get("recommendation", ""),
            cwe=kwargs.get("cwe", self.cwe),
            raw_request=request.raw_http,
            raw_response_preview=response.text[:4096],
            extra=kwargs.get("extra", {}),
        )

    def skip(self) -> CheckResult:
        """Вернуть результат «чек пропущен»."""
        return CheckResult(findings=[], checked=False)

    def ok(self) -> CheckResult:
        """Вернуть результат «проверено, уязвимостей нет»."""
        return CheckResult(findings=[], checked=True)

    def found(self, *findings: Finding) -> CheckResult:
        """Вернуть результат с находками."""
        return CheckResult(findings=list(findings), checked=True)

    def __repr__(self) -> str:
        state = "ON" if self.enabled else "OFF"
        return f"<{self.__class__.__name__} id={self.check_id} [{state}]>"
