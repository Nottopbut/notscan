"""
checks/registry.py — Реестр и загрузчик чеков уязвимостей.

CheckRegistry хранит все доступные чеки и позволяет:
  • получить список активных чеков по категориям/типам
  • включать/выключать отдельные чеки
  • запускать чеки против (request, response, context)
  • динамически добавлять пользовательские чеки
"""

from __future__ import annotations

import logging
from typing import Callable, Optional, Type

from .base import (
    BaseCheck, CheckContext, CheckResult, Finding,
    ScanRequest, ScanResponse, VulnCategory,
)
from .injections import ALL_INJECTION_CHECKS
from .client_side import ALL_CLIENT_CHECKS
from .other import ALL_OTHER_CHECKS
from .passive_extra import ALL_EXTRA_PASSIVE_CHECKS

logger = logging.getLogger(__name__)


# ══════════════════════════════════════════════════════════════════
#  CheckRegistry
# ══════════════════════════════════════════════════════════════════

class CheckRegistry:
    """
    Центральный реестр всех чеков.

    Использование:
        registry = CheckRegistry()
        registry.disable("csrf")       # отключить конкретный чек
        findings = registry.run_all(request, response, context)
    """

    def __init__(self):
        self._checks: dict[str, BaseCheck] = {}
        self._load_defaults()

    # ── Регистрация ──────────────────────────────────────────────

    def register(self, check_cls: Type[BaseCheck]) -> None:
        """Зарегистрировать чек по классу."""
        instance = check_cls()
        self._checks[instance.check_id] = instance
        logger.debug("Registered check: %s", instance.check_id)

    def register_instance(self, instance: BaseCheck) -> None:
        """Зарегистрировать готовый экземпляр чека."""
        self._checks[instance.check_id] = instance

    def unregister(self, check_id: str) -> None:
        self._checks.pop(check_id, None)

    def _load_defaults(self) -> None:
        for cls in ALL_INJECTION_CHECKS:
            self.register(cls)
        for cls in ALL_CLIENT_CHECKS:
            self.register(cls)
        for cls in ALL_OTHER_CHECKS:
            self.register(cls)
        for cls in ALL_EXTRA_PASSIVE_CHECKS:
            self.register(cls)

    # ── Управление состоянием ─────────────────────────────────────

    def enable(self, check_id: str) -> bool:
        if check_id in self._checks:
            self._checks[check_id].enabled = True
            return True
        return False

    def disable(self, check_id: str) -> bool:
        if check_id in self._checks:
            self._checks[check_id].enabled = False
            return True
        return False

    def enable_all(self) -> None:
        for c in self._checks.values():
            c.enabled = True

    def disable_all(self) -> None:
        for c in self._checks.values():
            c.enabled = False

    def set_enabled_by_vuln_type(self, vuln_type: str, enabled: bool) -> int:
        """Включить/выключить все чеки заданного vuln_type. Возвращает количество."""
        count = 0
        for c in self._checks.values():
            if c.vuln_type == vuln_type:
                c.enabled = enabled
                count += 1
        return count

    def set_enabled_by_category(self, category: VulnCategory, enabled: bool) -> int:
        count = 0
        for c in self._checks.values():
            if c.category == category:
                c.enabled = enabled
                count += 1
        return count

    # ── Запрос чеков ────────────────────────────────────────────

    def get(self, check_id: str) -> Optional[BaseCheck]:
        return self._checks.get(check_id)

    def all_checks(self) -> list[BaseCheck]:
        return list(self._checks.values())

    def enabled_checks(self) -> list[BaseCheck]:
        return [c for c in self._checks.values() if c.enabled]

    def active_checks(self, requires_payload: Optional[bool] = None) -> list[BaseCheck]:
        """
        Возвращает включённые чеки.
        requires_payload=True  → только активные (с payload)
        requires_payload=False → только пассивные
        requires_payload=None  → все
        """
        checks = self.enabled_checks()
        if requires_payload is None:
            return checks
        return [c for c in checks if c.requires_payload is requires_payload]

    def checks_for_type(self, vuln_type: str) -> list[BaseCheck]:
        return [c for c in self._checks.values() if c.vuln_type == vuln_type]

    # ── Выполнение ───────────────────────────────────────────────

    def run_all(
        self,
        request: ScanRequest,
        response: ScanResponse,
        context: CheckContext,
        only_passive: bool = False,
        only_active: bool = False,
        match_check_type: Optional[str] = None,
    ) -> list[Finding]:
        """
        Запускает все включённые чеки и собирает находки.

        only_passive=True — только пассивные (не требуют payload)
        only_active=True  — только активные (требуют payload)
        """
        all_findings: list[Finding] = []

        for check in self.enabled_checks():
            if only_passive and not check.passive:
                continue
            if only_active and check.passive:
                continue
            if match_check_type and check.check_id != match_check_type and check.vuln_type != match_check_type:
                continue

            try:
                result: CheckResult = check.check(request, response, context)
                if result.findings:
                    all_findings.extend(result.findings)
                if result.error:
                    logger.warning("Check %s error: %s", check.check_id, result.error)
            except Exception as exc:
                logger.exception("Check %s raised exception: %s", check.check_id, exc)

        return all_findings

    def run_passive(
        self,
        request: ScanRequest,
        response: ScanResponse,
        context: CheckContext,
    ) -> list[Finding]:
        """Запускает только пассивные чеки (без payload)."""
        return self.run_all(request, response, context, only_passive=True)

    # ── Сводка ───────────────────────────────────────────────────

    def summary(self) -> dict:
        total = len(self._checks)
        enabled = sum(1 for c in self._checks.values() if c.enabled)
        by_cat = {}
        for c in self._checks.values():
            cat = c.category.value
            by_cat.setdefault(cat, {"total": 0, "enabled": 0})
            by_cat[cat]["total"] += 1
            if c.enabled:
                by_cat[cat]["enabled"] += 1
        return {
            "total": total,
            "enabled": enabled,
            "disabled": total - enabled,
            "by_category": by_cat,
        }

    def __repr__(self) -> str:
        s = self.summary()
        return f"<CheckRegistry total={s['total']} enabled={s['enabled']}>"


# ══════════════════════════════════════════════════════════════════
#  Глобальный синглтон реестра
# ══════════════════════════════════════════════════════════════════

_default_registry: Optional[CheckRegistry] = None


def get_registry() -> CheckRegistry:
    global _default_registry
    if _default_registry is None:
        _default_registry = CheckRegistry()
    return _default_registry


def reset_registry() -> CheckRegistry:
    global _default_registry
    _default_registry = CheckRegistry()
    return _default_registry
