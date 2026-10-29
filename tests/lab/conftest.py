"""Регистрация pytest-маркеров лабы (см. )."""

from __future__ import annotations


def pytest_configure(config):  # noqa: ANN001
    config.addinivalue_line(
        "markers",
        "integration: интеграционные тесты локальной HTTP-лабы (быстрые)",
    )
