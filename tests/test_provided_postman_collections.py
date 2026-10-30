"""Тесты ровно на тех Postman-коллекциях, что отдавались пользователю.

Файлы в tests/fixtures/postman/ — копии:
  • no_env_collection.postman_collection.json — без переменных;
  • with_env_collection.postman_collection.json — требует env;
  • with_env.postman_environment.json — готовое окружение.
Проверяется парсинг/импорт/auth-extraction без сети (CI-safe).
"""

from pathlib import Path

import pytest

import collection_io

FIX = Path(__file__).resolve().parent / "fixtures" / "postman"
NO_ENV = FIX / "no_env_collection.postman_collection.json"
WITH_ENV = FIX / "with_env_collection.postman_collection.json"
ENV = FIX / "with_env.postman_environment.json"


def test_fixtures_exist():
    assert NO_ENV.exists() and WITH_ENV.exists() and ENV.exists()


def test_no_env_collection_needs_no_environment():
    assert collection_io.postman_missing_variables(NO_ENV) == []
    records = collection_io.import_collection(NO_ENV)
    assert len(records) == 4
    assert all("{{" not in r["url"] for r in records)
    assert all(r["url"].startswith("http://127.0.0.1:8081/") for r in records)


def test_with_env_collection_requires_environment():
    missing = collection_io.postman_missing_variables(WITH_ENV)
    assert set(missing) == {"baseUrl", "sessionCookie", "username", "password"}
    # searchTerm объявлен в самой коллекции — не missing
    assert "searchTerm" not in missing


def test_with_env_collection_imports_with_environment():
    env = collection_io.postman_environment(ENV)
    assert {"baseUrl", "username", "password", "sessionCookie"} <= set(env)
    assert collection_io.postman_missing_variables(WITH_ENV, environment=env) == []
    records = collection_io.import_collection(WITH_ENV, variables=env)
    assert len(records) == 4
    assert all("{{" not in r["url"] for r in records)
    assert any("/sqli_1.php" in r["url"] for r in records)


def test_with_env_collection_auth_headers_and_login_candidate():
    env = collection_io.postman_environment(ENV)
    auth = collection_io.postman_auth_headers(WITH_ENV, variables=env)
    assert "Cookie" in auth and auth["Cookie"]
    login = collection_io.postman_login_request(WITH_ENV, variables=env)
    assert login is not None
    assert login["url"].endswith("/login.php")
    assert login["body"].get("login") == env["username"]
    assert login["body"].get("password") == env["password"]
    assert login["otp_field"] is None


def test_no_env_collection_has_literal_credentials_but_no_auth_headers():
    # В коллекции есть login-формы с ЛИТЕРАЛЬНЫМИ креды (bee/bug) — это валидный
    # login-candidate для авто-логина, но готовых Cookie/Authorization нет.
    assert collection_io.postman_auth_headers(NO_ENV) == {}
    login = collection_io.postman_login_request(NO_ENV)
    assert login is not None
    assert login["body"].get("login") == "bee"
    assert login["body"].get("password") == "bug"
