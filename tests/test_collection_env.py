"""Postman: импорт коллекций с окружением/переменными.

Покрывает:
  • collection-variables (data.variable) и их подстановку в url/headers/body;
  • чтение Postman environment/globals (values/enabled/disabled, плоский dict);
  • postman_missing_variables — предупреждение GUI «нужен env-файл»;
  • import_collection(..., variables=...) — импорт с подстановкой окружения;
  • негатив: коллекция без переменных не требует окружения.
"""

import json
import tempfile
from pathlib import Path

import collection_io


def _write(tmp_path: Path, name: str, data: dict) -> Path:
    p = tmp_path / name
    p.write_text(json.dumps(data, ensure_ascii=False), encoding="utf-8")
    return p


def _collection(requests: list[dict], variables: list | None = None) -> dict:
    items = []
    for req in requests:
        headers = [{"key": k, "value": v} for k, v in (req.get("headers") or {}).items()]
        body = req.get("body")
        item = {
            "name": req.get("name", "req"),
            "request": {
                "method": req.get("method", "GET"),
                "header": headers,
                "url": {"raw": req["url"]},
            },
        }
        if body is not None:
            item["request"]["body"] = body
        items.append(item)
    coll = {
        "info": {"name": "test", "schema": "https://schema.getpostman.com/json/collection/v2.1.0/collection.json"},
        "item": items,
    }
    if variables:
        coll["variable"] = variables
    return coll


def test_collection_variables_resolved(tmp_path):
    coll = _collection(
        [
            {"url": "{{baseUrl}}/api/users?id=1", "headers": {"X-Token": "{{token}}"}},
        ],
        variables=[
            {"key": "baseUrl", "value": "http://target.test"},
            {"key": "token", "value": "secret"},
        ],
    )
    path = _write(tmp_path, "c.json", coll)
    assert collection_io.postman_missing_variables(path) == []
    records = collection_io.import_collection(path)
    assert records[0]["url"] == "http://target.test/api/users?id=1"
    assert records[0]["headers"]["X-Token"] == "secret"


def test_missing_environment_detected(tmp_path):
    coll = _collection([
        {"url": "{{baseUrl}}/login", "headers": {"Cookie": "{{sessionCookie}}"}},
    ])
    path = _write(tmp_path, "c.json", coll)
    assert collection_io.postman_missing_variables(path) == ["baseUrl", "sessionCookie"]
    # окружение как dict снимает missing
    env = {"baseUrl": "http://127.0.0.1:8081", "sessionCookie": "PHPSESSID=abc"}
    assert collection_io.postman_missing_variables(path, environment=env) == []
    records = collection_io.import_collection(path, variables=env)
    assert records[0]["url"] == "http://127.0.0.1:8081/login"
    assert records[0]["headers"]["Cookie"] == "PHPSESSID=abc"


def test_postman_environment_formats(tmp_path):
    p1 = _write(tmp_path, "env.json", {
        "values": [
            {"key": "baseUrl", "value": "http://a.test", "enabled": True},
            {"key": "disabledVar", "value": "x", "enabled": False},
            {"key": "num", "value": 42},
        ]
    })
    env = collection_io.postman_environment(p1)
    assert env["baseUrl"] == "http://a.test"
    assert env["num"] == "42"
    assert "disabledVar" not in env

    p2 = _write(tmp_path, "flat.json", {"baseUrl": "http://flat.test", "user": "bee"})
    assert collection_io.postman_environment(p2) == {
        "baseUrl": "http://flat.test", "user": "bee"
    }


def test_nested_variable_resolution(tmp_path):
    coll = _collection([{"url": "{{baseUrl}}/x"}], variables=[
        {"key": "host", "value": "target.test"},
        {"key": "baseUrl", "value": "http://{{host}}"},
    ])
    path = _write(tmp_path, "c.json", coll)
    recs = collection_io.import_collection(path)
    assert recs[0]["url"] == "http://target.test/x"


def test_no_variables_means_no_env_required(tmp_path):
    coll = _collection([{"url": "http://127.0.0.1:8081/login.php"}])
    path = _write(tmp_path, "plain.json", coll)
    assert collection_io.postman_missing_variables(path) == []


def test_import_without_env_keeps_placeholders(tmp_path):
    coll = _collection([{"url": "{{baseUrl}}/login"}])
    path = _write(tmp_path, "c.json", coll)
    recs = collection_io.import_collection(path)
    assert recs[0]["url"] == "{{baseUrl}}/login"


def test_body_and_header_variables_resolved(tmp_path):
    coll = _collection([{
        "url": "{{baseUrl}}/login",
        "headers": {"Content-Type": "application/x-www-form-urlencoded"},
        "body": {"mode": "raw", "raw": "login={{user}}&password={{pass}}"},
    }])
    path = _write(tmp_path, "c.json", coll)
    env = {"baseUrl": "http://lab.test", "user": "bee", "pass": "bug"}
    recs = collection_io.import_collection(path, variables=env)
    assert recs[0]["body"] == b"login=bee&password=bug"
