"""Postman auth extraction: готовые Cookie/Authorization + login-candidate."""

import json
import tempfile
from pathlib import Path

import collection_io


def _write(tmp_path: Path, data: dict) -> Path:
    p = tmp_path / "c.json"
    p.write_text(json.dumps(data, ensure_ascii=False), encoding="utf-8")
    return p


def _request(method, url, headers=None, body=None, auth=None):
    req = {
        "method": method,
        "header": [{"key": k, "value": v} for k, v in (headers or {}).items()],
        "url": {"raw": url},
    }
    if body:
        req["body"] = body
    if auth:
        req["auth"] = auth
    return {"name": "r", "request": req}


def _collection(items, variables=None, auth=None):
    c = {"info": {"name": "auth-test"}, "item": items}
    if variables:
        c["variable"] = variables
    if auth:
        c["auth"] = auth
    return c


def test_auth_headers_from_cookie_and_bearer(tmp_path):
    coll = _collection([
        _request("GET", "{{baseUrl}}/portal.php", {"Cookie": "{{sessionCookie}}"}),
        _request("GET", "{{baseUrl}}/api", {"Authorization": "Bearer {{token}}"}),
    ], variables=[{"key": "baseUrl", "value": "http://lab.test"}])
    path = _write(tmp_path, coll)
    env = {"sessionCookie": "PHPSESSID=abc", "token": "jwt123"}
    auth = collection_io.postman_auth_headers(path, variables=env)
    assert auth["Cookie"] == "PHPSESSID=abc"
    assert auth["Authorization"] == "Bearer jwt123"


def test_auth_headers_from_env_only(tmp_path):
    coll = _collection([_request("GET", "http://lab.test/x")])
    path = _write(tmp_path, coll)
    auth = collection_io.postman_auth_headers(
        path, variables={"sessionCookie": "sid=1", "accessToken": "tok"}
    )
    assert auth["Cookie"] == "sid=1"
    assert auth["Authorization"] == "Bearer tok"


def test_auth_headers_from_basic_auth_block(tmp_path):
    coll = _collection([], variables=[{"key": "baseUrl", "value": "http://lab.test"}],
                       auth={"type": "basic", "basic": [
                           {"key": "username", "value": "bee"},
                           {"key": "password", "value": "bug"},
                       ]})
    # auth-блок коллекции применяется к запросам; без запросов auth пуст
    auth = collection_io.postman_auth_headers(_write(tmp_path, coll))
    assert auth == {}
    coll["item"] = [_request("GET", "http://lab.test/portal.php")]
    auth = collection_io.postman_auth_headers(_write(tmp_path, coll))
    assert auth["Authorization"].startswith("Basic ")


def test_login_request_candidate(tmp_path):
    coll = _collection([
        _request("GET", "http://lab.test/portal.php"),
        _request("POST", "{{baseUrl}}/login.php",
                 {"Content-Type": "application/x-www-form-urlencoded"},
                 body={"mode": "urlencoded", "urlencoded": [
                     {"key": "login", "value": "{{username}}"},
                     {"key": "password", "value": "{{password}}"},
                     {"key": "security_level", "value": "0"},
                 ]}),
    ], variables=[{"key": "baseUrl", "value": "http://lab.test"}])
    path = _write(tmp_path, coll)
    cand = collection_io.postman_login_request(
        path, variables={"username": "bee", "password": "bug"}
    )
    assert cand is not None
    assert cand["url"] == "http://lab.test/login.php"
    assert cand["content_type"] == "form"
    assert cand["body"]["login"] == "bee"
    assert cand["body"]["password"] == "bug"
    assert cand["otp_field"] is None


def test_login_request_with_otp_field(tmp_path):
    coll = _collection([
        _request("POST", "http://lab.test/login",
                 body={"mode": "raw", "raw": json.dumps({
                     "username": "{{user}}", "password": "{{pass}}", "otp": "{{otp}}"
                 })},
                 headers={"Content-Type": "application/json"}),
    ])
    path = _write(tmp_path, coll)
    cand = collection_io.postman_login_request(path, variables={
        "user": "bee", "pass": "bug", "otp": "000000"
    })
    assert cand["content_type"] == "json"
    assert cand["body"]["otp"] == "000000"
    assert cand["otp_field"] == "otp"


def test_no_login_candidate_for_plain_collection(tmp_path):
    coll = _collection([_request("GET", "http://lab.test/login.php")])
    path = _write(tmp_path, coll)
    assert collection_io.postman_login_request(path) is None
