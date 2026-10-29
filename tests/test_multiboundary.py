"""
tests/test_multiboundary.py — multi-boundary mutations.

Сканер умеет мутировать query / body_form / body_json / header / body_raw.
Здесь — новые «границы» запроса:
  • cookie-значения   → mutation_point="cookie:<name>", original_param=<name>;
  • path-сегменты URL → mutation_point="path", original_param="path[<i>]"
    (статика .css/.js/.png/… пропускается, query/fragment сохраняются);
  • текстовые поля multipart/form-data → mutation_point="body_multipart",
    original_param=<имя поля> (файловые части не трогаем, boundary сохраняется).

Покрыты positive/negative templating-кейсы, apply_payload для новых точек и
build_scan_tasks (временная БД), включая negative для XXE на multipart.
"""

from __future__ import annotations

import tempfile
import urllib.parse
from pathlib import Path

import pytest

import db
import scanner_core
import templating

SQLI_PAYLOAD = "' OR 1=1--"
DESER_PAYLOAD = 'O:8:"stdClass":1:{s:1:"a";s:1:"b";}'
XXE_PAYLOAD = "<!DOCTYPE r [<!ENTITY e SYSTEM 'file:///etc/passwd'>]><r>&e;</r>"
BOUNDARY = "----notscanBoundary42"


@pytest.fixture()
def tmp_db(tmp_path: Path):
    db_path = tmp_path / "multiboundary-test.db"
    db.set_db_path(db_path)
    yield db_path
    db.set_db_path(tmp_path / "multiboundary-closed.db")
    for suffix in ("", "-wal", "-shm"):
        try:
            Path(str(db_path) + suffix).unlink(missing_ok=True)
        except OSError:
            pass


def _fake_load_payloads(mapping: dict[str, list[str]]):
    def _load(check_type: str, safe_mode: bool = True):  # noqa: ARG001
        return list(mapping.get(str(check_type or "").lower(), []))

    return _load


def _insert_history(
    method: str,
    url: str,
    *,
    headers: dict | None = None,
    body: bytes | None = None,
) -> int:
    return db.insert_history(method, url, headers or {}, body, 200, {}, b"baseline")


def _req(
    url: str,
    headers: dict | None = None,
    body: bytes = b"",
    method: str = "GET",
) -> templating.ParsedRequest:
    return templating.ParsedRequest(
        method=method,
        url=url,
        http_version="HTTP/1.1",
        headers=headers or {},
        body=body,
    )


def _multipart_body(
    fields: list[tuple[str, str]],
    *,
    file_field: tuple[str, str, bytes] | None = None,
    line_end: bytes = b"\r\n",
) -> bytes:
    chunks: list[bytes] = []
    for name, value in fields:
        chunks.append(
            b"--" + BOUNDARY.encode()
            + line_end
            + f'Content-Disposition: form-data; name="{name}"'.encode()
            + line_end + line_end
            + value.encode()
            + line_end
        )
    if file_field is not None:
        name, filename, content = file_field
        chunks.append(
            b"--" + BOUNDARY.encode()
            + line_end
            + f'Content-Disposition: form-data; name="{name}"; filename="{filename}"'.encode()
            + line_end
            + b"Content-Type: application/octet-stream"
            + line_end + line_end
            + content
            + line_end
        )
    chunks.append(b"--" + BOUNDARY.encode() + b"--" + line_end)
    return b"".join(chunks)


# ══════════════════════════════════════════════════════════════════
#  1. Cookies
# ══════════════════════════════════════════════════════════════════

class TestMutateCookies:
    def test_two_cookies_one_mutation_each(self):
        req = _req("http://example.test/profile", {"Cookie": "theme=dark; session=abc123"})
        mutations = templating.mutate_cookies(req)
        assert len(mutations) == 2
        assert [m.mutation_point for m in mutations] == ["cookie:theme", "cookie:session"]
        assert [m.original_param for m in mutations] == ["theme", "session"]
        # каждая мутация меняет ТОЛЬКО свою cookie
        assert mutations[0].headers["Cookie"] == "theme={{payload}}; session=abc123"
        assert mutations[1].headers["Cookie"] == "theme=dark; session={{payload}}"
        assert templating.PLACEHOLDER in mutations[0].raw_http

    def test_apply_payload_cookie_plain(self):
        req = _req("http://example.test/", {"Cookie": "a=1; b=2"})
        mutation = templating.mutate_cookies(req)[0]
        _url, headers, _body = templating.apply_payload(mutation, "x'y\"<z>")
        assert headers["Cookie"] == "a=x'y\"<z>; b=2"  # plain substitution, no URL-encode

    def test_no_cookie_or_empty(self):
        assert templating.mutate_cookies(_req("http://example.test/")) == []
        assert templating.mutate_cookies(_req("http://example.test/", {"Cookie": "   "})) == []
        assert templating.mutate_cookies(
            _req("http://example.test/", {"Cookie": ";; ;"})
        ) == []

    def test_do_cookies_false(self):
        req = _req("http://example.test/", {"Cookie": "a=1"})
        mutations = templating.get_mutations(req, do_cookies=False)
        assert all(m.mutation_point != "cookie:a" for m in mutations)


# ══════════════════════════════════════════════════════════════════
#  2. Path segments
# ══════════════════════════════════════════════════════════════════

class TestMutatePath:
    def test_api_segments_mutations(self):
        req = _req("http://example.test/api/v1/users/123?q=1#frag")
        mutations = templating.mutate_path(req)
        assert len(mutations) == 4, [m.url for m in mutations]
        assert [m.original_param for m in mutations] == [
            "path[0]", "path[1]", "path[2]", "path[3]",
        ]
        expected_paths = [
            "/{{payload}}/v1/users/123",
            "/api/{{payload}}/users/123",
            "/api/v1/{{payload}}/123",
            "/api/v1/users/{{payload}}",
        ]
        for mutation, expected_path in zip(mutations, expected_paths):
            assert mutation.mutation_point == "path"
            assert expected_path in mutation.url
            # query/fragment сохранены
            assert mutation.url.endswith("?q=1#frag")
            assert templating.PLACEHOLDER in mutation.raw_http

    def test_apply_payload_url_encodes_path(self):
        req = _req("http://example.test/api/v1/users/123")
        mutation = templating.mutate_path(req)[3]
        url, _headers, _body = templating.apply_payload(mutation, "../etc/passwd")
        assert "../etc/passwd" not in url
        assert "..%2Fetc%2Fpasswd" in url
        # структура URL не сломана: ровно 4 сегмента
        from urllib.parse import urlsplit

        assert urlsplit(url).path.count("/") == 4

    def test_static_and_empty_paths_skipped(self):
        assert templating.mutate_path(_req("http://example.test/static/app.css")) == []
        assert templating.mutate_path(_req("http://example.test/assets/logo.png")) == []
        assert templating.mutate_path(_req("http://example.test/app.js.map")) == []
        assert templating.mutate_path(_req("http://example.test/")) == []
        assert templating.mutate_path(_req("http://example.test")) == []
        assert templating.mutate_path(_req("http://example.test///")) == []

    def test_do_path_false(self):
        req = _req("http://example.test/api/v1")
        mutations = templating.get_mutations(req, do_path=False)
        assert all(m.mutation_point != "path" for m in mutations)


# ══════════════════════════════════════════════════════════════════
#  3. multipart/form-data
# ══════════════════════════════════════════════════════════════════

class TestMutateBodyMultipart:
    def _req_multipart(self, body: bytes, boundary: str = BOUNDARY) -> templating.ParsedRequest:
        return _req(
            "http://example.test/upload",
            {"Content-Type": f"multipart/form-data; boundary={boundary}"},
            body,
            method="POST",
        )

    def test_text_fields_only_file_untouched(self):
        body = _multipart_body(
            [("username", "alice"), ("note", "hello")],
            file_field=("avatar", "a.png", b"BINARY-PNG-DATA"),
        )
        req = self._req_multipart(body)
        mutations = templating.mutate_body_multipart(req)
        assert len(mutations) == 2, "файловая часть не должна мутироваться"
        assert [m.mutation_point for m in mutations] == ["body_multipart"] * 2
        assert [m.original_param for m in mutations] == ["username", "note"]

        for mutation, field_name in zip(mutations, ("username", "note")):
            new_body = mutation.body
            # boundary/структура и файл сохранены побайтово
            assert new_body.count(b"--" + BOUNDARY.encode()) == 4  # 3 parts + close
            assert new_body.endswith(b"--" + BOUNDARY.encode() + b"--\r\n")
            assert b'filename="a.png"' in new_body
            assert b"BINARY-PNG-DATA" in new_body
            # placeholder только в целевом поле: значение целевого поля заменено,
            # значение второго текстового поля не тронуто
            head, _sep, rest = new_body.partition(f'name="{field_name}"'.encode())
            assert templating.PLACEHOLDER.encode() in rest
            if field_name == "username":
                assert b"alice" not in new_body and b"hello" in new_body
            else:
                assert b"hello" not in new_body and b"alice" in new_body

    def test_apply_payload_multipart_plain(self):
        body = _multipart_body([("username", "alice")])
        mutation = templating.mutate_body_multipart(self._req_multipart(body))[0]
        _url, _headers, new_body = templating.apply_payload(mutation, "bob<&>")
        assert b'name="username"' in new_body
        assert b"bob<&>" in new_body  # plain, не JSON/url-escape
        assert b"--" + BOUNDARY.encode() + b"--" in new_body

    def test_lf_only_multipart(self):
        body = _multipart_body([("username", "alice")], line_end=b"\n")
        req = self._req_multipart(body)
        mutations = templating.mutate_body_multipart(req)
        assert len(mutations) == 1
        new_body = mutations[0].body
        assert new_body.endswith(b"--" + BOUNDARY.encode() + b"--\n")

    def test_quoted_boundary(self):
        body = _multipart_body([("a", "1")])
        req = _req(
            "http://example.test/upload",
            {"Content-Type": f'multipart/form-data; boundary="{BOUNDARY}"'},
            body,
            method="POST",
        )
        assert len(templating.mutate_body_multipart(req)) == 1

    def test_negative_cases(self):
        # не multipart
        assert templating.mutate_body_multipart(
            _req("http://example.test/", {"Content-Type": "application/json"}, b"{}", "POST")
        ) == []
        # multipart без boundary
        assert templating.mutate_body_multipart(
            _req("http://example.test/", {"Content-Type": "multipart/form-data"}, b"x", "POST")
        ) == []
        # пустое тело
        assert templating.mutate_body_multipart(
            _req("http://example.test/",
                 {"Content-Type": f"multipart/form-data; boundary={BOUNDARY}"},
                 b"", "POST")
        ) == []
        # только файл — текстовых полей нет
        body = _multipart_body([], file_field=("f", "a.bin", b"DATA"))
        assert templating.mutate_body_multipart(self._req_multipart(body)) == []

    def test_multipart_not_parsed_as_form(self):
        """multipart-тело не должно давать мусорных body_form-мутаций."""
        body = _multipart_body([("username", "alice")])
        points = [m.mutation_point for m in templating.get_mutations(self._req_multipart(body))]
        assert "body_form" not in points

    def test_do_body_multipart_false(self):
        body = _multipart_body([("a", "1")])
        mutations = templating.get_mutations(
            self._req_multipart(body), do_body_multipart=False
        )
        assert all(m.mutation_point != "body_multipart" for m in mutations)


# ══════════════════════════════════════════════════════════════════
#  4. get_mutations: новые параметры / обратная совместимость
# ══════════════════════════════════════════════════════════════════

class TestGetMutationsCompat:
    def test_new_points_included_by_default(self):
        req = _req("http://example.test/api/users", {"Cookie": "sid=1"}, b"", "GET")
        points = {m.mutation_point for m in templating.get_mutations(req)}
        assert "path" in points
        assert "cookie:sid" in points

    def test_old_positional_call_still_works(self):
        # старый вызов: 5 позиционных флагов (query/form/json/headers)
        req = _req(
            "http://example.test/form",
            {"Content-Type": "application/x-www-form-urlencoded"},
            b"a=1&b=2",
            "POST",
        )
        mutations = templating.get_mutations(req, True, True, True, False)
        assert any(m.mutation_point == "body_form" for m in mutations)

    def test_all_new_points_can_be_disabled(self):
        req = _req("http://example.test/api/users", {"Cookie": "sid=1"}, b"", "GET")
        mutations = templating.get_mutations(
            req, do_cookies=False, do_path=False, do_body_multipart=False
        )
        assert mutations == []


# ══════════════════════════════════════════════════════════════════
#  5. build_scan_tasks на временной БД
# ══════════════════════════════════════════════════════════════════

class TestBuildScanTasksMultiboundary:
    def test_sqli_cookie_and_path_tasks(self, tmp_db, monkeypatch):
        monkeypatch.setattr(
            scanner_core, "load_payloads",
            _fake_load_payloads({"sqli": [SQLI_PAYLOAD]}),
        )
        hid = _insert_history(
            "GET",
            "http://example.test/api/v1/users/123?q=1",
            headers={"Cookie": "theme=dark; session=abc123"},
        )
        tasks = scanner_core.build_scan_tasks([hid], ["sqli"])
        points = {t.mutation_point for t in tasks}
        assert {"query", "cookie:theme", "cookie:session", "path"} <= points

        cookie_sessions = [t for t in tasks if t.original_param == "session"]
        assert cookie_sessions
        assert "session=" + SQLI_PAYLOAD in cookie_sessions[0].headers["Cookie"]
        assert "theme=dark" in cookie_sessions[0].headers["Cookie"]  # чужая cookie цела

        path_tasks = [t for t in tasks if t.mutation_point == "path"]
        assert path_tasks
        assert all(t.original_param.startswith("path[") for t in path_tasks)
        encoded = urllib.parse.quote(SQLI_PAYLOAD, safe="")
        assert any(encoded in t.url for t in path_tasks)

    def test_path_mutations_preserve_query(self, tmp_db, monkeypatch):
        monkeypatch.setattr(
            scanner_core, "load_payloads",
            _fake_load_payloads({"cmdi": [";id"]}),
        )
        hid = _insert_history("GET", "http://example.test/api/items?x=1")
        tasks = [t for t in scanner_core.build_scan_tasks([hid], ["cmdi"])
                 if t.mutation_point == "path"]
        assert tasks
        assert all("?x=1" in t.url for t in tasks)

    def test_deserialization_multipart_task(self, tmp_db, monkeypatch):
        monkeypatch.setattr(
            scanner_core, "load_payloads",
            _fake_load_payloads({"deserialization": [DESER_PAYLOAD]}),
        )
        body = _multipart_body(
            [("username", "alice")],
            file_field=("avatar", "a.png", b"BINARY"),
        )
        hid = _insert_history(
            "POST", "http://example.test/upload",
            headers={"Content-Type": f"multipart/form-data; boundary={BOUNDARY}"},
            body=body,
        )
        tasks = scanner_core.build_scan_tasks([hid], ["deserialization"])
        mp_tasks = [t for t in tasks if t.mutation_point == "body_multipart"]
        assert len(mp_tasks) == 1
        task = mp_tasks[0]
        assert task.original_param == "username"
        assert task.payload == DESER_PAYLOAD
        assert DESER_PAYLOAD.encode() in task.body
        assert b"BINARY" in task.body  # файл не тронут

    def test_xxe_not_allowed_on_multipart(self, tmp_db, monkeypatch):
        monkeypatch.setattr(
            scanner_core, "load_payloads",
            _fake_load_payloads({"xxe": [XXE_PAYLOAD]}),
        )
        body = _multipart_body([("data", "1")])
        hid = _insert_history(
            "POST", "http://example.test/upload",
            headers={"Content-Type": f"multipart/form-data; boundary={BOUNDARY}"},
            body=body,
        )
        assert scanner_core.build_scan_tasks([hid], ["xxe"]) == []

    def test_new_kwargs_disable_points(self, tmp_db, monkeypatch):
        monkeypatch.setattr(
            scanner_core, "load_payloads",
            _fake_load_payloads({"sqli": [SQLI_PAYLOAD]}),
        )
        hid = _insert_history(
            "GET", "http://example.test/api/v1?q=1",
            headers={"Cookie": "session=abc"},
        )
        tasks = scanner_core.build_scan_tasks(
            [hid], ["sqli"], do_cookies=False, do_path=False
        )
        assert {t.mutation_point for t in tasks} == {"query"}

    def test_only_params_works_for_cookie_and_multipart(self, tmp_db, monkeypatch):
        monkeypatch.setattr(
            scanner_core, "load_payloads",
            _fake_load_payloads({"sqli": [SQLI_PAYLOAD]}),
        )
        hid = _insert_history(
            "GET", "http://example.test/api?q=1",
            headers={"Cookie": "Session=abc"},
        )
        tasks = scanner_core.build_scan_tasks(
            [hid], ["sqli"], only_params=["session", "Q"]
        )
        assert {t.original_param for t in tasks} == {"Session", "q"}
