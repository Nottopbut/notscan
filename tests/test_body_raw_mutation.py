"""
tests/test_body_raw_mutation.py — raw/XML mutation (`body_raw`).

Фича: XXE и deserialization реально работают, потому что их payload'ы — это
ЦЕЛЫЕ документы/объекты, а не значения query/form/json параметров.

Покрывает:
  • templating.mutate_body_raw / get_mutations(do_body_raw=...):
    XML/SOAP/PHP-serialized/сырые тела → одна мутация body_raw;
    form/JSON/пустое тело — без body_raw; apply_payload для body_raw (raw +
    tamper-encoder, без JSON-escape);
  • build_scan_tasks(do_body_raw=..., only_params=...):
    XML+xxe / soap+xxe / raw+deserialization → задачи body_raw с payload в body,
    method/url сохранены; xxe без XML CT, sqli/xss/cmdi на XML → 0 body_raw
    (в т.ч. planner_enabled=False); only_params фильтрует query/form/json/raw
    (case-insensitive); do_body_raw=False отключает raw-мутации.
"""

from __future__ import annotations

import tempfile
from pathlib import Path

import pytest

import db
import scanner_core
import templating

XML_BODY = b"<root><id>1</id><name>alice</name></root>"
SOAP_BODY = b"<soap:Envelope><soap:Body><id>1</id></soap:Body></soap:Envelope>"
PHP_SERIALIZED = b'O:8:"stdClass":0:{}'
XXE_PAYLOAD = "<!DOCTYPE r [<!ENTITY e SYSTEM 'file:///etc/passwd'>]><r>&e;</r>"
DESER_PAYLOAD = 'O:8:"stdClass":1:{s:1:"a";s:1:"b";}'
SQLI_PAYLOAD = "' OR 1=1--"


@pytest.fixture()
def tmp_db(tmp_path: Path):
    db_path = tmp_path / "raw-mutation-test.db"
    db.set_db_path(db_path)
    yield db_path
    db.set_db_path(tmp_path / "raw-mutation-closed.db")
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
    content_type: str | None = None,
    body: bytes | None = None,
) -> int:
    headers = {"Content-Type": content_type} if content_type else {}
    return db.insert_history(method, url, headers, body, 200, {}, b"baseline")


def _parsed(
    body: bytes,
    content_type: str = "",
    method: str = "POST",
    url: str = "http://example.test/api",
) -> templating.ParsedRequest:
    headers = {"Content-Type": content_type} if content_type else {}
    return templating.ParsedRequest(
        method=method, url=url, http_version="HTTP/1.1", headers=headers, body=body
    )


# ══════════════════════════════════════════════════════════════════
#  1. templating: mutate_body_raw / get_mutations
# ══════════════════════════════════════════════════════════════════

class TestMutateBodyRaw:
    @pytest.mark.parametrize(
        "content_type,body",
        [
            ("application/xml", XML_BODY),
            ("text/xml; charset=utf-8", XML_BODY),
            ("application/soap+xml", SOAP_BODY),
            ("application/octet-stream", PHP_SERIALIZED),
            ("text/plain", PHP_SERIALIZED),
            ("", PHP_SERIALIZED),  # сырое тело без Content-Type
        ],
    )
    def test_creates_single_body_raw_mutation(self, content_type, body):
        mutations = templating.mutate_body_raw(_parsed(body, content_type))
        assert len(mutations) == 1
        mutation = mutations[0]
        assert mutation.mutation_point == "body_raw"
        assert mutation.original_param == "body"
        assert mutation.body == templating.PLACEHOLDER.encode("utf-8")
        assert mutation.method == "POST"
        assert mutation.url == "http://example.test/api"
        assert "content-length" not in {k.lower() for k in mutation.headers}
        assert templating.PLACEHOLDER in mutation.raw_http

    @pytest.mark.parametrize(
        "content_type,body",
        [
            ("application/x-www-form-urlencoded", b"a=1&b=2"),
            ("application/json", b'{"a": 1}'),
            ("", b"{not-a-form-json}"),
            ("", b"a=1&b=2"),  # form-подобное тело без CT
        ],
    )
    def test_no_body_raw_for_form_or_json(self, content_type, body):
        assert templating.mutate_body_raw(_parsed(body, content_type)) == []

    def test_no_body_raw_for_empty_body(self):
        assert templating.mutate_body_raw(_parsed(b"", "application/xml")) == []
        assert templating.mutate_body_raw(_parsed(b"", "")) == []

    def test_xml_with_attributes_is_still_raw(self):
        # '=' в XML-атрибутах не должен превращать тело в form-мутацию
        body = b'<root attr="value"><a>x</a></root>'
        mutations = templating.mutate_body_raw(_parsed(body, "application/xml"))
        assert [m.mutation_point for m in mutations] == ["body_raw"]

    def test_get_mutations_includes_body_raw_by_default(self):
        req = _parsed(XML_BODY, "application/xml")
        points = [m.mutation_point for m in templating.get_mutations(req)]
        assert "body_raw" in points
        # do_body_raw=False — обратная совместимость «как раньше»
        without = templating.get_mutations(req, do_body_raw=False)
        assert all(m.mutation_point != "body_raw" for m in without)

    def test_get_mutations_old_positional_call_still_works(self):
        req = _parsed(b"a=1&b=2", "application/x-www-form-urlencoded")
        # старый вызов: 4 позиционных флага (query/form/json/headers)
        mutations = templating.get_mutations(req, True, True, True, False)
        assert all(m.mutation_point in ("body_form", "query") for m in mutations)

    def test_apply_payload_raw_substitution(self):
        mutation = templating.mutate_body_raw(_parsed(XML_BODY, "application/xml"))[0]
        _url, _headers, body = templating.apply_payload(mutation, XXE_PAYLOAD)
        assert body.decode("utf-8") == XXE_PAYLOAD  # raw, без JSON/url-escape

    def test_apply_payload_raw_with_encoder(self):
        mutation = templating.mutate_body_raw(_parsed(XML_BODY, "application/xml"))[0]
        _url, _headers, body = templating.apply_payload(
            mutation, "<x/>", encoder="url"
        )
        assert body.decode("utf-8") == templating.encode_payload("<x/>", "url")
        assert "%3Cx%2F%3E" in body.decode("utf-8")


# ══════════════════════════════════════════════════════════════════
#  2. build_scan_tasks: reachability для XXE/deserialization
# ══════════════════════════════════════════════════════════════════

class TestBuildScanTasksRaw:
    def test_xxe_xml_creates_body_raw_task(self, tmp_db, monkeypatch):
        monkeypatch.setattr(
            scanner_core, "load_payloads",
            _fake_load_payloads({"xxe": [XXE_PAYLOAD]}),
        )
        hid = _insert_history(
            "POST", "http://example.test/api/xml",
            content_type="application/xml", body=XML_BODY,
        )
        tasks = scanner_core.build_scan_tasks([hid], ["xxe"])
        assert len(tasks) == 1, f"ожидали 1 body_raw-задачу, получили {len(tasks)}"
        task = tasks[0]
        assert task.check_type == "xxe"
        assert task.mutation_point == "body_raw"
        assert task.original_param == "body"
        assert task.payload == XXE_PAYLOAD
        assert task.body.decode("utf-8") == XXE_PAYLOAD
        assert task.method == "POST"
        assert task.url == "http://example.test/api/xml"
        assert "content-length" not in {k.lower() for k in task.headers}
        assert task.history_id == hid

    def test_xxe_soap_creates_body_raw_task(self, tmp_db, monkeypatch):
        monkeypatch.setattr(
            scanner_core, "load_payloads",
            _fake_load_payloads({"xxe": [XXE_PAYLOAD]}),
        )
        hid = _insert_history(
            "POST", "http://example.test/soap",
            content_type="application/soap+xml", body=SOAP_BODY,
        )
        tasks = scanner_core.build_scan_tasks([hid], ["xxe"])
        assert [t.mutation_point for t in tasks] == ["body_raw"]

    def test_deserialization_raw_body_task(self, tmp_db, monkeypatch):
        monkeypatch.setattr(
            scanner_core, "load_payloads",
            _fake_load_payloads({"deserialization": [DESER_PAYLOAD]}),
        )
        hid = _insert_history(
            "POST", "http://example.test/deser",
            content_type="application/octet-stream", body=PHP_SERIALIZED,
        )
        tasks = scanner_core.build_scan_tasks([hid], ["deserialization"])
        raw_tasks = [t for t in tasks if t.mutation_point == "body_raw"]
        assert len(raw_tasks) == 1
        assert raw_tasks[0].payload == DESER_PAYLOAD
        assert raw_tasks[0].body.decode("utf-8") == DESER_PAYLOAD

    def test_xxe_requires_xml_content_type(self, tmp_db, monkeypatch):
        monkeypatch.setattr(
            scanner_core, "load_payloads",
            _fake_load_payloads({"xxe": [XXE_PAYLOAD]}),
        )
        hid = _insert_history(
            "POST", "http://example.test/deser",
            content_type="application/octet-stream", body=PHP_SERIALIZED,
        )
        assert scanner_core.build_scan_tasks([hid], ["xxe"]) == []

    def test_xxe_without_content_type_header(self, tmp_db, monkeypatch):
        monkeypatch.setattr(
            scanner_core, "load_payloads",
            _fake_load_payloads({"xxe": [XXE_PAYLOAD]}),
        )
        hid = _insert_history("POST", "http://example.test/api", body=XML_BODY)
        assert scanner_core.build_scan_tasks([hid], ["xxe"]) == []

    @pytest.mark.parametrize("check_type", ["sqli", "xss", "cmdi", "ssti"])
    def test_body_raw_not_used_by_other_checks(self, tmp_db, monkeypatch, check_type):
        monkeypatch.setattr(
            scanner_core, "load_payloads",
            _fake_load_payloads({check_type: [SQLI_PAYLOAD]}),
        )
        hid = _insert_history(
            "POST", "http://example.test/api/xml",
            content_type="application/xml", body=XML_BODY,
        )
        tasks = scanner_core.build_scan_tasks([hid], [check_type])
        assert all(t.mutation_point != "body_raw" for t in tasks), (
            f"{check_type}: body_raw не должен использоваться"
        )
        # Даже без planner'а гейт body_raw остаётся в силе.
        tasks_no_planner = scanner_core.build_scan_tasks(
            [hid], [check_type], planner_enabled=False
        )
        assert all(t.mutation_point != "body_raw" for t in tasks_no_planner)

    def test_json_and_form_have_no_body_raw(self, tmp_db, monkeypatch):
        monkeypatch.setattr(
            scanner_core, "load_payloads",
            _fake_load_payloads({"xxe": [XXE_PAYLOAD], "deserialization": [DESER_PAYLOAD]}),
        )
        json_hid = _insert_history(
            "POST", "http://example.test/json",
            content_type="application/json", body=b'{"a": 1}',
        )
        form_hid = _insert_history(
            "POST", "http://example.test/form",
            content_type="application/x-www-form-urlencoded", body=b"a=1&b=2",
        )
        assert all(
            t.mutation_point != "body_raw"
            for t in scanner_core.build_scan_tasks([json_hid], ["xxe", "deserialization"])
        )
        assert all(
            t.mutation_point != "body_raw"
            for t in scanner_core.build_scan_tasks([form_hid], ["xxe", "deserialization"])
        )

    def test_do_body_raw_false_disables_raw_tasks(self, tmp_db, monkeypatch):
        monkeypatch.setattr(
            scanner_core, "load_payloads",
            _fake_load_payloads({"xxe": [XXE_PAYLOAD]}),
        )
        hid = _insert_history(
            "POST", "http://example.test/api/xml",
            content_type="application/xml", body=XML_BODY,
        )
        assert scanner_core.build_scan_tasks([hid], ["xxe"]) != []
        assert scanner_core.build_scan_tasks([hid], ["xxe"], do_body_raw=False) == []


# ══════════════════════════════════════════════════════════════════
#  3. only_params: фильтр по original_param (интерфейс GUI)
# ══════════════════════════════════════════════════════════════════

class TestOnlyParams:
    def test_only_params_query_filter(self, tmp_db, monkeypatch):
        monkeypatch.setattr(
            scanner_core, "load_payloads",
            _fake_load_payloads({"sqli": [SQLI_PAYLOAD]}),
        )
        hid = _insert_history(
            "GET", "http://example.test/item?id=1&name=alice&q=text"
        )
        tasks = scanner_core.build_scan_tasks([hid], ["sqli"], only_params=["Name"])
        assert tasks
        assert {t.original_param for t in tasks} == {"name"}, "фильтр case-insensitive"

    def test_only_params_body_form_and_json(self, tmp_db, monkeypatch):
        monkeypatch.setattr(
            scanner_core, "load_payloads",
            _fake_load_payloads({"sqli": [SQLI_PAYLOAD]}),
        )
        hid = _insert_history(
            "POST", "http://example.test/form",
            content_type="application/x-www-form-urlencoded",
            body=b"username=alice&password=secret",
        )
        tasks = scanner_core.build_scan_tasks([hid], ["sqli"], only_params=["password"])
        assert tasks and {t.original_param for t in tasks} == {"password"}

    def test_only_params_raw_body(self, tmp_db, monkeypatch):
        monkeypatch.setattr(
            scanner_core, "load_payloads",
            _fake_load_payloads({"xxe": [XXE_PAYLOAD]}),
        )
        hid = _insert_history(
            "POST", "http://example.test/api/xml",
            content_type="application/xml", body=XML_BODY,
        )
        kept = scanner_core.build_scan_tasks([hid], ["xxe"], only_params=["BODY"])
        assert [t.mutation_point for t in kept] == ["body_raw"]
        assert scanner_core.build_scan_tasks([hid], ["xxe"], only_params=["id"]) == []

    def test_only_params_none_and_empty_means_no_filter(self, tmp_db, monkeypatch):
        monkeypatch.setattr(
            scanner_core, "load_payloads",
            _fake_load_payloads({"sqli": [SQLI_PAYLOAD]}),
        )
        hid = _insert_history("GET", "http://example.test/item?id=1&name=alice")
        for only in (None, [], ["", "  "]):
            tasks = scanner_core.build_scan_tasks([hid], ["sqli"], only_params=only)
            assert {t.original_param for t in tasks} == {"id", "name"}

    def test_only_params_keeps_matching_hidden_in_mixed_history(self, tmp_db, monkeypatch):
        # query-параметр + raw body в одном запросе: фильтр оставляет только body.
        monkeypatch.setattr(
            scanner_core, "load_payloads",
            _fake_load_payloads({"xxe": [XXE_PAYLOAD]}),
        )
        hid = _insert_history(
            "POST", "http://example.test/api/xml?id=1",
            content_type="application/xml", body=XML_BODY,
        )
        tasks = scanner_core.build_scan_tasks([hid], ["xxe"], only_params=["body"])
        assert [(t.mutation_point, t.original_param) for t in tasks] == [("body_raw", "body")]
