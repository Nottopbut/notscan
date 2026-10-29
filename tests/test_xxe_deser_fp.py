"""FP-регрессы для XXE/deserialization.

Реальные debug-страницы (bWAPP low: `Warning: simplexml_load_string():
Entity 'xxe' not defined`, PyGoat Django DEBUG 500) echo'ят payload и
раньше давали сотни HIGH-«находок» XXE; malformed XML/JSON с 500 — ложные
«deserialization». Проверяем, что теперь:
  • XXE-finding только при раскрытии содержимого файла;
  • deserialization-finding только по реальным маркерам,
    а голый 500 на сериализованный payload — не находка.
"""

from checks.base import CheckContext, ScanRequest, ScanResponse
from checks.injections import DeserializationCheck, XXECheck

XXE_BODY = (
    b'<?xml version="1.0"?><!DOCTYPE reset [<!ENTITY xxe SYSTEM '
    b'"file:///etc/passwd">]><reset><login>&xxe;</login></reset>'
)
XXE_PAYLOAD = XXE_BODY.decode()


def _xxe_check():
    chk = XXECheck()
    chk.enabled = True
    req = ScanRequest(
        method="POST", url="http://127.0.0.1/xxe",
        headers={"Content-Type": "text/xml"}, body=XXE_BODY,
    )
    ctx = CheckContext(payload=XXE_PAYLOAD, check_type="xxe", mutation_point="body_raw")
    return chk, req, ctx


def test_xxe_parser_warning_with_payload_echo_is_not_finding():
    chk, req, ctx = _xxe_check()
    resp = ScanResponse(
        status_code=200, headers={},
        text=(
            "Warning: simplexml_load_string(): Entity 'xxe' not defined in "
            "file:///etc/passwd <!DOCTYPE reset [<!ENTITY xxe SYSTEM ...]>"
        ),
    )
    res = chk.check(req, resp, ctx)
    assert res.findings == [], "эхо payload/ошибка парсера — не XXE"


def test_xxe_django_debug_page_is_not_finding():
    chk, req, ctx = _xxe_check()
    resp = ScanResponse(
        status_code=500, headers={"Content-Type": "text/html"},
        text='Traceback... request body: &lt;!DOCTYPE foo [&lt;!ENTITY xxe SYSTEM "file:///etc/passwd"&gt;]&gt;',
    )
    assert chk.check(req, resp, ctx).findings == []


def test_xxe_actual_file_disclosure_is_finding():
    chk, req, ctx = _xxe_check()
    resp = ScanResponse(
        status_code=200, headers={},
        text="root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:daemon:/usr/sbin",
    )
    res = chk.check(req, resp, ctx)
    assert res.findings, "раскрытие /etc/passwd должно флагаться"
    assert "root:x:0:0" in res.findings[0].evidence


def test_xxe_matcher_ignores_errors_but_detects_file_content():
    import scanner_core

    payload = XXE_PAYLOAD
    err = "Warning: simplexml_load_string(): Entity 'xxe' not defined; file:///"
    assert scanner_core.match_xxe(payload, err) is None
    assert scanner_core.match_xxe(payload, "<title>404</title>") is None
    ev = scanner_core.match_xxe(payload, "root:x:0:0:root:/root:/bin/bash")
    assert ev and "root:x:0" in ev


def _deser_check():
    chk = DeserializationCheck()
    chk.enabled = True
    body = b'O:4:"Test":1:{s:5:"admin";i:1;}'
    req = ScanRequest(
        method="POST", url="http://127.0.0.1/deser",
        headers={"Content-Type": "application/octet-stream"}, body=body,
    )
    ctx = CheckContext(payload=body.decode(), check_type="deserialization")
    return chk, req, ctx


def test_deserialization_bare_500_with_serialized_payload_is_not_finding():
    chk, req, ctx = _deser_check()
    resp = ScanResponse(status_code=500, headers={}, text="Internal Server Error")
    assert chk.check(req, resp, ctx).findings == [], "голый 500 — не deserialization"


def test_deserialization_marker_is_finding():
    chk, req, ctx = _deser_check()
    resp = ScanResponse(
        status_code=500, headers={},
        text="PHP Fatal error: unserialize(): Error at offset 0 of 26 bytes",
    )
    assert chk.check(req, resp, ctx).findings, "маркер unserialize() — находка"
