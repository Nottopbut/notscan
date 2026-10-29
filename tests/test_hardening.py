"""
Unit-тесты hardening-правок:

  • Баг #3 — apply_payload для body_json экранирует payload как JSON-строку:
    все payload-файлы (2972 подстановки) дают валидный JSON;
  • Tamper-энкодеры (TAMPER_MODES / encode_payload / apply_payload(encoder=...));
  • Баг #4 — FP-правила XSS (fp_rules) и фильтры XSSReflectedCheck;
  • M5 — SQLiTimeCheck: vuln_type="sqli_time", относительный порог по baseline_ms,
    детекция только по задержке;
  • M3 — CSRF: extract_csrf_token / patch_csrf_token, fetch_csrf_token и
    SessionManager.csrf_token_provider (локальный мини-сервер, без сети);
  • Прокидывание baseline_ms/baseline_text через CheckContext и run_checks_on_response;
  • InfoDisclosureCheck: FN на JSON-ключах ("spring.datasource.password": …)
    и FP base64-эвристики на JWT (аудит FP/FN).

Без сети: только 127.0.0.1 эфемерного порта. Временных файлов не оставляем.
"""

import base64
import hashlib
import json
import re
import threading
import unittest
import urllib.parse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import templating
from checks.base import CheckContext, ScanRequest, ScanResponse
from checks.client_side import InfoDisclosureCheck, XSSReflectedCheck
from checks.fp_rules import is_bare_html_tag, is_html_response, payload_in_baseline
from checks.injections import SQLI_TIME_PAYLOADS, SQLiTimeCheck
from checks.runner import run_checks_on_response

PROJECT_ROOT = Path(__file__).resolve().parent.parent
PAYLOADS_DIR = PROJECT_ROOT / "payloads"

# То же соответствие check_type → payload-файл, что использует движок
# (scanner_core.load_payloads) и acceptance-проба .
PAYLOAD_FILES = {
    "xss_reflected": "xss.txt",
    "sqli": "sqli.txt",
    "sqli_time": "sqli_time.txt",
    "cmdi": "cmdi.txt",
    "ssti": "ssti.txt",
    "path_traversal": "path_traversal.txt",
    "nosql_injection": "nosqli.txt",
    "ldap_injection": "ldapi.txt",
    "xpath_injection": "xpath.txt",
    "deserialization": "deserialization.txt",
    "crlf_injection": "crlf.txt",
    "open_redirect": "open_redirect.txt",
    "ssrf": "ssrf.txt",
    "file_upload": "file_upload.txt",
    "idor": "idor.txt",
    "xxe": "xxe.txt",
}

def _load_payload_file(filename: str) -> list[str]:
    lines = (PAYLOADS_DIR / filename).read_text(encoding="utf-8").splitlines()
    return [line.strip() for line in lines if line.strip() and not line.startswith("#")]


# payload-базы выросли — ожидаемое число подстановок
# считаем динамически по фактическим файлам (было захардкожено 2972).
TOTAL_PAYLOADS_EXPECTED = sum(len(_load_payload_file(f)) for f in PAYLOAD_FILES.values())


def _json_mutation() -> templating.MutatedRequest:
    """POST /api/user {"name": "test"} → единственная body_json-мутация."""
    req = templating.ParsedRequest(
        method="POST",
        url="http://x/api/user",
        http_version="HTTP/1.1",
        headers={"Content-Type": "application/json"},
        body=json.dumps({"name": "test"}).encode("utf-8"),
    )
    mutations = templating.mutate_body_json(req)
    assert len(mutations) == 1, mutations
    return mutations[0]


def _make_req(url="http://x/q?q=1", method="GET", body=b"", headers=None):
    return ScanRequest(
        method=method,
        url=url,
        headers=headers or {},
        body=body,
        raw_http="",
    )


def _make_resp(text="", status_code=200, headers=None, elapsed_ms=0.0):
    return ScanResponse(
        status_code=status_code,
        headers=headers or {},
        text=text,
        elapsed_ms=elapsed_ms,
        error=None,
    )


def _xss_ctx(payload, baseline_text=""):
    return CheckContext(
        payload=payload,
        check_type="xss_reflected",
        baseline_text=baseline_text,
    )


def _decode_unicode_tamper(encoded: str) -> str:
    """Декодер для encode_payload(..., mode="unicode") (%uXXXX + суррогаты)."""
    units = [int(m, 16) for m in re.findall(r"%u([0-9A-Fa-f]{4})", encoded)]
    raw = "".join(chr(u) for u in units)
    return raw.encode("utf-16", "surrogatepass").decode("utf-16")


# ══════════════════════════════════════════════════════════════════
#  Баг #3: JSON-мутация
# ══════════════════════════════════════════════════════════════════

class TestJsonBodyMutation(unittest.TestCase):
    def test_all_payload_files_produce_valid_json(self):
        """645/2972 невалидных JSON до фикса → 0 после."""
        mutation = _json_mutation()
        total = 0
        invalid = []
        for check_type, filename in PAYLOAD_FILES.items():
            for payload in _load_payload_file(filename):
                total += 1
                _url, _headers, body = templating.apply_payload(mutation, payload)
                try:
                    decoded = json.loads(body.decode("utf-8"))
                except (json.JSONDecodeError, UnicodeDecodeError) as exc:
                    invalid.append((check_type, payload[:60], str(exc)))
                    continue
                # payload должен доехать без искажений
                self.assertEqual(decoded["name"], payload)
        self.assertEqual(total, TOTAL_PAYLOADS_EXPECTED)
        self.assertEqual(
            invalid, [], f"{len(invalid)} invalid JSON из {total}: {invalid[:5]}"
        )

    def test_special_characters_are_json_escaped(self):
        mutation = _json_mutation()
        payloads = [
            '" OR 1=1--',
            "'); DROP TABLE users;--",
            "</script><script>alert(1)</script>",
            "back\\slash \\\\ double",
            "line1\nline2\r\ttab",
            "\u003cscript\u003e",
            "Юникод 'кавычки' и \"ёлочки\"",
            "{{payload}}",
            "\x00\x01control",
        ]
        for payload in payloads:
            with self.subTest(payload=payload):
                _url, _headers, body = templating.apply_payload(mutation, payload)
                decoded = json.loads(body.decode("utf-8"))
                self.assertEqual(decoded["name"], payload)

    def test_nested_and_multiple_fields_stay_valid(self):
        req = templating.ParsedRequest(
            method="POST",
            url="http://x/api/item",
            http_version="HTTP/1.1",
            headers={"Content-Type": "application/json"},
            body=json.dumps(
                {"user": {"name": "a", "tags": ["x", "y"]}, "id": 1}
            ).encode("utf-8"),
        )
        mutations = templating.mutate_body_json(req)
        self.assertGreaterEqual(len(mutations), 3)
        payload = '"; alert(1); //'
        for mutation in mutations:
            _url, _headers, body = templating.apply_payload(mutation, payload)
            decoded = json.loads(body.decode("utf-8"))
            self.assertIn(payload, json.dumps(decoded))

    def test_non_json_mutations_are_not_json_escaped(self):
        """Не-JSON подстановки должны остаться «сырыми» (не сломать form/query)."""
        req = templating.ParsedRequest(
            method="POST",
            url="http://x/form?q=test",
            http_version="HTTP/1.1",
            headers={"Content-Type": "application/x-www-form-urlencoded"},
            body=b"name=test&comment=hi",
        )
        mutations = templating.mutate_body_form(req)
        self.assertTrue(mutations)
        target = next(m for m in mutations if m.original_param == "comment")
        _url, _headers, body = templating.apply_payload(target, "</script>")
        self.assertIn(b"comment=</script>", body)
        self.assertNotIn(b'\\"', body)

        query_mutation = templating.mutate_query_params(req)[0]
        url, _headers, _body = templating.apply_payload(query_mutation, '<a b>')
        self.assertIn(urllib.parse.quote("<a b>", safe=""), url)
        self.assertNotIn("<a b>", url)

    def test_apply_payload_without_encoder_backward_compatible(self):
        mutation = _json_mutation()
        result = templating.apply_payload(mutation, "abc")
        self.assertEqual(len(result), 3)
        url, headers, body = result
        self.assertIsInstance(url, str)
        self.assertIsInstance(headers, dict)
        self.assertIsInstance(body, bytes)
        self.assertEqual(json.loads(body.decode())["name"], "abc")


# ══════════════════════════════════════════════════════════════════
#  Tamper-энкодеры (§4)
# ══════════════════════════════════════════════════════════════════

class TestTamperEncoders(unittest.TestCase):
    def test_tamper_modes_tuple(self):
        self.assertIsInstance(templating.TAMPER_MODES, tuple)
        self.assertEqual(
            templating.TAMPER_MODES, ("url", "unicode", "hex", "double-url")
        )

    def test_url_mode_roundtrip(self):
        payload = "<script>alert('x') & \"y\"</script>"
        encoded = templating.encode_payload(payload, "url")
        self.assertEqual(encoded, urllib.parse.quote(payload, safe=""))
        self.assertEqual(urllib.parse.unquote(encoded), payload)
        self.assertNotIn("<", encoded)

    def test_unicode_mode_roundtrip(self):
        payload = '<script>alert("X")</script>'
        encoded = templating.encode_payload(payload, "unicode")
        self.assertIn("%u003C", encoded)  # uppercase HEX, стиль %uXXXX
        self.assertEqual(_decode_unicode_tamper(encoded), payload)

    def test_hex_mode_roundtrip(self):
        payload = "AB<alert>"
        encoded = templating.encode_payload(payload, "hex")
        # кодируются ВСЕ байты, включая alnum (в отличие от url)
        self.assertTrue(encoded.startswith("%41%42"))
        self.assertEqual(
            urllib.parse.unquote_to_bytes(encoded).decode("utf-8"), payload
        )

    def test_double_url_mode_roundtrip(self):
        payload = "<script>"
        encoded = templating.encode_payload(payload, "double-url")
        self.assertEqual(urllib.parse.unquote(urllib.parse.unquote(encoded)), payload)
        self.assertNotEqual(encoded, templating.encode_payload(payload, "url"))

    def test_unknown_mode_raises(self):
        with self.assertRaises(ValueError):
            templating.encode_payload("<x>", "rot13")
        with self.assertRaises(ValueError):
            templating.encode_payload("<x>", "")

    def test_apply_payload_encoder_inserts_encoded_form(self):
        req = templating.ParsedRequest(
            method="POST",
            url="http://x/form?q=test",
            http_version="HTTP/1.1",
            headers={"Content-Type": "application/x-www-form-urlencoded"},
            body=b"name=test",
        )
        form_mutation = templating.mutate_body_form(req)[0]
        encoded = templating.encode_payload("<script>", "url")
        _url, _headers, body = templating.apply_payload(
            form_mutation, "<script>", encoder="url"
        )
        self.assertIn(encoded.encode(), body)
        self.assertNotIn(b"<script>", body)

    def test_apply_payload_encoder_json_stays_valid(self):
        mutation = _json_mutation()
        _url, _headers, body = templating.apply_payload(
            mutation, '"; alert(1); //', encoder="url"
        )
        decoded = json.loads(body.decode())
        self.assertEqual(decoded["name"], templating.encode_payload('"; alert(1); //', "url"))


# ══════════════════════════════════════════════════════════════════
#  Баг #4: fp_rules + XSSReflectedCheck
# ══════════════════════════════════════════════════════════════════

class TestFpRules(unittest.TestCase):
    def test_is_bare_html_tag_true(self):
        for payload in ("<body>", "<script>", "<img>", "<svg>", "</html>",
                        "<title>", "</svg>", "<br/>", "  <body>  "):
            with self.subTest(payload=payload):
                self.assertTrue(is_bare_html_tag(payload))

    def test_is_bare_html_tag_false(self):
        for payload in (
            "<script>alert(1)</script>",
            "<img src=x onerror=alert(1)>",
            "<body onload=alert(1)>",
            "<input type=text name=x>",
            "text<body>",
            "<body><body>",
            "</script><script>alert(1)</script>",
        ):
            with self.subTest(payload=payload):
                self.assertFalse(is_bare_html_tag(payload))
        self.assertFalse(is_bare_html_tag(""))
        self.assertFalse(is_bare_html_tag("alert(1)"))

    def test_is_html_response(self):
        self.assertTrue(is_html_response(None))
        self.assertTrue(is_html_response({}))
        self.assertTrue(is_html_response({"Server": "nginx"}))  # нет Content-Type
        self.assertTrue(is_html_response({"Content-Type": "text/html; charset=utf-8"}))
        self.assertTrue(is_html_response({"content-type": "application/xhtml+xml"}))
        self.assertTrue(is_html_response({"Content-Type": "text/xml"}))
        self.assertFalse(is_html_response({"Content-Type": "application/json"}))
        self.assertFalse(is_html_response({"content-type": "application/json; charset=utf-8"}))
        self.assertFalse(is_html_response({"Content-Type": "text/plain"}))

    def test_payload_in_baseline(self):
        payload = "<script>alert(1)</script>"
        self.assertTrue(payload_in_baseline(payload, f"<html>{payload}</html>"))
        encoded = urllib.parse.quote(payload, safe="")
        self.assertTrue(payload_in_baseline(payload, f"echo: {encoded}"))
        self.assertFalse(payload_in_baseline(payload, "<html><body>hi</body></html>"))
        self.assertFalse(payload_in_baseline("", "<html></html>"))
        self.assertFalse(payload_in_baseline(payload, ""))


class TestXSSReflectedCheckFilters(unittest.TestCase):
    def setUp(self):
        self.check = XSSReflectedCheck()

    def _findings(self, payload, resp_text, headers=None, baseline_text=""):
        req = _make_req()
        resp = _make_resp(text=resp_text, headers=headers or {})
        return self.check.check(req, resp, _xss_ctx(payload, baseline_text)).findings

    def test_bare_tag_no_finding(self):
        # /search: payload <body> уже есть в HTML-скелете → FP подавлен
        html = "<html><body><h1>Search</h1></body></html>"
        self.assertEqual(self._findings("<body>", html), [])
        self.assertEqual(self._findings("<script>", "<html><script src=x></script></html>"), [])

    def test_json_response_not_xss(self):
        payload = "<script>alert(1)</script>"
        self.assertEqual(
            self._findings(payload, json.dumps({"q": payload}),
                           {"Content-Type": "application/json"}),
            [],
        )
        self.assertEqual(
            self._findings(payload, payload, {"Content-Type": "text/plain"}),
            [],
        )

    def test_baseline_suppression(self):
        payload = "<script>alert(1)</script>"
        html = f"<html><body>{payload}</body></html>"
        self.assertEqual(self._findings(payload, html, baseline_text=html), [])

    def test_real_reflection_still_found(self):
        payload = "<script>alert(1)</script>"
        findings = self._findings(
            payload, f"<html><body>echo: {payload}</body></html>",
            {"Content-Type": "text/html"},
        )
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].vuln_type, "xss_reflected")

    def test_real_reflection_without_content_type_found(self):
        payload = "<img src=x onerror=alert(1)>"
        findings = self._findings(payload, f"<html><body>{payload}</body></html>")
        self.assertEqual(len(findings), 1)

    def test_url_encoded_reflection_found_in_html(self):
        payload = "<script>alert(1)</script>"
        encoded = urllib.parse.quote(payload, safe="")
        findings = self._findings(
            payload, f"<html><body>{encoded}</body></html>",
            {"Content-Type": "text/html"},
        )
        self.assertEqual(len(findings), 1)

    def test_url_encoded_reflection_not_found_in_json(self):
        payload = "<script>alert(1)</script>"
        encoded = urllib.parse.quote(payload, safe="")
        self.assertEqual(
            self._findings(payload, encoded, {"Content-Type": "application/json"}),
            [],
        )

    def test_payload_without_html_metacharacters_skipped(self):
        self.assertEqual(self._findings("alert(1)", "<html>alert(1)</html>"), [])


# ══════════════════════════════════════════════════════════════════
#  M5: SQLi time-based
# ══════════════════════════════════════════════════════════════════

class TestSQLiTimeCheck(unittest.TestCase):
    PAYLOAD = SQLI_TIME_PAYLOADS[0][1]      # "' AND SLEEP(5)-- -" (threshold 5.0s)
    ABS_THRESHOLD_MS = SQLI_TIME_PAYLOADS[0][2] * 1000.0

    def setUp(self):
        self.check = SQLiTimeCheck()

    def _findings(self, elapsed_ms, baseline_ms=0.0, payload=None, text=""):
        req = _make_req()
        resp = _make_resp(text=text, elapsed_ms=elapsed_ms)
        ctx = CheckContext(
            payload=self.PAYLOAD if payload is None else payload,
            check_type="sqli_time",
            baseline_ms=baseline_ms,
        )
        return self.check.check(req, resp, ctx).findings

    def test_vuln_type_is_sqli_time(self):
        self.assertEqual(SQLiTimeCheck.vuln_type, "sqli_time")
        self.assertEqual(SQLiTimeCheck.check_id, "sqli_time")
        findings = self._findings(self.ABS_THRESHOLD_MS + 500)
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].vuln_type, "sqli_time")

    def test_absolute_threshold_without_baseline(self):
        self.assertEqual(self._findings(self.ABS_THRESHOLD_MS - 1), [])
        self.assertEqual(len(self._findings(self.ABS_THRESHOLD_MS)), 1)  # >=

    def test_relative_threshold_for_slow_host(self):
        # baseline 1000ms → required max(5000, 1000*3+1000=4000) = 5000
        self.assertEqual(self._findings(4400, baseline_ms=1000.0), [])
        self.assertEqual(len(self._findings(5000, baseline_ms=1000.0)), 1)
        # baseline 2000ms → required max(5000, 7000) = 7000
        self.assertEqual(self._findings(6000, baseline_ms=2000.0), [])
        self.assertEqual(len(self._findings(7000, baseline_ms=2000.0)), 1)

    def test_required_delay_helper(self):
        self.assertEqual(self.check.required_delay_ms(5.0, 0.0), 5000.0)
        self.assertEqual(self.check.required_delay_ms(5.0, -1.0), 5000.0)
        self.assertEqual(self.check.required_delay_ms(5.0, 1000.0), 5000.0)
        self.assertEqual(self.check.required_delay_ms(5.0, 2000.0), 7000.0)
        self.assertEqual(self.check.required_delay_ms(4.0, 100.0), 4000.0)

    def test_no_error_signature_detection(self):
        # SQL-ошибка в теле при быстром ответе — НЕ time-based находка
        self.assertEqual(
            self._findings(120.0, text="You have an error in your SQL syntax"), []
        )
        # SQL-ошибка сама по себе (без задержки) не даёт sqli_time
        self.assertEqual(
            self._findings(0.0, text="ORA-00933: SQL command not properly ended"), []
        )

    def test_non_time_payload_not_flagged(self):
        self.assertEqual(self._findings(10_000.0, payload="' OR 1=1--"), [])
        self.assertEqual(self._findings(10_000.0, payload=""), [])

    def test_ctx_without_baseline_attr_falls_back(self):
        """CheckContext, собранный старым кодом (без baseline_ms), не падает."""
        req = _make_req()
        resp = _make_resp(elapsed_ms=6000.0)
        ctx = CheckContext(payload=self.PAYLOAD, check_type="sqli_time")
        findings = self.check.check(req, resp, ctx).findings
        self.assertEqual(len(findings), 1)


# ══════════════════════════════════════════════════════════════════
#  M3: CSRF — extraction & patching
# ══════════════════════════════════════════════════════════════════

def _mutation(point, *, url="http://x/form", headers=None, body=b"", original_param=""):
    return templating.MutatedRequest(
        method="POST" if point != "query" else "GET",
        url=url,
        headers=headers or {},
        body=body,
        mutation_point=point,
        original_param=original_param,
    )


class TestCsrfExtract(unittest.TestCase):
    def test_input_double_quotes(self):
        html = '<form><input type="hidden" name="csrf_token" value="TOK1"></form>'
        self.assertEqual(templating.extract_csrf_token(html), "TOK1")

    def test_input_attribute_order_any(self):
        html = '<input value="TOK2" type="hidden" name="csrf_token">'
        self.assertEqual(templating.extract_csrf_token(html), "TOK2")

    def test_input_single_quotes(self):
        html = "<input name='_token' value='TOK3'>"
        self.assertEqual(templating.extract_csrf_token(html), "TOK3")

    def test_input_unquoted_value(self):
        html = "<input value=TOK4 name=authenticity_token>"
        self.assertEqual(templating.extract_csrf_token(html), "TOK4")

    def test_input_case_insensitive(self):
        html = '<input name="__RequestVerificationToken" value="TOK5">'
        self.assertEqual(templating.extract_csrf_token(html), "TOK5")

    def test_meta_token(self):
        html = '<meta name="csrf-token" content="META1">'
        self.assertEqual(templating.extract_csrf_token(html), "META1")
        html_reordered = '<meta content="META2" name="csrf-token">'
        self.assertEqual(templating.extract_csrf_token(html_reordered), "META2")

    def test_no_token(self):
        self.assertIsNone(templating.extract_csrf_token("<html><body>hi</body></html>"))
        self.assertIsNone(templating.extract_csrf_token(""))
        self.assertIsNone(templating.extract_csrf_token('<input name="csrf_token" value="">'))
        self.assertIsNone(templating.extract_csrf_token('<input name="username" value="x">'))


class TestCsrfPatch(unittest.TestCase):
    TOKEN = "T0KEN"

    def test_patch_body_form(self):
        mutation = _mutation(
            "body_form",
            headers={"Content-Type": "application/x-www-form-urlencoded"},
            body=b"username=admin&csrf_token=OLD&comment=" + templating.PLACEHOLDER.encode(),
            original_param="comment",
        )
        patched = templating.patch_csrf_token(mutation, self.TOKEN)
        body = patched.body.decode()
        self.assertIn("csrf_token=" + self.TOKEN, body)
        self.assertNotIn("OLD", body)
        self.assertIn("username=admin", body)  # прочие поля не тронуты
        # PLACEHOLDER сохранён (в mutation body он лежит в декодированном виде)
        self.assertIn(templating.PLACEHOLDER, body)
        self.assertNotEqual(patched.body, mutation.body)
        self.assertEqual(
            mutation.body,
            b"username=admin&csrf_token=OLD&comment=" + templating.PLACEHOLDER.encode(),
        )

    def test_patch_body_form_preserves_placeholder_raw(self):
        mutation = _mutation(
            "body_form",
            headers={"Content-Type": "application/x-www-form-urlencoded"},
            body=b"csrf_token=OLD&q=" + templating.PLACEHOLDER.encode(),
            original_param="q",
        )
        patched = templating.patch_csrf_token(mutation, self.TOKEN)
        self.assertIn(templating.PLACEHOLDER.encode(), patched.body)

    def test_patch_body_form_token_urlencoded(self):
        mutation = _mutation(
            "body_form",
            headers={"Content-Type": "application/x-www-form-urlencoded"},
            body=b"csrf_token=OLD&q=x",
            original_param="q",
        )
        patched = templating.patch_csrf_token(mutation, "a+b/c")
        self.assertIn(b"csrf_token=a%2Bb%2Fc", patched.body)

    def test_patch_body_json(self):
        body = json.dumps(
            {"user": "bob", "csrf_token": "OLD", "name": templating.PLACEHOLDER}
        ).encode()
        mutation = _mutation(
            "body_json",
            headers={"Content-Type": "application/json"},
            body=body,
            original_param="name",
        )
        patched = templating.patch_csrf_token(mutation, self.TOKEN)
        decoded = json.loads(patched.body.decode())
        self.assertEqual(decoded["csrf_token"], self.TOKEN)
        self.assertEqual(decoded["name"], templating.PLACEHOLDER)
        self.assertEqual(decoded["user"], "bob")

    def test_patch_body_json_nested(self):
        body = json.dumps({"meta": {"_token": "OLD"}, "q": templating.PLACEHOLDER}).encode()
        mutation = _mutation("body_json", body=body, original_param="q")
        decoded = json.loads(templating.patch_csrf_token(mutation, self.TOKEN).body.decode())
        self.assertEqual(decoded["meta"]["_token"], self.TOKEN)
        self.assertEqual(decoded["q"], templating.PLACEHOLDER)

    def test_patch_headers(self):
        mutation = _mutation(
            "header:Referer",
            headers={"X-CSRF-Token": "OLD", "Referer": templating.PLACEHOLDER},
            original_param="Referer",
        )
        patched = templating.patch_csrf_token(mutation, self.TOKEN)
        self.assertEqual(patched.headers["X-CSRF-Token"], self.TOKEN)
        self.assertEqual(patched.headers["Referer"], templating.PLACEHOLDER)

    def test_patch_headers_absent_no_change(self):
        mutation = _mutation("query", url="http://x/a?q=1", original_param="q")
        patched = templating.patch_csrf_token(mutation, self.TOKEN)
        self.assertEqual(patched.headers, {})

    def test_patch_query(self):
        mutation = _mutation(
            "query",
            url="http://x/form?csrf=OLD&q=" + templating.PLACEHOLDER,
            original_param="q",
        )
        patched = templating.patch_csrf_token(mutation, self.TOKEN)
        parsed = urllib.parse.parse_qs(urllib.parse.urlsplit(patched.url).query)
        self.assertEqual(parsed["csrf"], [self.TOKEN])
        self.assertEqual(parsed["q"], [templating.PLACEHOLDER])

    def test_patch_returns_copy(self):
        mutation = _mutation(
            "body_form",
            headers={"X-CSRF-Token": "OLD"},
            body=b"csrf_token=OLD&q=" + templating.PLACEHOLDER.encode(),
            original_param="q",
        )
        patched = templating.patch_csrf_token(mutation, self.TOKEN)
        self.assertIsNot(patched, mutation)
        self.assertIn(b"OLD", mutation.body)
        self.assertEqual(mutation.headers["X-CSRF-Token"], "OLD")
        self.assertTrue(patched.raw_http)

    def test_mutation_targeting_csrf_field_gets_valid_token(self):
        """Если мутация нацелена на CSRF-поле, оно получает валидный токен:
        запрос должен остаться принятым сервером (иначе скан ложно 403)."""
        mutation = _mutation(
            "body_form",
            body=b"csrf_token=" + templating.PLACEHOLDER.encode() + b"&user=x",
            original_param="csrf_token",
        )
        patched = templating.patch_csrf_token(mutation, self.TOKEN)
        self.assertIn(b"csrf_token=" + self.TOKEN.encode(), patched.body)
        self.assertNotIn(templating.PLACEHOLDER.encode(), patched.body)
        self.assertIn(b"user=x", patched.body)

    def test_mutation_targeting_csrf_header_gets_valid_token(self):
        mutation = _mutation(
            "header:X-CSRF-Token",
            headers={"X-CSRF-Token": templating.PLACEHOLDER},
            original_param="X-CSRF-Token",
        )
        patched = templating.patch_csrf_token(mutation, self.TOKEN)
        self.assertEqual(patched.headers["X-CSRF-Token"], self.TOKEN)


# ══════════════════════════════════════════════════════════════════
#  Прокидывание baseline в CheckContext / runner
# ══════════════════════════════════════════════════════════════════

class _CapturingRegistry:
    def __init__(self):
        self.context = None
        self.kwargs = None

    def run_all(self, request, response, context, **kwargs):
        self.context = context
        self.kwargs = kwargs
        return []


class TestBaselinePlumbing(unittest.TestCase):
    def test_check_context_defaults(self):
        ctx = CheckContext()
        self.assertEqual(ctx.baseline_ms, 0.0)
        self.assertEqual(ctx.baseline_text, "")
        ctx2 = CheckContext(baseline_ms=42.5, baseline_text="<html>")
        self.assertEqual(ctx2.baseline_ms, 42.5)
        self.assertEqual(ctx2.baseline_text, "<html>")

    def _run(self, registry, **kwargs):
        return run_checks_on_response(
            method="GET",
            url="http://x/q?q=1",
            headers={},
            body=b"",
            raw_http="",
            resp_status=200,
            resp_headers={"Content-Type": "text/html"},
            resp_text="<html></html>",
            resp_elapsed_ms=10.0,
            resp_error=None,
            check_type="sqli_time",
            payload="' AND SLEEP(5)-- -",
            mutation_point="query",
            original_param="q",
            history_id=None,
            registry=registry,
            log_cb=lambda s: None,
            only_active=True,
            **kwargs,
        )

    def test_runner_passes_baseline_to_context(self):
        registry = _CapturingRegistry()
        self._run(registry, baseline_ms=250.0, baseline_text="<html>base</html>")
        self.assertEqual(registry.context.baseline_ms, 250.0)
        self.assertEqual(registry.context.baseline_text, "<html>base</html>")
        self.assertEqual(registry.kwargs.get("match_check_type"), "sqli_time")

    def test_runner_old_call_without_baseline(self):
        registry = _CapturingRegistry()
        findings = self._run(registry)
        self.assertEqual(findings, [])
        self.assertEqual(registry.context.baseline_ms, 0.0)
        self.assertEqual(registry.context.baseline_text, "")


# ══════════════════════════════════════════════════════════════════
#  M3: SessionManager / fetch_csrf_token (локальный мини-сервер)
# ══════════════════════════════════════════════════════════════════

class _CsrfHandler(BaseHTTPRequestHandler):
    requests = []  # [(path, headers_dict), ...]

    def do_GET(self):  # noqa: N802
        parsed = urllib.parse.urlsplit(self.path)
        type(self).requests.append(
            (parsed.path, {k.lower(): v for k, v in self.headers.items()})
        )
        if parsed.path == "/form":
            body = (
                b'<html><body><form method="post">'
                b'<input type="hidden" name="csrf_token" value="TOKEN123">'
                b"</form></body></html>"
            )
        elif parsed.path == "/meta":
            body = b'<html><head><meta name="csrf-token" content="META456"></head></html>'
        else:
            body = b"<html><body>no token here</body></html>"
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args):  # тишина в выводе тестов
        pass


class TestSessionCsrfProvider(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.server = ThreadingHTTPServer(("127.0.0.1", 0), _CsrfHandler)
        cls.port = cls.server.server_address[1]
        cls.base = f"http://127.0.0.1:{cls.port}"
        cls.thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()

    def setUp(self):
        _CsrfHandler.requests = []

    def test_fetch_csrf_token(self):
        import session_manager
        self.assertEqual(session_manager.fetch_csrf_token(self.base + "/form"), "TOKEN123")
        self.assertEqual(session_manager.fetch_csrf_token(self.base + "/meta"), "META456")
        self.assertIsNone(session_manager.fetch_csrf_token(self.base + "/plain"))

    def test_fetch_csrf_token_sends_cookies_and_headers(self):
        import session_manager
        session_manager.fetch_csrf_token(
            self.base + "/form",
            headers={"X-Test": "1"},
            cookies={"session": "abc"},
        )
        path, headers = _CsrfHandler.requests[-1]
        self.assertEqual(path, "/form")
        self.assertEqual(headers.get("x-test"), "1")
        self.assertIn("session=abc", headers.get("cookie", ""))

    def test_fetch_csrf_token_error_returns_none(self):
        import session_manager
        self.assertIsNone(
            session_manager.fetch_csrf_token("http://127.0.0.1:1/", timeout=0.25)
        )

    def test_provider_fetches_and_caches(self):
        from session_manager import AuthConfig, SessionManager
        sm = SessionManager(AuthConfig(enabled=False, login_url=self.base + "/form"))
        try:
            self.assertEqual(sm.csrf_token_provider(), "TOKEN123")
            # второй вызов — из кэша, без нового запроса
            self.assertEqual(sm.csrf_token_provider(), "TOKEN123")
            form_requests = [r for r in _CsrfHandler.requests if r[0] == "/form"]
            self.assertEqual(len(form_requests), 1)
            # logout сбрасывает кэш → снова запрос
            sm.logout()
            self.assertEqual(sm.csrf_token_provider(), "TOKEN123")
            form_requests = [r for r in _CsrfHandler.requests if r[0] == "/form"]
            self.assertEqual(len(form_requests), 2)
        finally:
            sm.close()

    def test_provider_without_url_returns_none(self):
        from session_manager import SessionManager
        sm = SessionManager()
        try:
            self.assertIsNone(sm.csrf_token_provider())
        finally:
            sm.close()

    def test_provider_uses_last_url_fallback(self):
        from session_manager import AuthConfig, SessionManager
        sm = SessionManager(AuthConfig(enabled=False))
        try:
            sm.request("GET", self.base + "/form")
            self.assertEqual(sm.csrf_token_provider(), "TOKEN123")
        finally:
            sm.close()

    def test_provider_error_returns_none(self):
        from session_manager import AuthConfig, SessionManager
        sm = SessionManager(AuthConfig(enabled=False, login_url="http://127.0.0.1:1/form"))
        try:
            self.assertIsNone(sm.csrf_token_provider())
        finally:
            sm.close()

    def test_provider_no_token_on_page_returns_none(self):
        from session_manager import AuthConfig, SessionManager
        sm = SessionManager(AuthConfig(enabled=False, login_url=self.base + "/plain"))
        try:
            self.assertIsNone(sm.csrf_token_provider())
        finally:
            sm.close()


# ══════════════════════════════════════════════════════════════════
#  Info Disclosure: FN (JSON-ключи) и FP (JWT/base64) из аудита
# ══════════════════════════════════════════════════════════════════

def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def _make_jwt(payload: dict | None = None) -> str:
    """Валидный по форме JWT (header.payload.signature, base64url)."""
    header = _b64url(json.dumps({"alg": "HS256", "typ": "JWT"}).encode())
    body = _b64url(json.dumps(
        payload or {"sub": "1234567890", "name": "John Doe", "iat": 1516239022}
    ).encode())
    signature = _b64url(hashlib.sha256(b"test-secret").digest())
    return f"{header}.{body}.{signature}"


class TestInfoDisclosureCheck(unittest.TestCase):
    """FN: JSON-ключи в кавычках; FP: JWT не должен флагаться как base64-секрет."""

    def setUp(self):
        self.check = InfoDisclosureCheck()

    def _titles(self, text: str) -> list[str]:
        req = _make_req()
        resp = _make_resp(text=text, headers={"Content-Type": "text/html"})
        return [f.title for f in self.check.check(req, resp, CheckContext()).findings]

    # ── FN: ключи в кавычках (JSON / /actuator/env) ─────────────────

    def test_actuator_env_json_key_password(self):
        titles = self._titles('{"spring.datasource.password": "s3cr3t"}')
        self.assertIn("Password in response", titles)

    def test_password_value_forms(self):
        for text in (
            'password: "abc12345"',
            "password='abc12345'",
            'password="abc12345"',
            '{"password": "abc12345"}',
            '{"db": {"password": "abc12345"}}',
        ):
            with self.subTest(text=text):
                self.assertIn("Password in response", self._titles(text), text)

    def test_json_secret_api_key_access_token_keys(self):
        cases = {
            '{"client_secret": "abcdefgh12"}': "Secret/key in response",
            '{"spring.datasource.secret": "abcdefghij"}': "Secret/key in response",
            '{"api_key": "0123456789"}': "API key in response",
            '{"x-api-key": "0123456789"}': "API key in response",
            '{"access_token": "0123456789"}': "Access token in response",
            '{"access-token": "0123456789"}': "Access token in response",
        }
        for text, expected in cases.items():
            with self.subTest(text=text):
                self.assertIn(expected, self._titles(text), text)

    def test_min_value_lengths_preserved(self):
        """Слишком короткие значения по-прежнему не считаются секретами."""
        for text in (
            'password="abc"',          # < 4
            'secret: "abcdefg"',       # < 8
            'api_key: "012345678"',    # < 10
            'access_token: "012345678"',  # < 10
            '{"spring.datasource.password": "abc"}',
        ):
            with self.subTest(text=text):
                titles = self._titles(text)
                self.assertNotIn("Password in response", titles, text)
                self.assertNotIn("Secret/key in response", titles, text)
                self.assertNotIn("API key in response", titles, text)
                self.assertNotIn("Access token in response", titles, text)

    def test_safe_json_has_no_secret_findings(self):
        safe = json.dumps({
            "username": "alice",
            "email": "alice@example.com",
            "keyword": "password field is not set here",
            "status": "ok",
        })
        self.assertEqual(
            [t for t in self._titles(safe) if "response" in t],
            [],
            self._titles(safe),
        )

    # ── FP: JWT / base64 ────────────────────────────────────────────

    def test_jwt_page_not_flagged_as_base64_secret(self):
        jwt = _make_jwt()
        for text in (
            f'<html><body><p>Authorization: Bearer {jwt}</p></body></html>',
            f"<html><body><code>{jwt}</code></body></html>",
        ):
            with self.subTest(text=text[:60]):
                self.assertEqual(self._titles(text), [], text)

    def test_jwt_with_extra_claims_not_flagged(self):
        jwt = _make_jwt({"sub": "u-42", "role": "admin", "scope": "read write"})
        self.assertEqual(
            self._titles(f"<html><body>Bearer {jwt}</body></html>"), []
        )

    def test_standalone_base64_json_is_treated_as_token(self):
        # base64 от JSON (без JWT-обёртки) — токен/данные, не утёкший секрет.
        blob = base64.b64encode(
            json.dumps({"user": "alice", "role": "admin", "scope": "read write"}).encode()
        ).decode()
        self.assertGreaterEqual(len(blob), 40)
        self.assertEqual(self._titles(f"<div>{blob}</div>"), [])

    def test_plain_base64_secret_still_flagged(self):
        secret = b"AKIAIOSFODNN7EXAMPLE:super-secret:value:1234567890"
        blob = base64.b64encode(secret).decode()
        self.assertGreaterEqual(len(blob), 40)
        titles = self._titles(f"<html><body><div>blob={blob}</div></body></html>")
        self.assertIn("Possible base64-encoded secret", titles)

    def test_jwt_plus_real_base64_secret_finds_only_secret(self):
        jwt = _make_jwt()
        secret = b"S3CR3T-CONFIG-VALUE:do-not-leak:0123456789abcdef"
        blob = base64.b64encode(secret).decode()
        text = f"<html><body>Bearer {jwt}<p>blob={blob}</p></body></html>"
        findings = self.check.check(
            _make_req(), _make_resp(text=text, headers={"Content-Type": "text/html"}),
            CheckContext(),
        ).findings
        base64_findings = [
            f for f in findings
            if f.title == "Possible base64-encoded secret"
        ]
        self.assertEqual(len(base64_findings), 1, [f.evidence for f in findings])
        self.assertIn(blob[:30], base64_findings[0].evidence)


if __name__ == "__main__":
    unittest.main()
