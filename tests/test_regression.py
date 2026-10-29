"""
Регрессионные тесты: матчеры (FP), scope-guard, коллекции, отчёты,
проекты, сессии, per-project DB, payloads.
"""

import json
import os
import shutil
import tempfile
import unittest
from pathlib import Path

import db
import scanner_core
import collection_io
import project_manager
import report_export
from scanner_core import (
    match_xss, match_ssrf, match_deserialization, match_nosql_injection,
    match_ldap_injection, match_open_redirect, match_path_traversal,
    match_crlf_injection, is_url_in_scope, load_payloads,
)


class TestMatchersFP(unittest.TestCase):
    """Слабые сигналы не должны давать находки (защита от ложных срабатываний)."""

    def test_xss_requires_reflection(self):
        # страница с JS-маркерами, но без отражённого payload — НЕ находка
        self.assertIsNone(match_xss("<script>alert(1)</script>",
                                    "<html><script src='app.js'></script><body onload=init()></body></html>"))
        # реальное отражение — находка
        self.assertIsNotNone(match_xss("<script>alert(1)</script>",
                                       "<html><script>alert(1)</script></html>"))

    def test_ssrf_rejects_bare_500(self):
        self.assertIsNone(match_ssrf("http://169.254.169.254/", "<html><title>Internal Server Error</title></html>", 500))

    def test_deserialization_rejects_bare_500(self):
        self.assertIsNone(match_deserialization("O:8:stdClass:0:{}", "Internal Server Error", 500))

    def test_nosql_rejects_word_heuristic(self):
        self.assertIsNone(match_nosql_injection('{"$ne":null}', "Login success page with success message", 200))

    def test_ldap_rejects_word_heuristic(self):
        self.assertIsNone(match_ldap_injection("*)(uid=*))(|(uid=*", "Welcome uid=admin page", 200))

    def test_open_redirect_rejects_generic_external(self):
        self.assertIsNone(match_open_redirect("http://evil.com", "", 302, {"Location": "https://legit.com/r"}))
        self.assertIsNotNone(match_open_redirect("http://evil.com", "", 302, {"Location": "http://evil.com/phish"}))

    def test_path_traversal_rejects_html(self):
        self.assertIsNone(match_path_traversal("../../etc/passwd", "<html><head><title>Home</title></head></html>", 200))
        self.assertIsNotNone(match_path_traversal("../../etc/passwd", "root:x:0:0:root:/root:/bin/bash", 200))


class TestScopeGuard(unittest.TestCase):
    def test_allowlist_overrides_block_private(self):
        self.assertTrue(is_url_in_scope("http://10.10.10.5/login", allowlist=["10.10.10.5"], block_private=True))
        self.assertTrue(is_url_in_scope("http://192.168.1.5/api", allowlist=["192.168.1.5"], block_private=True))

    def test_allowlist_non_match(self):
        self.assertFalse(is_url_in_scope("http://10.10.10.6/", allowlist=["10.10.10.5"], block_private=True))

    def test_block_private_without_allowlist(self):
        self.assertFalse(is_url_in_scope("http://10.10.10.5/", allowlist=None, block_private=True))
        self.assertTrue(is_url_in_scope("https://example.com/", allowlist=None, block_private=True))


class TestCollectionIO(unittest.TestCase):
    def test_raw_http_roundtrip_preserves_scheme(self):
        recs = [
            {"method": "POST", "url": "https://app.example.com/login", "headers": {"Content-Type": "application/json"}, "body": b'{"u":"a","p":"b"}'},
            {"method": "GET", "url": "http://app.example.com/api/users?id=1", "headers": {}, "body": b""},
        ]
        f = tempfile.mktemp(suffix=".http")
        collection_io.export_raw_http(recs, f)
        back = collection_io.parse_raw_http_collection(open(f).read())
        self.assertEqual([r["url"] for r in back], [recs[0]["url"], recs[1]["url"]])
        self.assertEqual(back[0]["body"], b'{"u":"a","p":"b"}')
        os.remove(f)

    def test_har_import(self):
        har = {"log": {"entries": [
            {"request": {"method": "POST", "url": "https://x.com/b", "headers": [], "postData": {"text": '{"a":1}'}}},
        ]}}
        f = tempfile.mktemp(suffix=".har")
        open(f, "w").write(json.dumps(har))
        recs = collection_io.import_collection(f)
        self.assertEqual(recs[0]["url"], "https://x.com/b")
        self.assertEqual(recs[0]["body"], b'{"a":1}')
        os.remove(f)

    def test_postman_import_recursive(self):
        pm = {"info": {}, "item": [
            {"name": "f", "item": [
                {"request": {"method": "POST", "url": {"raw": "https://y.com/api"}, "body": {"mode": "raw", "raw": '{"k":"v"}'}}},
            ]},
        ]}
        f = tempfile.mktemp(suffix=".json")
        open(f, "w").write(json.dumps(pm))
        recs = collection_io.import_collection(f)
        self.assertEqual(len(recs), 1)
        self.assertEqual(recs[0]["body"], b'{"k":"v"}')
        os.remove(f)


class TestPayloads(unittest.TestCase):
    def test_idor_uses_numeric_probes(self):
        payloads = load_payloads("idor", safe_mode=True)
        self.assertIn("1", payloads)
        self.assertIn("9999", payloads)
        # не должен тащить SQLi-строки
        self.assertFalse(any("'" in p or "OR 1=1" in p for p in payloads))

    def test_custom_payload_merge(self):
        from pathlib import Path
        custom = Path(__file__).parent.parent / "payloads" / "custom" / "sqli.txt"
        custom.parent.mkdir(parents=True, exist_ok=True)
        custom.write_text("CUSTOM_UNIQUE_PAYLOAD_123\n", encoding="utf-8")
        try:
            payloads = load_payloads("sqli", safe_mode=True)
            self.assertIn("CUSTOM_UNIQUE_PAYLOAD_123", payloads)
        finally:
            custom.unlink()


class TestProjectManager(unittest.TestCase):
    def test_create_and_list(self):
        proj = project_manager.create_project("test_project_xyz")
        self.assertTrue((proj / "reports").is_dir())
        self.assertIn(proj, project_manager.list_projects())
        shutil.rmtree(proj, ignore_errors=True)


class TestSessionManagerSaveLoad(unittest.TestCase):
    def test_roundtrip(self):
        from session_manager import AuthConfig, save_auth_config, load_auth_config
        cfg = AuthConfig(enabled=True, login_url="https://app/login", method="POST",
                         body={"username": "admin", "password": "S3cret!"},
                         content_type="form", unauth_codes={401, 403})
        f = tempfile.mktemp(suffix=".json")
        save_auth_config(cfg, f)
        loaded = load_auth_config(f)
        self.assertIsNotNone(loaded)
        self.assertEqual(loaded.login_url, cfg.login_url)
        self.assertEqual(loaded.body, cfg.body)
        self.assertEqual(loaded.unauth_codes, {401, 403})
        os.remove(f)


class TestPerProjectDB(unittest.TestCase):
    def test_isolation(self):
        p1 = tempfile.mktemp(suffix=".db")
        p2 = tempfile.mktemp(suffix=".db")
        db.set_db_path(p1)
        db.insert_history("GET", "http://a.com/", {}, None, 200, {}, None)
        self.assertEqual(len(db.fetch_history()), 1)
        db.set_db_path(p2)
        self.assertEqual(len(db.fetch_history()), 0)
        os.remove(p1); os.remove(p2)


class TestReportExport(unittest.TestCase):
    def setUp(self):
        self._db = tempfile.mktemp(suffix=".db")
        db.set_db_path(self._db)
        db.insert_scan_result(template_id="t1", worker_id=0, method="GET", url="http://x/a?id=1",
                              status_code=500, error=None, check_type="sqli", payload="'", evidence="SQL error: syntax")
        db.upsert_scan_meta(scan_result_id=1, severity="HIGH", detector="matcher", confidence=0.65, exploitability=0.6, fingerprint="fp")
        db.insert_scan_result(template_id="t2", worker_id=0, method="GET", url="http://x/b",
                              status_code=200, error=None, check_type="cmdi", payload=";id", evidence=None)

    def tearDown(self):
        if os.path.exists(self._db):
            os.remove(self._db)

    def test_md_matrix_and_recommendations(self):
        f = tempfile.mktemp(suffix=".md")
        report_export.export_md(f)
        text = open(f).read()
        self.assertIn("Detection Matrix", text)
        self.assertIn("True", text)
        self.assertIn("False", text)
        self.assertIn("Recommendations", text)
        self.assertIn("Параметризованные", text)  # sqli рекомендация
        os.remove(f)

    def test_json_matrix(self):
        f = tempfile.mktemp(suffix=".json")
        report_export.export_json(f)
        d = json.load(open(f))
        self.assertIn("detection_matrix", d)
        self.assertIn("recommendations", d)
        cmdi = [m for m in d["detection_matrix"] if m["check_type"] == "cmdi"][0]
        self.assertFalse(cmdi["detected"])
        os.remove(f)

    def test_docx_generates(self):
        try:
            import docx  # noqa: F401
        except ImportError:
            self.skipTest("python-docx not installed")
        f = tempfile.mktemp(suffix=".docx")
        report_export.export_docx(f)
        self.assertGreater(os.path.getsize(f), 1000)
        os.remove(f)


class TestJWTCheck(unittest.TestCase):
    def _run(self, headers):
        from checks.registry import reset_registry
        from checks.base import ScanRequest, ScanResponse, CheckContext
        reg = reset_registry()
        chk = reg.get("jwt")
        req = ScanRequest(method="GET", url="http://x/", headers=headers, body=b"", raw_http="")
        resp = ScanResponse(status_code=200, headers={}, text="", elapsed_ms=0.0, error=None)
        ctx = CheckContext(history_id=None, mutation_point="", original_param="", payload="", check_type="passive")
        return chk.check(req, resp, ctx).findings

    @staticmethod
    def _b64url(b):
        import base64
        return base64.urlsafe_b64encode(b).rstrip(b"=").decode()

    @staticmethod
    def _hs256_token(secret, payload):
        import hmac, hashlib
        header = TestJWTCheck._b64url(json.dumps({"alg": "HS256"}).encode())
        body = TestJWTCheck._b64url(json.dumps(payload).encode())
        sig = hmac.new(secret.encode(), f"{header}.{body}".encode(), hashlib.sha256).digest()
        return f"{header}.{body}.{TestJWTCheck._b64url(sig)}"

    def test_weak_secret(self):
        token = self._hs256_token("secret", {"sub": "admin"})
        f = self._run({"Authorization": f"Bearer {token}"})
        self.assertTrue(any("secret" in x.evidence for x in f))

    def test_alg_none(self):
        header = self._b64url(json.dumps({"alg": "none"}).encode())
        body = self._b64url(json.dumps({"sub": "admin"}).encode())
        f = self._run({"Authorization": f"Bearer {header}.{body}."})
        self.assertTrue(any("none" in x.evidence for x in f))

    def test_no_jwt(self):
        self.assertEqual(self._run({}), [])

    def test_strong_secret_no_fp(self):
        token = self._hs256_token("totally-random-strong-key-xyz", {"sub": "admin"})
        self.assertEqual(self._run({"Authorization": f"Bearer {token}"}), [])


class TestPathProbe(unittest.TestCase):
    def test_sensitive_path_detected(self):
        import threading, http.server, socketserver
        class H(http.server.BaseHTTPRequestHandler):
            def do_GET(self):
                if self.path == "/actuator/env":
                    self.send_response(200); self.end_headers(); self.wfile.write(b'{"x":1}')
                else:
                    self.send_response(404); self.end_headers()
            def log_message(self, *a): pass
        srv = socketserver.TCPServer(("127.0.0.1", 0), H)
        port = srv.server_address[1]
        threading.Thread(target=srv.serve_forever, daemon=True).start()
        try:
            db.set_db_path(tempfile.mktemp(suffix=".db"))
            import path_probe
            found = path_probe.run_info_disclosure_scan([f"http://127.0.0.1:{port}/"], log_cb=lambda s: None)
            self.assertEqual(found, 1)
        finally:
            srv.shutdown()
            db.get_db_path().unlink(missing_ok=True)




class TestCRLFMatcher(unittest.TestCase):
    """CRLF/header-injection матчер не должен флагать обычные заголовки."""

    def test_rejects_benign_headers(self):
        # /redirect отражает URL в Location, но это НЕ CRLF-инъекция
        self.assertIsNone(match_crlf_injection(
            "%0d%0aLocation: https://evil.com", "",
            302, {"Location": "/home", "Set-Cookie": "a=b", "Content-Type": "text/html"}))

    def test_detects_marker_header(self):
        self.assertIsNotNone(match_crlf_injection(
            "%0d%0aX-VulnScanner-CRLF-Test: injected", "",
            200, {"X-VulnScanner-CRLF-Test": "injected"}))

    def test_detects_nonstandard_injected_header(self):
        self.assertIsNotNone(match_crlf_injection(
            "%0d%0aX-Custom-Thing: 1", "",
            200, {"X-Custom-Thing": "1"}))

    def test_benign_injected_location_not_flagged(self):
        # Location — обычный заголовок, его наличие не доказывает инъекцию
        self.assertIsNone(match_crlf_injection(
            "%0d%0aLocation: https://evil.com", "",
            302, {"Location": "https://evil.com/phish"}))

    def test_no_headers_returns_none(self):
        self.assertIsNone(match_crlf_injection("%0d%0aX: 1", "body", 200, None))


class TestReportDedup(unittest.TestCase):
    def setUp(self):
        self._db = tempfile.mktemp(suffix=".db")
        db.set_db_path(self._db)
        # Два результата с одинаковым fingerprint и evidence → дубликаты
        for i in (1, 2):
            rid = db.insert_scan_result(
                template_id=f"t{i}", worker_id=0, method="GET",
                url=f"http://x/reflect?q=p{i}", status_code=200, error=None,
                check_type="xss_reflected", payload="<script>", evidence="XSS payload reflected")
            db.upsert_scan_meta(
                scan_result_id=rid, severity="HIGH", detector="matcher",
                confidence=0.65, exploitability=0.6, fingerprint="samefp")

    def tearDown(self):
        if os.path.exists(self._db):
            os.remove(self._db)

    def test_dedup_collapses_by_fingerprint(self):
        data = report_export._build_report_data(limit=100)
        self.assertEqual(data["findings_raw_count"], 2)
        self.assertEqual(data["findings_count"], 1)
        self.assertEqual(data["findings"][0]["occurrences"], 2)
        self.assertTrue(data["deduplicated"])

    def test_no_dedup_keeps_all(self):
        data = report_export._build_report_data(limit=100, deduplicate=False)
        self.assertEqual(data["findings_count"], 2)
        self.assertFalse(data["deduplicated"])

    def test_export_md_returns_unique_count(self):
        f = tempfile.mktemp(suffix=".md")
        n = report_export.export_md(f)
        self.assertEqual(n, 1)
        self.assertIn("| 2 |", open(f).read())  # Count column shows occurrences
        os.remove(f)


if __name__ == "__main__":
    unittest.main()
