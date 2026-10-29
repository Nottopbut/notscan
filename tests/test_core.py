import unittest

import scanner_core
import contract_inference


class TestEvidenceDiff(unittest.TestCase):
    def test_diff_snippet_contains_markers(self):
        base = "a\nb\nc\n"
        mut = "a\nb\nc2\n"
        diff = scanner_core.build_unified_diff_snippet(base, mut, context_lines=1, max_lines=50)
        self.assertIn("--- baseline", diff)
        self.assertIn("+++ mutated", diff)
        self.assertIn("-c", diff)
        self.assertIn("+c2", diff)


class TestRedaction(unittest.TestCase):
    def test_redact_headers(self):
        raw = "GET / HTTP/1.1\nAuthorization: Bearer abc\nCookie: a=b\nX-Api-Key: 123\n\nbody"
        red = scanner_core.redact_raw_http(raw)
        self.assertIn("Authorization: ***REDACTED***", red)
        self.assertIn("Cookie: ***REDACTED***", red)
        self.assertIn("X-Api-Key: ***REDACTED***", red)
        self.assertNotIn("abc", red)
        self.assertNotIn("a=b", red)
        self.assertNotIn("123", red)


class TestFingerprint(unittest.TestCase):
    def test_fingerprint_stable(self):
        fp1 = scanner_core._fingerprint_for_result("https://example.com/a?x=1", "sqli", "id")
        fp2 = scanner_core._fingerprint_for_result("https://example.com/a?x=2", "sqli", "id")
        self.assertEqual(fp1, fp2)


class TestContractInference(unittest.TestCase):
    def test_normalize_url_pattern(self):
        self.assertEqual(contract_inference.normalize_url_pattern("https://x/api/users/123"), "/api/users/{int}")
        self.assertEqual(
            contract_inference.normalize_url_pattern("http://x/api/items/550e8400-e29b-41d4-a716-446655440000"),
            "/api/items/{uuid}",
        )
        self.assertEqual(
            contract_inference.normalize_url_pattern("http://x/api/posts/hello-world?x=1&y=2"),
            "/api/posts/{slug}",
        )

    def test_infer_param_type(self):
        self.assertEqual(contract_inference.infer_param_type("id", "123"), "int")
        self.assertEqual(contract_inference.infer_param_type("price", "12.34"), "float")
        self.assertEqual(contract_inference.infer_param_type("email", "a@b.com"), "email")
        self.assertEqual(contract_inference.infer_param_type("next", "https://example.com/"), "url")
        self.assertEqual(contract_inference.infer_param_type("enabled", "true"), "bool")
        self.assertEqual(contract_inference.infer_param_type("q", '{"a":1}'), "json")


if __name__ == "__main__":
    unittest.main()

