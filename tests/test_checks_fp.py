"""
tests/test_checks_fp.py — FP отражений: XSS / HTML injection / SSI.

Проблема пользователя: «много FP, когда часть запроса просто рефлектится в
теле». Правила:
  • XSS — только DIRECT (неэкранированное) отражение payload'а в HTML-ответе;
    URL-encoded эхо (%3Cscript%3E) НЕ XSS: браузер не percent-декодирует HTML;
    HTML-escaped (&lt;script&gt;), JSON/plain-ответы, baseline-эхо — не находки;
  • HTML injection — только реальный неэкранированный маркерный HTML-тег
    в HTML-ответе (не «payload отражён verbatim»);
  • SSI — только SSI-ошибка или реальное исполнение директивы (вывод
    date/printenv/exec/маркер); простое raw/escaped/url-encoded эхо — не находка.

Без сети: только синтетические ScanRequest/ScanResponse.
"""

from __future__ import annotations

import html
import json
import urllib.parse

import pytest

import scanner_core
from checks.base import CheckContext, ScanRequest, ScanResponse
from checks.client_side import XSSReflectedCheck
from checks.injections import html_injection_indicator, ssi_indicator

HTML_HEADERS = {"Content-Type": "text/html; charset=utf-8"}
JSON_HEADERS = {"Content-Type": "application/json"}
TEXT_HEADERS = {"Content-Type": "text/plain"}

XSS_PAYLOAD = "<script>alert(1)</script>"
XSS_ALT_PAYLOAD = "<img src=x onerror=alert(1)>"
HTML_MARKER_PAYLOAD = '<h1 notscan=7>HTMLINJ_MARKER</h1>'
SSI_PAYLOAD = '<!--#echo var="DATE_LOCAL" -->'


def _req(url: str = "http://x/q?q=1") -> ScanRequest:
    return ScanRequest(method="GET", url=url, headers={}, body=b"", raw_http="")


def _resp(text: str, headers: dict | None = None) -> ScanResponse:
    return ScanResponse(
        status_code=200,
        headers=dict(headers or {}),
        text=text,
        elapsed_ms=1.0,
        error=None,
    )


def _xss_findings(payload: str, text: str, headers: dict | None = None,
                  baseline_text: str = ""):
    ctx = CheckContext(
        payload=payload, check_type="xss_reflected", baseline_text=baseline_text
    )
    return XSSReflectedCheck().check(_req(), _resp(text, headers), ctx).findings


# ══════════════════════════════════════════════════════════════════
#  XSSReflectedCheck
# ══════════════════════════════════════════════════════════════════


class TestXSSReflectedCheckFP:
    def test_direct_reflection_in_html_is_finding(self):
        findings = _xss_findings(
            XSS_PAYLOAD, f"<html><body>echo: {XSS_PAYLOAD}</body></html>", HTML_HEADERS
        )
        assert len(findings) == 1
        assert findings[0].vuln_type == "xss_reflected"

    def test_img_onerror_direct_is_finding(self):
        findings = _xss_findings(
            XSS_ALT_PAYLOAD, f"<html><body>{XSS_ALT_PAYLOAD}</body></html>", HTML_HEADERS
        )
        assert len(findings) == 1

    def test_html_escaped_reflection_not_finding(self):
        escaped = html.escape(XSS_PAYLOAD)
        findings = _xss_findings(
            XSS_PAYLOAD, f"<html><body>{escaped}</body></html>", HTML_HEADERS
        )
        assert findings == []

    def test_url_encoded_reflection_not_finding(self):
        """Percent-encoded эхо в HTML — главный FP: браузер его не декодирует."""
        encoded = urllib.parse.quote(XSS_PAYLOAD, safe="")
        text = f'<html><body><a href="/search?q={encoded}">back</a></body></html>'
        assert _xss_findings(XSS_PAYLOAD, text, HTML_HEADERS) == []

    def test_json_response_not_finding(self):
        text = json.dumps({"echo": XSS_PAYLOAD})
        assert _xss_findings(XSS_PAYLOAD, text, JSON_HEADERS) == []
        # прямой payload в JSON-строке тоже не исполняется как HTML
        assert _xss_findings(XSS_PAYLOAD, text, {"content-type": "application/json"}) == []

    def test_plain_text_response_not_finding(self):
        assert _xss_findings(XSS_PAYLOAD, XSS_PAYLOAD, TEXT_HEADERS) == []

    def test_baseline_echo_not_finding(self):
        text = f"<html><body>{XSS_PAYLOAD}</body></html>"
        assert _xss_findings(XSS_PAYLOAD, text, HTML_HEADERS, baseline_text=text) == []

    def test_bare_html_tag_not_finding(self):
        assert _xss_findings("<body>", "<html><body>hi</body></html>", HTML_HEADERS) == []

    def test_payload_without_metacharacters_not_finding(self):
        assert _xss_findings("alert(1)", "<html>alert(1)</html>", HTML_HEADERS) == []

    def test_partial_reflection_not_finding(self):
        partial = XSS_PAYLOAD[:10]
        assert _xss_findings(XSS_PAYLOAD, f"<html>{partial}</html>", HTML_HEADERS) == []


# ══════════════════════════════════════════════════════════════════
#  match_xss (engine matcher)
# ══════════════════════════════════════════════════════════════════


class TestMatchXssFP:
    def test_direct_reflection_evidence(self):
        evidence = scanner_core.match_xss(
            XSS_PAYLOAD, f"<html><body>{XSS_PAYLOAD}</body></html>", 200, HTML_HEADERS
        )
        assert evidence is not None
        assert "verbatim" in evidence

    def test_direct_reflection_without_headers_still_evidence(self):
        assert scanner_core.match_xss(
            XSS_PAYLOAD, f"<html><body>{XSS_PAYLOAD}</body></html>", 200
        ) is not None

    def test_404_error_page_reflection_not_evidence(self):
        """404/500-страницы часто печатают URL целиком (path-мутации) — не XSS."""
        body = f"<html><body>Not Found: /{XSS_PAYLOAD}?title=x</body></html>"
        assert scanner_core.match_xss(XSS_PAYLOAD, body, 404, HTML_HEADERS) is None
        assert scanner_core.run_matcher("xss", XSS_PAYLOAD, body, 404, HTML_HEADERS) is None
        resp = ScanResponse(status_code=404, headers=dict(HTML_HEADERS),
                            text=body, elapsed_ms=1.0, error=None)
        ctx = CheckContext(payload=XSS_PAYLOAD, check_type="xss_reflected", baseline_text="")
        assert XSSReflectedCheck().check(_req(), resp, ctx).findings == []

    def test_url_encoded_echo_not_evidence(self):
        encoded = urllib.parse.quote(XSS_PAYLOAD, safe="")
        body = f"<html><body><a href='/?q={encoded}'>x</a></body></html>"
        assert scanner_core.match_xss(XSS_PAYLOAD, body, 200, HTML_HEADERS) is None
        assert scanner_core.run_matcher(
            "xss", XSS_PAYLOAD, body, 200, HTML_HEADERS
        ) is None

    def test_html_escaped_echo_not_evidence(self):
        body = f"<html><body>{html.escape(XSS_PAYLOAD)}</body></html>"
        assert scanner_core.match_xss(XSS_PAYLOAD, body, 200, HTML_HEADERS) is None

    def test_json_context_not_evidence(self):
        body = json.dumps({"q": XSS_PAYLOAD})
        assert scanner_core.match_xss(XSS_PAYLOAD, body, 200, JSON_HEADERS) is None
        assert scanner_core.match_xss(XSS_PAYLOAD, body, 200, TEXT_HEADERS) is None

    def test_bare_tag_not_evidence(self):
        assert scanner_core.match_xss(
            "<body>", "<html><body>hi</body></html>", 200, HTML_HEADERS
        ) is None


# ══════════════════════════════════════════════════════════════════
#  HTML injection: только реальный неэкранированный маркерный тег
# ══════════════════════════════════════════════════════════════════


class TestHtmlInjectionFP:
    def test_real_marker_tag_is_finding(self):
        evidence = html_injection_indicator(
            HTML_MARKER_PAYLOAD, f"<html><body>{HTML_MARKER_PAYLOAD}</body></html>",
            HTML_HEADERS,
        )
        assert evidence is not None
        assert "неэкранированным" in evidence or "HTML" in evidence

    def test_escaped_marker_not_finding(self):
        escaped = f"<html><body>{html.escape(HTML_MARKER_PAYLOAD)}</body></html>"
        assert html_injection_indicator(HTML_MARKER_PAYLOAD, escaped, HTML_HEADERS) is None

    def test_url_encoded_marker_not_finding(self):
        encoded = urllib.parse.quote(HTML_MARKER_PAYLOAD, safe="")
        assert html_injection_indicator(
            HTML_MARKER_PAYLOAD, f"<html><body>{encoded}</body></html>", HTML_HEADERS
        ) is None

    def test_json_response_not_finding(self):
        body = json.dumps({"q": HTML_MARKER_PAYLOAD})
        assert html_injection_indicator(HTML_MARKER_PAYLOAD, body, JSON_HEADERS) is None

    def test_plain_echo_without_marker_not_finding(self):
        # payload без маркерного тега — вообще не HTML-injection кандидат
        assert html_injection_indicator(
            "просто текст", "<html><body>просто текст</body></html>", HTML_HEADERS
        ) is None

    def test_echo_only_without_tag_not_finding(self):
        payload = "notscan=7 Hello"
        assert html_injection_indicator(
            payload, f"<html><body>{payload}</body></html>", HTML_HEADERS
        ) is None

    def test_matcher_uses_same_rules(self):
        assert scanner_core.match_html_injection(
            HTML_MARKER_PAYLOAD, f"<html>{HTML_MARKER_PAYLOAD}</html>", 200, HTML_HEADERS
        ) is not None
        assert scanner_core.match_html_injection(
            HTML_MARKER_PAYLOAD,
            json.dumps({"q": HTML_MARKER_PAYLOAD}), 200, JSON_HEADERS,
        ) is None


# ══════════════════════════════════════════════════════════════════
#  SSI: только ошибка/исполнение директивы, не эхо
# ══════════════════════════════════════════════════════════════════


class TestSsiFP:
    def test_ssi_error_signature_is_evidence(self):
        evidence = ssi_indicator(
            SSI_PAYLOAD,
            "<html>[an error occurred while processing this directive]</html>",
            HTML_HEADERS,
        )
        assert evidence is not None
        assert "error" in evidence.lower()

    def test_executed_marker_output_is_evidence(self):
        payload = '<!--#echo var="NOTSCAN_SSI_MARKER" -->'
        evidence = ssi_indicator(
            payload, "<html><body>NOTSCAN_SSI_MARKER</body></html>", HTML_HEADERS
        )
        assert evidence is not None
        assert "executed" in evidence.lower()

    def test_executed_date_output_is_evidence(self):
        evidence = ssi_indicator(
            SSI_PAYLOAD, "<html>Last modified: Monday, 29-Oct-2026 15:00:00</html>",
            HTML_HEADERS,
        )
        assert evidence is not None
        assert "executed" in evidence.lower()

    def test_raw_directive_echo_not_finding(self):
        """Raw-эхо директивы (bWAPP SQL error) — не исполнение, не находка."""
        body = f"<html><body>Error near '{SSI_PAYLOAD}'</body></html>"
        assert ssi_indicator(SSI_PAYLOAD, body, HTML_HEADERS) is None
        assert scanner_core.run_matcher(
            "ssi_injection", SSI_PAYLOAD, body, 200, HTML_HEADERS
        ) is None

    def test_escaped_echo_not_finding(self):
        escaped = f"<html>{html.escape(SSI_PAYLOAD)}</html>"
        assert ssi_indicator(SSI_PAYLOAD, escaped, HTML_HEADERS) is None

    def test_url_encoded_echo_not_finding(self):
        encoded = urllib.parse.quote(SSI_PAYLOAD, safe="")
        assert ssi_indicator(SSI_PAYLOAD, f"<html>{encoded}</html>", HTML_HEADERS) is None

    def test_json_response_not_finding(self):
        body = json.dumps({"q": SSI_PAYLOAD})
        assert ssi_indicator(SSI_PAYLOAD, body, JSON_HEADERS) is None

    def test_non_directive_payload_not_finding(self):
        echo = "<!--#echo var=\"DATE_LOCAL\" -->"
        assert ssi_indicator(echo, f"<html>{echo}</html>", HTML_HEADERS) is None
        assert ssi_indicator("[an error occurred]", "<html>ok</html>", HTML_HEADERS) is None


# ══════════════════════════════════════════════════════════════════
#  Регрессия: реальный reflected XSS не должен ломаться
# ══════════════════════════════════════════════════════════════════


def test_real_reflected_xss_still_detected_through_run_matcher():
    body = f"<html><body>{XSS_PAYLOAD}</body></html>"
    assert scanner_core.run_matcher("xss", XSS_PAYLOAD, body, 200, HTML_HEADERS) is not None
    ctx = CheckContext(payload=XSS_PAYLOAD, check_type="xss_reflected", baseline_text="")
    findings = XSSReflectedCheck().check(_req(), _resp(body, HTML_HEADERS), ctx).findings
    assert len(findings) == 1


@pytest.mark.parametrize("display", ["json", "escaped", "urlencoded", "plain"])
def test_echo_only_variants_never_finding(display):
    encoded = urllib.parse.quote(XSS_PAYLOAD, safe="")
    escaped = html.escape(XSS_PAYLOAD)
    texts = {
        "json": (json.dumps({"q": XSS_PAYLOAD}), JSON_HEADERS),
        "escaped": (f"<html><body>{escaped}</body></html>", HTML_HEADERS),
        "urlencoded": (f"<html><body><a href='/?q={encoded}'>x</a></body></html>", HTML_HEADERS),
        "plain": (XSS_PAYLOAD, TEXT_HEADERS),
    }
    text, headers = texts[display]
    assert scanner_core.match_xss(XSS_PAYLOAD, text, 200, headers) is None
    assert _xss_findings(XSS_PAYLOAD, text, headers) == []
