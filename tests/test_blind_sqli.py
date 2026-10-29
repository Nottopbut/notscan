"""
tests/test_blind_sqli.py — boolean-based blind SQLi (sqli_blind).

Покрывает:
  • формат payload-файла `sqli_blind.txt` («true ||| false», парсер);
  • компаратор `scanner_core.evaluate_blind_pair` — TP (status-diff, body-diff
    с baseline в обе стороны) и FP (одинаковые ответы, body-diff без baseline,
    эхо payload'а, «плавающие» ответы, одинаковые 4xx/5xx);
  • `build_scan_tasks` — пары для query/form/json мутаций, готовые
    pair_url/pair_headers/pair_body, safe_mode, обратная совместимость ScanTask;
  • async-воркер — реальные два запроса, evidence/scan_meta detector="blind",
    одна строка scan_results на пару, отсутствие детекта при ошибке второго
    запроса;
  • регистрация чека: catalog ↔ registry ↔ WSTG-карта.

Тесты быстрые: локальный ThreadingHTTPServer на 127.0.0.1:0, короткие
payload-наборы через monkeypatch scanner_core.load_payloads.
"""

from __future__ import annotations

import http.server
import json
import socketserver
import threading
import urllib.parse
from pathlib import Path

import pytest

import db
import scanner_core
from checks.catalog import get as catalog_get, wstg_id_for
from checks.registry import get_registry
from tests.lab.server import BLIND_FALSE_MARKERS, BLIND_TRUE_MARKERS

PAYLOADS_FILE = Path(__file__).resolve().parent.parent / "payloads" / "sqli_blind.txt"


# ══════════════════════════════════════════════════════════════════
#  Стаб-сервер: /blind (boolean SQLi), /safe, /echo
# ══════════════════════════════════════════════════════════════════


def _classify_blind(value: str) -> str:
    lowered = (value or "").lower()
    if any(marker in lowered for marker in BLIND_FALSE_MARKERS):
        return "false"
    if any(marker in lowered for marker in BLIND_TRUE_MARKERS):
        return "true"
    return "normal"


class _BlindHandler(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def _send(self, status: int, text: str) -> None:
        body = text.encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self) -> None:  # noqa: N802
        parsed = urllib.parse.urlsplit(self.path)
        qs = urllib.parse.parse_qs(parsed.query, keep_blank_values=True)
        with self.server.lock:  # type: ignore[attr-defined]
            self.server.counts[parsed.path] = self.server.counts.get(parsed.path, 0) + 1  # type: ignore[attr-defined]
        if parsed.path == "/blind":
            value = (qs.get("id") or [""])[0]
            state = _classify_blind(value)
            if state == "false":
                self._send(404, "<html><body><h1>User not found</h1></body></html>")
            elif state == "true":
                self._send(200, "<html><body><h1>User found: admin</h1></body></html>")
            else:
                self._send(200, "<html><body><h1>User: admin</h1></body></html>")
        elif parsed.path == "/safe":
            self._send(200, "<html><body><h1>Safe page</h1><p>No reflection.</p></body></html>")
        elif parsed.path == "/echo":
            value = (qs.get("q") or [""])[0]
            self._send(200, f"<html><body>You searched: {value}</body></html>")
        else:
            self._send(200, "<html><body>ok</body></html>")

    def log_message(self, *args) -> None:  # noqa: D401 - тишина
        pass


class _StubServer(socketserver.ThreadingTCPServer):
    daemon_threads = True
    allow_reuse_address = True


@pytest.fixture()
def stub_server():
    server = _StubServer(("127.0.0.1", 0), _BlindHandler)
    server.counts = {}  # type: ignore[attr-defined]
    server.lock = threading.Lock()  # type: ignore[attr-defined]
    threading.Thread(target=server.serve_forever, daemon=True).start()
    server.base_url = f"http://127.0.0.1:{server.server_address[1]}"  # type: ignore[attr-defined]
    try:
        yield server
    finally:
        server.shutdown()
        server.server_close()


@pytest.fixture()
def tmp_db(tmp_path: Path):
    db_path = tmp_path / "blind-test.db"
    db.set_db_path(db_path)
    yield db_path
    db.set_db_path(tmp_path / "blind-test-closed.db")
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
    resp_status: int = 200,
    resp_body_preview: bytes = b"",
) -> int:
    return db.insert_history(
        method, url, headers or {}, body, resp_status, {}, resp_body_preview
    )


def _run(tasks, *, workers: int = 4):
    runner = scanner_core.ScannerRunner(
        tasks,
        workers=workers,
        log_callback=lambda _m: None,
        scope_allowlist=["127.0.0.1"],
    )
    runner.start()
    runner.wait()
    return runner


def _meta_for(result_id: int) -> dict:
    rows = db.fetch_scan_results_with_meta(limit=1000)
    row = next((r for r in rows if r["id"] == result_id), None)
    assert row is not None
    with db.get_conn() as conn:
        meta = conn.execute(
            "SELECT * FROM scan_meta WHERE scan_result_id=?", (result_id,)
        ).fetchone()
    return dict(meta) if meta else {}


# ══════════════════════════════════════════════════════════════════
#  1. Payload-файл и парсер пар
# ══════════════════════════════════════════════════════════════════

class TestPayloadFile:
    def test_file_exists_with_pairs(self):
        assert PAYLOADS_FILE.exists(), "payloads/sqli_blind.txt отсутствует"
        pairs = scanner_core.load_payloads("sqli_blind", safe_mode=False)
        assert len(pairs) >= 20, f"слишком мало пар: {len(pairs)}"
        parsed = [scanner_core.parse_blind_payload(p) for p in pairs]
        assert all(parsed), "все строки должны быть парами true ||| false"

    def test_true_and_false_differ(self):
        for line in scanner_core.load_payloads("sqli_blind", safe_mode=False):
            true_payload, false_payload = scanner_core.parse_blind_payload(line)
            assert true_payload != false_payload

    def test_boolean_conditions_only_no_destructive(self):
        for line in scanner_core.load_payloads("sqli_blind", safe_mode=False):
            true_payload, false_payload = scanner_core.parse_blind_payload(line)
            assert not scanner_core._is_destructive_payload(true_payload)
            assert not scanner_core._is_destructive_payload(false_payload)

    def test_parser_rejects_invalid_lines(self):
        assert scanner_core.parse_blind_payload("") is None
        assert scanner_core.parse_blind_payload("1 AND 1=1") is None
        assert scanner_core.parse_blind_payload("1 AND 1=1 |||") is None
        assert scanner_core.parse_blind_payload("||| 1 AND 1=2") is None
        assert scanner_core.parse_blind_payload("1=1 ||| 1=1") is None
        # комментарии/пустые строки отфильтрованы load_payloads
        assert all(not p.startswith("#") for p in scanner_core.load_payloads("sqli_blind"))


# ══════════════════════════════════════════════════════════════════
#  2. Компаратор evaluate_blind_pair
# ══════════════════════════════════════════════════════════════════

class TestEvaluateBlindPair:
    def test_tp_status_diff_without_baseline(self):
        result = scanner_core.evaluate_blind_pair(
            true_status=200,
            true_text="<html><h1>User found: admin</h1></html>",
            false_status=404,
            false_text="<html><h1>User not found</h1></html>",
        )
        assert result is not None
        assert result.confidence == 0.7
        assert "Blind SQLi (boolean)" in result.evidence
        assert "status 200 vs 404" in result.evidence
        assert "no baseline: status-diff only" in result.evidence

    def test_tp_body_diff_baseline_matches_true(self):
        result = scanner_core.evaluate_blind_pair(
            true_status=200,
            true_text="<html><body><h1>User found: admin</h1><p>details ...</p></body></html>",
            false_status=200,
            false_text="<html><body><h1>User not found</h1></body></html>",
            baseline_text="<html><body><h1>User: admin</h1><p>details ...</p></body></html>",
            baseline_status=200,
        )
        assert result is not None, "true-ответ, совпадающий с baseline, должен детектиться"
        assert result.confidence == 0.55
        assert "true matches baseline" in result.evidence

    def test_tp_body_diff_baseline_matches_false(self):
        # Baseline = «пустая» страница (как в ТЗ): false-ответ похож на baseline.
        result = scanner_core.evaluate_blind_pair(
            true_status=200,
            true_text="<html><body><h1>User found: admin</h1><p>full record</p></body></html>",
            false_status=200,
            false_text="<html><body><h1>User not found</h1></body></html>",
            baseline_text="<html><body><h1>User not found</h1></body></html>",
            baseline_status=200,
        )
        assert result is not None
        assert "false matches baseline" in result.evidence

    def test_fp_identical_responses(self):
        same = "<html><body><h1>Same page</h1></body></html>"
        assert scanner_core.evaluate_blind_pair(
            true_status=200, true_text=same, false_status=200, false_text=same,
            baseline_text=same, baseline_status=200,
        ) is None

    def test_fp_body_diff_without_baseline(self):
        # Без baseline body-diff сам по себе — не находка (только status-diff).
        assert scanner_core.evaluate_blind_pair(
            true_status=200,
            true_text="<html><body>completely different page A</body></html>",
            false_status=200,
            false_text="<html><body>another long page B with other content</body></html>",
        ) is None

    def test_fp_echo_only_difference(self):
        payload_true = "1 AND 1=1"
        payload_false = "1 AND 1=2"
        true_text = f"<html><body>You searched: {payload_true}</body></html>"
        false_text = f"<html><body>You searched: {payload_false}</body></html>"
        assert scanner_core.evaluate_blind_pair(
            true_status=200,
            true_text=true_text,
            false_status=200,
            false_text=false_text,
            payload_true=payload_true,
            payload_false=payload_false,
            baseline_text="<html><body>You searched: hello</body></html>",
            baseline_status=200,
        ) is None

    def test_fp_floating_responses(self):
        # true/false одинаково похожи на baseline, нет статус-паттерна → FP
        base = "<html><body><h1>Welcome</h1><p>random content 12345</p></body></html>"
        true_text = "<html><body><h1>Welcome</h1><p>random content 67890</p></body></html>"
        false_text = "<html><body><h1>Welcome</h1><p>random content 11111</p></body></html>"
        assert scanner_core.evaluate_blind_pair(
            true_status=200, true_text=true_text,
            false_status=200, false_text=false_text,
            baseline_text=base, baseline_status=200,
        ) is None

    def test_fp_same_4xx(self):
        assert scanner_core.evaluate_blind_pair(
            true_status=403,
            true_text="<html><body>Forbidden</body></html>",
            false_status=403,
            false_text="<html><body>Forbidden: blocked by WAF</body></html>",
            baseline_text="<html><body>Forbidden</body></html>",
            baseline_status=403,
        ) is None

    def test_missing_status_is_not_detected(self):
        assert scanner_core.evaluate_blind_pair(
            true_status=None, true_text="a", false_status=200, false_text="b"
        ) is None
        assert scanner_core.evaluate_blind_pair(
            true_status=200, true_text="a", false_status=None, false_text="b"
        ) is None


# ══════════════════════════════════════════════════════════════════
#  3. build_scan_tasks: пары для разных мутаций
# ══════════════════════════════════════════════════════════════════

class TestBuildScanTasks:
    PAIRS = [
        "1 AND 1=1 ||| 1 AND 1=2",
        "1 AND 2=2 ||| 1 AND 2=3",
        "' AND '1'='1 ||| ' AND '1'='2",
    ]

    def _build(self, history_ids, monkeypatch, **kwargs):
        monkeypatch.setattr(
            scanner_core, "load_payloads", _fake_load_payloads({"sqli_blind": self.PAIRS})
        )
        return scanner_core.build_scan_tasks(history_ids, ["sqli_blind"], **kwargs)

    def test_pairs_for_query_form_json(self, tmp_db, monkeypatch):
        h_query = _insert_history("GET", "http://example.test/item?id=1&name=alice")
        h_form = _insert_history(
            "POST", "http://example.test/form",
            headers={"Content-Type": "application/x-www-form-urlencoded"},
            body=b"username=alice&x=1",
        )
        h_json = _insert_history(
            "POST", "http://example.test/api",
            headers={"Content-Type": "application/json"},
            body=b'{"name": "alice"}',
        )
        tasks = self._build([h_query, h_form, h_json], monkeypatch)
        assert tasks, "нет blind-задач"
        assert all(t.check_type == "sqli_blind" for t in tasks)
        assert all(t.is_pair for t in tasks), "все blind-задачи должны быть парами"
        # 2 query-параметра + 2 form-поля + 1 json-поле = 5 мутаций × пары
        # + path-сегмент в каждом из 3 URL (item/form/api) × пары
        assert len(tasks) == (2 + 2 + 1 + 3) * len(self.PAIRS)

        for task in tasks:
            assert task.pair_payload
            assert task.pair_payload != task.payload
            assert task.pair_url
            assert "content-length" not in {k.lower() for k in task.pair_headers}
            # false-запрос отличается только payload'ом
            if task.mutation_point == "query":
                assert task.pair_url != task.url
                assert urllib.parse.quote(task.payload, safe="") in task.url
                assert urllib.parse.quote(task.pair_payload, safe="") in task.pair_url
            elif task.mutation_point == "body_form":
                assert task.payload.encode() in task.body
                assert task.pair_payload.encode() in task.pair_body
            elif task.mutation_point == "body_json":
                true_obj = json.loads(task.body.decode("utf-8"))
                false_obj = json.loads(task.pair_body.decode("utf-8"))
                assert task.payload in json.dumps(true_obj, ensure_ascii=False)
                assert task.pair_payload in json.dumps(false_obj, ensure_ascii=False)

    def test_safe_mode_filters_destructive_pairs(self, tmp_db, monkeypatch):
        h = _insert_history("GET", "http://example.test/item?id=1")
        bad_pairs = ["1=1; DROP TABLE users ||| 1=1; DELETE FROM users"]
        monkeypatch.setattr(
            scanner_core, "load_payloads", _fake_load_payloads({"sqli_blind": bad_pairs})
        )
        safe_tasks = scanner_core.build_scan_tasks([h], ["sqli_blind"], safe_mode=True)
        assert safe_tasks == [], "safe_mode должен отбросить деструктивные пары"
        unsafe_tasks = scanner_core.build_scan_tasks([h], ["sqli_blind"], safe_mode=False)
        assert len(unsafe_tasks) == 2  # query + path

    def test_scan_task_backward_compatibility(self):
        task = scanner_core.ScanTask(
            template_id="t",
            check_type="sqli",
            payload="'",
            method="GET",
            url="http://example.test/?id='",
            headers={},
            body=b"",
            raw_http="",
            mutation_point="query",
            original_param="id",
        )
        assert task.pair_payload == ""
        assert task.pair_url == ""
        assert task.pair_headers == {}
        assert task.pair_body == b""
        assert task.is_pair is False


# ══════════════════════════════════════════════════════════════════
#  4. Async-воркер: два запроса на пару + detector="blind"
# ══════════════════════════════════════════════════════════════════

class TestAsyncWorkerBlind:
    PAIRS = [
        "1 AND 1=1 ||| 1 AND 1=2",
        "1 AND 2=2 ||| 1 AND 2=3",
        "' AND '1'='1 ||| ' AND '1'='2",
    ]

    def test_detects_blind_and_persists_detector(self, stub_server, tmp_db, monkeypatch):
        monkeypatch.setattr(
            scanner_core, "load_payloads", _fake_load_payloads({"sqli_blind": self.PAIRS})
        )
        hid = _insert_history(
            "GET",
            f"{stub_server.base_url}/blind?id=1",
            resp_status=200,
            resp_body_preview=b"<html><body><h1>User: admin</h1></body></html>",
        )
        tasks = scanner_core.build_scan_tasks([hid], ["sqli_blind"], do_path=False)
        assert len(tasks) == len(self.PAIRS)

        _run(tasks)

        rows = db.fetch_scan_results_with_meta(limit=1000)
        assert len(rows) == len(tasks), "должна быть ОДНА строка на пару"
        assert all(r["evidence"] for r in rows), "blind-находки не сохранены"
        for row in rows:
            assert "Blind SQLi (boolean)" in row["evidence"]
            meta = _meta_for(row["id"])
            assert meta.get("detector") == "blind", meta
            assert float(meta.get("confidence") or 0) >= 0.7
            assert meta.get("severity") == "HIGH"
        # Каждая пара = два запроса к /blind.
        assert stub_server.counts.get("/blind", 0) == 2 * len(tasks)

    def test_no_fp_on_static_page(self, stub_server, tmp_db, monkeypatch):
        monkeypatch.setattr(
            scanner_core, "load_payloads", _fake_load_payloads({"sqli_blind": self.PAIRS})
        )
        hid = _insert_history(
            "GET",
            f"{stub_server.base_url}/safe?id=1",
            resp_status=200,
            resp_body_preview=b"<html><body><h1>Safe page</h1></body></html>",
        )
        tasks = scanner_core.build_scan_tasks([hid], ["sqli_blind"])
        assert tasks
        _run(tasks)
        rows = db.fetch_scan_results_with_meta(limit=1000)
        assert len(rows) == len(tasks)
        assert all(not r["evidence"] for r in rows), (
            f"FP на статичной странице: {[r['evidence'] for r in rows if r['evidence']]}"
        )

    def test_second_request_error_no_detection(self, stub_server, tmp_db, monkeypatch):
        monkeypatch.setattr(
            scanner_core, "load_payloads", _fake_load_payloads({"sqli_blind": self.PAIRS[:1]})
        )
        hid = _insert_history(
            "GET",
            f"{stub_server.base_url}/blind?id=1",
            resp_status=200,
            resp_body_preview=b"<html><body><h1>User: admin</h1></body></html>",
        )
        tasks = scanner_core.build_scan_tasks([hid], ["sqli_blind"], do_path=False)
        assert len(tasks) == 1
        task = tasks[0]
        # false-запрос уводим на закрытый порт → transport error
        import socket

        s = socket.socket()
        s.bind(("127.0.0.1", 0))
        closed_port = s.getsockname()[1]
        s.close()
        task.pair_url = f"http://127.0.0.1:{closed_port}/blind?id=1"
        _run(tasks)
        rows = db.fetch_scan_results_with_meta(limit=1000)
        assert len(rows) == 1
        assert rows[0]["evidence"] is None
        assert rows[0]["status_code"] == 200


# ══════════════════════════════════════════════════════════════════
#  5. Регистрация чека: каталог ↔ registry ↔ WSTG
# ══════════════════════════════════════════════════════════════════

def test_catalog_and_registry_registration():
    defn = catalog_get("sqli_blind")
    assert defn is not None
    assert defn.kind == "active"
    assert defn.category == "Injection"
    assert defn.severity == "HIGH"
    assert defn.cwe == "CWE-89"
    assert defn.payload_file == "sqli_blind.txt"
    assert wstg_id_for("sqli_blind") == "WSTG-INPV-05"

    check = get_registry().get("sqli_blind")
    assert check is not None
    assert check.check_id == "sqli_blind"
    assert check.vuln_type == "sqli_blind"
    assert check.requires_payload is True
    assert check.severity.value == "HIGH"


def test_load_payloads_uses_catalog_file():
    payloads = scanner_core.load_payloads("sqli_blind", safe_mode=True)
    assert payloads, "catalog.payload_file_for('sqli_blind') должен вести на файл"
    assert all("|||" in line for line in payloads)


# ══════════════════════════════════════════════════════════════════
#  FP-guard: статусы "шлюзов" (WAF/auth/rate-limit) — не boolean-blind
# ══════════════════════════════════════════════════════════════════


def test_gate_status_not_blind_with_baseline():
    """200 vs 403/401/429 при нормальном baseline — это WAF/сессия, не blind."""
    for gated in (401, 403, 406, 418, 429):
        assert gated in scanner_core.BLIND_GATE_STATUSES
        # gated = false-ответ
        res = scanner_core.evaluate_blind_pair(
            true_status=200, true_text="<html>admin panel size 1000</html>",
            false_status=gated, false_text="<html>blocked</html>",
            payload_true="' AND 1=1-- -", payload_false="' AND 1=2-- -",
            baseline_text="<html>admin panel size 1000</html>", baseline_status=200,
        )
        assert res is None, f"200 vs {gated}: ожидался FP-guard"
        # gated = true-ответ
        res = scanner_core.evaluate_blind_pair(
            true_status=gated, true_text="<html>blocked</html>",
            false_status=200, false_text="<html>admin panel size 1000</html>",
            payload_true="' AND 1=1-- -", payload_false="' AND 1=2-- -",
            baseline_text="<html>admin panel size 1000</html>", baseline_status=200,
        )
        assert res is None, f"{gated} vs 200: ожидался FP-guard"


def test_gate_status_without_baseline_not_blind():
    """Без baseline 200 vs 403 тоже не должен давать blind-находку."""
    for gated in (401, 403, 429):
        res = scanner_core.evaluate_blind_pair(
            true_status=200, true_text="ok page",
            false_status=gated, false_text="blocked",
            payload_true="' AND 1=1-- -", payload_false="' AND 1=2-- -",
        )
        assert res is None


def test_gate_status_matching_baseline_still_detected():
    """Если сам baseline — gated-статус (например 403), статус-паттерн валиден."""
    res = scanner_core.evaluate_blind_pair(
        true_status=403, true_text="<html>blocked page</html>",
        false_status=200, false_text="<html>admin panel size 1000</html>",
        payload_true="' AND 1=1-- -", payload_false="' AND 1=2-- -",
        baseline_text="<html>blocked page</html>", baseline_status=403,
    )
    assert res is not None


def test_error_error_pairs_not_blind_without_baseline():
    """500 vs 502 без baseline — WAF/upstream, не boolean-blind SQLi (FP-guard)."""
    res = scanner_core.evaluate_blind_pair(
        true_status=500, true_text="Internal Server Error",
        false_status=502, false_text="Bad Gateway",
        payload_true="' AND 1=1-- -", payload_false="' AND 1=2-- -",
    )
    assert res is None


def test_one_success_side_still_detected_without_baseline():
    """200 vs 500 без baseline: одна сторона 2xx — статус-дифф допустим."""
    res = scanner_core.evaluate_blind_pair(
        true_status=200, true_text="<html>admin panel size 1000</html>",
        false_status=500, false_text="<html>oops</html>",
        payload_true="' AND 1=1-- -", payload_false="' AND 1=2-- -",
    )
    assert res is not None


def test_server_error_side_vs_baseline_not_blind():
    """baseline 200 + false 502 — серверная ошибка на одной стороне, не blind."""
    res = scanner_core.evaluate_blind_pair(
        true_status=200, true_text="<html>admin panel size 1000</html>",
        false_status=502, false_text="<html>bad gateway</html>",
        payload_true="' AND 1=1-- -", payload_false="' AND 1=2-- -",
        baseline_text="<html>admin panel size 1000</html>", baseline_status=200,
    )
    assert res is None
