"""
tests/test_integration_lab.py — интеграционные тесты локальной лабы notscan.

Сквозная цепочка, которую проверяем:

    history (перехваченный запрос) → scanner_core.build_scan_tasks
        → ScannerRunner (start/wait) → scan_results + scan_meta
        → report_export._build_report_data / SQL-проверки

Тесты помечены ``@pytest.mark.integration`` (Makefile: ``make lab``), но
специально быстрые: payload-листы подменяются 2–5 значениями через
``tests/lab/harness.py`` (fake ``scanner_core.load_payloads``), а цель — локальный
``ThreadingHTTPServer`` на 127.0.0.1:0. Полный ручной прогон лабы с реальными
payload-файлами — отдельно (см. README/Makefile).

Покрытие :
  1. TP/FP: /reflect → XSS, /sqli → sqli, /redirect → open_redirect/crlf;
     /search и /safe → НИКАКИХ XSS-находок (регресс бага #4);
  2. Data integrity: findings_raw из отчёта == число evidence-строк в БД;
     limit=None не обрезает выборку (в т.ч. >5000 строк);
  3. JSON-мутация (баг #3): POST /api/user получает только валидный JSON
     (нет 400) и sqli-находка появляется;
  4. Time-based (M5): sqli_time детектится на /sleep и нет на быстрых
     эндпоинтах;
  5. CSRF (M3): свежий токен из session_manager.fetch_csrf_token подставляется
     в мутации POST /form; без токена сервер отвечает 403;
  6. Scope-guard: 302-редиректы не сопровождаются (follow_redirects=False).
"""

from __future__ import annotations

import json

import pytest

import checks.injections as injections
import db
import report_export
import session_manager
from tests.lab import harness
from tests.lab.server import CSRF_TOKEN

pytestmark = pytest.mark.integration

# ── payload-наборы (короткие: прогон — секунды) ────────────────────────────

#: Атакующие XSS-payload'ы для TP на /reflect.
XSS_ATTACK_PAYLOADS = [
    "<script>alert(1)</script>",
    "<img src=x onerror=alert(1)>",
]

#: «Голые» HTML-теги, из-за которых baseline давал FP на /search и /safe
#: (payload `<body>` просто совпадал с тегом в HTML-скелете ответа).
XSS_BARE_TAG_PAYLOADS = ["<body>", "</body>", "<title>"]
XSS_PAYLOADS = XSS_ATTACK_PAYLOADS + XSS_BARE_TAG_PAYLOADS

SQLI_PAYLOADS = ["'", '"', "' OR 1=1--"]
OPEN_REDIRECT_PAYLOADS = ["http://evil.example/", "//evil.example/"]
CRLF_PAYLOADS = ["x\r\nX-VulnScanner-CRLF-Test: injected"]
JSON_SQLI_PAYLOADS = ["' OR 1=1--", '" OR 1=1--']

#: Time-based payload и его порог (сек) — формат checks.injections.SQLI_TIME_PAYLOADS.
SLEEP_PAYLOAD = "' AND randomblob(500000000/1)--"
SLEEP_PAYLOADS = [("lab_sleep_sqlite", SLEEP_PAYLOAD, 0.3, "SQLite")]

#: Быстрый sleep лабы в тестах (по контракту default — 4.0 c).
FAST_SLEEP_SECONDS = 1.5


@pytest.fixture()
def lab(tmp_path):
    """Свежая лаба: свой сервер, своя временная БД, чистый history."""
    env = harness.Lab(tmp_path)
    try:
        yield env
    finally:
        env.close()


# ══════════════════════════════════════════════════════════════════
#  1. TP/FP: /reflect, /sqli, /redirect — находки; /search, /safe — нет
# ══════════════════════════════════════════════════════════════════


def test_tp_xss_sqli_open_redirect_on_vulnerable_endpoints(lab):
    """TP: сырое отражение → XSS, SQL-error → sqli, Location → open_redirect."""
    reflect = lab.add_get("/reflect", {"q": "hello"})
    sqli = lab.add_get("/sqli", {"id": "1"})
    redirect = lab.add_get("/redirect", {"url": "/home"})

    result = lab.build_and_run(
        [reflect, sqli, redirect],
        checks=["xss", "sqli", "open_redirect", "crlf_injection"],
        payloads={
            "xss": XSS_ATTACK_PAYLOADS,
            "sqli": SQLI_PAYLOADS,
            "open_redirect": OPEN_REDIRECT_PAYLOADS,
            "crlf_injection": CRLF_PAYLOADS,
        },
    )

    assert len(result.tasks) > 0
    assert result.has("xss", "/reflect"), (
        "сырой echo на /reflect должен давать XSS-находку; "
        f"evidence={[(r['check_type'], r['url']) for r in result.evidence]}"
    )
    assert result.has("sqli", "/sqli"), "SQL-error на /sqli должен детектиться"
    assert any(
        result.has(check_type, "/redirect")
        for check_type in ("open_redirect", "crlf_injection")
    ), "302 c Location=payload на /redirect должен давать open_redirect/CRLF"


def test_no_xss_fp_on_search_and_safe(lab):
    """FP-регресс бага #4: /search (html.escape) и /safe не дают XSS-находок."""
    search = lab.add_get("/search", {"q": "hello"})
    safe = lab.add_get("/safe", {"q": "hello"})

    result = lab.build_and_run(
        [search, safe],
        checks=["xss"],
        payloads={"xss": XSS_PAYLOADS},
    )

    # Задачи действительно ушли на оба эндпоинта (иначе тест ничего не проверяет).
    assert result.tasks_for_url("/search"), "нет задач на /search"
    assert result.tasks_for_url("/safe"), "нет задач на /safe"

    xss_findings = [
        r for r in result.evidence if (r.get("check_type") or "").lower().startswith("xss")
    ]
    assert xss_findings == [], (
        "на /search и /safe не должно быть XSS (экранирование/скелет — не payload): "
        f"{[(r['check_type'], r['url']) for r in xss_findings]}"
    )


# ══════════════════════════════════════════════════════════════════
#  2. Data integrity: отчёт видит все evidence-строки (limit=None)
# ══════════════════════════════════════════════════════════════════


def test_report_export_sees_all_evidence_rows(lab):
    """_build_report_data(limit=None, deduplicate=False) == COUNT(evidence) в БД."""
    reflect = lab.add_get("/reflect", {"q": "hello"})
    sqli = lab.add_get("/sqli", {"id": "1"})
    redirect = lab.add_get("/redirect", {"url": "/home"})

    result = lab.build_and_run(
        [reflect, sqli, redirect],
        checks=["xss", "sqli", "open_redirect"],
        payloads={
            "xss": XSS_ATTACK_PAYLOADS,
            "sqli": SQLI_PAYLOADS,
            "open_redirect": OPEN_REDIRECT_PAYLOADS,
        },
    )

    evidence_in_db = harness.count_evidence_rows()
    total_in_db = harness.count_scan_rows()
    assert evidence_in_db > 0, "скан не дал ни одной evidence-строки"
    assert len(result.evidence) == evidence_in_db

    # limit=None → без LIMIT: полная выборка, без обрезки.
    data = report_export._build_report_data(limit=None, deduplicate=False)
    assert data["total"] == total_in_db, (
        f"отчёт видит {data['total']} строк из {total_in_db} — данные обрезаны"
    )
    assert data["findings_raw_count"] == evidence_in_db, (
        f"findings_raw={data['findings_raw_count']} != evidence-строк {evidence_in_db}"
    )
    assert {r["id"] for r in data["findings"]} == {r["id"] for r in result.evidence}

    dedup = report_export._build_report_data(limit=None, deduplicate=True)
    assert dedup["findings_raw_count"] == evidence_in_db


def test_report_export_no_truncation_over_5000_rows(lab, tmp_path):
    """limit=None не обрезает выборку и на 6000+ evidence-строках (M2/§13.4)."""
    n_rows = 6001
    rows = [
        (
            float(i),
            f"synth-{i}",
            0,
            "GET",
            f"http://lab.local/synth?id={i}",
            200,
            None,
            "sqli",
            "'",
            "synthetic SQL error evidence",
        )
        for i in range(n_rows)
    ]
    with db.get_conn() as conn:
        conn.executemany(
            """INSERT INTO scan_results
               (time, template_id, worker_id, method, url,
                status_code, error, check_type, payload, evidence)
               VALUES (?,?,?,?,?,?,?,?,?,?)""",
            rows,
        )

    assert harness.count_evidence_rows() == n_rows
    data = report_export._build_report_data(limit=None, deduplicate=False)
    assert data["findings_raw_count"] == n_rows, (
        f"findings_raw={data['findings_raw_count']} из {n_rows} — старый limit=5000?"
    )
    assert data["total"] == n_rows
    exported = report_export._build_report_data(limit=None, deduplicate=False)["findings"]
    assert len(exported) == n_rows

    # Экспорт всех строк без обрезки (JSON как быстрый представитель 5 форматов).
    out_path = tmp_path / "report_6001.json"
    count = report_export.export_json(out_path, limit=None, deduplicate=False)
    assert count == n_rows, f"export_json вернул {count} из {n_rows}"
    payload = json.loads(out_path.read_text(encoding="utf-8"))
    assert payload["summary"]["findings_raw"] == n_rows
    assert payload["summary"]["total"] == n_rows
    assert len(payload["results"]) == n_rows


# ══════════════════════════════════════════════════════════════════
#  3. JSON-мутации (баг #3): тело остаётся валидным JSON
# ══════════════════════════════════════════════════════════════════


def test_json_mutation_stays_valid_and_detected(lab):
    """body_json: кавычки в payload не ломают JSON; сервер не отвечает 400."""
    history_id = lab.add_post(
        "/api/user",
        json.dumps({"name": "alice", "email": "alice@example.com"}),
        content_type="application/json",
    )
    lab.server.reset_log()

    result = lab.build_and_run(
        [history_id],
        checks=["sqli"],
        payloads={"sqli": JSON_SQLI_PAYLOADS},
    )

    api_tasks = [t for t in result.tasks_for_url("/api/user") if t.mutation_point == "body_json"]
    assert api_tasks, "planner не построил body_json-задачи для /api/user"

    # 1) сервер получил ТОЛЬКО валидный JSON (никаких 400 «invalid JSON»).
    assert lab.server.invalid_json_bodies == [], (
        f"сервер получил невалидный JSON: {[b[:80] for b in lab.server.invalid_json_bodies]}"
    )
    api_statuses = lab.server.statuses_for("/api/user", "POST")
    assert api_statuses, "запросы к /api/user не дошли до сервера"
    assert 400 not in api_statuses, f"были 400 на /api/user: {api_statuses}"

    # 2) каждое отправленное тело действительно парсится как JSON.
    for request in lab.server.requests_for("/api/user", "POST"):
        parsed = harness.parse_json_body(request["body"])
        assert isinstance(parsed, dict)

    # 3) и при этом sqli-находка на /api/user есть (name с одинарной кавычкой).
    assert result.has("sqli", "/api/user"), (
        "валидная JSON-мутация с SQL-payload должна дать sqli-находку: "
        f"{[(r['check_type'], r['url']) for r in result.evidence]}"
    )


# ══════════════════════════════════════════════════════════════════
#  4. Time-based blind SQLi (M5): только реальная задержка
# ══════════════════════════════════════════════════════════════════


def test_time_based_sqli_detected_only_on_slow_endpoint(lab, monkeypatch):
    """/sleep (реальная задержка) → sqli_time; быстрый /reflect → нет."""
    sleep_id = lab.add_get("/sleep", {"id": "1"})
    reflect_id = lab.add_get("/reflect", {"q": "hello"})

    # Тест быстрый: лаба спит 1.5 c, порог из подменённого списка payload'ов.
    lab.server.sleep_seconds = FAST_SLEEP_SECONDS
    monkeypatch.setattr(
        injections, "SQLI_TIME_PAYLOADS", SLEEP_PAYLOADS, raising=False
    )

    result = lab.build_and_run(
        [sleep_id, reflect_id],
        checks=["sqli_time"],
        payloads={"sqli_time": [SLEEP_PAYLOAD]},
    )

    sleep_hits = result.findings(check_type="sqli_time", url_contains="/sleep")
    fast_hits = result.findings(check_type="sqli_time", url_contains="/reflect")

    assert sleep_hits, (
        f"задержка {FAST_SLEEP_SECONDS}s на /sleep должна дать sqli_time; "
        f"evidence={[(r['check_type'], r['url'], r['status_code']) for r in result.evidence]}"
    )
    evidence_text = " ".join((r.get("evidence") or "") for r in sleep_hits).lower()
    assert "delay" in evidence_text or "ms" in evidence_text or "sleep" in evidence_text, (
        f"evidence sqli_time должен говорить про задержку: {evidence_text[:200]}"
    )
    assert fast_hits == [], "на быстром /reflect не должно быть sqli_time"


# ══════════════════════════════════════════════════════════════════
#  5. CSRF (M3): свежий токен подставляется в мутации
# ══════════════════════════════════════════════════════════════════


def test_csrf_token_refreshed_for_form_mutations(lab):
    """fetch_csrf_token → build_scan_tasks(csrf_token_provider) → POST /form 200."""
    # История: перехваченный POST формы с УСТАРЕВШИМ csrf-токеном.
    history_id = lab.add_post(
        "/form", "username=alice&password=secret&csrf_token=EXPIRED123"
    )

    # (a) Без провайдера токена: мутации уходят со старым токеном → сервер 403.
    lab.server.reset_log()
    result_without = lab.build_and_run(
        [history_id],
        checks=["sqli"],
        payloads={"sqli": ["'"]},
    )
    assert result_without.tasks_for_url("/form"), "нет body_form-задач на /form"
    post_statuses = lab.server.statuses_for("/form", "POST")
    assert post_statuses, "запросы к /form не дошли до сервера"
    assert all(code == 403 for code in post_statuses), (
        f"без свежего CSRF-токена сервер должен отвечать 403: {post_statuses}"
    )
    assert lab.server.form_accepted_tokens == []

    # (b) Токен реально извлекается из HTML-формы.
    token = session_manager.fetch_csrf_token(lab.base_url + "/form")
    assert token == CSRF_TOKEN, f"fetch_csrf_token вернул {token!r}"

    # (c) С провайдером: токен патчится в мутации → сервер принимает запросы.
    calls = []

    def _provider():
        calls.append(1)
        return token

    lab.server.reset_log()
    result_with = lab.build_and_run(
        [history_id],
        checks=["sqli"],
        payloads={"sqli": ["'"]},
        csrf_token_provider=_provider,
    )
    assert calls, "csrf_token_provider не был вызван движком"
    post_statuses = lab.server.statuses_for("/form", "POST")
    assert post_statuses, "запросы к /form (со свежим токеном) не дошли до сервера"
    assert 403 not in post_statuses, (
        f"со свежим CSRF-токеном сервер не должен отвечать 403: {post_statuses}"
    )
    assert lab.server.form_accepted_tokens, "сервер не принял ни одного CSRF-токена"
    assert set(lab.server.form_accepted_tokens) == {CSRF_TOKEN}
    assert result_with.tasks_for_url("/form")


# ══════════════════════════════════════════════════════════════════
#  6. Scope-guard: 302-редиректы не сопровождаются
# ══════════════════════════════════════════════════════════════════


def test_redirects_are_not_followed(lab):
    """Клиент не идёт по Location (follow_redirects=False), счётчик лабы = 0."""
    history_id = lab.add_get("/redirect", {"url": "/home"})
    follow_target = f"http://127.0.0.1:{lab.server.port}/followed-by-redirect"
    lab.server.reset_log()

    # check_type=sqli — НЕ входит в старый per-check whitelist редиректов,
    # значит отсутствие follow проверяет глобальный scope-guard движка.
    result = lab.build_and_run(
        [history_id],
        checks=["sqli"],
        payloads={"sqli": [follow_target, "'"]},
    )

    assert result.tasks_for_url("/redirect"), "нет задач на /redirect"
    assert lab.server.count("/redirect") > 0, "/redirect не получил запросов"
    assert lab.server.count("/followed-by-redirect") == 0, (
        "клиент сопровождал 302-редирект (scope-guard нарушен); "
        f"paths={lab.server.paths()}"
    )
    assert follow_target.split(str(lab.server.port), 1)[1] not in lab.server.paths()


# ══════════════════════════════════════════════════════════════════
#  Структурные проверки самого harness'а (быстрые, без скана)
# ══════════════════════════════════════════════════════════════════


def test_lab_history_capture_records_real_response(lab):
    """Harness пишет в history реальный baseline-ответ (FP-suppression опирается)."""
    history_id = lab.add_get("/search", {"q": "hello"})
    row = db.fetch_history_by_id(history_id)
    assert row is not None
    assert row["method"] == "GET"
    assert "/search" in row["url"]
    assert row["resp_status"] == 200
    assert b"<body>" in row["resp_body_preview"]  # HTML-скелет попал в baseline


def test_lab_server_request_log_and_csrf_page(lab):
    """GET /form отдаёт страницу с CSRF-токеном; журнал запросов работает."""
    cap = lab.capture("GET", "/form")
    assert cap.status == 200
    assert f'value="{CSRF_TOKEN}"' in cap.response_body.decode("utf-8")
    assert lab.server.requests_for("/form", "GET")
    assert lab.server.count("/form", "GET") >= 1
