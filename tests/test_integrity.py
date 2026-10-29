"""
Data-integrity тесты (M2): полная выборка scan_results без обрезки,
пагинация db/GUI, per-thread кэш соединений sqlite.

Покрывает:
  • db.fetch_scan_results*: limit=None → все строки; offset только с limit;
    пагинация не теряет и не дублирует строки;
  • db.count_scan_results();
  • per-thread кэш get_conn(): одно соединение на поток, сброс при set_db_path
    (в т.ч. для соединений, созданных в других потоках), параллельные записи;
  • report_export: _build_report_data(limit=None) и export_json(limit=None)
    отдают все findings на 6000+ строках; лимит по-прежнему работает;
  • "sqli_time" учитывается в severity/рекомендациях (M5).
"""

import inspect
import json
import os
import sqlite3
import tempfile
import threading
import time
import unittest

import db
import report_export


_COLS = (
    "time, template_id, worker_id, method, url, status_code, error, "
    "check_type, payload, evidence"
)


def _tmp_db_path() -> str:
    return tempfile.mktemp(suffix=".db")


def _remove_db_files(path: str) -> None:
    for suffix in ("", "-wal", "-shm"):
        try:
            os.unlink(path + suffix)
        except OSError:
            pass


def _bulk_insert(n: int, evidence_every: int = 5, check_type: str = "sqli") -> int:
    """Быстро вставляет n сырых строк scan_results в текущую БД."""
    now = time.time()
    rows = [
        (
            now,
            f"hist-{i}-x",
            0,
            "GET",
            f"http://example.com/item?id={i}",
            500 if i % 2 else 200,
            None,
            check_type,
            f"payload-{i}",
            (f"SQL error near input #{i}" if evidence_every and i % evidence_every == 0 else None),
        )
        for i in range(1, n + 1)
    ]
    with db.get_conn() as conn:
        conn.executemany(
            f"INSERT INTO scan_results ({_COLS}) VALUES (?,?,?,?,?,?,?,?,?,?)",
            rows,
        )
    return len(rows)


class _DbTestCase(unittest.TestCase):
    """Общая обвязка: свежая tempfile-БД на каждый тест, чистое закрытие."""

    def setUp(self):
        self._db = _tmp_db_path()
        db.set_db_path(self._db)

    def tearDown(self):
        # Закрываем кэшированные соединения, иначе удаляемые WAL/SHM держатся.
        db._close_all_conns()
        _remove_db_files(self._db)


# ──────────────────────────── db: полная выборка/пагинация ────────────────────────────


class TestFetchScanResults(_DbTestCase):
    def test_limit_none_returns_all_rows(self):
        _bulk_insert(25, evidence_every=0)
        self.assertEqual(db.count_scan_results(), 25)
        self.assertEqual(len(db.fetch_scan_results()), 25)          # default → все
        self.assertEqual(len(db.fetch_scan_results(limit=None)), 25)
        self.assertEqual(len(db.fetch_scan_results_with_meta()), 25)
        self.assertEqual(len(db.fetch_scan_results_with_meta(limit=None)), 25)

    def test_order_by_id_desc_preserved(self):
        _bulk_insert(5, evidence_every=0)
        full = db.fetch_scan_results(limit=None)
        self.assertEqual([r["id"] for r in full], [5, 4, 3, 2, 1])
        with_meta = db.fetch_scan_results_with_meta(limit=None)
        self.assertEqual([r["id"] for r in with_meta], [5, 4, 3, 2, 1])

    def test_pagination_no_loss_no_duplicates(self):
        _bulk_insert(25, evidence_every=0)
        full_ids = [r["id"] for r in db.fetch_scan_results(limit=None)]
        page_size = 10
        paged_ids = []
        offset = 0
        while True:
            page = db.fetch_scan_results(limit=page_size, offset=offset)
            if not page:
                break
            paged_ids.extend(r["id"] for r in page)
            offset += page_size
        self.assertEqual(paged_ids, full_ids)          # те же строки, тот же порядок
        self.assertEqual(len(set(paged_ids)), len(paged_ids))  # без дубликатов

        # with_meta: пагинация тоже ничего не теряет
        paged_meta = []
        for off in (0, 10, 20):
            paged_meta.extend(
                r["id"] for r in db.fetch_scan_results_with_meta(limit=page_size, offset=off)
            )
        self.assertEqual(paged_meta, full_ids)

    def test_offset_without_limit_is_ignored(self):
        _bulk_insert(12, evidence_every=0)
        rows = db.fetch_scan_results(limit=None, offset=7)
        self.assertEqual(len(rows), 12)

    def test_pagination_with_meta_join(self):
        _bulk_insert(6, evidence_every=0)
        for rid in (1, 3, 5):
            db.upsert_scan_meta(scan_result_id=rid, severity="HIGH", fingerprint=f"fp{rid}")
        page = db.fetch_scan_results_with_meta(limit=2, offset=1)
        self.assertEqual(len(page), 2)
        self.assertTrue(all("severity" in r for r in page))

    def test_count_scan_results(self):
        self.assertEqual(db.count_scan_results(), 0)
        _bulk_insert(7, evidence_every=0)
        self.assertEqual(db.count_scan_results(), 7)
        db.delete_scan_result(7)
        self.assertEqual(db.count_scan_results(), 6)


# ──────────────────────────── db: per-thread кэш соединений ────────────────────────────


class TestConnCache(_DbTestCase):
    def test_conn_cached_per_thread(self):
        c1 = db.get_conn()
        c2 = db.get_conn()
        self.assertIs(c1, c2)

        other = {}

        def worker():
            conn = db.get_conn()
            other["conn"] = conn
            other["same_in_thread"] = conn is db.get_conn()
            other["usable"] = conn.execute("SELECT COUNT(*) FROM scan_results").fetchone()[0]

        t = threading.Thread(target=worker)
        t.start()
        t.join(5)
        self.assertTrue(other["same_in_thread"])   # внутри потока — одно и то же
        self.assertIsNot(other["conn"], c1)        # у каждого потока своё соединение
        self.assertEqual(other["usable"], 0)       # соединение рабочее

    def test_finished_thread_conns_are_released(self):
        """Реестр не течёт: соединения завершившихся потоков освобождаются."""
        barrier = threading.Barrier(6)

        def worker():
            db.get_conn()
            barrier.wait(10)

        threads = [threading.Thread(target=worker) for _ in range(5)]
        for t in threads:
            t.start()
        barrier.wait(10)                 # все потоки успели создать соединения
        self.assertGreaterEqual(len(db._conn_registry), 5)
        for t in threads:
            t.join(10)
        live = [ref() for ref in db._conn_registry if ref() is not None]
        # Соединения мёртвых потоков закрыты (их thread-local очищен), в реестре
        # живым осталось только соединение текущего потока.
        self.assertEqual(len(live), 1)

    def test_set_db_path_resets_cache(self):
        old_conn = db.get_conn()
        db.insert_scan_result(
            template_id="t1", worker_id=0, method="GET", url="http://a/",
            status_code=200, error=None, check_type="sqli", payload="'", evidence="e",
        )
        new_path = _tmp_db_path()
        try:
            db.set_db_path(new_path)
            new_conn = db.get_conn()
            self.assertIsNot(new_conn, old_conn)
            # старые соединения закрыты — обращения к ним падают
            with self.assertRaises(sqlite3.ProgrammingError):
                old_conn.execute("SELECT 1")
            # новая БД пустая и рабочая
            self.assertEqual(db.count_scan_results(), 0)
            db.insert_scan_result(
                template_id="t2", worker_id=0, method="POST", url="http://b/",
                status_code=200, error=None, check_type="xss", payload="<x>", evidence=None,
            )
            self.assertEqual(db.count_scan_results(), 1)
        finally:
            db._close_all_conns()
            _remove_db_files(new_path)

    def test_reset_invalidates_conns_from_other_threads(self):
        started, proceed = threading.Event(), threading.Event()
        result = {}

        def worker():
            result["first"] = db.get_conn()
            started.set()
            proceed.wait(10)                     # main thread переключит БД
            conn = db.get_conn()                 # должен получить НОВОЕ соединение
            result["second"] = conn
            result["count"] = conn.execute("SELECT COUNT(*) FROM scan_results").fetchone()[0]

        t = threading.Thread(target=worker, daemon=True)
        t.start()
        self.assertTrue(started.wait(5))
        new_path = _tmp_db_path()
        try:
            db.set_db_path(new_path)             # закрывает соединения всех потоков
            proceed.set()
            t.join(10)
            self.assertFalse(t.is_alive())
            self.assertIsNot(result["second"], result["first"])
            self.assertEqual(result["count"], 0)  # читает уже новую БД
            with self.assertRaises(sqlite3.ProgrammingError):
                result["first"].execute("SELECT 1")
        finally:
            db._close_all_conns()
            _remove_db_files(new_path)

    def test_parallel_writes_persisted(self):
        n_threads, n_each = 4, 40
        errors = []

        def writer(tid: int):
            try:
                for i in range(n_each):
                    db.insert_scan_result(
                        template_id=f"thr-{tid}-{i}", worker_id=tid, method="GET",
                        url=f"http://x/{tid}/{i}", status_code=200, error=None,
                        check_type="sqli", payload="'", evidence=None,
                    )
            except Exception as exc:  # pragma: no cover - диагностика
                errors.append(exc)

        threads = [threading.Thread(target=writer, args=(tid,)) for tid in range(n_threads)]
        for t in threads:
            t.start()
        for t in threads:
            t.join(15)
        self.assertFalse(any(t.is_alive() for t in threads))
        self.assertEqual(errors, [])
        self.assertEqual(db.count_scan_results(), n_threads * n_each)
        self.assertEqual(len(db.fetch_scan_results(limit=None)), n_threads * n_each)


# ──────────────────────────── report_export: без обрезки ────────────────────────────


class TestReportFullExport(_DbTestCase):
    N = 6005

    def setUp(self):
        super().setUp()
        _bulk_insert(self.N, evidence_every=5)
        # каждые 5 строк — evidence; всего находок (уникальных URL с evidence)
        self.expected_findings = self.N // 5

    def test_build_report_data_default_is_full(self):
        data = report_export._build_report_data()
        self.assertEqual(data["total"], self.N)                       # default limit=None
        self.assertEqual(data["findings_raw_count"], self.expected_findings)
        self.assertEqual(data["findings_count"], self.expected_findings)
        self.assertGreater(data["total"], 6000)

    def test_build_report_data_limit_none_full_no_dedup(self):
        data = report_export._build_report_data(limit=None, deduplicate=False)
        self.assertEqual(data["total"], self.N)
        self.assertEqual(data["findings_raw_count"], self.expected_findings)
        self.assertEqual(data["findings_count"], self.expected_findings)
        self.assertFalse(data["deduplicated"])

    def test_export_json_limit_none_exports_all(self):
        f = tempfile.mktemp(suffix=".json")
        try:
            n = report_export.export_json(f)
            self.assertEqual(n, self.expected_findings)
            payload = json.load(open(f, encoding="utf-8"))
            self.assertEqual(payload["summary"]["total"], self.N)
            self.assertEqual(payload["summary"]["findings_raw"], self.expected_findings)
            self.assertEqual(len(payload["results"]), self.expected_findings)
        finally:
            if os.path.exists(f):
                os.remove(f)

    def test_explicit_limit_still_works(self):
        limited = report_export._build_report_data(limit=10, deduplicate=False)
        self.assertEqual(limited["total"], 10)
        expected_raw = sum(
            1 for r in db.fetch_scan_results_with_meta(limit=10) if r.get("evidence")
        )
        self.assertEqual(limited["findings_raw_count"], expected_raw)

        f = tempfile.mktemp(suffix=".json")
        try:
            n = report_export.export_json(f, limit=7, deduplicate=False)
            self.assertLessEqual(n, 7)
            self.assertEqual(json.load(open(f, encoding="utf-8"))["summary"]["total"], 7)
        finally:
            if os.path.exists(f):
                os.remove(f)

    def test_export_signatures_default_to_none_limit(self):
        for fn in (
            report_export._build_report_data,
            report_export.export_json,
            report_export.export_md,
            report_export.export_docx,
            report_export.export_html,
            report_export.export_sarif,
        ):
            default = inspect.signature(fn).parameters["limit"].default
            self.assertIsNone(default, msg=f"{fn.__name__}: limit default must be None")

    def test_export_html_and_sarif_full(self):
        f_html = tempfile.mktemp(suffix=".html")
        f_sarif = tempfile.mktemp(suffix=".sarif")
        try:
            n_html = report_export.export_html(f_html)
            self.assertEqual(n_html, self.expected_findings)
            html = open(f_html, encoding="utf-8").read()
            self.assertIn(f"Total: {self.N}", html)

            n_sarif = report_export.export_sarif(f_sarif)
            self.assertEqual(n_sarif, self.expected_findings)
            sarif = json.load(open(f_sarif, encoding="utf-8"))
            self.assertEqual(len(sarif["runs"][0]["results"]), self.expected_findings)
        finally:
            for f in (f_html, f_sarif):
                if os.path.exists(f):
                    os.remove(f)


class TestSqliTimeExport(_DbTestCase):
    def test_sqli_time_severity_and_recommendation(self):
        rid = db.insert_scan_result(
            template_id="t-sleep", worker_id=0, method="GET",
            url="http://x/sleep?id=1", status_code=200, error=None,
            check_type="sqli_time", payload="SLEEP(3)", evidence="delay 3120ms >= threshold",
        )
        db.upsert_scan_meta(scan_result_id=rid, detector="checks", severity=None)
        self.assertEqual(report_export._row_severity({"check_type": "sqli_time"}), "HIGH")
        rec = report_export._recommendation_for("sqli_time")
        self.assertNotEqual(rec, report_export.GENERIC_RECOMMENDATION)

        f = tempfile.mktemp(suffix=".json")
        try:
            n = report_export.export_json(f)
            self.assertEqual(n, 1)
            payload = json.load(open(f, encoding="utf-8"))
            self.assertEqual(payload["results"][0]["severity"], "HIGH")
            self.assertIn("sqli_time", [m["check_type"] for m in payload["detection_matrix"]])
        finally:
            if os.path.exists(f):
                os.remove(f)


class TestDeleteHistoryIds(unittest.TestCase):
    """Очистка History по id (кнопка «Clear browser noise»)."""

    def setUp(self):
        self._db = tempfile.mktemp(suffix=".db")
        db.set_db_path(self._db)

    def tearDown(self):
        if os.path.exists(self._db):
            os.remove(self._db)

    def _insert(self, url: str) -> int:
        return db.insert_history(
            method="GET", url=url, req_headers={}, req_body=None,
            resp_status=200, resp_headers={}, resp_body_preview=b"",
        )

    def test_delete_subset_keeps_other_rows(self):
        ids = [self._insert(f"http://x/{i}") for i in range(5)]
        deleted = db.delete_history_ids([ids[1], ids[3]])
        self.assertEqual(deleted, 2)
        remaining = {r["id"] for r in db.fetch_history(limit=100)}
        self.assertEqual(remaining, {ids[0], ids[2], ids[4]})

    def test_empty_unknown_and_all(self):
        self.assertEqual(db.delete_history_ids([]), 0)
        self.assertEqual(db.delete_history_ids([999999]), 0)
        i = self._insert("http://x/a")
        self.assertEqual(db.delete_history_ids([i]), 1)
        self.assertEqual(db.fetch_history(limit=100), [])


if __name__ == "__main__":
    unittest.main()
