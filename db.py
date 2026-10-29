"""
db.py — инициализация и работа с SQLite-базой данных history.db
"""

import sqlite3
import threading
import time
import weakref
import json
from pathlib import Path
from typing import Optional

DB_PATH = Path(__file__).parent / "history.db"

# ── Per-thread кэш соединений ────────────────────────────────────────
# Одно соединение на поток: создаётся лениво в get_conn() и используется
# только этим потоком. set_db_path() закрывает/сбрасывает кэш ВСЕХ ЖИВЫХ
# потоков (реестр + lock), иначе после смены пути потоки продолжили бы
# писать в старую БД. check_same_thread=False нужен потому, что закрывать
# соединения может другой поток (вызывающий set_db_path).
#
# sqlite3.Connection не поддерживает weakref, поэтому реестр хранит weakref
# на лёгкую обёртку _ConnHolder, а не на само соединение: реестр не продлевает
# жизнь соединению. Thread-local очищается при завершении потока — значит
# соединение завершившегося потока освобождается сборщиком мусора, и частые
# сканы (много короткоживущих потоков) не копят открытые файлы.
class _ConnHolder:
    """Обёртка соединения, по которой можно сделать weakref в реестре."""

    __slots__ = ("conn", "__weakref__")

    def __init__(self, conn: sqlite3.Connection) -> None:
        self.conn = conn


_conn_local = threading.local()
_conn_registry: list["weakref.ReferenceType[_ConnHolder]"] = []
_conn_lock = threading.Lock()
_conn_generation = 0


def _create_conn() -> tuple[sqlite3.Connection, _ConnHolder]:
    conn = sqlite3.connect(str(DB_PATH), check_same_thread=False)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA synchronous=NORMAL")
    holder = _ConnHolder(conn)
    with _conn_lock:
        # заодно подчищаем записи о соединениях завершившихся потоков
        _conn_registry[:] = [ref for ref in _conn_registry if ref() is not None]
        _conn_registry.append(weakref.ref(holder))
    return conn, holder


def _close_all_conns() -> None:
    """Закрывает кэш соединений всех живых потоков и инвалидирует кэш."""
    global _conn_generation
    with _conn_lock:
        holders = [holder for ref in _conn_registry if (holder := ref()) is not None]
        _conn_registry.clear()
        _conn_generation += 1
    for holder in holders:
        try:
            holder.conn.close()
        except Exception:
            pass
    # Текущий поток получит новое соединение при следующем get_conn().
    _conn_local.holder = None
    _conn_local.conn = None
    _conn_local.generation = -1


def set_db_path(path) -> None:
    """Переключает активную БД (per-project). Создаёт каталог и таблицы.

    Сбрасывает per-thread кэш соединений: старые соединения закрываются,
    каждый поток при следующем get_conn() откроет БД по новому пути.
    """
    global DB_PATH
    # Сначала новый путь, потом инвалидация кэша: иначе поток, вызвавший
    # get_conn() между сбросом и сменой пути, остался бы на старой БД.
    DB_PATH = Path(path)
    _close_all_conns()
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    init_db()


def get_db_path() -> Path:
    return DB_PATH


def get_conn() -> sqlite3.Connection:
    """Возвращает sqlite-соединение текущего потока (кэшируется per-thread).

    Соединение создаётся один раз на поток и не должно использоваться из
    других потоков. При set_db_path() кэш сбрасывается (см. _close_all_conns).
    """
    generation = _conn_generation
    holder = getattr(_conn_local, "holder", None)
    if holder is None or getattr(_conn_local, "generation", -1) != generation:
        conn, holder = _create_conn()
        _conn_local.holder = holder
        _conn_local.conn = conn
        _conn_local.generation = generation
        return conn
    return holder.conn


def init_db() -> None:
    with get_conn() as conn:
        conn.executescript("""
            CREATE TABLE IF NOT EXISTS history (
                id               INTEGER PRIMARY KEY AUTOINCREMENT,
                time             REAL    NOT NULL,
                method           TEXT    NOT NULL,
                url              TEXT    NOT NULL,
                req_headers      TEXT    NOT NULL,
                req_body         BLOB,
                resp_status      INTEGER,
                resp_headers     TEXT,
                resp_body_preview BLOB
            );

            CREATE TABLE IF NOT EXISTS scan_results (
                id           INTEGER PRIMARY KEY AUTOINCREMENT,
                time         REAL    NOT NULL,
                template_id  TEXT    NOT NULL,
                worker_id    INTEGER NOT NULL,
                method       TEXT    NOT NULL,
                url          TEXT    NOT NULL,
                status_code  INTEGER,
                error        TEXT,
                check_type   TEXT,
                payload      TEXT,
                evidence     TEXT
            );

            CREATE TABLE IF NOT EXISTS scan_requests (
                id               INTEGER PRIMARY KEY AUTOINCREMENT,
                scan_result_id   INTEGER NOT NULL,
                raw_request      TEXT,
                raw_response_preview TEXT,
                resp_status      INTEGER,
                resp_headers     TEXT
            );
            -- Migration: add resp_status/resp_headers if upgrading from older schema
            -- (SQLite ignores ADD COLUMN if it already exists — use a separate migration block)


            -- Extended metadata for scans (lineage, scoring, confirmations, calibration, correlation)
            CREATE TABLE IF NOT EXISTS scan_meta (
                scan_result_id    INTEGER PRIMARY KEY,
                history_id        INTEGER,
                mutation_point    TEXT,
                original_param    TEXT,
                payload_class     TEXT,
                detector          TEXT,        -- matcher | checks | zap
                confidence        REAL,        -- 0..1
                severity          TEXT,        -- Info/Low/Medium/High/Critical (optional)
                exploitability    REAL,        -- 0..1
                fingerprint       TEXT,        -- stable dedup key
                created_at        REAL NOT NULL
            );

            CREATE TABLE IF NOT EXISTS scan_confirmations (
                id               INTEGER PRIMARY KEY AUTOINCREMENT,
                scan_result_id   INTEGER NOT NULL,
                time             REAL    NOT NULL,
                kind             TEXT    NOT NULL, -- baseline | benign | suspicious
                status_code      INTEGER,
                elapsed_ms       REAL,
                resp_preview     TEXT,
                diff_snippet     TEXT,
                ok               INTEGER,          -- 0/1
                note             TEXT
            );

            CREATE TABLE IF NOT EXISTS host_calibration (
                host             TEXT PRIMARY KEY,
                time             REAL NOT NULL,
                baseline_ms_p50  REAL,
                baseline_ms_p95  REAL,
                typical_5xx_rate REAL,
                notes            TEXT
            );

            CREATE TABLE IF NOT EXISTS scan_evidence_snippets (
                scan_result_id   INTEGER PRIMARY KEY,
                time             REAL NOT NULL,
                diff_snippet     TEXT,
                snippet_type     TEXT,  -- unified_diff | minimal_lines
                baseline_ref     TEXT,  -- history:<id> or scan_result:<id>
                mutated_ref      TEXT
            );

            CREATE TABLE IF NOT EXISTS scan_links (
                id               INTEGER PRIMARY KEY AUTOINCREMENT,
                time             REAL NOT NULL,
                kind             TEXT NOT NULL,      -- duplicate | related
                src_result_id    INTEGER NOT NULL,
                dst_result_id    INTEGER NOT NULL,
                fingerprint      TEXT,
                note             TEXT
            );

            CREATE TABLE IF NOT EXISTS endpoint_contracts (
                id              INTEGER PRIMARY KEY AUTOINCREMENT,
                method          TEXT NOT NULL,
                url_pattern     TEXT NOT NULL,
                time_updated    REAL NOT NULL,
                param_types     TEXT,
                required_params TEXT,
                expected_codes  TEXT,
                resp_schema     TEXT,
                content_type    TEXT,
                sample_count    INTEGER DEFAULT 0,
                UNIQUE(method, url_pattern)
            );

            CREATE TABLE IF NOT EXISTS auth_boundary_results (
                id              INTEGER PRIMARY KEY AUTOINCREMENT,
                time            REAL NOT NULL,
                history_id      INTEGER,
                method          TEXT,
                url             TEXT,
                anon_status     INTEGER,
                auth_status     INTEGER,
                similarity      REAL,
                accessible_anon INTEGER,
                diff_snippet    TEXT,
                note            TEXT
            );
        """)
        # ── Schema migrations (safe for existing DBs) ───────────────────────────────────
        # SQLite raises OperationalError if column already exists — ignore it.
        for _alter in [
            "ALTER TABLE scan_requests ADD COLUMN resp_status INTEGER",
            "ALTER TABLE scan_requests ADD COLUMN resp_headers TEXT",
        ]:
            try:
                with get_conn() as _c:
                    _c.execute(_alter)
            except Exception:
                pass  # column already exists

        # ── Data migrations (idempotent) ──────────────────────────────────────────────
        # Normalize severity to UPPERCASE (old rows stored title/lower case).
        with get_conn() as _c:
            _c.execute(
                "UPDATE scan_meta SET severity = UPPER(severity) "
                "WHERE severity IS NOT NULL AND severity != UPPER(severity)"
            )


# ──────────────────────────── history ────────────────────────────

def insert_history(
    method: str,
    url: str,
    req_headers: dict,
    req_body: Optional[bytes],
    resp_status: Optional[int],
    resp_headers: Optional[dict],
    resp_body_preview: Optional[bytes],
) -> int:
    with get_conn() as conn:
        cur = conn.execute(
            """INSERT INTO history
               (time, method, url, req_headers, req_body,
                resp_status, resp_headers, resp_body_preview)
               VALUES (?,?,?,?,?,?,?,?)""",
            (
                time.time(),
                method,
                url,
                json.dumps(req_headers),
                req_body,
                resp_status,
                json.dumps(resp_headers) if resp_headers else None,
                resp_body_preview,
            ),
        )
        return cur.lastrowid


def fetch_history(limit: int = 500) -> list:
    with get_conn() as conn:
        rows = conn.execute(
            "SELECT * FROM history ORDER BY id DESC LIMIT ?", (limit,)
        ).fetchall()
    return [dict(r) for r in rows]


def fetch_history_by_id(history_id: int) -> Optional[dict]:
    with get_conn() as conn:
        row = conn.execute(
            "SELECT * FROM history WHERE id=?", (history_id,)
        ).fetchone()
    return dict(row) if row else None


# ──────────────────────────── scan_results ────────────────────────────

def insert_scan_result(
    template_id: str,
    worker_id: int,
    method: str,
    url: str,
    status_code: Optional[int],
    error: Optional[str],
    check_type: str,
    payload: str,
    evidence: Optional[str],
) -> int:
    with get_conn() as conn:
        cur = conn.execute(
            """INSERT INTO scan_results
               (time, template_id, worker_id, method, url,
                status_code, error, check_type, payload, evidence)
               VALUES (?,?,?,?,?,?,?,?,?,?)""",
            (
                time.time(),
                template_id,
                worker_id,
                method,
                url,
                status_code,
                error,
                check_type,
                payload,
                evidence,
            ),
        )
        return cur.lastrowid


def insert_scan_request(
    scan_result_id: int,
    raw_request: str,
    raw_response_preview: str,
    resp_status: Optional[int] = None,
    resp_headers: Optional[dict] = None,
) -> None:
    with get_conn() as conn:
        conn.execute(
            """INSERT INTO scan_requests
               (scan_result_id, raw_request, raw_response_preview, resp_status, resp_headers)
               VALUES (?,?,?,?,?)""",
            (
                scan_result_id,
                raw_request,
                raw_response_preview,
                resp_status,
                json.dumps(resp_headers) if resp_headers else None,
            ),
        )


def upsert_scan_meta(
    *,
    scan_result_id: int,
    history_id: int | None = None,
    mutation_point: str | None = None,
    original_param: str | None = None,
    payload_class: str | None = None,
    detector: str | None = None,
    confidence: float | None = None,
    severity: str | None = None,
    exploitability: float | None = None,
    fingerprint: str | None = None,
) -> None:
    with get_conn() as conn:
        conn.execute(
            """INSERT INTO scan_meta
               (scan_result_id, history_id, mutation_point, original_param, payload_class,
                detector, confidence, severity, exploitability, fingerprint, created_at)
               VALUES (?,?,?,?,?,?,?,?,?,?,?)
               ON CONFLICT(scan_result_id) DO UPDATE SET
                 history_id=COALESCE(excluded.history_id, history_id),
                 mutation_point=COALESCE(excluded.mutation_point, mutation_point),
                 original_param=COALESCE(excluded.original_param, original_param),
                 payload_class=COALESCE(excluded.payload_class, payload_class),
                 detector=COALESCE(excluded.detector, detector),
                 confidence=COALESCE(excluded.confidence, confidence),
                 severity=COALESCE(excluded.severity, severity),
                 exploitability=COALESCE(excluded.exploitability, exploitability),
                 fingerprint=COALESCE(excluded.fingerprint, fingerprint)
            """,
            (
                scan_result_id,
                history_id,
                mutation_point,
                original_param,
                payload_class,
                detector,
                confidence,
                severity,
                exploitability,
                fingerprint,
                time.time(),
            ),
        )


def insert_evidence_snippet(
    *,
    scan_result_id: int,
    diff_snippet: str,
    snippet_type: str = "unified_diff",
    baseline_ref: str = "",
    mutated_ref: str = "",
) -> None:
    with get_conn() as conn:
        conn.execute(
            """INSERT INTO scan_evidence_snippets
               (scan_result_id, time, diff_snippet, snippet_type, baseline_ref, mutated_ref)
               VALUES (?,?,?,?,?,?)
               ON CONFLICT(scan_result_id) DO UPDATE SET
                 time=excluded.time,
                 diff_snippet=excluded.diff_snippet,
                 snippet_type=excluded.snippet_type,
                 baseline_ref=excluded.baseline_ref,
                 mutated_ref=excluded.mutated_ref
            """,
            (scan_result_id, time.time(), diff_snippet, snippet_type, baseline_ref, mutated_ref),
        )


def fetch_evidence_snippet(scan_result_id: int) -> Optional[dict]:
    with get_conn() as conn:
        row = conn.execute(
            "SELECT * FROM scan_evidence_snippets WHERE scan_result_id=?",
            (scan_result_id,),
        ).fetchone()
    return dict(row) if row else None


def insert_confirmation(
    *,
    scan_result_id: int,
    kind: str,
    status_code: Optional[int],
    elapsed_ms: Optional[float],
    resp_preview: str,
    diff_snippet: str = "",
    ok: bool = False,
    note: str = "",
) -> int:
    with get_conn() as conn:
        cur = conn.execute(
            """INSERT INTO scan_confirmations
               (scan_result_id, time, kind, status_code, elapsed_ms, resp_preview, diff_snippet, ok, note)
               VALUES (?,?,?,?,?,?,?,?,?)""",
            (
                scan_result_id,
                time.time(),
                kind,
                status_code,
                elapsed_ms,
                resp_preview,
                diff_snippet,
                1 if ok else 0,
                note,
            ),
        )
        return cur.lastrowid


def fetch_confirmations(scan_result_id: int, limit: int = 50) -> list[dict]:
    with get_conn() as conn:
        rows = conn.execute(
            "SELECT * FROM scan_confirmations WHERE scan_result_id=? ORDER BY id DESC LIMIT ?",
            (scan_result_id, limit),
        ).fetchall()
    return [dict(r) for r in rows]


def upsert_host_calibration(
    *,
    host: str,
    baseline_ms_p50: float | None = None,
    baseline_ms_p95: float | None = None,
    typical_5xx_rate: float | None = None,
    notes: str = "",
) -> None:
    with get_conn() as conn:
        conn.execute(
            """INSERT INTO host_calibration
               (host, time, baseline_ms_p50, baseline_ms_p95, typical_5xx_rate, notes)
               VALUES (?,?,?,?,?,?)
               ON CONFLICT(host) DO UPDATE SET
                 time=excluded.time,
                 baseline_ms_p50=COALESCE(excluded.baseline_ms_p50, baseline_ms_p50),
                 baseline_ms_p95=COALESCE(excluded.baseline_ms_p95, baseline_ms_p95),
                 typical_5xx_rate=COALESCE(excluded.typical_5xx_rate, typical_5xx_rate),
                 notes=COALESCE(excluded.notes, notes)
            """,
            (host, time.time(), baseline_ms_p50, baseline_ms_p95, typical_5xx_rate, notes),
        )


def fetch_host_calibration(host: str) -> Optional[dict]:
    with get_conn() as conn:
        row = conn.execute("SELECT * FROM host_calibration WHERE host=?", (host,)).fetchone()
    return dict(row) if row else None


def upsert_endpoint_contract(
    *,
    method: str,
    url_pattern: str,
    param_types: dict,
    required_params: list[str],
    expected_codes: list[int],
    resp_schema: dict,
    content_type: str,
    sample_count: int,
) -> None:
    with get_conn() as conn:
        conn.execute(
            """INSERT INTO endpoint_contracts
               (method, url_pattern, time_updated, param_types, required_params, expected_codes, resp_schema, content_type, sample_count)
               VALUES (?,?,?,?,?,?,?,?,?)
               ON CONFLICT(method, url_pattern) DO UPDATE SET
                 time_updated=excluded.time_updated,
                 param_types=excluded.param_types,
                 required_params=excluded.required_params,
                 expected_codes=excluded.expected_codes,
                 resp_schema=excluded.resp_schema,
                 content_type=excluded.content_type,
                 sample_count=excluded.sample_count
            """,
            (
                method,
                url_pattern,
                time.time(),
                json.dumps(param_types, ensure_ascii=False),
                json.dumps(required_params, ensure_ascii=False),
                json.dumps(expected_codes, ensure_ascii=False),
                json.dumps(resp_schema, ensure_ascii=False),
                content_type,
                sample_count,
            ),
        )


def fetch_endpoint_contracts(limit: int = 2000) -> list[dict]:
    with get_conn() as conn:
        rows = conn.execute(
            "SELECT * FROM endpoint_contracts ORDER BY time_updated DESC LIMIT ?",
            (limit,),
        ).fetchall()
    return [dict(r) for r in rows]


def insert_auth_boundary_result(
    *,
    history_id: int | None,
    method: str,
    url: str,
    anon_status: int | None,
    auth_status: int | None,
    similarity: float,
    accessible_anon: bool,
    diff_snippet: str,
    note: str,
) -> int:
    with get_conn() as conn:
        cur = conn.execute(
            """INSERT INTO auth_boundary_results
               (time, history_id, method, url, anon_status, auth_status, similarity, accessible_anon, diff_snippet, note)
               VALUES (?,?,?,?,?,?,?,?,?,?)""",
            (
                time.time(),
                history_id,
                method,
                url,
                anon_status,
                auth_status,
                similarity,
                1 if accessible_anon else 0,
                diff_snippet,
                note,
            ),
        )
        return cur.lastrowid


def fetch_auth_boundary_results(limit: int = 500) -> list[dict]:
    with get_conn() as conn:
        rows = conn.execute(
            "SELECT * FROM auth_boundary_results ORDER BY id DESC LIMIT ?",
            (limit,),
        ).fetchall()
    return [dict(r) for r in rows]


def find_duplicate_by_fingerprint(fingerprint: str, exclude_result_id: int | None = None) -> Optional[int]:
    """
    Returns an existing scan_result id with same fingerprint and evidence.
    """
    with get_conn() as conn:
        if exclude_result_id is not None:
            row = conn.execute(
                """SELECT r.id
                   FROM scan_results r
                   JOIN scan_meta m ON m.scan_result_id = r.id
                   WHERE m.fingerprint=? AND r.evidence IS NOT NULL AND r.evidence != ''
                     AND r.id != ?
                   ORDER BY r.id DESC
                   LIMIT 1""",
                (fingerprint, exclude_result_id),
            ).fetchone()
        else:
            row = conn.execute(
                """SELECT r.id
                   FROM scan_results r
                   JOIN scan_meta m ON m.scan_result_id = r.id
                   WHERE m.fingerprint=? AND r.evidence IS NOT NULL AND r.evidence != ''
                   ORDER BY r.id DESC
                   LIMIT 1""",
                (fingerprint,),
            ).fetchone()
    return int(row["id"]) if row else None


def insert_scan_link(
    *,
    kind: str,
    src_result_id: int,
    dst_result_id: int,
    fingerprint: str = "",
    note: str = "",
) -> int:
    with get_conn() as conn:
        cur = conn.execute(
            """INSERT INTO scan_links (time, kind, src_result_id, dst_result_id, fingerprint, note)
               VALUES (?,?,?,?,?,?)""",
            (time.time(), kind, src_result_id, dst_result_id, fingerprint, note),
        )
        return cur.lastrowid


def fetch_scan_results(limit: int | None = None, offset: int = 0) -> list:
    """Строки scan_results (ORDER BY id DESC).

    limit=None → БЕЗ LIMIT (полная выборка). offset применяется только
    вместе с limit; offset без limit игнорируется.
    """
    with get_conn() as conn:
        if limit is None:
            rows = conn.execute(
                "SELECT * FROM scan_results ORDER BY id DESC"
            ).fetchall()
        else:
            rows = conn.execute(
                "SELECT * FROM scan_results ORDER BY id DESC LIMIT ? OFFSET ?",
                (int(limit), max(0, int(offset))),
            ).fetchall()
    return [dict(r) for r in rows]


def fetch_scan_results_with_meta(limit: int | None = None, offset: int = 0) -> list:
    """
    Returns scan_results joined with scan_meta (if present).

    limit=None → БЕЗ LIMIT (полная выборка); offset — только вместе с limit.
    """
    with get_conn() as conn:
        if limit is None:
            rows = conn.execute(
                """SELECT r.*,
                          m.confidence as confidence,
                          m.severity as severity,
                          m.exploitability as exploitability,
                          m.fingerprint as fingerprint
                   FROM scan_results r
                   LEFT JOIN scan_meta m ON m.scan_result_id = r.id
                   ORDER BY r.id DESC"""
            ).fetchall()
        else:
            rows = conn.execute(
                """SELECT r.*,
                          m.confidence as confidence,
                          m.severity as severity,
                          m.exploitability as exploitability,
                          m.fingerprint as fingerprint
                   FROM scan_results r
                   LEFT JOIN scan_meta m ON m.scan_result_id = r.id
                   ORDER BY r.id DESC
                   LIMIT ? OFFSET ?""",
                (int(limit), max(0, int(offset))),
            ).fetchall()
    return [dict(r) for r in rows]


def count_scan_results() -> int:
    """Общее число строк scan_results (для пагинации GUI и отчётов)."""
    with get_conn() as conn:
        row = conn.execute("SELECT COUNT(*) FROM scan_results").fetchone()
    return int(row[0]) if row else 0


def fetch_scan_result_by_id(result_id: int) -> Optional[dict]:
    with get_conn() as conn:
        row = conn.execute(
            "SELECT * FROM scan_results WHERE id=?", (result_id,)
        ).fetchone()
    return dict(row) if row else None


def fetch_scan_request_by_result(scan_result_id: int) -> Optional[dict]:
    with get_conn() as conn:
        row = conn.execute(
            "SELECT * FROM scan_requests WHERE scan_result_id=? LIMIT 1",
            (scan_result_id,),
        ).fetchone()
    return dict(row) if row else None


def fetch_scan_meta_by_result(scan_result_id: int) -> Optional[dict]:
    """Return scan_meta row for the given scan_result_id, or None."""
    with get_conn() as conn:
        row = conn.execute(
            "SELECT * FROM scan_meta WHERE scan_result_id=? LIMIT 1",
            (scan_result_id,),
        ).fetchone()
    return dict(row) if row else None


def clear_history() -> int:
    """Удаляет все записи из таблицы history. Возвращает кол-во удалённых строк."""
    with get_conn() as conn:
        cur = conn.execute("DELETE FROM history")
        conn.execute("DELETE FROM sqlite_sequence WHERE name='history'")
        return cur.rowcount


def delete_history_ids(ids: list[int]) -> int:
    """Удаляет записи history по списку id. Возвращает кол-во удалённых строк."""
    ids = [int(i) for i in (ids or []) if i is not None]
    if not ids:
        return 0
    deleted = 0
    with get_conn() as conn:
        for chunk_start in range(0, len(ids), 500):
            chunk = ids[chunk_start:chunk_start + 500]
            placeholders = ",".join("?" for _ in chunk)
            cur = conn.execute(
                f"DELETE FROM history WHERE id IN ({placeholders})", chunk
            )
            deleted += cur.rowcount or 0
    return deleted


def clear_scan_results() -> int:
    """
    Удаляет все результаты сканирования и связанные данные.
    Возвращает кол-во удалённых строк scan_results.
    """
    with get_conn() as conn:
        cur = conn.execute("DELETE FROM scan_results")
        conn.execute("DELETE FROM scan_requests")
        conn.execute("DELETE FROM scan_meta")
        conn.execute("DELETE FROM scan_confirmations")
        conn.execute("DELETE FROM scan_evidence_snippets")
        conn.execute("DELETE FROM scan_links WHERE 1=1")
        for tbl in ("scan_results", "scan_requests", "scan_meta",
                    "scan_confirmations", "scan_evidence_snippets"):
            try:
                conn.execute(f"DELETE FROM sqlite_sequence WHERE name='{tbl}'")
            except Exception:
                pass
        return cur.rowcount


def delete_scan_result(result_id: int) -> None:
    """Удаляет одну запись scan_results и все связанные данные по id."""
    with get_conn() as conn:
        conn.execute("DELETE FROM scan_requests WHERE scan_result_id=?", (result_id,))
        conn.execute("DELETE FROM scan_meta WHERE scan_result_id=?", (result_id,))
        conn.execute("DELETE FROM scan_confirmations WHERE scan_result_id=?", (result_id,))
        conn.execute("DELETE FROM scan_evidence_snippets WHERE scan_result_id=?", (result_id,))
        conn.execute("DELETE FROM scan_results WHERE id=?", (result_id,))


def fetch_history_baseline(method: str, url: str) -> Optional[dict]:
    """Первая запись истории, совпадающая по method+url (для baseline)."""
    with get_conn() as conn:
        row = conn.execute(
            "SELECT * FROM history WHERE method=? AND url=? LIMIT 1",
            (method, url),
        ).fetchone()
    return dict(row) if row else None


def latest_history_id() -> int:
    """Возвращает MAX(id) из history (0 если таблица пуста)."""
    with get_conn() as conn:
        row = conn.execute("SELECT MAX(id) FROM history").fetchone()
    return row[0] or 0


def latest_scan_result_id() -> int:
    """Возвращает MAX(id) из scan_results (0 если таблица пуста)."""
    with get_conn() as conn:
        row = conn.execute("SELECT MAX(id) FROM scan_results").fetchone()
    return row[0] or 0
