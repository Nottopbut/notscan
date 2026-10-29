"""
tests/lab/harness.py — хелперы для интеграционной лабы notscan.

Задачи модуля:
  • поднять/остановить ``LabServer`` (tests/lab/server.py);
  • переключить ``db`` на временную БД (каталог tmp, не репозиторий);
  • записать в ``history`` «перехваченный» baseline-запрос к лабе
    (реальный HTTP-запрос, реальный ответ — чтобы FP-suppression/диффы
    работали как в бою);
  • собрать ``ScanTask`` (``scanner_core.build_scan_tasks``) и прогнать их
    через ``ScannerRunner`` до полного завершения;
  • отдать результаты из БД вместе со ``scan_meta.detector``.

Тесты используют ``Lab`` как контекстный менеджер и monkeypatch'ат
``scanner_core.load_payloads`` (через аргумент ``payloads=``) — так прогон
занимает секунды.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Optional
from unittest import mock

import httpx

import db
import scanner_core
from tests.lab.server import LabServer

#: Заголовки baseline-запросов (history), которые записывает harness.
_DEFAULT_HEADERS = {
    "User-Agent": "notscan-lab/1.0",
    "Accept": "*/*",
}


@dataclass
class Captured:
    """Результат реального запроса к лабе, из которого делаем history row."""

    method: str
    url: str
    request_headers: dict[str, str]
    request_body: Optional[bytes]
    status: int
    response_headers: dict[str, str]
    response_body: bytes
    elapsed_ms: float


@dataclass
class LabResult:
    """Итог одного прогона: построенные задачи + строки scan_results(+meta)."""

    tasks: list[Any]
    rows: list[dict[str, Any]]
    db_path: str
    payloads: dict[str, list[str]] = field(default_factory=dict)

    @property
    def evidence(self) -> list[dict[str, Any]]:
        return [r for r in self.rows if r.get("evidence")]

    def findings(
        self,
        check_type: Optional[str] = None,
        url_contains: Optional[str] = None,
    ) -> list[dict[str, Any]]:
        """Evidence-строки с фильтром по check_type и подстроке URL."""
        out = self.evidence
        if check_type is not None:
            wanted = check_type.lower()
            out = [r for r in out if (r.get("check_type") or "").lower() == wanted]
        if url_contains is not None:
            out = [r for r in out if url_contains in (r.get("url") or "")]
        return out

    def tasks_for_url(self, url_contains: str) -> list[Any]:
        return [t for t in self.tasks if url_contains in (getattr(t, "url", "") or "")]

    def has(self, check_type: str, url_contains: str) -> bool:
        return bool(self.findings(check_type=check_type, url_contains=url_contains))


class Lab:
    """Изолированная лаба: сервер + временная БД + helpers для скана."""

    def __init__(self, tmp_dir: str | Path, *, sleep_seconds: float = 4.0):
        self.tmp_dir = Path(tmp_dir)
        self.tmp_dir.mkdir(parents=True, exist_ok=True)
        self.server = LabServer(sleep_seconds=sleep_seconds).start()
        self._prev_db_path = db.get_db_path()
        self.db_path = self.tmp_dir / "lab.db"
        db.set_db_path(self.db_path)
        self._httpx = httpx.Client(verify=False, follow_redirects=False, timeout=15.0)

    # ── жизненный цикл ──────────────────────────────────────────────

    def close(self) -> None:
        try:
            self._httpx.close()
        finally:
            self.server.stop()
            # Не оставляем глобальный db на удалённом каталоге.
            db.set_db_path(self.tmp_dir / "closed.db")

    def __enter__(self) -> "Lab":
        return self

    def __exit__(self, *exc_info) -> None:
        self.close()

    @property
    def base_url(self) -> str:
        return self.server.base_url

    # ── baseline history ────────────────────────────────────────────

    def capture(
        self,
        method: str,
        path: str,
        *,
        params: Optional[dict[str, Any]] = None,
        body: Optional[bytes | str] = None,
        headers: Optional[dict[str, str]] = None,
    ) -> Captured:
        """Реально дергает лабу (без follow_redirects) и возвращает запрос+ответ."""
        url = self.base_url + path
        req_headers = {"Host": self.server.netloc, **_DEFAULT_HEADERS}
        if headers:
            req_headers.update(headers)
        if isinstance(body, str):
            body = body.encode("utf-8")
        resp = self._httpx.request(
            method,
            url,
            params=params,
            headers=req_headers,
            content=body,
        )
        return Captured(
            method=method,
            url=str(resp.request.url),
            request_headers=dict(resp.request.headers),
            request_body=body,
            status=resp.status_code,
            response_headers=dict(resp.headers),
            response_body=resp.content,
            elapsed_ms=resp.elapsed.total_seconds() * 1000.0,
        )

    def add_history(
        self,
        method: str,
        path: str,
        *,
        params: Optional[dict[str, Any]] = None,
        body: Optional[bytes | str] = None,
        headers: Optional[dict[str, str]] = None,
    ) -> int:
        """Записывает baseline-запрос в history (как перехваченный прокси)."""
        cap = self.capture(method, path, params=params, body=body, headers=headers)
        return db.insert_history(
            cap.method,
            cap.url,
            cap.request_headers,
            cap.request_body,
            cap.status,
            cap.response_headers,
            cap.response_body[:8192],
        )

    def add_get(self, path: str, params: Optional[dict[str, Any]] = None) -> int:
        return self.add_history("GET", path, params=params)

    def add_post(
        self,
        path: str,
        body: bytes | str,
        *,
        content_type: str = "application/x-www-form-urlencoded",
    ) -> int:
        return self.add_history(
            "POST", path, body=body, headers={"Content-Type": content_type}
        )

    # ── скан ────────────────────────────────────────────────────────

    def build_tasks(
        self,
        history_ids: list[int],
        checks: list[str],
        *,
        payloads: Optional[dict[str, list[str]]] = None,
        **build_kwargs: Any,
    ) -> list[Any]:
        """build_scan_tasks с подменой load_payloads на короткие списки."""
        if payloads is None:
            return scanner_core.build_scan_tasks(history_ids, checks, **build_kwargs)
        with mock.patch.object(
            scanner_core, "load_payloads", _fake_payload_loader(payloads)
        ):
            return scanner_core.build_scan_tasks(history_ids, checks, **build_kwargs)

    def build_and_run(
        self,
        history_ids: list[int],
        checks: list[str],
        *,
        payloads: Optional[dict[str, list[str]]] = None,
        workers: int = 4,
        log: Optional[Any] = None,
        **build_kwargs: Any,
    ) -> LabResult:
        """Полный цикл: build_scan_tasks → ScannerRunner.start/wait → БД."""
        tasks = self.build_tasks(
            history_ids, checks, payloads=payloads, **build_kwargs
        )
        runner = scanner_core.ScannerRunner(
            tasks,
            workers=workers,
            log_callback=log or (lambda _msg: None),
            # Лаба живёт на 127.0.0.1 — явно разрешаем её в scope-guard.
            scope_allowlist=[self.server.host],
        )
        try:
            runner.start()
            runner.wait()
        finally:
            # На случай падения внутри wait() — не оставляем потоки висеть.
            if getattr(runner, "tasks_remaining", 0):
                runner.stop()
        return LabResult(
            tasks=tasks,
            rows=fetch_scan_rows(),
            db_path=str(self.db_path),
            payloads=payloads or {},
        )


# ──────────────────────────── module helpers ────────────────────────────


def _fake_payload_loader(payloads: dict[str, list[str]]):
    """Возвращает fake ``scanner_core.load_payloads`` с заданными списками."""
    normalized = {
        str(check_type).lower(): [str(p) for p in values]
        for check_type, values in payloads.items()
    }

    def fake_load_payloads(check_type: str, safe_mode: bool = True) -> list[str]:  # noqa: ARG001
        return list(normalized.get(str(check_type or "").lower(), []))

    return fake_load_payloads


def fetch_scan_rows() -> list[dict[str, Any]]:
    """Все строки scan_results(+meta); limit=None — по контракту без обрезки."""
    try:
        return db.fetch_scan_results_with_meta(limit=None)
    except Exception:
        # Переходный fallback для состояния репозитория до task-4 (db ещё не
        # принимает limit=None); финальный контракт проверяет data-integrity тест-
        # набор, а здесь нужны просто все строки текущего маленького скана.
        return db.fetch_scan_results_with_meta(limit=1_000_000)


def count_evidence_rows() -> int:
    """Число evidence-строк в scan_results (прямой SQL, без пагинации)."""
    with db.get_conn() as conn:
        row = conn.execute(
            "SELECT COUNT(*) FROM scan_results "
            "WHERE evidence IS NOT NULL AND evidence != ''"
        ).fetchone()
    return int(row[0])


def count_scan_rows() -> int:
    with db.get_conn() as conn:
        row = conn.execute("SELECT COUNT(*) FROM scan_results").fetchone()
    return int(row[0])


def sqlite_rows(sql: str, params: tuple = ()) -> list[dict[str, Any]]:
    """Прямой SQL к текущей БД (для проверок data integrity)."""
    with db.get_conn() as conn:
        rows = conn.execute(sql, params).fetchall()
    return [dict(r) for r in rows]


def server_json_ok(server: LabServer) -> bool:
    """True, если сервер не получил ни одного невалидного JSON-тела."""
    return len(server.invalid_json_bodies) == 0


def parse_json_body(raw: bytes) -> Any:
    return json.loads(raw.decode("utf-8"))


__all__ = [
    "Captured",
    "Lab",
    "LabResult",
    "count_evidence_rows",
    "count_scan_rows",
    "fetch_scan_rows",
    "parse_json_body",
    "server_json_ok",
    "sqlite_rows",
]
