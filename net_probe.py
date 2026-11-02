"""
net_probe.py — liveness-проверка хостов перед сканом.

Зачем: если цель (host:port) уже не отвечает, сканер не должен тратить время
на десятки мёртвых запросов и «искать уязвимости» у недоступного сервиса.

Публичный API:
  • ``check_host_alive(url, timeout=3.0, headers=None) -> (alive, detail)`` —
    HEAD → OPTIONS → GET fallback; ЛЮБОЙ HTTP-ответ (<600) = хост жив;
    transport errors/timeout/DNS = мёртв. Прямое соединение (без прокси,
    trust_env=False), verify=False, follow_redirects=False.
  • ``probe_host(url, timeout=3.0) -> (alive, detail)`` — alias/внутренний.
  • ``filter_alive_history_ids(history_ids, timeout=3.0, log_cb=None)`` —
    группирует history-URL по scheme://host:port, проверяет каждый хост
    РОВНО ОДИН РАЗ и возвращает (живые history_id в исходном порядке,
    {host_key: (alive, detail)}). Логи: ``[ALIVE] host — OK (...)`` /
    ``[ALIVE] host — DEAD (...)``.
"""

from __future__ import annotations

import logging
from typing import Callable, Optional
from urllib.parse import urlsplit

import httpx

import db

logger = logging.getLogger(__name__)

#: User-Agent для liveness-запросов (отличим от сканирующих).
LIVENESS_USER_AGENT = "notscan-liveness"
LIVENESS_TIMEOUT_DEFAULT = 3.0

#: Статусы, при которых пробуем следующий HTTP-метод (сервер не любит HEAD).
_HEAD_FALLBACK_STATUSES = frozenset({400, 403, 405, 501})
#: Порядок методов: HEAD (дёшево) → OPTIONS → GET (максимальная совместимость).
_LIVENESS_METHODS: tuple[str, ...] = ("HEAD", "OPTIONS", "GET")


def _host_key(url: str) -> Optional[str]:
    """scheme://host[:port] для группировки; None для невалидных/не-http URL."""
    if not url or not isinstance(url, str):
        return None
    try:
        parsed = urlsplit(url.strip())
    except Exception:
        return None
    scheme = (parsed.scheme or "").lower()
    host = (parsed.hostname or "").strip()
    if scheme not in ("http", "https") or not host:
        return None
    try:
        port = parsed.port
    except ValueError:
        return None
    netloc = host if port is None else f"{host}:{port}"
    return f"{scheme}://{netloc}"


def _make_client(timeout: float, headers: Optional[dict] = None) -> httpx.Client:
    client_headers = {"User-Agent": LIVENESS_USER_AGENT}
    if headers:
        client_headers.update({str(k): str(v) for k, v in headers.items()})
    return httpx.Client(
        verify=False,
        timeout=float(timeout),
        follow_redirects=False,
        trust_env=False,  # не тащим системные HTTP(S)_PROXY — сканируем напрямую
        headers=client_headers,
    )


def _format_transport_error(exc: Exception) -> str:
    """Короткая человекочитаемая причина смерти хоста."""
    name = type(exc).__name__
    text = str(exc).strip() or name
    if isinstance(exc, httpx.TimeoutException):
        return f"timeout: {text}"
    if isinstance(exc, (httpx.ConnectError, httpx.ConnectTimeout)):
        return f"connect error: {text}"
    if isinstance(exc, httpx.UnsupportedProtocol):
        return f"invalid URL: {text}"
    return f"{name}: {text}"


def check_host_alive(
    url: str,
    timeout: float = LIVENESS_TIMEOUT_DEFAULT,
    headers: Optional[dict] = None,
) -> tuple[bool, str]:
    """Проверяет доступность хоста из ``url``.

    Возвращает ``(alive, detail)``:
      • ``True`` + ``"HTTP <status> via <METHOD>"`` для любого HTTP-ответа
        со status < 600 (включая 4xx/5xx — хост отвечает);
      • ``False`` + причина (timeout / connect error / invalid URL / DNS).

    HEAD → OPTIONS → GET: fallback срабатывает, если сервер отвечает
    400/403/405/501 на предыдущий метод (некоторые серверы не любят HEAD).
    Большое тело GET не читается (stream=True + close).
    """
    host_key = _host_key(url)
    if host_key is None:
        return False, "invalid URL"

    last_status: Optional[int] = None
    last_method = ""
    try:
        with _make_client(timeout, headers) as client:
            for method in _LIVENESS_METHODS:
                try:
                    request = client.build_request(method, url)
                    response = client.send(request, stream=True)
                except httpx.TransportError as exc:
                    return False, _format_transport_error(exc)
                except (httpx.InvalidURL, httpx.UnsupportedProtocol) as exc:
                    return False, _format_transport_error(exc)
                except Exception as exc:  # noqa: BLE001 — liveness не должен падать
                    return False, _format_transport_error(exc)
                try:
                    status = response.status_code
                finally:
                    try:
                        response.close()
                    except Exception:
                        pass
                if status >= 600:  # невалидный HTTP-статус — пробуем следующий метод
                    continue
                last_status = status
                last_method = method
                if status not in _HEAD_FALLBACK_STATUSES:
                    return True, f"HTTP {status} via {method}"
                # сервер не любит этот метод — пробуем следующий
    except Exception as exc:  # noqa: BLE001
        return False, _format_transport_error(exc)

    if last_status is not None:
        return True, f"HTTP {last_status} via {last_method}"
    return False, "no HTTP response"


def probe_host(url: str, timeout: float = LIVENESS_TIMEOUT_DEFAULT) -> tuple[bool, str]:
    """Alias для check_host_alive (внутренние вызовы/совместимость)."""
    return check_host_alive(url, timeout=timeout)


def filter_alive_history_ids(
    history_ids: list[int],
    timeout: float = LIVENESS_TIMEOUT_DEFAULT,
    log_cb: Optional[Callable[[str], None]] = None,
) -> tuple[list[int], dict[str, tuple[bool, str]]]:
    """Оставляет только history_id живых хостов (один probe на хост).

    Группировка по ``scheme://host[:port]``: у каждого хоста выполняется РОВНО
    ОДИН liveness-запрос. Невалидные/не-http(s) URL и отсутствующие в БД
    записи считаются мёртвыми (сеть для них не дёргается).

    Returns:
        (live_ids в исходном порядке, {host_key: (alive, detail)}).
    """
    log = log_cb or (lambda _msg: None)
    results: dict[str, tuple[bool, str]] = {}
    live_ids: list[int] = []

    for history_id in history_ids or []:
        row = None
        try:
            row = db.fetch_history_by_id(history_id)
        except Exception as exc:  # noqa: BLE001
            logger.debug("filter_alive_history_ids: fetch %s failed: %s", history_id, exc)
        url = str((row or {}).get("url") or "")
        host_key = _host_key(url)

        if host_key is None:
            key = url[:100] if url else f"history#{history_id}"
            if key not in results:
                results[key] = (False, "invalid URL")
                log(f"[ALIVE] {key} — DEAD (invalid URL)")
            continue

        if host_key not in results:
            alive, detail = check_host_alive(url, timeout=timeout)
            results[host_key] = (alive, detail)
            status = "OK" if alive else "DEAD"
            log(f"[ALIVE] {host_key} — {status} ({detail})")

        alive = results[host_key][0]
        if alive:
            live_ids.append(history_id)

    return live_ids, results
