"""
session_manager.py — Управление HTTP-сессией для сканера.

Поддерживает:
  • Анонимный режим (без авторизации)
  • Авторизацию через HTTP-форму (POST) или JSON API
  • Автоматический повторный логин при 401/403
  • Хранение cookies и Bearer-токена
  • Точки расширения для refresh-token
  • Полное отключение авторизации через флаг enabled=False
  • Получение CSRF-токена для мутаций (M3): SessionManager.csrf_token_provider()
"""

from __future__ import annotations

import json
import logging
import os
import threading
import time
import urllib.parse
from dataclasses import dataclass, field
from typing import Any, Callable, Optional
from urllib.parse import urlparse
from pathlib import Path

import httpx

import templating

logger = logging.getLogger(__name__)

# Время жизни закэшированного CSRF-токена (секунды). Токен должен быть свежим:
# серверы часто ротируют его на каждой форме/сессии.
CSRF_TOKEN_TTL = 300.0


# ══════════════════════════════════════════════════════════════════
#  Конфигурация авторизации
# ══════════════════════════════════════════════════════════════════

@dataclass
class AuthConfig:
    """
    Все параметры для HTTP-логина. Задаётся конфигом или CLI.

    Пример (форма):
        AuthConfig(
            enabled=True,
            login_url="http://target/login",
            method="POST",
            body={"username": "admin", "password": "secret"},
            content_type="form",           # "form" | "json" | "raw"
            success_codes={200, 302},
            token_json_path="data.token",  # если сервер возвращает JSON-токен
        )

    Пример (Bearer API):
        AuthConfig(
            enabled=True,
            login_url="http://api/auth",
            method="POST",
            body={"user": "x", "pass": "y"},
            content_type="json",
            token_json_path="access_token",
            refresh_token_json_path="refresh_token",
            refresh_url="http://api/auth/refresh",
        )
    """
    # ── Флаг включения ──
    enabled: bool = False

    # ── Параметры логин-запроса ──
    login_url: str = ""
    method: str = "POST"                      # HTTP-метод
    body: dict[str, Any] = field(default_factory=dict)   # тело запроса
    extra_headers: dict[str, str] = field(default_factory=dict)
    content_type: str = "form"               # "form" | "json" | "raw"

    # ── Коды успешного логина ──
    success_codes: set[int] = field(default_factory=lambda: {200, 302, 303})

    # ── Коды "не авторизован" ──
    unauth_codes: set[int] = field(default_factory=lambda: {401, 403})

    # ── Token extraction (из JSON-ответа) ──
    token_json_path: str = ""                # e.g. "data.access_token"
    token_header_name: str = "Authorization" # заголовок для Bearer
    token_prefix: str = "Bearer "

    # ── Refresh token ──
    refresh_token_json_path: str = ""        # e.g. "data.refresh_token"
    refresh_url: str = ""
    refresh_method: str = "POST"
    refresh_body_template: str = '{"refresh_token": "{refresh_token}"}'

    # ── Максимум попыток повторного логина в сессии ──
    max_relogin_attempts: int = 3

    # ── Задержка между попытками (сек) ──
    retry_delay: float = 1.0

    # ── OTP / 2FA (task-25) ──
    # Имя поля/заголовка, куда подставляется одноразовый код.
    otp_field: str = "otp"
    # Маркеры «сервер требует OTP» в ответе на логин (text/JSON keys).
    otp_required_markers: tuple[str, ...] = (
        "otp", "2fa", "two-factor", "verification code", "one-time",
    )
    # Сколько раз пробовать отправить OTP-код за один login().
    otp_attempts: int = 1
    # Тестовая заглушка (или env NOTSCAN_OTP_STUB): код без GUI-провайдера.
    otp_test_stub: str = ""


# ══════════════════════════════════════════════════════════════════
#  Хранилище токенов/кук
# ══════════════════════════════════════════════════════════════════

@dataclass
class TokenStore:
    """Текущее состояние авторизации."""
    access_token: Optional[str] = None
    refresh_token: Optional[str] = None
    token_expires_at: Optional[float] = None   # unix timestamp или None
    cookies: dict[str, str] = field(default_factory=dict)
    last_login_at: Optional[float] = None

    def is_valid(self) -> bool:
        """Возвращает True, если токен не истёк (или нет информации об истечении)."""
        if self.token_expires_at is None:
            return self.access_token is not None
        return time.time() < self.token_expires_at

    def clear(self) -> None:
        self.access_token = None
        self.refresh_token = None
        self.token_expires_at = None
        self.cookies.clear()
        self.last_login_at = None


# ══════════════════════════════════════════════════════════════════
#  CSRF-токен (M3)
# ══════════════════════════════════════════════════════════════════

def fetch_csrf_token(
    url: str,
    headers: Optional[dict] = None,
    cookies: Optional[dict] = None,
    timeout: float = 10.0,
) -> Optional[str]:
    """
    GET ``url`` и извлекает CSRF-токен из HTML-ответа.

    • ``headers`` — дополнительные заголовки запроса;
    • ``cookies`` — cookies для запроса;
    • ``verify=False`` (стенды/самоподписанные сертификаты), редиректы сопровождаются;
    • любая ошибка (сеть, TLS, парсинг) → None, исключения не пробрасываются.
    """
    try:
        with httpx.Client(
            verify=False,
            timeout=timeout,
            follow_redirects=True,
        ) as client:
            if cookies:
                client.cookies.update(cookies)
            resp = client.get(url, headers=headers or {})
            return templating.extract_csrf_token(resp.text)
    except Exception as exc:  # noqa: BLE001 — скан не должен падать из-за CSRF
        logger.debug("fetch_csrf_token(%s) failed: %s", url, exc)
        return None


# ══════════════════════════════════════════════════════════════════
#  SessionManager
# ══════════════════════════════════════════════════════════════════

class SessionManager:
    """
    Управляет HTTP-сессией сканера:
      • login()   — аутентификация и сохранение credentials
      • request() — обёртка с авто-реloginom при 401/403
      • logout()  — сброс сессии
      • disable() / enable() — переключение режима авторизации
    """

    def __init__(
        self,
        auth_config: Optional[AuthConfig] = None,
        log_callback: Optional[Callable[[str], None]] = None,
        httpx_kwargs: Optional[dict] = None,
    ):
        self.auth = auth_config or AuthConfig(enabled=False)
        self.log_cb = log_callback or (lambda s: None)
        self._lock = threading.Lock()
        self._store = TokenStore()
        self._relogin_count = 0

        # CSRF-токен (M3): кэш с TTL; сбрасывается при logout/disable/re-login.
        self._csrf_token: Optional[str] = None
        self._csrf_ts: float = 0.0
        self._csrf_lock = threading.Lock()
        # Последний известный URL — fallback для csrf_token_provider(),
        # если auth.login_url не задан (анонимный скан).
        self._last_url: Optional[str] = None

        # OTP/2FA provider (задаёт GUI): blocking callable -> code | None.
        # Сам SessionManager Tk-диалоги не показывает (важно для воркеров).
        self._otp_provider: Optional[Callable[[], Optional[str]]] = None

        # httpx client (общий для всех запросов)
        kw = dict(
            verify=False,
            timeout=20.0,
            follow_redirects=True,
            limits=httpx.Limits(max_connections=20, max_keepalive_connections=10),
        )
        if httpx_kwargs:
            kw.update(httpx_kwargs)
        self._client = httpx.Client(**kw)

    # ── Включение/выключение ─────────────────────────────────────

    def enable(self) -> None:
        self.auth.enabled = True
        self.log_cb("[SESSION] Auth enabled")

    def disable(self) -> None:
        self.auth.enabled = False
        self._store.clear()
        self._clear_csrf_cache()
        self.log_cb("[SESSION] Auth disabled — anonymous mode")

    @property
    def auth_enabled(self) -> bool:
        return self.auth.enabled

    # ── Логин ────────────────────────────────────────────────────

    def login(self) -> bool:
        """
        Выполняет логин-запрос.
        Возвращает True при успехе, False при неудаче.
        Сохраняет cookies и/или Bearer-токен в TokenStore.
        """
        if not self.auth.enabled:
            self.log_cb("[SESSION] Auth disabled, skipping login")
            return True

        if not self.auth.login_url:
            self.log_cb("[SESSION][WARN] login_url not set")
            return False

        self.log_cb(f"[SESSION] Logging in → {self.auth.login_url}")

        try:
            resp = self._do_login_request()
        except Exception as exc:
            self.log_cb(f"[SESSION][ERR] Login request failed: {exc}")
            return False

        if resp.status_code not in self.auth.success_codes:
            if self._response_requires_otp(resp):
                self.log_cb(
                    "[SESSION] OTP/2FA required by login response — requesting code"
                )
                otp_resp = self._login_with_otp(resp)
                if otp_resp is None:
                    return False
                resp = otp_resp
            else:
                self.log_cb(
                    f"[SESSION][ERR] Login returned {resp.status_code}, "
                    f"expected one of {self.auth.success_codes}"
                )
                return False

        # Extract cookies
        with self._lock:
            self._store.cookies.update(dict(resp.cookies))
            # Sync httpx client cookies
            self._client.cookies.update(dict(resp.cookies))

            # Extract token from JSON body
            if self.auth.token_json_path:
                token = self._extract_json_field(resp, self.auth.token_json_path)
                if token:
                    self._store.access_token = str(token)
                    self.log_cb(f"[SESSION] Token acquired (len={len(self._store.access_token)})")

            # Extract refresh token
            if self.auth.refresh_token_json_path:
                rt = self._extract_json_field(resp, self.auth.refresh_token_json_path)
                if rt:
                    self._store.refresh_token = str(rt)

            self._store.last_login_at = time.time()
            self._relogin_count = 0

        # Новая сессия → ранее полученный CSRF-токен мог быть выдан анонимной
        # сессии; кэш сбрасываем, чтобы провайдер получил свежий.
        self._clear_csrf_cache()

        self.log_cb(
            f"[SESSION] Login OK — cookies={list(self._store.cookies.keys())}, "
            f"token={'yes' if self._store.access_token else 'no'}"
        )
        return True

    def _do_login_request(self, otp_code: Optional[str] = None) -> httpx.Response:
        """Формирует и выполняет логин-запрос (с OTP-кодом, если передан).

        OTP добавляется как поле формы/JSON (`auth.otp_field`). Для raw-тела:
        подставляется ``{otp}``-placeholder, иначе код уходит заголовком X-OTP.
        """
        headers = dict(self.auth.extra_headers)
        body: dict = dict(self.auth.body or {})
        if otp_code:
            body[self.auth.otp_field] = otp_code

        if self.auth.content_type == "json":
            resp = self._client.request(
                method=self.auth.method,
                url=self.auth.login_url,
                json=body,
                headers=headers,
            )
        elif self.auth.content_type == "form":
            resp = self._client.request(
                method=self.auth.method,
                url=self.auth.login_url,
                data=body,
                headers=headers,
            )
        else:  # raw
            raw_body = str(body.get("raw", ""))
            if otp_code:
                if "{otp}" in raw_body:
                    raw_body = raw_body.replace("{otp}", otp_code)
                elif raw_body:
                    raw_body = raw_body + "&" + urllib.parse.urlencode(
                        {self.auth.otp_field: otp_code}
                    )
                headers.setdefault("X-OTP", otp_code)
            resp = self._client.request(
                method=self.auth.method,
                url=self.auth.login_url,
                content=raw_body.encode() if isinstance(raw_body, str) else raw_body,
                headers=headers,
            )
        return resp

    # ── OTP / 2FA (task-25) ──────────────────────────────────────

    def set_otp_provider(self, provider: Optional[Callable[[], Optional[str]]]) -> None:
        """Задать провайдер OTP/2FA (bound method/closure из GUI или тестов).

        Провайдер — blocking callable без Tk-диалогов: для воркеров GUI кладёт
        туда чтение уже введённого кода. None — провайдер отключён.
        """
        self._otp_provider = provider

    @staticmethod
    def _otp_stub_from_env() -> str:
        return (os.environ.get("NOTSCAN_OTP_STUB") or "").strip()

    def _obtain_otp_code(self) -> Optional[str]:
        """Код OTP: env-заглушка → auth.otp_test_stub → provider. Иначе None."""
        stub = self._otp_stub_from_env() or (self.auth.otp_test_stub or "").strip()
        if stub:
            self.log_cb("[SESSION] OTP: using configured test stub")
            return stub
        provider = self._otp_provider
        if provider is None:
            return None
        try:
            value = provider()
        except Exception as exc:
            self.log_cb(f"[SESSION][ERR] OTP provider failed: {exc}")
            return None
        code = str(value).strip() if value else ""
        return code or None

    def _response_requires_otp(self, resp: httpx.Response) -> bool:
        """True, если ответ логина просит OTP/2FA (маркеры в text/JSON)."""
        markers = tuple(
            str(m).lower()
            for m in (getattr(self.auth, "otp_required_markers", ()) or ())
        )
        if not markers:
            return False
        text = (getattr(resp, "text", "") or "").lower()
        if any(marker in text for marker in markers):
            return True
        try:
            data = resp.json()
        except Exception:
            return False

        def _walk(node, depth: int = 0) -> bool:
            if depth > 5:
                return False
            if isinstance(node, dict):
                for key, value in node.items():
                    if any(marker in str(key).lower() for marker in markers):
                        return True
                    if _walk(value, depth + 1):
                        return True
                return False
            if isinstance(node, list):
                return any(_walk(item, depth + 1) for item in node)
            if isinstance(node, str):
                return any(marker in node.lower() for marker in markers)
            return False

        try:
            return _walk(data)
        except Exception:
            return False

    def _login_with_otp(self, first_resp: httpx.Response) -> Optional[httpx.Response]:
        """Повторный login с OTP-кодом. Возвращает успешный response или None."""
        attempts = max(1, int(getattr(self.auth, "otp_attempts", 1) or 1))
        code = self._obtain_otp_code()
        if not code:
            self.log_cb(
                "[SESSION][WARN] OTP required, but provider/test-stub returned "
                "empty code — login failed"
            )
            return None
        resp = first_resp
        for attempt in range(1, attempts + 1):
            self.log_cb(
                f"[SESSION] OTP required → submitting code "
                f"(attempt {attempt}/{attempts})"
            )
            try:
                resp = self._do_login_request(otp_code=code)
            except Exception as exc:
                self.log_cb(f"[SESSION][ERR] OTP login request failed: {exc}")
                return None
            if resp.status_code in self.auth.success_codes:
                self.log_cb("[SESSION] OTP accepted — login OK")
                return resp
            if not self._response_requires_otp(resp):
                self.log_cb(
                    f"[SESSION][ERR] OTP login rejected ({resp.status_code})"
                )
                return None
            if attempt < attempts:
                code = self._obtain_otp_code() or code
        self.log_cb(
            f"[SESSION][ERR] OTP login failed after {attempts} attempt(s) "
            f"({getattr(resp, 'status_code', '?')})"
        )
        return None

    # ── Refresh token ─────────────────────────────────────────────

    def refresh(self) -> bool:
        """
        Попытка обновить access_token через refresh_token.
        Точка расширения — по умолчанию только логирует намерение.
        """
        if not self.auth.refresh_url or not self._store.refresh_token:
            return False

        self.log_cb(f"[SESSION] Refreshing token via {self.auth.refresh_url}")
        try:
            body_str = self.auth.refresh_body_template.replace(
                "{refresh_token}", self._store.refresh_token
            )
            body = json.loads(body_str)
            resp = self._client.request(
                method=self.auth.refresh_method,
                url=self.auth.refresh_url,
                json=body,
            )
            if resp.status_code in self.auth.success_codes:
                new_token = self._extract_json_field(resp, self.auth.token_json_path)
                if new_token:
                    with self._lock:
                        self._store.access_token = str(new_token)
                    self.log_cb("[SESSION] Token refreshed successfully")
                    return True
        except Exception as exc:
            self.log_cb(f"[SESSION][ERR] Refresh failed: {exc}")
        return False

    # ── request() с авто-реloginom ────────────────────────────────

    def request(
        self,
        method: str,
        url: str,
        *,
        headers: Optional[dict] = None,
        content: Optional[bytes] = None,
        data: Optional[dict] = None,
        json_body: Optional[dict] = None,
        **kwargs,
    ) -> httpx.Response:
        """
        Обёртка над httpx.Client.request с авто-реloginom.

        Алгоритм:
          1. Добавляем Authorization-заголовок (если есть токен).
          2. Выполняем запрос.
          3. Если ответ 401/403 и auth.enabled:
             a. Пробуем refresh() (если есть refresh_token).
             b. Иначе — login().
             c. Повторяем запрос.
          4. Если снова 401/403 — логируем, возвращаем ответ (не падаем).
        """
        merged_headers = self._build_headers(headers or {})

        # Запоминаем URL: fallback-источник для csrf_token_provider()
        self._last_url = url

        resp = self._raw_request(method, url, merged_headers, content, data, json_body, **kwargs)

        # Auto-relogin on 401/403
        if self.auth.enabled and resp.status_code in self.auth.unauth_codes:
            self.log_cb(
                f"[SESSION] Got {resp.status_code} for {url} — attempting re-auth"
            )
            reauthed = False

            # Try refresh first (if available)
            if self._store.refresh_token and not self._store.is_valid():
                reauthed = self.refresh()

            # Full re-login
            if not reauthed and self._relogin_count < self.auth.max_relogin_attempts:
                with self._lock:
                    self._relogin_count += 1
                time.sleep(self.auth.retry_delay)
                reauthed = self.login()

            if reauthed:
                merged_headers = self._build_headers(headers or {})
                resp = self._raw_request(method, url, merged_headers, content, data, json_body, **kwargs)
                if resp.status_code in self.auth.unauth_codes:
                    self.log_cb(
                        f"[SESSION][ERR] Still {resp.status_code} after re-auth for {url} — skipping"
                    )
            else:
                self.log_cb(
                    f"[SESSION][ERR] Re-auth failed for {url} — continuing with unauthenticated response"
                )

        return resp

    def _raw_request(
        self,
        method: str,
        url: str,
        headers: dict,
        content: Optional[bytes],
        data: Optional[dict],
        json_body: Optional[dict],
        **kwargs,
    ) -> httpx.Response:
        try:
            return self._client.request(
                method=method,
                url=url,
                headers=headers,
                content=content,
                data=data,
                json=json_body,
                **kwargs,
            )
        except Exception as exc:
            logger.debug("SessionManager._raw_request error: %s", exc)
            # Return synthetic 0-status response to avoid crashes in callers
            return _make_error_response(url, str(exc))

    def _build_headers(self, extra: dict) -> dict:
        """Добавляет Authorization-заголовок если есть токен."""
        h = dict(extra)
        if self.auth.enabled and self._store.access_token:
            h[self.auth.token_header_name] = (
                self.auth.token_prefix + self._store.access_token
            )
        return h

    # ── CSRF-токен (M3) ──────────────────────────────────────────

    def _clear_csrf_cache(self) -> None:
        with self._csrf_lock:
            self._csrf_token = None
            self._csrf_ts = 0.0

    def _csrf_target_url(self) -> Optional[str]:
        """Страница, с которой берём токен: login_url или последний URL."""
        if self.auth.login_url:
            return self.auth.login_url
        return self._last_url

    def csrf_token_provider(self) -> Optional[str]:
        """
        Возвращает актуальный CSRF-токен для подстановки в мутации (M3).

        Вызывается движком один раз на scan-target (history record) до построения
        мутаций. Алгоритм:
          1) свежий кэш (TTL = CSRF_TOKEN_TTL);
          2) иначе GET на login_url / последний известный URL общим httpx-клиентом
             с текущими cookies (verify=False, timeout=10);
          3) templating.extract_csrf_token(resp.text) → кэшируем;
          4) любая ошибка → None (исключения не пробрасываются, скан не ломается).
        """
        now = time.time()
        with self._csrf_lock:
            if self._csrf_token and (now - self._csrf_ts) < CSRF_TOKEN_TTL:
                return self._csrf_token

        url = self._csrf_target_url()
        if not url:
            return None
        try:
            resp = self._client.get(url, timeout=10.0)
            token = templating.extract_csrf_token(resp.text)
        except Exception as exc:  # noqa: BLE001 — скан не должен падать из-за CSRF
            logger.debug("csrf_token_provider(%s) failed: %s", url, exc)
            return None

        if token:
            with self._csrf_lock:
                self._csrf_token = token
                self._csrf_ts = time.time()
            self.log_cb(f"[SESSION] CSRF token acquired (len={len(token)}) from {url}")
        return token

    # ── Logout / cleanup ─────────────────────────────────────────

    def logout(self) -> None:
        with self._lock:
            self._store.clear()
            self._client.cookies.clear()
            self._relogin_count = 0
        self._clear_csrf_cache()
        self.log_cb("[SESSION] Logged out, session cleared")

    def close(self) -> None:
        self._client.close()

    # ── Token extraction helper ──────────────────────────────────

    @staticmethod
    def _extract_json_field(resp: httpx.Response, path: str) -> Optional[Any]:
        """
        Извлекает поле из JSON-ответа по пути вида "data.access_token".
        Возвращает None если не нашёл или ответ не JSON.
        """
        try:
            data = resp.json()
        except Exception:
            return None
        parts = path.split(".")
        node = data
        for part in parts:
            if isinstance(node, dict) and part in node:
                node = node[part]
            else:
                return None
        return node

    # ── Свойства для внешних модулей ─────────────────────────────

    @property
    def cookies(self) -> dict:
        return dict(self._store.cookies)

    @property
    def access_token(self) -> Optional[str]:
        return self._store.access_token

    @property
    def token_store(self) -> TokenStore:
        return self._store

    def __repr__(self) -> str:
        mode = "auth" if self.auth.enabled else "anon"
        return (
            f"<SessionManager mode={mode} "
            f"token={'yes' if self._store.access_token else 'no'} "
            f"cookies={list(self._store.cookies.keys())}>"
        )


# ══════════════════════════════════════════════════════════════════
#  CLI / config builder helpers
# ══════════════════════════════════════════════════════════════════

def auth_config_from_dict(d: dict) -> AuthConfig:
    """
    Строит AuthConfig из словаря (например, из JSON-конфига или argparse).

    Пример конфига:
    {
        "enabled": true,
        "login_url": "http://target/login",
        "method": "POST",
        "body": {"username": "admin", "password": "secret"},
        "content_type": "form",
        "token_json_path": "",
        "success_codes": [200, 302]
    }
    """
    cfg = AuthConfig()
    for field_name, value in d.items():
        if hasattr(cfg, field_name):
            if field_name == "success_codes":
                value = set(value)
            elif field_name == "unauth_codes":
                value = set(value)
            elif field_name == "otp_required_markers":
                value = tuple(str(v) for v in value)
            setattr(cfg, field_name, value)
    return cfg


def auth_config_to_dict(cfg: AuthConfig) -> dict:
    """Сериализует AuthConfig в JSON-совместимый словарь (включая creds)."""
    return {
        "enabled": cfg.enabled,
        "login_url": cfg.login_url,
        "method": cfg.method,
        "body": cfg.body,
        "extra_headers": cfg.extra_headers,
        "content_type": cfg.content_type,
        "success_codes": sorted(cfg.success_codes),
        "unauth_codes": sorted(cfg.unauth_codes),
        "token_json_path": cfg.token_json_path,
        "token_header_name": cfg.token_header_name,
        "token_prefix": cfg.token_prefix,
        "refresh_token_json_path": cfg.refresh_token_json_path,
        "refresh_url": cfg.refresh_url,
        "refresh_method": cfg.refresh_method,
        "refresh_body_template": cfg.refresh_body_template,
        "max_relogin_attempts": cfg.max_relogin_attempts,
        "retry_delay": cfg.retry_delay,
        "otp_field": cfg.otp_field,
        "otp_required_markers": list(cfg.otp_required_markers),
        "otp_attempts": cfg.otp_attempts,
        "otp_test_stub": cfg.otp_test_stub,
    }


def save_auth_config(cfg: AuthConfig, path) -> None:
    """Сохраняет auth config (включая креды) на диск."""
    Path(path).write_text(
        json.dumps(auth_config_to_dict(cfg), indent=2, ensure_ascii=False),
        encoding="utf-8",
    )


def load_auth_config(path) -> Optional[AuthConfig]:
    """Загружает auth config с диска. Возвращает None если файла нет/битый."""
    p = Path(path)
    if not p.exists():
        return None
    try:
        data = json.loads(p.read_text(encoding="utf-8"))
        cfg = auth_config_from_dict(data)
        return cfg if cfg.login_url else None
    except Exception:
        return None


def auth_config_from_cli(args) -> AuthConfig:
    """
    Строит AuthConfig из argparse.Namespace или dict.

    Ожидаемые аргументы CLI:
      --login-url
      --login-method    (default: POST)
      --login-body      (JSON string)
      --login-type      (form|json|raw)
      --token-path      (JSON path к токену)
      --no-auth         (флаг отключения)
    """
    if isinstance(args, dict):
        d = args
    else:
        d = vars(args)

    if d.get("no_auth") or not d.get("login_url"):
        return AuthConfig(enabled=False)

    body = {}
    raw_body = d.get("login_body", "{}")
    if isinstance(raw_body, str):
        try:
            body = json.loads(raw_body)
        except json.JSONDecodeError:
            body = {"raw": raw_body}
    elif isinstance(raw_body, dict):
        body = raw_body

    return AuthConfig(
        enabled=True,
        login_url=d.get("login_url", ""),
        method=d.get("login_method", "POST").upper(),
        body=body,
        content_type=d.get("login_type", "form"),
        token_json_path=d.get("token_path", ""),
        refresh_url=d.get("refresh_url", ""),
    )


# ══════════════════════════════════════════════════════════════════
#  Синтетический ответ для обработки ошибок
# ══════════════════════════════════════════════════════════════════

def _make_error_response(url: str, error_msg: str) -> httpx.Response:
    """Возвращает "пустой" httpx.Response со status_code=0 при сетевых ошибках."""
    request = httpx.Request("GET", url)
    return httpx.Response(
        status_code=0,
        headers={},
        content=error_msg.encode("utf-8", errors="replace"),
        request=request,
    )
