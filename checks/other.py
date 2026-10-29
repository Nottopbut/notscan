"""
checks/other.py — Дополнительные проверки (секция "Other"):
  • JWT — проверка подписи JSON Web Token (alg=none, слабый HMAC-секрет)
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import re
from typing import Any

from .base import (
    BaseCheck, CheckContext, CheckResult, ScanRequest, ScanResponse,
    Severity, VulnCategory,
)

JWT_RE = re.compile(r"Bearer\s+([A-Za-z0-9\-_]{10,}\.[A-Za-z0-9\-_]{10,}\.[A-Za-z0-9\-_]{0,})", re.IGNORECASE)

WEAK_JWT_SECRETS = [
    "secret", "password", "123456", "12345678", "changeme", "key",
    "jwt", "jwt_secret", "secretkey", "secret_key", "supersecret",
    "default", "test", "admin", "letmein", "qwerty", "root",
]


def _b64url_decode(s: str) -> bytes:
    s += "=" * (-len(s) % 4)
    return base64.urlsafe_b64decode(s)


class JWTSignatureCheck(BaseCheck):
    """
    Пассивный чек: находит JWT в заголовке Authorization/Cookie и проверяет:
      • alg=none (unsigned token);
      • слабый HMAC-секрет (перебор типовых секретов).
    """

    check_id = "jwt"
    vuln_type = "jwt"
    category = VulnCategory.AUTH
    severity = Severity.HIGH
    name = "JWT Signature Verification"
    cwe = "CWE-347"
    passive = True
    requires_payload = False

    def check(self, req: ScanRequest, resp: ScanResponse, ctx: CheckContext) -> CheckResult:
        if not self.enabled:
            return self.skip()

        tokens = self._extract_tokens(req)
        if not tokens:
            return self.ok()

        findings = []
        for token in tokens:
            parts = token.split(".")
            if len(parts) != 3:
                continue
            header = self._decode_json(parts[0])
            if not header:
                continue
            alg = str(header.get("alg", "") or "").lower()

            if alg == "none":
                findings.append(self.make_finding(
                    "JWT использует алгоритм 'none' (токен без подписи может быть принят сервером)",
                    req, resp, ctx, severity=Severity.CRITICAL,
                    recommendation="Отклоняй токены с alg=none на сервере; требуй подписанные токены.",
                ))
                continue

            if alg.startswith("hs"):
                secret = self._bruteforce_secret(token, alg)
                if secret:
                    findings.append(self.make_finding(
                        f"JWT подписан слабым HMAC-секретом '{secret}' (алгоритм {alg.upper()})",
                        req, resp, ctx, severity=Severity.HIGH,
                        recommendation="Используй длинный случайный HMAC-секрет (или RS256 с доверенным ключом).",
                    ))

        if findings:
            return self.found(*findings)
        return self.ok()

    # ── helpers ──────────────────────────────────────────────────

    @staticmethod
    def _decode_json(part: str) -> dict[str, Any]:
        try:
            data = _b64url_decode(part)
            obj = json.loads(data.decode("utf-8", errors="replace"))
            return obj if isinstance(obj, dict) else {}
        except Exception:
            return {}

    @staticmethod
    def _extract_tokens(req: ScanRequest) -> list[str]:
        tokens: list[str] = []
        for name, value in req.headers.items():
            if name.lower() == "authorization" and "bearer" in value.lower():
                m = JWT_RE.search(value)
                if m:
                    tokens.append(m.group(1))
            elif name.lower() == "cookie":
                # jwt=... или token=...
                for pair in value.split(";"):
                    if "=" in pair:
                        k, _, v = pair.partition("=")
                        if "jwt" in k.lower() or "token" in k.lower():
                            v = v.strip()
                            if v.count(".") == 2:
                                tokens.append(v)
        return tokens

    @staticmethod
    def _bruteforce_secret(token: str, alg: str) -> str | None:
        hash_name = {"hs256": hashlib.sha256, "hs384": hashlib.sha384, "hs512": hashlib.sha512}.get(alg)
        if not hash_name:
            return None
        parts = token.split(".")
        signing_input = f"{parts[0]}.{parts[1]}".encode()
        try:
            sig = _b64url_decode(parts[2])
        except Exception:
            return None
        for secret in WEAK_JWT_SECRETS:
            expected = hmac.new(secret.encode(), signing_input, hash_name).digest()
            if hmac.compare_digest(expected, sig):
                return secret
        return None


ALL_OTHER_CHECKS: list[type[BaseCheck]] = [
    JWTSignatureCheck,
]
