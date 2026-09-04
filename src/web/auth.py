"""Single-operator password authentication.

A minimal, dependency-free session layer:
  - The operator sets LOGIN_PASSWORD in the environment.
  - POST /api/login with that password mints a signed, expiring session token
    stored in an HttpOnly cookie.
  - A middleware requires a valid token on every /api/* route except a small
    public allowlist (health, login, me).

If LOGIN_PASSWORD is unset, auth is DISABLED (open) so local development and the
offline test suite keep working — but the app logs a loud warning and /api/me
reports auth_enabled=false so the UI can surface it. Set LOGIN_PASSWORD before
exposing this on a network.

The signing secret is read from SESSION_SECRET, else persisted to
data/.session_secret so sessions survive restarts without config.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import secrets
import time
from pathlib import Path

COOKIE_NAME = "bh_session"
_TOKEN_TTL_SECONDS = 7 * 24 * 3600  # one week

_ROOT = Path(__file__).resolve().parent.parent.parent
_SECRET_FILE = _ROOT / "data" / ".session_secret"

# Public /api paths that never require authentication.
PUBLIC_API_PATHS = {"/api/health", "/api/login", "/api/logout", "/api/me"}


def _password() -> str:
    return os.getenv("LOGIN_PASSWORD", "").strip()


def auth_enabled() -> bool:
    return bool(_password())


def operator_name() -> str:
    return os.getenv("OPERATOR_NAME", "operator").strip() or "operator"


def _secret() -> bytes:
    env = os.getenv("SESSION_SECRET", "").strip()
    if env:
        return env.encode()
    try:
        if _SECRET_FILE.exists():
            return _SECRET_FILE.read_bytes()
        _SECRET_FILE.parent.mkdir(parents=True, exist_ok=True)
        gen = secrets.token_bytes(32)
        _SECRET_FILE.write_bytes(gen)
        try:
            os.chmod(_SECRET_FILE, 0o600)
        except OSError:
            pass
        return gen
    except OSError:
        # Fall back to a process-local secret (sessions won't survive restart).
        return secrets.token_bytes(32)


def _b64e(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).decode().rstrip("=")


def _b64d(s: str) -> bytes:
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def mint_token(now: float | None = None) -> str:
    now = now if now is not None else time.time()
    payload = {"iat": int(now), "exp": int(now) + _TOKEN_TTL_SECONDS, "sub": operator_name()}
    body = _b64e(json.dumps(payload, separators=(",", ":")).encode())
    sig = _b64e(hmac.new(_secret(), body.encode(), hashlib.sha256).digest())
    return f"{body}.{sig}"


def verify_token(token: str | None, now: float | None = None) -> bool:
    if not token or "." not in token:
        return False
    now = now if now is not None else time.time()
    body, _, sig = token.partition(".")
    expected = _b64e(hmac.new(_secret(), body.encode(), hashlib.sha256).digest())
    if not hmac.compare_digest(sig, expected):
        return False
    try:
        payload = json.loads(_b64d(body))
    except (ValueError, json.JSONDecodeError):
        return False
    return int(payload.get("exp", 0)) > now


def check_password(candidate: str) -> bool:
    pw = _password()
    if not pw:
        return False
    return hmac.compare_digest((candidate or "").strip(), pw)


def cookie_secure() -> bool:
    return os.getenv("COOKIE_SECURE", "0").strip() in ("1", "true", "True")
