"""Password hashing and the log-in check with lockout (FR6, QR16)."""

from __future__ import annotations

import hashlib
import hmac
import os
from dataclasses import dataclass

from pipeline.config import PipelineSettings
from pipeline.store import Store

MIN_PASSWORD_LENGTH = 10
_N, _R, _P = 2 ** 14, 8, 1


def hash_password(password: str, n: int = _N, r: int = _R, p: int = _P) -> str:
    salt = os.urandom(16)
    digest = hashlib.scrypt(password.encode(), salt=salt, n=n, r=r, p=p, dklen=32)
    return f"scrypt${n}${r}${p}${salt.hex()}${digest.hex()}"


def verify_password(password: str, stored: str) -> bool:
    try:
        scheme, n, r, p, salt, digest = stored.split("$")
        if scheme != "scrypt":
            return False
        candidate = hashlib.scrypt(password.encode(), salt=bytes.fromhex(salt), n=int(n), r=int(r), p=int(p), dklen=32)
        return hmac.compare_digest(candidate.hex(), digest)
    except (ValueError, TypeError):
        return False


_DUMMY = None


def _dummy_hash() -> str:
    global _DUMMY
    if _DUMMY is None:
        _DUMMY = hash_password("not-a-real-password")
    return _DUMMY


@dataclass
class LoginResult:
    ok: bool
    message: str = ""


def check_login(store: Store, settings: PipelineSettings, username: str, password: str, ip: str) -> LoginResult:
    username = (username or "").strip()[:64]
    lock_seconds = settings.lockout_minutes * 60
    until = store.locked_until(username, ip, settings.lockout_attempts, lock_seconds)
    if until is not None:
        minutes = max(1, int((until - store.clock()) / 60) + 1)
        return LoginResult(False, f"Too many failed attempts. Log-in is disabled for about {minutes} more minute(s).")
    stored = store.get_user_hash(username)
    # Always verify something, so an unknown user takes as long as a wrong password.
    ok = verify_password(password or "", stored or _dummy_hash()) and stored is not None
    store.record_attempt(username, ip, ok)
    store.audit(None, username or "unknown", "login succeeded" if ok else "login failed", f"from {ip}")
    return LoginResult(True) if ok else LoginResult(False, "Invalid user name or password.")
