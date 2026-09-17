"""HMAC-SHA256 verification of GitHub webhook payloads."""

from __future__ import annotations

import hashlib
import hmac
import os


def verify_signature(raw_body: bytes, signature_header: str | None) -> bool:
    """Return True if the X-Hub-Signature-256 header matches the payload HMAC."""
    secret = os.environ.get("GITHUB_WEBHOOK_SECRET", "")
    if not secret:
        return False
    if not signature_header or not signature_header.startswith("sha256="):
        return False
    expected = (
        "sha256=" + hmac.new(secret.encode(), raw_body, hashlib.sha256).hexdigest()
    )
    return hmac.compare_digest(expected, signature_header)