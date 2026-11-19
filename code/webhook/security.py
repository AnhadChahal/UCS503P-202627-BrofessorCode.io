"""HMAC-SHA256 verification of GitHub webhook deliveries."""

import hashlib
import hmac


def compute_signature(body: bytes, secret: str) -> str:
    """Return the value GitHub puts in the X-Hub-Signature-256 header."""
    digest = hmac.new(secret.encode(), body, hashlib.sha256).hexdigest()
    return f"sha256={digest}"


def verify_signature(body: bytes, signature_header: str, secret: str) -> bool:
    """True only if the header matches the body signed with our secret.

    compare_digest is constant-time, so attackers can't guess the
    signature byte by byte from response timing.
    """
    if not secret or not signature_header or not signature_header.startswith("sha256="):
        return False
    return hmac.compare_digest(compute_signature(body, secret), signature_header)