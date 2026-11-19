"""A small secret detector for lines that a PR adds.

It only looks at added lines, never prints the secret itself, and is meant as a
first line of defence. A dedicated tool such as gitleaks can replace it later."""

from __future__ import annotations

import re
from pathlib import PurePosixPath

from pipeline.models import ChangedFile, Finding, Severity, parse_added

AGENT = "SecurityAgent"

_PATTERNS: list[tuple[str, re.Pattern, Severity]] = [
    ("aws-access-key-id", re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b"), Severity.CRITICAL),
    ("github-token", re.compile(r"\bgh[pousr]_[A-Za-z0-9]{36,}\b"), Severity.CRITICAL),
    ("github-fine-grained-token", re.compile(r"\bgithub_pat_[A-Za-z0-9_]{22,}\b"), Severity.CRITICAL),
    ("slack-token", re.compile(r"\bxox[abprs]-[A-Za-z0-9-]{10,}\b"), Severity.CRITICAL),
    ("private-key", re.compile(r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY-----"), Severity.CRITICAL),
    ("google-api-key", re.compile(r"\bAIza[0-9A-Za-z_\-]{35}\b"), Severity.HIGH),
    ("hardcoded-credential",
     # the name may have a prefix (DB_PASSWORD, stripe_secret_key) but 'tokenizer = "..."' must not match
     re.compile(r"""(?i)\b[\w.-]*(?:api[_-]?key|secret|token|passwd|password|pwd)(?:[_-]?(?:key|value|id))?\s*[:=]\s*['"]([^'"\s]{8,})['"]"""),
     Severity.MEDIUM),
]
_PLACEHOLDERS = ("example", "changeme", "placeholder", "your-", "your_", "xxxx", "****", "<", ">", "${", "{{")
_ENV_TEMPLATES = (".example", ".sample", ".template", ".dist")


def _redact(value: str) -> str:
    return value[:4] + "****" if len(value) > 8 else "****"


def scan_added_lines(files: list[ChangedFile]) -> list[Finding]:
    findings: list[Finding] = []
    seen: set[tuple[str, int | None, str]] = set()

    def add(file: str, line: int | None, rule: str, sev: Severity, message: str, suggestion: str) -> None:
        key = (file, line, rule)
        if key not in seen:
            seen.add(key)
            findings.append(Finding(AGENT, "secret-scan", rule, sev, message, file, line, suggestion))

    for f in files:
        if f.status == "removed":
            continue
        base = PurePosixPath(f.filename).name
        if (base == ".env" or base.startswith(".env.")) and not base.endswith(_ENV_TEMPLATES):
            add(f.filename, None, "env-file-committed", Severity.HIGH,
                "An environment file is part of this PR. It usually contains secrets.",
                "Remove the file, add it to .gitignore and rotate any secret it held.")
        for line_no, text in parse_added(f.patch):
            for rule, pattern, sev in _PATTERNS:
                m = pattern.search(text)
                if not m:
                    continue
                value = m.group(1) if m.groups() else m.group(0)
                if rule == "hardcoded-credential" and any(p in value.lower() for p in _PLACEHOLDERS):
                    continue
                shown = "a private key block" if rule == "private-key" else f"value starting {_redact(value)}"
                add(f.filename, line_no, rule, sev, f"Possible secret committed ({rule}): {shown}.",
                    "Remove it from the code, rotate the secret and load it from the environment.")
    return findings


def mask_secrets(text: str) -> str:
    """Replace anything that looks like a secret with [REDACTED]. Used before code is shown to a model."""
    for rule, pattern, _ in _PATTERNS:
        if rule == "hardcoded-credential":
            text = pattern.sub(lambda m: m.group(0).replace(m.group(1), "[REDACTED]"), text)
        else:
            text = pattern.sub("[REDACTED]", text)
    return text
