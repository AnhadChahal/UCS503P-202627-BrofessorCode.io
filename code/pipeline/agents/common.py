"""Helpers used by more than one agent."""

from __future__ import annotations

import os
from pathlib import Path
from typing import Iterable, Iterator

from pipeline.config import PipelineSettings
from pipeline.models import Finding, PipelineContext, Severity, Status


def status_from(findings: list[Finding], block_at: Severity, tool_failed: bool) -> Status:
    """BLOCK if a finding reaches `block_at`; ESCALATE if a tool failed (never a silent
    pass); WARN if there is anything else to report; otherwise PASS."""
    real = [f for f in findings if f.severity >= Severity.LOW]
    if any(f.severity >= block_at for f in real):
        return Status.BLOCK
    if tool_failed:
        return Status.ESCALATE
    if real:
        return Status.WARN
    return Status.PASS


def rel(path: str, repo_dir: Path) -> str:
    """Make a tool's file path relative to the repository folder."""
    if not path:
        return path
    if os.path.isabs(path):
        for base in (repo_dir, repo_dir.resolve()):
            candidate = os.path.relpath(path, base)
            if not candidate.startswith(".."):
                return Path(candidate).as_posix()
        return Path(path).name
    return Path(os.path.normpath(path)).as_posix()


def short(text: str, limit: int = 200) -> str:
    text = " ".join((text or "").split())
    return text if len(text) <= limit else text[: limit - 3] + "..."


def chunks(items: list[str], size: int = 100) -> Iterator[list[str]]:
    for i in range(0, len(items), size):
        yield items[i:i + size]


def keep_changed(findings: Iterable[Finding], ctx: PipelineContext, settings: PipelineSettings) -> list[Finding]:
    """Drop findings on lines the PR did not add (when ONLY_CHANGED_LINES is on)."""
    findings = list(findings)
    if not settings.only_changed_lines:
        return findings
    added = {f.filename: f.added_line_numbers() for f in ctx.files}
    kept: list[Finding] = []
    for f in findings:
        lines = added.get(f.file) if f.file else None
        if f.file and f.line is not None and lines is not None and f.line not in lines:
            continue
        kept.append(f)
    return kept
