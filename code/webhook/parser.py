"""Extract PR context from a GitHub pull_request webhook payload."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass
class PRContext:
    repo: str
    pr_number: int
    title: str
    author: str
    base_branch: str
    head_branch: str
    head_sha: str
    diff_url: str
    changed_files: list[str] = field(default_factory=list)
    additions: int = 0
    deletions: int = 0



def parse_pr_payload(payload: dict[str, Any]) -> PRContext | None:
    """Return a PRContext from a GitHub pull_request event payload, or None if not applicable."""
    action = payload.get("action")
    if action not in ("opened", "synchronize", "reopened"):
        return None

    pr = payload.get("pull_request", {})
    base = pr.get("base", {})
    head = pr.get("head", {})
    repo = payload.get("repository", {})

    if base.get("ref") != "main":
        return None

    return PRContext(
        repo=repo.get("full_name", ""),
        pr_number=pr.get("number", 0),
        title=pr.get("title", ""),
        author=pr.get("user", {}).get("login", ""),
        base_branch=base.get("ref", "main"),
        head_branch=head.get("ref", ""),
        head_sha=head.get("sha", ""),
        diff_url=pr.get("diff_url", ""),
        changed_files=[],
        additions=pr.get("additions", 0),
        deletions=pr.get("deletions", 0),
    )