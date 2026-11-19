"""Plain data types shared by the orchestrator and the agents."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from enum import Enum, IntEnum
from pathlib import Path
from typing import Any


class Severity(IntEnum):
    INFO = 0
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4


class Status(str, Enum):
    PASS = "PASS"
    WARN = "WARN"
    BLOCK = "BLOCK"
    ESCALATE = "ESCALATE"


@dataclass
class Finding:
    agent: str
    tool: str
    rule: str
    severity: Severity
    message: str
    file: str | None = None
    line: int | None = None
    suggestion: str | None = None


@dataclass
class Verdict:
    agent: str
    status: Status
    findings: list[Finding] = field(default_factory=list)
    summary: str = ""
    notes: list[str] = field(default_factory=list)  # which checks ran or were skipped
    duration_s: float = 0.0
    data: dict = field(default_factory=dict)  # structured extras, e.g. the risk score


# ---- diffs ---------------------------------------------------------------

_HUNK = re.compile(r"^@@ -\d+(?:,\d+)? \+(\d+)(?:,\d+)? @@")


def parse_added(patch: str | None) -> list[tuple[int, str]]:
    """Return (line number in the new file, text) for every added line of a patch."""
    added: list[tuple[int, str]] = []
    if not patch:
        return added
    new_line = 0
    for raw in patch.splitlines():
        hunk = _HUNK.match(raw)
        if hunk:
            new_line = int(hunk.group(1))
            continue
        if raw.startswith("+"):
            added.append((new_line, raw[1:]))
            new_line += 1
        elif raw.startswith("-") or raw.startswith("\\"):
            continue  # removed line, or '\ No newline at end of file'
        else:
            new_line += 1  # context line
    return added


@dataclass
class ChangedFile:
    filename: str
    status: str  # added, modified, removed, renamed ...
    additions: int = 0
    deletions: int = 0
    patch: str | None = None  # GitHub omits it for binary or very large diffs

    def added_line_numbers(self) -> set[int] | None:
        """Lines added by the PR, or None if unknown (then treat the whole file as changed)."""
        if self.patch is None:
            return None
        return {n for n, _ in parse_added(self.patch)}


# ---- pull request --------------------------------------------------------

def _pick(obj: Any, *names: str) -> Any:
    for name in names:
        if isinstance(obj, dict):
            if name in obj and obj[name] is not None:
                return obj[name]
        elif getattr(obj, name, None) is not None:
            return getattr(obj, name)
    return None


@dataclass(frozen=True)
class PullRequest:
    repo: str          # "owner/name"
    number: int
    head_sha: str
    base_branch: str = ""
    head_branch: str = ""
    title: str = ""
    author: str = ""
    html_url: str = ""

    @classmethod
    def from_parsed(cls, obj: Any) -> "PullRequest":
        """Accept a PullRequest, a raw GitHub webhook payload, or any object or dict
        with common field names. Adapt here if your parser uses different names."""
        if isinstance(obj, cls):
            return obj
        if isinstance(obj, dict) and "pull_request" in obj:  # raw webhook payload
            pr = obj["pull_request"]
            return cls(
                repo=obj["repository"]["full_name"],
                number=int(pr["number"]),
                head_sha=pr["head"]["sha"],
                base_branch=pr["base"]["ref"],
                head_branch=pr["head"]["ref"],
                title=pr.get("title", ""),
                author=(pr.get("user") or {}).get("login", ""),
                html_url=pr.get("html_url", ""),
            )
        repo = _pick(obj, "repo", "repo_full_name", "full_name", "repository")
        number = _pick(obj, "number", "pr_number")
        sha = _pick(obj, "head_sha", "sha")
        if not (repo and number and sha):
            raise ValueError(
                "Cannot build a PullRequest: need repo, number and head_sha. "
                "Adapt PullRequest.from_parsed() to the names your parser uses."
            )
        return cls(
            repo=str(repo),
            number=int(number),
            head_sha=str(sha),
            base_branch=str(_pick(obj, "base_branch", "base") or ""),
            head_branch=str(_pick(obj, "head_branch", "head") or ""),
            title=str(_pick(obj, "title") or ""),
            author=str(_pick(obj, "author", "user") or ""),
            html_url=str(_pick(obj, "html_url", "url") or ""),
        )


@dataclass(frozen=True)
class Approval:
    decision: str  # approve | reject | block
    by: str        # the engineer's user name, or 'policy'
    reason: str
    head_sha: str  # the commit that was reviewed


@dataclass
class PipelineContext:
    """Everything the agents may read. The orchestrator fills `verdicts`."""
    pr: PullRequest
    files: list[ChangedFile]
    repo_dir: Path
    verdicts: list[Verdict] = field(default_factory=list)
    approval: Approval | None = None

    def existing_python_files(self) -> list[str]:
        return [
            f.filename for f in self.files
            if f.status != "removed" and f.filename.endswith(".py")
            and (self.repo_dir / f.filename).is_file()
        ]


def finding_key(agent: str, rule: str, file: str | None, line: int | None) -> str:
    """Identifies one finding, so a note from another agent (for example the AI triage)
    can be attached to it later, also after it has been stored and read back."""
    return f"{agent}|{rule}|{file or ''}|{line if line is not None else ''}"
