"""
Pipeline entry point.

For Step 1 this only proves the full loop works: it reads the PR's changed
files from the GitHub API and posts a comment back on the PR. In later steps
this is where the orchestrator runs Scan -> Security -> Risk -> Deploy -> Report.
"""

import logging
from dataclasses import dataclass

import requests

from webhook.config import settings

log = logging.getLogger("pipeline")
GITHUB_API = "https://api.github.com"


@dataclass(frozen=True)
class PullRequestEvent:
    delivery_id: str
    action: str
    repo_full_name: str  # "owner/repo"
    pr_number: int
    title: str
    author: str
    base_branch: str
    head_branch: str
    head_sha: str
    html_url: str

    @classmethod
    def from_payload(cls, payload: dict, delivery_id: str) -> "PullRequestEvent":
        pr = payload["pull_request"]
        return cls(
            delivery_id=delivery_id,
            action=payload["action"],
            repo_full_name=payload["repository"]["full_name"],
            pr_number=pr["number"],
            title=pr["title"],
            author=pr["user"]["login"],
            base_branch=pr["base"]["ref"],
            head_branch=pr["head"]["ref"],
            head_sha=pr["head"]["sha"],
            html_url=pr["html_url"],
        )


def _headers() -> dict:
    return {
        "Authorization": f"Bearer {settings.github_token}",
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28",
    }


def get_changed_files(event: PullRequestEvent) -> list[dict]:
    url = f"{GITHUB_API}/repos/{event.repo_full_name}/pulls/{event.pr_number}/files"
    files, page = [], 1
    while True:
        resp = requests.get(url, headers=_headers(), params={"per_page": 100, "page": page}, timeout=15)
        resp.raise_for_status()
        batch = resp.json()
        files.extend(batch)
        if len(batch) < 100:
            return files
        page += 1


def post_pr_comment(event: PullRequestEvent, body: str) -> None:
    url = f"{GITHUB_API}/repos/{event.repo_full_name}/issues/{event.pr_number}/comments"
    resp = requests.post(url, headers=_headers(), json={"body": body}, timeout=15)
    resp.raise_for_status()
    log.info("Comment posted: %s", resp.json().get("html_url"))


def run_pipeline(event: PullRequestEvent) -> None:
    if not settings.github_token:
        log.warning("GITHUB_TOKEN not set — skipping GitHub API calls (receiver-only mode)")
        return

    files = get_changed_files(event)
    log.info("PR #%s changes %d file(s)", event.pr_number, len(files))
    for f in files:
        log.info("  %-9s %s (+%s/-%s)", f["status"], f["filename"], f["additions"], f["deletions"])

    if not settings.post_comments:
        return

    rows = "\n".join(
        f"| `{f['filename']}` | {f['status']} | +{f['additions']} / -{f['deletions']} |" for f in files[:30]
    )
    more = f"\n\n…and {len(files) - 30} more file(s)." if len(files) > 30 else ""
    body = (
        "### 🛡️ DeployGuard-Local received this PR\n\n"
        f"Commit `{event.head_sha[:7]}` · action `{event.action}` · {len(files)} changed file(s)\n\n"
        "| File | Status | Lines |\n|---|---|---|\n"
        f"{rows}{more}\n\n"
        "_Agent review is not wired in yet — this comment confirms the webhook loop works._"
    )
    post_pr_comment(event, body)