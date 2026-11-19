"""The few GitHub REST calls the pipeline needs."""

from __future__ import annotations

import logging
from pathlib import Path

import requests

from pipeline.models import ChangedFile

log = logging.getLogger("pipeline.github")
API = "https://api.github.com"


class GitHubError(RuntimeError):
    pass


class GitHubClient:
    def __init__(self, token: str, session: requests.Session | None = None, timeout: int = 30) -> None:
        self.token = token
        self.session = session or requests.Session()
        self.timeout = timeout

    def _headers(self) -> dict[str, str]:
        return {
            "Authorization": f"Bearer {self.token}",
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28",
        }

    def _request(self, method: str, path: str, **kwargs) -> requests.Response:
        resp = self.session.request(method, f"{API}{path}", headers=self._headers(),
                                    timeout=self.timeout, **kwargs)
        if resp.status_code >= 400:
            raise GitHubError(f"{method} {path} -> HTTP {resp.status_code}: {resp.text[:200]}")
        return resp

    # ---- reading the PR ----
    def list_pr_files(self, repo: str, number: int) -> list[ChangedFile]:
        files: list[ChangedFile] = []
        page = 1
        while True:
            resp = self._request("GET", f"/repos/{repo}/pulls/{number}/files",
                                 params={"per_page": 100, "page": page})
            batch = resp.json()
            for f in batch:
                files.append(ChangedFile(
                    filename=f["filename"], status=f.get("status", "modified"),
                    additions=f.get("additions", 0), deletions=f.get("deletions", 0),
                    patch=f.get("patch")))
            if len(batch) < 100 or page >= 30:  # the API returns at most 3000 files
                return files
            page += 1

    def get_pr_head_sha(self, repo: str, number: int) -> str:
        return self._request("GET", f"/repos/{repo}/pulls/{number}").json()["head"]["sha"]

    def download_tarball(self, repo: str, sha: str, dest: Path, max_bytes: int) -> int:
        """Stream the repository at `sha` into `dest`. Returns the bytes written."""
        resp = self.session.get(f"{API}/repos/{repo}/tarball/{sha}", headers=self._headers(),
                                stream=True, timeout=60)
        if resp.status_code >= 400:
            raise GitHubError(f"tarball {repo}@{sha[:7]} -> HTTP {resp.status_code}")
        size = 0
        with open(dest, "wb") as out:
            for chunk in resp.iter_content(chunk_size=1 << 16):
                size += len(chunk)
                if size > max_bytes:
                    raise GitHubError("repository archive is larger than the allowed size")
                out.write(chunk)
        return size

    # ---- writing back ----
    def upsert_comment(self, repo: str, number: int, marker: str, body: str) -> str:
        """Update our earlier report comment if there is one, otherwise create it."""
        existing_id = None
        for page in range(1, 6):
            comments = self._request("GET", f"/repos/{repo}/issues/{number}/comments",
                                     params={"per_page": 100, "page": page}).json()
            for c in comments:
                if marker in (c.get("body") or ""):
                    existing_id = c["id"]
            if existing_id or len(comments) < 100:
                break
        if existing_id:
            resp = self._request("PATCH", f"/repos/{repo}/issues/comments/{existing_id}", json={"body": body})
        else:
            resp = self._request("POST", f"/repos/{repo}/issues/{number}/comments", json={"body": body})
        return resp.json().get("html_url", "")

    def set_commit_status(self, repo: str, sha: str, state: str, description: str,
                          context: str, target_url: str | None = None) -> None:
        payload = {"state": state, "description": description[:140], "context": context}
        if target_url:
            payload["target_url"] = target_url
        self._request("POST", f"/repos/{repo}/statuses/{sha}", json=payload)

    def dispatch_workflow(self, repo: str, workflow: str, ref: str, inputs: dict | None = None) -> None:
        """Start a GitHub Actions workflow that has a workflow_dispatch trigger."""
        payload: dict = {"ref": ref}
        if inputs:
            payload["inputs"] = inputs
        self._request("POST", f"/repos/{repo}/actions/workflows/{workflow}/dispatches", json=payload)
