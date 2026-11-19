"""Fakes shared by the Release 2 tests."""

from __future__ import annotations

import os
import tempfile
from pathlib import Path

from pipeline.github_client import GitHubError
from pipeline.models import ChangedFile, PullRequest
from pipeline.service import ReviewService
from pipeline.store import Store
from tests.pipeline_helpers import make_settings, make_tarball

SHA_A = "a" * 40
SHA_B = "b" * 40


def make_pr(sha: str = SHA_A, number: int = 7, repo: str = "me/r") -> PullRequest:
    return PullRequest(repo, number, sha, "main", "feature", "Add feature", "dev", "http://pr")


class FakeGitHub:
    def __init__(self, files=None, head_sha: str = SHA_A):
        self.files = files if files is not None else [ChangedFile("a.py", "added", 1, 0, "@@ -0,0 +1,1 @@\n+x = 1")]
        self.head_sha = head_sha
        self.fail_files = self.fail_head = self.fail_dispatch = False
        self.comments: list[str] = []
        self.statuses: list[tuple[str, str]] = []
        self.dispatches: list[tuple] = []

    def list_pr_files(self, repo, number):
        if self.fail_files:
            raise GitHubError("files -> HTTP 404")
        return self.files

    def download_tarball(self, repo, sha, dest, max_bytes):
        make_tarball(Path(dest), {"a.py": "x = 1\n"})
        return 1

    def get_pr_head_sha(self, repo, number):
        if self.fail_head:
            raise GitHubError("head -> HTTP 500")
        return self.head_sha

    def upsert_comment(self, repo, number, marker, body):
        self.comments.append(body)
        return "http://comment"

    def set_commit_status(self, repo, sha, state, description, context, target_url=None):
        self.statuses.append((state, description))

    def dispatch_workflow(self, repo, workflow, ref, inputs=None):
        if self.fail_dispatch:
            raise GitHubError("dispatch -> HTTP 422")
        self.dispatches.append((repo, workflow, ref, inputs))


def make_store(test_case, clock=None) -> Store:
    fd, path = tempfile.mkstemp(suffix=".db", prefix="bc-test-")
    os.close(fd)
    test_case.addCleanup(lambda: [os.path.exists(path + s) and os.remove(path + s) for s in ("", "-wal", "-shm")])
    return Store(path, clock) if clock else Store(path)


def make_service(test_case, agents=None, client=None, clock=None, **settings):
    store = make_store(test_case, clock)
    client = client or FakeGitHub()
    factory = (lambda s: list(agents)) if agents is not None else None
    service = ReviewService(store, make_settings(db_path=store.path, **settings), client=client, agents_factory=factory)
    return service, store, client
