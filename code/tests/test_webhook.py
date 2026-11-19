"""Run with:  python -m pytest -q   (no network, no GitHub needed)"""

import json
import os
import tempfile

import pytest

_TMP = tempfile.mkdtemp(prefix="bc-webhook-")
os.environ["GITHUB_WEBHOOK_SECRET"] = "test-secret"
os.environ["GITHUB_TOKEN"] = ""
os.environ["SAVE_PAYLOADS"] = "false"
os.environ["BASE_BRANCH"] = "main"
os.environ["DB_PATH"] = os.path.join(_TMP, "test.db")

from pipeline.store import Store, Submission  # noqa: E402
from webhook import app as app_module  # noqa: E402
from webhook.security import compute_signature, verify_signature  # noqa: E402

SECRET = "test-secret"

PR_PAYLOAD = {
    "action": "opened",
    "repository": {"full_name": "me/repo"},
    "pull_request": {
        "number": 7, "title": "t", "user": {"login": "u"},
        "base": {"ref": "main"}, "head": {"ref": "f", "sha": "a" * 40},
        "html_url": "https://github.com/me/repo/pull/7",
    },
}


class FakeWorker:
    """Stands in for pipeline.service.Worker: records what the webhook hands over."""

    def __init__(self, result=None, error=None):
        self.calls = []
        self.result, self.error = result, error

    def submit(self, payload, delivery_id=None):
        self.calls.append((payload, delivery_id))
        if self.error:
            raise self.error
        return self.result or Submission(len(self.calls))


@pytest.fixture
def worker(monkeypatch):
    fake = FakeWorker()
    monkeypatch.setattr(app_module, "get_worker", lambda: fake)
    return fake


def post(event, payload, signature=None, delivery="test-delivery"):
    body = json.dumps(payload).encode()
    headers = {"X-GitHub-Event": event, "X-Hub-Signature-256": signature or compute_signature(body, SECRET)}
    if delivery:
        headers["X-GitHub-Delivery"] = delivery
    return app_module.app.test_client().post("/webhook", data=body, content_type="application/json", headers=headers)


def test_signature_roundtrip():
    body = b'{"a": 1}'
    assert verify_signature(body, compute_signature(body, "s"), "s")
    assert not verify_signature(body, compute_signature(body, "other"), "s")
    assert not verify_signature(body, "", "s")
    assert not verify_signature(body, "sha1=abc", "s")


def test_rejects_bad_signature(worker):
    assert post("pull_request", PR_PAYLOAD, signature="sha256=bad").status_code == 401
    assert worker.calls == []


def test_ping_returns_pong(worker):
    resp = post("ping", {"hook_id": 1})
    assert resp.status_code == 200 and resp.get_json()["message"] == "pong"


def test_pr_opened_is_handed_to_the_worker(worker):
    resp = post("pull_request", PR_PAYLOAD)
    assert resp.status_code == 202 and resp.get_json()["message"] == "queued"
    (payload, delivery), = worker.calls
    assert payload["pull_request"]["number"] == 7 and delivery == "test-delivery"


def test_missing_delivery_header_is_passed_as_none(worker):
    post("pull_request", PR_PAYLOAD, delivery=None)
    assert worker.calls[0][1] is None


def test_duplicate_or_known_commit_is_acknowledged_but_not_queued(monkeypatch):
    fake = FakeWorker(result=Submission(None, [], "duplicate delivery"))
    monkeypatch.setattr(app_module, "get_worker", lambda: fake)
    resp = post("pull_request", PR_PAYLOAD)
    assert resp.status_code == 202 and resp.get_json()["message"] == "ignored"


def test_incomplete_payload_is_a_400_not_a_crash(monkeypatch):
    monkeypatch.setattr(app_module, "get_worker", lambda: FakeWorker(error=KeyError("head")))
    assert post("pull_request", PR_PAYLOAD).status_code == 400


@pytest.mark.parametrize("action", ["closed", "labeled", "edited"])
def test_other_actions_are_ignored(worker, action):
    assert post("pull_request", {**PR_PAYLOAD, "action": action}).status_code == 200
    assert worker.calls == []


def test_other_base_branch_is_ignored(worker):
    payload = json.loads(json.dumps(PR_PAYLOAD))
    payload["pull_request"]["base"]["ref"] = "dev"
    assert post("pull_request", payload).status_code == 200 and worker.calls == []


def test_push_event_is_ignored(worker):
    assert post("push", {"ref": "refs/heads/main"}).status_code == 200 and worker.calls == []


def test_real_worker_stores_a_queued_run_and_dedupes(monkeypatch):
    """No fake: the webhook -> Worker -> Store path, with the worker thread not started."""
    monkeypatch.setattr(app_module, "_worker", None)
    first = post("pull_request", PR_PAYLOAD, delivery="d-1")
    again = post("pull_request", PR_PAYLOAD, delivery="d-1")
    assert first.status_code == again.status_code == 202
    runs = Store(os.environ["DB_PATH"]).list_runs()
    assert [r["status"] for r in runs] == ["queued"]
    assert (runs[0]["repo"], runs[0]["pr_number"], runs[0]["head_sha"]) == ("me/repo", 7, "a" * 40)
    monkeypatch.setattr(app_module, "_worker", None)
