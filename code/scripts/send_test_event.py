"""
Send a correctly signed fake GitHub event to the local receiver - no GitHub
or ngrok needed. Useful for testing the receiver on its own.

    python scripts/send_test_event.py              # pull_request 'opened'
    python scripts/send_test_event.py --event ping
    python scripts/send_test_event.py --bad-signature
    python scripts/send_test_event.py --url https://<ngrok-domain>/webhook   # test through the tunnel
"""

import argparse
import json
import os
import sys
import uuid
from pathlib import Path

import requests
from dotenv import load_dotenv

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from webhook.security import compute_signature  # noqa: E402

load_dotenv()

FAKE_PR = {
    "action": "opened",
    "number": 1,
    "repository": {"full_name": "your-user/your-test-repo"},
    "pull_request": {
        "number": 1,
        "title": "Test PR from send_test_event.py",
        "user": {"login": "tester"},
        "base": {"ref": "main"},
        "head": {"ref": "feature/test", "sha": "0123456789abcdef0123456789abcdef01234567"},
        "html_url": "https://github.com/your-user/your-test-repo/pull/1",
    },
}


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--url", default=f"http://127.0.0.1:{os.getenv('PORT', '5000')}/webhook")
    parser.add_argument("--event", default="pull_request", choices=["pull_request", "ping", "push"])
    parser.add_argument("--bad-signature", action="store_true")
    args = parser.parse_args()

    payload = {"zen": "Keep it logically awesome.", "hook_id": 0} if args.event == "ping" else FAKE_PR
    body = json.dumps(payload).encode()
    secret = os.getenv("GITHUB_WEBHOOK_SECRET", "")
    signature = "sha256=deadbeef" if args.bad_signature else compute_signature(body, secret)

    resp = requests.post(
        args.url,
        data=body,
        headers={
            "Content-Type": "application/json",
            "X-GitHub-Event": args.event,
            "X-GitHub-Delivery": str(uuid.uuid4()),
            "X-Hub-Signature-256": signature,
        },
        timeout=10,
    )
    print(resp.status_code, resp.text)


if __name__ == "__main__":
    main()
