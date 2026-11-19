"""
DeployGuard-Local — Step 1: GitHub webhook receiver.

Flow:
    GitHub --(HTTPS)--> ngrok --(http://localhost:5000)--> this app
    1. Verify the HMAC-SHA256 signature (reject anything not from GitHub).
    2. Accept only the events we care about (pull_request opened / synchronize / reopened).
    3. Put the job on an in-memory queue and reply 202 immediately
       (GitHub gives up after ~10 s, agents will take longer).
    4. A background worker (pipeline.service.Worker) takes the run from the database queue and
    runs Scan -> Security -> (Triage) -> Risk, then waits for a person on the dashboard.

Run:
    python -m webhook.app
"""

import json
import logging
from datetime import datetime, timezone
from pathlib import Path

from flask import Flask, jsonify, request

from webhook.config import settings
from webhook.security import verify_signature

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s  %(levelname)-7s  %(name)s: %(message)s",
)
log = logging.getLogger("webhook")

app = Flask(__name__)

RELEVANT_PR_ACTIONS = {"opened", "synchronize", "reopened"}
PAYLOAD_DIR = Path("payloads")  # raw events saved here for debugging / tests

_worker = None  # created on first use, so importing this module does not open the database


def get_worker():
    """The review worker (queue + database). Built once, from the .env settings."""
    global _worker
    if _worker is None:
        from pipeline.service import build_runtime
        _worker = build_runtime()[1]
    return _worker


def save_payload(event_name: str, delivery_id: str, payload: dict) -> None:
    if not settings.save_payloads:
        return
    PAYLOAD_DIR.mkdir(exist_ok=True)
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S")
    path = PAYLOAD_DIR / f"{stamp}_{event_name}_{delivery_id[:8]}.json"
    path.write_text(json.dumps(payload, indent=2))
    log.info("Saved payload to %s", path)


# --------------------------------------------------------------------------- #
# Routes
# --------------------------------------------------------------------------- #
@app.get("/")
def health():
    """Open the ngrok URL in a browser to check the tunnel reaches this app."""
    queued = _worker.jobs.qsize() if _worker is not None else 0
    return jsonify(status="ok", service="brofessorcode-webhook", queued_jobs=queued)


@app.post("/webhook")
def github_webhook():
    raw_body = request.get_data()  # must use raw bytes for the signature check
    signature = request.headers.get("X-Hub-Signature-256", "")
    event_name = request.headers.get("X-GitHub-Event", "")
    delivery_id = request.headers.get("X-GitHub-Delivery") or None  # None: nothing to de-duplicate on

    # 1. Authenticate
    if not verify_signature(raw_body, signature, settings.webhook_secret):
        log.warning("Rejected delivery %s: bad or missing signature", delivery_id)
        return jsonify(error="invalid signature"), 401

    # 2. Parse
    if not request.is_json:
        log.warning("Delivery %s is not JSON - set Content type to application/json in GitHub", delivery_id)
        return jsonify(error="content type must be application/json"), 415
    payload = request.get_json(silent=True) or {}
    save_payload(event_name, delivery_id or "none", payload)

    # 3. Route by event type
    if event_name == "ping":
        log.info("Ping received (hook id %s) - webhook is connected", payload.get("hook_id"))
        return jsonify(message="pong"), 200

    if event_name != "pull_request":
        log.info("Ignoring event '%s'", event_name)
        return jsonify(message=f"ignored event {event_name}"), 200

    action = payload.get("action")
    if action not in RELEVANT_PR_ACTIONS:
        log.info("Ignoring pull_request action '%s'", action)
        return jsonify(message=f"ignored action {action}"), 200

    base = ((payload.get("pull_request") or {}).get("base") or {}).get("ref")
    if settings.base_branch and base != settings.base_branch:
        log.info("Ignoring PR into '%s' (only watching '%s')", base, settings.base_branch)
        return jsonify(message="ignored base branch"), 200

    # 4. Store the run and reply fast. The worker thread does the slow work.
    try:
        sub = get_worker().submit(payload, delivery_id)
    except (KeyError, TypeError, ValueError):
        log.warning("Delivery %s has a pull_request payload that is missing fields", delivery_id)
        return jsonify(error="incomplete pull_request payload"), 400
    if sub.run_id is None:
        log.info("Not queued: %s", sub.reason)
        return jsonify(message="ignored", reason=sub.reason, delivery=delivery_id), 202
    log.info("Queued run %s for PR #%s (%s)", sub.run_id, payload["pull_request"]["number"], action)
    return jsonify(message="queued", run=sub.run_id, superseded=sub.superseded, delivery=delivery_id), 202


def main() -> None:
    get_worker().start()  # re-queues unfinished runs, starts the worker and the expiry timer
    log.info("Listening on http://127.0.0.1:%s  (POST /webhook)", settings.port)
    # use_reloader=False: the reloader would start the worker twice
    app.run(host="127.0.0.1", port=settings.port, debug=False, use_reloader=False)


if __name__ == "__main__":
    main()
