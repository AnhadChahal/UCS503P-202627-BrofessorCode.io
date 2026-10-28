
## This is a simple flask server that receives GitHub webhook events and verifies their signatures using a shared secret.

## make the necessary imports

## os for environment variables, hmac and hashlib for signature verification, json for parsing payloads, dotenv for loading .env files, and flask for creating the server.
import os
import hmac
import hashlib
import json

from pathlib import Path
from dotenv import load_dotenv
from flask import Flask, request, abort

# Locate the directory containing Server.py
BASE_DIR = Path(__file__).resolve().parent

# Load .env from the same directory
load_dotenv(BASE_DIR / ".env")

app = Flask(__name__)

# Read the shared GitHub webhook secret from the env file
WEBHOOK_SECRET = os.getenv("GITHUB_WEBHOOK_SECRET")

# check presence of the secret string, if not present raise a runtime error
if not WEBHOOK_SECRET:
    print("DEBUG: GitHub signature header is missing")
    raise RuntimeError(
        "Set GITHUB_WEBHOOK_SECRET before starting the server."
    )

# function to verify the signature of the incoming webhook request
def verify_signature(payload: bytes, signature: str | None) -> bool:

    if not signature or not signature.startswith("sha256="):
        print("DEBUG: Signature mismatch — check your secret")
        return False

    expected = "sha256=" + hmac.new(
        WEBHOOK_SECRET.encode("utf-8"),
        payload,
        hashlib.sha256
    ).hexdigest()

    if not hmac.compare_digest(expected, signature):
        print("DEBUG: Signature mismatch — check the shared secret")
        return False

    print("DEBUG: Signature verified successfully")
    return True


@app.route("/webhook", methods=["POST"])
def github_webhook():

    # 1. Read the original request body.
    raw_payload = request.get_data(cache=True)

    # 2. Retrieve GitHub's signature header.
    signature = request.headers.get("X-Hub-Signature-256")

    # 3. Reject requests with an invalid signature.
    if not verify_signature(raw_payload, signature):
        abort(403, description="Invalid webhook signature")

    # 4. Parse JSON only after signature verification.
    try:
        payload = json.loads(raw_payload)
    except (json.JSONDecodeError, UnicodeDecodeError):
        abort(400, description="Invalid JSON payload")

    # GitHub webhook payloads should be JSON objects.
    if not isinstance(payload, dict):
        abort(400, description="Expected a JSON object")

    # 5. Read GitHub event metadata.
    event = request.headers.get("X-GitHub-Event", "unknown")
    delivery_id = request.headers.get(
        "X-GitHub-Delivery", "unknown"
    )

    print(f"\nReceived GitHub event: {event}")
    print(f"Delivery ID: {delivery_id}")

    # 6. Process the event.
    if event == "ping":
        print("Webhook connection test successful.")

    elif event == "push":
        repository = payload.get("repository", {})

        print("Repository:", repository.get("full_name"))
        print("Branch:", payload.get("ref"))
        print("Pusher:", payload.get("pusher", {}).get("name"))

        for commit in payload.get("commits", []):
            print("Commit:", commit.get("id", "")[:7])
            print("Message:", commit.get("message", ""))

    elif event == "issues":
        issue = payload.get("issue", {})

        print("Action:", payload.get("action"))
        print("Issue:", issue.get("title"))
        print("URL:", issue.get("html_url"))

    else:
        print(json.dumps(payload, indent=2))

    # 7. Return a successful HTTP response.
    return {"ok": True, "event": event}, 200


if __name__ == "__main__":
    app.run(
        host="127.0.0.1",
        port=5050,
        debug=False
    )
