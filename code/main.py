"""FastAPI webhook receiver for GitHub pull_request events."""

from __future__ import annotations

import logging
import sys
from pathlib import Path

from dotenv import load_dotenv
from fastapi import FastAPI, Header, HTTPException, Request, status  # pyright: ignore[reportMissingImports]

# `python main.py` puts this file's directory on sys.path, not the parent that
# contains the `webhook` package. Insert the parent so package imports work
# the same as `python -m webhook.main`.
_pkg_root = Path(__file__).resolve().parent.parent
if str(_pkg_root) not in sys.path:
    sys.path.insert(0, str(_pkg_root))

from webhook.parser import parse_pr_payload
from webhook.verifier import verify_signature

load_dotenv()  # load .env so GITHUB_WEBHOOK_SECRET is available

logger = logging.getLogger(__name__)
app = FastAPI(title=__name__)


@app.get("/health")
async def health() -> dict:
    return {"status": "ok"}


@app.post("/webhook", status_code=status.HTTP_202_ACCEPTED)
async def github_webhook(
    request: Request,
    x_github_event: str = Header(default=""),
    x_hub_signature_256: str = Header(default=""),
) -> dict:
    raw_body = await request.body()

    if not verify_signature(raw_body, x_hub_signature_256):
        raise HTTPException(status_code=401, detail="Invalid signature")

    if x_github_event != "pull_request":
        return {"ignored": True, "event": x_github_event}

    payload = await request.json()
    pr = parse_pr_payload(payload)
    if pr is None:
        return {"ignored": True, "reason": "not a main-targeting PR open/sync"}


if __name__ == "__main__":
    
    # This makes `python -m webhook.main` the single start command everywhere — no shell
    # variable expansion needed in the platform's start-command field.
    import os

    import uvicorn

    uvicorn.run(app, host="0.0.0.0", port=int(os.environ.get("PORT", "5001")))