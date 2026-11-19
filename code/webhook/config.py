"""Settings loaded from the .env file in the project root."""

import os
from dataclasses import dataclass

from dotenv import load_dotenv

load_dotenv()


@dataclass(frozen=True)
class Settings:
    webhook_secret: str
    github_token: str
    port: int
    base_branch: str
    post_comments: bool
    save_payloads: bool


def _flag(name: str, default: str) -> bool:
    return os.getenv(name, default).strip().lower() in {"1", "true", "yes", "on"}


settings = Settings(
    webhook_secret=os.getenv("GITHUB_WEBHOOK_SECRET", ""),
    github_token=os.getenv("GITHUB_TOKEN", ""),
    port=int(os.getenv("PORT", "5000")),
    base_branch=os.getenv("BASE_BRANCH", "main"),
    post_comments=_flag("POST_COMMENTS", "true"),
    save_payloads=_flag("SAVE_PAYLOADS", "true"),
)

if not settings.webhook_secret:
    raise SystemExit("GITHUB_WEBHOOK_SECRET is not set — copy .env.example to .env and fill it in.")
