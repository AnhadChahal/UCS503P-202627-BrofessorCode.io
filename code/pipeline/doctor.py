"""Preflight checks: is everything in place before you start the system or open a PR?

Each check returns ok / warn / fail with a plain sentence that says what to do. Used by
scripts/doctor.py and scripts/start_all.py. Nothing here changes any state."""

from __future__ import annotations

import os
import shutil
import socket
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Mapping

import requests

from pipeline.config import PipelineSettings
from pipeline.llm import LLMError, OllamaClient
from pipeline.store import Store


@dataclass(frozen=True)
class Check:
    level: str   # ok | warn | fail
    text: str


def _port_free(port: int) -> bool:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            s.bind(("127.0.0.1", port))
        except OSError:
            return False
    return True


def run_checks(settings: PipelineSettings, env: Mapping[str, str] | None = None, *,
               which: Callable[[str], str | None] = shutil.which,
               port_free: Callable[[int], bool] = _port_free,
               ports_must_be_free: bool = False,
               github_repo: str = "",
               http_get: Callable | None = None,
               platform: str = sys.platform,
               llm_client: OllamaClient | None = None) -> list[Check]:
    env = os.environ if env is None else env
    out: list[Check] = []

    def add(level: str, text: str) -> None:
        out.append(Check(level, text))

    # ---- secrets and tokens ----
    if env.get("GITHUB_WEBHOOK_SECRET"):
        add("ok", "GITHUB_WEBHOOK_SECRET is set")
    else:
        add("fail", "GITHUB_WEBHOOK_SECRET is not set. Put a random string in .env and the same one in the GitHub webhook settings.")
    token = settings.github_token
    if not token:
        add("fail", "GITHUB_TOKEN is not set. Create a fine-grained token (see the README) and put it in .env.")
    elif not token.startswith(("github_pat_", "ghp_", "gho_", "ghs_")):
        add("warn", "GITHUB_TOKEN does not look like a GitHub token (expected it to start with github_pat_).")
    else:
        add("ok", "GITHUB_TOKEN is set")
    key = settings.dashboard_secret_key
    if len(key) >= 16:
        add("ok", "DASHBOARD_SECRET_KEY is set")
    else:
        add("fail", "DASHBOARD_SECRET_KEY is missing or shorter than 16 characters. "
                    'Generate one: python -c "import secrets; print(secrets.token_hex(32))"')

    # ---- database ----
    db = Path(settings.db_path)
    if not db.is_absolute():
        add("warn", f"DB_PATH ({settings.db_path}) is relative. The webhook and the dashboard must start in the same "
                    "folder or they will use two different databases; an absolute path avoids that.")
    if not db.expanduser().resolve().parent.is_dir():
        add("fail", f"The folder for DB_PATH does not exist: {db.expanduser().resolve().parent}")
    elif not db.exists():
        add("ok", "The database does not exist yet; it is created on the first start")
        add("warn", "No dashboard user exists yet. Create one: python scripts/create_user.py <name>")
    else:
        try:
            users = Store(str(db)).user_count()
            add("ok", f"Database opens ({db.name})")
            if users == 0:
                add("warn", "No dashboard user exists yet. Create one: python scripts/create_user.py <name>")
        except Exception as exc:  # noqa: BLE001
            add("fail", f"Cannot open the database: {type(exc).__name__}: {exc}")

    # ---- tools ----
    for tool, why in (("ruff", "ScanAgent lint"), ("bandit", "SecurityAgent code scan"), ("pip-audit", "ScanAgent dependency check")):
        if which(tool):
            add("ok", f"{tool} is installed")
        else:
            add("warn", f"{tool} is not installed ({why}). Runs will still work but go to a person. pip install {tool}")
    if settings.enable_semgrep and not which("semgrep"):
        add("warn", "semgrep is not installed. It is optional; the report will say it was skipped.")
    if settings.allow_pr_code_execution:
        add("warn", "ALLOW_PR_CODE_EXECUTION is true: a PR's own tests run on this machine. Use only on repositories you trust.")

    # ---- ports ----
    webhook_port = int(env.get("PORT", "5000") or 5000)
    for name, port in (("webhook", webhook_port), ("dashboard", settings.dashboard_port)):
        if port_free(port):
            add("ok", f"port {port} ({name}) is free")
        else:
            add("fail" if ports_must_be_free else "warn",
                f"port {port} ({name}) is in use" + (" (is it already running?)" if not ports_must_be_free else ""))
    if webhook_port == 5000 and platform == "darwin":
        add("warn", "PORT=5000: on macOS, AirPlay Receiver uses port 5000 and GitHub will get 403. Use PORT=5001.")

    # ---- remote access (tunnel) ----
    public = settings.dashboard_url.startswith("https://")
    if settings.trust_proxy and settings.dashboard_host not in ("127.0.0.1", "localhost", "::1"):
        add("fail", "TRUST_PROXY=true but the dashboard listens on " + settings.dashboard_host + ". Anyone who can reach it "
                    "directly could fake their address. Keep DASHBOARD_HOST=127.0.0.1 when TRUST_PROXY is on.")
    if public and not settings.trust_proxy:
        add("warn", "DASHBOARD_URL is https but TRUST_PROXY is false: the dashboard will not see the real client address "
                    "or the https scheme behind the tunnel. Set TRUST_PROXY=true and use the gateway.")
    if settings.trust_proxy:
        add("ok", "TRUST_PROXY is on: only run the dashboard behind the gateway on this machine")
    if public and not env.get("NGROK_ALLOWED_EMAILS", "").strip():
        add("warn", "DASHBOARD_URL is public but NGROK_ALLOWED_EMAILS is empty: the tunnel would not ask for a sign-in "
                    "(python scripts/start_tunnel.py refuses to start that way unless you pass --no-signin).")

    # ---- deployment ----
    if settings.deploy_workflow:
        add("ok", f"deployment enabled: workflow {settings.deploy_workflow}")
    else:
        add("ok", "deployment not configured (approve only records the decision)")

    # ---- LLM ----
    if settings.llm_enabled:
        try:
            client = llm_client or OllamaClient(settings.ollama_url, settings.llm_timeout, settings.llm_keep_alive,
                                                settings.llm_allow_remote)
            if not client.available():
                add("warn", f"LLM_ENABLED is true but Ollama does not answer at {settings.ollama_url} (run: ollama serve). "
                            "Runs will go on without AI notes.")
            else:
                for m in [settings.llm_model] + ([settings.llm_heavy_model] if settings.llm_heavy_model else []):
                    add("ok" if client.has_model(m) else "warn",
                        f"Ollama model {m} is installed" if client.has_model(m) else f"Ollama model {m} is missing: ollama pull {m}")
        except LLMError as exc:
            add("warn", f"LLM: {exc}")
    else:
        add("ok", "LLM triage is off (LLM_ENABLED=false)")

    # ---- optional live GitHub check ----
    if github_repo and token:
        get = http_get or requests.get
        try:
            r = get(f"https://api.github.com/repos/{github_repo}", timeout=15,
                    headers={"Authorization": f"Bearer {token}", "Accept": "application/vnd.github+json"})
            if r.status_code == 200:
                add("ok", f"GitHub accepts the token for {github_repo}")
            elif r.status_code == 401:
                add("fail", "GitHub says the token is invalid or expired (401). Create a new one.")
            elif r.status_code in (403, 404):
                add("fail", f"The token cannot see {github_repo} ({r.status_code}). Check the repository name and that the "
                            "token was given access to this repository.")
            else:
                add("warn", f"GitHub answered {r.status_code} for {github_repo}")
        except requests.RequestException as exc:
            add("warn", f"Could not reach GitHub: {type(exc).__name__}")
    return out


def summarize(checks: list[Check]) -> tuple[int, int]:
    return sum(c.level == "fail" for c in checks), sum(c.level == "warn" for c in checks)
