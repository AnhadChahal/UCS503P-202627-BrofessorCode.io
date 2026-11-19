"""Settings for the review pipeline, read from environment variables (.env)."""

from __future__ import annotations

import os
from dataclasses import dataclass

from dotenv import load_dotenv

load_dotenv()


def _flag(name: str, default: bool) -> bool:
    raw = os.getenv(name)
    if raw is None:
        return default
    return raw.strip().lower() in {"1", "true", "yes", "on"}


def _int(name: str, default: int) -> int:
    try:
        return int(os.getenv(name, str(default)))
    except ValueError:
        return default


@dataclass(frozen=True)
class PipelineSettings:
    github_token: str
    # Running a PR's tests executes code written by someone else. Off by default.
    allow_pr_code_execution: bool
    # Report only problems on lines that the PR added or changed.
    only_changed_lines: bool
    # Stop running agents after the first BLOCK (FR24).
    stop_on_block: bool
    tool_timeout: int        # seconds, for fast tools (ruff, bandit)
    slow_tool_timeout: int   # seconds, for pytest, pip-audit, semgrep
    max_download_mb: int     # refuse to download a larger repository archive
    max_files: int           # refuse to extract more files than this
    enable_semgrep: bool
    semgrep_config: str
    post_comments: bool
    set_status: bool
    status_context: str
    # ---- Release 2 ----
    db_path: str = "brofessorcode.db"
    approval_policy: str = "always_human"   # or "auto_below_threshold"
    risk_threshold: int = 70                  # a score above this needs a person
    approval_timeout_hours: int = 24
    deploy_workflow: str = ""                 # e.g. deploy.yml; empty = deployment disabled
    deploy_ref: str = ""                      # branch to dispatch on; empty = the PR's head branch
    deploy_pass_inputs: bool = False          # send sha and pr number as workflow inputs
    risk_weights_file: str = ""               # optional JSON file overriding the risk weights
    dashboard_secret_key: str = ""
    dashboard_host: str = "127.0.0.1"
    dashboard_port: int = 5002
    lockout_attempts: int = 3
    lockout_minutes: int = 30
    dashboard_url: str = ""                  # base address used for links in comments, e.g. http://127.0.0.1:5002
    # ---- Release 3: local LLM (Ollama). Advisory only: it never changes a verdict or a routing decision ----
    llm_enabled: bool = False
    ollama_url: str = "http://127.0.0.1:11434"
    llm_allow_remote: bool = False            # sending code to a non-local server must be a deliberate choice
    llm_model: str = "qwen2.5-coder:7b"       # light model: used for most findings and the summary
    llm_heavy_model: str = ""                 # optional bigger model, used only for HIGH/CRITICAL findings
    llm_timeout: int = 120                    # seconds per request
    llm_keep_alive: str = "10m"               # how long Ollama keeps a model loaded between requests
    llm_unload_after_run: bool = True         # free the memory when the agent is done
    llm_max_findings: int = 8                 # findings sent to the model per run
    llm_context_lines: int = 8                # lines of code around a finding
    llm_summary: bool = True                  # also write a short summary of the change


def load_settings() -> PipelineSettings:
    """Read the environment each time, so tests can change it."""
    policy = os.getenv("APPROVAL_POLICY", "always_human").strip().lower()
    if policy not in {"always_human", "auto_below_threshold"}:
        policy = "always_human"  # an unknown value must never loosen the policy
    return PipelineSettings(
        github_token=os.getenv("GITHUB_TOKEN", ""),
        allow_pr_code_execution=_flag("ALLOW_PR_CODE_EXECUTION", False),
        only_changed_lines=_flag("ONLY_CHANGED_LINES", True),
        stop_on_block=_flag("STOP_ON_BLOCK", True),
        tool_timeout=_int("TOOL_TIMEOUT", 120),
        slow_tool_timeout=_int("SLOW_TOOL_TIMEOUT", 300),
        max_download_mb=_int("MAX_DOWNLOAD_MB", 100),
        max_files=_int("MAX_FILES", 20000),
        enable_semgrep=_flag("ENABLE_SEMGREP", True),
        semgrep_config=os.getenv("SEMGREP_CONFIG", "p/python"),
        post_comments=_flag("POST_COMMENTS", True),
        set_status=_flag("SET_STATUS", True),
        status_context=os.getenv("STATUS_CONTEXT", "BrofessorCode review"),
        db_path=os.getenv("DB_PATH", "brofessorcode.db"),
        approval_policy=policy,
        risk_threshold=_int("RISK_THRESHOLD", 70),
        approval_timeout_hours=_int("APPROVAL_TIMEOUT_HOURS", 24),
        deploy_workflow=os.getenv("DEPLOY_WORKFLOW", "").strip(),
        deploy_ref=os.getenv("DEPLOY_REF", "").strip(),
        deploy_pass_inputs=_flag("DEPLOY_PASS_INPUTS", False),
        risk_weights_file=os.getenv("RISK_WEIGHTS_FILE", "").strip(),
        dashboard_secret_key=os.getenv("DASHBOARD_SECRET_KEY", ""),
        dashboard_host=os.getenv("DASHBOARD_HOST", "127.0.0.1"),
        dashboard_port=_int("DASHBOARD_PORT", 5002),
        lockout_attempts=_int("LOCKOUT_ATTEMPTS", 3),
        lockout_minutes=_int("LOCKOUT_MINUTES", 30),
        dashboard_url=os.getenv("DASHBOARD_URL", "").strip().rstrip("/"),
        llm_enabled=_flag("LLM_ENABLED", False),
        ollama_url=os.getenv("OLLAMA_URL", "http://127.0.0.1:11434").strip().rstrip("/"),
        llm_allow_remote=_flag("LLM_ALLOW_REMOTE", False),
        llm_model=os.getenv("LLM_MODEL", "qwen2.5-coder:7b").strip(),
        llm_heavy_model=os.getenv("LLM_HEAVY_MODEL", "").strip(),
        llm_timeout=_int("LLM_TIMEOUT", 120),
        llm_keep_alive=os.getenv("LLM_KEEP_ALIVE", "10m").strip(),
        llm_unload_after_run=_flag("LLM_UNLOAD_AFTER_RUN", True),
        llm_max_findings=_int("LLM_MAX_FINDINGS", 8),
        llm_context_lines=_int("LLM_CONTEXT_LINES", 8),
        llm_summary=_flag("LLM_SUMMARY", True),
    )
