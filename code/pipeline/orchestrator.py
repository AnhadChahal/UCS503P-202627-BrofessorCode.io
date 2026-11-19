"""The orchestrator: fetch the PR, run the agents in order, report (FR24, FR35).

Plain Python, no framework. Agents never call each other: they read the context and
return a verdict, and this module decides what happens next."""

from __future__ import annotations

import logging
import time
from dataclasses import dataclass, field

from pipeline.agents import Agent, ScanAgent, SecurityAgent, TriageAgent
from pipeline.config import PipelineSettings, load_settings
from pipeline.github_client import GitHubClient
from pipeline.models import Finding, PipelineContext, PullRequest, Severity, Status, Verdict
from pipeline.report import FAILED, MARKER, build_report
from pipeline.workspace import Workspace, safe_extract

log = logging.getLogger("pipeline")

_RANK = {Status.PASS: 0, Status.WARN: 1, Status.ESCALATE: 2, Status.BLOCK: 3}


@dataclass
class RunResult:
    overall: str
    verdicts: list[Verdict] = field(default_factory=list)
    report: str = ""
    duration_s: float = 0.0
    error: str | None = None


def default_agents(settings: PipelineSettings) -> list[Agent]:
    # TriageAgent reads the findings of the agents before it, so it comes after them. RiskAgent and
    # DeployAgent are added by the review service (Release 2).
    agents: list[Agent] = [ScanAgent(settings), SecurityAgent(settings)]
    if settings.llm_enabled:
        agents.append(TriageAgent(settings))
    return agents


def decide_overall(verdicts: list[Verdict]) -> str:
    """The worst verdict wins. No verdicts at all is never a pass."""
    if not verdicts:
        return Status.ESCALATE.value
    return max((v.status for v in verdicts), key=lambda s: _RANK[s]).value


def github_state(overall: str, verdicts: list[Verdict]) -> tuple[str, str]:
    """(state, description) for the commit status. Release 1 has no approval step yet,
    so ESCALATE shows as failing until a person has decided."""
    if overall == Status.PASS.value:
        return "success", "No issues found"
    if overall == Status.WARN.value:
        count = sum(len(v.findings) for v in verdicts)
        return "success", f"Passed with {count} warning(s)"
    if overall == Status.BLOCK.value:
        who = next((v for v in verdicts if v.status == Status.BLOCK), None)
        return "failure", f"Blocked by {who.agent} ({len(who.findings)} finding(s))" if who else "Blocked"
    if overall == Status.ESCALATE.value:
        return "failure", "Needs human review"
    return "error", "Review failed; not approved"


def _safe_run(agent: Agent, ctx: PipelineContext) -> Verdict:
    """Fail closed: an agent that crashes counts as 'needs a human', never as a pass."""
    started = time.monotonic()
    try:
        verdict = agent.run(ctx)
        log.info("%s -> %s (%d finding(s))", agent.name, verdict.status.value, len(verdict.findings))
        return verdict
    except Exception as exc:  # noqa: BLE001 - one bad agent must not stop the pipeline
        log.exception("%s crashed", agent.name)
        finding = Finding(agent.name, "orchestrator", "agent-crashed", Severity.HIGH,
                          f"{agent.name} crashed ({type(exc).__name__}) and could not finish its checks.")
        return Verdict(agent.name, Status.ESCALATE, [finding], "agent crashed",
                       ["crashed; treated as needing human review"], round(time.monotonic() - started, 2))


def prepare_context(pr: PullRequest, client: GitHubClient, settings: PipelineSettings,
                    workspace: Workspace) -> PipelineContext:
    """Changed files + diffs, and the code at the PR's head commit in a temp folder (FR21, FR22)."""
    files = client.list_pr_files(pr.repo, pr.number)
    max_bytes = settings.max_download_mb * 1024 * 1024
    client.download_tarball(pr.repo, pr.head_sha, workspace.archive, max_bytes)
    count = safe_extract(workspace.archive, workspace.repo_dir, settings.max_files, max_bytes * 5)
    workspace.archive.unlink(missing_ok=True)
    log.info("PR #%s: %d changed file(s), %d file(s) checked out", pr.number, len(files), count)
    return PipelineContext(pr=pr, files=files, repo_dir=workspace.repo_dir)


def run_pipeline(pr_like, *, client: GitHubClient | None = None, agents: list[Agent] | None = None,
                 settings: PipelineSettings | None = None) -> RunResult:
    settings = settings or load_settings()
    pr = PullRequest.from_parsed(pr_like)
    if client is None:
        if not settings.github_token:
            raise RuntimeError("GITHUB_TOKEN is not set; the pipeline cannot talk to GitHub.")
        client = GitHubClient(settings.github_token)
    agents = agents if agents is not None else default_agents(settings)

    started = time.monotonic()
    log.info("Starting review of %s#%s at %s", pr.repo, pr.number, pr.head_sha[:7])
    _publish_status(client, pr, settings, "pending", "Review in progress")

    verdicts: list[Verdict] = []
    file_count = 0
    error: str | None = None
    overall: str
    workspace = Workspace()
    try:
        ctx = prepare_context(pr, client, settings, workspace)
        file_count = len(ctx.files)
        for agent in agents:
            verdict = _safe_run(agent, ctx)
            ctx.verdicts.append(verdict)
            verdicts.append(verdict)
            if verdict.status == Status.BLOCK and settings.stop_on_block:
                log.info("%s returned BLOCK; skipping the remaining agents", agent.name)
                break
        overall = decide_overall(verdicts)
    except Exception as exc:  # noqa: BLE001 - fail closed
        log.exception("Pipeline failed for %s#%s", pr.repo, pr.number)
        overall, error = FAILED, f"{type(exc).__name__}: {exc}"
    finally:
        workspace.cleanup()

    duration = time.monotonic() - started
    report = build_report(pr, verdicts, overall, file_count, duration, error)
    state, description = github_state(overall, verdicts)
    if settings.post_comments:
        try:
            url = client.upsert_comment(pr.repo, pr.number, MARKER, report)
            log.info("Report posted: %s", url)
        except Exception:  # noqa: BLE001
            log.exception("Could not post the report comment")
    _publish_status(client, pr, settings, state, description)
    log.info("Finished %s#%s: %s in %.1fs", pr.repo, pr.number, overall, duration)
    return RunResult(overall, verdicts, report, round(duration, 2), error)


def _publish_status(client: GitHubClient, pr: PullRequest, settings: PipelineSettings,
                    state: str, description: str) -> None:
    if not settings.set_status:
        return
    try:
        client.set_commit_status(pr.repo, pr.head_sha, state, description, settings.status_context)
    except Exception:  # noqa: BLE001 - e.g. the token lacks the commit-status permission
        log.exception("Could not set the commit status")
