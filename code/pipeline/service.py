"""The review service: the whole life of a run, from a queued PR event to a final state.

    queued -> running -> blocked
                      -> awaiting_approval -> approved -> deployed | failed
                                           -> rejected | expired | superseded
                      -> approved (policy allows it) -> deployed | failed
                      -> failed

All decisions are made by plain code here, and every change is stored in SQLite with an
audit entry. Agents never talk to each other or to the database."""

from __future__ import annotations

import json
import logging
import queue
import threading
import time
from dataclasses import dataclass
from pathlib import Path

from pipeline.agents import Agent, DeployAgent, RiskAgent
from pipeline.agents.secrets_scan import mask_secrets
from pipeline.config import PipelineSettings
from pipeline.github_client import GitHubClient
from pipeline.models import Approval, PipelineContext, PullRequest, Status, Verdict
from pipeline.orchestrator import _safe_run, default_agents, prepare_context
from pipeline.report import MARKER, build_run_report
from pipeline.store import Store, Submission
from pipeline.workspace import Workspace

log = logging.getLogger("pipeline.service")

BLOCKABLE = ("queued", "running", "awaiting_approval", "approved")
MAX_PATCH_CHARS = 100_000      # per file, stored for the dashboard's code view
MAX_STORED_CHARS = 1_000_000   # per run
MAX_STORED_FILES = 300


def storable_files(files) -> list[tuple]:
    """The changed files in the form the dashboard stores. Secrets are masked first, so the code view
    does not show what the report hides (only patterns we know are masked: the scan is not perfect)."""
    out, used = [], 0
    for f in files[:MAX_STORED_FILES]:
        patch, truncated = (mask_secrets(f.patch) if f.patch else None), 0
        if patch is not None:
            room = min(MAX_PATCH_CHARS, MAX_STORED_CHARS - used)
            if len(patch) > room:
                patch, truncated = patch[:max(room, 0)], 1
            used += len(patch)
        out.append((f.filename, f.status, f.additions, f.deletions, patch, truncated))
    return out


@dataclass
class DecisionResult:
    ok: bool
    message: str
    status: str = ""


class ReviewService:
    def __init__(self, store: Store, settings: PipelineSettings, *, client=None, agents_factory=None) -> None:
        self.store = store
        self.settings = settings
        self._client = client
        self._agents_factory = agents_factory or default_agents

    def client(self) -> GitHubClient:
        if self._client is None:
            if not self.settings.github_token:
                raise RuntimeError("GITHUB_TOKEN is not set; cannot talk to GitHub.")
            self._client = GitHubClient(self.settings.github_token)
        return self._client

    # ------------------------------------------------------------------ intake
    def submit(self, pr_like, delivery_id: str | None = None) -> Submission:
        """Called by the webhook. Creates a queued run unless it is a duplicate (FR34)."""
        pr = PullRequest.from_parsed(pr_like)
        sub = self.store.create_run(pr, delivery_id)
        for old in sub.superseded:
            self._publish(old, comment=False)  # best effort: mark the old commit as superseded
        if sub.run_id is None:
            log.info("PR event ignored: %s", sub.reason)
        return sub

    def recover(self) -> list[int]:
        """After a restart: put runs that were queued or half-way back in the queue (FR32)."""
        ids = self.store.unfinished_run_ids()
        for run_id in ids:
            self.store.transition(run_id, ("queued", "running"), "queued")
            self.store.audit(run_id, "system", "recovered after restart")
        return ids

    # ---------------------------------------------------------------- analysis
    def _stopped(self, run_id: int) -> bool:
        run = self.store.get_run(run_id)
        return run is None or run["status"] != "running"

    def _save(self, run_id: int, verdict: Verdict) -> None:
        self.store.add_verdict(run_id, verdict)
        self.store.step_done(run_id, verdict.agent, verdict.status.value)
        self.store.audit(run_id, verdict.agent, f"verdict {verdict.status.value}", verdict.summary)

    def process(self, run_id: int) -> None:
        run = self.store.get_run(run_id)
        if not run or run["status"] not in ("queued", "running"):
            return
        if not self.store.transition(run_id, ("queued", "running"), "running"):
            return
        pr = self.store.pr_of(run)
        self.store.clear_results(run_id)
        self.store.audit(run_id, "system", "analysis started", pr.head_sha[:7])
        self._set_status(pr, "pending", "Review in progress")

        route, detail = "", ""
        workspace = Workspace()
        try:
            ctx = prepare_context(pr, self.client(), self.settings, workspace)
            self.store.update_run(run_id, file_count=len(ctx.files))
            self.store.save_files(run_id, storable_files(ctx.files))
            agents = list(self._agents_factory(self.settings))
            risk_agent = RiskAgent(self.settings)
            self.store.plan_steps(run_id, [a.name for a in agents] + [risk_agent.name])
            for agent in agents:
                if self._stopped(run_id):
                    self.store.audit(run_id, "system", "analysis stopped", "the run is no longer active")
                    return
                self.store.step_start(run_id, agent.name)
                verdict = _safe_run(agent, ctx)
                ctx.verdicts.append(verdict)
                self._save(run_id, verdict)
                if verdict.status == Status.BLOCK and self.settings.stop_on_block:
                    break
            score = None
            if not any(v.status == Status.BLOCK for v in ctx.verdicts):
                if self._stopped(run_id):
                    return
                self.store.step_start(run_id, risk_agent.name)
                risk = _safe_run(risk_agent, ctx)
                ctx.verdicts.append(risk)
                self._save(run_id, risk)
                score = risk.data.get("score")
                if score is not None:
                    self.store.update_run(run_id, risk_score=score,
                                          risk_factors=json.dumps(risk.data.get("factors", [])))
            self.store.skip_steps(run_id)  # agents that did not run (after a BLOCK) are shown as skipped
            if self._stopped(run_id):
                return
            route, detail = self._route(ctx.verdicts, score)
        except Exception as exc:  # noqa: BLE001 - fail closed
            log.exception("Run %s failed", run_id)
            self.store.skip_steps(run_id, include_running=True)
            text = f"{type(exc).__name__}: {exc}"
            if self.store.transition(run_id, ("running",), "failed", error=text):
                self.store.audit(run_id, "system", "review failed", text)
                self._publish(run_id)
            return
        finally:
            workspace.cleanup()

        if route == "blocked":
            if self.store.transition(run_id, ("running",), "blocked"):
                self.store.audit(run_id, "system", "blocked automatically", detail)
                self._publish(run_id)
        elif route == "awaiting":
            if self.store.transition(run_id, ("running",), "awaiting_approval", escalation_reason=detail):
                self.store.audit(run_id, "system", "escalated to a person", detail)
                self._publish(run_id)
        else:
            self._approve(run_id, by="policy", reason=detail, from_states=("running",))

    def _route(self, verdicts: list[Verdict], score: int | None) -> tuple[str, str]:
        """FR29: block, ask a person, or (only if the policy says so) approve automatically."""
        blockers = [v.agent for v in verdicts if v.status == Status.BLOCK]
        if blockers:
            return "blocked", ", ".join(blockers)
        reasons = []
        if any(v.status == Status.ESCALATE and v.agent != "RiskAgent" for v in verdicts):
            reasons.append("a check could not complete or was uncertain")
        if score is None:
            reasons.append("the risk score is missing")
        elif score > self.settings.risk_threshold:
            reasons.append(f"risk score {score} is above {self.settings.risk_threshold}")
        if self.settings.approval_policy != "auto_below_threshold":
            reasons.append("the approval policy requires a person")
        if reasons:
            return "awaiting", "; ".join(reasons)
        return "auto", "Low risk and the policy allows automatic approval"

    # --------------------------------------------------------- approval and deploy
    def _verdict_objects(self, run_id: int) -> list[Verdict]:
        return [Verdict(v["agent"], Status(v["status"])) for v in self.store.get_verdicts(run_id)]

    def _approve(self, run_id: int, by: str, reason: str, from_states=("awaiting_approval",)) -> bool:
        run = self.store.get_run(run_id)
        if not run or not self.store.record_decision(run_id, from_states, "approved", run["head_sha"],
                                                     "approve", reason, by):
            return False
        self._deploy(run_id, by, reason)
        return True

    def _deploy(self, run_id: int, by: str, reason: str) -> None:
        run = self.store.get_run(run_id)
        pr = self.store.pr_of(run)
        ctx = PipelineContext(pr, [], Path("."), self._verdict_objects(run_id),
                              Approval("approve", by, reason, pr.head_sha))
        self.store.append_step(run_id, DeployAgent.name)
        self.store.step_start(run_id, DeployAgent.name)
        try:
            verdict = _safe_run(DeployAgent(self.settings, self.client()), ctx)
        except Exception as exc:  # noqa: BLE001 - e.g. no token
            verdict = Verdict("DeployAgent", Status.ESCALATE, [], "deployment trigger failed",
                              [f"deployment could not start ({type(exc).__name__})"], data={"triggered": False})
        self._save(run_id, verdict)
        note = "; ".join(verdict.notes)
        if verdict.data.get("triggered"):
            self.store.transition(run_id, ("approved",), "deployed", deployment=note)
            self.store.audit(run_id, "DeployAgent", "deployment started", note)
        elif verdict.status == Status.PASS:
            self.store.update_run(run_id, deployment="not configured")
        else:
            self.store.transition(run_id, ("approved",), "failed", deployment=note,
                                  error="approved, but the deployment could not be started")
            self.store.audit(run_id, "DeployAgent", "deployment failed", note)
        self._publish(run_id)

    def decide(self, run_id: int, action: str, reason: str, user: str) -> DecisionResult:
        """An engineer approves, rejects or blocks a run (UC8, UC9; FR10, FR11)."""
        action = (action or "").strip().lower()
        reason = (reason or "").strip()[:1000]
        if action not in ("approve", "reject", "block"):
            return DecisionResult(False, "Unknown action.")
        if action in ("reject", "block") and not reason:
            return DecisionResult(False, "A reason is required.")
        run = self.store.get_run(run_id)
        if not run:
            return DecisionResult(False, "Run not found.")
        allowed = ("awaiting_approval",) if action in ("approve", "reject") else BLOCKABLE
        if run["status"] not in allowed:
            return DecisionResult(False, f"This run is {run['status'].replace('_', ' ')}, so it cannot be {action}d.",
                                  run["status"])

        if action in ("approve", "reject"):
            try:
                current = self.client().get_pr_head_sha(run["repo"], run["pr_number"])
            except Exception:  # noqa: BLE001 - fail closed
                log.exception("Could not check the PR head commit")
                return DecisionResult(False, "Could not check the PR's current commit on GitHub. "
                                              "Nothing was changed; try again.", run["status"])
            if current != run["head_sha"]:
                if self.store.transition(run_id, ("awaiting_approval",), "superseded"):
                    self.store.audit(run_id, user, "decision refused", f"PR head is now {current[:7]}")
                    self._publish(run_id, comment=False)
                return DecisionResult(False, "New commits were pushed, so this run is superseded. "
                                              "Review the newer run instead.", "superseded")

        if action == "approve":
            if not self._approve(run_id, by=user, reason=reason):
                return DecisionResult(False, "The run changed in the meantime (someone else decided, or it expired).")
            status = self.store.get_run(run_id)["status"]
            text = {"deployed": "Approved. The deployment workflow was started.",
                    "approved": "Approved. Deployment is not configured, so the approval is only recorded.",
                    "failed": "Approved, but the deployment could not be started. See the run for details."}
            return DecisionResult(True, text.get(status, "Approved."), status)

        new_status = "rejected" if action == "reject" else "blocked"
        if not self.store.record_decision(run_id, allowed, new_status, run["head_sha"], action, reason, user):
            return DecisionResult(False, "The run changed in the meantime (someone else decided, or it expired).")
        self._publish(run_id)
        return DecisionResult(True, f"Run {new_status}.", new_status)

    # ------------------------------------------------------------- housekeeping
    def expire_stale(self) -> list[int]:
        """Runs that waited too long for a decision expire; they never auto-approve (FR12)."""
        cutoff = time.time() - self.settings.approval_timeout_hours * 3600
        expired = []
        for run_id in self.store.awaiting_older_than(cutoff):
            if self.store.transition(run_id, ("awaiting_approval",), "expired"):
                self.store.audit(run_id, "system", "expired", f"no decision within {self.settings.approval_timeout_hours}h")
                self._publish(run_id)
                expired.append(run_id)
        return expired

    # --------------------------------------------------------- reporting to GitHub
    def _github_state(self, run: dict, decisions: list[dict]) -> tuple[str, str]:
        status = run["status"]
        last = decisions[-1]["decided_by"] if decisions else ""
        return {
            "queued": ("pending", "Review in progress"),
            "running": ("pending", "Review in progress"),
            "awaiting_approval": ("pending", f"Awaiting approval (risk {run['risk_score']})"),
            "approved": ("success", f"Approved by {last}"),
            "deployed": ("success", f"Approved by {last}; deployment started"),
            "blocked": ("failure", "Blocked"),
            "rejected": ("failure", f"Rejected by {last}"),
            "expired": ("failure", "Expired without a decision"),
            "superseded": ("failure", "Superseded by a newer commit"),
            "failed": ("error", "Review failed; not approved"),
        }[status]

    def _set_status(self, pr, state: str, description: str) -> None:
        if not self.settings.set_status:
            return
        try:
            self.client().set_commit_status(pr.repo, pr.head_sha, state, description, self.settings.status_context)
        except Exception:  # noqa: BLE001
            log.exception("Could not set the commit status")

    def _publish(self, run_id: int, comment: bool = True) -> None:
        run = self.store.get_run(run_id)
        if not run:
            return
        pr = self.store.pr_of(run)
        decisions = self.store.get_decisions(run_id)
        if comment and self.settings.post_comments:
            try:
                report = build_run_report(run, self.store.get_verdicts(run_id), decisions, self.settings.dashboard_url)
                self.client().upsert_comment(pr.repo, pr.number, MARKER, report)
            except Exception:  # noqa: BLE001
                log.exception("Could not post the report comment")
        state, description = self._github_state(run, decisions)
        self._set_status(pr, state, description)


class Worker:
    """One background thread that processes queued runs one at a time, plus a timer for expiries."""

    def __init__(self, service: ReviewService) -> None:
        self.service = service
        self.jobs: "queue.Queue[int]" = queue.Queue()
        self._stop = threading.Event()
        self._threads: list[threading.Thread] = []

    def submit(self, pr_like, delivery_id: str | None = None) -> Submission:
        sub = self.service.submit(pr_like, delivery_id)
        if sub.run_id is not None:
            self.jobs.put(sub.run_id)
        return sub

    def _work(self) -> None:
        while not self._stop.is_set():
            try:
                run_id = self.jobs.get(timeout=0.5)
            except queue.Empty:
                continue
            try:
                self.service.process(run_id)
            except Exception:  # noqa: BLE001 - one bad run must not stop the worker
                log.exception("Run %s crashed the worker loop", run_id)
            finally:
                self.jobs.task_done()

    def _maintain(self, interval: float) -> None:
        """Every few seconds: a heartbeat (so the dashboard can tell the worker is alive); every `interval`: expiry."""
        tick, last_sweep = min(10.0, interval), time.monotonic()
        while not self._stop.wait(tick):
            try:
                self.service.store.beat("worker")
            except Exception:  # noqa: BLE001
                log.exception("Heartbeat failed")
            if time.monotonic() - last_sweep >= interval:
                last_sweep = time.monotonic()
                try:
                    self.service.expire_stale()
                except Exception:  # noqa: BLE001
                    log.exception("Expiry check failed")

    def start(self, maintenance_interval: float = 60.0) -> None:
        self.service.store.beat("worker")
        for run_id in self.service.recover():
            self.jobs.put(run_id)
        for target, args, name in ((self._work, (), "review-worker"), (self._maintain, (maintenance_interval,), "review-maintenance")):
            t = threading.Thread(target=target, args=args, name=name, daemon=True)
            t.start()
            self._threads.append(t)

    def stop(self) -> None:
        self._stop.set()
        for t in self._threads:
            t.join(timeout=5)


def build_runtime(settings: PipelineSettings | None = None) -> tuple[ReviewService, Worker]:
    """Wire the store, service and worker from the .env settings. Call .start() on the worker once."""
    from pipeline.config import load_settings
    settings = settings or load_settings()
    service = ReviewService(Store(settings.db_path), settings)
    return service, Worker(service)
