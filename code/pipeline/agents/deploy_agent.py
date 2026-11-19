"""DeployAgent: start the deployment workflow, only for an approved, unchanged commit (FR30)."""

from __future__ import annotations

import time

from pipeline.agents.base import Agent
from pipeline.config import PipelineSettings
from pipeline.github_client import GitHubClient
from pipeline.models import Finding, PipelineContext, Severity, Status, Verdict


class DeployAgent(Agent):
    name = "DeployAgent"

    def __init__(self, settings: PipelineSettings, client: GitHubClient) -> None:
        self.settings = settings
        self.client = client

    def _refuse(self, started: float, message: str) -> Verdict:
        finding = Finding(self.name, "deploy", "deployment-refused", Severity.HIGH, message)
        return Verdict(self.name, Status.BLOCK, [finding], "deployment refused",
                       ["deployment: refused"], round(time.monotonic() - started, 3), data={"triggered": False})

    def run(self, ctx: PipelineContext) -> Verdict:
        started = time.monotonic()
        s, pr = self.settings, ctx.pr
        # Safety checks come first, so nothing can deploy by accident, even when deployment is off.
        if ctx.approval is None or ctx.approval.decision != "approve":
            return self._refuse(started, "There is no approval for this run.")
        if ctx.approval.head_sha != pr.head_sha:
            return self._refuse(started, "The approval is for a different commit than the one being deployed.")
        if any(v.status == Status.BLOCK for v in ctx.verdicts if v.agent != self.name):
            return self._refuse(started, "An agent blocked this PR, so it cannot be deployed.")
        if not s.deploy_workflow:
            return Verdict(self.name, Status.PASS, [], "deployment not configured",
                           ["deployment: not configured (the approval is recorded only)"],
                           round(time.monotonic() - started, 3), data={"triggered": False})
        ref = s.deploy_ref or pr.head_branch or pr.base_branch or "main"
        inputs = {"sha": pr.head_sha, "pr": str(pr.number)} if s.deploy_pass_inputs else None
        try:
            self.client.dispatch_workflow(pr.repo, s.deploy_workflow, ref, inputs)
        except Exception as exc:  # noqa: BLE001 - report the failure, never pretend it deployed
            finding = Finding(self.name, "deploy", "trigger-failed", Severity.HIGH,
                              f"The deployment workflow could not be started: {type(exc).__name__}: {exc}")
            return Verdict(self.name, Status.ESCALATE, [finding], "deployment trigger failed",
                           ["deployment: trigger failed"], round(time.monotonic() - started, 3),
                           data={"triggered": False})
        note = f"deployment: workflow {s.deploy_workflow} started on {ref}"
        return Verdict(self.name, Status.PASS, [], "deployment started", [note],
                       round(time.monotonic() - started, 3),
                       data={"triggered": True, "workflow": s.deploy_workflow, "ref": ref})
