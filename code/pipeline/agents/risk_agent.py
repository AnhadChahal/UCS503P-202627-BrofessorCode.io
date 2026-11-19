"""RiskAgent: a 0 to 100 risk score from plain rules (FR28). No language model is involved.

Factors: which kinds of files changed, how big the change is, how many findings the other
agents reported, and whether any check was uncertain. The weights can be overridden with a
JSON file (RISK_WEIGHTS_FILE); a missing or broken file falls back to the defaults."""

from __future__ import annotations

import copy
import json
import logging
import re
import time

from pipeline.agents.base import Agent
from pipeline.config import PipelineSettings, load_settings
from pipeline.models import PipelineContext, Severity, Status, Verdict

log = logging.getLogger("pipeline.risk")

DEFAULT_WEIGHTS: dict = {
    # [label, regular expression matched against the lower-cased path, points]; each label counts once
    "paths": [
        ["CI/CD workflow", r"^\.github/workflows/", 25],
        ["container or deployment file", r"(^|/)(dockerfile|docker-compose[^/]*\.ya?ml|jenkinsfile|deploy[^/]*)$", 15],
        ["infrastructure as code", r"(^|/)(terraform|infra|k8s|helm)/|\.tf$", 20],
        ["authentication or crypto code", r"(auth|login|password|session|token|crypto|secret|permission)", 20],
        ["configuration", r"(^|/)(config|settings)[^/]*\.|(^|/)\.env", 15],
        ["dependency manifest", r"(^|/)(requirements[^/]*\.txt|pyproject\.toml|pipfile|package(-lock)?\.json|setup\.py)$", 10],
        ["database migration", r"(^|/)migrations?/", 10],
    ],
    "path_cap": 40,
    "size": [[50, 0], [200, 5], [500, 10], [1000, 15], [None, 20]],  # [max changed lines, points]
    "severity_points": {"CRITICAL": 30, "HIGH": 15, "MEDIUM": 5, "LOW": 1},
    "severity_caps": {"CRITICAL": 30, "HIGH": 30, "MEDIUM": 15, "LOW": 5},
    "findings_cap": 40,
    "uncertain": 20,
}


def load_weights(path: str = "") -> dict:
    weights = copy.deepcopy(DEFAULT_WEIGHTS)
    if path:
        try:
            with open(path, encoding="utf-8") as fh:
                weights.update(json.load(fh))
        except (OSError, ValueError) as exc:
            log.warning("Could not read the risk weights file %s (%s); using the defaults", path, exc)
    return weights


class RiskAgent(Agent):
    name = "RiskAgent"

    def __init__(self, settings: PipelineSettings | None = None, weights: dict | None = None) -> None:
        self.settings = settings or load_settings()
        self.weights = weights or load_weights(self.settings.risk_weights_file)

    def run(self, ctx: PipelineContext) -> Verdict:
        started = time.monotonic()
        w = self.weights
        factors: list[str] = []
        total = 0

        # 1. kinds of files that changed
        matched: dict[str, tuple[int, str]] = {}
        for f in ctx.files:
            if f.status == "removed":
                continue
            path = f.filename.lower()
            for label, pattern, points in w["paths"]:
                if label not in matched and re.search(pattern, path):
                    matched[label] = (points, f.filename)
        path_points = min(w["path_cap"], sum(p for p, _ in matched.values()))
        for label, (points, example) in matched.items():
            factors.append(f"{label}: {example} (+{points})")
        total += path_points

        # 2. size of the change
        lines = sum(f.additions + f.deletions for f in ctx.files)
        size_points = next(pts for limit, pts in w["size"] if limit is None or lines < limit)
        if size_points:
            factors.append(f"{lines} changed lines (+{size_points})")
        total += size_points

        # 3. findings of the other agents
        counts: dict[str, int] = {}
        uncertain = False
        for v in ctx.verdicts:
            if v.agent == self.name:
                continue
            uncertain = uncertain or v.status == Status.ESCALATE
            for finding in v.findings:
                if finding.severity >= Severity.LOW:
                    counts[finding.severity.name] = counts.get(finding.severity.name, 0) + 1
        finding_points = 0
        for sev, n in counts.items():
            pts = min(w["severity_caps"].get(sev, 0), n * w["severity_points"].get(sev, 0))
            if pts:
                factors.append(f"{n} {sev.lower()} finding(s) (+{pts})")
            finding_points += pts
        total += min(w["findings_cap"], finding_points)

        # 4. a check that could not finish
        if uncertain:
            factors.append(f"a check was uncertain or failed (+{w['uncertain']})")
            total += w["uncertain"]

        score = max(0, min(100, int(total)))
        threshold = self.settings.risk_threshold
        status = Status.ESCALATE if score > threshold else Status.PASS
        notes = [f"risk score {score} of 100 (threshold {threshold})"] + factors
        return Verdict(self.name, status, [], f"risk score {score}", notes, round(time.monotonic() - started, 3),
                       data={"score": score, "threshold": threshold, "factors": factors})
