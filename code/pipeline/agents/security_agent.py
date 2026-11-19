"""SecurityAgent: vulnerabilities and secrets (FR26).

Bandit and the built-in secret scan are always used. Semgrep is optional (it does not
run natively on Windows): if it is not installed it is skipped and the report says so.
Release 2 adds LLM triage on top of these findings (FR27)."""

from __future__ import annotations

import json
import time

from pipeline.agents.base import Agent
from pipeline.agents.common import chunks, keep_changed, rel, short, status_from
from pipeline.agents.secrets_scan import scan_added_lines
from pipeline.config import PipelineSettings, load_settings
from pipeline.models import Finding, PipelineContext, Severity, Verdict
from pipeline.runner import run_tool

_SEMGREP_SEVERITY = {"ERROR": Severity.HIGH, "WARNING": Severity.MEDIUM, "INFO": Severity.LOW}


def _bandit_severity(severity: str, confidence: str) -> Severity:
    sev, conf = (severity or "").upper(), (confidence or "").upper()
    if sev == "HIGH":
        return Severity.CRITICAL if conf == "HIGH" else Severity.HIGH
    return {"MEDIUM": Severity.MEDIUM, "LOW": Severity.LOW}.get(sev, Severity.LOW)


class SecurityAgent(Agent):
    name = "SecurityAgent"

    def __init__(self, settings: PipelineSettings | None = None) -> None:
        self.settings = settings or load_settings()

    def _bandit(self, ctx: PipelineContext) -> tuple[list[Finding], str, bool]:
        files = ctx.existing_python_files()
        if not files:
            return [], "bandit: no Python files changed", False
        findings: list[Finding] = []
        unparsed = 0
        for group in chunks(files):
            res = run_tool(["bandit", "-f", "json", "-q", *group], ctx.repo_dir, self.settings.tool_timeout)
            if res.missing:
                return [], "bandit: not installed", True
            if res.timed_out:
                return [], "bandit: timed out", True
            if res.returncode not in (0, 1):
                return [], f"bandit: failed ({short(res.stderr, 120)})", True
            try:
                data = json.loads(res.stdout or "{}")
            except ValueError:
                return [], "bandit: unreadable output", True
            unparsed += len(data.get("errors", []))
            for it in data.get("results", []):
                findings.append(Finding(
                    self.name, "bandit", f"{it.get('test_id')} {it.get('test_name')}",
                    _bandit_severity(it.get("issue_severity"), it.get("issue_confidence")),
                    it.get("issue_text", ""), rel(it.get("filename", ""), ctx.repo_dir),
                    it.get("line_number"), suggestion=it.get("more_info")))
        note = f"bandit: checked {len(files)} file(s)"
        if unparsed:
            note += f", could not parse {unparsed}"
        return findings, note, False

    def _semgrep(self, ctx: PipelineContext) -> tuple[list[Finding], str, bool]:
        if not self.settings.enable_semgrep:
            return [], "semgrep: disabled", False
        files = [f.filename for f in ctx.files
                 if f.status != "removed" and (ctx.repo_dir / f.filename).is_file()][:200]
        if not files:
            return [], "semgrep: no files to scan", False
        findings: list[Finding] = []
        for group in chunks(files):
            res = run_tool(["semgrep", "scan", "--config", self.settings.semgrep_config, "--json", "--quiet",
                            "--metrics=off", "--disable-version-check", *group],
                           ctx.repo_dir, self.settings.slow_tool_timeout)
            if res.missing:
                return [], "semgrep: not installed, skipped", False  # optional tool
            if res.timed_out:
                return [], "semgrep: timed out", True
            if res.returncode not in (0, 1):
                return [], f"semgrep: failed ({short(res.stderr, 120)})", True
            try:
                data = json.loads(res.stdout or "{}")
            except ValueError:
                return [], "semgrep: unreadable output", True
            for it in data.get("results", []):
                extra = it.get("extra", {})
                findings.append(Finding(
                    self.name, "semgrep", it.get("check_id", "semgrep"),
                    _SEMGREP_SEVERITY.get(str(extra.get("severity", "")).upper(), Severity.LOW),
                    extra.get("message", ""), rel(it.get("path", ""), ctx.repo_dir),
                    (it.get("start") or {}).get("line")))
        return findings, f"semgrep: scanned {len(files)} file(s)", False

    def run(self, ctx: PipelineContext) -> Verdict:
        started = time.monotonic()
        findings: list[Finding] = []
        notes: list[str] = []
        failed = False
        for check in (self._bandit, self._semgrep):
            f, note, bad = check(ctx)
            findings += f
            notes.append(note)
            failed = failed or bad
        findings = keep_changed(findings, ctx, self.settings)
        secrets = scan_added_lines(ctx.files)
        findings += secrets
        notes.append(f"secret scan: {len(secrets)} finding(s) in added lines")
        # A confirmed critical finding blocks (SRS FR26); everything else is a warning.
        status = status_from(findings, Severity.CRITICAL, failed)
        return Verdict(self.name, status, findings, f"{len(findings)} finding(s)", notes,
                       round(time.monotonic() - started, 2))
