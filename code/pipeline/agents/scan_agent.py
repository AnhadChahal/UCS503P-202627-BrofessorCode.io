"""ScanAgent: code quality and dependencies (FR25).

Runs ruff (lint), pytest (tests) and pip-audit (known vulnerable dependencies)."""

from __future__ import annotations

import json
import sys
import time
from pathlib import Path

from pipeline.agents.base import Agent
from pipeline.agents.common import chunks, keep_changed, rel, short, status_from
from pipeline.config import PipelineSettings, load_settings
from pipeline.models import Finding, PipelineContext, Severity, Verdict
from pipeline.runner import ToolResult, run_tool


def _ruff_severity(code: str | None) -> Severity:
    if code is None or code.startswith("E9") or code in {"F821", "F822", "F823"}:
        return Severity.HIGH  # syntax errors and undefined names are real bugs
    if code.startswith("F"):
        return Severity.MEDIUM
    return Severity.LOW


def _has_tests(repo_dir: Path) -> bool:
    return any(next(repo_dir.rglob(pattern), None) for pattern in ("test_*.py", "*_test.py"))


class ScanAgent(Agent):
    name = "ScanAgent"

    def __init__(self, settings: PipelineSettings | None = None) -> None:
        self.settings = settings or load_settings()

    # ---- the three checks; each returns (findings, note, tool_failed) ----
    def _ruff(self, ctx: PipelineContext) -> tuple[list[Finding], str, bool]:
        files = ctx.existing_python_files()
        if not files:
            return [], "ruff: no Python files changed", False
        findings: list[Finding] = []
        for group in chunks(files):
            # --isolated ignores the PR's own ruff settings, so a PR cannot switch rules off.
            res = run_tool(["ruff", "check", "--isolated", "--no-cache", "--output-format", "json", *group],
                           ctx.repo_dir, self.settings.tool_timeout)
            if res.missing:
                return [], "ruff: not installed", True
            if res.timed_out:
                return [], "ruff: timed out", True
            if res.returncode not in (0, 1):
                return [], f"ruff: failed ({short(res.stderr, 120)})", True
            try:
                items = json.loads(res.stdout or "[]")
            except ValueError:
                return [], "ruff: unreadable output", True
            for it in items:
                code = it.get("code")
                findings.append(Finding(
                    agent=self.name, tool="ruff", rule=code or "syntax-error",
                    severity=_ruff_severity(code), message=it.get("message", ""),
                    file=rel(it.get("filename", ""), ctx.repo_dir),
                    line=(it.get("location") or {}).get("row")))
        return findings, f"ruff: checked {len(files)} file(s)", False

    def _pytest(self, ctx: PipelineContext) -> tuple[list[Finding], str, bool]:
        if not _has_tests(ctx.repo_dir):
            return [], "pytest: no tests found", False
        if not self.settings.allow_pr_code_execution:
            return ([Finding(self.name, "pytest", "tests-not-run", Severity.LOW,
                             "Tests were not run because running code from a PR is switched off "
                             "(ALLOW_PR_CODE_EXECUTION=false).")],
                    "pytest: skipped (code execution disabled)", False)
        res = run_tool([sys.executable, "-m", "pytest", "-q", "-x", "-p", "no:cacheprovider", "--disable-warnings"],
                       ctx.repo_dir, self.settings.slow_tool_timeout)
        if res.timed_out:
            return [], "pytest: timed out", True
        output = (res.stdout + res.stderr)
        if res.returncode != 0 and "No module named pytest" in output:
            return [], "pytest: not installed in the host environment", True
        last = short(next((ln for ln in reversed(res.stdout.splitlines()) if ln.strip()), ""), 200)
        if res.returncode == 0:
            return [], f"pytest: passed ({last})", False
        if res.returncode == 1:
            return ([Finding(self.name, "pytest", "tests-failed", Severity.HIGH,
                             f"Automated tests failed: {last}",
                             suggestion="Run the tests locally and fix the failing ones.")],
                    "pytest: tests failed", False)
        if res.returncode == 2:
            return ([Finding(self.name, "pytest", "tests-could-not-run", Severity.MEDIUM,
                             f"Tests could not be collected or run (missing dependencies?): {last}")],
                    "pytest: could not run", False)
        if res.returncode == 5:
            return ([Finding(self.name, "pytest", "no-tests-collected", Severity.LOW,
                             "pytest found no tests to run.")], "pytest: no tests collected", False)
        return [], f"pytest: internal error (exit {res.returncode})", True

    def _audit(self, ctx: PipelineContext) -> tuple[list[Finding], str, bool]:
        req_files = sorted(p.name for p in ctx.repo_dir.glob("requirements*.txt") if p.is_file())
        if not req_files:
            return [], "pip-audit: no requirements file", False
        findings: list[Finding] = []
        for name in req_files:
            res = run_tool(["pip-audit", "-r", name, "--format", "json", "--progress-spinner", "off"],
                           ctx.repo_dir, self.settings.slow_tool_timeout)
            if res.missing:
                return [], "pip-audit: not installed", True
            if res.timed_out:
                return [], "pip-audit: timed out", True
            if res.returncode not in (0, 1):
                return [], f"pip-audit: failed ({short(res.stderr, 120)})", True
            try:
                data = json.loads(res.stdout or "{}")
            except ValueError:
                return [], "pip-audit: unreadable output", True
            deps = data.get("dependencies", []) if isinstance(data, dict) else data
            for dep in deps:
                for vuln in dep.get("vulns", []):
                    fixes = ", ".join(vuln.get("fix_versions") or []) or "no fixed version listed"
                    findings.append(Finding(
                        self.name, "pip-audit", vuln.get("id", "vulnerability"), Severity.HIGH,
                        f"{dep.get('name')} {dep.get('version')} has a known vulnerability. "
                        f"{short(vuln.get('description', ''), 120)}",
                        file=name, suggestion=f"Upgrade to: {fixes}"))
        return findings, f"pip-audit: checked {', '.join(req_files)}", False

    def run(self, ctx: PipelineContext) -> Verdict:
        started = time.monotonic()
        findings: list[Finding] = []
        notes: list[str] = []
        failed = False
        for check in (self._ruff, self._pytest, self._audit):
            f, note, bad = check(ctx)
            findings += f
            notes.append(note)
            failed = failed or bad
        findings = keep_changed(findings, ctx, self.settings)
        status = status_from(findings, Severity.HIGH, failed)
        return Verdict(self.name, status, findings, f"{len(findings)} finding(s)", notes,
                       round(time.monotonic() - started, 2))
