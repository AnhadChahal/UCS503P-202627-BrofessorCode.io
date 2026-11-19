"""Build the Markdown report that is posted on the PR (the deterministic part of ReportAgent).

Every number and verdict comes from the stored results, never from a language model."""

from __future__ import annotations

from pipeline.models import Finding, PullRequest, Severity, Verdict, finding_key

MARKER = "<!-- brofessorcode-report -->"
FAILED = "FAILED"  # the pipeline itself could not finish

HEADLINES = {
    "PASS": "Passed",
    "WARN": "Passed with warnings",
    "ESCALATE": "Needs human review",
    "BLOCK": "Blocked",
    FAILED: "Review failed (not approved)",
}
MAX_ROWS = 30
TRIAGE_TEXT = {"likely_real": "likely a real problem", "likely_false_positive": "likely a false positive",
               "unsure": "unsure"}


def _cell(text: object, limit: int = 240) -> str:
    text = " ".join(str(text if text is not None else "").split())
    text = text.replace("|", "\\|").replace("<", "&lt;").replace("@", "@\u200b")
    return text if len(text) <= limit else text[: limit - 3] + "..."


def _where(f: Finding) -> str:
    if not f.file:
        return "-"
    return f"`{f.file}:{f.line}`" if f.line else f"`{f.file}`"


def build_report(pr: PullRequest, verdicts: list[Verdict], overall: str, file_count: int,
                 duration_s: float, error: str | None = None) -> str:
    lines = [MARKER, f"## BrofessorCode review: {HEADLINES.get(overall, overall)}", "",
             f"Commit `{pr.head_sha[:7]}` | {file_count} changed file(s) | {duration_s:.0f}s", ""]
    if error:
        lines += [f"> The review could not be completed: {_cell(error, 300)}. The PR has **not** been approved.", ""]
    if overall == "ESCALATE":
        lines += ["> A person needs to look at this PR. The approval dashboard is not built yet, "
                  "so the status is set to failing until then.", ""]

    if verdicts:
        lines += ["| Agent | Verdict | Findings | Checks |", "|---|---|---|---|"]
        for v in verdicts:
            lines.append(f"| {v.agent} | {v.status.value} | {len(v.findings)} | {_cell('; '.join(v.notes), 400)} |")
        lines.append("")

    findings = [f for v in verdicts for f in v.findings if f.severity >= Severity.LOW]
    findings.sort(key=lambda f: (-int(f.severity), f.file or "", f.line or 0))
    if findings:
        lines += ["### Findings", "", "| Severity | Where | Rule | Details |", "|---|---|---|---|"]
        for f in findings[:MAX_ROWS]:
            detail = _cell(f.message)
            if f.suggestion:
                detail += f" **Fix:** {_cell(f.suggestion, 160)}"
            lines.append(f"| {f.severity.name} | {_where(f)} | {_cell(f.rule, 60)} | {detail} |")
        if len(findings) > MAX_ROWS:
            lines.append(f"\n...and {len(findings) - MAX_ROWS} more finding(s).")
        lines.append("")
    elif verdicts and not error:
        lines += ["No issues were found in the changes that were checked.", ""]

    lines.append("<sub>Automated review by BrofessorCode (prototype). Results come from the tools listed above.</sub>")
    return "\n".join(lines)


# ---- reports built from stored runs (Release 2) -----------------------------

RUN_HEADLINES = {
    "queued": "Queued",
    "running": "In progress",
    "awaiting_approval": "Awaiting human approval",
    "approved": "Approved",
    "deployed": "Approved, deployment started",
    "blocked": "Blocked",
    "rejected": "Rejected",
    "expired": "Expired (no decision in time)",
    "superseded": "Superseded by a newer commit",
    "failed": "Review failed (not approved)",
}


def _run_callout(run: dict, decisions: list[dict]) -> str | None:
    status = run["status"]
    last = decisions[-1] if decisions else None
    reason = f": {_cell(last['reason'], 300)}" if last and last["reason"] else ""
    if status == "awaiting_approval":
        return ("A person must approve or reject this PR before it can be deployed. "
                f"Why: {_cell(run['escalation_reason'] or 'review needed', 300)}.")
    if status in ("approved", "deployed") and last:
        who = "policy" if last["decided_by"] == "policy" else last["decided_by"]
        extra = f" Deployment: {_cell(run['deployment'], 200)}." if run["deployment"] else ""
        return f"Approved by **{_cell(who, 80)}**{reason}.{extra}"
    if status == "rejected" and last:
        return f"Rejected by **{_cell(last['decided_by'], 80)}**{reason}"
    if status == "blocked":
        if last and last["decision"] == "block":
            return f"Blocked by **{_cell(last['decided_by'], 80)}**{reason}"
        return "Blocked automatically. See the findings below."
    if status == "expired":
        return "Nobody decided in time, so this run expired. Nothing was deployed."
    if status == "superseded":
        return "New commits were pushed, so this review no longer applies. See the review of the latest commit."
    if status == "failed":
        return f"The review could not be completed: {_cell(run['error'] or 'unknown error', 300)}. The PR has **not** been approved."
    return None


def build_run_report(run: dict, verdicts: list[dict], decisions: list[dict], dashboard_url: str = "") -> str:
    lines = [MARKER, f"## BrofessorCode review: {RUN_HEADLINES.get(run['status'], run['status'])}", ""]
    meta = f"Commit `{run['head_sha'][:7]}` | {run['file_count']} changed file(s)"
    if run["risk_score"] is not None:
        meta += f" | risk score {run['risk_score']}/100"
    lines += [meta, ""]
    callout = _run_callout(run, decisions)
    if callout:
        lines += [f"> {callout}", ""]
    ai = next((v["data"] for v in verdicts if v["agent"] == "TriageAgent"), {})
    triage = ai.get("triage") or {}
    if ai.get("summary"):
        lines += [f"> **AI summary** (written by a local model, may be wrong): {_cell(ai['summary'], 420)}", ""]

    if verdicts:
        lines += ["| Agent | Verdict | Findings | Checks |", "|---|---|---|---|"]
        for v in verdicts:
            notes = "; ".join(v["notes"][:6])
            lines.append(f"| {v['agent']} | {v['status']} | {len(v['findings'])} | {_cell(notes, 400)} |")
        lines.append("")

    findings = [f for v in verdicts for f in v["findings"] if f["severity"] >= int(Severity.LOW)]
    findings.sort(key=lambda f: (-f["severity"], f["file"] or "", f["line"] or 0))
    if findings:
        lines += ["### Findings", "", "| Severity | Where | Rule | Details |", "|---|---|---|---|"]
        for f in findings[:MAX_ROWS]:
            where = "-" if not f["file"] else (f"`{f['file']}:{f['line']}`" if f["line"] else f"`{f['file']}`")
            detail = _cell(f["message"])
            if f["suggestion"]:
                detail += f" **Fix:** {_cell(f['suggestion'], 160)}"
            note = triage.get(finding_key(f["agent"], f["rule"], f["file"], f["line"]))
            if note:
                detail += f" _AI triage: {TRIAGE_TEXT.get(note['label'], 'unsure')}. {_cell(note['reason'], 220)}_"
            lines.append(f"| {Severity(f['severity']).name} | {where} | {_cell(f['rule'], 60)} | {detail} |")
        if len(findings) > MAX_ROWS:
            lines.append(f"\n...and {len(findings) - MAX_ROWS} more finding(s).")
        lines.append("")
    elif verdicts and run["status"] not in ("failed", "queued", "running"):
        lines += ["No issues were found in the changes that were checked.", ""]

    if dashboard_url:
        lines += [f"[Open this run in the dashboard]({dashboard_url}/runs/{run['id']})", ""]
    lines.append("<sub>Automated review by BrofessorCode (prototype). Results come from the tools listed above.</sub>")
    return "\n".join(lines)
