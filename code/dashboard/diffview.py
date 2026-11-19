"""Turn a stored GitHub patch plus the findings into lines the run page can show:
the changed code with each finding (and its AI note) under the line it is about."""

from __future__ import annotations

import re

from pipeline.models import Severity, finding_key

_HUNK = re.compile(r"^@@ -(\d+)(?:,\d+)? \+(\d+)(?:,\d+)? @@(.*)$")
MAX_LINES = 600


def parse_patch(patch: str | None, limit: int = MAX_LINES) -> tuple[list[dict], bool]:
    """Lines of a patch as dicts {kind: hunk|add|del|ctx|meta, old, new, text, notes}. Second value: cut short?"""
    lines: list[dict] = []
    old = new = 0
    for raw in (patch or "").splitlines():
        if len(lines) >= limit:
            return lines, True
        m = _HUNK.match(raw)
        if m:
            old, new = int(m.group(1)), int(m.group(2))
            lines.append({"kind": "hunk", "old": None, "new": None, "text": raw, "notes": []})
        elif raw.startswith("+"):
            lines.append({"kind": "add", "old": None, "new": new, "text": raw[1:], "notes": []})
            new += 1
        elif raw.startswith("-"):
            lines.append({"kind": "del", "old": old, "new": None, "text": raw[1:], "notes": []})
            old += 1
        elif raw.startswith("\\"):
            lines.append({"kind": "meta", "old": None, "new": None, "text": raw, "notes": []})
        else:
            lines.append({"kind": "ctx", "old": old, "new": new, "text": raw[1:] if raw.startswith(" ") else raw,
                          "notes": []})
            old += 1
            new += 1
    return lines, False


def _note(f: dict, triage: dict) -> dict:
    return {"severity": f["severity"], "sev_name": Severity(f["severity"]).name, "rule": f["rule"],
            "message": f["message"], "suggestion": f["suggestion"], "tool": f["tool"],
            "ai": triage.get(finding_key(f["agent"], f["rule"], f["file"], f["line"]))}


def build_file_views(files: list[dict], findings: list[dict], triage: dict) -> list[dict]:
    """One entry per changed file: its lines, the findings placed on their lines, and the ones that
    could not be placed (a line outside the shown part of the diff). Worst-first ordering of files."""
    views = []
    for f in files:
        lines, cut = parse_patch(f["patch"])
        mine = [x for x in findings if x["file"] == f["filename"] and x["severity"] >= int(Severity.LOW)]
        unplaced = []
        for x in sorted(mine, key=lambda y: -y["severity"]):
            target = next((ln for ln in lines if ln["new"] == x["line"] and ln["kind"] in ("add", "ctx")), None) \
                if x["line"] else None
            (target["notes"] if target else unplaced).append(_note(x, triage))
        views.append({
            "filename": f["filename"], "status": f["status"], "additions": f["additions"],
            "deletions": f["deletions"], "lines": lines, "cut": cut or bool(f["truncated"]),
            "no_patch": f["patch"] is None, "unplaced": unplaced, "count": len(mine),
            "worst": max((x["severity"] for x in mine), default=-1),
        })
    views.sort(key=lambda v: (-v["worst"], v["filename"]))
    return views
