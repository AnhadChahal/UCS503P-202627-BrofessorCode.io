"""Run the agents on a local folder, without GitHub, a webhook or a pull request.

    python scripts/analyze_dir.py path/to/project
    python scripts/analyze_dir.py path/to/project --run-tests

Every Python and text file is treated as changed. Use it to check that ruff, bandit and
the other tools are installed and that the report looks right."""

from __future__ import annotations

import argparse
import dataclasses
import logging
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from pipeline.config import load_settings  # noqa: E402
from pipeline.models import ChangedFile, PipelineContext, PullRequest, Status  # noqa: E402
from pipeline.orchestrator import _safe_run, decide_overall, default_agents  # noqa: E402
from pipeline.report import build_report  # noqa: E402

SKIP_DIRS = {".git", ".venv", "venv", "env", "node_modules", "__pycache__", ".mypy_cache", ".pytest_cache"}
MAX_BYTES = 300_000


def synthetic_patch(text: str) -> str:
    lines = text.splitlines()
    return f"@@ -0,0 +1,{len(lines)} @@\n" + "\n".join("+" + ln for ln in lines)


def collect(root: Path) -> list[ChangedFile]:
    files: list[ChangedFile] = []
    for path in sorted(root.rglob("*")):
        if not path.is_file() or any(part in SKIP_DIRS for part in path.relative_to(root).parts):
            continue
        if path.stat().st_size > MAX_BYTES:
            continue
        data = path.read_bytes()
        if b"\x00" in data:
            continue  # binary
        text = data.decode("utf-8", errors="replace")
        files.append(ChangedFile(path.relative_to(root).as_posix(), "added",
                                 additions=len(text.splitlines()), patch=synthetic_patch(text)))
    return files


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("path", type=Path)
    parser.add_argument("--run-tests", action="store_true", help="also run the project's pytest tests")
    args = parser.parse_args()
    logging.basicConfig(level=logging.INFO, format="%(levelname)-7s %(message)s")

    root = args.path.resolve()
    settings = load_settings()
    if args.run_tests:
        settings = dataclasses.replace(settings, allow_pr_code_execution=True)
    files = collect(root)
    ctx = PipelineContext(PullRequest("local/dir", 0, "0" * 40), files, root)

    started = time.monotonic()
    verdicts = []
    for agent in default_agents(settings):
        verdict = _safe_run(agent, ctx)
        ctx.verdicts.append(verdict)
        verdicts.append(verdict)
        if verdict.status == Status.BLOCK and settings.stop_on_block:
            break
    overall = decide_overall(verdicts)
    print(build_report(ctx.pr, verdicts, overall, len(files), time.monotonic() - started))


if __name__ == "__main__":
    main()
