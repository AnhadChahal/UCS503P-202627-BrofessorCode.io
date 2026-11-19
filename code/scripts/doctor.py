"""Check that everything is in place. Changes nothing.

    python scripts/doctor.py
    python scripts/doctor.py --repo OWNER/REPO     also asks GitHub whether the token can see that repository
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from pipeline.config import load_settings  # noqa: E402
from pipeline.doctor import run_checks, summarize  # noqa: E402

MARK = {"ok": "ok  ", "warn": "WARN", "fail": "FAIL"}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--repo", default="", help="OWNER/REPO to test the token against")
    args = parser.parse_args()
    checks = run_checks(load_settings(), github_repo=args.repo)
    for c in checks:
        print(f"{MARK[c.level]}  {c.text}")
    fails, warns = summarize(checks)
    print(f"\n{fails} problem(s) to fix, {warns} warning(s).")
    return 1 if fails else 0


if __name__ == "__main__":
    sys.exit(main())
