"""Demo mode: show the whole system with no GitHub, no ngrok and no token.

    python scripts/demo.py list                 what the sample pull requests are
    python scripts/demo.py seed                 fill a fresh demo database with runs in every state
    python scripts/demo.py dashboard            open the dashboard on the demo database (login printed)
    python scripts/demo.py run risky            run ONE sample PR through the real pipeline and print the result
    python scripts/demo.py export risky --to DIR   write a sample PR's files into DIR, to commit on a real branch
    python scripts/demo.py reset                delete demo_data/

Everything except GitHub is real (agents, rules, database, dashboard). What would have been posted to
GitHub is written to demo_data/ : comments/*.md, statuses.log, deploys.log.
Respects LLM_ENABLED / LLM_MODEL in .env, so you can show the AI notes too.
"""

from __future__ import annotations

import argparse
import logging
import secrets
import shutil
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from dashboard import create_app  # noqa: E402
from pipeline.auth import hash_password  # noqa: E402
from pipeline.config import load_settings  # noqa: E402
from pipeline.demo import (DEMO_PASSWORD, DEMO_USER, SCENARIOS, build_demo, demo_settings, review, seed)  # noqa: E402

OUT = ROOT / "demo_data"


def _settings():
    OUT.mkdir(exist_ok=True)
    return demo_settings(load_settings(), OUT)


def cmd_list(_: argparse.Namespace) -> None:
    for sc in SCENARIOS.values():
        print(f"{sc.key:<11} {sc.title}\n            {sc.says}\n            -> {sc.expect}\n")


def cmd_reset(_: argparse.Namespace) -> None:
    shutil.rmtree(OUT, ignore_errors=True)
    print(f"Deleted {OUT}")


def cmd_seed(_: argparse.Namespace) -> None:
    shutil.rmtree(OUT, ignore_errors=True)
    made = seed(_settings(), OUT)
    service, _client, store = build_demo(_settings(), OUT)
    print("Demo database filled:\n")
    for label, run_id in made:
        print(f"  run #{run_id:<3} {store.get_run(run_id)['status']:<18} {label}")
    print(f"\nNext: python scripts/demo.py dashboard   (log in as {DEMO_USER} / {DEMO_PASSWORD})")


def cmd_run(args: argparse.Namespace) -> None:
    settings = _settings()
    service, client, store = build_demo(settings, OUT)
    store.set_user(DEMO_USER, hash_password(DEMO_PASSWORD))
    number = 200 + len(store.list_runs(limit=10_000))
    run_id = review(service, client, args.scenario, number)
    run = store.get_run(run_id)
    print(f"\nRun #{run_id}: {run['status']}   risk score: {run['risk_score']}")
    if run["escalation_reason"]:
        print(f"Why a person is needed: {run['escalation_reason']}")
    for v in store.get_verdicts(run_id):
        print(f"  {v['agent']:<14} {v['status']:<9} {len(v['findings'])} finding(s)   " + "; ".join(v["notes"][:3]))
    sc = SCENARIOS[args.scenario]
    print(f"\nExpected: {sc.expect}")
    print(f"PR comment that would be posted: {OUT}/comments/demo_shop_pr{number}.md")
    print("Decide on it with: python scripts/demo.py dashboard")


def cmd_export(args: argparse.Namespace) -> None:
    """Write a sample PR's files to a folder, so you can put them on a branch and open a REAL pull request."""
    dest = Path(args.to).expanduser()
    for name, content in SCENARIOS[args.scenario].files.items():
        path = dest / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content, encoding="utf-8")
        print(f"wrote {path}")
    print("\nNow, in your test repository:\n"
          f"  git checkout -b demo/{args.scenario}\n  git add -A && git commit -m \"{SCENARIOS[args.scenario].title}\"\n"
          f"  git push -u origin demo/{args.scenario}   # then open a pull request into main")
    if args.scenario == "secret":
        print("\nNote: GitHub push protection may refuse a push that contains a key-shaped string. If it does, "
              "show this case with 'python scripts/demo.py run secret' instead.")


def cmd_dashboard(_: argparse.Namespace) -> None:
    settings = _settings()
    key = settings.dashboard_secret_key if len(settings.dashboard_secret_key) >= 16 else secrets.token_hex(32)
    service, _client, store = build_demo(demo_settings(load_settings(), OUT, key), OUT)
    store.set_user(DEMO_USER, hash_password(DEMO_PASSWORD))
    app = create_app(service, key, banner="DEMO MODE: no real GitHub is contacted and nothing is deployed")
    print(f"\nDemo dashboard: http://127.0.0.1:{settings.dashboard_port}   login: {DEMO_USER} / {DEMO_PASSWORD}")
    print(f"Simulated GitHub output goes to {OUT}/ (comments/, statuses.log, deploys.log)\n")
    app.run(host="127.0.0.1", port=settings.dashboard_port, debug=False)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("list").set_defaults(func=cmd_list)
    sub.add_parser("seed").set_defaults(func=cmd_seed)
    sub.add_parser("dashboard").set_defaults(func=cmd_dashboard)
    sub.add_parser("reset").set_defaults(func=cmd_reset)
    run = sub.add_parser("run")
    run.add_argument("scenario", choices=sorted(SCENARIOS))
    run.set_defaults(func=cmd_run)
    export = sub.add_parser("export")
    export.add_argument("scenario", choices=sorted(SCENARIOS))
    export.add_argument("--to", required=True, help="folder to write the files into")
    export.set_defaults(func=cmd_export)
    args = parser.parse_args()
    logging.basicConfig(level=logging.WARNING, format="%(levelname)s %(name)s: %(message)s")
    args.func(args)


if __name__ == "__main__":
    main()
