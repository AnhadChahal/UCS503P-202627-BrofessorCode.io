"""Start the ngrok tunnel for the gateway, with a sign-in in front of the dashboard.
(Or let start_all.py do it: python scripts/start_all.py --tunnel)

    python scripts/start_tunnel.py              # write ngrok-policy.yml, then run ngrok
    python scripts/start_tunnel.py --print-only # show the policy and the command, run nothing

Reads from .env:
    NGROK_ALLOWED_EMAILS   comma-separated e-mail addresses allowed to open the dashboard   (required)
    NGROK_OAUTH_PROVIDER   google (default) or github
    NGROK_URL              your ngrok domain, e.g. your-name.ngrok-free.app                 (optional, keeps the address fixed)
One-time: ngrok config add-authtoken <token from the ngrok dashboard>. Full guide: docs/NGROK_REMOTE.md
"""

from __future__ import annotations

import argparse
import os
import shutil
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from pipeline.config import load_settings  # noqa: E402
from pipeline.tunnel import plan_from_env  # noqa: E402

POLICY_FILE = ROOT / "ngrok-policy.yml"


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--print-only", action="store_true", help="show the policy and command, do not run ngrok")
    parser.add_argument("--no-signin", action="store_true",
                        help="do NOT ask for an ngrok sign-in (only the dashboard's own log-in protects it)")
    args = parser.parse_args()
    settings = load_settings()
    try:
        plan = plan_from_env(os.environ, settings.gateway_port, str(POLICY_FILE), args.no_signin)
    except ValueError as exc:
        print(f"Cannot build the tunnel settings: {exc}")
        return 1
    cmd, policy, emails, url = plan.command, plan.policy, plan.emails, plan.url
    if policy:
        if not args.print_only:
            POLICY_FILE.write_text(policy, encoding="utf-8")
        print(policy if args.print_only else f"Wrote {POLICY_FILE.name} (allowed: {', '.join(emails)})")
    else:
        print("WARNING: no ngrok sign-in. Anyone who finds the address can reach the dashboard log-in page.")
    print("Command: " + " ".join(cmd))
    shown = url or "the https address ngrok prints"
    print(f"\nSet in GitHub (Settings > Webhooks):  Payload URL = {shown}/webhook")
    print(f"Set in .env:  DASHBOARD_URL={url or '<that address>'}   TRUST_PROXY=true   then restart start_all.py --gateway\n", flush=True)
    if args.print_only:
        return 0
    if not shutil.which("ngrok"):
        print("ngrok is not installed or not on PATH. Install it from https://ngrok.com/download and run: "
              "ngrok config add-authtoken <your token>")
        return 1
    try:
        return subprocess.call(cmd, cwd=ROOT)
    except KeyboardInterrupt:
        return 0


if __name__ == "__main__":
    sys.exit(main())
