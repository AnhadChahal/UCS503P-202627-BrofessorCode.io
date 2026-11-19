"""Start the webhook (with the review worker) and the dashboard together.

    python scripts/start_all.py

Runs the preflight checks first and stops if something must be fixed (use --force to skip that).
Output of both programs is shown in one terminal with a prefix. Ctrl+C stops both.
ngrok is not started here; in another terminal run:  ngrok http <PORT from your .env>
"""

from __future__ import annotations

import argparse
import os
import signal
import subprocess
import sys
import threading
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from pipeline.config import load_settings  # noqa: E402
from pipeline.doctor import run_checks, summarize  # noqa: E402

MARK = {"ok": "ok  ", "warn": "WARN", "fail": "FAIL"}


def _pump(name: str, proc: subprocess.Popen) -> None:
    for line in proc.stdout:  # type: ignore[union-attr]
        print(f"[{name}] {line.rstrip()}", flush=True)


def _stop_on_signal(signum, frame):  # noqa: ARG001
    raise KeyboardInterrupt  # closing the terminal or `kill` must stop the children too, not orphan them


def main() -> int:
    for name in ("SIGTERM", "SIGHUP"):
        if hasattr(signal, name):
            signal.signal(getattr(signal, name), _stop_on_signal)
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--force", action="store_true", help="start even if a check fails")
    args = parser.parse_args()

    settings = load_settings()
    checks = run_checks(settings, ports_must_be_free=True)
    for c in checks:
        if c.level != "ok":
            print(f"{MARK[c.level]}  {c.text}")
    fails, warns = summarize(checks)
    if fails and not args.force:
        print(f"\n{fails} problem(s) to fix first (see above). Run python scripts/doctor.py for the full list.")
        return 1

    env = {**os.environ, "PYTHONUNBUFFERED": "1"}
    programs = [("webhook", [sys.executable, "-m", "webhook.app"]),
                ("dashboard", [sys.executable, "scripts/run_dashboard.py"])]
    procs: list[tuple[str, subprocess.Popen]] = []
    try:
        for name, cmd in programs:
            proc = subprocess.Popen(cmd, cwd=ROOT, env=env, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
            procs.append((name, proc))
            threading.Thread(target=_pump, args=(name, proc), daemon=True).start()
        port = os.getenv("PORT", "5000")
        print(f"\nWebhook   http://127.0.0.1:{port}/webhook   (tunnel it: ngrok http {port})")
        print(f"Dashboard http://127.0.0.1:{settings.dashboard_port}\nCtrl+C to stop both.\n", flush=True)
        while all(p.poll() is None for _, p in procs):
            threading.Event().wait(0.5)
        dead = next(n for n, p in procs if p.poll() is not None)
        print(f"\n{dead} stopped on its own (see its output above). Stopping the other one.")
        return 1
    except KeyboardInterrupt:
        print("\nStopping ...")
        return 0
    finally:
        for _, p in procs:
            if p.poll() is None:
                p.terminate()
        for _, p in procs:
            try:
                p.wait(timeout=10)
            except subprocess.TimeoutExpired:
                p.kill()


if __name__ == "__main__":
    sys.exit(main())
