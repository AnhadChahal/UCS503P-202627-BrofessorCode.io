"""Start the webhook (with the review worker) and the dashboard together.

    python scripts/start_all.py

Runs the preflight checks first and stops if something must be fixed (use --force to skip that).
Output of every program is shown in one terminal with a prefix. Ctrl+C stops everything this script started.

When LLM_ENABLED=true in .env it also starts `ollama serve` (left alone if Ollama already runs) and loads the model.
Ollama not installed is only a warning then (the AI note is skipped).

    python scripts/start_all.py --ollama      same, but refuse to start at all if Ollama is not installed
    python scripts/start_all.py --no-ollama   never start Ollama
    python scripts/start_all.py --ngrok       also runs `ngrok http <PORT>` for the webhook only (own Terminal window on a
                                              Mac; adds --url <NGROK_URL> if that is set). START_NGROK=true in .env does
                                              this on every run; --no-ngrok switches it off. The dashboard stays local.
    python scripts/start_all.py --tunnel      also starts the gateway and ngrok with a sign-in (see docs/NGROK_REMOTE.md)
    python scripts/start_all.py --all         everything: webhook, worker, dashboard, gateway, ngrok and Ollama

ngrok is never started without --ngrok or --tunnel. Run it yourself:  ngrok http <PORT from your .env>
"""

from __future__ import annotations

import argparse
import os
import shutil
import signal
import subprocess
import sys
import threading
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from pipeline.config import load_settings  # noqa: E402
from pipeline.doctor import run_checks, summarize  # noqa: E402
from pipeline.ngrok_window import can_open_window, open_in_terminal, webhook_command  # noqa: E402
from pipeline.ollama_run import plan_ollama, wait_until_answers, warm_model  # noqa: E402

POLICY_FILE = ROOT / "ngrok-policy.yml"
OPTIONAL = {"ollama"}   # the AI note is advisory: if Ollama stops, reviews carry on without it

MARK = {"ok": "ok  ", "warn": "WARN", "fail": "FAIL"}


def _pump(name: str, proc: subprocess.Popen) -> None:
    for line in proc.stdout:  # type: ignore[union-attr]
        if name == "ollama" and line.startswith("[GIN]"):
            continue   # one line per request, and the live page asks every few seconds: it would drown everything else
        print(f"[{name}] {line.rstrip()}", flush=True)


def _stop_on_signal(signum, frame):  # noqa: ARG001
    raise KeyboardInterrupt  # closing the terminal or `kill` must stop the children too, not orphan them


def main() -> int:
    for name in ("SIGTERM", "SIGHUP"):
        if hasattr(signal, name):
            signal.signal(getattr(signal, name), _stop_on_signal)
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--force", action="store_true", help="start even if a check fails")
    parser.add_argument("--gateway", action="store_true",
                        help="also start the one-port front door (/webhook -> webhook, the rest -> dashboard) for the tunnel")
    parser.add_argument("--tunnel", action="store_true",
                        help="also start ngrok (implies --gateway): needs NGROK_ALLOWED_EMAILS in .env and `ngrok config add-authtoken`")
    parser.add_argument("--ngrok", action="store_true",
                        help="also run `ngrok http <PORT>` for the webhook only (adds --url NGROK_URL if set; own Terminal window on a Mac)")
    parser.add_argument("--no-ngrok", action="store_true", help="do not start ngrok even when START_NGROK=true in .env")
    parser.add_argument("--no-signin", action="store_true",
                        help="with --tunnel: do NOT ask for an ngrok sign-in (only the dashboard log-in protects it)")
    parser.add_argument("--ollama", action="store_true",
                        help="start `ollama serve` when Ollama is not already running (refuse to start if it is not installed)")
    parser.add_argument("--no-ollama", action="store_true", help="do not start Ollama even when LLM_ENABLED=true")
    parser.add_argument("--all", action="store_true", help="same as --tunnel --ollama")
    args = parser.parse_args()
    if args.all:
        args.tunnel = args.ollama = True
    if args.tunnel:
        args.gateway = True
    if args.ngrok and args.tunnel:
        print("Choose one: --ngrok (webhook only) or --tunnel/--all (gateway + sign-in); both would start ngrok.")
        return 1

    settings = load_settings()
    procs: list[tuple[str, subprocess.Popen]] = []
    env = {**os.environ, "PYTHONUNBUFFERED": "1"}

    def launch(name: str, cmd: list[str], extra_env: dict[str, str] | None = None) -> subprocess.Popen:
        proc = subprocess.Popen(cmd, cwd=ROOT, env={**env, **(extra_env or {})}, stdout=subprocess.PIPE,
                                stderr=subprocess.STDOUT, text=True)
        procs.append((name, proc))
        threading.Thread(target=_pump, args=(name, proc), daemon=True).start()
        return proc

    try:
        # ---- decide everything that can be refused BEFORE starting anything ----
        plan = None
        if args.tunnel:
            from pipeline.tunnel import plan_from_env  # only needed with --tunnel (Release 7)
            try:
                plan = plan_from_env(os.environ, getattr(settings, "gateway_port", 8080), str(POLICY_FILE), args.no_signin)
            except ValueError as exc:
                print(f"Cannot start the tunnel: {exc}")
                return 1
            if not shutil.which("ngrok"):
                print("ngrok is not installed or not on PATH. Install it from https://ngrok.com/download and run: "
                      "ngrok config add-authtoken <your token>")
                return 1
        ngrok_cmd = None
        auto_ngrok = os.environ.get("START_NGROK", "").strip().lower() in ("1", "true", "yes", "on")
        if args.ngrok or (auto_ngrok and not args.tunnel and not args.no_ngrok):
            ngrok_url = ""
            if os.environ.get("NGROK_URL", "").strip():     # optional: without it this is exactly `ngrok http <PORT>`
                from pipeline.tunnel import parse_url  # Release 7
                try:
                    ngrok_url = parse_url(os.environ["NGROK_URL"])
                except ValueError as exc:
                    print(f"Cannot start ngrok: {exc}")
                    return 1
            if not shutil.which("ngrok"):
                if args.ngrok:
                    print("ngrok is not installed or not on PATH. Install it from https://ngrok.com/download")
                    return 1
                print("WARN  START_NGROK=true but ngrok is not installed or not on PATH, so it was not started.")
            else:
                ngrok_cmd = webhook_command(int(os.getenv("PORT", "5000")), ngrok_url)
        ollama_plan = None
        if args.ollama or (settings.llm_enabled and not args.no_ollama):
            ollama_plan = plan_ollama(settings)
            if ollama_plan.action == "missing":
                if args.ollama:
                    print(ollama_plan.message)
                    return 1
                print(f"WARN  {ollama_plan.message}\n      Reviews still run; the AI note is skipped.")
                ollama_plan = None

        # ---- Ollama first, so the checks below see it ----
        if ollama_plan is not None:
            print(ollama_plan.message, flush=True)
            if ollama_plan.action == "start":
                proc = launch("ollama", ollama_plan.command, ollama_plan.env)
                if wait_until_answers(settings, alive=lambda: proc.poll() is None):
                    print("Ollama answers.", flush=True)
                else:
                    print("WARN  Ollama did not answer in time. Reviews still run; the AI note is skipped until it does.")
            if ollama_plan.action in ("start", "already"):
                threading.Thread(target=lambda: print(f"[ollama] {warm_model(settings)}", flush=True), daemon=True).start()

        checks = run_checks(settings, ports_must_be_free=True)
        for c in checks:
            if c.level != "ok":
                print(f"{MARK[c.level]}  {c.text}")
        fails, warns = summarize(checks)
        if fails and not args.force:
            print(f"\n{fails} problem(s) to fix first (see above). Run python scripts/doctor.py for the full list.")
            return 1

        if plan is not None:
            if plan.policy:
                POLICY_FILE.write_text(plan.policy, encoding="utf-8")
            else:
                print("WARNING: --no-signin: only the dashboard's own log-in protects it from anyone who finds the address.")
            if not plan.url:
                print("NOTE: NGROK_URL is not set, so ngrok chooses the address. Set NGROK_URL (your fixed ngrok domain) so the "
                      "GitHub webhook URL and DASHBOARD_URL stay valid.")

        programs = [("webhook", [sys.executable, "-m", "webhook.app"]),
                    ("dashboard", [sys.executable, "scripts/run_dashboard.py"])]
        if args.gateway:
            programs.append(("gateway", [sys.executable, "scripts/gateway.py"]))
        if plan is not None:
            # Output goes through a pipe, so ngrok switches its console screen off by itself and logs nothing unless asked.
            programs.append(("tunnel", plan.command + ["--log", "stdout"]))
        for name, cmd in programs:
            launch(name, cmd)
        if ngrok_cmd is not None:
            if can_open_window():
                reason = open_in_terminal(ngrok_cmd)
                if reason is None:
                    print("ngrok opened in its own Terminal window (close that window to stop it).", flush=True)
                else:
                    print(f"Could not open a Terminal window ({reason}). Run this yourself:  {' '.join(ngrok_cmd)}")
            else:
                launch("ngrok", ngrok_cmd + ["--log", "stdout"])
        port = os.getenv("PORT", "5000")
        print(f"\nWebhook   http://127.0.0.1:{port}/webhook   (tunnel it: ngrok http {port})")
        print(f"Dashboard http://127.0.0.1:{settings.dashboard_port}")
        if args.gateway:
            print(f"Gateway   http://127.0.0.1:{getattr(settings, 'gateway_port', 8080)}   (tunnel THIS port: python scripts/start_tunnel.py)")
        if ngrok_cmd is not None and "--url" in ngrok_cmd:
            shown = ngrok_cmd[ngrok_cmd.index("--url") + 1]
            print(f"Public    {shown}   GitHub webhook Payload URL: {shown}/webhook")
        if plan is not None:
            shown = plan.url or "<the address ngrok prints below>"
            print(f"Public    {shown}   GitHub webhook Payload URL: {shown}/webhook")
        print("Ctrl+C to stop everything.\n", flush=True)
        noted: set[str] = set()
        while True:
            dead = [n for n, p in procs if p.poll() is not None]
            required_dead = [n for n in dead if n not in OPTIONAL]
            if required_dead:
                print(f"\n{required_dead[0]} stopped on its own (see its output above). Stopping the others.")
                return 1
            for n in dead:
                if n not in noted:
                    noted.add(n)
                    print(f"\nNOTE: {n} stopped (see its output above). Reviews carry on without it.", flush=True)
            threading.Event().wait(0.5)
    except KeyboardInterrupt:
        print("\nStopping ...")
        return 0
    finally:
        # Only what THIS script started is stopped: an Ollama that was already running is not ours to stop.
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
