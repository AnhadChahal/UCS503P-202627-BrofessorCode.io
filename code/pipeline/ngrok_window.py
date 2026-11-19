"""Run `ngrok http <webhook port> --url <your fixed address>` for the launcher (scripts/start_all.py --ngrok).

On a Mac ngrok opens in its own Terminal window (ngrok's normal screen, with its own sign-in state and its web
inspector), so it does not mix with the review programs' output. Elsewhere it runs as a child process of the launcher.
Only the webhook is exposed this way: the dashboard stays on this computer. (For the dashboard behind a sign-in too,
use --tunnel and docs/NGROK_REMOTE.md.)"""

from __future__ import annotations

import shlex
import subprocess
import sys
from typing import Callable


def webhook_command(port: int, url: str) -> list[str]:
    cmd = ["ngrok", "http", str(int(port))]
    if url:
        cmd += ["--url", url]
    return cmd


def applescript(command: list[str]) -> str:
    """AppleScript that opens a new Terminal window running the command."""
    line = shlex.join(command).replace("\\", "\\\\").replace('"', '\\"')
    return f'tell application "Terminal"\n    activate\n    do script "{line}"\nend tell'


def can_open_window(platform: str = sys.platform, which: Callable[[str], str | None] | None = None) -> bool:
    import shutil
    return platform == "darwin" and bool((which or shutil.which)("osascript"))


def open_in_terminal(command: list[str], run: Callable = subprocess.run) -> str | None:
    """Open the window. Returns None on success, otherwise a one-line reason."""
    try:
        done = run(["osascript", "-e", applescript(command)], capture_output=True, text=True, timeout=20, check=False)
    except (OSError, subprocess.SubprocessError) as exc:
        return f"{type(exc).__name__}: {exc}"
    if done.returncode != 0:
        return (done.stderr or "osascript failed").strip().splitlines()[-1]
    return None
