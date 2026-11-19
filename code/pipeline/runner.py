"""Run an external tool safely: no shell, a timeout, and a reduced environment."""

from __future__ import annotations

import os
import shutil
import signal
import subprocess
import tempfile
from dataclasses import dataclass
from pathlib import Path

# Only these variables are passed on. Tokens and secrets from .env are never included.
_SAFE_ENV_KEYS = ("PATH", "SYSTEMROOT", "COMSPEC", "PATHEXT", "TEMP", "TMP", "LANG", "LC_ALL", "VIRTUAL_ENV")


@dataclass
class ToolResult:
    args: list[str]
    returncode: int
    stdout: str = ""
    stderr: str = ""
    timed_out: bool = False
    missing: bool = False  # the program is not installed


def clean_env(home: Path | str | None = None) -> dict[str, str]:
    env = {k: os.environ[k] for k in _SAFE_ENV_KEYS if k in os.environ}
    home = str(home or tempfile.gettempdir())
    env.update(HOME=home, USERPROFILE=home, PYTHONDONTWRITEBYTECODE="1", PYTHONIOENCODING="utf-8")
    return env


def _kill(proc: subprocess.Popen) -> None:
    try:
        if os.name == "posix":
            os.killpg(os.getpgid(proc.pid), signal.SIGKILL)  # the tool and its children
        else:
            proc.kill()
    except (ProcessLookupError, PermissionError, OSError):
        pass


def run_tool(args: list[str], cwd: Path, timeout: int, env: dict[str, str] | None = None) -> ToolResult:
    env = env if env is not None else clean_env(cwd)
    exe = shutil.which(args[0], path=env.get("PATH"))
    if exe is None:
        return ToolResult(args, -1, stderr=f"{args[0]} is not installed", missing=True)
    kwargs: dict = dict(cwd=str(cwd), env=env, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                        text=True, encoding="utf-8", errors="replace")
    if os.name == "posix":
        kwargs["start_new_session"] = True
    try:
        proc = subprocess.Popen([exe, *args[1:]], **kwargs)
    except OSError as exc:
        return ToolResult(args, -1, stderr=f"could not start {args[0]}: {exc}")
    try:
        out, err = proc.communicate(timeout=timeout)
    except subprocess.TimeoutExpired:
        _kill(proc)
        out, err = proc.communicate()
        return ToolResult(args, -1, out or "", err or "", timed_out=True)
    return ToolResult(args, proc.returncode, out or "", err or "")
