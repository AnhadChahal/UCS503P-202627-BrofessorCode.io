"""Starting a local Ollama server for the launcher (scripts/start_all.py --ollama).

What is started is `ollama serve`, not `ollama run <model>`: `run` opens an interactive chat in the terminal
and would block the launcher, while the review only needs the server (the pipeline asks it for answers over
HTTP and Ollama loads the model on the first request). An Ollama that already answers is left alone, so the
macOS menu-bar app and `ollama serve` in another terminal both keep working. A server is only ever started
for a loopback address: code is never sent anywhere else by this launcher."""

from __future__ import annotations

import shutil
import time
from dataclasses import dataclass, field
from typing import Callable
from urllib.parse import urlparse

from pipeline.llm import LOOPBACK, LLMError, OllamaClient

DEFAULT_PORT = 11434


@dataclass
class OllamaPlan:
    action: str                      # "already" | "start" | "remote" | "missing"
    message: str
    command: list[str] = field(default_factory=list)
    env: dict[str, str] = field(default_factory=dict)


def _client(settings) -> OllamaClient:
    return OllamaClient(settings.ollama_url, 3, settings.llm_keep_alive, settings.llm_allow_remote)


def answers(settings) -> bool:
    """True when something answers as Ollama at OLLAMA_URL."""
    try:
        return _client(settings).available()
    except LLMError:
        return False


def plan_ollama(settings, which: Callable[[str], str | None] = shutil.which) -> OllamaPlan:
    parsed = urlparse(settings.ollama_url)
    host = parsed.hostname or ""
    if host not in LOOPBACK:
        return OllamaPlan("remote", f"OLLAMA_URL ({settings.ollama_url}) is not this computer, so the launcher did not start Ollama.")
    if answers(settings):
        return OllamaPlan("already", f"Ollama is already running at {settings.ollama_url}; using it.")
    exe = which("ollama")
    if not exe:
        return OllamaPlan("missing", "ollama is not installed or not on PATH. Install it from https://ollama.com/download "
                          "(or start without --ollama).")
    port = parsed.port or DEFAULT_PORT
    env: dict[str, str] = {}
    if port != DEFAULT_PORT or host == "::1":
        env["OLLAMA_HOST"] = f"[::1]:{port}" if host == "::1" else f"127.0.0.1:{port}"
    return OllamaPlan("start", f"Starting ollama serve for {settings.ollama_url} ...", [exe, "serve"], env)


def wait_until_answers(settings, timeout: float = 25.0, alive: Callable[[], bool] = lambda: True,
                       sleep: Callable[[float], None] = time.sleep) -> bool:
    """Wait for the server to answer; give up early when the process has died."""
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if answers(settings):
            return True
        if not alive():
            return False
        sleep(0.3)
    return answers(settings)


def warm_model(settings) -> str:
    """Load the configured model into memory now, so the first review does not wait for it. Best effort;
    returns one line to show. Run it in a thread: a big model can take a minute."""
    if not settings.llm_enabled:
        return "LLM_ENABLED is false in .env, so reviews will not use Ollama. Set LLM_ENABLED=true to use it."
    client = _client(settings)
    model = settings.llm_model
    if not client.has_model(model):
        return f"Ollama model {model} is not installed: run  ollama pull {model}"
    try:
        client.warm(model)
    except LLMError as exc:
        return f"Could not preload {model}: {exc}"
    return f"Ollama model {model} is loaded and ready."
