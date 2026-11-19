"""A small client for a local Ollama server (https://ollama.com).

Only what the pipeline needs: ask a model for a JSON answer, check which models are installed,
and unload a model so that a bigger one can take its place in memory. Code is sent only to a
loopback address unless LLM_ALLOW_REMOTE is set on purpose."""

from __future__ import annotations

import json
import logging
import re
from urllib.parse import urlparse

import requests

log = logging.getLogger("pipeline.llm")

LOOPBACK = {"127.0.0.1", "localhost", "::1"}
MAX_RESPONSE_BYTES = 200_000


class LLMError(Exception):
    """The model server could not give a usable answer."""


class OllamaClient:
    def __init__(self, base_url: str, timeout: int = 120, keep_alive: str = "10m",
                 allow_remote: bool = False, session: requests.Session | None = None) -> None:
        host = urlparse(base_url).hostname or ""
        if host not in LOOPBACK and not allow_remote:
            raise LLMError(f"refusing to send code to {host or base_url!r}: it is not a local address "
                           "(set LLM_ALLOW_REMOTE=true only if you really mean it)")
        self.base_url = base_url.rstrip("/")
        self.timeout = timeout
        self.keep_alive = keep_alive
        self.session = session or requests.Session()
        if session is None:
            self.session.trust_env = False  # a proxy from the environment must not see local traffic
        self.loaded: str | None = None      # the model this client last used
        self._installed: list[str] | None = None

    # ---- discovery ----
    def _tags(self) -> list[str]:
        if self._installed is None:
            resp = self.session.get(f"{self.base_url}/api/tags", timeout=(3, 10))
            resp.raise_for_status()
            self._installed = [m.get("name", "") for m in resp.json().get("models", [])]
        return self._installed

    def installed(self) -> list[str]:
        return list(self._tags())

    def available(self) -> bool:
        try:
            self._tags()
            return True
        except (requests.RequestException, ValueError):
            return False

    def has_model(self, name: str) -> bool:
        try:
            installed = self._tags()
        except (requests.RequestException, ValueError):
            return False
        if ":" in name:
            return name in installed
        return name in installed or f"{name}:latest" in installed

    def running(self) -> list[dict]:
        """Models Ollama currently holds in memory: [{name, size_bytes, expires_at}]."""
        resp = self.session.get(f"{self.base_url}/api/ps", timeout=(3, 5))
        resp.raise_for_status()
        return [{"name": m.get("name", ""), "size_bytes": int(m.get("size", 0) or 0),
                 "expires_at": str(m.get("expires_at", ""))} for m in resp.json().get("models", [])]

    # ---- asking ----
    def chat_json(self, model: str, system: str, user: str, max_tokens: int = 300) -> dict:
        """One question, one JSON object back. If another model is loaded, unload it first so two
        big models are never in memory together."""
        if self.loaded and self.loaded != model:
            self.unload(self.loaded)
        payload = {
            "model": model, "stream": False, "format": "json", "keep_alive": self.keep_alive,
            "messages": [{"role": "system", "content": system}, {"role": "user", "content": user}],
            "options": {"temperature": 0, "num_predict": max_tokens, "num_ctx": 4096},
        }
        try:
            resp = self.session.post(f"{self.base_url}/api/chat", json=payload, timeout=(3, self.timeout))
            resp.raise_for_status()
            if len(resp.content) > MAX_RESPONSE_BYTES:
                raise LLMError("the response was too large")
            self.loaded = model
            content = resp.json()["message"]["content"]
            answer = json.loads(content)
        except LLMError:
            raise
        except (requests.RequestException, KeyError, TypeError, ValueError) as exc:
            raise LLMError(f"{type(exc).__name__} while asking {model}") from exc
        if not isinstance(answer, dict):
            raise LLMError("the answer was not a JSON object")
        return answer

    def warm(self, model: str) -> None:
        """Load a model into memory without asking it anything (an empty generate request)."""
        try:
            resp = self.session.post(f"{self.base_url}/api/generate", json={"model": model, "keep_alive": self.keep_alive},
                                     timeout=(3, max(self.timeout, 120)))
            resp.raise_for_status()
        except requests.RequestException as exc:
            raise LLMError(f"{type(exc).__name__} while loading {model}") from exc
        self.loaded = model

    def unload(self, model: str) -> None:
        """Ask Ollama to drop a model from memory now (keep_alive 0). Best effort."""
        try:
            self.session.post(f"{self.base_url}/api/generate", json={"model": model, "keep_alive": 0},
                              timeout=(3, 30))
        except requests.RequestException:
            log.warning("Could not unload %s", model)
        if self.loaded == model:
            self.loaded = None

    def release(self) -> None:
        if self.loaded:
            self.unload(self.loaded)


# ---- cleaning what comes back and what goes in --------------------------------------------
_CONTROL = re.compile(r"[\x00-\x08\x0b-\x1f\x7f]")
_URL = re.compile(r"(?i)\b(?:https?|ftp|file)://\S+|\bwww\.\S+")


def clean_text(text: object, limit: int) -> str:
    """Make model output safe to show: one line, no links (a link in a comment could leak data when a
    page renders it), no markdown or HTML structure, no control characters, limited length."""
    text = _CONTROL.sub(" ", str(text if text is not None else ""))
    text = _URL.sub("(link removed)", text)
    text = re.sub(r"[\[\]<>`]", "", text)
    text = " ".join(text.split())
    return text if len(text) <= limit else text[: limit - 3] + "..."


def fence(text: str) -> str:
    """Untrusted text must not be able to close the <untrusted> block that wraps it."""
    return re.sub(r"(?i)</?\s*untrusted", "[untrusted", text)
