"""What the 'Status' page shows: is the worker alive, how busy is it, is Ollama up and which model is loaded.

Read-only. The dashboard is a different process from the worker, so liveness comes from a heartbeat
the worker writes into the database every few seconds."""

from __future__ import annotations

import time

import requests

from pipeline.config import PipelineSettings
from pipeline.llm import LLMError, OllamaClient
from pipeline.store import Store

WORKER_ALIVE_SECONDS = 45


def _gb(n: int) -> str:
    return f"{n / 1e9:.1f} GB"


def collect_status(store: Store, settings: PipelineSettings, llm_client: OllamaClient | None = None,
                   now: float | None = None) -> dict:
    now = time.time() if now is None else now
    beat = store.last_beat("worker")
    counts = store.status_counts()
    working = [{"id": r["id"], "repo": r["repo"], "pr_number": r["pr_number"]}
               for r in store.list_runs(status="running", limit=5)]
    out: dict = {
        "worker": {"alive": beat is not None and now - beat < WORKER_ALIVE_SECONDS,
                   "seconds_ago": None if beat is None else int(now - beat)},
        "queue": {"queued": counts.get("queued", 0), "running": counts.get("running", 0),
                  "awaiting": counts.get("awaiting_approval", 0), "working": working},
        "settings": {
            "approval policy": settings.approval_policy.replace("_", " "),
            "risk threshold": settings.risk_threshold,
            "approval timeout": f"{settings.approval_timeout_hours} h",
            "deployment workflow": settings.deploy_workflow or "not configured (approval is only recorded)",
            "run PR tests": "yes" if settings.allow_pr_code_execution else "no",
            "AI triage": "on" if settings.llm_enabled else "off",
        },
        "ollama": {"enabled": settings.llm_enabled},
    }
    if not settings.llm_enabled:
        return out
    o = out["ollama"]
    o.update(url=settings.ollama_url, light=settings.llm_model, heavy=settings.llm_heavy_model or "",
             reachable=False, installed=[], loaded=[], error="")
    try:
        client = llm_client or OllamaClient(settings.ollama_url, settings.llm_timeout, settings.llm_keep_alive,
                                            settings.llm_allow_remote)
        o["installed"] = client.installed()
        o["reachable"] = True
        o["loaded"] = [{"name": m["name"], "size": _gb(m["size_bytes"])} for m in client.running()]
    except LLMError as exc:
        o["error"] = str(exc)
    except (requests.RequestException, ValueError, KeyError):
        o["error"] = "Ollama does not answer. Start it with: ollama serve"
    return out
