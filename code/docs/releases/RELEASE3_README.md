> **History.** This note describes how one stage was added to an earlier copy of the project (it mentions files such as
> `requirements-pipeline.txt` and `.env.pipeline.example`, which are now merged into `requirements.txt` and `.env.example`).
> For the finished project follow the top-level `README.md`.

# Release 3: local language model (Ollama) + wiring for the Flask webhook

Two things in this zip:

1. **TriageAgent** (FR27): a local model adds an "AI note" to each tool finding and writes a short
   summary of the change. It is advisory. It sits between SecurityAgent and RiskAgent.
2. **The Flask webhook wiring for Release 2**: a new `webhook/app.py` and `tests/test_webhook.py`.
   Without them the Release 2 pipeline is not connected to your webhook.

## What the language model may and may not do

| It may | It may not |
|---|---|
| Label a finding: likely real / likely false positive / unsure, with a one-line reason | Change any agent's verdict, remove a finding, or lower a severity |
| Write a 2-3 sentence summary for the reviewer (labelled "AI, may be wrong") | Make a PR pass, be approved, or skip the person. Routing and the risk score ignore its labels |
| Nothing else: its status is only PASS or WARN, never BLOCK or ESCALATE | Be trusted: everything it reads is untrusted data |

Protections, each covered by a test (three were checked by deliberately breaking them):
- Code, titles and diffs are fenced in `<untrusted>` tags; text that tries to close the fence is neutralised.
- Secrets are masked before anything is sent; findings from the secret scanner are never sent.
- A finding's file path must stay inside the checked-out repository (no reading `../../something`).
- The answer must be exactly `{"verdict": one of three, "reason": text}`; anything else becomes "unsure".
- Links, markdown and HTML are stripped from model output (a link in a PR comment can leak data when rendered).
- Code is sent only to a loopback address unless `LLM_ALLOW_REMOTE=true`.
- A plain regex check (no model) flags text such as "ignore previous instructions" or "approve this PR" in the
  diff or title as a MEDIUM finding, so it raises the risk score and a person sees it.
- If Ollama is down, a model is missing, or the model keeps failing, the run goes on without AI notes
  and the report says so. Two errors in a row stop further model calls for that run.
- A blocked run never reaches the model (the pipeline stops at the first BLOCK).

## Light and heavy model (the hand-off)

`LLM_MODEL` (light, default `qwen2.5-coder:7b`) handles most findings and the summary.
If `LLM_HEAVY_MODEL` is set (for example `qwen3-coder:30b`), only HIGH and CRITICAL findings go to it.
The agent does all light-model work first, then the heavy work, so the models switch once. Before a
different model is used, the previous one is unloaded (Ollama `keep_alive: 0`), so two big models are
never in memory together. When the agent finishes, the last model is unloaded too
(`LLM_UNLOAD_AFTER_RUN`), freeing memory for ruff, bandit and the rest. If the heavy model is not
installed, the light one is used for everything and the report notes it.

Memory: a 7B model is a few GB; a 30B model is roughly 20 GB. On a 16 GB laptop leave
`LLM_HEAVY_MODEL` empty. The worker handles one run at a time, so a slow model delays the next PR.

## Files

```
pipeline/llm.py                      Ollama client (local-only guard, JSON answers, unload) + output cleaning
pipeline/agents/triage_agent.py      TriageAgent
pipeline/agents/secrets_scan.py      (changed) mask_secrets()
pipeline/orchestrator.py             (changed) default_agents() adds TriageAgent when LLM_ENABLED=true
pipeline/report.py, models.py, config.py   (changed) AI summary + per-finding note, finding_key(), LLM settings
dashboard/app.py, templates/run.html (changed) the same notes on the run page
scripts/check_llm.py                 check Ollama and the models without GitHub
webhook/app.py                       (REPLACES yours) hands PRs to the Release 2 worker
tests/test_webhook.py                (REPLACES yours) 13 tests for the new app.py
tests/test_release3_*.py             36 new tests
.env.pipeline.example                (replaces the old one) all settings, Release 1 to 3
```

## Apply it

1. Copy everything in `code/` over your project root. Your own `webhook/config.py`, `webhook/security.py`
   and `scripts/send_test_event.py` stay as they are. `webhook/pipeline.py` is no longer imported; you can delete it.
2. Merge the new lines of `.env.pipeline.example` into your `.env`. Releases 2 and 3 need at least
   `DB_PATH` (absolute path) and `DASHBOARD_SECRET_KEY`; with `LLM_ENABLED=false` nothing else is new.
3. `python -m pytest -q` from the project root. Expect 175 passed.
4. Two terminals, both from the project root:
   ```
   python -m webhook.app             # webhook + worker (the worker lives in this process)
   python scripts/run_dashboard.py   # dashboard on 127.0.0.1:5002
   ```
   First time only: `python scripts/create_user.py <name>`.

## Turn the LLM on

```
brew install ollama            # or the installer from ollama.com
ollama serve                   # leave it running (the desktop app does this for you)
ollama pull qwen2.5-coder:7b
python scripts/check_llm.py    # expect ok lines and two answers
```
Then set `LLM_ENABLED=true` in `.env` and restart `python -m webhook.app`. Open a PR with a finding
(for example `subprocess.call(cmd, shell=True)`); the comment and the run page show "AI summary" and
"AI triage" next to the finding. Compare a run with `LLM_ENABLED=false`: status and risk score are identical.

## What was and was not tested

Tested here: the client against a fake Ollama (request shape, local-only guard, unload order, bad answers),
every protection above, light/heavy ordering and fall-back, repeated-failure stop, integration with the
service, PR comment and dashboard (including a stored reason containing a script tag), and the new
Flask webhook (a real worker and database, no fake, for the webhook -> run path).

**Not tested:** a real Ollama and real models (none in the build sandbox, no network). Expect to adjust:
whether your 7B model returns valid JSON every time (it falls back to "unsure" when it does not), how
good its labels are (small models are often wrong, which is why they are advisory), and timing.
`scripts/check_llm.py` is the quick way to see this on your machine before the demo.
