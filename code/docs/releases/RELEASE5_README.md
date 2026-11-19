> **History.** This note describes how one stage was added to an earlier copy of the project (it mentions files such as
> `requirements-pipeline.txt` and `.env.pipeline.example`, which are now merged into `requirements.txt` and `.env.example`).
> For the finished project follow the top-level `README.md`.

# Stage 5: demo and run kit

Nothing here changes how the system decides. It makes it easier to start, check, demonstrate and fix.

## What is in it

| File | Purpose |
|---|---|
| `scripts/doctor.py` (`pipeline/doctor.py`) | Preflight: secrets, token, database, tools, ports, Ollama, optional live GitHub check. Changes nothing. |
| `scripts/start_all.py` | Runs the checks, then starts the webhook (with the worker) and the dashboard in one terminal. Ctrl+C, `kill` or closing the terminal stops both. |
| `scripts/demo.py` + `pipeline/demo.py` | **Offline demo mode**: five sample PRs run through the REAL pipeline with no GitHub, ngrok or token. `list`, `seed`, `run <name>`, `dashboard`, `export <name> --to DIR`, `reset`. |
| `docs/DEMO_SCRIPT.md` | 8-minute viva script, a fallback table, likely questions with short answers. |
| `docs/TROUBLESHOOTING.md` | Symptom, cause, fix: startup, GitHub, dashboard, Ollama, tests. |
| `tests/test_demo_kit.py` | 23 tests. |
| changed | `dashboard/app.py` + `base.html` (optional demo banner), `pipeline/store.py` (`user_count`), `pipeline/agents/secrets_scan.py` (see below) |

## Apply

```
unzip -o ~/Downloads/stage5.zip -d /tmp/stage5
cp -R /tmp/stage5/code/. code/          # includes stage 3 and 4, and the new docs/ folder
cd code && python -m pytest -q          # expect 198 passed
python scripts/doctor.py
python scripts/demo.py seed && python scripts/demo.py dashboard
```

## A fix that came out of building the demo

The secret scanner missed `DB_PASSWORD = "..."` and `stripe_secret_key = "..."`: it only matched a bare name such as
`password`. Names with a prefix are now caught (`hardcoded-credential`, MEDIUM, redacted). `tokenizer = "bert-base-uncased"`
and placeholders such as `your-api-key-here` are still not flagged. Both directions have tests.

## Things to know

- Offline demo: approving a run does not deploy anything; the "deployment" is a line in `demo_data/deploys.log`.
  The dashboard shows a yellow DEMO MODE banner. The same `ReviewService` and rules run as in the live system.
- Which statuses `seed` produces for the "vulnerable" sample depends on bandit: installed -> blocked; missing -> rejected after
  a person decides. The expected outcome of each sample is printed by `python scripts/demo.py list`.
- The "sneaky" sample (hidden instruction) only shows its finding with `LLM_ENABLED=true`, because that check lives in the TriageAgent.
- The risk score from file paths alone is capped at 40/100. With the default policy (a person always decides) that does not matter.
  With `APPROVAL_POLICY=auto_below_threshold` a PR that only touches sensitive paths would be auto-approved at the default
  threshold of 70. Lower `RISK_THRESHOLD` (for example 30) if you use that policy.

## Tested and not tested

Tested here: the doctor (every branch, with injected tools, ports and GitHub answers), the offline client, seeding every
state through the real service, a fresh process approving a seeded run, the CLI, and the launcher with real servers
(both start, a signed event is accepted, SIGTERM and SIGHUP stop both with no orphans).
Not tested: macOS specifics (AirPlay port warning is a text check only), a real GitHub token check, Windows,
and the Ctrl+C path from an interactive terminal (the same code path as SIGTERM, but I could not press it here).
