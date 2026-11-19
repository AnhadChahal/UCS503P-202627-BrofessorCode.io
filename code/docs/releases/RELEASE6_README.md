> **History.** This note describes how one stage was added to an earlier copy of the project (it mentions files such as
> `requirements-pipeline.txt` and `.env.pipeline.example`, which are now merged into `requirements.txt` and `.env.example`).
> For the finished project follow the top-level `README.md`.

# Stage 6: two-laptop live demo (see the PR on the server machine)

Laptop A runs Ollama, the webhook, the worker and the dashboard. Laptop B only edits the test repo. On A you watch the PR
being reviewed, with its code and the findings placed on the lines.

## What is new

| Area | Change |
|---|---|
| Dashboard run page | **Changed code**: the PR diff with line numbers; findings and the AI note appear on their line. Stage chips (Scan, Security, … Risk, Deploy) with waiting / working / done / skipped. Auto-refresh while the run is active (`static/live.js`, polls `/runs/<id>/live`). PR title, author, branch and a link to GitHub. |
| Runs page | Active runs show "now: <agent>". |
| `/status` page | Worker heartbeat, queue counts, Ollama reachable, which models are in memory. |
| Store | Tables `pr_files`, `run_steps`, `heartbeat`. Existing databases are upgraded automatically; old runs show "No changed files were stored". |
| Service | Stores the changed files (secrets masked, size capped) and records each agent step as it starts and finishes. Worker writes a heartbeat. |
| Docs | `docs/TWO_LAPTOP_DEMO.md` (setup, sample PRs for laptop B, what to expect, failures). |
| Tests | `tests/test_release6_live.py`, 37 tests. |

Changed files: `pipeline/store.py`, `pipeline/service.py`, `pipeline/llm.py`, `pipeline/status.py` (new), `dashboard/app.py`,
`dashboard/diffview.py` (new), `dashboard/static/live.js` (new), templates `base.html`, `runs.html`, `run.html`, `status.html`.

## Apply

```
unzip -o ~/Downloads/stage6.zip -d /tmp/stage6
cp -R /tmp/stage6/code/. code/
cd code && python -m pytest -q
python scripts/doctor.py
```
Then follow `docs/TWO_LAPTOP_DEMO.md`.

## Limits (say them honestly in the viva)

- The stored diff is masked only for known secret patterns; a secret in an unusual form would be visible to dashboard users.
- The PR description is not stored or shown.
- The dashboard refreshes the whole page when something changes (not partial updates).
- It uses Flask's development server over plain HTTP, bound to the local machine: fine for a demo, not for production.
- Verified with automated tests, fake GitHub and Ollama, and a real browser. Not yet run against real GitHub, ngrok or a real Ollama model:
  do one rehearsal PR before presenting.
