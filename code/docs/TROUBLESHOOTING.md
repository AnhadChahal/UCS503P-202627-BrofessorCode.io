# Troubleshooting

First step for almost everything: `python scripts/doctor.py` (add `--repo OWNER/REPO` to test the token against GitHub).
Run all commands from the project root (the folder that contains `webhook/`, `pipeline/`, `dashboard/`, `scripts/`).

## Starting up

| Symptom | Cause | Fix |
|---|---|---|
| `ModuleNotFoundError: No module named 'flask'` | packages not installed in this venv | `pip install -r requirements.txt -r requirements-pipeline.txt` |
| `No module named 'webhook'` when running `webhook/app.py` | started as a file | `python -m webhook.app` from the project root |
| `GITHUB_WEBHOOK_SECRET is not set` | no `.env`, or it is in another folder | create `.env` in the project root |
| `ImportError: cannot import name 'run_pipeline' from 'webhook.pipeline'` | old `webhook/app.py` with a changed `webhook/pipeline.py` | use the new `webhook/app.py` (it no longer imports that file) |
| `cannot import name 'DeployAgent'` or `No module named 'tests.service_helpers'` | the new files were only partly copied | copy the whole stage folder over `code/`, not single files |
| `unable to open database file` | folder in `DB_PATH` missing, or `~` used | absolute path to an existing folder |
| `DASHBOARD_SECRET_KEY is not set` | missing or shorter than 16 chars | `python -c "import secrets; print(secrets.token_hex(32))"` into `.env` |
| `Address already in use` / 403 from the tunnel on a Mac | port 5000 is taken by AirPlay Receiver | `PORT=5001` in `.env` and `ngrok http 5001` |
| Dashboard shows no runs | webhook and dashboard use different databases | same absolute `DB_PATH` in `.env`; start both from the project root |

## GitHub side

| Symptom | Cause | Fix |
|---|---|---|
| Delivery shows 401 | secret differs between `.env` and the GitHub webhook | make them identical, restart, redeliver |
| Delivery shows 415 | webhook content type is not JSON | set Content type to `application/json` |
| Delivery shows 404 / "failed to connect" | ngrok URL changed or ngrok stopped | copy the new `https://....ngrok...` + `/webhook` into the webhook settings |
| Delivery shows 202 but no comment appears | PR is not into `BASE_BRANCH`, action ignored, or the run failed | check the run in the dashboard and the webhook terminal |
| Run status `failed`, error `GitHubError ... 401` | token invalid or expired | new token (see the README) |
| `... 403` or `... 404` | token lacks a permission or the repository | needs Pull requests R/W, Contents R, Commit statuses R/W, and the repo selected |
| Approve says "Could not check the PR's current commit" | GitHub unreachable or token cannot read the PR | fix the token; nothing was changed (it fails closed) |
| Approve works but status `failed`, "deployment could not be started" | workflow missing, no `workflow_dispatch`, wrong ref, or token lacks Actions R/W | the workflow file must be on the default branch with `on: workflow_dispatch:` |
| Comment shows "bandit: not installed" | tool missing | `pip install bandit pip-audit ruff`; until then runs go to a person |

## Dashboard

| Symptom | Fix |
|---|---|
| Forgot password | `python scripts/create_user.py <name>` again (it replaces the password) |
| "Too many failed attempts" | wait 30 minutes, or `sqlite3 <DB_PATH> "delete from login_attempts"` |
| 400 after clicking a button | the page was open too long or cookies are blocked; reload and try again |
| Run stuck in `running` | restart the webhook process; unfinished runs are re-queued |

## Ollama (only with `LLM_ENABLED=true`)

| Symptom | Fix |
|---|---|
| "Ollama is not reachable, skipped" | `ollama serve` (or open the Ollama app); `python scripts/check_llm.py` |
| "model ... is not installed" | `ollama pull <model>` |
| "refusing to send code to ..." | `OLLAMA_URL` must be local; `LLM_ALLOW_REMOTE=true` only if you really mean it |
| Every finding is "unsure" | the model is not returning valid JSON; try a larger or better coder model; the run is unaffected |
| Slow runs | the worker handles one run at a time; use the light model, lower `LLM_MAX_FINDINGS`, or `LLM_SUMMARY=false` |
| Out of memory | leave `LLM_HEAVY_MODEL` empty; a 30B model needs roughly 20 GB free |

## Tests

| Symptom | Fix |
|---|---|
| `error collecting tests/test_webhook.py` | you are not in the project root, or `webhook/` is missing from it |
| Tests pass here but a tool-dependent run differs | the status of runs with `bandit` installed can differ from runs without it (missing tools go to a person); the automatic tests do not depend on installed tools |
