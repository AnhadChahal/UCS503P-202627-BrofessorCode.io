# Two-laptop live demo

```
 Laptop B (author)                    GitHub                    Laptop A (server, the one you present from)
 ─────────────────                    ──────                    ───────────────────────────────────────────
 edit test repo, push, open PR  ───►  PR event  ──webhook──►   ngrok ─► webhook + worker (port 5001)
                                                                        │ downloads the PR, runs the agents,
                                                                        │ asks Ollama (same machine)
                                       ◄── PR comment, status ──────────┘
                                                                  browser ─► dashboard http://127.0.0.1:5002
                                                                            (the PR, its code, the findings, live progress)
```

Only the webhook goes through ngrok. The dashboard and Ollama never leave laptop A, so the Approve button is not
exposed to the internet. Laptop B needs nothing installed except git and a browser.

## Laptop A: one-time setup

1. Unpack, then from the project root (`code/`): `python -m venv venv && source venv/bin/activate && pip install -r requirements-pipeline.txt`
   (it installs flask, ruff, bandit and pip-audit; bandit is needed for a live BLOCK).
2. `.env` in the project root:
   ```
   GITHUB_WEBHOOK_SECRET=<python -c "import secrets; print(secrets.token_hex(32))">
   GITHUB_TOKEN=<fine-grained token, test repo only>
   PORT=5001
   DASHBOARD_PORT=5002
   DASHBOARD_URL=http://127.0.0.1:5002
   DASHBOARD_SECRET_KEY=<another random value>
   LLM_ENABLED=true
   LLM_MODEL=<a small model you have pulled>
   LLM_HEAVY_MODEL=<optional, a bigger one>
   ```
3. Dashboard login: `python scripts/create_user.py <name>`
4. Ollama: `ollama serve` (the app only talks to the loopback address) and `python scripts/check_llm.py` once so the model is loaded before you present.
5. `python scripts/doctor.py` should show no FAIL.

## Laptop A: every time

| Terminal | Command |
|---|---|
| 1 | `python scripts/start_all.py` |
| 2 | `ngrok http 5001` and copy the `https://…` address |
| 3 (optional) | `ollama serve` if it is not already running |

GitHub test repo → Settings → Webhooks: **Payload URL** `https://<ngrok address>/webhook`, content type
`application/json`, the same secret, events: **Pull requests** only. The free ngrok address changes every restart, so
**update the webhook URL each time** (Recent Deliveries → Redeliver also lets you replay an event).

Open `http://127.0.0.1:5002`, log in, keep two tabs: **Runs** and **Status**. The Status page must say: review worker
running, AI triage on, Ollama reachable.

## Laptop B: make a PR

```
git clone https://github.com/<you>/<test-repo>.git && cd <test-repo>
git checkout -b demo-1
```
Edit or add one of the files below, then:
```
git add -A && git commit -m "Add feature" && git push -u origin demo-1
```
Open the PR on github.com (base branch must match `BASE_BRANCH`, default `main`).

### Sample changes

**Clean** (`app/greet.py`)
```python
def greet(name: str) -> str:
    return f"Hello, {name}!"
```
Expect: no findings, status **awaiting approval** (the default policy always asks a person).

**Vulnerable** (`app/run.py`)
```python
import subprocess

def run(cmd):
    return subprocess.call(cmd, shell=True)
```
Expect with bandit installed: **blocked** (CRITICAL, shell injection) and nobody is asked. Without bandit: awaiting approval.

**Hard-coded password** (`app/settings.py`)
```python
DB_PASSWORD = "hunter2-hunter2"
```
Expect: a MEDIUM finding, redacted, **awaiting approval**. (A real-looking cloud key can be refused by GitHub's own push
protection before it ever reaches the webhook, so use this form.)

**Risky path** (`.github/workflows/deploy.yml`, change any line)
Expect: higher risk score with "CI/CD workflow" as a factor, awaiting approval.

## What to show on laptop A

1. Push the PR on B. On A, **Runs** shows the new run with "now: ScanAgent…" within a few seconds.
2. Open the run: stage chips go waiting → working → done, the **Changed code** section is already visible, and the page
   refreshes itself.
3. When finished: findings sit on their lines inside the diff, each with the AI note (likely real / false positive / unsure) and the
   model that wrote it. The PR comment on GitHub shows the same table.
4. Click **Approve** (or Reject) with a reason. Show the **Decisions** table and the audit timeline.
5. **Superseded:** on B push a second commit to the same branch **before** approving. The old run becomes *superseded*, a new
   run starts, and approving the old one is refused. This is the "approval is tied to the reviewed commit" point.
6. **Status** page: which model is loaded in memory right now, and the worker heartbeat.

## Things that can go wrong

| Symptom | Likely cause |
|---|---|
| Nothing appears on A after a push | Webhook URL is the old ngrok address; check Settings → Webhooks → Recent Deliveries (red X = not delivered, 401 = secret mismatch, 202 `ignored` = wrong event or base branch). |
| Run stays "queued" | Worker not running: Status page shows it. Start with `start_all.py`, not just the webhook. |
| No AI notes | `LLM_ENABLED` not true, Ollama not running, or model not pulled. Status page says which. The gate still works without it. |
| Vulnerable sample is not blocked | bandit not installed on A (`doctor.py` warns). |
| Approve says "commit changed" | Correct: the PR head moved after review. Open the newer run. |
| Dashboard needs a refresh | It reloads itself when the run changes; if it does not, check the browser console for a blocked script (the CSP allows only the app's own `live.js`). |
