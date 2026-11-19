> **History.** This note describes how one stage was added to an earlier copy of the project (it mentions files such as
> `requirements-pipeline.txt` and `.env.pipeline.example`, which are now merged into `requirements.txt` and `.env.example`).
> For the finished project follow the top-level `README.md`.

# Release 2: database, risk score, approval and dashboard

Release 1 ended with a comment on the PR. Release 2 adds everything that makes the
system a **gate**: results are stored, a RiskAgent scores the change, a person approves or
rejects it on a dashboard, and only an approved, unchanged commit can trigger a deployment.
It covers FR2, FR4, FR6 to FR12, FR27-FR35 (except the LLM parts, see "Not in this release"),
UC8/UC9 and QR16.

## What happens to one PR

```
webhook (202 fast) -> worker.submit(pr, delivery_id)
  Store.create_run()       duplicate delivery or commit -> ignored; older unfinished runs of
                           this PR -> superseded
worker thread: service.process(run_id)
  status: pending          queued -> running
  ScanAgent, SecurityAgent (stop on BLOCK), then RiskAgent      every verdict saved in SQLite
  route (plain code, no LLM):
     any BLOCK                              -> blocked           (no one is asked)
     check uncertain / crashed, risk above threshold,
       or policy = always_human             -> awaiting_approval (status: pending)
     otherwise (policy = auto_below_threshold) -> approved by "policy"
  comment + commit status updated from the STORED run

dashboard (on-call engineer): service.decide(run_id, action, reason, user)
  approve / reject      only from awaiting_approval; asks GitHub for the PR's current head
                        commit first. If it moved: run -> superseded, nothing is deployed.
                        If GitHub cannot be reached: nothing changes (fail closed).
  block                 also allowed on an already approved run (records it, stops any later step)
  approve -> DeployAgent -> workflow_dispatch -> deployed | failed
  decision + status change are ONE database transaction, so a double click or an expiry that
  races a click cannot produce two outcomes

housekeeping: runs waiting longer than APPROVAL_TIMEOUT_HOURS -> expired (never approved);
              after a restart, queued/running runs are put back in the queue
```

Rules that never change: agents never call each other or the database; only `service.py`
writes state; a crashed or uncertain check is "needs a person", never a pass; an approval is
stored with the commit SHA that was reviewed; the audit log is append-only (SQLite triggers).

## Files (copy into your repo's `code/` folder, next to Release 1)

```
pipeline/store.py          SQLite: runs, verdicts, findings, decisions, audit log, users, log-in attempts
pipeline/service.py        ReviewService (process, decide, expire_stale, recover), Worker, build_runtime()
pipeline/auth.py           scrypt password hashes, log-in check with lockout
pipeline/agents/risk_agent.py     0-100 score from path patterns, size, findings, uncertainty
pipeline/agents/deploy_agent.py   dispatches the deploy workflow, only with a matching approval
pipeline/report.py         (changed) report built from stored data, safe against @mentions and HTML
pipeline/config.py, models.py, github_client.py   (changed) new settings and GitHub calls
dashboard/                 Flask app + 4 templates (login, run list, run detail)
scripts/create_user.py     create the on-call engineer's account
scripts/run_dashboard.py   start the dashboard (refuses non-loopback unless --allow-remote)
tests/                     126 tests in total: 61 from Release 1, 65 new
RELEASE2_README.md, .env.pipeline.example (replaces the old one), requirements-pipeline.txt
```

## Set up

```bash
cd code
pip install -r requirements-pipeline.txt
```

1. Copy the new lines of `.env.pipeline.example` into your `.env`. Set `DB_PATH` to an
   **absolute** path and `DASHBOARD_SECRET_KEY` to a random value.
2. Token: add **Actions: Read and write** (needed only for deployment). The full set is
   Pull requests R/W, Contents R, Commit statuses R/W, Actions R/W.
3. Create the engineer's account: `python scripts/create_user.py alice` (10+ characters).
4. Start the dashboard: `python scripts/run_dashboard.py` and open http://127.0.0.1:5002.
   Do not expose this port through ngrok; only the webhook route goes through the tunnel.

## Connect it to the webhook (FastAPI version)

Replace the Release 1 queue and `run_pipeline` call by the worker from `build_runtime()`.
It keeps the queue in memory but the runs in SQLite, so a restart loses nothing.

```python
from contextlib import asynccontextmanager
from pipeline.service import build_runtime

service, worker = build_runtime()

@asynccontextmanager
async def lifespan(app: FastAPI):
    worker.start()          # re-queues unfinished runs, starts the worker and the expiry timer
    yield
    worker.stop()

app = FastAPI(lifespan=lifespan)

# in github_webhook(), where you used jobs.put(pr):
#     delivery = request.headers.get("X-GitHub-Delivery")
#     sub = worker.submit(payload, delivery)      # the raw payload dict is accepted
#     return {"queued": sub.run_id is not None, "run": sub.run_id, "note": sub.reason}   # keep 202
```

(Flask version: call `worker.submit(payload, delivery_id)` in `github_webhook()` and delete the
old thread, queue and `webhook/pipeline.py`.)
The webhook process and the dashboard are two processes; they share only the SQLite file.

## Deploying (optional)

Set `DEPLOY_WORKFLOW=deploy.yml`. That workflow must be on the repository's default branch
and have `on: workflow_dispatch:`. With `DEPLOY_PASS_INPUTS=true` it receives `sha` and `pr` as
inputs and must declare them. With no workflow set, "approve" only records the decision.

## Try it

```bash
python -m pytest -q                       # 126 tests, no network needed
```
Then open a PR in your test repo. Expected: comment "Awaiting human approval", commit status
pending; log in, open the run, click Approve; comment and status change to approved.
Push a second commit to the PR before approving: the first run becomes "superseded".

## What was and was not tested

Tested here (automatically): store rules, atomic decisions, append-only audit log, log-in
lockout, risk scoring, deploy refusals, the whole run lifecycle against a fake GitHub
(routing, approve, reject, block, supersede, expiry, restart recovery, crashing agents,
unreachable GitHub), the worker, and the dashboard (log-in, CSRF, escaping, headers).
Also run once end-to-end with the real `ruff` on a sample file.

**Not tested** against the real thing: GitHub's API (comments, statuses, workflow dispatch),
`bandit`, `pip-audit`, `semgrep` (not installed in the build sandbox; the report then shows
"not installed" and the run goes to a person, which is the intended behaviour), and a browser.
Run it once on your machine with a test repo before the demo.

## Not in this release

- LLM triage and summaries (FR27, Ollama). Everything above is deterministic on purpose.
- A form to change risk weights, multi-user roles, HTTPS for the dashboard.
- A syntax error found by ruff is reported as LOW, as in Release 1.
