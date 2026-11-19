# BrofessorCode

A self-hosted **pull-request safety gate**. When someone opens a pull request, a set of agents checks it automatically
(lint, security scan, secret scan, risk score, optional local-LLM notes) and **a person must decide** before anything
deploys. It runs on your own machine: no cloud platform, local open-weight models through Ollama, SQLite for state.

UCS503P Software Engineering project, CSED, Thapar Institute of Engineering and Technology. Team C-137, Group 3Q22.
Derived from the DeployGuard design.

## How it works

```
GitHub PR event ──► webhook (signature check, filters) ──► queue ──► review worker
                                                                        │ ScanAgent      ruff, dependency audit
                                                                        │ SecurityAgent  bandit, secret scan (semgrep optional)
                                                                        │ TriageAgent    local LLM notes, advisory only (optional)
                                                                        │ RiskAgent      score 0-100 from paths, size, findings
                                                                        ▼
                                  PR comment + commit status  ◄──  SQLite  ──►  dashboard: see the code, findings, live progress
                                                                                  a person approves or rejects ──► DeployAgent
```

Design rules that the code and tests enforce:
- Agents are plain classes that return a verdict; they never call each other or write to the database. Only the service does.
- **Fail closed:** a crashed or uncertain check sends the run to a person; it is never treated as a pass.
- An approval is tied to the **reviewed commit**. If the PR head moved, the approval is refused and the run is marked superseded.
- A critical finding blocks the run automatically. Undecided runs expire and are never auto-approved.
- The LLM is advisory: it can add notes, never change a verdict or a routing decision. Only a local Ollama address is allowed.
- The audit log is append-only (database triggers).

## Folder map (everything is in `code/`)

| Path | What |
|---|---|
| `webhook/` | Flask receiver for GitHub events (`python -m webhook.app`) |
| `pipeline/` | agents, orchestrator, service and worker, SQLite store, GitHub client, LLM client, risk rules, report, demo mode, doctor, gateway, tunnel helper |
| `dashboard/` | the approval dashboard (Flask templates, `static/style.css`, `static/live.js`) |
| `scripts/` | `start_all.py`, `doctor.py`, `create_user.py`, `demo.py`, `check_llm.py`, `gateway.py`, `start_tunnel.py`, `send_test_event.py` |
| `tests/` | the automatic tests (302) |
| `docs/` | `DEMO_SCRIPT.md`, `TWO_LAPTOP_DEMO.md`, `NGROK_REMOTE.md`, `DESIGN_CONTRACT.md`, `TROUBLESHOOTING.md`, `releases/` (history of each stage) |

## Set up

Python 3.10 or newer. From the `code/` folder:

```
python -m venv venv
source venv/bin/activate            # Windows: venv\Scripts\activate
pip install -r requirements.txt
cp .env.example .env                # then fill in .env: the two secrets, GITHUB_TOKEN, and an absolute DB_PATH
python scripts/create_user.py <name>      # the dashboard log-in
python scripts/doctor.py                  # fix every FAIL line
python -m pytest -q                       # expect 302 passed
```

Run everything from `code/`. Start the webhook as a module (`python -m webhook.app`), not as a file path.
On a Mac use `PORT=5001`: AirPlay already uses port 5000.

## Try it without GitHub (offline demo)

```
python scripts/demo.py seed
python scripts/demo.py dashboard          # log in as demo / demo-password-123
```
Five sample pull requests run through the real agents and the real dashboard; only GitHub is simulated.

## Run it for real

```
python scripts/start_all.py               # webhook + worker + dashboard
ngrok http 5001                           # in another terminal: GitHub needs a public address for the webhook
```
GitHub test repo, Settings, Webhooks: Payload URL `https://<ngrok address>/webhook`, content type `application/json`,
the same secret as `GITHUB_WEBHOOK_SECRET`, events: **Pull requests** only. Open a pull request into `main`
(a push alone does nothing), then open `http://127.0.0.1:5002`.

More: two-laptop demo `docs/TWO_LAPTOP_DEMO.md`, dashboard through one ngrok tunnel `docs/NGROK_REMOTE.md`
(`python scripts/start_all.py --tunnel`), restyling the page `docs/DESIGN_CONTRACT.md`, problems `docs/TROUBLESHOOTING.md`.

## Security notes

- Never commit `.env`, the database or `payloads/` (the `.gitignore` already excludes them). If a secret reaches GitHub, replace it.
- The dashboard binds to `127.0.0.1`. Only the webhook route (or the gateway with a sign-in in front) is meant to be public.
- Stored diffs are masked only for known secret patterns. The PR description is not stored.
- The dashboard runs on Flask's development server over HTTP locally; there is no second factor and no read-only role yet.
- Tested with automated tests, fake GitHub and Ollama, and a real browser. The real ngrok tunnel and a real GitHub and Ollama
  end-to-end run need a rehearsal on your own machine.
