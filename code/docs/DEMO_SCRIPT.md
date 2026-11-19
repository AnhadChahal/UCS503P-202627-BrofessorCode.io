# BrofessorCode: demo script (about 8 minutes)

Two ways to run it. Prepare **both**; use the live one if the network behaves, the offline one if not.

| | Offline demo | Live demo |
|---|---|---|
| Needs | nothing (no GitHub, token, ngrok) | token, ngrok, a test repo, internet |
| What is real | everything except GitHub: the agents, rules, database, dashboard | everything |
| What is simulated | the PR, the PR comment, the commit status, the deployment (written to `demo_data/`) | nothing |

> **Two machines?** See `docs/TWO_LAPTOP_DEMO.md`: laptop A runs everything and shows the PR, laptop B only pushes the PR.

## Before you start (10 minutes earlier)

```
python scripts/doctor.py            # fix every FAIL; read the WARNs
```
Offline: `python scripts/demo.py seed`, then `python scripts/demo.py dashboard` (login `demo` / `demo-password-123`).
Live: `python scripts/start_all.py`, `ngrok http <PORT>`, check that the GitHub webhook URL still matches the
ngrok address (it changes at every ngrok restart on the free plan), and send one test PR the evening before.
Optional AI notes: `ollama serve`, `LLM_ENABLED=true`, run `python scripts/check_llm.py` once so the model is warm.

## The story (say this, then show it)

**1. The problem (30 s).** "A pull request can contain a leaked key, dangerous code or a change to the deploy
pipeline. We built a gate that checks every PR automatically and makes a person decide before anything deploys."

**2. A clean PR (1.5 min).** Offline: `python scripts/demo.py run clean`. Live: open the `clean` PR.
- Show: the PR comment (offline: `demo_data/comments/demo_shop_pr<N>.md`): one table, one row per agent, "Awaiting human approval".
- Say: "ScanAgent runs ruff, SecurityAgent runs bandit and a secret scan, RiskAgent scores the change. No finding,
  and it still waits for a person. That is the default policy, `always_human`."

**3. A secret in a PR (1.5 min).** `python scripts/demo.py run secret`.
- Show: status **blocked**, no one is asked; the finding shows `AKIA****`, never the whole key.
- Say: "A critical finding blocks automatically. It cannot be approved. Secrets are redacted so the report does not leak them."

**4. The decision (2 min).** In the dashboard open the run that is waiting ("risky change"). Point at the risk
factors and the findings. Click **Approve** with a reason.
- Show: status becomes deployed (offline: `demo_data/deploys.log`; live: the GitHub Actions run starts).
- Open the run again and show the **Decisions** table and the **Audit timeline**: who, when, why.
- Say: "The approval is tied to the commit that was reviewed. If the author pushes a new commit first, we ask
  GitHub for the current commit, notice it moved, and refuse. Nothing unreviewed can be deployed."

**5. A new commit (1 min).** Show the "superseded" run in the list. Live: push another commit to a waiting PR.
- Say: "Old reviews are never approvable after a new push; the new commit is reviewed from scratch."

**6. The AI part (1 min, only if Ollama is up).** Open a run with AI notes (`python scripts/demo.py run vulnerable`
with `LLM_ENABLED=true`).
- Show: "AI triage: likely a real problem" next to a finding and the "AI summary".
- Say: "A local model, on this laptop, no code leaves it. It is advisory: it cannot change a verdict, the risk score or
  who decides. Everything it reads is treated as untrusted. Same PR with the LLM off gives the same status and score."

**7. The hidden instruction (30 s, optional).** `python scripts/demo.py run sneaky` (needs `LLM_ENABLED=true`).
- Show: the `reviewer-injection-text` finding. "A comment that tries to talk an AI reviewer into approving is flagged for a human."

## If something breaks

| Problem | Do this |
|---|---|
| ngrok URL changed / GitHub shows red delivery | GitHub repo > Settings > Webhooks > edit the URL > "Redeliver" the last event |
| No internet / token problem | switch to the offline demo; say so, it uses the same code |
| Ollama is slow or not running | skip step 6; the system works without it, and the report says "Ollama is not reachable, skipped" |
| Dashboard login locked | wait 30 min, or `sqlite3 <DB_PATH> "delete from login_attempts"` |
| A run is stuck in "running" | restart `start_all.py`; unfinished runs are re-queued on start |
| Wrong database / empty dashboard | the webhook and dashboard must use the same absolute `DB_PATH` |

## Questions you may get, with short answers

- **Why does it not approve low-risk PRs by itself?** It can (`APPROVAL_POLICY=auto_below_threshold`), but only when no check
  was uncertain and the score is under the threshold. The default is a person, because the score is a heuristic.
  Note: the score from file paths alone is capped at 40/100, so with that policy lower `RISK_THRESHOLD` (for example 30)
  if you want sensitive paths to need a person.
- **What if a tool is not installed or crashes?** It counts as "uncertain" (a person decides), never as a pass.
- **Can the LLM approve something?** No. It has no effect on routing. Its status is only PASS or WARN.
- **Can a malicious PR attack the reviewer?** Its code is not run unless `ALLOW_PR_CODE_EXECUTION=true` (off by default);
  tools run with a reduced environment, timeouts and `ruff --isolated`; archives are extracted without links or path tricks.
- **Where is the history?** SQLite: runs, verdicts, findings, decisions, and an append-only audit log (database triggers refuse edits and deletes).
- **What is not done?** Only Python projects are analysed; one worker handles one run at a time; the dashboard is HTTP on
  localhost for one team; the risk weights are plain rules, not learned; small local models can be wrong.
