# Remote access with ngrok (dashboard + webhook through one tunnel)

Use this when someone, such as the on-call engineer, must open the dashboard from another laptop, or when you want
the whole system reachable at one HTTPS address. For the simpler "webhook only" demo (dashboard viewed on the server
laptop) you do not need any of this: see `TWO_LAPTOP_DEMO.md`.

```
 GitHub ──POST /webhook──┐                                           ┌─► webhook app  (PORT, e.g. 5001)
                         ├─► ngrok ──► gateway 127.0.0.1:8080 ───────┤
 engineer's browser ─────┘   (HTTPS,   (POST /webhook only → webhook) └─► dashboard    (DASHBOARD_PORT 5002)
                              sign-in)  (everything else → dashboard)
```

Ollama (port 11434) is never tunnelled. Everything listens on 127.0.0.1; only the tunnel agent reaches the gateway.

## What you need

| Component | Why | Notes |
|---|---|---|
| ngrok account + the `ngrok` program on the server laptop | the tunnel | `ngrok config add-authtoken <token>` once |
| Your ngrok domain (e.g. `your-name.ngrok-free.app`) | a fixed address, so the GitHub webhook URL does not change | The free plan gives one dev domain. Find it in the ngrok dashboard under Domains. |
| A Google (or GitHub) account for each person who may open the dashboard | ngrok signs them in before your page is reached | Listed in `NGROK_ALLOWED_EMAILS` |
| `scripts/gateway.py` (new) | one local port for the tunnel, so `/webhook` and the dashboard share one domain | started by `start_all.py --gateway` |
| `scripts/start_tunnel.py` (new), or `start_all.py --tunnel` | writes the ngrok sign-in policy from `.env` and runs ngrok | `--tunnel` runs ngrok as a child with `--log stdout`, so its log lines appear with a `[tunnel]` prefix |
| `TRUST_PROXY=true` and an `https://` `DASHBOARD_URL` | the app then knows it is behind HTTPS and sees the real visitor address | |

## Setup

1. `.env` (in addition to what you already have):
   ```
   TRUST_PROXY=true
   DASHBOARD_URL=https://your-name.ngrok-free.app
   NGROK_URL=your-name.ngrok-free.app
   NGROK_ALLOWED_EMAILS=you@gmail.com,teammate@gmail.com
   NGROK_OAUTH_PROVIDER=google
   ```
   `DASHBOARD_HOST` must stay `127.0.0.1` (the doctor fails if TRUST_PROXY is on and it is not).
2. One command: `python scripts/start_all.py --tunnel`  (webhook + worker + dashboard + gateway + ngrok, one terminal, Ctrl+C stops all).
   Before the first real run, `python scripts/start_tunnel.py --print-only` shows the policy and the exact ngrok command without running anything.
   Prefer two terminals (ngrok's own screen)? Use `start_all.py --gateway` in the first and `python scripts/start_tunnel.py` in the second.
4. GitHub test repo, Settings → Webhooks: **Payload URL** `https://your-name.ngrok-free.app/webhook`, content type
   `application/json`, the same secret as `GITHUB_WEBHOOK_SECRET`, event: Pull requests.
5. On any laptop open `https://your-name.ngrok-free.app/`. You will see, in order: ngrok's warning page (click Visit; on the
   free plan this appears once per browser for a few days), the Google sign-in, then the dashboard log-in page.
   On the server laptop `http://127.0.0.1:5002` still works as before.

## Which lock protects what

| Layer | Protects | Against |
|---|---|---|
| ngrok sign-in (policy) | everything except `POST /webhook` | strangers who find the address |
| Dashboard log-in | all dashboard pages | anyone who passes the first lock without an account |
| Lockout: 3 failures per account and address, 10 per account from all addresses (`LOCKOUT_USER_ATTEMPTS`, 0 = off) | log-in | password guessing, including from changing addresses |
| CSRF token on every POST | approve, reject, block, log-in, log-out | another site making your browser click Approve |
| Approval tied to the reviewed commit | deployment | approving something that was changed after review |
| GitHub HMAC signature | `/webhook` | forged events (a wrong signature gets 401) |
| Gateway | the webhook app | it forwards only `POST /webhook` (not GET, not other paths, bodies over 1 MB are refused) |
| Secure, HttpOnly, SameSite cookie; HSTS; CSP | the browser session | stolen cookies over plain HTTP, injected scripts, embedding in other sites |

## Check it works (from any machine)

```
curl -sI https://your-name.ngrok-free.app/            # must NOT be 200 with the dashboard page: expect ngrok's sign-in or warning
curl -s -X POST https://your-name.ngrok-free.app/webhook -d '{}' -H 'X-Hub-Signature-256: sha256=00'   # expect 401 invalid signature
curl -s -o /dev/null -w "%{http_code}\n" https://your-name.ngrok-free.app/webhook                      # a GET must give 405
```
Then open a test PR and watch it arrive on the dashboard. In GitHub: Webhooks → Recent Deliveries shows the response codes.

## Limits and honest warnings

- **Not run against real ngrok here.** The policy and command follow ngrok's current documentation (agent config, `oauth` and
  `deny` actions, `req.url.path`, `--url`, `--traffic-policy-file`), and everything on this side is tested with a stand-in tunnel. Run
  `start_tunnel.py --print-only` and compare with ngrok's docs; do one rehearsal before presenting. If ngrok rejects the policy it
  prints which line.
- **Free-plan limits change.** ngrok's pages show a small allowance of signed-in users per month for the sign-in feature
  (their pages disagree between 3 and 5). Plan for you plus one or two people, and check your own account.
- **Use Google, not GitHub, for the sign-in** if you can. A GitHub account's e-mail can be private and then never matches the list.
- **The page shows source code** (stored diffs), masked only for known secret patterns. Do not point this at a private
  repository you are not allowed to show to the people on the list.
- **Public address, sensitive page.** Run the tunnel only while you need it, and rotate `DASHBOARD_SECRET_KEY` and the dashboard
  passwords afterwards. If you pass `--no-signin`, only the dashboard's own log-in protects it.
- **TRUST_PROXY** makes the app believe `X-Forwarded-*` headers. It is only safe because the dashboard listens on 127.0.0.1 and the
  only thing in front of it is the gateway and tunnel on the same machine. Never turn it on if the dashboard can be reached directly.
- The dashboard still runs on Flask's development server. That is acceptable for a demo with a few people; it is not production.
- Sessions last 8 hours. There is no second factor and no separate "viewer" role yet: anyone with a dashboard account can approve.

## If something is wrong

| Symptom | Cause / fix |
|---|---|
| `start_tunnel.py`: "NGROK_ALLOWED_EMAILS is empty" | set it in `.env`, or pass `--no-signin` knowing the risk |
| ngrok: authentication failed | `ngrok config add-authtoken <token>` |
| GitHub deliveries show 403 or an HTML page | the sign-in policy is catching `/webhook`: the path must be exactly `/webhook` (no trailing slash) |
| GitHub deliveries show 502 | the webhook is not running, or `PORT` differs from the one the gateway forwards to |
| Dashboard works but log-in loops back to the form | cookie not stored: check that `TRUST_PROXY=true` and you use the https address |
| "Too many failed attempts" for a real user | 10 failures for the account from all addresses, or 3 from one; wait `LOCKOUT_MINUTES` |
| Doctor: "TRUST_PROXY is false" warning | set `TRUST_PROXY=true` when `DASHBOARD_URL` is https |
| Links in PR comments point to 127.0.0.1 | `DASHBOARD_URL` is not the https address |
