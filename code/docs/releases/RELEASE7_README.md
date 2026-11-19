> **History.** This note describes how one stage was added to an earlier copy of the project (it mentions files such as
> `requirements-pipeline.txt` and `.env.pipeline.example`, which are now merged into `requirements.txt` and `.env.example`).
> For the finished project follow the top-level `README.md`.

# Stage 7: remote access through ngrok, and a dashboard you can restyle

Two things: (1) the dashboard and the webhook can be reached through one ngrok address, with a sign-in in front of
the dashboard; (2) the page is organised so you can design it yourself without breaking what the system needs.

## What is new

| Area | Change |
|---|---|
| `pipeline/gateway.py`, `scripts/gateway.py` | One-port front door for the tunnel: `POST /webhook` goes to the webhook, everything else to the dashboard. Refuses other methods on `/webhook`, bodies over 1 MB and chunked bodies; never follows redirects; logs method, path and status only. |
| `pipeline/tunnel.py`, `scripts/start_tunnel.py` | Builds the ngrok sign-in policy from `.env` (only listed e-mail addresses; `/webhook` exempt) and runs `ngrok http <gateway port> --url ... --traffic-policy-file ...`. Refuses to start without allowed e-mails unless `--no-signin`. Inputs are validated so a typo cannot alter the policy. |
| `dashboard/app.py` | `TRUST_PROXY` (believe one proxy hop's forwarded headers); session cookie `Secure` whenever the request came over https, so local http and remote https both work; HSTS on https; `Referrer-Policy`, `X-Robots-Tag`; CSP now allows styles from the site itself. |
| Login lockout | In addition to 3 failures per account and address, 10 failures per account from **all** addresses (`LOCKOUT_USER_ATTEMPTS`, 0 = off). Behind a tunnel an attacker could otherwise change address between guesses. |
| `scripts/start_all.py --gateway` / `--tunnel` | `--gateway` also starts the gateway. `--tunnel` (implies it) also starts ngrok as a child process with `--log stdout`, after checking the e-mail list and that `ngrok` is installed; Ctrl+C or `kill` stops everything. Tested with a fake `ngrok` program, not the real one. |
| `pipeline/doctor.py` | New checks: TRUST_PROXY with a reachable dashboard (FAIL), https URL without TRUST_PROXY, public URL without allowed e-mails. |
| `dashboard/static/style.css` (new) | All CSS moved out of `base.html`; inline `style=""` attributes replaced by classes. |
| `docs/NGROK_REMOTE.md` | Components, setup, layers of protection, checks, limits, troubleshooting. |
| `docs/DESIGN_CONTRACT.md` | Where to restyle, the 11 rules, and the data each template receives. |
| `tests/test_design_contract.py` | 17 tests that fail if a redesign breaks log-in, CSRF, approve/reject, live refresh, the CSP or HTML escaping. Checked by breaking each rule on purpose. |
| `tests/test_release7_remote.py` | 50 tests: lockout across addresses, proxy trust, cookies and HSTS, the gateway against real local servers, tunnel policy and command, the launcher script, `start_all --tunnel` with a fake ngrok, doctor and config. |

New settings: `TRUST_PROXY`, `LOCKOUT_USER_ATTEMPTS`, `GATEWAY_PORT` (default 8080), and for the launcher
`NGROK_ALLOWED_EMAILS`, `NGROK_OAUTH_PROVIDER`, `NGROK_URL`.

## Apply

```
unzip -o ~/Downloads/stage7.zip -d /tmp/stage7
cp -R /tmp/stage7/code/. code/
cd code && python -m pytest -q          # expect 302 passed (with your webhook folder in place)
python scripts/doctor.py
```
Then `docs/NGROK_REMOTE.md` for the tunnel and `docs/DESIGN_CONTRACT.md` to start restyling.

## Verified, and not verified

- Verified: the full test suite (with your webhook folder); the real webhook, dashboard and gateway running together
  (signed POST accepted, bad signature 401, GET /webhook 405, dashboard served, real visitor address recorded from
  `X-Forwarded-For`); a real browser through the gateway with https headers (Secure cookie, HSTS, stylesheet loads under the CSP,
  no console errors); the policy parses as YAML with the intended rules; the contract tests catch seven deliberate breakages.
- **Not verified: real ngrok.** There is no network here, so the policy and flags follow ngrok's documentation but have not
  been run. Run `python scripts/start_tunnel.py --print-only`, then do one rehearsal. ngrok's free-plan limits change.
- Still true: the dashboard runs on Flask's development server; no second factor; no separate viewer/approver role; stored diffs
  are masked only for known secret patterns.
