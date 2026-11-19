# Designing the dashboard yourself

The dashboard is a small server-rendered site: Flask fills in HTML templates, a stylesheet makes it look like something,
one short script refreshes a running review. There is no build step and nothing to install. You can change **how it
looks and how it is laid out** freely. This page lists the few things the system needs from the pages.

```
dashboard/
  static/style.css      all the styling. Start here.
  static/live.js        reloads a run page while the review is running
  templates/base.html   page frame: <head>, header/nav, flash messages, footer. Every page extends it.
  templates/login.html  runs.html  run.html  status.html
  app.py                routes and the data each template receives (change only if you need new data)
```

Preview all states without GitHub: `python scripts/demo.py seed && python scripts/demo.py dashboard`
(log in as `demo` / `demo-password-123`), then reload the browser after each edit (pages are never cached).
Check the rules at any time: `python -m pytest tests/test_design_contract.py -q`. A failing test names the rule you broke.

## The rules

| # | Rule | Why | Checked by |
|---|---|---|---|
| 1 | Every page links `/static/style.css` (`base.html` does this) | the look | `rule_1` |
| 2 | No inline `<script>` code and no `onclick=`-style attributes. Scripts are files in `static/`. | The Content-Security-Policy blocks inline scripts, silently. | `rule_2` |
| 3 | Load nothing from other websites: no CDN CSS/JS, no Google Fonts, no remote images. Put files in `static/` (for a font use `@font-face` with a file there). | CSP is `default-src 'none'`; remote files would not load. | `rule_3` |
| 4 | Every `<form method="post">` keeps `<input type="hidden" name="csrf" value="{{ csrf_token() }}">` | Without it the server refuses the POST (log-in, approve, reject, block, log-out). | `rule_4` |
| 5 | Logged-in pages keep the log-out form (POST `/logout`) and links to `/` and `/status` | navigation | `rule_5` |
| 6 | Login form: POST `/login`, fields `username`, `password`, `csrf` | log-in | `login_form` |
| 7 | Decision form on the run page: POST `/runs/<id>/decision`, textarea `reason`, buttons `name="action"` with values `approve`, `reject`, `block`; shown only when the template says `can_decide` / `can_block` | the approval | `decision_form*` |
| 8 | While a review runs, the run page has `<div id="live" data-url="..." data-sig="...">` and loads `live.js` (the `{% if live %}` block) | live refresh | `live_hook*` |
| 9 | Show flashed messages (`get_flashed_messages`) | errors such as "commit changed" must be visible | `*_message_is_shown` |
| 10 | Never mark text from a pull request as safe (`\|safe`, `Markup`). Code, titles, finding messages and AI notes all come from outside. | A PR can contain HTML and script; Jinja escapes it unless you turn that off. | `escapes_code` |
| 11 | Keep the run page showing: PR title, file names, the changed code, finding text, rule and severity | what the reviewer decides on | `run_page_shows...` |

Nothing else is required. Rename classes, restructure, replace the tables with cards, add a dark theme: all fine.

## What each template receives

**All pages:** `session.user`, `csrf_token()`, `banner` (demo mode text or none), `url_for()`. Filters: `|ts` (time), `|pretty`
(underscores to spaces), `|sev` (number to CRITICAL/HIGH/...), `|ai_label`, `|fkey`.

**runs.html:** `runs` (list; each has `id repo pr_number title author head_sha status risk_score updated_at`), `status` (active filter or ""),
`statuses` (all status names), `working` (run id → the agent working now).

**run.html:**
- `run` (`id repo pr_number title author head_branch base_branch head_sha html_url status risk_score file_count escalation_reason error deployment`),
  `pr_link` (safe http(s) link or none), `live` (true while queued/running), `sig` (change signature for live.js)
- `steps` (list: `agent state verdict`; `state` is pending/running/done/skipped), `summary` (AI summary or none)
- `files` (list, worst first): `filename status additions deletions count cut no_patch unplaced lines`
  - each `lines` item: `kind` (hunk/add/del/ctx/meta), `old`, `new` (line numbers), `text`, `notes`
  - each note: `sev_name severity tool rule message suggestion ai` (ai: `label reason model`)
- `verdicts` (per agent: `agent status findings notes`), `triage`, `decisions` (`decided_at decision decided_by reason`),
  `audit` (`ts actor event detail`), `factors` (risk factor strings), `can_decide`, `can_block`

**status.html:** `info.worker` (`alive seconds_ago`), `info.queue` (`queued running awaiting working`), `info.settings` (name → value),
`info.ollama` (`enabled reachable url light heavy installed loaded error`).

**login.html:** nothing extra.

## Ideas that need a little backend work (ask for it)

- Updating only the changed part of a run page instead of reloading the whole page (a new endpoint that returns the stage chips).
- A fully separate front end (React or similar) talking to JSON endpoints. The data above would be exposed as JSON and the
  CSRF/session handling adapted. This is a bigger change than restyling and the contract tests would need rewriting.
- A "viewer" role that cannot approve, and a second factor for approvers.

## Safety notes for designers

- The CSP currently allows styles from `'self'` and inline `style=""` attributes; scripts only from `/static/`. If you need something
  else (for example remote fonts), change the policy in `dashboard/app.py` on purpose and tell the contract tests why.
- Do not put the dashboard URL, tokens or secrets in the HTML or in `static/` files: they are served to anyone who can open the page.
