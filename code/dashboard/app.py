"""The on-call engineer's dashboard (FR6 to FR12, UC8, UC9).

A small server-rendered Flask app. Run it on the loopback interface only and expose just the
webhook route through the tunnel, because the approve button is the most sensitive control."""

from __future__ import annotations

import datetime
import secrets
from functools import wraps

from flask import Flask, abort, flash, jsonify, redirect, render_template, request, session, url_for

from pipeline.auth import check_login
from pipeline.models import Severity, finding_key
from pipeline.report import TRIAGE_TEXT
from pipeline.status import collect_status
from dashboard.diffview import build_file_views
from pipeline.service import BLOCKABLE, ReviewService
from pipeline.store import ALL_STATUSES


def _signature(run: dict, steps: list[dict]) -> str:
    return run["status"] + "|" + ",".join(f"{x['agent']}:{x['state']}:{x['verdict']}" for x in steps)


def create_app(service: ReviewService, secret_key: str | None = None, banner: str | None = None) -> Flask:
    settings, store = service.settings, service.store
    key = secret_key or settings.dashboard_secret_key
    if not key or len(key) < 16:
        raise RuntimeError("DASHBOARD_SECRET_KEY is not set (use 16 or more random characters).")

    app = Flask(__name__)
    app.config.update(SECRET_KEY=key, SESSION_COOKIE_HTTPONLY=True, SESSION_COOKIE_SAMESITE="Lax",
                      PERMANENT_SESSION_LIFETIME=8 * 3600, MAX_CONTENT_LENGTH=64 * 1024)

    # ---- helpers for the templates ----
    def csrf_token() -> str:
        if "csrf" not in session:
            session["csrf"] = secrets.token_hex(16)
        return session["csrf"]

    app.jinja_env.globals["csrf_token"] = csrf_token
    app.jinja_env.globals["banner"] = banner
    app.jinja_env.filters["ts"] = lambda t: (
        datetime.datetime.fromtimestamp(t, datetime.timezone.utc).strftime("%Y-%m-%d %H:%M UTC") if t else "-")
    app.jinja_env.filters["pretty"] = lambda s: (s or "").replace("_", " ")
    app.jinja_env.filters["sev"] = lambda n: Severity(n).name
    app.jinja_env.filters["fkey"] = lambda f: finding_key(f["agent"], f["rule"], f["file"], f["line"])
    app.jinja_env.filters["ai_label"] = lambda label: TRIAGE_TEXT.get(label, "unsure")

    # ---- protection ----
    @app.before_request
    def protect_posts() -> None:
        if request.method == "POST":
            sent = request.form.get("csrf", "").encode()
            expected = session.get("csrf", "").encode()
            if not sent or not expected or not secrets.compare_digest(sent, expected):
                abort(400)

    @app.after_request
    def headers(resp):
        resp.headers["X-Frame-Options"] = "DENY"
        resp.headers["X-Content-Type-Options"] = "nosniff"
        resp.headers["Cache-Control"] = "no-store"
        resp.headers["Content-Security-Policy"] = ("default-src 'none'; script-src 'self'; connect-src 'self'; "
                                                   "style-src 'unsafe-inline'; form-action 'self'; base-uri 'none'; "
                                                   "frame-ancestors 'none'")
        return resp

    def login_required(view):
        @wraps(view)
        def wrapper(*args, **kwargs):
            if "user" not in session:
                return redirect(url_for("login"))
            return view(*args, **kwargs)
        return wrapper

    # ---- pages ----
    @app.get("/health")
    def health():
        return jsonify(status="ok")

    @app.route("/login", methods=["GET", "POST"])
    def login():
        if request.method == "POST":
            result = check_login(store, settings, request.form.get("username", ""),
                                 request.form.get("password", ""), request.remote_addr or "unknown")
            if result.ok:
                session.clear()
                session["user"] = request.form["username"].strip()
                session.permanent = True
                return redirect(url_for("runs"))
            flash(result.message, "error")
        return render_template("login.html")

    @app.post("/logout")
    def logout():
        session.clear()
        return redirect(url_for("login"))

    @app.get("/")
    @login_required
    def runs():
        status = request.args.get("status", "")
        if status and status not in ALL_STATUSES:
            abort(400)
        runs_ = store.list_runs(status or None)
        working = {}
        for r in runs_:
            if r["status"] == "running":
                step = next((x for x in store.get_steps(r["id"]) if x["state"] == "running"), None)
                working[r["id"]] = step["agent"] if step else "starting"
        return render_template("runs.html", runs=runs_, status=status, statuses=ALL_STATUSES, working=working)

    @app.get("/runs/<int:run_id>")
    @login_required
    def run_detail(run_id: int):
        run = store.get_run(run_id)
        if not run:
            abort(404)
        verdicts = store.get_verdicts(run_id)
        ai = next((v["data"] for v in verdicts if v["agent"] == "TriageAgent"), {})
        triage = ai.get("triage") or {}
        steps = store.get_steps(run_id)
        link = run["html_url"] if run["html_url"].startswith(("https://", "http://")) else None
        return render_template(
            "run.html", run=run, verdicts=verdicts, decisions=store.get_decisions(run_id),
            triage=triage, summary=ai.get("summary"), steps=steps, pr_link=link, sig=_signature(run, steps),
            live=run["status"] in ("queued", "running"),
            files=build_file_views(store.get_files(run_id), [f for v in verdicts for f in v["findings"]], triage),
            audit=store.get_audit(run_id), factors=run["risk_factors"],
            can_decide=run["status"] == "awaiting_approval", can_block=run["status"] in BLOCKABLE)

    @app.get("/runs/<int:run_id>/live")
    @login_required
    def run_live(run_id: int):
        """Tiny JSON for the page's script: it reloads the page when this signature changes."""
        run = store.get_run(run_id)
        if not run:
            abort(404)
        return jsonify(status=run["status"], sig=_signature(run, store.get_steps(run_id)))

    @app.get("/status")
    @login_required
    def status_page():
        return render_template("status.html", info=collect_status(store, settings))

    @app.post("/runs/<int:run_id>/decision")
    @login_required
    def decision(run_id: int):
        result = service.decide(run_id, request.form.get("action", ""), request.form.get("reason", ""),
                                session["user"])
        flash(result.message, "ok" if result.ok else "error")
        return redirect(url_for("run_detail", run_id=run_id))

    return app
