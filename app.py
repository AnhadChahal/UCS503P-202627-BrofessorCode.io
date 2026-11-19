"""A read-the-look preview of the dashboard for hosts that need a Flask entrypoint named `app` (Vercel, v0).

    Vercel / v0 : Root Directory `code`, entrypoint this file (see docs/VERCEL_PREVIEW.md)
    Locally     : flask --app app run        (or: python scripts/demo.py dashboard, which is the same thing)

It is DEMO MODE only: sample pull requests that went through the real agents, an offline GitHub stand-in (nothing is
contacted, nothing is deployed), no real token, no real database. The login is demo / demo-password-123 and is public
on purpose, so do not point this at real data. The real dashboard is scripts/run_dashboard.py and the real webhook is
webhook/app.py (that one is NOT a web page: it only receives GitHub's POST /webhook).

The demo database lives in the system temp folder because hosts like Vercel only allow writing there. Each server
instance has its own copy, so a decision made on one instance may not show on another: fine for looking at a design."""

from __future__ import annotations

import hashlib
import os
import shutil
import tempfile
from pathlib import Path

from dashboard import create_app
from pipeline.auth import hash_password
from pipeline.config import load_settings
from pipeline.demo import DEMO_PASSWORD, DEMO_USER, build_demo, demo_settings, seed

ROOT = Path(__file__).resolve().parent
PREBUILT = ROOT / "demo_data"          # filled at build time by `python scripts/demo.py seed` (docs/VERCEL_PREVIEW.md)
WORK = Path(os.getenv("BROFESSOR_DEMO_DIR") or Path(tempfile.gettempdir()) / "brofessorcode-demo")

# Not a secret: it only signs the cookie of a public demo login. A real deployment must use its own DASHBOARD_SECRET_KEY.
SECRET = os.getenv("DASHBOARD_SECRET_KEY", "")
if len(SECRET) < 16:
    SECRET = hashlib.sha256(b"brofessorcode-public-demo-preview").hexdigest()


def _build():
    if not (WORK / "demo.db").exists():
        WORK.parent.mkdir(parents=True, exist_ok=True)
        if (PREBUILT / "demo.db").exists():
            shutil.copytree(PREBUILT, WORK, dirs_exist_ok=True)       # fast: copy what the build produced
        else:
            WORK.mkdir(parents=True, exist_ok=True)
            seed(demo_settings(load_settings(), WORK), WORK)            # slower: run the sample PRs now
    settings = demo_settings(load_settings(), WORK, SECRET)
    service, _client, store = build_demo(settings, WORK)
    store.set_user(DEMO_USER, hash_password(DEMO_PASSWORD))
    return create_app(service, SECRET, banner="DEMO MODE: sample pull requests, nothing real is contacted or deployed. "
                                              f"Log in as {DEMO_USER} / {DEMO_PASSWORD}")


app = _build()
