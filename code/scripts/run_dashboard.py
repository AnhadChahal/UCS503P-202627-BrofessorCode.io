"""Start the dashboard on the loopback interface.

    python scripts/run_dashboard.py

Needs DASHBOARD_SECRET_KEY in .env. Generate one with:
    python -c "import secrets; print(secrets.token_hex(32))"
"""

from __future__ import annotations

import argparse
import logging
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from dashboard import create_app  # noqa: E402
from pipeline.config import load_settings  # noqa: E402
from pipeline.service import ReviewService  # noqa: E402
from pipeline.store import Store  # noqa: E402


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--allow-remote", action="store_true",
                        help="listen on a non-loopback address (only behind HTTPS and a firewall)")
    args = parser.parse_args()
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)-7s %(name)s: %(message)s")
    settings = load_settings()
    if settings.dashboard_host not in ("127.0.0.1", "localhost", "::1") and not args.allow_remote:
        sys.exit("Refusing to listen on a non-loopback address. Use --allow-remote if you really mean it.")
    if not settings.dashboard_secret_key:
        sys.exit("DASHBOARD_SECRET_KEY is not set. See the docstring of this script.")
    app = create_app(ReviewService(Store(settings.db_path), settings))
    print(f"Dashboard on http://{settings.dashboard_host}:{settings.dashboard_port}")
    app.run(host=settings.dashboard_host, port=settings.dashboard_port, debug=False)


if __name__ == "__main__":
    main()
