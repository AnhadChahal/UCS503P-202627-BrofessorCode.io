"""Run the one-port front door for the tunnel:  python scripts/gateway.py

Listens on 127.0.0.1:GATEWAY_PORT (default 8080). POST /webhook goes to the webhook (PORT), everything else to the
dashboard (DASHBOARD_PORT). Point the tunnel at the gateway port:  see docs/NGROK_REMOTE.md.
"""

from __future__ import annotations

import logging
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from pipeline.config import load_settings  # noqa: E402
from pipeline.gateway import Gateway  # noqa: E402


def main() -> int:
    logging.basicConfig(level=logging.INFO, format="%(asctime)s gateway %(message)s", datefmt="%H:%M:%S")
    s = load_settings()
    server = Gateway(("127.0.0.1", s.gateway_port), ("127.0.0.1", s.webhook_port), ("127.0.0.1", s.dashboard_port))
    print(f"Gateway on http://127.0.0.1:{s.gateway_port}   POST /webhook -> :{s.webhook_port}   everything else -> :{s.dashboard_port}",
          flush=True)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nGateway stopped.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
