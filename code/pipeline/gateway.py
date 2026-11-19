"""One local front door for the tunnel.

The tunnel (ngrok) can point at only one local port on the free plan, but we have two programs: the webhook
(GitHub posts to it) and the dashboard (people use it). The gateway listens on one loopback port and sends

    POST /webhook   -> the webhook app          (protected by GitHub's HMAC signature, no log-in possible)
    anything else   -> the dashboard            (protected by the tunnel's sign-in AND the dashboard's own log-in)

Nothing else of the webhook app is reachable, and a GET on /webhook is refused. It is a plain forwarder: it
does not read or change bodies, it forwards a request only after checking method, path and size, it never follows
redirects, and it logs the method, the path (no query string) and the status, never headers or bodies.
"""

from __future__ import annotations

import http.client
import logging
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

log = logging.getLogger("pipeline.gateway")

WEBHOOK_PATH = "/webhook"
MAX_BODY = 1_000_000          # bytes; a pull-request event is a few KB. The dashboard accepts far less.
HOP_BY_HOP = {"connection", "keep-alive", "proxy-authenticate", "proxy-authorization", "te", "trailer",
              "trailers", "transfer-encoding", "upgrade", "proxy-connection"}
SKIP_FROM_UPSTREAM = HOP_BY_HOP | {"content-length", "server", "date"}


def route(method: str, target: str) -> tuple[str | None, int]:
    """Decide where a request goes. Returns ("webhook" | "dashboard", 0) or (None, refusal status)."""
    if not target.startswith("/") or target.startswith("//"):
        return None, 400
    path = target.split("?", 1)[0].split("#", 1)[0]
    if path == WEBHOOK_PATH:
        return ("webhook", 0) if method == "POST" else (None, 405)
    return "dashboard", 0


class _Handler(BaseHTTPRequestHandler):
    server_version = "BrofessorGateway"
    sys_version = ""
    protocol_version = "HTTP/1.0"          # one request per connection: simple and safe for a forwarder

    def log_message(self, fmt, *args):  # noqa: ANN001, D401
        pass                                # we log in _finish, without the query string

    def _finish(self, status: int, path: str) -> None:
        log.info("%s %s -> %s", self.command, path.split("?", 1)[0], status)

    def _refuse(self, status: int, text: str) -> None:
        body = (text + "\n").encode()
        self.send_response(status)
        if status == 405:
            self.send_header("Allow", "POST")
        self.send_header("Content-Type", "text/plain; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(body)
        self._finish(status, self.path)

    def _handle(self) -> None:
        where, refusal = route(self.command, self.path)
        if where is None:
            return self._refuse(refusal, {400: "Bad request", 405: "Method not allowed"}[refusal])
        if "transfer-encoding" in {k.lower() for k in self.headers.keys()}:
            return self._refuse(411, "Length required")       # we forward only bodies with a known length
        try:
            length = int(self.headers.get("Content-Length") or 0)
        except ValueError:
            return self._refuse(400, "Bad request")
        if length < 0:
            return self._refuse(400, "Bad request")
        if length > MAX_BODY:
            return self._refuse(413, "Request too large")
        body = self.rfile.read(length) if length else None

        host, port = self.server.upstreams[where]            # type: ignore[attr-defined]
        headers = {k: v for k, v in self.headers.items() if k.lower() not in HOP_BY_HOP | {"content-length"}}
        if body is not None:
            headers["Content-Length"] = str(len(body))
        conn = http.client.HTTPConnection(host, port, timeout=self.server.timeout_s)  # type: ignore[attr-defined]
        try:
            conn.request(self.command, self.path, body=body, headers=headers)
            resp = conn.getresponse()
            data = resp.read()
        except (OSError, http.client.HTTPException):
            conn.close()
            return self._refuse(502, f"The {where} is not reachable")
        conn.close()

        self.send_response(resp.status, resp.reason)
        for key, value in resp.getheaders():                  # getheaders keeps repeated headers (Set-Cookie)
            if key.lower() not in SKIP_FROM_UPSTREAM:
                self.send_header(key, value)
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(data)
        self._finish(resp.status, self.path)

    do_GET = do_POST = do_PUT = do_DELETE = do_PATCH = do_OPTIONS = do_HEAD = _handle


class Gateway(ThreadingHTTPServer):
    daemon_threads = True

    def __init__(self, listen: tuple[str, int], webhook: tuple[str, int], dashboard: tuple[str, int],
                 timeout_s: float = 30.0):
        super().__init__(listen, _Handler)
        self.upstreams = {"webhook": webhook, "dashboard": dashboard}
        self.timeout_s = timeout_s
