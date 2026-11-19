import http.client
import json
import logging
import os
import re
import subprocess
import sys
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

from dashboard import create_app
from pipeline.auth import check_login, hash_password
from pipeline.config import load_settings
from pipeline.doctor import run_checks
from pipeline.gateway import MAX_BODY, Gateway, route
from pipeline.tunnel import build_command, build_policy, parse_emails, parse_url, plan_from_env
from tests.pipeline_helpers import make_settings
from tests.service_helpers import make_pr, make_service, make_store
from tests.test_pipeline_orchestrator import StubAgent

ROOT = Path(__file__).resolve().parents[1]
FAST = dict(n=2 ** 4)


class Clock:
    def __init__(self, now=10_000.0):
        self.now = now

    def __call__(self):
        return self.now


# ---------------------------------------------------------------- lockout across addresses
class UserWideLockoutTests(unittest.TestCase):
    def setUp(self):
        self.clock = Clock()
        self.store = make_store(self, self.clock)
        self.store.set_user("alice", hash_password("correct horse", **FAST))
        self.settings = make_settings(lockout_attempts=3, lockout_minutes=30, lockout_user_attempts=10)

    def fail(self, ip, n=1):
        for _ in range(n):
            check_login(self.store, self.settings, "alice", "bad", ip)

    def test_changing_address_does_not_reset_the_guess_counter(self):
        for i in range(10):
            self.fail(f"9.9.9.{i}")                     # one failure per address: the per-address lock never fires
        locked = check_login(self.store, self.settings, "alice", "correct horse", "8.8.8.8")
        self.assertFalse(locked.ok)
        self.assertIn("Too many", locked.message)

    def test_nine_failures_from_many_addresses_do_not_lock(self):
        for i in range(9):
            self.fail(f"9.9.9.{i}")
        self.assertTrue(check_login(self.store, self.settings, "alice", "correct horse", "8.8.8.8").ok)

    def test_it_expires(self):
        for i in range(10):
            self.fail(f"9.9.9.{i}")
        self.clock.now += 31 * 60
        self.assertTrue(check_login(self.store, self.settings, "alice", "correct horse", "8.8.8.8").ok)

    def test_a_good_login_resets_the_count(self):
        for i in range(9):
            self.fail(f"9.9.9.{i}")
        self.assertTrue(check_login(self.store, self.settings, "alice", "correct horse", "8.8.8.8").ok)
        self.fail("7.7.7.7", 2)
        self.assertTrue(check_login(self.store, self.settings, "alice", "correct horse", "8.8.8.8").ok)

    def test_zero_switches_it_off(self):
        self.settings = make_settings(lockout_attempts=3, lockout_user_attempts=0)
        for i in range(30):
            self.fail(f"9.9.9.{i}")
        self.assertTrue(check_login(self.store, self.settings, "alice", "correct horse", "8.8.8.8").ok)

    def test_per_address_lock_still_works(self):
        self.fail("1.1.1.1", 3)
        self.assertFalse(check_login(self.store, self.settings, "alice", "correct horse", "1.1.1.1").ok)
        self.assertTrue(check_login(self.store, self.settings, "alice", "correct horse", "2.2.2.2").ok)

    def test_other_accounts_are_not_affected(self):
        self.store.set_user("bob", hash_password("pw pw pw pw", **FAST))
        for i in range(10):
            self.fail(f"9.9.9.{i}")
        self.assertTrue(check_login(self.store, self.settings, "bob", "pw pw pw pw", "8.8.8.8").ok)


# ---------------------------------------------------------------- dashboard behind a proxy
class ProxyDashboardTests(unittest.TestCase):
    def setUp(self):
        logging.disable(logging.CRITICAL)
        self.addCleanup(logging.disable, logging.NOTSET)

    def app(self, **settings):
        service, store, _ = make_service(self, [StubAgent("ScanAgent")], **settings)
        store.set_user("alice", hash_password("correct horse", **FAST))
        return create_app(service, "k" * 32), store

    @staticmethod
    def cookies(resp):
        return resp.headers.getlist("Set-Cookie")

    def test_plain_http_cookie_is_not_secure_and_no_hsts(self):
        app, _ = self.app()
        r = app.test_client().get("/login")
        self.assertTrue(self.cookies(r))
        self.assertNotIn("Secure", self.cookies(r)[0])
        self.assertNotIn("Strict-Transport-Security", r.headers)

    def test_direct_https_cookie_is_secure_with_hsts(self):
        app, _ = self.app()
        r = app.test_client().get("/login", base_url="https://dash.example")
        self.assertIn("Secure", self.cookies(r)[0])
        self.assertIn("HttpOnly", self.cookies(r)[0])
        self.assertIn("SameSite=Lax", self.cookies(r)[0])
        self.assertIn("max-age=", r.headers["Strict-Transport-Security"])

    def test_forwarded_proto_is_trusted_only_when_trust_proxy_is_on(self):
        off, _ = self.app()
        r = off.test_client().get("/login", headers={"X-Forwarded-Proto": "https"})
        self.assertNotIn("Secure", self.cookies(r)[0])
        self.assertNotIn("Strict-Transport-Security", r.headers)
        on, _ = self.app(trust_proxy=True)
        r = on.test_client().get("/login", headers={"X-Forwarded-Proto": "https"})
        self.assertIn("Secure", self.cookies(r)[0])
        self.assertIn("Strict-Transport-Security", r.headers)

    def login_ip(self, app, store, headers):
        c = app.test_client()
        page = c.get("/login", headers=headers).get_data(as_text=True)
        csrf = re.search(r'name="csrf" value="([0-9a-f]+)"', page).group(1)
        c.post("/login", data={"username": "alice", "password": "bad", "csrf": csrf}, headers=headers)
        import sqlite3
        conn = sqlite3.connect(store.path)
        try:
            return "from " + conn.execute("SELECT ip FROM login_attempts WHERE ok=0").fetchone()[0]
        finally:
            conn.close()

    def test_real_client_address_is_used_for_the_login_record_behind_a_trusted_proxy(self):
        app, store = self.app(trust_proxy=True)
        self.assertEqual(self.login_ip(app, store, {"X-Forwarded-For": "203.0.113.7"}), "from 203.0.113.7")

    def test_forwarded_for_is_ignored_without_trust_proxy(self):
        app, store = self.app()
        self.assertEqual(self.login_ip(app, store, {"X-Forwarded-For": "203.0.113.7"}), "from 127.0.0.1")

    def test_only_the_last_forwarded_address_counts(self):
        """A client can put anything in X-Forwarded-For; the proxy appends the real address at the end."""
        app, store = self.app(trust_proxy=True)
        self.assertEqual(self.login_ip(app, store, {"X-Forwarded-For": "6.6.6.6, 203.0.113.7"}), "from 203.0.113.7")

    def test_security_headers(self):
        app, _ = self.app()
        r = app.test_client().get("/login")
        self.assertEqual(r.headers["Referrer-Policy"], "no-referrer")
        self.assertIn("noindex", r.headers["X-Robots-Tag"])
        csp = r.headers["Content-Security-Policy"]
        self.assertIn("style-src 'self' 'unsafe-inline'", csp)
        self.assertIn("script-src 'self'", csp)
        self.assertNotIn("script-src 'self' 'unsafe-inline'", csp)
        self.assertIn("frame-ancestors 'none'", csp)


# ---------------------------------------------------------------- gateway
class _Upstream(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    seen: list = []

    def log_message(self, *a):
        pass

    def _reply(self):
        n = int(self.headers.get("Content-Length") or 0)
        body = self.rfile.read(n) if n else b""
        type(self).seen.append({"method": self.command, "path": self.path, "body": body, "headers": dict(self.headers)})
        if self.path.startswith("/redirect"):
            self.send_response(302)
            self.send_header("Location", "/elsewhere")
            self.send_header("Content-Length", "0")
            self.end_headers()
            return
        payload = json.dumps({"who": type(self).name, "path": self.path, "len": len(body)}).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Set-Cookie", "a=1; Path=/")
        self.send_header("Set-Cookie", "b=2; Path=/")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(payload)

    do_GET = do_POST = do_HEAD = do_PUT = _reply


def _serve(name):
    cls = type("Up" + name, (_Upstream,), {"name": name, "seen": []})
    srv = ThreadingHTTPServer(("127.0.0.1", 0), cls)
    threading.Thread(target=srv.serve_forever, kwargs={"poll_interval": 0.02}, daemon=True).start()
    return srv, cls


class GatewayRouteTests(unittest.TestCase):
    def test_routes(self):
        self.assertEqual(route("POST", "/webhook"), ("webhook", 0))
        self.assertEqual(route("POST", "/webhook?x=1"), ("webhook", 0))
        self.assertEqual(route("GET", "/webhook"), (None, 405))
        self.assertEqual(route("PUT", "/webhook"), (None, 405))
        for path in ("/", "/login", "/runs/1", "/static/style.css", "/webhook/", "/webhookx", "/Webhook",
                     "/webhook/../login", "/%77ebhook", "/health"):
            self.assertEqual(route("POST", path), ("dashboard", 0), path)
        for bad in ("http://evil/webhook", "//evil/webhook", "webhook", ""):
            self.assertEqual(route("GET", bad), (None, 400), bad)


class GatewayTests(unittest.TestCase):
    def setUp(self):
        logging.disable(logging.CRITICAL)
        self.addCleanup(logging.disable, logging.NOTSET)
        self.hook, self.hook_cls = _serve("webhook")
        self.dash, self.dash_cls = _serve("dashboard")
        self.gw = Gateway(("127.0.0.1", 0), ("127.0.0.1", self.hook.server_port), ("127.0.0.1", self.dash.server_port),
                          timeout_s=3)
        threading.Thread(target=self.gw.serve_forever, kwargs={"poll_interval": 0.02}, daemon=True).start()
        for s in (self.hook, self.dash, self.gw):
            self.addCleanup(s.server_close)
            self.addCleanup(s.shutdown)

    def call(self, method, path, body=None, headers=None, port=None):
        c = http.client.HTTPConnection("127.0.0.1", port or self.gw.server_port, timeout=5)
        c.request(method, path, body=body, headers=headers or {})
        r = c.getresponse()
        data = r.read()
        out = (r.status, r.getheaders(), data)
        c.close()
        return out

    def test_post_webhook_goes_to_the_webhook_with_body_and_signature_intact(self):
        payload = b'{"action":"opened"}'
        status, _, data = self.call("POST", "/webhook", payload, {
            "Content-Type": "application/json", "X-Hub-Signature-256": "sha256=abc", "X-GitHub-Delivery": "d-1"})
        self.assertEqual(status, 200)
        self.assertEqual(json.loads(data)["who"], "webhook")
        seen = self.hook_cls.seen[0]
        self.assertEqual(seen["body"], payload)
        self.assertEqual(seen["headers"]["X-Hub-Signature-256"], "sha256=abc")
        self.assertEqual(seen["headers"]["X-GitHub-Delivery"], "d-1")
        self.assertEqual(self.dash_cls.seen, [])

    def test_everything_else_goes_to_the_dashboard(self):
        for path in ("/", "/login?next=/runs/1", "/runs/3/live"):
            status, _, data = self.call("GET", path)
            self.assertEqual((status, json.loads(data)["who"]), (200, "dashboard"))
        self.assertEqual(self.hook_cls.seen, [])
        self.assertEqual(self.dash_cls.seen[1]["path"], "/login?next=/runs/1")

    def test_form_post_to_a_dashboard_path_reaches_the_dashboard_not_the_webhook(self):
        status, _, data = self.call("POST", "/login", b"a=b", {"Content-Type": "application/x-www-form-urlencoded"})
        self.assertEqual(json.loads(data)["who"], "dashboard")
        self.assertEqual(self.hook_cls.seen, [])

    def test_get_on_webhook_is_refused_and_not_forwarded(self):
        status, headers, _ = self.call("GET", "/webhook")
        self.assertEqual(status, 405)
        self.assertEqual(dict(headers)["Allow"], "POST")
        self.assertEqual((self.hook_cls.seen, self.dash_cls.seen), ([], []))

    def test_path_tricks_do_not_reach_the_webhook(self):
        for path in ("/webhook/", "/webhook/../x", "/Webhook", "/webhookx"):
            self.call("POST", path, b"{}")
        self.assertEqual(self.hook_cls.seen, [])

    def test_repeated_set_cookie_headers_survive(self):
        _, headers, _ = self.call("GET", "/")
        self.assertEqual([v for k, v in headers if k.lower() == "set-cookie"], ["a=1; Path=/", "b=2; Path=/"])

    def test_redirects_are_passed_on_not_followed(self):
        status, headers, _ = self.call("GET", "/redirect")
        self.assertEqual(status, 302)
        self.assertEqual(dict(headers)["Location"], "/elsewhere")
        self.assertEqual(len(self.dash_cls.seen), 1)

    def test_forwarded_headers_from_the_tunnel_pass_through_and_hop_headers_do_not(self):
        self.call("GET", "/", headers={"X-Forwarded-For": "203.0.113.7", "X-Forwarded-Proto": "https",
                                       "X-Forwarded-Host": "x.ngrok-free.app", "Upgrade": "websocket"})
        h = {k.lower(): v for k, v in self.dash_cls.seen[0]["headers"].items()}
        self.assertEqual((h["x-forwarded-for"], h["x-forwarded-proto"], h["x-forwarded-host"]),
                         ("203.0.113.7", "https", "x.ngrok-free.app"))
        self.assertNotIn("upgrade", h)

    def test_oversize_body_is_refused_without_forwarding(self):
        c = http.client.HTTPConnection("127.0.0.1", self.gw.server_port, timeout=5)
        c.putrequest("POST", "/webhook")
        c.putheader("Content-Length", str(MAX_BODY + 1))
        c.endheaders()
        self.assertEqual(c.getresponse().status, 413)
        self.assertEqual(self.hook_cls.seen, [])

    def test_chunked_request_is_refused(self):
        c = http.client.HTTPConnection("127.0.0.1", self.gw.server_port, timeout=5)
        c.putrequest("POST", "/webhook")
        c.putheader("Transfer-Encoding", "chunked")
        c.endheaders()
        c.send(b"2\r\n{}\r\n0\r\n\r\n")
        self.assertEqual(c.getresponse().status, 411)
        self.assertEqual(self.hook_cls.seen, [])

    def test_bad_content_length_is_refused(self):
        c = http.client.HTTPConnection("127.0.0.1", self.gw.server_port, timeout=5)
        c.putrequest("POST", "/webhook")
        c.putheader("Content-Length", "abc")
        c.endheaders()
        self.assertEqual(c.getresponse().status, 400)

    def test_upstream_down_gives_502_without_details(self):
        self.hook.shutdown()
        self.hook.server_close()
        status, _, data = self.call("POST", "/webhook", b"{}")
        self.assertEqual(status, 502)
        self.assertNotIn(b"Traceback", data)
        self.assertNotIn(b"127.0.0.1", data)

    def test_head_has_no_body(self):
        status, headers, data = self.call("HEAD", "/")
        self.assertEqual((status, data), (200, b""))

    def test_the_log_has_no_query_string_and_no_headers(self):
        with self.assertLogs("pipeline.gateway", level="INFO") as cm:
            logging.disable(logging.NOTSET)
            self.call("GET", "/login?token=SECRET123", headers={"Authorization": "Bearer SECRET456"})
        text = "\n".join(cm.output)
        self.assertIn("GET /login -> 200", text)
        self.assertNotIn("SECRET", text)


# ---------------------------------------------------------------- tunnel policy and command
class TunnelTests(unittest.TestCase):
    def test_emails(self):
        self.assertEqual(parse_emails("A@X.com, b@y.org  a@x.com;c@z.io"), ["a@x.com", "b@y.org", "c@z.io"])
        self.assertEqual(parse_emails(""), [])
        for bad in ("nope", "a@b", "a@b.c", "x'] || true || ['y@z.com", "a@x.com,'; drop", "a b@x.com@y.com", "<a>@x.com"):
            with self.assertRaises(ValueError, msg=bad):
                parse_emails(bad)

    def test_url(self):
        self.assertEqual(parse_url("Name.ngrok-free.app/"), "https://name.ngrok-free.app")
        self.assertEqual(parse_url("https://name.ngrok-free.app"), "https://name.ngrok-free.app")
        self.assertEqual(parse_url(""), "")
        for bad in ("name", "https://a.b/path", "a b.com", "evil.com;rm -rf", "https://"):
            with self.assertRaises(ValueError, msg=bad):
                parse_url(bad)

    def test_policy_is_valid_yaml_with_the_expected_rules(self):
        yaml = self.import_yaml()
        doc = yaml.safe_load(build_policy(["a@x.com", "b@y.org"], "github"))
        first, second = doc["on_http_request"]
        self.assertEqual(first["expressions"], ["req.url.path != '/webhook'"])
        self.assertEqual(first["actions"], [{"type": "oauth", "config": {"provider": "github"}}])
        self.assertEqual(second["expressions"][0], "req.url.path != '/webhook'")
        self.assertEqual(second["expressions"][1], "!(actions.ngrok.oauth.identity.email in ['a@x.com', 'b@y.org'])")
        self.assertEqual(second["actions"], [{"type": "deny", "config": {"status_code": 403}}])

    def test_the_webhook_is_not_asked_to_sign_in_but_nothing_else_is_exempt(self):
        text = build_policy(["a@x.com"])
        self.assertEqual(text.count("/webhook'"), 2)       # only the two '!= /webhook' conditions mention it
        self.assertNotIn("startsWith", text)               # exact match, so /webhook/anything is NOT exempt

    def test_policy_refuses_empty_and_bad_input(self):
        with self.assertRaises(ValueError):
            build_policy([])
        with self.assertRaises(ValueError):
            build_policy(["a@x.com"], "facebook")
        with self.assertRaises(ValueError):
            build_policy(["x'] || true || ['y@z.com"])

    def test_command(self):
        self.assertEqual(build_command(8080, "https://n.ngrok-free.app", "p.yml"),
                         ["ngrok", "http", "8080", "--url", "https://n.ngrok-free.app", "--traffic-policy-file", "p.yml"])
        self.assertEqual(build_command(8080, "", None), ["ngrok", "http", "8080"])

    @staticmethod
    def import_yaml():
        try:
            import yaml
            return yaml
        except ImportError:
            raise unittest.SkipTest("PyYAML is not installed; the policy text is checked in the other tests")


class StartTunnelScriptTests(unittest.TestCase):
    def run_script(self, env_extra, *args):
        env = {k: v for k, v in os.environ.items() if not k.startswith("NGROK_")}
        env.update({"NGROK_URL": "", "NGROK_OAUTH_PROVIDER": "google"})   # explicit, so a developer's own .env cannot change the result
        env.update(env_extra)
        return subprocess.run([sys.executable, str(ROOT / "scripts" / "start_tunnel.py"), *args], cwd=ROOT, env=env,
                              capture_output=True, text=True, timeout=30)

    def test_print_only_shows_policy_and_command_and_runs_nothing(self):
        r = self.run_script({"NGROK_ALLOWED_EMAILS": "me@x.com", "NGROK_URL": "demo.ngrok-free.app",
                             "GATEWAY_PORT": "8123"}, "--print-only")
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn("ngrok http 8123 --url https://demo.ngrok-free.app --traffic-policy-file", r.stdout)
        self.assertIn("provider: google", r.stdout)
        self.assertIn("Payload URL = https://demo.ngrok-free.app/webhook", r.stdout)
        self.assertFalse((ROOT / "ngrok-policy.yml").exists())     # --print-only writes nothing

    def test_refuses_without_allowed_emails(self):
        r = self.run_script({"NGROK_ALLOWED_EMAILS": ""}, "--print-only")
        self.assertEqual(r.returncode, 1)
        self.assertIn("NGROK_ALLOWED_EMAILS is empty", r.stdout)

    def test_no_signin_is_explicit_and_warns(self):
        r = self.run_script({"NGROK_ALLOWED_EMAILS": ""}, "--print-only", "--no-signin")
        self.assertEqual(r.returncode, 0)
        self.assertIn("WARNING: no ngrok sign-in", r.stdout)
        self.assertNotIn("--traffic-policy-file", r.stdout)

    def test_bad_email_is_reported_not_crashed(self):
        r = self.run_script({"NGROK_ALLOWED_EMAILS": "x'] || true || ['y@z.com"}, "--print-only")
        self.assertEqual(r.returncode, 1)
        self.assertIn("not a plain e-mail", r.stdout)


class PlanTests(unittest.TestCase):
    def test_plan_with_signin(self):
        plan = plan_from_env({"NGROK_ALLOWED_EMAILS": "a@x.com", "NGROK_URL": "n.ngrok-free.app"}, 8080, "/p/policy.yml")
        self.assertEqual(plan.command, ["ngrok", "http", "8080", "--url", "https://n.ngrok-free.app",
                                        "--traffic-policy-file", "/p/policy.yml"])
        self.assertIn("a@x.com", plan.policy)
        self.assertEqual((plan.emails, plan.url), (["a@x.com"], "https://n.ngrok-free.app"))

    def test_no_emails_is_refused_unless_no_signin(self):
        with self.assertRaisesRegex(ValueError, "NGROK_ALLOWED_EMAILS is empty"):
            plan_from_env({}, 8080, "p.yml")
        plan = plan_from_env({}, 8080, "p.yml", no_signin=True)
        self.assertIsNone(plan.policy)
        self.assertNotIn("--traffic-policy-file", plan.command)

    def test_bad_values_are_refused(self):
        for env in ({"NGROK_ALLOWED_EMAILS": "nope"}, {"NGROK_ALLOWED_EMAILS": "a@x.com", "NGROK_URL": "bad host"},
                    {"NGROK_ALLOWED_EMAILS": "a@x.com", "NGROK_OAUTH_PROVIDER": "myspace"}):
            with self.assertRaises(ValueError, msg=env):
                plan_from_env(env, 8080, "p.yml")


class StartAllTunnelTests(unittest.TestCase):
    """start_all.py --tunnel, with a fake `ngrok` program on PATH (no network, nothing is tunnelled)."""

    def setUp(self):
        import shutil
        import tempfile
        self.tmp = Path(tempfile.mkdtemp(prefix="bc-tunnel-"))
        self.addCleanup(shutil.rmtree, self.tmp, True)
        self.bin = self.tmp / "bin"
        self.bin.mkdir()

    def env(self, **extra):
        import socket
        ports = []
        for _ in range(3):
            s = socket.socket()
            s.bind(("127.0.0.1", 0))
            ports.append(s.getsockname()[1])
            s.close()
        env = {k: v for k, v in os.environ.items() if not k.startswith(("NGROK_", "TRUST_PROXY", "DASHBOARD_URL"))}
        env.update(PORT=str(ports[0]), DASHBOARD_PORT=str(ports[1]), GATEWAY_PORT=str(ports[2]),
                   DASHBOARD_SECRET_KEY="k" * 32, GITHUB_WEBHOOK_SECRET="s", GITHUB_TOKEN="github_pat_x",
                   DB_PATH=str(self.tmp / "t.db"), NGROK_URL="", NGROK_ALLOWED_EMAILS="", NGROK_OAUTH_PROVIDER="google",
                   PATH=str(self.bin))
        env.update(extra)
        return env

    def start_all(self, *args, **env):
        return subprocess.Popen([sys.executable, str(ROOT / "scripts" / "start_all.py"), "--force", *args], cwd=ROOT,
                                env=self.env(**env), stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)

    def fake_ngrok(self):
        log = self.tmp / "ngrok-args.json"
        script = self.bin / "ngrok"
        script.write_text(f"#!{sys.executable}\nimport json, sys, time\njson.dump(sys.argv[1:], open({str(log)!r}, 'w'))\n"
                          "print('fake ngrok running', flush=True)\ntime.sleep(600)\n")
        script.chmod(0o755)
        return log

    def test_refuses_without_allowed_emails_and_starts_nothing(self):
        self.fake_ngrok()
        p = self.start_all("--tunnel")
        out, _ = p.communicate(timeout=30)
        self.assertEqual(p.returncode, 1)
        self.assertIn("NGROK_ALLOWED_EMAILS is empty", out)
        self.assertNotIn("[webhook]", out)

    def test_refuses_when_ngrok_is_not_installed(self):
        p = self.start_all("--tunnel", NGROK_ALLOWED_EMAILS="a@x.com")
        out, _ = p.communicate(timeout=30)
        self.assertEqual(p.returncode, 1)
        self.assertIn("ngrok is not installed", out)
        self.assertNotIn("[webhook]", out)

    def test_runs_the_gateway_and_ngrok_and_stops_everything_on_sigterm(self):
        if not (ROOT / "webhook" / "app.py").exists():
            self.skipTest("needs the webhook/ folder next to this code (the merged project tree)")
        import signal
        import time
        log = self.fake_ngrok()
        policy = ROOT / "ngrok-policy.yml"
        had_policy = policy.exists()
        if not had_policy:
            self.addCleanup(lambda: policy.exists() and policy.unlink())
        p = self.start_all("--tunnel", NGROK_ALLOWED_EMAILS="a@x.com", NGROK_URL="demo.ngrok-free.app")
        deadline = time.time() + 20
        while time.time() < deadline and not log.exists():
            time.sleep(0.1)
        self.assertTrue(log.exists(), "fake ngrok was never started")
        time.sleep(1.0)
        p.send_signal(signal.SIGTERM)
        out, _ = p.communicate(timeout=30)
        args = json.loads(log.read_text())
        self.assertEqual(args[0], "http")
        self.assertIn("--url", args)
        self.assertEqual(args[args.index("--url") + 1], "https://demo.ngrok-free.app")
        self.assertIn("--traffic-policy-file", args)
        self.assertEqual(args[-2:], ["--log", "stdout"])
        self.assertIn("[tunnel] fake ngrok running", out)
        self.assertIn("[gateway]", out)
        self.assertIn("Payload URL: https://demo.ngrok-free.app/webhook", out)
        left = subprocess.run(["pgrep", "-f", str(self.bin / "ngrok")], capture_output=True, text=True).stdout.strip()
        self.assertEqual(left, "", "the fake ngrok was left running")


# ---------------------------------------------------------------- config and doctor
class ConfigAndDoctorTests(unittest.TestCase):
    def setUp(self):
        self.store = make_store(self)
        self.store.set_user("alice", hash_password("correct horse", **FAST))
        self.settings = dict(github_token="github_pat_abc", dashboard_secret_key="k" * 32, db_path=self.store.path,
                             dashboard_port=5002)
        self.env = {"GITHUB_WEBHOOK_SECRET": "s", "PORT": "5001"}

    def check(self, env=None, **over):
        s = make_settings(**{**self.settings, **over})
        return run_checks(s, env if env is not None else self.env, which=lambda t: "/usr/bin/" + t, port_free=lambda p: True)

    def texts(self, checks, needle):
        return [c.level for c in checks if needle in c.text]

    def test_defaults_and_env(self):
        old = {k: os.environ.get(k) for k in ("TRUST_PROXY", "LOCKOUT_USER_ATTEMPTS", "GATEWAY_PORT", "PORT")}
        self.addCleanup(lambda: [os.environ.__setitem__(k, v) if v is not None else os.environ.pop(k, None)
                                 for k, v in old.items()])
        for k in old:
            os.environ.pop(k, None)
        s = load_settings()
        self.assertEqual((s.trust_proxy, s.lockout_user_attempts, s.gateway_port, s.webhook_port), (False, 10, 8080, 5000))
        os.environ.update(TRUST_PROXY="true", LOCKOUT_USER_ATTEMPTS="5", GATEWAY_PORT="9000", PORT="5001")
        s = load_settings()
        self.assertEqual((s.trust_proxy, s.lockout_user_attempts, s.gateway_port, s.webhook_port), (True, 5, 9000, 5001))

    def test_local_setup_has_no_new_warnings(self):
        self.assertEqual([c for c in self.check() if c.level != "ok"], [])

    def test_trust_proxy_with_a_reachable_dashboard_fails(self):
        self.assertEqual(self.texts(self.check(trust_proxy=True, dashboard_host="0.0.0.0"), "TRUST_PROXY=true but"), ["fail"])
        self.assertEqual(self.texts(self.check(trust_proxy=True, dashboard_host="127.0.0.1"), "TRUST_PROXY=true but"), [])

    def test_https_url_without_trust_proxy_warns(self):
        c = self.check(dashboard_url="https://x.ngrok-free.app")
        self.assertEqual(self.texts(c, "TRUST_PROXY is false"), ["warn"])

    def test_public_url_without_allowed_emails_warns(self):
        c = self.check(dashboard_url="https://x.ngrok-free.app", trust_proxy=True)
        self.assertEqual(self.texts(c, "NGROK_ALLOWED_EMAILS is empty"), ["warn"])
        c = self.check({**self.env, "NGROK_ALLOWED_EMAILS": "me@x.com"}, dashboard_url="https://x.ngrok-free.app", trust_proxy=True)
        self.assertEqual(self.texts(c, "NGROK_ALLOWED_EMAILS is empty"), [])


if __name__ == "__main__":
    unittest.main()
