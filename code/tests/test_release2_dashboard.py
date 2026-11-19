import logging
import re
import unittest

from dashboard import create_app
from pipeline.auth import hash_password
from pipeline.models import Finding, Severity, Status
from tests.service_helpers import make_pr, make_service
from tests.test_pipeline_orchestrator import StubAgent

KEY = "k" * 32


class DashboardTests(unittest.TestCase):
    def setUp(self):
        logging.disable(logging.CRITICAL)
        self.addCleanup(logging.disable, logging.NOTSET)
        bad = Finding("SecurityAgent", "bandit", "r<b>", Severity.HIGH, "<script>alert(1)</script>", "a.py", 1)
        self.service, self.store, self.client = make_service(
            self, [StubAgent("SecurityAgent", Status.WARN, [bad])], deploy_workflow="deploy.yml")
        self.store.set_user("alice", hash_password("correct horse", n=2 ** 4))
        self.rid = self.service.submit(make_pr(), "d1").run_id
        self.service.process(self.rid)
        self.app = create_app(self.service, KEY)
        self.http = self.app.test_client()

    def csrf(self, c=None):
        c = c or self.http
        page = c.get("/login").get_data(as_text=True)
        return re.search(r'name="csrf" value="([0-9a-f]+)"', page).group(1)

    def login(self, c=None, password="correct horse"):
        c = c or self.http
        return c.post("/login", data={"username": "alice", "password": password, "csrf": self.csrf(c)})

    def token(self):
        """The CSRF token of the logged-in session (taken from a rendered page, like a browser would)."""
        page = self.http.get("/").get_data(as_text=True)
        return re.search(r'name="csrf" value="([0-9a-f]+)"', page).group(1)

    def test_secret_key_is_required(self):
        with self.assertRaises(RuntimeError):
            create_app(self.service, "short")

    def test_pages_require_login(self):
        for url in ("/", f"/runs/{self.rid}"):
            r = self.http.get(url)
            self.assertEqual((r.status_code, r.headers["Location"].endswith("/login")), (302, True))
        r = self.http.post(f"/runs/{self.rid}/decision", data={"action": "approve"})
        self.assertIn(r.status_code, (302, 400))
        self.assertEqual(self.store.get_run(self.rid)["status"], "awaiting_approval")

    def test_login_then_list_and_detail(self):
        self.assertEqual(self.login().status_code, 302)
        listing = self.http.get("/").get_data(as_text=True)
        self.assertIn("awaiting approval", listing)
        detail = self.http.get(f"/runs/{self.rid}").get_data(as_text=True)
        self.assertIn("Approve", detail)
        self.assertEqual(self.http.get("/?status=nonsense").status_code, 400)
        self.assertEqual(self.http.get("/runs/999").status_code, 404)

    def test_finding_text_is_escaped(self):
        self.login()
        detail = self.http.get(f"/runs/{self.rid}").get_data(as_text=True)
        self.assertNotIn("<script>alert(1)</script>", detail)
        self.assertIn("&lt;script&gt;", detail)

    def test_wrong_password_and_lockout(self):
        for _ in range(3):
            self.login(password="nope")
        r = self.login()  # correct password, but locked
        self.assertEqual(r.status_code, 200)
        self.assertIn("Too many", r.get_data(as_text=True))
        self.assertNotIn("user", self.session_keys())

    def session_keys(self):
        with self.http.session_transaction() as s:
            return set(s.keys())

    def test_post_without_csrf_token_is_rejected(self):
        self.login()
        r = self.http.post(f"/runs/{self.rid}/decision", data={"action": "approve"})
        self.assertEqual(r.status_code, 400)
        r = self.http.post(f"/runs/{self.rid}/decision", data={"action": "approve", "csrf": "wrong"})
        self.assertEqual(r.status_code, 400)
        self.assertEqual(self.store.get_run(self.rid)["status"], "awaiting_approval")

    def test_approve_through_the_dashboard(self):
        self.login()
        r = self.http.post(f"/runs/{self.rid}/decision",
                           data={"action": "approve", "reason": "ok", "csrf": self.token()}, follow_redirects=True)
        self.assertIn("deployment workflow was started", r.get_data(as_text=True))
        self.assertEqual(self.store.get_decisions(self.rid)[0]["decided_by"], "alice")
        self.assertEqual(len(self.client.dispatches), 1)

    def test_reject_without_reason_shows_error(self):
        self.login()
        r = self.http.post(f"/runs/{self.rid}/decision", data={"action": "reject", "csrf": self.token()},
                           follow_redirects=True)
        self.assertIn("reason is required", r.get_data(as_text=True))
        self.assertEqual(self.store.get_run(self.rid)["status"], "awaiting_approval")

    def test_logout_clears_session(self):
        self.login()
        self.http.post("/logout", data={"csrf": self.token()})
        self.assertEqual(self.http.get("/").status_code, 302)

    def test_security_headers(self):
        r = self.http.get("/login")
        self.assertEqual(r.headers["X-Frame-Options"], "DENY")
        self.assertIn("default-src 'none'", r.headers["Content-Security-Policy"])
        self.assertEqual(r.headers["Cache-Control"], "no-store")


if __name__ == "__main__":
    unittest.main()
