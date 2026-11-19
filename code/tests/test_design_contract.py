"""The design contract (see docs/DESIGN_CONTRACT.md).

You may change how the dashboard looks as much as you like: the CSS, the layout, the wording, the order of sections,
the HTML around things. These tests check the few things the SYSTEM needs from the pages, so a redesign cannot silently
break log-in, the approve button, the live refresh or the browser's security rules.

    python -m pytest tests/test_design_contract.py -q

A failing test names the rule that was broken. Fix the template, not the test."""

import logging
import re
import unittest
from html.parser import HTMLParser

from dashboard import create_app
from pipeline.auth import hash_password
from pipeline.models import ChangedFile, Finding, Severity, Status
from tests.service_helpers import FakeGitHub, make_pr, make_service
from tests.test_pipeline_orchestrator import StubAgent


class Page(HTMLParser):
    """Collects the tags of a page so tests can ask structural questions."""

    def __init__(self, html):
        super().__init__(convert_charrefs=True)
        self.tags, self.forms, self.scripts, self.links, self.stack = [], [], [], [], []
        self.text = []
        self._form = None
        self._script = None
        self.feed(html)

    def handle_starttag(self, tag, attrs):
        a = dict(attrs)
        self.tags.append((tag, a))
        if tag == "form":
            self._form = {"attrs": a, "fields": []}
            self.forms.append(self._form)
        elif tag in ("input", "textarea", "button", "select") and self._form is not None:
            self._form["fields"].append((tag, a))
        elif tag == "script":
            self._script = {"attrs": a, "body": ""}
            self.scripts.append(self._script)
        elif tag == "link":
            self.links.append(a)

    def handle_endtag(self, tag):
        if tag == "form":
            self._form = None
        elif tag == "script":
            self._script = None

    def handle_data(self, data):
        if self._script is not None:
            self._script["body"] += data
        self.text.append(data)

    # ---- questions
    def by_id(self, ident):
        return next((a for _, a in self.tags if a.get("id") == ident), None)

    def form(self, action):
        return next((f for f in self.forms if f["attrs"].get("action") == action), None)

    def fields(self, form):
        return {a.get("name"): (t, a) for t, a in form["fields"] if a.get("name")}

    def hrefs(self):
        return [a["href"] for t, a in self.tags if t == "a" and "href" in a]


def page(html):
    return Page(html)


class ContractTests(unittest.TestCase):
    def setUp(self):
        logging.disable(logging.CRITICAL)
        self.addCleanup(logging.disable, logging.NOTSET)
        patch = '@@ -0,0 +1,3 @@\n+import os\n+os.system(cmd)\n+print("<script>alert(1)</script>")'
        self.gh = FakeGitHub(files=[ChangedFile("a.py", "added", 3, 0, patch)])
        finding = Finding("SecurityAgent", "bandit", "B602", Severity.CRITICAL, "shell injection risk", "a.py", 2, "use a list")
        self.service, self.store, _ = make_service(self, [StubAgent("SecurityAgent", Status.WARN, [finding])], client=self.gh)
        self.store.set_user("alice", hash_password("correct horse", n=2 ** 4))
        self.rid = self.service.submit(make_pr(), "d1").run_id
        self.service.process(self.rid)
        self.http = create_app(self.service, "k" * 32).test_client()

    def html(self, path, client=None):
        r = (client or self.http).get(path)
        self.assertEqual(r.status_code, 200, path)
        return r.get_data(as_text=True)

    def login(self):
        csrf = re.search(r'name="csrf" value="([0-9a-f]+)"', self.html("/login")).group(1)
        self.http.post("/login", data={"username": "alice", "password": "correct horse", "csrf": csrf})

    # ------------------------------------------------------------ every page
    def every_page(self):
        self.login()
        return {"/login": self.html("/login", create_app(self.service, "k" * 32).test_client()),
                "/": self.html("/"), "/status": self.html("/status"), f"/runs/{self.rid}": self.html(f"/runs/{self.rid}")}

    def test_rule_1_every_page_links_the_stylesheet_and_it_is_served(self):
        for path, html in self.every_page().items():
            hrefs = [a.get("href") for a in page(html).links if a.get("rel") == "stylesheet"]
            self.assertIn("/static/style.css", hrefs, f"{path}: base.html must link /static/style.css")
        r = self.http.get("/static/style.css")
        self.assertEqual(r.status_code, 200)
        self.assertIn("text/css", r.headers["Content-Type"])

    def test_rule_2_no_inline_scripts_and_no_event_handler_attributes(self):
        """The Content-Security-Policy only allows scripts served from this site; anything else is silently blocked."""
        for path, html in self.every_page().items():
            p = page(html)
            for s in p.scripts:
                self.assertTrue(s["attrs"].get("src", "").startswith("/static/"),
                                f"{path}: scripts must be files under /static/, not inline code")
                self.assertEqual(s["body"].strip(), "", f"{path}: an inline script body would be blocked by the CSP")
            for tag, attrs in p.tags:
                bad = [k for k in attrs if k.startswith("on")]
                self.assertEqual(bad, [], f"{path}: <{tag}> has an inline event handler {bad}; use a script in /static/")

    def test_rule_3_nothing_is_loaded_from_other_websites(self):
        """Fonts, icons, CSS or JS from a CDN are blocked by the CSP (default-src 'none'). Put files in dashboard/static/."""
        for path, html in self.every_page().items():
            p = page(html)
            urls = [a.get("src") for t, a in p.tags if a.get("src")] + [a.get("href") for a in p.links]
            for u in urls:
                self.assertFalse(re.match(r"(https?:)?//", u or ""), f"{path}: {u} is not served by this site")

    def test_rule_4_every_post_form_carries_the_csrf_token(self):
        for path, html in self.every_page().items():
            for f in page(html).forms:
                if f["attrs"].get("method", "get").lower() == "post":
                    fields = {a.get("name"): a for t, a in f["fields"]}
                    self.assertIn("csrf", fields, f"{path}: form {f['attrs'].get('action')} has no csrf field")
                    self.assertEqual(fields["csrf"].get("type"), "hidden")
                    self.assertTrue(fields["csrf"].get("value"), f"{path}: the csrf value is empty")

    def test_rule_5_signed_in_pages_have_the_logout_form_and_the_main_links(self):
        for path, html in self.every_page().items():
            if path == "/login":
                continue
            p = page(html)
            self.assertIsNotNone(p.form("/logout"), f"{path}: the log-out form (POST /logout) is missing")
            self.assertIn("/", p.hrefs())
            self.assertIn("/status", p.hrefs())

    # ------------------------------------------------------------ login
    def test_login_form(self):
        p = page(self.html("/login", create_app(self.service, "k" * 32).test_client()))
        f = p.form("/login")
        self.assertIsNotNone(f, "POST /login form missing")
        self.assertEqual(f["attrs"].get("method", "").lower(), "post")
        fields = p.fields(f)
        self.assertEqual(fields["username"][1].get("type"), "text")
        self.assertEqual(fields["password"][1].get("type"), "password")
        self.assertIn("csrf", fields)

    def test_a_wrong_password_message_is_shown(self):
        c = create_app(self.service, "k" * 32).test_client()
        csrf = re.search(r'name="csrf" value="([0-9a-f]+)"', self.html("/login", c)).group(1)
        r = c.post("/login", data={"username": "alice", "password": "nope", "csrf": csrf})
        self.assertIn("Invalid user name or password", r.get_data(as_text=True),
                      "flashed messages (get_flashed_messages) must be displayed")

    # ------------------------------------------------------------ runs list
    def test_runs_list_links_each_run_and_offers_status_filters(self):
        self.login()
        hrefs = page(self.html("/")).hrefs()
        self.assertIn(f"/runs/{self.rid}", hrefs)
        self.assertTrue(any(h.startswith("/?status=") for h in hrefs), "status filter links (?status=...) are missing")

    def test_runs_and_status_pages_keep_refreshing(self):
        """Either keep the meta refresh or replace it with your own script in /static/."""
        self.login()
        for path in ("/", "/status"):
            p = page(self.html(path))
            meta = any(a.get("http-equiv") == "refresh" for t, a in p.tags if t == "meta")
            script = any(s["attrs"].get("src", "").startswith("/static/") for s in p.scripts)
            self.assertTrue(meta or script, f"{path}: no auto-refresh (meta refresh or a /static/ script)")

    # ------------------------------------------------------------ run page
    def test_run_page_shows_what_a_reviewer_needs(self):
        self.login()
        html = self.html(f"/runs/{self.rid}")
        for needle, why in (("Add feature", "PR title"), ("os.system(cmd)", "the changed code"),
                            ("shell injection risk", "the finding text"), ("B602", "the rule"),
                            ("CRITICAL", "the severity"), ("a.py", "the file name")):
            self.assertIn(needle, html, f"the run page must show {why}")

    def test_run_page_escapes_code_from_the_pull_request(self):
        """Never mark PR text as safe (|safe, Markup): a PR can contain HTML and scripts."""
        self.login()
        html = self.html(f"/runs/{self.rid}")
        self.assertNotIn("<script>alert(1)</script>", html)
        self.assertIn("&lt;script&gt;alert(1)&lt;/script&gt;", html)

    def test_decision_form(self):
        self.login()
        p = page(self.html(f"/runs/{self.rid}"))
        f = p.form(f"/runs/{self.rid}/decision")
        self.assertIsNotNone(f, "the decision form (POST /runs/<id>/decision) must be on the page while a run awaits approval")
        self.assertEqual(f["attrs"].get("method", "").lower(), "post")
        fields = p.fields(f)
        self.assertIn("csrf", fields)
        self.assertIn("reason", fields)
        actions = {a.get("value") for t, a in f["fields"] if t == "button" and a.get("name") == "action"}
        self.assertTrue({"approve", "reject"} <= actions, f"buttons named 'action' with values approve and reject; found {actions}")

    def test_decision_form_is_absent_once_decided(self):
        self.login()
        csrf = re.search(r'name="csrf" value="([0-9a-f]+)"', self.html(f"/runs/{self.rid}")).group(1)
        self.http.post(f"/runs/{self.rid}/decision", data={"action": "reject", "reason": "no", "csrf": csrf})
        p = page(self.html(f"/runs/{self.rid}"))
        self.assertIsNone(p.form(f"/runs/{self.rid}/decision"), "a finished run must not offer Approve/Reject again")

    def test_a_refused_decision_shows_its_message(self):
        self.login()
        csrf = re.search(r'name="csrf" value="([0-9a-f]+)"', self.html(f"/runs/{self.rid}")).group(1)
        r = self.http.post(f"/runs/{self.rid}/decision", data={"action": "reject", "reason": "", "csrf": csrf},
                           follow_redirects=True)
        self.assertRegex(r.get_data(as_text=True), r"(?i)reason", "flashed messages must be displayed on the run page")

    def test_live_hook_exists_only_while_the_review_is_running(self):
        self.login()
        done = page(self.html(f"/runs/{self.rid}"))
        self.assertIsNone(done.by_id("live"), "a finished run needs no live element")
        rid = self.store.create_run(make_pr("b" * 40, number=8)).run_id
        self.store.transition(rid, ("queued",), "running")
        p = page(self.html(f"/runs/{rid}"))
        live = p.by_id("live")
        self.assertIsNotNone(live, 'a running run needs <div id="live" data-url=... data-sig=...></div>')
        self.assertEqual(live.get("data-url"), f"/runs/{rid}/live")
        self.assertTrue(live.get("data-sig"))
        self.assertIn("/static/live.js", [s["attrs"].get("src") for s in p.scripts], "live.js must be loaded on a running run")

    def test_live_script_still_reads_the_hooks_it_needs(self):
        js = self.http.get("/static/live.js").get_data(as_text=True)
        for needle in ('getElementById("live")', "data-url", "data-sig", "location.reload"):
            self.assertIn(needle, js)

    def test_status_page_content(self):
        self.login()
        html = self.html("/status")
        self.assertIn("Review worker", html)
        self.assertIn("AI triage", html)


if __name__ == "__main__":
    unittest.main()
