import logging
import os
import re
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from dashboard import create_app
from pipeline.agents.secrets_scan import scan_added_lines
from pipeline.auth import check_login
from pipeline.demo import DEMO_PASSWORD, DEMO_USER, SCENARIOS, OfflineClient, build_demo, demo_settings, review, seed
from pipeline.doctor import run_checks
from pipeline.llm import OllamaClient
from pipeline.models import ChangedFile, parse_added
from pipeline.workspace import safe_extract
from tests.pipeline_helpers import make_settings
from tests.service_helpers import make_store
from tests.test_release3_llm import FakeSession

ROOT = Path(__file__).resolve().parents[1]


def levels(checks, text):
    return [c.level for c in checks if text in c.text]


class DoctorTests(unittest.TestCase):
    def setUp(self):
        self.store = make_store(self)
        from pipeline.auth import hash_password
        self.store.set_user("alice", hash_password("correct horse", n=2 ** 4))
        self.settings = make_settings(github_token="github_pat_abc", dashboard_secret_key="k" * 32,
                                      db_path=self.store.path, dashboard_port=5002)
        self.env = {"GITHUB_WEBHOOK_SECRET": "s", "PORT": "5001"}

    def check(self, settings=None, env=None, **kw):
        return run_checks(settings or self.settings, env if env is not None else self.env,
                          which=kw.pop("which", lambda t: "/usr/bin/" + t),
                          port_free=kw.pop("port_free", lambda p: True), **kw)

    def test_all_good_has_no_problems(self):
        self.assertEqual([c for c in self.check() if c.level != "ok"], [])

    def test_missing_secrets_fail(self):
        self.assertEqual(levels(self.check(env={}), "GITHUB_WEBHOOK_SECRET"), ["fail"])
        s = make_settings(github_token="", dashboard_secret_key="short", db_path=self.store.path)
        c = self.check(s)
        self.assertEqual(levels(c, "GITHUB_TOKEN"), ["fail"])
        self.assertEqual(levels(c, "DASHBOARD_SECRET_KEY"), ["fail"])

    def test_odd_looking_token_is_a_warning(self):
        s = make_settings(github_token="abc", dashboard_secret_key="k" * 32, db_path=self.store.path)
        self.assertEqual(levels(self.check(s), "does not look like"), ["warn"])

    def test_database_checks(self):
        rel = make_settings(github_token="github_pat_x", dashboard_secret_key="k" * 32, db_path="rel.db")
        self.assertEqual(levels(self.check(rel), "relative"), ["warn"])
        missing = make_settings(github_token="github_pat_x", dashboard_secret_key="k" * 32,
                                db_path="/definitely/not/here/x.db")
        self.assertEqual(levels(self.check(missing), "does not exist: "), ["fail"])

    def test_doctor_does_not_create_the_database(self):
        d = tempfile.mkdtemp()
        path = os.path.join(d, "new.db")
        s = make_settings(github_token="github_pat_x", dashboard_secret_key="k" * 32, db_path=path)
        c = self.check(s)
        self.assertFalse(os.path.exists(path))
        self.assertEqual(levels(c, "No dashboard user"), ["warn"])

    def test_no_user_warns(self):
        empty = make_store(self)
        s = make_settings(github_token="github_pat_x", dashboard_secret_key="k" * 32, db_path=empty.path)
        self.assertEqual(levels(self.check(s), "No dashboard user"), ["warn"])

    def test_missing_tools_warn_not_fail(self):
        c = self.check(which=lambda t: None)
        self.assertEqual(levels(c, "bandit is not installed"), ["warn"])
        self.assertNotIn("fail", [x.level for x in c])

    def test_ports(self):
        busy = lambda p: p != 5002  # noqa: E731
        self.assertEqual(levels(self.check(port_free=busy), "5002"), ["warn"])
        self.assertEqual(levels(self.check(port_free=busy, ports_must_be_free=True), "5002"), ["fail"])

    def test_mac_port_5000_warning(self):
        c = self.check(env={"GITHUB_WEBHOOK_SECRET": "s", "PORT": "5000"}, platform="darwin")
        self.assertEqual(levels(c, "AirPlay"), ["warn"])
        self.assertEqual(levels(self.check(env={"GITHUB_WEBHOOK_SECRET": "s", "PORT": "5000"}, platform="linux"), "AirPlay"), [])

    def test_llm_checks(self):
        s = make_settings(github_token="github_pat_x", dashboard_secret_key="k" * 32, db_path=self.store.path,
                          llm_enabled=True, llm_heavy_model="big:30b")
        down = OllamaClient("http://127.0.0.1:11434", session=FakeSession(fail=True))
        self.assertEqual(levels(self.check(s, llm_client=down), "does not answer"), ["warn"])
        up = OllamaClient("http://127.0.0.1:11434", session=FakeSession(tags=("qwen2.5-coder:7b",)))
        c = self.check(s, llm_client=up)
        self.assertEqual(levels(c, "qwen2.5-coder:7b is installed"), ["ok"])
        self.assertEqual(levels(c, "big:30b is missing"), ["warn"])

    def test_live_github_check(self):
        class R:
            def __init__(self, code):
                self.status_code = code
        for code, level in ((200, "ok"), (401, "fail"), (404, "fail")):
            c = self.check(github_repo="me/r", http_get=lambda *a, _c=code, **k: R(_c))
            self.assertEqual(levels(c, "me/r") or levels(c, "token"), [level], code)


class SecretNameTests(unittest.TestCase):
    def rules(self, line):
        f = ChangedFile("a.py", "added", 1, 0, "@@ -0,0 +1,1 @@\n+" + line)
        return [x.rule for x in scan_added_lines([f])]

    def test_prefixed_names_are_caught(self):
        for line in ('DB_PASSWORD = "s3cr3t-prod-passw0rd"', 'stripe_secret_key = "sk_live_abcdef123456"',
                     'password = "hunter2hunter2"', 'AUTH_TOKEN: "abcdefgh12345678"'):
            self.assertEqual(self.rules(line), ["hardcoded-credential"], line)

    def test_lookalikes_are_not_flagged(self):
        for line in ('tokenizer = "bert-base-uncased"', 'token_type = "bearer-token-x"',
                     'API_KEY = "your-api-key-here"', 'password = os.environ["PW"]',
                     'csrf_token_name = "csrf-token-field"'):
            self.assertEqual(self.rules(line), [], line)


class OfflineClientTests(unittest.TestCase):
    def test_sample_source_has_no_literal_secret(self):
        text = (ROOT / "pipeline" / "demo.py").read_text()
        self.assertNotIn(("AKI" + "AIOSFODNN7EXAMPLE"), text)

    def test_every_scenario_is_well_formed(self):
        self.assertEqual(set(SCENARIOS), {"clean", "secret", "vulnerable", "risky", "sneaky"})
        for sc in SCENARIOS.values():
            self.assertTrue(sc.files and sc.says and sc.expect)
            for name, content in sc.files.items():
                from pipeline.demo import _patch
                self.assertEqual(len(parse_added(_patch(content))), len(content.splitlines()), name)

    def test_client_serves_files_and_a_safe_tarball(self):
        d = Path(tempfile.mkdtemp())
        self.addCleanup(lambda: __import__("shutil").rmtree(d, True))
        client = OfflineClient(d)
        client.publish("demo/shop", 1, "a" * 40, SCENARIOS["clean"].files)
        self.assertEqual({f.filename for f in client.list_pr_files("demo/shop", 1)}, set(SCENARIOS["clean"].files))
        archive, out = d / "x.tar.gz", d / "repo"
        client.download_tarball("demo/shop", "a" * 40, archive, 10 ** 7)
        safe_extract(archive, out, 100, 10 ** 7)
        self.assertTrue((out / "utils" / "text.py").is_file())

    def test_head_sha_falls_back_to_the_database(self):
        store = make_store(self)
        d = Path(tempfile.mkdtemp())
        self.addCleanup(lambda: __import__("shutil").rmtree(d, True))
        from tests.service_helpers import make_pr
        store.create_run(make_pr("c" * 40, number=9, repo="demo/shop"))
        self.assertEqual(OfflineClient(d, store).get_pr_head_sha("demo/shop", 9), "c" * 40)


class SeedAndDashboardTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        logging.disable(logging.CRITICAL)
        cls.out = Path(tempfile.mkdtemp(prefix="bc-demo-"))
        base = make_settings(enable_semgrep=False, dashboard_secret_key="k" * 32)
        cls.settings = demo_settings(base, cls.out)
        cls.made = seed(cls.settings, cls.out)

    @classmethod
    def tearDownClass(cls):
        logging.disable(logging.NOTSET)
        __import__("shutil").rmtree(cls.out, True)

    def statuses(self):
        _, _, store = build_demo(self.settings, self.out)
        return [r["status"] for r in store.list_runs()], store

    def test_every_state_is_present(self):
        statuses, _ = self.statuses()
        for expected in ("expired", "deployed", "blocked", "superseded", "failed", "awaiting_approval"):
            self.assertIn(expected, statuses)
        self.assertGreaterEqual(statuses.count("awaiting_approval"), 2)   # left for the live demo

    def test_secret_pr_is_blocked_by_the_real_scanner(self):
        _, store = self.statuses()
        run = next(r for r in store.list_runs() if r["pr_number"] == 103)
        self.assertEqual(run["status"], "blocked")
        findings = [f for v in store.get_verdicts(run["id"]) for f in v["findings"]]
        self.assertTrue(any(f["rule"] == "aws-access-key-id" for f in findings))
        self.assertTrue(any(f["rule"] == "hardcoded-credential" for f in findings))
        text = (self.out / "comments" / "demo_shop_pr103.md").read_text()
        self.assertNotIn(("AKI" + "AIOSFODNN7EXAMPLE"), text)      # the secret itself is never printed

    def test_simulated_github_output_was_written(self):
        self.assertIn("DEPLOY (simulated)", (self.out / "deploys.log").read_text())
        self.assertIn("Awaiting approval", (self.out / "statuses.log").read_text())
        self.assertGreaterEqual(len(list((self.out / "comments").glob("*.md"))), 7)

    def test_demo_login_works_and_banner_is_shown(self):
        _, store = self.statuses()
        service, _, _ = build_demo(self.settings, self.out)
        self.assertTrue(check_login(store, self.settings, DEMO_USER, DEMO_PASSWORD, "127.0.0.1").ok)
        http = create_app(service, "k" * 32, banner="DEMO MODE: test").test_client()
        page = http.get("/login").get_data(as_text=True)
        self.assertIn("DEMO MODE: test", page)

    def test_a_fresh_process_can_approve_a_seeded_run(self):
        """The dashboard is a different process from the one that seeded: it must still work."""
        first, client, store = build_demo(self.settings, self.out)
        run_id = review(first, client, "clean", 500)                 # its own run, so the others stay untouched
        service, _, _ = build_demo(self.settings, self.out)          # new OfflineClient with empty memory
        result = service.decide(run_id, "approve", "demo", "alice")
        self.assertTrue(result.ok, result.message)
        self.assertEqual(store.get_run(run_id)["status"], "deployed")

    def test_cli_list_runs(self):
        out = subprocess.run([sys.executable, "scripts/demo.py", "list"], cwd=ROOT, capture_output=True, text=True)
        self.assertEqual(out.returncode, 0)
        self.assertIn("secret", out.stdout)


if __name__ == "__main__":
    unittest.main()
