import logging
import re
import time
import unittest

from dashboard import create_app
from dashboard.diffview import build_file_views, parse_patch
from pipeline.auth import hash_password
from pipeline.llm import LLMError, OllamaClient
from pipeline.models import ChangedFile, Finding, Severity, Status, finding_key
from pipeline.service import MAX_PATCH_CHARS, Worker, storable_files
from pipeline.status import collect_status
from tests.pipeline_helpers import make_settings
from tests.service_helpers import FakeGitHub, make_pr, make_service, make_store
from tests.test_pipeline_orchestrator import CrashAgent, StubAgent
from tests.test_release3_llm import FakeSession

FAKE_KEY = "AKI" + "AIOSFODNN7EXAMPLE"


def finding(line=2, sev=Severity.HIGH, file="a.py", rule="B602"):
    return Finding("SecurityAgent", "bandit", rule, sev, "msg", file, line, "fix it")


def submit(service, pr=None):
    rid = service.submit(pr or make_pr(), "d" + str(time.time())).run_id
    service.process(rid)
    return rid


class StoreProgressTests(unittest.TestCase):
    def test_files_round_trip_and_replace(self):
        store = make_store(self)
        rid = store.create_run(make_pr()).run_id
        store.save_files(rid, [("a.py", "added", 2, 0, "@@ -0,0 +1,2 @@\n+x\n+y", 0), ("b.bin", "added", 0, 0, None, 0)])
        files = store.get_files(rid)
        self.assertEqual([f["filename"] for f in files], ["a.py", "b.bin"])
        self.assertIsNone(files[1]["patch"])
        store.save_files(rid, [("c.py", "added", 1, 0, "+z", 0)])
        self.assertEqual([f["filename"] for f in store.get_files(rid)], ["c.py"])

    def test_step_lifecycle(self):
        store = make_store(self)
        rid = store.create_run(make_pr()).run_id
        store.plan_steps(rid, ["ScanAgent", "SecurityAgent", "RiskAgent"])
        store.step_start(rid, "ScanAgent")
        self.assertEqual([s["state"] for s in store.get_steps(rid)], ["running", "pending", "pending"])
        store.step_done(rid, "ScanAgent", "PASS")
        store.step_start(rid, "SecurityAgent")
        store.skip_steps(rid)                      # pending ones only
        self.assertEqual([s["state"] for s in store.get_steps(rid)], ["done", "running", "skipped"])
        store.skip_steps(rid, include_running=True)
        self.assertEqual(store.get_steps(rid)[1]["state"], "skipped")
        store.append_step(rid, "DeployAgent")
        self.assertEqual(store.get_steps(rid)[-1]["agent"], "DeployAgent")
        self.assertEqual(store.get_steps(rid)[-1]["position"], 3)

    def test_clear_results_clears_progress_and_files_but_not_the_audit_log(self):
        store = make_store(self)
        rid = store.create_run(make_pr()).run_id
        store.plan_steps(rid, ["ScanAgent"])
        store.save_files(rid, [("a.py", "added", 1, 0, "+x", 0)])
        store.clear_results(rid)
        self.assertEqual((store.get_steps(rid), store.get_files(rid)), ([], []))
        self.assertGreaterEqual(len(store.get_audit(rid)), 1)

    def test_heartbeat_and_counts(self):
        store = make_store(self)
        self.assertIsNone(store.last_beat("worker"))
        store.beat("worker")
        self.assertIsNotNone(store.last_beat("worker"))
        store.create_run(make_pr())
        self.assertEqual(store.status_counts(), {"queued": 1})


class StorableFilesTests(unittest.TestCase):
    def test_secrets_are_masked_in_stored_diffs(self):
        f = ChangedFile("c.py", "added", 2, 0, f'@@ -0,0 +1,2 @@\n+KEY = "{FAKE_KEY}"\n+password = "hunter2hunter2"')
        stored = storable_files([f])[0][4]
        self.assertNotIn(FAKE_KEY, stored)
        self.assertNotIn("hunter2hunter2", stored)
        self.assertIn("[REDACTED]", stored)

    def test_big_patches_are_cut_and_missing_patches_stay_missing(self):
        big = ChangedFile("big.py", "added", 9, 0, "+" + "x" * (MAX_PATCH_CHARS + 500))
        none = ChangedFile("img.png", "added", 0, 0, None)
        (_, _, _, _, patch, truncated), (_, _, _, _, nopatch, t2) = storable_files([big, none])
        self.assertEqual((len(patch), truncated), (MAX_PATCH_CHARS, 1))
        self.assertEqual((nopatch, t2), (None, 0))

    def test_number_of_files_is_capped(self):
        files = [ChangedFile(f"f{i}.py", "added", 1, 0, "+x") for i in range(400)]
        self.assertEqual(len(storable_files(files)), 300)


class ServiceProgressTests(unittest.TestCase):
    def setUp(self):
        logging.disable(logging.CRITICAL)
        self.addCleanup(logging.disable, logging.NOTSET)

    def test_files_and_steps_are_stored_in_order(self):
        service, store, _ = make_service(self, [StubAgent("ScanAgent"), StubAgent("SecurityAgent", Status.WARN)])
        rid = submit(service)
        self.assertEqual([f["filename"] for f in store.get_files(rid)], ["a.py"])
        steps = store.get_steps(rid)
        self.assertEqual([(s["agent"], s["state"], s["verdict"]) for s in steps],
                         [("ScanAgent", "done", "PASS"), ("SecurityAgent", "done", "WARN"), ("RiskAgent", "done", "PASS")])
        self.assertTrue(all(s["started_at"] and s["finished_at"] for s in steps))

    def test_stored_diff_has_no_secret(self):
        gh = FakeGitHub(files=[ChangedFile("c.py", "added", 1, 0, f'@@ -0,0 +1,1 @@\n+KEY = "{FAKE_KEY}"')])
        service, store, _ = make_service(self, [StubAgent("ScanAgent")], client=gh)
        rid = submit(service)
        self.assertNotIn(FAKE_KEY, store.get_files(rid)[0]["patch"])

    def test_agents_after_a_block_are_marked_skipped(self):
        agents = [StubAgent("ScanAgent", Status.BLOCK, [finding()]), StubAgent("SecurityAgent")]
        service, store, _ = make_service(self, agents)
        rid = submit(service)
        self.assertEqual([(s["agent"], s["state"]) for s in store.get_steps(rid)],
                         [("ScanAgent", "done"), ("SecurityAgent", "skipped"), ("RiskAgent", "skipped")])

    def test_crashed_agent_still_finishes_its_step(self):
        service, store, _ = make_service(self, [CrashAgent()])
        rid = submit(service)
        self.assertEqual(store.get_steps(rid)[0]["state"], "done")
        self.assertEqual(store.get_steps(rid)[0]["verdict"], "ESCALATE")

    def test_deploy_appears_as_a_step_after_approval(self):
        service, store, _ = make_service(self, [StubAgent("ScanAgent")], deploy_workflow="deploy.yml")
        rid = submit(service)
        service.decide(rid, "approve", "ok", "alice")
        self.assertEqual(store.get_steps(rid)[-1]["agent"], "DeployAgent")
        self.assertEqual(store.get_steps(rid)[-1]["state"], "done")

    def test_reprocessing_does_not_duplicate_steps_or_files(self):
        service, store, _ = make_service(self, [StubAgent("ScanAgent")])
        rid = submit(service)
        store.transition(rid, ("awaiting_approval",), "queued")
        service.process(rid)
        self.assertEqual((len(store.get_steps(rid)), len(store.get_files(rid))), (2, 1))

    def test_worker_writes_a_heartbeat(self):
        service, store, _ = make_service(self, [StubAgent("ScanAgent")])
        worker = Worker(service)
        worker.start(maintenance_interval=0.05)
        self.addCleanup(worker.stop)
        first = store.last_beat("worker")
        self.assertIsNotNone(first)
        deadline = time.time() + 3
        while time.time() < deadline and store.last_beat("worker") == first:
            time.sleep(0.05)
        self.assertGreater(store.last_beat("worker"), first)


class DiffViewTests(unittest.TestCase):
    PATCH = "@@ -1,3 +1,4 @@\n a\n-b\n+B\n+c\n d\n\\ No newline at end of file"

    def test_line_numbers_and_kinds(self):
        lines, cut = parse_patch(self.PATCH)
        self.assertFalse(cut)
        self.assertEqual([(x["kind"], x["old"], x["new"]) for x in lines],
                         [("hunk", None, None), ("ctx", 1, 1), ("del", 2, None), ("add", None, 2),
                          ("add", None, 3), ("ctx", 3, 4), ("meta", None, None)])

    def test_cut_at_the_line_limit(self):
        lines, cut = parse_patch("@@ -0,0 +1,50 @@\n" + "\n".join("+x" for _ in range(50)), limit=10)
        self.assertEqual((len(lines), cut), (10, True))

    def row(self, **kw):
        base = {"filename": "a.py", "status": "added", "additions": 3, "deletions": 0, "patch": self.PATCH, "truncated": 0}
        return {**base, **kw}

    def test_findings_are_placed_on_their_lines_with_ai_notes(self):
        f = finding(line=3)
        triage = {finding_key("SecurityAgent", "B602", "a.py", 3): {"label": "likely_real", "reason": "r", "model": "m"}}
        stored = {"agent": f.agent, "tool": f.tool, "rule": f.rule, "severity": int(f.severity), "message": f.message,
                  "file": f.file, "line": f.line, "suggestion": f.suggestion}
        (view,) = build_file_views([self.row()], [stored], triage)
        placed = [ln for ln in view["lines"] if ln["notes"]]
        self.assertEqual([(ln["new"], ln["kind"]) for ln in placed], [(3, "add")])
        self.assertEqual(placed[0]["notes"][0]["ai"]["label"], "likely_real")
        self.assertEqual((view["count"], view["unplaced"]), (1, []))

    def test_finding_on_a_line_that_is_not_shown_is_listed_at_the_top_of_the_file(self):
        stored = {"agent": "S", "tool": "t", "rule": "r", "severity": 3, "message": "m", "file": "a.py", "line": 99, "suggestion": None}
        (view,) = build_file_views([self.row()], [stored], {})
        self.assertEqual(len(view["unplaced"]), 1)

    def test_info_findings_and_other_files_are_ignored_and_worst_file_comes_first(self):
        mk = lambda file, sev: {"agent": "S", "tool": "t", "rule": "r", "severity": sev, "message": "m", "file": file, "line": 2, "suggestion": None}  # noqa: E731
        views = build_file_views([self.row(filename="a.py"), self.row(filename="b.py")],
                                 [mk("b.py", 4), mk("a.py", 0), mk("c.py", 4)], {})
        self.assertEqual([v["filename"] for v in views], ["b.py", "a.py"])
        self.assertEqual([v["count"] for v in views], [1, 0])

    def test_missing_patch(self):
        (view,) = build_file_views([self.row(patch=None)], [], {})
        self.assertTrue(view["no_patch"])


class FakeOllamaHTTP(FakeSession):
    def __init__(self, ps=None, fail_ps=False, **kw):
        super().__init__(**kw)
        self.ps, self.fail_ps = ps if ps is not None else [], fail_ps

    def get(self, url, timeout=None):
        if url.endswith("/api/ps"):
            from tests.test_release3_llm import Resp
            if self.fail_ps:
                import requests
                raise requests.ConnectionError("down")
            return Resp({"models": self.ps})
        return super().get(url, timeout)


class StatusTests(unittest.TestCase):
    def test_worker_states(self):
        store = make_store(self)
        s = make_settings()
        self.assertIsNone(collect_status(store, s)["worker"]["seconds_ago"])
        self.assertFalse(collect_status(store, s)["worker"]["alive"])
        store.beat("worker")
        self.assertTrue(collect_status(store, s)["worker"]["alive"])
        later = time.time() + 120
        info = collect_status(store, s, now=later)
        self.assertFalse(info["worker"]["alive"])
        self.assertGreaterEqual(info["worker"]["seconds_ago"], 100)

    def test_queue_counts_and_working_run(self):
        store = make_store(self)
        a = store.create_run(make_pr(number=1)).run_id
        store.create_run(make_pr(number=2))
        store.transition(a, ("queued",), "running")
        q = collect_status(store, make_settings())["queue"]
        self.assertEqual((q["queued"], q["running"], q["working"][0]["pr_number"]), (1, 1, 1))

    def test_llm_off_and_on(self):
        store = make_store(self)
        self.assertEqual(collect_status(store, make_settings())["ollama"], {"enabled": False})
        s = make_settings(llm_enabled=True)
        ps = [{"name": "qwen2.5-coder:7b", "size": 4_900_000_000, "expires_at": "x"}]
        client = OllamaClient("http://127.0.0.1:11434", session=FakeOllamaHTTP(ps=ps, tags=("qwen2.5-coder:7b",)))
        o = collect_status(store, s, llm_client=client)["ollama"]
        self.assertTrue(o["reachable"])
        self.assertEqual(o["loaded"], [{"name": "qwen2.5-coder:7b", "size": "4.9 GB"}])

    def test_llm_down_is_reported_not_raised(self):
        o = collect_status(make_store(self), make_settings(llm_enabled=True),
                           llm_client=OllamaClient("http://127.0.0.1:11434", session=FakeOllamaHTTP(fail=True)))["ollama"]
        self.assertFalse(o["reachable"])
        self.assertIn("ollama serve", o["error"])

    def test_remote_url_is_reported_not_raised(self):
        o = collect_status(make_store(self), make_settings(llm_enabled=True, ollama_url="http://example.com:11434"))["ollama"]
        self.assertFalse(o["reachable"])
        self.assertIn("not a local address", o["error"])


class DashboardLiveTests(unittest.TestCase):
    def setUp(self):
        logging.disable(logging.CRITICAL)
        self.addCleanup(logging.disable, logging.NOTSET)
        patch = '@@ -0,0 +1,3 @@\n+import os\n+os.system(cmd)\n+print("<script>alert(1)</script>")'
        self.gh = FakeGitHub(files=[ChangedFile("a.py", "added", 3, 0, patch)])
        self.service, self.store, _ = make_service(
            self, [StubAgent("SecurityAgent", Status.WARN, [finding(line=2, sev=Severity.CRITICAL)])], client=self.gh)
        self.store.set_user("alice", hash_password("correct horse", n=2 ** 4))
        self.rid = submit(self.service)
        self.http = create_app(self.service, "k" * 32).test_client()
        page = self.http.get("/login").get_data(as_text=True)
        csrf = re.search(r'name="csrf" value="([0-9a-f]+)"', page).group(1)
        self.http.post("/login", data={"username": "alice", "password": "correct horse", "csrf": csrf})

    def page(self, rid=None):
        return self.http.get(f"/runs/{rid or self.rid}").get_data(as_text=True)

    def test_run_page_shows_the_pr_code_with_the_finding_on_its_line(self):
        page = self.page()
        self.assertIn("Changed code", page)
        self.assertIn("os.system(cmd)", page)
        self.assertRegex(page, r"CRITICAL</strong> &middot; bandit &middot; B602")
        self.assertIn("1 finding", page)
        self.assertIn("Add feature", page)                      # PR title
        self.assertIn("feature", page)                          # head branch

    def test_code_in_the_pr_is_escaped(self):
        page = self.page()
        self.assertNotIn('<script>alert(1)</script>', page)
        self.assertIn("&lt;script&gt;alert(1)&lt;/script&gt;", page)

    def test_stage_chips_for_a_finished_run(self):
        page = self.page()
        for name in ("Security", "Risk"):
            self.assertIn(name, page)
        self.assertIsNone(re.search(r'id="live"', page))          # finished: no polling

    def test_running_run_has_live_polling_and_a_working_chip(self):
        rid = self.store.create_run(make_pr("b" * 40, number=8)).run_id
        self.store.transition(rid, ("queued",), "running")
        self.store.plan_steps(rid, ["ScanAgent", "SecurityAgent"])
        self.store.step_start(rid, "ScanAgent")
        page = self.page(rid)
        self.assertIn('id="live"', page)
        self.assertIn("/static/live.js", page)
        self.assertRegex(page, r'class="stage running"')
        self.assertIn("working...", page)
        self.assertIn("now: ScanAgent", self.http.get("/").get_data(as_text=True))

    def test_live_endpoint_signature_changes_with_progress(self):
        rid = self.store.create_run(make_pr("b" * 40, number=8)).run_id
        self.store.transition(rid, ("queued",), "running")
        self.store.plan_steps(rid, ["ScanAgent"])
        first = self.http.get(f"/runs/{rid}/live").get_json()
        self.store.step_start(rid, "ScanAgent")
        second = self.http.get(f"/runs/{rid}/live").get_json()
        self.assertNotEqual(first["sig"], second["sig"])
        self.assertEqual(second["status"], "running")
        self.assertEqual(self.http.get("/runs/999/live").status_code, 404)

    def test_live_endpoint_requires_login(self):
        anon = create_app(self.service, "k" * 32).test_client()
        r = anon.get(f"/runs/{self.rid}/live")
        self.assertEqual(r.status_code, 302)

    def test_script_is_allowed_by_csp_and_served(self):
        r = self.http.get("/login")
        csp = r.headers["Content-Security-Policy"]
        self.assertIn("script-src 'self'", csp)
        self.assertNotIn("unsafe-inline'; form", csp.split("style-src")[0])   # scripts are not inline-allowed
        js = self.http.get("/static/live.js")
        self.assertEqual(js.status_code, 200)
        self.assertIn("window.location.reload", js.get_data(as_text=True))

    def test_status_page(self):
        self.store.beat("worker")
        page = self.http.get("/status").get_data(as_text=True)
        self.assertIn("Review worker", page)
        self.assertIn("running (last sign of life", page)
        self.assertIn("AI triage is off", page)
        self.assertNotIn("github_pat", page)

    def test_only_http_links_are_rendered_for_the_pr(self):
        rid = self.store.create_run(make_pr("c" * 40, number=9)).run_id
        self.store.update_run(rid)  # touch
        import sqlite3
        conn = sqlite3.connect(self.store.path)
        conn.execute("UPDATE runs SET html_url='javascript:alert(1)' WHERE id=?", (rid,))
        conn.commit(); conn.close()
        self.assertNotIn("javascript:alert(1)", self.page(rid))
        self.assertIn('href="http://pr"', self.page())

    def test_old_runs_without_stored_files_still_render(self):
        rid = self.store.create_run(make_pr("d" * 40, number=10)).run_id
        self.store.transition(rid, ("queued",), "failed", error="x")
        self.assertIn("No changed files were stored", self.page(rid))

    def test_secret_in_a_pr_is_not_shown_in_the_code_view(self):
        gh = FakeGitHub(files=[ChangedFile("c.py", "added", 1, 0, f'@@ -0,0 +1,1 @@\n+KEY = "{FAKE_KEY}"')])
        service, store, _ = make_service(self, [StubAgent("ScanAgent")], client=gh)
        store.set_user("alice", hash_password("correct horse", n=2 ** 4))
        rid = submit(service)
        http = create_app(service, "k" * 32).test_client()
        page = http.get("/login").get_data(as_text=True)
        http.post("/login", data={"username": "alice", "password": "correct horse",
                                  "csrf": re.search(r'name="csrf" value="([0-9a-f]+)"', page).group(1)})
        self.assertNotIn(FAKE_KEY, http.get(f"/runs/{rid}").get_data(as_text=True))


class OllamaRunningTests(unittest.TestCase):
    def test_running_lists_loaded_models(self):
        c = OllamaClient("http://127.0.0.1:11434", session=FakeOllamaHTTP(ps=[{"name": "m:1b", "size": 2_000_000_000}]))
        self.assertEqual(c.running(), [{"name": "m:1b", "size_bytes": 2_000_000_000, "expires_at": ""}])
        self.assertEqual(c.installed(), ["small:1b", "big:30b", "plain:latest"])


if __name__ == "__main__":
    unittest.main()
