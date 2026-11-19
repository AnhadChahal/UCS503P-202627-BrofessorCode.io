import logging
import time
import unittest

from pipeline.models import ChangedFile, Finding, Severity, Status
from pipeline.service import Worker
from tests.service_helpers import SHA_A, SHA_B, FakeGitHub, make_pr, make_service
from tests.test_pipeline_orchestrator import CrashAgent, StubAgent


def clean_agents():
    return [StubAgent("ScanAgent"), StubAgent("SecurityAgent")]


def blocking_agents():
    f = Finding("SecurityAgent", "bandit", "B602", Severity.CRITICAL, "shell injection", "a.py", 1)
    return [StubAgent("ScanAgent"), StubAgent("SecurityAgent", Status.BLOCK, [f])]


def submit_and_process(service, pr=None):
    sub = service.submit(pr or make_pr(), "d-" + str(time.time()))
    service.process(sub.run_id)
    return sub.run_id


class ServiceTestCase(unittest.TestCase):
    def setUp(self):
        logging.disable(logging.CRITICAL)
        self.addCleanup(logging.disable, logging.NOTSET)

    def status(self, store, rid):
        return store.get_run(rid)["status"]


class RoutingTests(ServiceTestCase):
    def test_default_policy_always_asks_a_person(self):
        service, store, client = make_service(self, clean_agents())
        rid = submit_and_process(service)
        run = store.get_run(rid)
        self.assertEqual(run["status"], "awaiting_approval")
        self.assertIn("policy requires a person", run["escalation_reason"])
        self.assertEqual(run["risk_score"], 0)
        self.assertEqual(client.statuses[-1][0], "pending")
        self.assertIn("approve", client.comments[-1].lower())
        self.assertEqual(client.dispatches, [])

    def test_block_skips_risk_and_never_asks(self):
        service, store, client = make_service(self, blocking_agents())
        rid = submit_and_process(service)
        self.assertEqual(self.status(store, rid), "blocked")
        self.assertNotIn("RiskAgent", [v["agent"] for v in store.get_verdicts(rid)])
        self.assertEqual(client.statuses[-1][0], "failure")

    def test_auto_policy_approves_low_risk_and_deploys(self):
        service, store, client = make_service(self, clean_agents(), approval_policy="auto_below_threshold",
                                              deploy_workflow="deploy.yml")
        rid = submit_and_process(service)
        self.assertEqual(self.status(store, rid), "deployed")
        self.assertEqual(len(client.dispatches), 1)
        self.assertEqual(store.get_decisions(rid)[0]["decided_by"], "policy")
        self.assertEqual(client.statuses[-1][0], "success")

    def test_auto_policy_still_asks_when_a_check_was_uncertain(self):
        agents = [StubAgent("ScanAgent", Status.ESCALATE), StubAgent("SecurityAgent")]
        service, store, client = make_service(self, agents, approval_policy="auto_below_threshold")
        rid = submit_and_process(service)
        self.assertEqual(self.status(store, rid), "awaiting_approval")
        self.assertEqual(client.dispatches, [])

    def test_auto_policy_still_asks_when_risk_is_high(self):
        client = FakeGitHub(files=[ChangedFile(".github/workflows/ci.yml", "modified", 600, 0)])
        service, store, _ = make_service(self, clean_agents(), client=client, approval_policy="auto_below_threshold",
                                         risk_threshold=20)
        rid = submit_and_process(service)
        run = store.get_run(rid)
        self.assertEqual(run["status"], "awaiting_approval")
        self.assertIn("above 20", run["escalation_reason"])

    def test_agent_crash_needs_a_person_not_a_pass(self):
        service, store, _ = make_service(self, [CrashAgent(), StubAgent("SecurityAgent")],
                                         approval_policy="auto_below_threshold")
        rid = submit_and_process(service)
        self.assertEqual(self.status(store, rid), "awaiting_approval")

    def test_github_failure_marks_run_failed(self):
        client = FakeGitHub()
        client.fail_files = True
        service, store, client = make_service(self, clean_agents(), client=client)
        rid = submit_and_process(service)
        run = store.get_run(rid)
        self.assertEqual(run["status"], "failed")
        self.assertIn("GitHubError", run["error"])
        self.assertEqual(client.statuses[-1][0], "error")
        self.assertIn("not** been approved", client.comments[-1])


class DecisionTests(ServiceTestCase):
    def waiting(self, **settings):
        service, store, client = make_service(self, clean_agents(), deploy_workflow="deploy.yml", **settings)
        return service, store, client, submit_and_process(service)

    def test_approve_deploys_and_records_who_and_why(self):
        service, store, client, rid = self.waiting()
        result = service.decide(rid, "approve", "looks fine", "alice")
        self.assertTrue(result.ok, result.message)
        self.assertEqual(self.status(store, rid), "deployed")
        d = store.get_decisions(rid)[0]
        self.assertEqual((d["decision"], d["decided_by"], d["head_sha"], d["reason"]), ("approve", "alice", SHA_A, "looks fine"))
        self.assertEqual(len(client.dispatches), 1)
        self.assertEqual(client.statuses[-1][0], "success")
        self.assertIn("alice", client.comments[-1])

    def test_approve_without_deploy_workflow_is_recorded_only(self):
        service, store, client = make_service(self, clean_agents())
        rid = submit_and_process(service)
        self.assertTrue(service.decide(rid, "approve", "", "alice").ok)
        self.assertEqual(self.status(store, rid), "approved")
        self.assertEqual(client.dispatches, [])

    def test_approve_refused_when_pr_head_moved(self):
        service, store, client, rid = self.waiting()
        client.head_sha = SHA_B
        result = service.decide(rid, "approve", "", "alice")
        self.assertFalse(result.ok)
        self.assertEqual(self.status(store, rid), "superseded")
        self.assertEqual(client.dispatches, [])
        self.assertEqual(store.get_decisions(rid), [])

    def test_approve_fails_closed_when_github_unreachable(self):
        service, store, client, rid = self.waiting()
        client.fail_head = True
        self.assertFalse(service.decide(rid, "approve", "", "alice").ok)
        self.assertEqual(self.status(store, rid), "awaiting_approval")
        self.assertEqual(client.dispatches, [])

    def test_second_decision_is_refused(self):
        service, store, client, rid = self.waiting()
        self.assertTrue(service.decide(rid, "approve", "", "alice").ok)
        self.assertFalse(service.decide(rid, "approve", "", "bob").ok)
        self.assertFalse(service.decide(rid, "reject", "no", "bob").ok)
        self.assertEqual(len(store.get_decisions(rid)), 1)
        self.assertEqual(len(client.dispatches), 1)

    def test_reject_and_block_need_a_reason(self):
        service, store, _, rid = self.waiting()
        self.assertFalse(service.decide(rid, "reject", "  ", "alice").ok)
        self.assertFalse(service.decide(rid, "block", "", "alice").ok)
        self.assertEqual(self.status(store, rid), "awaiting_approval")

    def test_reject(self):
        service, store, client, rid = self.waiting()
        self.assertTrue(service.decide(rid, "reject", "needs tests", "alice").ok)
        self.assertEqual(self.status(store, rid), "rejected")
        self.assertEqual(client.statuses[-1][0], "failure")
        self.assertEqual(client.dispatches, [])

    def test_block_an_approved_run_stops_nothing_already_started_but_is_recorded(self):
        service, store, _ = make_service(self, clean_agents())
        rid = submit_and_process(service)
        service.decide(rid, "approve", "", "alice")  # approved, no deploy configured
        self.assertTrue(service.decide(rid, "block", "found a problem", "bob").ok)
        self.assertEqual(self.status(store, rid), "blocked")

    def test_unknown_action_and_unknown_run(self):
        service, _, _, rid = self.waiting()
        self.assertFalse(service.decide(rid, "delete", "", "alice").ok)
        self.assertFalse(service.decide(9999, "approve", "", "alice").ok)

    def test_deploy_trigger_failure_is_not_reported_as_deployed(self):
        service, store, client, rid = self.waiting()
        client.fail_dispatch = True
        result = service.decide(rid, "approve", "", "alice")
        self.assertTrue(result.ok)
        self.assertEqual(self.status(store, rid), "failed")
        self.assertEqual(client.statuses[-1][0], "error")

    def test_audit_trail_names_the_actors(self):
        service, store, _, rid = self.waiting()
        service.decide(rid, "approve", "ok", "alice")
        actors = {a["actor"] for a in store.get_audit(rid)}
        self.assertTrue({"system", "alice", "DeployAgent"} <= actors)


class LifecycleTests(ServiceTestCase):
    def test_new_commit_supersedes_and_old_run_is_not_analysed(self):
        service, store, client = make_service(self, clean_agents())
        first = service.submit(make_pr(SHA_A), "d1").run_id
        second = service.submit(make_pr(SHA_B), "d2").run_id
        self.assertEqual(self.status(store, first), "superseded")
        service.process(first)
        self.assertEqual(store.get_verdicts(first), [])
        service.process(second)
        self.assertEqual(self.status(store, second), "awaiting_approval")

    def test_duplicate_delivery_creates_one_run(self):
        service, store, _ = make_service(self, clean_agents())
        self.assertIsNotNone(service.submit(make_pr(), "same").run_id)
        self.assertIsNone(service.submit(make_pr(), "same").run_id)
        self.assertEqual(len(store.list_runs()), 1)

    def test_expiry_never_approves(self):
        now = [time.time() - 3 * 3600]
        service, store, client = make_service(self, clean_agents(), clock=lambda: now[0], approval_timeout_hours=1)
        rid = submit_and_process(service)
        now[0] = time.time()
        self.assertEqual(service.expire_stale(), [rid])
        self.assertEqual(self.status(store, rid), "expired")
        self.assertEqual(client.dispatches, [])
        self.assertFalse(service.decide(rid, "approve", "", "alice").ok)

    def test_fresh_runs_do_not_expire(self):
        service, store, _ = make_service(self, clean_agents(), approval_timeout_hours=1)
        rid = submit_and_process(service)
        self.assertEqual(service.expire_stale(), [])
        self.assertEqual(self.status(store, rid), "awaiting_approval")

    def test_recover_requeues_interrupted_runs(self):
        service, store, _ = make_service(self, clean_agents())
        rid = service.submit(make_pr(), "d").run_id
        store.transition(rid, ("queued",), "running")  # the process died here
        self.assertEqual(service.recover(), [rid])
        self.assertEqual(self.status(store, rid), "queued")
        service.process(rid)
        self.assertEqual(self.status(store, rid), "awaiting_approval")

    def test_reprocessing_does_not_duplicate_verdicts(self):
        service, store, _ = make_service(self, clean_agents())
        rid = service.submit(make_pr(), "d").run_id
        service.process(rid)
        first = len(store.get_verdicts(rid))
        store.transition(rid, ("awaiting_approval",), "queued")
        service.process(rid)
        self.assertEqual(len(store.get_verdicts(rid)), first)

    def test_comment_contains_no_raw_mentions_or_html_from_findings(self):
        f = Finding("SecurityAgent", "bandit", "r", Severity.HIGH, "ping @everyone <script>alert(1)</script>", "a.py", 1)
        agents = [StubAgent("SecurityAgent", Status.WARN, [f])]
        service, _, client = make_service(self, agents)
        submit_and_process(service)
        body = client.comments[-1]
        self.assertNotIn("<script>", body)
        self.assertNotIn("@everyone", body)

    def test_worker_processes_queue_end_to_end(self):
        service, store, _ = make_service(self, clean_agents())
        worker = Worker(service)
        worker.start(maintenance_interval=3600)
        self.addCleanup(worker.stop)
        sub = worker.submit(make_pr(), "d1")
        worker.jobs.join()
        self.assertEqual(self.status(store, sub.run_id), "awaiting_approval")

    def test_worker_survives_a_crashing_run(self):
        service, store, _ = make_service(self, clean_agents())
        worker = Worker(service)
        original = service.process
        calls = []

        def flaky(run_id):
            calls.append(run_id)
            if len(calls) == 1:
                raise RuntimeError("boom")
            original(run_id)

        service.process = flaky
        worker.start(maintenance_interval=3600)
        self.addCleanup(worker.stop)
        worker.submit(make_pr(number=1), "d1")
        second = worker.submit(make_pr(number=2), "d2")
        worker.jobs.join()
        self.assertEqual(self.status(store, second.run_id), "awaiting_approval")


if __name__ == "__main__":
    unittest.main()
