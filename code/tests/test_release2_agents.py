import json
import tempfile
import unittest
from pathlib import Path

from pipeline.agents import DeployAgent, RiskAgent
from pipeline.models import Approval, ChangedFile, Finding, PipelineContext, Severity, Status, Verdict
from tests.pipeline_helpers import make_settings
from tests.service_helpers import SHA_A, SHA_B, FakeGitHub, make_pr


def ctx(files=(), verdicts=(), approval=None, pr=None):
    return PipelineContext(pr or make_pr(), list(files), Path("."), list(verdicts), approval)


def changed(name, adds=1, dels=0, status="modified"):
    return ChangedFile(name, status, adds, dels)


class RiskAgentTests(unittest.TestCase):
    def score(self, c, **settings):
        v = RiskAgent(make_settings(**settings)).run(c)
        return v.data["score"], v

    def test_small_plain_change_is_low(self):
        score, v = self.score(ctx([changed("src/util.py", 5)]))
        self.assertEqual((score, v.status), (0, Status.PASS))

    def test_workflow_change_adds_points(self):
        score, _ = self.score(ctx([changed(".github/workflows/ci.yml", 3)]))
        self.assertEqual(score, 25)

    def test_each_path_label_counts_once_and_total_is_capped(self):
        files = [changed(".github/workflows/a.yml"), changed(".github/workflows/b.yml"),
                 changed("auth/login.py"), changed("Dockerfile"), changed("terraform/main.tf")]
        score, _ = self.score(ctx(files))
        self.assertEqual(score, 40)  # path_cap

    def test_size_bands(self):
        self.assertEqual(self.score(ctx([changed("a.py", 300)]))[0], 10)
        self.assertEqual(self.score(ctx([changed("a.py", 5000)]))[0], 20)

    def test_removed_files_do_not_count_as_paths(self):
        self.assertEqual(self.score(ctx([changed("auth.py", 0, 3, "removed")]))[0], 0)

    def test_findings_and_uncertainty_raise_score_and_threshold_escalates(self):
        finding = Finding("SecurityAgent", "bandit", "B1", Severity.HIGH, "m")
        verdicts = [Verdict("SecurityAgent", Status.WARN, [finding]), Verdict("ScanAgent", Status.ESCALATE)]
        score, v = self.score(ctx([changed("auth.py", 400)], verdicts), risk_threshold=40)
        self.assertEqual(score, 20 + 10 + 15 + 20)
        self.assertEqual(v.status, Status.ESCALATE)
        _, low = self.score(ctx([changed("auth.py", 400)], verdicts), risk_threshold=90)
        self.assertEqual(low.status, Status.PASS)

    def test_score_never_exceeds_100(self):
        crit = [Finding("S", "t", "r", Severity.CRITICAL, "m")] * 10
        files = [changed(".github/workflows/x.yml", 5000), changed("auth.py"), changed("Dockerfile")]
        score, _ = self.score(ctx(files, [Verdict("S", Status.ESCALATE, crit)]))
        self.assertLessEqual(score, 100)

    def test_broken_weights_file_falls_back_to_defaults(self):
        with tempfile.TemporaryDirectory() as d:
            bad = Path(d) / "w.json"
            bad.write_text("{not json")
            score, _ = self.score(ctx([changed(".github/workflows/ci.yml")]), risk_weights_file=str(bad))
        self.assertEqual(score, 25)

    def test_weights_file_overrides(self):
        with tempfile.TemporaryDirectory() as d:
            f = Path(d) / "w.json"
            f.write_text(json.dumps({"size": [[None, 7]]}))
            score, _ = self.score(ctx([changed("a.py")]), risk_weights_file=str(f))
        self.assertEqual(score, 7)


class DeployAgentTests(unittest.TestCase):
    def agent(self, client=None, **settings):
        client = client or FakeGitHub()
        return DeployAgent(make_settings(deploy_workflow="deploy.yml", **settings), client), client

    def approval(self, sha=SHA_A, decision="approve"):
        return Approval(decision, "alice", "ok", sha)

    def test_refuses_without_approval(self):
        agent, client = self.agent()
        self.assertEqual(agent.run(ctx()).status, Status.BLOCK)
        self.assertEqual(agent.run(ctx(approval=self.approval(decision="reject"))).status, Status.BLOCK)
        self.assertEqual(client.dispatches, [])

    def test_refuses_when_approval_is_for_another_commit(self):
        agent, client = self.agent()
        v = agent.run(ctx(approval=self.approval(SHA_B)))
        self.assertEqual(v.status, Status.BLOCK)
        self.assertEqual(client.dispatches, [])

    def test_refuses_when_another_agent_blocked(self):
        agent, client = self.agent()
        v = agent.run(ctx(verdicts=[Verdict("SecurityAgent", Status.BLOCK)], approval=self.approval()))
        self.assertEqual(v.status, Status.BLOCK)
        self.assertEqual(client.dispatches, [])

    def test_not_configured_records_only(self):
        agent = DeployAgent(make_settings(deploy_workflow=""), FakeGitHub())
        v = agent.run(ctx(approval=self.approval()))
        self.assertEqual((v.status, v.data["triggered"]), (Status.PASS, False))

    def test_dispatches_on_head_branch_with_inputs(self):
        agent, client = self.agent(deploy_pass_inputs=True)
        v = agent.run(ctx(approval=self.approval()))
        self.assertTrue(v.data["triggered"])
        self.assertEqual(client.dispatches, [("me/r", "deploy.yml", "feature", {"sha": SHA_A, "pr": "7"})])

    def test_dispatch_failure_escalates_and_never_claims_success(self):
        client = FakeGitHub()
        client.fail_dispatch = True
        agent, _ = self.agent(client)
        v = agent.run(ctx(approval=self.approval()))
        self.assertEqual((v.status, v.data["triggered"]), (Status.ESCALATE, False))


if __name__ == "__main__":
    unittest.main()
