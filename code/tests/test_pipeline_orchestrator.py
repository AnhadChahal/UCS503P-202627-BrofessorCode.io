import logging
import unittest
from pathlib import Path

from pipeline.agents.base import Agent
from pipeline.github_client import GitHubError
from pipeline.models import ChangedFile, Finding, PullRequest, Severity, Status, Verdict
from pipeline.orchestrator import decide_overall, github_state, run_pipeline
from pipeline.report import MARKER, build_report
from tests.pipeline_helpers import make_settings, make_tarball

PR = PullRequest("me/r", 7, "abcdef1234567890" * 2 + "abcd", "main", "feature", "A change", "dev", "http://pr")


class FakeClient:
    def __init__(self, files=None, fail_files=False, fail_comment=False, fail_status=False):
        self.files = files if files is not None else [ChangedFile("a.py", "added", patch="@@ -0,0 +1,1 @@\n+x = 1")]
        self.fail_files, self.fail_comment, self.fail_status = fail_files, fail_comment, fail_status
        self.comments: list[str] = []
        self.statuses: list[tuple[str, str]] = []

    def list_pr_files(self, repo, number):
        if self.fail_files:
            raise GitHubError("GET files -> HTTP 404")
        return self.files

    def download_tarball(self, repo, sha, dest, max_bytes):
        make_tarball(Path(dest), {"a.py": "x = 1\n"})
        return 1

    def upsert_comment(self, repo, number, marker, body):
        if self.fail_comment:
            raise GitHubError("comment failed")
        self.comments.append(body)
        return "http://comment"

    def set_commit_status(self, repo, sha, state, description, context, target_url=None):
        if self.fail_status:
            raise GitHubError("status failed")
        self.statuses.append((state, description))


class StubAgent(Agent):
    def __init__(self, name, status=Status.PASS, findings=None):
        self.name, self.status, self.findings, self.calls = name, status, findings or [], 0

    def run(self, ctx):
        self.calls += 1
        return Verdict(self.name, self.status, self.findings, "stub", ["stub check"])


class CrashAgent(Agent):
    name = "CrashAgent"

    def run(self, ctx):
        raise RuntimeError("boom")


class RecordingAgent(Agent):
    name = "RecordingAgent"

    def run(self, ctx):
        self.seen_dir = ctx.repo_dir
        self.had_file = (ctx.repo_dir / "a.py").is_file()
        return Verdict(self.name, Status.PASS)


def finding(sev=Severity.HIGH):
    return Finding("StubAgent", "tool", "rule-1", sev, "something is wrong | with a pipe", "a.py", 3)


class RunPipelineTests(unittest.TestCase):
    def setUp(self):
        logging.disable(logging.CRITICAL)  # some tests inject failures on purpose
        self.addCleanup(logging.disable, logging.NOTSET)

    def run_it(self, agents, client=None, **settings):
        client = client or FakeClient()
        result = run_pipeline(PR, client=client, agents=agents, settings=make_settings(**settings))
        return result, client

    def test_all_pass(self):
        result, client = self.run_it([StubAgent("A"), StubAgent("B")])
        self.assertEqual(result.overall, "PASS")
        self.assertEqual([s[0] for s in client.statuses], ["pending", "success"])
        self.assertIn(MARKER, client.comments[0])
        self.assertIn("Passed", client.comments[0])

    def test_warnings_still_succeed(self):
        result, client = self.run_it([StubAgent("A", Status.WARN, [finding(Severity.LOW)])])
        self.assertEqual(result.overall, "WARN")
        self.assertEqual(client.statuses[-1][0], "success")

    def test_block_stops_later_agents(self):
        blocker, later = StubAgent("Blocker", Status.BLOCK, [finding()]), StubAgent("Later")
        result, client = self.run_it([blocker, later])
        self.assertEqual(result.overall, "BLOCK")
        self.assertEqual(later.calls, 0)
        self.assertEqual(client.statuses[-1][0], "failure")
        self.assertIn("Blocked by Blocker", client.statuses[-1][1])

    def test_block_can_be_configured_not_to_stop(self):
        later = StubAgent("Later")
        self.run_it([StubAgent("Blocker", Status.BLOCK, [finding()]), later], stop_on_block=False)
        self.assertEqual(later.calls, 1)

    def test_crashing_agent_is_treated_as_needing_a_human(self):
        after = StubAgent("After")
        result, client = self.run_it([CrashAgent(), after])
        self.assertEqual(result.overall, "ESCALATE")
        self.assertEqual(after.calls, 1)  # the pipeline carries on
        self.assertEqual(client.statuses[-1], ("failure", "Needs human review"))
        self.assertIn("crashed", client.comments[0])

    def test_error_while_fetching_fails_closed(self):
        result, client = self.run_it([StubAgent("A")], client=FakeClient(fail_files=True))
        self.assertEqual(result.overall, "FAILED")
        self.assertEqual(client.statuses[-1][0], "error")
        self.assertIn("could not be completed", client.comments[0])
        self.assertIn("not** been approved", client.comments[0])

    def test_no_agents_is_not_a_pass(self):
        result, _ = self.run_it([])
        self.assertEqual(result.overall, "ESCALATE")

    def test_workspace_exists_during_the_run_and_is_removed_after(self):
        agent = RecordingAgent()
        self.run_it([agent])
        self.assertTrue(agent.had_file)
        self.assertFalse(agent.seen_dir.exists())
        self.assertFalse(agent.seen_dir.parent.exists())

    def test_publishing_problems_do_not_crash_the_run(self):
        result, _ = self.run_it([StubAgent("A")], client=FakeClient(fail_comment=True, fail_status=True))
        self.assertEqual(result.overall, "PASS")

    def test_comment_and_status_can_be_switched_off(self):
        _, client = self.run_it([StubAgent("A")], post_comments=False, set_status=False)
        self.assertEqual((client.comments, client.statuses), ([], []))

    def test_missing_token_without_a_client_is_an_error(self):
        with self.assertRaises(RuntimeError):
            run_pipeline(PR, agents=[], settings=make_settings(github_token=""))


class DecisionTests(unittest.TestCase):
    def test_worst_verdict_wins(self):
        v = lambda s: Verdict("x", s)
        self.assertEqual(decide_overall([v(Status.PASS), v(Status.WARN)]), "WARN")
        self.assertEqual(decide_overall([v(Status.WARN), v(Status.ESCALATE)]), "ESCALATE")
        self.assertEqual(decide_overall([v(Status.ESCALATE), v(Status.BLOCK), v(Status.PASS)]), "BLOCK")

    def test_status_mapping(self):
        self.assertEqual(github_state("PASS", [])[0], "success")
        self.assertEqual(github_state("ESCALATE", [])[0], "failure")
        self.assertEqual(github_state("FAILED", [])[0], "error")


class ReportTests(unittest.TestCase):
    def test_table_cells_are_safe_and_ordered_by_severity(self):
        verdicts = [Verdict("StubAgent", Status.BLOCK, [finding(Severity.LOW), finding(Severity.CRITICAL)], "", ["n"])]
        text = build_report(PR, verdicts, "BLOCK", 2, 3.2)
        self.assertIn("something is wrong \\| with a pipe", text)
        self.assertLess(text.index("CRITICAL"), text.index("| LOW"))
        self.assertIn("`a.py:3`", text)
        self.assertTrue(text.startswith(MARKER))

    def test_long_lists_are_cut(self):
        many = [Finding("A", "t", f"r{i}", Severity.LOW, "m", "f.py", i) for i in range(1, 45)]
        text = build_report(PR, [Verdict("A", Status.WARN, many)], "WARN", 1, 1)
        self.assertIn("and 14 more finding(s)", text)


if __name__ == "__main__":
    unittest.main()
