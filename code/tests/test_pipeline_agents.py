import json
import unittest
from unittest.mock import patch

from pipeline.agents import ScanAgent, SecurityAgent
from pipeline.models import ChangedFile, PipelineContext, PullRequest, Severity, Status
from tests.pipeline_helpers import make_patch, make_repo, make_settings, tool_result

PR = PullRequest("me/r", 1, "a" * 40)


def ctx_for(repo, files):
    return PipelineContext(PR, files, repo)


def runner(**tools):
    """Fake run_tool: answers by tool name and fails loudly if an unexpected tool is called."""
    def run(args, cwd, timeout, env=None):
        name = "pytest" if "pytest" in args else args[0]
        if name not in tools:
            raise AssertionError(f"unexpected tool: {name}")
        return tools[name]
    return run


def ruff_json(code, row, repo, name="a.py", message="problem"):
    return json.dumps([{"code": code, "message": message, "filename": str(repo / name),
                        "location": {"row": row, "column": 1}}])


class ScanAgentTests(unittest.TestCase):
    def agent(self, **kw):
        return ScanAgent(make_settings(**kw))

    def test_lint_warning_on_a_changed_line(self):
        repo = make_repo(self, {"a.py": "import os\nx = 1\n"})
        files = [ChangedFile("a.py", "added", patch=make_patch(["import os", "x = 1"]))]
        with patch("pipeline.agents.scan_agent.run_tool", runner(ruff=tool_result(ruff_json("F401", 1, repo), 1))):
            v = self.agent().run(ctx_for(repo, files))
        self.assertEqual(v.status, Status.WARN)
        self.assertEqual((v.findings[0].file, v.findings[0].line, v.findings[0].tool), ("a.py", 1, "ruff"))

    def test_finding_on_an_untouched_line_is_ignored(self):
        repo = make_repo(self, {"a.py": "x = 1\n"})
        files = [ChangedFile("a.py", "modified", patch=make_patch(["x = 1"]))]
        with patch("pipeline.agents.scan_agent.run_tool", runner(ruff=tool_result(ruff_json("F401", 40, repo), 1))):
            v = self.agent().run(ctx_for(repo, files))
        self.assertEqual(v.status, Status.PASS)
        self.assertEqual(v.findings, [])

    def test_all_lines_count_when_the_patch_is_unknown(self):
        repo = make_repo(self, {"a.py": "x = 1\n"})
        files = [ChangedFile("a.py", "modified", patch=None)]
        with patch("pipeline.agents.scan_agent.run_tool", runner(ruff=tool_result(ruff_json("F401", 40, repo), 1))):
            v = self.agent().run(ctx_for(repo, files))
        self.assertEqual(v.status, Status.WARN)

    def test_syntax_error_blocks(self):
        repo = make_repo(self, {"a.py": "def (:\n"})
        files = [ChangedFile("a.py", "added", patch=make_patch(["def (:"]))]
        with patch("pipeline.agents.scan_agent.run_tool", runner(ruff=tool_result(ruff_json(None, 1, repo), 1))):
            v = self.agent().run(ctx_for(repo, files))
        self.assertEqual(v.status, Status.BLOCK)
        self.assertEqual(v.findings[0].rule, "syntax-error")

    def test_missing_tool_is_never_a_pass(self):
        repo = make_repo(self, {"a.py": "x = 1\n"})
        files = [ChangedFile("a.py", "added", patch=make_patch(["x = 1"]))]
        with patch("pipeline.agents.scan_agent.run_tool", runner(ruff=tool_result(missing=True, returncode=-1))):
            v = self.agent().run(ctx_for(repo, files))
        self.assertEqual(v.status, Status.ESCALATE)
        self.assertIn("ruff: not installed", v.notes)

    def test_tests_are_not_run_unless_allowed(self):
        repo = make_repo(self, {"a.py": "x = 1\n", "test_a.py": "def test_x(): pass\n"})
        files = [ChangedFile("a.py", "added", patch=make_patch(["x = 1"]))]
        with patch("pipeline.agents.scan_agent.run_tool", runner(ruff=tool_result("[]", 0))):
            v = self.agent(allow_pr_code_execution=False).run(ctx_for(repo, files))
        self.assertEqual(v.status, Status.WARN)
        self.assertEqual(v.findings[0].rule, "tests-not-run")

    def test_failing_tests_block(self):
        repo = make_repo(self, {"a.py": "x = 1\n", "test_a.py": "def test_x(): assert False\n"})
        files = [ChangedFile("a.py", "added", patch=make_patch(["x = 1"]))]
        tools = runner(ruff=tool_result("[]", 0), pytest=tool_result("1 failed, 2 passed in 0.1s\n", 1))
        with patch("pipeline.agents.scan_agent.run_tool", tools):
            v = self.agent(allow_pr_code_execution=True).run(ctx_for(repo, files))
        self.assertEqual(v.status, Status.BLOCK)
        self.assertIn("1 failed", v.findings[0].message)

    def test_passing_tests_pass(self):
        repo = make_repo(self, {"a.py": "x = 1\n", "test_a.py": "def test_x(): pass\n"})
        files = [ChangedFile("a.py", "added", patch=make_patch(["x = 1"]))]
        tools = runner(ruff=tool_result("[]", 0), pytest=tool_result("3 passed in 0.1s\n", 0))
        with patch("pipeline.agents.scan_agent.run_tool", tools):
            v = self.agent(allow_pr_code_execution=True).run(ctx_for(repo, files))
        self.assertEqual(v.status, Status.PASS)

    def test_pytest_timeout_escalates(self):
        repo = make_repo(self, {"a.py": "x = 1\n", "test_a.py": "def test_x(): pass\n"})
        files = [ChangedFile("a.py", "added", patch=make_patch(["x = 1"]))]
        tools = runner(ruff=tool_result("[]", 0), pytest=tool_result(timed_out=True, returncode=-1))
        with patch("pipeline.agents.scan_agent.run_tool", tools):
            v = self.agent(allow_pr_code_execution=True).run(ctx_for(repo, files))
        self.assertEqual(v.status, Status.ESCALATE)

    def test_vulnerable_dependency_blocks(self):
        repo = make_repo(self, {"a.py": "x = 1\n", "requirements.txt": "flask==0.5\n"})
        files = [ChangedFile("a.py", "added", patch=make_patch(["x = 1"]))]
        audit = json.dumps({"dependencies": [{"name": "flask", "version": "0.5", "vulns": [
            {"id": "PYSEC-1", "fix_versions": ["2.0"], "description": "bad"}]}]})
        tools = runner(ruff=tool_result("[]", 0), **{"pip-audit": tool_result(audit, 1)})
        with patch("pipeline.agents.scan_agent.run_tool", tools):
            v = self.agent().run(ctx_for(repo, files))
        self.assertEqual(v.status, Status.BLOCK)
        self.assertEqual((v.findings[0].tool, v.findings[0].file), ("pip-audit", "requirements.txt"))
        self.assertIn("2.0", v.findings[0].suggestion)


def bandit_json(repo, severity, confidence, row=1, name="a.py"):
    return json.dumps({"errors": [], "results": [{
        "filename": str(repo / name), "line_number": row, "issue_severity": severity,
        "issue_confidence": confidence, "issue_text": "Use of shell=True", "test_id": "B602",
        "test_name": "subprocess_popen_with_shell_equals_true", "more_info": "https://bandit.example/B602"}]})


FAKE_AWS_KEY = "AKIA" + "ABCDEFGHIJKLMNOP"  # built from parts so this file holds no real-looking secret


class SecurityAgentTests(unittest.TestCase):
    def agent(self, **kw):
        return SecurityAgent(make_settings(**kw))

    def run_with(self, repo, files, bandit=None, semgrep=None, **kw):
        tools = {"bandit": bandit or tool_result("{}", 0),
                 "semgrep": semgrep or tool_result(missing=True, returncode=-1)}
        with patch("pipeline.agents.security_agent.run_tool", runner(**tools)):
            return self.agent(**kw).run(ctx_for(repo, files))

    def test_high_severity_high_confidence_blocks(self):
        repo = make_repo(self, {"a.py": "import subprocess\n"})
        files = [ChangedFile("a.py", "added", patch=make_patch(["import subprocess"]))]
        v = self.run_with(repo, files, bandit=tool_result(bandit_json(repo, "HIGH", "HIGH"), 1))
        self.assertEqual(v.status, Status.BLOCK)
        self.assertEqual(v.findings[0].severity, Severity.CRITICAL)

    def test_medium_finding_is_only_a_warning(self):
        repo = make_repo(self, {"a.py": "x = 1\n"})
        files = [ChangedFile("a.py", "added", patch=make_patch(["x = 1"]))]
        v = self.run_with(repo, files, bandit=tool_result(bandit_json(repo, "MEDIUM", "HIGH"), 1))
        self.assertEqual(v.status, Status.WARN)

    def test_high_severity_with_low_confidence_is_a_warning(self):
        repo = make_repo(self, {"a.py": "x = 1\n"})
        files = [ChangedFile("a.py", "added", patch=make_patch(["x = 1"]))]
        v = self.run_with(repo, files, bandit=tool_result(bandit_json(repo, "HIGH", "LOW"), 1))
        self.assertEqual(v.status, Status.WARN)

    def test_missing_semgrep_is_skipped_not_a_failure(self):
        repo = make_repo(self, {"a.py": "x = 1\n"})
        files = [ChangedFile("a.py", "added", patch=make_patch(["x = 1"]))]
        v = self.run_with(repo, files)
        self.assertEqual(v.status, Status.PASS)
        self.assertIn("semgrep: not installed, skipped", v.notes)

    def test_semgrep_that_fails_escalates(self):
        repo = make_repo(self, {"a.py": "x = 1\n"})
        files = [ChangedFile("a.py", "added", patch=make_patch(["x = 1"]))]
        v = self.run_with(repo, files, semgrep=tool_result(returncode=2, stderr="rules download failed"))
        self.assertEqual(v.status, Status.ESCALATE)

    def test_semgrep_findings_are_mapped(self):
        repo = make_repo(self, {"a.py": "x = 1\n"})
        files = [ChangedFile("a.py", "added", patch=make_patch(["x = 1"]))]
        out = json.dumps({"results": [{"check_id": "python.eval", "path": "a.py", "start": {"line": 1},
                                       "extra": {"message": "eval is dangerous", "severity": "ERROR"}}]})
        v = self.run_with(repo, files, semgrep=tool_result(out, 0))
        self.assertEqual(v.status, Status.WARN)
        self.assertEqual(v.findings[0].severity, Severity.HIGH)

    def test_secret_in_added_line_blocks_and_is_redacted(self):
        repo = make_repo(self, {"config.txt": f"aws = {FAKE_AWS_KEY}\n"})
        files = [ChangedFile("config.txt", "added", patch=make_patch([f"aws = {FAKE_AWS_KEY}"]))]
        v = self.run_with(repo, files)
        self.assertEqual(v.status, Status.BLOCK)
        self.assertEqual(v.findings[0].rule, "aws-access-key-id")
        self.assertEqual(v.findings[0].line, 1)
        for f in v.findings:
            self.assertNotIn(FAKE_AWS_KEY, f.message)

    def test_secret_that_was_only_removed_is_not_reported(self):
        repo = make_repo(self, {"config.txt": "clean\n"})
        patch_text = f"@@ -1,1 +1,1 @@\n-aws = {FAKE_AWS_KEY}\n+clean"
        v = self.run_with(repo, [ChangedFile("config.txt", "modified", patch=patch_text)])
        self.assertEqual(v.status, Status.PASS)

    def test_placeholder_credentials_and_env_templates_are_not_flagged(self):
        repo = make_repo(self, {"s.py": "x\n", ".env.example": "A=1\n"})
        files = [ChangedFile("s.py", "added", patch=make_patch(['password = "your-password-here"'])),
                 ChangedFile(".env.example", "added", patch=make_patch(["A=1"]))]
        v = self.run_with(repo, files, bandit=tool_result("{}", 0))
        self.assertEqual(v.findings, [])

    def test_real_looking_password_and_env_file_are_flagged(self):
        repo = make_repo(self, {"s.py": "x\n", ".env": "A=1\n"})
        files = [ChangedFile("s.py", "added", patch=make_patch(['password = "hunter2hunter2"'])),
                 ChangedFile(".env", "added", patch=make_patch(["A=1"]))]
        v = self.run_with(repo, files, bandit=tool_result("{}", 0))
        self.assertEqual({f.rule for f in v.findings}, {"hardcoded-credential", "env-file-committed"})
        self.assertEqual(v.status, Status.WARN)


if __name__ == "__main__":
    unittest.main()
