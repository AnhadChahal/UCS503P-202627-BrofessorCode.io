import os
import sys
import tempfile
import time
import unittest
from pathlib import Path
from unittest.mock import patch

from pipeline.runner import clean_env, run_tool


class RunToolTests(unittest.TestCase):
    def setUp(self):
        self.cwd = Path(tempfile.gettempdir())

    def test_runs_a_program_and_captures_output(self):
        res = run_tool([sys.executable, "-c", "print('hi')"], self.cwd, 10)
        self.assertEqual((res.returncode, res.stdout.strip()), (0, "hi"))

    def test_nonzero_exit_code_is_returned(self):
        res = run_tool([sys.executable, "-c", "import sys; sys.exit(3)"], self.cwd, 10)
        self.assertEqual(res.returncode, 3)

    def test_missing_program_is_reported(self):
        res = run_tool(["definitely-not-a-real-tool-xyz"], self.cwd, 5)
        self.assertTrue(res.missing)

    def test_timeout_stops_the_program(self):
        started = time.monotonic()
        res = run_tool([sys.executable, "-c", "import time; time.sleep(30)"], self.cwd, 1)
        self.assertTrue(res.timed_out)
        self.assertLess(time.monotonic() - started, 10)

    def test_secrets_in_the_environment_are_not_passed_on(self):
        with patch.dict(os.environ, {"GITHUB_TOKEN": "super-secret", "GITHUB_WEBHOOK_SECRET": "also-secret"}):
            res = run_tool([sys.executable, "-c",
                            "import os; print(os.environ.get('GITHUB_TOKEN'), os.environ.get('GITHUB_WEBHOOK_SECRET'))"],
                           self.cwd, 10)
        self.assertEqual(res.stdout.strip(), "None None")

    def test_clean_env_only_keeps_safe_variables(self):
        with patch.dict(os.environ, {"GITHUB_TOKEN": "x", "PATH": "/usr/bin"}):
            env = clean_env("/tmp/home")
        self.assertNotIn("GITHUB_TOKEN", env)
        self.assertEqual(env["HOME"], "/tmp/home")


if __name__ == "__main__":
    unittest.main()
