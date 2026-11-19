"""start_all.py --ngrok: webhook-only ngrok on a fixed address (fake ngrok / osascript programs, no real tunnel)."""

from __future__ import annotations

import json
import os
import shutil
import signal
import socket
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path
from types import SimpleNamespace

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from pipeline.ngrok_window import applescript, can_open_window, open_in_terminal, webhook_command  # noqa: E402


def free_port() -> int:
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


class WindowTests(unittest.TestCase):
    def test_command_has_the_port_and_the_fixed_address(self):
        self.assertEqual(webhook_command(5001, "https://me.ngrok-free.app"),
                         ["ngrok", "http", "5001", "--url", "https://me.ngrok-free.app"])
        self.assertEqual(webhook_command(5001, ""), ["ngrok", "http", "5001"])

    def test_applescript_opens_terminal_and_runs_the_command(self):
        script = applescript(["ngrok", "http", "5001", "--url", "https://me.ngrok-free.app"])
        self.assertIn('tell application "Terminal"', script)
        self.assertIn('do script "ngrok http 5001 --url https://me.ngrok-free.app"', script)

    def test_applescript_cannot_be_broken_out_of(self):
        script = applescript(["ngrok", 'x" & (do shell script "id") & "', "a\\b"])
        body = script.split('do script "', 1)[1].rsplit('"\nend tell', 1)[0]
        self.assertNotIn('"', body.replace('\\"', ""))   # every quote inside the string is escaped
        self.assertIn("\\\\", body)                        # and the backslash too

    def test_only_on_a_mac_with_osascript(self):
        self.assertTrue(can_open_window("darwin", which=lambda _: "/usr/bin/osascript"))
        self.assertFalse(can_open_window("darwin", which=lambda _: None))
        self.assertFalse(can_open_window("linux", which=lambda _: "/usr/bin/osascript"))
        self.assertFalse(can_open_window("win32", which=lambda _: "x"))

    def test_open_reports_success_and_failure(self):
        ok = lambda *a, **k: SimpleNamespace(returncode=0, stderr="")  # noqa: E731
        bad = lambda *a, **k: SimpleNamespace(returncode=1, stderr="line\nnot allowed to control Terminal")  # noqa: E731

        def boom(*a, **k):
            raise FileNotFoundError("osascript")
        self.assertIsNone(open_in_terminal(["ngrok"], run=ok))
        self.assertIn("not allowed", open_in_terminal(["ngrok"], run=bad))
        self.assertIn("FileNotFoundError", open_in_terminal(["ngrok"], run=boom))


class StartAllNgrokTests(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix="bc-ngrok-"))
        self.addCleanup(shutil.rmtree, self.tmp, True)
        self.bin = self.tmp / "bin"
        self.bin.mkdir()
        self.web_port = free_port()

    def env(self, **extra):
        env = {k: v for k, v in os.environ.items() if not k.startswith(("NGROK_", "TRUST_PROXY", "DASHBOARD_URL", "OLLAMA"))}
        env.update(PORT=str(self.web_port), DASHBOARD_PORT=str(free_port()), GATEWAY_PORT=str(free_port()),
                   DASHBOARD_SECRET_KEY="k" * 32, GITHUB_WEBHOOK_SECRET="s", GITHUB_TOKEN="github_pat_x",
                   DB_PATH=str(self.tmp / "t.db"), PATH=str(self.bin), LLM_ENABLED="false")
        env.update(extra)
        return env

    def start_all(self, *args, **env):
        return subprocess.Popen([sys.executable, str(ROOT / "scripts" / "start_all.py"), "--force", *args], cwd=ROOT,
                                env=self.env(**env), stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)

    def fake(self, name):
        """A fake program that records its arguments and then waits."""
        log = self.tmp / f"{name}.json"
        script = self.bin / name
        script.write_text(f"#!{sys.executable}\nimport json, sys, time\n"
                          f"json.dump(sys.argv[1:], open({str(log)!r}, 'w'))\n"
                          f"print('fake {name} running', flush=True)\ntime.sleep(600)\n")
        script.chmod(0o755)
        return log

    def test_refuses_when_ngrok_is_not_installed(self):
        out, _ = self.start_all("--ngrok", NGROK_URL="me.ngrok-free.app").communicate(timeout=30)
        self.assertIn("ngrok is not installed", out)
        self.assertNotIn("[webhook]", out)

    def test_refuses_a_bad_address(self):
        self.fake("ngrok")
        out, _ = self.start_all("--ngrok", NGROK_URL="not a host!").communicate(timeout=30)
        self.assertIn("Cannot start ngrok", out)
        self.assertNotIn("[webhook]", out)

    def test_ngrok_and_tunnel_together_are_refused(self):
        self.fake("ngrok")
        p = self.start_all("--ngrok", "--tunnel", NGROK_URL="me.ngrok-free.app", NGROK_ALLOWED_EMAILS="a@b.com")
        out, _ = p.communicate(timeout=30)
        self.assertEqual(p.returncode, 1)
        self.assertIn("Choose one", out)

    def _run_for(self, secs, *args, **env):
        p = self.start_all(*args, **env)
        time.sleep(secs)
        p.send_signal(signal.SIGTERM)
        out, _ = p.communicate(timeout=30)
        return out

    def _need_tree(self):
        if not (ROOT / "webhook" / "app.py").exists():
            self.skipTest("needs the webhook/ folder next to this code (the merged project tree)")
        if sys.platform == "darwin":
            self.skipTest("on a Mac this would open a Terminal window; the window path is covered by WindowTests")

    def test_without_an_address_it_is_plain_ngrok_http_port(self):
        self._need_tree()
        log = self.fake("ngrok")
        out = self._run_for(4, "--ngrok")
        self.assertEqual(json.loads(log.read_text())[:2], ["http", str(self.web_port)])
        self.assertNotIn("--url", log.read_text())
        self.assertNotIn("random address", out)

    def test_start_ngrok_in_the_env_file_starts_it_without_a_flag(self):
        self._need_tree()
        log = self.fake("ngrok")
        self._run_for(4, START_NGROK="true")
        self.assertEqual(json.loads(log.read_text())[:2], ["http", str(self.web_port)])

    def test_no_ngrok_flag_wins_and_the_default_is_off(self):
        self._need_tree()
        log = self.fake("ngrok")
        self._run_for(3, "--no-ngrok", START_NGROK="true")
        self.assertFalse(log.exists())
        self._run_for(3)
        self.assertFalse(log.exists())

    def test_start_ngrok_without_ngrok_installed_only_warns(self):
        self._need_tree()
        out = self._run_for(3, START_NGROK="true")
        self.assertIn("ngrok is not installed", out)
        self.assertIn("[webhook]", out)

    def test_runs_ngrok_for_the_webhook_port_on_the_fixed_address(self):
        if not (ROOT / "webhook" / "app.py").exists():
            self.skipTest("needs the webhook/ folder next to this code (the merged project tree)")
        mac = sys.platform == "darwin"
        # On a Mac the launcher opens a Terminal window through osascript: a fake one records the script instead.
        log = self.fake("osascript" if mac else "ngrok")
        if mac:
            self.fake("ngrok")
        p = self.start_all("--ngrok", NGROK_URL="https://Me.ngrok-free.app/")
        deadline = time.time() + 30
        while time.time() < deadline and not log.exists():
            time.sleep(0.1)
        time.sleep(1.5)
        p.send_signal(signal.SIGTERM)
        out, _ = p.communicate(timeout=30)
        args = json.loads(log.read_text())
        if mac:
            self.assertIn(f"ngrok http {self.web_port} --url https://me.ngrok-free.app", args[-1])
            self.assertIn("own Terminal window", out)
        else:
            self.assertEqual(args[:5], ["http", str(self.web_port), "--url", "https://me.ngrok-free.app", "--log"])
        self.assertIn("GitHub webhook Payload URL: https://me.ngrok-free.app/webhook", out)
        self.assertIn("[webhook]", out)
        left = subprocess.run(["pgrep", "-f", str(self.bin / "ngrok")], capture_output=True, text=True, check=False).stdout.strip()
        if not mac:
            self.assertEqual(left, "", "the child ngrok was left running")


if __name__ == "__main__":
    unittest.main()
