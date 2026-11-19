"""start_all.py --ollama / --all: the launcher starts `ollama serve` only when needed (a fake `ollama` program,
no real model server, nothing is downloaded)."""

from __future__ import annotations

import json
import os
import shutil
import signal
import socket
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from types import SimpleNamespace

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from pipeline.llm import LLMError, OllamaClient  # noqa: E402
from pipeline.ollama_run import plan_ollama, wait_until_answers, warm_model  # noqa: E402


def free_port() -> int:
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


class FakeOllama(BaseHTTPRequestHandler):
    """Answers like Ollama on /api/tags and /api/generate; remembers what was asked."""
    seen: list = []

    def log_message(self, *a):  # noqa: D401
        pass

    def do_GET(self):  # noqa: N802
        body = json.dumps({"models": [{"name": "qwen2.5-coder:7b"}]}).encode()
        self.send_response(200)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_POST(self):  # noqa: N802
        n = int(self.headers.get("Content-Length", 0))
        type(self).seen.append((self.path, json.loads(self.rfile.read(n) or b"{}")))
        self.send_response(200)
        self.send_header("Content-Length", "2")
        self.end_headers()
        self.wfile.write(b"{}")


def settings(port: int, **over):
    base = dict(ollama_url=f"http://127.0.0.1:{port}", llm_timeout=5, llm_keep_alive="10m", llm_allow_remote=False,
                llm_enabled=True, llm_model="qwen2.5-coder:7b")
    base.update(over)
    return SimpleNamespace(**base)


class PlanTests(unittest.TestCase):
    def test_a_running_ollama_is_left_alone(self):
        FakeOllama.seen = []
        srv = HTTPServer(("127.0.0.1", 0), FakeOllama)
        threading.Thread(target=srv.serve_forever, daemon=True).start()
        self.addCleanup(srv.shutdown)
        plan = plan_ollama(settings(srv.server_port), which=lambda _: None)   # not even installed: still "already"
        self.assertEqual(plan.action, "already")
        self.assertEqual(plan.command, [])

    def test_not_running_and_installed_means_start(self):
        plan = plan_ollama(settings(free_port()), which=lambda _: "/usr/bin/ollama")
        self.assertEqual(plan.action, "start")
        self.assertEqual(plan.command, ["/usr/bin/ollama", "serve"])
        self.assertTrue(plan.env["OLLAMA_HOST"].startswith("127.0.0.1:"))   # a non-default port is passed on

    def test_the_default_port_needs_no_override(self):
        plan = plan_ollama(settings(11434), which=lambda _: "/usr/bin/ollama")
        if plan.action == "start":   # (skipped when a real Ollama happens to run on this machine)
            self.assertEqual(plan.env, {})

    def test_not_installed_is_reported(self):
        plan = plan_ollama(settings(free_port()), which=lambda _: None)
        self.assertEqual(plan.action, "missing")
        self.assertIn("not installed", plan.message)

    def test_a_remote_address_is_never_started(self):
        s = settings(11434, ollama_url="http://gpu-box.example:11434")
        plan = plan_ollama(s, which=lambda _: "/usr/bin/ollama")
        self.assertEqual(plan.action, "remote")
        self.assertEqual(plan.command, [])

    def test_waiting_gives_up_when_the_process_died(self):
        calls = []
        ok = wait_until_answers(settings(free_port()), timeout=5, alive=lambda: False, sleep=calls.append)
        self.assertFalse(ok)
        self.assertEqual(calls, [])   # it did not keep waiting


class WarmTests(unittest.TestCase):
    def setUp(self):
        FakeOllama.seen = []
        self.srv = HTTPServer(("127.0.0.1", 0), FakeOllama)
        threading.Thread(target=self.srv.serve_forever, daemon=True).start()
        self.addCleanup(self.srv.shutdown)

    def test_loads_the_configured_model(self):
        msg = warm_model(settings(self.srv.server_port))
        self.assertIn("loaded", msg)
        path, body = FakeOllama.seen[-1]
        self.assertEqual(path, "/api/generate")
        self.assertEqual(body["model"], "qwen2.5-coder:7b")
        self.assertNotIn("prompt", body)   # nothing is asked: the model is only loaded

    def test_says_so_when_the_model_is_missing(self):
        msg = warm_model(settings(self.srv.server_port, llm_model="other:1b"))
        self.assertIn("ollama pull other:1b", msg)
        self.assertEqual(FakeOllama.seen, [])

    def test_does_nothing_when_the_llm_is_off(self):
        msg = warm_model(settings(self.srv.server_port, llm_enabled=False))
        self.assertIn("LLM_ENABLED", msg)
        self.assertEqual(FakeOllama.seen, [])

    def test_client_warm_reports_failure(self):
        with self.assertRaises(LLMError):
            OllamaClient(f"http://127.0.0.1:{free_port()}", timeout=1).warm("m")


class StartAllOllamaTests(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix="bc-ollama-"))
        self.addCleanup(shutil.rmtree, self.tmp, True)
        self.bin = self.tmp / "bin"
        self.bin.mkdir()
        self.ollama_port = free_port()

    def env(self, **extra):
        env = {k: v for k, v in os.environ.items() if not k.startswith(("NGROK_", "TRUST_PROXY", "DASHBOARD_URL", "OLLAMA"))}
        env.update(PORT=str(free_port()), DASHBOARD_PORT=str(free_port()), GATEWAY_PORT=str(free_port()),
                   DASHBOARD_SECRET_KEY="k" * 32, GITHUB_WEBHOOK_SECRET="s", GITHUB_TOKEN="github_pat_x",
                   DB_PATH=str(self.tmp / "t.db"), PATH=str(self.bin), LLM_ENABLED="false",
                   OLLAMA_URL=f"http://127.0.0.1:{self.ollama_port}")
        env.update(extra)
        return env

    def start_all(self, *args, **env):
        return subprocess.Popen([sys.executable, str(ROOT / "scripts" / "start_all.py"), "--force", *args], cwd=ROOT,
                                env=self.env(**env), stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)

    def fake_ollama(self):
        """A fake `ollama serve`: listens where OLLAMA_HOST says and answers /api/tags."""
        log = self.tmp / "ollama-args.json"
        script = self.bin / "ollama"
        script.write_text(f"""#!{sys.executable}
import json, os, sys
from http.server import BaseHTTPRequestHandler, HTTPServer
json.dump({{"args": sys.argv[1:], "host": os.environ.get("OLLAMA_HOST")}}, open({str(log)!r}, "w"))
class H(BaseHTTPRequestHandler):
    def log_message(self, *a): pass
    def do_GET(self):
        b = b'{{"models": []}}'
        self.send_response(200); self.send_header("Content-Length", str(len(b))); self.end_headers(); self.wfile.write(b)
print("fake ollama serving", flush=True)
print("[GIN] 2026/11/19 - 20:22:50 | 200 | 6.7us | 127.0.0.1 | GET /api/ps", flush=True)
host, port = os.environ["OLLAMA_HOST"].rsplit(":", 1)
HTTPServer((host, int(port)), H).serve_forever()
""")
        script.chmod(0o755)
        return log

    def test_refuses_when_ollama_is_not_installed(self):
        p = self.start_all("--ollama")
        out, _ = p.communicate(timeout=30)
        self.assertEqual(p.returncode, 1)
        self.assertIn("ollama is not installed", out)
        self.assertNotIn("[webhook]", out)

    def test_starts_ollama_and_stops_it_with_everything_else(self):
        if not (ROOT / "webhook" / "app.py").exists():
            self.skipTest("needs the webhook/ folder next to this code (the merged project tree)")
        log = self.fake_ollama()
        p = self.start_all("--ollama")
        deadline = time.time() + 30
        while time.time() < deadline and not log.exists():
            time.sleep(0.1)
        self.assertTrue(log.exists(), "fake ollama was never started")
        time.sleep(1.5)
        p.send_signal(signal.SIGTERM)
        out, _ = p.communicate(timeout=30)
        seen = json.loads(log.read_text())
        self.assertEqual(seen["args"], ["serve"])
        self.assertEqual(seen["host"], f"127.0.0.1:{self.ollama_port}")
        self.assertIn("[ollama] fake ollama serving", out)
        self.assertNotIn("[GIN]", out)           # request noise is filtered
        self.assertIn("Ollama answers.", out)
        self.assertIn("[webhook]", out)
        left = subprocess.run(["pgrep", "-f", str(self.bin / "ollama")], capture_output=True, text=True).stdout.strip()
        self.assertEqual(left, "", "the fake ollama was left running")

    def _run_for(self, secs, *args, **env):
        p = self.start_all(*args, **env)
        time.sleep(secs)
        p.send_signal(signal.SIGTERM)
        out, _ = p.communicate(timeout=30)
        return out

    def test_started_by_default_when_the_llm_is_enabled(self):
        if not (ROOT / "webhook" / "app.py").exists():
            self.skipTest("needs the webhook/ folder next to this code (the merged project tree)")
        log = self.fake_ollama()
        out = self._run_for(5, LLM_ENABLED="true")       # no --ollama flag
        self.assertTrue(log.exists())
        self.assertIn("Ollama answers.", out)
        self.assertIn("[webhook]", out)

    def test_missing_ollama_is_only_a_warning_by_default(self):
        if not (ROOT / "webhook" / "app.py").exists():
            self.skipTest("needs the webhook/ folder next to this code (the merged project tree)")
        out = self._run_for(3, LLM_ENABLED="true")
        self.assertIn("ollama is not installed", out)
        self.assertIn("[webhook]", out)                  # ... and the system started anyway

    def test_no_ollama_flag_and_llm_off_start_nothing(self):
        if not (ROOT / "webhook" / "app.py").exists():
            self.skipTest("needs the webhook/ folder next to this code (the merged project tree)")
        log = self.fake_ollama()
        self._run_for(3, "--no-ollama", LLM_ENABLED="true")
        self.assertFalse(log.exists())
        self._run_for(3, LLM_ENABLED="false")
        self.assertFalse(log.exists())

    def test_an_ollama_that_already_runs_is_used_and_not_stopped(self):
        if not (ROOT / "webhook" / "app.py").exists():
            self.skipTest("needs the webhook/ folder next to this code (the merged project tree)")
        FakeOllama.seen = []
        srv = HTTPServer(("127.0.0.1", self.ollama_port), FakeOllama)
        threading.Thread(target=srv.serve_forever, daemon=True).start()
        self.addCleanup(srv.shutdown)
        p = self.start_all("--ollama")        # no ollama program on PATH at all: it must not be needed
        time.sleep(2.5)
        p.send_signal(signal.SIGTERM)
        out, _ = p.communicate(timeout=30)
        self.assertIn("already running", out)
        self.assertIn("[webhook]", out)
        self.assertNotIn("Starting ollama serve", out)   # nothing of ours was started
        self.assertTrue(OllamaClient(f"http://127.0.0.1:{self.ollama_port}").available())   # still up


if __name__ == "__main__":
    unittest.main()
