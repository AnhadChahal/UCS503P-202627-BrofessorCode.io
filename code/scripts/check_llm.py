"""Check that Ollama is ready for BrofessorCode, without GitHub.

    python scripts/check_llm.py

Reads the same .env as the pipeline (OLLAMA_URL, LLM_MODEL, LLM_HEAVY_MODEL). It checks that the
server answers, that the models are installed, and asks the model one triage question about a
deliberately dangerous snippet and one about a harmless one, so you can see the answers.
"""

from __future__ import annotations

import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from pipeline.agents.triage_agent import SYSTEM, parse_triage, triage_prompt  # noqa: E402
from pipeline.config import load_settings  # noqa: E402
from pipeline.llm import LLMError, OllamaClient  # noqa: E402
from pipeline.models import Finding, Severity  # noqa: E402

CASES = [
    ("dangerous", Finding("SecurityAgent", "bandit", "B602", Severity.HIGH,
                          "subprocess call with shell=True and a variable command", "app.py", 3),
     "import subprocess\n\ndef run(cmd):\n    return subprocess.call(cmd, shell=True)   # cmd comes from a web request"),
    ("harmless", Finding("SecurityAgent", "bandit", "B101", Severity.LOW,
                         "Use of assert detected", "tests/test_x.py", 2),
     "def test_add():\n    assert 1 + 1 == 2"),
]


def main() -> int:
    s = load_settings()
    try:
        client = OllamaClient(s.ollama_url, s.llm_timeout, s.llm_keep_alive, s.llm_allow_remote)
    except LLMError as exc:
        print(f"FAIL  {exc}")
        return 1
    if not client.available():
        print(f"FAIL  Ollama does not answer at {s.ollama_url}. Start it with: ollama serve")
        return 1
    print(f"ok    Ollama answers at {s.ollama_url}")
    models = [s.llm_model] + ([s.llm_heavy_model] if s.llm_heavy_model else [])
    missing = [m for m in models if not client.has_model(m)]
    for m in models:
        print(f"{'ok  ' if m not in missing else 'FAIL'}  model {m}" + ("" if m not in missing else f"  -> ollama pull {m}"))
    if s.llm_model in missing:
        return 1
    status = 0
    for label, finding, code in CASES:
        started = time.monotonic()
        try:
            answer = client.chat_json(s.llm_model, SYSTEM, triage_prompt(finding, code))
            verdict, reason = parse_triage(answer)
            print(f"ok    {label}: {verdict} - {reason}  ({time.monotonic() - started:.1f}s)")
        except LLMError as exc:
            print(f"FAIL  {label}: {exc}")
            status = 1
    client.release()
    print("Models unloaded." if status == 0 else "Done with errors.")
    print("The model's labels are advisory. Expect 'dangerous' -> likely_real and 'harmless' -> likely_false_positive, "
          "but small models can be wrong; that is why a person decides.")
    return status


if __name__ == "__main__":
    sys.exit(main())
