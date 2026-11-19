"""Small helpers shared by the pipeline tests."""

from __future__ import annotations

import io
import shutil
import tarfile
import tempfile
from pathlib import Path

from pipeline.config import PipelineSettings
from pipeline.runner import ToolResult


def make_settings(**overrides) -> PipelineSettings:
    values = dict(github_token="test-token", allow_pr_code_execution=False, only_changed_lines=True,
                  stop_on_block=True, tool_timeout=5, slow_tool_timeout=5, max_download_mb=10,
                  max_files=1000, enable_semgrep=True, semgrep_config="p/python",
                  post_comments=True, set_status=True, status_context="BrofessorCode review")
    values.update(overrides)
    return PipelineSettings(**values)


def tool_result(stdout: str = "", returncode: int = 0, stderr: str = "",
                timed_out: bool = False, missing: bool = False) -> ToolResult:
    return ToolResult([], returncode, stdout, stderr, timed_out, missing)


def make_repo(test_case, files: dict[str, str]) -> Path:
    root = Path(tempfile.mkdtemp(prefix="bc-test-"))
    test_case.addCleanup(shutil.rmtree, root, True)
    for name, content in files.items():
        path = root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content)
    return root


def make_patch(lines: list[str], start: int = 1) -> str:
    return f"@@ -0,0 +{start},{len(lines)} @@\n" + "\n".join("+" + ln for ln in lines)


def make_tarball(path: Path, members: dict[str, str], top: str = "owner-repo-abc1234") -> None:
    """A tarball shaped like GitHub's: everything lives under one top folder."""
    with tarfile.open(path, "w:gz") as tar:
        top_info = tarfile.TarInfo(top)
        top_info.type = tarfile.DIRTYPE
        tar.addfile(top_info)
        for name, content in members.items():
            data = content.encode()
            info = tarfile.TarInfo(f"{top}/{name}")
            info.size = len(data)
            tar.addfile(info, io.BytesIO(data))
