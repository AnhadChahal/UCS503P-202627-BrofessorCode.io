"""A temporary folder that holds the PR's code. It is deleted when the run ends."""

from __future__ import annotations

import os
import shutil
import stat
import tarfile
import tempfile
from pathlib import Path, PurePosixPath


class UnsafeArchive(RuntimeError):
    """The archive tried something it must not (path traversal, too large, too many files)."""


def _on_rm_error(func, path, _exc):  # read-only files on Windows
    try:
        os.chmod(path, stat.S_IWRITE)
        func(path)
    except OSError:
        pass


class Workspace:
    def __init__(self) -> None:
        self.root = Path(tempfile.mkdtemp(prefix="brofessorcode-"))
        self.repo_dir = self.root / "repo"
        self.repo_dir.mkdir()
        self.archive = self.root / "source.tar.gz"

    def cleanup(self) -> None:
        shutil.rmtree(self.root, onerror=_on_rm_error)

    def __enter__(self) -> "Workspace":
        return self

    def __exit__(self, *exc) -> None:
        self.cleanup()


def safe_extract(archive: Path, dest: Path, max_files: int, max_bytes: int) -> int:
    """Extract a GitHub source tarball into `dest`, dropping the top folder.

    Only regular files and folders are written. Links, devices and anything that
    would leave `dest` are refused, because the archive content is untrusted."""
    dest = dest.resolve()
    files = 0
    total = 0
    with tarfile.open(archive, "r:*") as tar:
        for member in tar:
            if not (member.isfile() or member.isdir()):
                continue  # symlinks, hard links, devices, the pax header
            pure = PurePosixPath(member.name)
            if pure.is_absolute() or any(p == ".." or ":" in p for p in pure.parts):
                raise UnsafeArchive(f"unsafe path in archive: {member.name!r}")
            parts = pure.parts[1:]  # strip the 'owner-repo-sha/' folder
            if not parts:
                continue
            target = (dest.joinpath(*parts)).resolve()
            if dest != target and dest not in target.parents:
                raise UnsafeArchive(f"path escapes the workspace: {member.name!r}")
            if member.isdir():
                target.mkdir(parents=True, exist_ok=True)
                continue
            files += 1
            total += member.size
            if files > max_files:
                raise UnsafeArchive(f"archive has more than {max_files} files")
            if total > max_bytes:
                raise UnsafeArchive("archive is larger than the allowed size")
            target.parent.mkdir(parents=True, exist_ok=True)
            src = tar.extractfile(member)
            if src is None:
                continue
            with src, open(target, "wb") as out:
                shutil.copyfileobj(src, out)
    return files
