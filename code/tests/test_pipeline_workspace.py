import io
import tarfile
import unittest
from pathlib import Path

from pipeline.workspace import UnsafeArchive, Workspace, safe_extract
from tests.pipeline_helpers import make_tarball


class SafeExtractTests(unittest.TestCase):
    def setUp(self):
        self.ws = Workspace()
        self.addCleanup(self.ws.cleanup)

    def test_strips_top_folder_and_writes_files(self):
        make_tarball(self.ws.archive, {"a.py": "x = 1\n", "pkg/b.py": "y = 2\n"})
        count = safe_extract(self.ws.archive, self.ws.repo_dir, 100, 10_000)
        self.assertEqual(count, 2)
        self.assertEqual((self.ws.repo_dir / "a.py").read_text(), "x = 1\n")
        self.assertTrue((self.ws.repo_dir / "pkg" / "b.py").is_file())

    def test_symlinks_are_skipped(self):
        with tarfile.open(self.ws.archive, "w:gz") as tar:
            link = tarfile.TarInfo("top/link")
            link.type = tarfile.SYMTYPE
            link.linkname = "/etc/passwd"
            tar.addfile(link)
        self.assertEqual(safe_extract(self.ws.archive, self.ws.repo_dir, 100, 10_000), 0)
        self.assertFalse((self.ws.repo_dir / "link").exists())

    def test_path_traversal_is_refused(self):
        with tarfile.open(self.ws.archive, "w:gz") as tar:
            info = tarfile.TarInfo("top/../../evil.py")
            info.size = 1
            tar.addfile(info, io.BytesIO(b"x"))
        with self.assertRaises(UnsafeArchive):
            safe_extract(self.ws.archive, self.ws.repo_dir, 100, 10_000)
        self.assertFalse((self.ws.root.parent / "evil.py").exists())

    def test_absolute_path_is_refused(self):
        with tarfile.open(self.ws.archive, "w:gz") as tar:
            info = tarfile.TarInfo("/tmp/evil.py")
            info.size = 1
            tar.addfile(info, io.BytesIO(b"x"))
        with self.assertRaises(UnsafeArchive):
            safe_extract(self.ws.archive, self.ws.repo_dir, 100, 10_000)

    def test_limits(self):
        make_tarball(self.ws.archive, {f"f{i}.py": "x" for i in range(5)})
        with self.assertRaises(UnsafeArchive):
            safe_extract(self.ws.archive, self.ws.repo_dir, 3, 10_000)
        with self.assertRaises(UnsafeArchive):
            safe_extract(self.ws.archive, self.ws.repo_dir, 100, 2)

    def test_cleanup_removes_everything(self):
        root = Path(self.ws.root)
        (self.ws.repo_dir / "x.txt").write_text("x")
        self.ws.cleanup()
        self.assertFalse(root.exists())


if __name__ == "__main__":
    unittest.main()
