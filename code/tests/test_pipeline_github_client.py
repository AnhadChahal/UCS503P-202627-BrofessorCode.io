import tempfile
import unittest
from pathlib import Path

from pipeline.github_client import GitHubClient, GitHubError


class FakeResponse:
    def __init__(self, data=None, status=200, chunks=()):
        self._data, self.status_code, self._chunks, self.text = data, status, chunks, str(data)

    def json(self):
        return self._data

    def iter_content(self, chunk_size=0):
        return iter(self._chunks)


class FakeSession:
    def __init__(self, responses):
        self.responses, self.calls = list(responses), []

    def request(self, method, url, **kwargs):
        self.calls.append((method, url, kwargs))
        return self.responses.pop(0)

    def get(self, url, **kwargs):
        self.calls.append(("GET", url, kwargs))
        return self.responses.pop(0)


def api_file(i):
    return {"filename": f"f{i}.py", "status": "added", "additions": 1, "deletions": 0, "patch": "@@ -0,0 +1 @@\n+x"}


class ClientTests(unittest.TestCase):
    def test_list_files_follows_pages(self):
        session = FakeSession([FakeResponse([api_file(i) for i in range(100)]), FakeResponse([api_file(100)])])
        files = GitHubClient("tok", session).list_pr_files("me/r", 7)
        self.assertEqual(len(files), 101)
        self.assertEqual(session.calls[1][2]["params"]["page"], 2)
        self.assertEqual(files[0].patch, "@@ -0,0 +1 @@\n+x")

    def test_authorization_header_is_sent(self):
        session = FakeSession([FakeResponse([])])
        GitHubClient("tok", session).list_pr_files("me/r", 7)
        self.assertEqual(session.calls[0][2]["headers"]["Authorization"], "Bearer tok")

    def test_http_errors_raise_without_leaking_the_token(self):
        session = FakeSession([FakeResponse({"message": "Not Found"}, status=404)])
        with self.assertRaises(GitHubError) as ctx:
            GitHubClient("tok-secret", session).list_pr_files("me/r", 7)
        self.assertIn("404", str(ctx.exception))
        self.assertNotIn("tok-secret", str(ctx.exception))

    def test_comment_is_created_when_none_exists(self):
        session = FakeSession([FakeResponse([{"id": 1, "body": "someone else"}]), FakeResponse({"html_url": "u"})])
        url = GitHubClient("t", session).upsert_comment("me/r", 7, "<!-- m -->", "body")
        self.assertEqual((session.calls[1][0], url), ("POST", "u"))

    def test_existing_comment_is_updated(self):
        session = FakeSession([FakeResponse([{"id": 42, "body": "<!-- m --> old"}]), FakeResponse({"html_url": "u"})])
        GitHubClient("t", session).upsert_comment("me/r", 7, "<!-- m -->", "new body")
        method, url, kwargs = session.calls[1]
        self.assertEqual(method, "PATCH")
        self.assertTrue(url.endswith("/issues/comments/42"))
        self.assertEqual(kwargs["json"], {"body": "new body"})

    def test_status_description_is_cut_to_140_characters(self):
        session = FakeSession([FakeResponse({})])
        GitHubClient("t", session).set_commit_status("me/r", "abc", "success", "x" * 300, "ctx")
        self.assertEqual(len(session.calls[0][2]["json"]["description"]), 140)

    def test_download_writes_the_archive_and_enforces_the_limit(self):
        dest = Path(tempfile.mkdtemp()) / "a.tar.gz"
        client = GitHubClient("t", FakeSession([FakeResponse(chunks=[b"abc", b"def"])]))
        self.assertEqual(client.download_tarball("me/r", "abc1234", dest, 100), 6)
        self.assertEqual(dest.read_bytes(), b"abcdef")
        client = GitHubClient("t", FakeSession([FakeResponse(chunks=[b"abc", b"def"])]))
        with self.assertRaises(GitHubError):
            client.download_tarball("me/r", "abc1234", dest, 4)


if __name__ == "__main__":
    unittest.main()
