import unittest

from pipeline.models import ChangedFile, PullRequest, parse_added


PATCH = "\n".join([
    "@@ -1,3 +1,4 @@",
    " import os",
    "+import sys",
    " ",
    "-old = 1",
    "+new = 2",
    "@@ -10,2 +11,3 @@ def f():",
    "     pass",
    "+    return 1",
    "\\ No newline at end of file",
])


class ParseAddedTests(unittest.TestCase):
    def test_line_numbers_follow_the_new_file(self):
        self.assertEqual(parse_added(PATCH), [(2, "import sys"), (4, "new = 2"), (12, "    return 1")])

    def test_empty_patch(self):
        self.assertEqual(parse_added(None), [])
        self.assertEqual(parse_added(""), [])

    def test_unknown_patch_means_whole_file(self):
        self.assertIsNone(ChangedFile("a.py", "modified").added_line_numbers())
        self.assertEqual(ChangedFile("a.py", "modified", patch=PATCH).added_line_numbers(), {2, 4, 12})


class PullRequestTests(unittest.TestCase):
    def test_from_flat_dict(self):
        pr = PullRequest.from_parsed({"repo_full_name": "me/r", "pr_number": "7", "head_sha": "a" * 40, "title": "t"})
        self.assertEqual((pr.repo, pr.number, pr.title), ("me/r", 7, "t"))

    def test_from_raw_webhook_payload(self):
        payload = {"action": "opened", "repository": {"full_name": "me/r"},
                   "pull_request": {"number": 3, "title": "x", "user": {"login": "u"}, "html_url": "http://x",
                                    "base": {"ref": "main"}, "head": {"ref": "f", "sha": "b" * 40}}}
        pr = PullRequest.from_parsed(payload)
        self.assertEqual((pr.repo, pr.number, pr.head_sha, pr.author), ("me/r", 3, "b" * 40, "u"))

    def test_from_object_with_attributes(self):
        class Parsed:
            repo_full_name = "me/r"
            pr_number = 9
            head_sha = "c" * 40
        self.assertEqual(PullRequest.from_parsed(Parsed()).number, 9)

    def test_missing_fields_give_a_clear_error(self):
        with self.assertRaises(ValueError):
            PullRequest.from_parsed({"title": "only a title"})


if __name__ == "__main__":
    unittest.main()
