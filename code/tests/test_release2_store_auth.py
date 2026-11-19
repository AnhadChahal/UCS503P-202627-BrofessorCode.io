import sqlite3
import unittest

from pipeline.auth import check_login, hash_password, verify_password
from pipeline.models import Finding, Severity, Status, Verdict
from tests.pipeline_helpers import make_settings
from tests.service_helpers import SHA_A, SHA_B, make_pr, make_store


class Clock:
    def __init__(self, now=1000.0):
        self.now = now

    def __call__(self):
        return self.now


class StoreTests(unittest.TestCase):
    def test_create_run_and_duplicates(self):
        store = make_store(self)
        first = store.create_run(make_pr(), "d1")
        self.assertIsNotNone(first.run_id)
        self.assertEqual(store.create_run(make_pr(), "d1").reason, "duplicate delivery")
        again = store.create_run(make_pr(), "d2")  # same commit, new delivery
        self.assertIsNone(again.run_id)
        self.assertIn("already covers", again.reason)

    def test_new_commit_supersedes_unfinished_runs(self):
        store = make_store(self)
        a = store.create_run(make_pr(SHA_A)).run_id
        sub = store.create_run(make_pr(SHA_B))
        self.assertEqual(sub.superseded, [a])
        self.assertEqual(store.get_run(a)["status"], "superseded")
        self.assertEqual(store.get_run(sub.run_id)["status"], "queued")

    def test_other_pr_is_not_superseded(self):
        store = make_store(self)
        a = store.create_run(make_pr(SHA_A, number=1)).run_id
        store.create_run(make_pr(SHA_B, number=2))
        self.assertEqual(store.get_run(a)["status"], "queued")

    def test_transition_is_atomic(self):
        store = make_store(self)
        rid = store.create_run(make_pr()).run_id
        self.assertTrue(store.transition(rid, ("queued",), "running"))
        self.assertFalse(store.transition(rid, ("queued",), "running"))
        with self.assertRaises(ValueError):
            store.transition(rid, ("running",), "failed", status="x")

    def test_record_decision_is_all_or_nothing(self):
        store = make_store(self)
        rid = store.create_run(make_pr()).run_id
        store.transition(rid, ("queued",), "awaiting_approval")
        self.assertTrue(store.record_decision(rid, ("awaiting_approval",), "approved", SHA_A, "approve", "ok", "alice"))
        self.assertFalse(store.record_decision(rid, ("awaiting_approval",), "rejected", SHA_A, "reject", "no", "bob"))
        self.assertEqual(len(store.get_decisions(rid)), 1)
        self.assertEqual(store.get_run(rid)["status"], "approved")

    def test_verdicts_and_findings_round_trip(self):
        store = make_store(self)
        rid = store.create_run(make_pr()).run_id
        f = Finding("SecurityAgent", "bandit", "B101", Severity.HIGH, "msg", "a.py", 3, "fix it")
        store.add_verdict(rid, Verdict("SecurityAgent", Status.BLOCK, [f], "s", ["bandit: ran"], 1.5, {"k": 1}))
        v = store.get_verdicts(rid)[0]
        self.assertEqual((v["status"], v["notes"], v["data"]), ("BLOCK", ["bandit: ran"], {"k": 1}))
        self.assertEqual((v["findings"][0]["rule"], v["findings"][0]["severity"]), ("B101", 3))

    def test_audit_log_is_append_only(self):
        store = make_store(self)
        rid = store.create_run(make_pr()).run_id
        store.audit(rid, "alice", "approved", "ok")
        conn = sqlite3.connect(store.path, isolation_level=None)
        self.addCleanup(conn.close)
        with self.assertRaises(sqlite3.DatabaseError):
            conn.execute("UPDATE audit_log SET actor='eve'")
        with self.assertRaises(sqlite3.DatabaseError):
            conn.execute("DELETE FROM audit_log")
        store.clear_results(rid)  # re-analysis must not touch the audit log
        self.assertGreaterEqual(len(store.get_audit(rid)), 2)

    def test_awaiting_older_than(self):
        clock = Clock(1000)
        store = make_store(self, clock)
        rid = store.create_run(make_pr()).run_id
        store.transition(rid, ("queued",), "awaiting_approval")
        self.assertEqual(store.awaiting_older_than(900), [])
        self.assertEqual(store.awaiting_older_than(1001), [rid])

    def test_unfinished_runs_listed(self):
        store = make_store(self)
        rid = store.create_run(make_pr()).run_id
        store.transition(rid, ("queued",), "running")
        self.assertEqual(store.unfinished_run_ids(), [rid])


class AuthTests(unittest.TestCase):
    FAST = dict(n=2 ** 4)

    def test_hash_and_verify(self):
        stored = hash_password("correct horse", **self.FAST)
        self.assertTrue(verify_password("correct horse", stored))
        self.assertFalse(verify_password("wrong", stored))
        self.assertNotEqual(stored, hash_password("correct horse", **self.FAST))  # random salt
        self.assertFalse(verify_password("x", "garbage"))

    def test_lockout_after_three_failures_then_expires(self):
        clock = Clock(10_000)
        store = make_store(self, clock)
        settings = make_settings(lockout_attempts=3, lockout_minutes=30)
        store.set_user("alice", hash_password("correct horse", **self.FAST))
        for _ in range(3):
            self.assertFalse(check_login(store, settings, "alice", "bad", "1.1.1.1").ok)
        locked = check_login(store, settings, "alice", "correct horse", "1.1.1.1")
        self.assertFalse(locked.ok)
        self.assertIn("Too many", locked.message)
        clock.now += 31 * 60
        self.assertTrue(check_login(store, settings, "alice", "correct horse", "1.1.1.1").ok)

    def test_unknown_user_fails(self):
        store = make_store(self)
        self.assertFalse(check_login(store, make_settings(), "nobody", "whatever", "1.1.1.1").ok)

    def test_success_does_not_lock(self):
        store = make_store(self)
        store.set_user("alice", hash_password("correct horse", **self.FAST))
        for _ in range(5):
            self.assertTrue(check_login(store, make_settings(), "alice", "correct horse", "1.1.1.1").ok)


if __name__ == "__main__":
    unittest.main()
