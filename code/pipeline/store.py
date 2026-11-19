"""SQLite storage: runs, verdicts, findings, decisions, the audit log and dashboard users.

Only the standard library is used. Each call opens its own short connection, so the
webhook process and the dashboard process can share one database file safely (WAL mode)."""

from __future__ import annotations

import json
import sqlite3
import time
from contextlib import contextmanager
from dataclasses import dataclass, field
from typing import Callable, Iterable, Iterator

from pipeline.models import PullRequest, Verdict

ACTIVE = ("queued", "running", "awaiting_approval")
TERMINAL = ("approved", "deployed", "blocked", "rejected", "expired", "superseded", "failed")
ALL_STATUSES = ACTIVE + TERMINAL
_RUN_FIELDS = {"escalation_reason", "risk_score", "risk_factors", "file_count", "error", "deployment"}

SCHEMA = """
CREATE TABLE IF NOT EXISTS runs (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  repo TEXT NOT NULL, pr_number INTEGER NOT NULL, head_sha TEXT NOT NULL,
  base_branch TEXT NOT NULL DEFAULT '', head_branch TEXT NOT NULL DEFAULT '',
  title TEXT NOT NULL DEFAULT '', author TEXT NOT NULL DEFAULT '', html_url TEXT NOT NULL DEFAULT '',
  status TEXT NOT NULL, escalation_reason TEXT NOT NULL DEFAULT '',
  risk_score INTEGER, risk_factors TEXT NOT NULL DEFAULT '[]',
  file_count INTEGER NOT NULL DEFAULT 0, error TEXT NOT NULL DEFAULT '', deployment TEXT NOT NULL DEFAULT '',
  created_at REAL NOT NULL, updated_at REAL NOT NULL, awaiting_since REAL, finished_at REAL
);
CREATE INDEX IF NOT EXISTS idx_runs_pr ON runs(repo, pr_number, head_sha);
CREATE INDEX IF NOT EXISTS idx_runs_status ON runs(status);
CREATE TABLE IF NOT EXISTS deliveries (delivery_id TEXT PRIMARY KEY, received_at REAL NOT NULL);
CREATE TABLE IF NOT EXISTS verdicts (
  id INTEGER PRIMARY KEY AUTOINCREMENT, run_id INTEGER NOT NULL REFERENCES runs(id),
  agent TEXT NOT NULL, status TEXT NOT NULL, summary TEXT NOT NULL DEFAULT '',
  notes TEXT NOT NULL DEFAULT '[]', data TEXT NOT NULL DEFAULT '{}', duration_s REAL NOT NULL DEFAULT 0,
  created_at REAL NOT NULL
);
CREATE TABLE IF NOT EXISTS findings (
  id INTEGER PRIMARY KEY AUTOINCREMENT, run_id INTEGER NOT NULL REFERENCES runs(id),
  verdict_id INTEGER NOT NULL REFERENCES verdicts(id),
  agent TEXT, tool TEXT, rule TEXT, severity INTEGER NOT NULL, message TEXT, file TEXT, line INTEGER, suggestion TEXT
);
CREATE TABLE IF NOT EXISTS decisions (
  id INTEGER PRIMARY KEY AUTOINCREMENT, run_id INTEGER NOT NULL REFERENCES runs(id),
  head_sha TEXT NOT NULL, decision TEXT NOT NULL, reason TEXT NOT NULL DEFAULT '',
  decided_by TEXT NOT NULL, decided_at REAL NOT NULL
);
CREATE TABLE IF NOT EXISTS audit_log (
  id INTEGER PRIMARY KEY AUTOINCREMENT, ts REAL NOT NULL, run_id INTEGER,
  actor TEXT NOT NULL, event TEXT NOT NULL, detail TEXT NOT NULL DEFAULT ''
);
CREATE TRIGGER IF NOT EXISTS audit_no_update BEFORE UPDATE ON audit_log
  BEGIN SELECT RAISE(ABORT, 'audit log is append-only'); END;
CREATE TRIGGER IF NOT EXISTS audit_no_delete BEFORE DELETE ON audit_log
  BEGIN SELECT RAISE(ABORT, 'audit log is append-only'); END;
CREATE TABLE IF NOT EXISTS users (username TEXT PRIMARY KEY, password_hash TEXT NOT NULL, created_at REAL NOT NULL);
CREATE TABLE IF NOT EXISTS login_attempts (
  id INTEGER PRIMARY KEY AUTOINCREMENT, username TEXT NOT NULL, ip TEXT NOT NULL, ts REAL NOT NULL, ok INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_login ON login_attempts(username, ip, ts);
CREATE TABLE IF NOT EXISTS pr_files (
  run_id INTEGER NOT NULL REFERENCES runs(id), position INTEGER NOT NULL, filename TEXT NOT NULL,
  status TEXT NOT NULL, additions INTEGER NOT NULL DEFAULT 0, deletions INTEGER NOT NULL DEFAULT 0,
  patch TEXT, truncated INTEGER NOT NULL DEFAULT 0, PRIMARY KEY (run_id, position)
);
CREATE TABLE IF NOT EXISTS run_steps (
  run_id INTEGER NOT NULL REFERENCES runs(id), position INTEGER NOT NULL, agent TEXT NOT NULL,
  state TEXT NOT NULL, verdict TEXT NOT NULL DEFAULT '', started_at REAL, finished_at REAL,
  PRIMARY KEY (run_id, position)
);
CREATE TABLE IF NOT EXISTS heartbeat (name TEXT PRIMARY KEY, ts REAL NOT NULL);
"""


@dataclass
class Submission:
    run_id: int | None                      # None when nothing was queued
    superseded: list[int] = field(default_factory=list)
    reason: str = ""                        # why nothing was queued


class Store:
    def __init__(self, path: str, clock: Callable[[], float] = time.time) -> None:
        self.path = path
        self.clock = clock
        conn = self._connect()
        try:
            conn.executescript(SCHEMA)
        finally:
            conn.close()

    # ---- plumbing ----
    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.path, timeout=15, isolation_level=None)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA foreign_keys=ON")
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA busy_timeout=15000")
        return conn

    @contextmanager
    def _tx(self) -> Iterator[sqlite3.Connection]:
        conn = self._connect()
        try:
            conn.execute("BEGIN IMMEDIATE")
            yield conn
            conn.execute("COMMIT")
        except BaseException:
            try:
                conn.execute("ROLLBACK")
            except sqlite3.Error:
                pass
            raise
        finally:
            conn.close()

    @contextmanager
    def _read(self) -> Iterator[sqlite3.Connection]:
        conn = self._connect()
        try:
            yield conn
        finally:
            conn.close()

    def _audit(self, conn: sqlite3.Connection, run_id: int | None, actor: str, event: str, detail: str = "") -> None:
        conn.execute("INSERT INTO audit_log (ts, run_id, actor, event, detail) VALUES (?,?,?,?,?)",
                     (self.clock(), run_id, actor, event, detail))

    # ---- runs ----
    def create_run(self, pr: PullRequest, delivery_id: str | None = None) -> Submission:
        """Queue a run for this commit. Refuses duplicates (FR34) and supersedes older
        unfinished runs of the same PR (FR2), all in one transaction."""
        now = self.clock()
        with self._tx() as c:
            if delivery_id:
                if c.execute("SELECT 1 FROM deliveries WHERE delivery_id=?", (delivery_id,)).fetchone():
                    return Submission(None, [], "duplicate delivery")
                c.execute("INSERT INTO deliveries (delivery_id, received_at) VALUES (?,?)", (delivery_id, now))
            dup = c.execute("SELECT id FROM runs WHERE repo=? AND pr_number=? AND head_sha=? AND status != 'failed' "
                            "ORDER BY id DESC LIMIT 1", (pr.repo, pr.number, pr.head_sha)).fetchone()
            if dup:
                return Submission(None, [], f"run {dup['id']} already covers this commit")
            older = [r["id"] for r in c.execute(
                "SELECT id FROM runs WHERE repo=? AND pr_number=? AND head_sha != ? "
                "AND status IN ('queued','running','awaiting_approval')", (pr.repo, pr.number, pr.head_sha))]
            for rid in older:
                c.execute("UPDATE runs SET status='superseded', updated_at=?, finished_at=? WHERE id=?", (now, now, rid))
                self._audit(c, rid, "system", "superseded", f"by commit {pr.head_sha[:7]}")
            cur = c.execute(
                "INSERT INTO runs (repo, pr_number, head_sha, base_branch, head_branch, title, author, html_url, "
                "status, created_at, updated_at) VALUES (?,?,?,?,?,?,?,?, 'queued', ?, ?)",
                (pr.repo, pr.number, pr.head_sha, pr.base_branch, pr.head_branch, pr.title, pr.author,
                 pr.html_url, now, now))
            run_id = cur.lastrowid
            self._audit(c, run_id, "system", "run queued", f"PR #{pr.number} at {pr.head_sha[:7]}")
        return Submission(run_id, older)

    def get_run(self, run_id: int) -> dict | None:
        with self._read() as c:
            row = c.execute("SELECT * FROM runs WHERE id=?", (run_id,)).fetchone()
        return self._run_dict(row) if row else None

    def list_runs(self, status: str | None = None, limit: int = 200) -> list[dict]:
        with self._read() as c:
            if status:
                rows = c.execute("SELECT * FROM runs WHERE status=? ORDER BY id DESC LIMIT ?", (status, limit)).fetchall()
            else:
                rows = c.execute("SELECT * FROM runs ORDER BY id DESC LIMIT ?", (limit,)).fetchall()
        return [self._run_dict(r) for r in rows]

    @staticmethod
    def _run_dict(row: sqlite3.Row) -> dict:
        d = dict(row)
        d["risk_factors"] = json.loads(d.get("risk_factors") or "[]")
        return d

    @staticmethod
    def pr_of(run: dict) -> PullRequest:
        return PullRequest(run["repo"], run["pr_number"], run["head_sha"], run["base_branch"],
                           run["head_branch"], run["title"], run["author"], run["html_url"])

    def transition(self, run_id: int, allowed: Iterable[str], new: str, **fields) -> bool:
        """Atomically move a run to `new` if it is currently in one of `allowed`.
        Returns False when someone else got there first (for example, an expiry and a click)."""
        allowed = tuple(allowed)
        now = self.clock()
        sets, vals = ["status=?", "updated_at=?"], [new, now]
        if new == "awaiting_approval":
            sets.append("awaiting_since=?"); vals.append(now)
        if new in TERMINAL:
            sets.append("finished_at=?"); vals.append(now)
        for key, value in fields.items():
            if key not in _RUN_FIELDS:
                raise ValueError(f"unknown run field: {key}")
            sets.append(f"{key}=?"); vals.append(value)
        marks = ",".join("?" for _ in allowed)
        with self._tx() as c:
            cur = c.execute(f"UPDATE runs SET {', '.join(sets)} WHERE id=? AND status IN ({marks})",
                            (*vals, run_id, *allowed))
            return cur.rowcount == 1

    def update_run(self, run_id: int, **fields) -> None:
        sets, vals = ["updated_at=?"], [self.clock()]
        for key, value in fields.items():
            if key not in _RUN_FIELDS:
                raise ValueError(f"unknown run field: {key}")
            sets.append(f"{key}=?"); vals.append(value)
        with self._tx() as c:
            c.execute(f"UPDATE runs SET {', '.join(sets)} WHERE id=?", (*vals, run_id))

    def unfinished_run_ids(self) -> list[int]:
        with self._read() as c:
            return [r["id"] for r in c.execute("SELECT id FROM runs WHERE status IN ('queued','running') ORDER BY id")]

    def requeue(self, run_id: int) -> None:
        self.transition(run_id, ("running",), "queued")

    def awaiting_older_than(self, cutoff: float) -> list[int]:
        with self._read() as c:
            return [r["id"] for r in c.execute(
                "SELECT id FROM runs WHERE status='awaiting_approval' AND awaiting_since < ?", (cutoff,))]

    # ---- verdicts and findings ----
    def clear_results(self, run_id: int) -> None:
        """Forget earlier results of a run that is being analysed again. The audit log is never touched."""
        with self._tx() as c:
            c.execute("DELETE FROM findings WHERE run_id=?", (run_id,))
            c.execute("DELETE FROM verdicts WHERE run_id=?", (run_id,))
            c.execute("DELETE FROM pr_files WHERE run_id=?", (run_id,))
            c.execute("DELETE FROM run_steps WHERE run_id=?", (run_id,))

    # ---- the changed code, for the dashboard ----
    def save_files(self, run_id: int, files: list[tuple]) -> None:
        """files: (filename, status, additions, deletions, patch, truncated). The caller has already
        masked secrets and applied the size limits."""
        with self._tx() as c:
            c.execute("DELETE FROM pr_files WHERE run_id=?", (run_id,))
            c.executemany("INSERT INTO pr_files (run_id, position, filename, status, additions, deletions, patch, truncated) "
                          "VALUES (?,?,?,?,?,?,?,?)", [(run_id, i, *f) for i, f in enumerate(files)])

    def get_files(self, run_id: int) -> list[dict]:
        with self._read() as c:
            return [dict(r) for r in c.execute("SELECT * FROM pr_files WHERE run_id=? ORDER BY position", (run_id,))]

    # ---- progress of a run: which agent is waiting, running, done ----
    def plan_steps(self, run_id: int, names: list[str]) -> None:
        with self._tx() as c:
            c.execute("DELETE FROM run_steps WHERE run_id=?", (run_id,))
            c.executemany("INSERT INTO run_steps (run_id, position, agent, state) VALUES (?,?,?,'pending')",
                          [(run_id, i, n) for i, n in enumerate(names)])

    def append_step(self, run_id: int, name: str) -> None:
        with self._tx() as c:
            pos = c.execute("SELECT COALESCE(MAX(position), -1) + 1 FROM run_steps WHERE run_id=?", (run_id,)).fetchone()[0]
            c.execute("INSERT INTO run_steps (run_id, position, agent, state) VALUES (?,?,?,'pending')", (run_id, pos, name))

    def step_start(self, run_id: int, agent: str) -> None:
        with self._tx() as c:
            c.execute("UPDATE run_steps SET state='running', started_at=? WHERE run_id=? AND agent=? AND state='pending'",
                      (self.clock(), run_id, agent))

    def step_done(self, run_id: int, agent: str, verdict: str) -> None:
        with self._tx() as c:
            c.execute("UPDATE run_steps SET state='done', verdict=?, finished_at=? WHERE run_id=? AND agent=? "
                      "AND state IN ('pending','running')", (verdict, self.clock(), run_id, agent))

    def skip_steps(self, run_id: int, include_running: bool = False) -> None:
        states = "('pending','running')" if include_running else "('pending')"
        with self._tx() as c:
            c.execute(f"UPDATE run_steps SET state='skipped' WHERE run_id=? AND state IN {states}", (run_id,))

    def get_steps(self, run_id: int) -> list[dict]:
        with self._read() as c:
            return [dict(r) for r in c.execute("SELECT * FROM run_steps WHERE run_id=? ORDER BY position", (run_id,))]

    # ---- is the worker alive? (the dashboard is another process) ----
    def beat(self, name: str) -> None:
        with self._tx() as c:
            c.execute("INSERT INTO heartbeat (name, ts) VALUES (?,?) ON CONFLICT(name) DO UPDATE SET ts=excluded.ts",
                      (name, self.clock()))

    def last_beat(self, name: str) -> float | None:
        with self._read() as c:
            row = c.execute("SELECT ts FROM heartbeat WHERE name=?", (name,)).fetchone()
        return row["ts"] if row else None

    def status_counts(self) -> dict[str, int]:
        with self._read() as c:
            return {r["status"]: r["n"] for r in c.execute("SELECT status, COUNT(*) AS n FROM runs GROUP BY status")}

    def add_verdict(self, run_id: int, v: Verdict) -> int:
        with self._tx() as c:
            cur = c.execute(
                "INSERT INTO verdicts (run_id, agent, status, summary, notes, data, duration_s, created_at) "
                "VALUES (?,?,?,?,?,?,?,?)",
                (run_id, v.agent, v.status.value, v.summary, json.dumps(v.notes), json.dumps(v.data),
                 v.duration_s, self.clock()))
            vid = cur.lastrowid
            for f in v.findings:
                c.execute("INSERT INTO findings (run_id, verdict_id, agent, tool, rule, severity, message, file, line, suggestion) "
                          "VALUES (?,?,?,?,?,?,?,?,?,?)",
                          (run_id, vid, f.agent, f.tool, f.rule, int(f.severity), f.message, f.file, f.line, f.suggestion))
        return vid

    def get_verdicts(self, run_id: int) -> list[dict]:
        with self._read() as c:
            verdicts = [dict(r) for r in c.execute("SELECT * FROM verdicts WHERE run_id=? ORDER BY id", (run_id,))]
            for v in verdicts:
                v["notes"] = json.loads(v["notes"])
                v["data"] = json.loads(v["data"])
                v["findings"] = [dict(r) for r in c.execute(
                    "SELECT * FROM findings WHERE verdict_id=? ORDER BY severity DESC, file, line, id", (v["id"],))]
        return verdicts

    # ---- decisions and audit ----
    def add_decision(self, run_id: int, head_sha: str, decision: str, reason: str, by: str) -> None:
        with self._tx() as c:
            c.execute("INSERT INTO decisions (run_id, head_sha, decision, reason, decided_by, decided_at) "
                      "VALUES (?,?,?,?,?,?)", (run_id, head_sha, decision, reason, by, self.clock()))

    def record_decision(self, run_id: int, allowed: Iterable[str], new_status: str, head_sha: str,
                        decision: str, reason: str, by: str, **fields) -> bool:
        """Change the run's status and store the decision in ONE transaction, so a crash can
        never leave a status without its decision. False if the run was no longer in `allowed`."""
        allowed = tuple(allowed)
        now = self.clock()
        sets, vals = ["status=?", "updated_at=?"], [new_status, now]
        if new_status in TERMINAL:
            sets.append("finished_at=?"); vals.append(now)
        for key, value in fields.items():
            if key not in _RUN_FIELDS:
                raise ValueError(f"unknown run field: {key}")
            sets.append(f"{key}=?"); vals.append(value)
        marks = ",".join("?" for _ in allowed)
        with self._tx() as c:
            cur = c.execute(f"UPDATE runs SET {', '.join(sets)} WHERE id=? AND status IN ({marks})",
                            (*vals, run_id, *allowed))
            if cur.rowcount != 1:
                return False
            c.execute("INSERT INTO decisions (run_id, head_sha, decision, reason, decided_by, decided_at) "
                      "VALUES (?,?,?,?,?,?)", (run_id, head_sha, decision, reason, by, now))
            self._audit(c, run_id, by, f"decision: {decision}", reason)
        return True

    def get_decisions(self, run_id: int) -> list[dict]:
        with self._read() as c:
            return [dict(r) for r in c.execute("SELECT * FROM decisions WHERE run_id=? ORDER BY id", (run_id,))]

    def audit(self, run_id: int | None, actor: str, event: str, detail: str = "") -> None:
        with self._tx() as c:
            self._audit(c, run_id, actor, event, detail)

    def get_audit(self, run_id: int) -> list[dict]:
        with self._read() as c:
            return [dict(r) for r in c.execute("SELECT * FROM audit_log WHERE run_id=? ORDER BY id", (run_id,))]

    # ---- dashboard users and log-in attempts ----
    def set_user(self, username: str, password_hash: str) -> None:
        with self._tx() as c:
            c.execute("INSERT INTO users (username, password_hash, created_at) VALUES (?,?,?) "
                      "ON CONFLICT(username) DO UPDATE SET password_hash=excluded.password_hash",
                      (username, password_hash, self.clock()))

    def user_count(self) -> int:
        with self._read() as c:
            return c.execute("SELECT COUNT(*) FROM users").fetchone()[0]

    def get_user_hash(self, username: str) -> str | None:
        with self._read() as c:
            row = c.execute("SELECT password_hash FROM users WHERE username=?", (username,)).fetchone()
        return row["password_hash"] if row else None

    def record_attempt(self, username: str, ip: str, ok: bool) -> None:
        with self._tx() as c:
            c.execute("INSERT INTO login_attempts (username, ip, ts, ok) VALUES (?,?,?,?)",
                      (username, ip, self.clock(), 1 if ok else 0))

    def locked_until(self, username: str, ip: str, max_attempts: int, lockout_seconds: float) -> float | None:
        """After `max_attempts` failures in a row from the same account and address, log-in is
        refused for `lockout_seconds`, counted from the last of those failures (FR6, QR16)."""
        with self._read() as c:
            last_ok = c.execute("SELECT MAX(ts) AS t FROM login_attempts WHERE username=? AND ip=? AND ok=1",
                                (username, ip)).fetchone()["t"] or 0
            fails = [r["ts"] for r in c.execute(
                "SELECT ts FROM login_attempts WHERE username=? AND ip=? AND ok=0 AND ts>? ORDER BY ts",
                (username, ip, last_ok))]
        streak, until = 0, None
        for ts in fails:
            if until is not None and ts < until:
                continue
            if until is not None:
                until, streak = None, 0
            streak += 1
            if streak >= max_attempts:
                until = ts + lockout_seconds
        return until if until is not None and self.clock() < until else None
