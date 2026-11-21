from __future__ import annotations

import json
import sqlite3
import subprocess
from datetime import datetime, timezone


def _git_sha() -> str | None:
    try:
        return subprocess.run(["git", "rev-parse", "--short", "HEAD"], capture_output=True,
                              text=True, timeout=5).stdout.strip() or None
    except Exception:
        return None


class RunRepository:
    def __init__(self, conn: sqlite3.Connection):
        self.conn = conn

    def create_run(self, label: str | None = None) -> int:
        cur = self.conn.execute("INSERT INTO runs(label, started_at, git_sha) VALUES (?,?,?)",
                                (label, datetime.now(timezone.utc).isoformat(), _git_sha()))
        self.conn.commit()
        return cur.lastrowid

    def finish_run(self, run_id: int) -> None:
        self.conn.execute("UPDATE runs SET finished_at=? WHERE id=?",
                          (datetime.now(timezone.utc).isoformat(), run_id))
        self.conn.commit()

    def save_result(self, run_id: int, row: dict) -> None:
        self.conn.execute(
            "INSERT INTO results(run_id,test_id,name,technique,platform,negative,verdict,"
            "latency_seconds,matched_rule_ids,error) VALUES (?,?,?,?,?,?,?,?,?,?)",
            (run_id, row["test_id"], row["name"], row["technique"], row["platform"], int(row["negative"]),
             row["verdict"], row["latency_seconds"], json.dumps(row["matched_rule_ids"]), row["error"]))
        self.conn.commit()

    def results(self, run_id: int) -> list[dict]:
        out = []
        for r in self.conn.execute("SELECT * FROM results WHERE run_id=? ORDER BY test_id", (run_id,)):
            d = dict(r)
            d["negative"] = bool(d["negative"])
            d["matched_rule_ids"] = json.loads(d["matched_rule_ids"] or "[]")
            out.append(d)
        return out

    def get_run(self, run_id: int) -> dict | None:
        r = self.conn.execute("SELECT * FROM runs WHERE id=?", (run_id,)).fetchone()
        return dict(r) if r else None

    def latest_run_id(self, label: str | None = None, before: int | None = None) -> int | None:
        q, p = "SELECT id FROM runs WHERE finished_at IS NOT NULL", []
        if label:
            q += " AND label=?"
            p.append(label)
        if before:
            q += " AND id<?"
            p.append(before)
        r = self.conn.execute(q + " ORDER BY id DESC LIMIT 1", p).fetchone()
        return r["id"] if r else None

    def last_verdicts(self) -> dict[str, str]:
        """Most recent verdict per test id across all runs."""
        q = ("SELECT test_id, verdict FROM results WHERE id IN "
             "(SELECT MAX(id) FROM results GROUP BY test_id)")
        return {r["test_id"]: r["verdict"] for r in self.conn.execute(q)}
