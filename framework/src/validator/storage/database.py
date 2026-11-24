from __future__ import annotations

import sqlite3
from pathlib import Path

SCHEMA = """
CREATE TABLE IF NOT EXISTS runs (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  label TEXT, started_at TEXT NOT NULL, finished_at TEXT, git_sha TEXT,
  status TEXT NOT NULL DEFAULT 'running',
  canary_status TEXT, canary_detail TEXT, meta TEXT
);
CREATE TABLE IF NOT EXISTS results (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  run_id INTEGER NOT NULL REFERENCES runs(id),
  test_id TEXT NOT NULL, name TEXT, technique TEXT, platform TEXT,
  negative INTEGER, verdict TEXT NOT NULL, latency_seconds REAL,
  matched_rule_ids TEXT, error TEXT, exec_id TEXT, correlation TEXT, test_hash TEXT
);
CREATE INDEX IF NOT EXISTS idx_results_run ON results(run_id);
"""


def _migrate(conn: sqlite3.Connection) -> None:
    """Add run-status columns to databases created before the pipeline canary existed."""
    columns = {row[1] for row in conn.execute("PRAGMA table_info(runs)")}
    for name, ddl in (
        ("status", "ALTER TABLE runs ADD COLUMN status TEXT NOT NULL DEFAULT 'completed'"),
        ("canary_status", "ALTER TABLE runs ADD COLUMN canary_status TEXT"),
        ("canary_detail", "ALTER TABLE runs ADD COLUMN canary_detail TEXT"),
        ("meta", "ALTER TABLE runs ADD COLUMN meta TEXT"),
    ):
        if name not in columns:
            conn.execute(ddl)
    result_cols = {row[1] for row in conn.execute("PRAGMA table_info(results)")}
    for name in ("exec_id", "correlation", "test_hash"):
        if name not in result_cols:
            conn.execute(f"ALTER TABLE results ADD COLUMN {name} TEXT")
    # A finished run predates the status column, so it completed; an unfinished one crashed.
    conn.execute("UPDATE runs SET status='completed' WHERE status='running' AND finished_at IS NOT NULL")
    conn.commit()


def connect(path: Path) -> sqlite3.Connection:
    path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(path)
    conn.row_factory = sqlite3.Row
    conn.executescript(SCHEMA)
    _migrate(conn)
    return conn
