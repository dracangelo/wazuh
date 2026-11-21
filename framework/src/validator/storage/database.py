from __future__ import annotations

import sqlite3
from pathlib import Path

SCHEMA = """
CREATE TABLE IF NOT EXISTS runs (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  label TEXT, started_at TEXT NOT NULL, finished_at TEXT, git_sha TEXT
);
CREATE TABLE IF NOT EXISTS results (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  run_id INTEGER NOT NULL REFERENCES runs(id),
  test_id TEXT NOT NULL, name TEXT, technique TEXT, platform TEXT,
  negative INTEGER, verdict TEXT NOT NULL, latency_seconds REAL,
  matched_rule_ids TEXT, error TEXT
);
CREATE INDEX IF NOT EXISTS idx_results_run ON results(run_id);
"""


def connect(path: Path) -> sqlite3.Connection:
    path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(path)
    conn.row_factory = sqlite3.Row
    conn.executescript(SCHEMA)
    return conn
