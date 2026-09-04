"""SQLite-backed store for web-attested targets.

The static config/targets.json remains a read-only seed allowlist (benchmarks
and repos the operator curates by hand). Targets submitted through the web UI
are written HERE instead of mutating the JSON file at request time — which
removes the config-file write race and its unbounded growth.
"""

from __future__ import annotations

import sqlite3
import threading
import time
from pathlib import Path

SCHEMA = """
CREATE TABLE IF NOT EXISTS attested_targets (
    name         TEXT PRIMARY KEY,
    repo         TEXT NOT NULL,
    ref          TEXT NOT NULL DEFAULT 'main',
    category     TEXT NOT NULL DEFAULT 'attested',
    notes        TEXT,
    attested_by  TEXT,
    created_at   REAL NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_targets_repo ON attested_targets(repo);
"""


class TargetsStore:
    def __init__(self, db_path: Path):
        db_path.parent.mkdir(parents=True, exist_ok=True)
        self.conn = sqlite3.connect(db_path, check_same_thread=False)
        self.conn.row_factory = sqlite3.Row
        self._lock = threading.Lock()
        with self._lock:
            self.conn.executescript(SCHEMA)
            self.conn.commit()

    def add(self, *, name: str, repo: str, ref: str, category: str,
            notes: str, attested_by: str) -> dict:
        row = {
            "name": name, "repo": repo, "ref": ref, "category": category,
            "notes": notes, "attested_by": attested_by,
        }
        with self._lock:
            self.conn.execute(
                """INSERT OR REPLACE INTO attested_targets
                   (name, repo, ref, category, notes, attested_by, created_at)
                   VALUES (?,?,?,?,?,?,?)""",
                (name, repo, ref, category, notes, attested_by, time.time()),
            )
            self.conn.commit()
        return row

    def get_by_repo(self, repo: str) -> dict | None:
        with self._lock:
            cur = self.conn.execute(
                "SELECT * FROM attested_targets WHERE repo = ?", (repo,)
            )
            row = cur.fetchone()
        return dict(row) if row else None

    def get_by_name(self, name: str) -> dict | None:
        with self._lock:
            cur = self.conn.execute(
                "SELECT * FROM attested_targets WHERE name = ?", (name,)
            )
            row = cur.fetchone()
        return dict(row) if row else None

    def list(self) -> list[dict]:
        with self._lock:
            cur = self.conn.execute(
                "SELECT * FROM attested_targets ORDER BY created_at DESC"
            )
            return [dict(r) for r in cur.fetchall()]

    def names(self) -> set[str]:
        with self._lock:
            cur = self.conn.execute("SELECT name FROM attested_targets")
            return {r[0] for r in cur.fetchall()}

    def close(self) -> None:
        self.conn.close()
