"""SQLite-backed findings index. Source of truth for artifacts is JSON on disk;
this table is a queryable index across runs."""

from __future__ import annotations

import json
import sqlite3
import time
from pathlib import Path

SCHEMA = """
CREATE TABLE IF NOT EXISTS findings (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    run_id          TEXT NOT NULL,
    target          TEXT NOT NULL,
    hypothesis_id   TEXT NOT NULL,
    cwe             TEXT,
    severity        TEXT,
    file            TEXT,
    line_range      TEXT,
    title           TEXT,
    validated       INTEGER NOT NULL DEFAULT 0,
    has_patch       INTEGER NOT NULL DEFAULT 0,
    has_report      INTEGER NOT NULL DEFAULT 0,
    artifact_dir    TEXT NOT NULL,
    created_at      REAL NOT NULL,
    metadata_json   TEXT
);
CREATE INDEX IF NOT EXISTS idx_findings_target ON findings(target);
CREATE INDEX IF NOT EXISTS idx_findings_run ON findings(run_id);
"""


class FindingsStore:
    def __init__(self, db_path: Path):
        db_path.parent.mkdir(parents=True, exist_ok=True)
        self.conn = sqlite3.connect(db_path)
        self.conn.executescript(SCHEMA)
        self.conn.commit()

    def record(
        self,
        *,
        run_id: str,
        target: str,
        hypothesis_id: str,
        cwe: str | None,
        severity: str | None,
        file: str | None,
        line_range: str | None,
        title: str | None,
        validated: bool,
        has_patch: bool,
        has_report: bool,
        artifact_dir: Path,
        metadata: dict | None = None,
    ) -> int:
        cur = self.conn.execute(
            """INSERT INTO findings
               (run_id, target, hypothesis_id, cwe, severity, file, line_range,
                title, validated, has_patch, has_report, artifact_dir, created_at,
                metadata_json)
               VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
            (
                run_id, target, hypothesis_id, cwe, severity, file, line_range,
                title, int(validated), int(has_patch), int(has_report),
                str(artifact_dir), time.time(), json.dumps(metadata or {}),
            ),
        )
        self.conn.commit()
        return cur.lastrowid

    def list_findings(self, target: str | None = None) -> list[dict]:
        q = "SELECT * FROM findings"
        params: tuple = ()
        if target:
            q += " WHERE target = ?"
            params = (target,)
        q += " ORDER BY created_at DESC"
        cur = self.conn.execute(q, params)
        cols = [c[0] for c in cur.description]
        return [dict(zip(cols, row)) for row in cur.fetchall()]

    def close(self) -> None:
        self.conn.close()
