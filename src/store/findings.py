"""SQLite-backed findings index. Source of truth for artifacts is JSON on disk;
this table is a queryable index across runs."""

from __future__ import annotations

import json
import sqlite3
import threading
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
    patch_validated INTEGER NOT NULL DEFAULT 0,
    dedupe_key      TEXT,
    artifact_dir    TEXT NOT NULL,
    created_at      REAL NOT NULL,
    metadata_json   TEXT
);
CREATE INDEX IF NOT EXISTS idx_findings_target ON findings(target);
CREATE INDEX IF NOT EXISTS idx_findings_run ON findings(run_id);
"""

# Created after migrations, since it references a possibly-migrated-in column.
_DEDUPE_INDEX = "CREATE INDEX IF NOT EXISTS idx_findings_dedupe ON findings(dedupe_key)"

# Columns added after the initial release; applied as best-effort migrations.
_MIGRATIONS = [
    ("patch_validated", "ALTER TABLE findings ADD COLUMN patch_validated INTEGER NOT NULL DEFAULT 0"),
    ("dedupe_key", "ALTER TABLE findings ADD COLUMN dedupe_key TEXT"),
]


def dedupe_key(target: str, cwe: str | None, file: str | None, line_range: str | None) -> str:
    """Stable identity for a vulnerability so the same bug across runs collapses."""
    return "|".join([target, (cwe or "").upper(), file or "", line_range or ""])


class FindingsStore:
    def __init__(self, db_path: Path):
        db_path.parent.mkdir(parents=True, exist_ok=True)
        # check_same_thread=False so the store can be created in one thread
        # (e.g. the web request handler) and written from another (the worker).
        self.conn = sqlite3.connect(db_path, check_same_thread=False)
        self.conn.row_factory = sqlite3.Row
        self._lock = threading.Lock()
        with self._lock:
            self.conn.executescript(SCHEMA)
            self._migrate()
            self.conn.execute(_DEDUPE_INDEX)
            self.conn.commit()

    def _migrate(self) -> None:
        existing = {r[1] for r in self.conn.execute("PRAGMA table_info(findings)").fetchall()}
        for col, ddl in _MIGRATIONS:
            if col not in existing:
                self.conn.execute(ddl)

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
        patch_validated: bool = False,
        metadata: dict | None = None,
    ) -> int:
        key = dedupe_key(target, cwe, file, line_range)
        with self._lock:
            cur = self.conn.execute(
                """INSERT INTO findings
                   (run_id, target, hypothesis_id, cwe, severity, file, line_range,
                    title, validated, has_patch, has_report, patch_validated,
                    dedupe_key, artifact_dir, created_at, metadata_json)
                   VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                (
                    run_id, target, hypothesis_id, cwe, severity, file, line_range,
                    title, int(validated), int(has_patch), int(has_report),
                    int(patch_validated), key, str(artifact_dir), time.time(),
                    json.dumps(metadata or {}),
                ),
            )
            self.conn.commit()
            return cur.lastrowid

    def list_findings(
        self,
        target: str | None = None,
        limit: int | None = None,
        offset: int = 0,
    ) -> list[dict]:
        q = "SELECT * FROM findings"
        params: list = []
        if target:
            q += " WHERE target = ?"
            params.append(target)
        q += " ORDER BY created_at DESC"
        if limit is not None:
            q += " LIMIT ? OFFSET ?"
            params.extend([int(limit), int(offset)])
        with self._lock:
            cur = self.conn.execute(q, tuple(params))
            return [dict(row) for row in cur.fetchall()]

    def count_findings(self, target: str | None = None) -> int:
        q = "SELECT COUNT(*) FROM findings"
        params: tuple = ()
        if target:
            q += " WHERE target = ?"
            params = (target,)
        with self._lock:
            return int(self.conn.execute(q, params).fetchone()[0])

    def duplicates(self) -> list[dict]:
        """Group findings by dedupe_key where more than one row shares the key."""
        rows = self.list_findings()
        groups: dict[str, list[dict]] = {}
        for r in rows:
            groups.setdefault(r["dedupe_key"] or f"_row_{r['id']}", []).append(r)
        return [
            {"dedupe_key": k, "count": len(v), "findings": v}
            for k, v in groups.items() if len(v) > 1
        ]

    def close(self) -> None:
        self.conn.close()

    def __enter__(self) -> "FindingsStore":
        return self

    def __exit__(self, *exc) -> None:
        self.close()
