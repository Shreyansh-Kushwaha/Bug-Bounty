from pathlib import Path

from src.store.findings import FindingsStore, dedupe_key


def _store(tmp_path: Path) -> FindingsStore:
    return FindingsStore(tmp_path / "findings.db")


def test_record_and_list(tmp_path: Path):
    s = _store(tmp_path)
    s.record(
        run_id="r1", target="t", hypothesis_id="H1", cwe="CWE-502",
        severity="high", file="a.py", line_range="1-2", title="RCE",
        validated=True, has_patch=True, has_report=False,
        patch_validated=True, artifact_dir=tmp_path,
    )
    rows = s.list_findings()
    assert len(rows) == 1
    assert rows[0]["patch_validated"] == 1
    assert rows[0]["dedupe_key"] == dedupe_key("t", "CWE-502", "a.py", "1-2")
    s.close()


def test_target_filter(tmp_path: Path):
    s = _store(tmp_path)
    for tgt in ("a", "a", "b"):
        s.record(run_id="r", target=tgt, hypothesis_id="H1", cwe="C", severity="low",
                 file="f", line_range="1", title="t", validated=False,
                 has_patch=False, has_report=False, artifact_dir=tmp_path)
    assert len(s.list_findings(target="a")) == 2
    assert len(s.list_findings(target="b")) == 1
    s.close()


def test_duplicates(tmp_path: Path):
    s = _store(tmp_path)
    common = dict(target="t", hypothesis_id="H1", cwe="CWE-89", file="q.py",
                  line_range="10", title="SQLi", validated=True, has_patch=False,
                  has_report=False, artifact_dir=tmp_path)
    s.record(run_id="r1", severity="high", **common)
    s.record(run_id="r2", severity="high", **common)
    s.record(run_id="r3", target="other", hypothesis_id="H1", cwe="CWE-1", file="x",
             line_range="1", title="t", severity="low", validated=False,
             has_patch=False, has_report=False, artifact_dir=tmp_path)
    dups = s.duplicates()
    assert len(dups) == 1
    assert dups[0]["count"] == 2
    s.close()


def test_migration_from_old_schema(tmp_path: Path):
    """A pre-existing table without the new columns should be migrated in place."""
    import sqlite3

    db = tmp_path / "findings.db"
    conn = sqlite3.connect(db)
    conn.execute("""CREATE TABLE findings (
        id INTEGER PRIMARY KEY AUTOINCREMENT, run_id TEXT NOT NULL, target TEXT NOT NULL,
        hypothesis_id TEXT NOT NULL, cwe TEXT, severity TEXT, file TEXT, line_range TEXT,
        title TEXT, validated INTEGER NOT NULL DEFAULT 0, has_patch INTEGER NOT NULL DEFAULT 0,
        has_report INTEGER NOT NULL DEFAULT 0, artifact_dir TEXT NOT NULL,
        created_at REAL NOT NULL, metadata_json TEXT)""")
    conn.commit()
    conn.close()

    s = FindingsStore(db)  # should ALTER in the missing columns
    s.record(run_id="r", target="t", hypothesis_id="H1", cwe="C", severity="low",
             file="f", line_range="1", title="t", validated=False,
             has_patch=False, has_report=False, patch_validated=True, artifact_dir=tmp_path)
    assert s.list_findings()[0]["patch_validated"] == 1
    s.close()
