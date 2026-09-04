from pathlib import Path

from src.store.findings import FindingsStore


def _rec(store, i):
    store.record(
        run_id=f"r{i}", target="demo", hypothesis_id=f"H{i}", cwe="CWE-79",
        severity="high", file="a.py", line_range="1-2", title=f"t{i}",
        validated=False, has_patch=False, has_report=False,
        artifact_dir=Path("/tmp/x"),
    )


def test_limit_offset_and_count(tmp_path):
    store = FindingsStore(tmp_path / "db.sqlite")
    for i in range(10):
        _rec(store, i)
    assert store.count_findings() == 10
    page1 = store.list_findings(limit=4, offset=0)
    page2 = store.list_findings(limit=4, offset=4)
    assert len(page1) == 4 and len(page2) == 4
    ids1 = {r["run_id"] for r in page1}
    ids2 = {r["run_id"] for r in page2}
    assert ids1.isdisjoint(ids2)
    # No limit returns everything.
    assert len(store.list_findings()) == 10
    store.close()
