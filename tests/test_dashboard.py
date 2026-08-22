from pathlib import Path

from src.store.dashboard import generate_dashboard, triage_report
from src.store.findings import FindingsStore


def test_dashboard_renders(tmp_path: Path):
    db = tmp_path / "findings.db"
    s = FindingsStore(db)
    s.record(run_id="r1", target="demo", hypothesis_id="H1", cwe="CWE-502",
             severity="critical", file="v.py", line_range="1-2", title="RCE",
             validated=True, has_patch=True, has_report=True,
             patch_validated=True, artifact_dir=tmp_path)
    s.close()

    out = generate_dashboard(db, tmp_path / "dash.html")
    html = out.read_text()
    assert "<!doctype html>" in html.lower()
    assert "RCE" in html
    assert "CWE-502" in html
    assert "Findings" in html


def test_dashboard_empty(tmp_path: Path):
    db = tmp_path / "empty.db"
    FindingsStore(db).close()
    out = generate_dashboard(db, tmp_path / "d.html")
    assert "No findings yet" in out.read_text()


def test_triage_report(tmp_path: Path):
    db = tmp_path / "f.db"
    s = FindingsStore(db)
    common = dict(target="t", hypothesis_id="H1", cwe="CWE-89", file="q.py",
                  line_range="10", title="SQLi", severity="high", validated=True,
                  has_patch=False, has_report=False, artifact_dir=tmp_path)
    s.record(run_id="r1", **common)
    s.record(run_id="r2", **common)
    s.close()
    rep = triage_report(db)
    assert rep["total"] == 2
    assert len(rep["duplicates"]) == 1
