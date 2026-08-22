import json
from pathlib import Path

import src.orchestrator as orch
from src.agents.recon import ReconAgent
from src.models.router import MockProvider, ModelRouter
from src.sandbox import docker_runner
from src.sandbox.patch_verifier import PatchVerification
from src.store.audit import AuditLog
from src.store.findings import FindingsStore

RECON = json.dumps({
    "target": "demo",
    "entry_points": ["v.py"],
    "risky_files": [{"path": "v.py", "reason": "yaml.load", "risk_level": "high",
                     "cwe_hints": ["CWE-502"]}],
    "dependencies": ["pyyaml"],
    "summary": "One risky file.",
})
ANALYST = json.dumps({
    "target": "demo",
    "hypotheses": [{
        "id": "H1", "file": "v.py", "line_range": "1-2", "cwe": "CWE-502",
        "title": "Unsafe yaml.load", "description": "attacker controls input",
        "severity": "high", "exploitability": "high", "rank": 1,
        "evidence_snippet": "yaml.load(data)",
    }],
    "summary": "Deserialization.",
})
EXPLOIT = json.dumps({
    "language": "python", "code": "print('PWNED')",
    "reproduction_steps": ["run poc"], "expected_signal": "PWNED",
    "extra_files": {}, "destructive": False,
})
PATCH = json.dumps({
    "hypothesis_id": "H1",
    "files_modified": [{"path": "v.py",
                        "unified_diff": "--- a/v.py\n+++ b/v.py\n@@ -1 +1 @@\n-yaml.load(data)\n+yaml.safe_load(data)\n"}],
    "regression_test_path": "tests/test_h1.py",
    "regression_test_code": "def test_h1():\n    assert True\n",
    "rationale": "use safe_load", "minimal": True,
})
REPORT = json.dumps({
    "title": "Unsafe Deserialization in v.py", "target": "demo", "cwe": "CWE-502",
    "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", "cvss_score": 9.8,
    "severity": "Critical", "summary": "s", "steps_to_reproduce": ["a"],
    "proof_of_concept": "print('PWNED')", "impact": "RCE", "remediation": "safe_load",
    "references": ["https://cwe.mitre.org/data/definitions/502.html"],
    "markdown": "# Report\nBody.",
})

RESPONSES = {
    "Pattern scan hits": RECON,
    "Recon findings:": ANALYST,
    "Hypothesis to prove:": EXPLOIT,
    "Confirmed vulnerability:": PATCH,
    "Reproduction steps from exploit agent:": REPORT,
}


def _ctx(tmp_path: Path):
    clone = tmp_path / "repo"
    clone.mkdir()
    (clone / "v.py").write_text("yaml.load(data)\n")
    router = ModelRouter(providers=[MockProvider(RESPONSES, default="{}")])
    return orch.RunContext(
        run_id="demo_test",
        target={"name": "demo", "repo": "https://example/demo.git", "ref": "main"},
        clone_dir=clone,
        artifact_dir=tmp_path / "artifacts",
        audit=AuditLog(tmp_path / "audit.jsonl"),
        store=FindingsStore(tmp_path / "findings.db"),
        router=router,
        auto_approve=True,
        top_n=1,
    ), clone


def test_full_pipeline_offline(tmp_path, monkeypatch):
    ctx, _ = _ctx(tmp_path)
    ctx.artifact_dir.mkdir(parents=True, exist_ok=True)

    # Offline stubs: no clone, no semgrep, sandbox "succeeds", patch "verifies".
    monkeypatch.setattr(ReconAgent, "clone", staticmethod(lambda *a, **k: None))
    monkeypatch.setattr(ReconAgent, "_semgrep_scan", classmethod(lambda cls, root: ""))
    monkeypatch.setattr(
        "src.agents.exploit.run_poc",
        lambda **k: docker_runner.SandboxResult(True, 0, "PWNED", "", False),
    )
    monkeypatch.setattr(
        orch, "verify_patch",
        lambda **k: PatchVerification(True, True, True, True, "confirmed"),
    )

    orch.run_pipeline(ctx, stop_after=None)

    # Artifacts on disk
    for name in ("01_recon", "02_analyst", "03_exploit_H1", "04_patch_H1", "05_report_H1"):
        assert (ctx.artifact_dir / f"{name}.json").exists(), name
    assert (ctx.artifact_dir / "05_report_H1.md").exists()

    # Finding recorded end to end
    rows = ctx.store.list_findings()
    assert len(rows) == 1
    r = rows[0]
    assert r["validated"] == 1 and r["has_patch"] == 1
    assert r["patch_validated"] == 1 and r["has_report"] == 1
    assert r["severity"] == "Critical"

    # Audit chain intact and cost recorded
    ok, broken = ctx.audit.verify()
    assert ok and broken is None
    assert ctx.router.call_count >= 5
    ctx.store.close()


def test_stop_after_analyst(tmp_path, monkeypatch):
    ctx, _ = _ctx(tmp_path)
    ctx.artifact_dir.mkdir(parents=True, exist_ok=True)
    monkeypatch.setattr(ReconAgent, "clone", staticmethod(lambda *a, **k: None))
    monkeypatch.setattr(ReconAgent, "_semgrep_scan", classmethod(lambda cls, root: ""))

    orch.run_pipeline(ctx, stop_after="analyst")
    assert (ctx.artifact_dir / "02_analyst.json").exists()
    assert not (ctx.artifact_dir / "03_exploit_H1.json").exists()
    assert ctx.store.list_findings() == []
    ctx.store.close()


def test_resume_reuses_artifacts(tmp_path, monkeypatch):
    ctx, _ = _ctx(tmp_path)
    ctx.artifact_dir.mkdir(parents=True, exist_ok=True)
    (ctx.artifact_dir / "01_recon.json").write_text(RECON)
    (ctx.artifact_dir / "02_analyst.json").write_text(ANALYST)

    # If resume works, clone/recon/analyst LLM calls are skipped entirely.
    def boom(*a, **k):
        raise AssertionError("should not be called on resume")

    monkeypatch.setattr(ReconAgent, "clone", staticmethod(boom))
    monkeypatch.setattr(
        "src.agents.exploit.run_poc",
        lambda **k: docker_runner.SandboxResult(True, 0, "PWNED", "", False),
    )
    monkeypatch.setattr(
        orch, "verify_patch",
        lambda **k: PatchVerification(True, True, True, True, "confirmed"),
    )

    orch.run_pipeline(ctx, stop_after="exploit", resume=True)
    assert (ctx.artifact_dir / "03_exploit_H1.json").exists()
    ctx.store.close()
