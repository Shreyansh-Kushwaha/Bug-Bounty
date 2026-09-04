import pytest

import src.orchestrator as orch
from src.agents.recon import ReconAgent
from src.models.router import MockProvider, ModelRouter
from src.store.audit import AuditLog
from src.store.findings import FindingsStore
from tests.test_orchestrator import RESPONSES


def _ctx(tmp_path, cancel):
    clone = tmp_path / "repo"
    clone.mkdir()
    (clone / "v.py").write_text("yaml.load(data)\n")
    router = ModelRouter(providers=[MockProvider(RESPONSES, default="{}")])
    ctx = orch.RunContext(
        run_id="cancel_test",
        target={"name": "demo", "repo": "https://example/demo.git", "ref": "main"},
        clone_dir=clone,
        artifact_dir=tmp_path / "artifacts",
        audit=AuditLog(tmp_path / "audit.jsonl"),
        store=FindingsStore(tmp_path / "findings.db"),
        router=router,
        auto_approve=True,
        cancel_check=cancel,
    )
    ctx.artifact_dir.mkdir(parents=True, exist_ok=True)
    return ctx


def test_check_cancel_raises(tmp_path):
    ctx = _ctx(tmp_path, cancel=lambda: True)
    with pytest.raises(orch.RunCancelled):
        orch._check_cancel(ctx)
    ctx.store.close()


def test_pipeline_stops_when_cancelled(tmp_path, monkeypatch):
    monkeypatch.setattr(ReconAgent, "clone", staticmethod(lambda *a, **k: None))
    monkeypatch.setattr(ReconAgent, "_semgrep_scan", classmethod(lambda cls, root: ""))
    ctx = _ctx(tmp_path, cancel=lambda: True)
    with pytest.raises(orch.RunCancelled):
        orch.run_pipeline(ctx, stop_after=None)
    # Recon ran and was written, but analyst never did (cancelled at the boundary).
    assert (ctx.artifact_dir / "01_recon.json").exists()
    assert not (ctx.artifact_dir / "02_analyst.json").exists()
    ctx.store.close()
