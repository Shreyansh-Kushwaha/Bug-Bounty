from pathlib import Path

from src.agents.exploit import ExploitAgent, ExploitInput, PoC
from src.agents.analyst import Hypothesis
from src.models.router import MockProvider, ModelRouter
from src.sandbox import docker_runner
from src.sandbox.patch_verifier import verify_patch


def _hyp() -> Hypothesis:
    return Hypothesis(
        id="H1", file="v.py", line_range="1-2", cwe="CWE-502",
        title="t", description="d", severity="high", exploitability="high",
        rank=1, evidence_snippet="yaml.load(x)",
    )


def test_destructive_poc_is_refused(monkeypatch):
    # If docker were available, a destructive PoC must still never execute.
    called = {"ran": False}
    monkeypatch.setattr(docker_runner, "docker_available", lambda: True)

    def fake_run(*a, **k):
        called["ran"] = True
        return docker_runner.SandboxResult(True, 0, "PWNED", "", False)

    monkeypatch.setattr("src.agents.exploit.run_poc", fake_run)

    poc_json = PoC(language="python", code="", reproduction_steps=[],
                   expected_signal="PWNED", destructive=True).model_dump_json()
    router = ModelRouter(providers=[MockProvider(default=poc_json)])
    out = ExploitAgent(router).run(ExploitInput(hypothesis=_hyp(), clone_dir=Path(".")))
    assert out.validated is False
    assert called["ran"] is False
    assert "refused" in (out.validation_reason or "").lower()


def test_validated_when_signal_present(monkeypatch):
    monkeypatch.setattr(
        "src.agents.exploit.run_poc",
        lambda **k: docker_runner.SandboxResult(True, 0, "...PWNED...", "", False),
    )
    poc_json = PoC(language="python", code="print('PWNED')", reproduction_steps=["run"],
                   expected_signal="PWNED").model_dump_json()
    router = ModelRouter(providers=[MockProvider(default=poc_json)])
    out = ExploitAgent(router).run(ExploitInput(hypothesis=_hyp(), clone_dir=Path(".")))
    assert out.validated is True


def test_run_poc_no_docker(monkeypatch):
    monkeypatch.setattr(docker_runner, "docker_available", lambda: False)
    res = docker_runner.run_poc("print(1)", "python")
    assert res.executed is False
    assert "docker" in (res.reason or "").lower()


def test_verify_patch_degrades_without_docker(monkeypatch, tmp_path):
    monkeypatch.setattr(docker_runner, "docker_available", lambda: False)
    (tmp_path / "v.py").write_text("x = 1\n")
    from src.agents.patch import FileEdit

    v = verify_patch(
        clone_dir=tmp_path,
        files_modified=[FileEdit(path="v.py", unified_diff="")],
        regression_test_path="tests/test_x.py",
        regression_test_code="def test_x():\n    assert True\n",
    )
    assert v.verified is False
    assert v.applied is False
