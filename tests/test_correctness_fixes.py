"""Regression tests for the Phase-0 correctness fixes."""

from pathlib import Path

from src.agents.analyst import Hypothesis
from src.agents.exploit import ExploitAgent, ExploitInput, PoC
from src.models.router import LLMResponse, ModelRouter, MockProvider, ResponseCache, Tier, Usage
from src.sandbox import docker_runner
from src.scanners.deps import _cvss3_base_score, _cvss_to_band, _osv_severity


def _hyp() -> Hypothesis:
    return Hypothesis(
        id="H1", file="v.py", line_range="1-2", cwe="CWE-502",
        title="t", description="d", severity="high", exploitability="high",
        rank=1, evidence_snippet="yaml.load(x)",
    )


# --- Exploit validation no longer false-positives on a clean exit ---------

def test_no_signal_clean_exit_is_not_validated(monkeypatch):
    """A PoC that exits 0 but declares no expected_signal must NOT validate."""
    monkeypatch.setattr(
        "src.agents.exploit.run_poc",
        lambda **k: docker_runner.SandboxResult(True, 0, "some output", "", False),
    )
    poc_json = PoC(language="python", code="print('hi')", reproduction_steps=["run"],
                   expected_signal="").model_dump_json()
    router = ModelRouter(providers=[MockProvider(default=poc_json)])
    out = ExploitAgent(router).run(ExploitInput(hypothesis=_hyp(), clone_dir=Path(".")))
    assert out.validated is False
    assert "not proof" in (out.validation_reason or "").lower()


def test_signal_missing_is_not_validated(monkeypatch):
    monkeypatch.setattr(
        "src.agents.exploit.run_poc",
        lambda **k: docker_runner.SandboxResult(True, 0, "nothing here", "", False),
    )
    poc_json = PoC(language="python", code="print('x')", reproduction_steps=["run"],
                   expected_signal="PWNED").model_dump_json()
    router = ModelRouter(providers=[MockProvider(default=poc_json)])
    out = ExploitAgent(router).run(ExploitInput(hypothesis=_hyp(), clone_dir=Path(".")))
    assert out.validated is False


# --- CVSS vector -> severity band -----------------------------------------

def test_cvss3_base_score_known_vectors():
    # Critical (9.8) — network RCE, no privileges/UI.
    s = _cvss3_base_score("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")
    assert abs(s - 9.8) < 0.05
    # Medium (6.1) — reflected XSS, scope changed.
    s2 = _cvss3_base_score("CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N")
    assert abs(s2 - 6.1) < 0.05


def test_cvss_to_band_numeric_and_vector():
    assert _cvss_to_band("9.8") == "critical"
    assert _cvss_to_band("7.0") == "high"
    assert _cvss_to_band("5.5") == "medium"
    assert _cvss_to_band("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H") == "critical"
    assert _cvss_to_band("garbage") == "unknown"


def test_osv_severity_prefers_band_word():
    assert _osv_severity({"database_specific": {"severity": "MODERATE"}}) == "medium"
    assert _osv_severity({"severity": [{"type": "CVSS_V3",
                          "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}]}) == "critical"
    assert _osv_severity({}) == "unknown"


# --- Cache keys consistently across a provider's model fallback -----------

class _FallbackProvider(MockProvider):
    """Primary model 'primary-1' but always answers as fallback 'fallback-2'."""

    name = "fallbackprov"
    MODELS = {Tier.FAST: "primary-1", Tier.REASONING: "primary-1", Tier.CODER: "primary-1"}

    def call(self, prompt, system, tier):
        return LLMResponse(text="answer", provider=self.name, model="fallback-2",
                           usage=Usage(prompt_tokens=1, completion_tokens=1))


def test_cache_hits_when_fallback_model_answered(tmp_path):
    cache = ResponseCache(tmp_path / "cache")
    r = ModelRouter(providers=[_FallbackProvider()], cache=cache)
    first = r.call("prompt", tier=Tier.FAST)
    assert first.cached is False
    second = r.call("prompt", tier=Tier.FAST)
    assert second.cached is True
    assert r.cache_hits == 1
