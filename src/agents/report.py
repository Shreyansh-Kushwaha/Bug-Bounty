"""Report agent: drafts a responsible-disclosure report in HackerOne style."""

from __future__ import annotations

from pydantic import BaseModel, Field

from src.agents.analyst import Hypothesis
from src.agents.base import Agent
from src.agents.exploit import ExploitOutput
from src.agents.patch import Patch
from src.models.router import Tier


class ReportInput(BaseModel):
    target: str
    repo_url: str
    hypothesis: Hypothesis
    exploit: ExploitOutput
    patch: Patch | None = None


class Report(BaseModel):
    title: str
    target: str
    cwe: str
    cvss_vector: str = Field(
        description="e.g. CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
    )
    cvss_score: float
    severity: str
    summary: str
    steps_to_reproduce: list[str]
    proof_of_concept: str
    impact: str
    remediation: str
    references: list[str] = Field(default_factory=list)
    markdown: str = Field(description="Full report formatted as markdown")


class ReportAgent(Agent[ReportInput, Report]):
    name = "Report"
    tier = Tier.FAST

    def system_prompt(self) -> str:
        return (
            "You draft responsible-disclosure reports for bug bounty programs. "
            "Use HackerOne report structure: Summary, Steps to Reproduce, PoC, Impact, "
            "Suggested Remediation, References. Include a CVSS 3.1 vector and score. "
            "Be precise, factual, and constructive. Output ONLY valid JSON."
        )

    def build_prompt(self, inp: ReportInput) -> str:
        h = inp.hypothesis
        patch_block = ""
        if inp.patch:
            patch_block = f"Proposed patch rationale: {inp.patch.rationale}\n"
            patch_block += f"Test: {inp.patch.regression_test_path}"

        return f"""Target: {inp.target} ({inp.repo_url})

Vulnerability:
  id: {h.id}
  file: {h.file}:{h.line_range}
  cwe: {h.cwe}
  title: {h.title}
  description: {h.description}
  severity hint: {h.severity}, exploitability hint: {h.exploitability}

PoC (validated={inp.exploit.validated}):
{inp.exploit.poc.code[:2500]}

Reproduction steps from exploit agent:
{inp.exploit.poc.reproduction_steps}

{patch_block}

Produce JSON:
{{
  "title": "short descriptive title",
  "target": "{inp.target}",
  "cwe": "{h.cwe}",
  "cvss_vector": "CVSS:3.1/AV:.../AC:.../...",
  "cvss_score": 0.0,
  "severity": "Critical|High|Medium|Low",
  "summary": "1 paragraph",
  "steps_to_reproduce": ["step 1", "step 2"],
  "proof_of_concept": "the PoC code or command",
  "impact": "what an attacker gains",
  "remediation": "how to fix",
  "references": ["CWE URL", "related CVE if any"],
  "markdown": "the full report formatted as markdown using all the fields above"
}}
"""

    def output_model(self) -> type[Report]:
        return Report
