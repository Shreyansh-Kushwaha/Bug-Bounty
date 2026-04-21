"""Analyst agent: forms ranked vulnerability hypotheses from Recon output."""

from __future__ import annotations

from pathlib import Path

from pydantic import BaseModel, Field

from src.agents.base import Agent
from src.agents.recon import ReconOutput
from src.models.router import Tier


class AnalystInput(BaseModel):
    recon: ReconOutput
    clone_dir: Path
    max_files_to_read: int = 10


class Hypothesis(BaseModel):
    id: str = Field(description="Short stable ID, e.g. 'H1'")
    file: str
    line_range: str = Field(description="e.g. '84-92' or 'unknown'")
    cwe: str = Field(description="CWE identifier, e.g. 'CWE-502'")
    title: str
    description: str
    severity: str = Field(description="critical | high | medium | low")
    exploitability: str = Field(description="high | medium | low")
    rank: int = Field(description="1 = highest priority")
    evidence_snippet: str


class AnalystOutput(BaseModel):
    target: str
    hypotheses: list[Hypothesis]
    summary: str


class AnalystAgent(Agent[AnalystInput, AnalystOutput]):
    name = "Analyst"
    tier = Tier.REASONING

    def system_prompt(self) -> str:
        return (
            "You are a senior application security engineer. Given a recon summary "
            "and source code of suspected-risky files, produce ranked vulnerability "
            "hypotheses. Each hypothesis MUST cite a real line from the provided "
            "source — do not invent code. If the evidence is weak, mark exploitability "
            "as low or omit the hypothesis. Output ONLY valid JSON."
        )

    def build_prompt(self, inp: AnalystInput) -> str:
        file_contents = self._read_risky_files(inp)
        recon_json = inp.recon.model_dump_json(indent=2)

        return f"""Recon findings:
{recon_json}

Source of risky files (truncated):
{file_contents}

Produce JSON:
{{
  "target": "{inp.recon.target}",
  "hypotheses": [
    {{
      "id": "H1",
      "file": "relative/path.py",
      "line_range": "84-92",
      "cwe": "CWE-502",
      "title": "Short descriptive name",
      "description": "Why this is exploitable, what the attacker controls",
      "severity": "critical|high|medium|low",
      "exploitability": "high|medium|low",
      "rank": 1,
      "evidence_snippet": "the exact vulnerable line(s)"
    }}
  ],
  "summary": "2-3 sentence overview"
}}
Rank 1 = highest priority. Produce 1-5 hypotheses; quality over quantity.
"""

    def output_model(self) -> type[AnalystOutput]:
        return AnalystOutput

    @staticmethod
    def _read_risky_files(inp: AnalystInput) -> str:
        out = []
        budget = 16000
        for rf in inp.recon.risky_files[: inp.max_files_to_read]:
            path = inp.clone_dir / rf.path
            if not path.exists() or not path.is_file():
                continue
            try:
                text = path.read_text(errors="ignore")
            except (OSError, UnicodeDecodeError):
                continue
            snippet = text[:3000]
            out.append(f"\n--- {rf.path} (risk={rf.risk_level}, reason={rf.reason}) ---\n{snippet}")
            budget -= len(snippet)
            if budget <= 0:
                out.append("\n... (remaining files truncated) ...")
                break
        return "\n".join(out)
