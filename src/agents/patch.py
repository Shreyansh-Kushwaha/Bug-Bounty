"""Patch agent: proposes a minimal fix plus a regression test."""

from __future__ import annotations

from pathlib import Path

from pydantic import BaseModel, Field

from src.agents.analyst import Hypothesis
from src.agents.base import Agent
from src.agents.exploit import ExploitOutput
from src.models.router import Tier


class PatchInput(BaseModel):
    hypothesis: Hypothesis
    exploit: ExploitOutput
    clone_dir: Path
    source_context: str = ""


class FileEdit(BaseModel):
    path: str
    unified_diff: str = Field(description="Standard unified diff against the current file")


class Patch(BaseModel):
    hypothesis_id: str
    files_modified: list[FileEdit]
    regression_test_path: str
    regression_test_code: str
    rationale: str
    minimal: bool = Field(description="True if this is the smallest safe fix")


class PatchAgent(Agent[PatchInput, Patch]):
    name = "Patch"
    tier = Tier.CODER

    def system_prompt(self) -> str:
        return (
            "You are a senior engineer writing the MINIMAL secure fix for a confirmed "
            "vulnerability. Preserve existing public API, follow the project's style, "
            "and include a regression test that would fail before the patch and pass "
            "after. Output ONLY valid JSON."
        )

    def build_prompt(self, inp: PatchInput) -> str:
        h = inp.hypothesis
        return f"""Confirmed vulnerability:
  id: {h.id}
  file: {h.file}:{h.line_range}
  cwe: {h.cwe}
  title: {h.title}

PoC that triggers it (language={inp.exploit.poc.language}):
{inp.exploit.poc.code[:3000]}

Current source context:
{inp.source_context[:6000]}

Produce JSON:
{{
  "hypothesis_id": "{h.id}",
  "files_modified": [
    {{"path": "relative/path.py", "unified_diff": "--- a/...\\n+++ b/...\\n@@ ...\\n-old\\n+new"}}
  ],
  "regression_test_path": "tests/test_{h.id.lower()}_regression.py",
  "regression_test_code": "full test file contents",
  "rationale": "why this fixes it and why it is minimal",
  "minimal": true
}}
"""

    def output_model(self) -> type[Patch]:
        return Patch
