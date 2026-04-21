"""Base class for all agents. Handles structured output parsing and logging."""

from __future__ import annotations

import json
import re
from abc import ABC, abstractmethod
from pathlib import Path
from typing import Generic, TypeVar

from pydantic import BaseModel, ValidationError
from rich.console import Console

from src.models.router import ModelRouter, Tier, default_router

TInput = TypeVar("TInput", bound=BaseModel)
TOutput = TypeVar("TOutput", bound=BaseModel)

console = Console()


class Agent(ABC, Generic[TInput, TOutput]):
    """Each agent has a typed input/output contract and a single `run` method."""

    name: str
    tier: Tier = Tier.REASONING

    def __init__(self, router: ModelRouter | None = None):
        self.router = router or default_router()

    @abstractmethod
    def system_prompt(self) -> str: ...

    @abstractmethod
    def build_prompt(self, inp: TInput) -> str: ...

    @abstractmethod
    def output_model(self) -> type[TOutput]: ...

    def run(self, inp: TInput) -> TOutput:
        console.rule(f"[bold cyan]{self.name}[/]")
        console.print(f"[dim]tier={self.tier.value} providers={self.router.active_providers()}[/]")

        prompt = self.build_prompt(inp)
        resp = self.router.call(prompt, system=self.system_prompt(), tier=self.tier)

        console.print(f"[green]↳ {resp.provider}/{resp.model}[/]")

        parsed = self._parse_json(resp.text)
        try:
            return self.output_model().model_validate(parsed)
        except ValidationError as e:
            console.print(f"[red]Validation failed:[/]\n{e}")
            console.print(f"[dim]Raw model output:\n{resp.text[:2000]}[/]")
            raise

    @staticmethod
    def _parse_json(text: str) -> dict:
        """Extract JSON from a model response. Handles ```json fences and plain JSON."""
        fence = re.search(r"```(?:json)?\s*(.*?)```", text, re.DOTALL)
        payload = fence.group(1).strip() if fence else text.strip()
        start = payload.find("{")
        end = payload.rfind("}")
        if start == -1 or end == -1:
            raise ValueError(f"No JSON object found in response: {text[:500]}")
        return json.loads(payload[start : end + 1])


def save_artifact(name: str, data: dict, out_dir: Path) -> Path:
    out_dir.mkdir(parents=True, exist_ok=True)
    path = out_dir / f"{name}.json"
    path.write_text(json.dumps(data, indent=2))
    return path
