"""Multi-provider LLM router with automatic failover.

Tiers:
  - reasoning: deep code analysis (Analyst, Patch) -> Gemini 2.5 Pro / DeepSeek R1
  - fast:      routing, classification, summarization -> Gemini Flash / Groq Llama
  - coder:     patch writing                          -> Qwen 2.5 Coder / DeepSeek

Providers are tried in order; on rate-limit or transient error, falls through.
"""

from __future__ import annotations

import os
import time
from dataclasses import dataclass
from enum import Enum
from typing import Callable

from dotenv import load_dotenv

load_dotenv()


class Tier(str, Enum):
    REASONING = "reasoning"
    FAST = "fast"
    CODER = "coder"


@dataclass
class LLMResponse:
    text: str
    provider: str
    model: str


class AllProvidersExhausted(RuntimeError):
    pass


class _Provider:
    name: str

    def available(self) -> bool: ...
    def call(self, prompt: str, system: str | None, tier: Tier) -> LLMResponse: ...


class GeminiProvider(_Provider):
    name = "gemini"

    MODELS = {
        Tier.REASONING: "gemini-3-flash-preview",
        Tier.FAST: "gemini-3-flash-preview",
        Tier.CODER: "gemini-3-flash-preview",
    }
    # Ordered fallback list per tier — tried in sequence on 503/429
    FALLBACK_MODELS: dict[Tier, list[str]] = {
        Tier.REASONING: ["gemini-2.5-flash", "gemini-2.5-flash-lite"],
        Tier.FAST: ["gemini-2.5-flash", "gemini-2.5-flash-lite"],
        Tier.CODER: ["gemini-2.5-flash", "gemini-2.5-flash-lite"],
    }

    def __init__(self):
        self.key = os.getenv("GEMINI_API_KEY")
        self._client = None

    def available(self) -> bool:
        return bool(self.key)

    def _get_client(self):
        if self._client is None:
            from google import genai
            self._client = genai.Client(api_key=self.key)
        return self._client

    def call(self, prompt: str, system: str | None, tier: Tier) -> LLMResponse:
        client = self._get_client()
        from google.genai import types
        config = types.GenerateContentConfig(system_instruction=system) if system else None
        candidates = [self.MODELS[tier]] + self.FALLBACK_MODELS.get(tier, [])
        last_err: Exception | None = None
        for model_name in candidates:
            try:
                resp = client.models.generate_content(
                    model=model_name,
                    contents=prompt,
                    config=config,
                )
                return LLMResponse(text=resp.text, provider=self.name, model=model_name)
            except Exception as e:
                msg = str(e).lower()
                if any(k in msg for k in ("503", "unavailable", "overloaded", "high demand", "quota", "429", "resource_exhausted")):
                    last_err = e
                    continue
                raise
        raise last_err


class GroqProvider(_Provider):
    name = "groq"

    MODELS = {
        Tier.REASONING: "llama-3.3-70b-versatile",
        Tier.FAST: "llama-3.1-8b-instant",
        Tier.CODER: "llama-3.3-70b-versatile",
    }

    def __init__(self):
        self.key = os.getenv("GROQ_API_KEY")
        self._client = None

    def available(self) -> bool:
        return bool(self.key)

    def _get_client(self):
        if self._client is None:
            from groq import Groq
            self._client = Groq(api_key=self.key)
        return self._client

    def call(self, prompt: str, system: str | None, tier: Tier) -> LLMResponse:
        client = self._get_client()
        model_name = self.MODELS[tier]
        messages = []
        if system:
            messages.append({"role": "system", "content": system})
        messages.append({"role": "user", "content": prompt})
        resp = client.chat.completions.create(
            model=model_name,
            messages=messages,
            temperature=0.2,
        )
        return LLMResponse(
            text=resp.choices[0].message.content,
            provider=self.name,
            model=model_name,
        )


class OpenRouterProvider(_Provider):
    name = "openrouter"

    MODELS = {
        Tier.REASONING: "deepseek/deepseek-r1:free",
        Tier.FAST: "meta-llama/llama-3.3-70b-instruct:free",
        Tier.CODER: "qwen/qwen-2.5-coder-32b-instruct:free",
    }

    def __init__(self):
        self.key = os.getenv("OPENROUTER_API_KEY")
        self._client = None

    def available(self) -> bool:
        return bool(self.key)

    def _get_client(self):
        if self._client is None:
            from openai import OpenAI
            self._client = OpenAI(
                api_key=self.key,
                base_url="https://openrouter.ai/api/v1",
            )
        return self._client

    def call(self, prompt: str, system: str | None, tier: Tier) -> LLMResponse:
        client = self._get_client()
        model_name = self.MODELS[tier]
        messages = []
        if system:
            messages.append({"role": "system", "content": system})
        messages.append({"role": "user", "content": prompt})
        resp = client.chat.completions.create(
            model=model_name,
            messages=messages,
            temperature=0.2,
        )
        return LLMResponse(
            text=resp.choices[0].message.content,
            provider=self.name,
            model=model_name,
        )


class ModelRouter:
    """Tries providers in order; on failure falls through. Raises if all exhausted."""

    def __init__(self, providers: list[_Provider] | None = None):
        self.providers = providers or [
            GeminiProvider(),
            GroqProvider(),
            OpenRouterProvider(),
        ]
        self._active = [p for p in self.providers if p.available()]
        if not self._active:
            raise RuntimeError(
                "No LLM providers configured. Set at least one of "
                "GEMINI_API_KEY, GROQ_API_KEY, OPENROUTER_API_KEY in .env"
            )

    def active_providers(self) -> list[str]:
        return [p.name for p in self._active]

    def call(
        self,
        prompt: str,
        system: str | None = None,
        tier: Tier = Tier.REASONING,
        max_retries_per_provider: int = 3,
    ) -> LLMResponse:
        errors: list[tuple[str, Exception]] = []
        for provider in self._active:
            for attempt in range(max_retries_per_provider):
                try:
                    return provider.call(prompt, system, tier)
                except Exception as e:  # noqa: BLE001 — intentionally broad for failover
                    errors.append((provider.name, e))
                    msg = str(e).lower()
                    if any(k in msg for k in ("rate", "quota", "429", "503", "unavailable", "overloaded")):
                        time.sleep(5 * (2 ** attempt))
                        continue
                    break
        raise AllProvidersExhausted(
            "All providers failed:\n"
            + "\n".join(f"  {name}: {err}" for name, err in errors)
        )


def default_router() -> ModelRouter:
    return ModelRouter()
