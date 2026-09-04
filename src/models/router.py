"""Multi-provider LLM router with automatic failover, caching, and cost tracking.

Tiers:
  - reasoning: deep code analysis (Analyst, Patch) -> Gemini / DeepSeek R1
  - fast:      routing, classification, summarization -> Gemini Flash / Groq Llama
  - coder:     patch writing                          -> Qwen 2.5 Coder / DeepSeek

Providers are tried in order; on rate-limit or transient error, falls through.
Within a provider, models are tried in a fallback chain (primary -> fallbacks)
on 429/503/overload errors. Responses can be cached on disk (keyed by
prompt+system+model) so re-runs are free and deterministic. Every call records
token usage, an estimated cost, and (best-effort) a persistent per-run usage
row for the dashboard/quota tracking.
"""

from __future__ import annotations

import hashlib
import json
import os
import threading
import time
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path

from dotenv import load_dotenv

load_dotenv()


class Tier(str, Enum):
    REASONING = "reasoning"
    FAST = "fast"
    CODER = "coder"


@dataclass
class Usage:
    prompt_tokens: int = 0
    completion_tokens: int = 0
    cost_usd: float = 0.0

    @property
    def total_tokens(self) -> int:
        return self.prompt_tokens + self.completion_tokens


@dataclass
class LLMResponse:
    text: str
    provider: str
    model: str
    usage: Usage = field(default_factory=Usage)
    cached: bool = False


class AllProvidersExhausted(RuntimeError):
    pass


# Rough per-1M-token pricing (USD) for cost estimates. Free tiers are ~0 but we
# keep nominal numbers so the accounting is meaningful if paid keys are used.
# (input, output) per 1M tokens.
_PRICES: dict[str, tuple[float, float]] = {
    "gemini-pro-latest": (1.25, 10.0),
    "gemini-2.5-pro": (1.25, 10.0),
    "gemini-flash-latest": (0.10, 0.40),
    "gemini-2.5-flash": (0.10, 0.40),
    "gemini-2.5-flash-lite": (0.05, 0.20),
    "gemini-3-flash-preview": (0.10, 0.40),
    "gemini-2.0-flash": (0.10, 0.40),
    "llama-3.3-70b-versatile": (0.59, 0.79),
    "llama-3.1-8b-instant": (0.05, 0.08),
    "claude-sonnet-5": (3.0, 15.0),
    "claude-haiku-4-5-20251001": (1.0, 5.0),
}

# Hardcoded Gemini free-tier daily request limits on this project's API key.
# Update as Google revises them. Missing keys mean "no limit enforced / unknown".
MODEL_DAILY_LIMITS: dict[str, int] = {
    "gemini-2.5-flash-lite": 20,
    "gemini-2.5-flash": 50,
    "gemini-3-flash-preview": 50,
}


def _estimate_cost(model: str, u: Usage) -> float:
    inp, out = _PRICES.get(model, (0.0, 0.0))
    return round(u.prompt_tokens / 1e6 * inp + u.completion_tokens / 1e6 * out, 6)


def _approx_tokens(text: str) -> int:
    """Cheap token estimate (~4 chars/token) for providers that don't report usage."""
    return max(1, len(text) // 4)


_usage_store_singleton = None


def _usage_store():
    """Lazy singleton so the CLI doesn't pay the import/connect cost unless used."""
    global _usage_store_singleton
    if _usage_store_singleton is None:
        from src.store.usage import UsageStore
        root = Path(__file__).resolve().parent.parent.parent
        _usage_store_singleton = UsageStore(root / "data" / "findings.db")
    return _usage_store_singleton


def _record_usage(resp: LLMResponse) -> None:
    """Persist a usage row for the dashboard/quota tracking. Best-effort — a
    telemetry failure must never break the LLM call it's recording."""
    try:
        from src.current_run import get_run_id
        _usage_store().record(
            run_id=get_run_id(),
            provider=resp.provider,
            model=resp.model,
            prompt_tokens=resp.usage.prompt_tokens,
            completion_tokens=resp.usage.completion_tokens,
            total_tokens=resp.usage.total_tokens,
        )
    except Exception:  # noqa: BLE001
        pass


class _Provider:
    name: str

    def available(self) -> bool: ...
    def call(self, prompt: str, system: str | None, tier: Tier) -> LLMResponse: ...


class GeminiProvider(_Provider):
    name = "gemini"

    # Override any tier via env, e.g. GEMINI_MODEL_FAST=gemini-3.6-flash.
    MODELS = {
        Tier.REASONING: os.getenv("GEMINI_MODEL_REASONING", "gemini-3-flash-preview"),
        Tier.FAST: os.getenv("GEMINI_MODEL_FAST", "gemini-3-flash-preview"),
        Tier.CODER: os.getenv("GEMINI_MODEL_CODER", "gemini-3-flash-preview"),
    }
    # Ordered fallback list per tier — tried in sequence on 429/503/overload.
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
                    model=model_name, contents=prompt, config=config,
                )
                meta = getattr(resp, "usage_metadata", None)
                usage = Usage(
                    prompt_tokens=getattr(meta, "prompt_token_count", 0) or 0,
                    completion_tokens=getattr(meta, "candidates_token_count", 0) or 0,
                )
                usage.cost_usd = _estimate_cost(model_name, usage)
                llm = LLMResponse(text=resp.text, provider=self.name, model=model_name, usage=usage)
                _record_usage(llm)
                return llm
            except Exception as e:  # noqa: BLE001
                msg = str(e).lower()
                if any(k in msg for k in (
                    "503", "unavailable", "overloaded", "high demand",
                    "quota", "429", "resource_exhausted",
                )):
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
        usage = _usage_from_openai(resp, model_name, system, prompt)
        llm = LLMResponse(
            text=resp.choices[0].message.content,
            provider=self.name,
            model=model_name,
            usage=usage,
        )
        _record_usage(llm)
        return llm


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
        usage = _usage_from_openai(resp, model_name, system, prompt)
        llm = LLMResponse(
            text=resp.choices[0].message.content,
            provider=self.name,
            model=model_name,
            usage=usage,
        )
        _record_usage(llm)
        return llm


class AnthropicProvider(_Provider):
    name = "anthropic"

    MODELS = {
        Tier.REASONING: "claude-sonnet-5",
        Tier.FAST: "claude-haiku-4-5-20251001",
        Tier.CODER: "claude-sonnet-5",
    }

    def __init__(self):
        self.key = os.getenv("ANTHROPIC_API_KEY")
        self._client = None

    def available(self) -> bool:
        return bool(self.key)

    def _get_client(self):
        if self._client is None:
            import anthropic
            self._client = anthropic.Anthropic(api_key=self.key)
        return self._client

    def call(self, prompt: str, system: str | None, tier: Tier) -> LLMResponse:
        client = self._get_client()
        model_name = self.MODELS[tier]
        resp = client.messages.create(
            model=model_name,
            max_tokens=4096,
            system=system or "",
            messages=[{"role": "user", "content": prompt}],
            temperature=0.2,
        )
        text = "".join(block.text for block in resp.content if getattr(block, "type", "") == "text")
        usage = Usage()
        if getattr(resp, "usage", None) is not None:
            usage.prompt_tokens = resp.usage.input_tokens
            usage.completion_tokens = resp.usage.output_tokens
        usage.cost_usd = _estimate_cost(model_name, usage)
        llm = LLMResponse(text=text, provider=self.name, model=model_name, usage=usage)
        _record_usage(llm)
        return llm


class OllamaProvider(_Provider):
    """Local models via Ollama (http://localhost:11434). Free, offline fallback."""

    name = "ollama"

    def __init__(self):
        self.host = os.getenv("OLLAMA_HOST", "http://localhost:11434")
        self.model = os.getenv("OLLAMA_MODEL", "")

    def available(self) -> bool:
        # Only advertise availability if the user explicitly opted in with a model.
        return bool(self.model)

    def call(self, prompt: str, system: str | None, tier: Tier) -> LLMResponse:
        import urllib.request

        body = json.dumps({
            "model": self.model,
            "prompt": prompt,
            "system": system or "",
            "stream": False,
            "options": {"temperature": 0.2},
        }).encode()
        req = urllib.request.Request(
            f"{self.host}/api/generate", data=body,
            headers={"Content-Type": "application/json"},
        )
        with urllib.request.urlopen(req, timeout=180) as r:
            data = json.loads(r.read().decode())
        text = data.get("response", "")
        usage = Usage(
            prompt_tokens=data.get("prompt_eval_count", _approx_tokens((system or "") + prompt)),
            completion_tokens=data.get("eval_count", _approx_tokens(text)),
        )
        llm = LLMResponse(text=text, provider=self.name, model=self.model, usage=usage)
        _record_usage(llm)
        return llm


class MockProvider(_Provider):
    """Deterministic offline provider for tests and dry runs.

    `responses` maps a substring found in the prompt -> canned response text.
    The first matching key wins; `default` is used when nothing matches.
    """

    name = "mock"
    model = "mock-1"

    def __init__(self, responses: dict[str, str] | None = None, default: str = "{}"):
        self.responses = responses or {}
        self.default = default
        self.calls: list[dict] = []

    def available(self) -> bool:
        return True

    def call(self, prompt: str, system: str | None, tier: Tier) -> LLMResponse:
        self.calls.append({"prompt": prompt, "system": system, "tier": tier.value})
        text = self.default
        for needle, canned in self.responses.items():
            if needle in prompt:
                text = canned
                break
        usage = Usage(
            prompt_tokens=_approx_tokens((system or "") + prompt),
            completion_tokens=_approx_tokens(text),
        )
        return LLMResponse(text=text, provider=self.name, model=self.model, usage=usage)


def _usage_from_openai(resp, model_name: str, system: str | None, prompt: str) -> Usage:
    usage = Usage()
    u = getattr(resp, "usage", None)
    if u is not None:
        usage.prompt_tokens = getattr(u, "prompt_tokens", 0) or 0
        usage.completion_tokens = getattr(u, "completion_tokens", 0) or 0
    else:
        usage.prompt_tokens = _approx_tokens((system or "") + prompt)
        usage.completion_tokens = _approx_tokens(resp.choices[0].message.content)
    usage.cost_usd = _estimate_cost(model_name, usage)
    return usage


class ResponseCache:
    """Content-addressed on-disk cache of LLM responses (JSON files)."""

    def __init__(self, cache_dir: Path | None):
        self.dir = cache_dir
        if self.dir is not None:
            self.dir.mkdir(parents=True, exist_ok=True)

    def _key(self, provider: str, model: str, system: str | None, prompt: str) -> str:
        h = hashlib.sha256()
        h.update(f"{provider}\x00{model}\x00{system or ''}\x00{prompt}".encode())
        return h.hexdigest()

    def get(self, provider: str, model: str, system: str | None, prompt: str) -> LLMResponse | None:
        if self.dir is None:
            return None
        path = self.dir / f"{self._key(provider, model, system, prompt)}.json"
        if not path.exists():
            return None
        d = json.loads(path.read_text())
        u = d.get("usage", {})
        return LLMResponse(
            text=d["text"], provider=d["provider"], model=d["model"],
            usage=Usage(u.get("prompt_tokens", 0), u.get("completion_tokens", 0), u.get("cost_usd", 0.0)),
            cached=True,
        )

    def put(
        self,
        system: str | None,
        prompt: str,
        resp: LLMResponse,
        model: str | None = None,
    ) -> None:
        if self.dir is None:
            return
        # Key the write on the SAME model identity that `get` will look up
        # (the tier's requested model), not the model that actually answered.
        # Otherwise a response served by a fallback model is stored under a key
        # no future lookup ever computes, and the cache silently never hits.
        key_model = model or resp.model
        path = self.dir / f"{self._key(resp.provider, key_model, system, prompt)}.json"
        path.write_text(json.dumps({
            "text": resp.text, "provider": resp.provider, "model": resp.model,
            "usage": {
                "prompt_tokens": resp.usage.prompt_tokens,
                "completion_tokens": resp.usage.completion_tokens,
                "cost_usd": resp.usage.cost_usd,
            },
        }, indent=2))


class ModelRouter:
    """Tries providers in order; on failure falls through. Raises if all exhausted.

    Tracks cumulative usage across all calls and optionally caches responses.
    """

    def __init__(
        self,
        providers: list[_Provider] | None = None,
        cache: ResponseCache | None = None,
    ):
        self.providers = providers or [
            GeminiProvider(),
            AnthropicProvider(),
            GroqProvider(),
            OpenRouterProvider(),
            OllamaProvider(),
        ]
        self._active = [p for p in self.providers if p.available()]
        if not self._active:
            raise RuntimeError(
                "No LLM providers configured. Set at least one of "
                "GEMINI_API_KEY, ANTHROPIC_API_KEY, GROQ_API_KEY, OPENROUTER_API_KEY "
                "in .env (or OLLAMA_MODEL for a local model)."
            )
        self.cache = cache
        self.total_usage = Usage()
        self.call_count = 0
        self.cache_hits = 0
        self._acct_lock = threading.Lock()

    def active_providers(self) -> list[str]:
        return [p.name for p in self._active]

    def _account(self, resp: LLMResponse) -> None:
        with self._acct_lock:
            self.call_count += 1
            self.total_usage.prompt_tokens += resp.usage.prompt_tokens
            self.total_usage.completion_tokens += resp.usage.completion_tokens
            if resp.cached:
                self.cache_hits += 1  # cached responses are free — don't add cost
            else:
                self.total_usage.cost_usd = round(
                    self.total_usage.cost_usd + resp.usage.cost_usd, 6
                )

    def call(
        self,
        prompt: str,
        system: str | None = None,
        tier: Tier = Tier.REASONING,
        max_retries_per_provider: int = 3,
    ) -> LLMResponse:
        errors: list[tuple[str, Exception]] = []
        for provider in self._active:
            model_name = getattr(provider, "MODELS", {}).get(tier) or getattr(provider, "model", provider.name)
            if self.cache is not None:
                hit = self.cache.get(provider.name, model_name, system, prompt)
                if hit is not None:
                    self._account(hit)
                    return hit
            for attempt in range(max_retries_per_provider):
                try:
                    resp = provider.call(prompt, system, tier)
                    if self.cache is not None:
                        self.cache.put(system, prompt, resp, model=model_name)
                    self._account(resp)
                    return resp
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


def default_router(cache_dir: Path | None = None) -> ModelRouter:
    cache = ResponseCache(cache_dir) if cache_dir is not None else None
    return ModelRouter(cache=cache)
