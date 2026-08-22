from pathlib import Path

import pytest

from src.models.router import (
    AllProvidersExhausted,
    MockProvider,
    ModelRouter,
    ResponseCache,
    Tier,
)


def test_mock_provider_matches_and_defaults():
    p = MockProvider({"hello": "world"}, default="none")
    r = ModelRouter(providers=[p])
    assert r.call("say hello please").text == "world"
    assert r.call("nothing here").text == "none"
    assert r.call_count == 2


def test_usage_accounting():
    p = MockProvider(default="a response")
    r = ModelRouter(providers=[p])
    r.call("some prompt")
    assert r.total_usage.prompt_tokens > 0
    assert r.total_usage.completion_tokens > 0


class _Boom(MockProvider):
    name = "boom"

    def call(self, *a, **k):
        raise RuntimeError("permanent failure")


def test_failover_to_next_provider():
    good = MockProvider(default="ok")
    r = ModelRouter(providers=[_Boom(), good])
    assert r.call("x").text == "ok"


def test_all_providers_exhausted():
    r = ModelRouter(providers=[_Boom()])
    with pytest.raises(AllProvidersExhausted):
        r.call("x")


def test_cache_round_trip(tmp_path: Path):
    cache = ResponseCache(tmp_path / "cache")
    counter = {"n": 0}

    class Counting(MockProvider):
        name = "counting"

        def call(self, *a, **k):
            counter["n"] += 1
            return super().call(*a, **k)

    r = ModelRouter(providers=[Counting(default="cached-value")], cache=cache)
    first = r.call("prompt", tier=Tier.FAST)
    assert first.cached is False
    second = r.call("prompt", tier=Tier.FAST)
    assert second.cached is True
    assert second.text == "cached-value"
    assert counter["n"] == 1  # provider only hit once
    assert r.cache_hits == 1
