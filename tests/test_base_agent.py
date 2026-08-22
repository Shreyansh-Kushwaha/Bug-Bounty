import pytest
from pydantic import BaseModel

from src.agents.base import Agent
from src.models.router import MockProvider, ModelRouter, Tier


class Out(BaseModel):
    value: int


class Toy(Agent):
    name = "Toy"
    tier = Tier.FAST

    def system_prompt(self):
        return "sys"

    def build_prompt(self, inp):
        return inp

    def output_model(self):
        return Out


def test_parse_plain_json():
    assert Agent._parse_json('{"a": 1}') == {"a": 1}


def test_parse_fenced_json():
    assert Agent._parse_json('prefix\n```json\n{"a": 2}\n```\nsuffix') == {"a": 2}


def test_parse_embedded_json():
    assert Agent._parse_json('here you go: {"a": 3} thanks') == {"a": 3}


def test_parse_no_json_raises():
    with pytest.raises(ValueError):
        Agent._parse_json("no json here at all")


def test_json_repair_recovers():
    # First response is garbage; the repair reprompt returns valid JSON.
    provider = MockProvider({
        "Return ONLY a single valid JSON object": '{"value": 42}',
    }, default="not json at all")
    router = ModelRouter(providers=[provider])
    agent = Toy(router)
    out = agent.run("first user prompt")
    assert out.value == 42
