from __future__ import annotations

import json

from pydantic import BaseModel

import pytest

from fortiedr_mcp.errors import FortiEDRLLMResponseError
from fortiedr_mcp.llm.ollama import (
    OllamaStructuredLLMClient,
    _parse_json_object_content,
    _prepare_schema_for_ollama,
)
from fortiedr_mcp.skills.base import SkillDefinition
from fortiedr_mcp.skills.incident_senior_soc_v1 import INCIDENT_SENIOR_SOC_V1


class _DummyInput(BaseModel):
    prompt: str


class _DummyOutput(BaseModel):
    value: str


class _RetryOutput(BaseModel):
    skill_version: str
    incident_id: str
    executive_summary: str
    risk_level: str
    key_metadata: dict
    possible_classification: dict
    recommended_next_steps: dict
    verdict: str


class _FakeResponse:
    def __init__(
        self,
        *,
        status_code: int,
        text: str,
        payload: dict | None = None,
        headers: dict[str, str] | None = None,
    ) -> None:
        self.status_code = status_code
        self.text = text
        self._payload = payload or {}
        self.headers = headers or {}

    @property
    def ok(self) -> bool:
        return 200 <= self.status_code < 300

    def json(self) -> dict:
        return self._payload


def test_prepare_schema_for_ollama_drops_metadata_only_fields():
    prepared = _prepare_schema_for_ollama(INCIDENT_SENIOR_SOC_V1.output_model.model_json_schema())

    assert prepared["$defs"]["EvidenceReference"]["properties"]["value"] == {}
    assert "title" not in prepared["$defs"]["EvidenceReference"]["properties"]["value"]
    assert "default" not in prepared["$defs"]["EvidenceReference"]["properties"]["value"]
    assert "title" not in prepared


def test_parse_json_object_content_accepts_fenced_json():
    parsed, mode = _parse_json_object_content('```json\n{"value":"ok"}\n```')

    assert parsed == {"value": "ok"}
    assert mode == "fenced"


def test_parse_json_object_content_accepts_embedded_json():
    parsed, mode = _parse_json_object_content('Here is the result:\n{"value":"ok"}\nDone.')

    assert parsed == {"value": "ok"}
    assert mode == "embedded"


def test_parse_json_object_content_accepts_stringified_json_object():
    parsed, mode = _parse_json_object_content('"{\\"value\\": \\"ok\\"}"')

    assert parsed == {"value": "ok"}
    assert mode == "direct"


def test_parse_json_object_content_prefers_candidate_matching_required_keys():
    content = (
        'Schema hint: {"missing_information":[],"skill_version":"incident_senior_soc_v1","value":null}\n'
        'Final answer: {"skill_version":"incident_senior_soc_v1","incident_id":"123","executive_summary":"ok",'
        '"risk_level":"medium","key_metadata":{},"possible_classification":{},'
        '"recommended_next_steps":{},"verdict":"pending"}'
    )

    parsed, mode = _parse_json_object_content(
        content,
        expected_keys={
            "skill_version",
            "incident_id",
            "executive_summary",
            "risk_level",
            "key_metadata",
            "possible_classification",
            "recommended_next_steps",
            "verdict",
            "missing_information",
        },
        required_keys={
            "skill_version",
            "incident_id",
            "executive_summary",
            "risk_level",
            "key_metadata",
            "possible_classification",
            "recommended_next_steps",
            "verdict",
        },
    )

    assert parsed["incident_id"] == "123"
    assert "value" not in parsed
    assert mode == "embedded"


def test_parse_json_object_content_rejects_non_json_text():
    with pytest.raises(FortiEDRLLMResponseError):
        _parse_json_object_content("not json at all")


def test_ollama_client_falls_back_to_json_mode_on_invalid_schema_error(monkeypatch):
    calls: list[dict] = []
    skill = SkillDefinition[_DummyInput, _DummyOutput](
        name="dummy_skill",
        version="v1",
        description="dummy",
        system_instructions="Return JSON only.",
        input_model=_DummyInput,
        output_model=_DummyOutput,
    )
    client = OllamaStructuredLLMClient(
        model="qwen2.5:7b",
        base_url="http://10.163.3.76:11434/",
    )

    def fake_post_chat(request_body: dict):
        calls.append(request_body)
        if len(calls) == 1:
            return _FakeResponse(
                status_code=500,
                text='{"error":"invalid JSON schema in format"}',
            )
        return _FakeResponse(
            status_code=200,
            text='{"message":{"content":"{\\"value\\": \\"ok\\"}"}}',
            payload={
                "model": "qwen2.5:7b",
                "message": {"role": "assistant", "content": '{"value": "ok"}'},
                "done": True,
            },
        )

    monkeypatch.setattr(client, "_post_chat", fake_post_chat)

    result = client.generate_structured_output(
        skill=skill,
        analysis_input=_DummyInput(prompt="test"),
    )

    assert len(calls) == 2
    assert calls[0]["format"] != "json"
    assert calls[1]["format"] == "json"
    assert result.output == {"value": "ok"}


def test_ollama_client_parses_fenced_json_in_response_payload():
    client = OllamaStructuredLLMClient(
        model="qwen2.5:1.5b",
        base_url="http://10.163.3.76:11434/",
    )

    result = client._parse_response_payload(
        {
            "model": "qwen2.5:1.5b",
            "message": {"role": "assistant", "content": '```json\n{"value":"ok"}\n```'},
            "done": True,
        },
        request_id=None,
    )

    assert result.output == {"value": "ok"}
    assert result.response_metadata["content_parse_mode"] == "fenced"


def test_ollama_client_retries_when_response_is_missing_required_fields(monkeypatch):
    calls: list[dict] = []
    skill = SkillDefinition[_DummyInput, _RetryOutput](
        name="retry_skill",
        version="v1",
        description="dummy",
        system_instructions="Return JSON only.",
        input_model=_DummyInput,
        output_model=_RetryOutput,
    )
    client = OllamaStructuredLLMClient(
        model="gemma3:1b",
        base_url="http://10.163.3.76:11434/",
    )

    partial_output = {
        "skill_version": "incident_senior_soc_v1",
        "value": None,
        "key_metadata": {},
        "observed_facts": [],
        "investigation_notes": [],
        "hypotheses": [],
        "recommended_next_steps": {"immediate": [], "short_term": [], "validation": []},
        "missing_information": [],
    }
    completed_output = {
        "skill_version": "incident_senior_soc_v1",
        "incident_id": "5468293",
        "executive_summary": "ok",
        "risk_level": "medium",
        "key_metadata": {},
        "possible_classification": {},
        "recommended_next_steps": {},
        "verdict": "review",
    }

    def fake_post_chat(request_body: dict):
        calls.append(request_body)
        if len(calls) == 1:
            return _FakeResponse(
                status_code=200,
                text=json.dumps({"message": {"content": json.dumps(partial_output)}}),
                payload={
                    "model": "gemma3:1b",
                    "message": {"role": "assistant", "content": json.dumps(partial_output)},
                    "done": True,
                },
            )
        return _FakeResponse(
            status_code=200,
            text=json.dumps({"message": {"content": json.dumps(completed_output)}}),
            payload={
                "model": "gemma3:1b",
                "message": {"role": "assistant", "content": json.dumps(completed_output)},
                "done": True,
            },
        )

    monkeypatch.setattr(client, "_post_chat", fake_post_chat)

    result = client.generate_structured_output(
        skill=skill,
        analysis_input=_DummyInput(prompt="test"),
    )

    assert len(calls) == 2
    assert calls[1]["format"] == "json"
    assert "Missing required top-level fields" in calls[1]["messages"][1]["content"]
    assert result.output["incident_id"] == "5468293"
    assert result.response_metadata["retried_for_missing_required_keys"] == [
        "executive_summary",
        "incident_id",
        "possible_classification",
        "risk_level",
        "verdict",
    ]


def test_ollama_client_parse_response_payload_prefers_schema_matching_object():
    client = OllamaStructuredLLMClient(
        model="gemma3:1b",
        base_url="http://10.163.3.76:11434/",
    )

    result = client._parse_response_payload(
        {
            "model": "gemma3:1b",
            "message": {
                "role": "assistant",
                "content": (
                    'First object: {"missing_information":[],"skill_version":"incident_senior_soc_v1","value":null}\n'
                    'Second object: {"skill_version":"incident_senior_soc_v1","incident_id":"5468293",'
                    '"executive_summary":"ok","risk_level":"medium","key_metadata":{},'
                    '"possible_classification":{},"recommended_next_steps":{},"verdict":"review"}'
                ),
            },
            "done": True,
        },
        request_id=None,
        expected_keys=set(INCIDENT_SENIOR_SOC_V1.output_model.model_json_schema()["properties"].keys()),
        required_keys=set(INCIDENT_SENIOR_SOC_V1.output_model.model_json_schema()["required"]),
    )

    assert result.output["incident_id"] == "5468293"
    assert "value" not in result.output
