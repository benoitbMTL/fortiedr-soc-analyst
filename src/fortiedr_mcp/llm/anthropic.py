from __future__ import annotations

import os
from typing import Any

import requests
from pydantic import BaseModel
from requests.exceptions import RequestException, Timeout

from fortiedr_mcp.errors import (
    FortiEDRLLMConfigurationError,
    FortiEDRLLMResponseError,
    FortiEDRLLMTimeoutError,
)
from fortiedr_mcp.models import LLMTokenUsage, StructuredLLMResult
from fortiedr_mcp.skills.base import SkillDefinition


class AnthropicStructuredLLMClient:
    """Structured-output client backed by Anthropic's Messages API."""

    def __init__(
        self,
        *,
        api_key: str,
        model: str,
        base_url: str = "https://api.anthropic.com",
        max_tokens: int = 4096,
        timeout_seconds: float = 120.0,
    ):
        if not api_key:
            raise FortiEDRLLMConfigurationError("ANTHROPIC_API_KEY is required.")
        if not model:
            raise FortiEDRLLMConfigurationError("ANTHROPIC_MODEL is required.")

        self._api_key = api_key
        self._model = model
        self._base_url = base_url.rstrip("/")
        self._max_tokens = max_tokens
        self._timeout_seconds = timeout_seconds
        self._session = requests.Session()
        self._session.headers.update(
            {
                "x-api-key": self._api_key,
                "anthropic-version": "2023-06-01",
                "content-type": "application/json",
            }
        )

    @property
    def provider_name(self) -> str:
        return "anthropic"

    @property
    def model_name(self) -> str:
        return self._model

    @classmethod
    def from_env(cls, *, model_name: str | None = None) -> "AnthropicStructuredLLMClient":
        api_key = os.getenv("ANTHROPIC_API_KEY", "")
        model = model_name or os.getenv("ANTHROPIC_MODEL", "")
        base_url = os.getenv("ANTHROPIC_BASE_URL", "https://api.anthropic.com")
        max_tokens_raw = os.getenv("ANTHROPIC_MAX_TOKENS", "4096")
        timeout_raw = os.getenv("ANTHROPIC_TIMEOUT_SECONDS", "120")

        try:
            max_tokens = int(max_tokens_raw)
            timeout_seconds = float(timeout_raw)
        except ValueError as exc:
            raise FortiEDRLLMConfigurationError(
                "ANTHROPIC_MAX_TOKENS and ANTHROPIC_TIMEOUT_SECONDS must be numeric."
            ) from exc

        return cls(
            api_key=api_key,
            model=model,
            base_url=base_url,
            max_tokens=max_tokens,
            timeout_seconds=timeout_seconds,
        )

    def generate_structured_output(
        self,
        *,
        skill: SkillDefinition,
        analysis_input: BaseModel,
    ) -> StructuredLLMResult:
        output_schema = skill.output_model.model_json_schema()
        request_body = {
            "model": self._model,
            "max_tokens": self._max_tokens,
            "system": skill.system_instructions,
            "messages": [
                {
                    "role": "user",
                    "content": skill.build_user_prompt(analysis_input),
                }
            ],
            "tools": [
                {
                    "name": "submit_incident_analysis",
                    "description": (
                        "Return the final incident analysis object. Call this tool exactly "
                        "once with JSON that matches the provided schema."
                    ),
                    "input_schema": output_schema,
                    "strict": True,
                }
            ],
            "tool_choice": {
                "type": "tool",
                "name": "submit_incident_analysis",
            },
        }

        try:
            response = self._session.post(
                f"{self._base_url}/v1/messages",
                json=request_body,
                timeout=self._timeout_seconds,
            )
        except Timeout as exc:
            raise FortiEDRLLMTimeoutError("Anthropic request timed out.") from exc
        except RequestException as exc:
            raise FortiEDRLLMResponseError(
                "Anthropic request failed before a response was returned."
            ) from exc
        if not response.ok:
            raise FortiEDRLLMResponseError(
                f"Anthropic API request failed with status {response.status_code}: {response.text[:300]}"
            )

        payload = response.json()
        content = payload.get("content")
        if not isinstance(content, list):
            raise FortiEDRLLMResponseError("Anthropic response did not contain content blocks.")

        for block in content:
            if (
                isinstance(block, dict)
                and block.get("type") == "tool_use"
                and block.get("name") == "submit_incident_analysis"
            ):
                tool_input = block.get("input")
                if not isinstance(tool_input, dict):
                    raise FortiEDRLLMResponseError("Anthropic tool output did not contain a JSON object.")
                usage_payload = payload.get("usage")
                usage = None
                if isinstance(usage_payload, dict):
                    input_tokens = usage_payload.get("input_tokens")
                    output_tokens = usage_payload.get("output_tokens")
                    usage = LLMTokenUsage(
                        prompt_tokens=int(input_tokens) if isinstance(input_tokens, int) else None,
                        completion_tokens=int(output_tokens) if isinstance(output_tokens, int) else None,
                        total_tokens=(
                            int(input_tokens) + int(output_tokens)
                            if isinstance(input_tokens, int) and isinstance(output_tokens, int)
                            else None
                        ),
                    )
                return StructuredLLMResult(
                    provider_name=self.provider_name,
                    model_name=payload.get("model") or self._model,
                    output=tool_input,
                    request_id=response.headers.get("request-id") or response.headers.get("x-request-id"),
                    token_usage=usage,
                    estimated_cost_usd=None,
                    response_metadata={},
                )

        raise FortiEDRLLMResponseError(
            "Anthropic response did not contain the required structured tool output."
        )
