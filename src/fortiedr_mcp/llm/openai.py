from __future__ import annotations

import json
import os
import re
import time
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


def _prepare_schema_for_openai(schema: Any) -> Any:
    if isinstance(schema, dict):
        prepared: dict[str, Any] = {}
        for key, value in schema.items():
            if key == "default":
                continue
            prepared[key] = _prepare_schema_for_openai(value)

        if prepared.get("type") == "object" and "additionalProperties" not in prepared:
            prepared["additionalProperties"] = False

        return prepared

    if isinstance(schema, list):
        return [_prepare_schema_for_openai(item) for item in schema]

    return schema


class OpenAIStructuredLLMClient:
    """Structured-output client backed by OpenAI's Chat Completions API."""

    def __init__(
        self,
        *,
        api_key: str,
        model: str,
        base_url: str = "https://api.openai.com/v1",
        max_tokens: int = 4096,
        temperature: float = 0.0,
        timeout_seconds: float = 120.0,
        max_retries: int = 2,
    ):
        if not api_key:
            raise FortiEDRLLMConfigurationError("OPENAI_API_KEY is required.")
        if not model:
            raise FortiEDRLLMConfigurationError("OPENAI_MODEL is required.")

        self._api_key = api_key
        self._model = model
        self._base_url = base_url.rstrip("/")
        self._max_tokens = max_tokens
        self._temperature = temperature
        self._timeout_seconds = timeout_seconds
        self._max_retries = max(0, max_retries)
        self._session = requests.Session()
        self._session.headers.update(
            {
                "authorization": f"Bearer {self._api_key}",
                "content-type": "application/json",
            }
        )

    @property
    def provider_name(self) -> str:
        return "openai"

    @property
    def model_name(self) -> str:
        return self._model

    @classmethod
    def from_env(cls, *, model_name: str | None = None) -> "OpenAIStructuredLLMClient":
        api_key = os.getenv("OPENAI_API_KEY", "")
        model = model_name or os.getenv("OPENAI_MODEL", "")
        base_url = os.getenv("OPENAI_BASE_URL", "https://api.openai.com/v1")
        max_tokens_raw = os.getenv("OPENAI_MAX_TOKENS", "4096")
        timeout_raw = os.getenv("OPENAI_TIMEOUT_SECONDS", "120")
        temperature_raw = os.getenv("OPENAI_TEMPERATURE", "0")
        retry_raw = os.getenv("OPENAI_MAX_RETRIES", "2")

        try:
            max_tokens = int(max_tokens_raw)
            timeout_seconds = float(timeout_raw)
            temperature = float(temperature_raw)
            max_retries = int(retry_raw)
        except ValueError as exc:
            raise FortiEDRLLMConfigurationError(
                "OPENAI_MAX_TOKENS, OPENAI_TIMEOUT_SECONDS, OPENAI_TEMPERATURE, and OPENAI_MAX_RETRIES must be numeric."
            ) from exc

        return cls(
            api_key=api_key,
            model=model,
            base_url=base_url,
            max_tokens=max_tokens,
            temperature=temperature,
            timeout_seconds=timeout_seconds,
            max_retries=max_retries,
        )

    @staticmethod
    def _retry_delay_seconds(response: requests.Response) -> float:
        retry_after = response.headers.get("retry-after")
        if retry_after:
            try:
                return max(0.0, float(retry_after))
            except ValueError:
                pass

        match = re.search(r"try again in ([0-9.]+)s", response.text, re.IGNORECASE)
        if match:
            try:
                return max(0.0, float(match.group(1)))
            except ValueError:
                pass

        return 5.0

    def _post_chat_completion(self, request_body: dict[str, Any]) -> requests.Response:
        last_response = None
        for attempt in range(self._max_retries + 1):
            try:
                response = self._session.post(
                    f"{self._base_url}/chat/completions",
                    json=request_body,
                    timeout=self._timeout_seconds,
                )
            except Timeout as exc:
                raise FortiEDRLLMTimeoutError("OpenAI request timed out.") from exc
            except RequestException as exc:
                raise FortiEDRLLMResponseError(
                    "OpenAI request failed before a response was returned."
                ) from exc

            if response.status_code != 429 or attempt >= self._max_retries:
                return response

            last_response = response
            time.sleep(min(self._retry_delay_seconds(response), 15.0))

        return last_response

    def _parse_response_payload(
        self,
        payload: dict[str, Any],
        *,
        request_id: str | None,
    ) -> StructuredLLMResult:
        choices = payload.get("choices")
        if not isinstance(choices, list) or not choices:
            raise FortiEDRLLMResponseError("OpenAI response did not contain any choices.")

        message = choices[0].get("message")
        if not isinstance(message, dict):
            raise FortiEDRLLMResponseError("OpenAI response did not contain a message payload.")

        refusal = message.get("refusal")
        if refusal:
            raise FortiEDRLLMResponseError(f"OpenAI model refused the request: {refusal}")

        content = message.get("content")
        if not isinstance(content, str) or not content.strip():
            raise FortiEDRLLMResponseError("OpenAI response did not contain JSON content.")

        try:
            parsed = json.loads(content)
        except json.JSONDecodeError as exc:
            raise FortiEDRLLMResponseError("OpenAI response was not valid JSON.") from exc

        if not isinstance(parsed, dict):
            raise FortiEDRLLMResponseError("OpenAI JSON response was not an object.")

        usage_payload = payload.get("usage")
        usage = None
        if isinstance(usage_payload, dict):
            prompt_tokens = usage_payload.get("prompt_tokens")
            completion_tokens = usage_payload.get("completion_tokens")
            total_tokens = usage_payload.get("total_tokens")
            usage = LLMTokenUsage(
                prompt_tokens=int(prompt_tokens) if isinstance(prompt_tokens, int) else None,
                completion_tokens=int(completion_tokens) if isinstance(completion_tokens, int) else None,
                total_tokens=int(total_tokens) if isinstance(total_tokens, int) else None,
            )

        return StructuredLLMResult(
            provider_name=self.provider_name,
            model_name=str(payload.get("model") or self._model),
            output=parsed,
            request_id=request_id,
            token_usage=usage,
            estimated_cost_usd=None,
            response_metadata={},
        )

    def _build_json_mode_prompt(
        self,
        *,
        skill: SkillDefinition,
        analysis_input: BaseModel,
        output_schema: dict[str, Any],
    ) -> str:
        return (
            f"{skill.build_user_prompt(analysis_input)}\n\n"
            "Return only a single JSON object that matches this JSON Schema exactly.\n\n"
            "Output JSON Schema:\n"
            f"{json.dumps(output_schema, indent=2, sort_keys=True)}"
        )

    def generate_structured_output(
        self,
        *,
        skill: SkillDefinition,
        analysis_input: BaseModel,
    ) -> StructuredLLMResult:
        output_schema = _prepare_schema_for_openai(skill.output_model.model_json_schema())
        messages = [
            {"role": "system", "content": skill.system_instructions},
            {"role": "user", "content": skill.build_user_prompt(analysis_input)},
        ]
        request_body = {
            "model": self._model,
            "messages": messages,
            "response_format": {
                "type": "json_schema",
                "json_schema": {
                    "name": skill.skill_version,
                    "strict": True,
                    "schema": output_schema,
                },
            },
            "max_completion_tokens": self._max_tokens,
            "temperature": self._temperature,
        }

        response = self._post_chat_completion(request_body)

        if response.status_code == 400:
            fallback_body = {
                "model": self._model,
                "messages": [
                    {"role": "system", "content": skill.system_instructions},
                    {
                        "role": "user",
                        "content": self._build_json_mode_prompt(
                            skill=skill,
                            analysis_input=analysis_input,
                            output_schema=output_schema,
                        ),
                    },
                ],
                "response_format": {"type": "json_object"},
                "max_completion_tokens": self._max_tokens,
                "temperature": self._temperature,
            }
            response = self._post_chat_completion(fallback_body)

        if not response.ok:
            raise FortiEDRLLMResponseError(
                f"OpenAI API request failed with status {response.status_code}: {response.text[:300]}"
            )

        return self._parse_response_payload(
            response.json(),
            request_id=response.headers.get("x-request-id") or response.headers.get("request-id"),
        )
