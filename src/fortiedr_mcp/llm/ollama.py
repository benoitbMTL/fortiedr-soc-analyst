from __future__ import annotations

import json
import os
import re
from typing import Any
from urllib.parse import urlparse

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

_OLLAMA_SCHEMA_METADATA_KEYS = {"default", "title", "description", "examples"}
_OLLAMA_SCHEMA_CONTAINER_KEYS = {"$defs", "definitions", "properties", "patternProperties"}
_OLLAMA_SCHEMA_VALIDATION_KEYS = {
    "$ref",
    "$defs",
    "additionalProperties",
    "allOf",
    "anyOf",
    "const",
    "enum",
    "format",
    "items",
    "maxItems",
    "maxLength",
    "maximum",
    "minItems",
    "minLength",
    "minimum",
    "oneOf",
    "pattern",
    "properties",
    "required",
    "type",
}


def _prepare_schema_for_ollama(schema: Any, *, schema_node: bool = True) -> Any:
    if isinstance(schema, dict):
        prepared: dict[str, Any] = {}
        for key, value in schema.items():
            if key in _OLLAMA_SCHEMA_METADATA_KEYS:
                continue
            if key in _OLLAMA_SCHEMA_CONTAINER_KEYS and isinstance(value, dict):
                prepared[key] = {
                    child_key: _prepare_schema_for_ollama(child_value)
                    for child_key, child_value in value.items()
                }
                continue
            prepared[key] = _prepare_schema_for_ollama(value, schema_node=key not in _OLLAMA_SCHEMA_CONTAINER_KEYS)

        if schema_node and not any(key in prepared for key in _OLLAMA_SCHEMA_VALIDATION_KEYS):
            return {}
        return prepared
    if isinstance(schema, list):
        return [_prepare_schema_for_ollama(item) for item in schema]
    return schema


def _should_retry_in_json_mode(response: requests.Response) -> bool:
    if response.status_code == 400:
        return True
    if response.status_code != 500:
        return False

    response_text = response.text.lower()
    return "invalid json schema" in response_text and "format" in response_text


def _score_json_object_candidate(
    candidate: dict[str, Any],
    *,
    expected_keys: set[str] | None,
    required_keys: set[str] | None,
) -> tuple[int, int, int, int]:
    candidate_keys = {key for key in candidate if isinstance(key, str)}
    required_match_count = len(candidate_keys & required_keys) if required_keys else 0
    expected_match_count = len(candidate_keys & expected_keys) if expected_keys else 0
    skill_version_bonus = 1 if candidate.get("skill_version") is not None else 0
    return (
        required_match_count,
        expected_match_count,
        skill_version_bonus,
        len(candidate_keys),
    )


def _missing_required_keys(
    candidate: dict[str, Any],
    *,
    required_keys: set[str] | None,
) -> set[str]:
    if not required_keys:
        return set()
    candidate_keys = {key for key in candidate if isinstance(key, str)}
    return required_keys - candidate_keys


def _coerce_json_object_candidate(candidate: Any) -> dict[str, Any] | None:
    current = candidate
    for _ in range(3):
        if isinstance(current, dict):
            return current
        if isinstance(current, list) and len(current) == 1:
            current = current[0]
            continue
        if isinstance(current, str):
            stripped = current.strip()
            if not stripped:
                return None
            try:
                current = json.loads(stripped)
            except json.JSONDecodeError:
                return None
            continue
        return None
    return current if isinstance(current, dict) else None


def _parse_json_object_content(
    content: str,
    *,
    expected_keys: set[str] | None = None,
    required_keys: set[str] | None = None,
) -> tuple[dict[str, Any], str]:
    stripped = content.strip()
    candidates: list[tuple[dict[str, Any], str]] = []
    seen_payloads: set[str] = set()

    def register_candidate(candidate: dict[str, Any], mode: str) -> None:
        fingerprint = json.dumps(candidate, sort_keys=True, default=str)
        if fingerprint in seen_payloads:
            return
        seen_payloads.add(fingerprint)
        candidates.append((candidate, mode))

    try:
        parsed = json.loads(stripped)
    except json.JSONDecodeError:
        parsed = None
    else:
        coerced = _coerce_json_object_candidate(parsed)
        if coerced is not None:
            register_candidate(coerced, "direct")

    fenced_match = re.search(r"```(?:json)?\s*(\{.*?\})\s*```", stripped, re.DOTALL | re.IGNORECASE)
    if fenced_match:
        fenced_payload = fenced_match.group(1).strip()
        try:
            parsed = json.loads(fenced_payload)
        except json.JSONDecodeError:
            parsed = None
        else:
            coerced = _coerce_json_object_candidate(parsed)
            if coerced is not None:
                register_candidate(coerced, "fenced")

    decoder = json.JSONDecoder()
    for index, char in enumerate(stripped):
        if char != "{":
            continue
        try:
            parsed, _ = decoder.raw_decode(stripped[index:])
        except json.JSONDecodeError:
            continue
        coerced = _coerce_json_object_candidate(parsed)
        if coerced is not None:
            register_candidate(coerced, "embedded")

    if candidates:
        if expected_keys or required_keys:
            best_candidate, best_mode = max(
                candidates,
                key=lambda item: _score_json_object_candidate(
                    item[0],
                    expected_keys=expected_keys,
                    required_keys=required_keys,
                ),
            )
            return best_candidate, best_mode
        return candidates[0]

    raise FortiEDRLLMResponseError("Ollama response was not valid JSON.")


def normalize_ollama_base_url(base_url: str) -> str:
    raw = base_url.strip()
    if not raw:
        raise FortiEDRLLMConfigurationError("LLM server URL is required.")

    parsed = urlparse(raw if "://" in raw else f"http://{raw}")
    if not parsed.scheme or not parsed.netloc:
        raise FortiEDRLLMConfigurationError("LLM server URL must be a valid HTTP or HTTPS URL.")
    if parsed.scheme not in {"http", "https"}:
        raise FortiEDRLLMConfigurationError("LLM server URL must use http or https.")

    normalized = f"{parsed.scheme}://{parsed.netloc}{parsed.path.rstrip('/')}"
    if normalized.endswith("/v1"):
        normalized = normalized[:-3]
    return normalized.rstrip("/")


class OllamaStructuredLLMClient:
    """Structured-output client backed by Ollama's native chat API."""

    def __init__(
        self,
        *,
        model: str,
        base_url: str,
        max_tokens: int = 4096,
        context_length: int = 4096,
        temperature: float = 0.0,
        timeout_seconds: float = 120.0,
    ):
        if not model:
            raise FortiEDRLLMConfigurationError("OLLAMA_MODEL is required.")

        self._model = model
        self._base_url = normalize_ollama_base_url(base_url)
        self._max_tokens = max_tokens
        self._context_length = context_length
        self._temperature = temperature
        self._timeout_seconds = timeout_seconds
        self._session = requests.Session()
        self._session.headers.update({"content-type": "application/json"})

    @property
    def provider_name(self) -> str:
        return "ollama"

    @property
    def model_name(self) -> str:
        return self._model

    @classmethod
    def from_env(cls, *, model_name: str | None = None) -> "OllamaStructuredLLMClient":
        base_url = os.getenv("FORTIEDR_LLM_SERVER_URL") or os.getenv("OLLAMA_BASE_URL", "")
        max_tokens_raw = os.getenv("OLLAMA_MAX_TOKENS", "4096")
        context_length_raw = os.getenv("OLLAMA_CONTEXT_LENGTH", "4096")
        timeout_raw = os.getenv("OLLAMA_TIMEOUT_SECONDS", "120")
        temperature_raw = os.getenv("OLLAMA_TEMPERATURE", "0")

        try:
            max_tokens = int(max_tokens_raw)
            context_length = int(context_length_raw)
            timeout_seconds = float(timeout_raw)
            temperature = float(temperature_raw)
        except ValueError as exc:
            raise FortiEDRLLMConfigurationError(
                "OLLAMA_MAX_TOKENS, OLLAMA_CONTEXT_LENGTH, OLLAMA_TIMEOUT_SECONDS, and OLLAMA_TEMPERATURE must be numeric."
            ) from exc

        model = model_name or os.getenv("OLLAMA_MODEL", "")
        if not model:
            models = cls.list_models(base_url=base_url, timeout_seconds=min(timeout_seconds, 5.0))
            model = models[0] if models else ""

        return cls(
            model=model,
            base_url=base_url,
            max_tokens=max_tokens,
            context_length=context_length,
            temperature=temperature,
            timeout_seconds=timeout_seconds,
        )

    @classmethod
    def list_models(
        cls,
        *,
        base_url: str,
        timeout_seconds: float = 5.0,
    ) -> list[str]:
        normalized_base_url = normalize_ollama_base_url(base_url)
        try:
            response = requests.get(
                f"{normalized_base_url}/api/tags",
                timeout=timeout_seconds,
                headers={"accept": "application/json"},
            )
        except Timeout as exc:
            raise FortiEDRLLMTimeoutError("Ollama model discovery timed out.") from exc
        except RequestException as exc:
            raise FortiEDRLLMResponseError(
                "Ollama model discovery failed before a response was returned."
            ) from exc

        if not response.ok:
            raise FortiEDRLLMResponseError(
                f"Ollama model discovery failed with status {response.status_code}: {response.text[:300]}"
            )

        payload = response.json()
        models_payload = payload.get("models")
        if not isinstance(models_payload, list):
            raise FortiEDRLLMResponseError("Ollama did not return a valid models payload.")

        models: list[str] = []
        for item in models_payload:
            if not isinstance(item, dict):
                continue
            name = item.get("model") or item.get("name")
            if isinstance(name, str) and name and name not in models:
                models.append(name)
        return models

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

    def _build_completion_retry_prompt(
        self,
        *,
        skill: SkillDefinition,
        analysis_input: BaseModel,
        output_schema: dict[str, Any],
        missing_required_keys: set[str],
    ) -> str:
        return (
            f"{skill.build_user_prompt(analysis_input)}\n\n"
            "Your previous answer was incomplete and did not satisfy the required output schema.\n"
            f"Missing required top-level fields: {', '.join(sorted(missing_required_keys))}.\n"
            "Return only one final JSON object for the incident analysis. Do not return a schema hint, "
            "placeholder object, wrapper object, or explanatory text.\n\n"
            "Output JSON Schema:\n"
            f"{json.dumps(output_schema, indent=2, sort_keys=True)}"
        )

    def _post_chat(self, request_body: dict[str, Any]) -> requests.Response:
        try:
            return self._session.post(
                f"{self._base_url}/api/chat",
                json=request_body,
                timeout=self._timeout_seconds,
            )
        except Timeout as exc:
            raise FortiEDRLLMTimeoutError("Ollama request timed out.") from exc
        except RequestException as exc:
            raise FortiEDRLLMResponseError(
                "Ollama request failed before a response was returned."
            ) from exc

    def _parse_response_payload(
        self,
        payload: dict[str, Any],
        *,
        request_id: str | None,
        expected_keys: set[str] | None = None,
        required_keys: set[str] | None = None,
    ) -> StructuredLLMResult:
        message = payload.get("message")
        if not isinstance(message, dict):
            raise FortiEDRLLMResponseError("Ollama response did not contain a message payload.")

        content = message.get("content")
        if not isinstance(content, str) or not content.strip():
            raise FortiEDRLLMResponseError("Ollama response did not contain JSON content.")

        parsed, parse_mode = _parse_json_object_content(
            content,
            expected_keys=expected_keys,
            required_keys=required_keys,
        )

        prompt_tokens = payload.get("prompt_eval_count")
        completion_tokens = payload.get("eval_count")
        usage = None
        if isinstance(prompt_tokens, int) or isinstance(completion_tokens, int):
            usage = LLMTokenUsage(
                prompt_tokens=int(prompt_tokens) if isinstance(prompt_tokens, int) else None,
                completion_tokens=int(completion_tokens) if isinstance(completion_tokens, int) else None,
                total_tokens=(
                    int(prompt_tokens) + int(completion_tokens)
                    if isinstance(prompt_tokens, int) and isinstance(completion_tokens, int)
                    else None
                ),
            )

        return StructuredLLMResult(
            provider_name=self.provider_name,
            model_name=str(payload.get("model") or self._model),
            output=parsed,
            request_id=request_id,
            token_usage=usage,
            estimated_cost_usd=None,
            response_metadata={
                "total_duration": payload.get("total_duration"),
                "load_duration": payload.get("load_duration"),
                "done_reason": payload.get("done_reason"),
                "content_parse_mode": parse_mode,
                "raw_content_preview": content[:500],
            },
        )

    def _request_structured_response(
        self,
        *,
        messages: list[dict[str, str]],
        format_spec: dict[str, Any] | str,
        expected_keys: set[str],
        required_keys: set[str],
    ) -> StructuredLLMResult:
        response = self._post_chat(
            {
                "model": self._model,
                "messages": messages,
                "format": format_spec,
                "stream": False,
                "options": {
                    "temperature": self._temperature,
                    "num_predict": self._max_tokens,
                    "num_ctx": self._context_length,
                },
            }
        )

        if not response.ok:
            raise FortiEDRLLMResponseError(
                f"Ollama API request failed with status {response.status_code}: {response.text[:300]}"
            )

        return self._parse_response_payload(
            response.json(),
            request_id=response.headers.get("x-request-id") or response.headers.get("request-id"),
            expected_keys=expected_keys,
            required_keys=required_keys,
        )

    def generate_structured_output(
        self,
        *,
        skill: SkillDefinition,
        analysis_input: BaseModel,
    ) -> StructuredLLMResult:
        full_output_schema = skill.output_model.model_json_schema()
        output_schema = _prepare_schema_for_ollama(full_output_schema)
        expected_keys = set(full_output_schema.get("properties", {}).keys())
        required_keys = {
            key for key in full_output_schema.get("required", []) if isinstance(key, str)
        }
        request_body = {
            "model": self._model,
            "messages": [
                {"role": "system", "content": skill.system_instructions},
                {"role": "user", "content": skill.build_user_prompt(analysis_input)},
            ],
            "format": output_schema,
            "stream": False,
            "options": {
                "temperature": self._temperature,
                "num_predict": self._max_tokens,
                "num_ctx": self._context_length,
            },
        }

        response = self._post_chat(request_body)

        if _should_retry_in_json_mode(response):
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
                "format": "json",
                "stream": False,
                "options": {
                    "temperature": self._temperature,
                    "num_predict": self._max_tokens,
                    "num_ctx": self._context_length,
                },
            }
            response = self._post_chat(fallback_body)

        if not response.ok:
            raise FortiEDRLLMResponseError(
                f"Ollama API request failed with status {response.status_code}: {response.text[:300]}"
            )

        parsed_result = self._parse_response_payload(
            response.json(),
            request_id=response.headers.get("x-request-id") or response.headers.get("request-id"),
            expected_keys=expected_keys,
            required_keys=required_keys,
        )
        missing_keys = _missing_required_keys(parsed_result.output, required_keys=required_keys)
        if not missing_keys:
            return parsed_result

        retry_result = self._request_structured_response(
            messages=[
                {"role": "system", "content": skill.system_instructions},
                {
                    "role": "user",
                    "content": self._build_completion_retry_prompt(
                        skill=skill,
                        analysis_input=analysis_input,
                        output_schema=output_schema,
                        missing_required_keys=missing_keys,
                    ),
                },
            ],
            format_spec="json",
            expected_keys=expected_keys,
            required_keys=required_keys,
        )
        retry_result.response_metadata["retried_for_missing_required_keys"] = sorted(missing_keys)
        return retry_result
