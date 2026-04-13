from __future__ import annotations

from typing import Any

from pydantic import BaseModel, Field


class LLMTokenUsage(BaseModel):
    prompt_tokens: int | None = None
    completion_tokens: int | None = None
    total_tokens: int | None = None


class StructuredLLMResult(BaseModel):
    provider_name: str
    model_name: str
    output: dict[str, Any]
    request_id: str | None = None
    token_usage: LLMTokenUsage | None = None
    estimated_cost_usd: float | None = None
    response_metadata: dict[str, Any] = Field(default_factory=dict)
