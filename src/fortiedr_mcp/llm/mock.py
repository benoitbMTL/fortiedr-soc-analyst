from __future__ import annotations

from pydantic import BaseModel

from fortiedr_mcp.models import StructuredLLMResult
from fortiedr_mcp.skills.base import SkillDefinition


class MockStructuredLLMClient:
    """Test double that returns a pre-defined structured payload."""

    provider_name = "mock"
    model_name = "mock-structured-model"

    def __init__(self, response: dict):
        self._response = response

    def generate_structured_output(
        self,
        *,
        skill: SkillDefinition,
        analysis_input: BaseModel,
    ) -> StructuredLLMResult:
        return StructuredLLMResult(
            provider_name=self.provider_name,
            model_name=self.model_name,
            output=self._response,
        )
