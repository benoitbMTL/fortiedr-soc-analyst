from __future__ import annotations

from typing import Protocol

from pydantic import BaseModel

from fortiedr_mcp.models import StructuredLLMResult
from fortiedr_mcp.skills.base import SkillDefinition


class StructuredLLMClient(Protocol):
    @property
    def provider_name(self) -> str:
        """Stable provider identifier used for audit and caching."""

    @property
    def model_name(self) -> str:
        """Resolved model identifier used for audit and caching."""

    def generate_structured_output(
        self,
        *,
        skill: SkillDefinition,
        analysis_input: BaseModel,
    ) -> StructuredLLMResult:
        """Generate a structured output object for the given skill."""
