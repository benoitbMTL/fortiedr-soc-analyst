from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Generic, TypeVar

from pydantic import BaseModel

InputModelT = TypeVar("InputModelT", bound=BaseModel)
OutputModelT = TypeVar("OutputModelT", bound=BaseModel)


@dataclass(frozen=True)
class SkillDefinition(Generic[InputModelT, OutputModelT]):
    name: str
    version: str
    description: str
    system_instructions: str
    input_model: type[InputModelT]
    output_model: type[OutputModelT]

    @property
    def skill_version(self) -> str:
        return f"{self.name}_{self.version}"

    def build_user_prompt(self, analysis_input: InputModelT) -> str:
        payload = analysis_input.model_dump(mode="json")
        return (
            "Analyze the FortiEDR incident context below and return the final result "
            "using the structured output contract.\n\n"
            "Incident context JSON:\n"
            f"{json.dumps(payload, indent=2, sort_keys=True)}"
        )
