from __future__ import annotations

from fortiedr_mcp.errors import FortiEDRSkillNotFoundError
from fortiedr_mcp.skills.base import SkillDefinition
from fortiedr_mcp.skills.incident_senior_soc_v1 import INCIDENT_SENIOR_SOC_V1

_SKILLS: dict[str, SkillDefinition] = {
    "incident_senior_soc_v1": INCIDENT_SENIOR_SOC_V1,
}


def get_skill(skill_name: str) -> SkillDefinition:
    try:
        return _SKILLS[skill_name]
    except KeyError as exc:
        raise FortiEDRSkillNotFoundError(f"Unknown analysis skill: {skill_name}") from exc


def list_skills() -> list[str]:
    return sorted(_SKILLS)
