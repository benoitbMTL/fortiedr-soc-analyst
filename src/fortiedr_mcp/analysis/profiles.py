from __future__ import annotations

from dataclasses import dataclass
from typing import Literal

AnalysisProfileName = Literal["lite", "standard", "full"]


@dataclass(frozen=True)
class AnalysisProfileConfig:
    name: AnalysisProfileName
    label: str
    description: str
    raw_data_limit: int
    related_limit: int
    collector_limit: int
    include_host_context: bool
    include_related_events: bool
    include_forensics: bool
    max_rule_descriptions: int
    max_forensics_detail_chars: int


_PROFILES: dict[AnalysisProfileName, AnalysisProfileConfig] = {
    "lite": AnalysisProfileConfig(
        name="lite",
        label="Lite",
        description="Lower-cost profile for fast triage and testing with tighter context limits.",
        raw_data_limit=6,
        related_limit=3,
        collector_limit=5,
        include_host_context=False,
        include_related_events=False,
        include_forensics=True,
        max_rule_descriptions=2,
        max_forensics_detail_chars=320,
    ),
    "standard": AnalysisProfileConfig(
        name="standard",
        label="Standard",
        description="Balanced profile for routine analyst use with curated context.",
        raw_data_limit=25,
        related_limit=10,
        collector_limit=10,
        include_host_context=True,
        include_related_events=True,
        include_forensics=True,
        max_rule_descriptions=5,
        max_forensics_detail_chars=900,
    ),
    "full": AnalysisProfileConfig(
        name="full",
        label="Full",
        description="Richer profile for deeper investigations with broader context collection.",
        raw_data_limit=50,
        related_limit=20,
        collector_limit=25,
        include_host_context=True,
        include_related_events=True,
        include_forensics=True,
        max_rule_descriptions=5,
        max_forensics_detail_chars=2400,
    ),
}


def get_analysis_profile(name: str | None) -> AnalysisProfileConfig:
    if not name:
        return _PROFILES["standard"]
    normalized = str(name).strip().lower()
    if normalized not in _PROFILES:
        raise ValueError(f"Unknown analysis profile: {name}")
    return _PROFILES[normalized]  # type: ignore[index]


def list_analysis_profiles() -> list[AnalysisProfileConfig]:
    return [_PROFILES["lite"], _PROFILES["standard"], _PROFILES["full"]]
