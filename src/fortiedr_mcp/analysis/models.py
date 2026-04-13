from __future__ import annotations

from enum import StrEnum
from typing import Any, Literal

from pydantic import BaseModel, Field, model_validator


class RiskLevel(StrEnum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class HypothesisConfidence(StrEnum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"


class PossibleClassificationLabel(StrEnum):
    FALSE_POSITIVE = "false_positive"
    LEGITIMATE_ADMIN_ACTIVITY = "legitimate_admin_activity"
    RED_TEAM_ACTIVITY = "red_team_activity"
    SUSPICIOUS_ACTIVITY_REQUIRING_VALIDATION = "suspicious_activity_requiring_validation"
    CONFIRMED_MALICIOUS_ACTIVITY = "confirmed_malicious_activity"


class EvidenceReference(BaseModel):
    evidence_id: str | None = Field(
        default=None,
        description="Stable evidence identifier from the analysis input catalog.",
    )
    tool: str
    path: str
    value: Any = None
    normalized_value: Any | None = None


class EvidenceBackedValue(BaseModel):
    value: Any | None = None
    evidence: list[EvidenceReference] = Field(default_factory=list)

    @model_validator(mode="after")
    def validate_evidence_for_present_value(self) -> "EvidenceBackedValue":
        if self.value is not None and not self.evidence:
            raise ValueError("Non-null metadata values must include evidence.")
        return self


class HashMetadata(BaseModel):
    md5: str | None = None
    sha1: str | None = None
    sha256: str | None = None
    evidence: list[EvidenceReference] = Field(default_factory=list)

    @model_validator(mode="after")
    def validate_evidence_for_present_hash(self) -> "HashMetadata":
        if any(value is not None for value in (self.md5, self.sha1, self.sha256)) and not self.evidence:
            raise ValueError("Hash values must include evidence when present.")
        return self


class KeyMetadata(BaseModel):
    hostname: EvidenceBackedValue
    user: EvidenceBackedValue
    process_name: EvidenceBackedValue
    process_path: EvidenceBackedValue
    hashes: HashMetadata
    severity: EvidenceBackedValue
    classification: EvidenceBackedValue
    first_seen: EvidenceBackedValue
    last_seen: EvidenceBackedValue
    action: EvidenceBackedValue


class ObservedFact(BaseModel):
    statement: str
    evidence: list[EvidenceReference] = Field(min_length=1)


class InvestigationNote(BaseModel):
    topic: str
    content: str


class Hypothesis(BaseModel):
    label: str
    confidence: HypothesisConfidence
    rationale: str


class PossibleClassification(BaseModel):
    label: PossibleClassificationLabel
    rationale: str


class RecommendedNextSteps(BaseModel):
    immediate: list[str] = Field(default_factory=list)
    short_term: list[str] = Field(default_factory=list)
    validation: list[str] = Field(default_factory=list)


class IncidentAnalysisResult(BaseModel):
    skill_version: Literal["incident_senior_soc_v1"]
    incident_id: str
    executive_summary: str
    risk_level: RiskLevel
    key_metadata: KeyMetadata
    observed_facts: list[ObservedFact] = Field(default_factory=list)
    investigation_notes: list[InvestigationNote] = Field(default_factory=list)
    hypotheses: list[Hypothesis] = Field(default_factory=list)
    possible_classification: PossibleClassification
    recommended_next_steps: RecommendedNextSteps
    missing_information: list[str] = Field(default_factory=list)
    verdict: str

