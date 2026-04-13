from __future__ import annotations

from datetime import datetime
from enum import StrEnum
from typing import Any, Literal

from pydantic import BaseModel, Field

from fortiedr_mcp.models.llm import LLMTokenUsage


class AnalysisRunStatus(StrEnum):
    RUNNING = "running"
    SUCCESS = "success"
    FAILED = "failed"


class ValidationStatus(StrEnum):
    PASSED = "passed"
    FAILED = "failed"
    SKIPPED = "skipped"


class AnalysisTimingMetrics(BaseModel):
    total_duration_ms: int | None = None
    source_retrieval_duration_ms: int | None = None
    normalization_duration_ms: int | None = None
    llm_duration_ms: int | None = None
    validation_duration_ms: int | None = None


class AnalysisSourceContext(BaseModel):
    analysis_profile: str = "standard"
    raw_data_limit: int
    related_limit: int
    collector_limit: int
    include_host_context: bool
    include_related_events: bool
    include_forensics: bool
    host_context_included: bool
    related_events_included: bool
    forensics_included: bool
    raw_data_item_count: int
    forensics_event_count: int = 0


class AnalystFeedback(BaseModel):
    usefulness: Literal["useful", "not_useful"] | None = None
    correctness: Literal["correct", "partially_correct", "incorrect"] | None = None
    analyst_classification: (
        Literal["benign", "false_positive", "red_team", "malicious", "needs_validation"] | None
    ) = None
    comment: str | None = None
    updated_at: datetime | None = None


class AnalysisErrorInfo(BaseModel):
    code: str
    message: str
    details: list[str] = Field(default_factory=list)


class AnalysisRunRecord(BaseModel):
    run_id: str
    incident_id: str
    skill_name: str
    skill_version: str
    llm_provider: str | None = None
    model_name: str | None = None
    request_id: str | None = None
    status: AnalysisRunStatus
    validation_status: ValidationStatus
    validation_errors: list[str] = Field(default_factory=list)
    error: AnalysisErrorInfo | None = None
    source_context: AnalysisSourceContext
    timing: AnalysisTimingMetrics = Field(default_factory=AnalysisTimingMetrics)
    usage: LLMTokenUsage | None = None
    estimated_cost_usd: float | None = None
    created_at: datetime
    completed_at: datetime | None = None
    idempotency_key: str
    source_fingerprint: str | None = None
    normalized_input: dict[str, Any] | None = None
    llm_output: dict[str, Any] | None = None
    validated_output: dict[str, Any] | None = None
    analyst_feedback: AnalystFeedback | None = None


class AnalysisRunExecution(BaseModel):
    from_cache: bool = False
    run: AnalysisRunRecord
