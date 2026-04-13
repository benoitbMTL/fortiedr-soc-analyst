from __future__ import annotations

from dataclasses import dataclass

from pydantic import ValidationError

from fortiedr_mcp.analysis.repair import repair_incident_analysis_output
from fortiedr_mcp.analysis.context import IncidentAnalysisInput, IncidentAnalysisInputBuilder
from fortiedr_mcp.analysis.profiles import get_analysis_profile
from fortiedr_mcp.analysis.models import IncidentAnalysisResult
from fortiedr_mcp.analysis.validation import (
    canonicalize_analysis_result_evidence,
    validate_analysis_result_evidence,
)
from fortiedr_mcp.errors import FortiEDRLLMConfigurationError, FortiEDRValidationError
from fortiedr_mcp.models import IncidentDetailsResult, StructuredLLMResult
from fortiedr_mcp.services.incident_data import IncidentDataService
from fortiedr_mcp.skills.base import SkillDefinition
from fortiedr_mcp.skills.registry import get_skill


@dataclass(frozen=True)
class PreparedIncidentAnalysis:
    skill: SkillDefinition
    incident_details: IncidentDetailsResult
    analysis_input: IncidentAnalysisInput


@dataclass(frozen=True)
class ExecutedIncidentAnalysis:
    prepared: PreparedIncidentAnalysis
    llm_result: StructuredLLMResult
    result: IncidentAnalysisResult


class IncidentAnalysisService:
    """Orchestrates structured incident analysis on top of FortiEDR incident data."""

    def __init__(
        self,
        *,
        data_service: IncidentDataService,
        llm_client,
        input_builder: IncidentAnalysisInputBuilder | None = None,
    ):
        self._data_service = data_service
        self._llm_client = llm_client
        self._input_builder = input_builder or IncidentAnalysisInputBuilder()

    @property
    def llm_provider_name(self) -> str | None:
        return getattr(self._llm_client, "provider_name", None)

    @property
    def llm_model_name(self) -> str | None:
        return getattr(self._llm_client, "model_name", None)

    def fetch_incident_details(
        self,
        incident_id: int,
        *,
        analysis_profile: str = "standard",
        raw_data_limit: int | None = None,
        related_limit: int | None = None,
        collector_limit: int | None = None,
        include_host_context: bool | None = None,
        include_related_events: bool | None = None,
        include_forensics: bool | None = None,
    ) -> IncidentDetailsResult:
        profile = get_analysis_profile(analysis_profile)
        return self._data_service.get_incident_details(
            incident_id,
            raw_data_limit=raw_data_limit or profile.raw_data_limit,
            related_limit=related_limit or profile.related_limit,
            collector_limit=collector_limit or profile.collector_limit,
            include_host_context=(
                profile.include_host_context if include_host_context is None else include_host_context
            ),
            include_related_events=(
                profile.include_related_events
                if include_related_events is None
                else include_related_events
            ),
            include_forensics=(
                profile.include_forensics if include_forensics is None else include_forensics
            ),
        )

    def prepare_analysis(
        self,
        *,
        incident_details: IncidentDetailsResult,
        skill_name: str = "incident_senior_soc_v1",
        analysis_profile: str = "standard",
    ) -> PreparedIncidentAnalysis:
        skill = get_skill(skill_name)
        analysis_input = self._input_builder.build(
            incident_details,
            analysis_profile=analysis_profile,
        )
        validated_input = skill.input_model.model_validate(analysis_input.model_dump(mode="json"))
        return PreparedIncidentAnalysis(
            skill=skill,
            incident_details=incident_details,
            analysis_input=validated_input,
        )

    def build_analysis_input(
        self,
        incident_id: int,
        *,
        skill_name: str = "incident_senior_soc_v1",
        analysis_profile: str = "standard",
        raw_data_limit: int | None = None,
        related_limit: int | None = None,
        collector_limit: int | None = None,
        include_host_context: bool | None = None,
        include_related_events: bool | None = None,
        include_forensics: bool | None = None,
    ) -> tuple[SkillDefinition, IncidentAnalysisInput]:
        details = self.fetch_incident_details(
            incident_id,
            analysis_profile=analysis_profile,
            raw_data_limit=raw_data_limit,
            related_limit=related_limit,
            collector_limit=collector_limit,
            include_host_context=include_host_context,
            include_related_events=include_related_events,
            include_forensics=include_forensics,
        )
        prepared = self.prepare_analysis(
            incident_details=details,
            skill_name=skill_name,
            analysis_profile=analysis_profile,
        )
        return prepared.skill, prepared.analysis_input

    def generate_structured_output(
        self,
        *,
        prepared: PreparedIncidentAnalysis,
    ) -> StructuredLLMResult:
        if self._llm_client is None:
            raise FortiEDRLLMConfigurationError(
                "No LLM client is configured for structured incident analysis."
            )

        return self._llm_client.generate_structured_output(
            skill=prepared.skill,
            analysis_input=prepared.analysis_input,
        )

    def validate_structured_output(
        self,
        *,
        prepared: PreparedIncidentAnalysis,
        llm_result: StructuredLLMResult,
    ) -> IncidentAnalysisResult:
        skill_name = prepared.skill.skill_version
        repaired_output = repair_incident_analysis_output(
            llm_result.output,
            skill_version=skill_name,
            incident_id=prepared.analysis_input.incident_id,
        )
        llm_result.output = repaired_output

        try:
            result = prepared.skill.output_model.model_validate(repaired_output)
        except ValidationError as exc:
            details = [
                f"{'.'.join(str(part) for part in error['loc'])}: {error['msg']}"
                for error in exc.errors()
            ]
            raise FortiEDRValidationError(
                f"Structured incident analysis did not match the {skill_name} schema.",
                details=details,
            ) from exc

        result = canonicalize_analysis_result_evidence(prepared.analysis_input, result)
        validate_analysis_result_evidence(prepared.analysis_input, result)
        return result

    def execute_prepared_analysis(
        self,
        *,
        prepared: PreparedIncidentAnalysis,
    ) -> ExecutedIncidentAnalysis:
        llm_result = self.generate_structured_output(prepared=prepared)
        result = self.validate_structured_output(
            prepared=prepared,
            llm_result=llm_result,
        )
        return ExecutedIncidentAnalysis(
            prepared=prepared,
            llm_result=llm_result,
            result=result,
        )

    def analyze_incident(
        self,
        incident_id: int,
        *,
        skill_name: str = "incident_senior_soc_v1",
        analysis_profile: str = "standard",
        raw_data_limit: int | None = None,
        related_limit: int | None = None,
        collector_limit: int | None = None,
        include_host_context: bool | None = None,
        include_related_events: bool | None = None,
        include_forensics: bool | None = None,
    ) -> IncidentAnalysisResult:
        details = self.fetch_incident_details(
            incident_id,
            analysis_profile=analysis_profile,
            raw_data_limit=raw_data_limit,
            related_limit=related_limit,
            collector_limit=collector_limit,
            include_host_context=include_host_context,
            include_related_events=include_related_events,
            include_forensics=include_forensics,
        )
        prepared = self.prepare_analysis(
            incident_details=details,
            skill_name=skill_name,
            analysis_profile=analysis_profile,
        )
        return self.execute_prepared_analysis(prepared=prepared).result
