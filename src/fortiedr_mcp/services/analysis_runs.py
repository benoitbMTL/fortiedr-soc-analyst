from __future__ import annotations

import hashlib
import json
import os
from datetime import datetime, timezone
from threading import BoundedSemaphore, Thread
from time import perf_counter
from uuid import uuid4

from fortiedr_mcp.errors import (
    FortiEDRAPIError,
    FortiEDRAuthenticationError,
    FortiEDRError,
    FortiEDRLLMConfigurationError,
    FortiEDRLLMResponseError,
    FortiEDRLLMTimeoutError,
    FortiEDRNotFoundError,
    FortiEDRSkillNotFoundError,
    FortiEDRValidationError,
)
from fortiedr_mcp.analysis.profiles import get_analysis_profile
from fortiedr_mcp.models import (
    AnalysisErrorInfo,
    AnalysisRunExecution,
    AnalysisRunRecord,
    AnalysisRunStatus,
    AnalysisSourceContext,
    AnalysisTimingMetrics,
    AnalystFeedback,
    ValidationStatus,
)
from fortiedr_mcp.repositories import AnalysisRunRepository
from fortiedr_mcp.services.incident_analysis import IncidentAnalysisService, PreparedIncidentAnalysis
from fortiedr_mcp.skills.registry import get_skill


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


def _duration_ms(start: float) -> int:
    return int(round((perf_counter() - start) * 1000))


def _stable_digest(payload: object) -> str:
    rendered = json.dumps(
        payload,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
    )
    return hashlib.sha256(rendered.encode("utf-8")).hexdigest()


def _analysis_concurrency_limit() -> int:
    try:
        return max(1, int(os.getenv("FORTIEDR_ANALYSIS_CONCURRENCY", "2")))
    except ValueError:
        return 2


_ANALYSIS_EXECUTION_GATE = BoundedSemaphore(_analysis_concurrency_limit())


class AnalysisRunService:
    """Persistent product layer around the structured incident analysis pipeline."""

    def __init__(
        self,
        *,
        analysis_service: IncidentAnalysisService,
        repository: AnalysisRunRepository,
    ):
        self._analysis_service = analysis_service
        self._repository = repository

    def _build_idempotency_key(
        self,
        *,
        incident_id: int,
        skill_name: str,
        analysis_profile: str,
        raw_data_limit: int,
        related_limit: int,
        collector_limit: int,
        include_host_context: bool,
        include_related_events: bool,
        include_forensics: bool,
    ) -> str:
        try:
            skill_version = get_skill(skill_name).skill_version
        except FortiEDRError:
            skill_version = skill_name
        payload = {
            "incident_id": incident_id,
            "skill_name": skill_name,
            "skill_version": skill_version,
            "analysis_profile": analysis_profile,
            "provider": self._analysis_service.llm_provider_name,
            "model_name": self._analysis_service.llm_model_name,
            "raw_data_limit": raw_data_limit,
            "related_limit": related_limit,
            "collector_limit": collector_limit,
            "include_host_context": include_host_context,
            "include_related_events": include_related_events,
            "include_forensics": include_forensics,
        }
        return _stable_digest(payload)

    @staticmethod
    def _build_source_fingerprint(prepared: PreparedIncidentAnalysis) -> str:
        return _stable_digest(prepared.analysis_input.model_dump(mode="json"))

    @staticmethod
    def _build_source_context(
        *,
        analysis_profile: str,
        raw_data_limit: int,
        related_limit: int,
        collector_limit: int,
        include_host_context: bool,
        include_related_events: bool,
        include_forensics: bool,
        prepared: PreparedIncidentAnalysis | None = None,
    ) -> AnalysisSourceContext:
        details = prepared.incident_details if prepared else None
        return AnalysisSourceContext(
            analysis_profile=analysis_profile,
            raw_data_limit=raw_data_limit,
            related_limit=related_limit,
            collector_limit=collector_limit,
            include_host_context=include_host_context,
            include_related_events=include_related_events,
            include_forensics=include_forensics,
            host_context_included=details.host_context is not None if details else False,
            related_events_included=details.related_events is not None if details else False,
            forensics_included=details.forensics_events is not None if details else False,
            raw_data_item_count=details.raw_data_item_count if details else 0,
            forensics_event_count=details.forensics_events.selected_count if details and details.forensics_events else 0,
        )

    @staticmethod
    def _classify_error(exc: Exception) -> tuple[AnalysisErrorInfo, ValidationStatus, list[str]]:
        message = str(exc)
        validation_errors: list[str] = []
        validation_status = ValidationStatus.SKIPPED

        if isinstance(exc, FortiEDRNotFoundError):
            code = "incident_not_found"
        elif isinstance(exc, FortiEDRSkillNotFoundError):
            code = "skill_not_found"
        elif isinstance(exc, FortiEDRAuthenticationError):
            code = "source_authentication_failed"
        elif isinstance(exc, FortiEDRAPIError):
            code = "source_retrieval_failed"
        elif isinstance(exc, FortiEDRLLMConfigurationError):
            code = "llm_configuration_error"
        elif isinstance(exc, FortiEDRLLMTimeoutError):
            code = "llm_timeout"
        elif isinstance(exc, FortiEDRLLMResponseError):
            code = "llm_response_error"
        elif isinstance(exc, FortiEDRValidationError):
            validation_status = ValidationStatus.FAILED
            validation_errors = exc.details or [message]
            if "schema" in message.lower():
                code = "schema_validation_failed"
            else:
                code = "evidence_validation_failed"
        elif isinstance(exc, ValueError):
            code = "invalid_request"
        else:
            code = "analysis_failed"

        return (
            AnalysisErrorInfo(
                code=code,
                message=message,
                details=validation_errors,
            ),
            validation_status,
            validation_errors,
        )

    def _prepare_analysis_request(
        self,
        incident_id: int,
        *,
        skill_name: str,
        analysis_profile: str,
        raw_data_limit: int,
        related_limit: int,
        collector_limit: int,
        include_host_context: bool,
        include_related_events: bool,
        include_forensics: bool,
        timing: AnalysisTimingMetrics,
    ) -> tuple[PreparedIncidentAnalysis, dict, str, AnalysisSourceContext]:
        source_start = perf_counter()
        details = self._analysis_service.fetch_incident_details(
            incident_id,
            raw_data_limit=raw_data_limit,
            related_limit=related_limit,
            collector_limit=collector_limit,
            include_host_context=include_host_context,
            include_related_events=include_related_events,
            include_forensics=include_forensics,
        )
        timing.source_retrieval_duration_ms = _duration_ms(source_start)

        normalization_start = perf_counter()
        prepared = self._analysis_service.prepare_analysis(
            incident_details=details,
            skill_name=skill_name,
            analysis_profile=analysis_profile,
        )
        timing.normalization_duration_ms = _duration_ms(normalization_start)
        normalized_input = prepared.analysis_input.model_dump(mode="json")
        source_fingerprint = self._build_source_fingerprint(prepared)
        source_context = self._build_source_context(
            analysis_profile=analysis_profile,
            raw_data_limit=raw_data_limit,
            related_limit=related_limit,
            collector_limit=collector_limit,
            include_host_context=include_host_context,
            include_related_events=include_related_events,
            include_forensics=include_forensics,
            prepared=prepared,
        )
        return prepared, normalized_input, source_fingerprint, source_context

    def _build_run_record(
        self,
        *,
        run_id: str,
        incident_id: int,
        created_at: datetime,
        idempotency_key: str,
        source_fingerprint: str | None,
        source_context: AnalysisSourceContext,
        timing: AnalysisTimingMetrics,
        skill_name: str,
        skill_version: str,
        normalized_input: dict | None,
        status: AnalysisRunStatus,
        validation_status: ValidationStatus,
    ) -> AnalysisRunRecord:
        return AnalysisRunRecord(
            run_id=run_id,
            incident_id=str(incident_id),
            skill_name=skill_name,
            skill_version=skill_version,
            llm_provider=self._analysis_service.llm_provider_name,
            model_name=self._analysis_service.llm_model_name,
            request_id=None,
            status=status,
            validation_status=validation_status,
            source_context=source_context,
            timing=timing,
            usage=None,
            estimated_cost_usd=None,
            created_at=created_at,
            completed_at=None,
            idempotency_key=idempotency_key,
            source_fingerprint=source_fingerprint,
            normalized_input=normalized_input,
            llm_output=None,
            validated_output=None,
        )

    def _execute_prepared_run(
        self,
        *,
        run: AnalysisRunRecord,
        prepared: PreparedIncidentAnalysis,
        total_start: float,
        persist_existing: bool,
    ) -> AnalysisRunRecord:
        llm_result = None
        validated_output = None

        try:
            with _ANALYSIS_EXECUTION_GATE:
                llm_start = perf_counter()
                llm_result = self._analysis_service.generate_structured_output(prepared=prepared)
                run.timing.llm_duration_ms = _duration_ms(llm_start)

                validation_start = perf_counter()
                result = self._analysis_service.validate_structured_output(
                    prepared=prepared,
                    llm_result=llm_result,
                )
                run.timing.validation_duration_ms = _duration_ms(validation_start)
                validated_output = result.model_dump(mode="json")

            run.llm_provider = llm_result.provider_name
            run.model_name = llm_result.model_name
            run.request_id = llm_result.request_id
            run.status = AnalysisRunStatus.SUCCESS
            run.validation_status = ValidationStatus.PASSED
            run.validation_errors = []
            run.error = None
            run.usage = llm_result.token_usage
            run.estimated_cost_usd = llm_result.estimated_cost_usd
            run.llm_output = llm_result.output
            run.validated_output = validated_output
        except Exception as exc:
            error, validation_status, validation_errors = self._classify_error(exc)
            run.status = AnalysisRunStatus.FAILED
            run.validation_status = validation_status
            run.validation_errors = validation_errors
            run.error = error
            run.llm_provider = llm_result.provider_name if llm_result else run.llm_provider
            run.model_name = llm_result.model_name if llm_result else run.model_name
            run.request_id = llm_result.request_id if llm_result else run.request_id
            run.usage = llm_result.token_usage if llm_result else None
            run.estimated_cost_usd = llm_result.estimated_cost_usd if llm_result else None
            run.llm_output = llm_result.output if llm_result else None
            run.validated_output = validated_output

        run.completed_at = _utcnow()
        run.timing.total_duration_ms = _duration_ms(total_start)
        if persist_existing:
            return self._repository.update_run(run)
        return self._repository.save_run(run)

    def _persist_failed_run(
        self,
        *,
        run_id: str,
        incident_id: int,
        created_at: datetime,
        total_start: float,
        idempotency_key: str,
        skill_name: str,
        skill_version: str,
        source_context: AnalysisSourceContext,
        timing: AnalysisTimingMetrics,
        normalized_input: dict | None,
        source_fingerprint: str | None,
        exc: Exception,
    ) -> AnalysisRunRecord:
        timing.total_duration_ms = _duration_ms(total_start)
        error, validation_status, validation_errors = self._classify_error(exc)
        run = AnalysisRunRecord(
            run_id=run_id,
            incident_id=str(incident_id),
            skill_name=skill_name,
            skill_version=skill_version,
            llm_provider=self._analysis_service.llm_provider_name,
            model_name=self._analysis_service.llm_model_name,
            request_id=None,
            status=AnalysisRunStatus.FAILED,
            validation_status=validation_status,
            validation_errors=validation_errors,
            error=error,
            source_context=source_context,
            timing=timing,
            usage=None,
            estimated_cost_usd=None,
            created_at=created_at,
            completed_at=_utcnow(),
            idempotency_key=idempotency_key,
            source_fingerprint=source_fingerprint,
            normalized_input=normalized_input,
            llm_output=None,
            validated_output=None,
        )
        return self._repository.save_run(run)

    def _spawn_background_completion(
        self,
        *,
        run: AnalysisRunRecord,
        prepared: PreparedIncidentAnalysis,
        total_start: float,
    ) -> None:
        run_for_worker = run.model_copy(deep=True)
        thread = Thread(
            target=self._execute_prepared_run,
            kwargs={
                "run": run_for_worker,
                "prepared": prepared,
                "total_start": total_start,
                "persist_existing": True,
            },
            daemon=True,
            name=f"analysis-run-{run.run_id}",
        )
        thread.start()

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
        force: bool = False,
        async_run: bool = False,
    ) -> AnalysisRunExecution:
        profile = get_analysis_profile(analysis_profile)
        effective_raw_data_limit = raw_data_limit or profile.raw_data_limit
        effective_related_limit = related_limit or profile.related_limit
        effective_collector_limit = collector_limit or profile.collector_limit
        effective_include_host_context = (
            profile.include_host_context if include_host_context is None else include_host_context
        )
        effective_include_related_events = (
            profile.include_related_events
            if include_related_events is None
            else include_related_events
        )
        effective_include_forensics = (
            profile.include_forensics if include_forensics is None else include_forensics
        )
        idempotency_key = self._build_idempotency_key(
            incident_id=incident_id,
            skill_name=skill_name,
            analysis_profile=profile.name,
            raw_data_limit=effective_raw_data_limit,
            related_limit=effective_related_limit,
            collector_limit=effective_collector_limit,
            include_host_context=effective_include_host_context,
            include_related_events=effective_include_related_events,
            include_forensics=effective_include_forensics,
        )
        try:
            skill_version = get_skill(skill_name).skill_version
        except FortiEDRError:
            skill_version = skill_name

        run_id = str(uuid4())
        created_at = _utcnow()
        total_start = perf_counter()
        timing = AnalysisTimingMetrics()
        prepared: PreparedIncidentAnalysis | None = None
        normalized_input = None
        source_fingerprint = None
        source_context = self._build_source_context(
            analysis_profile=profile.name,
            raw_data_limit=effective_raw_data_limit,
            related_limit=effective_related_limit,
            collector_limit=effective_collector_limit,
            include_host_context=effective_include_host_context,
            include_related_events=effective_include_related_events,
            include_forensics=effective_include_forensics,
        )

        try:
            prepared, normalized_input, source_fingerprint, source_context = self._prepare_analysis_request(
                incident_id,
                skill_name=skill_name,
                analysis_profile=profile.name,
                raw_data_limit=effective_raw_data_limit,
                related_limit=effective_related_limit,
                collector_limit=effective_collector_limit,
                include_host_context=effective_include_host_context,
                include_related_events=effective_include_related_events,
                include_forensics=effective_include_forensics,
                timing=timing,
            )

            if not force:
                cached = self._repository.get_latest_successful_run(
                    incident_id=str(incident_id),
                    idempotency_key=idempotency_key,
                    source_fingerprint=source_fingerprint,
                )
                if cached is not None:
                    return AnalysisRunExecution(from_cache=True, run=cached)

            run = self._build_run_record(
                run_id=run_id,
                incident_id=incident_id,
                created_at=created_at,
                idempotency_key=idempotency_key,
                source_fingerprint=source_fingerprint,
                source_context=source_context,
                timing=timing,
                skill_name=prepared.skill.name,
                skill_version=prepared.skill.skill_version,
                normalized_input=normalized_input,
                status=AnalysisRunStatus.RUNNING if async_run else AnalysisRunStatus.SUCCESS,
                validation_status=ValidationStatus.SKIPPED if async_run else ValidationStatus.PASSED,
            )

            if async_run:
                self._repository.save_run(run)
                self._spawn_background_completion(
                    run=run,
                    prepared=prepared,
                    total_start=total_start,
                )
                return AnalysisRunExecution(from_cache=False, run=run)

            completed_run = self._execute_prepared_run(
                run=run,
                prepared=prepared,
                total_start=total_start,
                persist_existing=False,
            )
            return AnalysisRunExecution(from_cache=False, run=completed_run)
        except Exception as exc:
            failed_run = self._persist_failed_run(
                run_id=run_id,
                incident_id=incident_id,
                created_at=created_at,
                total_start=total_start,
                idempotency_key=idempotency_key,
                skill_name=prepared.skill.name if prepared else skill_name,
                skill_version=prepared.skill.skill_version if prepared else skill_version,
                source_context=source_context,
                timing=timing,
                normalized_input=normalized_input,
                source_fingerprint=source_fingerprint,
                exc=exc,
            )
            return AnalysisRunExecution(from_cache=False, run=failed_run)

    def get_run(self, run_id: str) -> AnalysisRunRecord | None:
        return self._repository.get_run(run_id)

    def get_latest_successful_analysis(self, incident_id: int) -> AnalysisRunRecord | None:
        return self._repository.get_latest_successful_run(incident_id=str(incident_id))

    def list_analysis_history(self, incident_id: int, *, limit: int = 20) -> list[AnalysisRunRecord]:
        return self._repository.list_runs_for_incident(
            incident_id=str(incident_id),
            limit=limit,
        )

    def get_latest_successful_analyses_for_incidents(
        self,
        incident_ids: list[int],
    ) -> dict[str, AnalysisRunRecord]:
        return self._repository.get_latest_successful_runs_for_incidents(
            incident_ids=[str(incident_id) for incident_id in incident_ids],
        )

    def get_latest_runs_for_incidents(
        self,
        incident_ids: list[int],
    ) -> dict[str, AnalysisRunRecord]:
        return self._repository.get_latest_runs_for_incidents(
            incident_ids=[str(incident_id) for incident_id in incident_ids],
        )

    def get_feedback(self, run_id: str) -> AnalystFeedback | None:
        run = self.get_run(run_id)
        if run is None:
            return None
        return run.analyst_feedback

    def upsert_feedback(
        self,
        run_id: str,
        *,
        usefulness: str | None = None,
        correctness: str | None = None,
        analyst_classification: str | None = None,
        comment: str | None = None,
    ) -> AnalysisRunRecord | None:
        run = self.get_run(run_id)
        if run is None:
            return None

        run.analyst_feedback = AnalystFeedback(
            usefulness=usefulness,
            correctness=correctness,
            analyst_classification=analyst_classification,
            comment=comment,
            updated_at=_utcnow(),
        )
        return self._repository.update_run(run)

    def clear_all_runs(self) -> int:
        return self._repository.clear_all_runs()
