from __future__ import annotations

import copy
import time

from fortiedr_mcp.llm.mock import MockStructuredLLMClient
from fortiedr_mcp.repositories import AnalysisRunRepository
from fortiedr_mcp.services import AnalysisRunService, IncidentAnalysisService
from fortiedr_mcp.models import AnalysisRunStatus, ValidationStatus


class FakeIncidentDataService:
    def __init__(self, details):
        self._details = details

    def get_incident_details(
        self,
        incident_id: int,
        *,
        raw_data_limit: int = 25,
        related_limit: int = 10,
        collector_limit: int = 10,
        include_host_context: bool = True,
        include_related_events: bool = True,
        include_forensics: bool = True,
    ):
        assert incident_id == 5440222
        return self._details


class SequenceIncidentDataService:
    def __init__(self, details_sequence):
        self._details_sequence = list(details_sequence)
        self._index = 0

    def get_incident_details(
        self,
        incident_id: int,
        *,
        raw_data_limit: int = 25,
        related_limit: int = 10,
        collector_limit: int = 10,
        include_host_context: bool = True,
        include_related_events: bool = True,
        include_forensics: bool = True,
    ):
        assert incident_id == 5440222
        current = self._details_sequence[min(self._index, len(self._details_sequence) - 1)]
        self._index += 1
        return copy.deepcopy(current)


def _find_evidence(sample_analysis_input, path: str):
    for evidence in sample_analysis_input.evidence_catalog:
        if evidence.path == path:
            return evidence
    raise AssertionError(f"Evidence not found for path: {path}")


def _valid_response(sample_analysis_input):
    hostname_evidence = _find_evidence(sample_analysis_input, "incident.host")
    user_evidence = _find_evidence(sample_analysis_input, "incident.logged_user")
    process_evidence = _find_evidence(sample_analysis_input, "incident.process")
    process_path_evidence = _find_evidence(sample_analysis_input, "incident.process_path")
    severity_evidence = _find_evidence(sample_analysis_input, "incident.severity")
    classification_evidence = _find_evidence(sample_analysis_input, "incident.classification")
    first_seen_evidence = _find_evidence(sample_analysis_input, "incident.first_seen")
    last_seen_evidence = _find_evidence(sample_analysis_input, "incident.last_seen")
    action_evidence = _find_evidence(sample_analysis_input, "incident.action")
    raw_destination_evidence = _find_evidence(sample_analysis_input, "raw_data_items[0].destination")

    return {
        "skill_version": "incident_senior_soc_v1",
        "incident_id": "5440222",
        "executive_summary": "FortiEDR blocked a cmd.exe execution on WS-01 for ACME\\alice and related context suggests suspicious but not yet confirmed malicious activity.",
        "risk_level": "high",
        "key_metadata": {
            "hostname": {"value": "WS-01", "evidence": [hostname_evidence.model_dump(mode="json")]},
            "user": {"value": "ACME\\alice", "evidence": [user_evidence.model_dump(mode="json")]},
            "process_name": {"value": "cmd.exe", "evidence": [process_evidence.model_dump(mode="json")]},
            "process_path": {
                "value": "C:\\Windows\\System32\\cmd.exe",
                "evidence": [process_path_evidence.model_dump(mode="json")],
            },
            "hashes": {"md5": None, "sha1": None, "sha256": None, "evidence": []},
            "severity": {"value": "High", "evidence": [severity_evidence.model_dump(mode="json")]},
            "classification": {"value": "Suspicious", "evidence": [classification_evidence.model_dump(mode="json")]},
            "first_seen": {"value": "2026-04-10T12:00:00Z", "evidence": [first_seen_evidence.model_dump(mode="json")]},
            "last_seen": {"value": "2026-04-10T12:05:00Z", "evidence": [last_seen_evidence.model_dump(mode="json")]},
            "action": {"value": "Blocked", "evidence": [action_evidence.model_dump(mode="json")]},
        },
        "observed_facts": [
            {
                "statement": "FortiEDR recorded a blocked cmd.exe execution on WS-01.",
                "evidence": [
                    hostname_evidence.model_dump(mode="json"),
                    process_evidence.model_dump(mode="json"),
                    action_evidence.model_dump(mode="json"),
                ],
            },
            {
                "statement": "The first raw event destination recorded for the incident was 198.51.100.10.",
                "evidence": [raw_destination_evidence.model_dump(mode="json")],
            },
        ],
        "investigation_notes": [
            {
                "topic": "related_activity",
                "content": "A recent PowerShell event on the same host suggests adjacent scripting activity worth validating.",
            }
        ],
        "hypotheses": [
            {
                "label": "The blocked command shell launch may be part of a script-driven execution chain.",
                "confidence": "medium",
                "rationale": "Related PowerShell activity is present on the same host and user context, but parent-process telemetry is unavailable.",
            }
        ],
        "possible_classification": {
            "label": "suspicious_activity_requiring_validation",
            "rationale": "The available data supports suspicious activity, but it is insufficient for a stronger label.",
        },
        "recommended_next_steps": {
            "immediate": ["Review parent-process telemetry and command-line context in FortiEDR and endpoint logs."],
            "short_term": ["Check whether ACME\\alice or IT operations initiated the blocked command execution."],
            "validation": ["Validate whether 198.51.100.10 and 203.0.113.12 are expected destinations for WS-01."],
        },
        "missing_information": ["Full parent-process and command-line telemetry are not present in the current dataset."],
        "verdict": "Blocked suspicious command execution on WS-01 requires analyst validation before stronger classification.",
    }


def test_analysis_run_service_persists_success_and_reuses_cache(
    tmp_path,
    sample_incident_details,
    sample_analysis_input,
):
    repository = AnalysisRunRepository(tmp_path / "analysis.sqlite3")
    analysis_service = IncidentAnalysisService(
        data_service=FakeIncidentDataService(sample_incident_details),
        llm_client=MockStructuredLLMClient(_valid_response(sample_analysis_input)),
    )
    run_service = AnalysisRunService(
        analysis_service=analysis_service,
        repository=repository,
    )

    first = run_service.analyze_incident(5440222, analysis_profile="lite")
    second = run_service.analyze_incident(5440222, analysis_profile="lite")

    assert first.from_cache is False
    assert first.run.status == AnalysisRunStatus.SUCCESS
    assert first.run.validation_status == ValidationStatus.PASSED
    assert first.run.validated_output is not None
    assert first.run.normalized_input is not None
    assert first.run.source_fingerprint is not None
    assert first.run.source_context.analysis_profile == "lite"
    assert first.run.source_context.include_related_events is False
    assert first.run.timing.total_duration_ms is not None
    assert first.run.timing.llm_duration_ms is not None
    assert second.from_cache is True
    assert second.run.run_id == first.run.run_id

    history = run_service.list_analysis_history(5440222)
    assert len(history) == 1


def test_analysis_run_service_persists_validation_failures(tmp_path, sample_incident_details, sample_analysis_input):
    invalid_response = _valid_response(sample_analysis_input)
    invalid_response["observed_facts"][0]["evidence"][0] = {
        "evidence_id": "unknown",
        "tool": "get_incident_details",
        "path": "incident.fake_field",
        "value": "nope",
        "normalized_value": None,
    }
    repository = AnalysisRunRepository(tmp_path / "analysis.sqlite3")
    analysis_service = IncidentAnalysisService(
        data_service=FakeIncidentDataService(sample_incident_details),
        llm_client=MockStructuredLLMClient(invalid_response),
    )
    run_service = AnalysisRunService(
        analysis_service=analysis_service,
        repository=repository,
    )

    execution = run_service.analyze_incident(5440222)

    assert execution.from_cache is False
    assert execution.run.status == AnalysisRunStatus.FAILED
    assert execution.run.validation_status == ValidationStatus.FAILED
    assert execution.run.error is not None
    assert execution.run.error.code == "evidence_validation_failed"
    assert execution.run.llm_output is not None
    assert execution.run.validated_output is None


def test_analysis_run_service_does_not_reuse_cache_when_source_fingerprint_changes(
    tmp_path,
    sample_incident_details,
    sample_analysis_input,
):
    changed_details = copy.deepcopy(sample_incident_details)
    changed_details.raw_data_items[0]["count"] = 99

    repository = AnalysisRunRepository(tmp_path / "analysis.sqlite3")
    analysis_service = IncidentAnalysisService(
        data_service=SequenceIncidentDataService([sample_incident_details, changed_details]),
        llm_client=MockStructuredLLMClient(_valid_response(sample_analysis_input)),
    )
    run_service = AnalysisRunService(
        analysis_service=analysis_service,
        repository=repository,
    )

    first = run_service.analyze_incident(5440222)
    second = run_service.analyze_incident(5440222)

    assert first.from_cache is False
    assert second.from_cache is False
    assert second.run.run_id != first.run.run_id
    assert second.run.source_fingerprint != first.run.source_fingerprint
    assert len(run_service.list_analysis_history(5440222)) == 2


def test_analysis_run_service_upserts_feedback(tmp_path, sample_incident_details, sample_analysis_input):
    repository = AnalysisRunRepository(tmp_path / "analysis.sqlite3")
    analysis_service = IncidentAnalysisService(
        data_service=FakeIncidentDataService(sample_incident_details),
        llm_client=MockStructuredLLMClient(_valid_response(sample_analysis_input)),
    )
    run_service = AnalysisRunService(
        analysis_service=analysis_service,
        repository=repository,
    )

    execution = run_service.analyze_incident(5440222)
    updated_run = run_service.upsert_feedback(
        execution.run.run_id,
        usefulness="useful",
        correctness="correct",
        analyst_classification="needs_validation",
        comment="Reasonable first-pass triage.",
    )

    assert updated_run is not None
    assert updated_run.analyst_feedback is not None
    assert updated_run.analyst_feedback.usefulness == "useful"
    assert updated_run.analyst_feedback.correctness == "correct"
    assert updated_run.analyst_feedback.analyst_classification == "needs_validation"
    assert updated_run.analyst_feedback.updated_at is not None
    assert run_service.get_feedback(execution.run.run_id) is not None


def test_analysis_run_service_supports_async_background_runs(
    tmp_path,
    sample_incident_details,
    sample_analysis_input,
):
    repository = AnalysisRunRepository(tmp_path / "analysis.sqlite3")
    analysis_service = IncidentAnalysisService(
        data_service=FakeIncidentDataService(sample_incident_details),
        llm_client=MockStructuredLLMClient(_valid_response(sample_analysis_input)),
    )
    run_service = AnalysisRunService(
        analysis_service=analysis_service,
        repository=repository,
    )

    execution = run_service.analyze_incident(5440222, async_run=True, force=True)

    assert execution.run.status == AnalysisRunStatus.RUNNING
    completed = None
    for _ in range(20):
        completed = run_service.get_run(execution.run.run_id)
        if completed and completed.status != AnalysisRunStatus.RUNNING:
            break
        time.sleep(0.05)

    assert completed is not None
    assert completed.status == AnalysisRunStatus.SUCCESS
    assert completed.validation_status == ValidationStatus.PASSED
