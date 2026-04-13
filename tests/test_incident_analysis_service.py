from __future__ import annotations

import copy

import pytest

from fortiedr_mcp.analysis.context import IncidentAnalysisInputBuilder
from fortiedr_mcp.analysis.policies import load_policy_rule_descriptions
from fortiedr_mcp.errors import FortiEDRValidationError
from fortiedr_mcp.llm.mock import MockStructuredLLMClient
from fortiedr_mcp.services.incident_analysis import IncidentAnalysisService


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
        "executive_summary": "FortiEDR blocked a cmd.exe execution on WS-01 for ACME\\\\alice and related context suggests suspicious but not yet confirmed malicious activity.",
        "risk_level": "high",
        "key_metadata": {
            "hostname": {"value": "WS-01", "evidence": [hostname_evidence.model_dump(mode="json")]},
            "user": {"value": "ACME\\\\alice", "evidence": [user_evidence.model_dump(mode="json")]},
            "process_name": {"value": "cmd.exe", "evidence": [process_evidence.model_dump(mode="json")]},
            "process_path": {
                "value": "C:\\\\Windows\\\\System32\\\\cmd.exe",
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
            "immediate": [
                "Review parent-process telemetry and command-line context in FortiEDR and endpoint logs."
            ],
            "short_term": [
                "Check whether ACME\\\\alice or IT operations initiated the blocked command execution."
            ],
            "validation": [
                "Validate whether 198.51.100.10 and 203.0.113.12 are expected destinations for WS-01."
            ]
        },
        "missing_information": [
            "Full parent-process and command-line telemetry are not present in the current dataset."
        ],
        "verdict": "Blocked suspicious command execution on WS-01 requires analyst validation before stronger classification."
    }


def test_incident_analysis_service_returns_valid_result(sample_incident_details, sample_analysis_input):
    service = IncidentAnalysisService(
        data_service=FakeIncidentDataService(sample_incident_details),
        llm_client=MockStructuredLLMClient(_valid_response(sample_analysis_input)),
    )

    result = service.analyze_incident(5440222)

    assert result.skill_version == "incident_senior_soc_v1"
    assert result.incident_id == "5440222"
    assert result.observed_facts[0].evidence[0].tool == "get_incident_details"
    assert result.hypotheses[0].confidence == "medium"


def test_incident_analysis_service_rejects_unregistered_evidence(sample_incident_details, sample_analysis_input):
    invalid_response = _valid_response(sample_analysis_input)
    invalid_response["observed_facts"][0]["evidence"][0] = {
        "evidence_id": "unknown",
        "tool": "get_incident_details",
        "path": "incident.fake_field",
        "value": "nope",
        "normalized_value": None,
    }

    service = IncidentAnalysisService(
        data_service=FakeIncidentDataService(sample_incident_details),
        llm_client=MockStructuredLLMClient(invalid_response),
    )

    with pytest.raises(FortiEDRValidationError):
        service.analyze_incident(5440222)


def test_incident_analysis_service_canonicalizes_unique_tool_value_evidence(
    sample_incident_details,
    sample_analysis_input,
):
    response = _valid_response(sample_analysis_input)
    response["observed_facts"][1]["evidence"][0] = {
        "tool": "raw_data_items",
        "path": "raw_data_items[0].StackInfos[0].CommonAdditionalInfo[6]",
        "value": "198.51.100.10",
        "normalized_value": None,
    }

    service = IncidentAnalysisService(
        data_service=FakeIncidentDataService(sample_incident_details),
        llm_client=MockStructuredLLMClient(response),
    )

    result = service.analyze_incident(5440222)

    assert result.observed_facts[1].evidence[0].path == "raw_data_items[0].destination"


def test_incident_analysis_service_accepts_nested_raw_data_evidence_from_model(sample_incident_details):
    nested_details = copy.deepcopy(sample_incident_details)
    nested_details.raw_data_items[0]["StackInfos"] = [
        {
            "CommonAdditionalInfo": [
                {
                    "FileHashMD5": "0AD99D6EE05634EF71FA11020ACCFFE6",
                    "FileHashSHA2": "5726B610B8DF672E55F1368D32327B9C93FBE4734C3DED8307A4B4D3B927B9B1",
                }
            ]
        }
    ]

    response = {
        "skill_version": "incident_senior_soc_v1",
        "incident_id": "5440222",
        "executive_summary": "Nested raw telemetry includes file hashes that support a suspicious executable assessment.",
        "risk_level": "high",
        "key_metadata": {
            "hostname": {"value": "WS-01", "evidence": [{"tool": "get_incident_details", "path": "incident.host", "value": "WS-01"}]},
            "user": {"value": "ACME\\alice", "evidence": [{"tool": "get_incident_details", "path": "incident.logged_user", "value": "ACME\\alice"}]},
            "process_name": {"value": "cmd.exe", "evidence": [{"tool": "get_incident_details", "path": "incident.process", "value": "cmd.exe"}]},
            "process_path": {"value": "C:\\Windows\\System32\\cmd.exe", "evidence": [{"tool": "get_incident_details", "path": "incident.process_path", "value": "C:\\Windows\\System32\\cmd.exe"}]},
            "hashes": {"md5": None, "sha1": None, "sha256": None, "evidence": []},
            "severity": {"value": "High", "evidence": [{"tool": "get_incident_details", "path": "incident.severity", "value": "High"}]},
            "classification": {"value": "Suspicious", "evidence": [{"tool": "get_incident_details", "path": "incident.classification", "value": "Suspicious"}]},
            "first_seen": {"value": "2026-04-10T12:00:00Z", "evidence": [{"tool": "get_incident_details", "path": "incident.first_seen", "value": "2026-04-10T12:00:00Z"}]},
            "last_seen": {"value": "2026-04-10T12:05:00Z", "evidence": [{"tool": "get_incident_details", "path": "incident.last_seen", "value": "2026-04-10T12:05:00Z"}]},
            "action": {"value": "Blocked", "evidence": [{"tool": "get_incident_details", "path": "incident.action", "value": "Blocked"}]},
        },
        "observed_facts": [
            {
                "statement": "Nested raw telemetry exposes the executable hashes for the suspicious sample.",
                "evidence": [
                    {
                        "tool": "raw_data_items",
                        "path": "StackInfos[0].CommonAdditionalInfo[5]",
                        "value": {
                            "FileHashMD5": "0AD99D6EE05634EF71FA11020ACCFFE6",
                            "FileHashSHA2": "5726B610B8DF672E55F1368D32327B9C93FBE4734C3DED8307A4B4D3B927B9B1",
                        },
                    }
                ],
            }
        ],
        "investigation_notes": [],
        "hypotheses": [],
        "possible_classification": {
            "label": "suspicious_activity_requiring_validation",
            "rationale": "The nested telemetry is suspicious but still requires broader context.",
        },
        "recommended_next_steps": {"immediate": [], "short_term": [], "validation": []},
        "missing_information": [],
        "verdict": "Suspicious executable evidence is present in nested raw telemetry and should be validated."
    }

    service = IncidentAnalysisService(
        data_service=FakeIncidentDataService(nested_details),
        llm_client=MockStructuredLLMClient(response),
    )

    result = service.analyze_incident(5440222)

    assert result.observed_facts[0].evidence[0].tool == "get_incident_details"
    assert result.observed_facts[0].evidence[0].path == "raw_data_items[0].StackInfos[0].CommonAdditionalInfo[0]"


def test_incident_analysis_service_moves_zero_evidence_missing_info_facts(
    sample_incident_details,
    sample_analysis_input,
):
    response = _valid_response(sample_analysis_input)
    response["observed_facts"].append(
        {
            "statement": "Host context and hostname information are unavailable for this incident.",
            "evidence": [],
        }
    )

    service = IncidentAnalysisService(
        data_service=FakeIncidentDataService(sample_incident_details),
        llm_client=MockStructuredLLMClient(response),
    )

    result = service.analyze_incident(5440222)

    assert all(fact.statement != "Host context and hostname information are unavailable for this incident." for fact in result.observed_facts)
    assert "Host context and hostname information are unavailable for this incident." in result.missing_information


def test_incident_analysis_service_repairs_sparse_small_model_output(
    sample_incident_details,
):
    sparse_response = {
        "skill_version": "incident_senior_soc_v1",
        "incident_id": 5440222,
        "executive_summary": "Log",
        "risk_level": "critical",
        "key_metadata": {
            "hostname": {"value": None},
            "user": {"value": None},
            "process_name": {"value": None},
            "process_path": {"value": None},
            "hashes": {"md5": "1234567890"},
            "severity": {"value": None},
            "classification": {"value": None},
            "first_seen": {"value": None},
            "last_seen": {"value": None},
            "action": {"value": None},
        },
        "possible_classification": {
            "label": "suspicious_activity_requiring_validation",
            "rationale": "The event needs analyst review.",
        },
        "recommended_next_steps": {
            "validation": [],
        },
        "verdict": "malicious",
    }

    service = IncidentAnalysisService(
        data_service=FakeIncidentDataService(sample_incident_details),
        llm_client=MockStructuredLLMClient(sparse_response),
    )

    result = service.analyze_incident(5440222)

    assert result.incident_id == "5440222"
    assert result.key_metadata.hashes.md5 is None
    assert result.recommended_next_steps.immediate == []
    assert result.recommended_next_steps.short_term == []
    assert "Hash values were returned without evidence, so they were cleared during repair." in result.missing_information


def test_incident_analysis_service_rejects_partial_output_missing_required_fields(
    sample_incident_details,
):
    partial_response = {
        "hostname": "server1.example.com",
        "hypotheses": [],
        "investigation_notes": [],
        "key_metadata": {
            "action": {"evidence": [], "value": None},
            "classification": {"evidence": [], "value": None},
            "first_seen": {"evidence": [], "value": None},
            "hashes": {"evidence": [], "md5": None, "sha1": None, "sha256": None},
            "hostname": {"evidence": [], "value": None},
            "last_seen": {"evidence": [], "value": None},
            "process_name": {"evidence": [], "value": None},
            "process_path": {"evidence": [], "value": None},
            "severity": {"evidence": [], "value": None},
            "user": {"evidence": [], "value": None},
        },
        "missing_information": [],
        "observed_facts": [],
        "process_name": "login",
        "process_path": "/login",
        "recommended_next_steps": {"immediate": [], "short_term": [], "validation": []},
        "severity": "critical",
        "skill_version": "incident_senior_soc_v1",
        "user": "john.doe",
    }

    service = IncidentAnalysisService(
        data_service=FakeIncidentDataService(sample_incident_details),
        llm_client=MockStructuredLLMClient(partial_response),
    )

    with pytest.raises(FortiEDRValidationError) as exc_info:
        service.analyze_incident(5440222)

    assert "executive_summary: Field required" in exc_info.value.details
    assert "risk_level: Field required" in exc_info.value.details
    assert "possible_classification: Field required" in exc_info.value.details
    assert "verdict: Field required" in exc_info.value.details


def test_analysis_input_builder_extracts_hashes_from_nested_raw_data(sample_incident_details):
    nested_details = copy.deepcopy(sample_incident_details)
    nested_details.raw_data_items[0]["StackInfos"] = [
        {
            "CommonAdditionalInfo": [
                {
                    "FileHashMD5": "0AD99D6EE05634EF71FA11020ACCFFE6",
                    "FileHashSHA2": "5726B610B8DF672E55F1368D32327B9C93FBE4734C3DED8307A4B4D3B927B9B1",
                }
            ]
        }
    ]

    analysis_input = IncidentAnalysisInputBuilder().build(nested_details)

    assert analysis_input.key_metadata_candidates.hashes.md5 == "0AD99D6EE05634EF71FA11020ACCFFE6"
    assert (
        analysis_input.key_metadata_candidates.hashes.sha256
        == "5726B610B8DF672E55F1368D32327B9C93FBE4734C3DED8307A4B4D3B927B9B1"
    )
    assert analysis_input.key_metadata_candidates.hashes.evidence[0].path == (
        "raw_data_items[0].StackInfos[0].CommonAdditionalInfo[0].FileHashMD5"
    )


def test_analysis_input_builder_derives_forensic_execution_context(sample_incident_details):
    analysis_input = IncidentAnalysisInputBuilder().build(sample_incident_details)

    assert analysis_input.derived_context.matched_rules == [
        "Execution Prevention",
        "Malicious File Detected",
    ]
    assert analysis_input.derived_context.violated_policies == ["POD - Execution Prevention"]
    assert [entry.process_name for entry in analysis_input.derived_context.process_stack] == [
        "winlogon.exe",
        "explorer.exe",
        "cmd.exe",
    ]
    assert analysis_input.derived_context.process_stack[-1].highlighted is True
    assert analysis_input.derived_context.relevant_command_lines[0].process_name == "cmd.exe"
    assert analysis_input.derived_context.forensics_summary is not None
    assert analysis_input.derived_context.forensics_summary.certificate_status == "Unsigned"
    assert analysis_input.derived_context.matched_rule_descriptions[0].rule_name == "Malicious File Detected"
    assert (
        analysis_input.derived_context.matched_rule_descriptions[0].policy_name
        == "Execution Prevention"
    )


def test_analysis_input_builder_standard_profile_keeps_up_to_five_rule_descriptions(
    sample_incident_details,
):
    enriched_details = copy.deepcopy(sample_incident_details)
    enriched_details.incident.rules = [
        "Malicious File Detected",
        "Unconfirmed Executable",
        "Unmapped Executable",
        "Invalid Checksum",
        "Process Hollowing",
    ]

    analysis_input = IncidentAnalysisInputBuilder().build(enriched_details)

    names = [entry.rule_name for entry in analysis_input.derived_context.matched_rule_descriptions]
    assert "Invalid Checksum" in names
    assert "Process Hollowing" in names


def test_analysis_input_builder_lite_profile_reduces_optional_context(sample_incident_details):
    analysis_input = IncidentAnalysisInputBuilder().build(
        sample_incident_details,
        analysis_profile="lite",
    )

    assert analysis_input.host_context is None
    assert analysis_input.related_events is None
    assert analysis_input.derived_context.forensics_summary is not None
    assert len(analysis_input.derived_context.matched_rule_descriptions) <= 2


def test_policy_rule_descriptions_load_from_packaged_json():
    entries = load_policy_rule_descriptions()

    assert entries
    assert any(entry.rule_name == "Malicious File Detected" for entry in entries)
    unconfirmed = next(entry for entry in entries if entry.rule_name == "Unconfirmed Executable")
    assert unconfirmed.rule_subtitle == "Executable File Failed Verification Test"
import copy
