import pytest
from pydantic import ValidationError

from fortiedr_mcp.analysis.models import (
    EvidenceBackedValue,
    EvidenceReference,
    HashMetadata,
    IncidentAnalysisResult,
    InvestigationNote,
    KeyMetadata,
    ObservedFact,
    PossibleClassification,
    PossibleClassificationLabel,
    RecommendedNextSteps,
    RiskLevel,
)


def _evidence() -> EvidenceReference:
    return EvidenceReference(
        evidence_id="e1",
        tool="get_incident_details",
        path="incident.process",
        value="cmd.exe",
    )


def _valid_result() -> IncidentAnalysisResult:
    evidence = _evidence()
    return IncidentAnalysisResult(
        skill_version="incident_senior_soc_v1",
        incident_id="5440222",
        executive_summary="Command execution on WS-01 triggered a blocked prevention event.",
        risk_level=RiskLevel.HIGH,
        key_metadata=KeyMetadata(
            hostname=EvidenceBackedValue(value="WS-01", evidence=[evidence]),
            user=EvidenceBackedValue(value="ACME\\alice", evidence=[evidence]),
            process_name=EvidenceBackedValue(value="cmd.exe", evidence=[evidence]),
            process_path=EvidenceBackedValue(
                value="C:\\Windows\\System32\\cmd.exe",
                evidence=[evidence],
            ),
            hashes=HashMetadata(md5=None, sha1=None, sha256=None, evidence=[]),
            severity=EvidenceBackedValue(value="High", evidence=[evidence]),
            classification=EvidenceBackedValue(value="Suspicious", evidence=[evidence]),
            first_seen=EvidenceBackedValue(value="2026-04-10T12:00:00Z", evidence=[evidence]),
            last_seen=EvidenceBackedValue(value="2026-04-10T12:05:00Z", evidence=[evidence]),
            action=EvidenceBackedValue(value="Blocked", evidence=[evidence]),
        ),
        observed_facts=[
            ObservedFact(
                statement="FortiEDR recorded a blocked cmd.exe execution on WS-01.",
                evidence=[evidence],
            )
        ],
        investigation_notes=[
            InvestigationNote(
                topic="host_context",
                content="The host had a recent related PowerShell event.",
            )
        ],
        hypotheses=[
            {
                "label": "Suspicious script or admin command execution preceded the blocked command shell launch.",
                "confidence": "medium",
                "rationale": "A related PowerShell event exists on the same host and user context."
            }
        ],
        possible_classification=PossibleClassification(
            label=PossibleClassificationLabel.SUSPICIOUS_ACTIVITY_REQUIRING_VALIDATION,
            rationale="The visible data supports suspicious activity but does not prove malicious intent.",
        ),
        recommended_next_steps=RecommendedNextSteps(
            immediate=["Review the parent process and command line in FortiEDR and Windows telemetry."],
            short_term=["Correlate this activity with change windows or admin tasks for ACME\\alice."],
            validation=["Confirm whether the destination IPs are expected for this endpoint."],
        ),
        missing_information=["The parent process and full command line are unavailable in the current dataset."],
        verdict="Blocked suspicious command execution on WS-01 requires validation before stronger classification.",
    )


def test_metadata_values_require_evidence():
    with pytest.raises(ValidationError):
        EvidenceBackedValue(value="WS-01", evidence=[])


def test_observed_facts_require_evidence():
    with pytest.raises(ValidationError):
        ObservedFact(statement="cmd.exe ran", evidence=[])


def test_valid_structured_analysis_result_builds():
    result = _valid_result()
    assert result.observed_facts
    assert result.hypotheses
    assert result.key_metadata.hostname.value == "WS-01"
