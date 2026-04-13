from __future__ import annotations

import json
from collections.abc import Iterable

from fortiedr_mcp.analysis.context import IncidentAnalysisInput
from fortiedr_mcp.analysis.models import (
    EvidenceReference,
    HashMetadata,
    IncidentAnalysisResult,
    KeyMetadata,
)
from fortiedr_mcp.errors import FortiEDRValidationError


def _freeze_value(value: object) -> str:
    return json.dumps(value, sort_keys=True, default=str)


def _section_path_prefix(tool_name: str) -> str | None:
    if tool_name == "raw_data_items":
        return "raw_data_items["
    if tool_name == "host_context":
        return "host_context"
    if tool_name == "related_events":
        return "related_events"
    return None


def _match_section_relative_path(
    evidence: EvidenceReference,
    *,
    evidence_candidates: Iterable[EvidenceReference],
) -> EvidenceReference | None:
    section_prefix = _section_path_prefix(evidence.tool)
    if not section_prefix:
        return None

    if evidence.path.startswith(section_prefix):
        return None

    suffix = evidence.path
    matches = [
        candidate
        for candidate in evidence_candidates
        if candidate.path.startswith(section_prefix)
        and (
            candidate.path.endswith(f".{suffix}")
            or candidate.path.endswith(suffix)
        )
    ]
    if len(matches) == 1:
        return matches[0]
    return None


def _walk_nested_evidence(
    *,
    tool: str,
    path: str,
    value: object,
) -> Iterable[EvidenceReference]:
    yield EvidenceReference(
        evidence_id=None,
        tool=tool,
        path=path,
        value=value,
        normalized_value=None,
    )

    if isinstance(value, dict):
        for key, nested_value in value.items():
            yield from _walk_nested_evidence(
                tool=tool,
                path=f"{path}.{key}",
                value=nested_value,
            )
    elif isinstance(value, list):
        for index, nested_value in enumerate(value):
            yield from _walk_nested_evidence(
                tool=tool,
                path=f"{path}[{index}]",
                value=nested_value,
            )


def _build_validation_evidence_candidates(
    analysis_input: IncidentAnalysisInput,
) -> list[EvidenceReference]:
    candidates = list(analysis_input.evidence_catalog)

    for index, raw_item in enumerate(analysis_input.raw_data_items):
        candidates.extend(
            _walk_nested_evidence(
                tool="get_incident_details",
                path=f"raw_data_items[{index}]",
                value=raw_item,
            )
        )

    deduplicated: list[EvidenceReference] = []
    seen_keys: set[tuple[str, str, str]] = set()
    for evidence in candidates:
        key = (evidence.tool, evidence.path, _freeze_value(evidence.value))
        if key in seen_keys:
            continue
        seen_keys.add(key)
        deduplicated.append(evidence)

    return deduplicated


def _canonicalize_evidence_reference(
    evidence: EvidenceReference,
    *,
    evidence_by_id: dict[str, EvidenceReference],
    evidence_by_tuple: dict[tuple[str, str, str], EvidenceReference],
    evidence_by_tool_value: dict[tuple[str, str], list[EvidenceReference]],
    evidence_by_path_value: dict[tuple[str, str], list[EvidenceReference]],
    evidence_by_value: dict[str, list[EvidenceReference]],
    evidence_by_tool_normalized: dict[tuple[str, str], list[EvidenceReference]],
    evidence_by_path_normalized: dict[tuple[str, str], list[EvidenceReference]],
    evidence_by_normalized: dict[str, list[EvidenceReference]],
    evidence_candidates: list[EvidenceReference],
) -> EvidenceReference:
    if evidence.evidence_id and evidence.evidence_id in evidence_by_id:
        return evidence_by_id[evidence.evidence_id]

    tuple_key = (evidence.tool, evidence.path, _freeze_value(evidence.value))
    if tuple_key in evidence_by_tuple:
        return evidence_by_tuple[tuple_key]

    relative_path_match = _match_section_relative_path(
        evidence,
        evidence_candidates=evidence_candidates,
    )
    if relative_path_match is not None:
        return relative_path_match

    if evidence.value is not None:
        tool_value_matches = evidence_by_tool_value.get(
            (evidence.tool, _freeze_value(evidence.value)),
            [],
        )
        if len(tool_value_matches) == 1:
            return tool_value_matches[0]

        path_value_matches = evidence_by_path_value.get(
            (evidence.path, _freeze_value(evidence.value)),
            [],
        )
        if len(path_value_matches) == 1:
            return path_value_matches[0]

        value_matches = evidence_by_value.get(_freeze_value(evidence.value), [])
        section_prefix = _section_path_prefix(evidence.tool)
        if section_prefix:
            section_matches = [
                candidate for candidate in value_matches if candidate.path.startswith(section_prefix)
            ]
            if len(section_matches) == 1:
                return section_matches[0]
        if len(value_matches) == 1:
            return value_matches[0]

    if evidence.normalized_value is not None:
        normalized_matches = evidence_by_tool_normalized.get(
            (evidence.tool, _freeze_value(evidence.normalized_value)),
            [],
        )
        if len(normalized_matches) == 1:
            return normalized_matches[0]

        path_normalized_matches = evidence_by_path_normalized.get(
            (evidence.path, _freeze_value(evidence.normalized_value)),
            [],
        )
        if len(path_normalized_matches) == 1:
            return path_normalized_matches[0]

        normalized_value_matches = evidence_by_normalized.get(
            _freeze_value(evidence.normalized_value),
            [],
        )
        if len(normalized_value_matches) == 1:
            return normalized_value_matches[0]

    return evidence


def _iter_metadata_evidence(key_metadata: KeyMetadata) -> Iterable[EvidenceReference]:
    for field_name in (
        "hostname",
        "user",
        "process_name",
        "process_path",
        "severity",
        "classification",
        "first_seen",
        "last_seen",
        "action",
    ):
        field_value = getattr(key_metadata, field_name)
        yield from field_value.evidence
    yield from key_metadata.hashes.evidence


def _iter_result_evidence(result: IncidentAnalysisResult) -> Iterable[EvidenceReference]:
    yield from _iter_metadata_evidence(result.key_metadata)
    for fact in result.observed_facts:
        yield from fact.evidence


def canonicalize_analysis_result_evidence(
    analysis_input: IncidentAnalysisInput,
    result: IncidentAnalysisResult,
) -> IncidentAnalysisResult:
    evidence_candidates = _build_validation_evidence_candidates(analysis_input)
    evidence_by_id = {
        evidence.evidence_id: evidence
        for evidence in evidence_candidates
        if evidence.evidence_id
    }
    evidence_by_tuple = {
        (evidence.tool, evidence.path, _freeze_value(evidence.value)): evidence
        for evidence in evidence_candidates
    }
    evidence_by_tool_value: dict[tuple[str, str], list[EvidenceReference]] = {}
    evidence_by_path_value: dict[tuple[str, str], list[EvidenceReference]] = {}
    evidence_by_value: dict[str, list[EvidenceReference]] = {}
    evidence_by_tool_normalized: dict[tuple[str, str], list[EvidenceReference]] = {}
    evidence_by_path_normalized: dict[tuple[str, str], list[EvidenceReference]] = {}
    evidence_by_normalized: dict[str, list[EvidenceReference]] = {}

    for evidence in evidence_candidates:
        frozen_value = _freeze_value(evidence.value)
        tool_value_key = (evidence.tool, frozen_value)
        evidence_by_tool_value.setdefault(tool_value_key, []).append(evidence)
        path_value_key = (evidence.path, frozen_value)
        evidence_by_path_value.setdefault(path_value_key, []).append(evidence)
        evidence_by_value.setdefault(frozen_value, []).append(evidence)
        if evidence.normalized_value is not None:
            frozen_normalized = _freeze_value(evidence.normalized_value)
            normalized_key = (evidence.tool, frozen_normalized)
            evidence_by_tool_normalized.setdefault(normalized_key, []).append(evidence)
            path_normalized_key = (evidence.path, frozen_normalized)
            evidence_by_path_normalized.setdefault(path_normalized_key, []).append(evidence)
            evidence_by_normalized.setdefault(frozen_normalized, []).append(evidence)

    def canonicalize_items(items: list[EvidenceReference]) -> list[EvidenceReference]:
        return [
            _canonicalize_evidence_reference(
                evidence,
                evidence_by_id=evidence_by_id,
                evidence_by_tuple=evidence_by_tuple,
                evidence_by_tool_value=evidence_by_tool_value,
                evidence_by_path_value=evidence_by_path_value,
                evidence_by_value=evidence_by_value,
                evidence_by_tool_normalized=evidence_by_tool_normalized,
                evidence_by_path_normalized=evidence_by_path_normalized,
                evidence_by_normalized=evidence_by_normalized,
                evidence_candidates=evidence_candidates,
            )
            for evidence in items
        ]

    for field_name in (
        "hostname",
        "user",
        "process_name",
        "process_path",
        "severity",
        "classification",
        "first_seen",
        "last_seen",
        "action",
    ):
        field_value = getattr(result.key_metadata, field_name)
        field_value.evidence = canonicalize_items(field_value.evidence)

    result.key_metadata.hashes.evidence = canonicalize_items(result.key_metadata.hashes.evidence)

    for fact in result.observed_facts:
        fact.evidence = canonicalize_items(fact.evidence)

    return result


def validate_analysis_result_evidence(
    analysis_input: IncidentAnalysisInput,
    result: IncidentAnalysisResult,
) -> None:
    evidence_candidates = _build_validation_evidence_candidates(analysis_input)
    evidence_by_id = {
        evidence.evidence_id: evidence
        for evidence in evidence_candidates
        if evidence.evidence_id
    }
    evidence_by_tuple = {
        (evidence.tool, evidence.path, _freeze_value(evidence.value)): evidence
        for evidence in evidence_candidates
    }

    for evidence in _iter_result_evidence(result):
        if evidence.evidence_id and evidence.evidence_id in evidence_by_id:
            source = evidence_by_id[evidence.evidence_id]
            if source.tool != evidence.tool or source.path != evidence.path:
                raise FortiEDRValidationError(
                    f"Evidence {evidence.evidence_id} does not match the registered tool/path."
                )
            continue

        key = (evidence.tool, evidence.path, _freeze_value(evidence.value))
        if key not in evidence_by_tuple:
            raise FortiEDRValidationError(
                f"Evidence reference {evidence.tool}:{evidence.path} is not present in the input catalog."
            )
