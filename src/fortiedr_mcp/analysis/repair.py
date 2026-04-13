from __future__ import annotations

from copy import deepcopy
from typing import Any


_MISSING_INFO_MARKERS = (
    "unavailable",
    "not available",
    "missing",
    "no hash",
    "no hashes",
    "no related events",
    "not present",
    "not provided",
)
_KEY_METADATA_FIELDS = (
    "hostname",
    "user",
    "process_name",
    "process_path",
    "severity",
    "classification",
    "first_seen",
    "last_seen",
    "action",
)


def _append_missing_information(missing_information: list[Any], statement: str) -> None:
    if statement not in missing_information:
        missing_information.append(statement)


def _normalize_evidence_backed_value(
    key_metadata: dict[str, Any],
    field_name: str,
    *,
    missing_information: list[Any],
) -> None:
    field_value = key_metadata.get(field_name)

    if field_value is None:
        key_metadata[field_name] = {"value": None, "evidence": []}
        return

    if not isinstance(field_value, dict):
        field_value = {"value": field_value}
        key_metadata[field_name] = field_value

    evidence = field_value.get("evidence")
    if not isinstance(evidence, list):
        evidence = []
    field_value["evidence"] = evidence

    if field_value.get("value") is not None and not evidence:
        _append_missing_information(
            missing_information,
            f"Evidence was missing for key metadata field '{field_name}', so the value was cleared during repair.",
        )
        field_value["value"] = None


def _normalize_hash_metadata(
    key_metadata: dict[str, Any],
    *,
    missing_information: list[Any],
) -> None:
    hashes = key_metadata.get("hashes")

    if hashes is None:
        key_metadata["hashes"] = {"md5": None, "sha1": None, "sha256": None, "evidence": []}
        return

    if not isinstance(hashes, dict):
        hashes = {"md5": None, "sha1": None, "sha256": None, "evidence": []}
        key_metadata["hashes"] = hashes

    evidence = hashes.get("evidence")
    if not isinstance(evidence, list):
        evidence = []
    hashes["evidence"] = evidence

    present_hash_fields = [field_name for field_name in ("md5", "sha1", "sha256") if hashes.get(field_name)]
    for field_name in ("md5", "sha1", "sha256"):
        hashes.setdefault(field_name, None)

    if present_hash_fields and not evidence:
        _append_missing_information(
            missing_information,
            "Hash values were returned without evidence, so they were cleared during repair.",
        )
        for field_name in present_hash_fields:
            hashes[field_name] = None


def _normalize_key_metadata(
    repaired: dict[str, Any],
    *,
    missing_information: list[Any],
) -> None:
    key_metadata = repaired.get("key_metadata")
    if not isinstance(key_metadata, dict):
        key_metadata = {}
        repaired["key_metadata"] = key_metadata

    for field_name in _KEY_METADATA_FIELDS:
        _normalize_evidence_backed_value(
            key_metadata,
            field_name,
            missing_information=missing_information,
        )

    _normalize_hash_metadata(
        key_metadata,
        missing_information=missing_information,
    )


def _normalize_recommended_next_steps(repaired: dict[str, Any]) -> None:
    next_steps = repaired.get("recommended_next_steps")
    if not isinstance(next_steps, dict):
        next_steps = {}
        repaired["recommended_next_steps"] = next_steps

    for field_name in ("immediate", "short_term", "validation"):
        field_value = next_steps.get(field_name)
        if isinstance(field_value, list):
            continue
        if field_value is None:
            next_steps[field_name] = []
        else:
            next_steps[field_name] = [str(field_value)]


def _looks_like_missing_information(statement: str) -> bool:
    normalized = statement.strip().lower()
    return any(marker in normalized for marker in _MISSING_INFO_MARKERS)


def repair_incident_analysis_output(
    payload: dict[str, Any],
    *,
    skill_version: str,
    incident_id: str | None = None,
) -> dict[str, Any]:
    repaired = deepcopy(payload)
    repaired.setdefault("skill_version", skill_version)

    payload_incident_id = repaired.get("incident_id")
    if payload_incident_id is not None:
        repaired["incident_id"] = str(payload_incident_id)

    missing_information = repaired.get("missing_information")
    if not isinstance(missing_information, list):
        missing_information = []
        repaired["missing_information"] = missing_information

    _normalize_key_metadata(
        repaired,
        missing_information=missing_information,
    )
    _normalize_recommended_next_steps(repaired)
    repaired.setdefault("observed_facts", [])
    repaired.setdefault("investigation_notes", [])
    repaired.setdefault("hypotheses", [])
    if incident_id:
        repaired.setdefault("incident_id", incident_id)

    observed_facts = repaired.get("observed_facts")
    if isinstance(observed_facts, list):
        retained_facts: list[Any] = []
        for fact in observed_facts:
            if not isinstance(fact, dict):
                retained_facts.append(fact)
                continue

            evidence = fact.get("evidence")
            statement = fact.get("statement")
            if (
                isinstance(statement, str)
                and isinstance(evidence, list)
                and len(evidence) == 0
                and _looks_like_missing_information(statement)
            ):
                if statement not in missing_information:
                    missing_information.append(statement)
                continue

            retained_facts.append(fact)
        repaired["observed_facts"] = retained_facts

    return repaired
