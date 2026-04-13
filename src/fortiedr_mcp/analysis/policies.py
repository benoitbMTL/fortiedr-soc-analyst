from __future__ import annotations

import json
import os
import re
from dataclasses import dataclass
from functools import lru_cache
from importlib.resources import files
from pathlib import Path


@dataclass(frozen=True)
class PolicyRuleDescription:
    policy_name: str
    rule_name: str
    rule_details: str
    rule_subtitle: str | None = None
    forensics_recommendations: str | None = None


def _default_policy_file() -> Path:
    override = os.getenv("FORTIEDR_POLICY_DESCRIPTIONS_PATH")
    if override:
        return Path(override)
    return Path(str(files("fortiedr_mcp").joinpath("data/fortiedr_security_policies.json")))


def _normalize_lookup(value: str | None) -> str:
    candidate = str(value or "").strip()
    candidate = re.sub(r"^[A-Z]{2,6}\s*-\s*", "", candidate)
    candidate = re.sub(r"\s+", " ", candidate)
    return candidate.casefold()


def _split_rule_title(value: str | None) -> tuple[str, str | None]:
    candidate = str(value or "").strip()
    parts = re.split(r"\s*-\s*", candidate, maxsplit=1)
    if len(parts) == 2:
        return parts[0].strip(), parts[1].strip() or None
    return candidate, None


@lru_cache(maxsize=1)
def load_policy_rule_descriptions() -> tuple[PolicyRuleDescription, ...]:
    path = _default_policy_file()
    if not path.exists():
        return ()

    if path.suffix.lower() == ".json":
        payload = json.loads(path.read_text(encoding="utf-8"))
        return tuple(
            PolicyRuleDescription(
                policy_name=entry["policy_name"],
                rule_name=entry["rule_name"],
                rule_subtitle=entry.get("rule_subtitle"),
                rule_details=entry["rule_details"],
                forensics_recommendations=entry.get("forensics_recommendations"),
            )
            for entry in payload.get("rules", [])
        )

    lines = [line.rstrip() for line in path.read_text(encoding="utf-8").splitlines()]
    entries: list[PolicyRuleDescription] = []
    current_policy: str | None = None
    current_rule: str | None = None
    current_details: list[str] = []
    current_recommendations: list[str] = []
    mode: str | None = None

    def flush_rule() -> None:
        nonlocal current_rule, current_details, current_recommendations, mode
        if not current_policy or not current_rule:
            current_rule = None
            current_details = []
            current_recommendations = []
            mode = None
            return
        entries.append(
            PolicyRuleDescription(
                policy_name=current_policy,
                rule_name=_split_rule_title(current_rule)[0],
                rule_subtitle=_split_rule_title(current_rule)[1],
                rule_details=" ".join(part.strip() for part in current_details if part.strip()),
                forensics_recommendations=(
                    " ".join(part.strip() for part in current_recommendations if part.strip()) or None
                ),
            )
        )
        current_rule = None
        current_details = []
        current_recommendations = []
        mode = None

    for raw_line in lines:
        line = raw_line.strip()
        if not line:
            continue
        if line == "---":
            continue
        if line.startswith("POLICY NAME:"):
            flush_rule()
            current_policy = line.split(":", 1)[1].strip()
            continue
        if line.startswith("Rule Name:"):
            flush_rule()
            current_rule = line.split(":", 1)[1].strip()
            continue
        if line == "Rule Details":
            mode = "details"
            continue
        if line == "Forensics Recommendations":
            mode = "recommendations"
            continue
        if mode == "details":
            current_details.append(line)
        elif mode == "recommendations":
            current_recommendations.append(line)

    flush_rule()
    return tuple(entries)


@lru_cache(maxsize=1)
def _policy_rule_indexes() -> tuple[dict[str, PolicyRuleDescription], set[str]]:
    by_rule_name: dict[str, PolicyRuleDescription] = {}
    policy_names: set[str] = set()
    for entry in load_policy_rule_descriptions():
        by_rule_name.setdefault(_normalize_lookup(entry.rule_name), entry)
        policy_names.add(_normalize_lookup(entry.policy_name))
    return by_rule_name, policy_names


def match_rule_descriptions(rule_candidates: list[str], *, limit: int = 3) -> list[PolicyRuleDescription]:
    by_rule_name, policy_names = _policy_rule_indexes()
    matched: list[PolicyRuleDescription] = []
    seen: set[str] = set()

    for candidate in rule_candidates:
        normalized = _normalize_lookup(candidate)
        if not normalized or normalized in policy_names:
            continue
        entry = by_rule_name.get(normalized)
        if not entry:
            continue
        dedupe_key = _normalize_lookup(entry.rule_name)
        if dedupe_key in seen:
            continue
        seen.add(dedupe_key)
        matched.append(entry)
        if len(matched) >= limit:
            break
    return matched
