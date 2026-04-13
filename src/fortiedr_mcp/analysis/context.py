from __future__ import annotations

from collections.abc import Callable
from typing import Any, Literal

from pydantic import BaseModel, Field

from fortiedr_mcp.analysis.policies import match_rule_descriptions
from fortiedr_mcp.analysis.profiles import get_analysis_profile
from fortiedr_mcp.analysis.models import (
    EvidenceBackedValue,
    EvidenceReference,
    HashMetadata,
    KeyMetadata,
)
from fortiedr_mcp.models import IncidentDetailsResult

_INTERESTING_COMMAND_PROCESSES = {
    "cmd.exe",
    "powershell.exe",
    "pwsh.exe",
    "wscript.exe",
    "cscript.exe",
    "mshta.exe",
    "rundll32.exe",
    "wmic.exe",
    "python.exe",
    "pythonw.exe",
    "regsvr32.exe",
}
_BROWSER_PROCESSES = {"chrome.exe", "msedge.exe", "iexplore.exe", "firefox.exe", "brave.exe", "opera.exe"}
_SHELL_PARENT_PROCESSES = {"cmd.exe", "powershell.exe", "pwsh.exe", "explorer.exe"}
_OFFICE_PROCESSES = {"winword.exe", "excel.exe", "powerpnt.exe", "outlook.exe"}


def _iter_nested_values(value: Any, *, path: str) -> list[tuple[str, str, Any]]:
    items: list[tuple[str, str, Any]] = []
    if isinstance(value, dict):
        for key, nested in value.items():
            nested_path = f"{path}.{key}" if path else key
            items.append((nested_path, str(key), nested))
            items.extend(_iter_nested_values(nested, path=nested_path))
    elif isinstance(value, list):
        for index, nested in enumerate(value):
            nested_path = f"{path}[{index}]"
            items.append((nested_path, str(index), nested))
            items.extend(_iter_nested_values(nested, path=nested_path))
    return items


def _strip_text(value: Any) -> str | None:
    if isinstance(value, str):
        candidate = value.strip()
        return candidate or None
    return None


def _basename(path: str | None) -> str | None:
    candidate = _strip_text(path)
    if not candidate:
        return None
    normalized = candidate.rstrip("\\/")
    for separator in ("\\", "/"):
        if separator in normalized:
            normalized = normalized.rsplit(separator, 1)[-1]
    return normalized or None


def _unique_strings(values: list[str]) -> list[str]:
    seen: set[str] = set()
    unique: list[str] = []
    for value in values:
        candidate = _strip_text(value)
        if not candidate:
            continue
        key = candidate.casefold()
        if key in seen:
            continue
        seen.add(key)
        unique.append(candidate)
    return unique


def _truncate_text(value: str | None, *, max_chars: int) -> str | None:
    candidate = _strip_text(value)
    if not candidate or max_chars <= 0:
        return candidate
    if len(candidate) <= max_chars:
        return candidate
    return f"{candidate[: max_chars - 1].rstrip()}…"


def _compact_mapping(value: dict[str, Any], allowed_fields: tuple[str, ...]) -> dict[str, Any]:
    return {field: value.get(field) for field in allowed_fields if value.get(field) not in (None, "", [], {})}


def _compact_additional_info(value: Any, *, max_items: int) -> list[dict[str, Any]]:
    if not isinstance(value, list):
        return []
    compacted: list[dict[str, Any]] = []
    for entry in value[:max_items]:
        if not isinstance(entry, dict):
            continue
        compact = _compact_mapping(
            entry,
            (
                "ProcessOwner",
                "CommandLine",
                "FileHashMD5",
                "FileHashSHA1",
                "FileHashSHA2",
                "BaseAddress",
                "EndAddress",
            ),
        )
        if compact:
            compacted.append(compact)
    return compacted


def _compact_alerts(value: Any, *, max_items: int) -> list[dict[str, Any]]:
    if not isinstance(value, list):
        return []
    compacted: list[dict[str, Any]] = []
    for alert in value[:max_items]:
        if not isinstance(alert, dict):
            continue
        compact = _compact_mapping(
            alert,
            (
                "Policy",
                "Description",
                "Severity",
            ),
        )
        main_app = alert.get("MainApp")
        if isinstance(main_app, dict):
            compact_main_app = _compact_mapping(
                main_app,
                (
                    "Executable",
                    "CommandLine",
                ),
            )
            if compact_main_app:
                compact["MainApp"] = compact_main_app
        if compact:
            compacted.append(compact)
    return compacted


def _compact_stack_infos(value: Any, *, max_items: int, max_additional_info: int) -> list[dict[str, Any]]:
    if not isinstance(value, list):
        return []
    compacted: list[dict[str, Any]] = []
    for stack_info in value[:max_items]:
        if not isinstance(stack_info, dict):
            continue
        compact = _compact_mapping(
            stack_info,
            (
                "ProcessName",
                "ImageBase",
                "ImageEnd",
                "IsExecutable",
            ),
        )
        additional_info = _compact_additional_info(
            stack_info.get("CommonAdditionalInfo"),
            max_items=max_additional_info,
        )
        if additional_info:
            compact["CommonAdditionalInfo"] = additional_info
        if compact:
            compacted.append(compact)
    return compacted


def _compact_app_details(value: Any) -> dict[str, Any] | None:
    if not isinstance(value, dict):
        return None
    compact = _compact_mapping(
        value,
        (
            "Executable",
            "CommandLine",
            "FileHashMD5",
            "FileHashSHA1",
            "FileHashSHA2",
            "Publisher",
            "Signer",
        ),
    )
    return compact or None


def _compact_raw_data_item(raw_item: dict[str, Any], *, analysis_profile: str) -> dict[str, Any]:
    profile = get_analysis_profile(analysis_profile)
    compact = _compact_mapping(
        raw_item,
        (
            "EventId",
            "EventType",
            "FirstSeen",
            "LastSeen",
            "Count",
            "HostName",
            "device",
            "destination",
            "LoggedUsers",
            "Application",
            "AppVendor",
            "OperatingSystem",
            "EventClassification",
            "EventClassificationStage",
            "AppSourceAlert",
        ),
    )

    app_details = _compact_app_details(raw_item.get("AppDetails"))
    if app_details:
        compact["AppDetails"] = app_details

    alerts = _compact_alerts(
        raw_item.get("Alerts"),
        max_items=2 if profile.name == "lite" else 4,
    )
    if alerts:
        compact["Alerts"] = alerts

    if profile.name != "lite":
        stack_infos = _compact_stack_infos(
            raw_item.get("StackInfos"),
            max_items=4 if profile.name == "standard" else 10,
            max_additional_info=1 if profile.name == "standard" else 3,
        )
        if stack_infos:
            compact["StackInfos"] = stack_infos

    return compact


def _coerce_logged_users(value: Any) -> list[str]:
    users: list[str] = []
    if isinstance(value, list):
        for item in value:
            if isinstance(item, str):
                users.append(item)
                continue
            if isinstance(item, dict):
                name = _strip_text(item.get("Name") or item.get("name"))
                if name:
                    users.append(name)
    return _unique_strings(users)


def _looks_like_process(process_name: str | None, process_path: str | None) -> bool:
    name = _strip_text(process_name)
    if not name:
        return False
    if "." in name:
        return True
    path = _strip_text(process_path)
    if path and ("\\" in path or "/" in path):
        return True
    return False


def _path_matches(left: str | None, right: str | None) -> bool:
    if not left or not right:
        return False
    return left.casefold() == right.casefold()


def _normalize_command_line(
    process_name: str | None,
    command_line: str | None,
    *,
    process_path: str | None = None,
) -> str | None:
    candidate = _strip_text(command_line)
    if not candidate:
        return None
    normalized_name = (process_name or "").casefold()
    if normalized_name in _INTERESTING_COMMAND_PROCESSES:
        return candidate
    if process_path and candidate.casefold() == process_path.casefold():
        return None
    if any(marker in candidate.casefold() for marker in (" /c", " -", ".ps1", ".bat", ".vbs", ".js", "http://", "https://")):
        return candidate
    return None


class ProcessStackEntry(BaseModel):
    process_name: str
    process_path: str | None = None
    process_owner: str | None = None
    command_line: str | None = None
    highlighted: bool = False


class CommandLineContext(BaseModel):
    process_name: str
    command_line: str


class ForensicsSummary(BaseModel):
    selected_count: int = 0
    certificate_status: str | None = None
    process_owner: str | None = None
    host_state: str | None = None
    handling_tooltip: str | None = None
    destinations: list[str] = Field(default_factory=list)
    process_script_module: str | None = None
    process_script_module_path: str | None = None


class RuleDescriptionContext(BaseModel):
    policy_name: str
    rule_name: str
    rule_subtitle: str | None = None
    rule_details: str
    forensics_recommendations: str | None = None
    source: str = "FortiEDR_Security_Policies.txt"


class DerivedIncidentContext(BaseModel):
    matched_rules: list[str] = Field(default_factory=list)
    violated_policies: list[str] = Field(default_factory=list)
    matched_rule_descriptions: list[RuleDescriptionContext] = Field(default_factory=list)
    process_stack: list[ProcessStackEntry] = Field(default_factory=list)
    relevant_command_lines: list[CommandLineContext] = Field(default_factory=list)
    launch_context_clues: list[str] = Field(default_factory=list)
    forensics_summary: ForensicsSummary | None = None


class IncidentAnalysisInput(BaseModel):
    skill_version: Literal["incident_senior_soc_v1"]
    incident_id: str
    key_metadata_candidates: KeyMetadata
    incident_snapshot: dict[str, Any]
    derived_context: DerivedIncidentContext = Field(default_factory=DerivedIncidentContext)
    raw_data_items: list[dict[str, Any]] = Field(default_factory=list)
    host_context: dict[str, Any] | None = None
    related_events: dict[str, Any] | None = None
    evidence_catalog: list[EvidenceReference] = Field(default_factory=list)
    missing_source_data: list[str] = Field(default_factory=list)


class IncidentAnalysisInputBuilder:
    """Builds auditable skill input from the incident data service outputs."""

    def _build_derived_context(
        self,
        details: IncidentDetailsResult,
        *,
        analysis_profile: str = "standard",
        add_evidence: Callable[[str, str, Any], EvidenceReference | None] | None = None,
    ) -> DerivedIncidentContext:
        profile = get_analysis_profile(analysis_profile)
        incident = details.incident
        raw_data_items = details.raw_data_items[: profile.raw_data_limit]
        if profile.name == "full":
            prompt_raw_data_items = raw_data_items
        else:
            prompt_raw_data_items = [
                _compact_raw_data_item(raw_item, analysis_profile=profile.name)
                for raw_item in raw_data_items
            ]

        matched_rules = _unique_strings([str(item) for item in incident.rules if item])
        if add_evidence and matched_rules:
            add_evidence("get_incident_details", "incident.rules", matched_rules)
        matched_rule_descriptions = [
            RuleDescriptionContext(
                policy_name=entry.policy_name,
                rule_name=entry.rule_name,
                rule_subtitle=entry.rule_subtitle,
                rule_details=_truncate_text(
                    entry.rule_details,
                    max_chars=profile.max_forensics_detail_chars,
                )
                or entry.rule_details,
                forensics_recommendations=_truncate_text(
                    entry.forensics_recommendations,
                    max_chars=profile.max_forensics_detail_chars,
                ),
            )
            for entry in match_rule_descriptions(
                matched_rules,
                limit=profile.max_rule_descriptions,
            )
        ]

        violated_policies: list[str] = []
        process_stack: list[ProcessStackEntry] = []
        relevant_command_lines: list[CommandLineContext] = []
        launch_context_clues: list[str] = []

        seen_command_lines: set[tuple[str, str]] = set()

        def add_command_line(
            process_name: str | None,
            command_line: str | None,
            *,
            process_path: str | None = None,
            tool: str,
            path: str,
        ) -> None:
            normalized_command_line = _normalize_command_line(
                process_name,
                command_line,
                process_path=process_path,
            )
            normalized_process = _basename(process_path) or _strip_text(process_name)
            if not normalized_command_line or not normalized_process:
                return
            dedupe_key = (normalized_process.casefold(), normalized_command_line)
            if dedupe_key in seen_command_lines:
                return
            seen_command_lines.add(dedupe_key)
            relevant_command_lines.append(
                CommandLineContext(
                    process_name=normalized_process,
                    command_line=normalized_command_line,
                )
            )
            if add_evidence:
                add_evidence(tool, path, normalized_command_line)

        for raw_index, raw_item in enumerate(raw_data_items):
            alerts = raw_item.get("Alerts")
            if isinstance(alerts, list):
                for alert_index, alert in enumerate(alerts):
                    if not isinstance(alert, dict):
                        continue
                    policy = _strip_text(alert.get("Policy"))
                    if policy:
                        violated_policies.append(policy)
                        if add_evidence:
                            add_evidence(
                                "get_incident_details",
                                f"raw_data_items[{raw_index}].Alerts[{alert_index}].Policy",
                                policy,
                            )

                    main_app = alert.get("MainApp")
                    if isinstance(main_app, dict):
                        executable = _strip_text(main_app.get("Executable"))
                        add_command_line(
                            _basename(executable) or incident.process,
                            main_app.get("CommandLine"),
                            process_path=executable,
                            tool="get_incident_details",
                            path=f"raw_data_items[{raw_index}].Alerts[{alert_index}].MainApp.CommandLine",
                        )

            app_details = raw_item.get("AppDetails")
            if isinstance(app_details, dict):
                executable = _strip_text(app_details.get("Executable")) or incident.process_path
                add_command_line(
                    _basename(executable) or incident.process,
                    app_details.get("CommandLine"),
                    process_path=executable,
                    tool="get_incident_details",
                    path=f"raw_data_items[{raw_index}].AppDetails.CommandLine",
                )

            stack_infos = raw_item.get("StackInfos")
            if process_stack or not isinstance(stack_infos, list):
                continue

            child_first_entries: list[ProcessStackEntry] = []
            seen_stack_entries: set[tuple[str | None, str]] = set()

            for stack_index, stack_info in enumerate(stack_infos):
                if not isinstance(stack_info, dict):
                    continue

                process_path = _strip_text(stack_info.get("ProcessName"))
                process_name = _basename(process_path)
                if not _looks_like_process(process_name, process_path):
                    continue

                process_owner = None
                stack_command_line = None
                process_owner_path = None
                additional_info = stack_info.get("CommonAdditionalInfo")
                if isinstance(additional_info, list):
                    for info_index, info in enumerate(additional_info):
                        if not isinstance(info, dict):
                            continue
                        if process_owner is None:
                            process_owner = _strip_text(info.get("ProcessOwner"))
                            if process_owner:
                                process_owner_path = (
                                    f"raw_data_items[{raw_index}].StackInfos[{stack_index}]."
                                    f"CommonAdditionalInfo[{info_index}].ProcessOwner"
                                )
                        if stack_command_line is None:
                            stack_command_line = _strip_text(info.get("CommandLine"))
                        if add_evidence and _strip_text(info.get("CommandLine")):
                            add_evidence(
                                "get_incident_details",
                                f"raw_data_items[{raw_index}].StackInfos[{stack_index}].CommonAdditionalInfo[{info_index}].CommandLine",
                                _strip_text(info.get("CommandLine")),
                            )

                dedupe_key = ((process_path or "").casefold() or None, process_name.casefold())
                if dedupe_key in seen_stack_entries:
                    continue
                seen_stack_entries.add(dedupe_key)

                if add_evidence:
                    add_evidence(
                        "get_incident_details",
                        f"raw_data_items[{raw_index}].StackInfos[{stack_index}].ProcessName",
                        process_path,
                    )
                    if process_owner:
                        add_evidence(
                            "get_incident_details",
                            process_owner_path
                            or f"raw_data_items[{raw_index}].StackInfos[{stack_index}].ProcessOwner",
                            process_owner,
                        )

                child_first_entries.append(
                    ProcessStackEntry(
                        process_name=process_name,
                        process_path=process_path,
                        process_owner=process_owner,
                        command_line=_normalize_command_line(
                            process_name,
                            stack_command_line,
                            process_path=process_path,
                        ),
                    )
                )

            if child_first_entries:
                process_stack = list(reversed(child_first_entries))
                highlight_index = len(process_stack) - 1
                for index, entry in enumerate(process_stack):
                    if _path_matches(entry.process_path, incident.process_path) or (
                        incident.process and entry.process_name.casefold() == incident.process.casefold()
                    ):
                        highlight_index = index
                process_stack[highlight_index].highlighted = True

                for entry in process_stack:
                    if entry.command_line:
                        dedupe_key = (entry.process_name.casefold(), entry.command_line)
                        if dedupe_key not in seen_command_lines:
                            relevant_command_lines.append(
                                CommandLineContext(
                                    process_name=entry.process_name,
                                    command_line=entry.command_line,
                                )
                            )
                            seen_command_lines.add(dedupe_key)

                if highlight_index > 0:
                    parent_name = process_stack[highlight_index - 1].process_name.casefold()
                    if parent_name in _BROWSER_PROCESSES:
                        launch_context_clues.append(
                            f"Process stack indicates the highlighted process was launched from {process_stack[highlight_index - 1].process_name}."
                        )
                    elif parent_name == "explorer.exe":
                        launch_context_clues.append(
                            "Process stack indicates the highlighted process was launched from Windows Explorer."
                        )
                    elif parent_name in _SHELL_PARENT_PROCESSES:
                        launch_context_clues.append(
                            f"Process stack indicates the highlighted process was launched by {process_stack[highlight_index - 1].process_name}."
                        )
                    elif parent_name in _OFFICE_PROCESSES:
                        launch_context_clues.append(
                            f"Process stack indicates the highlighted process was launched from Microsoft Office via {process_stack[highlight_index - 1].process_name}."
                        )

        process_path = _strip_text(incident.process_path)
        if process_path and "\\downloads\\" in process_path.casefold():
            launch_context_clues.append("Incident process path points to a Downloads directory.")
        if process_path and "\\desktop\\" in process_path.casefold():
            launch_context_clues.append("Incident process path points to a Desktop location.")
        if process_path and (
            process_path.casefold().startswith("\\\\")
            or "\\device\\mup\\" in process_path.casefold()
            or "\\device\\lanmanredirector\\" in process_path.casefold()
        ):
            launch_context_clues.append("Incident process path suggests execution from a network share.")

        forensics_summary = None
        if profile.include_forensics and details.forensics_events and details.forensics_events.selected_events:
            primary_event = details.forensics_events.selected_events[0]
            forensics_summary = ForensicsSummary(
                selected_count=details.forensics_events.selected_count,
                certificate_status=primary_event.certificate_status,
                process_owner=primary_event.process_owner,
                host_state=primary_event.host_state,
                handling_tooltip=_truncate_text(
                    primary_event.handling_tooltip,
                    max_chars=profile.max_forensics_detail_chars,
                ),
                destinations=primary_event.destinations,
                process_script_module=primary_event.process_script_module,
                process_script_module_path=primary_event.process_script_module_path,
            )
            if add_evidence:
                if primary_event.certificate_status:
                    add_evidence(
                        "get_forensics_events",
                        "forensics_events.selected_events[0].certificate_status",
                        primary_event.certificate_status,
                    )
                if primary_event.process_owner:
                    add_evidence(
                        "get_forensics_events",
                        "forensics_events.selected_events[0].process_owner",
                        primary_event.process_owner,
                    )
                if primary_event.host_state:
                    add_evidence(
                        "get_forensics_events",
                        "forensics_events.selected_events[0].host_state",
                        primary_event.host_state,
                    )
                if primary_event.destinations:
                    add_evidence(
                        "get_forensics_events",
                        "forensics_events.selected_events[0].destinations",
                        primary_event.destinations,
                    )
                if primary_event.process_script_module:
                    add_evidence(
                        "get_forensics_events",
                        "forensics_events.selected_events[0].process_script_module",
                        primary_event.process_script_module,
                    )
                if primary_event.process_script_module_path:
                    add_evidence(
                        "get_forensics_events",
                        "forensics_events.selected_events[0].process_script_module_path",
                        primary_event.process_script_module_path,
                    )

            if primary_event.process_script_module:
                launch_context_clues.append(
                    f"Forensics identified script/module context: {primary_event.process_script_module}."
                )
            if primary_event.destinations:
                launch_context_clues.append(
                    f"Forensics context: {primary_event.destinations[0]}."
                )

        return DerivedIncidentContext(
            matched_rules=_unique_strings(matched_rules),
            violated_policies=_unique_strings(violated_policies),
            matched_rule_descriptions=matched_rule_descriptions,
            process_stack=process_stack,
            relevant_command_lines=relevant_command_lines,
            launch_context_clues=_unique_strings(launch_context_clues),
            forensics_summary=forensics_summary,
        )

    def build_derived_context(
        self,
        details: IncidentDetailsResult,
        *,
        analysis_profile: str = "standard",
    ) -> DerivedIncidentContext:
        return self._build_derived_context(details, analysis_profile=analysis_profile)

    def build(
        self,
        details: IncidentDetailsResult,
        *,
        analysis_profile: str = "standard",
    ) -> IncidentAnalysisInput:
        profile = get_analysis_profile(analysis_profile)
        evidence_catalog: list[EvidenceReference] = []
        evidence_index = 0

        def add_evidence(
            tool: str,
            path: str,
            value: Any,
            *,
            normalized_value: Any | None = None,
        ) -> EvidenceReference:
            nonlocal evidence_index
            evidence_index += 1
            evidence = EvidenceReference(
                evidence_id=f"e{evidence_index}",
                tool=tool,
                path=path,
                value=value,
                normalized_value=normalized_value,
            )
            evidence_catalog.append(evidence)
            return evidence

        def extract_hash_metadata(raw_items: list[dict[str, Any]]) -> HashMetadata:
            hashes: dict[str, str | None] = {"md5": None, "sha1": None, "sha256": None}
            hash_evidence: list[EvidenceReference] = []
            field_map = {
                "filehashmd5": "md5",
                "filehashsha1": "sha1",
                "filehashsha2": "sha256",
                "filehashsha256": "sha256",
            }

            for index, raw_item in enumerate(raw_items):
                nested_items = _iter_nested_values(raw_item, path=f"raw_data_items[{index}]")
                for nested_path, key, nested_value in nested_items:
                    if not isinstance(nested_value, str):
                        continue
                    hash_field = field_map.get(key.lower())
                    if hash_field is None:
                        continue
                    if "codesigning" in nested_path.lower():
                        continue
                    if hashes[hash_field] is not None:
                        continue
                    hashes[hash_field] = nested_value
                    hash_evidence.append(
                        add_evidence(
                            "get_incident_details",
                            nested_path,
                            nested_value,
                        )
                    )

            return HashMetadata(
                md5=hashes["md5"],
                sha1=hashes["sha1"],
                sha256=hashes["sha256"],
                evidence=hash_evidence,
            )

        incident = details.incident
        missing_source_data: list[str] = []

        incident_evidence: dict[str, list[EvidenceReference]] = {}
        incident_values = {
            "incident_id": incident.incident_id,
            "process": incident.process,
            "process_path": incident.process_path,
            "process_type": incident.process_type,
            "logged_user": incident.logged_user,
            "process_owner": incident.process_owner,
            "severity": incident.severity,
            "classification": incident.classification,
            "handling_state": incident.handling_state,
            "action": incident.action,
            "first_seen": incident.first_seen,
            "last_seen": incident.last_seen,
            "organization": incident.organization,
            "seen": incident.seen,
            "archived": incident.archived,
            "muted": incident.muted,
            "threat_name": incident.threat_name,
            "threat_family": incident.threat_family,
            "destinations": incident.destinations,
            "rules": incident.rules,
        }
        for path_suffix, value in incident_values.items():
            if value is None or value == []:
                continue
            incident_evidence[path_suffix] = [
                add_evidence("get_incident_details", f"incident.{path_suffix}", value)
            ]

        host_value = incident.host
        host_evidence: list[EvidenceReference] = []
        if host_value:
            host_evidence.append(
                add_evidence(
                    "get_incident_details",
                    "incident.host",
                    host_value,
                )
            )

        raw_data_items = details.raw_data_items[: profile.raw_data_limit]
        if profile.name == "full":
            prompt_raw_data_items = raw_data_items
        else:
            prompt_raw_data_items = [
                _compact_raw_data_item(raw_item, analysis_profile=profile.name)
                for raw_item in raw_data_items
            ]
        for index, raw_item in enumerate(raw_data_items):
            for field in ("device", "deviceIp", "destination", "firstSeen", "lastSeen", "count", "loggedUsers"):
                value = raw_item.get(field)
                if value is None or value == []:
                    continue
                evidence = add_evidence(
                    "get_incident_details",
                    f"raw_data_items[{index}].{field}",
                    value,
                )
                if field == "device" and not host_value:
                    host_value = value
                    host_evidence.append(evidence)

        host_context_payload = None
        if details.host_context and profile.include_host_context:
            host_context = details.host_context
            host_context_payload = host_context.model_dump(
                mode="json",
                exclude={
                    "collectors": {"__all__": {"raw"}},
                    "recent_incidents": {"__all__": {"raw"}},
                },
            )
            if not host_value:
                host_value = host_context.host
            host_evidence.append(add_evidence("get_host_context", "host", host_context.host))
            add_evidence("get_host_context", "collector_count", host_context.collector_count)
            add_evidence("get_host_context", "recent_incident_count", host_context.recent_incident_count)
            for index, collector in enumerate(host_context.collectors[:10]):
                collector_dump = collector.model_dump(mode="json")
                for field in (
                    "collector_id",
                    "name",
                    "collector_group_name",
                    "operating_system",
                    "os_family",
                    "ip_address",
                    "state",
                    "version",
                ):
                    value = collector_dump.get(field)
                    if value is None:
                        continue
                    add_evidence("get_host_context", f"collectors[{index}].{field}", value)
            for index, related_incident in enumerate(host_context.recent_incidents[:10]):
                incident_dump = related_incident.model_dump(mode="json")
                for field in ("incident_id", "severity", "classification", "first_seen", "last_seen", "process"):
                    value = incident_dump.get(field)
                    if value is None:
                        continue
                    add_evidence("get_host_context", f"recent_incidents[{index}].{field}", value)
        elif profile.include_host_context:
            missing_source_data.append("Host context was unavailable for this incident.")

        related_events_payload = None
        if details.related_events and profile.include_related_events:
            related_events = details.related_events
            related_events_payload = related_events.model_dump(
                mode="json",
                exclude={"related_events": {"__all__": {"raw"}}},
            )
            add_evidence("get_related_events", "pivot_used", related_events.pivot_used)
            add_evidence("get_related_events", "related_count", related_events.related_count)
            for index, related_event in enumerate(related_events.related_events[:10]):
                event_dump = related_event.model_dump(mode="json")
                for field in (
                    "incident_id",
                    "severity",
                    "classification",
                    "first_seen",
                    "last_seen",
                    "process",
                    "logged_user",
                ):
                    value = event_dump.get(field)
                    if value is None:
                        continue
                    add_evidence("get_related_events", f"related_events[{index}].{field}", value)
        elif profile.include_related_events:
            missing_source_data.append("Related event context was unavailable for this incident.")

        if not raw_data_items:
            missing_source_data.append("No raw data items were available from FortiEDR.")
        if not incident.process_path:
            missing_source_data.append("Process path was not available in the incident payload.")
        if not host_value:
            missing_source_data.append("Hostname was not available in incident or raw event data.")

        derived_context = self._build_derived_context(
            details,
            analysis_profile=analysis_profile,
            add_evidence=add_evidence,
        )
        if not details.forensics_events and profile.include_forensics:
            missing_source_data.append("Forensics event enrichment was unavailable for this incident.")
        if not derived_context.process_stack:
            missing_source_data.append("Process lineage stack was not available in FortiEDR raw telemetry.")
        if (
            incident.process
            and incident.process.casefold() in _INTERESTING_COMMAND_PROCESSES
            and not derived_context.relevant_command_lines
        ):
            missing_source_data.append(
                "Command-line telemetry was not available for the relevant script or shell process."
            )

        hash_metadata = extract_hash_metadata(raw_data_items)

        key_metadata = KeyMetadata(
            hostname=EvidenceBackedValue(value=host_value, evidence=host_evidence),
            user=EvidenceBackedValue(
                value=incident.logged_user,
                evidence=incident_evidence.get("logged_user", []),
            ),
            process_name=EvidenceBackedValue(
                value=incident.process,
                evidence=incident_evidence.get("process", []),
            ),
            process_path=EvidenceBackedValue(
                value=incident.process_path,
                evidence=incident_evidence.get("process_path", []),
            ),
            hashes=hash_metadata,
            severity=EvidenceBackedValue(
                value=incident.severity,
                evidence=incident_evidence.get("severity", []),
            ),
            classification=EvidenceBackedValue(
                value=incident.classification,
                evidence=incident_evidence.get("classification", []),
            ),
            first_seen=EvidenceBackedValue(
                value=incident.first_seen,
                evidence=incident_evidence.get("first_seen", []),
            ),
            last_seen=EvidenceBackedValue(
                value=incident.last_seen,
                evidence=incident_evidence.get("last_seen", []),
            ),
            action=EvidenceBackedValue(
                value=incident.action,
                evidence=incident_evidence.get("action", []),
            ),
        )

        incident_snapshot = {
            "incident": incident.model_dump(mode="json", exclude={"raw"}),
            "raw_data_item_count": details.raw_data_item_count,
            "forensics_event_count": details.forensics_events.selected_count if details.forensics_events else 0,
        }

        return IncidentAnalysisInput(
            skill_version="incident_senior_soc_v1",
            incident_id=str(incident.incident_id),
            key_metadata_candidates=key_metadata,
            incident_snapshot=incident_snapshot,
            derived_context=derived_context,
            raw_data_items=prompt_raw_data_items,
            host_context=host_context_payload,
            related_events=related_events_payload,
            evidence_catalog=evidence_catalog,
            missing_source_data=_unique_strings(missing_source_data),
        )
