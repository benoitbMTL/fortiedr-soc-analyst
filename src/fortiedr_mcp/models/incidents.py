from __future__ import annotations

from typing import Any, Mapping

from pydantic import BaseModel, Field


def _first_list_value(value: Any) -> str | None:
    if isinstance(value, list) and value:
        first = value[0]
        return first if isinstance(first, str) else None
    return None


def _signature_status_from_event(event: Mapping[str, Any]) -> str | None:
    certified = event.get("certified")
    if certified is True:
        return "signed"
    if certified is False:
        return "unsigned"
    return None


def _string_list(value: Any) -> list[str]:
    if isinstance(value, list):
        return [str(item) for item in value if item not in (None, "")]
    if isinstance(value, str) and value:
        return [value]
    return []


def _host_from_event(event: Mapping[str, Any], *, host_hint: str | None = None) -> str | None:
    if isinstance(host_hint, str) and host_hint.strip():
        return host_hint.strip()
    for field in ("host", "hostname", "hostName", "HostName", "device"):
        value = event.get(field)
        if isinstance(value, str) and value.strip():
            return value.strip()
    return None


class IncidentSummary(BaseModel):
    incident_id: int = Field(description="FortiEDR event identifier.")
    process: str | None = None
    process_path: str | None = None
    process_type: str | None = None
    signature_status: str | None = None
    host: str | None = Field(default=None, description="Best-effort host value.")
    logged_user: str | None = None
    process_owner: str | None = None
    severity: str | None = None
    classification: str | None = None
    handling_state: str | None = None
    action: str | None = None
    first_seen: str | None = None
    last_seen: str | None = None
    organization: str | None = None
    seen: bool | None = None
    archived: bool | None = None
    muted: bool | None = None
    threat_name: str | None = None
    threat_family: str | None = None
    collectors: list[Any] = Field(default_factory=list)
    destinations: list[Any] = Field(default_factory=list)
    rules: list[Any] = Field(default_factory=list)
    raw: dict[str, Any] = Field(
        default_factory=dict,
        description="Original FortiEDR event payload.",
    )

    @classmethod
    def from_event(
        cls, event: Mapping[str, Any], *, host_hint: str | None = None
    ) -> "IncidentSummary":
        threat_details = event.get("threatDetails")
        threat_name = None
        threat_family = None
        if isinstance(threat_details, Mapping):
            threat_name = threat_details.get("threatName")
            threat_family = threat_details.get("threatFamily")

        return cls(
            incident_id=int(event["eventId"]),
            process=event.get("process"),
            process_path=event.get("processPath"),
            process_type=event.get("processType"),
            signature_status=_signature_status_from_event(event),
            host=_host_from_event(event, host_hint=host_hint),
            logged_user=_first_list_value(event.get("loggedUsers")),
            process_owner=event.get("processOwner"),
            severity=event.get("severity"),
            classification=event.get("classification"),
            handling_state=event.get("handlingState"),
            action=event.get("action"),
            first_seen=event.get("firstSeen"),
            last_seen=event.get("lastSeen"),
            organization=event.get("organization"),
            seen=event.get("seen"),
            archived=event.get("archived"),
            muted=event.get("muted"),
            threat_name=threat_name,
            threat_family=threat_family,
            collectors=list(event.get("collectors") or []),
            destinations=list(event.get("destinations") or []),
            rules=list(event.get("rules") or []),
            raw=dict(event),
        )


class IncidentListResult(BaseModel):
    organization: str | None = None
    page_number: int
    items_per_page: int
    count: int
    incidents: list[IncidentSummary]


class CollectorSummary(BaseModel):
    collector_id: int | None = None
    name: str | None = None
    collector_group_name: str | None = None
    operating_system: str | None = None
    os_family: str | None = None
    ip_address: str | None = None
    state: str | None = None
    version: str | None = None
    organization: str | None = None
    raw: dict[str, Any] = Field(
        default_factory=dict,
        description="Original FortiEDR collector payload.",
    )

    @classmethod
    def from_collector(cls, collector: Mapping[str, Any]) -> "CollectorSummary":
        collector_id = collector.get("id")
        return cls(
            collector_id=int(collector_id) if collector_id is not None else None,
            name=collector.get("name"),
            collector_group_name=collector.get("collectorGroupName"),
            operating_system=collector.get("operatingSystem"),
            os_family=collector.get("osFamily"),
            ip_address=collector.get("ipAddress"),
            state=collector.get("state"),
            version=collector.get("version"),
            organization=collector.get("organization"),
            raw=dict(collector),
        )


class HostContextResult(BaseModel):
    host: str
    collector_count: int
    collectors: list[CollectorSummary]
    recent_incident_count: int
    recent_incidents: list[IncidentSummary]


class RelatedEventsResult(BaseModel):
    incident_id: int
    pivot_used: dict[str, Any]
    related_count: int
    related_events: list[IncidentSummary]


class ForensicsSelectedEvent(BaseModel):
    incident_id: int | None = None
    event_id: int | None = None
    device: str | None = None
    process: str | None = None
    process_path: str | None = None
    process_path_unformatted: str | None = None
    process_owner: str | None = None
    logged_users: list[str] = Field(default_factory=list)
    severity: str | None = None
    classification: str | None = None
    handling_state: str | None = None
    certificate_status: str | None = None
    destinations: list[str] = Field(default_factory=list)
    process_script_module: str | None = None
    process_script_module_path: str | None = None
    host_state: str | None = None
    threat_name: str | None = None
    threat_family: str | None = None
    threat_type: str | None = None
    handling_tooltip: str | None = None
    raw: dict[str, Any] = Field(
        default_factory=dict,
        description="Original FortiEDR forensics selected-event payload.",
    )

    @classmethod
    def from_event(cls, event: Mapping[str, Any]) -> "ForensicsSelectedEvent":
        event_id = event.get("eventId") or event.get("id")
        incident_id = event.get("eventId") or event.get("id")
        return cls(
            incident_id=int(incident_id) if incident_id is not None else None,
            event_id=int(event_id) if event_id is not None else None,
            device=event.get("device"),
            process=event.get("process"),
            process_path=event.get("processPath"),
            process_path_unformatted=event.get("processPathUnformated"),
            process_owner=event.get("processOwner"),
            logged_users=_string_list(event.get("loggedUsers")),
            severity=event.get("severity"),
            classification=event.get("classification"),
            handling_state=event.get("handlingState"),
            certificate_status=event.get("certificateStatus"),
            destinations=_string_list(event.get("destinations")),
            process_script_module=event.get("processScriptModule"),
            process_script_module_path=event.get("processScriptModulePath"),
            host_state=event.get("hostState"),
            threat_name=event.get("threatName"),
            threat_family=event.get("threatFamily"),
            threat_type=event.get("threatType"),
            handling_tooltip=event.get("handlingTooltipInfo"),
            raw=dict(event),
        )


class ForensicsEventsResult(BaseModel):
    incident_ids: list[int] = Field(default_factory=list)
    event_ids: list[int] = Field(default_factory=list)
    organization_id: int | None = None
    offset: int = 0
    page_size: int = 25
    selected_count: int = 0
    aggregations_total_count: int | None = None
    selected_events: list[ForensicsSelectedEvent] = Field(default_factory=list)


class IncidentDetailsResult(BaseModel):
    incident: IncidentSummary
    raw_data_item_count: int
    raw_data_items: list[dict[str, Any]]
    host_context: HostContextResult | None = None
    related_events: RelatedEventsResult | None = None
    forensics_events: ForensicsEventsResult | None = None
