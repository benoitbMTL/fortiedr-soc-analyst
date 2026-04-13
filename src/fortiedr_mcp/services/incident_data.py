from __future__ import annotations

import time
from typing import Any

from fortiedr_mcp.errors import FortiEDRAPIError, FortiEDRError
from fortiedr_mcp.fortiedr_client import FortiEDRClient
from fortiedr_mcp.models import (
    CollectorSummary,
    ForensicsEventsResult,
    ForensicsSelectedEvent,
    HostContextResult,
    IncidentDetailsResult,
    IncidentListResult,
    IncidentSummary,
    RelatedEventsResult,
)


def _require_non_empty(name: str, value: str) -> str:
    if not value or not value.strip():
        raise ValueError(f"{name} must be a non-empty string.")
    return value.strip()


def _validate_paging(page_number: int, items_per_page: int) -> tuple[int, int]:
    if page_number < 0:
        raise ValueError("page_number must be zero or greater.")
    if items_per_page <= 0 or items_per_page > 1000:
        raise ValueError("items_per_page must be between 1 and 1000.")
    return page_number, items_per_page


def _require_incident_id(incident_id: int) -> int:
    if incident_id <= 0:
        raise ValueError("incident_id must be greater than zero.")
    return incident_id


def _normalize_logged_user_search_value(user: str) -> str:
    candidate = user.strip()
    if "\\" in candidate:
        _, _, candidate = candidate.rpartition("\\")
    return candidate


def _extract_host_from_raw_data_items(raw_data_items: list[dict]) -> str | None:
    for item in raw_data_items:
        for field in ("device", "HostName", "hostName", "hostname", "host"):
            host = item.get(field)
            if isinstance(host, str) and host.strip():
                return host.strip()
    return None


def _build_incident_list(
    events: list[dict],
    *,
    page_number: int,
    items_per_page: int,
    host_hint: str | None = None,
) -> IncidentListResult:
    incidents = [IncidentSummary.from_event(event, host_hint=host_hint) for event in events]
    organization = incidents[0].organization if incidents else None
    return IncidentListResult(
        organization=organization,
        page_number=page_number,
        items_per_page=items_per_page,
        count=len(incidents),
        incidents=incidents,
    )


class IncidentDataService:
    """Shared read-only FortiEDR incident retrieval service."""

    def __init__(self, client: FortiEDRClient, *, list_cache_ttl_seconds: float = 30.0):
        self._client = client
        self._incident_host_cache: dict[int, str | None] = {}
        self._list_cache_ttl_seconds = max(0.0, list_cache_ttl_seconds)
        self._list_cache: dict[tuple[Any, ...], tuple[float, IncidentListResult]] = {}

    def _resolve_incident_host(self, incident_id: int) -> str | None:
        if incident_id in self._incident_host_cache:
            return self._incident_host_cache[incident_id]

        host: str | None = None
        for full_data_requested in (False, True):
            try:
                raw_data_items = self._client.list_raw_data_items(
                    incident_id,
                    page_number=0,
                    items_per_page=1,
                    full_data_requested=full_data_requested,
                )
            except FortiEDRError:
                continue

            host = _extract_host_from_raw_data_items(raw_data_items)
            if host:
                break

        self._incident_host_cache[incident_id] = host
        return host

    def _with_resolved_host(self, incident: IncidentSummary) -> IncidentSummary:
        if incident.host:
            return incident

        host = self._resolve_incident_host(incident.incident_id)
        if not host:
            return incident

        return incident.model_copy(update={"host": host})

    def _with_resolved_hosts(self, result: IncidentListResult) -> IncidentListResult:
        incidents = [self._with_resolved_host(incident) for incident in result.incidents]
        if incidents == result.incidents:
            return result
        return result.model_copy(update={"incidents": incidents})

    def _cache_key(self, operation: str, *parts: Any) -> tuple[Any, ...]:
        return (operation, *parts)

    def _cache_list_result(self, cache_key: tuple[Any, ...], result: IncidentListResult) -> IncidentListResult:
        if self._list_cache_ttl_seconds <= 0:
            return result
        self._list_cache[cache_key] = (
            time.monotonic() + self._list_cache_ttl_seconds,
            result.model_copy(deep=True),
        )
        return result

    def _get_cached_list_result(self, cache_key: tuple[Any, ...]) -> IncidentListResult | None:
        if self._list_cache_ttl_seconds <= 0:
            return None

        cached = self._list_cache.get(cache_key)
        if cached is None:
            return None

        expires_at, result = cached
        if expires_at <= time.monotonic():
            self._list_cache.pop(cache_key, None)
            return None
        return result.model_copy(deep=True)

    def _finalize_incident_list(
        self,
        events: list[dict],
        *,
        page_number: int,
        items_per_page: int,
        host_hint: str | None = None,
        resolve_hosts: bool = False,
    ) -> IncidentListResult:
        result = _build_incident_list(
            events,
            page_number=page_number,
            items_per_page=items_per_page,
            host_hint=host_hint,
        )
        return self._with_resolved_hosts(result) if resolve_hosts else result

    def _list_incident_events(
        self,
        *,
        page_number: int,
        items_per_page: int,
        classification: str | None = None,
        severity: str | None = None,
        handled: bool | None = None,
        archived: bool | None = None,
        **filters: Any,
    ) -> list[dict]:
        return self._client.list_events(
            pageNumber=page_number,
            itemsPerPage=items_per_page,
            classifications=[classification] if classification else None,
            severities=[severity] if severity else None,
            handled=handled,
            archived=archived,
            **filters,
        )

    def list_incidents(
        self,
        *,
        page_number: int = 0,
        items_per_page: int = 25,
        classification: str | None = None,
        severity: str | None = None,
        handled: bool | None = None,
        archived: bool | None = None,
        resolve_hosts: bool = False,
    ) -> IncidentListResult:
        page_number, items_per_page = _validate_paging(page_number, items_per_page)
        cache_key = self._cache_key(
            "list_incidents",
            page_number,
            items_per_page,
            classification,
            severity,
            handled,
            archived,
            resolve_hosts,
        )
        cached = self._get_cached_list_result(cache_key)
        if cached is not None:
            return cached

        events = self._list_incident_events(
            page_number=page_number,
            items_per_page=items_per_page,
            classification=classification,
            severity=severity,
            handled=handled,
            archived=archived,
        )
        result = self._finalize_incident_list(
            events,
            page_number=page_number,
            items_per_page=items_per_page,
            resolve_hosts=resolve_hosts,
        )
        return self._cache_list_result(cache_key, result).model_copy(deep=True)

    def list_all_incidents(
        self,
        *,
        items_per_page: int = 1000,
        classification: str | None = None,
        severity: str | None = None,
        handled: bool | None = None,
        archived: bool | None = None,
        resolve_hosts: bool = False,
    ) -> IncidentListResult:
        _, items_per_page = _validate_paging(0, items_per_page)
        cache_key = self._cache_key(
            "list_all_incidents",
            items_per_page,
            classification,
            severity,
            handled,
            archived,
            resolve_hosts,
        )
        cached = self._get_cached_list_result(cache_key)
        if cached is not None:
            return cached

        page_number = 0
        events: list[dict] = []

        while True:
            page_events = self._list_incident_events(
                page_number=page_number,
                items_per_page=items_per_page,
                classification=classification,
                severity=severity,
                handled=handled,
                archived=archived,
            )
            if not page_events:
                break
            events.extend(page_events)
            if len(page_events) < items_per_page:
                break
            page_number += 1

        result = self._finalize_incident_list(
            events,
            page_number=0,
            items_per_page=items_per_page,
            resolve_hosts=resolve_hosts,
        )
        return self._cache_list_result(cache_key, result).model_copy(deep=True)

    def get_incident(self, incident_id: int) -> IncidentSummary:
        event = self._client.get_event(_require_incident_id(incident_id))
        return self._with_resolved_host(IncidentSummary.from_event(event))

    def search_incidents_by_id(
        self,
        incident_id: int,
        *,
        classification: str | None = None,
        severity: str | None = None,
        handled: bool | None = None,
        archived: bool | None = None,
        resolve_hosts: bool = False,
    ) -> IncidentListResult:
        incident_id = _require_incident_id(incident_id)
        events = self._list_incident_events(
            eventIds=[incident_id],
            page_number=0,
            items_per_page=1,
            classification=classification,
            severity=severity,
            handled=handled,
            archived=archived,
        )
        if not events:
            return IncidentListResult(
                organization=None,
                page_number=0,
                items_per_page=1,
                count=0,
                incidents=[],
            )
        return self._finalize_incident_list(
            events,
            page_number=0,
            items_per_page=1,
            resolve_hosts=resolve_hosts,
        )

    def get_incident_details(
        self,
        incident_id: int,
        *,
        raw_data_limit: int = 25,
        related_limit: int = 10,
        collector_limit: int = 25,
        include_host_context: bool = True,
        include_related_events: bool = True,
        include_forensics: bool = True,
    ) -> IncidentDetailsResult:
        _require_incident_id(incident_id)
        _, raw_data_limit = _validate_paging(0, raw_data_limit)
        _, related_limit = _validate_paging(0, related_limit)
        _, collector_limit = _validate_paging(0, collector_limit)

        event = self._client.get_event(incident_id)
        raw_data_items = self._client.list_raw_data_items(
            incident_id,
            page_number=0,
            items_per_page=raw_data_limit,
            full_data_requested=True,
        )
        host = _extract_host_from_raw_data_items(raw_data_items)

        incident = IncidentSummary.from_event(event, host_hint=host)

        host_context = None
        if include_host_context and host:
            host_context = self.get_host_context(
                host,
                incident_limit=related_limit,
                collector_limit=collector_limit,
            )

        related_events = None
        if include_related_events:
            related_events = self.get_related_events(
                incident_id,
                items_per_page=related_limit,
                raw_data_items=raw_data_items,
                source_event=event,
            )

        forensics_events = None
        if include_forensics:
            try:
                forensics_events = self.get_forensics_events(
                    incident_id,
                    page_size=min(max(raw_data_limit, related_limit), 25),
                )
            except FortiEDRAPIError:
                forensics_events = None

        return IncidentDetailsResult(
            incident=incident,
            raw_data_item_count=len(raw_data_items),
            raw_data_items=raw_data_items,
            host_context=host_context,
            related_events=related_events,
            forensics_events=forensics_events,
        )

    def search_incidents_by_host(
        self,
        host: str,
        *,
        page_number: int = 0,
        items_per_page: int = 25,
        classification: str | None = None,
        severity: str | None = None,
        handled: bool | None = None,
        archived: bool | None = None,
        resolve_hosts: bool = False,
    ) -> IncidentListResult:
        page_number, items_per_page = _validate_paging(page_number, items_per_page)
        host = _require_non_empty("host", host)
        cache_key = self._cache_key(
            "search_incidents_by_host",
            host,
            page_number,
            items_per_page,
            classification,
            severity,
            handled,
            archived,
            resolve_hosts,
        )
        cached = self._get_cached_list_result(cache_key)
        if cached is not None:
            return cached

        events = self._list_incident_events(
            page_number=page_number,
            items_per_page=items_per_page,
            classification=classification,
            severity=severity,
            handled=handled,
            archived=archived,
            device=host,
        )
        result = self._finalize_incident_list(
            events,
            page_number=page_number,
            items_per_page=items_per_page,
            host_hint=host,
            resolve_hosts=resolve_hosts,
        )
        return self._cache_list_result(cache_key, result).model_copy(deep=True)

    def search_incidents_by_hash(
        self,
        file_hash: str,
        *,
        page_number: int = 0,
        items_per_page: int = 25,
        resolve_hosts: bool = False,
    ) -> IncidentListResult:
        page_number, items_per_page = _validate_paging(page_number, items_per_page)
        file_hash = _require_non_empty("file_hash", file_hash)
        cache_key = self._cache_key(
            "search_incidents_by_hash",
            file_hash,
            page_number,
            items_per_page,
            resolve_hosts,
        )
        cached = self._get_cached_list_result(cache_key)
        if cached is not None:
            return cached

        events = self._list_incident_events(
            fileHash=file_hash,
            page_number=page_number,
            items_per_page=items_per_page,
        )
        result = self._finalize_incident_list(
            events,
            page_number=page_number,
            items_per_page=items_per_page,
            resolve_hosts=resolve_hosts,
        )
        return self._cache_list_result(cache_key, result).model_copy(deep=True)

    def search_incidents_by_process(
        self,
        process: str,
        *,
        page_number: int = 0,
        items_per_page: int = 25,
        classification: str | None = None,
        severity: str | None = None,
        handled: bool | None = None,
        archived: bool | None = None,
        resolve_hosts: bool = False,
    ) -> IncidentListResult:
        page_number, items_per_page = _validate_paging(page_number, items_per_page)
        process = _require_non_empty("process", process)
        cache_key = self._cache_key(
            "search_incidents_by_process",
            process,
            page_number,
            items_per_page,
            classification,
            severity,
            handled,
            archived,
            resolve_hosts,
        )
        cached = self._get_cached_list_result(cache_key)
        if cached is not None:
            return cached

        events = self._list_incident_events(
            process=process,
            page_number=page_number,
            items_per_page=items_per_page,
            classification=classification,
            severity=severity,
            handled=handled,
            archived=archived,
        )
        result = self._finalize_incident_list(
            events,
            page_number=page_number,
            items_per_page=items_per_page,
            resolve_hosts=resolve_hosts,
        )
        return self._cache_list_result(cache_key, result).model_copy(deep=True)

    def search_incidents_by_user(
        self,
        user: str,
        *,
        page_number: int = 0,
        items_per_page: int = 25,
        resolve_hosts: bool = False,
    ) -> IncidentListResult:
        page_number, items_per_page = _validate_paging(page_number, items_per_page)
        normalized_user = _normalize_logged_user_search_value(_require_non_empty("user", user))
        cache_key = self._cache_key(
            "search_incidents_by_user",
            normalized_user,
            page_number,
            items_per_page,
            resolve_hosts,
        )
        cached = self._get_cached_list_result(cache_key)
        if cached is not None:
            return cached

        events = self._list_incident_events(
            loggedUser=normalized_user,
            page_number=page_number,
            items_per_page=items_per_page,
        )
        result = self._finalize_incident_list(
            events,
            page_number=page_number,
            items_per_page=items_per_page,
            resolve_hosts=resolve_hosts,
        )
        return self._cache_list_result(cache_key, result).model_copy(deep=True)

    def get_host_context(
        self,
        host: str,
        *,
        incident_limit: int = 10,
        collector_limit: int = 25,
    ) -> HostContextResult:
        host = _require_non_empty("host", host)
        _, incident_limit = _validate_paging(0, incident_limit)
        _, collector_limit = _validate_paging(0, collector_limit)

        collectors = self._client.list_collectors(
            devices=[host],
            page_number=0,
            items_per_page=collector_limit,
        )
        events = self._client.list_events(
            device=host,
            pageNumber=0,
            itemsPerPage=incident_limit,
        )
        return HostContextResult(
            host=host,
            collector_count=len(collectors),
            collectors=[CollectorSummary.from_collector(item) for item in collectors],
            recent_incident_count=len(events),
            recent_incidents=[IncidentSummary.from_event(item, host_hint=host) for item in events],
        )

    def get_related_events(
        self,
        incident_id: int,
        *,
        items_per_page: int = 10,
        raw_data_items: list[dict] | None = None,
        source_event: dict | None = None,
    ) -> RelatedEventsResult:
        _require_incident_id(incident_id)
        _, items_per_page = _validate_paging(0, items_per_page)

        event = source_event or self._client.get_event(incident_id)
        evidence_raw_items = raw_data_items
        if evidence_raw_items is None:
            evidence_raw_items = self._client.list_raw_data_items(
                incident_id,
                page_number=0,
                items_per_page=25,
                full_data_requested=True,
            )

        pivot_used: dict[str, str] = {}
        query: dict[str, object] = {
            "pageNumber": 0,
            "itemsPerPage": min(items_per_page + 1, 1000),
        }

        host = _extract_host_from_raw_data_items(evidence_raw_items)
        if host:
            pivot_used["host"] = host
            query["device"] = host
        else:
            logged_users = event.get("loggedUsers")
            if isinstance(logged_users, list) and logged_users:
                raw_user = str(logged_users[0])
                normalized_user = _normalize_logged_user_search_value(raw_user)
                pivot_used["logged_user"] = raw_user
                if normalized_user != raw_user:
                    pivot_used["logged_user_query"] = normalized_user
                query["loggedUser"] = normalized_user

        process = event.get("process")
        if isinstance(process, str) and process:
            pivot_used["process"] = process
            if "device" not in query:
                query["process"] = process

        events = self._client.list_events(**query)
        related_events = []
        for item in events:
            if int(item["eventId"]) == incident_id:
                continue
            related_events.append(IncidentSummary.from_event(item, host_hint=host))
            if len(related_events) >= items_per_page:
                break

        if not pivot_used:
            raise FortiEDRAPIError(
                "FortiEDR did not return enough context to derive a related-events pivot."
            )

        return RelatedEventsResult(
            incident_id=incident_id,
            pivot_used=pivot_used,
            related_count=len(related_events),
            related_events=related_events,
        )

    def get_forensics_events(
        self,
        incident_id: int,
        *,
        offset: int = 0,
        page_size: int = 10,
    ) -> ForensicsEventsResult:
        _require_incident_id(incident_id)
        if offset < 0:
            raise ValueError("offset must be zero or greater.")
        _, page_size = _validate_paging(0, page_size)

        payload = self._client.get_forensics_events(
            incident_ids=[incident_id],
            offset=offset,
            page_size=page_size,
        )
        selected_events = payload.get("selectedEvents") or []
        if not isinstance(selected_events, list):
            raise FortiEDRAPIError("FortiEDR returned an unexpected forensics selectedEvents payload.")

        aggregations_total_count = payload.get("aggregationsTotalCount")
        return ForensicsEventsResult(
            incident_ids=[incident_id],
            event_ids=[],
            organization_id=self._client.get_organization_id(),
            offset=offset,
            page_size=page_size,
            selected_count=len(selected_events),
            aggregations_total_count=(
                int(aggregations_total_count) if aggregations_total_count is not None else None
            ),
            selected_events=[ForensicsSelectedEvent.from_event(item) for item in selected_events],
        )
