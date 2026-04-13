from __future__ import annotations

from collections.abc import Callable

from mcp.server.fastmcp import FastMCP

from fortiedr_mcp.errors import FortiEDRError
from fortiedr_mcp.fortiedr_client import FortiEDRClient
from fortiedr_mcp.models import (
    ForensicsEventsResult,
    HostContextResult,
    IncidentDetailsResult,
    IncidentListResult,
    IncidentSummary,
    RelatedEventsResult,
)
from fortiedr_mcp.services.incident_data import IncidentDataService


def _safe_tool_error(exc: FortiEDRError) -> ValueError:
    return ValueError(str(exc))


def register_incident_tools(
    mcp: FastMCP, client_factory: Callable[[], FortiEDRClient]
) -> None:
    def build_service() -> IncidentDataService:
        return IncidentDataService(client_factory())

    @mcp.tool()
    def list_incidents(
        page_number: int = 0,
        items_per_page: int = 25,
        classification: str | None = None,
        severity: str | None = None,
        handled: bool | None = None,
        archived: bool | None = None,
    ) -> IncidentListResult:
        """List FortiEDR incidents, currently mapped to FortiEDR event records."""
        try:
            return build_service().list_incidents(
                page_number=page_number,
                items_per_page=items_per_page,
                classification=classification,
                severity=severity,
                handled=handled,
                archived=archived,
            )
        except FortiEDRError as exc:
            raise _safe_tool_error(exc) from exc

    @mcp.tool()
    def get_incident(incident_id: int) -> IncidentSummary:
        """Fetch a single FortiEDR incident by event ID."""
        try:
            return build_service().get_incident(incident_id)
        except FortiEDRError as exc:
            raise _safe_tool_error(exc) from exc

    @mcp.tool()
    def get_incident_details(
        incident_id: int,
        related_limit: int = 10,
        include_forensics: bool = True,
    ) -> IncidentDetailsResult:
        """Fetch a single incident with raw data, host context, related events, and forensic enrichment."""
        try:
            return build_service().get_incident_details(
                incident_id,
                related_limit=related_limit,
                include_forensics=include_forensics,
            )
        except FortiEDRError as exc:
            raise _safe_tool_error(exc) from exc

    @mcp.tool()
    def search_incidents_by_host(
        host: str,
        page_number: int = 0,
        items_per_page: int = 25,
    ) -> IncidentListResult:
        """Search incidents by host using the FortiEDR device filter."""
        try:
            return build_service().search_incidents_by_host(
                host,
                page_number=page_number,
                items_per_page=items_per_page,
            )
        except FortiEDRError as exc:
            raise _safe_tool_error(exc) from exc

    @mcp.tool()
    def search_incidents_by_hash(
        file_hash: str,
        page_number: int = 0,
        items_per_page: int = 25,
    ) -> IncidentListResult:
        """Search incidents by FortiEDR file hash."""
        try:
            return build_service().search_incidents_by_hash(
                file_hash,
                page_number=page_number,
                items_per_page=items_per_page,
            )
        except FortiEDRError as exc:
            raise _safe_tool_error(exc) from exc

    @mcp.tool()
    def search_incidents_by_process(
        process: str,
        page_number: int = 0,
        items_per_page: int = 25,
    ) -> IncidentListResult:
        """Search incidents by process name."""
        try:
            return build_service().search_incidents_by_process(
                process,
                page_number=page_number,
                items_per_page=items_per_page,
            )
        except FortiEDRError as exc:
            raise _safe_tool_error(exc) from exc

    @mcp.tool()
    def search_incidents_by_user(
        user: str,
        page_number: int = 0,
        items_per_page: int = 25,
    ) -> IncidentListResult:
        """Search incidents by logged-on user."""
        try:
            return build_service().search_incidents_by_user(
                user,
                page_number=page_number,
                items_per_page=items_per_page,
            )
        except FortiEDRError as exc:
            raise _safe_tool_error(exc) from exc

    @mcp.tool()
    def get_host_context(
        host: str,
        incident_limit: int = 10,
        collector_limit: int = 25,
    ) -> HostContextResult:
        """Fetch collector inventory and recent incidents for a host."""
        try:
            return build_service().get_host_context(
                host,
                incident_limit=incident_limit,
                collector_limit=collector_limit,
            )
        except FortiEDRError as exc:
            raise _safe_tool_error(exc) from exc

    @mcp.tool()
    def get_related_events(
        incident_id: int,
        items_per_page: int = 10,
    ) -> RelatedEventsResult:
        """Find read-only related events using host-first pivoting from incident details."""
        try:
            return build_service().get_related_events(
                incident_id,
                items_per_page=items_per_page,
            )
        except FortiEDRError as exc:
            raise _safe_tool_error(exc) from exc

    @mcp.tool()
    def get_forensics_events(
        incident_id: int,
        page_size: int = 10,
        offset: int = 0,
    ) -> ForensicsEventsResult:
        """Call FortiEDR /api/forensics/get-events for an incident and return curated forensic context."""
        try:
            return build_service().get_forensics_events(
                incident_id,
                page_size=page_size,
                offset=offset,
            )
        except FortiEDRError as exc:
            raise _safe_tool_error(exc) from exc
