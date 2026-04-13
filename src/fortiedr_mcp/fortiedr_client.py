from __future__ import annotations

import base64
from typing import Any

import requests
from requests import Response, Session
from requests.exceptions import RequestException

from fortiedr_mcp.config import FortiEDRConfig
from fortiedr_mcp.errors import (
    FortiEDRAPIError,
    FortiEDRAuthenticationError,
    FortiEDRConfigurationError,
    FortiEDRNotFoundError,
)


class FortiEDRClient:
    """Narrow read-only wrapper around the FortiEDR API."""

    def __init__(self, config: FortiEDRConfig):
        self._config = config
        self._session = self._build_session(config)
        self._organization_id: int | None = None

    @staticmethod
    def _build_session(config: FortiEDRConfig) -> Session:
        credential = (
            f"{config.organization}\\{config.user}:{config.password}"
            if config.organization
            else f"{config.user}:{config.password}"
        )
        encoded = base64.b64encode(credential.encode("ascii")).decode("ascii")

        session = requests.Session()
        session.headers.update(
            {
                "Authorization": f"Basic {encoded}",
                "Accept": "application/json",
            }
        )
        return session

    @staticmethod
    def _normalize_query_params(params: dict[str, Any] | None) -> dict[str, Any]:
        normalized: dict[str, Any] = {}
        if not params:
            return normalized

        for key, value in params.items():
            if value is None:
                continue
            if isinstance(value, list):
                normalized[key] = ",".join(str(item) for item in value)
                continue
            normalized[key] = value

        return normalized

    @classmethod
    def _normalize_json_body(cls, payload: Any) -> Any:
        if payload is None:
            return None
        if isinstance(payload, dict):
            return {
                key: cls._normalize_json_body(value)
                for key, value in payload.items()
                if value is not None
            }
        if isinstance(payload, list):
            return [cls._normalize_json_body(item) for item in payload if item is not None]
        return payload

    def _request(
        self,
        method: str,
        path: str,
        *,
        params: dict[str, Any] | None = None,
        json_body: dict[str, Any] | None = None,
    ) -> Any:
        url = f"{self._config.base_url}{path}"
        query = self._normalize_query_params(params)
        body = self._normalize_json_body(json_body)

        try:
            response = self._session.request(
                method=method,
                url=url,
                params=query or None,
                json=body if method.upper() != "GET" else None,
                verify=self._config.verify_ssl,
                timeout=self._config.timeout_seconds,
            )
        except RequestException as exc:
            raise FortiEDRAPIError(
                "FortiEDR request failed before a response was returned."
            ) from exc

        return self._handle_response(response)

    @staticmethod
    def _handle_response(response: Response) -> Any:
        if response.status_code == 401:
            raise FortiEDRAuthenticationError("FortiEDR rejected the configured credentials.")
        if response.status_code == 403:
            raise FortiEDRAuthenticationError(
                "FortiEDR denied access to the requested read-only endpoint."
            )
        if response.status_code == 404:
            raise FortiEDRNotFoundError("FortiEDR did not find the requested record.")

        if not response.ok:
            try:
                payload = response.json()
            except ValueError:
                payload = None

            if isinstance(payload, dict):
                message = payload.get("errorMessage") or payload.get("message")
            else:
                message = None

            raise FortiEDRAPIError(
                message or f"FortiEDR API request failed with status {response.status_code}."
            )

        if not response.content:
            return None

        try:
            return response.json()
        except ValueError:
            return response.text

    def list_events(self, **filters: Any) -> list[dict[str, Any]]:
        params = {"organization": self._config.organization, **filters}
        data = self._request("GET", "/management-rest/events/list-events", params=params)
        if not isinstance(data, list):
            raise FortiEDRAPIError("FortiEDR returned an unexpected events payload.")
        return data

    def get_event(self, incident_id: int) -> dict[str, Any]:
        data = self.list_events(
            eventIds=[incident_id],
            pageNumber=0,
            itemsPerPage=1,
        )
        if not data:
            raise FortiEDRNotFoundError(f"Incident {incident_id} was not found in FortiEDR.")
        return data[0]

    def list_raw_data_items(
        self,
        incident_id: int,
        *,
        page_number: int = 0,
        items_per_page: int = 100,
        full_data_requested: bool = True,
    ) -> list[dict[str, Any]]:
        params = {
            "organization": self._config.organization,
            "eventId": incident_id,
            "pageNumber": page_number,
            "itemsPerPage": items_per_page,
            "fullDataRequested": full_data_requested,
        }
        data = self._request(
            "GET",
            "/management-rest/events/list-raw-data-items",
            params=params,
        )
        if not isinstance(data, list):
            raise FortiEDRAPIError("FortiEDR returned an unexpected raw data payload.")
        return data

    def list_collectors(
        self,
        *,
        devices: list[str] | None = None,
        page_number: int = 0,
        items_per_page: int = 100,
    ) -> list[dict[str, Any]]:
        params = {
            "organization": self._config.organization,
            "devices": devices,
            "pageNumber": page_number,
            "itemsPerPage": items_per_page,
        }
        data = self._request(
            "GET",
            "/management-rest/inventory/list-collectors",
            params=params,
        )
        if not isinstance(data, list):
            raise FortiEDRAPIError("FortiEDR returned an unexpected collectors payload.")
        return data

    def list_organizations(self, *, name: str | None = None) -> list[dict[str, Any]]:
        params = {"name": name} if name else None
        data = self._request(
            "GET",
            "/management-rest/organizations/list-organizations",
            params=params,
        )
        if not isinstance(data, list):
            raise FortiEDRAPIError("FortiEDR returned an unexpected organizations payload.")
        return data

    def get_organization_id(self) -> int:
        if self._organization_id is not None:
            return self._organization_id

        configured_name = (self._config.organization or "").strip()
        organizations = self.list_organizations(name=configured_name or None)
        if not organizations:
            raise FortiEDRConfigurationError(
                "FortiEDR organization could not be resolved from the configured environment."
            )

        candidates = organizations
        if configured_name:
            exact_matches = [
                item
                for item in organizations
                if str(item.get("name") or item.get("organization") or "").strip() == configured_name
            ]
            if exact_matches:
                candidates = exact_matches
        elif len(organizations) != 1:
            raise FortiEDRConfigurationError(
                "FORTIEDR_ORG is required when FortiEDR exposes more than one organization."
            )

        organization = candidates[0]
        organization_id = organization.get("organizationId") or organization.get("id")
        if organization_id is None:
            raise FortiEDRAPIError("FortiEDR organization metadata did not include an organization ID.")

        self._organization_id = int(organization_id)
        return self._organization_id

    def get_forensics_events(
        self,
        *,
        incident_ids: list[int] | None = None,
        event_ids: list[int] | None = None,
        offset: int = 0,
        page_size: int = 25,
    ) -> dict[str, Any]:
        if not incident_ids and not event_ids:
            raise ValueError("incident_ids or event_ids must be provided.")

        payload = {
            "incidentIds": incident_ids,
            "eventIds": event_ids,
            "offset": offset,
            "pageSize": page_size,
            "organizationId": self.get_organization_id(),
        }
        data = self._request(
            "POST",
            "/api/forensics/get-events",
            json_body=payload,
        )
        if not isinstance(data, dict):
            raise FortiEDRAPIError("FortiEDR returned an unexpected forensics events payload.")
        return data
