from __future__ import annotations

from fortiedr_mcp.services.incident_data import IncidentDataService


class FakeClient:
    def __init__(self):
        self.raw_calls = 0
        self.list_calls = 0

    def list_events(self, **filters):
        self.list_calls += 1
        return [
            {
                "eventId": 5468165,
                "process": "sample_1.exe",
                "processPath": "C:\\Users\\Alice\\Downloads\\sample_1.exe",
                "classification": "Malicious",
                "severity": "Critical",
                "organization": "FabricLab",
                "rules": [],
            }
        ]

    def list_raw_data_items(
        self,
        incident_id: int,
        *,
        page_number: int = 0,
        items_per_page: int = 100,
        full_data_requested: bool = True,
    ):
        assert incident_id == 5468165
        self.raw_calls += 1
        if full_data_requested:
            return [{"HostName": "win-edr-2"}]
        return [{"device": "win-edr-2"}]


class PaginatedFakeClient:
    def __init__(self):
        self.calls: list[dict] = []

    def list_events(self, **filters):
        self.calls.append(dict(filters))
        page_number = filters["pageNumber"]
        if page_number == 0:
            return [
                {
                    "eventId": 5468165,
                    "process": "sample_1.exe",
                    "processPath": "C:\\Users\\Alice\\Downloads\\sample_1.exe",
                    "classification": "Malicious",
                    "severity": "Critical",
                    "organization": "FabricLab",
                    "host": "win-edr-2",
                    "rules": [],
                },
                {
                    "eventId": 5468172,
                    "process": "sample_2.exe",
                    "processPath": "C:\\Users\\Alice\\Downloads\\sample_2.exe",
                    "classification": "Malicious",
                    "severity": "Critical",
                    "organization": "FabricLab",
                    "host": "win-edr-3",
                    "rules": [],
                },
            ]
        if page_number == 1:
            return [
                {
                    "eventId": 5468179,
                    "process": "sample_3.exe",
                    "processPath": "C:\\Users\\Alice\\Downloads\\sample_3.exe",
                    "classification": "Suspicious",
                    "severity": "High",
                    "organization": "FabricLab",
                    "host": "win-edr-4",
                    "rules": [],
                }
            ]
        return []


def test_list_incidents_skips_host_enrichment_and_uses_list_cache_by_default():
    client = FakeClient()
    service = IncidentDataService(client)

    first_result = service.list_incidents()
    second_result = service.list_incidents()

    assert first_result.incidents[0].host is None
    assert second_result.incidents[0].host is None
    assert client.raw_calls == 0
    assert client.list_calls == 1


def test_list_incidents_can_resolve_hosts_when_requested():
    client = FakeClient()
    service = IncidentDataService(client)

    first_result = service.list_incidents(resolve_hosts=True)
    second_result = service.list_incidents(resolve_hosts=True)

    assert first_result.incidents[0].host == "win-edr-2"
    assert second_result.incidents[0].host == "win-edr-2"
    assert client.raw_calls == 1
    assert client.list_calls == 1


def test_list_all_incidents_walks_pages_until_exhausted():
    client = PaginatedFakeClient()
    service = IncidentDataService(client)

    result = service.list_all_incidents(items_per_page=2)

    assert result.count == 3
    assert [incident.incident_id for incident in result.incidents] == [5468165, 5468172, 5468179]
    assert [call["pageNumber"] for call in client.calls] == [0, 1]
    assert all(call["itemsPerPage"] == 2 for call in client.calls)
