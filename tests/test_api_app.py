from __future__ import annotations

import os

from starlette.testclient import TestClient

from fortiedr_mcp.api.app import _resolve_requested_llm_config, create_app
from fortiedr_mcp.llm.mock import MockStructuredLLMClient
from fortiedr_mcp.models import IncidentListResult
from fortiedr_mcp.repositories import AnalysisRunRepository
from fortiedr_mcp.services import AnalysisRunService, IncidentAnalysisService


class FakeIncidentDataService:
    def __init__(self, details):
        self._details = details

    def get_incident_details(
        self,
        incident_id: int,
        *,
        raw_data_limit: int = 25,
        related_limit: int = 10,
        collector_limit: int = 10,
        include_host_context: bool = True,
        include_related_events: bool = True,
        include_forensics: bool = True,
    ):
        assert incident_id == 5440222
        return self._details


def _find_evidence(sample_analysis_input, path: str):
    for evidence in sample_analysis_input.evidence_catalog:
        if evidence.path == path:
            return evidence
    raise AssertionError(f"Evidence not found for path: {path}")


def _valid_response(sample_analysis_input):
    hostname_evidence = _find_evidence(sample_analysis_input, "incident.host")
    user_evidence = _find_evidence(sample_analysis_input, "incident.logged_user")
    process_evidence = _find_evidence(sample_analysis_input, "incident.process")
    process_path_evidence = _find_evidence(sample_analysis_input, "incident.process_path")
    severity_evidence = _find_evidence(sample_analysis_input, "incident.severity")
    classification_evidence = _find_evidence(sample_analysis_input, "incident.classification")
    first_seen_evidence = _find_evidence(sample_analysis_input, "incident.first_seen")
    last_seen_evidence = _find_evidence(sample_analysis_input, "incident.last_seen")
    action_evidence = _find_evidence(sample_analysis_input, "incident.action")

    return {
        "skill_version": "incident_senior_soc_v1",
        "incident_id": "5440222",
        "executive_summary": "FortiEDR blocked a cmd.exe execution on WS-01 for ACME\\alice and related context suggests suspicious but not yet confirmed malicious activity.",
        "risk_level": "high",
        "key_metadata": {
            "hostname": {"value": "WS-01", "evidence": [hostname_evidence.model_dump(mode="json")]},
            "user": {"value": "ACME\\alice", "evidence": [user_evidence.model_dump(mode="json")]},
            "process_name": {"value": "cmd.exe", "evidence": [process_evidence.model_dump(mode="json")]},
            "process_path": {"value": "C:\\Windows\\System32\\cmd.exe", "evidence": [process_path_evidence.model_dump(mode="json")]},
            "hashes": {"md5": None, "sha1": None, "sha256": None, "evidence": []},
            "severity": {"value": "High", "evidence": [severity_evidence.model_dump(mode="json")]},
            "classification": {"value": "Suspicious", "evidence": [classification_evidence.model_dump(mode="json")]},
            "first_seen": {"value": "2026-04-10T12:00:00Z", "evidence": [first_seen_evidence.model_dump(mode="json")]},
            "last_seen": {"value": "2026-04-10T12:05:00Z", "evidence": [last_seen_evidence.model_dump(mode="json")]},
            "action": {"value": "Blocked", "evidence": [action_evidence.model_dump(mode="json")]},
        },
        "observed_facts": [
            {
                "statement": "FortiEDR recorded a blocked cmd.exe execution on WS-01.",
                "evidence": [
                    hostname_evidence.model_dump(mode="json"),
                    process_evidence.model_dump(mode="json"),
                    action_evidence.model_dump(mode="json"),
                ],
            }
        ],
        "investigation_notes": [],
        "hypotheses": [],
        "possible_classification": {
            "label": "suspicious_activity_requiring_validation",
            "rationale": "The available data supports suspicious activity, but it is insufficient for a stronger label.",
        },
        "recommended_next_steps": {"immediate": [], "short_term": [], "validation": []},
        "missing_information": [],
        "verdict": "Blocked suspicious command execution on WS-01 requires analyst validation before stronger classification.",
    }


class FakeApiIncidentDataService(FakeIncidentDataService):
    def __init__(self, details):
        super().__init__(details)
        self.list_all_called = False
        self.list_all_calls: list[dict] = []
        self.list_calls: list[dict] = []
        self.id_search_calls: list[dict] = []
        self.process_search_calls: list[dict] = []
        self.host_search_calls: list[dict] = []

    def _empty_list_result(self, *, page_number: int, items_per_page: int):
        return IncidentListResult.model_validate({
            "organization": None,
            "page_number": page_number,
            "items_per_page": items_per_page,
            "count": 0,
            "incidents": [],
        })

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
    ):
        self.list_calls.append({
            "page_number": page_number,
            "items_per_page": items_per_page,
            "classification": classification,
            "severity": severity,
            "handled": handled,
            "archived": archived,
            "resolve_hosts": resolve_hosts,
        })
        incident = self._details.incident
        return IncidentListResult.model_validate({
            "organization": incident.organization,
            "page_number": page_number,
            "items_per_page": items_per_page,
            "count": 1,
            "incidents": [incident.model_dump(mode="json")],
        })

    def search_incidents_by_id(
        self,
        incident_id: int,
        *,
        classification: str | None = None,
        severity: str | None = None,
        handled: bool | None = None,
        archived: bool | None = None,
        resolve_hosts: bool = False,
    ):
        assert incident_id == 5440222
        self.id_search_calls.append({
            "incident_id": incident_id,
            "classification": classification,
            "severity": severity,
            "handled": handled,
            "archived": archived,
            "resolve_hosts": resolve_hosts,
        })
        return self.list_incidents(
            page_number=0,
            items_per_page=1,
            classification=classification,
            severity=severity,
            handled=handled,
            archived=archived,
            resolve_hosts=resolve_hosts,
        )

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
    ):
        self.process_search_calls.append({
            "process": process,
            "page_number": page_number,
            "items_per_page": items_per_page,
            "classification": classification,
            "severity": severity,
            "handled": handled,
            "archived": archived,
            "resolve_hosts": resolve_hosts,
        })
        if process != self._details.incident.process:
            return self._empty_list_result(page_number=page_number, items_per_page=items_per_page)
        return self.list_incidents(
            page_number=page_number,
            items_per_page=items_per_page,
            classification=classification,
            severity=severity,
            handled=handled,
            archived=archived,
            resolve_hosts=resolve_hosts,
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
    ):
        self.host_search_calls.append({
            "host": host,
            "page_number": page_number,
            "items_per_page": items_per_page,
            "classification": classification,
            "severity": severity,
            "handled": handled,
            "archived": archived,
            "resolve_hosts": resolve_hosts,
        })
        if host != self._details.incident.host:
            return self._empty_list_result(page_number=page_number, items_per_page=items_per_page)
        return self.list_incidents(
            page_number=page_number,
            items_per_page=items_per_page,
            classification=classification,
            severity=severity,
            handled=handled,
            archived=archived,
            resolve_hosts=resolve_hosts,
        )

    def list_all_incidents(
        self,
        *,
        items_per_page: int = 1000,
        classification: str | None = None,
        severity: str | None = None,
        handled: bool | None = None,
        archived: bool | None = None,
        resolve_hosts: bool = False,
    ):
        self.list_all_called = True
        self.list_all_calls.append({
            "items_per_page": items_per_page,
            "classification": classification,
            "severity": severity,
            "handled": handled,
            "archived": archived,
            "resolve_hosts": resolve_hosts,
        })
        return self.list_incidents(
            page_number=0,
            items_per_page=items_per_page,
            classification=classification,
            severity=severity,
            handled=handled,
            archived=archived,
            resolve_hosts=resolve_hosts,
        )


def test_api_analyze_latest_and_history(
    tmp_path,
    sample_incident_details,
    sample_analysis_input,
    monkeypatch,
):
    monkeypatch.setenv("FORTIEDR_ENABLE_DB_RESET", "false")
    data_service = FakeApiIncidentDataService(sample_incident_details)
    repository = AnalysisRunRepository(tmp_path / "analysis.sqlite3")
    analysis_service = IncidentAnalysisService(
        data_service=data_service,
        llm_client=MockStructuredLLMClient(_valid_response(sample_analysis_input)),
    )
    run_service = AnalysisRunService(
        analysis_service=analysis_service,
        repository=repository,
    )
    client = TestClient(create_app(data_service=data_service, analysis_run_service=run_service))

    analyze_response = client.post("/incidents/5440222/analyze", json={"analysis_profile": "lite"})
    run_id = analyze_response.json()["run"]["run_id"]
    latest_response = client.get("/incidents/5440222/analysis/latest")
    history_response = client.get("/incidents/5440222/analysis/history")
    detail_response = client.get(f"/analysis/runs/{run_id}")
    feedback_post = client.post(
        f"/analysis/runs/{run_id}/feedback",
        json={
            "usefulness": "useful",
            "correctness": "partially_correct",
            "analyst_classification": "needs_validation",
            "comment": "Needs confirmation before escalation.",
        },
    )
    feedback_get = client.get(f"/analysis/runs/{run_id}/feedback")
    detail_after_feedback = client.get(f"/analysis/runs/{run_id}")
    list_response = client.get("/incidents?all=true")
    incident_response = client.get("/incidents/5440222")
    models_response = client.get("/analysis/models")
    portal_redirect = client.get("/", follow_redirects=False)
    portal_index = client.get("/portal")
    portal_incident = client.get("/portal/incidents/5440222")
    portal_run = client.get(f"/portal/runs/{run_id}")
    portal_static = client.get("/portal/static/styles.css")
    favicon_response = client.get("/favicon.ico")

    assert analyze_response.status_code == 200
    assert analyze_response.json()["run"]["validated_output"]["skill_version"] == "incident_senior_soc_v1"
    assert analyze_response.json()["run"]["source_fingerprint"] is not None
    assert portal_redirect.status_code == 307
    assert portal_redirect.headers["location"] == "/portal"
    assert portal_index.status_code == 200
    assert "FortiEDR Virtual Security Analyst" in portal_index.text
    assert portal_incident.status_code == 200
    assert "Incident Detail" in portal_incident.text
    assert portal_run.status_code == 200
    assert "Analysis Run" in portal_run.text
    assert portal_static.status_code == 200
    assert "background" in portal_static.text
    assert favicon_response.status_code == 200
    assert list_response.status_code == 200
    assert list_response.json()["count"] == 1
    assert data_service.list_all_called is True
    assert data_service.list_all_calls == [
        {
            "items_per_page": 1000,
            "classification": None,
            "severity": None,
            "handled": None,
            "archived": None,
            "resolve_hosts": False,
        }
    ]
    assert list_response.json()["incidents"][0]["analysis"]["exists"] is True
    assert list_response.json()["incidents"][0]["analysis"]["run_id"] == run_id
    assert list_response.json()["incidents"][0]["rules"] == ["Execution Prevention", "Malicious File Detected"]
    assert models_response.status_code == 200
    assert "options" in models_response.json()
    assert models_response.json()["default_profile"] == "standard"
    assert [profile["name"] for profile in models_response.json()["analysis_profiles"]] == [
        "lite",
        "standard",
        "full",
    ]
    assert models_response.json()["capabilities"]["allow_db_reset"] is False
    assert incident_response.status_code == 200
    assert incident_response.json()["incident"]["incident_id"] == 5440222
    assert "derived_hashes" in incident_response.json()
    assert incident_response.json()["derived_context"]["matched_rules"] == [
        "Execution Prevention",
        "Malicious File Detected",
    ]
    assert incident_response.json()["derived_context"]["violated_policies"] == [
        "POD - Execution Prevention"
    ]
    assert incident_response.json()["derived_context"]["matched_rule_descriptions"][0]["rule_name"] == "Malicious File Detected"
    assert incident_response.json()["derived_context"]["process_stack"][-1]["highlighted"] is True
    assert latest_response.status_code == 200
    assert latest_response.json()["status"] == "success"
    assert history_response.status_code == 200
    assert history_response.json()["count"] == 1
    assert history_response.json()["runs"][0]["status"] == "success"
    assert detail_response.status_code == 200
    assert detail_response.json()["run_id"] == run_id
    assert detail_response.json()["source_context"]["analysis_profile"] == "lite"
    assert detail_response.json()["normalized_input"] is not None
    assert detail_response.json()["llm_output"] is not None
    assert feedback_post.status_code == 200
    assert feedback_post.json()["feedback"]["analyst_classification"] == "needs_validation"
    assert feedback_get.status_code == 200
    assert feedback_get.json()["feedback"]["correctness"] == "partially_correct"
    assert detail_after_feedback.status_code == 200
    assert detail_after_feedback.json()["analyst_feedback"]["usefulness"] == "useful"


def test_api_list_supports_pagination_and_server_side_search(
    tmp_path,
    sample_incident_details,
    sample_analysis_input,
    monkeypatch,
):
    monkeypatch.setenv("FORTIEDR_ENABLE_DB_RESET", "false")
    data_service = FakeApiIncidentDataService(sample_incident_details)
    repository = AnalysisRunRepository(tmp_path / "analysis.sqlite3")
    analysis_service = IncidentAnalysisService(
        data_service=data_service,
        llm_client=MockStructuredLLMClient(_valid_response(sample_analysis_input)),
    )
    run_service = AnalysisRunService(
        analysis_service=analysis_service,
        repository=repository,
    )
    client = TestClient(create_app(data_service=data_service, analysis_run_service=run_service))

    paged_response = client.get("/incidents?page_number=0&items_per_page=1")
    process_search_response = client.get(
        "/incidents?query=cmd.exe&page_number=1&items_per_page=50&classification=Malicious&severity=Critical"
    )
    global_host_search_response = client.get(
        "/incidents?query=WS-01&page_number=0&items_per_page=25"
    )
    host_search_response = client.get("/incidents/search/host?host=WS-01&page_number=0&items_per_page=25")

    assert paged_response.status_code == 200
    assert paged_response.json()["count"] == 1
    assert paged_response.json()["has_more"] is True
    assert paged_response.json()["next_page_number"] == 1
    assert data_service.list_calls[0] == {
        "page_number": 0,
        "items_per_page": 1,
        "classification": None,
        "severity": None,
        "handled": None,
        "archived": None,
        "resolve_hosts": True,
    }

    assert process_search_response.status_code == 200
    assert process_search_response.json()["count"] == 1
    assert data_service.process_search_calls[0] == {
        "process": "cmd.exe",
        "page_number": 1,
        "items_per_page": 50,
        "classification": "Malicious",
        "severity": "Critical",
        "handled": None,
        "archived": None,
        "resolve_hosts": True,
    }

    assert global_host_search_response.status_code == 200
    assert global_host_search_response.json()["count"] == 1

    assert host_search_response.status_code == 200
    assert data_service.host_search_calls == [
        {
            "host": "WS-01",
            "page_number": 0,
            "items_per_page": 25,
            "classification": None,
            "severity": None,
            "handled": None,
            "archived": None,
            "resolve_hosts": True,
        },
        {
            "host": "WS-01",
            "page_number": 0,
            "items_per_page": 25,
            "classification": None,
            "severity": None,
            "handled": None,
            "archived": None,
            "resolve_hosts": False,
        }
    ]
    assert data_service.process_search_calls[-1] == {
        "process": "WS-01",
        "page_number": 0,
        "items_per_page": 25,
        "classification": None,
        "severity": None,
        "handled": None,
        "archived": None,
        "resolve_hosts": True,
    }


def test_api_can_clear_analysis_database_when_enabled(
    tmp_path,
    sample_incident_details,
    sample_analysis_input,
    monkeypatch,
):
    monkeypatch.setenv("FORTIEDR_ENABLE_DB_RESET", "true")
    data_service = FakeApiIncidentDataService(sample_incident_details)
    repository = AnalysisRunRepository(tmp_path / "analysis.sqlite3")
    analysis_service = IncidentAnalysisService(
        data_service=data_service,
        llm_client=MockStructuredLLMClient(_valid_response(sample_analysis_input)),
    )
    run_service = AnalysisRunService(
        analysis_service=analysis_service,
        repository=repository,
    )
    client = TestClient(create_app(data_service=data_service, analysis_run_service=run_service))

    analyze_response = client.post("/incidents/5440222/analyze", json={})
    clear_response = client.post("/analysis/database/clear", json={})
    history_response = client.get("/incidents/5440222/analysis/history")
    models_response = client.get("/analysis/models")

    assert analyze_response.status_code == 200
    assert clear_response.status_code == 200
    assert clear_response.json()["cleared"] is True
    assert clear_response.json()["deleted_runs"] == 1
    assert history_response.status_code == 200
    assert history_response.json()["count"] == 0
    assert models_response.json()["capabilities"]["allow_db_reset"] is True


def test_incident_detail_uses_raw_hostname_when_device_field_is_absent(
    tmp_path,
    sample_incident_details,
    sample_analysis_input,
):
    details = sample_incident_details.model_copy(deep=True)
    details.incident.host = None
    details.raw_data_items[0].pop("device", None)
    details.raw_data_items[0]["HostName"] = "win-edr-2"

    data_service = FakeApiIncidentDataService(details)
    repository = AnalysisRunRepository(tmp_path / "analysis.sqlite3")
    analysis_service = IncidentAnalysisService(
        data_service=data_service,
        llm_client=MockStructuredLLMClient(_valid_response(sample_analysis_input)),
    )
    run_service = AnalysisRunService(
        analysis_service=analysis_service,
        repository=repository,
    )
    client = TestClient(create_app(data_service=data_service, analysis_run_service=run_service))

    incident_response = client.get("/incidents/5440222")

    assert incident_response.status_code == 200
    assert incident_response.json()["incident"]["host"] == "win-edr-2"


def test_api_settings_endpoints_support_read_test_and_save(
    tmp_path,
    sample_incident_details,
    sample_analysis_input,
    monkeypatch,
):
    monkeypatch.setenv("FORTIEDR_ANALYSIS_ENGINE_SOURCE", "")
    monkeypatch.setenv("FORTIEDR_LLM_SERVER_PROVIDER", "")
    monkeypatch.setenv("FORTIEDR_LLM_SERVER_URL", "")
    monkeypatch.setenv("OLLAMA_BASE_URL", "")
    monkeypatch.setenv("OLLAMA_MODEL", "")
    monkeypatch.setenv("OLLAMA_AVAILABLE_MODELS", "")
    monkeypatch.setenv("FORTIEDR_HOST", "fortiedr.initial.local")
    monkeypatch.setenv("FORTIEDR_ORG", "InitialOrg")
    monkeypatch.setenv("FORTIEDR_USER", "initial-user")
    monkeypatch.setenv("FORTIEDR_PASS", "initial-pass")
    monkeypatch.setenv("FORTIEDR_DOTENV_PATH", str(tmp_path / ".env"))

    data_service = FakeApiIncidentDataService(sample_incident_details)
    repository = AnalysisRunRepository(tmp_path / "analysis.sqlite3")
    analysis_service = IncidentAnalysisService(
        data_service=data_service,
        llm_client=MockStructuredLLMClient(_valid_response(sample_analysis_input)),
    )
    run_service = AnalysisRunService(
        analysis_service=analysis_service,
        repository=repository,
    )
    client = TestClient(create_app(data_service=data_service, analysis_run_service=run_service))

    def fake_list_events(self, **filters):
        return []

    monkeypatch.setattr("fortiedr_mcp.api.app.FortiEDRClient.list_events", fake_list_events)

    current_settings = client.get("/settings")
    test_connection = client.post(
        "/settings/test-connection",
        json={
            "host": "fortiedr.next.local",
            "organization": "NextOrg",
            "user": "next-user",
            "password": "next-pass",
            "engine_source": "private",
            "llm_server_provider": "ollama",
            "llm_server_url": "http://10.163.3.76:11434/",
            "llm_server_model": "qwen2.5:14b",
        },
    )
    monkeypatch.setattr(
        "fortiedr_mcp.api.app.probe_remote_llm_server",
        lambda provider, *, base_url: {
            "provider": provider,
            "base_url": "http://10.163.3.76:11434",
            "models": ["qwen2.5:14b"],
        },
    )
    test_llm_connection = client.post(
        "/settings/test-llm",
        json={
            "host": "fortiedr.next.local",
            "organization": "NextOrg",
            "user": "next-user",
            "password": "next-pass",
            "engine_source": "private",
            "llm_server_provider": "ollama",
            "llm_server_url": "http://10.163.3.76:11434/",
            "llm_server_model": "qwen2.5:14b",
        },
    )
    save_settings = client.post(
        "/settings",
        json={
            "host": "fortiedr.saved.local",
            "organization": "SavedOrg",
            "user": "saved-user",
            "password": "saved-pass",
            "engine_source": "private",
            "llm_server_provider": "ollama",
            "llm_server_url": "http://10.163.3.76:11434/",
            "llm_server_model": "qwen2.5:14b",
        },
    )

    assert current_settings.status_code == 200
    assert current_settings.json()["host"] == "fortiedr.initial.local"
    assert current_settings.json()["organization"] == "InitialOrg"
    assert current_settings.json()["engine_source"] == "public"
    assert current_settings.json()["llm_server_provider"] == ""
    assert current_settings.json()["llm_server_url"] == ""
    assert current_settings.json()["llm_server_model"] == ""
    assert test_connection.status_code == 200
    assert test_connection.json()["ok"] is True
    assert test_llm_connection.status_code == 200
    assert test_llm_connection.json()["provider"] == "ollama"
    assert test_llm_connection.json()["base_url"] == "http://10.163.3.76:11434"
    assert test_llm_connection.json()["model_count"] == 1
    assert save_settings.status_code == 200
    assert save_settings.json()["saved"] is True
    dotenv_contents = (tmp_path / ".env").read_text(encoding="utf-8")
    assert 'FORTIEDR_HOST="fortiedr.saved.local"' in dotenv_contents
    assert 'FORTIEDR_ORG="SavedOrg"' in dotenv_contents
    assert 'FORTIEDR_USER="saved-user"' in dotenv_contents
    assert 'FORTIEDR_PASS="saved-pass"' in dotenv_contents
    assert 'FORTIEDR_ANALYSIS_ENGINE_SOURCE="private"' in dotenv_contents
    assert 'FORTIEDR_LLM_SERVER_PROVIDER="ollama"' in dotenv_contents
    assert 'FORTIEDR_LLM_SERVER_URL="http://10.163.3.76:11434/"' in dotenv_contents
    assert 'OLLAMA_BASE_URL="http://10.163.3.76:11434/"' in dotenv_contents
    assert 'OLLAMA_MODEL="qwen2.5:14b"' in dotenv_contents
    assert 'OLLAMA_AVAILABLE_MODELS="qwen2.5:14b"' in dotenv_contents
    assert os.environ["FORTIEDR_HOST"] == "fortiedr.saved.local"
    assert os.environ["FORTIEDR_ANALYSIS_ENGINE_SOURCE"] == "private"
    assert os.environ["FORTIEDR_LLM_SERVER_PROVIDER"] == "ollama"
    assert os.environ["FORTIEDR_LLM_SERVER_URL"] == "http://10.163.3.76:11434/"
    assert os.environ["OLLAMA_BASE_URL"] == "http://10.163.3.76:11434/"
    assert os.environ["OLLAMA_MODEL"] == "qwen2.5:14b"
    assert os.environ["OLLAMA_AVAILABLE_MODELS"] == "qwen2.5:14b"


def test_resolve_requested_llm_config_prefers_private_engine_settings(monkeypatch):
    monkeypatch.setenv("FORTIEDR_ANALYSIS_ENGINE_SOURCE", "private")
    monkeypatch.setenv("OLLAMA_MODEL", "qwen2.5:7b")

    provider, model_name = _resolve_requested_llm_config("openai", "gpt-4.1-mini")

    assert provider == "ollama"
    assert model_name == "qwen2.5:7b"


def test_resolve_requested_llm_config_uses_public_provider_when_public_engine(monkeypatch):
    monkeypatch.setenv("FORTIEDR_ANALYSIS_ENGINE_SOURCE", "public")
    monkeypatch.setenv("OLLAMA_MODEL", "qwen2.5:7b")

    provider, model_name = _resolve_requested_llm_config("openai", "gpt-4.1-mini")

    assert provider == "openai"
    assert model_name == "gpt-4.1-mini"
