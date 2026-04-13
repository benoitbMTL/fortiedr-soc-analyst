from __future__ import annotations

import argparse
import json
import os
import re
from functools import lru_cache
from pathlib import Path
from typing import Any, Literal

from dotenv import load_dotenv
from pydantic import BaseModel, ValidationError
from starlette.applications import Starlette
from starlette.requests import Request
from starlette.responses import FileResponse, JSONResponse, RedirectResponse
from starlette.routing import Mount, Route
from starlette.staticfiles import StaticFiles

from fortiedr_mcp.config import FortiEDRConfig
from fortiedr_mcp.analysis.context import IncidentAnalysisInputBuilder
from fortiedr_mcp.analysis.profiles import list_analysis_profiles
from fortiedr_mcp.errors import (
    FortiEDRAPIError,
    FortiEDRAuthenticationError,
    FortiEDRConfigurationError,
    FortiEDRError,
    FortiEDRLLMConfigurationError,
    FortiEDRLLMResponseError,
    FortiEDRLLMTimeoutError,
    FortiEDRNotFoundError,
    FortiEDRPersistenceError,
    FortiEDRSkillNotFoundError,
    FortiEDRValidationError,
)
from fortiedr_mcp.fortiedr_client import FortiEDRClient
from fortiedr_mcp.llm import build_llm_client, get_available_llm_options, probe_remote_llm_server
from fortiedr_mcp.models import AnalysisRunExecution, AnalysisRunRecord, AnalysisRunStatus
from fortiedr_mcp.repositories import AnalysisRunRepository
from fortiedr_mcp.services import AnalysisRunService, IncidentAnalysisService, IncidentDataService


PORTAL_DIR = Path(__file__).resolve().parents[1] / "portal"
SETTINGS_ENV_KEYS = (
    "FORTIEDR_HOST",
    "FORTIEDR_ORG",
    "FORTIEDR_USER",
    "FORTIEDR_PASS",
    "FORTIEDR_ANALYSIS_ENGINE_SOURCE",
    "FORTIEDR_LLM_SERVER_PROVIDER",
    "FORTIEDR_LLM_SERVER_URL",
    "OLLAMA_BASE_URL",
    "OLLAMA_MODEL",
    "OLLAMA_AVAILABLE_MODELS",
)
SETTINGS_FIELD_BY_ENV_KEY = {
    "FORTIEDR_HOST": "host",
    "FORTIEDR_ORG": "organization",
    "FORTIEDR_USER": "user",
    "FORTIEDR_PASS": "password",
    "FORTIEDR_ANALYSIS_ENGINE_SOURCE": "engine_source",
    "FORTIEDR_LLM_SERVER_PROVIDER": "llm_server_provider",
    "FORTIEDR_LLM_SERVER_URL": "llm_server_url",
    "OLLAMA_BASE_URL": "llm_server_url",
    "OLLAMA_MODEL": "llm_server_model",
    "OLLAMA_AVAILABLE_MODELS": "llm_server_available_models",
}


def _load_project_dotenv() -> Path:
    project_root = Path(__file__).resolve().parents[3]
    dotenv_path = project_root / ".env"
    if dotenv_path.exists():
        load_dotenv(dotenv_path, override=False)
    return project_root


def _project_dotenv_path() -> Path:
    override = os.getenv("FORTIEDR_DOTENV_PATH")
    if override:
        return Path(override)
    return _load_project_dotenv() / ".env"


def _parse_bool(value: str | None, *, default: bool) -> bool:
    if value is None:
        return default
    normalized = value.strip().lower()
    if normalized in {"1", "true", "yes", "on"}:
        return True
    if normalized in {"0", "false", "no", "off"}:
        return False
    raise ValueError("Expected a boolean value.")


def _parse_int(value: str | None, *, default: int) -> int:
    if value is None:
        return default
    return int(value)


def _db_reset_enabled() -> bool:
    return _parse_bool(os.getenv("FORTIEDR_ENABLE_DB_RESET"), default=False)


def _timeout_seconds_from_env() -> float:
    raw = os.getenv("FORTIEDR_TIMEOUT_SECONDS", "30").strip()
    return float(raw)


def _list_cache_ttl_seconds_from_env() -> float:
    raw = os.getenv("FORTIEDR_LIST_CACHE_TTL_SECONDS", "30").strip()
    return float(raw)


def _current_fortiedr_settings() -> dict[str, str]:
    _load_project_dotenv()
    engine_source = os.getenv("FORTIEDR_ANALYSIS_ENGINE_SOURCE", "").strip().lower()
    llm_server_provider = os.getenv("FORTIEDR_LLM_SERVER_PROVIDER", "").strip().lower()
    llm_server_url = os.getenv("FORTIEDR_LLM_SERVER_URL") or os.getenv("OLLAMA_BASE_URL", "")
    if engine_source not in {"public", "private"}:
        if llm_server_url and not (
            (os.getenv("OPENAI_API_KEY") and os.getenv("OPENAI_MODEL"))
            or (os.getenv("ANTHROPIC_API_KEY") and os.getenv("ANTHROPIC_MODEL"))
        ):
            engine_source = "private"
        else:
            engine_source = "public"
    return {
        "host": os.getenv("FORTIEDR_HOST", ""),
        "organization": os.getenv("FORTIEDR_ORG", ""),
        "user": os.getenv("FORTIEDR_USER") or os.getenv("FORTIEDR_API_USER") or "",
        "password": os.getenv("FORTIEDR_PASS") or os.getenv("FORTIEDR_API_PASSWORD") or "",
        "engine_source": engine_source,
        "llm_server_provider": llm_server_provider or ("ollama" if llm_server_url else ""),
        "llm_server_url": llm_server_url,
        "llm_server_model": os.getenv("OLLAMA_MODEL", ""),
        "llm_server_available_models": os.getenv("OLLAMA_AVAILABLE_MODELS", ""),
    }


def _dotenv_quote(value: str) -> str:
    return json.dumps(value)


def _write_fortiedr_settings_to_dotenv(settings: dict[str, str]) -> None:
    dotenv_path = _project_dotenv_path()
    existing_lines = dotenv_path.read_text(encoding="utf-8").splitlines() if dotenv_path.exists() else []
    updated_lines: list[str] = []
    remaining = set(SETTINGS_ENV_KEYS)

    for line in existing_lines:
        stripped = line.lstrip()
        updated = False
        for env_key in SETTINGS_ENV_KEYS:
            if re.match(rf"^(export\s+)?{re.escape(env_key)}=", stripped):
                field_key = SETTINGS_FIELD_BY_ENV_KEY[env_key]
                updated_lines.append(f"{env_key}={_dotenv_quote(settings[field_key])}")
                remaining.discard(env_key)
                updated = True
                break
        if not updated:
            updated_lines.append(line)

    if remaining and updated_lines and updated_lines[-1].strip():
        updated_lines.append("")

    for env_key in SETTINGS_ENV_KEYS:
        if env_key not in remaining:
            continue
        field_key = SETTINGS_FIELD_BY_ENV_KEY[env_key]
        updated_lines.append(f"{env_key}={_dotenv_quote(settings[field_key])}")

    dotenv_path.write_text("\n".join(updated_lines) + "\n", encoding="utf-8")


def _apply_runtime_fortiedr_settings(app: Starlette, settings: dict[str, str]) -> None:
    os.environ["FORTIEDR_HOST"] = settings["host"]
    os.environ["FORTIEDR_ORG"] = settings["organization"]
    os.environ["FORTIEDR_USER"] = settings["user"]
    os.environ["FORTIEDR_PASS"] = settings["password"]
    os.environ["FORTIEDR_ANALYSIS_ENGINE_SOURCE"] = settings["engine_source"]
    os.environ["FORTIEDR_LLM_SERVER_PROVIDER"] = settings["llm_server_provider"]
    os.environ["FORTIEDR_LLM_SERVER_URL"] = settings["llm_server_url"]
    os.environ["OLLAMA_BASE_URL"] = settings["llm_server_url"]
    os.environ["OLLAMA_MODEL"] = settings["llm_server_model"]
    os.environ["OLLAMA_AVAILABLE_MODELS"] = settings["llm_server_available_models"]

    get_data_service.cache_clear()
    get_analysis_run_service.cache_clear()

    if getattr(app.state, "uses_default_data_service", False):
        app.state.data_service = get_data_service()
    if getattr(app.state, "uses_default_analysis_run_service", False):
        app.state.analysis_run_service = get_analysis_run_service()
        app.state.analysis_run_service_factory = build_analysis_run_service


def _build_settings_config(settings: dict[str, str]) -> FortiEDRConfig:
    return FortiEDRConfig.from_values(
        host=settings["host"],
        user=settings["user"],
        password=settings["password"],
        organization=settings.get("organization"),
        verify_ssl=_parse_bool(os.getenv("FORTIEDR_VERIFY_SSL"), default=True),
        timeout_seconds=_timeout_seconds_from_env(),
    )


def _serialize_run(
    run: AnalysisRunRecord,
    *,
    include_input: bool = False,
    include_llm_output: bool = False,
) -> dict[str, Any]:
    exclude: set[str] = set()
    if not include_input:
        exclude.add("normalized_input")
    if not include_llm_output:
        exclude.add("llm_output")
    return run.model_dump(mode="json", exclude=exclude)


def _portal_file_response(filename: str) -> FileResponse:
    return FileResponse(PORTAL_DIR / filename)


async def favicon(request: Request) -> FileResponse:
    return FileResponse(PORTAL_DIR / "favicon.ico", media_type="image/x-icon")


_analysis_input_builder = IncidentAnalysisInputBuilder()

FORTIEDR_ASCII = """\
███████╗ ██████╗ ██████╗ ████████╗██╗███████╗██████╗ ██████╗
██╔════╝██╔═══██╗██╔══██╗╚══██╔══╝██║██╔════╝██╔══██╗██╔══██╗
█████╗  ██║   ██║██████╔╝   ██║   ██║█████╗  ██║  ██║██████╔╝
██╔══╝  ██║   ██║██╔══██╗   ██║   ██║██╔══╝  ██║  ██║██╔══██╗
██║     ╚██████╔╝██║  ██║   ██║   ██║███████╗██████╔╝██║  ██║
╚═╝      ╚═════╝ ╚═╝  ╚═╝   ╚═╝   ╚═╝╚══════╝╚═════╝ ╚═╝  ╚═╝
"""


def _print_startup_banner(*, host: str, port: int, db_path: str) -> None:
    supports_color = os.getenv("TERM") not in {None, "", "dumb"}
    accent = "\033[36m" if supports_color else ""
    muted = "\033[90m" if supports_color else ""
    reset = "\033[0m" if supports_color else ""
    banner = f"""
{accent}{FORTIEDR_ASCII.rstrip()}{reset}

{muted}Structured incident analysis backend
Portal: http://{host}:{port}/portal
API:    http://{host}:{port}/incidents
DB:     {db_path}{reset}
Reset:  {"enabled" if _db_reset_enabled() else "disabled"}{reset}
"""
    print(banner)


def _serialize_analysis_list_summary(run: AnalysisRunRecord | None) -> dict[str, Any]:
    if run is None:
        return {
            "exists": False,
            "run_id": None,
            "created_at": None,
            "completed_at": None,
            "status": None,
            "validation_status": None,
            "skill_version": None,
            "provider": None,
            "model_name": None,
        }

    payload = run.model_dump(mode="json")
    return {
        "exists": True,
        "run_id": payload["run_id"],
        "created_at": payload["created_at"],
        "completed_at": payload["completed_at"],
        "status": payload["status"],
        "validation_status": payload["validation_status"],
        "skill_version": payload["skill_version"],
        "provider": payload["llm_provider"],
        "model_name": payload["model_name"],
    }


def _host_from_raw_data_items(raw_data_items: list[dict[str, Any]]) -> str | None:
    for item in raw_data_items:
        for field in ("HostName", "hostName", "hostname", "host", "device"):
            value = item.get(field)
            if isinstance(value, str) and value.strip():
                return value.strip()
    return None


def _execution_status_code(execution: AnalysisRunExecution) -> int:
    if execution.run.status == AnalysisRunStatus.RUNNING:
        return 202
    if execution.run.status == AnalysisRunStatus.SUCCESS:
        return 200

    code = execution.run.error.code if execution.run.error else "analysis_failed"
    if code == "incident_not_found":
        return 404
    if code == "skill_not_found":
        return 400
    if code == "invalid_request":
        return 400
    if code == "llm_timeout":
        return 504
    if code in {"schema_validation_failed", "evidence_validation_failed"}:
        return 422
    if code == "llm_configuration_error":
        return 500
    if code == "source_authentication_failed":
        return 502
    if code == "source_retrieval_failed":
        return 502
    if code == "llm_response_error":
        return 502
    return 500


def _error_response(exc: Exception, *, status_code: int | None = None) -> JSONResponse:
    if status_code is None:
        if isinstance(exc, FortiEDRNotFoundError):
            status_code = 404
        elif isinstance(exc, FortiEDRSkillNotFoundError):
            status_code = 400
        elif isinstance(exc, ValueError):
            status_code = 400
        elif isinstance(exc, FortiEDRConfigurationError):
            status_code = 400
        elif isinstance(exc, FortiEDRValidationError):
            status_code = 422
        elif isinstance(exc, FortiEDRLLMTimeoutError):
            status_code = 504
        elif isinstance(exc, (FortiEDRAPIError, FortiEDRAuthenticationError, FortiEDRLLMResponseError)):
            status_code = 502
        elif isinstance(exc, (FortiEDRPersistenceError, FortiEDRLLMConfigurationError)):
            status_code = 500
        elif isinstance(exc, FortiEDRError):
            status_code = 500
        else:
            status_code = 500

    code = "internal_error"
    if isinstance(exc, FortiEDRNotFoundError):
        code = "not_found"
    elif isinstance(exc, FortiEDRSkillNotFoundError):
        code = "skill_not_found"
    elif isinstance(exc, ValueError):
        code = "invalid_request"
    elif isinstance(exc, FortiEDRConfigurationError):
        code = "invalid_configuration"
    elif isinstance(exc, FortiEDRPersistenceError):
        code = "persistence_error"
    elif isinstance(exc, FortiEDRValidationError):
        code = "validation_error"
    elif isinstance(exc, FortiEDRLLMTimeoutError):
        code = "llm_timeout"
    elif isinstance(exc, FortiEDRLLMConfigurationError):
        code = "llm_configuration_error"
    elif isinstance(exc, FortiEDRLLMResponseError):
        code = "llm_response_error"
    elif isinstance(exc, FortiEDRAPIError):
        code = "source_retrieval_failed"
    elif isinstance(exc, FortiEDRAuthenticationError):
        code = "source_authentication_failed"

    payload: dict[str, Any] = {"error": {"code": code, "message": str(exc)}}
    if isinstance(exc, FortiEDRValidationError) and exc.details:
        payload["error"]["details"] = exc.details
    return JSONResponse(payload, status_code=status_code)


class AnalyzeIncidentRequest(BaseModel):
    skill_name: str = "incident_senior_soc_v1"
    provider: str = "auto"
    model_name: str | None = None
    analysis_profile: Literal["lite", "standard", "full"] = "standard"
    raw_data_limit: int | None = None
    related_limit: int | None = None
    collector_limit: int | None = None
    include_host_context: bool | None = None
    include_related_events: bool | None = None
    include_forensics: bool | None = None
    force: bool = False
    async_run: bool = False
    include_input_in_response: bool = False
    include_llm_output_in_response: bool = False


class RunFeedbackRequest(BaseModel):
    usefulness: Literal["useful", "not_useful"] | None = None
    correctness: Literal["correct", "partially_correct", "incorrect"] | None = None
    analyst_classification: (
        Literal["benign", "false_positive", "red_team", "malicious", "needs_validation"] | None
    ) = None
    comment: str | None = None


class BackendSettingsRequest(BaseModel):
    host: str
    organization: str = ""
    user: str
    password: str
    engine_source: Literal["public", "private"] = "public"
    llm_server_provider: Literal["", "ollama"] = ""
    llm_server_url: str = ""
    llm_server_model: str = ""
    llm_server_available_models: str = ""


def _resolve_requested_llm_config(provider: str, model_name: str | None) -> tuple[str, str | None]:
    engine_source = _current_fortiedr_settings()["engine_source"]
    normalized_provider = provider.strip().lower()

    if engine_source == "private":
        return "ollama", os.getenv("OLLAMA_MODEL") or model_name

    if normalized_provider in {"openai", "anthropic"}:
        return normalized_provider, model_name
    return "auto", None


@lru_cache(maxsize=1)
def get_data_service() -> IncidentDataService:
    _load_project_dotenv()
    return IncidentDataService(
        FortiEDRClient(FortiEDRConfig.from_env()),
        list_cache_ttl_seconds=_list_cache_ttl_seconds_from_env(),
    )


@lru_cache(maxsize=1)
def get_analysis_run_repository() -> AnalysisRunRepository:
    project_root = _load_project_dotenv()
    database_path = os.getenv(
        "FORTIEDR_ANALYSIS_DB_PATH",
        str(project_root / "data" / "analysis_runs.sqlite3"),
    )
    return AnalysisRunRepository(database_path)


def build_analysis_run_service(
    *,
    provider: str = "auto",
    model_name: str | None = None,
) -> AnalysisRunService:
    data_service = get_data_service()
    analysis_service = IncidentAnalysisService(
        data_service=data_service,
        llm_client=build_llm_client(provider, model_name=model_name),
    )
    return AnalysisRunService(
        analysis_service=analysis_service,
        repository=get_analysis_run_repository(),
    )


@lru_cache(maxsize=1)
def get_analysis_run_service() -> AnalysisRunService:
    return build_analysis_run_service()


def _request_analysis_run_service(
    request: Request,
    *,
    provider: str = "auto",
    model_name: str | None = None,
) -> AnalysisRunService:
    factory = getattr(request.app.state, "analysis_run_service_factory", None)
    if factory is None:
        return request.app.state.analysis_run_service
    return factory(provider=provider, model_name=model_name)


def _optional_query_param(value: str | None) -> str | None:
    if value is None:
        return None
    stripped = value.strip()
    return stripped or None


def _serialize_incident_list_payload(
    request: Request,
    result,
) -> dict[str, Any]:
    payload = result.model_dump(mode="json")
    payload["has_more"] = bool(result.incidents) and len(result.incidents) == result.items_per_page
    payload["next_page_number"] = result.page_number + 1 if payload["has_more"] else None
    latest_runs = request.app.state.analysis_run_service.get_latest_runs_for_incidents(
        [incident.incident_id for incident in result.incidents]
    )
    for incident_payload in payload["incidents"]:
        incident_payload["analysis"] = _serialize_analysis_list_summary(
            latest_runs.get(str(incident_payload["incident_id"]))
        )
    return payload


def _search_incident_list(
    data_service: IncidentDataService,
    *,
    query: str,
    page_number: int,
    items_per_page: int,
    classification: str | None = None,
    severity: str | None = None,
    handled: bool | None = None,
    archived: bool | None = None,
    resolve_hosts: bool = False,
):
    if query.isdigit():
        return data_service.search_incidents_by_id(
            int(query),
            classification=classification,
            severity=severity,
            handled=handled,
            archived=archived,
            resolve_hosts=resolve_hosts,
        )

    process_result = data_service.search_incidents_by_process(
        query,
        page_number=page_number,
        items_per_page=items_per_page,
        classification=classification,
        severity=severity,
        handled=handled,
        archived=archived,
        resolve_hosts=resolve_hosts,
    )
    if process_result.incidents:
        return process_result

    return data_service.search_incidents_by_host(
        query,
        page_number=page_number,
        items_per_page=items_per_page,
        classification=classification,
        severity=severity,
        handled=handled,
        archived=archived,
        resolve_hosts=resolve_hosts,
    )


async def list_incidents(request: Request) -> JSONResponse:
    try:
        include_all = (
            _parse_bool(request.query_params.get("all"), default=False)
            if request.query_params.get("all") is not None
            else False
        )
        page_number = _parse_int(request.query_params.get("page_number"), default=0)
        query = _optional_query_param(request.query_params.get("query"))
        classification = _optional_query_param(request.query_params.get("classification"))
        severity = _optional_query_param(request.query_params.get("severity"))
        handled = (
            _parse_bool(request.query_params.get("handled"), default=False)
            if request.query_params.get("handled") is not None
            else None
        )
        archived = (
            _parse_bool(request.query_params.get("archived"), default=False)
            if request.query_params.get("archived") is not None
            else None
        )
        resolve_hosts = not include_all
        list_kwargs = {
            "items_per_page": _parse_int(
                request.query_params.get("items_per_page"),
                default=1000 if include_all else 25,
            ),
            "classification": classification,
            "severity": severity,
            "handled": handled,
            "archived": archived,
            "resolve_hosts": resolve_hosts,
        }
        if query:
            result = _search_incident_list(
                request.app.state.data_service,
                query=query,
                page_number=page_number,
                **list_kwargs,
            )
        elif include_all:
            result = request.app.state.data_service.list_all_incidents(**list_kwargs)
        else:
            result = request.app.state.data_service.list_incidents(
                page_number=page_number,
                **list_kwargs,
            )
    except Exception as exc:
        return _error_response(exc)

    return JSONResponse(_serialize_incident_list_payload(request, result))


async def search_incidents_by_host(request: Request) -> JSONResponse:
    try:
        host = _optional_query_param(request.query_params.get("host"))
        if host is None:
            raise ValueError("host query parameter is required.")
        result = request.app.state.data_service.search_incidents_by_host(
            host,
            page_number=_parse_int(request.query_params.get("page_number"), default=0),
            items_per_page=_parse_int(request.query_params.get("items_per_page"), default=25),
            classification=_optional_query_param(request.query_params.get("classification")),
            severity=_optional_query_param(request.query_params.get("severity")),
            handled=(
                _parse_bool(request.query_params.get("handled"), default=False)
                if request.query_params.get("handled") is not None
                else None
            ),
            archived=(
                _parse_bool(request.query_params.get("archived"), default=False)
                if request.query_params.get("archived") is not None
                else None
            ),
        )
    except Exception as exc:
        return _error_response(exc)

    return JSONResponse(_serialize_incident_list_payload(request, result))


async def list_available_models(request: Request) -> JSONResponse:
    return JSONResponse(
        {
            **get_available_llm_options(),
            "analysis_profiles": [
                {
                    "name": profile.name,
                    "label": profile.label,
                    "description": profile.description,
                }
                for profile in list_analysis_profiles()
            ],
            "default_profile": "standard",
            "capabilities": {
                "allow_db_reset": _db_reset_enabled(),
            },
        }
    )


async def get_backend_settings(request: Request) -> JSONResponse:
    return JSONResponse(_current_fortiedr_settings())


async def test_backend_settings_connection(request: Request) -> JSONResponse:
    try:
        raw_body = await request.body()
        payload = json.loads(raw_body.decode("utf-8")) if raw_body else {}
        settings_request = BackendSettingsRequest.model_validate(payload)
        config = _build_settings_config(settings_request.model_dump())
        client = FortiEDRClient(config)
        events = client.list_events(pageNumber=0, itemsPerPage=1)
    except json.JSONDecodeError:
        return _error_response(ValueError("Request body must contain valid JSON."))
    except ValidationError as exc:
        return _error_response(ValueError(f"Invalid settings request: {exc.errors()}"))
    except Exception as exc:
        return _error_response(exc)

    return JSONResponse(
        {
            "ok": True,
            "message": "FortiEDR connection succeeded.",
            "organization": config.organization,
            "sample_count": len(events),
        }
    )


async def test_backend_llm_connection(request: Request) -> JSONResponse:
    try:
        raw_body = await request.body()
        payload = json.loads(raw_body.decode("utf-8")) if raw_body else {}
        settings_request = BackendSettingsRequest.model_validate(payload)
        provider = settings_request.llm_server_provider.strip().lower()
        base_url = settings_request.llm_server_url.strip()
        if not provider:
            raise ValueError("Select an LLM server provider before testing.")
        if not base_url:
            raise ValueError("LLM server URL is required.")
        test_result = probe_remote_llm_server(provider, base_url=base_url)
    except json.JSONDecodeError:
        return _error_response(ValueError("Request body must contain valid JSON."))
    except ValidationError as exc:
        return _error_response(ValueError(f"Invalid settings request: {exc.errors()}"))
    except Exception as exc:
        return _error_response(exc)

    return JSONResponse(
        {
            "ok": True,
            "message": "LLM server connection succeeded.",
            "provider": test_result["provider"],
            "base_url": test_result["base_url"],
            "model_count": len(test_result["models"]),
            "models": test_result["models"],
        }
    )


async def save_backend_settings(request: Request) -> JSONResponse:
    try:
        raw_body = await request.body()
        payload = json.loads(raw_body.decode("utf-8")) if raw_body else {}
        settings_request = BackendSettingsRequest.model_validate(payload)
        settings = settings_request.model_dump()
        if settings["engine_source"] == "private" and settings["llm_server_url"] and not settings["llm_server_provider"]:
            settings["llm_server_provider"] = "ollama"
        if settings["engine_source"] == "public" and not settings["llm_server_provider"]:
            settings["llm_server_provider"] = "ollama" if settings["llm_server_url"] else ""
        if not settings["llm_server_available_models"].strip():
            settings["llm_server_available_models"] = (
                os.getenv("OLLAMA_AVAILABLE_MODELS", "").strip()
                or settings["llm_server_model"]
            )
        _build_settings_config(settings)
        _write_fortiedr_settings_to_dotenv(settings)
        _apply_runtime_fortiedr_settings(request.app, settings)
    except json.JSONDecodeError:
        return _error_response(ValueError("Request body must contain valid JSON."))
    except ValidationError as exc:
        return _error_response(ValueError(f"Invalid settings request: {exc.errors()}"))
    except Exception as exc:
        return _error_response(exc)

    return JSONResponse(
        {
            "saved": True,
            "settings": {
                "host": settings["host"],
                "organization": settings["organization"],
                "user": settings["user"],
                "password": settings["password"],
            },
        }
    )


async def get_incident(request: Request) -> JSONResponse:
    incident_id = int(request.path_params["incident_id"])
    try:
        result = request.app.state.data_service.get_incident_details(
            incident_id,
            raw_data_limit=_parse_int(request.query_params.get("raw_data_limit"), default=25),
            related_limit=_parse_int(request.query_params.get("related_limit"), default=10),
            collector_limit=_parse_int(request.query_params.get("collector_limit"), default=10),
            include_host_context=_parse_bool(request.query_params.get("include_host_context"), default=True),
            include_related_events=_parse_bool(request.query_params.get("include_related_events"), default=True),
            include_forensics=_parse_bool(request.query_params.get("include_forensics"), default=True),
        )
    except Exception as exc:
        return _error_response(exc)

    if result.incident.host is None:
        host = _host_from_raw_data_items(result.raw_data_items)
        if host is not None:
            result = result.model_copy(
                update={"incident": result.incident.model_copy(update={"host": host})}
            )

    payload = result.model_dump(mode="json")
    analysis_input = _analysis_input_builder.build(result)
    payload["derived_hashes"] = analysis_input.key_metadata_candidates.hashes.model_dump(mode="json")
    payload["derived_context"] = analysis_input.derived_context.model_dump(mode="json")
    return JSONResponse(payload)


async def analyze_incident(request: Request) -> JSONResponse:
    incident_id = int(request.path_params["incident_id"])
    try:
        raw_body = await request.body()
        payload = json.loads(raw_body.decode("utf-8")) if raw_body else {}
        analysis_request = AnalyzeIncidentRequest.model_validate(payload)
    except json.JSONDecodeError:
        return _error_response(ValueError("Request body must contain valid JSON."))
    except ValidationError as exc:
        return _error_response(ValueError(f"Invalid analysis request: {exc.errors()}"))

    try:
        provider, model_name = _resolve_requested_llm_config(
            analysis_request.provider,
            analysis_request.model_name,
        )
        run_service = _request_analysis_run_service(
            request,
            provider=provider,
            model_name=model_name,
        )
        execution = run_service.analyze_incident(
            incident_id,
            skill_name=analysis_request.skill_name,
            analysis_profile=analysis_request.analysis_profile,
            raw_data_limit=analysis_request.raw_data_limit,
            related_limit=analysis_request.related_limit,
            collector_limit=analysis_request.collector_limit,
            include_host_context=analysis_request.include_host_context,
            include_related_events=analysis_request.include_related_events,
            include_forensics=analysis_request.include_forensics,
            force=analysis_request.force,
            async_run=analysis_request.async_run,
        )
    except Exception as exc:
        return _error_response(exc)

    response_payload = {
        "from_cache": execution.from_cache,
        "run": _serialize_run(
            execution.run,
            include_input=analysis_request.include_input_in_response,
            include_llm_output=analysis_request.include_llm_output_in_response,
        ),
    }
    if execution.run.status in {AnalysisRunStatus.SUCCESS, AnalysisRunStatus.RUNNING}:
        return JSONResponse(response_payload, status_code=_execution_status_code(execution))

    response_payload["error"] = execution.run.error.model_dump(mode="json") if execution.run.error else None
    return JSONResponse(response_payload, status_code=_execution_status_code(execution))


async def get_latest_analysis(request: Request) -> JSONResponse:
    incident_id = int(request.path_params["incident_id"])
    include_input = _parse_bool(request.query_params.get("include_input"), default=False)
    include_llm_output = _parse_bool(request.query_params.get("include_llm_output"), default=False)
    try:
        run = request.app.state.analysis_run_service.get_latest_successful_analysis(incident_id)
    except Exception as exc:
        return _error_response(exc)

    if run is None:
        return JSONResponse(
            {"error": {"code": "analysis_not_found", "message": "No successful analysis run is stored for this incident."}},
            status_code=404,
        )

    return JSONResponse(_serialize_run(run, include_input=include_input, include_llm_output=include_llm_output))


async def get_analysis_history(request: Request) -> JSONResponse:
    incident_id = int(request.path_params["incident_id"])
    include_input = _parse_bool(request.query_params.get("include_input"), default=False)
    include_llm_output = _parse_bool(request.query_params.get("include_llm_output"), default=False)
    limit = _parse_int(request.query_params.get("limit"), default=20)
    try:
        runs = request.app.state.analysis_run_service.list_analysis_history(incident_id, limit=limit)
    except Exception as exc:
        return _error_response(exc)

    return JSONResponse(
        {
            "incident_id": str(incident_id),
            "count": len(runs),
            "runs": [
                _serialize_run(run, include_input=include_input, include_llm_output=include_llm_output)
                for run in runs
            ],
        }
    )


async def get_analysis_run(request: Request) -> JSONResponse:
    run_id = request.path_params["run_id"]
    include_input = _parse_bool(request.query_params.get("include_input"), default=True)
    include_llm_output = _parse_bool(request.query_params.get("include_llm_output"), default=True)
    try:
        run = request.app.state.analysis_run_service.get_run(run_id)
    except Exception as exc:
        return _error_response(exc)

    if run is None:
        return JSONResponse(
            {"error": {"code": "run_not_found", "message": "The requested analysis run was not found."}},
            status_code=404,
        )

    return JSONResponse(
        _serialize_run(run, include_input=include_input, include_llm_output=include_llm_output)
    )


async def get_analysis_run_feedback(request: Request) -> JSONResponse:
    run_id = request.path_params["run_id"]
    try:
        run = request.app.state.analysis_run_service.get_run(run_id)
    except Exception as exc:
        return _error_response(exc)

    if run is None:
        return JSONResponse(
            {"error": {"code": "run_not_found", "message": "The requested analysis run was not found."}},
            status_code=404,
        )

    return JSONResponse(
        {
            "run_id": run_id,
            "feedback": run.analyst_feedback.model_dump(mode="json") if run.analyst_feedback else None,
        }
    )


async def post_analysis_run_feedback(request: Request) -> JSONResponse:
    run_id = request.path_params["run_id"]
    try:
        raw_body = await request.body()
        payload = json.loads(raw_body.decode("utf-8")) if raw_body else {}
        feedback_request = RunFeedbackRequest.model_validate(payload)
    except json.JSONDecodeError:
        return _error_response(ValueError("Request body must contain valid JSON."))
    except ValidationError as exc:
        return _error_response(ValueError(f"Invalid feedback request: {exc.errors()}"))

    try:
        run = request.app.state.analysis_run_service.upsert_feedback(
            run_id,
            usefulness=feedback_request.usefulness,
            correctness=feedback_request.correctness,
            analyst_classification=feedback_request.analyst_classification,
            comment=feedback_request.comment,
        )
    except Exception as exc:
        return _error_response(exc)

    if run is None:
        return JSONResponse(
            {"error": {"code": "run_not_found", "message": "The requested analysis run was not found."}},
            status_code=404,
        )

    return JSONResponse(
        {
            "run_id": run_id,
            "feedback": run.analyst_feedback.model_dump(mode="json") if run.analyst_feedback else None,
        }
    )


async def clear_analysis_database(request: Request) -> JSONResponse:
    if not _db_reset_enabled():
        return JSONResponse(
            {"error": {"code": "not_found", "message": "Database reset is not enabled on this backend."}},
            status_code=404,
        )

    try:
        deleted_runs = request.app.state.analysis_run_service.clear_all_runs()
    except Exception as exc:
        return _error_response(exc)

    return JSONResponse({"cleared": True, "deleted_runs": deleted_runs})


async def portal_root_redirect(request: Request) -> RedirectResponse:
    return RedirectResponse(url="/portal", status_code=307)


async def portal_index_page(request: Request) -> FileResponse:
    return _portal_file_response("index.html")


async def portal_incident_page(request: Request) -> FileResponse:
    return _portal_file_response("incident.html")


async def portal_run_page(request: Request) -> FileResponse:
    return _portal_file_response("run.html")


def create_app(
    *,
    data_service: IncidentDataService | None = None,
    analysis_run_service: AnalysisRunService | None = None,
) -> Starlette:
    app = Starlette(
        debug=False,
        routes=[
            Route("/favicon.ico", favicon, methods=["GET"]),
            Route("/", portal_root_redirect, methods=["GET"]),
            Route("/portal", portal_index_page, methods=["GET"]),
            Route("/portal/", portal_index_page, methods=["GET"]),
            Route("/portal/incidents/{incident_id:int}", portal_incident_page, methods=["GET"]),
            Route("/portal/runs/{run_id}", portal_run_page, methods=["GET"]),
            Mount("/portal/static", app=StaticFiles(directory=PORTAL_DIR), name="portal-static"),
            Route("/analysis/models", list_available_models, methods=["GET"]),
            Route("/settings", get_backend_settings, methods=["GET"]),
            Route("/settings", save_backend_settings, methods=["POST"]),
            Route("/settings/test-connection", test_backend_settings_connection, methods=["POST"]),
            Route("/settings/test-llm", test_backend_llm_connection, methods=["POST"]),
            Route("/incidents", list_incidents, methods=["GET"]),
            Route("/incidents/search/host", search_incidents_by_host, methods=["GET"]),
            Route("/incidents/{incident_id:int}", get_incident, methods=["GET"]),
            Route("/incidents/{incident_id:int}/analyze", analyze_incident, methods=["POST"]),
            Route("/incidents/{incident_id:int}/analysis/latest", get_latest_analysis, methods=["GET"]),
            Route("/incidents/{incident_id:int}/analysis/history", get_analysis_history, methods=["GET"]),
            Route("/analysis/runs/{run_id}", get_analysis_run, methods=["GET"]),
            Route("/analysis/runs/{run_id}/feedback", get_analysis_run_feedback, methods=["GET"]),
            Route("/analysis/runs/{run_id}/feedback", post_analysis_run_feedback, methods=["POST"]),
            Route("/analysis/database/clear", clear_analysis_database, methods=["POST"]),
        ],
    )
    app.state.uses_default_data_service = data_service is None
    app.state.uses_default_analysis_run_service = analysis_run_service is None
    app.state.data_service = data_service or get_data_service()
    app.state.analysis_run_service = analysis_run_service or get_analysis_run_service()
    if analysis_run_service is None:
        app.state.analysis_run_service_factory = build_analysis_run_service
    return app


def main() -> None:
    import uvicorn

    project_root = _load_project_dotenv()
    default_host = os.getenv("FORTIEDR_BACKEND_HOST", "127.0.0.1")
    default_port = int(os.getenv("FORTIEDR_BACKEND_PORT", "8080"))
    parser = argparse.ArgumentParser(description="Run the FortiEDR backend API.")
    parser.add_argument("--host", default=default_host, help="Bind host for the backend API.")
    parser.add_argument("--port", type=int, default=default_port, help="Bind port for the backend API.")
    parser.add_argument(
        "--db-path",
        default=os.getenv(
            "FORTIEDR_ANALYSIS_DB_PATH",
            str(project_root / "data" / "analysis_runs.sqlite3"),
        ),
        help="SQLite path used to persist analysis runs.",
    )
    args = parser.parse_args()

    os.environ["FORTIEDR_ANALYSIS_DB_PATH"] = args.db_path
    _print_startup_banner(host=args.host, port=args.port, db_path=args.db_path)
    uvicorn.run(create_app(), host=args.host, port=args.port)
