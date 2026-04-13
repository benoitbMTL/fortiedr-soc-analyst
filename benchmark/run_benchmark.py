from __future__ import annotations

import argparse
import csv
import hashlib
import json
import multiprocessing as mp
import re
import traceback
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from time import perf_counter
from typing import Any


REPO_ROOT = Path(__file__).resolve().parents[1]
SRC_DIR = REPO_ROOT / "src"
if str(SRC_DIR) not in __import__("sys").path:
    __import__("sys").path.insert(0, str(SRC_DIR))

from fortiedr_mcp.analyze_incident import build_data_service
from fortiedr_mcp.errors import FortiEDRLLMTimeoutError, FortiEDRValidationError
from fortiedr_mcp.llm.ollama import OllamaStructuredLLMClient
from fortiedr_mcp.services.incident_analysis import IncidentAnalysisService, PreparedIncidentAnalysis
from fortiedr_mcp.skills.registry import get_skill


DEFAULT_INCIDENT_ID = 5468293
DEFAULT_PROFILE = "LITE"
DEFAULT_SERVER_URL = "http://10.163.3.76:11434/"
DEFAULT_TIMEOUT_SECONDS = 300
DEFAULT_MODELS = [
    "llama3.1:8b",
    "phi3:mini",
    "gemma3:4b",
    "gemma3:1b",
    "qwen2.5:1.5b",
    "qwen2.5:3b",
    "qwen2.5:7b",
]
DEFAULT_SKILL = "incident_senior_soc_v1"


@dataclass(frozen=True)
class BenchmarkConfig:
    incident_id: int
    profile: str
    server_url: str
    timeout_seconds: int
    models: list[str]
    skill_name: str
    max_tokens: int
    context_length: int
    temperature: float
    output_dir: Path


def utcnow_iso() -> str:
    return datetime.now(tz=UTC).isoformat()


def normalize_profile_name(profile: str) -> str:
    return profile.strip().lower()


def model_slug(model_name: str) -> str:
    return re.sub(r"[^a-zA-Z0-9._-]+", "_", model_name)


def write_json(path: Path, payload: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")


def count_populated_top_level_fields(
    payload: dict[str, Any] | None, expected_fields: list[str]
) -> dict[str, int]:
    if not isinstance(payload, dict):
        return {"populated": 0, "expected_total": len(expected_fields)}
    populated = 0
    for field in expected_fields:
        value = payload.get(field)
        if value is None:
            continue
        if isinstance(value, str) and not value.strip():
            continue
        if isinstance(value, (list, dict)) and len(value) == 0:
            continue
        populated += 1
    return {"populated": populated, "expected_total": len(expected_fields)}


def build_summary_table_rows(runs: list[dict[str, Any]]) -> list[dict[str, str]]:
    rows: list[dict[str, str]] = []
    for run in runs:
        usage = run.get("token_usage") or {}
        prompt_tokens = usage.get("prompt_tokens")
        completion_tokens = usage.get("completion_tokens")
        total_tokens = usage.get("total_tokens")
        token_text = (
            f"p:{prompt_tokens if prompt_tokens is not None else '-'} "
            f"c:{completion_tokens if completion_tokens is not None else '-'} "
            f"t:{total_tokens if total_tokens is not None else '-'}"
        )
        rows.append(
            {
                "model": str(run.get("model", "")),
                "duration": f"{float(run.get('duration_seconds', 0.0)):.1f}s",
                "status": str(run.get("status", "")),
                "json_valid": "yes" if run.get("json_valid") else "no",
                "schema_valid": "yes" if run.get("schema_valid") else "no",
                "tokens": token_text,
            }
        )
    return rows


def print_summary_table(runs: list[dict[str, Any]]) -> None:
    rows = build_summary_table_rows(runs)
    headers = ["model", "duration", "status", "json_valid", "schema_valid", "tokens"]
    widths = {header: len(header) for header in headers}
    for row in rows:
        for header in headers:
            widths[header] = max(widths[header], len(row[header]))
    line = " | ".join(header.ljust(widths[header]) for header in headers)
    sep = "-+-".join("-" * widths[header] for header in headers)
    print(line)
    print(sep)
    for row in rows:
        print(" | ".join(row[header].ljust(widths[header]) for header in headers))


def parse_models(models_arg: str) -> list[str]:
    models = [part.strip() for part in models_arg.split(",") if part.strip()]
    if not models:
        raise ValueError("At least one model must be provided.")
    return models


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Benchmark local Ollama models on one normalized FortiEDR incident input."
    )
    parser.add_argument("--incident-id", type=int, default=DEFAULT_INCIDENT_ID)
    parser.add_argument("--profile", default=DEFAULT_PROFILE, help="Analysis profile (e.g., LITE).")
    parser.add_argument("--server-url", default=DEFAULT_SERVER_URL)
    parser.add_argument("--models", default=",".join(DEFAULT_MODELS))
    parser.add_argument("--timeout", type=int, default=DEFAULT_TIMEOUT_SECONDS, help="Seconds per model.")
    parser.add_argument("--skill", default=DEFAULT_SKILL, help="Registered analysis skill name.")
    parser.add_argument("--max-tokens", type=int, default=4096)
    parser.add_argument("--context-length", type=int, default=4096)
    parser.add_argument("--temperature", type=float, default=0.0)
    parser.add_argument("--output-dir", default=str(REPO_ROOT / "benchmark" / "results"))
    return parser


def build_normalized_input(
    *,
    incident_id: int,
    profile: str,
    skill_name: str,
) -> tuple[dict[str, Any], dict[str, Any]]:
    service = IncidentAnalysisService(data_service=build_data_service(), llm_client=None)
    skill, analysis_input = service.build_analysis_input(
        incident_id,
        skill_name=skill_name,
        analysis_profile=profile,
    )
    normalized = analysis_input.model_dump(mode="json")
    output_schema = skill.output_model.model_json_schema()
    prompt = skill.build_user_prompt(analysis_input)
    skill_snapshot = {
        "skill_name": skill.name,
        "skill_version": skill.skill_version,
        "description": skill.description,
        "system_instructions": skill.system_instructions,
        "output_schema": output_schema,
        "user_prompt_preview": prompt[:4000],
    }
    return normalized, skill_snapshot


def _worker_run_model(
    queue: Any,
    *,
    normalized_input_path: str,
    skill_name: str,
    model_name: str,
    server_url: str,
    request_timeout_seconds: int,
    max_tokens: int,
    context_length: int,
    temperature: float,
) -> None:
    try:
        started_at = utcnow_iso()
        start_clock = perf_counter()
        payload = json.loads(Path(normalized_input_path).read_text(encoding="utf-8"))
        skill = get_skill(skill_name)
        analysis_input = skill.input_model.model_validate(payload)

        prepared = PreparedIncidentAnalysis(
            skill=skill,
            incident_details=None,  # type: ignore[arg-type]
            analysis_input=analysis_input,
        )
        llm_client = OllamaStructuredLLMClient(
            model=model_name,
            base_url=server_url,
            timeout_seconds=float(request_timeout_seconds),
            max_tokens=max_tokens,
            context_length=context_length,
            temperature=temperature,
        )
        analysis_service = IncidentAnalysisService(data_service=None, llm_client=llm_client)  # type: ignore[arg-type]
        llm_result = analysis_service.generate_structured_output(prepared=prepared)

        raw_output = llm_result.output if isinstance(llm_result.output, dict) else None
        json_valid = isinstance(raw_output, dict)
        schema_valid = False
        status = "success"
        error_message = None
        validated_output: dict[str, Any] | None = None

        if not json_valid:
            status = "invalid_json"
        else:
            try:
                validated = analysis_service.validate_structured_output(
                    prepared=prepared,
                    llm_result=llm_result,
                )
                validated_output = validated.model_dump(mode="json")
                schema_valid = True
            except FortiEDRValidationError as exc:
                status = "schema_error"
                details = "; ".join(exc.details) if exc.details else ""
                error_message = f"{exc}. {details}".strip()

        expected_fields = list(skill.output_model.model_fields.keys())
        top_level = count_populated_top_level_fields(raw_output, expected_fields)
        output_preview = json.dumps(raw_output, ensure_ascii=False)[:400] if raw_output else ""

        queue.put(
            {
                "worker_started_at": started_at,
                "worker_finished_at": utcnow_iso(),
                "worker_duration_seconds": round(perf_counter() - start_clock, 3),
                "status": status,
                "json_valid": json_valid,
                "schema_valid": schema_valid,
                "error": error_message,
                "raw_output": raw_output,
                "validated_output": validated_output,
                "output_preview": output_preview,
                "output_present": bool(raw_output),
                "output_char_count": len(json.dumps(raw_output, ensure_ascii=False)) if raw_output else 0,
                "output_key_count": len(raw_output) if raw_output else 0,
                "top_level_fields_populated": top_level["populated"],
                "top_level_fields_expected": top_level["expected_total"],
                "request_id": llm_result.request_id,
                "provider_name": llm_result.provider_name,
                "model_name": llm_result.model_name,
                "token_usage": (
                    llm_result.token_usage.model_dump(mode="json") if llm_result.token_usage else None
                ),
                "response_metadata": llm_result.response_metadata or {},
            }
        )
    except FortiEDRLLMTimeoutError as exc:
        queue.put(
            {
                "status": "timeout",
                "timed_out": True,
                "json_valid": False,
                "schema_valid": False,
                "error": f"{type(exc).__name__}: {exc}",
                "traceback": traceback.format_exc(),
                "raw_output": None,
                "validated_output": None,
                "output_preview": "",
                "output_present": False,
                "output_char_count": 0,
                "output_key_count": 0,
                "top_level_fields_populated": 0,
                "top_level_fields_expected": 0,
                "request_id": None,
                "provider_name": "ollama",
                "model_name": model_name,
                "token_usage": None,
                "response_metadata": {},
            }
        )
    except Exception as exc:  # noqa: BLE001
        queue.put(
            {
                "status": "error",
                "timed_out": False,
                "json_valid": False,
                "schema_valid": False,
                "error": f"{type(exc).__name__}: {exc}",
                "traceback": traceback.format_exc(),
                "raw_output": None,
                "validated_output": None,
                "output_preview": "",
                "output_present": False,
                "output_char_count": 0,
                "output_key_count": 0,
                "top_level_fields_populated": 0,
                "top_level_fields_expected": 0,
                "request_id": None,
                "provider_name": "ollama",
                "model_name": model_name,
                "token_usage": None,
                "response_metadata": {},
            }
        )


def run_single_model(
    *,
    model_name: str,
    normalized_input_path: Path,
    skill_name: str,
    server_url: str,
    timeout_seconds: int,
    max_tokens: int,
    context_length: int,
    temperature: float,
) -> dict[str, Any]:
    start_clock = perf_counter()
    started_at = utcnow_iso()
    ctx = mp.get_context("spawn")
    queue = ctx.Queue()
    process = ctx.Process(
        target=_worker_run_model,
        kwargs={
            "queue": queue,
            "normalized_input_path": str(normalized_input_path),
            "skill_name": skill_name,
            "model_name": model_name,
            "server_url": server_url,
            "request_timeout_seconds": timeout_seconds,
            "max_tokens": max_tokens,
            "context_length": context_length,
            "temperature": temperature,
        },
    )
    process.start()
    process.join(timeout=timeout_seconds)

    timed_out = process.is_alive()
    worker_payload: dict[str, Any] = {}
    if timed_out:
        process.terminate()
        process.join(timeout=2)
    else:
        try:
            worker_payload = queue.get_nowait()
        except Exception:  # noqa: BLE001
            worker_payload = {
                "status": "error",
                "json_valid": False,
                "schema_valid": False,
                "error": "Worker finished without returning a payload.",
                "raw_output": None,
                "validated_output": None,
                "output_preview": "",
                "output_present": False,
                "output_char_count": 0,
                "output_key_count": 0,
                "top_level_fields_populated": 0,
                "top_level_fields_expected": 0,
                "request_id": None,
                "provider_name": "ollama",
                "model_name": model_name,
                "token_usage": None,
                "response_metadata": {},
            }

    finished_at = utcnow_iso()
    duration_seconds = round(perf_counter() - start_clock, 3)
    if timed_out:
        return {
            "model": model_name,
            "started_at": started_at,
            "finished_at": finished_at,
            "duration_seconds": duration_seconds,
            "status": "timeout",
            "timed_out": True,
            "json_valid": False,
            "schema_valid": False,
            "error": f"Timed out after {timeout_seconds} seconds.",
            "output_preview": "",
            "output_present": False,
            "output_char_count": 0,
            "output_key_count": 0,
            "top_level_fields_populated": 0,
            "top_level_fields_expected": 0,
            "token_usage": None,
            "request_id": None,
            "provider_name": "ollama",
            "raw_output": None,
            "validated_output": None,
            "response_metadata": {},
        }

    result = {
        "model": model_name,
        "started_at": started_at,
        "finished_at": finished_at,
        "duration_seconds": duration_seconds,
        **worker_payload,
    }
    result.setdefault("timed_out", False)
    result.setdefault("status", "error")
    result.setdefault("json_valid", False)
    result.setdefault("schema_valid", False)
    return result


def save_run_artifacts(results_dir: Path, run: dict[str, Any]) -> dict[str, str | None]:
    model = str(run["model"])
    slug = model_slug(model)
    outputs_dir = results_dir / "outputs"
    outputs_dir.mkdir(parents=True, exist_ok=True)
    raw_output_path = None
    validated_output_path = None

    if run.get("raw_output") is not None:
        raw_output_path = outputs_dir / f"{slug}-raw_output.json"
        write_json(raw_output_path, run["raw_output"])
    if run.get("validated_output") is not None:
        validated_output_path = outputs_dir / f"{slug}-validated_output.json"
        write_json(validated_output_path, run["validated_output"])

    return {
        "raw_output_path": str(raw_output_path) if raw_output_path else None,
        "validated_output_path": str(validated_output_path) if validated_output_path else None,
    }


def save_summary_csv(results_dir: Path, runs: list[dict[str, Any]]) -> Path:
    csv_path = results_dir / "summary.csv"
    fieldnames = [
        "model",
        "status",
        "duration_seconds",
        "timed_out",
        "json_valid",
        "schema_valid",
        "prompt_tokens",
        "completion_tokens",
        "total_tokens",
        "error",
    ]
    with csv_path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fieldnames)
        writer.writeheader()
        for run in runs:
            usage = run.get("token_usage") or {}
            writer.writerow(
                {
                    "model": run.get("model"),
                    "status": run.get("status"),
                    "duration_seconds": run.get("duration_seconds"),
                    "timed_out": run.get("timed_out"),
                    "json_valid": run.get("json_valid"),
                    "schema_valid": run.get("schema_valid"),
                    "prompt_tokens": usage.get("prompt_tokens"),
                    "completion_tokens": usage.get("completion_tokens"),
                    "total_tokens": usage.get("total_tokens"),
                    "error": run.get("error"),
                }
            )
    return csv_path


def run_benchmark(config: BenchmarkConfig) -> Path:
    profile = normalize_profile_name(config.profile)
    benchmark_name = f"incident_{config.incident_id}_{profile}_ollama_models"
    run_stamp = datetime.now(tz=UTC).strftime("%Y%m%dT%H%M%SZ")
    results_dir = config.output_dir / f"{benchmark_name}_{run_stamp}"
    results_dir.mkdir(parents=True, exist_ok=True)

    normalized_input, skill_snapshot = build_normalized_input(
        incident_id=config.incident_id,
        profile=profile,
        skill_name=config.skill_name,
    )
    normalized_input_path = results_dir / "normalized_input.json"
    write_json(normalized_input_path, normalized_input)
    skill_snapshot_path = results_dir / "skill_snapshot.json"
    write_json(skill_snapshot_path, skill_snapshot)

    normalized_hash = hashlib.sha256(
        json.dumps(normalized_input, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()

    runs: list[dict[str, Any]] = []
    for model in config.models:
        print(f"Running model: {model}")
        run = run_single_model(
            model_name=model,
            normalized_input_path=normalized_input_path,
            skill_name=config.skill_name,
            server_url=config.server_url,
            timeout_seconds=config.timeout_seconds,
            max_tokens=config.max_tokens,
            context_length=config.context_length,
            temperature=config.temperature,
        )
        run["incident_id"] = config.incident_id
        run["profile"] = profile.upper()
        artifact_paths = save_run_artifacts(results_dir, run)
        run["raw_output_path"] = artifact_paths["raw_output_path"]
        run["validated_output_path"] = artifact_paths["validated_output_path"]
        runs.append(run)

    benchmark_payload = {
        "benchmark_name": benchmark_name,
        "started_at": runs[0]["started_at"] if runs else utcnow_iso(),
        "finished_at": runs[-1]["finished_at"] if runs else utcnow_iso(),
        "incident_id": config.incident_id,
        "profile": profile.upper(),
        "skill_name": config.skill_name,
        "server_url": config.server_url,
        "timeout_seconds_per_model": config.timeout_seconds,
        "normalized_input_path": str(normalized_input_path),
        "normalized_input_sha256": normalized_hash,
        "skill_snapshot_path": str(skill_snapshot_path),
        "models": config.models,
        "runs": runs,
    }
    results_json_path = results_dir / "results.json"
    write_json(results_json_path, benchmark_payload)
    summary_csv_path = save_summary_csv(results_dir, runs)

    print("\nBenchmark summary")
    print_summary_table(runs)
    print(f"\nResults JSON: {results_json_path}")
    print(f"Summary CSV: {summary_csv_path}")
    return results_json_path


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()
    config = BenchmarkConfig(
        incident_id=args.incident_id,
        profile=args.profile,
        server_url=args.server_url,
        timeout_seconds=args.timeout,
        models=parse_models(args.models),
        skill_name=args.skill,
        max_tokens=args.max_tokens,
        context_length=args.context_length,
        temperature=args.temperature,
        output_dir=Path(args.output_dir),
    )
    run_benchmark(config)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
