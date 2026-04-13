from importlib.util import module_from_spec, spec_from_file_location
from pathlib import Path
import sys


def _load_benchmark_module():
    path = Path(__file__).resolve().parents[1] / "benchmark" / "run_benchmark.py"
    spec = spec_from_file_location("benchmark_run_benchmark", path)
    assert spec and spec.loader
    module = module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


benchmark_module = _load_benchmark_module()
build_summary_table_rows = benchmark_module.build_summary_table_rows
count_populated_top_level_fields = benchmark_module.count_populated_top_level_fields
normalize_profile_name = benchmark_module.normalize_profile_name
parse_models = benchmark_module.parse_models


def test_normalize_profile_name():
    assert normalize_profile_name(" LITE ") == "lite"


def test_parse_models():
    assert parse_models("qwen2.5:3b, phi3:mini") == ["qwen2.5:3b", "phi3:mini"]


def test_count_populated_top_level_fields():
    payload = {
        "executive_summary": "Some summary",
        "observed_facts": [],
        "risk_level": "high",
        "verdict": "",
        "recommended_next_steps": {"immediate": ["a"]},
    }
    fields = [
        "executive_summary",
        "observed_facts",
        "risk_level",
        "verdict",
        "recommended_next_steps",
        "missing_information",
    ]
    counts = count_populated_top_level_fields(payload, fields)
    assert counts == {"populated": 3, "expected_total": 6}


def test_build_summary_table_rows():
    rows = build_summary_table_rows(
        [
            {
                "model": "qwen2.5:3b",
                "duration_seconds": 12.34,
                "status": "success",
                "json_valid": True,
                "schema_valid": True,
                "token_usage": {"prompt_tokens": 11, "completion_tokens": 22, "total_tokens": 33},
            }
        ]
    )
    assert rows == [
        {
            "model": "qwen2.5:3b",
            "duration": "12.3s",
            "status": "success",
            "json_valid": "yes",
            "schema_valid": "yes",
            "tokens": "p:11 c:22 t:33",
        }
    ]
