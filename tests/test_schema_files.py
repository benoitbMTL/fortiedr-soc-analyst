from __future__ import annotations

import json
from pathlib import Path


def test_skill_schema_files_exist_and_have_expected_properties():
    base = Path(__file__).resolve().parents[1] / "src" / "fortiedr_mcp" / "schemas"
    input_schema = json.loads((base / "incident_senior_soc_v1_input.schema.json").read_text())
    output_schema = json.loads((base / "incident_senior_soc_v1_output.schema.json").read_text())

    assert "incident_id" in input_schema["properties"]
    assert "key_metadata_candidates" in input_schema["properties"]
    assert "possible_classification" in output_schema["properties"]
    assert "observed_facts" in output_schema["properties"]
