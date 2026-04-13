from __future__ import annotations

import json
from pathlib import Path

from fortiedr_mcp.skills.registry import get_skill


def main() -> None:
    skill = get_skill("incident_senior_soc_v1")
    base_dir = Path(__file__).resolve().parents[1] / "src" / "fortiedr_mcp" / "schemas"
    base_dir.mkdir(parents=True, exist_ok=True)

    input_schema_path = base_dir / "incident_senior_soc_v1_input.schema.json"
    output_schema_path = base_dir / "incident_senior_soc_v1_output.schema.json"

    input_schema_path.write_text(
        json.dumps(skill.input_model.model_json_schema(), indent=2, sort_keys=True) + "\n"
    )
    output_schema_path.write_text(
        json.dumps(skill.output_model.model_json_schema(), indent=2, sort_keys=True) + "\n"
    )


if __name__ == "__main__":
    main()
