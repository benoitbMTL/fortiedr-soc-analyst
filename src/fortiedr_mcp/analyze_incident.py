from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from fortiedr_mcp.config import FortiEDRConfig
from fortiedr_mcp.errors import FortiEDRError, FortiEDRLLMConfigurationError
from fortiedr_mcp.fortiedr_client import FortiEDRClient
from fortiedr_mcp.llm import build_llm_client
from fortiedr_mcp.services.incident_analysis import IncidentAnalysisService
from fortiedr_mcp.services.incident_data import IncidentDataService


def build_data_service() -> IncidentDataService:
    fortiedr_client = FortiEDRClient(FortiEDRConfig.from_env())
    return IncidentDataService(fortiedr_client)


def build_analysis_service(provider: str = "auto") -> IncidentAnalysisService:
    data_service = build_data_service()
    llm_client = build_llm_client(provider)
    return IncidentAnalysisService(
        data_service=data_service,
        llm_client=llm_client,
    )


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Run structured incident analysis for a FortiEDR incident.",
    )
    parser.add_argument("incident_id", type=int, help="FortiEDR event/incident identifier.")
    parser.add_argument(
        "--skill",
        default="incident_senior_soc_v1",
        help="Registered analysis skill name.",
    )
    parser.add_argument(
        "--provider",
        default="auto",
        help="Structured LLM provider to use: auto, openai, or anthropic.",
    )
    parser.add_argument(
        "--analysis-profile",
        default="standard",
        choices=["lite", "standard", "full"],
        help="Context profile used to collect and normalize source data.",
    )
    parser.add_argument(
        "--save",
        default=None,
        help="Optional path to write the structured analysis JSON.",
    )
    parser.add_argument(
        "--dump-input",
        default=None,
        help="Optional path to write the normalized analysis input JSON before LLM generation.",
    )
    parser.add_argument(
        "--input-only",
        action="store_true",
        help="Build and optionally dump the normalized analysis input without calling the LLM.",
    )
    args = parser.parse_args()

    try:
        if args.input_only or args.dump_input:
            input_service = IncidentAnalysisService(
                data_service=build_data_service(),
                llm_client=None,
            )
            _, analysis_input = input_service.build_analysis_input(
                args.incident_id,
                skill_name=args.skill,
                analysis_profile=args.analysis_profile,
            )
            rendered_input = json.dumps(analysis_input.model_dump(mode="json"), indent=2)
            if args.dump_input:
                Path(args.dump_input).write_text(rendered_input + "\n")
            if args.input_only:
                print(rendered_input)
                return 0

        service = build_analysis_service(provider=args.provider)

        result = service.analyze_incident(
            args.incident_id,
            skill_name=args.skill,
            analysis_profile=args.analysis_profile,
        )
        rendered = json.dumps(result.model_dump(mode="json"), indent=2)
        print(rendered)

        if args.save:
            Path(args.save).write_text(rendered + "\n")

        return 0
    except FortiEDRLLMConfigurationError as exc:
        message_lines = [f"Error: {exc}"]
        if args.dump_input:
            message_lines.append(f"Normalized analysis input was written to: {args.dump_input}")
        message_lines.append(
            "Set the required LLM environment variables or rerun with --input-only."
        )
        print("\n".join(message_lines), file=sys.stderr)
        return 2
    except FortiEDRError as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 1
