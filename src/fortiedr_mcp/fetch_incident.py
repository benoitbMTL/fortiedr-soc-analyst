from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from fortiedr_mcp.analyze_incident import build_data_service
from fortiedr_mcp.errors import FortiEDRError


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Fetch a FortiEDR incident summary and detailed payload into separate JSON files.",
    )
    parser.add_argument("incident_id", type=int, help="FortiEDR event/incident identifier.")
    parser.add_argument(
        "--incident-out",
        type=Path,
        default=None,
        help="Output path for get_incident JSON. Defaults to incident-<id>.json.",
    )
    parser.add_argument(
        "--details-out",
        type=Path,
        default=None,
        help="Output path for get_incident_details JSON. Defaults to incident-<id>-details.json.",
    )
    parser.add_argument(
        "--raw-data-limit",
        type=int,
        default=25,
        help="Maximum number of raw data items to include in get_incident_details.",
    )
    parser.add_argument(
        "--related-limit",
        type=int,
        default=10,
        help="Maximum number of related events / host incidents to include.",
    )
    parser.add_argument(
        "--collector-limit",
        type=int,
        default=25,
        help="Maximum number of collectors to include in host context.",
    )
    parser.add_argument(
        "--no-host-context",
        action="store_true",
        help="Skip host context collection for get_incident_details.",
    )
    parser.add_argument(
        "--no-related-events",
        action="store_true",
        help="Skip related event collection for get_incident_details.",
    )
    return parser


def write_json(path: Path, payload: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()

    incident_out = args.incident_out or Path(f"incident-{args.incident_id}.json")
    details_out = args.details_out or Path(f"incident-{args.incident_id}-details.json")

    try:
        service = build_data_service()
        incident = service.get_incident(args.incident_id)
        incident_details = service.get_incident_details(
            args.incident_id,
            raw_data_limit=args.raw_data_limit,
            related_limit=args.related_limit,
            collector_limit=args.collector_limit,
            include_host_context=not args.no_host_context,
            include_related_events=not args.no_related_events,
        )
    except FortiEDRError as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 1

    write_json(incident_out, incident.model_dump(mode="json"))
    write_json(details_out, incident_details.model_dump(mode="json"))

    print(f"get_incident -> {incident_out}")
    print(f"get_incident_details -> {details_out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
