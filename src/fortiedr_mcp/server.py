from __future__ import annotations

import argparse
import os
import sys
from functools import lru_cache

from mcp.server.fastmcp import FastMCP

from fortiedr_mcp.config import FortiEDRConfig
from fortiedr_mcp.fortiedr_client import FortiEDRClient
from fortiedr_mcp.tools import register_incident_tools

mcp = FastMCP(
    name="FortiEDR Read-Only MCP",
    instructions=(
        "Read-only FortiEDR integration layer. Use these tools to list, fetch, and "
        "pivot on FortiEDR incidents, which currently map to FortiEDR event records."
    ),
)


@lru_cache(maxsize=1)
def get_client() -> FortiEDRClient:
    return FortiEDRClient(FortiEDRConfig.from_env())


register_incident_tools(mcp, get_client)


MCP_FORTIEDR_ASCII = """\
███╗   ███╗ ██████╗██████╗      ███████╗ ██████╗ ██████╗ ████████╗██╗███████╗██████╗ ██████╗
████╗ ████║██╔════╝██╔══██╗     ██╔════╝██╔═══██╗██╔══██╗╚══██╔══╝██║██╔════╝██╔══██╗██╔══██╗
██╔████╔██║██║     ██████╔╝     █████╗  ██║   ██║██████╔╝   ██║   ██║█████╗  ██║  ██║██████╔╝
██║╚██╔╝██║██║     ██╔═══╝      ██╔══╝  ██║   ██║██╔══██╗   ██║   ██║██╔══╝  ██║  ██║██╔══██╗
██║ ╚═╝ ██║╚██████╗██║          ██║     ╚██████╔╝██║  ██║   ██║   ██║███████╗██████╔╝██║  ██║
╚═╝     ╚═╝ ╚═════╝╚═╝          ╚═╝      ╚═════╝ ╚═╝  ╚═╝   ╚═╝   ╚═╝╚══════╝╚═════╝ ╚═╝  ╚═╝
"""


def _print_startup_banner(*, transport: str) -> None:
    supports_color = os.getenv("TERM") not in {None, "", "dumb"}
    accent = "\033[36m" if supports_color else ""
    muted = "\033[90m" if supports_color else ""
    reset = "\033[0m" if supports_color else ""

    endpoint_line = ""
    if transport == "streamable-http":
        endpoint_line = f"\nEndpoint: http://127.0.0.1:8000/mcp"

    banner = (
        f"\n{accent}{MCP_FORTIEDR_ASCII.rstrip()}{reset}\n\n"
        f"{muted}Transport: {transport}{endpoint_line}{reset}\n"
    )
    print(banner, file=sys.stderr, end="")


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Run the FortiEDR MCP server."
    )
    parser.add_argument(
        "--transport",
        choices=("streamable-http", "stdio", "sse"),
        default="streamable-http",
        help="MCP transport to start. Defaults to streamable-http.",
    )
    args = parser.parse_args()
    _print_startup_banner(transport=args.transport)
    mcp.run(transport=args.transport)


if __name__ == "__main__":
    main()
