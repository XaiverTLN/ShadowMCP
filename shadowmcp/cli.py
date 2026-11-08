"""ShadowMCP command-line entry point."""

from __future__ import annotations

import argparse
import sys


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="shadowmcp",
        description="ShadowMCP command-line tools. Use shadowmcp-proxy to wrap a stdio MCP server.",
    )
    parser.add_argument("--version", action="version", version="shadowmcp 0.1.0")
    args = sys.argv[1:] if argv is None else argv
    parser.parse_args(args)
    if not args:
        parser.print_help()
    return 0
