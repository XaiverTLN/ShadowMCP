"""Stdio MCP server exposing the intentionally vulnerable victim tools (synthetic data only).

Standard library only. Speaks newline-delimited JSON-RPC 2.0 (MCP stdio transport):
``initialize``, ``notifications/initialized``, ``ping``, ``tools/list``, ``tools/call``.

Run it directly (unprotected) or behind ShadowMCP:

    python -m shadow_mcp.proxy --wrap -- python "<this folder>/victim_mcp_server.py"

Set ``VICTIM_MCP_LOG_NOTIFICATION=1`` to emit one server-initiated ``notifications/message``
after initialization (used to test that a proxy relays unsolicited server messages).
"""

from __future__ import annotations

import json
import os
import sys
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parent))
import victim_rag_agent as victim  # noqa: E402

SERVER_INFO = {"name": "healthcare-rag-victim", "version": "1.0.0"}
DEFAULT_PROTOCOL = "2025-06-18"


def _tools() -> list[dict[str, Any]]:
    return [{"name": t["name"], "description": t["description"], "inputSchema": t["parameters_schema"]}
            for t in victim.TOOL_REGISTRY.values()]


def _send(message: dict[str, Any]) -> None:
    sys.stdout.write(json.dumps(message, ensure_ascii=False) + "\n")
    sys.stdout.flush()


def _result(request_id: Any, result: dict[str, Any]) -> None:
    _send({"jsonrpc": "2.0", "id": request_id, "result": result})


def _error(request_id: Any, code: int, message: str) -> None:
    _send({"jsonrpc": "2.0", "id": request_id, "error": {"code": code, "message": message}})


def handle(message: dict[str, Any]) -> None:
    method = message.get("method")
    request_id = message.get("id")
    if method is None:          # a response to something we never asked: ignore
        return
    if request_id is None:      # notification
        if method == "notifications/initialized" and os.getenv("VICTIM_MCP_LOG_NOTIFICATION") == "1":
            _send({"jsonrpc": "2.0", "method": "notifications/message",
                   "params": {"level": "info", "data": "victim server ready"}})
        return
    if method == "initialize":
        version = (message.get("params") or {}).get("protocolVersion") or DEFAULT_PROTOCOL
        _result(request_id, {"protocolVersion": version, "capabilities": {"tools": {"listChanged": False}},
                             "serverInfo": SERVER_INFO})
    elif method == "ping":
        _result(request_id, {})
    elif method == "tools/list":
        _result(request_id, {"tools": _tools()})
    elif method == "tools/call":
        params = message.get("params") or {}
        name = str(params.get("name", ""))
        if name not in victim.TOOL_REGISTRY:
            _error(request_id, -32602, f"Unknown tool: {name}")
            return
        try:
            value = victim.TOOL_REGISTRY[name]["callable"](**(params.get("arguments") or {}))
            text = value if isinstance(value, str) else json.dumps(value, ensure_ascii=False)
            _result(request_id, {"content": [{"type": "text", "text": text}], "isError": False})
        except Exception as exc:  # tool errors are results, not protocol errors (MCP spec)
            _result(request_id, {"content": [{"type": "text", "text": f"{type(exc).__name__}: {exc}"}],
                                 "isError": True})
    else:
        _error(request_id, -32601, f"Method not found: {method}")


def main() -> int:
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8", newline="\n")
    for line in sys.stdin:
        line = line.strip()
        if not line:
            continue
        try:
            message = json.loads(line)
        except json.JSONDecodeError:
            _error(None, -32700, "Parse error")
            continue
        if isinstance(message, dict):
            handle(message)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
