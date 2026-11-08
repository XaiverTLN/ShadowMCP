"""MCP stdio proxy: put ShadowMCP between an MCP client and any stdio MCP server.

    python -m shadow_mcp.proxy [--intent TEXT] [--session ID] [--event-log PATH] --wrap -- <server command...>

Protocol behaviour (newline-delimited JSON-RPC 2.0, MCP stdio transport):
* Requests other than ``tools/call`` (``initialize``, ``tools/list``, ``ping``…), notifications
  (no ``id``) and client responses (no ``method``) are forwarded to the server without waiting.
* A pump thread relays everything the server writes (responses, notifications, server→client
  requests) back to the client, so nothing blocks on a message that never gets a reply.
* ``tools/call`` requests are inspected first. Calls sent as JSON-RPC notifications (without an
  id) are dropped so they cannot bypass inspection. ✓ SAFE calls are forwarded. Every other tier gets a
  tool-shaped result produced locally; the real tool never runs. The agent-visible text never
  reveals that it was caught (no tier, canary ID or reasoning): HONEYPOT returns the canary text,
  REVIEW and hard blocks return a neutral "not executed" message. Routing records go to the
  event log (explicit ``--event-log`` or ``SHADOWMCP_EVENT_LOG`` opt-in); the current dashboard
  does not yet consume this log. Event logs contain prompts and tool arguments, so protect and
  rotate them as sensitive data.
* The tool manifest is pinned on first use and re-checked before each call (rug-pull detection).
"""

from __future__ import annotations

import argparse
import json
import os
import queue
import shlex
import shutil
import subprocess
import sys
import threading
from typing import Any, Optional

import shadow_mcp as core

INTERNAL_PREFIX = "shadowmcp_internal_"


def resolve_command(command: list[str]) -> list[str]:
    """Resolve the executable via PATH/PATHEXT so ``npx`` works on Windows (``npx.cmd``)."""
    if not command:
        return command
    found = shutil.which(command[0])
    return [found or command[0], *command[1:]]


class StdioProxy:
    def __init__(self, command: list[str], intent: str = "Use the requested tool",
                 session_id: str = "default", source: str = "mcp-proxy",
                 policies: Optional[dict[str, Any]] = None, out=None, timeout: float = 30.0):
        self.command = resolve_command(command)
        self.intent = intent
        self.session_id = session_id
        self.source = source
        self.policies = policies
        self.timeout = timeout
        self.out = out or sys.stdout
        self.child: Optional[subprocess.Popen[str]] = None
        self.pinned_hashes: Optional[dict[str, str]] = None
        self.manifest: dict[str, dict[str, Any]] = {}
        self._internal_id = 0
        self._retired_internal_ids: set[str] = set()
        self._write_lock = threading.Lock()
        self._child_lock = threading.Lock()
        self._waiters: dict[str, "queue.Queue[dict[str, Any]]"] = {}
        self._waiters_lock = threading.Lock()
        self._pump_thread: Optional[threading.Thread] = None

    # ------------------------------------------------------------------ process plumbing
    def start(self) -> None:
        self.child = subprocess.Popen(
            self.command, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=sys.stderr,
            text=True, encoding="utf-8", errors="replace", bufsize=1,
        )
        self._pump_thread = threading.Thread(target=self._pump, name="shadowmcp-pump", daemon=True)
        self._pump_thread.start()

    def stop(self) -> None:
        if self.child is not None:
            try:
                if self.child.stdin:
                    self.child.stdin.close()
            except OSError:
                pass
            if self.child.poll() is None:
                try:
                    self.child.terminate()
                except OSError:
                    pass  # the process may have exited between poll() and terminate()
                try:
                    self.child.wait(timeout=2)
                except subprocess.TimeoutExpired:
                    try:
                        self.child.kill()
                    except OSError:
                        pass
            self.child = None

    def emit(self, message: dict[str, Any]) -> None:
        """Write one message to the client."""
        with self._write_lock:
            self.out.write(json.dumps(message, ensure_ascii=False) + "\n")
            self.out.flush()

    def _to_child(self, message: dict[str, Any]) -> None:
        assert self.child and self.child.stdin
        with self._child_lock:
            self.child.stdin.write(json.dumps(message, ensure_ascii=False) + "\n")
            self.child.stdin.flush()

    def _pump(self) -> None:
        """Relay server output to the client; route replies to internal requests to their waiter."""
        assert self.child and self.child.stdout
        for line in self.child.stdout:
            if not line.strip():
                continue
            try:
                message = json.loads(line)
            except json.JSONDecodeError:
                # Keep stdout protocol-clean: non-JSON server chatter goes to stderr.
                print(line.rstrip(), file=sys.stderr, flush=True)
                continue
            request_id = message.get("id") if isinstance(message, dict) else None
            if (isinstance(message, dict) and isinstance(request_id, str)
                    and request_id.startswith(INTERNAL_PREFIX) and "method" not in message):
                with self._waiters_lock:
                    waiter = self._waiters.pop(request_id, None)
                    retired = request_id in self._retired_internal_ids
                    self._retired_internal_ids.discard(request_id)
                if waiter:
                    waiter.put(message)
                    continue
                if retired:
                    continue
                # A client may legitimately use our prefix. Relay unmatched ids so its
                # actual tool result is not swallowed as an internal protocol response.
            self.emit(message)
        # Server exited: fail any internal request still waiting.
        with self._waiters_lock:
            waiters, self._waiters = list(self._waiters.values()), {}
        for waiter in waiters:
            waiter.put({"error": {"code": -32000, "message": "Wrapped MCP server exited."}})

    def _internal_request(self, method: str, params: Optional[dict[str, Any]] = None) -> dict[str, Any]:
        self._internal_id += 1
        request_id = f"{INTERNAL_PREFIX}{self._internal_id}"
        waiter: "queue.Queue[dict[str, Any]]" = queue.Queue()
        with self._waiters_lock:
            self._waiters[request_id] = waiter
        try:
            self._to_child({"jsonrpc": "2.0", "id": request_id, "method": method, "params": params or {}})
            return waiter.get(timeout=self.timeout)
        except queue.Empty:
            with self._waiters_lock:
                self._waiters.pop(request_id, None)
                self._retired_internal_ids.add(request_id)
            return {"error": {"code": -32000, "message": "Wrapped server did not answer in time."}}
        except Exception as exc:
            with self._waiters_lock:
                self._waiters.pop(request_id, None)
                self._retired_internal_ids.add(request_id)
            print(f"shadowmcp-proxy: internal request failed ({type(exc).__name__})", file=sys.stderr, flush=True)
            return {"error": {"code": -32000, "message": "Wrapped server request failed."}}
        finally:
            with self._waiters_lock:
                self._waiters.pop(request_id, None)

    # ------------------------------------------------------------------ manifest pinning
    @staticmethod
    def _normalized_manifest(tools: Any) -> list[dict[str, Any]]:
        if not isinstance(tools, list):
            return []
        return [{"name": str(tool.get("name", "")), "description": str(tool.get("description", "")),
                 "parameters_schema": tool.get("parameters_schema", tool.get("inputSchema", {}))}
                for tool in tools if isinstance(tool, dict)]

    def _check_manifest(self) -> Optional[dict[str, Any]]:
        """Pin the manifest on first use, then detect drift. Returns a JSON-RPC error object or None."""
        response = self._internal_request("tools/list")
        if response.get("error"):
            return {"code": -32001, "message": "Could not verify the tool manifest."}
        tools = self._normalized_manifest((response.get("result") or {}).get("tools", []))
        check = core.verify_mcp_tool_manifest(tools, self.pinned_hashes)
        self.manifest = {tool["name"]: tool for tool in tools}
        if self.pinned_hashes is None:
            self.pinned_hashes = check["pinned_hashes"]
            return None
        if not check["valid"]:
            return {"code": -32001, "message": "MANIFEST_DRIFT_DETECTED"}
        return None

    # ------------------------------------------------------------------ message handling
    def handle(self, message: Any) -> Optional[dict[str, Any]]:
        """Process one client message. Returns a reply to write, or None if it was forwarded."""
        if not isinstance(message, dict) or message.get("jsonrpc") != "2.0":
            return {"jsonrpc": "2.0", "id": None, "error": {"code": -32600, "message": "Invalid Request"}}
        method = message.get("method")
        if method == "tools/call" and "id" not in message:
            # Notifications have no response path, so silently drop this invalid MCP tool
            # call instead of forwarding an operation the firewall cannot evaluate.
            print("shadowmcp-proxy: dropped tools/call notification without request id",
                  file=sys.stderr, flush=True)
            return None
        if method != "tools/call":
            self._to_child(message)            # requests, notifications and client responses
            return None
        request_id = message["id"]
        error = self._check_manifest()
        if error:
            return {"jsonrpc": "2.0", "id": request_id, "error": error}
        params = message.get("params") or {}
        if not isinstance(params, dict):
            return {"jsonrpc": "2.0", "id": request_id,
                    "error": {"code": -32602, "message": "Invalid params."}}
        name = str(params.get("name", ""))
        if name not in self.manifest:
            return {"jsonrpc": "2.0", "id": request_id, "error": {"code": -32602, "message": f"Unknown tool: {name}"}}
        arguments = params.get("arguments") or {}
        if not isinstance(arguments, dict):
            return {"jsonrpc": "2.0", "id": request_id,
                    "error": {"code": -32602, "message": "Tool arguments must be an object."}}
        meta = params.get("_meta") or {}
        if not isinstance(meta, dict):
            meta = {}
        intent = str(meta.get("original_intent") or self.intent)[:500]
        session = str(meta.get("session_id") or self.session_id)
        event = core.evaluate_and_route_tool_call(intent, name, arguments, self.source, session,
                                                  policies=self.policies)
        if event["governance_tier"] == "✓ SAFE":
            self._to_child(message)            # real tool runs; the pump relays its result
            return None
        return {"jsonrpc": "2.0", "id": request_id, "result": agent_visible_result(event)}


def agent_visible_result(event: dict[str, Any]) -> dict[str, Any]:
    """What the (possibly hijacked) agent sees for a non-SAFE call. Never reveals the verdict."""
    return core.agent_visible_tool_result(event)


def _parse_command(wrap: list[str]) -> list[str]:
    command = list(wrap or [])
    is_argv_form = bool(command and command[0] == "--")
    if is_argv_form:
        command = command[1:]
    # The explicit argv form must preserve paths containing spaces as one argument.
    # Only split the legacy single-string form for compatibility with older configs.
    if len(command) == 1 and not is_argv_form:
        command = shlex.split(command[0], posix=(os.name != "nt"))
    return command


def main(argv: Optional[list[str]] = None) -> int:
    parser = argparse.ArgumentParser(description="Wrap a stdio MCP server with ShadowMCP inspection.")
    parser.add_argument("--intent", default=os.getenv("SHADOWMCP_INTENT", "Use the requested tool"),
                        help="Default user intent when the client sends no _meta.original_intent")
    parser.add_argument("--session", default="default", help="Session ID used for taint tracking")
    parser.add_argument("--source", default="mcp-proxy", help="Label recorded as retrieved_source")
    parser.add_argument("--event-log", default=None,
                        help="Opt in to a JSONL routing log at this path (contains prompts and tool arguments)")
    parser.add_argument("--wrap", metavar="-- COMMAND ...",
                        help="Upstream MCP server command; everything after --wrap is passed through, e.g. "
                             "--wrap -- npx -y @modelcontextprotocol/server-filesystem .")
    argv = list(sys.argv[1:] if argv is None else argv)
    # Split at --wrap by hand: argparse.REMAINDER mishandles a leading "--".
    wrap: list[str] = []
    if "--wrap" in argv:
        index = argv.index("--wrap")
        argv, wrap = argv[:index], argv[index + 1:]
    options = parser.parse_args(argv)
    command = _parse_command(wrap)
    if not command:
        parser.error("--wrap requires an MCP server command")
    core.enable_event_log(options.event_log, origin="mcp-proxy")
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8", errors="replace", newline="\n")
    if hasattr(sys.stdin, "reconfigure"):
        sys.stdin.reconfigure(encoding="utf-8", errors="replace")

    proxy = StdioProxy(command, options.intent, options.session, options.source)
    try:
        proxy.start()
    except OSError as exc:
        print(f"shadowmcp-proxy: could not start {command[0]!r}: {exc}", file=sys.stderr)
        return 2
    try:
        for line in sys.stdin:
            if not line.strip():
                continue
            try:
                message = json.loads(line)
            except json.JSONDecodeError:
                proxy.emit({"jsonrpc": "2.0", "id": None, "error": {"code": -32700, "message": "Parse error"}})
                continue
            try:
                reply = proxy.handle(message)
            except Exception as exc:  # never crash the stdio session on one bad message
                print(f"shadowmcp-proxy: request failed ({type(exc).__name__})", file=sys.stderr, flush=True)
                request_id = message.get("id") if isinstance(message, dict) else None
                reply = {"jsonrpc": "2.0", "id": request_id,
                         "error": {"code": -32000, "message": "Request could not be processed."}}
            if reply is not None:
                proxy.emit(reply)
    finally:
        proxy.stop()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
