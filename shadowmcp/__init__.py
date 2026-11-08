"""Installable public API for ShadowMCP.

The original facade remains in ``shadow_mcp.py`` for compatibility. New code should import from
``shadowmcp``; the wrapper preserves the six documented facade names and optional adapters.
"""

from .core import (
    adk_shadow_mcp_after_tool_callback,
    adk_shadow_mcp_before_tool_callback,
    evaluate_and_route_tool_call,
    export_protected_mcp_config,
    format_plain_english_receipt,
    get_dashboard_state,
    handle_mcp_jsonrpc_request,
    resolve_human_review,
    run_custom_redteam_prompt,
    run_preset_scenario,
    shadow_mcp_guard,
    verify_mcp_tool_manifest,
)

__all__ = [
    "get_dashboard_state",
    "run_preset_scenario",
    "run_custom_redteam_prompt",
    "resolve_human_review",
    "format_plain_english_receipt",
    "export_protected_mcp_config",
    "evaluate_and_route_tool_call",
    "shadow_mcp_guard",
    "adk_shadow_mcp_before_tool_callback",
    "adk_shadow_mcp_after_tool_callback",
    "verify_mcp_tool_manifest",
    "handle_mcp_jsonrpc_request",
]
