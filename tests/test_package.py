"""Compatibility tests for the new installable package surface."""

from pathlib import Path

import shadow_mcp as legacy
import shadowmcp
import shadowmcp.core as packaged_core
import shadowmcp.proxy as packaged_proxy
from shadow_mcp.proxy import StdioProxy as legacy_proxy


def test_package_exports_the_six_spec_facades():
    expected = (
        "get_dashboard_state",
        "run_preset_scenario",
        "run_custom_redteam_prompt",
        "resolve_human_review",
        "format_plain_english_receipt",
        "export_protected_mcp_config",
    )
    assert all(callable(getattr(shadowmcp, name)) for name in expected)
    assert all(getattr(shadowmcp, name) is getattr(legacy, name) for name in expected)
    assert Path(packaged_core.__file__).name == "core.py"
    assert Path(packaged_core.__file__).parent.name == "shadowmcp"
    assert Path(legacy.__file__).name == "shadow_mcp.py"
    assert len(Path(legacy.__file__).read_text(encoding="utf-8").splitlines()) < 30


def test_legacy_proxy_path_reexports_packaged_proxy():
    assert legacy_proxy is packaged_proxy.StdioProxy
    assert callable(packaged_proxy.main)
