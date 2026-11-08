"""Backward-compatible import shim for the installable :mod:`shadowmcp` package."""
from __future__ import annotations

from pathlib import Path
import sys
from shadowmcp import core as _core

ROOT = Path(__file__).resolve().parent
_PROXY_MODULE_DIR = ROOT / "shadow_mcp"
if not _PROXY_MODULE_DIR.is_dir():
    _PROXY_MODULE_DIR = ROOT / "shadowmcp"
    from shadowmcp import proxy as _proxy
    sys.modules.setdefault(__name__ + ".proxy", _proxy)
__path__ = [str(_PROXY_MODULE_DIR)]


def __getattr__(name: str):
    return getattr(_core, name)


def __dir__() -> list[str]:
    return sorted(set(globals()) | set(dir(_core)))
