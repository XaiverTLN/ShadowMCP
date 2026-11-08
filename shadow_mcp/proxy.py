"""Compatibility shim for the installable shadowmcp.proxy implementation."""
from shadowmcp.proxy import *  # noqa: F401,F403
from shadowmcp.proxy import _parse_command  # noqa: F401

if __name__ == "__main__":
    raise SystemExit(main())
