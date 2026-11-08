"""Compatibility entry point for the packaged stdio proxy."""
from shadowmcp.proxy import *  # noqa: F401,F403

if __name__ == "__main__":
    raise SystemExit(main())
