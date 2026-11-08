"""Launch the bundled Streamlit dashboard from an installed distribution."""

from __future__ import annotations

import importlib.util
import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

from importlib.resources import files as package_files


def main() -> int:
    spec = importlib.util.find_spec("app")
    if spec is None or not spec.origin:
        raise RuntimeError("ShadowMCP dashboard module is missing from this installation.")
    env = os.environ.copy()
    # Streamlit's help and startup messages contain Unicode; this matters on Windows consoles
    # whose default code page cannot encode the UI's arrows and status glyphs.
    env["PYTHONUTF8"] = "1"
    env["PYTHONIOENCODING"] = "utf-8"
    app_path = Path(spec.origin).resolve()
    command_prefix = [
        sys.executable, "-m", "streamlit", "run",
    ]
    streamlit_options = [
        "--server.address=127.0.0.1",
        "--server.enableStaticServing=true",
        "--client.toolbarMode=viewer",
    ]
    if (app_path.parent / "static" / "world_110m.json").is_file():
        return subprocess.call(command_prefix + [str(app_path), *streamlit_options, *sys.argv[1:]],
                               cwd=str(app_path.parent), env=env)

    # A wheel keeps the app and offline basemap inside site-packages. Streamlit expects static
    # assets next to its script, so materialize a temporary launch copy instead of writing into
    # the installed package directory.
    with tempfile.TemporaryDirectory(prefix="shadowmcp-dashboard-") as temp_dir:
        launch_dir = Path(temp_dir)
        launch_app = launch_dir / "app.py"
        shutil.copyfile(app_path, launch_app)
        static_dir = launch_dir / "static"
        static_dir.mkdir()
        topojson = package_files("shadowmcp").joinpath("data", "world_110m.json")
        (static_dir / "world_110m.json").write_bytes(topojson.read_bytes())
        return subprocess.call(command_prefix + [str(launch_app), *streamlit_options, *sys.argv[1:]],
                               cwd=str(launch_dir), env=env)
