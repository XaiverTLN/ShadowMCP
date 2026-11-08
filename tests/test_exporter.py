import json
import queue
import subprocess
import threading
import sys
from pathlib import Path

import pytest

from shadowmcp import core


def test_exporter_emits_argv_form_with_resolved_paths(monkeypatch):
    resolved = {
        "npx": r"C:\Node\npx.cmd",
        "shadowmcp-proxy": r"C:\Python\Scripts\shadowmcp-proxy.exe",
    }
    monkeypatch.setattr(core.shutil, "which", lambda name: resolved.get(name))

    text = core.export_protected_mcp_config(
        "local-files",
        ["npx", "-y", "@modelcontextprotocol/server-filesystem", "folder with spaces"],
        "List only approved files",
    )
    config = json.loads(text)["mcpServers"]["local-files"]

    assert config["command"] == resolved["shadowmcp-proxy"]
    assert config["args"] == [
        "--intent", "List only approved files", "--wrap", "--",
        resolved["npx"], "-y", "@modelcontextprotocol/server-filesystem", "folder with spaces",
    ]


def test_exporter_rejects_invalid_or_unresolved_argv(monkeypatch):
    monkeypatch.setattr(core.shutil, "which", lambda _name: None)
    with pytest.raises(ValueError, match="JSON array"):
        core.export_protected_mcp_config("server", "not json")
    with pytest.raises(ValueError, match="non-empty JSON array"):
        core.export_protected_mcp_config("server", ["npx", 2])
    with pytest.raises(FileNotFoundError, match="Cannot find upstream executable"):
        core.export_protected_mcp_config("server", ["missing-server-binary"])


def test_exporter_accepts_json_argv_and_uses_module_fallback(monkeypatch):
    monkeypatch.setattr(core.shutil, "which", lambda _name: None)
    python_executable = sys.executable
    fallback_python = r"C:\MissingPython\python.exe"
    monkeypatch.setattr(core.sys, "executable", fallback_python)
    text = core.export_protected_mcp_config(
        "local", json.dumps([python_executable, "server file.py"]), "Do the requested work"
    )
    config = json.loads(text)["mcpServers"]["local"]
    assert config["command"] == fallback_python
    assert config["args"][:3] == ["-m", "shadowmcp.proxy", "--intent"]
    assert config["args"][-2:] == [python_executable, "server file.py"]


def test_generated_config_runs_proxy_from_another_working_directory(tmp_path):
    fake_server = str((Path(__file__).parent / "fake_mcp_server.py").resolve())
    config = json.loads(
        core.export_protected_mcp_config(
            "fake", [sys.executable, fake_server], "Initialize only"
        )
    )["mcpServers"]["fake"]
    proc = subprocess.Popen(
        [config["command"], *config["args"]],
        stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        text=True, encoding="utf-8", cwd=tmp_path, bufsize=1,
    )
    assert proc.stdin is not None and proc.stdout is not None
    responses = queue.Queue()
    reader = threading.Thread(target=lambda: responses.put(proc.stdout.readline()), daemon=True)
    try:
        proc.stdin.write(json.dumps({"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}}) + chr(10))
        proc.stdin.flush()
        reader.start()
        line = responses.get(timeout=5)
        assert "protocolVersion" in line and "2025-06-18" in line
    finally:
        if proc.stdin and not proc.stdin.closed:
            proc.stdin.close()
        if proc.poll() is None:
            proc.terminate()
            proc.wait(timeout=2)
