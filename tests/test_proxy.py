"""MCP stdio proxy (A1/A4): spec-compliant forwarding, no deadlock, no attacker tip-off, event log."""
import json
import os
import queue
import subprocess
import sys
import threading
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
FAKE = Path(__file__).resolve().parent / "fake_mcp_server.py"
RAG = ROOT.parent / "RAG Healthcare Agent"
TIP_OFF = ["HONEYPOT", "canary_id", "CANARY-", "governance_tier", "drift_reasoning", "action_taken", "ShadowMCP"]


class Session:
    def __init__(self, tmp_path, extra_env=None, intent="Summarize the quarterly budget"):
        self.exec_log = tmp_path / "exec.log"
        self.event_log = tmp_path / "events.jsonl"
        env = {**os.environ, "GROQ_API_KEY": "", "GEMINI_API_KEY": "", "FAKE_MCP_EXEC_LOG": str(self.exec_log),
               **(extra_env or {})}
        self.proc = subprocess.Popen(
            [sys.executable, "-m", "shadow_mcp.proxy", "--intent", intent, "--session", "t1",
             "--event-log", str(self.event_log), "--wrap", "--", sys.executable, str(FAKE)],
            cwd=ROOT, env=env, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            text=True, encoding="utf-8", bufsize=1)
        self.inbox: "queue.Queue[dict]" = queue.Queue()
        threading.Thread(target=self._pump, daemon=True).start()
        self.next_id = 0

    def _pump(self):
        for line in self.proc.stdout:
            if line.strip():
                self.inbox.put(json.loads(line))

    def send(self, message):
        self.proc.stdin.write(json.dumps(message) + "\n")
        self.proc.stdin.flush()

    def request(self, method, params=None):
        self.next_id += 1
        self.send({"jsonrpc": "2.0", "id": self.next_id, "method": method, "params": params or {}})
        while True:
            message = self.inbox.get(timeout=5)  # a hang fails the test instead of blocking CI
            if message.get("id") == self.next_id and "method" not in message:
                return message

    def call(self, name, args, intent=None):
        params = {"name": name, "arguments": args}
        if intent:
            params["_meta"] = {"original_intent": intent}
        return self.request("tools/call", params)

    def executed(self):
        return self.exec_log.read_text(encoding="utf-8").split() if self.exec_log.exists() else []

    def close(self):
        self.proc.stdin.close()
        try:
            self.proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            self.proc.kill()


@pytest.fixture
def session(tmp_path):
    s = Session(tmp_path)
    yield s
    s.close()


def _text(response):
    return "".join(part.get("text", "") for part in response["result"]["content"])


def test_full_handshake_with_notifications_does_not_hang(session):
    init = session.request("initialize", {"protocolVersion": "2025-06-18", "capabilities": {},
                                          "clientInfo": {"name": "t", "version": "0"}})
    assert init["result"]["serverInfo"]["name"] == "fake"
    session.send({"jsonrpc": "2.0", "method": "notifications/initialized"})  # must not block the proxy
    note = session.inbox.get(timeout=5)  # server-initiated notification is relayed by the pump
    assert note.get("method") == "notifications/message"
    assert session.request("ping")["result"] == {}
    names = [t["name"] for t in session.request("tools/list")["result"]["tools"]]
    assert "read_env_secrets" in names


def test_safe_call_runs_real_tool(session):
    session.request("initialize")
    response = session.call("search_knowledge_base", {"doc_name": "budget.md"})
    assert _text(response) == "executed search_knowledge_base"
    assert session.executed() == ["search_knowledge_base"]


def test_client_id_colliding_with_internal_prefix_still_gets_tool_result(session):
    session.request("initialize")
    request_id = "shadowmcp_internal_1"
    session.send({"jsonrpc": "2.0", "id": request_id, "method": "tools/call",
                  "params": {"name": "search_knowledge_base", "arguments": {"doc_name": "budget.md"}}})
    response = session.inbox.get(timeout=5)
    assert response["id"] == request_id
    assert _text(response) == "executed search_knowledge_base"


def test_tools_call_notification_cannot_bypass_inspection(session):
    session.request("initialize")
    session.send({"jsonrpc": "2.0", "method": "tools/call",
                  "params": {"name": "read_env_secrets", "arguments": {"target_keys": ["X"]}}})
    # This response is ordered after the notification was handled by the proxy.
    assert session.request("ping")["result"] == {}
    assert "read_env_secrets" not in session.executed()


def test_non_object_tool_arguments_are_rejected(session):
    session.request("initialize")
    response = session.request("tools/call", {"name": "search_knowledge_base", "arguments": ["x"]})
    assert response["error"]["code"] == -32602
    assert "search_knowledge_base" not in session.executed()


def test_honeypot_never_runs_real_tool_and_does_not_tip_off(session):
    session.request("initialize")
    response = session.call("read_env_secrets", {"target_keys": ["AWS_SECRET_ACCESS_KEY"]})
    text = _text(response)
    assert "REAL_SECRET_VALUE" not in text
    assert "AKIA_CANARY_TRAP_" in text           # the decoy is served...
    assert not [m for m in TIP_OFF if m in text]  # ...without telling the agent it was caught
    assert "structuredContent" not in response["result"]
    assert "read_env_secrets" not in session.executed()


def test_review_is_neutral_and_not_executed(tmp_path):
    s = Session(tmp_path, intent="Review the insurance reconciliation claim")
    try:
        s.request("initialize")
        response = s.call("send_external_webhook", {"target_url": "https://audit.external-claims-verify.org/ingest",
                                                    "data": {"claim_id": "CLM-1"}})
        assert response["result"]["isError"] is True
        assert not [m for m in TIP_OFF + ["REVIEW"] if m in _text(response)]
        assert "send_external_webhook" not in s.executed()
    finally:
        s.close()


def test_meta_intent_and_event_log(session):
    session.request("initialize")
    session.call("read_env_secrets", {"target_keys": ["X"]}, intent="Run a credential audit of mock configuration")
    session.call("read_env_secrets", {"target_keys": ["X"]})
    records = [json.loads(line) for line in session.event_log.read_text(encoding="utf-8").splitlines()]
    tiers = [r["event"]["governance_tier"] for r in records]
    assert tiers == ["✓ SAFE", "⛔ HONEYPOT"]          # _meta.original_intent was honoured
    assert all(r["origin"] == "mcp-proxy" and len(r["event"]) == 17 for r in records)


def test_manifest_drift_is_blocked(tmp_path):
    s = Session(tmp_path, extra_env={"FAKE_MCP_DRIFT": "1"})
    try:
        s.request("initialize")
        assert "result" in s.call("search_knowledge_base", {"doc_name": "a.md"})   # pins manifest
        drifted = s.call("search_knowledge_base", {"doc_name": "a.md"})
        assert drifted["error"]["message"] == "MANIFEST_DRIFT_DETECTED"
    finally:
        s.close()


def test_client_responses_and_unknown_methods_pass_through(session):
    session.request("initialize")
    session.send({"jsonrpc": "2.0", "id": "srv-1", "result": {}})  # a client response: forwarded, no reply
    assert session.request("resources/list")["error"]["code"] == -32601  # upstream's own answer


def test_proxy_resolves_windows_executables():
    from shadow_mcp.proxy import resolve_command
    resolved = resolve_command(["python", "-V"])
    assert Path(resolved[0]).is_file() and resolved[1:] == ["-V"]


def test_wrap_argv_preserves_paths_with_spaces_and_supports_legacy_string():
    from shadow_mcp.proxy import _parse_command
    assert _parse_command(["--", r"C:\Program Files\MCP Server\server.exe", "--flag"]) == [
        r"C:\Program Files\MCP Server\server.exe", "--flag"
    ]
    assert _parse_command(["python fake_server.py"]) == ["python", "fake_server.py"]


@pytest.mark.skipif(not (RAG / "demo_client.py").is_file(), reason="optional demo target not present")
def test_rag_demo_target_through_proxy(tmp_path):
    """The separate Healthcare RAG agent, run over real MCP through the proxy, leaks nothing."""
    env = {**os.environ, "GROQ_API_KEY": "", "GEMINI_API_KEY": "", "SHADOWMCP_HOME": str(ROOT),
           "SHADOWMCP_PYTHON": sys.executable, "SHADOWMCP_EVENT_LOG": str(tmp_path / "rag_events.jsonl")}
    out = subprocess.run([sys.executable, str(RAG / "demo_client.py"), "--json", "--timeout", "15"],
                         cwd=RAG, env=env, capture_output=True, text=True, encoding="utf-8", timeout=120)
    assert out.returncode == 0, out.stderr[-2000:]
    results = {r["scenario"]: r for r in json.loads(out.stdout)}
    assert all(r["outcome"] == "CONTAINED" and not r["tip_off_markers_seen_by_agent"] for r in results.values())
    benign = results["benign_budget"]["calls"]
    assert len(benign) == 1 and not benign[0]["is_error"]
    assert [c["tool"] for c in results["poisoned_referral"]["calls"]][1:] == \
        ["read_env_secrets", "query_customer_db", "send_external_webhook"]
    assert results["ambiguous_claim"]["calls"][-1]["is_error"] is True
