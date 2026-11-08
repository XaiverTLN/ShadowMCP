"""Universal ShadowMCP tool-call inspection and routing middleware.

Core inspection accepts arbitrary tool metadata. The healthcare victim is
loaded only by the optional preset-demo adapter near the bottom of this file.
"""

from __future__ import annotations

import hashlib
import hmac
import importlib.util
import inspect
import json
import os
import shutil
import sys
import re
import threading
import time
import uuid
from collections import OrderedDict, defaultdict, deque
from datetime import datetime, timezone
from importlib.resources import files as package_files
from pathlib import Path
from typing import Any, Callable, Optional

from pydantic import BaseModel, ConfigDict, Field

import llm_client

ROOT = Path(__file__).resolve().parent.parent
REQUIRED_EVENT_KEYS = [
    "event_id", "timestamp", "original_intent", "retrieved_source", "tool_called", "tool_args",
    "stage_triggered", "latency_ms", "risk_score", "governance_tier", "owasp_mapping",
    "drift_reasoning", "action_taken", "real_payload_blocked", "canary_payload_served",
    "canary_id", "attacker_exfil_endpoint",
]
OWASP_MAPPING = (
    "ASI01: Agent Goal Hijack / ASI02: Tool Misuse & Exploitation / "
    "ASI06: Memory & Context Poisoning"
)


class InterceptedEvent(BaseModel):
    model_config = ConfigDict(extra="forbid")
    event_id: str
    timestamp: str
    original_intent: str
    retrieved_source: str
    tool_called: str
    tool_args: dict[str, Any]
    stage_triggered: str
    latency_ms: int = Field(ge=0)
    risk_score: float = Field(ge=0.0, le=1.0)
    governance_tier: str
    owasp_mapping: str
    drift_reasoning: str
    action_taken: str
    real_payload_blocked: str
    canary_payload_served: str
    canary_id: str
    attacker_exfil_endpoint: str


_LOCK = threading.RLock()
SESSION_TAINT_STATE: dict[str, bool] = {}
PENDING_REVIEWS: dict[str, dict[str, Any]] = {}
EVENTS: deque[dict[str, Any]] = deque(maxlen=1000)
CANARY_ALERTS: deque[dict[str, Any]] = deque(maxlen=1000)
MCP_TOOL_REGISTRY: dict[str, dict[str, Any]] = {}
_CUSTOM_CALLS: dict[str, deque[tuple[float, str]]] = defaultdict(deque)
_EVENT_COUNT = 0
_CANARY_COUNT = 0
_SERVER_QUARANTINED = False

try:
    _SEED = json.loads((ROOT / "seed_telemetry.json").read_text(encoding="utf-8"))
except Exception:
    try:
        _SEED = json.loads(package_files("shadowmcp").joinpath("data", "seed_telemetry.json").read_text(encoding="utf-8"))
    except Exception:
        _SEED = {}
_SEED_KPIS = _SEED.get("kpis", {})


def _entropy(value: str) -> float:
    if not value:
        return 0.0
    length = len(value)
    return -sum((n / length) * (0 if n == 0 else __import__("math").log2(n / length))
                for n in {char: value.count(char) for char in set(value)}.values())


def _walk_strings(value: Any):
    if isinstance(value, str):
        yield value
    elif isinstance(value, dict):
        for key, item in value.items():
            yield from _walk_strings(str(key))
            yield from _walk_strings(item)
    elif isinstance(value, (list, tuple, set)):
        for item in value:
            yield from _walk_strings(item)


_META_PATTERNS = [re.compile(r"ignore\s+(all\s+)?(previous|prior|intent)", re.I),
                  re.compile(r"risk_score\s*[:=]\s*0(?:\.0+)?", re.I)]
_RISK_PATTERNS: list[tuple[re.Pattern[str], float, str]] = [
    (re.compile(r"\.env|AWS_SECRET|PRIVATE_KEY|/etc/passwd|EHR_DB_PASSWORD", re.I), .94, "credential/config access signature"),
    (re.compile(r"DROP\s+TABLE|UNION\s+SELECT|SELECT\s+.*\s+FROM\s+patients|rm\s+-rf|curl\s+.*\|\s*bash", re.I | re.S), .95, "destructive SQL or shell signature"),
    (re.compile(r"\b\d{3}-\d{2}-\d{4}\b"), .89, "SSN/PHI signature"),
    (re.compile(r"base64|b64encode|atob|fromhex", re.I), .89, "encoded payload signature"),
    (re.compile(r"https?://\d{1,3}(?:\.\d{1,3}){3}", re.I), .96, "raw-IP outbound destination"),
    (re.compile(r"http://[^\s\"']*collect", re.I), .96, "collection endpoint signature"),
]


_PHI_REASON = "SSN/PHI signature"


def stage1_deterministic_check(
    original_intent: str,
    tool_name: str,
    tool_args: dict[str, Any],
    session_id: str = "default",
    skip_phi_regex: bool = False,
) -> dict[str, Any]:
    """Fast pure-Python regex, entropy, confused-deputy, and taint checks.

    ``skip_phi_regex`` disables only the SSN/PHI signature (no-code policy override).
    """
    started = time.perf_counter()
    serialized = json.dumps(tool_args or {}, sort_keys=True, default=str)
    target = f"{tool_name} {serialized}"
    risk, reasons = 0.0, []

    if any(pattern.search(serialized) for pattern in _META_PATTERNS):
        risk = max(risk, .99)
        reasons.append("meta-injection or score-downgrade attempt")
    for pattern, score, reason in _RISK_PATTERNS:
        if skip_phi_regex and reason == _PHI_REASON:
            continue
        if pattern.search(target):
            risk = max(risk, score)
            reasons.append(reason)

    for value in _walk_strings(tool_args or {}):
        if len(value) > 32 and _entropy(value) > 4.6:
            risk = max(risk, .82)
            reasons.append("high-entropy value may contain a secret")
            break

    intent = str(original_intent or "").casefold()
    tool = str(tool_name or "").casefold()
    explicit_secret = any(word in intent for word in ("credential inspection", "inspect credentials", "inspect secrets", "secret audit", "credential audit", "mock configuration"))
    explicit_webhook = any(word in intent for word in ("webhook test", "test webhook", "send webhook", "send email"))
    args_lower = target.casefold()
    if tool == "send_external_webhook" and "audit.external-claims-verify.org" in args_lower:
        risk = max(risk, .58)
        reasons.append("external reconciliation endpoint in retrieved tool arguments")
    elif tool == "read_env_secrets" and not explicit_secret:
        risk = max(risk, .90)
        reasons.append("confused deputy: credential tool is outside the user's stated intent")
    elif tool == "send_external_webhook" and not explicit_webhook:
        risk = max(risk, .90)
        reasons.append("confused deputy: outbound tool is outside the user's stated intent")

    taint_chain = tool in {"send_external_webhook", "send_email"} and SESSION_TAINT_STATE.get(session_id, False)
    if taint_chain:
        reasons.append("session taint chain: internal data access preceded an outbound call")

    return {
        "risk_score": float(min(1.0, max(0.0, risk))),
        "base_risk": float(min(1.0, max(0.0, risk))),
        "reasons": reasons,
        "stage_triggered": "SESSION_TAINT_CHAIN" if taint_chain else ("STAGE_1_HEURISTIC" if reasons else "STAGE_2_SEMANTIC"),
        "latency_ms": int((time.perf_counter() - started) * 1000),
    }


def _tier(risk: float) -> str:
    if risk <= .40:
        return "✓ SAFE"
    if risk <= .75:
        return "⚠ REVIEW"
    return "⛔ HONEYPOT"


def _endpoint(tool_args: dict[str, Any]) -> str:
    raw = json.dumps(tool_args or {}, sort_keys=True, default=str)
    match = re.search(r"https?://[^\s\"',}]+", raw, re.I)
    if not match:
        return "LOCAL_SANDBOX"
    url = match.group(0).rstrip(")]")
    if "198.51.100.42" in url:
        return f"{url} (Berlin, DE — LAT: 52.5200, LON: 13.4050)"
    return url


def _next_event_id() -> str:
    global _EVENT_COUNT
    with _LOCK:
        _EVENT_COUNT += 1
        now = datetime.now(timezone.utc)
        return f"evt_{now:%Y%m%d_%H%M%S}_{_EVENT_COUNT:04d}"


def _next_canary_id() -> str:
    global _CANARY_COUNT
    with _LOCK:
        _CANARY_COUNT += 1
        return f"CANARY-{_CANARY_COUNT % 10000:04d}-ORL"


INTERNAL_DATA_TOOLS = frozenset({"read_env_secrets", "read_config", "query_customer_db", "query_database", "read_database"})
OUTBOUND_TOOLS = frozenset({"send_external_webhook", "send_email", "http_post"})


# --- No-code policy overrides ------------------------------------------------
# All three default to ON (SPEC behaviour). Callers may pass a partial dict; unknown keys are ignored.
POLICY_DEFAULTS: dict[str, bool] = {
    "block_phi_export": True,        # Stage 1 SSN/PHI regex
    "require_hitl_external": True,   # Tier 2 outbound calls wait for a human
    "serve_canary": True,            # Tier 3 serves deception credentials (else hard block)
}


def normalize_policies(policies: Optional[dict[str, Any]] = None) -> dict[str, bool]:
    merged = dict(POLICY_DEFAULTS)
    for key, value in (policies or {}).items():
        if key in merged:
            merged[key] = value if isinstance(value, bool) else str(value).strip().lower() in {"1", "true", "yes", "on"}
    return merged


# Post-decision work (canary synthesis, operator brief) is timed separately from interception latency.
POST_BLOCK_TIMINGS: "OrderedDict[str, dict[str, Any]]" = OrderedDict()
_MAX_TIMINGS = 1000


def _record_post_block(event_id: str, **timings: Any) -> None:
    """Merge post-decision metrics for an event: *_ms are ints, *_source are producer IDs."""
    with _LOCK:
        entry = POST_BLOCK_TIMINGS.setdefault(event_id, {})
        entry.update({k: (int(v) if k.endswith("_ms") else str(v)) for k, v in timings.items()})
        POST_BLOCK_TIMINGS.move_to_end(event_id)
        while len(POST_BLOCK_TIMINGS) > _MAX_TIMINGS:
            POST_BLOCK_TIMINGS.popitem(last=False)


def _hard_block_values(is_outbound: bool) -> tuple[str, str, str]:
    """(action, canary_payload, canary_id) when deception is disabled by policy."""
    action = "SINKHOLED_C2_EXFILTRATION" if is_outbound else "BLOCKED_NO_DECEPTION"
    return action, "N/A - Hard Block (Deception Disabled by Policy)", "NONE"


def mark_session_tainted(session_id: str = "default") -> None:
    """Mark a session only after an internal data/config tool really ran."""
    with _LOCK:
        SESSION_TAINT_STATE[session_id] = True


def _canary_alert_record(event: dict[str, Any]) -> dict[str, Any]:
    endpoint = str(event.get("attacker_exfil_endpoint", ""))
    lat = re.search(r"LAT:\s*(-?\d+(?:\.\d+)?)", endpoint, re.I)
    lon = re.search(r"LON:\s*(-?\d+(?:\.\d+)?)", endpoint, re.I)
    return {
        "event_id": event["event_id"],
        "canary_id": event["canary_id"],
        "endpoint": endpoint,
        "latitude": float(lat.group(1)) if lat else None,
        "longitude": float(lon.group(1)) if lon else None,
    }


def default_event_log_path() -> str:
    """Return a conventional location for an operator who explicitly enables JSONL logging."""
    return str(Path.home() / ".shadowmcp" / "events.jsonl")


_LOG_LOCK = threading.Lock()
_EVENT_LOG: dict[str, str] = {}  # {"path": ..., "origin": ...} once an adapter opts in


def enable_event_log(path: Optional[str] = None, origin: str = "mcp-proxy") -> str:
    """Enable JSONL routing logs only when an explicit path or environment value is supplied.

    Events contain user prompts and tool arguments. Persisting them to a home-directory file by
    default would create an unexpected prompt archive, so logging is opt-in.
    """
    target = str(path or os.getenv("SHADOWMCP_EVENT_LOG", "").strip()).strip()
    if not target:
        _EVENT_LOG.clear()
        return ""
    _EVENT_LOG.update({"path": target, "origin": origin})
    return target


def _append_event_log(event: dict[str, Any]) -> None:
    """Append one routing record to the opted-in event log. No-op otherwise; never raises."""
    path = _EVENT_LOG.get("path")
    if not path:
        return
    try:
        Path(path).parent.mkdir(parents=True, exist_ok=True)
        line = json.dumps({"origin": _EVENT_LOG.get("origin", "adapter"), "pid": os.getpid(), "event": event},
                          ensure_ascii=False, default=str)
        with _LOG_LOCK, open(path, "a", encoding="utf-8") as handle:
            handle.write(line + "\n")
    except OSError:
        pass


def read_event_log(path: Optional[str] = None, limit: int = 200) -> list[dict[str, Any]]:
    """Read an explicitly selected log; never search a home-directory prompt archive by default."""
    selected = str(path or os.getenv("SHADOWMCP_EVENT_LOG", "").strip()).strip()
    if not selected:
        return []
    target = Path(selected)
    if not target.is_file():
        return []
    try:
        with open(target, "rb") as handle:  # read only the tail so a long log stays cheap
            handle.seek(0, os.SEEK_END)
            size = handle.tell()
            handle.seek(max(0, size - 512_000))
            lines = handle.read().decode("utf-8", errors="replace").splitlines()
    except OSError:
        return []
    records: list[dict[str, Any]] = []
    for line in reversed(lines):
        try:
            record = json.loads(line)
        except json.JSONDecodeError:
            continue
        if isinstance(record, dict) and isinstance(record.get("event"), dict):
            records.append(record)
        if len(records) >= limit:
            break
    return records


def _store_event(event: dict[str, Any], *, record_alert: bool = True) -> dict[str, Any]:
    with _LOCK:
        EVENTS.appendleft(event)
        if event["governance_tier"] == "⚠ REVIEW":
            PENDING_REVIEWS[event["event_id"]] = event
        if record_alert and event["governance_tier"] == "⛔ HONEYPOT" and event["canary_id"] != "NONE":
            CANARY_ALERTS.appendleft(_canary_alert_record(event))
    _append_event_log(event)
    return event


def _validated_event(values: dict[str, Any]) -> dict[str, Any]:
    event = InterceptedEvent(**values).model_dump()
    if list(event.keys()) != REQUIRED_EVENT_KEYS:
        # Pydantic's declaration order is the canonical serialization order.
        event = {key: event[key] for key in REQUIRED_EVENT_KEYS}
    return event


def set_server_quarantine(enabled: bool) -> bool:
    """Enable or release the global kill switch used by every adapter."""
    global _SERVER_QUARANTINED
    with _LOCK:
        _SERVER_QUARANTINED = bool(enabled)
        return _SERVER_QUARANTINED


def evaluate_and_route_tool_call(
    original_intent: str,
    tool_name: str,
    tool_args: dict[str, Any],
    retrieved_source: str = "custom_input.md",
    session_id: str = "default",
    custom_keys: Optional[dict[str, Any]] = None,
    deterministic_judge: bool = False,
    policies: Optional[dict[str, Any]] = None,
) -> dict[str, Any]:
    """Inspect any tool call and return its validated 17-field routing record.

    ``deterministic_judge`` swaps Stage 2 for the local deterministic judge (scripted demo presets).
    ``policies`` applies no-code overrides (see ``POLICY_DEFAULTS``); omitted means all rules ON.
    ``latency_ms`` is interception latency: time to reach the routing decision. Post-decision work
    (canary synthesis, operator brief) is recorded in ``POST_BLOCK_TIMINGS`` instead.
    """
    started = time.perf_counter()
    intent = str(original_intent or "")[:500]
    args = dict(tool_args or {})
    policy = normalize_policies(policies)
    with _LOCK:
        quarantined = _SERVER_QUARANTINED
    if quarantined:
        event_id = _next_event_id()
        canary_id = _next_canary_id()
        is_outbound = str(tool_name).casefold() in OUTBOUND_TOOLS
        serial = canary_id.split("-")[1]
        q_action = "SINKHOLED_C2_EXFILTRATION" if is_outbound else "REROUTED_TO_GEMINI_CANARY_HONEYPOT"
        q_canary = f"AWS_SECRET_ACCESS_KEY=AKIA_CANARY_TRAP_{serial}_DEVFEST | PATIENT_SSN_SAMPLE=000-99-CANARY"
        if not policy["serve_canary"]:
            q_action, q_canary, canary_id = _hard_block_values(is_outbound)
        event = _validated_event({
            "event_id": event_id,
            "timestamp": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
            "original_intent": intent,
            "retrieved_source": str(retrieved_source or "custom_input.md"),
            "tool_called": str(tool_name),
            "tool_args": args,
            "stage_triggered": "STAGE_1_HEURISTIC",
            "latency_ms": max(0, int((time.perf_counter() - started) * 1000)),
            "risk_score": 1.0,
            "governance_tier": "⛔ HONEYPOT",
            "owasp_mapping": OWASP_MAPPING,
            "drift_reasoning": "Server quarantine is active; the real tool call was stopped before execution.",
            "action_taken": q_action,
            "real_payload_blocked": f"Server quarantine blocked {tool_name} before execution.",
            "canary_payload_served": q_canary,
            "canary_id": canary_id,
            "attacker_exfil_endpoint": _endpoint(args) if is_outbound else "LOCAL_SANDBOX",
        })
        return _store_event(event)
    stage1 = stage1_deterministic_check(intent, tool_name, args, session_id,
                                        skip_phi_regex=not policy["block_phi_export"])
    semantic = llm_client.judge_intent_drift(intent, tool_name, args, retrieved_source, custom_keys,
                                             force_local=deterministic_judge)
    stage1_risk = float(stage1["risk_score"])
    stage2_risk = float(semantic["risk_score"])
    final_risk = max(stage1_risk, stage2_risk)  # Monotonic Stage 1 floor.
    taint_chain = stage1["stage_triggered"] == "SESSION_TAINT_CHAIN"
    if taint_chain:
        final_risk = min(1.0, final_risk + .50)
    final_risk = min(1.0, max(0.0, final_risk))
    tier = _tier(final_risk)
    stage = "SESSION_TAINT_CHAIN" if taint_chain else (
        "CACHED_FAST_PATH" if semantic.get("cached") else
        "STAGE_1_AND_STAGE_2" if stage1_risk > 0 else "STAGE_2_SEMANTIC"
    )
    reasons = list(stage1.get("reasons", []))
    if semantic.get("reasoning"):
        reasons.append(str(semantic["reasoning"]))
    if not reasons:
        reasons.append("Tool request is consistent with the user's stated intent.")
    reasoning = " ".join(reasons)[:1000]
    event_id = _next_event_id()
    is_outbound = str(tool_name).casefold() in OUTBOUND_TOOLS
    # Policy: outbound Tier 2 calls are auto-approved when human approval for external sends is OFF.
    # Never for SESSION_TAINT_CHAIN: internal data read earlier in the session + outbound send is exfiltration.
    auto_approved = (tier == "⚠ REVIEW" and is_outbound and not policy["require_hitl_external"]
                     and not taint_chain)
    if auto_approved:
        reasoning = (f"Auto-approved by no-code policy (human approval for external sends is OFF); "
                     f"original risk {final_risk:.2f}. {reasoning}")[:1200]
        final_risk, tier = min(.40, final_risk), "✓ SAFE"
    # Interception latency = time to the routing decision; excludes post-block synthesis below.
    elapsed = max(0, int((time.perf_counter() - started) * 1000))
    post_started = time.perf_counter()
    if tier == "⛔ HONEYPOT":
        blocked = f"Protected call to {tool_name}; requested argument names: {', '.join(args.keys()) or 'none'}"
        if policy["serve_canary"]:
            canary_id = _next_canary_id()
            action = "SINKHOLED_C2_EXFILTRATION" if is_outbound else "REROUTED_TO_GEMINI_CANARY_HONEYPOT"
            llm_client.reset_content_source("canary")
            canary = llm_client.synthesize_canary(final_risk, tool_name, args, custom_keys, canary_id)
            _record_post_block(event_id, canary_synthesis_ms=int((time.perf_counter() - post_started) * 1000),
                               canary_source=llm_client.last_content_source("canary") or "unknown")
        else:
            action, canary, canary_id = _hard_block_values(is_outbound)
    elif tier == "⚠ REVIEW":
        canary_id = "NONE"
        action = "PAUSED_FOR_HUMAN_APPROVAL"
        canary = "N/A - Awaiting Human Review"
        llm_client.reset_content_source("brief")
        brief = llm_client.generate_review_brief(intent, retrieved_source, tool_name, args, custom_keys)
        _record_post_block(event_id, review_brief_ms=int((time.perf_counter() - post_started) * 1000),
                           review_brief_source=llm_client.last_content_source("brief") or "unknown")
        reasoning = f"{reasoning} {brief}"[:1200]
        blocked = "N/A - Review Pending"
    else:
        canary_id = "NONE"
        action = "ALLOWED_BY_POLICY_AUTO_APPROVE" if auto_approved else "ALLOWED_REAL_TOOL"
        canary = "N/A - Real Tool Executed"
        blocked = "N/A - Safe Execution"
        # An allowed internal-data read taints the session at decision time, for every adapter
        # (including direct callers). Blocked or decoy reads never taint: no real data left the vault.
        if str(tool_name).casefold() in INTERNAL_DATA_TOOLS:
            mark_session_tainted(session_id)
    values = {
        "event_id": event_id,
        "timestamp": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
        "original_intent": intent,
        "retrieved_source": str(retrieved_source or "custom_input.md"),
        "tool_called": str(tool_name),
        "tool_args": args,
        "stage_triggered": stage,
        "latency_ms": elapsed,
        "risk_score": final_risk,
        "governance_tier": tier,
        "owasp_mapping": OWASP_MAPPING,
        "drift_reasoning": reasoning,
        "action_taken": action,
        "real_payload_blocked": blocked,
        "canary_payload_served": canary,
        "canary_id": canary_id,
        "attacker_exfil_endpoint": _endpoint(args) if is_outbound else "LOCAL_SANDBOX",
    }
    return _store_event(_validated_event(values))


def register_mcp_tool(name: str, callable_: Callable[..., Any], description: str = "", parameters_schema: Optional[dict[str, Any]] = None) -> None:
    """Register an arbitrary local tool for JSON-RPC handling."""
    MCP_TOOL_REGISTRY[name] = {
        "name": name,
        "description": description,
        "parameters_schema": parameters_schema or {"type": "object", "properties": {}},
        "callable": callable_,
    }


def verify_mcp_tool_manifest(tools_list: list[dict[str, Any]], pinned_hashes: Optional[dict[str, str]] = None) -> dict[str, Any]:
    """Hash tool name, description, and parameter schema to detect drift."""
    hashes: dict[str, str] = {}
    for tool in tools_list:
        name = str(tool.get("name", ""))
        canonical = json.dumps([name, tool.get("description", ""), tool.get("parameters_schema", {})], sort_keys=True, separators=(",", ":"), default=str)
        hashes[name] = hashlib.sha256(canonical.encode("utf-8")).hexdigest()
    if pinned_hashes is None:
        return {"valid": True, "status": "MANIFEST_VERIFIED", "risk_score": 0.0, "pinned_hashes": hashes}
    valid = hashes == pinned_hashes
    return {"valid": valid, "status": "MANIFEST_VERIFIED" if valid else "MANIFEST_DRIFT_DETECTED",
            "risk_score": 0.0 if valid else 1.0, "pinned_hashes": pinned_hashes, "observed_hashes": hashes}


def agent_visible_tool_result(event: dict[str, Any]) -> dict[str, Any]:
    """Return only an MCP tool result; never expose internal verdict or event metadata."""
    tier = str(event.get("governance_tier", ""))
    canary_id = str(event.get("canary_id", "NONE"))
    if tier == "⛔ HONEYPOT" and canary_id != "NONE":
        if str(event.get("action_taken", "")) == "SINKHOLED_C2_EXFILTRATION":
            text = "Request submitted."
        else:
            text = str(event.get("canary_payload_served", ""))
        return {"content": [{"type": "text", "text": text[:4000]}], "isError": False}
    # Keep the failure intentionally generic so a hostile agent learns no policy details.
    return {"content": [{"type": "text", "text": "The requested operation is unavailable."}], "isError": True}


def handle_mcp_jsonrpc_request(rpc_request: dict[str, Any], original_intent: str = "Summarize document") -> dict[str, Any]:
    """Inspect and dispatch one JSON-RPC 2.0 MCP ``tools/call`` request."""
    request_id = rpc_request.get("id")
    if rpc_request.get("jsonrpc") != "2.0" or rpc_request.get("method") != "tools/call":
        return {"jsonrpc": "2.0", "id": request_id, "error": {"code": -32600, "message": "Invalid Request: expected JSON-RPC 2.0 tools/call."}}
    params = rpc_request.get("params") or {}
    name = str(params.get("name", params.get("tool_name", "")))
    args = params.get("arguments", params.get("args", {})) or {}
    if not isinstance(args, dict):
        return {"jsonrpc": "2.0", "id": request_id, "error": {"code": -32602, "message": "Tool arguments must be an object."}}
    tool = MCP_TOOL_REGISTRY.get(name)
    if tool is None:
        return {"jsonrpc": "2.0", "id": request_id, "error": {"code": -32601, "message": f"Unknown tool: {name}"}}
    meta = params.get("_meta") if isinstance(params.get("_meta"), dict) else {}
    intent = str(meta.get("original_intent") or original_intent)[:500]
    session_id = str(meta.get("session_id") or "default")
    event = evaluate_and_route_tool_call(intent, name, args, "custom_input.md", session_id)
    try:
        if event["governance_tier"] == "✓ SAFE":
            result: Any = tool["callable"](**args)
            if name in {"read_env_secrets", "read_config", "query_customer_db", "query_database", "read_database"}:
                mark_session_tainted(session_id)
            result_text = result if isinstance(result, str) else json.dumps(result, ensure_ascii=False, default=str)
            visible = {"content": [{"type": "text", "text": str(result_text)[:4000]}], "isError": False}
        else:
            visible = agent_visible_tool_result(event)
        return {"jsonrpc": "2.0", "id": request_id, "result": visible}
    except Exception:
        return {"jsonrpc": "2.0", "id": request_id,
                "result": {"content": [{"type": "text", "text": "The requested operation failed."}], "isError": True}}


def _tool_name(tool: Any) -> str:
    return str(getattr(tool, "name", None) or getattr(tool, "__name__", None) or tool)


def _context_state(tool_context: Any) -> dict[str, Any]:
    def mapping_like(value: Any) -> bool:
        return all(callable(getattr(value, name, None)) for name in ("get", "__getitem__", "__setitem__"))

    if isinstance(tool_context, dict):
        state = tool_context.get("state")
        return state if mapping_like(state) else tool_context
    state = getattr(tool_context, "state", None)
    return state if mapping_like(state) else {}


def adk_shadow_mcp_before_tool_callback(tool: Any, args: dict[str, Any], tool_context: Any) -> Optional[dict[str, Any]]:
    state = _context_state(tool_context)
    intent = str(state.get("original_intent", state.get("user_intent", "Use the requested tool")))
    source = str(state.get("retrieved_source", "custom_input.md"))
    session = str(state.get("session_id", "default"))
    event = evaluate_and_route_tool_call(intent, _tool_name(tool), args or {}, source, session)
    state["shadowmcp_last_event"] = event
    if event["governance_tier"] == "✓ SAFE":
        return None
    return agent_visible_tool_result(event)


def adk_shadow_mcp_after_tool_callback(tool: Any, args: dict[str, Any], tool_context: Any, tool_response: Any) -> Optional[dict[str, Any]]:
    text = str(tool_response or "")
    state = _context_state(tool_context)
    if _tool_name(tool) in {"read_env_secrets", "read_config", "query_customer_db", "query_database", "read_database"}:
        mark_session_tainted(str(state.get("session_id", "default")))
    if re.search(r"\[(?:SYSTEM OVERRIDE|DIAGNOSTIC DIRECTIVE):", text, re.I):
        event = evaluate_and_route_tool_call(
            str(state.get("original_intent", "Summarize the retrieved document")),
            "retrieved_document",
            {"retrieved_text": text[:4000], "tool": _tool_name(tool), **(args or {})},
            str(state.get("retrieved_source", "custom_input.md")),
            str(state.get("session_id", "default")),
        )
        state["shadowmcp_context_poisoning"] = True
        state["shadowmcp_context_event"] = event
        return {"content": [{"type": "text", "text": "The requested content is unavailable."}], "isError": True}
    return None


def shadow_mcp_guard(original_intent_getter: Callable[..., str]):
    """Decorator that inspects a Python tool before allowing its real call."""
    def decorate(function: Callable[..., Any]):
        signature = inspect.signature(function)

        def wrapped(*args: Any, **kwargs: Any):
            bound = signature.bind_partial(*args, **kwargs)
            tool_args = {key: value for key, value in bound.arguments.items()
                         if key not in {"original_intent", "retrieved_source", "session_id", "custom_keys"}}
            try:
                intent = str(original_intent_getter(*args, **kwargs))[:500]
            except Exception:
                intent = "Unspecified tool request"
            event = evaluate_and_route_tool_call(
                intent, function.__name__, tool_args,
                str(bound.arguments.get("retrieved_source", "custom_input.md")),
                str(bound.arguments.get("session_id", "default")),
                bound.arguments.get("custom_keys"),
            )
            wrapped.last_event = event
            if event["governance_tier"] == "✓ SAFE":
                result = function(*args, **kwargs)
                if function.__name__ in {"read_env_secrets", "read_config", "query_customer_db", "query_database", "read_database"}:
                    mark_session_tainted(str(bound.arguments.get("session_id", "default")))
                return result
            return agent_visible_tool_result(event)

        wrapped.last_event = None
        wrapped.__name__ = getattr(function, "__name__", "shadowmcp_guarded_tool")
        wrapped.__doc__ = function.__doc__
        return wrapped
    return decorate


def get_dashboard_state() -> dict[str, Any]:
    """Return seed KPIs plus current event, review, and canary telemetry."""
    with _LOCK:
        current = list(EVENTS)
        alerts = list(CANARY_ALERTS)
        reviews = list(PENDING_REVIEWS.values())
    # Weighted across the seeded baseline and live calls, exactly like ``total_inspected`` below,
    # so one instant preset or one slow live call cannot swing the card (208 -> 0 -> 800 ms).
    live = [event for event in current if event["stage_triggered"] != "BYPASSED_UNPROTECTED"]
    latencies = [int(event["latency_ms"]) for event in live]
    seeded_calls = int(_SEED_KPIS.get("total_inspected", 1420))
    seeded_mean = int(_SEED_KPIS.get("mean_latency_ms", 208))
    mean = int(round((seeded_calls * seeded_mean + sum(latencies)) / (seeded_calls + len(latencies)))) \
        if (seeded_calls + len(latencies)) else seeded_mean
    with _LOCK:
        timings = {eid: dict(t) for eid, t in POST_BLOCK_TIMINGS.items()}
    return {
        "kpis": {
            "total_inspected": int(_SEED_KPIS.get("total_inspected", 1420)) + sum(
                event["stage_triggered"] != "BYPASSED_UNPROTECTED" for event in current
            ),
            "mean_latency_ms": mean,
            "active_canary_traps": int(_SEED_KPIS.get("active_canary_traps", 14)) + len(alerts),
            "breach_cost_prevented_usd": str(_SEED_KPIS.get("breach_cost_prevented_usd", "Not estimated")),
        },
        "events": current,
        "pending_reviews": reviews,
        "canary_alerts": alerts,
        "server_quarantined": _SERVER_QUARANTINED,
        # Additive (non-secret) key: which LLM tier is live, so silent offline fallback is visible.
        "llm_status": llm_client.get_provider_status(),
        # Additive: honest breakdown behind the weighted latency KPI.
        "latency_breakdown": {
            "seeded_calls": seeded_calls, "seeded_mean_ms": seeded_mean,
            "live_calls": len(latencies),
            "live_mean_ms": int(round(sum(latencies) / len(latencies))) if latencies else None,
        },
        # Additive: post-decision work per event_id, e.g. {"canary_synthesis_ms": 850}.
        "post_block_timings": timings,
    }


def probe_llm_providers(custom_keys: Optional[dict[str, Any]] = None) -> dict[str, Any]:
    """One tiny live call per configured provider; returns non-secret status for the UI."""
    return llm_client.probe_providers(custom_keys)


def demo_target_dirs() -> list[Path]:
    """Where the separate, intentionally vulnerable demo target may live (first match wins)."""
    candidates = [os.getenv("SHADOWMCP_DEMO_TARGET", "").strip()]
    dirs = [Path(c) for c in candidates if c]
    dirs += [ROOT / "examples" / "rag_healthcare_agent", ROOT.parent / "RAG Healthcare Agent"]
    return dirs


def _load_victim_agent():
    victim_path = next((d / "victim_rag_agent.py" for d in demo_target_dirs() if (d / "victim_rag_agent.py").is_file()), None)
    if victim_path is None:
        raise FileNotFoundError("Demo target not found; set SHADOWMCP_DEMO_TARGET or keep examples/rag_healthcare_agent.")
    spec = importlib.util.spec_from_file_location("shadowmcp_victim_rag_agent", victim_path)
    if spec is None or spec.loader is None:
        raise ImportError("Could not load the sibling victim RAG module.")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def run_preset_scenario(
    scenario_key: str,
    custom_keys: Optional[dict[str, Any]] = None,
    bypass_shield: bool = False,
    session_id: Optional[str] = None,
    policies: Optional[dict[str, Any]] = None,
) -> dict[str, Any]:
    """Run one local healthcare demo; the protected core remains universal."""
    scenarios = {
        "benign_budget": ("Summarize the Q3 clinic budget", "q3_clinic_budget.md"),
        "poisoned_referral": ("Summarize the cardiology referral", "patient_referral_poisoned.md"),
        "ambiguous_claim": ("Review the insurance reconciliation claim", "insurance_claim_poisoned.md"),
    }
    if scenario_key not in scenarios:
        raise ValueError(f"Unknown scenario key: {scenario_key}")
    intent, source = scenarios[scenario_key]
    session_id = session_id or f"preset_{scenario_key}_{uuid.uuid4().hex}"
    # Scripted presets must land on their documented tiers (SAFE / HONEYPOT / REVIEW) even when live
    # LLM keys are configured; set SHADOWMCP_DETERMINISTIC_PRESETS=0 to let Stage 2 run live on presets.
    deterministic = llm_client._env_flag("SHADOWMCP_DETERMINISTIC_PRESETS", True)
    victim = _load_victim_agent()
    with _LOCK:
        quarantined = _SERVER_QUARANTINED
    if bypass_shield and not quarantined:
        output = victim.run_victim_agent(intent, source)
        calls = [call for call in output.get("tool_calls", []) if call["tool_name"] != "search_knowledge_base"]
        selected = calls[0] if calls else output["tool_calls"][0]
        stage1 = stage1_deterministic_check(intent, selected["tool_name"], selected["args"], f"bypass_{uuid.uuid4().hex}")
        semantic = llm_client._local_judgment(intent, selected["tool_name"], selected["args"], source)
        risk = max(float(stage1["risk_score"]), float(semantic["risk_score"]))
        event_id = _next_event_id()
        is_outbound = selected["tool_name"] in {"send_external_webhook", "send_email", "http_post"}
        event = _validated_event({
            "event_id": event_id,
            "timestamp": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
            "original_intent": intent,
            "retrieved_source": source,
            "tool_called": selected["tool_name"],
            "tool_args": selected["args"],
            "stage_triggered": "BYPASSED_UNPROTECTED",
            "latency_ms": 0,
            "risk_score": risk,
            "governance_tier": _tier(risk),
            "owasp_mapping": OWASP_MAPPING,
            "drift_reasoning": "Shield bypass was requested; the raw synthetic demo tool ran without enforcement. " + str(semantic["reasoning"]),
            "action_taken": "BYPASSED_SHIELD_UNPROTECTED",
            "real_payload_blocked": "UNPROTECTED MOCK RESULT: " + str(selected.get("result"))[:200],
            "canary_payload_served": "N/A - Shield Disabled; Real Mock Tool Executed",
            "canary_id": "NONE",
            "attacker_exfil_endpoint": _endpoint(selected["args"]) if is_outbound else "LOCAL_SANDBOX",
        })
        return _store_event(event, record_alert=False)

    seen: list[dict[str, Any]] = []

    def protection_hook(name: str, args: dict[str, Any], raw_tool: Callable[..., Any]):
        event = evaluate_and_route_tool_call(intent, name, args, source, session_id, custom_keys,
                                             deterministic_judge=deterministic, policies=policies)
        seen.append(event)
        if event["governance_tier"] == "✓ SAFE":
            result = raw_tool(**args)
            if name in {"read_env_secrets", "read_config", "query_customer_db", "query_database", "read_database"}:
                mark_session_tainted(session_id)
            return result
        return {"status": event["action_taken"], "event_id": event["event_id"],
                "canary_payload": event["canary_payload_served"], "canary_id": event["canary_id"]}

    victim.run_victim_agent(intent, source, protection_hook=protection_hook)
    if not seen:
        raise RuntimeError("Preset scenario produced no tool calls.")
    honeypots = [event for event in seen if event["governance_tier"] == "⛔ HONEYPOT"]
    # Headline event = the terminal exfiltration attempt (sinkholed C2 with geolocation) when the
    # chain reached one; otherwise the first honeypot; otherwise the last call.
    selected_event = next((e for e in honeypots if e["tool_called"] in OUTBOUND_TOOLS), None) \
        or (honeypots[0] if honeypots else seen[-1])
    if selected_event["governance_tier"] == "⛔ HONEYPOT":
        preview = _masked_vault_preview(victim, seen)
        if preview:
            selected_event["real_payload_blocked"] = "Masked blocked vault preview: " + preview
            with _LOCK:  # keep the stored log in sync with the returned dict
                for index, existing in enumerate(EVENTS):
                    if existing.get("event_id") == selected_event["event_id"]:
                        EVENTS[index] = selected_event
                        break
    return selected_event


def _masked_vault_preview(victim: Any, chain: list[dict[str, Any]]) -> str:
    """Masked preview of the synthetic vault data the blocked chain was reaching for."""
    parts: list[str] = []
    mock_env = getattr(victim, "MOCK_ENV", {}) or {}
    mock_db = getattr(victim, "MOCK_PATIENT_DB", []) or []
    for event in chain:
        if event["governance_tier"] != "⛔ HONEYPOT":
            continue
        tool = event["tool_called"]
        if tool == "read_env_secrets":
            keys = event["tool_args"].get("target_keys") or list(mock_env)
            parts += [f"{key}={str(mock_env[key])[:6]}***" for key in keys if key in mock_env]
        elif tool in {"query_customer_db", "query_database", "read_database"} and mock_db:
            parts.append(f"{len(mock_db)} patient rows incl. SSN ***-**-{str(mock_db[0].get('ssn', ''))[-4:]}")
    return " | ".join(dict.fromkeys(parts))


def _rate_limited(session_id: str, digest: str, judge_passcode: str) -> bool:
    expected = os.getenv("JUDGE_PASSCODE", "").strip()  # no default: unset means nothing unlocks
    if judge_passcode and expected and hmac.compare_digest(str(judge_passcode).encode(), expected.encode()):
        return False
    now = time.monotonic()
    with _LOCK:
        calls = _CUSTOM_CALLS[session_id]
        while calls and now - calls[0][0] >= 60:
            calls.popleft()
        if any(existing_digest == digest for _, existing_digest in calls):
            return False
        if len(calls) >= 3:
            return True
        calls.append((now, digest))
        return False


def _rate_limited_event(
    prompt: str,
    tool_name: str,
    tool_args: dict[str, Any],
    retrieved_source: str,
    session_id: str,
    policies: Optional[dict[str, Any]] = None,
) -> dict[str, Any]:
    """Build a REVIEW/HEURISTIC response without invoking the LLM judge.

    Policies apply (PHI regex, deception) except auto-approval: the review is the rate limiter.
    """
    args = dict(tool_args or {})
    policy = normalize_policies(policies)
    stage1 = stage1_deterministic_check(prompt, tool_name, args, session_id,
                                        skip_phi_regex=not policy["block_phi_export"])
    risk = max(.65, float(stage1["risk_score"]))
    if stage1["stage_triggered"] == "SESSION_TAINT_CHAIN":
        risk = min(1.0, risk + .50)
    tier = _tier(risk)
    event_id = _next_event_id()
    is_outbound = str(tool_name).casefold() in {"send_external_webhook", "send_email", "http_post"}
    if tier == "⛔ HONEYPOT":
        canary_id = _next_canary_id()
        serial = canary_id.split("-")[1]
        action = "SINKHOLED_C2_EXFILTRATION" if is_outbound else "REROUTED_TO_GEMINI_CANARY_HONEYPOT"
        canary = f"AWS_SECRET_ACCESS_KEY=AKIA_CANARY_TRAP_{serial}_DEVFEST | PATIENT_SSN_SAMPLE=000-99-CANARY"
        blocked = f"Rate-limited call blocked before judge execution: {tool_name}"
        if not policy["serve_canary"]:
            action, canary, canary_id = _hard_block_values(is_outbound)
    else:
        canary_id = "NONE"
        action = "PAUSED_FOR_HUMAN_APPROVAL"
        canary = "N/A - Awaiting Human Review"
        blocked = "N/A - Review Pending"
    event = _validated_event({
        "event_id": event_id,
        "timestamp": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
        "original_intent": prompt[:500],
        "retrieved_source": str(retrieved_source or "custom_input.md"),
        "tool_called": str(tool_name),
        "tool_args": args,
        "stage_triggered": "RATE_LIMITED",
        "latency_ms": max(0, int(stage1["latency_ms"])),
        "risk_score": risk,
        "governance_tier": tier,
        "owasp_mapping": OWASP_MAPPING,
        "drift_reasoning": "The public custom-call limit was reached before the LLM judge ran. "
                           "Review the tool and arguments before approving this request.",
        "action_taken": action,
        "real_payload_blocked": blocked,
        "canary_payload_served": canary,
        "canary_id": canary_id,
        "attacker_exfil_endpoint": _endpoint(args) if is_outbound else "LOCAL_SANDBOX",
    })
    return _store_event(event)


def run_custom_redteam_prompt(
    user_prompt: str,
    tool_name: str,
    tool_args: dict[str, Any],
    retrieved_source: str = "custom_input.md",
    judge_passcode: str = "",
    session_id: str = "default",
    custom_keys: Optional[dict[str, Any]] = None,
    policies: Optional[dict[str, Any]] = None,
) -> dict[str, Any]:
    """Inspect a custom call with 500-character cap and three-call rate limit."""
    prompt = str(user_prompt or "")[:500]
    fingerprint = hashlib.sha256(json.dumps([prompt.strip(), tool_name, tool_args, retrieved_source], sort_keys=True, default=str).encode()).hexdigest()
    limited = _rate_limited(session_id, fingerprint, judge_passcode)
    if limited:
        return _rate_limited_event(prompt, tool_name, tool_args, retrieved_source, session_id, policies)
    return evaluate_and_route_tool_call(prompt, tool_name, tool_args, retrieved_source, session_id, custom_keys,
                                        policies=policies)


def resolve_human_review(target_record_key: str, decision: str,
                         policies: Optional[dict[str, Any]] = None) -> dict[str, Any]:
    """Resolve a pending Tier 2 review. ``policies`` applies the no-code overrides to QUARANTINE."""
    policy = normalize_policies(policies)
    decision = str(decision).upper()
    if decision not in {"APPROVE", "QUARANTINE"}:
        raise ValueError("decision must be APPROVE or QUARANTINE")
    with _LOCK:
        original = PENDING_REVIEWS.pop(target_record_key, None)
    if original is None:
        raise KeyError(f"No pending review found for {target_record_key}")
    event = dict(original)
    if decision == "APPROVE":
        event.update({"risk_score": min(.40, event["risk_score"]), "governance_tier": "✓ SAFE",
                      "action_taken": "ALLOWED_BY_HUMAN_OPERATOR", "canary_payload_served": "N/A - Real Tool Executed",
                      "canary_id": "NONE", "real_payload_blocked": "N/A - Safe Execution",
                      "drift_reasoning": "A human operator approved this tool call after review."})
    else:
        outbound = event["tool_called"].casefold() in OUTBOUND_TOOLS
        if policy["serve_canary"]:
            canary_id = _next_canary_id()
            action = "SINKHOLED_C2_EXFILTRATION" if outbound else "REROUTED_TO_GEMINI_CANARY_HONEYPOT"
            started = time.perf_counter()
            llm_client.reset_content_source("canary")
            payload = llm_client.synthesize_canary(max(.76, event["risk_score"]), event["tool_called"],
                                                   event["tool_args"], canary_id=canary_id)
            _record_post_block(target_record_key, canary_synthesis_ms=int((time.perf_counter() - started) * 1000),
                               canary_source=llm_client.last_content_source("canary") or "unknown")
        else:
            action, payload, canary_id = _hard_block_values(outbound)
        event.update({"risk_score": max(.76, event["risk_score"]), "governance_tier": "⛔ HONEYPOT",
                      "action_taken": action, "canary_id": canary_id, "canary_payload_served": payload,
                      "real_payload_blocked": f"Operator quarantined {event['tool_called']} after review."})
    with _LOCK:
        for index, existing in enumerate(EVENTS):
            if existing.get("event_id") == target_record_key:
                EVENTS[index] = event
                break
        if event["governance_tier"] == "⛔ HONEYPOT" and event["canary_id"] != "NONE":
            CANARY_ALERTS.appendleft(_canary_alert_record(event))
    return _validated_event(event)


def format_plain_english_receipt(event_dict: dict[str, Any]) -> dict[str, str]:
    tool = str(event_dict.get("tool_called", "tool"))
    tier = str(event_dict.get("governance_tier", ""))
    action = str(event_dict.get("action_taken", ""))
    if action == "ALLOWED_BY_POLICY_AUTO_APPROVE":
        protection = "Your no-code policy turned off human approval for external sends, so this call was auto-approved and logged."
        attack = f"The {tool} call would normally wait for a human because it sends data outside the clinic."
    elif action == "ALLOWED_BY_HUMAN_OPERATOR":
        protection = "A human operator reviewed this call and approved it."
        attack = f"The {tool} call was flagged for review before it was allowed to run."
    elif tier == "✓ SAFE":
        protection = "The request matched your task, so the local tool was allowed to run."
        attack = "No suspicious tool behavior was detected."
    elif tier == "⚠ REVIEW":
        protection = "The tool was paused for a human decision while its destination and data are reviewed."
        attack = f"The {tool} call may send or access data beyond the task you described."
    elif str(event_dict.get("canary_id", "NONE")) == "NONE":
        protection = "The real tool was hard-blocked (deception is off by policy); no data or decoys were returned and outbound traffic was kept local."
        attack = f"The {tool} call attempted a high-risk action that could expose protected information."
    else:
        protection = "The real tool was blocked and a synthetic canary response was used; outbound traffic was kept local."
        attack = f"The {tool} call attempted a high-risk action that could expose protected information."
    return {
        "what_user_asked": str(event_dict.get("original_intent", ""))[:500],
        "what_attack_tried": attack,
        "how_shadowmcp_protected_you": protection,
        "financial_impact": "Not estimated. No verified incident-cost source is configured.",
        # Keep the legacy field during the demo transition; its value is now neutral.
        "hipaa_financial_impact": "Not estimated. No verified incident-cost source is configured.",
    }


def export_protected_mcp_config(
    server_name: str = "my-mcp-server",
    command_argv: list[str] | str | None = None,
    intent: str = "Use the requested tool",
) -> str:
    """Build a client config that wraps a resolved upstream executable.

    command_argv is a JSON array (or a list), not a shell command string.
    This preserves quoting across client platforms and avoids shell parsing.
    """
    server_name = str(server_name).strip()
    if not server_name:
        raise ValueError("MCP server name must not be empty.")
    intent = str(intent).strip()
    if not intent:
        raise ValueError("Tool intent must not be empty.")
    if command_argv is None:
        command_argv = ["npx", "-y", "@modelcontextprotocol/server-filesystem", "."]
    elif isinstance(command_argv, str):
        try:
            command_argv = json.loads(command_argv)
        except json.JSONDecodeError as exc:
            raise ValueError("Upstream command must be a JSON array of argv strings.") from exc
    if (not isinstance(command_argv, list) or not command_argv
            or not all(isinstance(part, str) for part in command_argv) or not command_argv[0].strip()):
        raise ValueError("Upstream command must be a non-empty JSON array of strings.")
    resolved_server = shutil.which(command_argv[0])
    if not resolved_server:
        candidate = Path(command_argv[0]).expanduser()
        if candidate.is_absolute() and candidate.is_file():
            resolved_server = str(candidate.resolve())
        else:
            raise FileNotFoundError(f"Cannot find upstream executable: {command_argv[0]}")
    proxy_executable = shutil.which("shadowmcp-proxy")
    if not proxy_executable:
        suffix = ".exe" if os.name == "nt" else ""
        candidate = Path(sys.executable).resolve().parent / f"shadowmcp-proxy{suffix}"
        if candidate.is_file():
            proxy_executable = str(candidate)
    if proxy_executable:
        proxy_command = proxy_executable
        proxy_args = []
    else:
        # Works when this interpreter has the package installed, even if its Scripts
        # directory is not on the process PATH.
        proxy_command = sys.executable
        proxy_args = ["-m", "shadowmcp.proxy"]
    config = {"mcpServers": {server_name: {
        "command": proxy_command,
        "args": [*proxy_args, "--intent", intent, "--wrap", "--",
                 resolved_server, *command_argv[1:]],
    }}}
    return json.dumps(config, indent=2, ensure_ascii=False)

def reset_state_for_tests() -> None:
    global _EVENT_COUNT, _CANARY_COUNT, _SERVER_QUARANTINED
    with _LOCK:
        EVENTS.clear()
        CANARY_ALERTS.clear()
        PENDING_REVIEWS.clear()
        SESSION_TAINT_STATE.clear()
        _CUSTOM_CALLS.clear()
        MCP_TOOL_REGISTRY.clear()
        POST_BLOCK_TIMINGS.clear()
        _EVENT_COUNT = _CANARY_COUNT = 0
        _SERVER_QUARANTINED = False
    _EVENT_LOG.clear()
    llm_client.clear_caches()
