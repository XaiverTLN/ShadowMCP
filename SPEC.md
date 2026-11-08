# ShadowMCP Canonical Data Contract

This document defines the interface between the universal middleware, tool adapters, and UI.

## Intercepted event

Every inspection is validated as a Pydantic `InterceptedEvent` and serialized with exactly these 17 keys:

`event_id`, `timestamp`, `original_intent`, `retrieved_source`, `tool_called`, `tool_args`, `stage_triggered`, `latency_ms`, `risk_score`, `governance_tier`, `owasp_mapping`, `drift_reasoning`, `action_taken`, `real_payload_blocked`, `canary_payload_served`, `canary_id`, `attacker_exfil_endpoint`.

Strings are never null; intent is capped at 500 characters; scores are floats in `[0, 1]`. The governance tiers are `✓ SAFE` (0.00–0.40), `⚠ REVIEW` (0.41–0.75), and `⛔ HONEYPOT` (0.76–1.00). Stage 2 cannot lower the Stage 1 score.

## Public facade

`shadow_mcp.py` exposes `get_dashboard_state`, `run_preset_scenario`, `run_custom_redteam_prompt`, `resolve_human_review`, `format_plain_english_receipt`, and `export_protected_mcp_config`. It also offers a generic Python decorator, Google ADK-compatible callbacks, SHA-256 tool-manifest verification, and a JSON-RPC 2.0 `tools/call` handler.

## Safety and fallback

The core evaluator is domain agnostic and does not import the healthcare agent. LLM routing uses only Groq and Gemini credentials, synchronous calls with a 3.5 second timeout (no SDK retries), a 500-character prompt cap, a per-key circuit breaker, and a deterministic offline fallback. Mock patient data and secrets stay in memory; outbound webhook demonstrations are sinkholed locally.

## Implementation notes (synced 2026-11-08)

The 17-key event, the three tiers, and the six facade names are unchanged, and every new parameter is optional. Omitting `policies` gives the SPEC default (all three rules on), and omitting `deterministic_judge` uses the live Stage 2 judge. Two behaviour changes apply to **all** callers. First, the meaning of `latency_ms` and the `mean_latency_ms` formula changed (see *Latency semantics*). Second, a SAFE read of an internal-data tool now taints the session at decision time.

### Models and LLM configuration (`.env`)

| Variable | Active value | Role |
|---|---|---|
| `GROQ_MODEL` | `qwen/qwen3.8-27b` | Stage 2 primary judge |
| `GEMINI_FLASH_MODEL` | `gemini-3.1-flash-lite` | Stage 2 fallback judge and canary synthesis |
| `GEMINI_PRO_MODEL` | `gemini-3.1-flash-lite` | Tier 2 operator brief (no Pro model was usable on the current account) |
| `GEMINI_REASONING_EFFORT` | `none` | Gemini thinking disabled for latency; retried without the field if a model rejects it |
| `LLM_TIMEOUT_SECONDS` | `3.5` | Per-call timeout |
| `SHADOWMCP_BREAKER_SECONDS` | `60` | Skip a failing provider (keyed by provider + key fingerprint) |
| `SHADOWMCP_DETERMINISTIC_PRESETS` | `1` | The three preset scenarios use the local deterministic Stage 2 judge so they always land SAFE / HONEYPOT / REVIEW; canary and brief text may still be LLM-generated |
| `SHADOWMCP_REQUIRE_BYOK` | `0` | `1` = never use server keys; visitors must supply their own |

The code defaults (used when a variable is unset) are the same working models: `qwen/qwen3.8-27b` for `GROQ_MODEL`, and `gemini-3.1-flash-lite` for both Gemini variables. `SHADOWMCP_ENV` no longer selects a model. `.env.example` ships with these values. The earlier defaults `llama-3.1-8b-instant`, `gemini-2.5-flash` and `gemini-2.5-pro` are retired or unavailable on the current account. Every canary payload starts with `AWS_SECRET_ACCESS_KEY=AKIA_CANARY_TRAP_<serial>_DEVFEST`. LLM-generated decoy entries are kept only if they contain `CANARY_<serial>`, contain no `AKIA` string, and are in `KEY=VALUE` form. At most two are kept.

### Additive facade helpers and parameters

- `set_server_quarantine(enabled: bool) -> bool`: global kill switch. While it is on, `evaluate_and_route_tool_call()` blocks every call before any real tool runs.
- `probe_llm_providers(custom_keys=None) -> dict`: one tiny live call per configured provider. Returns non-secret status (see `llm_status`).
- `run_preset_scenario(..., session_id: Optional[str] = None, policies: Optional[dict] = None)`: each preset run gets a fresh session unless `session_id` is given.
- `run_custom_redteam_prompt(..., policies: Optional[dict] = None)`.
- `evaluate_and_route_tool_call(..., deterministic_judge: bool = False, policies: Optional[dict] = None)`.
- `resolve_human_review(target_record_key, decision, policies: Optional[dict] = None)`: QUARANTINE honours `serve_canary`.

### No-code policies (`policies` dict; all default `True`)

| Key | When `False` |
|---|---|
| `block_phi_export` | Stage 1 skips only the SSN/PHI regex (other signatures and Stage 2 still apply) |
| `require_hitl_external` | Tier 2 **outbound** calls (`send_external_webhook`, `send_email`, `http_post`) auto-approve: `governance_tier="✓ SAFE"`, `risk_score=min(0.40, score)`, `action_taken="ALLOWED_BY_POLICY_AUTO_APPROVE"`; the original score is recorded in `drift_reasoning`. Never applied to rate-limited calls or to `SESSION_TAINT_CHAIN` calls (an internal data read earlier in the session followed by an outbound send). |
| `serve_canary` | Tier 3 returns no decoy: `canary_id="NONE"`, `canary_payload_served="N/A - Hard Block (Deception Disabled by Policy)"`, `action_taken="BLOCKED_NO_DECEPTION"` (outbound calls stay `SINKHOLED_C2_EXFILTRATION`); no canary alert is recorded. This applies on every Tier 3 path: routing, kill-switch quarantine, rate limit, and operator QUARANTINE. |

### Additional enum values now emitted

- `action_taken`: `ALLOWED_BY_HUMAN_OPERATOR`, `ALLOWED_BY_POLICY_AUTO_APPROVE`, `BLOCKED_NO_DECEPTION`, `BYPASSED_SHIELD_UNPROTECTED`
- `stage_triggered`: `BYPASSED_UNPROTECTED` (shield-off demo; excluded from KPIs), `RATE_LIMITED`

### Latency semantics

`latency_ms` is **interception latency**: the time from receiving the call to the routing decision (Stage 1 + Stage 2). Canary synthesis and operator-brief generation happen after the decision, including canary synthesis started by an operator QUARANTINE. They are excluded from `latency_ms` and reported in `post_block_timings`, together with the producer that actually generated the text. `kpis.mean_latency_ms` is a weighted mean over the seeded baseline and live calls, on the same basis as `kpis.total_inspected`: `(seeded_calls × seeded_mean + Σ live) / (seeded_calls + live_calls)`. Shield-bypass events are excluded.

### Additive `get_dashboard_state()` keys

```py
"llm_status": {                       # non-secret; never contains key material
    "require_byok": bool,
    "models": {"judge": str, "flash": str, "pro": str},
    "groq":   {"key_source": "byok"|"env"|"none", "state": "ok"|"error"|"cooldown"|"untested"|"no key",
               "last_error": str, "cooldown_s": int, "model": str},
    "gemini": {...same shape...},
},
"latency_breakdown": {"seeded_calls": int, "seeded_mean_ms": int, "live_calls": int, "live_mean_ms": int | None},
"post_block_timings": {event_id: {"canary_synthesis_ms": int, "canary_source": str,   # model ID or "local-template"
                                   "review_brief_ms": int, "review_brief_source": str}},  # keys present only when that work ran
```

### UI assets

`static/world_110m.json` (Plotly's Natural Earth basemap, served at `app/static/` with `server.enableStaticServing = true`) makes the interactive map work offline. If it is missing and `cdn.plot.ly` is unreachable, `app.py` renders an offline dot-matrix radar map instead. That map is an SVG embedded as an `<img>` data URI, because `st.html` strips inline `<svg>`. Its land mask is rasterized from the TopoJSON `countries` object, because that file's `land` object omits Afro-Eurasia. The UI labels canary and brief provenance from `post_block_timings` and never names a model that did not produce the text.
