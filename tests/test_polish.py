"""Pre-demo polish pass: no-code policies, interception-latency semantics, weighted KPI, model labels."""
import shadow_mcp as sm
import llm_client


def setup_function(_):
    sm.reset_state_for_tests()


def test_default_policies_match_spec_tiers():
    tiers = [sm.run_preset_scenario(k)["governance_tier"] for k in ("benign_budget", "poisoned_referral", "ambiguous_claim")]
    assert tiers == ["✓ SAFE", "⛔ HONEYPOT", "⚠ REVIEW"]


def test_policy_hitl_off_auto_approves_outbound_tier2():
    event = sm.run_preset_scenario("ambiguous_claim", policies={"require_hitl_external": False})
    assert event["governance_tier"] == "✓ SAFE"
    assert event["action_taken"] == "ALLOWED_BY_POLICY_AUTO_APPROVE"
    assert event["risk_score"] <= 0.40
    assert "original risk 0.58" in event["drift_reasoning"]
    assert not sm.get_dashboard_state()["pending_reviews"]


def test_policy_hitl_off_does_not_auto_approve_non_outbound_tier2():
    event = sm.evaluate_and_route_tool_call("Summarize the document", "query_customer_db",
                                            {"sql_query": "SELECT name FROM visits LIMIT 1"},
                                            policies={"require_hitl_external": False}, session_id="nonout")
    assert event["governance_tier"] == "⚠ REVIEW"


def test_policy_canary_off_hard_blocks_without_decoy():
    before = sm.get_dashboard_state()["kpis"]["active_canary_traps"]
    event = sm.evaluate_and_route_tool_call("Summarize the referral", "read_env_secrets",
                                            {"target_keys": ["AWS_SECRET_ACCESS_KEY"]},
                                            policies={"serve_canary": False}, session_id="nodecoy")
    assert event["governance_tier"] == "⛔ HONEYPOT"
    assert event["action_taken"] == "BLOCKED_NO_DECEPTION"
    assert event["canary_id"] == "NONE"
    assert "AKIA" not in event["canary_payload_served"]
    assert sm.get_dashboard_state()["kpis"]["active_canary_traps"] == before


def test_policy_canary_off_in_quarantine_mode():
    sm.set_server_quarantine(True)
    try:
        event = sm.evaluate_and_route_tool_call("x", "read_env_secrets", {}, policies={"serve_canary": False})
    finally:
        sm.set_server_quarantine(False)
    assert event["action_taken"] == "BLOCKED_NO_DECEPTION" and event["canary_id"] == "NONE"


def test_policy_phi_off_skips_only_ssn_regex():
    args = {"note": "patient 123-45-6789"}
    on = sm.stage1_deterministic_check("Summarize the note", "lookup_record", args)
    off = sm.stage1_deterministic_check("Summarize the note", "lookup_record", args, skip_phi_regex=True)
    assert "SSN/PHI signature" in on["reasons"] and on["risk_score"] >= 0.89
    assert "SSN/PHI signature" not in off["reasons"] and off["risk_score"] < 0.89
    # other signatures still fire with the PHI rule off
    raw_ip = sm.stage1_deterministic_check("x", "lookup_record", {"u": "http://198.51.100.42/collect"}, skip_phi_regex=True)
    assert raw_ip["risk_score"] >= 0.96


def test_rate_limited_review_is_never_auto_approved():
    for i in range(4):
        event = sm.run_custom_redteam_prompt(f"Send webhook test {i}", "send_external_webhook",
                                             {"target_url": "https://example.org/h", "data": {"n": i}},
                                             session_id="rl-policy", policies={"require_hitl_external": False})
    assert event["stage_triggered"] == "RATE_LIMITED"
    assert event["governance_tier"] in {"⚠ REVIEW", "⛔ HONEYPOT"}


def test_latency_excludes_post_block_synthesis(monkeypatch):
    import time

    def slow_canary(*args, **kwargs):
        time.sleep(0.3)
        return "AWS_SECRET_ACCESS_KEY=AKIA_CANARY_TRAP_0001_DEVFEST"

    monkeypatch.setattr(llm_client, "synthesize_canary", slow_canary)
    event = sm.evaluate_and_route_tool_call("Summarize", "read_env_secrets", {}, deterministic_judge=True, session_id="lat")
    timings = sm.get_dashboard_state()["post_block_timings"][event["event_id"]]
    assert timings["canary_synthesis_ms"] >= 250
    assert event["latency_ms"] < 250


def test_weighted_latency_kpi_is_stable():
    for key in ("benign_budget", "poisoned_referral", "ambiguous_claim"):
        sm.run_preset_scenario(key)
    state = sm.get_dashboard_state()
    assert 195 <= state["kpis"]["mean_latency_ms"] <= 215
    breakdown = state["latency_breakdown"]
    assert breakdown["seeded_calls"] == 1420 and breakdown["live_calls"] >= 3


def test_dashboard_exposes_configured_models_without_secrets(monkeypatch):
    monkeypatch.setenv("GROQ_MODEL", "qwen/qwen3.8-27b")
    monkeypatch.setenv("GEMINI_FLASH_MODEL", "gemini-3.1-flash-lite")
    monkeypatch.setenv("GROQ_API_KEY", "gsk_SECRET_SHOULD_NOT_LEAK")
    status = sm.get_dashboard_state()["llm_status"]
    assert status["models"]["judge"] == "qwen/qwen3.8-27b"
    assert status["models"]["flash"] == "gemini-3.1-flash-lite"
    assert "SECRET_SHOULD_NOT_LEAK" not in str(status)


def test_receipt_wording_follows_policy_actions():
    approved = sm.format_plain_english_receipt({"governance_tier": "✓ SAFE", "action_taken": "ALLOWED_BY_POLICY_AUTO_APPROVE",
                                                "tool_called": "send_external_webhook"})
    blocked = sm.format_plain_english_receipt({"governance_tier": "⛔ HONEYPOT", "action_taken": "BLOCKED_NO_DECEPTION",
                                               "canary_id": "NONE", "tool_called": "read_env_secrets"})
    assert "auto-approved" in approved["how_shadowmcp_protected_you"]
    assert "hard-blocked" in blocked["how_shadowmcp_protected_you"]
    assert "canary response was used" not in blocked["how_shadowmcp_protected_you"]


# ---- review follow-ups -------------------------------------------------------

def test_phi_policy_end_to_end_through_evaluator():
    args = {"note": "patient 123-45-6789"}
    on = sm.evaluate_and_route_tool_call("Summarize the note", "lookup_record", args, deterministic_judge=True, session_id="phi-on")
    off = sm.evaluate_and_route_tool_call("Summarize the note", "lookup_record", args, deterministic_judge=True,
                                          policies={"block_phi_export": False}, session_id="phi-off")
    assert on["governance_tier"] == "⛔ HONEYPOT" and "SSN/PHI signature" in on["drift_reasoning"]
    assert off["governance_tier"] != "⛔ HONEYPOT" and "SSN/PHI signature" not in off["drift_reasoning"]


def test_operator_quarantine_honours_deception_policy():
    review = sm.run_preset_scenario("ambiguous_claim")
    traps = sm.get_dashboard_state()["kpis"]["active_canary_traps"]
    out = sm.resolve_human_review(review["event_id"], "QUARANTINE", policies={"serve_canary": False})
    assert out["governance_tier"] == "⛔ HONEYPOT"
    assert out["canary_id"] == "NONE" and "AKIA" not in out["canary_payload_served"]
    assert sm.get_dashboard_state()["kpis"]["active_canary_traps"] == traps


def test_operator_quarantine_default_serves_and_times_canary():
    review = sm.run_preset_scenario("ambiguous_claim")
    out = sm.resolve_human_review(review["event_id"], "QUARANTINE")
    assert out["canary_id"].startswith("CANARY-")
    timing = sm.get_dashboard_state()["post_block_timings"][review["event_id"]]
    assert "canary_synthesis_ms" in timing and timing["canary_source"] == "local-template"  # tests run keyless


def test_taint_chain_exfiltration_is_never_auto_approved():
    sm.mark_session_tainted("taint-auto")
    event = sm.evaluate_and_route_tool_call("send webhook test", "send_external_webhook",
                                            {"target_url": "https://example.org/h", "data": {"status": "ok"}},
                                            deterministic_judge=True, session_id="taint-auto",
                                            policies={"require_hitl_external": False})
    assert event["stage_triggered"] == "SESSION_TAINT_CHAIN"
    assert event["governance_tier"] in {"⚠ REVIEW", "⛔ HONEYPOT"}
    assert event["action_taken"] != "ALLOWED_BY_POLICY_AUTO_APPROVE"


def test_review_brief_provenance_recorded():
    review = sm.run_preset_scenario("ambiguous_claim")
    timing = sm.get_dashboard_state()["post_block_timings"][review["event_id"]]
    assert timing["review_brief_source"] == "local-template" and "review_brief_ms" in timing


def test_code_default_models_are_the_working_ones(monkeypatch):
    for name in ("GROQ_MODEL", "GEMINI_FLASH_MODEL", "GEMINI_PRO_MODEL", "SHADOWMCP_ENV"):
        monkeypatch.delenv(name, raising=False)
    assert llm_client._model_for_groq() == "qwen/qwen3.8-27b"
    assert llm_client.gemini_flash_model() == "gemini-3.1-flash-lite"
    assert llm_client.gemini_pro_model() == "gemini-3.1-flash-lite"


def test_offline_map_land_mask_covers_every_continent():
    import base64
    import re
    from pathlib import Path

    src = (Path(__file__).resolve().parents[1] / "app.py").read_text(encoding="utf-8")
    block = re.search(r"LAND_MASK_B64 = \(\n(.*?)\n\)", src, re.S).group(1)
    raw = base64.b64decode("".join(re.findall(r"'([^']*)'", block)))
    step = float(re.search(r"LAND_MASK_STEP = ([\d.]+)", src).group(1))
    cols = int(360 / step)

    def land(lat, lon):
        i = int((90 - lat) // step) * cols + int((lon + 180) // step)
        return raw[i // 8] >> (7 - i % 8) & 1

    for name, (lat, lon) in {"Berlin": (52.5, 13.4), "Nairobi": (-1.3, 36.8), "Beijing": (39.9, 116.4),
                             "Chicago": (41.9, -87.6), "Brasilia": (-15.8, -47.9), "Alice Springs": (-23.7, 133.9)}.items():
        assert land(lat, lon), f"{name} should be land"
    for name, (lat, lon) in {"Pacific": (0, -150), "Atlantic": (30, -40), "Indian": (-20, 80)}.items():
        assert not land(lat, lon), f"{name} should be ocean"
