"""Keep the pytest suite hermetic: never call live LLM providers, whatever is in .env.

llm_client loads .env at import time with override=False, so pre-setting empty values here
(before the test module imports it) makes the deterministic offline judge the test baseline.
Tests that need keys set them explicitly with monkeypatch.
"""
import os

for _name in ("GROQ_API_KEY", "GEMINI_API_KEY", "SHADOWMCP_REQUIRE_BYOK"):
    os.environ[_name] = ""
