"""Offline Streamlit smoke coverage for the presentation-critical UI path."""
from __future__ import annotations

from pathlib import Path

from streamlit.testing.v1 import AppTest


APP = Path(__file__).resolve().parents[1] / "app.py"


def test_dashboard_preset_and_accessible_event_summary(monkeypatch):
    monkeypatch.setenv("PYTHON_DOTENV_DISABLED", "1")
    monkeypatch.setenv("SHADOWMCP_REQUIRE_BYOK", "1")
    monkeypatch.setenv("SHADOWMCP_DETERMINISTIC_PRESETS", "1")
    monkeypatch.setenv("GROQ_API_KEY", "")
    monkeypatch.setenv("GEMINI_API_KEY", "")
    monkeypatch.setenv("SHADOWMCP_OPERATOR_PASSCODE", "")

    app = AppTest.from_file(str(APP)).run(timeout=20)
    assert not app.exception
    assert any("Accessibility" in item.label for item in app.expander)

    motion = next(toggle for toggle in app.toggle if toggle.label == "Reduce motion")
    motion.set_value(True).run(timeout=20)
    assert not app.exception
    assert any("animation: none !important" in str(item.value) for item in app.html)

    preset = next(button for button in app.button if "Benign RAG Task" in button.label)
    preset.click().run(timeout=20)
    assert not app.exception

    html_blocks = "\n".join(str(item.value) for item in app.html)
    assert "Latest intercepted tool calls" in html_blocks
    assert 'scope="col"' in html_blocks
    assert 'aria-label="Latest intercepted tool-call events"' in html_blocks
