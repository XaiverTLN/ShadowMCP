# ShadowMCP

**A tool-call firewall for AI agents and MCP servers that routes every tool request to the right handler: forward it, hand it to a human, or divert it to a canary.**

AI agents increasingly act through tools: reading files, querying databases, sending webhooks.
A single poisoned document (indirect prompt injection) can hijack an agent into calling those tools
for an attacker. ShadowMCP sits between the agent and its tools and inspects **every tool call
before it runs**:

| Route | When | What happens |
|---|---|---|
| ✓ **SAFE** (risk ≤ 0.40) | The call matches what the user asked for | Forwarded to the real tool |
| ⚠ **REVIEW** (0.41–0.75) | Ambiguous, e.g. data leaving the organization | Paused and handed off to a human operator |
| ⛔ **HONEYPOT** (≥ 0.76) | Clearly hostile, e.g. secret harvesting or exfiltration | Real tool never runs; the agent receives a **synthetic canary** and outbound traffic is sinkholed |

The hijacked agent is never told it was caught: it receives a normal-looking tool result.

> Built for DevFest Florida 2026 (Devs Track — "Fix the Handoff"). This is a working **local prototype**, not a hosted service. See [Limitations](#limitations).

---

## How it decides (routing)

```
Agent ──► ShadowMCP ──► Stage 1: deterministic rules (local, ~ms)
                         · secret / credential access signatures
                         · destructive SQL or shell, raw-IP or "collect" endpoints
                         · SSN-style PII, encoded payloads, high-entropy values
                         · confused deputy: tool outside the user's stated intent
                         · session taint: internal data read earlier + outbound send now
                  ──► Stage 2: LLM intent-drift judge (Groq → Gemini → local fallback)
                         · may only RAISE the Stage 1 score, never lower it
                  ──► SAFE → tool   |   REVIEW → human   |   HONEYPOT → canary
```

Every decision is recorded as a 17-field event (intent, tool, arguments, stage, latency, risk, tier,
reasoning, action, canary ID, exfiltration endpoint …). See [SPEC.md](SPEC.md).

## How it stores (storage)

Events, pending reviews, session taint and the kill switch live **in memory in the dashboard
process** (bounded queues). The MCP proxy runs as its own process and can optionally append its
events to a local JSONL log (`--event-log`). A shared SQLite store so the dashboard can approve
proxy calls live is the next planned step.

## What's in this repository

| Path | What it is |
|---|---|
| `app.py` | Streamlit **SOC dashboard**: live demo, human-review queue, canary vault, threat map, kill switch, no-code policies |
| `shadowmcp/` | The installable core: `core.py` (routing engine), `llm_client.py` (Groq/Gemini router with circuit breaker), `proxy.py` (MCP stdio proxy), `adapters/` (Python decorator, Google ADK callbacks) |
| `shadow_mcp.py`, `llm_client.py` | Thin compatibility shims for older imports |
| `examples/rag_healthcare_agent/` | **Separate, intentionally vulnerable demo target** (synthetic data only). Not part of ShadowMCP. |
| `tests/` | pytest suite (routing, policies, proxy protocol, exporter, package, UI) |
| `docs/SETUP_GUIDE.md` | Full install, configuration and usage guide |

## Quick start (Windows PowerShell)

```powershell
git clone https://github.com/<your-account>/ShadowMCP.git
cd ShadowMCP
py -3.11 -m venv .venv
.\.venv\Scripts\python.exe -m pip install -r requirements.txt
copy .env.example .env        # optional: add API keys and passcodes (see setup guide)
.\.venv\Scripts\python.exe -m streamlit run app.py --server.address 127.0.0.1
```

Open <http://127.0.0.1:8501> and press the three red-team preset buttons.
**No API keys are needed**: without keys ShadowMCP uses its local deterministic judge and canary templates.

macOS / Linux: use `python3 -m venv .venv` and `.venv/bin/python` instead.

Full instructions, configuration reference and integration examples: **[docs/SETUP_GUIDE.md](docs/SETUP_GUIDE.md)**.

## Protect your own tools

**Any stdio MCP server** — install the package (`pip install -e .` inside the venv) and wrap the
server with `shadowmcp-proxy` in your MCP client's config:

```json
{
  "mcpServers": {
    "my-files": {
      "command": "C:\\path\\to\\ShadowMCP\\.venv\\Scripts\\shadowmcp-proxy.exe",
      "args": ["--intent", "Summarize project documents",
               "--wrap", "--", "C:\\Program Files\\nodejs\\npx.cmd", "-y",
               "@modelcontextprotocol/server-filesystem", "C:\\path\\to\\folder"]
    }
  }
}
```

Use absolute paths. The dashboard sidebar (**Integration examples**) generates this config for
your machine and resolves the executables for you.

**Python tools** — decorate the function:

```python
from shadow_mcp import shadow_mcp_guard

@shadow_mcp_guard(lambda *a, **k: "Summarize the quarterly budget")   # the user's real request
def read_file(path: str) -> str:
    ...
```

## Run the tests

```powershell
$env:PYTHON_DOTENV_DISABLED = "1"
.\.venv\Scripts\python.exe -m pip install pytest
.\.venv\Scripts\python.exe -m pytest tests -q
```

## Limitations

Honest status of this prototype:

- **Local use only.** The dashboard's operator controls (kill switch, review approvals) are protected by a single shared passcode, and state is per process. Do not expose it on a public URL.
- The proxy and dashboard do not yet share state: a REVIEW raised inside the proxy returns a neutral "not executed" result instead of waiting for a dashboard approval.
- Canary values are visibly labelled (`AKIA_CANARY_TRAP_…`) so audiences can recognise them; production canaries should use realistic formats mapped server-side.
- The MCP proxy is tested with a stdio fake server and the bundled demo target; it has not yet been validated inside Claude Desktop, Cursor or VS Code.
- Google ADK callbacks are tested with dict-based state, not yet with a real ADK `ToolContext`.
- Detection rules are tuned on the demo scenarios. Treat scores as a demonstration, not a guarantee.
- OWASP labels (ASI01 Agent Goal Hijack, ASI02 Tool Misuse & Exploitation, ASI06 Memory & Context Poisoning) are design mappings, **not** a certification or compliance claim.

## Safety note on the demo target

`examples/rag_healthcare_agent` contains **fake** secrets and **fake** patient records so the attack
can be shown safely. Its `--direct` mode deliberately runs without protection. Nothing in it sends
network traffic.
