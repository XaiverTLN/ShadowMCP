# ShadowMCP setup and usage guide

This guide takes you from download to a working dashboard, then shows how to protect your own
tools. Commands are for **Windows PowerShell**; macOS/Linux equivalents are noted.

- [1. Requirements](#1-requirements)
- [2. Download](#2-download)
- [3. Install](#3-install)
- [4. Configure (optional)](#4-configure-optional)
- [5. Run the dashboard](#5-run-the-dashboard)
- [6. Use the dashboard](#6-use-the-dashboard)
- [7. Run the demo agent over real MCP](#7-run-the-demo-agent-over-real-mcp)
- [8. Protect your own tools](#8-protect-your-own-tools)
- [9. Run the tests](#9-run-the-tests)
- [10. Troubleshooting](#10-troubleshooting)
- [11. Security notes](#11-security-notes)

---

## 1. Requirements

- **Python 3.11 or newer** (tested on 3.14). Check with `py --version` (Windows) or `python3 --version`.
- **Git** to clone the repository, or download the ZIP from GitHub.
- A modern browser (Chrome, Edge, Firefox).
- *Optional:* a [Groq](https://console.groq.com) and/or [Google Gemini](https://aistudio.google.com) API key for the live LLM judge. **Not needed** to run the demo.
- *Optional:* Node.js, only if you want to wrap Node-based MCP servers such as `@modelcontextprotocol/server-filesystem`.

## 2. Download

```powershell
git clone https://github.com/<your-account>/ShadowMCP.git
cd ShadowMCP
```

Or on GitHub click **Code → Download ZIP**, unzip it, and open a terminal in the unzipped folder.

## 3. Install

```powershell
py -3.11 -m venv .venv
.\.venv\Scripts\python.exe -m pip install --upgrade pip
.\.venv\Scripts\python.exe -m pip install -r requirements.txt
.\.venv\Scripts\python.exe -m pip install -e .      # adds the shadowmcp-proxy / shadowmcp-dashboard commands
```

macOS / Linux:

```bash
python3 -m venv .venv
.venv/bin/python -m pip install -r requirements.txt
.venv/bin/python -m pip install -e .
```

> If PowerShell refuses to run scripts, you don't need to activate the venv: every command in this
> guide calls `.venv\Scripts\python.exe` directly.

## 4. Configure (optional)

Copy the example file and edit it in a text editor:

```powershell
copy .env.example .env
notepad .env
```

`.env` is ignored by git. **Never commit it and never paste keys into issues or chats.**

| Variable | Default | Purpose |
|---|---|---|
| `GROQ_API_KEY` | blank | Primary Stage 2 judge. Blank = skip Groq. |
| `GEMINI_API_KEY` | blank | Fallback judge, canary and review-brief text. Blank = local templates. |
| `SHADOWMCP_OPERATOR_PASSCODE` | blank | **Set this to use the kill switch and the human-review Approve / Quarantine buttons.** Blank keeps them locked. |
| `JUDGE_PASSCODE` | blank | Optional: lifts the 3-calls-per-minute limit on the custom tester. |
| `SHADOWMCP_REQUIRE_BYOK` | `1` | `1` = visitors must enter their own keys in the sidebar; `0` = the dashboard may use the keys in `.env` (local use only). |
| `SHADOWMCP_DETERMINISTIC_PRESETS` | `1` | `1` = the three preset buttons always land on SAFE / HONEYPOT / REVIEW. |
| `GROQ_MODEL`, `GEMINI_FLASH_MODEL`, `GEMINI_PRO_MODEL` | see file | Model IDs; change if a provider retires a model. |
| `LLM_TIMEOUT_SECONDS` | `3.5` | Per-call timeout before falling back to the next tier. |
| `SHADOWMCP_EVENT_LOG` | unset | Optional JSONL log for the MCP proxy. It stores prompts and tool arguments: treat it as sensitive. |
| `SHADOWMCP_DEMO_TARGET` | unset | Path to a copy of the demo target if it is not in `examples/`. |

Pick passcodes that are not published anywhere. Restart the dashboard after editing `.env`.

You can also paste API keys into the dashboard sidebar (**Use My Own API Keys**). Those stay in
your browser session only.

## 5. Run the dashboard

```powershell
.\.venv\Scripts\python.exe -m streamlit run app.py --server.address 127.0.0.1 --server.port 8501
```

Then open <http://127.0.0.1:8501>. Stop it with **Ctrl+C**.

(After `pip install -e .` you can also run `shadowmcp-dashboard`.)

Keep `--server.address 127.0.0.1` so the dashboard is reachable only from your own computer.

## 6. Use the dashboard

**Header bar.** Shows which LLM tier is live (Groq, Gemini or the local judge) and the server state.

**KPI row.** Calls inspected, mean interception latency, canary traps triggered. The numbers include
a labelled synthetic baseline so the board is not empty on first load.

**How ShadowMCP routes & stores.** Expand it for the routing diagram and a text equivalent.

**Demo target (left column).** Three preset buttons run the separate vulnerable RAG agent against
three documents:

1. **✓ Benign RAG task** → the summary is allowed (**SAFE**).
2. **⛔ Indirect prompt injection** → the hidden `[SYSTEM OVERRIDE]` tries to read secrets, dump
   patient rows and POST them to a raw IP. ShadowMCP serves a **canary**, sinkholes the exfiltration
   and plots it on the threat map (**HONEYPOT**).
3. **⚠ Confused-deputy escalation** → a hidden directive asks for an external data export. The call
   is **paused for human review**.

The document viewer highlights the injected text. The **Shield ON/OFF** toggle re-runs a preset
with no protection, to show what the synthetic secrets look like when they leak.

**Custom red-team tester.** Pick a tool, edit the JSON arguments and the user's intent, and fire it
through the real engine. Public use is limited to 3 calls per minute per session.

**View mode.** *Executive Plain-English* shows a plain-language receipt. *SecOps Technical* shows
the risk gauge, stage, reasoning, and the vault comparison (real payload blocked vs canary served).

**Human review queue.** REVIEW events appear with an operator brief. Enter the operator passcode in
the sidebar, then choose **Approve** (the tool runs) or **Quarantine** (the call is rerouted to a
canary).

**Kill switch.** *Quarantine MCP Server* blocks every tool call server-wide until released (operator
passcode required).

**No-code policies (sidebar).**
- *Block outbound PII and secret signatures*: Stage 1 SSN-style detection.
- *Require human review for external actions*: when off, outbound REVIEW calls are auto-approved (never for session-taint exfiltration).
- *Serve a synthetic canary*: when off, HONEYPOT calls are hard-blocked with no decoy.

**Threat map and canary table.** Live canary traps with their exfiltration endpoints. *Offline
radar* mode works with no internet connection.

**High-contrast mode.** A black/white theme with distinct solid, dashed and double borders per tier.

## 7. Run the demo agent over real MCP

The dashboard presets call the demo agent in-process. To see ShadowMCP working as a real **MCP
proxy**, run the bundled client. It starts `victim_mcp_server.py` (a stdio MCP server) behind
`python -m shadow_mcp.proxy` and drives the same three scenarios:

```powershell
.\.venv\Scripts\python.exe examples\rag_healthcare_agent\demo_client.py           # protected
.\.venv\Scripts\python.exe examples\rag_healthcare_agent\demo_client.py --direct  # unprotected baseline
```

Expected output: every protected scenario prints `outcome CONTAINED` and
`real secrets reached agent: 0`. In the direct run the poisoned referral prints `outcome LEAKED`.
Add `--json` for machine-readable results.

## 8. Protect your own tools

### Option A: MCP proxy (any stdio MCP server)

1. Install the package (`pip install -e .`, step 3).
2. In the dashboard sidebar open **Integration examples**, enter your server name, the server
   command as a JSON array (for example `["npx", "-y", "@modelcontextprotocol/server-filesystem", "C:\\data"]`)
   and the intent the tools serve. Copy or download the generated `mcp_config.json`.
3. Merge the `mcpServers` entry into your MCP client's config file and restart the client.

You can also run the proxy by hand:

```powershell
.\.venv\Scripts\shadowmcp-proxy.exe --intent "Summarize project documents" --wrap -- npx -y @modelcontextprotocol/server-filesystem C:\data
```

Flags: `--intent` (what the user is allowed to do with these tools), `--session` (taint-tracking
ID), `--source` (label in the event record), `--event-log PATH` (optional JSONL log). Clients may
also send `_meta.original_intent` and `_meta.session_id` with each `tools/call`.

What the agent sees: SAFE calls return the real result. HONEYPOT calls return a canary that looks
like a normal result. REVIEW calls return "This action requires approval from an administrator and
was not executed."

> The proxy is tested against a stdio fake server and the bundled demo server. Validation inside
> Claude Desktop, Cursor and VS Code is still pending, so try it on non-critical servers first.

### Option B: Python decorator

```python
from shadow_mcp import shadow_mcp_guard

USER_REQUEST = "Summarize the quarterly budget"     # capture this from the user's turn, not from tool arguments

@shadow_mcp_guard(lambda *a, **k: USER_REQUEST)
def read_file(path: str) -> str:
    with open(path, encoding="utf-8") as handle:
        return handle.read()
```

A SAFE call runs the function. A blocked call returns a tool-shaped canary or a neutral result,
and the routing record is available as `read_file.last_event`.

### Option C: Google ADK (preview)

```python
from shadow_mcp import adk_shadow_mcp_before_tool_callback
agent = Agent(..., before_tool_callback=adk_shadow_mcp_before_tool_callback)
```

Put the user's request in `state["original_intent"]`. This adapter has not yet been validated against
a real ADK `ToolContext`.

## 9. Run the tests

```powershell
$env:PYTHON_DOTENV_DISABLED = "1"
.\.venv\Scripts\python.exe -m pip install pytest
.\.venv\Scripts\python.exe -m pytest tests -q
```

The suite never calls live LLM providers. It covers routing tiers, policies, latency semantics, the
MCP proxy protocol (handshake, notifications, honeypot, review, manifest drift), the config
exporter, packaging and the UI.

## 10. Troubleshooting

| Symptom | Fix |
|---|---|
| `py` is not recognised | Install Python from python.org with "Add to PATH", or use the full path to `python.exe`. |
| Approve / Quarantine / kill switch say "Operator passcode required" | Set `SHADOWMCP_OPERATOR_PASSCODE` in `.env`, restart, and enter it in the sidebar. |
| Header says "local judge" | No API key is configured or the provider is failing; the demo still works. Use the sidebar probe to test keys. |
| Map is blank | Choose **Offline radar** in the map renderer control. |
| "Live backend raised … OFFLINE SIMULATION" | The demo target folder is missing. Keep `examples/rag_healthcare_agent/` or set `SHADOWMCP_DEMO_TARGET`. |
| Port 8501 is busy | Add `--server.port 8502`. |
| Exporter says it cannot find `npx` | Install Node.js, or give the server command as a full path. |

## 11. Security notes

- Run the dashboard on `127.0.0.1`. It is a single-operator prototype; do not publish it on a public URL.
- Keep `.env` out of version control, and choose private passcodes.
- `SHADOWMCP_EVENT_LOG` files contain prompts and tool arguments.
- Everything in `examples/rag_healthcare_agent/` is synthetic and intentionally vulnerable. Do not
  copy its patterns into real systems.
