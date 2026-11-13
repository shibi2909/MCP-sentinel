# MCP-Sentinel

**Approved title:** MCP: A Control-Theoretic Orchestration Framework
**Domain:** Cybersecurity · Model Context Protocol (MCP) · AI security · intelligent access control

MCP-Sentinel is a security gateway that sits between AI agents (MCP clients) and MCP servers.
Every tool call is authenticated, authorised, checked for tool-definition integrity, validated,
risk-scored (rules + ML), decided by a policy engine whose thresholds are adapted by a
**PI feedback controller**, forwarded to a trusted MCP server, monitored on output, and recorded
in a **SHA-256 hash-chained audit log**. A React dashboard shows all of it from live backend data.

```
AI agent ──tools/call──►  MCP-Sentinel gateway  ──MCP──►  trusted MCP servers
                         (M1–M9 + PI controller)          (official MCP Python SDK)
                                   │
                         React security dashboard (M10)
```

## What is implemented

| Module | Status | Where |
|---|---|---|
| M1 Security gateway (JSON-RPC `tools/list`, `tools/call`) | ✅ | `backend/app/gateway.py`, `routers/gateway.py` |
| M2 IAM: API keys (SHA-256), JWT, RBAC (admin/analyst/viewer) | ✅ | `security/auth.py` |
| M3 Tool integrity: SHA-256 of canonical tool definitions | ✅ | `security/integrity.py` |
| M4 Input validation: JSON Schema + injection detectors | ✅ | `security/validation.py` |
| M5 Sandbox simulation (isolated subprocess + audit hook) | ✅ (demonstration-grade) | `security/sandbox.py` |
| M6 Risk engine: explainable rules + scikit-learn Logistic Regression | ✅ (ML trained on **synthetic** data) | `security/risk_engine.py`, `ml/` |
| M7 Policy: ALLOW / MONITOR / REQUIRE_APPROVAL / BLOCK | ✅ | `security/policy.py` |
| M8 Behaviour monitoring of tool outputs (+ redaction) | ✅ | `security/monitor.py` |
| M9 Tamper-evident audit log + verification | ✅ | `security/audit.py` |
| M10 Dashboard (React, TypeScript, Vite, Tailwind, Recharts) | ✅ | `frontend/` |
| PI feedback controller with anti-windup, adaptive thresholds | ✅ | `security/controller.py` |
| A/B/C configuration comparison (repeatable, seeded) | ✅ | `backend/app/experiments.py` |
| Docker files | provided, **not build-tested** | `backend/Dockerfile`, `frontend/Dockerfile`, `docker-compose.yml` |
| Kubernetes, Hyperledger Fabric | ❌ **not implemented** (future work) | `docs/LIMITATIONS.md` |

## Requirements

- Windows 10/11
- Python **3.11+** (tested with 3.13.1)
- Node.js **18+** (tested with 22.13.0, npm 10.9)

## Installation (Windows, first time only)

Open a terminal in VS Code (**Terminal → New Terminal**). The commands below are for **PowerShell**
(the VS Code default on Windows).

```powershell
# 1. Backend: create and activate a virtual environment, then install dependencies
cd C:\Users\dilba\mcp-sentinel\backend
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt

# 2. Frontend: install packages
cd C:\Users\dilba\mcp-sentinel\frontend
npm install
```

> If PowerShell says *"running scripts is disabled on this system"* when activating, run once:
> `Set-ExecutionPolicy -Scope CurrentUser RemoteSigned` and answer **Y**.
> In **Command Prompt (cmd)** activate with `.venv\Scripts\activate.bat` instead.

## Running the application

You need **two terminals** (click **+** in the VS Code terminal panel for the second one).

**Terminal 1 – backend (FastAPI on port 8000)**
```powershell
cd C:\Users\dilba\mcp-sentinel\backend
.\.venv\Scripts\Activate.ps1
uvicorn app.main:app --reload --port 8000
```

**Terminal 2 – frontend (React on port 5173)**
```powershell
cd C:\Users\dilba\mcp-sentinel\frontend
npm run dev
```

Open **http://localhost:5173** and sign in. Interactive API docs: **http://localhost:8000/docs**.

Shortcut: double-click `start-backend.bat`, then `start-frontend.bat` in the project folder.

### Demo accounts (local demonstration only)

| Dashboard user | Password | Role |
|---|---|---|
| admin | Admin@123 | everything, incl. tamper demos, reset, mode switch |
| analyst | Analyst@123 | run demos, approve requests, verify audit |
| viewer | Viewer@123 | read-only |

| Agent (MCP client) | API key | Trust |
|---|---|---|
| research-assistant | `sk-sentinel-research-7f3a9c2e` | high |
| analytics-agent | `sk-sentinel-analytics-2b8e41d0` | medium |
| intern-agent | `sk-sentinel-intern-91d0c6aa` | low |
| revoked-agent | `sk-sentinel-revoked-00000000` | revoked |

## Running the tests

```powershell
cd C:\Users\dilba\mcp-sentinel\backend
.\.venv\Scripts\Activate.ps1
python -m pytest -v
```
Expected: **58 passed**. Tests use a temporary database, so your demo data is not touched.

Frontend type-check and production build:
```powershell
cd C:\Users\dilba\mcp-sentinel\frontend
npm run build
```

## Re-running the experiment and retraining the model

```powershell
cd C:\Users\dilba\mcp-sentinel\backend
.\.venv\Scripts\Activate.ps1
python -m app.ml.train        # retrain the classifier, prints held-out metrics (synthetic data)
python -m app.experiments     # A/B/C comparison, writes docs/results/experiment_results.{md,json}
```
The same experiment can be started from the dashboard (**Experiments → Run experiment**).

## Suggested live demonstration (≈10 minutes)

1. Sign in as **admin**. Optional clean start: **Controller → Reset all demo data**.
2. **Demo Scenarios → Run all 7.** Explain each decision panel (risk factors, reasons, findings).
3. **Overview** – counters, charts, controller now in ELEVATED/LOCKDOWN after the attacks.
4. **Approval Queue** – approve the bulk export from scenario 5 (integrity is re-checked first).
5. **Tool Integrity** – show the modified `get_weather` hash, *compare* the definitions, then *Restore trusted definition*.
6. **Audit Log** – *Verify* (fails because of scenario 7) → *Undo tampering* → *Verify* (valid).
7. **Controller** – threshold chart; switch configuration A/B/C.
8. **Sandbox** – run the five scenarios.
9. **Experiments** – run the comparison and discuss the trade-off table honestly.
10. **Gateway & Requests** – type your own malicious arguments in the playground.

## Calling the gateway like a real MCP client

```powershell
$headers = @{ "X-API-Key" = "sk-sentinel-research-7f3a9c2e" }
$body = '{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"utility-server.calculator","arguments":{"expression":"(2+3)*4"}}}'
Invoke-RestMethod -Uri http://localhost:8000/mcp -Method Post -Headers $headers -ContentType "application/json" -Body $body | ConvertTo-Json -Depth 8
```

## Optional: Docker

`docker compose up --build` (from the project folder, with Docker Desktop running) builds both
images and serves the dashboard on http://localhost:8080.
**Status: the Dockerfiles were written but NOT build-tested** (Docker Desktop was not running on
the development machine). The supported, tested way to run the project is the local setup above.

## Documentation

| Document | Contents |
|---|---|
| [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) | System architecture diagram, data-flow diagram, module descriptions, controller design |
| [docs/DATABASE_SCHEMA.md](docs/DATABASE_SCHEMA.md) | Tables, columns, relationships |
| [docs/API.md](docs/API.md) | REST + JSON-RPC API reference |
| [docs/TESTING.md](docs/TESTING.md) | Test strategy, test list, experiment method, screenshots checklist |
| [docs/LIMITATIONS.md](docs/LIMITATIONS.md) | Known limitations and future work |
| [docs/results/experiment_results.md](docs/results/experiment_results.md) | Generated experiment results |

## Project structure

```
mcp-sentinel/
├── backend/
│   ├── app/
│   │   ├── main.py              FastAPI app + startup
│   │   ├── gateway.py           M1 pipeline (connects all modules)
│   │   ├── demo.py              7 demonstration scenarios
│   │   ├── experiments.py       A/B/C comparison
│   │   ├── seed.py              demo users, agents, trusted registry
│   │   ├── models.py            SQLAlchemy tables
│   │   ├── security/            auth, integrity, validation, sandbox, risk_engine,
│   │   │                        policy, monitor, audit, controller, controller_service
│   │   ├── ml/                  synthetic dataset, training, model loading
│   │   ├── mcp_servers/         3 safe MCP servers (official SDK) + MCP client
│   │   └── routers/             HTTP endpoints
│   ├── tests/                   pytest suite (58 tests)
│   ├── sandbox_files/           the only folder the filesystem MCP server can read
│   └── requirements.txt
├── frontend/                    React + TypeScript + Vite + Tailwind + Recharts
├── docs/                        academic documentation + generated results
├── docker-compose.yml
├── start-backend.bat / start-frontend.bat
└── README.md
```

## Technology notes / substitutions

- **MCP SDK 2.x** (`mcp==2.3.0`): `FastMCP` was renamed to `MCPServer`; the code uses the 2.x API.
  The demo MCP servers run in-process and are reached through the SDK's `Client` with a full MCP
  initialize handshake (no subprocesses needed on Windows).
- **Password hashing** uses PBKDF2-HMAC-SHA256 (600 000 iterations) from the Python standard
  library instead of `passlib/bcrypt`, avoiding a known passlib–bcrypt incompatibility.
- **SQLite** is used for zero-setup local operation; switching to PostgreSQL only requires setting
  `MCP_SENTINEL_DATABASE_URL`.
