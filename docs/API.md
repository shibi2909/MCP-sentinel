# API documentation

Base URL: `http://localhost:8000`. Interactive OpenAPI docs (try requests in the browser):
`http://localhost:8000/docs`.

Authentication:
* **Agents** → header `X-API-Key: <key>` on `POST /mcp`.
* **Dashboard** → `POST /api/auth/login`, then header `Authorization: Bearer <token>`.
  Missing/invalid token → 401; insufficient role → 403.

## MCP gateway (JSON-RPC 2.0)

### `POST /mcp` — `tools/list`
```json
{"jsonrpc": "2.0", "id": 1, "method": "tools/list"}
```
Returns the approved definitions of the tools the agent may use (names `server.tool`). Tools whose
integrity status is not `trusted` are hidden.

### `POST /mcp` — `tools/call`
```json
{"jsonrpc": "2.0", "id": 2, "method": "tools/call",
 "params": {"name": "utility-server.calculator", "arguments": {"expression": "(2+3)*4"}}}
```
Success: MCP `CallToolResult` plus `result._meta.sentinel` = `{request_id, action, status,
violation, risk_score, rule_score, ml_score, reasons, explanation, approval_id, enforcement_mode,
security_mode}`.

Errors (`error.data.sentinel` carries the same explanation):

| Code | Meaning |
|---|---|
| −32600 | invalid JSON-RPC request |
| −32601 | method not supported |
| −32001 | authentication failed / agent not authorised for tool |
| −32002 | unregistered tool or blocked by risk policy |
| −32003 | tool integrity violation |
| −32004 | held for human approval (`approval_id` given) |
| −32602 | input validation failure |
| −32603 | upstream MCP server error |

## Dashboard REST API

| Method | Path | Permission | Description |
|---|---|---|---|
| POST | `/api/auth/login` | – | `{username, password}` → `{access_token, user}` |
| GET | `/api/auth/me` | any user | current user, role, permissions |
| GET | `/api/health` | – | liveness check |
| GET | `/api/dashboard/summary` | dashboard:view | totals, actions, risk distribution, integrity, controller, events, timeline |
| GET | `/api/dashboard/events?limit=` | dashboard:view | security events |
| GET | `/api/dashboard/controller-history?limit=` | dashboard:view | controller steps |
| GET | `/api/requests?limit=&action=` | dashboard:view | gateway request log |
| GET | `/api/agents` | dashboard:view | agents, trust levels, scopes (no keys) |
| POST | `/api/gateway/test` | gateway:test | playground: `{agent or api_key, server, tool, arguments}` → full decision |
| GET | `/api/integrity/tools` | dashboard:view | registry with approved/current hashes and definitions |
| POST | `/api/integrity/check` | integrity:check | re-hash all live tool definitions |
| POST | `/api/integrity/tools/{id}/approve` | integrity:manage | accept current definition as trusted |
| POST | `/api/integrity/servers/{name}/restore` | integrity:manage | demo: restore original definitions |
| GET | `/api/audit?limit=&offset=` | audit:view | audit records (newest first) |
| POST | `/api/audit/verify` | audit:verify | verify the entire hash chain |
| POST | `/api/audit/tamper-demo?seq=` | audit:tamper_demo | demo: modify a record directly in the DB |
| POST | `/api/audit/restore-demo` | audit:tamper_demo | demo: undo the modification |
| GET | `/api/approvals?status=` | dashboard:view | approval queue |
| POST | `/api/approvals/{id}/approve` | approvals:decide | `{note}` → re-check integrity, execute |
| POST | `/api/approvals/{id}/reject` | approvals:decide | `{note}` |
| GET | `/api/controller` | dashboard:view | controller state and configuration |
| PUT | `/api/controller/mode` | controller:manage | `{mode: A_STATIC \| B_ML \| C_CONTROLLER}` |
| POST | `/api/controller/reset` | controller:manage | reset controller state/history |
| GET | `/api/demo/scenarios` | dashboard:view | list of the 7 scenarios |
| POST | `/api/demo/scenarios/{id}/run` | demo:run | run scenario 1–7 through the real pipeline |
| GET | `/api/sandbox/scenarios` | dashboard:view | sandbox scenarios |
| POST | `/api/sandbox/run/{key}` | sandbox:run | run one sandbox scenario |
| GET | `/api/sandbox/runs` | dashboard:view | recorded sandbox results |
| POST | `/api/experiments/run?seed=` | experiments:run | A/B/C comparison (≈20 s) |
| GET | `/api/experiments/latest` | dashboard:view | latest stored experiment |
| GET | `/api/ml/info` | dashboard:view | classifier metrics (synthetic held-out set) |
| POST | `/api/admin/reset` | system:reset | recreate the database with demo data |
