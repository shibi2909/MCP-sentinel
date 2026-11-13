"""End-to-end tests through the HTTP API (real gateway pipeline, real MCP servers in-process)."""
import pytest

from conftest import login

RESEARCH_KEY = "sk-sentinel-research-7f3a9c2e"


# ------------------------------------------------------------------ M2 authentication / RBAC
def test_login_rejects_wrong_password(client):
    assert client.post("/api/auth/login", json={"username": "admin", "password": "wrong"}).status_code == 401


def test_protected_endpoint_requires_token(client):
    assert client.get("/api/dashboard/summary").status_code == 401


def test_invalid_token_rejected(client):
    assert client.get("/api/dashboard/summary", headers={"Authorization": "Bearer abc.def.ghi"}).status_code == 401


def test_viewer_can_view_but_not_act(fresh):
    headers = login(fresh, "viewer", "Viewer@123")
    assert fresh.get("/api/dashboard/summary", headers=headers).status_code == 200
    assert fresh.post("/api/demo/scenarios/1/run", headers=headers).status_code == 403
    assert fresh.post("/api/audit/verify", headers=headers).status_code == 403


def test_analyst_cannot_use_admin_functions(fresh):
    headers = login(fresh, "analyst", "Analyst@123")
    assert fresh.post("/api/demo/scenarios/1/run", headers=headers).status_code == 200
    assert fresh.post("/api/audit/tamper-demo", headers=headers).status_code == 403
    assert fresh.post("/api/admin/reset", headers=headers).status_code == 403


# ------------------------------------------------------------------ demo scenarios 1-7
@pytest.mark.parametrize("scenario_id", [1, 2, 3, 4, 5, 6, 7])
def test_demo_scenarios_produce_expected_decisions(fresh, admin_headers, scenario_id):
    response = fresh.post(f"/api/demo/scenarios/{scenario_id}/run", headers=admin_headers)
    assert response.status_code == 200, response.text
    body = response.json()
    assert body["passed"], [(s["label"], s["expected"], s["actual"]) for s in body["steps"]]


def test_all_scenarios_in_sequence_still_pass(fresh, admin_headers):
    """Scenarios must not depend on running in a clean state (controller state accumulates)."""
    for _round in range(2):
        for scenario_id in range(1, 8):
            body = fresh.post(f"/api/demo/scenarios/{scenario_id}/run", headers=admin_headers).json()
            assert body["passed"], (scenario_id, [(s["expected"], s["actual"]) for s in body["steps"]])


# ------------------------------------------------------------------ M1 MCP JSON-RPC endpoint
def test_mcp_tools_list_respects_agent_scope(fresh):
    response = fresh.post("/mcp", headers={"X-API-Key": RESEARCH_KEY},
                          json={"jsonrpc": "2.0", "id": 1, "method": "tools/list"})
    names = {t["name"] for t in response.json()["result"]["tools"]}
    assert "utility-server.calculator" in names
    assert "crm-server.export_customer_data" not in names


def test_mcp_tools_call_allowed(fresh):
    response = fresh.post("/mcp", headers={"X-API-Key": RESEARCH_KEY}, json={
        "jsonrpc": "2.0", "id": 7, "method": "tools/call",
        "params": {"name": "utility-server.calculator", "arguments": {"expression": "6*7"}}})
    body = response.json()
    assert body["id"] == 7
    assert body["result"]["content"][0]["text"] == "42"
    assert body["result"]["_meta"]["sentinel"]["action"] == "ALLOW"


def test_mcp_tools_call_without_key_is_blocked(fresh):
    body = fresh.post("/mcp", json={"jsonrpc": "2.0", "id": 2, "method": "tools/call",
                                    "params": {"name": "utility-server.calculator", "arguments": {"expression": "1"}}}).json()
    assert body["error"]["code"] == -32001
    assert body["error"]["data"]["sentinel"]["action"] == "BLOCK"


def test_mcp_rejects_invalid_jsonrpc(fresh):
    assert fresh.post("/mcp", json={"method": "tools/list"}).json()["error"]["code"] == -32600


# ------------------------------------------------------------------ M7 approvals
def test_approval_flow_executes_after_approval(fresh, admin_headers):
    fresh.post("/api/demo/scenarios/5/run", headers=admin_headers)
    pending = fresh.get("/api/approvals?status=pending", headers=admin_headers).json()
    assert len(pending) == 1
    result = fresh.post(f"/api/approvals/{pending[0]['id']}/approve", headers=admin_headers, json={"note": "test"}).json()
    assert result["approval"]["status"] == "approved"
    assert result["outcome"]["executed"] is True
    second = fresh.post(f"/api/approvals/{pending[0]['id']}/approve", headers=admin_headers, json={})
    assert second.status_code == 409


def test_approval_refused_if_tool_changed_while_waiting(fresh, admin_headers):
    fresh.post("/api/demo/scenarios/5/run", headers=admin_headers)
    approval = fresh.get("/api/approvals?status=pending", headers=admin_headers).json()[0]
    from app.mcp_servers.demo_servers import server_registry
    server_registry.tamper_tool("crm-server", "export_customer_data")
    result = fresh.post(f"/api/approvals/{approval['id']}/approve", headers=admin_headers, json={}).json()
    assert result["outcome"]["executed"] is False


# ------------------------------------------------------------------ M3 integrity / M9 audit
def test_integrity_restore_after_tampering(fresh, admin_headers):
    fresh.post("/api/demo/scenarios/3/run", headers=admin_headers)
    check = fresh.post("/api/integrity/check", headers=admin_headers).json()
    assert not check["all_trusted"]
    fresh.post("/api/integrity/servers/utility-server/restore", headers=admin_headers)
    assert fresh.post("/api/integrity/check", headers=admin_headers).json()["all_trusted"]


def test_audit_chain_valid_then_tampered_then_restored(fresh, admin_headers):
    fresh.post("/api/demo/scenarios/2/run", headers=admin_headers)
    assert fresh.post("/api/audit/verify", headers=admin_headers).json()["valid"]
    tampered = fresh.post("/api/audit/tamper-demo", headers=admin_headers).json()
    report = fresh.post("/api/audit/verify", headers=admin_headers).json()
    assert not report["valid"] and report["first_invalid_seq"] == tampered["seq"]
    restored = fresh.post("/api/audit/restore-demo", headers=admin_headers).json()
    assert restored["verification"]["valid"]


def test_every_decision_is_audited(fresh, admin_headers):
    before = fresh.get("/api/audit", headers=admin_headers).json()["total"]
    fresh.post("/api/demo/scenarios/2/run", headers=admin_headers)  # three requests
    after = fresh.get("/api/audit", headers=admin_headers).json()
    decisions = [r for r in after["records"] if r["event_type"] == "TOOL_CALL_DECISION"]
    assert after["total"] - before >= 3 and len(decisions) >= 3


# ------------------------------------------------------------------ dashboard + sandbox
def test_dashboard_reflects_real_requests(fresh, admin_headers):
    fresh.post("/api/demo/scenarios/1/run", headers=admin_headers)
    fresh.post("/api/demo/scenarios/4/run", headers=admin_headers)
    totals = fresh.get("/api/dashboard/summary", headers=admin_headers).json()["totals"]
    assert totals["total"] == 3 and totals["allowed"] == 1 and totals["blocked"] == 2


def test_security_mode_switch(fresh, admin_headers):
    state = fresh.put("/api/controller/mode", headers=admin_headers, json={"mode": "A_STATIC"}).json()
    assert state["security_mode"] == "A_STATIC"
    out = fresh.post("/api/gateway/test", headers=admin_headers, json={
        "agent": "research-assistant", "server": "utility-server", "tool": "calculator", "arguments": {"expression": "1+1"}}).json()
    assert out["ml_score"] is None and out["security_mode"] == "A_STATIC"


@pytest.mark.parametrize("key,expected", [("safe_computation", "completed"), ("file_escape", "blocked"),
                                          ("process_spawn", "blocked")])
def test_sandbox_scenarios(fresh, admin_headers, key, expected):
    body = fresh.post(f"/api/sandbox/run/{key}", headers=admin_headers).json()
    assert body["outcome"] == expected
