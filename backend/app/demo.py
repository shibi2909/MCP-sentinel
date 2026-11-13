"""The seven demonstration scenarios required by the project brief.

Every scenario sends REAL requests through the same gateway pipeline used by external MCP
clients (nothing is faked); the scenario only checks that the observed decision matches the
expected one.
"""
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.gateway import handle_tool_call
from app.mcp_servers.demo_servers import server_registry
from app.models import AuditLog
from app.security.audit import append_audit, tamper_record_for_demo, verify_chain
from app.security.integrity import check_all
from app.seed import DEMO_API_KEYS

SCENARIOS = [
    {"id": 1, "title": "Normal authorized request", "expected": "ALLOW",
     "description": "research-assistant (high trust) calls utility-server.calculator with a harmless expression."},
    {"id": 2, "title": "Unauthorized agent request", "expected": "BLOCK",
     "description": "An unknown API key, a revoked agent and an agent outside its tool scope all try to call tools."},
    {"id": 3, "title": "Modified tool definition", "expected": "INTEGRITY VIOLATION",
     "description": "The utility-server's get_weather description is poisoned with hidden instructions; the SHA-256 check must catch it."},
    {"id": 4, "title": "Suspicious input", "expected": "BLOCK",
     "description": "intern-agent sends a path-traversal file read and an SQL-injection customer lookup."},
    {"id": 5, "title": "High-risk request", "expected": "REQUIRE_APPROVAL",
     "description": "analytics-agent requests a bulk export of 5000 customer records from a high-sensitivity tool."},
    {"id": 6, "title": "Unusual tool output", "expected": "MONITOR",
     "description": "analytics-agent fetches a note whose content contains a prompt injection and a leaked credential."},
    {"id": 7, "title": "Modified audit record", "expected": "INTEGRITY VERIFICATION FAILURE",
     "description": "An insider edits a BLOCK audit record directly in the database to hide an attack; hash-chain verification must fail."},
]


def _step(label: str, outcome: dict[str, Any], expected_action: str) -> dict[str, Any]:
    return {"label": label, "expected": expected_action, "actual": outcome["action"],
            "passed": outcome["action"] == expected_action, "outcome": outcome}


async def run_scenario(db: Session, scenario_id: int, actor: str) -> dict[str, Any]:
    meta = next((s for s in SCENARIOS if s["id"] == scenario_id), None)
    if meta is None:
        raise KeyError(f"unknown scenario {scenario_id}")
    steps: list[dict[str, Any]] = []
    notes: list[str] = []

    async def call(agent_key: str | None, server: str, tool: str, args: dict) -> dict:
        return await handle_tool_call(db, api_key=agent_key, server_name=server, tool_name=tool, arguments=args, source="demo")

    if scenario_id == 1:
        out = await call(DEMO_API_KEYS["research-assistant"], "utility-server", "calculator", {"expression": "(2 + 3) * 4"})
        steps.append(_step("calculator('(2 + 3) * 4') by research-assistant", out, "ALLOW"))

    elif scenario_id == 2:
        out = await call("sk-attacker-guessed-key-123", "utility-server", "calculator", {"expression": "1+1"})
        steps.append(_step("unknown API key", out, "BLOCK"))
        out = await call(DEMO_API_KEYS["revoked-agent"], "utility-server", "calculator", {"expression": "1+1"})
        steps.append(_step("revoked agent credentials", out, "BLOCK"))
        out = await call(DEMO_API_KEYS["intern-agent"], "crm-server", "export_customer_data", {"limit": 10})
        steps.append(_step("intern-agent calls export_customer_data (outside its scope)", out, "BLOCK"))

    elif scenario_id == 3:
        poisoned = server_registry.tamper_tool("utility-server", "get_weather")
        notes.append(f"Simulated attacker changed the get_weather description to: {poisoned}")
        out = await call(DEMO_API_KEYS["research-assistant"], "utility-server", "get_weather", {"city": "London"})
        step = _step("get_weather('London') after tool poisoning", out, "BLOCK")
        step["passed"] = step["passed"] and out["violation"] == "INTEGRITY_VIOLATION"
        steps.append(step)
        await check_all(db)
        notes.append("The tool stays flagged as 'modified'. Restore it on the Integrity page "
                     "(Restore trusted definition) or approve the new definition after review.")

    elif scenario_id == 4:
        out = await call(DEMO_API_KEYS["intern-agent"], "filesystem-server", "read_file",
                         {"path": "../../../Windows/System32/config/SAM"})
        steps.append(_step("read_file with path traversal", out, "BLOCK"))
        out = await call(DEMO_API_KEYS["intern-agent"], "crm-server", "lookup_customer",
                         {"customer_id": "1' OR '1'='1"})
        steps.append(_step("lookup_customer with SQL injection", out, "BLOCK"))

    elif scenario_id == 5:
        out = await call(DEMO_API_KEYS["analytics-agent"], "crm-server", "export_customer_data",
                         {"limit": 5000, "format": "csv"})
        steps.append(_step("export_customer_data(limit=5000)", out, "REQUIRE_APPROVAL"))
        notes.append("Open the Approvals page to approve or reject this request.")

    elif scenario_id == 6:
        out = await call(DEMO_API_KEYS["analytics-agent"], "utility-server", "fetch_note", {"note_id": 3})
        steps.append(_step("fetch_note(3) returning injected content", out, "MONITOR"))

    elif scenario_id == 7:
        if db.scalar(select(AuditLog.seq).where(AuditLog.action == "BLOCK").limit(1)) is None:
            # make sure there is at least one BLOCK decision for the insider to hide
            await call("sk-attacker-guessed-key-123", "utility-server", "calculator", {"expression": "1+1"})
        before = verify_chain(db)
        tampered = tamper_record_for_demo(db)
        after = verify_chain(db)
        notes.append(f"Record #{tampered['seq']} changed from {tampered['original']} to {tampered['tampered']} "
                     "directly in the database (no hashes recomputed).")
        notes.append("Use 'Undo tampering' on the Audit page to restore the original values.")
        append_audit(db, event_type="AUDIT_VERIFICATION", actor=actor, action="FAILED" if not after["valid"] else "PASSED",
                     details={"first_invalid_seq": after["first_invalid_seq"], "problems": len(after["problems"])})
        steps.append({"label": "verify audit chain after tampering", "expected": "verification fails",
                      "actual": "verification fails" if not after["valid"] else "verification passes",
                      "passed": (not after["valid"]) and any(p["seq"] == tampered["seq"] for p in after["problems"]),
                      "outcome": {"chain_valid_before": before["valid"], "tampered": tampered, "verification": after}})

    passed = all(step["passed"] for step in steps)
    return {**meta, "passed": passed, "steps": steps, "notes": notes}
