"""M1 - Security Gateway: the request pipeline that connects every security module.

    agent --tools/call--> [1 authenticate] -> [2 registry lookup] -> [3 authorise (scopes)]
                          -> [4 tool integrity (SHA-256)] -> [5 input validation]
                          -> [6 risk engine (rules + ML)] -> [7 policy (controller thresholds)]
                          -> [8 forward to trusted MCP server] -> [9 output monitoring]
                          -> [10 controller feedback] -> [11 tamper-evident audit]
"""
import json
import time
import uuid
from datetime import datetime, timedelta, timezone
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.mcp_servers.client import UpstreamServerError, call_tool, result_text
from app.ml.model import get_classifier
from app.models import Agent, Approval, GatewayRequest, McpServer, SecurityEvent, Tool
from app.security import controller_service
from app.security.audit import append_audit
from app.security.auth import agent_can_use_tool, authenticate_agent
from app.security.integrity import check_tool_integrity
from app.security.monitor import scan_output
from app.security.policy import PolicyDecision, decide, escalate
from app.security.risk_engine import RiskAssessment, assess, build_features, is_bulk_request
from app.security.validation import validate_request

# JSON-RPC error codes returned by the gateway (application-defined range)
ERROR_CODES = {
    "AUTHENTICATION_FAILED": -32001,
    "UNAUTHORIZED_TOOL": -32001,
    "UNREGISTERED_TOOL": -32002,
    "POLICY_BLOCK": -32002,
    "INTEGRITY_VIOLATION": -32003,
    "APPROVAL_REQUIRED": -32004,
    "INPUT_VALIDATION": -32602,
    "UPSTREAM_ERROR": -32603,
}


def _agent_context(db: Session, agent: Agent | None) -> dict[str, Any]:
    """Behavioural context of the agent, computed from its recent history in the database."""
    if agent is None:
        return {"agent_block_ratio": 0.0, "request_rate": 0, "recent_output_anomalies": 0}
    recent = list(db.scalars(
        select(GatewayRequest).where(GatewayRequest.agent_name == agent.name)
        .order_by(GatewayRequest.created_at.desc()).limit(20)
    ))
    one_minute_ago = datetime.now(timezone.utc).replace(tzinfo=None) - timedelta(seconds=60)
    rate = sum(1 for r in recent if r.created_at.replace(tzinfo=None) >= one_minute_ago)
    # Integrity violations are caused by the *server*, not the agent, so they do not count against it.
    blocked = sum(1 for r in recent if r.action == "BLOCK" and r.violation != "INTEGRITY_VIOLATION")
    anomalies = sum(1 for r in recent if r.output_findings)
    return {
        "agent_block_ratio": round(blocked / len(recent), 3) if recent else 0.0,
        "request_rate": rate,
        "recent_output_anomalies": anomalies,
    }


def _redact(value: Any) -> Any:
    """Apply output redaction to every string inside an MCP result."""
    if isinstance(value, str):
        return scan_output(value).redacted_text
    if isinstance(value, dict):
        return {k: _redact(v) for k, v in value.items()}
    if isinstance(value, list):
        return [_redact(v) for v in value]
    return value


def _event(db: Session, request_id: str | None, event_type: str, severity: str, module: str,
           message: str, details: dict | None = None) -> None:
    db.add(SecurityEvent(request_id=request_id, event_type=event_type, severity=severity,
                         source_module=module, message=message[:500], details=details or {}))


async def _forward_and_monitor(server_name: str, tool_name: str, arguments: dict) -> dict[str, Any]:
    """Forward to the trusted server, then scan and redact the output (M8)."""
    try:
        result = await call_tool(server_name, tool_name, arguments)
    except UpstreamServerError as exc:
        return {"ok": False, "error": str(exc), "result": None, "output_findings": [], "text": ""}
    text = result_text(result)
    report = scan_output(text)
    if report.has_anomaly:
        result = _redact(result)
    return {
        "ok": True, "error": None, "result": result, "output_findings": report.to_list(),
        "output_severity": report.max_severity, "text": report.redacted_text,
        "upstream_error": bool(result.get("isError")),
    }


async def handle_tool_call(db: Session, *, api_key: str | None, server_name: str, tool_name: str,
                           arguments: Any, source: str = "api") -> dict[str, Any]:
    started = time.perf_counter()
    request_id = str(uuid.uuid4())
    security_mode, thresholds, enforcement_mode = controller_service.effective_policy_inputs(db)

    agent, auth_failure = authenticate_agent(db, api_key)
    agent_name = agent.name if agent else "anonymous"
    arguments_for_log = arguments if isinstance(arguments, dict) else {"_raw": str(arguments)[:500]}

    violation: str | None = None
    violation_detail = ""
    tool: Tool | None = None
    assessment: RiskAssessment | None = None
    validation_findings: list[dict] = []
    integrity_info: dict | None = None

    # ---- 1. Authentication (M2)
    if auth_failure:
        violation, violation_detail = "AUTHENTICATION_FAILED", auth_failure
    # ---- 2. Registry lookup (M3)
    if not violation:
        tool = db.scalar(select(Tool).join(McpServer).where(McpServer.name == server_name, Tool.name == tool_name))
        if tool is None or not tool.server.is_trusted:
            violation, violation_detail = "UNREGISTERED_TOOL", f"'{server_name}.{tool_name}' is not a registered trusted tool"
    # ---- 3. Authorisation / least privilege (M2)
    if not violation and not agent_can_use_tool(agent, server_name, tool_name):
        violation, violation_detail = "UNAUTHORIZED_TOOL", f"agent '{agent_name}' is not permitted to call {server_name}.{tool_name}"
    # ---- 4. Tool integrity (M3)
    if not violation:
        integrity_info = await check_tool_integrity(db, tool)
        if integrity_info["status"] != "trusted":
            violation = "INTEGRITY_VIOLATION"
            violation_detail = (f"tool definition is '{integrity_info['status']}'"
                                f" (changed: {', '.join(integrity_info['changed_fields']) or 'n/a'})")
    # ---- 5. Input validation (M4) + 6. risk assessment (M6)
    if not violation or violation == "INTEGRITY_VIOLATION":
        report = validate_request(arguments, tool.approved_definition.get("inputSchema"))
        validation_findings = report.to_list()
        context = _agent_context(db, agent)
        features = build_features(
            sensitivity=tool.sensitivity, validation_report=report, payload_bytes=report.payload_bytes,
            bulk=is_bulk_request(server_name, tool_name, arguments if isinstance(arguments, dict) else {}),
            trust_level=agent.trust_level, **context,
        )
        assessment = assess(features, security_mode, None if security_mode == "A_STATIC" else get_classifier())
        if not violation and report.critical:
            categories = sorted({f["category"] for f in validation_findings if f["severity"] == "critical"})
            violation, violation_detail = "INPUT_VALIDATION", "critical input finding(s): " + ", ".join(categories)

    # ---- 7. Policy decision (M7) - critical violations are non-overridable BLOCKs
    risk_score = 100.0 if violation else assessment.final_score
    decision: PolicyDecision = decide(
        risk_score=risk_score, thresholds=thresholds, critical_violation=violation,
        sensitivity=tool.sensitivity if tool else "high",
        bulk_request=bool(assessment and assessment.features["bulk_request"]),
        enforcement_mode=enforcement_mode, has_input_findings=bool(validation_findings),
    )
    if violation:
        decision.reasons.append(violation_detail)

    action = decision.action
    status, result, error, approval_id = "blocked", None, None, None
    output_findings: list[dict] = []
    observed_risk = 1.0 if violation else risk_score / 100.0

    if action == "REQUIRE_APPROVAL":
        status = "pending_approval"
    elif action in ("ALLOW", "MONITOR"):
        # ---- 8. Forward to the trusted MCP server + 9. output monitoring (M8)
        forwarded = await _forward_and_monitor(server_name, tool_name, arguments)
        if not forwarded["ok"]:
            status = "error"
            error = {"code": ERROR_CODES["UPSTREAM_ERROR"], "message": forwarded["error"]}
        else:
            status = "error" if forwarded["upstream_error"] else "executed"
            result = forwarded["result"]
            output_findings = forwarded["output_findings"]
            if output_findings:
                new_action = escalate(action, "MONITOR")
                decision.reasons.append("behaviour monitor: anomalous tool output (" +
                                        ", ".join(sorted({f["category"] for f in output_findings})) + "); output redacted")
                action = new_action
                observed_risk = max(observed_risk, 0.7 if forwarded["output_severity"] == "high" else 0.5)

    # ---- 10. Controller feedback (always observes, only enforces in mode C)
    snapshot, previous_mode, new_mode = controller_service.observe(db, observed_risk, request_id)

    preview = json.dumps(result, ensure_ascii=False)[:1500] if result is not None else ""
    record = GatewayRequest(
        id=request_id, source=source, agent_name=agent_name, server_name=server_name, tool_name=tool_name,
        arguments=json.loads(json.dumps(arguments_for_log, default=str)),
        rule_score=assessment.rule_score if assessment else 100.0,
        ml_score=assessment.ml_score if assessment else None,
        risk_score=risk_score, action=action, status=status, violation=violation, reasons=decision.reasons,
        risk_factors=assessment.factors if assessment else [{"factor": "critical_violation", "points": 100, "explanation": violation_detail}],
        validation_findings=validation_findings, output_findings=output_findings, thresholds=thresholds,
        security_mode=security_mode, controller_mode=enforcement_mode, response_preview=preview,
        latency_ms=round((time.perf_counter() - started) * 1000, 1),
    )
    db.add(record)
    db.flush()

    if action == "REQUIRE_APPROVAL":
        approval = Approval(request_id=request_id, agent_name=agent_name, server_name=server_name,
                            tool_name=tool_name, arguments=record.arguments, risk_score=risk_score,
                            reasons=decision.reasons)
        db.add(approval)
        db.flush()
        approval_id = approval.id
        error = {"code": ERROR_CODES["APPROVAL_REQUIRED"], "message": "Request held for human approval"}
    elif action == "BLOCK":
        code = ERROR_CODES.get(violation or "POLICY_BLOCK", -32002)
        error = {"code": code, "message": f"Blocked by MCP-Sentinel: {decision.reasons[-1] if violation else decision.reasons[0]}"}

    # ---- Security events (M8 feeds the dashboard)
    if violation:
        module = {"AUTHENTICATION_FAILED": "M2-IAM", "UNAUTHORIZED_TOOL": "M2-IAM", "UNREGISTERED_TOOL": "M3-Integrity",
                  "INTEGRITY_VIOLATION": "M3-Integrity", "INPUT_VALIDATION": "M4-Validation"}[violation]
        _event(db, request_id, violation, "critical", module, f"{agent_name} -> {server_name}.{tool_name}: {violation_detail}",
               {"integrity": integrity_info, "findings": validation_findings})
    elif action == "BLOCK":
        _event(db, request_id, "HIGH_RISK_BLOCKED", "high", "M7-Policy", f"{agent_name} -> {server_name}.{tool_name} blocked, risk {risk_score}")
    elif action == "REQUIRE_APPROVAL":
        _event(db, request_id, "APPROVAL_REQUIRED", "medium", "M7-Policy", f"{agent_name} -> {server_name}.{tool_name} held for approval, risk {risk_score}")
    if output_findings:
        _event(db, request_id, "OUTPUT_ANOMALY", "high", "M8-Monitor",
               f"Unexpected output from {server_name}.{tool_name}: " + "; ".join(f["detail"] for f in output_findings),
               {"findings": output_findings})
    elif action == "MONITOR":
        _event(db, request_id, "MONITORED_REQUEST", "low", "M7-Policy", f"{agent_name} -> {server_name}.{tool_name} monitored, risk {risk_score}")
    if previous_mode != new_mode:
        _event(db, request_id, "CONTROLLER_MODE_CHANGE", "medium" if new_mode != "NORMAL" else "info", "Controller",
               f"Enforcement mode changed {previous_mode} -> {new_mode} (u = {snapshot.control_signal})",
               {"thresholds": snapshot.thresholds})
    db.commit()

    # ---- 11. Tamper-evident audit record (M9)
    append_audit(db, event_type="TOOL_CALL_DECISION", actor=agent_name, action=action, risk_score=risk_score,
                 request_id=request_id, details={
                     "server": server_name, "tool": tool_name, "status": status, "violation": violation,
                     "reasons": decision.reasons, "thresholds": thresholds, "security_mode": security_mode,
                     "controller_mode": enforcement_mode, "output_anomalies": [f["category"] for f in output_findings],
                     "source": source,
                 })

    return {
        "request_id": request_id,
        "agent": agent_name,
        "server": server_name,
        "tool": tool_name,
        "action": action,
        "status": status,
        "violation": violation,
        "risk_score": risk_score,
        "rule_score": record.rule_score,
        "ml_score": record.ml_score,
        "risk_method": assessment.method if assessment else "critical violation (score fixed at 100)",
        "risk_factors": record.risk_factors,
        "explanation": assessment.explanation() if assessment else [violation_detail],
        "reasons": decision.reasons,
        "thresholds": thresholds,
        "security_mode": security_mode,
        "enforcement_mode": enforcement_mode,
        "controller_after": {"estimated_risk": snapshot.estimated_risk, "control_signal": snapshot.control_signal,
                             "enforcement_mode": snapshot.enforcement_mode, "thresholds": snapshot.thresholds},
        "validation_findings": validation_findings,
        "output_findings": output_findings,
        "integrity": integrity_info,
        "approval_id": approval_id,
        "result": result,
        "error": error,
        "latency_ms": record.latency_ms,
    }


async def execute_approved(db: Session, approval: Approval, approver: str, note: str) -> dict[str, Any]:
    """Run a request after a human approved it. Integrity is re-checked at execution time
    (prevents time-of-check/time-of-use attacks where the tool changes while waiting)."""
    request = db.get(GatewayRequest, approval.request_id)
    tool = db.scalar(select(Tool).join(McpServer).where(McpServer.name == approval.server_name, Tool.name == approval.tool_name))
    integrity_info = await check_tool_integrity(db, tool)
    approval.decided_by, approval.decided_at, approval.decision_note = approver, datetime.now(timezone.utc), note
    if integrity_info["status"] != "trusted":
        approval.status = "rejected"
        approval.result_preview = "Execution refused: tool integrity violation detected after approval"
        request.status = "blocked"
        request.violation = "INTEGRITY_VIOLATION"
        outcome = {"executed": False, "reason": approval.result_preview}
        audit_action = "REJECTED_INTEGRITY"
    else:
        forwarded = await _forward_and_monitor(approval.server_name, approval.tool_name, approval.arguments)
        approval.status = "approved"
        approval.result_preview = json.dumps(forwarded["result"], ensure_ascii=False)[:1500] if forwarded["ok"] else str(forwarded["error"])
        request.status = "executed" if forwarded["ok"] else "error"
        request.response_preview = approval.result_preview
        request.output_findings = forwarded["output_findings"]
        outcome = {"executed": forwarded["ok"], "result": forwarded["result"], "output_findings": forwarded["output_findings"]}
        audit_action = "APPROVED"
    _event(db, approval.request_id, "APPROVAL_DECISION", "info", "M7-Policy",
           f"{approver} {audit_action.lower()} request {approval.request_id[:8]} ({approval.server_name}.{approval.tool_name})")
    db.commit()
    append_audit(db, event_type="APPROVAL_DECISION", actor=approver, action=audit_action, risk_score=approval.risk_score,
                 request_id=approval.request_id, details={"approval_id": approval.id, "note": note,
                                                          "tool": f"{approval.server_name}.{approval.tool_name}"})
    return outcome


def reject_approval(db: Session, approval: Approval, approver: str, note: str) -> None:
    approval.status, approval.decided_by = "rejected", approver
    approval.decided_at, approval.decision_note = datetime.now(timezone.utc), note
    request = db.get(GatewayRequest, approval.request_id)
    request.status = "rejected"
    _event(db, approval.request_id, "APPROVAL_DECISION", "info", "M7-Policy",
           f"{approver} rejected request {approval.request_id[:8]} ({approval.server_name}.{approval.tool_name})")
    db.commit()
    append_audit(db, event_type="APPROVAL_DECISION", actor=approver, action="REJECTED", risk_score=approval.risk_score,
                 request_id=approval.request_id, details={"approval_id": approval.id, "note": note})
