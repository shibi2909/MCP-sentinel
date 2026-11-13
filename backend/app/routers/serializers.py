"""Convert ORM rows to JSON-friendly dicts."""
from datetime import datetime, timezone

from app.models import Approval, AuditLog, GatewayRequest, SandboxRun, SecurityEvent, Tool


def iso(value: datetime | None) -> str | None:
    """SQLite drops timezone info; all stored datetimes are UTC, so mark them explicitly."""
    if value is None:
        return None
    if value.tzinfo is None:
        value = value.replace(tzinfo=timezone.utc)
    return value.isoformat()


def request_dict(r: GatewayRequest) -> dict:
    return {
        "id": r.id, "created_at": iso(r.created_at), "source": r.source, "agent": r.agent_name,
        "server": r.server_name, "tool": r.tool_name, "arguments": r.arguments, "rule_score": r.rule_score,
        "ml_score": r.ml_score, "risk_score": r.risk_score, "action": r.action, "status": r.status,
        "violation": r.violation, "reasons": r.reasons, "risk_factors": r.risk_factors,
        "validation_findings": r.validation_findings, "output_findings": r.output_findings,
        "thresholds": r.thresholds, "security_mode": r.security_mode, "controller_mode": r.controller_mode,
        "response_preview": r.response_preview, "latency_ms": r.latency_ms,
    }


def event_dict(e: SecurityEvent) -> dict:
    return {"id": e.id, "created_at": iso(e.created_at), "request_id": e.request_id, "event_type": e.event_type,
            "severity": e.severity, "source_module": e.source_module, "message": e.message, "details": e.details}


def tool_dict(t: Tool) -> dict:
    return {"id": t.id, "server": t.server.name, "name": t.name, "sensitivity": t.sensitivity,
            "integrity_status": t.integrity_status, "approved_hash": t.approved_hash, "current_hash": t.current_hash,
            "approved_definition": t.approved_definition, "current_definition": t.current_definition,
            "last_checked": iso(t.last_checked), "approved_by": t.approved_by, "approved_at": iso(t.approved_at)}


def audit_dict(a: AuditLog) -> dict:
    return {"seq": a.seq, "timestamp": a.timestamp, "request_id": a.request_id, "event_type": a.event_type,
            "actor": a.actor, "action": a.action, "risk_score": a.risk_score, "details": a.details,
            "prev_hash": a.prev_hash, "record_hash": a.record_hash}


def approval_dict(a: Approval) -> dict:
    return {"id": a.id, "request_id": a.request_id, "created_at": iso(a.created_at), "agent": a.agent_name,
            "server": a.server_name, "tool": a.tool_name, "arguments": a.arguments, "risk_score": a.risk_score,
            "reasons": a.reasons, "status": a.status, "decided_by": a.decided_by, "decided_at": iso(a.decided_at),
            "decision_note": a.decision_note, "result_preview": a.result_preview}


def sandbox_dict(s: SandboxRun) -> dict:
    return {"id": s.id, "created_at": iso(s.created_at), "scenario": s.scenario, "outcome": s.outcome,
            "expected": s.expected_outcome, "passed": s.outcome == s.expected_outcome, "duration_ms": s.duration_ms,
            "output": s.output, "blocked_operation": s.blocked_operation, "run_by": s.run_by}
