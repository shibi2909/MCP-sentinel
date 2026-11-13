"""Integrity registry, audit log, approvals and controller management endpoints."""
from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.config import SECURITY_MODES
from app.database import get_db
from app.gateway import execute_approved, reject_approval
from app.mcp_servers.demo_servers import TRUSTED_CATALOG, server_registry
from app.models import Approval, AuditLog, McpServer, SecurityEvent, Tool, User
from app.routers.serializers import approval_dict, audit_dict, tool_dict
from app.security import controller_service
from app.security.audit import (append_audit, audit_count, restore_tampered_records, tamper_record_for_demo,
                                tampered_seqs, verify_chain)
from app.security.auth import require_permission
from app.security.integrity import approve_current_definition, check_all, check_server_integrity

router = APIRouter(prefix="/api", tags=["security"])


# ----------------------------------------------------------------------------- M3 integrity
@router.get("/integrity/tools")
def list_tools(db: Session = Depends(get_db), _user: User = Depends(require_permission("dashboard:view"))):
    tools = db.scalars(select(Tool).join(McpServer).order_by(McpServer.name, Tool.name))
    return {"tools": [tool_dict(t) for t in tools], "simulated_tampering": server_registry.tampered_tools()}


@router.post("/integrity/check")
async def run_integrity_check(db: Session = Depends(get_db), user: User = Depends(require_permission("integrity:check"))):
    results = await check_all(db)
    modified = [r for r in results if r["status"] != "trusted"]
    for r in modified:
        db.add(SecurityEvent(event_type="TOOL_INTEGRITY_ALERT", severity="critical", source_module="M3-Integrity",
                             message=f"{r['server']}.{r['tool']} is {r['status']} (changed: {', '.join(r['changed_fields']) or 'n/a'})",
                             details=r))
    db.commit()
    append_audit(db, event_type="INTEGRITY_CHECK", actor=user.username, action="FAILED" if modified else "PASSED",
                 details={"checked": len(results), "not_trusted": [f"{r['server']}.{r['tool']}" for r in modified]})
    return {"results": results, "all_trusted": not modified}


@router.post("/integrity/tools/{tool_id}/approve")
def approve_tool(tool_id: int, db: Session = Depends(get_db), user: User = Depends(require_permission("integrity:manage"))):
    tool = db.get(Tool, tool_id)
    if tool is None:
        raise HTTPException(404, "tool not found")
    old_hash = tool.approved_hash
    try:
        approve_current_definition(db, tool, user.username)
    except ValueError as exc:
        raise HTTPException(400, str(exc))
    append_audit(db, event_type="TOOL_DEFINITION_APPROVED", actor=user.username, action="APPROVED",
                 details={"tool": f"{tool.server.name}.{tool.name}", "old_hash": old_hash, "new_hash": tool.approved_hash})
    return tool_dict(tool)


@router.post("/integrity/servers/{server_name}/restore")
async def restore_server(server_name: str, db: Session = Depends(get_db),
                         user: User = Depends(require_permission("integrity:manage"))):
    """Demo helper: put the original (trusted) tool definitions back on the simulated server."""
    if server_name not in TRUSTED_CATALOG:
        raise HTTPException(404, "unknown server")
    server_registry.restore_server(server_name)
    server = db.scalar(select(McpServer).where(McpServer.name == server_name))
    results = await check_server_integrity(db, server)
    append_audit(db, event_type="SERVER_RESTORED", actor=user.username, action="RESTORED",
                 details={"server": server_name, "statuses": {r["tool"]: r["status"] for r in results}})
    return {"results": results}


# ----------------------------------------------------------------------------- M9 audit
@router.get("/audit")
def list_audit(limit: int = Query(100, le=1000), offset: int = 0, db: Session = Depends(get_db),
               _user: User = Depends(require_permission("audit:view"))):
    rows = db.scalars(select(AuditLog).order_by(AuditLog.seq.desc()).offset(offset).limit(limit))
    return {"total": audit_count(db), "records": [audit_dict(a) for a in rows], "tampered_demo_records": tampered_seqs()}


@router.post("/audit/verify")
def verify_audit(db: Session = Depends(get_db), user: User = Depends(require_permission("audit:verify"))):
    report = verify_chain(db)
    if not report["valid"]:
        db.add(SecurityEvent(event_type="AUDIT_TAMPERING_DETECTED", severity="critical", source_module="M9-Audit",
                             message=f"Audit chain verification failed at record #{report['first_invalid_seq']}",
                             details={"problems": report["problems"][:5]}))
        db.commit()
    append_audit(db, event_type="AUDIT_VERIFICATION", actor=user.username, action="PASSED" if report["valid"] else "FAILED",
                 details={"records_checked": report["total_records"], "first_invalid_seq": report["first_invalid_seq"]})
    return report


@router.post("/audit/tamper-demo")
def tamper_demo(seq: int | None = None, db: Session = Depends(get_db),
                _user: User = Depends(require_permission("audit:tamper_demo"))):
    try:
        return tamper_record_for_demo(db, seq)
    except ValueError as exc:
        raise HTTPException(400, str(exc))


@router.post("/audit/restore-demo")
def restore_demo(db: Session = Depends(get_db), _user: User = Depends(require_permission("audit:tamper_demo"))):
    return {"restored": restore_tampered_records(db), "verification": verify_chain(db)}


# ----------------------------------------------------------------------------- M7 approvals
class DecisionBody(BaseModel):
    note: str = ""


@router.get("/approvals")
def list_approvals(status: str | None = None, db: Session = Depends(get_db),
                   _user: User = Depends(require_permission("dashboard:view"))):
    query = select(Approval).order_by(Approval.created_at.desc()).limit(100)
    if status:
        query = query.where(Approval.status == status)
    return [approval_dict(a) for a in db.scalars(query)]


def _pending(db: Session, approval_id: int) -> Approval:
    approval = db.get(Approval, approval_id)
    if approval is None:
        raise HTTPException(404, "approval not found")
    if approval.status != "pending":
        raise HTTPException(409, f"approval already {approval.status}")
    return approval


@router.post("/approvals/{approval_id}/approve")
async def approve(approval_id: int, body: DecisionBody, db: Session = Depends(get_db),
                  user: User = Depends(require_permission("approvals:decide"))):
    approval = _pending(db, approval_id)
    outcome = await execute_approved(db, approval, user.username, body.note)
    return {"approval": approval_dict(approval), "outcome": outcome}


@router.post("/approvals/{approval_id}/reject")
def reject(approval_id: int, body: DecisionBody, db: Session = Depends(get_db),
           user: User = Depends(require_permission("approvals:decide"))):
    approval = _pending(db, approval_id)
    reject_approval(db, approval, user.username, body.note)
    return {"approval": approval_dict(approval)}


# ----------------------------------------------------------------------------- controller
class ModeBody(BaseModel):
    mode: str


@router.get("/controller")
def controller_state(db: Session = Depends(get_db), _user: User = Depends(require_permission("dashboard:view"))):
    return controller_service.state_dict(db)


@router.put("/controller/mode")
def set_mode(body: ModeBody, db: Session = Depends(get_db), user: User = Depends(require_permission("controller:manage"))):
    if body.mode not in SECURITY_MODES:
        raise HTTPException(400, f"mode must be one of {list(SECURITY_MODES)}")
    previous = controller_service.security_mode(db)
    controller_service.set_security_mode(db, body.mode)
    append_audit(db, event_type="SECURITY_MODE_CHANGE", actor=user.username, action="CHANGED",
                 details={"from": previous, "to": body.mode})
    return controller_service.state_dict(db)


@router.post("/controller/reset")
def reset_controller(db: Session = Depends(get_db), user: User = Depends(require_permission("controller:manage"))):
    controller_service.reset(db)
    append_audit(db, event_type="CONTROLLER_RESET", actor=user.username, action="RESET")
    return controller_service.state_dict(db)
