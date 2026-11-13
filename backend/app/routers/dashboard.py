"""M10 - aggregated data for the security dashboard (all numbers come from the database)."""
from fastapi import APIRouter, Depends, Query
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.database import get_db
from app.models import Approval, ControllerHistory, GatewayRequest, SecurityEvent, Tool, User
from app.routers.serializers import event_dict, iso
from app.security import controller_service
from app.security.audit import audit_count
from app.security.auth import require_permission

router = APIRouter(prefix="/api/dashboard", tags=["dashboard"])


@router.get("/summary")
def summary(db: Session = Depends(get_db), _user: User = Depends(require_permission("dashboard:view"))):
    counts = dict(db.execute(select(GatewayRequest.action, func.count()).group_by(GatewayRequest.action)).all())
    total = sum(counts.values())
    scores = [s for (s,) in db.execute(select(GatewayRequest.risk_score))]
    buckets = [{"range": f"{lo}-{lo + 9 if lo < 90 else 100}", "count": 0} for lo in range(0, 100, 10)]
    for score in scores:
        buckets[min(int(score // 10), 9)]["count"] += 1
    integrity = dict(db.execute(select(Tool.integrity_status, func.count()).group_by(Tool.integrity_status)).all())
    pending = db.scalar(select(func.count()).select_from(Approval).where(Approval.status == "pending")) or 0
    recent_events = db.scalars(select(SecurityEvent).order_by(SecurityEvent.created_at.desc()).limit(12))
    timeline = list(db.scalars(select(GatewayRequest).order_by(GatewayRequest.created_at.desc()).limit(40)))[::-1]
    violations = dict(db.execute(select(GatewayRequest.violation, func.count())
                                 .where(GatewayRequest.violation.is_not(None)).group_by(GatewayRequest.violation)).all())
    return {
        "totals": {
            "total": total,
            "allowed": counts.get("ALLOW", 0),
            "monitored": counts.get("MONITOR", 0),
            "approval_required": counts.get("REQUIRE_APPROVAL", 0),
            "blocked": counts.get("BLOCK", 0),
            "suspicious": counts.get("MONITOR", 0) + counts.get("REQUIRE_APPROVAL", 0),
            "average_risk": round(sum(scores) / len(scores), 1) if scores else 0,
            "pending_approvals": pending,
            "audit_records": audit_count(db),
        },
        "actions": [{"action": a, "count": counts.get(a, 0)} for a in ("ALLOW", "MONITOR", "REQUIRE_APPROVAL", "BLOCK")],
        "violations": [{"violation": k, "count": v} for k, v in violations.items()],
        "risk_distribution": buckets,
        "integrity": {"trusted": integrity.get("trusted", 0), "modified": integrity.get("modified", 0),
                      "missing": integrity.get("missing", 0)},
        "controller": controller_service.state_dict(db),
        "recent_events": [event_dict(e) for e in recent_events],
        "timeline": [{"id": r.id, "created_at": iso(r.created_at), "risk_score": r.risk_score, "action": r.action,
                      "tool": f"{r.server_name}.{r.tool_name}", "agent": r.agent_name} for r in timeline],
    }


@router.get("/events")
def events(limit: int = Query(50, le=500), db: Session = Depends(get_db),
           _user: User = Depends(require_permission("dashboard:view"))):
    return [event_dict(e) for e in db.scalars(select(SecurityEvent).order_by(SecurityEvent.created_at.desc()).limit(limit))]


@router.get("/controller-history")
def controller_history(limit: int = Query(200, le=1000), db: Session = Depends(get_db),
                       _user: User = Depends(require_permission("dashboard:view"))):
    rows = list(db.scalars(select(ControllerHistory).order_by(ControllerHistory.id.desc()).limit(limit)))[::-1]
    return [{"step": h.step, "created_at": iso(h.created_at), "observed_risk": h.observed_risk,
             "estimated_risk": h.estimated_risk, "error": h.error, "integral": h.integral,
             "control_signal": h.control_signal, "monitor": h.monitor_threshold, "approval": h.approval_threshold,
             "block": h.block_threshold, "enforcement_mode": h.enforcement_mode} for h in rows]
