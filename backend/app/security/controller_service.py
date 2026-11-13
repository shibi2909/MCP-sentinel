"""Persistence wrapper around the pure PIController (state lives in the database)."""
from datetime import datetime, timezone

from sqlalchemy import delete, select
from sqlalchemy.orm import Session

from app.config import DEFAULT_SECURITY_MODE, SECURITY_MODES
from app.models import ControllerHistory, ControllerState
from app.security.controller import STATIC_THRESHOLDS, ControllerConfig, ControllerSnapshot, PIController, thresholds_for

CONFIG = ControllerConfig()


def _state_row(db: Session) -> ControllerState:
    row = db.scalar(select(ControllerState).limit(1))
    if row is None:
        initial = thresholds_for(0.0, CONFIG)
        row = ControllerState(
            estimated_risk=0.0, integral=0.0, last_error=0.0, control_signal=0.0,
            monitor_threshold=initial["monitor"], approval_threshold=initial["approval"],
            block_threshold=initial["block"], enforcement_mode="NORMAL",
            security_mode=DEFAULT_SECURITY_MODE if DEFAULT_SECURITY_MODE in SECURITY_MODES else "C_CONTROLLER",
            step=0,
        )
        db.add(row)
        db.commit()
    return row


def load_controller(db: Session) -> PIController:
    row = _state_row(db)
    snapshot = ControllerSnapshot(
        estimated_risk=row.estimated_risk, integral=row.integral, error=row.last_error,
        control_signal=row.control_signal,
        thresholds={"monitor": row.monitor_threshold, "approval": row.approval_threshold, "block": row.block_threshold},
        enforcement_mode=row.enforcement_mode, step=row.step,
    )
    return PIController(CONFIG, snapshot)


def security_mode(db: Session) -> str:
    return _state_row(db).security_mode


def set_security_mode(db: Session, mode: str) -> None:
    if mode not in SECURITY_MODES:
        raise ValueError(f"unknown security mode {mode}")
    _state_row(db).security_mode = mode
    db.commit()


def effective_policy_inputs(db: Session) -> tuple[str, dict, str]:
    """Return (security_mode, thresholds used for decisions, enforcement mode used for decisions).

    Only configuration C lets the controller influence enforcement; in A and B the controller
    still observes (so its behaviour can be inspected) but static thresholds are enforced.
    """
    mode = security_mode(db)
    if mode == "C_CONTROLLER":
        controller = load_controller(db)
        return mode, dict(controller.state.thresholds), controller.state.enforcement_mode
    return mode, dict(STATIC_THRESHOLDS), "NORMAL"


def observe(db: Session, observed_risk: float, request_id: str | None) -> tuple[ControllerSnapshot, str, str]:
    """Run one controller step and persist it. Returns (snapshot, previous_mode, new_mode)."""
    controller = load_controller(db)
    previous_mode = controller.state.enforcement_mode
    snapshot = controller.step(observed_risk)
    row = _state_row(db)
    row.estimated_risk = snapshot.estimated_risk
    row.integral = snapshot.integral
    row.last_error = snapshot.error
    row.control_signal = snapshot.control_signal
    row.monitor_threshold = snapshot.thresholds["monitor"]
    row.approval_threshold = snapshot.thresholds["approval"]
    row.block_threshold = snapshot.thresholds["block"]
    row.enforcement_mode = snapshot.enforcement_mode
    row.step = snapshot.step
    row.updated_at = datetime.now(timezone.utc)
    db.add(ControllerHistory(
        step=snapshot.step, request_id=request_id, observed_risk=round(observed_risk, 4),
        estimated_risk=snapshot.estimated_risk, error=snapshot.error, integral=snapshot.integral,
        control_signal=snapshot.control_signal, monitor_threshold=snapshot.thresholds["monitor"],
        approval_threshold=snapshot.thresholds["approval"], block_threshold=snapshot.thresholds["block"],
        enforcement_mode=snapshot.enforcement_mode,
    ))
    db.commit()
    return snapshot, previous_mode, snapshot.enforcement_mode


def reset(db: Session) -> None:
    row = _state_row(db)
    initial = thresholds_for(0.0, CONFIG)
    row.estimated_risk = row.integral = row.last_error = row.control_signal = 0.0
    row.monitor_threshold, row.approval_threshold, row.block_threshold = initial["monitor"], initial["approval"], initial["block"]
    row.enforcement_mode, row.step = "NORMAL", 0
    db.execute(delete(ControllerHistory))
    db.commit()


def state_dict(db: Session) -> dict:
    row = _state_row(db)
    return {
        "security_mode": row.security_mode,
        "security_mode_description": SECURITY_MODES[row.security_mode],
        "controller_active": row.security_mode == "C_CONTROLLER",
        "estimated_risk": row.estimated_risk,
        "integral": row.integral,
        "error": row.last_error,
        "control_signal": row.control_signal,
        "enforcement_mode": row.enforcement_mode,
        "thresholds": {"monitor": row.monitor_threshold, "approval": row.approval_threshold, "block": row.block_threshold},
        "static_thresholds": STATIC_THRESHOLDS,
        "step": row.step,
        "config": {
            "alpha": CONFIG.alpha, "setpoint": CONFIG.setpoint, "kp": CONFIG.kp, "ki": CONFIG.ki,
            "integral_bounds": [CONFIG.integral_min, CONFIG.integral_max],
            "control_bounds": [CONFIG.u_min, CONFIG.u_max],
            "threshold_ranges": {"monitor": CONFIG.monitor[2:], "approval": CONFIG.approval[2:], "block": CONFIG.block[2:]},
        },
        "updated_at": row.updated_at.isoformat() if row.updated_at else None,
    }
