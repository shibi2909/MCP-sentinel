"""M7 - Policy Enforcement.

Actions, from least to most restrictive: ALLOW < MONITOR < REQUIRE_APPROVAL < BLOCK.

Security invariants (tested in tests/test_policy.py):
1. A critical violation (auth failure, integrity violation, critical input finding) is ALWAYS
   BLOCK - no risk score, threshold or controller state can override it.
2. Policy rules and the controller's enforcement mode can only ESCALATE a decision, never relax it.
"""
from dataclasses import dataclass, field

ACTIONS = ["ALLOW", "MONITOR", "REQUIRE_APPROVAL", "BLOCK"]


def escalate(current: str, minimum: str) -> str:
    """Return the more restrictive of two actions."""
    return current if ACTIONS.index(current) >= ACTIONS.index(minimum) else minimum


@dataclass
class PolicyDecision:
    action: str
    reasons: list[str] = field(default_factory=list)
    violation: str | None = None


def decide(*, risk_score: float, thresholds: dict, critical_violation: str | None = None,
           sensitivity: str = "low", bulk_request: bool = False,
           enforcement_mode: str = "NORMAL", has_input_findings: bool = False) -> PolicyDecision:
    if critical_violation:
        return PolicyDecision("BLOCK", [f"critical violation: {critical_violation} (non-overridable)"], critical_violation)

    reasons: list[str] = []
    if risk_score >= thresholds["block"]:
        action = "BLOCK"
        reasons.append(f"risk {risk_score} >= block threshold {thresholds['block']}")
    elif risk_score >= thresholds["approval"]:
        action = "REQUIRE_APPROVAL"
        reasons.append(f"risk {risk_score} >= approval threshold {thresholds['approval']}")
    elif risk_score >= thresholds["monitor"]:
        action = "MONITOR"
        reasons.append(f"risk {risk_score} >= monitor threshold {thresholds['monitor']}")
    else:
        action = "ALLOW"
        reasons.append(f"risk {risk_score} < monitor threshold {thresholds['monitor']}")

    # Static policy rule: bulk access to a high-sensitivity tool always needs a human.
    if sensitivity == "high" and bulk_request:
        new_action = escalate(action, "REQUIRE_APPROVAL")
        if new_action != action:
            reasons.append("policy rule: bulk access to a high-sensitivity tool requires approval")
        action = new_action

    # Controller-driven rules (enforcement mode set by the PI controller):
    #   LOCKDOWN: high-sensitivity calls need approval, and "allow but watch" (MONITOR) is no longer
    #             acceptable for requests with suspicious input findings -> REQUIRE_APPROVAL.
    #   ELEVATED: every high-sensitivity call is at least monitored.
    if enforcement_mode == "LOCKDOWN" and (sensitivity == "high" or (action == "MONITOR" and has_input_findings)):
        new_action = escalate(action, "REQUIRE_APPROVAL")
        if new_action != action:
            reasons.append("controller LOCKDOWN: " + ("high-sensitivity tools require approval" if sensitivity == "high"
                                                      else "suspicious monitored requests require approval"))
        action = new_action
    elif enforcement_mode == "ELEVATED" and sensitivity == "high":
        new_action = escalate(action, "MONITOR")
        if new_action != action:
            reasons.append("controller ELEVATED: high-sensitivity tools are monitored")
        action = new_action

    return PolicyDecision(action, reasons)
