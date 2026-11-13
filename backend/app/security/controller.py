"""Control-theoretic feedback controller (the core academic contribution).

A deliberately simple, bounded and explainable discrete-time PI controller. One controller step
happens per gateway request (event-driven, dt = 1 step).

    observation        r_k  = risk of request k in [0, 1]
                             (1.0 for critical/integrity violations; >= 0.7 if output anomaly)
    state estimate     x_k  = alpha * r_k + (1 - alpha) * x_{k-1}        (first-order low-pass observer)
    error              e_k  = x_k - setpoint                              (positive = riskier than desired)
    integral           I_k  = clamp(I_{k-1} + e_k, I_min, I_max)          (+ conditional-integration anti-windup)
    control signal     u_k  = clamp(Kp * e_k + Ki * I_k, u_min, u_max)
    thresholds         T_i  = clamp(T_i_base - gain_i * u_k, T_i_min, T_i_max)

u > 0 tightens security (lower thresholds); u < 0 relaxes it slightly, but never below the bounded
minimum. Because every quantity is clamped, the controller is BIBO-stable by construction: the
thresholds can never leave their configured ranges, whatever the input sequence.

Enforcement mode is derived from u: NORMAL (u < 0.15), ELEVATED (0.15 <= u < 0.45), LOCKDOWN (u >= 0.45).
"""
from dataclasses import asdict, dataclass, field


@dataclass(frozen=True)
class ControllerConfig:
    alpha: float = 0.3          # observer gain (how fast the estimate follows new observations)
    setpoint: float = 0.18      # acceptable average risk (measured benign baseline is ~0.15)
    kp: float = 1.5             # proportional gain
    ki: float = 0.12            # integral gain
    integral_min: float = -0.5  # anti-windup bounds; a small negative bound stops calm periods from
    integral_max: float = 3.0   # "banking" relaxation that would delay the reaction to a new attack
    u_min: float = -0.25        # maximum relaxation
    u_max: float = 1.0          # maximum tightening
    # (base, gain, min, max) for each threshold
    monitor: tuple[float, float, float, float] = (30.0, 15.0, 15.0, 35.0)
    approval: tuple[float, float, float, float] = (55.0, 15.0, 40.0, 60.0)
    block: tuple[float, float, float, float] = (85.0, 13.0, 72.0, 88.0)


STATIC_THRESHOLDS = {"monitor": 30.0, "approval": 55.0, "block": 85.0}


def clamp(value: float, low: float, high: float) -> float:
    return max(low, min(high, value))


@dataclass
class ControllerSnapshot:
    estimated_risk: float = 0.0
    integral: float = 0.0
    error: float = 0.0
    control_signal: float = 0.0
    thresholds: dict = field(default_factory=lambda: dict(STATIC_THRESHOLDS))
    enforcement_mode: str = "NORMAL"
    step: int = 0


def enforcement_mode_for(u: float) -> str:
    if u >= 0.45:
        return "LOCKDOWN"
    if u >= 0.15:
        return "ELEVATED"
    return "NORMAL"


def thresholds_for(u: float, config: ControllerConfig) -> dict:
    result = {}
    for name in ("monitor", "approval", "block"):
        base, gain, low, high = getattr(config, name)
        result[name] = round(clamp(base - gain * u, low, high), 2)
    return result


class PIController:
    """Pure (side-effect free) controller; persistence is handled by controller_service."""

    def __init__(self, config: ControllerConfig | None = None, snapshot: ControllerSnapshot | None = None):
        self.config = config or ControllerConfig()
        self.state = snapshot or ControllerSnapshot(thresholds=thresholds_for(0.0, self.config))

    def step(self, observed_risk: float) -> ControllerSnapshot:
        cfg, prev = self.config, self.state
        r = clamp(observed_risk, 0.0, 1.0)

        estimate = cfg.alpha * r + (1 - cfg.alpha) * prev.estimated_risk
        error = estimate - cfg.setpoint

        # Anti-windup (conditional integration): do not keep integrating in the direction in
        # which the actuator is already saturated; then hard-clamp the integral as a second guard.
        saturated_high = prev.control_signal >= cfg.u_max and error > 0
        saturated_low = prev.control_signal <= cfg.u_min and error < 0
        integral = prev.integral if (saturated_high or saturated_low) else prev.integral + error
        integral = clamp(integral, cfg.integral_min, cfg.integral_max)

        u = clamp(cfg.kp * error + cfg.ki * integral, cfg.u_min, cfg.u_max)

        self.state = ControllerSnapshot(
            estimated_risk=round(estimate, 4),
            integral=round(integral, 4),
            error=round(error, 4),
            control_signal=round(u, 4),
            thresholds=thresholds_for(u, cfg),
            enforcement_mode=enforcement_mode_for(u),
            step=prev.step + 1,
        )
        return self.state

    def snapshot(self) -> dict:
        return asdict(self.state)
