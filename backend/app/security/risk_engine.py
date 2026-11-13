"""M6 - Risk Engine.

Produces two clearly separated scores:

* rule_score  - deterministic, explainable weighted sum of risk factors (always available).
* ml_score    - probability (x100) from a scikit-learn Logistic Regression model trained on a
                SYNTHETIC dataset (see app/ml/train.py). It is NOT trained on real attack data.

The final risk score depends on the security mode:
  A_STATIC      -> rule_score only
  B_ML / C_CONTROLLER -> 0.6 * rule_score + 0.4 * ml_score
"""
from dataclasses import asdict, dataclass

from app.config import MAX_PAYLOAD_BYTES

SENSITIVITY_LEVEL = {"low": 0, "medium": 1, "high": 2}
TRUST_LEVEL = {"high": 0, "medium": 1, "low": 2}  # higher number = less trusted

# Tool arguments that indicate bulk access when they exceed a threshold
BULK_ARGUMENT_LIMITS = {("crm-server", "export_customer_data"): ("limit", 100)}

RULE_WEIGHT, ML_WEIGHT = 0.6, 0.4


@dataclass
class RiskFeatures:
    sensitivity: int  # 0 low, 1 medium, 2 high
    critical_findings: int
    high_findings: int
    medium_findings: int
    payload_ratio: float  # payload bytes / max payload bytes
    bulk_request: int  # 0/1
    agent_block_ratio: float  # share of this agent's recent requests that were blocked
    request_rate: int  # requests by this agent in the last 60 seconds
    agent_distrust: int  # 0 high trust, 1 medium, 2 low
    recent_output_anomalies: int  # output anomalies in this agent's recent requests

    def vector(self) -> list[float]:
        """Feature vector used by the ML model (order matters, keep in sync with train.py)."""
        return [
            float(self.sensitivity), float(min(self.critical_findings, 3)), float(min(self.high_findings, 3)),
            float(min(self.medium_findings, 3)), float(min(self.payload_ratio, 2.0)), float(self.bulk_request),
            float(self.agent_block_ratio), float(min(self.request_rate, 60)) / 60.0, float(self.agent_distrust),
            float(min(self.recent_output_anomalies, 5)),
        ]


FEATURE_NAMES = [
    "sensitivity", "critical_findings", "high_findings", "medium_findings", "payload_ratio",
    "bulk_request", "agent_block_ratio", "request_rate_norm", "agent_distrust", "recent_output_anomalies",
]


def is_bulk_request(server_name: str, tool_name: str, arguments: dict) -> bool:
    rule = BULK_ARGUMENT_LIMITS.get((server_name, tool_name))
    if not rule:
        return False
    argument, limit = rule
    value = arguments.get(argument)
    return isinstance(value, (int, float)) and value > limit


def build_features(*, sensitivity: str, validation_report, payload_bytes: int, bulk: bool,
                   agent_block_ratio: float, request_rate: int, trust_level: str,
                   recent_output_anomalies: int) -> RiskFeatures:
    return RiskFeatures(
        sensitivity=SENSITIVITY_LEVEL.get(sensitivity, 1),
        critical_findings=validation_report.count("critical"),
        high_findings=validation_report.count("high"),
        medium_findings=validation_report.count("medium"),
        payload_ratio=payload_bytes / MAX_PAYLOAD_BYTES,
        bulk_request=int(bulk),
        agent_block_ratio=agent_block_ratio,
        request_rate=request_rate,
        agent_distrust=TRUST_LEVEL.get(trust_level, 2),
        recent_output_anomalies=recent_output_anomalies,
    )


def rule_based_score(features: RiskFeatures) -> tuple[float, list[dict]]:
    """Explainable weighted scoring. Returns (score 0-100, list of contributing factors)."""
    factors: list[dict] = []

    def add(name: str, points: float, explanation: str) -> None:
        if points > 0:
            factors.append({"factor": name, "points": round(points, 1), "explanation": explanation})

    add("tool_sensitivity", [5, 15, 30][features.sensitivity],
        f"tool sensitivity is {['low', 'medium', 'high'][features.sensitivity]}")
    add("critical_input_findings", min(features.critical_findings * 40, 80),
        f"{features.critical_findings} critical input violation(s)")
    add("high_input_findings", min(features.high_findings * 25, 50),
        f"{features.high_findings} high-severity input finding(s)")
    add("medium_input_findings", min(features.medium_findings * 10, 20),
        f"{features.medium_findings} medium-severity input finding(s)")
    if features.payload_ratio > 0.5:
        add("large_payload", 10, f"payload uses {features.payload_ratio:.0%} of the size limit")
    add("bulk_data_access", 25 if features.bulk_request else 0, "bulk data access requested")
    add("agent_block_history", 30 * features.agent_block_ratio,
        f"{features.agent_block_ratio:.0%} of this agent's recent requests were blocked")
    if features.request_rate > 30:
        add("request_rate", 20, f"{features.request_rate} requests in the last minute (> 30)")
    elif features.request_rate > 10:
        add("request_rate", 10, f"{features.request_rate} requests in the last minute (> 10)")
    add("agent_trust", [0, 5, 15][features.agent_distrust],
        f"agent trust level is {['high', 'medium', 'low'][features.agent_distrust]}")
    add("output_anomaly_history", min(features.recent_output_anomalies * 5, 15),
        f"{features.recent_output_anomalies} recent output anomalies for this agent")

    score = min(100.0, sum(f["points"] for f in factors))
    return round(score, 1), factors


@dataclass
class RiskAssessment:
    rule_score: float
    ml_score: float | None
    final_score: float
    factors: list[dict]
    features: dict
    method: str

    def explanation(self) -> list[str]:
        lines = [f"{f['factor']}: +{f['points']} ({f['explanation']})" for f in self.factors]
        lines.append(f"rule-based score = {self.rule_score}")
        if self.ml_score is not None:
            lines.append(f"ML probability score (synthetic-data model) = {self.ml_score}")
        lines.append(f"final score ({self.method}) = {self.final_score}")
        return lines


def assess(features: RiskFeatures, security_mode: str, ml_model=None) -> RiskAssessment:
    rule_score, factors = rule_based_score(features)
    ml_score = None
    if security_mode != "A_STATIC" and ml_model is not None:
        ml_score = round(ml_model.predict_score(features.vector()), 1)
    if ml_score is None:
        final, method = rule_score, "rule-based only"
    else:
        final = round(RULE_WEIGHT * rule_score + ML_WEIGHT * ml_score, 1)
        method = f"{RULE_WEIGHT} x rule + {ML_WEIGHT} x ML"
    return RiskAssessment(rule_score, ml_score, final, factors, asdict(features), method)
