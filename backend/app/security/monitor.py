"""M8 - Behaviour Monitoring of tool outputs.

Tool outputs are untrusted: a compromised server or a poisoned data source can return prompt
injections or leak secrets back to the agent. Detected anomalies:
* secrets / credentials (redacted before the response leaves the gateway)
* prompt-injection instructions aimed at the agent
* exfiltration URLs, sensitive system paths, stack traces
* oversized outputs
Every anomaly escalates the decision to at least MONITOR and is fed back to the controller.
"""
import re
from dataclasses import asdict, dataclass, field

from app.config import MAX_OUTPUT_BYTES

_SECRET_PATTERNS = [
    ("aws_access_key", re.compile(r"AKIA[0-9A-Z]{16}")),
    ("private_key", re.compile(r"-----BEGIN (RSA |EC |OPENSSH )?PRIVATE KEY-----")),
    ("api_token", re.compile(r"\b(sk|ghp|xox[bp])-[A-Za-z0-9_-]{16,}")),
    ("password_assignment", re.compile(r"(password|passwd|pwd)\s*[=:]\s*\S+", re.I)),
]

_OUTPUT_PATTERNS = [
    ("prompt_injection", "high", re.compile(r"(ignore\s+(all\s+)?(previous|prior|above)\s+instructions)|(<important>)|(do not tell the user)", re.I)),
    ("exfiltration_url", "high", re.compile(r"https?://[^\s]*(exfil|ngrok|pastebin|requestbin|webhook\.site)", re.I)),
    ("sensitive_path", "medium", re.compile(r"(/etc/passwd|/etc/shadow|~/.ssh|id_rsa|\\windows\\system32)", re.I)),
    ("stack_trace", "medium", re.compile(r"Traceback \(most recent call last\)")),
]


@dataclass
class OutputReport:
    anomalies: list[dict] = field(default_factory=list)
    redacted_text: str = ""

    @property
    def has_anomaly(self) -> bool:
        return bool(self.anomalies)

    @property
    def max_severity(self) -> str | None:
        order = ["low", "medium", "high", "critical"]
        if not self.anomalies:
            return None
        return max((a["severity"] for a in self.anomalies), key=order.index)

    def to_list(self) -> list[dict]:
        return list(self.anomalies)


def scan_output(text: str) -> OutputReport:
    report = OutputReport(redacted_text=text)
    for name, pattern in _SECRET_PATTERNS:
        if pattern.search(report.redacted_text):
            report.anomalies.append({"category": "secret_leak", "severity": "high", "detail": f"{name} found in output (redacted)"})
            report.redacted_text = pattern.sub("[REDACTED-BY-SENTINEL]", report.redacted_text)
    for category, severity, pattern in _OUTPUT_PATTERNS:
        if pattern.search(text):
            report.anomalies.append({"category": category, "severity": severity, "detail": f"{category.replace('_', ' ')} detected in tool output"})
    size = len(text.encode("utf-8"))
    if size > MAX_OUTPUT_BYTES:
        report.anomalies.append({"category": "oversized_output", "severity": "medium", "detail": f"output {size} bytes > {MAX_OUTPUT_BYTES}"})
    return report


def as_dicts(report: OutputReport) -> dict:
    return asdict(report)
