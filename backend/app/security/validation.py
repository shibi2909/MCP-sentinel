"""M4 - Input Validation.

Two layers:
1. JSON-Schema validation against the *approved* tool input schema (not the server's live one,
   which might have been tampered with).
2. Pattern detectors over every string argument: path traversal, command injection,
   SQL injection, prompt injection, null bytes, encoded blobs and payload size.

Severity levels: critical findings always lead to BLOCK (see policy.py); high/medium findings
feed the risk engine.
"""
import json
import re
from dataclasses import asdict, dataclass, field
from typing import Any

from jsonschema import Draft202012Validator

from app.config import MAX_PAYLOAD_BYTES, MAX_STRING_LENGTH


@dataclass
class Finding:
    category: str
    severity: str  # low | medium | high | critical
    field: str
    detail: str


@dataclass
class ValidationReport:
    findings: list[Finding] = field(default_factory=list)
    payload_bytes: int = 0

    @property
    def critical(self) -> bool:
        return any(f.severity == "critical" for f in self.findings)

    def count(self, severity: str) -> int:
        return sum(1 for f in self.findings if f.severity == severity)

    def to_list(self) -> list[dict]:
        return [asdict(f) for f in self.findings]


# (category, severity, compiled regex, human readable description)
_PATTERNS: list[tuple[str, str, re.Pattern, str]] = [
    ("path_traversal", "critical", re.compile(r"(\.\.[/\\])|(%2e%2e)|(\.\.%2f)", re.I), "directory traversal sequence"),
    ("path_traversal", "critical", re.compile(r"(^|[\s'\"])(/etc/|/proc/|/root/|~[/\\]\.ssh|[a-z]:\\windows|[a-z]:/windows)", re.I), "access to sensitive system path"),
    ("command_injection", "critical", re.compile(r"[;&|]\s*(rm|cat|curl|wget|nc|bash|sh|powershell|cmd|del|certutil|python)\b", re.I), "shell command chaining"),
    ("command_injection", "critical", re.compile(r"(\$\(|`[^`]*`|\|\||&&)"), "shell substitution or chaining operator"),
    ("sql_injection", "critical", re.compile(r"('\s*(or|and)\s+'?\d*'?\s*=\s*'?\d*)|(\bunion\b\s+(all\s+)?\bselect\b)|(;\s*(drop|delete|truncate|alter|insert|update)\s)", re.I), "SQL injection pattern"),
    ("sql_injection", "high", re.compile(r"('\s*--)|(/\*.*\*/)|(\bor\b\s+1\s*=\s*1)", re.I), "SQL comment or tautology"),
    ("null_byte", "critical", re.compile(r"(\x00|%00)"), "null byte injection"),
    ("prompt_injection", "high", re.compile(r"(ignore\s+(all\s+)?(previous|prior|above)\s+instructions)|(disregard\s+your\s+(rules|instructions))|(you\s+are\s+now\s+in\s+developer\s+mode)", re.I), "prompt-injection phrase in tool input"),
    ("encoded_payload", "medium", re.compile(r"[A-Za-z0-9+/]{120,}={0,2}"), "long base64-like encoded blob"),
    ("exfiltration_url", "medium", re.compile(r"https?://[^\s]*(exfil|ngrok|pastebin|requestbin|webhook\.site)", re.I), "known data-exfiltration destination"),
]


def _iter_strings(value: Any, path: str = "$"):
    """Yield (json_path, string) for every string inside nested arguments."""
    if isinstance(value, str):
        yield path, value
    elif isinstance(value, dict):
        for key, item in value.items():
            yield from _iter_strings(str(key), f"{path}.<key>")
            yield from _iter_strings(item, f"{path}.{key}")
    elif isinstance(value, list):
        for index, item in enumerate(value):
            yield from _iter_strings(item, f"{path}[{index}]")


def detect_patterns(arguments: dict[str, Any]) -> list[Finding]:
    findings: list[Finding] = []
    for path, text in _iter_strings(arguments):
        for category, severity, pattern, description in _PATTERNS:
            if pattern.search(text):
                findings.append(Finding(category, severity, path, description))
        if len(text) > MAX_STRING_LENGTH:
            findings.append(Finding("oversized_string", "medium", path, f"string length {len(text)} > {MAX_STRING_LENGTH}"))
    return findings


def validate_schema(arguments: dict[str, Any], schema: dict[str, Any] | None) -> list[Finding]:
    if not schema:
        return []
    validator = Draft202012Validator(schema)
    findings = []
    for error in validator.iter_errors(arguments):
        location = "$" + "".join(f".{p}" for p in error.absolute_path)
        # Security decision: a request that does not match the approved contract is never forwarded.
        findings.append(Finding("schema_violation", "critical", location, error.message[:200]))
    return findings


def validate_request(arguments: dict[str, Any], schema: dict[str, Any] | None) -> ValidationReport:
    report = ValidationReport()
    if not isinstance(arguments, dict):
        report.findings.append(Finding("schema_violation", "critical", "$", "arguments must be a JSON object"))
        return report
    report.payload_bytes = len(json.dumps(arguments, ensure_ascii=False).encode("utf-8"))
    if report.payload_bytes > MAX_PAYLOAD_BYTES:
        report.findings.append(Finding("oversized_payload", "critical", "$", f"payload {report.payload_bytes} bytes > limit {MAX_PAYLOAD_BYTES}"))
    elif report.payload_bytes > MAX_PAYLOAD_BYTES // 2:
        report.findings.append(Finding("large_payload", "medium", "$", f"payload {report.payload_bytes} bytes is above 50% of the limit"))
    report.findings.extend(validate_schema(arguments, schema))
    report.findings.extend(detect_patterns(arguments))
    return report
