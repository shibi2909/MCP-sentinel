"""Database tables. See docs/DATABASE_SCHEMA.md for the ER description."""
from datetime import datetime, timezone

from sqlalchemy import JSON, Boolean, DateTime, Float, ForeignKey, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.database import Base


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


class User(Base):
    """Dashboard user (JWT authentication, RBAC role)."""
    __tablename__ = "users"
    id: Mapped[int] = mapped_column(primary_key=True)
    username: Mapped[str] = mapped_column(String(64), unique=True, index=True)
    password_hash: Mapped[str] = mapped_column(String(256))
    role: Mapped[str] = mapped_column(String(16))  # admin | analyst | viewer
    is_active: Mapped[bool] = mapped_column(Boolean, default=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class Agent(Base):
    """An AI agent / MCP client that calls tools through the gateway with an API key."""
    __tablename__ = "agents"
    id: Mapped[int] = mapped_column(primary_key=True)
    name: Mapped[str] = mapped_column(String(64), unique=True, index=True)
    api_key_hash: Mapped[str] = mapped_column(String(64), unique=True, index=True)  # SHA-256, never plaintext
    api_key_prefix: Mapped[str] = mapped_column(String(24))  # shown in UI to identify a key
    trust_level: Mapped[str] = mapped_column(String(8))  # high | medium | low
    allowed_tools: Mapped[list] = mapped_column(JSON, default=list)  # e.g. ["utility-server.*"]
    is_active: Mapped[bool] = mapped_column(Boolean, default=True)
    description: Mapped[str] = mapped_column(String(256), default="")


class McpServer(Base):
    """A trusted MCP server in the registry (M3)."""
    __tablename__ = "mcp_servers"
    id: Mapped[int] = mapped_column(primary_key=True)
    name: Mapped[str] = mapped_column(String(64), unique=True, index=True)
    description: Mapped[str] = mapped_column(String(256))
    transport: Mapped[str] = mapped_column(String(32), default="in-process")
    is_trusted: Mapped[bool] = mapped_column(Boolean, default=True)
    tools: Mapped[list["Tool"]] = relationship(back_populates="server", cascade="all, delete-orphan")


class Tool(Base):
    """A tool approved for use, with its approved SHA-256 definition hash (M3)."""
    __tablename__ = "tools"
    id: Mapped[int] = mapped_column(primary_key=True)
    server_id: Mapped[int] = mapped_column(ForeignKey("mcp_servers.id"))
    name: Mapped[str] = mapped_column(String(64))
    sensitivity: Mapped[str] = mapped_column(String(8))  # low | medium | high
    approved_definition: Mapped[dict] = mapped_column(JSON)
    approved_hash: Mapped[str] = mapped_column(String(64))
    current_hash: Mapped[str | None] = mapped_column(String(64), nullable=True)
    current_definition: Mapped[dict | None] = mapped_column(JSON, nullable=True)
    integrity_status: Mapped[str] = mapped_column(String(16), default="trusted")  # trusted|modified|missing
    last_checked: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    approved_by: Mapped[str] = mapped_column(String(64), default="system-seed")
    approved_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    server: Mapped[McpServer] = relationship(back_populates="tools")


class GatewayRequest(Base):
    """Every tool request seen by the gateway together with its security decision."""
    __tablename__ = "gateway_requests"
    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, index=True)
    source: Mapped[str] = mapped_column(String(16), default="api")  # api | demo | playground
    agent_name: Mapped[str] = mapped_column(String(64))
    server_name: Mapped[str] = mapped_column(String(64))
    tool_name: Mapped[str] = mapped_column(String(64))
    arguments: Mapped[dict] = mapped_column(JSON, default=dict)
    rule_score: Mapped[float] = mapped_column(Float, default=0)
    ml_score: Mapped[float | None] = mapped_column(Float, nullable=True)
    risk_score: Mapped[float] = mapped_column(Float, default=0)
    action: Mapped[str] = mapped_column(String(20), index=True)  # ALLOW|MONITOR|REQUIRE_APPROVAL|BLOCK
    status: Mapped[str] = mapped_column(String(24))  # executed|blocked|pending_approval|rejected|error
    violation: Mapped[str | None] = mapped_column(String(48), nullable=True)
    reasons: Mapped[list] = mapped_column(JSON, default=list)
    risk_factors: Mapped[list] = mapped_column(JSON, default=list)
    validation_findings: Mapped[list] = mapped_column(JSON, default=list)
    output_findings: Mapped[list] = mapped_column(JSON, default=list)
    thresholds: Mapped[dict] = mapped_column(JSON, default=dict)
    security_mode: Mapped[str] = mapped_column(String(16))
    controller_mode: Mapped[str] = mapped_column(String(16), default="NORMAL")
    response_preview: Mapped[str] = mapped_column(Text, default="")
    latency_ms: Mapped[float] = mapped_column(Float, default=0)


class SecurityEvent(Base):
    """Notable security observations (blocked attacks, anomalies, integrity changes...)."""
    __tablename__ = "security_events"
    id: Mapped[int] = mapped_column(primary_key=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, index=True)
    request_id: Mapped[str | None] = mapped_column(String(36), nullable=True)
    event_type: Mapped[str] = mapped_column(String(48))
    severity: Mapped[str] = mapped_column(String(12))  # info | low | medium | high | critical
    source_module: Mapped[str] = mapped_column(String(32))
    message: Mapped[str] = mapped_column(String(512))
    details: Mapped[dict] = mapped_column(JSON, default=dict)


class Approval(Base):
    """Human-in-the-loop approval queue for REQUIRE_APPROVAL decisions (M7)."""
    __tablename__ = "approvals"
    id: Mapped[int] = mapped_column(primary_key=True)
    request_id: Mapped[str] = mapped_column(ForeignKey("gateway_requests.id"))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    agent_name: Mapped[str] = mapped_column(String(64))
    server_name: Mapped[str] = mapped_column(String(64))
    tool_name: Mapped[str] = mapped_column(String(64))
    arguments: Mapped[dict] = mapped_column(JSON, default=dict)
    risk_score: Mapped[float] = mapped_column(Float)
    reasons: Mapped[list] = mapped_column(JSON, default=list)
    status: Mapped[str] = mapped_column(String(12), default="pending")  # pending | approved | rejected
    decided_by: Mapped[str | None] = mapped_column(String(64), nullable=True)
    decided_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    decision_note: Mapped[str] = mapped_column(String(256), default="")
    result_preview: Mapped[str] = mapped_column(Text, default="")


class AuditLog(Base):
    """Tamper-evident audit record. record_hash = SHA-256(canonical record incl. prev_hash) (M9)."""
    __tablename__ = "audit_logs"
    seq: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=False)
    timestamp: Mapped[str] = mapped_column(String(40))  # ISO-8601 string, hashed verbatim
    request_id: Mapped[str | None] = mapped_column(String(36), nullable=True, index=True)
    event_type: Mapped[str] = mapped_column(String(48))
    actor: Mapped[str] = mapped_column(String(64))
    action: Mapped[str] = mapped_column(String(24))
    risk_score: Mapped[float | None] = mapped_column(Float, nullable=True)
    details: Mapped[dict] = mapped_column(JSON, default=dict)
    prev_hash: Mapped[str] = mapped_column(String(64))
    record_hash: Mapped[str] = mapped_column(String(64))


class ControllerState(Base):
    """Single-row persisted state of the PI feedback controller."""
    __tablename__ = "controller_state"
    id: Mapped[int] = mapped_column(primary_key=True)
    estimated_risk: Mapped[float] = mapped_column(Float, default=0.0)
    integral: Mapped[float] = mapped_column(Float, default=0.0)
    last_error: Mapped[float] = mapped_column(Float, default=0.0)
    control_signal: Mapped[float] = mapped_column(Float, default=0.0)
    monitor_threshold: Mapped[float] = mapped_column(Float)
    approval_threshold: Mapped[float] = mapped_column(Float)
    block_threshold: Mapped[float] = mapped_column(Float)
    enforcement_mode: Mapped[str] = mapped_column(String(16), default="NORMAL")
    security_mode: Mapped[str] = mapped_column(String(16))
    step: Mapped[int] = mapped_column(Integer, default=0)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class ControllerHistory(Base):
    """One row per controller update, used for the controller chart."""
    __tablename__ = "controller_history"
    id: Mapped[int] = mapped_column(primary_key=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    step: Mapped[int] = mapped_column(Integer)
    request_id: Mapped[str | None] = mapped_column(String(36), nullable=True)
    observed_risk: Mapped[float] = mapped_column(Float)
    estimated_risk: Mapped[float] = mapped_column(Float)
    error: Mapped[float] = mapped_column(Float)
    integral: Mapped[float] = mapped_column(Float)
    control_signal: Mapped[float] = mapped_column(Float)
    monitor_threshold: Mapped[float] = mapped_column(Float)
    approval_threshold: Mapped[float] = mapped_column(Float)
    block_threshold: Mapped[float] = mapped_column(Float)
    enforcement_mode: Mapped[str] = mapped_column(String(16))


class SandboxRun(Base):
    """Result of a controlled sandbox scenario (M5)."""
    __tablename__ = "sandbox_runs"
    id: Mapped[int] = mapped_column(primary_key=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    scenario: Mapped[str] = mapped_column(String(48))
    outcome: Mapped[str] = mapped_column(String(16))  # completed | blocked | timeout | error
    expected_outcome: Mapped[str] = mapped_column(String(16))
    duration_ms: Mapped[float] = mapped_column(Float)
    output: Mapped[str] = mapped_column(Text, default="")
    blocked_operation: Mapped[str | None] = mapped_column(String(128), nullable=True)
    run_by: Mapped[str] = mapped_column(String(64))


class ExperimentRun(Base):
    """Stored output of the A/B/C configuration comparison."""
    __tablename__ = "experiment_runs"
    id: Mapped[int] = mapped_column(primary_key=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    seed: Mapped[int] = mapped_column(Integer)
    results: Mapped[dict] = mapped_column(JSON)
    run_by: Mapped[str] = mapped_column(String(64))
