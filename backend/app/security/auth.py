"""M2 - Identity and Access Management.

* Agents (MCP clients) authenticate with API keys. Only the SHA-256 hash of a key is stored.
  API keys are long random strings, so a fast hash is appropriate (no dictionary attack possible).
* Dashboard users authenticate with username/password and receive a signed JWT.
  Passwords are hashed with PBKDF2-HMAC-SHA256 (Python standard library, 600k iterations, salted).
* Role-based access control: every protected endpoint declares the permission it needs.
"""
import fnmatch
import hashlib
import hmac
import os
import secrets
from datetime import datetime, timedelta, timezone

import jwt
from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.config import JWT_ALGORITHM, JWT_EXPIRE_MINUTES, JWT_SECRET
from app.database import get_db
from app.models import Agent, User

PBKDF2_ITERATIONS = int(os.getenv("MCP_SENTINEL_PBKDF2_ITERATIONS", "600000"))  # tests lower this for speed

# RBAC matrix: role -> set of permissions
ROLE_PERMISSIONS: dict[str, set[str]] = {
    "viewer": {"dashboard:view", "audit:view"},
    "analyst": {
        "dashboard:view", "audit:view", "audit:verify", "approvals:decide", "demo:run",
        "sandbox:run", "experiments:run", "gateway:test", "integrity:check",
    },
    "admin": {
        "dashboard:view", "audit:view", "audit:verify", "approvals:decide", "demo:run",
        "sandbox:run", "experiments:run", "gateway:test", "integrity:check",
        "integrity:manage", "audit:tamper_demo", "controller:manage", "system:reset",
    },
}


# ------------------------------------------------------------------ passwords
def hash_password(password: str) -> str:
    salt = secrets.token_hex(16)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode(), bytes.fromhex(salt), PBKDF2_ITERATIONS)
    return f"pbkdf2_sha256${PBKDF2_ITERATIONS}${salt}${digest.hex()}"


def verify_password(password: str, stored_hash: str) -> bool:
    try:
        _algorithm, iterations, salt, expected = stored_hash.split("$")
        digest = hashlib.pbkdf2_hmac("sha256", password.encode(), bytes.fromhex(salt), int(iterations))
    except (ValueError, TypeError):
        return False
    return hmac.compare_digest(digest.hex(), expected)  # constant-time comparison


# ------------------------------------------------------------------ API keys
def hash_api_key(api_key: str) -> str:
    return hashlib.sha256(api_key.encode()).hexdigest()


def authenticate_agent(db: Session, api_key: str | None) -> tuple[Agent | None, str | None]:
    """Return (agent, failure_reason). Inactive (revoked) agents are rejected."""
    if not api_key:
        return None, "missing API key"
    agent = db.scalar(select(Agent).where(Agent.api_key_hash == hash_api_key(api_key)))
    if agent is None:
        return None, "unknown API key"
    if not agent.is_active:
        return agent, "agent credentials have been revoked"
    return agent, None


def agent_can_use_tool(agent: Agent, server_name: str, tool_name: str) -> bool:
    """Least privilege: the agent's scope list must explicitly match 'server.tool' (wildcards allowed)."""
    qualified = f"{server_name}.{tool_name}"
    return any(fnmatch.fnmatchcase(qualified, pattern) for pattern in agent.allowed_tools)


# ------------------------------------------------------------------ JWT for dashboard users
def create_access_token(user: User) -> str:
    now = datetime.now(timezone.utc)
    payload = {
        "sub": user.username,
        "role": user.role,
        "iat": now,
        "exp": now + timedelta(minutes=JWT_EXPIRE_MINUTES),
    }
    return jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALGORITHM)


_bearer = HTTPBearer(auto_error=False)


def get_current_user(
    credentials: HTTPAuthorizationCredentials | None = Depends(_bearer),
    db: Session = Depends(get_db),
) -> User:
    if credentials is None:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Not authenticated")
    try:
        # algorithms is pinned explicitly to prevent 'alg=none' / algorithm-confusion attacks.
        payload = jwt.decode(credentials.credentials, JWT_SECRET, algorithms=[JWT_ALGORITHM])
    except jwt.ExpiredSignatureError:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Token expired")
    except jwt.InvalidTokenError:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Invalid token")
    user = db.scalar(select(User).where(User.username == payload.get("sub")))
    if user is None or not user.is_active:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "User not found or disabled")
    return user


def has_permission(user: User, permission: str) -> bool:
    return permission in ROLE_PERMISSIONS.get(user.role, set())


def require_permission(permission: str):
    """FastAPI dependency factory: `Depends(require_permission("audit:verify"))`."""
    def dependency(user: User = Depends(get_current_user)) -> User:
        if not has_permission(user, permission):
            raise HTTPException(status.HTTP_403_FORBIDDEN, f"Role '{user.role}' lacks permission '{permission}'")
        return user
    return dependency
