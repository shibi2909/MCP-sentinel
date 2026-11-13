"""Database initialisation and demo data.

Demo credentials (for local demonstration only - change them for any real deployment):

  Dashboard users            Agent API keys (MCP clients)
  admin   / Admin@123        research-assistant  sk-sentinel-research-7f3a9c2e   trust high
  analyst / Analyst@123      analytics-agent     sk-sentinel-analytics-2b8e41d0  trust medium
  viewer  / Viewer@123       intern-agent        sk-sentinel-intern-91d0c6aa     trust low
                             revoked-agent       sk-sentinel-revoked-00000000    (revoked)
"""
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.database import Base, SessionLocal, engine
from app.mcp_servers.client import list_tool_definitions
from app.mcp_servers.demo_servers import TRUSTED_CATALOG, server_registry
from app.models import Agent, McpServer, Tool, User
from app.security import controller_service
from app.security.audit import append_audit, clear_tamper_backup
from app.security.auth import hash_api_key, hash_password
from app.security.integrity import canonical_tool_definition, compute_tool_hash

DEMO_USERS = [("admin", "Admin@123", "admin"), ("analyst", "Analyst@123", "analyst"), ("viewer", "Viewer@123", "viewer")]

DEMO_AGENTS = [
    {"name": "research-assistant", "api_key": "sk-sentinel-research-7f3a9c2e", "trust_level": "high",
     "allowed_tools": ["utility-server.calculator", "utility-server.get_weather", "filesystem-server.*", "crm-server.lookup_customer"],
     "description": "Trusted research agent with read-only tools", "is_active": True},
    {"name": "analytics-agent", "api_key": "sk-sentinel-analytics-2b8e41d0", "trust_level": "medium",
     "allowed_tools": ["crm-server.*", "utility-server.fetch_note", "utility-server.calculator"],
     "description": "Business analytics agent with CRM access", "is_active": True},
    {"name": "intern-agent", "api_key": "sk-sentinel-intern-91d0c6aa", "trust_level": "low",
     "allowed_tools": ["filesystem-server.*", "utility-server.calculator", "crm-server.lookup_customer"],
     "description": "Low-trust experimental agent", "is_active": True},
    {"name": "revoked-agent", "api_key": "sk-sentinel-revoked-00000000", "trust_level": "low",
     "allowed_tools": ["utility-server.*"], "description": "Agent whose credentials were revoked", "is_active": False},
]

DEMO_API_KEYS = {agent["name"]: agent["api_key"] for agent in DEMO_AGENTS}


async def seed(db: Session) -> None:
    for username, password, role in DEMO_USERS:
        db.add(User(username=username, password_hash=hash_password(password), role=role))
    for spec in DEMO_AGENTS:
        db.add(Agent(name=spec["name"], api_key_hash=hash_api_key(spec["api_key"]),
                     api_key_prefix=spec["api_key"][:14] + "...", trust_level=spec["trust_level"],
                     allowed_tools=spec["allowed_tools"], is_active=spec["is_active"], description=spec["description"]))
    # Trusted registry: approved hashes are taken from the servers' own tools/list responses
    # at installation time (trust-on-first-use by the administrator).
    for server_name, info in TRUSTED_CATALOG.items():
        server = McpServer(name=server_name, description=info["description"])
        definitions = {d["name"]: d for d in await list_tool_definitions(server_name)}
        for tool_name, sensitivity in info["tools"].items():
            definition = canonical_tool_definition(definitions[tool_name])
            server.tools.append(Tool(name=tool_name, sensitivity=sensitivity, approved_definition=definition,
                                     approved_hash=compute_tool_hash(definition), current_hash=compute_tool_hash(definition),
                                     current_definition=definition, integrity_status="trusted"))
        db.add(server)
    db.commit()
    controller_service.reset(db)
    append_audit(db, event_type="SYSTEM_INIT", actor="system", action="INIT",
                 details={"message": "MCP-Sentinel initialised with trusted registry",
                          "servers": list(TRUSTED_CATALOG)})


async def init_database(reset: bool = False) -> None:
    if reset:
        Base.metadata.drop_all(bind=engine)
        server_registry.restore_all()
        clear_tamper_backup()
    Base.metadata.create_all(bind=engine)
    with SessionLocal() as db:
        if db.scalar(select(User).limit(1)) is None:
            await seed(db)
