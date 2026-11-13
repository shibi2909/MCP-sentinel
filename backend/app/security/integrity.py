"""M3 - Server and Tool Integrity.

Each approved tool definition is canonicalised (stable JSON: sorted keys, no whitespace) and
hashed with SHA-256. Before a request is forwarded the gateway fetches the server's *current*
definition via MCP `tools/list` and compares hashes. Any difference (e.g. a poisoned description
or a changed input schema) is an integrity violation and the request is blocked.
"""
import hashlib
import json
from datetime import datetime, timezone
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.mcp_servers.client import list_tool_definitions
from app.models import McpServer, Tool

# Only these fields define a tool's behaviour contract; other metadata is ignored.
HASHED_FIELDS = ("name", "description", "inputSchema", "outputSchema", "annotations")


def canonical_tool_definition(definition: dict[str, Any]) -> dict[str, Any]:
    return {key: definition[key] for key in HASHED_FIELDS if key in definition}


def canonical_json(data: Any) -> str:
    return json.dumps(data, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def compute_tool_hash(definition: dict[str, Any]) -> str:
    return hashlib.sha256(canonical_json(canonical_tool_definition(definition)).encode("utf-8")).hexdigest()


def _diff_fields(approved: dict, current: dict) -> list[str]:
    a, c = canonical_tool_definition(approved), canonical_tool_definition(current)
    return sorted(key for key in set(a) | set(c) if a.get(key) != c.get(key))


async def check_server_integrity(db: Session, server: McpServer) -> list[dict[str, Any]]:
    """Compare every registered tool of `server` with what the server currently advertises."""
    try:
        live_definitions = {d["name"]: d for d in await list_tool_definitions(server.name)}
    except Exception as exc:  # unreachable server -> every tool is 'missing'
        live_definitions = {}
        unreachable_reason = str(exc)
    else:
        unreachable_reason = None

    now = datetime.now(timezone.utc)
    results = []
    for tool in server.tools:
        live = live_definitions.get(tool.name)
        if live is None:
            tool.integrity_status, tool.current_hash, tool.current_definition = "missing", None, None
            changed: list[str] = []
        else:
            tool.current_definition = canonical_tool_definition(live)
            tool.current_hash = compute_tool_hash(live)
            changed = _diff_fields(tool.approved_definition, live)
            tool.integrity_status = "trusted" if tool.current_hash == tool.approved_hash else "modified"
        tool.last_checked = now
        results.append({
            "server": server.name,
            "tool": tool.name,
            "status": tool.integrity_status,
            "approved_hash": tool.approved_hash,
            "current_hash": tool.current_hash,
            "changed_fields": changed,
            "error": unreachable_reason,
        })
    # Tools advertised by the server that were never approved (shadow tools)
    registered = {t.name for t in server.tools}
    for name in sorted(set(live_definitions) - registered):
        results.append({"server": server.name, "tool": name, "status": "unregistered",
                        "approved_hash": None, "current_hash": compute_tool_hash(live_definitions[name]),
                        "changed_fields": [], "error": None})
    db.commit()
    return results


async def check_tool_integrity(db: Session, tool: Tool) -> dict[str, Any]:
    results = await check_server_integrity(db, tool.server)
    return next(r for r in results if r["tool"] == tool.name)


async def check_all(db: Session) -> list[dict[str, Any]]:
    results = []
    for server in db.scalars(select(McpServer).order_by(McpServer.name)):
        results.extend(await check_server_integrity(db, server))
    return results


def approve_current_definition(db: Session, tool: Tool, approver: str) -> None:
    """Human review step: accept the server's current definition as the new trusted baseline."""
    if tool.current_definition is None or tool.current_hash is None:
        raise ValueError("run an integrity check first; no current definition is known")
    tool.approved_definition = tool.current_definition
    tool.approved_hash = tool.current_hash
    tool.integrity_status = "trusted"
    tool.approved_by = approver
    tool.approved_at = datetime.now(timezone.utc)
    db.commit()
