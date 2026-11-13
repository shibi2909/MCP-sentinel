"""M1 - MCP gateway endpoint (JSON-RPC 2.0) plus the dashboard playground and request log.

External MCP clients/agents call:

    POST /mcp            header  X-API-Key: <agent key>
    {"jsonrpc": "2.0", "id": 1, "method": "tools/call",
     "params": {"name": "utility-server.calculator", "arguments": {"expression": "2+2"}}}

`tools/list` returns only the tools the calling agent is permitted to use.
"""
from typing import Any

from fastapi import APIRouter, Depends, Header, Query
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.database import get_db
from app.gateway import ERROR_CODES, handle_tool_call
from app.models import Agent, GatewayRequest, McpServer, Tool, User
from app.routers.serializers import request_dict
from app.security.auth import agent_can_use_tool, authenticate_agent, require_permission
from app.seed import DEMO_API_KEYS

router = APIRouter(tags=["gateway"])


def _rpc_error(request_id: Any, code: int, message: str, data: Any = None) -> JSONResponse:
    error: dict[str, Any] = {"code": code, "message": message}
    if data is not None:
        error["data"] = data
    return JSONResponse({"jsonrpc": "2.0", "id": request_id, "error": error})


def _split_name(params: dict) -> tuple[str, str]:
    """Accept either {"server": s, "name": t} or {"name": "s.t"}."""
    name = str(params.get("name", ""))
    server = params.get("server")
    if not server and "." in name:
        server, name = name.split(".", 1)
    return str(server or ""), name


def _sentinel_summary(outcome: dict) -> dict:
    keys = ("request_id", "action", "status", "violation", "risk_score", "rule_score", "ml_score",
            "reasons", "explanation", "approval_id", "enforcement_mode", "security_mode")
    return {k: outcome[k] for k in keys}


@router.post("/mcp")
async def mcp_endpoint(payload: dict, x_api_key: str | None = Header(default=None), db: Session = Depends(get_db)):
    rpc_id = payload.get("id")
    if payload.get("jsonrpc") != "2.0" or "method" not in payload:
        return _rpc_error(rpc_id, -32600, "Invalid JSON-RPC 2.0 request")
    method, params = payload["method"], payload.get("params") or {}

    if method == "tools/list":
        agent, failure = authenticate_agent(db, x_api_key)
        if failure:
            return _rpc_error(rpc_id, ERROR_CODES["AUTHENTICATION_FAILED"], f"Authentication failed: {failure}")
        tools = []
        for tool in db.scalars(select(Tool).join(McpServer).order_by(McpServer.name, Tool.name)):
            if agent_can_use_tool(agent, tool.server.name, tool.name) and tool.integrity_status == "trusted":
                definition = dict(tool.approved_definition)
                definition["name"] = f"{tool.server.name}.{tool.name}"
                tools.append(definition)
        return {"jsonrpc": "2.0", "id": rpc_id, "result": {"tools": tools}}

    if method == "tools/call":
        server_name, tool_name = _split_name(params)
        outcome = await handle_tool_call(db, api_key=x_api_key, server_name=server_name, tool_name=tool_name,
                                         arguments=params.get("arguments", {}), source="api")
        if outcome["error"]:
            return _rpc_error(rpc_id, outcome["error"]["code"], outcome["error"]["message"], {"sentinel": _sentinel_summary(outcome)})
        result = dict(outcome["result"] or {})
        result["_meta"] = {"sentinel": _sentinel_summary(outcome)}
        return {"jsonrpc": "2.0", "id": rpc_id, "result": result}

    return _rpc_error(rpc_id, -32601, f"Method '{method}' is not supported by the gateway")


class PlaygroundRequest(BaseModel):
    agent: str | None = Field(default=None, description="Name of a demo agent (uses its demo API key)")
    api_key: str | None = Field(default=None, description="Explicit API key (overrides agent)")
    server: str
    tool: str
    arguments: dict[str, Any] = Field(default_factory=dict)


@router.post("/api/gateway/test")
async def playground(body: PlaygroundRequest, db: Session = Depends(get_db),
                     _user: User = Depends(require_permission("gateway:test"))):
    api_key = body.api_key if body.api_key is not None else DEMO_API_KEYS.get(body.agent or "")
    return await handle_tool_call(db, api_key=api_key, server_name=body.server, tool_name=body.tool,
                                  arguments=body.arguments, source="playground")


@router.get("/api/requests")
def list_requests(limit: int = Query(50, le=500), action: str | None = None, db: Session = Depends(get_db),
                  _user: User = Depends(require_permission("dashboard:view"))):
    query = select(GatewayRequest).order_by(GatewayRequest.created_at.desc()).limit(limit)
    if action:
        query = query.where(GatewayRequest.action == action)
    return [request_dict(r) for r in db.scalars(query)]


@router.get("/api/agents")
def list_agents(db: Session = Depends(get_db), _user: User = Depends(require_permission("dashboard:view"))):
    return [{"name": a.name, "trust_level": a.trust_level, "allowed_tools": a.allowed_tools, "is_active": a.is_active,
             "api_key_prefix": a.api_key_prefix, "description": a.description}
            for a in db.scalars(select(Agent).order_by(Agent.name))]
