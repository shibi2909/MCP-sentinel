"""MCP client used by the gateway to talk to trusted servers (official SDK `mcp.Client`)."""
from typing import Any

from mcp import Client

from app.mcp_servers.demo_servers import server_registry


class UpstreamServerError(Exception):
    pass


def _client_for(server_name: str) -> Client:
    server = server_registry.get(server_name)
    if server is None:
        raise UpstreamServerError(f"MCP server '{server_name}' is not reachable")
    # cache=None: integrity checks must always see the server's *current* tool definitions.
    # mode="legacy": full MCP initialize handshake over the SDK's in-memory transport.
    return Client(server, cache=None, mode="legacy")


async def list_tool_definitions(server_name: str) -> list[dict[str, Any]]:
    """Return tool definitions exactly as advertised by the server (`tools/list`)."""
    async with _client_for(server_name) as client:
        result = await client.list_tools()
    return [tool.model_dump(mode="json", by_alias=True, exclude_none=True) for tool in result.tools]


async def call_tool(server_name: str, tool_name: str, arguments: dict[str, Any]) -> dict[str, Any]:
    """Forward a `tools/call` request and return the MCP result as a JSON-serialisable dict."""
    async with _client_for(server_name) as client:
        result = await client.call_tool(tool_name, arguments)
    return result.model_dump(mode="json", by_alias=True, exclude_none=True)


def result_text(result: dict[str, Any]) -> str:
    """Concatenate the text content blocks of a CallToolResult (used for output monitoring)."""
    parts = [block.get("text", "") for block in result.get("content", []) if block.get("type") == "text"]
    return "\n".join(parts)
