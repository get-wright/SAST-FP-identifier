"""MCP client for gkg server using Streamable HTTP transport.

The gkg MCP server requires:
1. Accept header: "application/json, text/event-stream"
2. Session handshake: initialize → notifications/initialized → tools/call
3. Responses are SSE-formatted: "data: {json}\n\n"
"""

from __future__ import annotations

import json
import logging
from typing import Any, Optional

import httpx

logger = logging.getLogger(__name__)

_request_id = 0


def _next_id() -> int:
    global _request_id
    _request_id += 1
    return _request_id


def _parse_sse(text: str) -> dict:
    """Extract JSON from SSE 'data: {...}' response."""
    for line in text.strip().splitlines():
        if line.startswith("data: "):
            return json.loads(line[6:])
    return json.loads(text)


class GkgMCPClient:
    """Talks to gkg server via MCP Streamable HTTP transport at /mcp."""

    MCP_HEADERS = {
        "Content-Type": "application/json",
        "Accept": "application/json, text/event-stream",
    }

    def __init__(self, base_url: str = "http://localhost:27495", timeout: int = 30):
        self.base_url = base_url
        self.timeout = timeout
        self._session_id: Optional[str] = None
        self._initialized = False

    async def _ensure_session(self, client: httpx.AsyncClient) -> None:
        """Initialize MCP session if not yet done."""
        if self._initialized:
            return

        # Step 1: initialize
        resp = await client.post(
            f"{self.base_url}/mcp",
            headers=self.MCP_HEADERS,
            json={
                "jsonrpc": "2.0",
                "id": _next_id(),
                "method": "initialize",
                "params": {
                    "protocolVersion": "2025-03-26",
                    "capabilities": {},
                    "clientInfo": {"name": "semgrep-analyzer", "version": "1.0"},
                },
            },
        )
        resp.raise_for_status()
        self._session_id = resp.headers.get("mcp-session-id")

        # Step 2: notifications/initialized
        headers = {**self.MCP_HEADERS}
        if self._session_id:
            headers["mcp-session-id"] = self._session_id

        await client.post(
            f"{self.base_url}/mcp",
            headers=headers,
            json={"jsonrpc": "2.0", "method": "notifications/initialized"},
        )
        self._initialized = True

    async def get_references(self, file: str, line: int, symbol: str) -> list[dict]:
        """Find all references to a definition."""
        return await self._call_tool("get_references", {
            "definition_name": symbol,
            "absolute_file_path": file,
        })

    async def get_definition(self, file: str, line: int, symbol: str, line_text: str = "") -> Optional[dict]:
        """Jump to definition of a symbol."""
        results = await self._call_tool("get_definition", {
            "absolute_file_path": file,
            "line": line_text,
            "symbol_name": symbol,
        })
        return results[0] if results else None

    async def read_definitions(self, definitions: list[dict]) -> list[dict]:
        """Batch-read function bodies for a list of definitions."""
        return await self._call_tool("read_definitions", {
            "definitions": definitions,
        })

    async def search_definitions(self, query: str, project_path: str = "") -> list[dict]:
        """Search for functions/classes by name."""
        params = {"search_terms": [query]}
        if project_path:
            params["project_absolute_path"] = project_path
        return await self._call_tool("search_codebase_definitions", params)

    async def repo_map(self, project_path: str) -> str:
        """Get compact repo overview."""
        result = await self._call_tool("repo_map", {
            "project_absolute_path": project_path,
            "relative_paths": ["."],
        })
        if isinstance(result, str):
            return result
        if isinstance(result, list) and result:
            return str(result[0])
        return ""

    async def index_project(self, project_path: str) -> dict:
        """Trigger re-index for a project."""
        return await self._call_tool("index_project", {
            "project_absolute_path": project_path,
        })

    async def _call_tool(self, tool_name: str, arguments: dict) -> Any:
        """Call an MCP tool via the Streamable HTTP transport.

        Protocol:
        - POST /mcp with Accept: application/json, text/event-stream
        - JSON-RPC 2.0 with method "tools/call"
        - Response is SSE: "data: {json-rpc response}\n\n"
        - Session ID must be sent after initialization
        """
        try:
            async with httpx.AsyncClient(timeout=self.timeout) as client:
                await self._ensure_session(client)

                headers = {**self.MCP_HEADERS}
                if self._session_id:
                    headers["mcp-session-id"] = self._session_id

                resp = await client.post(
                    f"{self.base_url}/mcp",
                    headers=headers,
                    json={
                        "jsonrpc": "2.0",
                        "id": _next_id(),
                        "method": "tools/call",
                        "params": {
                            "name": tool_name,
                            "arguments": arguments,
                        },
                    },
                )
                resp.raise_for_status()

                body = _parse_sse(resp.text)

                if "error" in body:
                    error_msg = body["error"]
                    logger.warning("MCP tool %s error: %s", tool_name, error_msg)
                    raise RuntimeError(f"MCP tool {tool_name} error: {error_msg}")

                result = body.get("result", {})
                content = result.get("content", [])

                # Extract text blocks from MCP content array
                texts = []
                for block in content:
                    if block.get("type") == "text":
                        text = block.get("text", "")
                        try:
                            parsed = json.loads(text)
                            if isinstance(parsed, list):
                                return parsed
                            texts.append(parsed)
                        except (json.JSONDecodeError, TypeError):
                            texts.append(text)

                return texts if texts else content

        except Exception as e:
            logger.warning("MCP call %s failed: %s", tool_name, e)
            return []
