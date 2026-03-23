"""
MCP Protocol types and proxy schemas.

We implement a subset of the MCP JSON-RPC 2.0 spec sufficient for the proxy:
- tools/call (main enforcement point)
- tools/list (pass-through, logged)
- initialize / ping (pass-through)
"""
from __future__ import annotations

from typing import Any

from pydantic import BaseModel, Field


# ---------------------------------------------------------------------------
# JSON-RPC 2.0 envelope
# ---------------------------------------------------------------------------


class JsonRpcRequest(BaseModel):
    jsonrpc: str = "2.0"
    id: str | int | None = None
    method: str
    params: dict[str, Any] | None = None


class JsonRpcError(BaseModel):
    code: int
    message: str
    data: Any = None


class JsonRpcResponse(BaseModel):
    jsonrpc: str = "2.0"
    id: str | int | None = None
    result: Any = None
    error: JsonRpcError | None = None


# ---------------------------------------------------------------------------
# MCP tools/call
# ---------------------------------------------------------------------------


class ToolCallParams(BaseModel):
    name: str
    arguments: dict[str, Any] | None = None


# ---------------------------------------------------------------------------
# MCP Server registration
# ---------------------------------------------------------------------------


class MCPServerConfig(BaseModel):
    """Configuration for a backend MCP server."""
    id: str
    name: str
    transport: str = "http"         # http | stdio
    url: str | None = None          # for http transport
    command: list[str] | None = None  # for stdio transport
    env: dict[str, str] | None = None  # extra env vars for stdio
    description: str | None = None
    enabled: bool = True


# ---------------------------------------------------------------------------
# Proxy result
# ---------------------------------------------------------------------------


class ProxyResult(BaseModel):
    """Internal result from the proxy enforcement pipeline."""
    allowed: bool
    policy_result: str      # allow | deny | escalate
    policy_reason: str
    policy_id: str
    response: JsonRpcResponse | None = None
    latency_ms: float = 0.0
    error: str | None = None
