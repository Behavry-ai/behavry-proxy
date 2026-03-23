"""
HTTP MCP backend.

Forwards MCP JSON-RPC requests to a remote MCP server over HTTP
using the Streamable HTTP transport (standard MCP protocol).
"""
from __future__ import annotations

import logging
from typing import Any

import httpx

from behavry_proxy.proxy.mcp import JsonRpcRequest, JsonRpcResponse, JsonRpcError

logger = logging.getLogger(__name__)

# JSON-RPC error codes (MCP spec)
JSONRPC_INTERNAL_ERROR = -32603
JSONRPC_TIMEOUT = -32001
JSONRPC_BACKEND_UNREACHABLE = -32002


class HTTPBackend:
    """
    Forwards MCP requests to a backend HTTP server.
    Maintains a persistent httpx client per backend server.
    """

    def __init__(self, server_url: str, timeout: float = 30.0) -> None:
        self.server_url = server_url.rstrip("/")
        self.timeout = timeout
        self._client: httpx.AsyncClient | None = None

    async def _get_client(self) -> httpx.AsyncClient:
        if self._client is None or self._client.is_closed:
            self._client = httpx.AsyncClient(
                timeout=self.timeout,
                headers={"Content-Type": "application/json", "Accept": "application/json"},
            )
        return self._client

    async def close(self) -> None:
        if self._client and not self._client.is_closed:
            await self._client.aclose()

    async def forward(
        self,
        request: JsonRpcRequest,
        extra_headers: dict[str, str] | None = None,
    ) -> JsonRpcResponse:
        """
        Forward a JSON-RPC request to the backend MCP server.
        Returns a JsonRpcResponse (error response on failure).
        """
        client = await self._get_client()
        headers = extra_headers or {}

        try:
            resp = await client.post(
                self.server_url,
                json=request.model_dump(exclude_none=True),
                headers=headers,
            )
            resp.raise_for_status()
            data = resp.json()
            return JsonRpcResponse.model_validate(data)

        except httpx.TimeoutException:
            logger.warning("Backend timeout: %s", self.server_url)
            return JsonRpcResponse(
                id=request.id,
                error=JsonRpcError(
                    code=JSONRPC_TIMEOUT,
                    message=f"Backend server timed out: {self.server_url}",
                ),
            )
        except httpx.HTTPStatusError as exc:
            logger.error("Backend HTTP %d: %s", exc.response.status_code, self.server_url)
            return JsonRpcResponse(
                id=request.id,
                error=JsonRpcError(
                    code=JSONRPC_BACKEND_UNREACHABLE,
                    message=f"Backend returned HTTP {exc.response.status_code}",
                ),
            )
        except Exception as exc:
            logger.exception("Backend error: %s", exc)
            return JsonRpcResponse(
                id=request.id,
                error=JsonRpcError(
                    code=JSONRPC_INTERNAL_ERROR,
                    message=f"Backend error: {exc}",
                ),
            )
