"""
FastAPI routes for the MCP proxy.

Exposes:
- POST /mcp/{server_id}  — Main proxy endpoint (Streamable HTTP)
- GET  /health            — Health check (OPA + backends)
- GET  /servers           — List registered MCP servers
- GET  /stats             — Audit event counters
"""
from __future__ import annotations

import logging
import time

from fastapi import APIRouter, Header, HTTPException, Request
from fastapi.responses import JSONResponse

from behavry_proxy.audit.emitter import get_emitter
from behavry_proxy.config import get_config
from behavry_proxy.policy.client import get_opa_client
from behavry_proxy.proxy.mcp import JsonRpcRequest, JsonRpcResponse
from behavry_proxy.proxy.pipeline import enforce
from behavry_proxy.proxy.registry import list_servers

logger = logging.getLogger(__name__)

router = APIRouter()


@router.post("/mcp/{server_id}")
async def mcp_proxy(
    server_id: str,
    request: Request,
    authorization: str | None = Header(None),
) -> JSONResponse:
    """
    Main MCP proxy endpoint.

    Accepts JSON-RPC 2.0 requests, runs them through the enforcement pipeline,
    and returns the (possibly blocked) response.
    """
    cfg = get_config()

    # Optional bearer token auth
    if cfg.auth_token:
        if not authorization or not authorization.startswith("Bearer "):
            raise HTTPException(status_code=401, detail="Missing or invalid Authorization header")
        token = authorization[7:]
        if token != cfg.auth_token:
            raise HTTPException(status_code=401, detail="Invalid token")

    # Parse JSON-RPC request
    try:
        body = await request.json()
        rpc_request = JsonRpcRequest.model_validate(body)
    except Exception as exc:
        raise HTTPException(status_code=400, detail=f"Invalid JSON-RPC request: {exc}")

    # Extract agent_id from header or default to anonymous
    agent_id = request.headers.get("x-agent-id", "anonymous")

    # Run enforcement pipeline
    result = await enforce(rpc_request, server_id=server_id, agent_id=agent_id)

    if result.response:
        return JSONResponse(
            content=result.response.model_dump(exclude_none=True),
            headers={"X-Policy-Result": result.policy_result},
        )

    # Shouldn't happen, but fallback
    return JSONResponse(
        content=JsonRpcResponse(id=rpc_request.id, result={}).model_dump(exclude_none=True),
    )


@router.get("/health")
async def health_check() -> JSONResponse:
    """Health check — reports OPA connectivity and server count."""
    opa = get_opa_client()
    opa_healthy = await opa.is_healthy()
    servers = list_servers()

    status = "healthy" if opa_healthy else "degraded"
    return JSONResponse(
        content={
            "status": status,
            "opa": "connected" if opa_healthy else "unreachable",
            "servers": len(servers),
            "timestamp": time.time(),
        },
        status_code=200 if opa_healthy else 503,
    )


@router.get("/servers")
async def get_servers() -> JSONResponse:
    """List all registered MCP servers."""
    servers = list_servers()
    return JSONResponse(
        content={
            "servers": [
                {
                    "id": s.id,
                    "name": s.name,
                    "transport": s.transport,
                    "enabled": s.enabled,
                    "description": s.description,
                }
                for s in servers
            ]
        }
    )


@router.get("/stats")
async def get_stats() -> JSONResponse:
    """Return audit event counters."""
    emitter = get_emitter()
    return JSONResponse(content=emitter.get_stats())
