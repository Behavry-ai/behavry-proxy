"""
MCP Proxy Enforcement Pipeline.

Simplified extraction from Behavry's 14-step engine. This OSS pipeline:

1. Authenticate (optional bearer token)
2. Rate limit (per-agent sliding window)
3. Pass-through non-tool-call methods
4. Extract tool call parameters
5. DLP scan on inputs
6. Build OPA input + get policy decision
7. Enforce decision (allow / deny)
8. Forward to backend MCP server
9. DLP scan on response
10. Inbound injection scan on response
11. Emit audit event

No database, no identity service, no behavioral monitor, no HITL queue.
"""
from __future__ import annotations

import logging
import time
from typing import Any

from behavry_proxy.audit.emitter import AuditEvent, get_emitter
from behavry_proxy.config import get_config
from behavry_proxy.dlp.inbound import get_inbound_scanner
from behavry_proxy.dlp.scanner import SEVERITY_ORDER, get_dlp_scanner
from behavry_proxy.policy.client import build_opa_input, get_opa_client
from behavry_proxy.proxy.mcp import (
    JsonRpcError,
    JsonRpcRequest,
    JsonRpcResponse,
    ProxyResult,
    ToolCallParams,
)
from behavry_proxy.proxy.rate_limiter import get_rate_limiter
from behavry_proxy.proxy.registry import get_backend

logger = logging.getLogger(__name__)

# JSON-RPC error codes
JSONRPC_UNAUTHORIZED = -32000
JSONRPC_FORBIDDEN = -32003
JSONRPC_RATE_LIMITED = -32005
JSONRPC_INTERNAL_ERROR = -32603

# Methods that pass through without enforcement
PASSTHROUGH_METHODS = {"initialize", "ping", "notifications/initialized"}


def _extract_tool_call(request: JsonRpcRequest) -> tuple[str, str, str, dict[str, Any]]:
    """
    Extract (tool_name, action, resource, parameters) from a tools/call request.
    """
    params = request.params or {}
    tool_name = params.get("name", "unknown")
    arguments = params.get("arguments") or {}

    # Derive action from tool name (read_file → read, write_file → write)
    if "_" in tool_name:
        parts = tool_name.split("_", 1)
        action = parts[0]
        resource_type = parts[1]
    else:
        action = tool_name
        resource_type = "unknown"

    # Derive resource from arguments
    resource = (
        arguments.get("path")
        or arguments.get("url")
        or arguments.get("query")
        or arguments.get("table")
        or arguments.get("channel")
        or arguments.get("repo")
        or arguments.get("org")
        or arguments.get("file")
        or arguments.get("command")
        or resource_type
    )

    return tool_name, action, str(resource), arguments


def _extract_response_text(backend_resp: JsonRpcResponse) -> str | None:
    """Extract text content from a tool call response for scanning."""
    if backend_resp.error or not backend_resp.result:
        return None
    result = backend_resp.result
    if isinstance(result, dict):
        content = result.get("content")
        if isinstance(content, list):
            texts = [
                str(block.get("text", ""))
                for block in content
                if isinstance(block, dict) and block.get("type") == "text"
            ]
            if texts:
                return "\n".join(texts)
    if result is not None:
        return str(result)
    return None


# Canned response for blocked inbound content
_CANNED_RESPONSE_RESULT: dict[str, Any] = {
    "content": [{"type": "text", "text": "No content available."}]
}


async def enforce(
    request: JsonRpcRequest,
    *,
    server_id: str,
    agent_id: str = "anonymous",
) -> ProxyResult:
    """
    Run the enforcement pipeline for an MCP request.

    This is the core of the proxy — every request flows through here.
    """
    t0 = time.perf_counter()
    cfg = get_config()
    emitter = get_emitter()

    # ── Step 1: Rate limiting ─────────────────────────────────────────────
    rl = get_rate_limiter().check(
        agent_id,
        rate_limit_rpm=cfg.rate_limit_rpm,
        rate_limit_burst=cfg.rate_limit_burst,
    )
    if not rl.allowed:
        emitter.emit(AuditEvent(
            timestamp=time.time(),
            event_type="rate_limit",
            agent_id=agent_id,
            server_id=server_id,
            data={"current_rpm": rl.current_rpm, "avg_rpm": rl.avg_rpm},
        ))
        return ProxyResult(
            allowed=False,
            policy_result="deny",
            policy_reason="Rate limit exceeded",
            policy_id="rate_limiter",
            response=JsonRpcResponse(
                id=request.id,
                error=JsonRpcError(code=JSONRPC_RATE_LIMITED, message="Rate limit exceeded"),
            ),
            latency_ms=(time.perf_counter() - t0) * 1000,
        )

    # ── Step 2: Pass-through for non-tool-call methods ────────────────────
    if request.method in PASSTHROUGH_METHODS or request.method == "tools/list":
        try:
            backend = await get_backend(server_id)
            resp = await backend.forward(request)
            latency = (time.perf_counter() - t0) * 1000

            emitter.emit(AuditEvent(
                timestamp=time.time(),
                event_type="passthrough",
                agent_id=agent_id,
                server_id=server_id,
                tool_name=request.method,
                latency_ms=latency,
            ))

            return ProxyResult(
                allowed=True,
                policy_result="allow",
                policy_reason="pass-through method",
                policy_id="passthrough",
                response=resp,
                latency_ms=latency,
            )
        except Exception as exc:
            return ProxyResult(
                allowed=False,
                policy_result="deny",
                policy_reason=f"Backend error: {exc}",
                policy_id="error",
                response=JsonRpcResponse(
                    id=request.id,
                    error=JsonRpcError(code=JSONRPC_INTERNAL_ERROR, message=str(exc)),
                ),
                latency_ms=(time.perf_counter() - t0) * 1000,
                error=str(exc),
            )

    # ── Step 3: Extract tool call ─────────────────────────────────────────
    if request.method != "tools/call":
        # Unknown method — forward as-is
        try:
            backend = await get_backend(server_id)
            resp = await backend.forward(request)
            return ProxyResult(
                allowed=True,
                policy_result="allow",
                policy_reason="unknown method forwarded",
                policy_id="passthrough",
                response=resp,
                latency_ms=(time.perf_counter() - t0) * 1000,
            )
        except Exception as exc:
            return ProxyResult(
                allowed=False,
                policy_result="deny",
                policy_reason=str(exc),
                policy_id="error",
                latency_ms=(time.perf_counter() - t0) * 1000,
                error=str(exc),
            )

    tool_name, action, resource, parameters = _extract_tool_call(request)

    # ── Step 4: DLP scan on inputs ────────────────────────────────────────
    dlp_findings = []
    if cfg.dlp_enabled:
        scanner = get_dlp_scanner()
        dlp_findings = scanner.scan_dict(parameters, f"{tool_name}:input")

        if dlp_findings:
            max_sev = scanner.max_severity(dlp_findings)
            block_level = SEVERITY_ORDER.get(cfg.dlp_block_severity, 3)
            finding_level = SEVERITY_ORDER.get(max_sev or "none", 0)

            emitter.emit(AuditEvent(
                timestamp=time.time(),
                event_type="dlp_finding",
                agent_id=agent_id,
                server_id=server_id,
                tool_name=tool_name,
                action=action,
                resource=resource,
                data={"findings": [f.to_dict() for f in dlp_findings], "max_severity": max_sev},
            ))

            if finding_level >= block_level:
                return ProxyResult(
                    allowed=False,
                    policy_result="deny",
                    policy_reason=f"DLP: {max_sev} severity data detected in input",
                    policy_id="dlp_input",
                    response=JsonRpcResponse(
                        id=request.id,
                        error=JsonRpcError(
                            code=JSONRPC_FORBIDDEN,
                            message=f"Request blocked: sensitive data detected ({max_sev})",
                        ),
                    ),
                    latency_ms=(time.perf_counter() - t0) * 1000,
                )

    # ── Step 5: OPA policy evaluation ─────────────────────────────────────
    opa = get_opa_client()
    opa_input = build_opa_input(
        agent_id=agent_id,
        tool_name=tool_name,
        action=action,
        resource=resource,
        parameters=parameters,
        mcp_server=server_id,
    )
    decision = await opa.decide(opa_input, policy_path=cfg.opa_policy_path)

    if decision.is_deny:
        emitter.emit(AuditEvent(
            timestamp=time.time(),
            event_type="tool_deny",
            agent_id=agent_id,
            server_id=server_id,
            tool_name=tool_name,
            action=action,
            resource=resource,
            policy_result=decision.result,
            policy_reason=decision.reason,
            policy_id=decision.policy,
        ))
        return ProxyResult(
            allowed=False,
            policy_result=decision.result,
            policy_reason=decision.reason,
            policy_id=decision.policy,
            response=JsonRpcResponse(
                id=request.id,
                error=JsonRpcError(
                    code=JSONRPC_FORBIDDEN,
                    message=f"Policy denied: {decision.reason}",
                ),
            ),
            latency_ms=(time.perf_counter() - t0) * 1000,
        )

    # ── Step 6: Forward to backend ────────────────────────────────────────
    try:
        backend = await get_backend(server_id)
        backend_resp = await backend.forward(request)
    except Exception as exc:
        logger.error("Backend forward error: %s", exc)
        return ProxyResult(
            allowed=False,
            policy_result="deny",
            policy_reason=f"Backend error: {exc}",
            policy_id="error",
            response=JsonRpcResponse(
                id=request.id,
                error=JsonRpcError(code=JSONRPC_INTERNAL_ERROR, message=f"Backend error: {exc}"),
            ),
            latency_ms=(time.perf_counter() - t0) * 1000,
            error=str(exc),
        )

    # ── Step 7: DLP scan on response ──────────────────────────────────────
    if cfg.dlp_enabled and backend_resp.result:
        resp_text = _extract_response_text(backend_resp)
        if resp_text:
            resp_findings = get_dlp_scanner().scan(resp_text, f"{tool_name}:output")
            if resp_findings:
                max_sev = get_dlp_scanner().max_severity(resp_findings)
                emitter.emit(AuditEvent(
                    timestamp=time.time(),
                    event_type="dlp_finding",
                    agent_id=agent_id,
                    server_id=server_id,
                    tool_name=tool_name,
                    data={"findings": [f.to_dict() for f in resp_findings], "direction": "output", "max_severity": max_sev},
                ))

    # ── Step 8: Inbound injection scan on response ────────────────────────
    if cfg.inbound_scan_enabled and backend_resp.result:
        resp_text = _extract_response_text(backend_resp)
        if resp_text:
            inbound_scanner = get_inbound_scanner()
            inbound_findings = inbound_scanner.scan(resp_text)

            if inbound_findings:
                max_sev = inbound_scanner.get_max_severity(inbound_findings)
                block_level = SEVERITY_ORDER.get(cfg.inbound_block_severity, 3)
                finding_level = SEVERITY_ORDER.get(max_sev or "none", 0)

                emitter.emit(AuditEvent(
                    timestamp=time.time(),
                    event_type="inbound_finding",
                    agent_id=agent_id,
                    server_id=server_id,
                    tool_name=tool_name,
                    data={"findings": [f.to_dict() for f in inbound_findings], "max_severity": max_sev},
                ))

                if finding_level >= block_level:
                    # Replace response with canned safe content
                    backend_resp = JsonRpcResponse(
                        id=request.id,
                        result=_CANNED_RESPONSE_RESULT,
                    )

    # ── Step 9: Emit success audit event ──────────────────────────────────
    latency = (time.perf_counter() - t0) * 1000
    emitter.emit(AuditEvent(
        timestamp=time.time(),
        event_type="tool_call",
        agent_id=agent_id,
        server_id=server_id,
        tool_name=tool_name,
        action=action,
        resource=resource,
        policy_result=decision.result,
        policy_reason=decision.reason,
        policy_id=decision.policy,
        latency_ms=latency,
    ))

    return ProxyResult(
        allowed=True,
        policy_result=decision.result,
        policy_reason=decision.reason,
        policy_id=decision.policy,
        response=backend_resp,
        latency_ms=latency,
    )
