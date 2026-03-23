"""
OPA REST client for Behavry Proxy.

Sends structured policy decision requests to the OPA sidecar and returns
typed results. Implements fail-closed semantics by default.
"""
from __future__ import annotations

import asyncio
import logging
import time
from dataclasses import dataclass, field
from typing import Any

import httpx

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Decision result
# ---------------------------------------------------------------------------


@dataclass
class PolicyDecision:
    result: str  # allow | deny | escalate
    reason: str = ""
    policy: str = ""
    metadata: dict[str, Any] = field(default_factory=dict)

    @property
    def is_allow(self) -> bool:
        return self.result == "allow"

    @property
    def is_deny(self) -> bool:
        return self.result == "deny"

    @property
    def is_escalate(self) -> bool:
        return self.result == "escalate"


DENY_CLOSED = PolicyDecision(result="deny", reason="OPA unreachable — fail closed")
DENY_ERROR = PolicyDecision(result="deny", reason="Policy evaluation error")


# ---------------------------------------------------------------------------
# OPA input builder (simplified for OSS proxy)
# ---------------------------------------------------------------------------


def build_opa_input(
    *,
    agent_id: str,
    tool_name: str,
    action: str,
    resource: str,
    parameters: dict[str, Any] | None = None,
    context: dict[str, Any] | None = None,
    mcp_server: str | None = None,
) -> dict[str, Any]:
    """Build the standard OPA input envelope for policy decisions."""
    return {
        "input": {
            "agent": {
                "id": agent_id,
            },
            "request": {
                "tool_name": tool_name,
                "action": action,
                "resource": resource,
                "parameters": parameters or {},
                "mcp_server": mcp_server,
            },
            "context": context or {},
        }
    }


# ---------------------------------------------------------------------------
# OPA client
# ---------------------------------------------------------------------------


class OPAClient:
    """
    Async OPA REST client.

    Evaluates policy at a given OPA path (e.g. "behavry/authz/decision").
    Reuses a single httpx.AsyncClient for connection pooling.
    """

    def __init__(
        self,
        base_url: str = "http://localhost:8181",
        timeout: float = 5.0,
        fail_closed: bool = True,
    ) -> None:
        self._base_url = base_url.rstrip("/")
        self._timeout = timeout
        self._fail_closed = fail_closed
        self._client: httpx.AsyncClient | None = None

    async def _get_client(self) -> httpx.AsyncClient:
        if self._client is None or self._client.is_closed:
            self._client = httpx.AsyncClient(timeout=self._timeout)
        return self._client

    async def close(self) -> None:
        if self._client and not self._client.is_closed:
            await self._client.aclose()

    async def decide(
        self,
        input_envelope: dict[str, Any],
        policy_path: str = "behavry/authz/decision",
    ) -> PolicyDecision:
        """
        POST input to OPA and return a PolicyDecision.

        Implements 1 retry with 100ms backoff for transient network errors.
        On persistent failure: deny (fail_closed=True) or allow (fail_closed=False).
        """
        url = f"{self._base_url}/v1/data/{policy_path}"
        resp = None
        for attempt in range(2):
            try:
                client = await self._get_client()
                resp = await client.post(url, json=input_envelope)
                resp.raise_for_status()
                break
            except (httpx.TimeoutException, httpx.ConnectError) as exc:
                if attempt == 0:
                    logger.warning("OPA transient error (attempt 1), retrying in 100ms: %s", exc)
                    await asyncio.sleep(0.1)
                    continue
                logger.error("OPA timeout/connection error after retry at %s: %s", url, exc)
                return DENY_CLOSED if self._fail_closed else PolicyDecision(result="allow", reason="OPA timeout — fail open")
            except httpx.HTTPStatusError as exc:
                logger.error("OPA HTTP error %s at %s", exc.response.status_code, url)
                return DENY_ERROR if self._fail_closed else PolicyDecision(result="allow", reason="OPA HTTP error — fail open")
            except Exception as exc:
                logger.exception("OPA unexpected error: %s", exc)
                return DENY_CLOSED if self._fail_closed else PolicyDecision(result="allow", reason="OPA error — fail open")

        if resp is None:
            return DENY_CLOSED if self._fail_closed else PolicyDecision(result="allow", reason="OPA unreachable after retry")

        data = resp.json()

        # OPA wraps result in {"result": ...}
        raw = data.get("result", {})
        if not raw:
            return PolicyDecision(result="deny", reason="No policy result returned by OPA")

        result = raw.get("result", "deny")
        reason = raw.get("reason", "")
        policy = raw.get("policy", "")
        meta = {k: v for k, v in raw.items() if k not in ("result", "reason", "policy")}

        return PolicyDecision(result=result, reason=reason, policy=policy, metadata=meta)

    async def push_policy(self, policy_id: str, rego_content: str) -> None:
        """Push a Rego policy to OPA via REST API."""
        from urllib.parse import quote
        encoded_id = quote(policy_id, safe="")
        url = f"{self._base_url}/v1/policies/{encoded_id}"
        for attempt in range(3):
            try:
                client = await self._get_client()
                resp = await client.put(url, content=rego_content.encode(), headers={"Content-Type": "text/plain"})
                resp.raise_for_status()
                logger.info("Pushed policy to OPA: %s", policy_id)
                return
            except Exception as exc:
                if attempt < 2:
                    logger.warning("Push policy attempt %d failed for %s: %s", attempt + 1, policy_id, exc)
                    await asyncio.sleep(0.2)
                    continue
                logger.error("Failed to push policy %s after %d attempts: %s", policy_id, attempt + 1, exc)
                raise

    async def is_healthy(self) -> bool:
        """Check if OPA sidecar is reachable."""
        try:
            client = await self._get_client()
            resp = await client.get(f"{self._base_url}/health", timeout=1.0)
            return resp.status_code == 200
        except Exception:
            return False


# Module-level singleton
_opa_client: OPAClient | None = None


def get_opa_client() -> OPAClient:
    global _opa_client
    if _opa_client is None:
        from behavry_proxy.config import get_config
        cfg = get_config()
        _opa_client = OPAClient(
            base_url=cfg.opa_url,
            timeout=cfg.opa_timeout,
            fail_closed=cfg.opa_fail_closed,
        )
    return _opa_client
