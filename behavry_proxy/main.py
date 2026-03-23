"""
Behavry Proxy — FastAPI application entrypoint.

Usage:
    uvicorn behavry_proxy.main:app --host 0.0.0.0 --port 8080
    # or via CLI:
    behavry-proxy
"""
from __future__ import annotations

import logging

from fastapi import FastAPI

from behavry_proxy import __version__
from behavry_proxy.config import get_config
from behavry_proxy.proxy.mcp import MCPServerConfig
from behavry_proxy.proxy.registry import close_all, register_server
from behavry_proxy.proxy.router import router

logger = logging.getLogger("behavry_proxy")


def create_app() -> FastAPI:
    """Create and configure the FastAPI application."""
    app = FastAPI(
        title="Behavry Proxy",
        description="Open-source MCP governance proxy — DLP, policy enforcement, and injection scanning for AI agents",
        version=__version__,
        docs_url="/docs",
        redoc_url=None,
    )

    app.include_router(router)

    @app.on_event("startup")
    async def startup() -> None:
        cfg = get_config()

        # Configure logging
        logging.basicConfig(
            level=logging.INFO,
            format="%(asctime)s %(name)s %(levelname)s %(message)s",
        )

        # Register configured MCP servers
        for server_cfg in cfg.servers:
            try:
                register_server(server_cfg)
            except Exception as exc:
                logger.error("Failed to register server %s: %s", server_cfg.id, exc)

        # Push Rego policies to OPA if policies_dir is set
        if cfg.policies_dir:
            await _push_policies(cfg.policies_dir)

        logger.info(
            "Behavry Proxy v%s started — %d servers, OPA=%s, DLP=%s, inbound=%s",
            __version__,
            len(cfg.servers),
            cfg.opa_url,
            cfg.dlp_enabled,
            cfg.inbound_scan_enabled,
        )

    @app.on_event("shutdown")
    async def shutdown() -> None:
        await close_all()
        from behavry_proxy.policy.client import get_opa_client
        await get_opa_client().close()
        logger.info("Behavry Proxy shutdown complete")

    return app


async def _push_policies(policies_dir: str) -> None:
    """Push all .rego files from a directory to OPA."""
    from pathlib import Path

    from behavry_proxy.policy.client import get_opa_client

    opa = get_opa_client()
    policies_path = Path(policies_dir)

    if not policies_path.exists():
        logger.warning("Policies directory not found: %s", policies_dir)
        return

    for rego_file in sorted(policies_path.rglob("*.rego")):
        if "test" in rego_file.parts:
            continue
        policy_id = str(rego_file.relative_to(policies_path))
        try:
            content = rego_file.read_text()
            await opa.push_policy(policy_id, content)
        except Exception as exc:
            logger.error("Failed to push policy %s: %s", policy_id, exc)


app = create_app()
