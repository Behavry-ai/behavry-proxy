"""
MCP Server Registry.

Manages configured backend MCP servers and their connection backends.
Supports both HTTP and stdio transports.

Servers are loaded from servers.yaml on startup.
"""
from __future__ import annotations

import logging
from typing import Union

from behavry_proxy.proxy.backends.http import HTTPBackend
from behavry_proxy.proxy.backends.stdio import StdioBackend
from behavry_proxy.proxy.mcp import MCPServerConfig

logger = logging.getLogger(__name__)

BackendType = Union[HTTPBackend, StdioBackend]

# In-memory registry: server_id → (config, backend_instance)
_registry: dict[str, tuple[MCPServerConfig, BackendType]] = {}


def register_server(config: MCPServerConfig) -> None:
    """Register a backend MCP server in the registry."""
    if config.id in _registry:
        _close_backend(_registry[config.id][1])

    if config.transport == "http":
        if not config.url:
            raise ValueError(f"HTTP backend {config.id} requires a URL")
        backend: BackendType = HTTPBackend(server_url=config.url)
    elif config.transport == "stdio":
        if not config.command:
            raise ValueError(f"Stdio backend {config.id} requires a command")
        backend = StdioBackend(command=config.command, env=config.env)
    else:
        raise ValueError(f"Unknown transport: {config.transport}")

    _registry[config.id] = (config, backend)
    logger.info("Registered MCP server: %s (%s, %s)", config.name, config.id, config.transport)


def unregister_server(server_id: str) -> bool:
    """Remove a server from the registry and close its backend."""
    if server_id not in _registry:
        return False
    config, backend = _registry.pop(server_id)
    _close_backend(backend)
    logger.info("Unregistered MCP server: %s (%s)", config.name, server_id)
    return True


async def get_backend(server_id: str) -> BackendType:
    """Get the backend for a server ID. Raises ValueError if not found."""
    if server_id not in _registry:
        raise ValueError(f"MCP server not registered: {server_id}")
    config, backend = _registry[server_id]
    if not config.enabled:
        raise ValueError(f"MCP server disabled: {server_id}")
    return backend


def list_servers() -> list[MCPServerConfig]:
    """List all registered server configs."""
    return [config for config, _ in _registry.values()]


def get_server_config(server_id: str) -> MCPServerConfig | None:
    """Get config for a specific server."""
    entry = _registry.get(server_id)
    return entry[0] if entry else None


def _close_backend(backend: BackendType) -> None:
    """Schedule backend close (fire-and-forget)."""
    import asyncio
    try:
        loop = asyncio.get_event_loop()
        if loop.is_running():
            loop.create_task(backend.close())
    except Exception as exc:
        logger.debug("Backend close error: %s", exc)


async def close_all() -> None:
    """Close all backends gracefully (called on shutdown)."""
    for server_id, (config, backend) in list(_registry.items()):
        try:
            await backend.close()
            logger.info("Closed backend: %s (%s)", config.name, server_id)
        except Exception as exc:
            logger.error("Error closing backend %s: %s", server_id, exc)
    _registry.clear()
