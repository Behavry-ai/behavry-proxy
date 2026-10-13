"""
Configuration for Behavry Proxy.

Loads settings from environment variables and optionally from servers.yaml.
"""
from __future__ import annotations

import logging
import os
from dataclasses import dataclass, field
from pathlib import Path

import yaml

from behavry_proxy.proxy.mcp import MCPServerConfig
from behavry_proxy.resources import (
    SERVERS_CONFIG_SEARCH_PATH,
    bundled_policies_dir,
    find_servers_config,
)

logger = logging.getLogger(__name__)


@dataclass
class ProxyConfig:
    """All configuration for the proxy, loaded from env + YAML."""
    # Server
    host: str = "0.0.0.0"
    port: int = 8080

    # OPA
    opa_url: str = "http://localhost:8181"
    opa_timeout: float = 5.0
    opa_fail_closed: bool = True
    opa_policy_path: str = "behavry/authz/decision"

    # Rate limiting
    rate_limit_rpm: int = 60
    rate_limit_burst: int = 100

    # DLP
    dlp_enabled: bool = True
    dlp_block_severity: str = "high"  # block at this severity or above

    # Inbound injection scanning
    inbound_scan_enabled: bool = True
    inbound_block_severity: str = "critical"

    # Audit
    audit_log_file: str | None = None  # None = stdout only
    audit_log_format: str = "jsonl"    # jsonl | text

    # Auth
    auth_token: str | None = None  # Simple bearer token auth (optional)

    # Servers (loaded from YAML)
    servers: list[MCPServerConfig] = field(default_factory=list)

    # Policies directory (Rego files to push to OPA on startup).
    # Defaults to the reference policies bundled in the wheel.
    policies_dir: str | None = None

    # True when policies_dir is the bundled set rather than the user's own.
    policies_are_bundled: bool = False


def load_servers_yaml(path: str | Path) -> list[MCPServerConfig]:
    """Load MCP server configurations from a YAML file."""
    path = Path(path)
    if not path.exists():
        logger.warning("Servers config not found: %s", path)
        return []
    logger.info("Loading MCP servers from %s", path)

    with open(path) as f:
        data = yaml.safe_load(f)

    if not data or "servers" not in data or not data["servers"]:
        return []

    servers: list[MCPServerConfig] = []
    for entry in data["servers"]:
        try:
            servers.append(MCPServerConfig(**entry))
        except Exception as exc:
            logger.warning("Invalid server config entry: %s — %s", entry, exc)
    return servers


def load_config() -> ProxyConfig:
    """Load configuration from environment variables and servers.yaml."""
    config = ProxyConfig(
        host=os.environ.get("BEHAVRY_PROXY_HOST", "0.0.0.0"),
        port=int(os.environ.get("BEHAVRY_PROXY_PORT", "8080")),
        opa_url=os.environ.get("BEHAVRY_OPA_URL", "http://localhost:8181"),
        opa_timeout=float(os.environ.get("BEHAVRY_OPA_TIMEOUT", "5.0")),
        opa_fail_closed=os.environ.get("BEHAVRY_OPA_FAIL_CLOSED", "true").lower() == "true",
        opa_policy_path=os.environ.get("BEHAVRY_OPA_POLICY_PATH", "behavry/authz/decision"),
        rate_limit_rpm=int(os.environ.get("BEHAVRY_RATE_LIMIT_RPM", "60")),
        rate_limit_burst=int(os.environ.get("BEHAVRY_RATE_LIMIT_BURST", "100")),
        dlp_enabled=os.environ.get("BEHAVRY_DLP_ENABLED", "true").lower() == "true",
        dlp_block_severity=os.environ.get("BEHAVRY_DLP_BLOCK_SEVERITY", "high"),
        inbound_scan_enabled=os.environ.get("BEHAVRY_INBOUND_SCAN_ENABLED", "true").lower() == "true",
        inbound_block_severity=os.environ.get("BEHAVRY_INBOUND_BLOCK_SEVERITY", "critical"),
        audit_log_file=os.environ.get("BEHAVRY_AUDIT_LOG_FILE"),
        audit_log_format=os.environ.get("BEHAVRY_AUDIT_LOG_FORMAT", "jsonl"),
        auth_token=os.environ.get("BEHAVRY_AUTH_TOKEN"),
    )

    # Policies: an explicit directory wins, otherwise fall back to the
    # reference policies bundled in the wheel so a pip install has something
    # valid to push to OPA.
    policies_dir = os.environ.get("BEHAVRY_POLICIES_DIR")
    if policies_dir:
        config.policies_dir = policies_dir
        config.policies_are_bundled = False
    else:
        config.policies_dir = str(bundled_policies_dir())
        config.policies_are_bundled = True

    # Servers: explicit path wins, otherwise search the working directory.
    explicit = os.environ.get("BEHAVRY_SERVERS_CONFIG")
    servers_path = find_servers_config(explicit)
    if servers_path is None:
        logger.warning(
            "No MCP servers configured — looked for %s in %s. "
            "Run `behavry-proxy init` to create one.",
            " and ".join(SERVERS_CONFIG_SEARCH_PATH),
            Path.cwd(),
        )
    else:
        config.servers = load_servers_yaml(servers_path)

    return config


# Singleton
_config: ProxyConfig | None = None


def get_config() -> ProxyConfig:
    global _config
    if _config is None:
        _config = load_config()
    return _config
