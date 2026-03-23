"""
CLI entrypoint for Behavry Proxy.

Usage:
    behavry-proxy                      # Start with defaults
    behavry-proxy --port 9090          # Custom port
    behavry-proxy --config servers.yaml # Custom server config
"""
from __future__ import annotations

import argparse
import os
import sys


def main() -> None:
    parser = argparse.ArgumentParser(
        prog="behavry-proxy",
        description="Behavry Proxy — Open-source MCP governance proxy",
    )
    parser.add_argument("--host", default=None, help="Bind host (default: 0.0.0.0)")
    parser.add_argument("--port", type=int, default=None, help="Bind port (default: 8080)")
    parser.add_argument("--config", default=None, help="Path to servers.yaml")
    parser.add_argument("--policies", default=None, help="Path to Rego policies directory")
    parser.add_argument("--opa-url", default=None, help="OPA sidecar URL")
    parser.add_argument("--fail-open", action="store_true", help="Fail open when OPA is unreachable (default: fail closed)")
    parser.add_argument("--no-dlp", action="store_true", help="Disable DLP scanning")
    parser.add_argument("--no-inbound", action="store_true", help="Disable inbound injection scanning")
    parser.add_argument("--auth-token", default=None, help="Required bearer token for proxy access")
    parser.add_argument("--log-file", default=None, help="Audit log file path (JSONL)")

    args = parser.parse_args()

    # Set env vars from CLI args (config.py reads env vars)
    if args.host:
        os.environ["BEHAVRY_PROXY_HOST"] = args.host
    if args.port:
        os.environ["BEHAVRY_PROXY_PORT"] = str(args.port)
    if args.config:
        os.environ["BEHAVRY_SERVERS_CONFIG"] = args.config
    if args.policies:
        os.environ["BEHAVRY_POLICIES_DIR"] = args.policies
    if args.opa_url:
        os.environ["BEHAVRY_OPA_URL"] = args.opa_url
    if args.fail_open:
        os.environ["BEHAVRY_OPA_FAIL_CLOSED"] = "false"
    if args.no_dlp:
        os.environ["BEHAVRY_DLP_ENABLED"] = "false"
    if args.no_inbound:
        os.environ["BEHAVRY_INBOUND_SCAN_ENABLED"] = "false"
    if args.auth_token:
        os.environ["BEHAVRY_AUTH_TOKEN"] = args.auth_token
    if args.log_file:
        os.environ["BEHAVRY_AUDIT_LOG_FILE"] = args.log_file

    # Import after env vars are set
    from behavry_proxy.config import get_config
    cfg = get_config()

    import uvicorn
    uvicorn.run(
        "behavry_proxy.main:app",
        host=cfg.host,
        port=cfg.port,
        log_level="info",
    )


if __name__ == "__main__":
    main()
