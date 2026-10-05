"""
CLI entrypoint for Behavry Proxy.

Usage:
    behavry-proxy                       # Start with defaults
    behavry-proxy --port 9090           # Custom port
    behavry-proxy --config servers.yaml # Custom server config
    behavry-proxy init                  # Scaffold config, policies, docker-compose
"""
from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path

from behavry_proxy import __version__


def _build_run_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="behavry-proxy",
        description="Behavry Proxy — Open-source MCP governance proxy",
        epilog=(
            "Run `behavry-proxy init` to scaffold config/servers.yaml, an editable "
            "copy of the reference policies, and a docker-compose.yml that starts "
            "the required OPA sidecar."
        ),
    )
    parser.add_argument("--version", action="version", version=f"behavry-proxy {__version__}")
    parser.add_argument("--host", default=None, help="Bind host (default: 0.0.0.0)")
    parser.add_argument("--port", type=int, default=None, help="Bind port (default: 8080)")
    parser.add_argument("--config", default=None, help="Path to servers.yaml")
    parser.add_argument("--policies", default=None, help="Path to Rego policies directory")
    parser.add_argument("--opa-url", default=None, help="OPA sidecar URL")
    parser.add_argument(
        "--fail-open",
        action="store_true",
        help="Fail open when OPA is unreachable (default: fail closed)",
    )
    parser.add_argument("--no-dlp", action="store_true", help="Disable DLP scanning")
    parser.add_argument("--no-inbound", action="store_true", help="Disable inbound injection scanning")
    parser.add_argument("--auth-token", default=None, help="Required bearer token for proxy access")
    parser.add_argument("--log-file", default=None, help="Audit log file path (JSONL)")
    return parser


def _run(argv: list[str]) -> None:
    args = _build_run_parser().parse_args(argv)

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


def _init(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(
        prog="behavry-proxy init",
        description=(
            "Write a working local setup into a directory: config/servers.yaml, "
            "an editable copy of the reference Rego policies, and a "
            "docker-compose.yml that runs the proxy alongside the OPA sidecar "
            "it needs to make policy decisions."
        ),
    )
    parser.add_argument(
        "directory",
        nargs="?",
        default=".",
        help="Target directory (default: current directory)",
    )
    parser.add_argument(
        "--force",
        action="store_true",
        help="Overwrite files that already exist",
    )
    args = parser.parse_args(argv)

    from behavry_proxy.resources import scaffold

    target = Path(args.directory).resolve()
    target.mkdir(parents=True, exist_ok=True)

    written, skipped = scaffold(target, force=args.force)

    for path in written:
        print(f"  created  {path.relative_to(target)}")
    for path in skipped:
        print(f"  exists   {path.relative_to(target)}  (use --force to overwrite)")

    if not written and skipped:
        print("\nNothing to do — everything is already in place.")
        return 0

    print(
        "\nNext:\n"
        "  1. Edit config/servers.yaml to point at your MCP servers.\n"
        "  2. docker compose up        # starts the proxy and the OPA sidecar\n"
        "  3. curl http://localhost:8080/health\n"
        "\n"
        "Without a reachable OPA the proxy denies every tool call by default."
    )
    return 0


def main() -> None:
    argv = sys.argv[1:]

    if argv and argv[0] == "init":
        raise SystemExit(_init(argv[1:]))

    _run(argv)


if __name__ == "__main__":
    main()
