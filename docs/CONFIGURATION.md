# Configuration

## Environment Variables

All configuration is via environment variables. No database, no config files (except `servers.yaml` for upstream MCP servers).

| Variable | Default | Description |
|----------|---------|-------------|
| `BEHAVRY_PROXY_HOST` | `0.0.0.0` | Bind address |
| `BEHAVRY_PROXY_PORT` | `8080` | Listen port |
| `BEHAVRY_PROXY_LOG_LEVEL` | `info` | Log level: debug, info, warning, error |
| `BEHAVRY_PROXY_OPA_URL` | `http://localhost:8181` | OPA sidecar URL |
| `BEHAVRY_PROXY_OPA_TIMEOUT` | `2.0` | OPA request timeout (seconds) |
| `BEHAVRY_PROXY_OPA_FAIL_CLOSED` | `true` | Deny all on OPA failure (`true`) or allow all (`false`) |
| `BEHAVRY_PROXY_RATE_LIMIT_RPM` | `60` | Per-agent requests per minute limit |
| `BEHAVRY_PROXY_RATE_LIMIT_BURST` | `100` | Hard per-agent burst cap |
| `BEHAVRY_PROXY_AUDIT_LOG` | `audit.jsonl` | Audit log file path |
| `BEHAVRY_PROXY_AUDIT_STDOUT` | `true` | Also write audit events to stdout |
| `BEHAVRY_PROXY_SERVERS_CONFIG` | `config/servers.yaml` | Path to upstream server config |

## Upstream Servers (`servers.yaml`)

Define your backend MCP servers in `config/servers.yaml`:

```yaml
servers:
  - id: github
    name: GitHub MCP Server
    transport: http
    url: http://localhost:3000
    description: GitHub API via MCP

  - id: filesystem
    name: Filesystem Server
    transport: http
    url: http://localhost:3001

  - id: slack
    name: Slack MCP Server
    transport: http
    url: http://localhost:3002
    enabled: false  # disable without removing
```

Each server entry:

| Field | Required | Default | Description |
|-------|----------|---------|-------------|
| `id` | Yes | — | Unique identifier (used in URL path) |
| `name` | Yes | — | Display name |
| `transport` | No | `http` | Transport type (`http` only in v0.1) |
| `url` | Yes (http) | — | Backend server URL |
| `description` | No | — | Human-readable description |
| `enabled` | No | `true` | Set `false` to disable without removing |

## MCP Client Configuration

Point your MCP client at the proxy instead of directly at the MCP server.

### Claude Desktop

Edit `~/Library/Application Support/Claude/claude_desktop_config.json`:

```json
{
  "mcpServers": {
    "github-governed": {
      "url": "http://localhost:8080/mcp/github",
      "headers": {
        "X-Agent-Id": "claude-desktop"
      }
    }
  }
}
```

### Claude Code

```json
{
  "mcpServers": {
    "github-governed": {
      "type": "url",
      "url": "http://localhost:8080/mcp/github",
      "headers": {
        "X-Agent-Id": "claude-code"
      }
    }
  }
}
```

### Cursor

```json
{
  "mcpServers": {
    "github-governed": {
      "url": "http://localhost:8080/mcp/github",
      "headers": {
        "X-Agent-Id": "cursor"
      }
    }
  }
}
```

## Agent Identification

The proxy identifies agents via the `X-Agent-Id` HTTP header. This is used for:
- Rate limiting (per-agent sliding window)
- Audit logging (who made each tool call)

If no header is provided, the agent is identified as `"default"`.

> **Note:** This is a simple string identifier, not a cryptographic binding. For authenticated agent identity, see [Behavry Enterprise](../COMMERCIAL.md).

## OPA Policies

A reference policy set ships inside the package, so the proxy always has
something valid to push to OPA. Run `behavry-proxy init` for an editable copy
in `./policies`, or point `BEHAVRY_POLICIES_DIR` / `--policies` at your own
directory. Policies are pushed to OPA on proxy startup.

Policies are Rego v1 and require OPA 1.0 or newer.

### Policy Structure

```
policies/
├── decision.rego            # Entry point — aggregates `deny`, owns `decision`
├── base/
│   └── action_policies.rego # Cross-server action rules (destructive verbs)
├── servers/
│   ├── filesystem.rego      # Filesystem-specific rules
│   ├── github.rego          # GitHub-specific rules
│   ├── database.rego        # Database-specific rules
│   ├── slack.rego           # Slack-specific rules
│   └── web_api.rego         # Generic web API rules
└── dlp/
    └── sensitive_data.rego  # DLP-aware policy rules
```

Only `decision.rego` defines `decision`. Every other file contributes to a
`deny` set so that rules compose instead of conflicting — see
[Policies](POLICIES.md).

### Policy Input Document

Every tool call generates this OPA input:

```json
{
  "input": {
    "agent": {
      "id": "claude-desktop"
    },
    "request": {
      "tool_name": "read_file",
      "action": "read",
      "resource": "/tmp/test.txt",
      "parameters": {"path": "/tmp/test.txt"},
      "mcp_server": "filesystem"
    },
    "context": {},
    "dlp": {
      "findings": [],
      "has_findings": false
    },
    "inbound": {
      "findings": [],
      "has_findings": false
    }
  }
}
```

### Expected Policy Output

`data.behavry.authz.decision` resolves to:

```json
{
  "result": "allow",
  "reason": "no deny rule matched",
  "policy": "base/decision"
}
```

Valid `result` values: `allow`, `deny`, `escalate` (enforced as deny in the OSS
proxy, which has no approval queue).

Your own files do not build this object — they add entries to `deny` and
`decision.rego` turns the set into the response above.

### Hot Reload

Edit `.rego` files, then restart the proxy to push updates to OPA. In a future version, file watching will enable live reload without restart.

## Docker Compose

`behavry-proxy init` writes a `docker-compose.yml` that runs the proxy and the
OPA sidecar (the repository ships an equivalent `docker-compose.yaml`):

```bash
docker compose up        # foreground
docker compose up -d     # background
docker compose down      # stop
docker compose logs -f   # follow logs
```

Services:
- **proxy** — Behavry Proxy on port 8080
- **opa** — OPA on port 8181
