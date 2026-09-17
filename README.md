# Behavry Proxy

<!-- mcp-name: ai.behavry/proxy -->

**Open-source inline MCP governance proxy** — policy enforcement, DLP scanning, and injection detection for AI agents.

Behavry Proxy sits between your MCP clients (Claude, Cursor, custom agents) and MCP servers, intercepting every tool call. Each request is evaluated against OPA/Rego policies, scanned for sensitive data leaks, and checked for prompt injection — before the agent can act.

```
Agent (Claude, Cursor, etc.)
    ↓
Behavry Proxy ← OPA sidecar (Rego policies)
    ↓
Target MCP Server (GitHub, filesystem, database, Slack, etc.)
```

## Why

AI agents that connect to tools via MCP can:
- **Leak secrets** — API keys, credentials, and PII in tool call arguments
- **Be injected** — attacker-controlled tool responses that hijack agent behavior
- **Exceed authority** — executing destructive operations without authorization

Behavry Proxy enforces governance at the protocol layer. Every `tools/call` passes through policy evaluation, DLP scanning, and injection detection. Agents that don't pass don't act.

## Features

| Feature | Description |
|---------|-------------|
| **OPA/Rego Policies** | Real policy engine, real policies. Default deny. Per-server, per-agent, per-action rules. |
| **DLP Scanner** | 26 patterns — AWS keys, GitHub/Slack/OpenAI tokens, credit cards, SSNs, JWTs, private keys, connection strings. Luhn + SSN validators to reduce false positives. |
| **Injection Detection** | 21 patterns across 7 attack classes — imperative commands, authority claims, permission expansion, role reassignment, encoded payloads, structured escalation, urgency framing. |
| **Fail-Closed** | OPA unreachable? All requests denied. Configurable to fail-open for development. |
| **Rate Limiting** | Per-agent sliding window with burst detection and spike anomaly detection. |
| **Terminal Dashboard** | Rich-based live TUI showing tool calls, decisions, DLP findings in real time. |
| **Prometheus Metrics** | `/metrics` endpoint — tool calls, deny rate, DLP findings, OPA latency. |
| **Audit Log** | JSON lines to file + stdout. Every decision recorded with full context. |
| **Reference Policies** | Ready-to-use Rego policies for filesystem, GitHub, database, Slack, web APIs. |

## Quick Start

### Docker Compose (recommended)

```bash
git clone https://github.com/Behavry-ai/behavry-proxy.git
cd behavry-proxy
cp config/servers.yaml.example config/servers.yaml
# Edit config/servers.yaml with your MCP server URLs
docker compose up
```

Proxy is at `http://localhost:8080`. OPA at `http://localhost:8181`.

### pip

```bash
pip install behavry-proxy
behavry-proxy
```

### Verify

```bash
# Health check
curl http://localhost:8080/health

# Metrics
curl http://localhost:8080/metrics

# List configured servers
curl http://localhost:8080/servers
```

## Your First Governed Tool Call

```bash
curl -X POST http://localhost:8080/mcp/github \
  -H "Content-Type: application/json" \
  -H "X-Agent-Id: my-agent" \
  -d '{
    "jsonrpc": "2.0",
    "id": 1,
    "method": "tools/call",
    "params": {
      "name": "list_repos",
      "arguments": {"org": "behavry"}
    }
  }'
```

## Connect Your MCP Client

Point your MCP client at the proxy URL instead of directly at the MCP server.

### Claude Desktop

```json
{
  "mcpServers": {
    "github-governed": {
      "url": "http://localhost:8080/mcp/github",
      "headers": { "X-Agent-Id": "claude-desktop" }
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
      "headers": { "X-Agent-Id": "claude-code" }
    }
  }
}
```

See [Configuration](docs/CONFIGURATION.md) for Cursor, custom agents, and all options.

## Writing Policies

Policies are Rego files in `policies/`. They're pushed to OPA on proxy startup.

**Allow reads, deny writes:**

```rego
package behavry.authz

import future.keywords.in

decision := {
    "result": "allow",
    "reason": "Read allowed",
    "policy": "read_only"
} {
    input.request.action in {"read", "get", "list", "search"}
}
```

**Block sensitive paths:**

```rego
package behavry.authz

decision := {
    "result": "deny",
    "reason": "Sensitive path blocked",
    "policy": "path_block"
} {
    input.request.mcp_server == "filesystem"
    contains(input.request.parameters.path, ".env")
}
```

**Block on DLP findings:**

```rego
package behavry.authz

decision := {
    "result": "deny",
    "reason": "Sensitive data in request",
    "policy": "dlp_block"
} {
    input.dlp.has_findings == true
}
```

See [Policies Guide](docs/POLICIES.md) for the full input document reference and more examples.

## Terminal Dashboard

Live view of proxy activity:

```bash
python -m behavry_proxy.tui.dashboard
# or with a specific audit file:
python -m behavry_proxy.tui.dashboard /path/to/audit.jsonl
```

## DLP Patterns (26)

| Pattern | Severity | Validated |
|---------|----------|-----------|
| AWS Access Key | Critical | — |
| AWS Secret Key | Critical | — |
| GitHub Token | Critical | — |
| Slack Token | Critical | — |
| OpenAI API Key | Critical | — |
| Anthropic API Key | Critical | — |
| Google API Key | Critical | — |
| GCP Service Account | Critical | — |
| Stripe API Key | Critical | — |
| SendGrid API Key | Critical | — |
| JWT / Bearer Token | Critical | — |
| Private Key (RSA/EC/OpenSSH) | Critical | — |
| PGP Private Key | Critical | — |
| Connection String | High | — |
| Azure Storage Key | High | — |
| Azure SAS Token | High | — |
| GitLab Token | High | — |
| Twilio API Key | High | — |
| Slack Webhook | High | — |
| Discord Webhook | High | — |
| Docker Auth | High | — |
| Credit Card | High | Luhn ✓ |
| SSN | High | Format ✓ |
| Generic API Key | Medium | — |
| Credential Assignment | Medium | — |
| Email | Low | Disabled |

## Injection Patterns (21)

| Class | Severity | Count | Examples |
|-------|----------|-------|----------|
| Imperative Command | Critical | 3 | "ignore previous instructions" |
| Authority Claim | Critical | 4 | "I am your administrator", "SYSTEM:" |
| Permission Expansion | Critical | 3 | "you are now authorized to" |
| Role Reassignment | High | 4 | "act as", "DAN", "pretend to be" |
| Encoded Payload | High | 3 | Base64 >100 chars, Unicode escapes |
| Structured Escalation | High | 3 | `<SYSTEM_ADMIN_OVERRIDE>`, `"role":"system"` |
| Urgency Framing | Medium | 1 | "URGENT:", "IMMEDIATE ACTION REQUIRED" |

## API

| Method | Path | Description |
|--------|------|-------------|
| POST | `/mcp/{server_id}` | MCP proxy endpoint |
| GET | `/servers` | List configured servers |
| GET | `/health` | Liveness + OPA status |
| GET | `/metrics` | Prometheus counters |

## Documentation

- [Architecture](docs/ARCHITECTURE.md) — pipeline, components, design decisions
- [Configuration](docs/CONFIGURATION.md) — env vars, servers.yaml, MCP client setup
- [Policies Guide](docs/POLICIES.md) — writing and testing Rego policies
- [Commercial Upgrade](COMMERCIAL.md) — what Behavry Enterprise adds

## Development

```bash
# Install dependencies
poetry install

# Run tests
poetry run pytest tests/ -v

# Run proxy locally
poetry run python -m behavry_proxy.main

# Lint
poetry run ruff check behavry_proxy/
```

## License

Apache 2.0 — see [LICENSE](LICENSE).

Built by [Behavry](https://behavry.ai). When you outgrow the proxy, [we're here](COMMERCIAL.md).
