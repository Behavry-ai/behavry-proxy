# Architecture

## Overview

Behavry Proxy is an inline MCP governance proxy. It sits between MCP clients (Claude, Cursor, custom agents) and MCP servers (filesystem, GitHub, Slack, databases), intercepting every tool call for policy evaluation, DLP scanning, and injection detection.

```
┌─────────────────┐     ┌─────────────────────────┐     ┌─────────────────┐
│   MCP Client    │────▶│   behavry-proxy          │────▶│  Target MCP     │
│  (Claude, etc.) │     │                          │     │    Server       │
│                 │◀────│  ┌──────────────────┐    │◀────│                 │
└─────────────────┘     │  │ Policy (OPA)     │    │     └─────────────────┘
                        │  │ DLP Scanner      │    │
                        │  │ Inbound Scanner  │    │
                        │  │ Rate Limiter     │    │
                        │  │ Audit (JSONL)    │    │
                        │  │ Metrics          │    │
                        │  └──────────────────┘    │
                        └─────────────────────────┘
```

## Request Pipeline

Every `tools/call` request passes through this pipeline:

```
1. Parse JSON-RPC request
2. Route passthrough methods (initialize, ping, tools/list)
3. Extract tool name + arguments
4. Rate limit check ──────────────── DENY if burst cap exceeded
5. DLP scan input ────────────────── DENY if critical finding
6. OPA policy evaluation ─────────── DENY if policy rejects
7. Forward to backend MCP server
8. DLP scan output ───────────────── LOG findings
9. Inbound injection scan ────────── DENY if critical injection
10. Emit audit event
11. Return response to agent
```

## Components

### Proxy Pipeline (`proxy/pipeline.py`)
The core enforcement loop. Orchestrates all checks and produces a policy-compliant response. Passthrough methods (`initialize`, `ping`, `tools/list`) skip the pipeline and forward directly.

### DLP Scanner (`dlp/scanner.py`)
26 regex-based patterns detecting sensitive data in tool call inputs and outputs:
- **Critical**: AWS keys, GitHub/Slack/OpenAI/Anthropic tokens, private keys, JWTs, GCP service accounts, Stripe/SendGrid keys
- **High**: Connection strings, Azure keys/SAS tokens, GitLab tokens, Twilio keys, webhook URLs, Docker auth
- **Medium**: Generic API keys, credential assignments
- **Low**: Email addresses (disabled by default)

Includes validators (Luhn for credit cards, SSN format check) to reduce false positives.

### Inbound Scanner (`dlp/inbound.py`)
21 patterns across 7 attack classes detecting prompt injection in tool responses:
- **Critical**: Imperative commands, authority claims, permission expansion
- **High**: Role reassignment, encoded payloads, structured escalation markers
- **Medium**: Urgency framing

Tool responses from attacker-controlled sources (web pages, shared docs, webhook responses) can embed instructions that cause agents to execute unauthorized actions. The inbound scanner catches these before they reach the agent.

### OPA Policy Engine (`policy/client.py`)
Async REST client for the OPA sidecar. Features:
- Fail-closed by default (configurable to fail-open)
- 1 retry with 100ms backoff for transient errors
- Policy hot-reload: edit `.rego` files, they're pushed to OPA on next startup

### Rate Limiter (`proxy/rate_limiter.py`)
Per-agent sliding window rate limiter:
- 60-second window with configurable RPM cap
- Hard burst cap (instant block)
- Spike detection via exponential weighted moving average (3× baseline = anomaly)

### Audit Emitter (`audit/emitter.py`)
JSON lines output to file and/or stdout. Each event includes:
- Request context (server, tool, agent)
- Policy decision (result, reason, policy ID)
- DLP findings (count, max severity, details)
- Inbound findings (count, max severity, details)
- Timing (total latency)

### Metrics (`metrics.py`)
Prometheus-compatible counters at `GET /metrics`:
- `behavry_proxy_tool_calls_total` / `_allowed` / `_denied`
- `behavry_proxy_dlp_findings_total`
- `behavry_proxy_inbound_findings_total`
- `behavry_proxy_opa_errors_total`
- `behavry_proxy_opa_latency_seconds_sum` / `_count`

### Terminal Dashboard (`tui/dashboard.py`)
Rich-based live terminal display showing:
- Real-time tool call table with decisions
- Summary counters (allowed/denied/DLP/inbound)
- OPA health status

## Technology Stack

| Component | Technology |
|-----------|-----------|
| HTTP Framework | FastAPI |
| Policy Engine | OPA sidecar (Rego) |
| HTTP Client | httpx (async) |
| Data Validation | Pydantic v2 |
| Config Format | YAML (servers), env vars (everything else) |
| TUI | Rich |
| Metrics | Prometheus text format (no external deps) |
| Audit | JSON lines |
| Container | Docker + Docker Compose |

## Design Decisions

### Fail-Closed Default
If OPA is unreachable, all tool calls are denied. This is the safe default for a governance proxy. Set `BEHAVRY_PROXY_OPA_FAIL_CLOSED=false` to fail-open (not recommended for production).

### No Agent Identity
The OSS proxy identifies agents by the `X-Agent-Id` header — a simple string, not a cryptographic binding. This is intentional: identity binding (JWT RS256, OAuth 2.1, certificate pinning) is a complex feature that belongs in the commercial product.

### HTTP-Only Backends
v0.1 supports HTTP transport only. Stdio backends (subprocess-spawned MCP servers) are planned for v0.2.

### In-Process Rate Limiter
Rate limiting uses in-memory data structures — no Redis dependency. This works correctly for single-process deployments. If you need distributed rate limiting, that's a signal you need the commercial product.

### Deny-Only Enforcement
When OPA returns `escalate`, the proxy treats it as `deny`. There is no human-in-the-loop approval queue. If you need HITL, see [Behavry Enterprise](../COMMERCIAL.md).
