# Behavry Proxy → Behavry Enterprise

Behavry Proxy is a fully functional open-source MCP governance proxy. It gives you real policy enforcement, DLP scanning, and injection detection — for free.

When you outgrow it, Behavry is the commercial platform that adds identity, visibility, and fleet management.

## What You Get (Open Source)

| Capability | Status |
|-----------|--------|
| Inline MCP enforcement (intercept → evaluate → enforce → forward → audit) | ✅ |
| OPA/Rego policy evaluation (real sidecar, real policies) | ✅ |
| DLP scanning — 26 builtin patterns (AWS keys, tokens, PII, credentials) | ✅ |
| Inbound injection detection — 21 patterns across 7 attack classes | ✅ |
| Fail-closed on OPA unavailability (configurable) | ✅ |
| Reference policies per server type (filesystem, database, GitHub, Slack, web) | ✅ |
| Terminal dashboard — live tool calls, decisions, DLP findings | ✅ |
| Prometheus metrics — tool calls/sec, deny rate, DLP findings, OPA latency | ✅ |
| Per-agent rate limiting with spike detection | ✅ |
| JSON lines audit log | ✅ |

## What You'll Want Next

As your agent fleet grows, you'll notice gaps. Here's the upgrade path:

| You realize... | You need... | Behavry feature |
|---------------|------------|-----------------|
| "Who made this tool call?" | Agent Identity | Cryptographic agent binding (JWT RS256, OAuth 2.1) |
| "I need to approve, not just block" | Human-in-the-Loop | Durable escalation queue with approval workflow |
| "Show me a dashboard" | Enterprise Dashboard | Widget-based dashboard with CIO/CTO/CISO views |
| "This agent is acting weird" | Behavioral Baselining | Welford variance tracking, Bray-Curtis divergence |
| "Something is exfiltrating across sessions" | Cross-session DLP | Session correlation, pattern accumulation detection |
| "My CISO wants tamper-proof audit" | Hash-chained Audit | SHA-256 chain, TimescaleDB hypertables, SIEM export |
| "I have 50 agents to manage" | Fleet Management | Multi-tenant, provisioning, bulk operations |
| "What's the blast radius?" | Risk Scoring | 6-dimension Behavry Risk Framework |
| "We need compliance reports" | OWASP ASI Mapping | Compliance scoring, PDF export |
| "I need to see what AI tools employees use" | Discovery | 30-platform fingerprinting, IdP connectors |

## Architecture Comparison

```
Open Source (behavry-proxy)          Enterprise (Behavry)
─────────────────────────           ────────────────────────
MCP Client                          MCP Client
    ↓                                   ↓
behavry-proxy                       Behavry SDK (identity binding)
    ↓                                   ↓
┌──────────────┐                    ┌──────────────────────────────────┐
│ DLP Scanner  │                    │ Identity Service  │ Policy Engine │
│ OPA Policy   │                    │ Behavioral Monitor│ Risk Scorer   │
│ Inbound Scan │                    │ HITL Queue       │ Audit Logger   │
│ Audit (JSONL)│                    │ DLP + Correlation │ SIEM Export   │
│ Rate Limiter │                    │ Dashboard        │ Discovery      │
└──────────────┘                    └──────────────────────────────────┘
    ↓                                   ↓
Target MCP Server                   Target MCP Server
```

## Getting Started with Behavry Enterprise

Visit [behavry.ai](https://behavry.ai) or email [hello@behavry.ai](mailto:hello@behavry.ai) for:

- **Design partner program** — hands-on onboarding with the Behavry team
- **Enterprise trial** — full platform access for evaluation
- **Architecture review** — we'll map your agent fleet and recommend a governance strategy

---

*Behavry Proxy is Apache 2.0 licensed. Use it freely. When you're ready for more, we're here.*
