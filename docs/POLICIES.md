# Writing Policies

Behavry Proxy uses [Open Policy Agent (OPA)](https://www.openpolicyagent.org/) with Rego policies for tool call authorization. This guide covers writing and testing policies.

Policies are **Rego v1** and require **OPA 1.0 or newer**. Start every file with `import rego.v1` when it uses `if`, `in` or `contains`.

## Quick Start

1. Run `behavry-proxy init` to get an editable copy of the reference policies in `policies/`
2. Add a `.rego` file that contributes to the `deny` set in the `behavry.authz` package
3. Restart the proxy (policies are pushed to OPA on startup)

## Policy Format

The proxy evaluates exactly one path: `data.behavry.authz.decision`.

**Your policies never define `decision`.** `decision.rego` owns it. Every other
file contributes to a `deny` set:

```rego
package behavry.authz

import rego.v1

deny contains {
    "reason": "Read-only agent cannot write",
    "policy": "my_policy",
} if {
    input.request.action in {"write", "create", "update"}
}
```

Any number of files may contribute. If the set is empty the request is allowed.
Otherwise the lowest-sorting entry (by `policy`, then `reason`) is returned, so
the decision is deterministic no matter how many rules match at once.

> **Why not define `decision` directly?** `decision` is a complete rule. Two
> files that both define it for the same request make OPA fail the whole
> evaluation with `complete rules must not produce multiple outputs` — and a
> failed evaluation is a denied request. Partial set rules (`deny contains`)
> compose instead of colliding.

### Changing the default posture

`decision.rego` allows anything no rule denied. For default-deny, add a
catch-all that denies unless an explicit condition holds:

```rego
package behavry.authz

import rego.v1

deny contains {
    "reason": "Not on the allowlist",
    "policy": "base/default_deny",
} if {
    not input.request.action in {"read", "get", "list", "search"}
}
```

## Decision Values

| Result | Effect |
|--------|--------|
| `allow` | Request forwarded to backend |
| `deny` | Request blocked, error returned to agent |
| `escalate` | Enforced as `deny` — the OSS proxy has no approval queue (requires Behavry Enterprise for HITL) |

## Input Document Reference

The full input document available to policies:

```rego
input.agent.id                    # Agent identifier (from X-Agent-Id header)

input.request.tool_name           # e.g. "read_file", "create_issue"
input.request.action              # Extracted verb: "read", "create", "delete", etc.
input.request.resource            # Extracted resource: file path, repo name, etc.
input.request.parameters          # Full tool call arguments dict
input.request.mcp_server          # Target server ID: "github", "filesystem"

input.dlp.has_findings            # true if the DLP scanner flagged the request
input.dlp.findings                # Array of {pattern, severity, ...}
input.dlp.max_severity            # none | low | medium | high | critical

input.context                     # Additional context (reserved for future use)
```

`input.request.action` and `input.request.resource` are derived by the proxy:
the action is the tool name up to the first underscore (`read_file` → `read`),
and the resource is the first of `path`, `url`, `query`, `table`, `channel`,
`repo`, `org`, `file` or `command` present in the arguments.

> Inbound injection scanning runs on the tool **response**, after the policy
> decision has been made, so there is no `input.inbound`. Configure it with
> `BEHAVRY_INBOUND_BLOCK_SEVERITY` rather than in Rego.

## Common Patterns

### Deny specific tools

```rego
package behavry.authz

import rego.v1

deny contains {
    "reason": "Tool is blocked",
    "policy": "blocked_tools",
} if {
    input.request.tool_name == "delete_repository"
}
```

### Block based on DLP findings

```rego
package behavry.authz

import rego.v1

deny contains {
    "reason": "Sensitive data detected",
    "policy": "dlp_block",
} if {
    some finding in input.dlp.findings
    finding.severity == "critical"
}
```

### Per-server policies

```rego
package behavry.authz

import rego.v1

# Only allow reads on the database server
deny contains {
    "reason": "Only read queries allowed on database",
    "policy": "database_read_only",
} if {
    input.request.mcp_server == "database"
    not input.request.action in {"query", "read", "get", "list", "describe"}
}
```

### Per-agent policies

```rego
package behavry.authz

import rego.v1

# Block all writes for the "reader" agent
deny contains {
    "reason": "Reader agent cannot write",
    "policy": "agent_reader",
} if {
    input.agent.id == "reader-agent"
    input.request.action in {"write", "create", "update", "delete"}
}
```

### Path-based restrictions

```rego
package behavry.authz

import rego.v1

deny contains {
    "reason": "Access to sensitive path blocked",
    "policy": "path_restrictions",
} if {
    input.request.mcp_server == "filesystem"
    _is_sensitive(input.request.resource)
}

_is_sensitive(path) if startswith(path, "/etc/")

_is_sensitive(path) if contains(path, ".env")

_is_sensitive(path) if contains(path, "credentials")

_is_sensitive(path) if contains(path, ".ssh/")
```

## Testing Policies

### With OPA CLI

`opa eval -i` takes the input document **unwrapped** — no outer `"input"` key.
(The REST API the proxy uses does expect the wrapper; only the CLI differs.)

```bash
# Install OPA (1.0 or newer)
brew install opa  # or download from openpolicyagent.org

# Check that everything parses and there are no conflicts
opa check --strict policies/

# Evaluate a single request
echo '{"agent":{"id":"test"},"request":{"tool_name":"read_file","action":"read","resource":"/tmp/test.txt","parameters":{},"mcp_server":"filesystem"},"dlp":{"has_findings":false,"findings":[],"max_severity":"none"}}' | \
  opa eval -d policies/ -i /dev/stdin "data.behavry.authz.decision"
```

To see which rules fired, evaluate the set instead of the decision:

```bash
opa eval -d policies/ -i input.json "data.behavry.authz.deny"
```

### With the Running Proxy

```bash
curl -X POST http://localhost:8080/mcp/filesystem \
  -H "Content-Type: application/json" \
  -H "X-Agent-Id: test-agent" \
  -d '{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"read_file","arguments":{"path":"/tmp/test.txt"}}}'
```

The `X-Policy-Result` response header carries `allow`, `deny` or `escalate`.

### OPA Unit Tests

Create test files in `policies/test/` — the proxy skips any path containing
`test` when pushing policies, so they never reach the running OPA.

```rego
# policies/test/filesystem_test.rego
package behavry.authz_test

import data.behavry.authz
import rego.v1

test_read_allowed if {
    authz.decision.result == "allow" with input as {
        "agent": {"id": "test"},
        "request": {
            "tool_name": "read_file",
            "action": "read",
            "resource": "/tmp/test.txt",
            "parameters": {},
            "mcp_server": "filesystem",
        },
        "dlp": {"has_findings": false, "findings": [], "max_severity": "none"},
    }
}

test_delete_denied if {
    authz.decision.result == "deny" with input as {
        "agent": {"id": "test"},
        "request": {
            "tool_name": "delete_file",
            "action": "delete",
            "resource": "/tmp/test.txt",
            "parameters": {},
            "mcp_server": "filesystem",
        },
        "dlp": {"has_findings": false, "findings": [], "max_severity": "none"},
    }
}
```

Run with: `opa test policies/ -v`
