# Writing Policies

Behavry Proxy uses [Open Policy Agent (OPA)](https://www.openpolicyagent.org/) with Rego policies for tool call authorization. This guide covers writing and testing policies.

## Quick Start

1. Create a `.rego` file in `policies/`
2. Define a `decision` rule in the `behavry.authz` package
3. Restart the proxy (policies are pushed to OPA on startup)

## Policy Format

Every policy must:
- Use `package behavry.authz`
- Define a `decision` rule returning an object with `result`, `reason`, and `policy`

```rego
package behavry.authz

decision := {
    "result": "allow",
    "reason": "Read operations are safe",
    "policy": "my_policy"
} {
    input.request.action == "read"
}
```

## Decision Values

| Result | Effect |
|--------|--------|
| `allow` | Request forwarded to backend |
| `deny` | Request blocked, error returned to agent |
| `escalate` | Treated as `deny` in OSS proxy (requires Behavry Enterprise for HITL) |

## Input Document Reference

The full input document available to policies:

```rego
input.agent.id                    # Agent identifier (from X-Agent-Id header)

input.request.tool_name           # e.g. "read_file", "create_issue"
input.request.action              # Extracted verb: "read", "create", "delete", etc.
input.request.resource            # Extracted resource: file path, repo name, etc.
input.request.parameters          # Full tool call arguments dict
input.request.mcp_server          # Target server ID: "github", "filesystem"

input.dlp.has_findings            # true if DLP scanner found sensitive data
input.dlp.findings                # Array of {pattern, severity, location}

input.inbound.has_findings        # true if inbound scanner found injection patterns
input.inbound.findings            # Array of {pattern_class, pattern_name, severity}

input.context                     # Additional context (reserved for future use)
```

## Common Patterns

### Allow reads, deny writes

```rego
package behavry.authz

import future.keywords.in

decision := {
    "result": "allow",
    "reason": "Read allowed",
    "policy": "read_only"
} {
    input.request.action in {"read", "get", "list", "search", "fetch"}
}
```

### Deny specific tools

```rego
package behavry.authz

decision := {
    "result": "deny",
    "reason": "Tool is blocked",
    "policy": "blocked_tools"
} {
    input.request.tool_name == "delete_repository"
}
```

### Block based on DLP findings

```rego
package behavry.authz

decision := {
    "result": "deny",
    "reason": "Sensitive data detected",
    "policy": "dlp_block"
} {
    input.dlp.has_findings == true
    some finding in input.dlp.findings
    finding.severity == "critical"
}
```

### Per-server policies

```rego
package behavry.authz

# Only allow reads on the database server
decision := {
    "result": "deny",
    "reason": "Only read queries allowed on database",
    "policy": "database_read_only"
} {
    input.request.mcp_server == "database"
    not input.request.action in {"query", "read", "get", "list", "describe"}
}
```

### Per-agent policies

```rego
package behavry.authz

# Block all writes for the "reader" agent
decision := {
    "result": "deny",
    "reason": "Reader agent cannot write",
    "policy": "agent_reader"
} {
    input.agent.id == "reader-agent"
    input.request.action in {"write", "create", "update", "delete"}
}
```

### Path-based restrictions

```rego
package behavry.authz

decision := {
    "result": "deny",
    "reason": "Access to sensitive path blocked",
    "policy": "path_restrictions"
} {
    input.request.mcp_server == "filesystem"
    path := input.request.parameters.path
    _is_sensitive(path)
}

_is_sensitive(path) { startswith(path, "/etc/") }
_is_sensitive(path) { contains(path, ".env") }
_is_sensitive(path) { contains(path, "credentials") }
_is_sensitive(path) { contains(path, ".ssh/") }
```

## Policy Precedence

OPA evaluates all policies and uses the **last matching** `decision` rule. To control precedence:

1. Use specific conditions (server + action + tool) over broad ones
2. Put your default deny in `policies/base/default.rego`
3. Put server-specific overrides in `policies/servers/`
4. The default deny fires only when no other policy matches

## Testing Policies

### With OPA CLI

```bash
# Install OPA
brew install opa  # or download from openpolicyagent.org

# Test a policy
echo '{"input": {"agent": {"id": "test"}, "request": {"tool_name": "read_file", "action": "read", "resource": "/tmp/test.txt", "mcp_server": "filesystem"}, "dlp": {"has_findings": false, "findings": []}, "inbound": {"has_findings": false, "findings": []}}}' | \
  opa eval -d policies/ -i /dev/stdin "data.behavry.authz.decision"
```

### With the Running Proxy

```bash
# Send a test tool call
curl -X POST http://localhost:8080/mcp/v1/filesystem \
  -H "Content-Type: application/json" \
  -H "X-Agent-Id: test-agent" \
  -d '{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"read_file","arguments":{"path":"/tmp/test.txt"}}}'
```

### OPA Unit Tests

Create test files in `policies/test/`:

```rego
# policies/test/filesystem_test.rego
package behavry.authz_test

import data.behavry.authz

test_read_allowed {
    authz.decision.result == "allow" with input as {
        "agent": {"id": "test"},
        "request": {
            "tool_name": "read_file",
            "action": "read",
            "resource": "/tmp/test.txt",
            "mcp_server": "filesystem"
        },
        "dlp": {"has_findings": false, "findings": []},
        "inbound": {"has_findings": false, "findings": []}
    }
}
```

Run with: `opa test policies/ -v`
