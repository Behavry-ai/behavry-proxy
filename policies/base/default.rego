# Behavry Proxy — Default Policy
#
# Default-allow policy for getting started. Replace with your own rules.
#
# OPA evaluates this at: POST /v1/data/behavry/authz/decision
#
# Input schema:
#   input.agent.id       — agent identifier (from X-Agent-Id header)
#   input.request.tool_name  — MCP tool being called
#   input.request.action     — derived action (read, write, execute, etc.)
#   input.request.resource   — derived resource (file path, URL, query, etc.)
#   input.request.parameters — raw tool call arguments
#   input.request.mcp_server — backend server ID

package behavry.authz

import rego.v1

# Default: allow all requests
# Change to `default decision := {"result": "deny", ...}` for default-deny
default decision := {
    "result": "allow",
    "reason": "default allow policy",
    "policy": "base/default",
}

# Example: deny write operations on sensitive paths
# decision := {
#     "result": "deny",
#     "reason": "write to sensitive path blocked",
#     "policy": "base/default",
# } if {
#     input.request.action == "write"
#     startswith(input.request.resource, "/etc/")
# }

# Example: deny all requests from a specific agent
# decision := {
#     "result": "deny",
#     "reason": "agent blocked by policy",
#     "policy": "base/default",
# } if {
#     input.agent.id == "blocked-agent-id"
# }
