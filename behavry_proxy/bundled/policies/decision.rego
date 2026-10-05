# Behavry Proxy — policy entry point
#
# The proxy evaluates exactly one path: data.behavry.authz.decision
# (configurable via BEHAVRY_OPA_POLICY_PATH).
#
# Policy files never define `decision` directly. Instead they contribute
# to the `deny` set:
#
#   deny contains {"reason": "why", "policy": "servers/github"} if {
#       input.request.action == "delete"
#   }
#
# Any number of files may contribute. If the set is empty the request is
# allowed; otherwise the lowest-sorting entry (by policy, then reason) is
# returned, so the decision is deterministic no matter how many rules match.
#
# Input schema:
#   input.agent.id            — agent identifier (from X-Agent-Id header)
#   input.request.tool_name   — MCP tool being called
#   input.request.action      — derived action (read, write, delete, ...)
#   input.request.resource    — derived resource (file path, URL, query, ...)
#   input.request.parameters  — raw tool call arguments
#   input.request.mcp_server  — backend server ID
#   input.dlp.has_findings    — true when the DLP scanner flagged the input
#   input.dlp.findings        — list of {type, severity, field}
#   input.dlp.max_severity    — highest severity seen (none|low|medium|high|critical)

package behavry.authz

import rego.v1

# Declares `deny` as a set so this file evaluates on its own, with no other
# policy files loaded. Contributes nothing.
deny contains entry if {
	false
	entry := {"reason": "", "policy": ""}
}

_ranked := sort([[d.policy, d.reason] | some d in deny])

decision := {
	"result": "deny",
	"reason": _ranked[0][1],
	"policy": _ranked[0][0],
} if {
	count(deny) > 0
}

# Default posture: allow anything no rule denied.
# For default-deny, replace the body of this rule with `false` and write
# explicit allow rules, or add a catch-all deny in base/action_policies.rego.
decision := {
	"result": "allow",
	"reason": "no deny rule matched",
	"policy": "base/decision",
} if {
	count(deny) == 0
}
