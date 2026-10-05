# Behavry Proxy — GitHub server policy
#
# Reads and issue/PR creation are allowed by default. Destructive repository
# operations are blocked.

package behavry.authz

import rego.v1

deny contains {
	"reason": sprintf("Destructive GitHub operation %q blocked", [input.request.action]),
	"policy": "servers/github",
} if {
	input.request.mcp_server == "github"
	input.request.action in {"delete", "remove", "force_push"}
}

# Repository administration is blocked regardless of derived action.
deny contains {
	"reason": sprintf("GitHub admin tool %q blocked", [input.request.tool_name]),
	"policy": "servers/github",
} if {
	input.request.mcp_server == "github"
	input.request.tool_name in {"delete_repository", "transfer_repository", "update_branch_protection"}
}
