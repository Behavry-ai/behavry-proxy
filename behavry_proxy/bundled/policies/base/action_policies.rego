# Behavry Proxy — action-based policies
#
# Coarse rules that apply to every backend, keyed off the derived action.
# Server-specific rules live in servers/.

package behavry.authz

import rego.v1

# Destructive actions are denied by default across all servers.
# Remove this rule, or narrow it per server, if your agents need to delete.
deny contains {
	"reason": sprintf("Destructive action %q is denied by default", [input.request.action]),
	"policy": "base/action_policies",
} if {
	input.request.action in {"delete", "remove", "drop", "truncate", "destroy"}
}
