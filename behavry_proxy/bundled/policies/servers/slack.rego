# Behavry Proxy — Slack server policy
#
# Reads and sending messages are allowed by default. Admin and destructive
# workspace operations are blocked.

package behavry.authz

import rego.v1

deny contains {
	"reason": sprintf("Slack admin operation %q blocked", [input.request.action]),
	"policy": "servers/slack",
} if {
	input.request.mcp_server == "slack"
	input.request.action in {"delete", "remove", "archive", "kick", "ban"}
}
