# Behavry Proxy — generic web/API server policy
#
# Conservative default for untrusted HTTP backends: reads allowed, anything
# that mutates remote state is blocked until you allow it explicitly.

package behavry.authz

import rego.v1

deny contains {
	"reason": sprintf("Web API write operation %q blocked by default", [input.request.action]),
	"policy": "servers/web_api",
} if {
	input.request.mcp_server == "web_api"
	input.request.action in {"post", "put", "delete", "patch", "create", "update", "remove"}
}
