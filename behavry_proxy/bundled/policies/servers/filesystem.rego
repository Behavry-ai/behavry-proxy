# Behavry Proxy — filesystem server policy
#
# Reference policy for filesystem MCP servers: reads are allowed, writes to
# sensitive paths are blocked, deletes are blocked by base/action_policies.

package behavry.authz

import rego.v1

deny contains {
	"reason": sprintf("Write to sensitive path %q blocked", [input.request.resource]),
	"policy": "servers/filesystem",
} if {
	input.request.mcp_server == "filesystem"
	input.request.action in {"write", "create", "update", "edit"}
	_is_sensitive_path(input.request.resource)
}

_sensitive_prefixes := ["/etc/", "/root/", "/var/root/"]

_sensitive_fragments := [".ssh/", ".env", "credentials", "secrets", ".aws/", ".kube/"]

_is_sensitive_path(path) if {
	some prefix in _sensitive_prefixes
	startswith(path, prefix)
}

_is_sensitive_path(path) if {
	some fragment in _sensitive_fragments
	contains(path, fragment)
}
