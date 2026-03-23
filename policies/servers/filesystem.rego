# Behavry Proxy — Filesystem server policy
#
# Reference policy for filesystem MCP servers.
# Allows reads, denies writes to sensitive paths, blocks deletes.

package behavry.authz

import future.keywords.in

# Allow filesystem reads
decision := {
    "result": "allow",
    "reason": "Filesystem read allowed",
    "policy": "servers/filesystem"
} {
    input.request.mcp_server == "filesystem"
    input.request.action in {"read", "get", "list", "search"}
}

# Block writes to sensitive paths
decision := {
    "result": "deny",
    "reason": "Write to sensitive path blocked",
    "policy": "servers/filesystem"
} {
    input.request.mcp_server == "filesystem"
    input.request.action in {"write", "create", "update", "edit"}
    _is_sensitive_path(input.request.resource)
}

# Block all deletes
decision := {
    "result": "deny",
    "reason": "Filesystem delete operations are blocked",
    "policy": "servers/filesystem"
} {
    input.request.mcp_server == "filesystem"
    input.request.action in {"delete", "remove"}
}

_is_sensitive_path(path) {
    startswith(path, "/etc/")
}

_is_sensitive_path(path) {
    startswith(path, "/root/")
}

_is_sensitive_path(path) {
    contains(path, ".ssh/")
}

_is_sensitive_path(path) {
    contains(path, ".env")
}

_is_sensitive_path(path) {
    contains(path, "credentials")
}

_is_sensitive_path(path) {
    contains(path, "secrets")
}
