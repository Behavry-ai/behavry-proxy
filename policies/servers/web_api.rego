# Behavry Proxy — Web API server policy
#
# Reference policy for generic web/API MCP servers.
# Conservative: allows reads, blocks writes by default.

package behavry.authz

import future.keywords.in

# Allow web API reads
decision := {
    "result": "allow",
    "reason": "Web API read allowed",
    "policy": "servers/web_api"
} {
    input.request.mcp_server == "web_api"
    input.request.action in {"get", "fetch", "search", "list", "read"}
}

# Block POST/PUT/DELETE by default (override per-server as needed)
decision := {
    "result": "deny",
    "reason": "Web API write operation blocked by default",
    "policy": "servers/web_api"
} {
    input.request.mcp_server == "web_api"
    input.request.action in {"post", "put", "delete", "patch", "create", "update", "remove"}
}
