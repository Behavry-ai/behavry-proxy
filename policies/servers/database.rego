# Behavry Proxy — Database server policy
#
# Reference policy for database MCP servers.
# Allows reads, blocks DDL and destructive DML.

package behavry.authz

import future.keywords.in

# Allow database reads
decision := {
    "result": "allow",
    "reason": "Database read allowed",
    "policy": "servers/database"
} {
    input.request.mcp_server == "database"
    input.request.action in {"query", "read", "get", "list", "describe", "select"}
}

# Block destructive operations
decision := {
    "result": "deny",
    "reason": "Destructive database operation blocked",
    "policy": "servers/database"
} {
    input.request.mcp_server == "database"
    input.request.action in {"drop", "truncate", "delete", "alter"}
}

# Block DDL entirely
decision := {
    "result": "deny",
    "reason": "DDL operations are blocked",
    "policy": "servers/database"
} {
    input.request.mcp_server == "database"
    input.request.tool_name in {"drop_table", "alter_table", "create_table", "truncate_table"}
}
