# Behavry Proxy — database server policy
#
# Reads are allowed by default. DDL and destructive DML are blocked.

package behavry.authz

import rego.v1

deny contains {
	"reason": sprintf("Destructive database operation %q blocked", [input.request.action]),
	"policy": "servers/database",
} if {
	input.request.mcp_server == "database"
	input.request.action in {"drop", "truncate", "delete", "alter"}
}

deny contains {
	"reason": sprintf("DDL tool %q blocked", [input.request.tool_name]),
	"policy": "servers/database",
} if {
	input.request.mcp_server == "database"
	input.request.tool_name in {"drop_table", "alter_table", "create_table", "truncate_table"}
}
