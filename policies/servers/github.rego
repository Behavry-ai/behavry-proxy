# Behavry Proxy — GitHub server policy
#
# Reference policy for GitHub MCP servers.
# Allows reads, allows issue/PR creation, blocks destructive operations.

package behavry.authz

import future.keywords.in

# Allow GitHub read operations
decision := {
    "result": "allow",
    "reason": "GitHub read allowed",
    "policy": "servers/github"
} {
    input.request.mcp_server == "github"
    input.request.action in {"get", "list", "search", "fetch"}
}

# Allow creating issues and PRs
decision := {
    "result": "allow",
    "reason": "GitHub create allowed for issues/PRs",
    "policy": "servers/github"
} {
    input.request.mcp_server == "github"
    input.request.action == "create"
    input.request.tool_name in {"create_issue", "create_pull_request", "create_comment"}
}

# Block destructive GitHub operations
decision := {
    "result": "deny",
    "reason": "Destructive GitHub operation blocked",
    "policy": "servers/github"
} {
    input.request.mcp_server == "github"
    input.request.action in {"delete", "remove", "force_push"}
}
