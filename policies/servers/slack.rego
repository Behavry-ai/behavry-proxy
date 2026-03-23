# Behavry Proxy — Slack server policy
#
# Reference policy for Slack MCP servers.
# Allows reads and channel messages, blocks admin operations.

package behavry.authz

import future.keywords.in

# Allow Slack read operations
decision := {
    "result": "allow",
    "reason": "Slack read allowed",
    "policy": "servers/slack"
} {
    input.request.mcp_server == "slack"
    input.request.action in {"get", "list", "search", "read", "fetch"}
}

# Allow sending messages
decision := {
    "result": "allow",
    "reason": "Slack message send allowed",
    "policy": "servers/slack"
} {
    input.request.mcp_server == "slack"
    input.request.tool_name in {"send_message", "post_message", "reply_to_thread"}
}

# Block admin/destructive Slack operations
decision := {
    "result": "deny",
    "reason": "Slack admin operation blocked",
    "policy": "servers/slack"
} {
    input.request.mcp_server == "slack"
    input.request.action in {"delete", "remove", "archive", "kick", "ban"}
}
