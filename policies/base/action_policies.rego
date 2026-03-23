# Behavry Proxy — Action-based policies
#
# Classifies tool calls by action type and applies appropriate decisions.
# Override by defining more specific policies per server.

package behavry.authz

import future.keywords.in

# Read actions are generally safe
decision := {
    "result": "allow",
    "reason": "Read action allowed",
    "policy": "base/action_policies"
} {
    input.request.action in {"get", "list", "search", "read", "fetch", "describe", "show", "find", "query"}
}

# DLP findings trigger deny regardless of action
decision := {
    "result": "deny",
    "reason": "DLP finding detected in request",
    "policy": "base/action_policies"
} {
    input.dlp.has_findings == true
}

# Inbound injection findings trigger deny
decision := {
    "result": "deny",
    "reason": "Inbound injection detected in response",
    "policy": "base/action_policies"
} {
    input.inbound.has_findings == true
}
