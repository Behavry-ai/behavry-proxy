# Behavry Proxy — Allow-all policy (development only)
#
# WARNING: This policy allows all tool calls. Use only for development
# and testing. Replace with specific policies in production.
#
# To use: rename to default.rego or set higher priority.

package behavry.authz

decision := {
    "result": "allow",
    "reason": "Allow-all policy (development mode)",
    "policy": "base/allow_all"
}
