# Behavry Proxy — DLP-aware policy
#
# Denies tool calls when DLP findings are present in the request.
# Provides policy-layer enforcement on top of the pipeline's DLP scanner.

package behavry.authz

import future.keywords.in

# Deny when critical DLP findings exist
decision := {
    "result": "deny",
    "reason": "Critical sensitive data detected by DLP scanner",
    "policy": "dlp/sensitive_data"
} {
    input.dlp.has_findings == true
    some finding in input.dlp.findings
    finding.severity == "critical"
}

# Deny when high-severity DLP findings in write operations
decision := {
    "result": "deny",
    "reason": "High-severity sensitive data detected in write operation",
    "policy": "dlp/sensitive_data"
} {
    input.dlp.has_findings == true
    some finding in input.dlp.findings
    finding.severity == "high"
    input.request.action in {"write", "create", "send", "post", "update"}
}
