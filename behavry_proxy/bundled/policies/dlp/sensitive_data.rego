# Behavry Proxy — DLP-aware policy
#
# The proxy's DLP scanner runs before policy evaluation and passes its
# findings in as input.dlp. These rules add a policy-layer decision on top,
# so you can express DLP posture per action or per server in Rego rather
# than only through BEHAVRY_DLP_BLOCK_SEVERITY.

package behavry.authz

import rego.v1

# Any critical finding in the request is denied.
deny contains {
	"reason": "Critical sensitive data detected by DLP scanner",
	"policy": "dlp/sensitive_data",
} if {
	some finding in input.dlp.findings
	finding.severity == "critical"
}

# High-severity findings are denied only on operations that leave the boundary.
deny contains {
	"reason": "High-severity sensitive data in an outbound write operation",
	"policy": "dlp/sensitive_data",
} if {
	some finding in input.dlp.findings
	finding.severity == "high"
	input.request.action in {"write", "create", "send", "post", "update"}
}
