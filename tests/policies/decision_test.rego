# Unit tests for the bundled reference policies.
#
# These live outside behavry_proxy/ so they are not packaged into the wheel.
# Run with: opa test behavry_proxy/bundled/policies tests/policies -v
#
# They guard two regressions:
#   1. Rego v0 syntax, which does not parse on OPA 1.x at all.
#   2. Two policy files both matching one request. Complete `decision` rules
#      conflict in that case and fail the whole evaluation (which denies the
#      request); the `deny` set composes instead.

package behavry.authz_test

import data.behavry.authz
import rego.v1

_clean_dlp := {"has_findings": false, "findings": [], "max_severity": "none"}

_request(server, action, tool, resource) := {
	"agent": {"id": "test-agent"},
	"request": {
		"tool_name": tool,
		"action": action,
		"resource": resource,
		"parameters": {},
		"mcp_server": server,
	},
	"dlp": _clean_dlp,
	"context": {},
}

_with_dlp(server, action, tool, resource, severity) := object.union(
	_request(server, action, tool, resource),
	{"dlp": {
		"has_findings": true,
		"findings": [{"severity": severity, "pattern": "test_pattern"}],
		"max_severity": severity,
	}},
)

# --- default posture ------------------------------------------------------

test_unmatched_request_is_allowed if {
	decision := authz.decision with input as _request("filesystem", "read", "read_file", "/tmp/ok.txt")
	decision.result == "allow"
	decision.policy == "base/decision"
}

# --- base/action_policies -------------------------------------------------

test_destructive_action_is_denied if {
	decision := authz.decision with input as _request("filesystem", "delete", "delete_file", "/tmp/ok.txt")
	decision.result == "deny"
}

test_truncate_is_denied if {
	authz.decision.result == "deny" with input as _request("database", "truncate", "truncate_table", "users")
}

# --- servers/filesystem --------------------------------------------------

test_write_to_sensitive_path_is_denied if {
	decision := authz.decision with input as _request("filesystem", "write", "write_file", "/etc/passwd")
	decision.result == "deny"
	decision.policy == "servers/filesystem"
}

test_write_to_dotssh_is_denied if {
	authz.decision.result == "deny" with input as _request("filesystem", "write", "write_file", "/home/u/.ssh/id_rsa")
}

test_write_to_safe_path_is_allowed if {
	authz.decision.result == "allow" with input as _request("filesystem", "write", "write_file", "/tmp/ok.txt")
}

test_sensitive_path_rule_is_scoped_to_filesystem if {
	authz.decision.result == "allow" with input as _request("github", "write", "write_file", "/etc/passwd")
}

# --- servers/database ----------------------------------------------------

test_ddl_tool_is_denied if {
	authz.decision.result == "deny" with input as _request("database", "execute", "drop_table", "users")
}

test_select_is_allowed if {
	authz.decision.result == "allow" with input as _request("database", "query", "query", "SELECT 1")
}

# --- servers/web_api -----------------------------------------------------

test_web_api_write_is_denied if {
	authz.decision.result == "deny" with input as _request("web_api", "post", "http_post", "https://example.com")
}

test_web_api_read_is_allowed if {
	authz.decision.result == "allow" with input as _request("web_api", "get", "http_get", "https://example.com")
}

# --- dlp/sensitive_data --------------------------------------------------

test_critical_dlp_finding_is_denied if {
	decision := authz.decision with input as _with_dlp("filesystem", "read", "read_file", "/tmp/ok.txt", "critical")
	decision.result == "deny"
	decision.policy == "dlp/sensitive_data"
}

test_high_dlp_finding_on_read_is_allowed if {
	authz.decision.result == "allow" with input as _with_dlp("filesystem", "read", "read_file", "/tmp/ok.txt", "high")
}

test_high_dlp_finding_on_send_is_denied if {
	authz.decision.result == "deny" with input as _with_dlp("slack", "send", "send_message", "#general", "high")
}

# --- composition ---------------------------------------------------------

test_overlapping_denials_resolve_to_one_decision if {
	# `delete` trips base/action_policies and servers/github at once. Under the
	# old design this was an eval_conflict_error, not a decision.
	decision := authz.decision with input as _request("github", "delete", "delete_repo", "behavry/x")
	decision.result == "deny"
	is_string(decision.reason)
	is_string(decision.policy)
}

test_decision_is_always_defined if {
	# Every shape of request must yield a decision; an undefined decision
	# surfaces to the proxy as "No policy result returned by OPA".
	authz.decision.result != ""  with input as _request("unknown-server", "frobnicate", "frob", "x")
}
