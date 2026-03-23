"""Tests for DLP scanner — 26 builtin patterns."""
from behavry_proxy.dlp.scanner import (
    DLPScanner,
    BUILTIN_PATTERNS,
    luhn_check,
    ssn_check,
    redact_match,
    get_dlp_scanner,
)


class TestLuhnCheck:
    def test_valid_visa(self):
        assert luhn_check("4111111111111111") is True

    def test_valid_mastercard(self):
        assert luhn_check("5500000000000004") is True

    def test_invalid_number(self):
        assert luhn_check("1234567890123456") is False

    def test_too_short(self):
        assert luhn_check("12345") is False


class TestSSNCheck:
    def test_valid_ssn(self):
        assert ssn_check("123-45-6789") is True

    def test_invalid_area_000(self):
        assert ssn_check("000-12-3456") is False

    def test_invalid_area_666(self):
        assert ssn_check("666-12-3456") is False

    def test_invalid_area_900(self):
        assert ssn_check("900-12-3456") is False


class TestRedactMatch:
    def test_short_string(self):
        assert redact_match("short") == "***"

    def test_long_string(self):
        result = redact_match("AKIAIOSFODNN7EXAMPLE")
        assert result.startswith("AKI")
        assert result.endswith("PLE")
        assert "***" in result


class TestDLPScanner:
    def setup_method(self):
        self.scanner = DLPScanner(BUILTIN_PATTERNS)

    def test_aws_access_key(self):
        findings = self.scanner.scan("my key is AKIAIOSFODNN7EXAMPLE", "test")
        assert len(findings) == 1
        assert findings[0].pattern == "aws_access_key"
        assert findings[0].severity == "critical"

    def test_github_token(self):
        findings = self.scanner.scan("token: ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijkl", "test")
        assert len(findings) >= 1
        patterns = {f.pattern for f in findings}
        assert "github_token" in patterns

    def test_slack_token(self):
        # Fake token for testing — not a real credential
        findings = self.scanner.scan("xoxb-not-a-real-token-for-testing", "test")
        assert any(f.pattern == "slack_token" for f in findings)

    def test_private_key(self):
        findings = self.scanner.scan("-----BEGIN RSA PRIVATE KEY-----", "test")
        assert any(f.pattern == "private_key" for f in findings)

    def test_jwt_token(self):
        jwt = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U"
        findings = self.scanner.scan(jwt, "test")
        assert any(f.pattern == "jwt_token" for f in findings)

    def test_openai_api_key(self):
        findings = self.scanner.scan("sk-proj-ABCDEFGHIJKLMNOPQRSTUVWXYZabc", "test")
        assert any(f.pattern == "openai_api_key" for f in findings)

    def test_anthropic_api_key(self):
        findings = self.scanner.scan("sk-ant-ABCDEFGHIJKLMNOPQRSTUVWXYZabc", "test")
        assert any(f.pattern == "anthropic_api_key" for f in findings)

    def test_connection_string(self):
        findings = self.scanner.scan("postgresql://user:pass@host:5432/db", "test")
        assert any(f.pattern == "connection_string" for f in findings)

    def test_no_findings_clean_text(self):
        findings = self.scanner.scan("Hello, this is normal text.", "test")
        assert len(findings) == 0

    def test_scan_dict(self):
        data = {"key": "AKIAIOSFODNN7EXAMPLE", "nested": {"secret": "normal"}}
        findings = self.scanner.scan_dict(data, "test")
        assert len(findings) == 1

    def test_scan_tool_call(self):
        findings = self.scanner.scan_tool_call(
            tool_name="write_file",
            parameters={"content": "AKIAIOSFODNN7EXAMPLE"},
            result="File written successfully",
        )
        assert len(findings) >= 1

    def test_max_severity(self):
        findings = self.scanner.scan(
            "AKIAIOSFODNN7EXAMPLE and password=mysecretpassword123",
            "test",
        )
        sev = DLPScanner.max_severity(findings)
        assert sev == "critical"

    def test_max_severity_empty(self):
        assert DLPScanner.max_severity([]) is None

    def test_credit_card_luhn_validated(self):
        # Valid Luhn number
        findings = self.scanner.scan("4111 1111 1111 1111", "test")
        assert any(f.pattern == "credit_card" for f in findings)

        # Invalid Luhn number — should NOT match
        findings = self.scanner.scan("1234 5678 9012 3456", "test")
        cc_findings = [f for f in findings if f.pattern == "credit_card"]
        assert len(cc_findings) == 0


class TestSingleton:
    def test_get_dlp_scanner_returns_same_instance(self):
        s1 = get_dlp_scanner()
        s2 = get_dlp_scanner()
        assert s1 is s2

    def test_builtin_pattern_count(self):
        assert len(BUILTIN_PATTERNS) == 26
