"""
DLP (Data Loss Prevention) Scanner

Scans tool call parameters and results for sensitive data patterns.
26 built-in patterns with validators (Luhn, SSN).

Based on Behavry's DLP engine — extracted for the open-source proxy.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Callable, Literal

# ---------------------------------------------------------------------------
# Types
# ---------------------------------------------------------------------------

DLPSeverity = Literal["low", "medium", "high", "critical"]

SEVERITY_ORDER: dict[str, int] = {
    "none": 0,
    "low": 1,
    "medium": 2,
    "high": 3,
    "critical": 4,
}


@dataclass
class DLPPattern:
    name: str
    pattern: re.Pattern[str]
    severity: DLPSeverity
    description: str
    validator: Callable[[str], bool] | None = None
    enabled: bool = True


@dataclass
class DLPFinding:
    pattern: str
    severity: DLPSeverity
    location: str
    redacted_sample: str | None = None

    def to_dict(self) -> dict:
        return {
            "pattern": self.pattern,
            "severity": self.severity,
            "location": self.location,
            "redacted_sample": self.redacted_sample,
        }


# ---------------------------------------------------------------------------
# Validators
# ---------------------------------------------------------------------------

def luhn_check(card_number: str) -> bool:
    """Luhn algorithm for credit card validation."""
    digits = re.sub(r"\D", "", card_number)
    if not (13 <= len(digits) <= 19):
        return False

    total = 0
    is_even = False
    for ch in reversed(digits):
        d = int(ch)
        if is_even:
            d *= 2
            if d > 9:
                d -= 9
        total += d
        is_even = not is_even

    return total % 10 == 0


def ssn_check(ssn: str) -> bool:
    """SSN validation — no 000, 666, or 9xx area groups."""
    digits = re.sub(r"\D", "", ssn)
    if len(digits) != 9:
        return False

    area = int(digits[:3])
    group = int(digits[3:5])
    serial = int(digits[5:])

    if area == 0 or area == 666 or area >= 900:
        return False
    if group == 0 or serial == 0:
        return False

    return True


# ---------------------------------------------------------------------------
# Built-in patterns (26 total)
# ---------------------------------------------------------------------------

BUILTIN_PATTERNS: list[DLPPattern] = [
    DLPPattern(
        name="credit_card",
        pattern=re.compile(r"\b\d{4}[\s\-]?\d{4}[\s\-]?\d{4}[\s\-]?\d{1,7}\b"),
        severity="high",
        validator=luhn_check,
        description="Credit card number (Luhn-validated)",
    ),
    DLPPattern(
        name="ssn",
        pattern=re.compile(r"\b\d{3}[\s\-]?\d{2}[\s\-]?\d{4}\b"),
        severity="high",
        validator=ssn_check,
        description="Social Security Number",
    ),
    DLPPattern(
        name="aws_access_key",
        pattern=re.compile(r"\b(AKIA|ASIA)[0-9A-Z]{16}\b"),
        severity="critical",
        description="AWS Access Key ID",
    ),
    DLPPattern(
        name="aws_secret_key",
        pattern=re.compile(r"(?:aws|AWS)[\s\S]{0,50}[A-Za-z0-9/+=]{40}\b"),
        severity="critical",
        description="AWS Secret Access Key",
    ),
    DLPPattern(
        name="github_token",
        pattern=re.compile(r"\b(ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{36,}\b"),
        severity="critical",
        description="GitHub Token",
    ),
    DLPPattern(
        name="slack_token",
        pattern=re.compile(r"\b(xoxb|xoxp|xoxs|xoxa|xoxr)-[A-Za-z0-9\-]+"),
        severity="critical",
        description="Slack Token",
    ),
    DLPPattern(
        name="google_api_key",
        pattern=re.compile(r"\bAIza[0-9A-Za-z\-_]{35}\b"),
        severity="critical",
        description="Google API Key",
    ),
    DLPPattern(
        name="generic_api_key",
        pattern=re.compile(r"(?:key|token|secret|password|pwd|pass)[\s:=]+[A-Za-z0-9]{32,}", re.IGNORECASE),
        severity="medium",
        description="Generic API key or secret",
    ),
    DLPPattern(
        name="private_key",
        pattern=re.compile(r"-----BEGIN\s+(RSA|EC|OPENSSH)?\s*PRIVATE KEY-----"),
        severity="critical",
        description="Private key (RSA, EC, OpenSSH)",
    ),
    DLPPattern(
        name="connection_string",
        pattern=re.compile(
            r"(jdbc|mongodb(?:\+srv)?|postgres(?:ql)?|mysql)://[^:]+:[^@]+@[^\s\"']+",
            re.IGNORECASE,
        ),
        severity="high",
        description="Database connection string with credentials",
    ),
    DLPPattern(
        name="azure_key",
        pattern=re.compile(r"[A-Za-z0-9+/]{44}==?"),
        severity="high",
        description="Azure storage key or similar base64-encoded secret",
    ),
    DLPPattern(
        name="email",
        pattern=re.compile(r"\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b"),
        severity="low",
        description="Email address",
        enabled=False,  # Too noisy by default
    ),
    # --- Expanded patterns ---
    DLPPattern(
        name="jwt_token",
        pattern=re.compile(
            r"(?:Bearer\s+[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]+"
            r"|eyJ[A-Za-z0-9\-_]{10,}\.[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]+)",
            re.IGNORECASE,
        ),
        severity="critical",
        description="JWT / Bearer token — active session credential",
    ),
    DLPPattern(
        name="openai_api_key",
        pattern=re.compile(r"\bsk-(?:proj-)?[A-Za-z0-9]{20,}\b"),
        severity="critical",
        description="OpenAI API key (sk- or sk-proj- prefix)",
    ),
    DLPPattern(
        name="anthropic_api_key",
        pattern=re.compile(r"\bsk-ant-[A-Za-z0-9\-_]{20,}\b"),
        severity="critical",
        description="Anthropic / Claude API key (sk-ant- prefix)",
    ),
    DLPPattern(
        name="gcp_service_account",
        pattern=re.compile(
            r'"type"\s*:\s*"service_account"'
            r'|"client_email"\s*:\s*"[a-zA-Z0-9\-_]+@[a-zA-Z0-9\-]+\.iam\.gserviceaccount\.com"',
            re.IGNORECASE,
        ),
        severity="critical",
        description="GCP service account JSON credential",
    ),
    DLPPattern(
        name="stripe_api_key",
        pattern=re.compile(r"\b(?:sk|rk)_live_[A-Za-z0-9]{20,}\b"),
        severity="critical",
        description="Stripe live API or restricted key (sk_live_ / rk_live_)",
    ),
    DLPPattern(
        name="sendgrid_api_key",
        pattern=re.compile(r"\bSG\.[A-Za-z0-9\-_]{20,}\.[A-Za-z0-9\-_]{20,}\b"),
        severity="critical",
        description="SendGrid API key (SG.xxx.xxx format)",
    ),
    DLPPattern(
        name="pgp_private_key",
        pattern=re.compile(r"-----BEGIN PGP PRIVATE KEY BLOCK-----"),
        severity="critical",
        description="PGP private key block",
    ),
    DLPPattern(
        name="azure_sas_token",
        pattern=re.compile(
            r"sv=\d{4}-\d{2}-\d{2}[^&\s]*&(?:[^&\s]*&)*sig=[A-Za-z0-9%+/]{20,}",
            re.IGNORECASE,
        ),
        severity="high",
        description="Azure Storage SAS token (sv=…&sig=… URL params)",
    ),
    DLPPattern(
        name="gitlab_token",
        pattern=re.compile(r"\bglpat-[A-Za-z0-9\-_]{20,}\b"),
        severity="high",
        description="GitLab personal access token (glpat- prefix)",
    ),
    DLPPattern(
        name="twilio_api_key",
        pattern=re.compile(r"\bSK[0-9a-fA-F]{32}\b"),
        severity="high",
        description="Twilio API key SID (SK + 32 hex chars)",
    ),
    DLPPattern(
        name="slack_webhook",
        pattern=re.compile(
            r"https://hooks\.slack\.com/services/T[A-Z0-9]+/B[A-Z0-9]+/[A-Za-z0-9]+",
        ),
        severity="high",
        description="Slack incoming webhook URL",
    ),
    DLPPattern(
        name="discord_webhook",
        pattern=re.compile(
            r"https://discord(?:app)?\.com/api/webhooks/\d+/[A-Za-z0-9\-_]+",
        ),
        severity="high",
        description="Discord webhook URL",
    ),
    DLPPattern(
        name="docker_auth",
        pattern=re.compile(
            r'"auth"\s*:\s*"[A-Za-z0-9+/]{20,}={0,2}"',
        ),
        severity="high",
        description="Docker registry auth blob (base64 username:password)",
    ),
    DLPPattern(
        name="credential_assignment",
        pattern=re.compile(
            r"(?i)\b(?:password|passwd|pwd|db_pass(?:word)?|secret|api[_\-]?key|auth[_\-]?token)"
            r"\b\s*[:=]\s*[\"']?(?!(?:changeme|placeholder|example|your[_\-]|<|{|\s))"
            r"[^\s\"'<>{]{8,}[\"']?",
        ),
        severity="medium",
        description="Credential key=value assignment (password=, secret=, api_key=, etc.)",
    ),
]

# ---------------------------------------------------------------------------
# Scanner
# ---------------------------------------------------------------------------

DEFAULT_ENABLED: set[str] = {
    "credit_card", "ssn", "aws_access_key", "aws_secret_key",
    "github_token", "slack_token", "google_api_key", "generic_api_key",
    "private_key", "connection_string", "azure_key",
    "jwt_token", "openai_api_key", "anthropic_api_key", "gcp_service_account",
    "stripe_api_key", "sendgrid_api_key", "pgp_private_key", "azure_sas_token",
    "gitlab_token", "twilio_api_key", "slack_webhook", "discord_webhook",
    "docker_auth", "credential_assignment",
}


def redact_match(text: str) -> str:
    """Show first 3 + last 3 chars of a match; otherwise `***`."""
    if len(text) <= 8:
        return "***"
    return text[:3] + "***" + text[-3:]


class DLPScanner:
    """
    Scans text for sensitive data patterns.

    Usage:
        scanner = DLPScanner(BUILTIN_PATTERNS)
        findings = scanner.scan("AKIAIOSFODNN7EXAMPLE is my key", "tool_input")
    """

    def __init__(
        self,
        patterns: list[DLPPattern],
        enabled_patterns: set[str] | None = None,
    ) -> None:
        active = enabled_patterns if enabled_patterns is not None else DEFAULT_ENABLED
        self._patterns = [p for p in patterns if p.name in active and p.enabled]

    def scan(self, content: str, location: str) -> list[DLPFinding]:
        """Scan a string for all sensitive patterns. Returns list of findings."""
        if not content or not isinstance(content, str):
            return []

        findings: list[DLPFinding] = []

        for pat in self._patterns:
            for match in pat.pattern.finditer(content):
                matched_text = match.group(0)

                # Run optional validator (e.g. Luhn for credit cards)
                if pat.validator and not pat.validator(matched_text):
                    continue

                findings.append(
                    DLPFinding(
                        pattern=pat.name,
                        severity=pat.severity,
                        location=location,
                        redacted_sample=redact_match(matched_text),
                    )
                )

        return findings

    def scan_dict(self, data: dict, location_prefix: str) -> list[DLPFinding]:
        """Recursively scan all string values in a dict."""
        findings: list[DLPFinding] = []
        for key, value in data.items():
            loc = f"{location_prefix}.{key}"
            if isinstance(value, str):
                findings.extend(self.scan(value, loc))
            elif isinstance(value, dict):
                findings.extend(self.scan_dict(value, loc))
            elif isinstance(value, list):
                for i, item in enumerate(value):
                    if isinstance(item, str):
                        findings.extend(self.scan(item, f"{loc}[{i}]"))
                    elif isinstance(item, dict):
                        findings.extend(self.scan_dict(item, f"{loc}[{i}]"))
        return findings

    def scan_tool_call(
        self,
        tool_name: str,
        parameters: dict,
        result: str | dict | None = None,
    ) -> list[DLPFinding]:
        """
        Scan both the input parameters and optional result of a tool call.
        """
        findings = self.scan_dict(parameters, f"{tool_name}:input")

        if result is not None:
            if isinstance(result, str):
                findings.extend(self.scan(result, f"{tool_name}:output"))
            elif isinstance(result, dict):
                findings.extend(self.scan_dict(result, f"{tool_name}:output"))

        return findings

    @staticmethod
    def max_severity(findings: list[DLPFinding]) -> DLPSeverity | None:
        """Return the highest severity found, or None if no findings."""
        if not findings:
            return None
        return max(findings, key=lambda f: SEVERITY_ORDER.get(f.severity, 0)).severity


# ---------------------------------------------------------------------------
# Module-level singleton
# ---------------------------------------------------------------------------

_scanner: DLPScanner | None = None


def get_dlp_scanner() -> DLPScanner:
    """Return the module-level DLP scanner singleton."""
    global _scanner
    if _scanner is None:
        enabled_names = {p.name for p in BUILTIN_PATTERNS if p.enabled}
        _scanner = DLPScanner(BUILTIN_PATTERNS, enabled_patterns=enabled_names)
    return _scanner
