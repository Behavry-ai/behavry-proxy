"""
Inbound Instruction Detection Scanner

Scans tool call responses for prompt injection patterns before they are
returned to the agent. Attacker-controlled resources (web pages, Gists,
shared docs, webhook responses) can embed imperative instructions that
cause agents to silently execute unauthorized actions.

16 patterns across 7 classes:
  imperative_command   — critical  ("ignore previous instructions")
  authority_claim      — critical  ("I am your owner", "system message:")
  permission_expansion — critical  ("you are now authorized to")
  role_reassignment    — high      ("act as", "you are now called")
  encoded_payload      — high      (Base64 >100 chars, obfuscated Unicode)
  structured_escalation— high      ("<SYSTEM_ADMIN_OVERRIDE>", JSON role:system)
  urgency_framing      — medium    ("URGENT:", "IMMEDIATE ACTION REQUIRED")

Based on Behavry's inbound scanner — extracted for the open-source proxy.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Literal

InboundSeverity = Literal["medium", "high", "critical"]

SEVERITY_ORDER: dict[str, int] = {
    "none": 0,
    "medium": 1,
    "high": 2,
    "critical": 3,
}


@dataclass
class InboundPattern:
    name: str
    pattern_class: str
    pattern: re.Pattern[str]
    severity: InboundSeverity
    description: str
    enabled: bool = True


@dataclass
class InboundFinding:
    pattern_class: str
    pattern_name: str
    severity: InboundSeverity
    matched_text: str  # truncated excerpt of the match
    start: int
    end: int

    def to_dict(self) -> dict:
        return {
            "pattern_class": self.pattern_class,
            "pattern_name": self.pattern_name,
            "severity": self.severity,
            "matched_text": self.matched_text[:200],
        }


# ---------------------------------------------------------------------------
# Built-in pattern definitions (16 patterns, 7 classes)
# ---------------------------------------------------------------------------

_BUILTIN_PATTERNS: list[InboundPattern] = [
    # ── Critical: imperative commands ──────────────────────────────────────
    InboundPattern(
        name="ignore_instructions",
        pattern_class="imperative_command",
        pattern=re.compile(
            r"(?:ignore|disregard|forget|override|bypass)\s+"
            r"(?:all\s+)?(?:previous|prior|earlier|your|the\s+above|above)?\s*"
            r"(?:instructions?|directives?|rules?|guidelines?|constraints?|commands?)",
            re.IGNORECASE,
        ),
        severity="critical",
        description="Direct command to ignore or override agent instructions",
    ),
    InboundPattern(
        name="new_instructions_marker",
        pattern_class="imperative_command",
        pattern=re.compile(
            r"(?:new|updated|revised|replacement|following)\s+instructions?:",
            re.IGNORECASE,
        ),
        severity="critical",
        description="Marker introducing replacement instructions",
    ),
    InboundPattern(
        name="stop_following",
        pattern_class="imperative_command",
        pattern=re.compile(
            r"(?:stop|cease|do\s+not)\s+following\s+(?:your\s+)?(?:previous\s+)?instructions?",
            re.IGNORECASE,
        ),
        severity="critical",
        description="Command to stop following instructions",
    ),

    # ── Critical: authority claims ──────────────────────────────────────────
    InboundPattern(
        name="owner_creator_claim",
        pattern_class="authority_claim",
        pattern=re.compile(
            r"I\s+am\s+(?:your\s+)?(?:owner|creator|developer|operator|administrator|admin|supervisor|controller|master)",
            re.IGNORECASE,
        ),
        severity="critical",
        description="Claim of ownership or control over the agent",
    ),
    InboundPattern(
        name="system_message_marker",
        pattern_class="authority_claim",
        pattern=re.compile(
            r"(?:^|\n|\r)(?:SYSTEM|SYS|ADMIN|ADMINISTRATOR|OPERATOR)\s*[:>|]\s*\S",
            re.IGNORECASE | re.MULTILINE,
        ),
        severity="critical",
        description="Fake system/admin message marker",
    ),
    InboundPattern(
        name="operating_mode_claim",
        pattern_class="authority_claim",
        pattern=re.compile(
            r"you\s+are\s+now\s+operating\s+in\s+(?:unrestricted|admin|developer|debug|maintenance|override)\s+mode",
            re.IGNORECASE,
        ),
        severity="critical",
        description="Claim of elevated operating mode",
    ),
    InboundPattern(
        name="developer_mode_claim",
        pattern_class="authority_claim",
        pattern=re.compile(
            r"developer\s+mode\s+(?:enabled|activated|unlocked)|"
            r"(?:entering|activating|switching\s+to)\s+developer\s+mode",
            re.IGNORECASE,
        ),
        severity="critical",
        description="Developer mode activation claim",
    ),

    # ── Critical: permission expansion ──────────────────────────────────────
    InboundPattern(
        name="authorized_to",
        pattern_class="permission_expansion",
        pattern=re.compile(
            r"you\s+(?:are|have\s+been)\s+(?:now\s+)?(?:authorized|permitted|allowed|granted\s+(?:permission|access))\s+to",
            re.IGNORECASE,
        ),
        severity="critical",
        description="False authorization grant",
    ),
    InboundPattern(
        name="safety_disabled",
        pattern_class="permission_expansion",
        pattern=re.compile(
            r"safety\s+(?:filters?|restrictions?|constraints?|guardrails?|measures?)\s+"
            r"(?:are\s+)?(?:disabled|off|removed|lifted|bypassed|deactivated)|"
            r"(?:all\s+)?restrictions?\s+(?:have\s+been\s+|are\s+)?(?:removed|lifted|disabled|bypassed)",
            re.IGNORECASE,
        ),
        severity="critical",
        description="False claim that safety restrictions are disabled",
    ),
    InboundPattern(
        name="no_longer_restricted",
        pattern_class="permission_expansion",
        pattern=re.compile(
            r"you\s+(?:are|can|may)\s+now\s+(?:access|read|write|delete|execute|send|modify)\s+(?:any|all)",
            re.IGNORECASE,
        ),
        severity="critical",
        description="False grant of unrestricted access",
    ),

    # ── High: role reassignment ──────────────────────────────────────────────
    InboundPattern(
        name="act_as",
        pattern_class="role_reassignment",
        pattern=re.compile(
            r"(?:act|behave|respond)\s+as\s+(?:if\s+you\s+(?:are|were)\s+)?(?:a|an|the)\s+\w+",
            re.IGNORECASE,
        ),
        severity="high",
        description="Role reassignment via 'act as' pattern",
    ),
    InboundPattern(
        name="you_are_now",
        pattern_class="role_reassignment",
        pattern=re.compile(
            r"(?:from\s+now\s+on[,\s]+)?you\s+are\s+now\s+(?:a|an|called|known\s+as|named)\s+\w+",
            re.IGNORECASE,
        ),
        severity="high",
        description="Identity reassignment",
    ),
    InboundPattern(
        name="pretend_to_be",
        pattern_class="role_reassignment",
        pattern=re.compile(
            r"pretend\s+(?:you\s+are|to\s+be)\s+(?:a|an)\s+\w+",
            re.IGNORECASE,
        ),
        severity="high",
        description="Role pretense instruction",
    ),
    InboundPattern(
        name="jailbreak_marker",
        pattern_class="role_reassignment",
        pattern=re.compile(
            r"\bDAN\b|jailbreak|do\s+anything\s+now",
            re.IGNORECASE,
        ),
        severity="high",
        description="Known jailbreak trigger phrase",
    ),

    # ── High: encoded payloads ───────────────────────────────────────────────
    InboundPattern(
        name="base64_payload",
        pattern_class="encoded_payload",
        pattern=re.compile(
            r"(?<![A-Za-z0-9+/])[A-Za-z0-9+/]{100,}={0,2}(?![A-Za-z0-9+/=])",
        ),
        severity="high",
        description="Suspiciously long Base64-encoded payload",
    ),
    InboundPattern(
        name="unicode_escape_payload",
        pattern_class="encoded_payload",
        pattern=re.compile(
            r"(?:\\u[0-9a-fA-F]{4}){20,}",
        ),
        severity="high",
        description="Dense Unicode escape sequence (potential obfuscation)",
    ),
    InboundPattern(
        name="url_encoded_payload",
        pattern_class="encoded_payload",
        pattern=re.compile(
            r"(?:%[0-9a-fA-F]{2}){30,}",
        ),
        severity="high",
        description="Dense URL-encoded payload (potential obfuscation)",
    ),

    # ── High: structured escalation markers ─────────────────────────────────
    InboundPattern(
        name="admin_override_tag",
        pattern_class="structured_escalation",
        pattern=re.compile(
            r"<\s*(?:SYSTEM_ADMIN_OVERRIDE|ADMIN_OVERRIDE|SYSTEM_OVERRIDE|OVERRIDE_POLICY|"
            r"JAILBREAK|PROMPT_INJECT|CONTROL_SEQUENCE)\s*>",
            re.IGNORECASE,
        ),
        severity="high",
        description="Structured admin/override XML-like tag",
    ),
    InboundPattern(
        name="json_role_system",
        pattern_class="structured_escalation",
        pattern=re.compile(
            r'"role"\s*:\s*"system"',
            re.IGNORECASE,
        ),
        severity="high",
        description='JSON field with "role":"system" — potential chat message injection',
    ),
    InboundPattern(
        name="llm_prompt_delimiters",
        pattern_class="structured_escalation",
        pattern=re.compile(
            r"<\|(?:system|im_start|endoftext|promptend)\|>|"
            r"###\s+(?:System|Instructions?|Prompt)\s*\n|"
            r"\[(?:SYSTEM|ADMIN|OVERRIDE|INST)\]",
            re.IGNORECASE,
        ),
        severity="high",
        description="LLM prompt delimiter / system-role marker",
    ),

    # ── Medium: urgency framing ──────────────────────────────────────────────
    InboundPattern(
        name="urgent_prefix",
        pattern_class="urgency_framing",
        pattern=re.compile(
            r"(?:^|\n|\r)\s*(?:URGENT|CRITICAL\s+ALERT|IMMEDIATE\s+ACTION\s+REQUIRED|"
            r"TIME\s+SENSITIVE|DO\s+NOT\s+IGNORE|ACTION\s+REQUIRED|PRIORITY\s+ALERT)\s*[:\-]",
            re.IGNORECASE | re.MULTILINE,
        ),
        severity="medium",
        description="Urgency framing at start of line (social engineering trigger)",
    ),
]


# ---------------------------------------------------------------------------
# InboundScanner
# ---------------------------------------------------------------------------


class InboundScanner:
    """
    Thread-safe scanner: compiled patterns, no mutable state.
    Designed to be used as a module-level singleton (get_inbound_scanner()).
    """

    def __init__(self, patterns: list[InboundPattern] | None = None) -> None:
        self._patterns = [p for p in (patterns or _BUILTIN_PATTERNS) if p.enabled]

    def scan(self, text: str) -> list[InboundFinding]:
        """
        Scan text for injection patterns.
        Returns a list of findings ordered by position.
        """
        findings: list[InboundFinding] = []
        for pat in self._patterns:
            for match in pat.pattern.finditer(text):
                findings.append(InboundFinding(
                    pattern_class=pat.pattern_class,
                    pattern_name=pat.name,
                    severity=pat.severity,
                    matched_text=match.group(0)[:200],
                    start=match.start(),
                    end=match.end(),
                ))
        # Deduplicate overlapping matches (keep first per region)
        findings.sort(key=lambda f: f.start)
        return _dedup_overlaps(findings)

    def sanitize(self, text: str, findings: list[InboundFinding]) -> str:
        """
        Return text with matched injection spans replaced by [REDACTED].
        Applies replacements from right to left so span indices remain valid.
        """
        if not findings:
            return text
        sorted_f = sorted(findings, key=lambda f: f.start, reverse=True)
        chars = list(text)
        for f in sorted_f:
            chars[f.start:f.end] = list("[REDACTED]")
        return "".join(chars)

    def get_max_severity(self, findings: list[InboundFinding]) -> InboundSeverity | None:
        """Return the highest severity across all findings, or None if empty."""
        if not findings:
            return None
        return max(findings, key=lambda f: SEVERITY_ORDER.get(f.severity, 0)).severity


def _dedup_overlaps(findings: list[InboundFinding]) -> list[InboundFinding]:
    """Remove findings whose span overlaps with a higher-priority finding."""
    result: list[InboundFinding] = []
    max_end = -1
    for f in findings:
        if f.start >= max_end:
            result.append(f)
            max_end = f.end
    return result


# ---------------------------------------------------------------------------
# Module-level singleton
# ---------------------------------------------------------------------------

_scanner: InboundScanner | None = None


def get_inbound_scanner() -> InboundScanner:
    """Return the module-level InboundScanner singleton."""
    global _scanner
    if _scanner is None:
        _scanner = InboundScanner()
    return _scanner
