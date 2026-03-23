"""
Audit Event Emitter.

Emits structured audit events as JSON lines to stdout and optionally to a file.
No database dependency — designed for the open-source proxy.
"""
from __future__ import annotations

import json
import logging
import sys
import time
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)


@dataclass
class AuditEvent:
    """A single audit event from the proxy pipeline."""
    timestamp: float
    event_type: str  # tool_call | tool_deny | tool_escalate | dlp_finding | inbound_finding | rate_limit
    agent_id: str
    server_id: str
    tool_name: str | None = None
    action: str | None = None
    resource: str | None = None
    policy_result: str | None = None
    policy_reason: str | None = None
    policy_id: str | None = None
    latency_ms: float = 0.0
    data: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        # Remove None values for cleaner output
        return {k: v for k, v in d.items() if v is not None}

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), default=str)


class AuditEmitter:
    """
    Emits audit events to stdout (always) and optionally to a JSONL file.
    Thread-safe for asyncio single-thread assumption.
    """

    def __init__(
        self,
        log_file: str | None = None,
        log_format: str = "jsonl",
    ) -> None:
        self._log_format = log_format
        self._file_handle = None
        self._event_count = 0
        self._deny_count = 0
        self._dlp_count = 0
        self._inbound_count = 0

        if log_file:
            path = Path(log_file)
            path.parent.mkdir(parents=True, exist_ok=True)
            self._file_handle = open(path, "a", buffering=1)  # line-buffered
            logger.info("Audit log file: %s", path)

    def emit(self, event: AuditEvent) -> None:
        """Emit an audit event to all configured outputs."""
        self._event_count += 1
        if event.event_type == "tool_deny":
            self._deny_count += 1
        elif event.event_type == "dlp_finding":
            self._dlp_count += 1
        elif event.event_type == "inbound_finding":
            self._inbound_count += 1

        line = event.to_json()

        # Always emit to stdout
        print(line, file=sys.stdout, flush=True)

        # Optionally write to file
        if self._file_handle:
            self._file_handle.write(line + "\n")

    def get_stats(self) -> dict[str, int]:
        """Return event counters for the health/metrics endpoint."""
        return {
            "total_events": self._event_count,
            "denials": self._deny_count,
            "dlp_findings": self._dlp_count,
            "inbound_findings": self._inbound_count,
        }

    def close(self) -> None:
        if self._file_handle:
            self._file_handle.close()
            self._file_handle = None


# Singleton
_emitter: AuditEmitter | None = None


def get_emitter() -> AuditEmitter:
    global _emitter
    if _emitter is None:
        from behavry_proxy.config import get_config
        cfg = get_config()
        _emitter = AuditEmitter(
            log_file=cfg.audit_log_file,
            log_format=cfg.audit_log_format,
        )
    return _emitter
