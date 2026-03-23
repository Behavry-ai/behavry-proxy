"""Tests for audit event emitter."""
import json
import tempfile
from pathlib import Path

from behavry_proxy.audit.emitter import AuditEvent, AuditEmitter


class TestAuditEvent:
    def test_defaults(self):
        event = AuditEvent()
        assert event.event_type == "TOOL_CALL"
        assert event.event_id  # UUID generated
        assert event.timestamp  # ISO timestamp generated

    def test_to_dict_minimal(self):
        event = AuditEvent(
            server_id="github",
            tool_name="read_file",
            policy_result="allow",
        )
        d = event.to_dict()
        assert d["server_id"] == "github"
        assert d["tool_name"] == "read_file"
        assert d["policy_result"] == "allow"
        assert "dlp_findings_count" not in d  # omitted when 0
        assert "inbound_findings_count" not in d

    def test_to_dict_with_dlp(self):
        event = AuditEvent(
            dlp_findings_count=2,
            dlp_max_severity="critical",
            dlp_findings=[{"pattern": "aws_access_key", "severity": "critical"}],
        )
        d = event.to_dict()
        assert d["dlp_findings_count"] == 2
        assert d["dlp_max_severity"] == "critical"

    def test_to_dict_with_extra(self):
        event = AuditEvent(extra={"custom_field": "value"})
        d = event.to_dict()
        assert d["extra"]["custom_field"] == "value"

    def test_to_dict_no_extra_when_empty(self):
        event = AuditEvent()
        d = event.to_dict()
        assert "extra" not in d


class TestAuditEmitter:
    def test_emit_to_file(self):
        with tempfile.NamedTemporaryFile(mode="w", suffix=".jsonl", delete=False) as f:
            path = f.name

        emitter = AuditEmitter(log_file=path, log_stdout=False)
        emitter.start()

        event = AuditEvent(
            server_id="test",
            tool_name="read_file",
            policy_result="allow",
        )
        emitter.emit(event)
        emitter.stop()

        content = Path(path).read_text()
        lines = content.strip().split("\n")
        assert len(lines) == 1

        parsed = json.loads(lines[0])
        assert parsed["server_id"] == "test"
        assert parsed["tool_name"] == "read_file"

    def test_event_count(self):
        with tempfile.NamedTemporaryFile(suffix=".jsonl", delete=False) as f:
            path = f.name

        emitter = AuditEmitter(log_file=path, log_stdout=False)
        emitter.start()

        for _ in range(5):
            emitter.emit(AuditEvent())

        assert emitter.event_count == 5
        emitter.stop()
