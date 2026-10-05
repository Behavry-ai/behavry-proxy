"""Tests for the audit event emitter."""
import json
from pathlib import Path

import pytest

from behavry_proxy.audit.emitter import AuditEmitter, AuditEvent


def _event(**overrides) -> AuditEvent:
    """Build an AuditEvent with the four required fields filled in."""
    fields = {
        "timestamp": 1719792000.0,
        "event_type": "tool_call",
        "agent_id": "agent-1",
        "server_id": "github",
    }
    fields.update(overrides)
    return AuditEvent(**fields)


class TestAuditEvent:
    def test_required_fields_round_trip(self):
        event = _event(tool_name="read_file", policy_result="allow")
        d = event.to_dict()
        assert d["timestamp"] == 1719792000.0
        assert d["event_type"] == "tool_call"
        assert d["agent_id"] == "agent-1"
        assert d["server_id"] == "github"
        assert d["tool_name"] == "read_file"
        assert d["policy_result"] == "allow"

    def test_to_dict_omits_none_optionals(self):
        d = _event().to_dict()
        for key in ("tool_name", "action", "resource", "policy_result", "policy_reason", "policy_id"):
            assert key not in d

    def test_to_dict_keeps_zero_latency(self):
        """0.0 is a real measurement, not a missing value — only None is dropped."""
        d = _event().to_dict()
        assert d["latency_ms"] == 0.0

    def test_to_dict_carries_data_payload(self):
        event = _event(
            event_type="dlp_finding",
            data={
                "findings": [{"pattern": "aws_access_key", "severity": "critical"}],
                "max_severity": "critical",
            },
        )
        d = event.to_dict()
        assert d["data"]["max_severity"] == "critical"
        assert d["data"]["findings"][0]["pattern"] == "aws_access_key"

    def test_data_defaults_to_empty_dict(self):
        assert _event().to_dict()["data"] == {}

    def test_to_json_is_parseable(self):
        parsed = json.loads(_event(tool_name="read_file").to_json())
        assert parsed["tool_name"] == "read_file"
        assert parsed["server_id"] == "github"


class TestAuditEmitter:
    @pytest.fixture
    def log_path(self, tmp_path) -> Path:
        return tmp_path / "audit.jsonl"

    def test_emit_writes_one_json_line_per_event(self, log_path, capsys):
        emitter = AuditEmitter(log_file=str(log_path))
        emitter.emit(_event(tool_name="read_file"))
        emitter.emit(_event(tool_name="write_file"))
        emitter.close()

        lines = log_path.read_text().strip().split("\n")
        assert len(lines) == 2
        assert json.loads(lines[0])["tool_name"] == "read_file"
        assert json.loads(lines[1])["tool_name"] == "write_file"

    def test_emit_also_writes_to_stdout(self, capsys):
        emitter = AuditEmitter()
        emitter.emit(_event(tool_name="read_file"))
        emitter.close()

        out = capsys.readouterr().out.strip()
        assert json.loads(out)["tool_name"] == "read_file"

    def test_creates_parent_directory(self, tmp_path, capsys):
        nested = tmp_path / "logs" / "nested" / "audit.jsonl"
        emitter = AuditEmitter(log_file=str(nested))
        emitter.emit(_event())
        emitter.close()
        assert nested.exists()

    def test_stats_count_total_events(self, capsys):
        emitter = AuditEmitter()
        for _ in range(5):
            emitter.emit(_event())
        assert emitter.get_stats()["total_events"] == 5

    def test_stats_classify_event_types(self, capsys):
        emitter = AuditEmitter()
        emitter.emit(_event(event_type="tool_call"))
        emitter.emit(_event(event_type="tool_deny"))
        emitter.emit(_event(event_type="tool_deny"))
        emitter.emit(_event(event_type="dlp_finding"))
        emitter.emit(_event(event_type="inbound_finding"))

        stats = emitter.get_stats()
        assert stats == {
            "total_events": 5,
            "denials": 2,
            "dlp_findings": 1,
            "inbound_findings": 1,
        }

    def test_stats_start_at_zero(self):
        assert AuditEmitter().get_stats() == {
            "total_events": 0,
            "denials": 0,
            "dlp_findings": 0,
            "inbound_findings": 0,
        }

    def test_close_is_idempotent(self, log_path, capsys):
        emitter = AuditEmitter(log_file=str(log_path))
        emitter.emit(_event())
        emitter.close()
        emitter.close()  # must not raise

    def test_appends_to_existing_file(self, log_path, capsys):
        log_path.write_text('{"pre": "existing"}\n')
        emitter = AuditEmitter(log_file=str(log_path))
        emitter.emit(_event())
        emitter.close()

        lines = log_path.read_text().strip().split("\n")
        assert len(lines) == 2
        assert json.loads(lines[0]) == {"pre": "existing"}
