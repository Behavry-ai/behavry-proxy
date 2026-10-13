"""Tests for audit event emitter."""
import json
import time

from behavry_proxy.audit.emitter import AuditEmitter, AuditEvent


def _event(**overrides):
    """An AuditEvent with the four required fields filled in."""
    fields = {
        "timestamp": time.time(),
        "event_type": "tool_call",
        "agent_id": "test-agent",
        "server_id": "github",
    }
    fields.update(overrides)
    return AuditEvent(**fields)


class TestAuditEvent:
    def test_required_fields(self):
        event = _event()
        assert event.event_type == "tool_call"
        assert event.agent_id == "test-agent"
        assert event.server_id == "github"
        assert event.timestamp > 0

    def test_to_dict_minimal(self):
        event = _event(tool_name="read_file", policy_result="allow")
        d = event.to_dict()
        assert d["server_id"] == "github"
        assert d["tool_name"] == "read_file"
        assert d["policy_result"] == "allow"
        # Unset optional fields are dropped rather than serialized as null.
        assert "action" not in d
        assert "resource" not in d

    def test_to_dict_with_data(self):
        event = _event(
            event_type="dlp_finding",
            data={
                "max_severity": "critical",
                "findings": [{"pattern": "aws_access_key", "severity": "critical"}],
            },
        )
        d = event.to_dict()
        assert d["data"]["max_severity"] == "critical"
        assert d["data"]["findings"][0]["severity"] == "critical"

    def test_to_json_roundtrips(self):
        event = _event(tool_name="read_file", latency_ms=12.5)
        parsed = json.loads(event.to_json())
        assert parsed["tool_name"] == "read_file"
        assert parsed["latency_ms"] == 12.5


class TestAuditEmitter:
    def test_emit_to_file(self, tmp_path):
        path = tmp_path / "audit.jsonl"
        emitter = AuditEmitter(log_file=str(path))

        emitter.emit(_event(tool_name="read_file", policy_result="allow"))
        emitter.close()

        lines = path.read_text().strip().split("\n")
        assert len(lines) == 1

        parsed = json.loads(lines[0])
        assert parsed["server_id"] == "github"
        assert parsed["tool_name"] == "read_file"

    def test_creates_parent_directory(self, tmp_path):
        path = tmp_path / "nested" / "dir" / "audit.jsonl"
        emitter = AuditEmitter(log_file=str(path))
        emitter.emit(_event())
        emitter.close()
        assert path.is_file()

    def test_stats_counts_events(self):
        emitter = AuditEmitter()
        for _ in range(5):
            emitter.emit(_event())
        assert emitter.get_stats()["total_events"] == 5

    def test_stats_counts_denials_and_findings(self):
        emitter = AuditEmitter()
        emitter.emit(_event(event_type="tool_call"))
        emitter.emit(_event(event_type="tool_deny"))
        emitter.emit(_event(event_type="dlp_finding"))
        emitter.emit(_event(event_type="inbound_finding"))

        stats = emitter.get_stats()
        assert stats["total_events"] == 4
        assert stats["denials"] == 1
        assert stats["dlp_findings"] == 1
        assert stats["inbound_findings"] == 1

    def test_escalation_counts_as_a_denial(self):
        """The OSS proxy enforces escalate as deny, so stats must agree."""
        emitter = AuditEmitter()
        emitter.emit(_event(event_type="tool_escalate"))
        assert emitter.get_stats()["denials"] == 1

    def test_no_file_handle_without_log_file(self):
        emitter = AuditEmitter()
        emitter.emit(_event())
        emitter.close()  # must not raise
        assert emitter.get_stats()["total_events"] == 1


class TestEmitterFileHandling:
    """Durability details of the JSONL sink, which runs for the life of the proxy."""

    def test_appends_to_existing_file(self, tmp_path, capsys):
        path = tmp_path / "audit.jsonl"
        path.write_text('{"pre": "existing"}\n')

        emitter = AuditEmitter(log_file=str(path))
        emitter.emit(_event())
        emitter.close()

        lines = path.read_text().strip().split("\n")
        assert len(lines) == 2, "a restart must not truncate the existing audit log"
        assert json.loads(lines[0]) == {"pre": "existing"}

    def test_creates_parent_directory(self, tmp_path, capsys):
        nested = tmp_path / "logs" / "deep" / "audit.jsonl"

        emitter = AuditEmitter(log_file=str(nested))
        emitter.emit(_event())
        emitter.close()

        assert nested.exists()

    def test_close_is_idempotent(self, tmp_path, capsys):
        emitter = AuditEmitter(log_file=str(tmp_path / "audit.jsonl"))
        emitter.emit(_event())
        emitter.close()
        emitter.close()  # a second shutdown must not raise

    def test_emit_writes_to_stdout(self, capsys):
        emitter = AuditEmitter()
        emitter.emit(_event(tool_name="read_file"))
        emitter.close()

        assert json.loads(capsys.readouterr().out.strip())["tool_name"] == "read_file"


class TestAuditEventSerialisation:
    def test_zero_latency_is_kept_not_dropped(self):
        """0.0 is a real measurement; only None is filtered out of to_dict()."""
        assert _event(latency_ms=0.0).to_dict()["latency_ms"] == 0.0

    def test_data_defaults_to_empty_dict(self):
        assert _event().to_dict()["data"] == {}
