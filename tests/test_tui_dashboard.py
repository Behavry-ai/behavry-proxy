"""Tests for TUI dashboard state and rendering."""
from behavry_proxy.tui.dashboard import (
    DashboardState,
    render_header,
    render_counters,
    render_event_table,
    render_dashboard,
)


class TestDashboardState:
    def test_initial_state(self):
        state = DashboardState()
        assert state.total_calls == 0
        assert state.allowed == 0
        assert state.denied == 0
        assert state.deny_rate == 0.0

    def test_add_tool_call_allow(self):
        state = DashboardState()
        state.add_event({
            "event_type": "TOOL_CALL",
            "policy_result": "allow",
            "server_id": "github",
            "tool_name": "list_repos",
            "timestamp": "2026-03-23T10:00:00+00:00",
        })
        assert state.total_calls == 1
        assert state.allowed == 1
        assert state.denied == 0

    def test_add_tool_call_deny(self):
        state = DashboardState()
        state.add_event({
            "event_type": "TOOL_CALL",
            "policy_result": "deny",
            "dlp_findings_count": 2,
        })
        assert state.total_calls == 1
        assert state.denied == 1
        assert state.dlp_findings == 2

    def test_add_passthrough(self):
        state = DashboardState()
        state.add_event({"event_type": "PASSTHROUGH"})
        assert state.passthrough == 1
        assert state.total_calls == 0

    def test_deny_rate(self):
        state = DashboardState()
        state.add_event({"event_type": "TOOL_CALL", "policy_result": "allow"})
        state.add_event({"event_type": "TOOL_CALL", "policy_result": "allow"})
        state.add_event({"event_type": "TOOL_CALL", "policy_result": "deny"})
        assert abs(state.deny_rate - 33.33) < 0.1

    def test_max_events_trimmed(self):
        state = DashboardState(max_events=5)
        for i in range(10):
            state.add_event({"event_type": "TOOL_CALL", "policy_result": "allow"})
        assert len(state.events) == 5

    def test_uptime_str(self):
        state = DashboardState()
        assert isinstance(state.uptime_str, str)

    def test_inbound_findings_counted(self):
        state = DashboardState()
        state.add_event({
            "event_type": "TOOL_CALL",
            "policy_result": "deny",
            "inbound_findings_count": 3,
        })
        assert state.inbound_findings == 3


class TestRendering:
    def test_render_header(self):
        state = DashboardState()
        panel = render_header(state)
        assert panel is not None

    def test_render_counters(self):
        state = DashboardState()
        state.add_event({"event_type": "TOOL_CALL", "policy_result": "allow"})
        panel = render_counters(state)
        assert panel is not None

    def test_render_event_table_empty(self):
        state = DashboardState()
        panel = render_event_table(state)
        assert panel is not None

    def test_render_event_table_with_events(self):
        state = DashboardState()
        state.add_event({
            "event_type": "TOOL_CALL",
            "server_id": "github",
            "tool_name": "list_repos",
            "policy_result": "allow",
            "policy_reason": "Read allowed",
            "timestamp": "2026-03-23T10:00:00+00:00",
            "latency_ms": 12.5,
            "dlp_findings_count": 0,
            "inbound_findings_count": 0,
        })
        state.add_event({
            "event_type": "TOOL_CALL",
            "server_id": "filesystem",
            "tool_name": "delete_file",
            "policy_result": "deny",
            "policy_reason": "Destructive operation blocked",
            "timestamp": "2026-03-23T10:00:01+00:00",
            "latency_ms": 5.2,
            "dlp_findings_count": 1,
            "inbound_findings_count": 0,
        })
        panel = render_event_table(state)
        assert panel is not None

    def test_render_dashboard(self):
        state = DashboardState()
        layout = render_dashboard(state)
        assert layout is not None
