"""Tests for Prometheus metrics."""
from behavry_proxy.metrics import ProxyMetrics


class TestProxyMetrics:
    def setup_method(self):
        self.metrics = ProxyMetrics()

    def test_record_tool_call_allowed(self):
        self.metrics.record_tool_call(allowed=True)
        assert self.metrics.tool_calls_total == 1
        assert self.metrics.tool_calls_allowed == 1
        assert self.metrics.tool_calls_denied == 0

    def test_record_tool_call_denied(self):
        self.metrics.record_tool_call(allowed=False)
        assert self.metrics.tool_calls_total == 1
        assert self.metrics.tool_calls_denied == 1

    def test_record_dlp_findings(self):
        self.metrics.record_dlp_findings(3)
        assert self.metrics.dlp_findings_total == 3

    def test_record_inbound_findings(self):
        self.metrics.record_inbound_findings(2)
        assert self.metrics.inbound_findings_total == 2

    def test_record_opa_latency(self):
        self.metrics.record_opa_latency(0.015)
        assert self.metrics.opa_latency_count == 1
        assert abs(self.metrics.opa_latency_sum - 0.015) < 0.001

    def test_prometheus_format(self):
        self.metrics.record_tool_call(allowed=True)
        self.metrics.record_tool_call(allowed=False)
        self.metrics.record_dlp_findings(5)

        output = self.metrics.to_prometheus()
        assert "behavry_proxy_tool_calls_total 2" in output
        assert "behavry_proxy_tool_calls_allowed 1" in output
        assert "behavry_proxy_tool_calls_denied 1" in output
        assert "behavry_proxy_dlp_findings_total 5" in output
        assert "# HELP" in output
        assert "# TYPE" in output
