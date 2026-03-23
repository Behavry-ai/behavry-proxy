"""
Health and metrics endpoints — Prometheus text format.

Provides:
  GET /health      — liveness check (200 OK)
  GET /metrics     — Prometheus-compatible counters

Counters tracked:
  behavry_proxy_tool_calls_total        — total tool calls processed
  behavry_proxy_tool_calls_allowed      — tool calls allowed
  behavry_proxy_tool_calls_denied       — tool calls denied
  behavry_proxy_dlp_findings_total      — DLP findings detected
  behavry_proxy_inbound_findings_total  — inbound injection findings detected
  behavry_proxy_opa_errors_total        — OPA communication errors
  behavry_proxy_opa_latency_seconds     — OPA decision latency (sum + count for avg)
"""
from __future__ import annotations

import time
from dataclasses import dataclass, field
from threading import Lock


@dataclass
class ProxyMetrics:
    """Thread-safe in-memory metrics counters."""

    _lock: Lock = field(default_factory=Lock, repr=False)

    tool_calls_total: int = 0
    tool_calls_allowed: int = 0
    tool_calls_denied: int = 0
    dlp_findings_total: int = 0
    inbound_findings_total: int = 0
    opa_errors_total: int = 0
    opa_latency_sum: float = 0.0
    opa_latency_count: int = 0
    rate_limit_hits: int = 0
    passthrough_total: int = 0

    def record_tool_call(self, allowed: bool) -> None:
        with self._lock:
            self.tool_calls_total += 1
            if allowed:
                self.tool_calls_allowed += 1
            else:
                self.tool_calls_denied += 1

    def record_dlp_findings(self, count: int) -> None:
        with self._lock:
            self.dlp_findings_total += count

    def record_inbound_findings(self, count: int) -> None:
        with self._lock:
            self.inbound_findings_total += count

    def record_opa_error(self) -> None:
        with self._lock:
            self.opa_errors_total += 1

    def record_opa_latency(self, seconds: float) -> None:
        with self._lock:
            self.opa_latency_sum += seconds
            self.opa_latency_count += 1

    def record_rate_limit_hit(self) -> None:
        with self._lock:
            self.rate_limit_hits += 1

    def record_passthrough(self) -> None:
        with self._lock:
            self.passthrough_total += 1

    def to_prometheus(self) -> str:
        """Render metrics in Prometheus text exposition format."""
        with self._lock:
            lines = [
                "# HELP behavry_proxy_tool_calls_total Total tool calls processed",
                "# TYPE behavry_proxy_tool_calls_total counter",
                f"behavry_proxy_tool_calls_total {self.tool_calls_total}",
                "",
                "# HELP behavry_proxy_tool_calls_allowed Tool calls allowed by policy",
                "# TYPE behavry_proxy_tool_calls_allowed counter",
                f"behavry_proxy_tool_calls_allowed {self.tool_calls_allowed}",
                "",
                "# HELP behavry_proxy_tool_calls_denied Tool calls denied by policy",
                "# TYPE behavry_proxy_tool_calls_denied counter",
                f"behavry_proxy_tool_calls_denied {self.tool_calls_denied}",
                "",
                "# HELP behavry_proxy_dlp_findings_total DLP findings detected",
                "# TYPE behavry_proxy_dlp_findings_total counter",
                f"behavry_proxy_dlp_findings_total {self.dlp_findings_total}",
                "",
                "# HELP behavry_proxy_inbound_findings_total Inbound injection findings detected",
                "# TYPE behavry_proxy_inbound_findings_total counter",
                f"behavry_proxy_inbound_findings_total {self.inbound_findings_total}",
                "",
                "# HELP behavry_proxy_opa_errors_total OPA communication errors",
                "# TYPE behavry_proxy_opa_errors_total counter",
                f"behavry_proxy_opa_errors_total {self.opa_errors_total}",
                "",
                "# HELP behavry_proxy_opa_latency_seconds_sum OPA decision latency sum",
                "# TYPE behavry_proxy_opa_latency_seconds_sum counter",
                f"behavry_proxy_opa_latency_seconds_sum {self.opa_latency_sum:.6f}",
                "",
                "# HELP behavry_proxy_opa_latency_seconds_count OPA decision count",
                "# TYPE behavry_proxy_opa_latency_seconds_count counter",
                f"behavry_proxy_opa_latency_seconds_count {self.opa_latency_count}",
                "",
                "# HELP behavry_proxy_rate_limit_hits_total Rate limit rejections",
                "# TYPE behavry_proxy_rate_limit_hits_total counter",
                f"behavry_proxy_rate_limit_hits_total {self.rate_limit_hits}",
                "",
                "# HELP behavry_proxy_passthrough_total Non-tool-call requests passed through",
                "# TYPE behavry_proxy_passthrough_total counter",
                f"behavry_proxy_passthrough_total {self.passthrough_total}",
                "",
            ]
            return "\n".join(lines)


# ---------------------------------------------------------------------------
# Module-level singleton
# ---------------------------------------------------------------------------

_metrics = ProxyMetrics()


def get_metrics() -> ProxyMetrics:
    return _metrics
