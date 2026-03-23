"""
Per-agent sliding window rate limiter.

Uses an in-memory deque per agent to track request timestamps within a
60-second window. No Redis dependency — designed for single-process deployment.

Features:
- Sliding window: count requests in the last 60 seconds
- Burst detection: current_rpm >= hard cap → block immediately
- Spike detection: current_rpm > 3× rolling average AND baseline > MIN_RPM
- Rolling average: exponential weighted moving average updated per request
"""
from __future__ import annotations

import time
from collections import deque
from dataclasses import dataclass

DEFAULT_RPM: int = 60
DEFAULT_BURST: int = 100

SPIKE_MULTIPLIER: float = 3.0
SPIKE_MIN_AVG_RPM: float = 5.0
EWA_ALPHA: float = 0.2
WINDOW_SECONDS: float = 60.0


@dataclass
class RateLimitResult:
    allowed: bool
    current_rpm: float
    avg_rpm: float
    is_spike: bool
    is_burst: bool


class AgentRateLimiter:
    """In-memory per-agent sliding window rate limiter."""

    def __init__(self) -> None:
        self._windows: dict[str, deque[float]] = {}
        self._avg_rpm: dict[str, float] = {}

    def check(
        self,
        agent_id: str,
        rate_limit_rpm: int = DEFAULT_RPM,
        rate_limit_burst: int = DEFAULT_BURST,
    ) -> RateLimitResult:
        now = time.monotonic()
        cutoff = now - WINDOW_SECONDS

        if agent_id not in self._windows:
            self._windows[agent_id] = deque()
            self._avg_rpm[agent_id] = 0.0

        window = self._windows[agent_id]

        while window and window[0] < cutoff:
            window.popleft()

        current_rpm = float(len(window))
        avg_rpm = self._avg_rpm[agent_id]

        if avg_rpm == 0.0:
            self._avg_rpm[agent_id] = current_rpm
        else:
            self._avg_rpm[agent_id] = EWA_ALPHA * current_rpm + (1.0 - EWA_ALPHA) * avg_rpm
        avg_rpm = self._avg_rpm[agent_id]

        is_burst = current_rpm >= rate_limit_burst
        is_spike = (
            avg_rpm >= SPIKE_MIN_AVG_RPM
            and current_rpm > SPIKE_MULTIPLIER * avg_rpm
        )

        if not is_burst:
            window.append(now)

        return RateLimitResult(
            allowed=not is_burst,
            current_rpm=current_rpm,
            avg_rpm=avg_rpm,
            is_spike=is_spike,
            is_burst=is_burst,
        )

    def reset(self, agent_id: str) -> None:
        """Clear all rate state for an agent."""
        self._windows.pop(agent_id, None)
        self._avg_rpm.pop(agent_id, None)


_limiter = AgentRateLimiter()


def get_rate_limiter() -> AgentRateLimiter:
    return _limiter
