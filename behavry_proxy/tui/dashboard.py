"""
Terminal TUI Dashboard — Rich/Textual live dashboard.

Shows real-time proxy activity:
- Live tool call table (last N calls with decision, DLP, timing)
- Summary counters (allowed/denied/DLP/inbound)
- OPA health status
- Rate limit activity

Runs alongside the proxy in a separate thread or as a standalone viewer
reading from the audit.jsonl file.
"""
from __future__ import annotations

import asyncio
import json
import time
from datetime import datetime, timezone
from pathlib import Path
from threading import Thread
from typing import Any

from rich.console import Console
from rich.layout import Layout
from rich.live import Live
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from behavry_proxy import __version__


# ---------------------------------------------------------------------------
# Data model
# ---------------------------------------------------------------------------

class DashboardState:
    """Holds current dashboard state — updated by the event feed."""

    def __init__(self, max_events: int = 50) -> None:
        self.max_events = max_events
        self.events: list[dict[str, Any]] = []
        self.total_calls: int = 0
        self.allowed: int = 0
        self.denied: int = 0
        self.dlp_findings: int = 0
        self.inbound_findings: int = 0
        self.passthrough: int = 0
        self.start_time: float = time.monotonic()
        self.opa_healthy: bool | None = None
        self.last_event_time: str = ""

    def add_event(self, event: dict[str, Any]) -> None:
        """Add an audit event to the dashboard state."""
        self.events.append(event)
        if len(self.events) > self.max_events:
            self.events = self.events[-self.max_events:]

        event_type = event.get("event_type", "")
        self.last_event_time = event.get("timestamp", "")

        if event_type == "PASSTHROUGH":
            self.passthrough += 1
            return

        if event_type == "TOOL_CALL":
            self.total_calls += 1
            result = event.get("policy_result", "")
            if result == "allow":
                self.allowed += 1
            elif result in ("deny", "escalate"):
                self.denied += 1

            self.dlp_findings += event.get("dlp_findings_count", 0)
            self.inbound_findings += event.get("inbound_findings_count", 0)

    @property
    def uptime_str(self) -> str:
        elapsed = int(time.monotonic() - self.start_time)
        hours, rem = divmod(elapsed, 3600)
        minutes, seconds = divmod(rem, 60)
        if hours > 0:
            return f"{hours}h {minutes}m {seconds}s"
        elif minutes > 0:
            return f"{minutes}m {seconds}s"
        return f"{seconds}s"

    @property
    def deny_rate(self) -> float:
        if self.total_calls == 0:
            return 0.0
        return (self.denied / self.total_calls) * 100


# ---------------------------------------------------------------------------
# Rendering
# ---------------------------------------------------------------------------

def _severity_color(severity: str | None) -> str:
    """Map severity to Rich color."""
    return {
        "critical": "bold red",
        "high": "red",
        "medium": "yellow",
        "low": "dim",
    }.get(severity or "", "white")


def _result_style(result: str) -> str:
    """Map policy result to Rich style."""
    return {
        "allow": "green",
        "deny": "bold red",
        "escalate": "bold yellow",
        "passthrough": "dim cyan",
    }.get(result, "white")


def render_header(state: DashboardState) -> Panel:
    """Render the header panel with version and status."""
    opa_status = "● connected" if state.opa_healthy else "○ unreachable"
    opa_color = "green" if state.opa_healthy else "red"
    if state.opa_healthy is None:
        opa_status = "○ unknown"
        opa_color = "yellow"

    text = Text()
    text.append("Behavry Proxy ", style="bold white")
    text.append(f"v{__version__}", style="dim")
    text.append("  │  ", style="dim")
    text.append("OPA: ", style="dim")
    text.append(opa_status, style=opa_color)
    text.append("  │  ", style="dim")
    text.append(f"Uptime: {state.uptime_str}", style="dim")

    return Panel(text, style="blue", height=3)


def render_counters(state: DashboardState) -> Panel:
    """Render summary counters."""
    table = Table(show_header=False, box=None, padding=(0, 2))
    table.add_column(justify="center", width=16)
    table.add_column(justify="center", width=16)
    table.add_column(justify="center", width=16)
    table.add_column(justify="center", width=16)
    table.add_column(justify="center", width=16)
    table.add_column(justify="center", width=16)

    table.add_row(
        Text("Tool Calls", style="dim"),
        Text("Allowed", style="dim"),
        Text("Denied", style="dim"),
        Text("Deny Rate", style="dim"),
        Text("DLP Findings", style="dim"),
        Text("Injections", style="dim"),
    )
    table.add_row(
        Text(str(state.total_calls), style="bold white"),
        Text(str(state.allowed), style="bold green"),
        Text(str(state.denied), style="bold red" if state.denied > 0 else "bold white"),
        Text(f"{state.deny_rate:.1f}%", style="yellow" if state.deny_rate > 0 else "white"),
        Text(str(state.dlp_findings), style="bold red" if state.dlp_findings > 0 else "bold white"),
        Text(str(state.inbound_findings), style="bold red" if state.inbound_findings > 0 else "bold white"),
    )

    return Panel(table, title="Summary", style="blue", height=6)


def render_event_table(state: DashboardState) -> Panel:
    """Render the live event table."""
    table = Table(
        show_header=True,
        header_style="bold",
        box=None,
        padding=(0, 1),
        expand=True,
    )
    table.add_column("Time", width=10, style="dim")
    table.add_column("Server", width=14)
    table.add_column("Tool", width=24)
    table.add_column("Decision", width=10)
    table.add_column("Reason", width=36, no_wrap=True)
    table.add_column("DLP", width=6, justify="center")
    table.add_column("Inj", width=6, justify="center")
    table.add_column("ms", width=8, justify="right")

    # Show last 20 events (newest first)
    for event in reversed(state.events[-20:]):
        event_type = event.get("event_type", "")
        if event_type == "PASSTHROUGH":
            table.add_row(
                _format_time(event.get("timestamp", "")),
                event.get("server_id", ""),
                event.get("method", ""),
                Text("pass", style="dim cyan"),
                "",
                "",
                "",
                f"{event.get('latency_ms', 0):.0f}",
            )
            continue

        result = event.get("policy_result", "")
        dlp_count = event.get("dlp_findings_count", 0)
        inbound_count = event.get("inbound_findings_count", 0)

        dlp_text = Text(str(dlp_count), style="red") if dlp_count > 0 else Text("0", style="dim")
        inbound_text = Text(str(inbound_count), style="red") if inbound_count > 0 else Text("0", style="dim")

        reason = event.get("policy_reason", "")
        if len(reason) > 36:
            reason = reason[:33] + "..."

        table.add_row(
            _format_time(event.get("timestamp", "")),
            event.get("server_id", ""),
            event.get("tool_name", ""),
            Text(result, style=_result_style(result)),
            reason,
            dlp_text,
            inbound_text,
            f"{event.get('latency_ms', 0):.0f}",
        )

    return Panel(table, title="Live Tool Calls", style="blue")


def _format_time(iso_timestamp: str) -> str:
    """Format ISO timestamp to HH:MM:SS."""
    try:
        dt = datetime.fromisoformat(iso_timestamp)
        return dt.strftime("%H:%M:%S")
    except (ValueError, TypeError):
        return ""


def render_dashboard(state: DashboardState) -> Layout:
    """Compose the full dashboard layout."""
    layout = Layout()
    layout.split_column(
        Layout(render_header(state), name="header", size=3),
        Layout(render_counters(state), name="counters", size=6),
        Layout(render_event_table(state), name="events"),
    )
    return layout


# ---------------------------------------------------------------------------
# File tail watcher (for standalone mode)
# ---------------------------------------------------------------------------

def tail_audit_file(path: str, state: DashboardState, stop_event: asyncio.Event) -> None:
    """Tail an audit.jsonl file and feed events to the dashboard state."""
    audit_path = Path(path)

    # Wait for file to exist
    while not audit_path.exists() and not stop_event.is_set():
        time.sleep(0.5)

    if stop_event.is_set():
        return

    with open(audit_path) as f:
        # Seek to end to only show new events
        f.seek(0, 2)
        while not stop_event.is_set():
            line = f.readline()
            if line:
                try:
                    event = json.loads(line.strip())
                    state.add_event(event)
                except json.JSONDecodeError:
                    pass
            else:
                time.sleep(0.1)


# ---------------------------------------------------------------------------
# Live dashboard runner
# ---------------------------------------------------------------------------

def run_dashboard(
    audit_file: str = "audit.jsonl",
    refresh_rate: float = 0.5,
) -> None:
    """Run the terminal dashboard, tailing the audit log file.

    This is a blocking call that renders the Rich Live display.
    Press Ctrl+C to exit.
    """
    console = Console()
    state = DashboardState()
    stop_event = asyncio.Event()

    # Start file tailer in background thread
    tailer = Thread(
        target=tail_audit_file,
        args=(audit_file, state, stop_event),
        daemon=True,
    )
    tailer.start()

    try:
        with Live(
            render_dashboard(state),
            console=console,
            refresh_per_second=int(1 / refresh_rate),
            screen=True,
        ) as live:
            while True:
                live.update(render_dashboard(state))
                time.sleep(refresh_rate)
    except KeyboardInterrupt:
        stop_event.set()
        console.print("\n[dim]Dashboard stopped.[/dim]")


# ---------------------------------------------------------------------------
# CLI entry point for standalone dashboard
# ---------------------------------------------------------------------------

def main() -> None:
    """CLI entry point: `python -m behavry_proxy.tui.dashboard [audit_file]`"""
    import sys
    audit_file = sys.argv[1] if len(sys.argv) > 1 else "audit.jsonl"
    run_dashboard(audit_file=audit_file)


if __name__ == "__main__":
    main()
