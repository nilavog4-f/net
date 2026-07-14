#!/usr/bin/env python3
"""
VOID PING - Server ping / stability checker

Pings any IP or hostname and reports latency + connection stability.
Works on regular servers AND game servers (e.g. Minecraft, port 25565)
where raw ICMP ping is often blocked by the host's firewall - in that
case just pass --port to switch to TCP latency mode.

Usage:
    python ping_tool.py <ip_or_host>                # ICMP ping (like normal ping)
    python ping_tool.py <ip_or_host> --port 25565    # TCP ping (works on Minecraft servers)
    python ping_tool.py <ip_or_host> -c 20           # custom ping count

Legit dual-use network diagnostic tool. No exploitation, no attack traffic.
"""

import argparse
import platform
import re
import socket
import statistics
import subprocess
import sys
import time

from rich.console import Console, Group
from rich.live import Live
from rich.panel import Panel
from rich.table import Table
from rich.text import Text
from rich.align import Align

try:
    import pyfiglet
    HAS_FIGLET = True
except ImportError:
    HAS_FIGLET = False

console = Console()

IS_WINDOWS = platform.system().lower() == "windows"


def banner():
    if HAS_FIGLET:
        text = pyfiglet.figlet_format("VOID PING", font="slant")
        console.print(Text(text, style="bold cyan"))
    else:
        console.print(Text("VOID PING", style="bold cyan"))
    console.print(Align.center("[dim]server latency & stability checker[/dim]\n"))


def resolve_host(host: str) -> str | None:
    try:
        return socket.gethostbyname(host)
    except socket.gaierror:
        return None


def icmp_ping_once(host: str, timeout_s: float = 2.0) -> float | None:
    """Run one OS-level ICMP ping and parse the round-trip time in ms."""
    if IS_WINDOWS:
        cmd = ["ping", "-n", "1", "-w", str(int(timeout_s * 1000)), host]
    else:
        cmd = ["ping", "-c", "1", "-W", str(max(1, int(timeout_s))), host]

    try:
        result = subprocess.run(
            cmd, capture_output=True, text=True, timeout=timeout_s + 1
        )
    except Exception:
        return None

    if result.returncode != 0:
        return None

    match = re.search(r"time[=<]([\d.]+)", result.stdout)
    if match:
        return float(match.group(1))
    return None


def tcp_ping_once(host: str, port: int, timeout_s: float = 2.0) -> float | None:
    """Open a TCP connection and time the handshake, in ms. Works through
    firewalls that block ICMP but allow the game/service port (Minecraft
    servers almost always fall in this category)."""
    start = time.perf_counter()
    try:
        with socket.create_connection((host, port), timeout=timeout_s):
            pass
    except (socket.timeout, OSError):
        return None
    return (time.perf_counter() - start) * 1000


def classify_stability(loss_pct: float, jitter_ms: float, avg_ms: float | None) -> tuple[str, str]:
    """Return (label, rich color style) for the connection quality."""
    if avg_ms is None or loss_pct >= 80:
        return "UNREACHABLE", "bold red"
    if loss_pct == 0 and jitter_ms < 15 and avg_ms < 100:
        return "STABLE", "bold green"
    if loss_pct <= 5 and jitter_ms < 40 and avg_ms < 250:
        return "STABLE", "bold green"
    if loss_pct <= 20 and jitter_ms < 100:
        return "UNSTABLE", "bold yellow"
    return "VERY UNSTABLE", "bold red"


def ping_quality_tag(ms: float | None) -> tuple[str, str]:
    if ms is None:
        return "TIMEOUT", "red"
    if ms < 50:
        return "excellent", "green"
    if ms < 100:
        return "good", "green"
    if ms < 150:
        return "okay", "yellow"
    if ms < 300:
        return "laggy", "yellow"
    return "bad", "red"


def build_table(rows: list[tuple[int, float | None]], mode: str) -> Table:
    table = Table(title=f"Ping results ({mode})", expand=False)
    table.add_column("#", justify="right", style="dim")
    table.add_column("Latency", justify="right")
    table.add_column("Quality", justify="center")
    for seq, ms in rows:
        if ms is None:
            table.add_row(str(seq), "-", Text("timeout", style="red"))
        else:
            tag, color = ping_quality_tag(ms)
            table.add_row(str(seq), f"{ms:.0f} ms", Text(tag, style=color))
    return table


class FloodDetector:
    """Watches the live ping stream for a sudden onset of heavy loss/latency
    spikes after an established stable baseline - the signature of a target
    getting flooded (DDoS'd) or its link getting saturated, as opposed to it
    just always being a bit laggy from the start."""

    BASELINE_SAMPLES = 5
    WINDOW = 8
    SPIKE_MULTIPLIER = 4.0
    MIN_SPIKE_MS = 40.0

    def __init__(self):
        self.baseline_ms: float | None = None
        self.under_attack = False
        self.ever_flagged = False
        self.first_flag_seq: int | None = None

    def _is_spike(self, ms: float | None) -> bool:
        if self.baseline_ms is None:
            return False
        if ms is None:
            return True
        threshold = max(self.baseline_ms * self.SPIKE_MULTIPLIER, self.baseline_ms + self.MIN_SPIKE_MS)
        return ms > threshold

    def update(self, rows: list[tuple[int, float | None]]) -> str:
        """Feed the full rows list so far, return current status label."""
        successes = [ms for _, ms in rows if ms is not None]

        if self.baseline_ms is None and len(successes) >= self.BASELINE_SAMPLES:
            # Lock in the baseline from the first clean samples only, before
            # any spikes could have skewed it.
            self.baseline_ms = statistics.median(successes[: self.BASELINE_SAMPLES])

        if self.baseline_ms is None:
            return "WARMING UP"

        window = rows[-self.WINDOW:]
        if len(window) < 4:
            return "STABLE" if not self.under_attack else "UNDER ATTACK"

        spikes = sum(1 for _, ms in window if self._is_spike(ms))
        spike_ratio = spikes / len(window)

        if spike_ratio >= 0.5:
            if not self.under_attack:
                self.first_flag_seq = rows[-1][0]
            self.under_attack = True
            self.ever_flagged = True
        elif spike_ratio <= 0.2:
            # Recovered - stop showing the alert, but remember it happened
            self.under_attack = False

        return "UNDER ATTACK" if self.under_attack else "STABLE"


def build_status_banner(status: str) -> Text | None:
    if status == "UNDER ATTACK":
        return Text(
            "  \u26a0  POSSIBLE FLOOD / DDoS DETECTED - sudden heavy packet loss & latency spikes  \u26a0  ",
            style="bold white on red",
            justify="center",
        )
    return None


def summarize(
    host: str,
    target_display: str,
    rows: list[tuple[int, float | None]],
    mode: str,
    detector: "FloodDetector | None" = None,
    interrupted: bool = False,
):
    successes = [ms for _, ms in rows if ms is not None]
    total = len(rows)
    lost = total - len(successes)
    loss_pct = (lost / total * 100) if total else 100.0

    avg_ms = statistics.mean(successes) if successes else None
    min_ms = min(successes) if successes else None
    max_ms = max(successes) if successes else None
    jitter_ms = statistics.pstdev(successes) if len(successes) > 1 else 0.0

    label, style = classify_stability(loss_pct, jitter_ms, avg_ms)
    flood_detected = bool(detector and detector.ever_flagged)

    lines = [f"[bold]Target:[/bold] {target_display}"]
    if interrupted:
        lines.append(f"[bold]Pings sent:[/bold] {total} [dim](stopped early with Ctrl+C)[/dim]")
    if avg_ms is not None:
        lines.append(f"[bold]Average ping:[/bold] {avg_ms:.0f} ms")
        lines.append(f"[bold]Min / Max:[/bold] {min_ms:.0f} ms / {max_ms:.0f} ms")
        lines.append(f"[bold]Jitter:[/bold] {jitter_ms:.1f} ms")
    else:
        lines.append("[bold]Average ping:[/bold] n/a")
    if detector and detector.baseline_ms is not None:
        lines.append(f"[bold]Baseline ping:[/bold] {detector.baseline_ms:.0f} ms")
    lines.append(f"[bold]Packet/connection loss:[/bold] {loss_pct:.0f}% ({lost}/{total})")
    lines.append("")

    if flood_detected:
        alert_style = "bold white on red"
        lines.append(f"[{alert_style}] \u26a0  POSSIBLE FLOOD / DDoS DETECTED  \u26a0 [/{alert_style}]")
        seq_note = f" around ping #{detector.first_flag_seq}" if detector.first_flag_seq else ""
        lines.append(
            f"[dim]Latency/loss spiked hard{seq_note} well above the connection's own baseline "
            f"({detector.baseline_ms:.0f} ms) - that pattern (sudden mass timeouts/latency after a "
            "clean start) is typical of the link or server being flooded, not normal network jitter.[/dim]"
        )
        lines.append("")

    lines.append(f"[{style}]STATUS: {label}[/{style}]")

    if mode == "tcp" and label in ("STABLE",) and not flood_detected:
        lines.append("[dim]Good enough for gameplay, e.g. Minecraft, with minimal lag.[/dim]")
    elif label == "UNSTABLE":
        lines.append("[dim]Expect noticeable lag / rubber-banding on real-time games.[/dim]")
    elif label == "VERY UNSTABLE":
        lines.append("[dim]Connection is dropping heavily - likely unplayable.[/dim]")
    elif label == "UNREACHABLE":
        lines.append("[dim]Host did not respond at all - check the address/port or try --port for game servers.[/dim]")

    border_style = "red" if flood_detected else style.split()[-1]
    console.print(Panel("\n".join(lines), title="Summary", border_style=border_style))


def run(host: str, port: int | None, count: int, interval: float):
    banner()

    resolved = resolve_host(host)
    if resolved is None:
        console.print(f"[bold red]Could not resolve host:[/bold red] {host}")
        sys.exit(1)

    target_display = f"{host} ({resolved})" if resolved != host else host
    if port:
        target_display += f":{port}"

    mode = "tcp" if port else "icmp"
    if port:
        console.print(f"[cyan]Pinging {target_display} over TCP (works for firewalled game servers like Minecraft)...[/cyan]\n")
    else:
        console.print(f"[cyan]Pinging {target_display} via ICMP...[/cyan]\n")

    console.print("[dim]Press Ctrl+C at any time to stop early and see the stability summary.[/dim]\n")

    rows: list[tuple[int, float | None]] = []
    detector = FloodDetector()
    interrupted = False

    def render(status: str):
        table = build_table(rows, mode)
        alert = build_status_banner(status)
        if alert is not None:
            return Group(alert, table)
        return table

    try:
        with Live(render("WARMING UP"), console=console, refresh_per_second=8) as live:
            for seq in range(1, count + 1):
                if port:
                    ms = tcp_ping_once(resolved, port)
                else:
                    ms = icmp_ping_once(resolved)
                rows.append((seq, ms))
                status = detector.update(rows)
                live.update(render(status))
                if seq < count:
                    time.sleep(interval)
    except KeyboardInterrupt:
        interrupted = True
        console.print("\n[yellow]Stopped early (Ctrl+C) - here's the stability summary so far:[/yellow]")

    console.print()
    summarize(host, target_display, rows, mode, detector=detector, interrupted=interrupted)

    if port is None and rows and all(ms is None for _, ms in rows):
        console.print(
            "\n[yellow]Tip: every ICMP ping timed out.[/yellow] Many servers (including most "
            "Minecraft hosts) block ICMP but keep the game port open - retry with e.g. "
            "[bold]--port 25565[/bold] for a TCP-based ping instead."
        )


def main():
    parser = argparse.ArgumentParser(description="Ping a server and check its stability (supports Minecraft/game servers).")
    parser.add_argument("host", help="IP address or hostname to ping")
    parser.add_argument("--port", "-p", type=int, default=None, help="Use TCP ping to this port instead of ICMP (e.g. 25565 for Minecraft)")
    parser.add_argument("--count", "-c", type=int, default=10, help="Number of pings to send (default: 10)")
    parser.add_argument("--interval", "-i", type=float, default=0.4, help="Seconds between pings (default: 0.4)")
    args = parser.parse_args()

    try:
        run(args.host, args.port, max(1, args.count), max(0.05, args.interval))
    except KeyboardInterrupt:
        console.print("\n[yellow]Cancelled.[/yellow]")
        sys.exit(0)


if __name__ == "__main__":
    main()
