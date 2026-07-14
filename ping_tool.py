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

from rich.console import Console
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


def summarize(host: str, target_display: str, rows: list[tuple[int, float | None]], mode: str):
    successes = [ms for _, ms in rows if ms is not None]
    total = len(rows)
    lost = total - len(successes)
    loss_pct = (lost / total * 100) if total else 100.0

    avg_ms = statistics.mean(successes) if successes else None
    min_ms = min(successes) if successes else None
    max_ms = max(successes) if successes else None
    jitter_ms = statistics.pstdev(successes) if len(successes) > 1 else 0.0

    label, style = classify_stability(loss_pct, jitter_ms, avg_ms)

    lines = [f"[bold]Target:[/bold] {target_display}"]
    if avg_ms is not None:
        lines.append(f"[bold]Average ping:[/bold] {avg_ms:.0f} ms")
        lines.append(f"[bold]Min / Max:[/bold] {min_ms:.0f} ms / {max_ms:.0f} ms")
        lines.append(f"[bold]Jitter:[/bold] {jitter_ms:.1f} ms")
    else:
        lines.append("[bold]Average ping:[/bold] n/a")
    lines.append(f"[bold]Packet/connection loss:[/bold] {loss_pct:.0f}% ({lost}/{total})")
    lines.append("")
    lines.append(f"[{style}]STATUS: {label}[/{style}]")

    if mode == "tcp" and label in ("STABLE",):
        lines.append("[dim]Good enough for gameplay, e.g. Minecraft, with minimal lag.[/dim]")
    elif label == "UNSTABLE":
        lines.append("[dim]Expect noticeable lag / rubber-banding on real-time games.[/dim]")
    elif label == "VERY UNSTABLE":
        lines.append("[dim]Connection is dropping heavily - likely unplayable.[/dim]")
    elif label == "UNREACHABLE":
        lines.append("[dim]Host did not respond at all - check the address/port or try --port for game servers.[/dim]")

    console.print(Panel("\n".join(lines), title="Summary", border_style=style.split()[-1]))


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

    rows: list[tuple[int, float | None]] = []

    with Live(build_table(rows, mode), console=console, refresh_per_second=8) as live:
        for seq in range(1, count + 1):
            if port:
                ms = tcp_ping_once(resolved, port)
            else:
                ms = icmp_ping_once(resolved)
                if ms is None and seq == 1:
                    # ICMP likely blocked (common for cloud/game hosts) - hint once, keep going
                    pass
            rows.append((seq, ms))
            live.update(build_table(rows, mode))
            if seq < count:
                time.sleep(interval)

    console.print()
    summarize(host, target_display, rows, mode)

    if port is None and all(ms is None for _, ms in rows):
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
