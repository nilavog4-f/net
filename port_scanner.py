#!/usr/bin/env python3
# ══════════════════════════════════════════════════════════════════
#  VOID Port Scanner — TCP recon + vulnerability heuristics
#  For use only against hosts/networks you own or are explicitly
#  authorized to test. Unauthorized scanning of systems you do not
#  control may be illegal in your jurisdiction.
# ══════════════════════════════════════════════════════════════════
"""
VOID Port Scanner

Everything happens on your machine. It opens TCP connections to the
target host/port range you specify, records which ports respond,
grabs a banner if the service offers one, and flags each open port
with a plain-English risk note based on well-known service exposure
patterns (e.g. Telnet, SMB, Redis, RDP with no auth).

This is a heuristic scanner, not an exploit tool: it never attempts
to log in, brute force, or exploit anything. It only opens a socket
and reads whatever the service sends first, the same thing your web
browser does when it connects to any port.

Usage:
    python3 port_scanner.py <host> [--start-port 1] [--end-port 1024]
                             [--timeout 0.8] [--json out.json]

Examples:
    python3 port_scanner.py 127.0.0.1
    python3 port_scanner.py scanme.example.com --start-port 1 --end-port 4000
"""

import argparse
import json
import socket
import subprocess
import sys
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone


def _ensure_deps() -> None:
    for mod, pkg in [("rich", "rich"), ("pyfiglet", "pyfiglet")]:
        try:
            __import__(mod)
        except ImportError:
            print(f"[*] Installing {pkg}...")
            try:
                subprocess.check_call(
                    [sys.executable, "-m", "pip", "install", pkg, "-q",
                     "--break-system-packages"],
                    stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            except subprocess.CalledProcessError:
                subprocess.check_call(
                    [sys.executable, "-m", "pip", "install", pkg, "-q"],
                    stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)


_ensure_deps()

import pyfiglet
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.align import Align
from rich.text import Text
from rich.rule import Rule
from rich import box

console = Console()

# ══════════════════════════════════════════════════════════════════
#  VULNERABILITY HEURISTICS
#  Informational risk profile per well-known port. This flags
#  commonly-abused or historically vulnerable services; it does not
#  fingerprint exact versions or match CVEs.
# ══════════════════════════════════════════════════════════════════

RISK_COLORS = {
    "info": "cyan",
    "low": "green",
    "medium": "yellow",
    "high": "orange3",
    "critical": "bold red",
}

RISK_WEIGHT = {"info": 2, "low": 6, "medium": 15, "high": 30, "critical": 50}

VULN_PROFILES = {
    21: ("ftp", "medium",
         "FTP is frequently misconfigured for anonymous access and sends credentials in plaintext."),
    22: ("ssh", "info",
         "SSH is expected for remote administration. Ensure key-based auth, disable root login, keep it patched."),
    23: ("telnet", "critical",
         "Telnet transmits everything, including passwords, unencrypted. It should never be exposed."),
    25: ("smtp", "low",
         "Open SMTP relays can be abused to send spam. Confirm relay restrictions are enforced."),
    53: ("dns", "low",
         "Open DNS resolvers can be abused for amplification attacks. Restrict recursion to trusted clients."),
    80: ("http", "info",
         "Standard plaintext web traffic. Confirm the app behind it is patched and doesn't leak sensitive data."),
    110: ("pop3", "medium",
          "POP3 without TLS sends mailbox credentials in plaintext."),
    111: ("rpcbind", "high",
          "RPC portmapper services have a long history of information disclosure and remote exploits."),
    135: ("msrpc", "high",
          "Windows RPC endpoint mapper. A common vector for historical worms; should not face the internet."),
    139: ("netbios-ssn", "high",
          "NetBIOS session service. Legacy Windows file sharing surface with known remote exploits."),
    143: ("imap", "medium",
          "IMAP without TLS exposes mailbox credentials in plaintext."),
    443: ("https", "info",
          "Encrypted web traffic. Verify certificates and TLS configuration are up to date."),
    445: ("microsoft-ds", "critical",
          "SMB has been the entry point for major ransomware worms (WannaCry, NotPetya). Never expose to the internet."),
    1433: ("mssql", "high",
           "Exposed SQL Server increases risk of credential stuffing and known remote exploits."),
    1521: ("oracle", "high",
           "Exposed Oracle listener; restrict to trusted networks and keep patched."),
    3306: ("mysql", "high",
           "Exposed MySQL is a common brute-force and credential-stuffing target."),
    3389: ("rdp", "critical",
           "RDP exposed to the internet is one of the most common ransomware entry vectors. Require VPN and MFA."),
    5432: ("postgresql", "high",
           "Exposed PostgreSQL should be restricted to trusted networks with strong authentication."),
    5900: ("vnc", "critical",
           "VNC frequently runs with weak or no authentication, granting full remote desktop control."),
    6379: ("redis", "critical",
           "Redis has no authentication by default in many deployments and has been mass-exploited for cryptomining."),
    8080: ("http-alt", "info",
           "Alternate HTTP port, often used for proxies or dev servers. Confirm it's intentionally exposed."),
    8443: ("https-alt", "info",
           "Alternate HTTPS port. Verify certificates and access controls."),
    9200: ("elasticsearch", "high",
           "Unauthenticated Elasticsearch instances have leaked massive datasets when exposed publicly."),
    27017: ("mongodb", "critical",
            "MongoDB historically ships without authentication by default and is regularly mass-ransomed when exposed."),
}

DEFAULT_PROFILE = ("unknown", "low",
                    "Open port with no fingerprinted service. Confirm it's intentional and restrict access if not needed.")

_print_lock = threading.Lock()


def probe_port(host: str, port: int, timeout: float):
    """Returns (is_open, banner) for a single TCP port."""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(timeout)
            sock.connect((host, port))
            banner = None
            try:
                sock.settimeout(min(timeout, 0.4))
                data = sock.recv(200)
                if data:
                    banner = data.decode("utf-8", errors="replace").strip() or None
            except (socket.timeout, OSError):
                pass
            return True, banner
    except (socket.timeout, ConnectionRefusedError, OSError):
        return False, None


def scan(host: str, start_port: int, end_port: int, timeout: float, max_workers: int = 200):
    ports = list(range(start_port, end_port + 1))
    findings = []
    scanned = 0
    total = len(ports)

    with console.status(f"[bold cyan]Scanning {host} ({total} ports)...", spinner="dots") as status:
        with ThreadPoolExecutor(max_workers=max_workers) as pool:
            futures = {pool.submit(probe_port, host, port, timeout): port for port in ports}
            for future in as_completed(futures):
                port = futures[future]
                scanned += 1
                is_open, banner = future.result()
                if is_open:
                    service, risk, note = VULN_PROFILES.get(port, DEFAULT_PROFILE)
                    findings.append({
                        "port": port,
                        "service": service,
                        "banner": banner,
                        "risk": risk,
                        "note": note,
                    })
                if scanned % 50 == 0 or scanned == total:
                    status.update(f"[bold cyan]Scanning {host}... {scanned}/{total} ports checked")

    findings.sort(key=lambda f: f["port"])
    return findings


def risk_score(findings) -> int:
    return min(100, sum(RISK_WEIGHT[f["risk"]] for f in findings))


def print_banner():
    banner_text = pyfiglet.figlet_format("VOID SCANNER", font="slant")
    console.print(Align.center(Text(banner_text, style="bold cyan")))
    console.print(Align.center(Text("TCP port scanner + vulnerability heuristics", style="dim")))
    console.print(Rule(style="cyan"))


def print_disclaimer():
    console.print(
        Panel(
            "Only scan hosts and networks you own or have explicit written authorization to test.\n"
            "Unauthorized scanning of systems you do not control may be illegal in your jurisdiction.",
            title="[bold]Authorized use only[/bold]",
            border_style="red",
            box=box.ROUNDED,
        )
    )


def print_results(host: str, start_port: int, end_port: int, findings, duration: float):
    score = risk_score(findings)

    table = Table(title=f"Open ports on {host}", box=box.SIMPLE_HEAVY, show_lines=False)
    table.add_column("Port", style="bold", justify="right")
    table.add_column("Service")
    table.add_column("Banner", overflow="fold", max_width=40)
    table.add_column("Risk", justify="center")
    table.add_column("Note", overflow="fold", max_width=50)

    if not findings:
        console.print(f"\n[dim]No open ports found in {host}:{start_port}-{end_port}[/dim]\n")
    else:
        for f in findings:
            risk_style = RISK_COLORS.get(f["risk"], "white")
            table.add_row(
                str(f["port"]),
                f["service"],
                f["banner"] or "-",
                f"[{risk_style}]{f['risk'].upper()}[/{risk_style}]",
                f["note"],
            )
        console.print(table)

    critical = sum(1 for f in findings if f["risk"] == "critical")
    high = sum(1 for f in findings if f["risk"] == "high")

    if critical:
        summary = f"{len(findings)} open port(s) — {critical} CRITICAL exposure(s). Investigate immediately."
        summary_style = "bold red"
    elif high:
        summary = f"{len(findings)} open port(s) — {high} high-risk service(s) exposed."
        summary_style = "orange3"
    elif findings:
        summary = f"{len(findings)} open port(s) found. Exposure score: {score}/100."
        summary_style = "yellow"
    else:
        summary = "No open ports found in the scanned range."
        summary_style = "green"

    console.print(
        Panel(
            f"[{summary_style}]{summary}[/{summary_style}]\n"
            f"[dim]Range {start_port}-{end_port} · {len(findings)} open · "
            f"scanned in {duration:.2f}s · exposure score {score}/100[/dim]",
            title="Summary",
            border_style="cyan",
            box=box.ROUNDED,
        )
    )


def main():
    parser = argparse.ArgumentParser(
        description="VOID Port Scanner — TCP recon with vulnerability heuristics. Authorized use only.",
    )
    parser.add_argument("host", help="Hostname or IP address to scan (must be authorized)")
    parser.add_argument("--start-port", type=int, default=1, help="First port to scan (default: 1)")
    parser.add_argument("--end-port", type=int, default=1024, help="Last port to scan (default: 1024)")
    parser.add_argument("--timeout", type=float, default=0.8, help="Per-port connect timeout in seconds (default: 0.8)")
    parser.add_argument("--workers", type=int, default=200, help="Concurrent connection attempts (default: 200)")
    parser.add_argument("--json", metavar="FILE", help="Write results as JSON to this file")
    args = parser.parse_args()

    if args.start_port < 1 or args.end_port > 65535 or args.start_port > args.end_port:
        console.print("[bold red]Invalid port range.[/bold red] Ports must be within 1-65535 and start <= end.")
        sys.exit(1)

    print_banner()
    print_disclaimer()
    console.print(f"\n[bold]Target:[/bold] {args.host}   [bold]Range:[/bold] {args.start_port}-{args.end_port}\n")

    start = time.time()
    findings = scan(args.host, args.start_port, args.end_port, args.timeout, args.workers)
    duration = time.time() - start

    print_results(args.host, args.start_port, args.end_port, findings, duration)

    if args.json:
        payload = {
            "host": args.host,
            "startPort": args.start_port,
            "endPort": args.end_port,
            "scannedAt": datetime.now(timezone.utc).isoformat(),
            "durationSeconds": round(duration, 2),
            "openPortCount": len(findings),
            "riskScore": risk_score(findings),
            "findings": findings,
        }
        with open(args.json, "w") as fh:
            json.dump(payload, fh, indent=2)
        console.print(f"\n[dim]Results written to {args.json}[/dim]")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        console.print("\n[dim]Scan interrupted.[/dim]")
        sys.exit(130)
