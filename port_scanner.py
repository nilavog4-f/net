#!/usr/bin/env python3
# ══════════════════════════════════════════════════════════════════
#  VOID Port Scanner — TCP/UDP recon + service fingerprinting
#  For use only against hosts/networks you own or are explicitly
#  authorized to test. Unauthorized scanning of systems you do not
#  control may be illegal in your jurisdiction.
# ══════════════════════════════════════════════════════════════════
"""
VOID Port Scanner

Everything happens on your machine. It opens TCP connections (and,
optionally, sends UDP probes) to the target host/port range you
specify, records which ports respond, grabs a banner, and — for a
few well-known services — goes a step further than a raw banner:

  * HTTP / HTTPS   -> sends a real HEAD request and reads the
                       Server / X-Powered-By response headers
  * SSH             -> parses the SSH-<proto>-<product>_<version>
                       banner into readable protocol/product/version
  * Minecraft Java  -> speaks the real Server List Ping protocol to
                       pull version, MOTD and player count
  * Minecraft Bedrock (UDP 19132) -> sends a RakNet unconnected ping
                       and parses the pong for the same info

Minecraft's default ports (25565/tcp, 19132/udp) are always checked
in addition to whatever range you pick, since they're easy to miss
in a generic 1-1024 scan.

This is a heuristic scanner, not an exploit tool: it never attempts
to log in, brute force, or exploit anything. It only opens a socket,
sends the same kind of request a browser/game client sends, and
reads whatever comes back.

Usage:
    python3 port_scanner.py <host> [--start-port 1] [--end-port 1024]
                             [--udp] [--timeout 0.8] [--json out.json]

Examples:
    python3 port_scanner.py 127.0.0.1
    python3 port_scanner.py my.server.com --start-port 1 --end-port 4000 --udp
    python3 port_scanner.py play.myserver.net --udp   # will also probe 25565/19132
"""

import argparse
import json
import re
import socket
import ssl
import struct
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
#  DEFAULTS — Minecraft ports are always included
# ══════════════════════════════════════════════════════════════════

MINECRAFT_JAVA_PORTS = {25565}
MINECRAFT_BEDROCK_PORTS = {19132}

HTTP_PORTS = {80, 8080, 8000, 8008, 8888}
HTTPS_PORTS = {443, 8443, 9443}

# ══════════════════════════════════════════════════════════════════
#  VULNERABILITY HEURISTICS (TCP)
#  Informational risk profile per well-known port. This flags
#  commonly-abused or historically vulnerable services; it does not
#  fingerprint exact versions or match CVEs on its own (see the
#  fingerprinting functions below for that).
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
    25565: ("minecraft-java", "info",
            "Minecraft Java server. Game servers are common DDoS/flood targets — consider a proxy like "
            "TCPShield/BungeeGuard or a firewall allowlist if exposed publicly."),
    27017: ("mongodb", "critical",
            "MongoDB historically ships without authentication by default and is regularly mass-ransomed when exposed."),
}

DEFAULT_PROFILE = ("unknown", "low",
                    "Open port with no fingerprinted service. Confirm it's intentional and restrict access if not needed.")

# ══════════════════════════════════════════════════════════════════
#  VULNERABILITY HEURISTICS (UDP)
# ══════════════════════════════════════════════════════════════════

UDP_VULN_PROFILES = {
    17: ("qotd", "medium", "Quote-of-the-day is an obsolete amplification vector; should not be exposed."),
    19: ("chargen", "critical", "Chargen is a classic UDP amplification/reflection attack vector. Disable it."),
    53: ("dns", "low", "Open DNS resolvers can be abused for amplification attacks. Restrict recursion to trusted clients."),
    67: ("dhcp-server", "low", "DHCP server; should only be reachable on trusted local networks."),
    68: ("dhcp-client", "info", "DHCP client port."),
    69: ("tftp", "high", "TFTP has no authentication and is frequently used to pull device configs/firmware."),
    123: ("ntp", "medium", "NTP can be abused for amplification attacks (monlist). Ensure it's patched and rate-limited."),
    137: ("netbios-ns", "high", "Legacy NetBIOS name service; exposes hostnames and has known info-disclosure issues."),
    138: ("netbios-dgm", "high", "Legacy NetBIOS datagram service; should not face the internet."),
    161: ("snmp", "critical", "SNMP with default/public community strings gives full device visibility or control."),
    162: ("snmptrap", "medium", "SNMP trap receiver; verify authentication and access restrictions."),
    500: ("isakmp", "low", "IPsec/IKE endpoint. Expected for VPN gateways; keep patched."),
    514: ("syslog", "medium", "Syslog over UDP is unauthenticated and unencrypted; anyone can inject log entries."),
    1900: ("ssdp", "high", "SSDP/UPnP is a well-known amplification vector and should never face the internet."),
    3702: ("wsd", "medium", "WS-Discovery; another common UDP amplification vector when internet-exposed."),
    5353: ("mdns", "low", "Multicast DNS; fine on a LAN, should not be reachable from the internet."),
    11211: ("memcached", "critical", "Memcached over UDP is a massive amplification vector and often has no auth at all."),
    19132: ("minecraft-bedrock", "info",
            "Minecraft Bedrock server. Game servers are common DDoS/flood targets — consider DDoS protection if exposed publicly."),
}

DEFAULT_UDP_PROFILE = ("unknown", "low",
                        "UDP port responded or is open|filtered. Confirm it's intentional.")

_print_lock = threading.Lock()

# ══════════════════════════════════════════════════════════════════
#  TCP PROBING
# ══════════════════════════════════════════════════════════════════


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


# ── Fingerprinting: SSH ──────────────────────────────────────────

_SSH_RE = re.compile(r"^SSH-(?P<proto>\d\.\d+)-(?P<soft>\S+)(?:\s+(?P<comment>.*))?$")


def fingerprint_ssh(banner: str | None) -> dict:
    if not banner or not banner.startswith("SSH-"):
        return {}
    m = _SSH_RE.match(banner.strip())
    if not m:
        return {}
    product, _, ver = m.group("soft").partition("_")
    version_str = f"{product} {ver}".strip() or m.group("soft")
    comment = m.group("comment")
    if comment:
        version_str += f" ({comment})"
    return {
        "service_version": version_str,
        "extra": {"ssh_protocol": m.group("proto")},
    }


# ── Fingerprinting: HTTP / HTTPS ─────────────────────────────────

def fingerprint_http(host: str, port: int, timeout: float, use_tls: bool) -> dict:
    try:
        raw = socket.create_connection((host, port), timeout=timeout)
        sock = raw
        if use_tls:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            sock = ctx.wrap_socket(raw, server_hostname=host)
        sock.settimeout(timeout)
        req = (
            f"HEAD / HTTP/1.1\r\nHost: {host}\r\nUser-Agent: void-scanner/1.0\r\n"
            "Accept: */*\r\nConnection: close\r\n\r\n"
        )
        sock.sendall(req.encode())
        data = b""
        try:
            while len(data) < 8192:
                chunk = sock.recv(4096)
                if not chunk:
                    break
                data += chunk
                if b"\r\n\r\n" in data:
                    break
        except (socket.timeout, OSError):
            pass
        finally:
            sock.close()

        if not data:
            return {}

        text = data.decode("utf-8", errors="replace")
        lines = text.split("\r\n")
        status_line = lines[0].strip() if lines else ""
        headers = {}
        for line in lines[1:]:
            if ":" in line:
                k, v = line.split(":", 1)
                headers[k.strip().lower()] = v.strip()

        server = headers.get("server")
        powered = headers.get("x-powered-by")
        bits = []
        if server:
            bits.append(server)
        if powered:
            bits.append(f"({powered})")
        version_str = " ".join(bits) if bits else None

        return {
            "service_version": version_str,
            "extra": {
                "http_status": status_line,
                "server_header": server,
                "x_powered_by": powered,
                "tls": use_tls,
            },
        }
    except Exception:
        return {}


# ── Fingerprinting: Minecraft Java (Server List Ping) ────────────

def _pack_varint(value: int) -> bytes:
    value &= 0xFFFFFFFF
    out = bytearray()
    while True:
        b = value & 0x7F
        value >>= 7
        if value:
            out.append(b | 0x80)
        else:
            out.append(b)
            break
    return bytes(out)


def _pack_mc_string(s: str) -> bytes:
    data = s.encode("utf-8")
    return _pack_varint(len(data)) + data


def _read_varint_from_socket(sock) -> int:
    value = 0
    position = 0
    while True:
        b = sock.recv(1)
        if not b:
            raise ConnectionError("connection closed while reading varint")
        byte = b[0]
        value |= (byte & 0x7F) << position
        if not (byte & 0x80):
            return value
        position += 7
        if position >= 35:
            raise ValueError("varint too long")


def _flatten_motd(desc) -> str:
    if isinstance(desc, str):
        return desc
    if isinstance(desc, dict):
        text = desc.get("text", "")
        for part in desc.get("extra", []) or []:
            if isinstance(part, dict):
                text += part.get("text", "")
            elif isinstance(part, str):
                text += part
        return text
    return str(desc) if desc is not None else ""


def minecraft_java_ping(host: str, port: int, timeout: float = 1.5) -> dict | None:
    try:
        with socket.create_connection((host, port), timeout=timeout) as sock:
            sock.settimeout(timeout)

            handshake = (
                _pack_varint(0x00)
                + _pack_varint(-1)  # protocol version: -1 signals "just checking status"
                + _pack_mc_string(host)
                + struct.pack(">H", port)
                + _pack_varint(1)  # next state = 1 (status)
            )
            sock.sendall(_pack_varint(len(handshake)) + handshake)

            status_request = _pack_varint(0x00)
            sock.sendall(_pack_varint(len(status_request)) + status_request)

            _read_varint_from_socket(sock)  # total packet length (unused)
            _read_varint_from_socket(sock)  # packet id (should be 0x00)
            json_len = _read_varint_from_socket(sock)

            data = b""
            while len(data) < json_len:
                chunk = sock.recv(json_len - len(data))
                if not chunk:
                    break
                data += chunk

            payload = json.loads(data.decode("utf-8", errors="replace"))
            version = payload.get("version", {}) or {}
            players = payload.get("players", {}) or {}
            return {
                "version_name": version.get("name"),
                "protocol": version.get("protocol"),
                "online": players.get("online"),
                "max_players": players.get("max"),
                "motd": _flatten_motd(payload.get("description")),
            }
    except Exception:
        return None


# ── Fingerprinting: Minecraft Bedrock (RakNet unconnected ping, UDP) ──

_RAKNET_MAGIC = bytes.fromhex("00ffff00fefefefefdfdfdfd12345678")


def minecraft_bedrock_ping(host: str, port: int = 19132, timeout: float = 1.5) -> dict | None:
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(timeout)
    try:
        ts = int(time.time() * 1000) & 0xFFFFFFFFFFFFFFFF
        packet = bytes([0x01]) + struct.pack(">Q", ts) + _RAKNET_MAGIC + struct.pack(">Q", 0)
        sock.sendto(packet, (host, port))
        data, _ = sock.recvfrom(2048)
        if not data or data[0] != 0x1C:
            return None
        offset = 1 + 8 + 16  # id + server guid + magic
        str_len = struct.unpack(">H", data[offset:offset + 2])[0]
        offset += 2
        info = data[offset:offset + str_len].decode("utf-8", errors="replace")
        parts = info.split(";")
        if len(parts) < 6:
            return None
        return {
            "edition": parts[0],
            "motd": parts[1],
            "protocol": parts[2],
            "version_name": parts[3],
            "online": parts[4],
            "max_players": parts[5],
            "submotd": parts[7] if len(parts) > 7 else None,
            "gamemode": parts[8] if len(parts) > 8 else None,
        }
    except Exception:
        return None
    finally:
        sock.close()


def apply_tcp_fingerprint(host: str, port: int, banner: str | None, timeout: float) -> dict:
    """Best-effort deeper fingerprint for an open TCP port. Returns a dict
    that may override service/risk/note and add service_version/extra."""
    if port in MINECRAFT_JAVA_PORTS:
        mc = minecraft_java_ping(host, port, timeout=max(timeout, 1.0))
        if mc:
            note = (
                f"Minecraft Java server — version {mc['version_name']} (protocol {mc['protocol']}), "
                f"{mc['online']}/{mc['max_players']} players online. MOTD: \"{mc['motd']}\""
            )
            return {
                "service": "minecraft-java",
                "risk": "info",
                "note": note,
                "service_version": mc["version_name"],
                "extra": mc,
            }

    if banner and banner.startswith("SSH-"):
        return fingerprint_ssh(banner)

    if port in HTTP_PORTS or port in HTTPS_PORTS or (banner and "HTTP/" in banner):
        return fingerprint_http(host, port, timeout, use_tls=port in HTTPS_PORTS)

    return {}


# ── UDP PROBING ───────────────────────────────────────────────────

def _dns_probe_payload() -> bytes:
    # Minimal DNS query for "." (root) NS record - most resolvers reply.
    return bytes.fromhex("0001010000010000000000000000060001")


def _ntp_probe_payload() -> bytes:
    # NTP client request (LI=0, VN=4, Mode=3), rest zeroed.
    payload = bytearray(48)
    payload[0] = 0x23
    return bytes(payload)


def _snmp_probe_payload() -> bytes:
    # SNMPv1 GetRequest for sysDescr.0 with community "public".
    return bytes.fromhex(
        "302602010004067075626c6963a01902044a6f9e3402010002010030"
        "0b300906052b0601020101050001"
    )


_UDP_PROBE_BUILDERS = {
    53: _dns_probe_payload,
    123: _ntp_probe_payload,
    161: _snmp_probe_payload,
}


def probe_udp_port(host: str, port: int, timeout: float):
    """Returns (state, banner) where state is 'open', 'closed', or
    'open|filtered' (UDP gives no reliable closed signal without an
    ICMP unreachable, which many hosts/firewalls suppress)."""
    if port in MINECRAFT_BEDROCK_PORTS:
        result = minecraft_bedrock_ping(host, port, timeout=max(timeout, 1.0))
        if result:
            return "open", result
        # fall through to a generic probe in case it just didn't answer as Bedrock

    payload = _UDP_PROBE_BUILDERS.get(port, lambda: b"\x00")()
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(timeout)
    try:
        sock.sendto(payload, (host, port))
        data, _ = sock.recvfrom(2048)
        return "open", (data[:200].decode("utf-8", errors="replace").strip() or None)
    except socket.timeout:
        return "open|filtered", None
    except ConnectionRefusedError:
        return "closed", None
    except OSError:
        return "open|filtered", None
    finally:
        sock.close()


# ══════════════════════════════════════════════════════════════════
#  SCANNING
# ══════════════════════════════════════════════════════════════════


def scan_tcp(host: str, ports: list[int], timeout: float, max_workers: int = 200):
    findings = []
    scanned = 0
    total = len(ports)

    with console.status(f"[bold cyan]TCP scanning {host} ({total} ports)...", spinner="dots") as status:
        with ThreadPoolExecutor(max_workers=max_workers) as pool:
            futures = {pool.submit(probe_port, host, port, timeout): port for port in ports}
            for future in as_completed(futures):
                port = futures[future]
                scanned += 1
                is_open, banner = future.result()
                if is_open:
                    service, risk, note = VULN_PROFILES.get(port, DEFAULT_PROFILE)
                    finding = {
                        "proto": "tcp",
                        "port": port,
                        "service": service,
                        "banner": banner,
                        "risk": risk,
                        "note": note,
                        "service_version": None,
                        "extra": {},
                    }
                    fp = apply_tcp_fingerprint(host, port, banner, timeout)
                    if fp:
                        finding.update({k: v for k, v in fp.items() if v is not None})
                    findings.append(finding)
                if scanned % 50 == 0 or scanned == total:
                    status.update(f"[bold cyan]TCP scanning {host}... {scanned}/{total} ports checked")

    findings.sort(key=lambda f: f["port"])
    return findings


def scan_udp(host: str, ports: list[int], timeout: float, max_workers: int = 100):
    """Only ports that actually sent back data (or a valid Minecraft
    Bedrock pong) are reported as open. A UDP port that never responds is
    NOT counted as open — with no ICMP "port unreachable" (common in
    sandboxes/firewalled networks), silence is indistinguishable from
    closed, so counting it would make almost every unused port look open.
    Those silent ports are tracked separately as low-confidence/ambiguous."""
    findings = []
    ambiguous = 0
    scanned = 0
    total = len(ports)

    with console.status(f"[bold cyan]UDP scanning {host} ({total} ports)...", spinner="dots") as status:
        with ThreadPoolExecutor(max_workers=max_workers) as pool:
            futures = {pool.submit(probe_udp_port, host, port, timeout): port for port in ports}
            for future in as_completed(futures):
                port = futures[future]
                scanned += 1
                state, result = future.result()
                if state == "open":
                    service, risk, note = UDP_VULN_PROFILES.get(port, DEFAULT_UDP_PROFILE)
                    finding = {
                        "proto": "udp",
                        "port": port,
                        "service": service,
                        "banner": None,
                        "risk": risk,
                        "note": note,
                        "service_version": None,
                        "extra": {"state": state},
                    }
                    if port in MINECRAFT_BEDROCK_PORTS and isinstance(result, dict):
                        finding.update({
                            "service": "minecraft-bedrock",
                            "risk": "info",
                            "note": (
                                f"Minecraft Bedrock server — version {result.get('version_name')} "
                                f"(protocol {result.get('protocol')}), {result.get('online')}/"
                                f"{result.get('max_players')} players. MOTD: \"{result.get('motd')}\""
                            ),
                            "service_version": result.get("version_name"),
                            "extra": result,
                        })
                    elif isinstance(result, str):
                        finding["banner"] = result
                    findings.append(finding)
                elif state == "open|filtered":
                    ambiguous += 1
                if scanned % 50 == 0 or scanned == total:
                    status.update(f"[bold cyan]UDP scanning {host}... {scanned}/{total} ports checked")

    findings.sort(key=lambda f: f["port"])
    return findings, ambiguous


def risk_score(findings) -> int:
    return min(100, sum(RISK_WEIGHT[f["risk"]] for f in findings))


def print_banner():
    banner_text = pyfiglet.figlet_format("VOID SCANNER", font="slant")
    console.print(Align.center(Text(banner_text, style="bold cyan")))
    console.print(Align.center(Text("TCP/UDP port scanner + service fingerprinting", style="dim")))
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


def print_results(host: str, start_port: int, end_port: int, findings, duration: float, udp_enabled: bool, udp_ambiguous: int = 0):
    score = risk_score(findings)

    table = Table(title=f"Open ports on {host}", box=box.SIMPLE_HEAVY, show_lines=False)
    table.add_column("Proto", justify="center", style="dim")
    table.add_column("Port", style="bold", justify="right")
    table.add_column("Service")
    table.add_column("Version / Banner", overflow="fold", max_width=34)
    table.add_column("Risk", justify="center")
    table.add_column("Note", overflow="fold", max_width=46)

    if not findings:
        console.print(f"\n[dim]No open ports found in {host}:{start_port}-{end_port}[/dim]\n")
    else:
        for f in findings:
            risk_style = RISK_COLORS.get(f["risk"], "white")
            version_or_banner = f.get("service_version") or f.get("banner") or "-"
            table.add_row(
                f["proto"].upper(),
                str(f["port"]),
                f["service"],
                version_or_banner,
                f"[{risk_style}]{f['risk'].upper()}[/{risk_style}]",
                f["note"],
            )
        console.print(table)

    critical = sum(1 for f in findings if f["risk"] == "critical")
    high = sum(1 for f in findings if f["risk"] == "high")
    mc_hits = [f for f in findings if f["service"].startswith("minecraft")]

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

    proto_note = "TCP + UDP" if udp_enabled else "TCP only (pass --udp to also probe UDP)"
    mc_note = f" · {len(mc_hits)} Minecraft server(s) found" if mc_hits else " · no Minecraft server detected"
    ambiguous_note = ""
    if udp_enabled and udp_ambiguous:
        ambiguous_note = (
            f"\n[dim]{udp_ambiguous} UDP port(s) gave no response at all — not counted as open. "
            "Without an ICMP \"port unreachable\" reply (often suppressed by firewalls/sandboxes), "
            "silence can't be told apart from closed, so these are excluded from the results above.[/dim]"
        )

    console.print(
        Panel(
            f"[{summary_style}]{summary}[/{summary_style}]\n"
            f"[dim]Range {start_port}-{end_port} ({proto_note}) · {len(findings)} open · "
            f"scanned in {duration:.2f}s · exposure score {score}/100{mc_note}[/dim]"
            f"{ambiguous_note}",
            title="Summary",
            border_style="cyan",
            box=box.ROUNDED,
        )
    )


def main():
    parser = argparse.ArgumentParser(
        description="VOID Port Scanner — TCP/UDP recon with service fingerprinting. Authorized use only.",
    )
    parser.add_argument("host", help="Hostname or IP address to scan (must be authorized)")
    parser.add_argument("--start-port", type=int, default=1, help="First port to scan (default: 1)")
    parser.add_argument("--end-port", type=int, default=1024, help="Last port to scan (default: 1024)")
    parser.add_argument("--udp", action="store_true", help="Also probe UDP ports in the same range")
    parser.add_argument("--no-minecraft", action="store_true",
                         help="Don't auto-include Minecraft's default ports (25565/tcp, 19132/udp)")
    parser.add_argument("--timeout", type=float, default=0.8, help="Per-port connect timeout in seconds (default: 0.8)")
    parser.add_argument("--workers", type=int, default=200, help="Concurrent connection attempts (default: 200)")
    parser.add_argument("--json", metavar="FILE", help="Write results as JSON to this file")
    args = parser.parse_args()

    if args.start_port < 1 or args.end_port > 65535 or args.start_port > args.end_port:
        console.print("[bold red]Invalid port range.[/bold red] Ports must be within 1-65535 and start <= end.")
        sys.exit(1)

    print_banner()
    print_disclaimer()
    mc_hint = "" if args.no_minecraft else "  [dim](Minecraft ports 25565/tcp + 19132/udp auto-included)[/dim]"
    console.print(f"\n[bold]Target:[/bold] {args.host}   [bold]Range:[/bold] {args.start_port}-{args.end_port}{mc_hint}\n")

    tcp_ports = set(range(args.start_port, args.end_port + 1))
    udp_ports = set(range(args.start_port, args.end_port + 1)) if args.udp else set()
    if not args.no_minecraft:
        tcp_ports |= MINECRAFT_JAVA_PORTS
        if args.udp:
            udp_ports |= MINECRAFT_BEDROCK_PORTS

    start = time.time()
    findings = scan_tcp(args.host, sorted(tcp_ports), args.timeout, args.workers)
    udp_ambiguous = 0
    if udp_ports:
        udp_findings, udp_ambiguous = scan_udp(args.host, sorted(udp_ports), max(args.timeout, 1.0), min(args.workers, 100))
        findings += udp_findings
    duration = time.time() - start

    findings.sort(key=lambda f: (f["port"], f["proto"]))
    print_results(args.host, args.start_port, args.end_port, findings, duration, args.udp, udp_ambiguous)

    if args.json:
        payload = {
            "host": args.host,
            "startPort": args.start_port,
            "endPort": args.end_port,
            "udpEnabled": args.udp,
            "udpAmbiguousCount": udp_ambiguous,
            "minecraftAutoIncluded": not args.no_minecraft,
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
