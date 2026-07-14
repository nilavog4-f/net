# net-tools

Two standalone network diagnostic CLI scripts, plus a colored terminal launcher (`run.sh`).

## Tools

| # | Script | What it does |
|---|--------|---------------|
| 1 | `port_scanner.py` | TCP port scan with banner grabbing + heuristic vulnerability notes |
| 2 | `ping_tool.py` | Ping/latency + connection-stability checker. Supports ICMP or TCP mode (`--port`), the latter useful for servers that block ICMP but keep a game port open (e.g. Minecraft) |

## Setup

```bash
git clone <this-repo-url>
cd net-tools
pip install -r requirements.txt
./run.sh
```

Requires Python 3.10+. `run.sh` also tries to install dependencies automatically on first run.

## Usage

Run directly:

```bash
python3 port_scanner.py <host> --start-port 1 --end-port 1024
python3 ping_tool.py <host>                  # ICMP ping
python3 ping_tool.py <host> --port 25565     # TCP ping (e.g. Minecraft server)
```

Or launch the interactive menu:

```bash
./run.sh
```

## Responsible use

Only scan or ping targets you own or are explicitly authorized to test.
