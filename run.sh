#!/usr/bin/env bash
# ##############################################################
# ##   NET TOOLS — Launcher                                   ##
# ##   Port Scanner + Ping/Stability Checker                  ##
# ##############################################################

cd "$(dirname "$(realpath "$0")")" 2>/dev/null || cd "$(dirname "$0")"

# ── Palette ───────────────────────────────────────────────────
LR='\033[1;31m'  LG='\033[1;32m'  LY='\033[1;33m'  LC='\033[1;36m'
LW='\033[1;37m'  DIM='\033[2m'   RST='\033[0m'    BOLD='\033[1m'
BLOOD='\033[38;5;160m'  CRIMSON='\033[38;5;196m'
GRAY='\033[38;5;240m'   LGRAY='\033[38;5;246m'

OK="${LG}✔${RST}"
ERR="${LR}✘${RST}"
WARN="${LY}!${RST}"

PYBIN="python3"
if [ -x "../.pythonlibs/bin/python" ]; then
  PYBIN="../.pythonlibs/bin/python"
elif [ -x ".pythonlibs/bin/python" ]; then
  PYBIN=".pythonlibs/bin/python"
fi

COLS() { tput cols 2>/dev/null || echo 80; }

rule() {
  local char="${1:-─}" color="${2:-$GRAY}"
  local w; w=$(COLS)
  printf "${color}"; printf '%*s' "$w" '' | tr ' ' "$char"; printf "${RST}\n"
}

center() {
  local text="$1"
  local plain; plain=$(printf '%b' "$text" | sed 's/\x1B\[[0-9;:]*[mK]//g')
  local w pad; w=$(COLS); pad=$(( (w - ${#plain}) / 2 ))
  [ $pad -lt 0 ] && pad=0
  printf "%${pad}s" ""; printf '%b\n' "$text"
}

show_banner() {
  clear
  echo ""
  rule "═" "$BLOOD"
  echo ""
  printf '%b' "${CRIMSON}${BOLD}"
  center "███╗   ██╗███████╗████████╗    ████████╗ ██████╗  ██████╗ ██╗     ███████╗"
  center "████╗  ██║██╔════╝╚══██╔══╝    ╚══██╔══╝██╔═══██╗██╔═══██╗██║     ██╔════╝"
  center "██╔██╗ ██║█████╗     ██║          ██║   ██║   ██║██║   ██║██║     ███████╗"
  center "██║╚██╗██║██╔══╝     ██║          ██║   ██║   ██║██║   ██║██║     ╚════██║"
  center "██║ ╚████║███████╗   ██║          ██║   ╚██████╔╝╚██████╔╝███████╗███████║"
  center "╚═╝  ╚═══╝╚══════╝   ╚═╝          ╚═╝    ╚═════╝  ╚═════╝ ╚══════╝╚══════╝"
  printf '%b' "${RST}"
  echo ""
  center "${LGRAY}P O R T   S C A N   +   P I N G   /   S T A B I L I T Y${RST}"
  echo ""
  rule "═" "$BLOOD"
  echo ""
}

startup_checks() {
  echo -e "  ${BOLD}${LW}ENVIRONMENT${RST}\n"

  if ! command -v "$PYBIN" &>/dev/null && ! command -v python3 &>/dev/null; then
    echo -e "  ${ERR}  ${LW}Python3 not found${RST}"
    exit 1
  fi
  PY=$("$PYBIN" --version 2>&1 | awk '{print $2}')
  echo -e "  ${OK}  ${LW}Python ${LG}${PY}${RST}  ${DIM}(${PYBIN})${RST}"

  echo ""
  echo -e "  ${BOLD}${LW}DEPENDENCIES${RST}\n"

  if [ -f requirements.txt ]; then
    "$PYBIN" -m pip install -r requirements.txt -q --break-system-packages 2>/dev/null \
      || "$PYBIN" -m pip install -r requirements.txt -q 2>/dev/null
  fi

  echo -e "  ${OK}  ${LW}Ready${RST}"
  echo ""
  rule "═" "$BLOOD"
  echo ""
}

menu_row() {
  local key="$1" file="$2" label="$3" desc="$4" dot
  if [ -f "$file" ]; then dot="${LG}●${RST}"; else dot="${LR}○${RST}"; fi
  printf "  ${BLOOD}[${RST}${BOLD}${LY}%s${RST}${BLOOD}]${RST}  %b  ${BOLD}${LC}%-16s${RST}  ${LGRAY}%s${RST}\n" \
    "$key" "$dot" "$label" "$desc"
}

show_menu() {
  show_banner
  center "${BOLD}${CRIMSON}— SELECT A TOOL —${RST}"
  echo ""
  rule "─" "$BLOOD"
  echo ""

  menu_row "1" "port_scanner.py" "Port Scanner"     "TCP recon + vulnerability heuristics"
  menu_row "2" "ping_tool.py"    "Ping / Stability" "Latency + stability check (Minecraft-friendly)"

  echo ""
  rule "─" "$BLOOD"
  echo ""
  echo -e "  ${GRAY}[Q]  Quit${RST}"
  echo ""
  printf "  ${BLOOD}◈${RST}  ${LW}Choice: ${RST}"
}

pause_return() {
  local rc="$1" name="$2"
  echo ""
  rule "═" "$BLOOD"
  if [ "$rc" -eq 0 ]; then
    center "${LG}✔  ${name} exited cleanly${RST}"
  else
    center "${LR}✘  ${name} exited with code ${rc}${RST}"
  fi
  rule "═" "$BLOOD"
  echo ""
  echo -e "  ${GRAY}Press Enter to return to the menu…${RST}"
  read -r
}

launch_port_scanner() {
  clear; echo ""
  rule "═" "$BLOOD"
  echo ""
  center "${BLOOD}▶▶  ${LC}${BOLD}Port Scanner${RST}  ${BLOOD}◀◀${RST}"
  echo ""
  rule "═" "$BLOOD"
  echo ""

  read -r -p "$(printf "  ${LW}Target host: ${RST}")" target
  if [ -z "$target" ]; then
    echo -e "\n  ${ERR}  ${LW}No host given.${RST}\n"
    sleep 2; return
  fi
  read -r -p "$(printf "  ${LW}Start port [1]: ${RST}")" sp
  read -r -p "$(printf "  ${LW}End port [1024]: ${RST}")" ep
  sp="${sp:-1}"; ep="${ep:-1024}"

  echo ""
  "$PYBIN" port_scanner.py "$target" --start-port "$sp" --end-port "$ep"
  pause_return "$?" "Port Scanner"
}

launch_ping_tool() {
  clear; echo ""
  rule "═" "$BLOOD"
  echo ""
  center "${BLOOD}▶▶  ${LC}${BOLD}Ping / Stability Checker${RST}  ${BLOOD}◀◀${RST}"
  echo ""
  rule "═" "$BLOOD"
  echo ""

  read -r -p "$(printf "  ${LW}Target host or IP: ${RST}")" target
  if [ -z "$target" ]; then
    echo -e "\n  ${ERR}  ${LW}No host given.${RST}\n"
    sleep 2; return
  fi
  read -r -p "$(printf "  ${LW}Port (blank = ICMP ping, e.g. 25565 for Minecraft): ${RST}")" port
  read -r -p "$(printf "  ${LW}Number of pings [10]: ${RST}")" count
  count="${count:-10}"

  echo ""
  if [ -n "$port" ]; then
    "$PYBIN" ping_tool.py "$target" --port "$port" --count "$count"
  else
    "$PYBIN" ping_tool.py "$target" --count "$count"
  fi
  pause_return "$?" "Ping / Stability Checker"
}

# ── Main ──────────────────────────────────────────────────────
show_banner
startup_checks

while true; do
  show_menu
  read -r choice

  case "$choice" in
    1) launch_port_scanner ;;
    2) launch_ping_tool ;;
    q|Q|quit|exit)
      clear; echo ""
      rule "═" "$BLOOD"
      center "${GRAY}Session ended${RST}"
      rule "═" "$BLOOD"
      echo ""
      exit 0
      ;;
    *)
      echo ""
      echo -e "  ${WARN}  ${LY}Enter 1, 2 or Q to quit${RST}"
      sleep 1
      ;;
  esac
done
