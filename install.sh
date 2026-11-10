#!/bin/sh
# Install lan-inventory: venv, reference data, systemd units. Run as your normal user (uses sudo for systemd).
#   LAN_PORT=8480 LAN_BIND=<ip> ./install.sh      (bind defaults to this host's LAN address)
set -e
DIR="$(cd "$(dirname "$0")" && pwd)"
USER_NAME="$(id -un)"
cd "$DIR"

missing=""
for c in nmap arp-scan avahi-browse mtr python3 ip curl; do command -v "$c" >/dev/null 2>&1 || missing="$missing $c"; done
if [ -n "$missing" ]; then
  echo "Missing:$missing"
  echo "  Arch:   sudo pacman -S nmap arp-scan avahi nss-mdns mtr"
  echo "  Debian: sudo apt install nmap arp-scan avahi-utils python3-venv curl iproute2 mtr-tiny"
  exit 1
fi
systemctl is-active --quiet avahi-daemon || echo "note: avahi-daemon is not running (mDNS survey needs it): sudo systemctl enable --now avahi-daemon"

python3 -m venv venv
./venv/bin/pip install -q -r requirements.txt
./fetch_data.sh

BIND="${LAN_BIND:-$(python3 -c 'import netinfo;print(netinfo.ip())')}"
PORT="${LAN_PORT:-8480}"
CLAUDE_PATH="$(command -v claude || true)"
for f in systemd/*.service.in; do
  out="/etc/systemd/system/$(basename "${f%.in}")"
  sed -e "s#@DIR@#$DIR#g" -e "s#@USER@#$USER_NAME#g" -e "s#@BIND@#$BIND#g" -e "s#@PORT@#$PORT#g" -e "s#@HOME@#$HOME#g" -e "s#@CLAUDE@#${CLAUDE_PATH:-claude}#g" "$f" | sudo tee "$out" >/dev/null
done
sudo cp systemd/*.timer /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now lan-inventory.service lan-passive.service lan-ping.service lan-presence.timer lan-collect.timer
# Router page/API: only if router.env (or DECO_EMAIL/DECO_ACCTPW in the env) is configured.
if [ -s router.env ] || [ -n "$DECO_EMAIL" ]; then
  sudo systemctl enable --now lan-router.timer lan-router-full.timer
  sudo systemctl start --no-block lan-router-full.service
else
  echo "Router page has no Deco credentials yet. Create router.env next to install.sh:"
  echo "  DECO_HOST=192.168.2.1"
  echo "  DECO_EMAIL=<your TP-Link account email>"
  echo "  DECO_ACCTPW=<your TP-Link account password>"
  echo "  ROUTER_WEB_USER=<pick something that isn't 'user'>"
  echo "  ROUTER_WEB_PASS=<pick something that isn't 'user'>"
  echo "then: sudo systemctl enable --now lan-router.timer lan-router-full.timer && sudo systemctl restart lan-inventory"
fi
if [ ! -s router.env ] || grep -q '^ROUTER_WEB_PASS=user$' router.env 2>/dev/null; then
  echo "NOTE: the router page is using the default login user/user until you set ROUTER_WEB_USER/ROUTER_WEB_PASS in router.env."
fi

# MCP server for Claude Code: give it its own .mcp.json (not committed -- has an absolute,
# machine-specific interpreter path) if one doesn't already exist.
if [ ! -f .mcp.json ]; then
  sed -e "s#@DIR@#$DIR#g" mcp.json.example > .mcp.json
  echo "Wrote .mcp.json for the deco-router MCP server. Restart Claude Code (or /mcp reconnect) in this project to pick it up."
fi
# Opt-in: sends minimised device fingerprints (OUI prefix, ports, banners, model strings - no MACs/IPs/names) to Claude for web research.
if [ "${ENABLE_RESEARCH:-0}" = "1" ]; then
  [ -n "$CLAUDE_PATH" ] || { echo "ENABLE_RESEARCH=1 but the claude CLI is not on PATH"; exit 1; }
  sudo systemctl enable --now lan-research.timer
else
  echo "AI research is off. To enable (needs the claude CLI, logged in): ENABLE_RESEARCH=1 ./install.sh"
fi
# first data: an ARP pass now, the deep sweep in the background
sudo systemctl start lan-presence.service || true
sudo systemctl start --no-block lan-collect.service
echo "Page: http://$BIND:$PORT/  (fills in as the first sweep finishes, ~20-40 min)"
