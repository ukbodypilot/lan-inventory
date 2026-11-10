#!/bin/sh
# Download the reference databases used by identify.py into ./data
set -e
cd "$(dirname "$0")"
mkdir -p data
# Wireshark manufacturer database: covers 24-, 28- and 36-bit MAC blocks (plain OUI lists miss the small ones)
curl -fsSL --max-time 120 -o data/manuf.tmp https://www.wireshark.org/download/automated/data/manuf && mv data/manuf.tmp data/manuf
# Fingerbank/PacketFence open DHCP fingerprint list (ODbL; old, used only as a fallback)
curl -fsSL --max-time 120 -o data/dhcp_fingerprints.conf.tmp \
  https://raw.githubusercontent.com/inverse-inc/packetfence/devel/conf/dhcp_fingerprints.conf \
  && mv data/dhcp_fingerprints.conf.tmp data/dhcp_fingerprints.conf
echo "ok: $(wc -l < data/manuf) manuf lines, $(grep -c '^\[os' data/dhcp_fingerprints.conf) DHCP OS entries"
