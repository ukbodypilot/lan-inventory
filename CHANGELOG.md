# Changelog

The version is the git tag. Releases before 2.0.0 were never tagged.

## 2.0.0 - 2026-11-09

Identification rebuilt around the MAC address, and a new Devices page.

### Changed (breaking)
- `state/passive.json` is now keyed by MAC (`{"v": 2, "hosts": {...}}`). The listener migrates an old file on its
  first start; anything reading the old per-IP `mdns` / `ssdp` tables must use `evidence.passive()` instead.
- `web/data.json` has one row per MAC. A device no longer disappears when another device takes its last address;
  `ip_stale` marks an address that has since been reused. New fields: `aliases`, `conflict`, `ip_history`, `seen`,
  `scan_at`, `scan_kind`, `link`, `signal_dbm`, `network`, plus top-level `history`, `scans`, `subnet`.
- The listener is no longer listen-only: it sends one mDNS query and one SSDP M-SEARCH every 10 minutes
  (`PASSIVE_PROBE=0` restores listen-only).
- `build_report.py` no longer takes a scan directory argument; it merges every sweep of the last `SCAN_DAYS` (21).
- Identities cached under older rules are dropped (`identify.VERSION`).

### Added
- `evidence.py`: one per-MAC view of sweeps, quick scans and listener data. Sweep files are re-filed under the MAC
  nmap saw at each address during that sweep (`scans/<stamp>/by_mac.json`), and older sweeps fill what the newest lacks.
- `quickscan.py`: a short nmap + vendor-probe look at any online device with no scan evidence, one per presence pass.
- Listener: ARP sightings, mDNS TXT records per service instance, UPnP description fetch, DHCP requested address.
- Presence: runs every minute and merges what the listener heard, so devices that sleep through an ARP sweep still
  count; keeps an address history per device; logs joins, address changes and online/offline to a `devices` log stream.
- Devices that appear under several MACs (Wi-Fi + dock, private + real address) are linked by a shared specific host name.
- Devices page: summary tiles, devices-online chart, type bars, address map, confidence and connection bars,
  first-time devices per day, per-device presence strips, type icons, and an evidence view per device.
- Logs page: Devices stream.
- Second daily sweep at 19:30.
- Offline tests: `python3 -m unittest discover tests`.

### Fixed
- Evidence stranded at a device's old address after a lease change, and scan evidence withheld until the next sweep.
- The Deco's `client_type` was trusted at medium confidence (it files Echos as tablets and an Apple TV as a phone);
  it is now a low-confidence hint. Its placeholder names ("Device_1A2B", "iot_device_5E6F") are no longer used as names.
- Any HomeKit device was typed "IoT" at high confidence; the HomeKit category is now used, and none means no type.
- Roku devices reported as Android; an iPad on a private MAC reported as a phone; the router reported as an access point.
- The listener's per-device mDNS name list filled with rotating UUID host names and then refused new names.
- mDNS names with non-ASCII characters were mis-decoded.
- A Kasa plug that missed one discovery lost its model until the next successful sweep.

### Upgrading
```sh
git pull
sudo cp systemd/lan-presence.timer systemd/lan-collect.timer /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl restart lan-passive.service lan-presence.timer lan-collect.timer
```
Restarting `lan-collect.timer` after 19:30 starts a sweep straight away.
