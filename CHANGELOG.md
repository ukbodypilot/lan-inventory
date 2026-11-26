# Changelog

The version is the git tag. Releases before 2.0.0 were never tagged.

## Unreleased

## 2.4.0 - 2026-11-26

One look with the sibling apps, and an Apps menu.

- **One look with its sibling apps.** Every page loads `rig.css`, the "rig front panel" house style
  shared with radio-gateway, tesla-tools and Family Locator (vendored with its fonts in `web/`). The
  patch-panel names now map onto its tokens: amber for links, focus and the selected control, yellow
  for attention, green link lights, red faults; label tape is cream so it never reads as a warning.
  Barlow Semi Condensed and JetBrains Mono replace Overpass (removed). **Dark only.** Mesh links are
  coloured by health (green, yellow when weak). Offline cache bumped to v4.
- **Apps menu.** A `web/apps.json` (see `web/apps.example.json`, git-ignored) adds an "Apps" menu to the
  top bar linking your other apps; no file = no menu.
- **Network adapters can't disprove a brand.** USB and dock network-adapter makers (Belkin, Plugable,
  UGREEN, StarTech, Anker, ASIX…) join the parts makers: a laptop on a Belkin adapter is not a mismatch.

## 2.3.0 - 2026-11-25

Name checks that tell a disguise from a dock, a rename or a parts maker.

- **Fewer false name mismatches.** A MAC prefix from a parts or contract maker (LG Innotek, Murata, Pegatron…)
  no longer disproves a brand name, and the AI name reading is told so. A dock's or USB adapter's own name is
  treated as a shared network port: the docked device's name is shown and it is not a conflict. Two names that
  were never in use at the same time are reported as a rename (the listener now keeps when each DHCP host name
  was used, and when the mDNS host name was last heard). A device going back to a name it has used before is
  no longer a "renamed" event (`state/name_history.json`).
- nmap's OS guess is only used when the host has an open TCP port; a host answering only on UDP (mDNS) got
  noise such as "Aerohive HiveOS".

## 2.2.0 - 2026-11-24

Per-device bandwidth history, and a web-only mode for Deco firmware that closes the TMP control port.

- **Bandwidth per device.** Each device on the Devices page and in the Clients drawer gets a 7-day download/upload
  chart and an estimated data-per-day table; Clients gets a sortable "Data · 24h" column. The Deco reports only
  speeds at each 5-minute read, never byte counts, so totals hold each speed until the next read (gaps over
  10 min count as 10 min) and miss bursts between reads. `/api/usage` serves them. The unit is still assumed kB/s.
- **Living without port 20001.** Some Deco firmware (seen on an X55 with 1.11.1) refuses every connection to the
  TMP control port. `deco_web_discover.py` maps what the admin web interface offers instead (it follows the
  page's own module registry, then sends one paced read per endpoint, with secrets redacted); IPv6 and Wi-Fi band
  settings are now read from it on the hourly run when TMP is down. Reservations, DHCP leases, port forwarding,
  per-client signal, node speeds and all writes have no web equivalent.
- While the port is closed the collector makes no TMP logins (one bare connect per run notices it coming back),
  the Settings page and Clients drawer switch off every change with the reason, and sections frozen from before
  the port closed are labelled with their date. `router.json` carries `tmp_port`.

## 2.1.0 - 2026-11-21

Device names are checked instead of trusted, and the web pages get a new look with the device list first.

- **New look: "patch panel".** The web pages borrow from the network closet: rack-steel background, faceplate
  panels and a dark top rail, with the port LEDs as the only bright colours (green online, amber needs attention,
  red conflict, grey offline). A hand-labelled device wears a strip of label-maker tape. Light and dark themes.
  Overpass and Overpass Mono are bundled in `web/fonts/` (OFL), so no page loads fonts from Google any more.
  Shared tokens live in the new `web/panel.css`.
- **Address map as a patch panel.** The /24 is drawn as 256 ports at the top of the Devices page; empty runs of
  32 fold into one band. Selecting a port (mouse or keyboard) opens that device in the list.
- **Devices list first.** The list now follows the address map instead of six charts, which move to a Trends
  section below it. The five number cards are now one strip of filter buttons (online, needs attention, new this
  week); "New" is also a filter.
- **Easier to work through a long list.** The search bar and table header stay visible while scrolling, with a
  "Showing N of M" count. `/` focuses search and Esc clears it. Search, type and filter are kept in the URL
  (`?q=`, `?type=`, `?show=`), so a filtered view can be bookmarked; an empty result offers to clear the filters.
- The router pages no longer draw ordinary data (wired clients, upload) in the warning colour.
- **SSDP searches are no longer read as services.** The listener filed the `ST` of an `M-SEARCH` request under the
  sender as if the sender offered it, so a phone whose casting app looks for Roku, webOS and Samsung TVs was
  labelled a Roku. Only `NOTIFY` announcements and replies count as what a device offers; what it searches for is
  kept apart as `ssdp_searches`. Identity cache `VERSION` 5.
- **A game console is not "disagreeing" with its media renderer.** A console that also answers as a UPnP
  MediaRenderer no longer gets an "evidence disagrees" flag and a lowered confidence.
- **Names are checked, not trusted.** Every name a device gives (its own API, AirPlay, DHCP, mDNS, UPnP, the router
  label) is kept per source. A device whose names point to different people, or claim a product or OS the hardware
  is not, gets a "name mismatch" tag and counts under "Needs attention".
- **Both names shown.** A row with conflicting names shows them side by side, the rival in red; search matches
  every name a device gives and the inferred owner.
- **Replaced names expire.** A service name is dropped once the device announces another name for the same
  service; an old sweep's names no longer override newer announcements; a rename queues a fresh look at the
  device (`state/relook.json`) and older answers lose their names until it succeeds.
- **Rename alerts.** A device that changes one of its names, or a new device that arrives with a name another device
  already uses, is logged to the Devices stream and e-mailed (`state/names.json`).
- **AI name reading** (`names_ai.py`). Claude, with no tools, decomposes the names into owner / thing / place and
  flags contradictions. Runs from the presence pass only when names changed. It sends device-given names to Claude;
  `NAMES_AI=0` switches it off.
- **Measured names win.** A name the device reports now beats a hand label in `findings.json`, and a name typed in
  the Deco app is used only when the device reports none.
- `Ring-<id>` host names are typed as cameras; `linux-2` / `none-2` style host names are no longer used as names.

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
