# lan-inventory

A self-hosted LAN device inventory that works out **what each device actually is** - model, OS family, type -
by combining active and passive fingerprinting, and shows it on a small web page that keeps working offline.

It started as a replacement for NetAlertX: MAC-vendor lookup alone names a device "Ring LLC" or "Texas Instruments".
This combines many weaker signals into a model number, with the evidence listed so you can judge it.

## What it collects

| Source | How | What it yields |
|---|---|---|
| Presence | `arp-scan` every minute, merged with every MAC the listener heard | online/offline, first/last seen, address history |
| Quick look | `quickscan.py`: short nmap + vendor probes of any online device with no scan evidence, one per pass | ports and model within minutes of a device appearing, not at the next sweep |
| nmap | `-sS -O -sV -sC` + extra NSE, TCP 1-1024 and ~50 IoT/media ports; UDP discovery ports | OS guess, services, versions, NetBIOS/SMB names, TLS cert and web titles |
| mDNS | `avahi-browse` incl. TXT records | model identifiers (`ty=`, `md=`, `model=`), HomeKit category, printer model, device names |
| SSDP/UPnP | M-SEARCH + device-description XML | manufacturer, model, device type, server banner |
| Vendor APIs | unauthenticated local endpoints | Philips Hue bridge, Roku, Chromecast, AirPlay (`AppleTV6,2`, `Mac17,4` ...) |
| python-kasa | broadcast discovery | TP-Link Kasa / Tapo exact model |
| tinytuya | broadcast discovery | Tuya protocol version and product key |
| Listener | `scapy`: ARP, DHCP, mDNS (with TXT), SSDP + UPnP description; asks with one mDNS query and one M-SEARCH every 10 min (`PASSIVE_PROBE=0` for listen-only) | who holds which address right now, DHCP fingerprints, model identifiers, without waiting for a sweep |
| Reference data | Wireshark `manuf`, Fingerbank open DHCP list | manufacturer from small MAC blocks, DHCP OS family |

**Everything is filed under the device's MAC** (`evidence.py`). An IP address is only where a device was last seen: sweep
results are re-filed under the MAC nmap saw at that address during that sweep, and the last 21 days of sweeps are merged
per device, so a lease change, a device asleep at sweep time or a reused address never detaches a device from its
evidence or hands it to the next tenant. MACs that share a specific host name (Wi-Fi + dock, private + real address)
are linked as one device.

`identify.py` weighs the evidence. Each source has a weight: a device answering its own protocol (Hue, Roku, Kasa,
AirPlay, mDNS TXT) outranks a host name, which outranks open ports or nmap's OS class, which outrank the router's own
category or a manufacturer-only guess. Agreeing sources add up; a strong source that disagrees lowers the confidence and
is shown. Each device gets a confidence level and the list of reasons. Tests: `python3 -m unittest discover tests`. nmap's OS guess is ignored for hosts with no open ports, where it is noise.

You can override anything per device in `findings.json` (see `findings.example.json`); overrides win and are shown as "curated".

## Install

Needs nmap, arp-scan, avahi (running), Python 3.10+, and systemd. Linux only.

```sh
./install.sh            # venv, reference data, systemd units, first sweep
```

The page is served by a tiny `python -m http.server` bound to this host's LAN address (port 8480 by default; `LAN_PORT`, `LAN_BIND`).
The interface and subnet are detected from the default route (`LAN_IFACE`, `LAN_SUBNET` to override).

| unit | what |
|---|---|
| `lan-presence.timer` | presence pass every minute, rebuilds the page data |
| `lan-collect.timer` | deep sweep at 04:30 and 19:30; publishes to `scans/<date>_<time>/` only when finished |
| `lan-passive.service` | always-on listener (`state/passive.json`, keyed by MAC) |
| `lan-inventory.service` | serves `web/` |

Scans run as your user with only `CAP_NET_RAW` / `CAP_NET_ADMIN`; nothing runs as root.

## New-device alerts

Every presence pass (1 min) compares MACs against everything seen before. A never-seen MAC triggers an alert: a quick look at it
(short nmap, plus what the passive collector overheard) is run through the same identification engine, so the message says
what the device probably is, not just its MAC. Then:

- Sent on every configured channel in `ALERT_CHANNELS` (default `email,voicemonkey`; a channel with no credentials is skipped). Each channel's delivery is tracked separately, so one failing never causes another to repeat. **Email** is Gmail SMTP, the same way the radio gateway sends.
  Credentials are not stored here: set `ALERT_CONFIG=/path/to/file` (any `KEY=VALUE` file with `EMAIL_ADDRESS`,
  `EMAIL_APP_PASSWORD`, `EMAIL_RECIPIENT` - the gateway's config works as-is), or put those keys in an `alerts.env` next to the code
  (git-ignored), or use environment variables.
- **Alexa announcements** go through [Voice Monkey](https://voicemonkey.io) (`POST api-v3.voicemonkey.io/announce`). Create a free account, a Speaker
  wired to your Echo(s) with an Alexa Routine (a multi-room Speaker with one routine per Echo reaches several), and an API token, then put
  `VOICEMONKEY_TOKEN=...` and `VOICEMONKEY_DEVICES=<speaker-id>[,<speaker-id>...]` in `alerts.env` (git-ignored, mode 600). Spoken text is
  stripped of unusual characters and XML-escaped, because Voice Monkey passes it to Alexa as SSML and parts of it come from the network.
  The free plan allows 200 announcements a month; a 429 (throttle/quota) just leaves the alert pending for the next pass.
- The quick look at a new device is a short nmap of the ports that identify home gear, plus the same vendor probes the daily sweep uses
  (Hue, Roku, Chromecast, AirPlay) and, for TP-Link devices, Kasa/Tapo discovery - so most alerts name the model straight away.
  The spoken line is a sentence built from what is known: type and model, maker, the device's own name, OS, the last part of its address,
  and "I'm not very sure" when confidence is low.
- If sending fails the alert stays pending and is retried each pass for up to 24 h; it is never sent twice.
- The first run, and every device that existed before alerts were enabled, never alert.
- More than 4 new devices in one pass (guests arriving, a new router) become a single digest mail.
- `ALERT_RANDOMIZED=0` silences randomized (private) MACs. Some phones rotate those periodically, which looks like a new device each time.
- `python3 newdevice.py --test` sends a labelled test; `--simulate` prints a sample alert without sending.

## AI research for the gaps (opt-in)

`research.py` finds devices the sweep could not fully identify and asks Claude Code to research them on the web
(`lan-research.timer`, daily after the sweep). Enable with `ENABLE_RESEARCH=1 ./install.sh` (needs the `claude` CLI, logged in).

- **A standing Claude Code session in tmux** (`tmux attach -t lan-research`). Prompts are pasted in as a real bracketed paste and
  submitted with a verify-and-retry Enter (a plain Enter right after a big paste gets swallowed by the TUI); replies are read from
  Claude Code's own session transcript, not scraped from the screen. The session is sent `/clear` once a day, before the first batch,
  to stop context growth. `RESEARCH_MODE=oneshot` switches to a fresh `claude -p` per batch instead.
- **Web search is required, and checked.** The prompt demands a search per device; the transcript is inspected for real
  `WebSearch`/`WebFetch` calls, with one forced follow-up if it skipped them; answers that cite no `https` sources are discarded.
- **What leaves the machine:** per device only the OUI prefix (not the MAC), manufacturer, open ports/banners, web titles, mDNS service
  types and model-ish TXT keys, UPnP model fields, DHCP vendor class / option list and nmap's OS guess. No IPs, hostnames or
  device-given names. Inspect exactly what would be sent in `state/evidence.json`.
- **Contained:** the session is dedicated (not your day-to-day one) and started with only `WebSearch`/`WebFetch` - no shell, files or MCP
  connectors - in an empty directory. The evidence is presented as untrusted data, and the reply is parsed as JSON with every field
  validated and length-capped.
- **Only fills gaps:** answers go to `state/research.json`, show as "AI-researched" with the reasoning and sources, and never override
  curated labels or medium/high-confidence measured identity.
- **Bounded:** at most 15 devices per run in batches of 5, unchanged evidence cached for 30 days.

## Router console

Four pages under **Router** in the top nav (Devices / Router / Ping), sharing `web/console.css` + `web/console.js`
(top bar in `web/nav.css`, also used by the Devices page):

- **Overview** (`router.html`): attention items (weak wireless backhaul, offline nodes, firmware, gateway memory),
  status tiles, gateway throughput chart (1h/24h/7d/30d from `/api/history`), mesh at a glance, client breakdowns.
- **Mesh** (`router-mesh.html`): topology tree built from each node's `parent_device_id` (it really is a tree:
  most M5s hang off the Office X55), wired / wireless / weak / offline links, and a node table with sparklines.
- **Clients** (`router-clients.html`): search, filters, signal and traffic sparklines, and a detail panel with
  reserve-IP / block actions. `?node=<device_id>`, `?mac=<mac>`, `?f=weak` deep-link into it.
- **Settings** (`router-settings.html`): settings grouped with verified / tested-upstream / unverified badges.
  Every write goes through one review panel (`LC.review`): field diff, the exact params, a required tick-box for
  anything unverified or not low-risk, then a verdict from the **read-back**, never the ACK. Redacted secrets are
  never sent back (the page leaves those keys out, and `/api/write` refuses params containing the placeholder).

"Refresh now" (`POST /api/refresh`) runs one `router_collect.py` snapshot immediately (~15 s).

**After a write the router closes its control port for up to ~90 s** while it applies the change (it varies;
sometimes not at all). `router_busy.py` locks every router connection during that time, across the web server,
collector and MCP server: requests get a 503 with `Retry-After`, and the collector skips its run. A watcher
probes the port every 5 s and releases the lock when the router is back, then takes a fresh snapshot.
The pages show a progress bar and grey out their router controls until then.

Node names: preset rooms arrive as plain `nickname` ("garage"); renamed nodes have `nickname: "custom"` and the
name in `custom_nickname`, sometimes base64 ("VGVjaCBjbG9zZXQ=" = "Tech closet"). `LC.text()` decodes either.

**Two read paths.** Every 5 minutes `lan-router.timer` runs `router_collect.py --web-only`: it reads the
router's local admin web interface on :80 (`deco_web.py`: encrypted LuCI-style login with the account
password, `DECO_WEBPW` overrides; the session is saved in `state/deco_web_session.json` and reused). That
gives nodes (with parents), clients (with their node, via per-node client lists), WAN and gateway CPU/memory.
The web interface has no node speeds, so the same run also logs in to TMP for one read (`device_list_speed`,
~1.5 s) to feed the throughput graph; if that is ever refused or times out it stops for an hour (logged as
`speed_backoff`, state in `state/tmp_speed.json`). `TMP_SPEED_READS=0` in `router.env` turns it off.
The TMP control port (20001) gets a full read hourly (`lan-router-full.timer`) and on **Refresh now**
(settings, client signal, node speeds), with its ~30 reads paced `TMP_READ_GAP` seconds apart (default 1,
`router.env`). Collector runs are serialised by `state/router_collect.lock`. A web snapshot carries the last full read's other sections over, marked stale, with the full
read's time shown in the top bar; speeds are never carried. A write's read-back is saved straight into the
snapshot. If a full read is refused, the web snapshot is used and the page says so. Writes never use the web
interface.
The web (:80) snapshot is paced too: `WEB_READ_GAP` seconds between requests (default 1.5). Which node each client is on costs one
request per node, so each run re-asks only `WEB_NODE_PROBES` nodes (default 2, rotating: every node about every 15 min, so a roam
shows up at most that late) and the whole map (`state/deco_web_nodes.json`) is rebuilt every `WEB_NODE_MAP_TTL` s (6 h) or for a new client.
Only a refused connection counts as port 20001 down; a timeout logs `speed_slow` and changes nothing.

## Ping

`ping.html`: continuous traceroute, a Linux port of the Windows "pingtrace" tool. `ping_collect.py`
(`lan-ping.service`, always on) runs `mtr --json -c1 -G1` every `PING_INTERVAL` s (default 2) to `PING_TARGET`
(default 8.8.8.8), both read from `router.env` each round, so edits apply without a restart. Rounds go to
`state/ping_history.sqlite` (24 h kept, per target: a new target starts a fresh history), or `PING_DB` in
`router.env` (relative to the repo; needs a restart of both services). It's written every round, so on a box
that cares about SSD wear point `PING_DB` at a tmpfs and copy it to disk with `sqlite3 <db> ".backup <file>"`
(a plain file copy of a live WAL database can be torn). `HISTORY_DB` does the same for the router history
(`state/router_history.sqlite`, 30 days, written every 5 min). `GET /api/ping?window=<s>`
returns per-hop loss/last/avg/min/max, reverse-DNS names, the last 120 rounds per hop, and the collector's
counters (`rounds_ok`, `rounds_failed`, `last_error`). Needs `mtr` (Arch: `mtr`, Debian: `mtr-tiny`).

## Logs

`logs.html` (top bar → Logs) shows what happened, newest first, with a full record behind each line.
`lan_log.py` writes one JSON line per event into `logs/<stream>-YYYY-MM-DD.jsonl` and deletes day files
older than 30 days. Run `python3 lan_log.py [stream ...]` to print the last day of events in a terminal.

| Stream | Written by | What |
|---|---|---|
| `collect` | router_collect.py | every snapshot: full or web, trigger (timer / refresh by user), reads OK/failed, slowest reads, seconds |
| `writes` | router_web.py, deco_mcp_server.py | every router write and refused write: who, params (secrets scrubbed), ACK, read-back |
| `busy` | router_busy.py | post-write lockout: when port 20001 closed after the write, how long it stayed shut |
| `tmp` | router_collect.py | port 20001 stopped / started answering (one bare TCP connect per 5-min run, no login) |
| `mesh` | router_changes.py | node left/rejoined, renamed, new IP, new upstream, backhaul wired↔wireless, backhaul signal, firmware |
| `clients` | router_changes.py | client came online, went offline, moved node (roamed), changed band or IP |
| `ping` | ping_collect.py | outages to the target (3+ rounds without a reply), route changes, mtr failures |
| `web` | router_web.py | failed logins to this site |

The page also has a **Service journal** view (the four systemd units, page requests hidden by default).
New history metrics feed the Overview's "Last 24 hours" card: `tmp_port_up`, `node_online`, `node_wired`,
`node_sig_5g` / `node_sig_24g`, `node_clients`, `collect_seconds` (see router_history.py).

Logs go to `LAN_LOG_DIR` if set, else `logs/`. To keep them off the SSD, mount a tmpfs there and copy
it to disk daily and at shutdown; the reference box does this with its existing `ram-writeback-flush`
(rsync to `/var/backups/ram-writeback/lan-inventory-logs/`) and merges the copy back at boot.

## Router protocol

The console talks to a TP-Link Deco mesh over its native TMP
protocol (the one the Deco Android app uses) - no cloud account involved beyond your TP-Link login, no SSH
or debug backdoor. It's built from a reverse-engineered protocol writeup, not vendored third-party code -
see `deco_tmp.py`'s module docstring.

- **Read side:** `router_collect.py` (full read over TMP: hourly via `lan-router-full.timer` and on "Refresh now"; `lan-router.timer` runs `--web-only` every 5 min) snapshots ~30 opcodes - mesh nodes,
  clients (with the router's own hostname/device-type/band/signal data, which also feeds `identify.py` -
  see `router_clients()` in `build_report.py`), Wi-Fi, QoS, port forwarding, DHCP, DDNS, VPN config, firmware
  - into `web/router.json`. VPN private keys and Wi-Fi passwords are redacted by default (`deco_tmp.redact`).
- **Write side:** the page can edit most of what it reads. Every write is tagged **verified** (proven live,
  with a before/after read-back, not just a trusted "success") or **unverified** (the opcode exists in the
  public opcode-numbering pattern but nobody has confirmed what it does - it may silently no-op, which is
  exactly what happened testing HomeShield's protection toggle: the router ACKs and changes nothing). The
  page shows this status on every section and requires an extra tick-box for anything unverified or higher
  risk (WAN-affecting settings like IPv6/DDNS/internet backup). See `deco_tmp.WRITE` and `deco_tmp.SETTINGS`
  for the full table and reasoning per opcode.
- **Login:** the whole site (not just the router page) sits behind HTTP Basic Auth -
  `ROUTER_WEB_USER`/`ROUTER_WEB_PASS` in `router.env` (git-ignored, mode 600), **default `user`/`user`** -
  `router_web.py` prints a loud warning on startup while that default is live. Change it before leaving this
  reachable beyond localhost.
- **Credentials:** `router.env` next to the code (same KEY=VALUE convention as `alerts.env`) needs
  `DECO_HOST`, `DECO_EMAIL`, `DECO_ACCTPW` - your TP-Link *account* email/password, not the admin page's.
  Missing credentials just mean the router page/collector sit idle; the device page keeps working.
- **MCP server for Claude:** `deco_mcp_server.py` exposes the same `deco_tmp.py` client as MCP tools (reads,
  `list_writes`, `write_router_setting`) so you can ask Claude to look at or change router settings directly.
  `install.sh` writes a project `.mcp.json` from `mcp.json.example`. Same verified/unverified gating as the
  web page; writes always return the read-back state, not just the router's ACK. Refusals (unverified write,
  unknown name, post-write lockout) reach the model with their reason, before any router login.
  Two tools never touch the router: `network_summary` (mesh, WAN, where this host is connected, ping loss
  and per-hop latency, control-port state, notable events over the last N minutes) and `get_logs` (the
  event logs above). `DECO_MCP_READONLY=1` leaves only those plus `list_reads`/`get_router_data`, for
  unattended callers. Example, giving another project's Claude a read-only view:
  `claude mcp add deco-router -s local -e DECO_MCP_READONLY=1 -- <repo>/venv/bin/python3 <repo>/deco_mcp_server.py`

## Notes

- **The page requires a login** (HTTP Basic Auth - see "Router page" above for where the credentials live).
  It lists MACs, device names, and (on the router page) live router configuration.
- **Offline cache:** the page keeps its last data in `localStorage` and shows an "offline" banner if the server is unreachable. A service worker
  is included but browsers only allow those on HTTPS/localhost, so on a plain-HTTP LAN address `localStorage` is the cache.
- Randomized (private) MACs have no usable manufacturer. For those, the DHCP fingerprint, mDNS and open-port signals are what identify the device.
- Only scan networks you own or are authorized to test.
- Private data (`scans/`, `state/`, `web/data.json`, `findings.json`) is git-ignored.

## Credits

[nmap](https://nmap.org), [arp-scan](https://github.com/royhills/arp-scan), [scapy](https://scapy.net),
[python-kasa](https://github.com/python-kasa/python-kasa), [tinytuya](https://github.com/jasonacox/tinytuya),
Wireshark's manufacturer database, and the Fingerbank/PacketFence open DHCP fingerprint data (ODbL).
Reference data is downloaded by `fetch_data.sh`, not bundled.

The router side stands on two projects' protocol work. No code from either is copied here; the clients are
reimplementations from their descriptions:

- [mthsg/pydeco-tmp](https://github.com/mthsg/pydeco-tmp) (MIT): the Deco TMP protocol: SSH transport,
  framing, login and opcode tables. Writes tagged "upstream-confirmed" in `deco_tmp.py` are the ones it
  lists as seen in real app captures. `deco_tmp.py` is built on that.
- [tplinkrouterc6u](https://github.com/AlexandrErohin/TP-Link-Archer-C6U) (GPL-3.0): the encrypted LuCI-style
  login of TP-Link's local web interface, which `deco_web.py` uses as the fallback path. Compared line by
  line on 2026-10-25: no code in common, only the protocol, so the MIT licence covers this repo whole.
