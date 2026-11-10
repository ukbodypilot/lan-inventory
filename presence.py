#!/usr/bin/env python3
"""Presence tracker: who is on the LAN, first seen, last seen, at which address.

Run every minute (lan-presence.timer). Two sources, merged per MAC:
  arp-scan      an active sweep of the subnet (needs CAP_NET_RAW)
  passive.py    every MAC the listener heard since the last pass (ARP, DHCP, mDNS, SSDP). Catches devices that
                sleep through an ARP sweep (phones, a dozing laptop renewing its lease) and address changes
                the moment they happen.
Keeps state/presence.json, logs joins / address changes to the "devices" log, alerts on new devices, gives one
device without scan evidence a quick look (quickscan.py), then rebuilds web/data.json.
"""
import datetime
import json
import os
import re
import subprocess
import sys

import evidence
import netinfo

ROOT = os.path.dirname(os.path.abspath(__file__))
STATE = os.path.join(ROOT, "state", "presence.json")
IFACE = netinfo.iface()
UNKNOWN_VENDOR = re.compile(r"^\(Unknown")
HEARD_WINDOW = int(os.environ.get("PRESENCE_HEARD_SECONDS", "180"))  # a passive sighting this fresh counts as present
BACKFILL = 3600  # a MAC the listener has known longer than this is not "new" when presence first records it
MAX_HISTORY = 12
OFFLINE_AFTER = int(os.environ.get("ONLINE_MINUTES", "10")) * 60


def now():
    return datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def load():
    return json.load(open(STATE)) if os.path.exists(STATE) else {}


def self_entry():
    try:
        return netinfo.mac(IFACE), netinfo.ip(IFACE)
    except Exception:
        return None, None


def save(state):
    evidence.jsave(STATE, state)


def log(ev, **kw):
    try:
        import lan_log
        lan_log.event("devices", ev, **kw)
    except Exception:
        pass


def arp_scan():
    # no --ignoredups: two MACs answering one IP is evidence
    out = subprocess.run(["arp-scan", "--interface=" + IFACE, "--localnet", "--plain", "--retry=3"],
                         capture_output=True, text=True, timeout=240)
    if out.returncode != 0:
        raise SystemExit("arp-scan failed: " + out.stderr.strip()[:300])
    seen = {}
    for l in out.stdout.splitlines():
        if re.match(r"^\d+\.\d+\.\d+\.\d+\t", l):
            ip, mac, vendor = (l.split("\t") + ["", ""])[:3]
            seen[mac.lower()] = (ip, re.sub(r"\s*\(DUP: \d+\)$", "", vendor))
    return seen


def heard():
    """mac -> (ip or None, first_seen) for MACs the passive listener heard within HEARD_WINDOW.
    The IP is given only if it was itself seen that recently; an older one may have moved on."""
    out = {}
    for mac, h in evidence.passive_hosts().items():
        if evidence.age_days(h.get("last_seen")) * 86400 > HEARD_WINDOW:
            continue
        ip = h.get("ip")
        if ip and evidence.age_days((h.get("ips") or {}).get(ip)) * 86400 > HEARD_WINDOW:
            ip = None
        out[mac] = (ip, h.get("first_seen", ""))
    return out


def sighting(state, mac, ip, t, via, vendor=""):
    """Record one sighting. Returns 'new', 'moved' or None."""
    what = None
    rec = state.get(mac)
    if rec is None:
        rec = state[mac] = {"first_seen": t}
        what = "new"
    old = rec.get("ip")
    if ip and ip != old:
        if old:
            rec["ip_history"] = ([{"ip": old, "until": t}] + rec.get("ip_history", []))[:MAX_HISTORY]
            what = what or "moved"
        rec["ip"] = ip
    rec["last_seen"] = t
    if via == "arp":
        rec["last_arp"] = t
    rec["via"] = sorted(set(rec.get("via_now", [])) | {via})
    rec["via_now"] = rec["via"]
    if vendor and not UNKNOWN_VENDOR.match(vendor):
        rec["vendor"] = vendor
    return what


def main():
    state = load()
    known = set(state)
    t = now()
    for r in state.values():
        r.pop("via_now", None)
    arp = arp_scan()
    smac, sip = self_entry()
    if smac:
        arp[smac] = (sip, "")
    new, moved, online = [], [], set()
    for mac, (ip, vendor) in arp.items():
        old = state.get(mac, {}).get("ip")
        w = sighting(state, mac, ip, t, "arp", vendor)
        online.add(mac)
        if w == "new":
            new.append(mac)
        elif w == "moved":
            moved.append((mac, old, ip))
    for mac, (ip, first) in heard().items():
        if mac not in state:
            if not ip:
                continue  # never seen holding an address (a mesh node's internal interface, a failed join)
            fresh = evidence.age_days(first) * 86400 < BACKFILL
            sighting(state, mac, ip, t, "heard")
            if fresh:
                new.append(mac)
            else:
                known.add(mac)  # the listener has known it for a while: record it, do not announce it
            online.add(mac)
            continue
        old = state[mac].get("ip")
        # an ARP answer this pass is the authority on the address; otherwise take what the listener saw
        w = sighting(state, mac, None if mac in arp else ip, t, "heard")
        online.add(mac)
        if w == "moved":
            moved.append((mac, old, ip))
    for r in state.values():
        r.pop("via_now", None)
    # online/offline transitions -> "devices" log (the page draws each device's presence history from these).
    # A device is online while it was seen within OFFLINE_AFTER, so one missed sweep does not flap it.
    first_run = not any("online" in r for r in state.values())
    for mac, r in state.items():
        on = evidence.age_days(r.get("last_seen")) * 86400 <= OFFLINE_AFTER
        if r.get("online") != on:
            if not first_run:
                log("online" if on else "offline", mac=mac, ip=r.get("ip"), last_seen=r.get("last_seen"))
            r["online"] = on
    if first_run:
        log("baseline", online=sorted(m for m, r in state.items() if r["online"]))
    save(state)  # first_seen is on disk before anything else can go wrong
    for mac in new:
        log("joined", mac=mac, ip=state[mac].get("ip"), vendor=state[mac].get("vendor"), first=True)
    for mac, old, ip in moved:
        log("ip_changed", mac=mac, was=old, ip=ip)
    print("presence: %d on LAN now (%d by ARP), %d known, %d new, %d moved" % (len(online), len(arp), len(state), len(new), len(moved)))
    # New-device alerts. Skipped on the very first run (empty state = everything would look new). Never allowed to
    # break the scan cycle: a mail/nmap problem just leaves the record pending and the next pass retries.
    if known:
        try:
            import newdevice
            newdevice.process(state, [m for m in new if m not in known])
            save(state)
        except Exception as e:
            print("alerts: %s: %s" % (type(e).__name__, str(e)[:200]))
    build = [sys.executable, os.path.join(ROOT, "build_report.py")]
    subprocess.run(build, check=True)
    if os.environ.get("QUICK_SCAN", "1") != "0":
        try:
            import quickscan
            done = quickscan.scan_missing(state, online, smac)
            if done:
                print("quick look: %s" % ", ".join(done))
                subprocess.run(build, check=True)
        except Exception as e:
            print("quick look: %s: %s" % (type(e).__name__, str(e)[:200]))


if __name__ == "__main__":
    main()
