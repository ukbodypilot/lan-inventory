#!/usr/bin/env python3
"""Merge all evidence into web/data.json for the LAN inventory page. One row per MAC.

Inputs, all read per MAC through evidence.py (an IP is only where a device was last seen, never a key):
  scans/<stamp>/      collect.py sweeps of the last SCAN_DAYS (nmap, mDNS, SSDP, vendor probes, Kasa, Tuya)
  state/quick/        quickscan.py targeted looks
  state/passive.json  what passive.py heard: DHCP, mDNS + TXT, SSDP/UPnP
  state/presence.json who is on the LAN (presence.py): first/last seen, current IP, IP history
  web/router.json     Deco client list (router_collect.py): its name for the client, band/wired
  findings.json, scans/*/findings.json   hand labels (by "mac"; top-level file wins)
identify.py turns the merged evidence into model / OS / type / confidence.

  build_report.py
"""
import base64
import datetime
import glob
import json
import os
import re

import evidence
import identify
import netinfo
from evidence import jload, nmap_hosts  # noqa: F401  (re-exported: older callers import them from here)

ROOT = os.path.dirname(os.path.abspath(__file__))
ONLINE_WINDOW = datetime.timedelta(minutes=int(os.environ.get("ONLINE_MINUTES", "10")))
LAN = re.compile(r"^192\.168\.|^10\.|^172\.(1[6-9]|2\d|3[01])\.")
HIDE_RANDOM_DAYS = int(os.environ.get("HIDE_RANDOM_DAYS", "14"))   # an unlabelled private MAC unseen this long is dropped
HIDE_DAYS = int(os.environ.get("HIDE_DAYS", "120"))                # any unlabelled device unseen this long is dropped
RANK = {"low": 0, "medium": 1, "high": 2}
CACHE_DAYS = 45
# Host names that are a model or a default, not one particular device: sharing one does not make two MACs one device.
SHARED_NAME = re.compile(r"^(iphone|ipad|android|mac|xbox(one)?|samsung|galaxy.*|pixel.*|ep\d+|hs\d+|kp\d+|wlan\d|espressif|"
                         r"deco[-_ ]?.*|amazon-.*|localhost|linux|roku.*|chromecast.*|homepod.*|apple-?tv.*|.*roku ?tv)$", re.I)


def router_clients():
    """mac -> {name, client_type, wired, band, signal_dbm, interface, ip, online} from the Deco's client list, if
    router_collect.py has written one. The Deco's `name` is base64."""
    snap = jload(os.path.join(ROOT, "web", "router.json"), {})
    read = (snap.get("reads") or {}).get("client_list", {})
    if not read.get("ok"):
        return {}
    out = {}
    for c in (read["result"].get("client_list") or []):
        mac = c.get("mac", "").replace("-", ":").lower()
        if not mac:
            continue
        name = None
        try:
            decoded = base64.b64decode(c.get("name", "")).decode("utf-8", "replace").strip()
            if decoded and decoded.lower() not in ("none", ""):
                name = decoded
        except Exception:
            pass
        link = c.get("linked_device_info") or {}
        band = next(iter(link.get("connection_type") or []), None) or (c.get("connection_type") if isinstance(c.get("connection_type"), str) else None)
        signal = (link.get("signal_strength") or {}).get(band) if band else None
        out[mac] = {
            "name": name,
            "client_type": c.get("client_type") if c.get("client_type") not in (None, "", "other") else None,
            "wired": c.get("wire_type") == "wired",
            "band": {"band2_4": "2.4GHz", "band5": "5GHz", "band6": "6GHz"}.get(band, band),
            "signal_dbm": signal,
            "interface": c.get("interface"),  # main / guest / iot
            "ip": c.get("ip"), "online": c.get("online"),
        }
    return out


def netinfo_subnet():
    try:
        return netinfo.subnet()
    except (Exception, SystemExit):
        return None


def randomized(mac):
    return bool(mac) and int(mac[1], 16) & 2 == 2


def recent(ts):
    t = evidence.parse_ts(ts or "")
    return bool(t) and evidence.utcnow() - t <= ONLINE_WINDOW


def ip_key(x):
    try:
        return [int(p) for p in x.split(".")]
    except (ValueError, AttributeError):
        return [999, 999, 999, 999]


def passive_records(pm):
    """Kept for callers of the old per-IP passive format: names -> {svc, instance, txt} records."""
    out = []
    for name in (pm or {}).get("names", []):
        m = evidence.SVC.match(name)
        if m and not m.group(1).startswith("_"):
            out.append({"svc": m.group(2).lower(), "instance": evidence.unescape(m.group(1)), "txt": {}})
    return out


TXT_KEYS = {"md", "model", "ty", "am", "product", "usb_MDL", "usb_MFG", "mfg", "manufacturer", "ci", "rmodel", "ver", "fv", "sf"}


def packet(mac, vendor, ev, h, idn):
    """Minimised evidence for external research: OUI prefix only, no IPs, hostnames or device-given names."""
    txt, svcs = {}, []
    for m in ev.get("mdns_records", []):
        svcs.append(m["svc"])
        for k, v in (m.get("txt") or {}).items():
            if k in TXT_KEYS and v:
                txt[k] = v[:60]
    ss = ev.get("ssdp") or {}
    d = ss.get("description") or {}
    dh = ev.get("dhcp") or {}
    p = {
        "oui": mac[:8].upper(), "vendor": vendor or None, "randomized_mac": True if ev["randomized"] else None,
        "nmap_os_guess": ev["os"] if ev["ports"] else None,
        "open_ports": ["%d/%s %s %s" % (x["port"], x["proto"], x.get("service", ""), x.get("product", "")) for x in ev["ports"]][:14],
        "web": h.get("web", [])[:6],
        "mdns_services": sorted(set(svcs))[:12], "mdns_txt": txt,
        "upnp": {k: d.get(k) for k in ("manufacturer", "modelName", "modelNumber", "deviceType") if d.get(k)} | ({"server": ss["server"]} if ss.get("server") else {}),
        "dhcp": {"vendor_class": dh.get("vendor_class"), "option_list": ",".join(map(str, dh.get("prl", []))) or None} if dh else None,
        "current_guess": {k: idn[k] for k in ("type", "model", "os_family") if idn.get(k)},
    }
    return {k: v for k, v in p.items() if v not in (None, [], {}, "")}


def apply_research(rec, r):
    """Researched answer fills gaps only. Curated labels and medium/high measured evidence are never overridden;
    a curated device with no model can still get its model/OS filled in."""
    locked = rec["curated"] or rec["confidence"] in ("high", "medium", "curated")
    changed = False
    for fld in ("model", "os_family"):
        if r.get(fld) and not rec.get(fld):
            rec[fld], changed = r[fld], True
    if not locked and r.get("type") and (not rec["type"] or rec["confidence"] == "low"):
        rec["type"], rec["type_source"], changed = r["type"], "research", True
    if changed and not locked:
        rec["confidence"], rec["identified"], rec["type_verified"] = "researched", True, False
    rec["research"] = {k: r.get(k) for k in ("manufacturer", "model", "type", "os_family", "confidence", "rationale", "sources", "date")}
    if changed and r.get("rationale"):
        rec["reasons"] = rec["reasons"] + ["AI research (%s confidence): %s" % (r.get("confidence", "?"), r["rationale"])]


def merge_mdns(a, b):
    """Union of two record lists by (service, instance); the copy that carries TXT wins."""
    out = {}
    for r in list(a) + list(b):
        k = (r["svc"], r["instance"])
        if k not in out or (r.get("txt") and not out[k].get("txt")):
            out[k] = r
    return list(out.values())


def load_findings():
    """(by mac, by ip) hand labels. A label with a "mac" belongs to that device wherever DHCP puts it."""
    fmac, fip = {}, {}
    if os.environ.get("NO_FINDINGS"):
        return fmac, fip
    srcs = [(fp, os.path.basename(os.path.dirname(fp))) for fp in sorted(glob.glob(os.path.join(ROOT, "scans", "*", "findings.json")))]
    srcs.append((os.path.join(ROOT, "findings.json"), "manual"))
    for fp, date in srcs:
        for r in jload(fp, []):
            if r.get("mac"):
                tab, key = fmac, r["mac"].lower()
            elif r.get("ip"):
                tab, key = fip, r["ip"]
            else:
                continue
            tab[key] = {**tab.get(key, {}), **r, "_date": date}
    return fmac, fip


def name_key(n):
    return identify.norm_name(re.sub(r"\(\d+\.\d+\.\d+\.\d+\)", "", n or ""))


def track_names(out):
    """Remember every name each device has given (state/names.json) and report changes: a device that renames itself,
    and a newly seen device that turns up with a name another device already uses. Logged to the 'devices' stream and
    e-mailed (no voice). The first run only records a baseline."""
    path = os.path.join(ROOT, "state", "names.json")
    prev = jload(path, None)
    known = prev or {}
    events = []
    for d in out:
        mac, old = d["mac"], known.get(d["mac"])
        cur = dict(old or {})
        for src, nm in (d.get("names") or {}).items():
            if old is not None and src in old and name_key(old[src]) != name_key(nm):
                events.append(("renamed", d, "%s changed from '%s' to '%s'" % (src, old[src], nm)))
            cur[src] = nm
        if prev is not None and old is None and not d.get("aliases"):
            for src, nm in (d.get("names") or {}).items():
                k = name_key(nm)
                twin = [m for m, names in known.items() if m != mac and len(k) >= 6 and any(name_key(x) == k for x in names.values())]
                if twin:
                    events.append(("name_reused", d, "new device uses the name '%s' (%s), already used by %s" % (nm, src, ", ".join(twin))))
                    break
        if cur:
            known[mac] = cur
    evidence.jsave(path, known)
    if not events:
        return
    try:
        import lan_log
        import notify
        for ev, d, text in events:
            lan_log.event("devices", ev, mac=d["mac"], ip=d["ip"], name=d["name"], detail=text)
        body = "\n".join("%s  %s  %s (%s %s)\n    %s" % (d["mac"], d["ip"], d["name"] or "(no name)", d["vendor"], d["model"] or d["type"], text)
                         for _, d, text in events)
        notify.notify("LAN: %d device name change%s" % (len(events), "" if len(events) == 1 else "s"), body, skip=("voicemonkey",))
    except Exception as e:  # reporting must never break the build
        print("track_names: %s: %s" % (type(e).__name__, str(e)[:160]))


def link_aliases(out):
    """One device often shows up under several MACs (Wi-Fi + ethernet/dock, private + real address). MACs that share a
    specific host name are linked; a member with little evidence takes the identity of the best-known one."""
    groups = {}
    for d in out:
        for nm in {d["_host"], d["_mdns_host"]}:
            key = identify.norm_name(nm)
            if nm and len(key) >= 6 and identify.good_name(nm) and not SHARED_NAME.match(nm.strip()):
                groups.setdefault(key, {})[d["mac"]] = d
    order = {"curated": 4, "high": 3, "researched": 2, "medium": 2, "low": 0}
    for key, members in groups.items():
        if not 2 <= len(members) <= 4:
            continue  # a name on five MACs is a model name, not a device
        ms = list(members.values())
        best = max(ms, key=lambda d: (order.get(d["confidence"], 0), bool(d["model"]), d["last_seen"] or ""))
        for d in ms:
            d["aliases"] = sorted({m["mac"] for m in ms if m is not d} | set(d.get("aliases") or []))
            if d is best or order.get(d["confidence"], 0) >= order.get(best["confidence"], 0):
                continue
            why = "same device as %s (both use the host name '%s')" % (best["mac"], best["_host"] or best["_mdns_host"])
            for f in ("type", "model", "os_family"):
                if best.get(f) and (f == "type" or not d.get(f)):
                    d[f] = best[f]
            d["name"] = d["name"] if d["curated"] else (best["name"] or d["name"])
            d["confidence"], d["type_source"] = ("medium" if best["confidence"] in ("curated", "high") else best["confidence"]), "alias"
            d["identified"] = d["type_verified"] = bool(d["type"]) and d["confidence"] != "low"
            d["reasons"] = [why] + d["reasons"]


def history(pres, days=7):
    """Online intervals per MAC and the online count over time, rebuilt from presence.py's online/offline events
    in the "devices" log. Returns (since, {mac: [[start, end], ...]}, [[t, count], ...]) in epoch seconds."""
    import lan_log
    now = int(evidence.utcnow().timestamp())
    start = now - days * 86400
    evs, first = [], None
    for path in sorted(glob.glob(os.path.join(lan_log.LOG_DIR, "devices-*.jsonl"))):
        try:
            with open(path) as f:
                for line in f:
                    try:
                        e = json.loads(line)
                    except ValueError:
                        continue
                    first = e["t"] if first is None else min(first, e["t"])
                    if e.get("ev") in ("online", "offline") and e.get("mac"):
                        t = e["t"]
                        if e["ev"] == "offline" and e.get("last_seen"):  # it left when it was last seen, not when we noticed
                            ls = evidence.parse_ts(e["last_seen"])
                            t = ls.timestamp() if ls else t
                        evs.append((int(t), e["mac"], e["ev"] == "online"))
        except OSError:
            continue
    if first is None:
        return now, {}, []
    start = max(start, int(first))
    evs.sort()
    by_mac = {}
    for t, mac, on in evs:
        by_mac.setdefault(mac, []).append((t, on))
    spans = {}
    for mac, r in pres.items():
        seq = [(t, on) for t, on in by_mac.get(mac, []) if t > start]
        before = [on for t, on in by_mac.get(mac, []) if t <= start]
        state = before[-1] if before else (not seq[0][1] if seq else bool(r.get("online")))
        out, cur = [], start if state else None
        for t, on in seq:
            if on and cur is None:
                cur = t
            elif not on and cur is not None:
                out.append([cur, max(cur, t)])
                cur = None
        if cur is not None:
            out.append([cur, now])
        if out:
            spans[mac] = out[-40:]
    edges = sorted([(a, 1) for v in spans.values() for a, b in v] + [(b, -1) for v in spans.values() for a, b in v if b < now])
    series, n = [], 0
    for t, d in edges:
        n += d
        if series and series[-1][0] == t:
            series[-1][1] = n
        else:
            series.append([t, n])
    if series:
        series.append([now, n])
    return start, spans, series


def main():
    try:
        self_mac, self_ip = netinfo.mac(), netinfo.ip()
    except (Exception, SystemExit):
        self_mac = self_ip = None
    scans = evidence.load_scans(self_mac, self_ip)
    phosts = evidence.passive_hosts()
    pres = jload(os.path.join(ROOT, "state", "presence.json"), {})
    fmac, fip = load_findings()
    router = router_clients()
    research = jload(os.path.join(ROOT, "state", "research.json"), {})
    readings = jload(os.path.join(ROOT, "state", "name_reading.json"), {}).get("devices", {})
    icache = jload(os.path.join(ROOT, "state", "identity_cache.json"), {})
    if icache.get("_v") != identify.VERSION:  # identities cached under older rules are re-derived, not trusted
        icache = {"_v": identify.VERSION}
    today = datetime.date.today()

    # who holds each IP now: the MAC seen there most recently
    holder = {}
    for mac, r in pres.items():
        if r.get("ip") and r.get("last_seen", "") > holder.get(r["ip"], ("", ""))[0]:
            holder[r["ip"]] = (r["last_seen"], mac)
    macs = set(pres) | ({m for m in scans[0]["hosts"]} if scans else set())
    out, evid = [], {}
    for mac in macs:
        n = pres.get(mac, {})
        h, scan_at, scan_kind = evidence.scan_for(mac, scans)
        pv = evidence.passive(mac, phosts)
        ip = n.get("ip") or pv["ip"] or h.get("ip") or ""
        if not mac or (ip and not LAN.match(ip)):
            continue
        last_seen = n.get("last_seen") or scan_at
        online = recent(n.get("last_seen", ""))
        f = fmac.get(mac) or {}
        cur_holder = holder.get(ip, (None, mac))[1]
        others = [m for m, r in pres.items() if m != mac and r.get("ip") == ip and recent(r.get("last_seen", ""))] if online and ip else []
        if not f and ip and cur_holder == mac and not others:
            f = fip.get(ip, {})  # old IP-only label: only for the one device provably at that address
        rnd = randomized(mac)
        age = evidence.age_days(last_seen)
        if not f and not online and (age > HIDE_DAYS or (rnd and age > HIDE_RANDOM_DAYS)):
            continue
        vendor = "" if rnd else (identify.manuf_lookup(mac) or n.get("vendor") or h.get("scan_vendor") or "")
        pdhcp = pv["dhcp"]
        recs = merge_mdns(h.get("mdns_records", []), pv["mdns_records"])
        ss = dict(pv["ssdp"])
        for k, v in (h.get("ssdp") or {}).items():
            if v:
                ss[k] = v
        rc = router.get(mac)
        ev = {
            "ports": h.get("ports", []), "scripts": h.get("scripts", {}), "os": h.get("os"), "osclass": h.get("osclass"),
            "mdns_records": recs, "mdns_host": h.get("mdns_host") or pv["mdns_host"], "ssdp": ss,
            "probes": h.get("probes") or {}, "kasa": h.get("kasa"), "tuya": h.get("tuya"), "dhcp": pdhcp,
            "vendor": vendor, "randomized": rnd, "seed_name": n.get("name_guess"), "router_client": rc,
        }
        idn = identify.identify(ev)
        c = icache.get(mac)
        if c and RANK[idn["confidence"]] < RANK[c["confidence"]] and (today - datetime.date.fromisoformat(c["date"])).days <= CACHE_DAYS:
            # the evidence has aged out but the device was identified better before: keep that, say so
            idn = dict(idn, model=idn["model"] or c["model"], manufacturer=idn["manufacturer"] or c["manufacturer"],
                       os_family=idn["os_family"] or c["os_family"], type=c["type"], type_source=c["type_source"],
                       confidence=c["confidence"], name=idn["name"] or c.get("name"),
                       reasons=["carried over from %s (that evidence is no longer on hand)" % c["date"]] + c["reasons"][:8])
        elif idn["confidence"] in ("medium", "high") and (idn["model"] or idn["type"]):
            icache[mac] = {k: idn.get(k) for k in ("model", "manufacturer", "os_family", "type", "type_source", "confidence", "name", "reasons")} | {"date": today.isoformat()}
        has_ports = bool(h.get("ports"))
        curated = bool(f)
        verified = bool(f.get("type")) or (bool(idn["type"]) and idn["confidence"] in ("high", "medium"))
        reasons = idn["reasons"][:16]
        if others:
            reasons = ["IP conflict: %s also answers for %s" % (", ".join(others), ip)] + reasons
        if rc and rc.get("ip") and ip and rc["ip"] != ip and online:
            reasons.append("Deco router still lists this client at %s (ARP says %s)" % (rc["ip"], ip))
        rec = {
            "ip": ip, "mac": mac, "randomized_mac": rnd, "vendor": vendor,
            "name": idn["name"] or f.get("name") or "", "type": f.get("type") or idn["type"] or "", "type_verified": verified,
            "model": idn["model"] or "", "os_family": idn["os_family"] or "",
            "confidence": "curated" if curated and f.get("type") else idn["confidence"],
            "conflict": idn.get("conflict"),
            "names": idn.get("names") or {}, "name_flags": idn.get("name_flags") or [],
            "ip_conflict": others or None,
            "ip_stale": bool(ip) and cur_holder != mac,  # someone else has been seen at this address since
            "ip_history": n.get("ip_history") or [],
            "reasons": reasons, "type_source": "curated" if f.get("type") else (idn["type_source"] or ""),
            "os": h.get("os") if has_ports else None, "os_accuracy": h.get("os_accuracy") if has_ports else None,
            "os_ignored": h.get("os") if (h.get("os") and not has_ports) else None,
            "ports": sorted(h.get("ports", []), key=lambda p: (p["proto"], p["port"])),
            "web": h.get("web", [])[:6],
            "mdns": ["%s (%s)" % (m["instance"], m["svc"]) for m in recs][:12],
            "upnp": (ss.get("description") or {}) | ({"server": ss["server"]} if ss.get("server") else {}),
            "dhcp": {"hostname": pdhcp.get("hostname"), "vendor_class": pdhcp.get("vendor_class"),
                     "options": ",".join(map(str, pdhcp.get("prl", []))) or None, "requests": pdhcp.get("count")} if pdhcp else None,
            "note": f.get("note", ""), "note_source": f.get("source", ""), "note_date": f.get("_date", ""),
            "identified": curated or (bool(idn["type"]) and idn["confidence"] in ("high", "medium")),
            "curated": curated, "in_scan": bool(scan_at), "scan_at": scan_at, "scan_kind": scan_kind,
            "online_now": online, "seen_via": n.get("via") or [],
            "link": ("wired" if rc.get("wired") else rc.get("band")) if rc else None, "signal_dbm": rc.get("signal_dbm") if rc else None,
            "network": rc.get("interface") if rc else None,
            "first_seen": n.get("first_seen"), "last_seen": last_seen,
            "_host": pdhcp.get("hostname") or "", "_mdns_host": ev["mdns_host"] or "",
        }
        pk = packet(mac, vendor, ev, h, idn)
        evid[mac] = {"packet": pk, "curated": curated, "confidence": rec["confidence"], "has_model": bool(rec["model"]),
                     "signal": any(k in pk for k in ("open_ports", "mdns_services", "upnp", "dhcp", "nmap_os_guess", "web"))}
        if mac in research:
            apply_research(rec, research[mac])
        # what the names mean: the AI reading (names_ai.py) while it matches the current names, else the possessive rule
        rd = readings.get(mac)
        if rd and rd.get("hash") == identify.names_hash(rec["names"], rec["vendor"], rec["model"], rec["os_family"]):
            rec["name_reading"] = {k: rd.get(k) for k in ("owner", "thing", "place", "mismatch", "note", "date")}
            if rd.get("mismatch") and rd.get("note"):
                flag = "AI reading of the names: " + rd["note"]
                rec["name_flags"] = rec["name_flags"] + [flag]
                rec["reasons"] = [flag] + rec["reasons"]
        else:
            rec["name_reading"] = None
        rec["name_also"] = [{"name": n, "source": src} for n, src in
                            identify.name_rivals(rec["name"], rec["names"], rec["vendor"], rec["model"])] if rec["name_flags"] else []
        rec["owner"] = (rec["name_reading"] or {}).get("owner") or identify.owner_hint(rec["names"]) or ""
        out.append(rec)
    link_aliases(out)
    if not os.environ.get("NO_FINDINGS"):
        track_names(out)
    for d in out:
        d.pop("_host"), d.pop("_mdns_host")
    out.sort(key=lambda d: (ip_key(d["ip"]), d["ip_stale"], d["mac"]))
    try:
        since, spans, series = history(pres)
    except Exception as e:  # the page works without its history
        print("history: %s: %s" % (type(e).__name__, str(e)[:160]))
        since, spans, series = None, {}, []
    for d in out:
        d["seen"] = spans.get(d["mac"], [])
    data = {
        "generated": datetime.datetime.now(datetime.timezone.utc).isoformat(timespec="seconds"),
        "scan_dir": scans[0]["dir"] if scans else "",
        "scans": [{"dir": s["dir"], "stamp": s["stamp"], "hosts": len(s["hosts"])} for s in scans],
        "sources": sorted({"passive"} if phosts else set()),
        "subnet": netinfo_subnet(), "self_ip": self_ip,
        "history": {"since": since, "online": series},
        "devices": out,
    }
    evidence.jsave(os.path.join(ROOT, "web", "data.json"), data)
    if not os.environ.get("NO_FINDINGS"):
        evidence.jsave(os.path.join(ROOT, "state", "identity_cache.json"), icache)
    evidence.jsave(os.path.join(ROOT, "state", "evidence.json"), evid)  # private: not under web/
    print("wrote web/data.json: %d devices, %d identified (%d curated), %d online, %d never scanned" % (
        len(out), sum(d["identified"] for d in out), sum(d["curated"] for d in out), sum(d["online_now"] for d in out),
        sum(not d["in_scan"] for d in out)))


if __name__ == "__main__":
    main()
