"""Evidence, filed per MAC. Read side of the collectors; no network I/O.

Three stores, all keyed by MAC so a lease change, an address conflict or a device that was asleep during the
nightly sweep never detaches a device from what is known about it:

  passive(mac)   what passive.py heard (state/passive.json): DHCP, mDNS instances + TXT, SSDP/UPnP
  deep scans     scans/<stamp>/ from collect.py. Its files are per IP; digest() re-files them under the MAC nmap
                 saw at that IP *during that scan* and caches the result as scans/<stamp>/by_mac.json
  quick scans    state/quick/<mac>.json from quickscan.py (short targeted look at one device)

scan_for(mac) returns the newest of those, so a device seen by any sweep in the last SCAN_DAYS keeps its ports,
banners and probe answers wherever it is today.
"""
import datetime
import glob
import json
import os
import re
import xml.etree.ElementTree as ET

ROOT = os.path.dirname(os.path.abspath(__file__))
SCAN_DAYS = int(os.environ.get("SCAN_DAYS", "21"))
NAME_DAYS = int(os.environ.get("PASSIVE_NAME_DAYS", "30"))  # an mDNS name unheard this long is no longer evidence
DIGEST_V = 3
FILL = ("ports", "probes", "kasa", "tuya", "ssdp", "mdns_records", "mdns_host")
QUICK_DIR = os.path.join(ROOT, "state", "quick")
SVC = re.compile(r"^(.+)\.(_[a-z0-9-]+\._(?:tcp|udp))\.local$", re.I)


def jload(path, default):
    try:
        with open(path) as f:
            return json.load(f)
    except (OSError, ValueError):
        return default


def jsave(path, obj):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    tmp = path + ".tmp"
    with open(tmp, "w") as f:
        json.dump(obj, f, indent=1, default=str)
    os.replace(tmp, path)


def utcnow():
    return datetime.datetime.now(datetime.timezone.utc)


def stamp(t=None):
    return (t or utcnow()).strftime("%Y-%m-%dT%H:%M:%SZ")


def parse_ts(ts):
    try:
        return datetime.datetime.fromisoformat(ts.replace("Z", "+00:00"))
    except Exception:
        return None


def age_days(ts):
    t = parse_ts(ts or "")
    return (utcnow() - t).total_seconds() / 86400 if t else 1e9


def unescape(s):
    """DNS-SD decimal escapes (\\226\\128\\153) are bytes of UTF-8, not code points."""
    if "\\" not in s:
        return s
    raw = re.sub(rb"\\(\d{3})", lambda m: bytes([int(m.group(1)) & 255]), s.encode("utf-8", "replace"))
    return raw.decode("utf-8", "replace")


# ---------------------------------------------------------------- passive
def passive_hosts():
    """mac -> record from passive.py. An old-format file (before the MAC-keyed rewrite) reads as empty."""
    p = jload(os.path.join(ROOT, "state", "passive.json"), {})
    return p.get("hosts", {}) if p.get("v") == 2 else {}


def passive(mac, hosts):
    """Identification evidence passive.py holds for one MAC, in the shape identify() takes."""
    h = hosts.get(mac) or {}
    m = h.get("mdns") or {}
    recs, plain = [], []
    for name, ts in sorted((m.get("names") or {}).items()):
        if age_days(ts) > NAME_DAYS:
            continue
        s = SVC.match(name)
        if s and not s.group(1).startswith("_"):
            recs.append({"svc": s.group(2).lower(), "instance": unescape(s.group(1)), "txt": (m.get("txt") or {}).get(name, {})})
        elif not s and name.endswith(".local"):
            plain.append(name[:-6])
    host = m.get("host") or (plain[0] if len(plain) == 1 else None)
    s = h.get("ssdp") or {}
    ssdp = {"server": s.get("server", ""), "st": s.get("types", [])} if s else {}
    if s.get("description"):
        ssdp["description"] = s["description"]
    return {"dhcp": h.get("dhcp") or {}, "mdns_records": recs, "mdns_host": host, "ssdp": ssdp,
            "ip": h.get("ip"), "ips": h.get("ips") or {}, "last_seen": h.get("last_seen"), "via": h.get("via") or {}}


# ---------------------------------------------------------------- nmap / avahi parsers (per IP, as the tools write them)
def nmap_hosts(path, proto, hosts):
    if not os.path.exists(path):
        return
    for h in ET.parse(path).getroot().findall("host"):
        if h.find("status").get("state") != "up":
            continue
        ip = mac = vendor = None
        for a in h.findall("address"):
            if a.get("addrtype") == "ipv4":
                ip = a.get("addr")
            elif a.get("addrtype") == "mac":
                mac, vendor = a.get("addr").lower(), a.get("vendor")
        if not ip:
            continue
        d = hosts.setdefault(ip, {"ip": ip, "ports": [], "scripts": {}, "web": []})
        d["mac"] = mac or d.get("mac")
        d["scan_vendor"] = vendor or d.get("scan_vendor")
        for s in h.findall("hostscript/script"):
            d["scripts"].setdefault(s.get("id"), s.get("output", "")[:600])
        for p in h.findall("ports/port"):
            if p.find("state").get("state") != "open":
                continue
            s = p.find("service")
            port = int(p.get("portid"))
            d["ports"].append({
                "port": port, "proto": proto,
                "service": s.get("name", "") if s is not None else "",
                "product": (s.get("product", "") + " " + s.get("version", "")).strip() if s is not None else "",
            })
            for sc in p.findall("script"):
                out = sc.get("output", "")
                d["scripts"].setdefault(sc.get("id"), out[:600])
                if sc.get("id") == "http-title" and out:
                    d["web"].append("%d: %s" % (port, out.split("\n")[0][:80]))
                if sc.get("id") == "ssl-cert":
                    cn = re.search(r"commonName=([^/\n]+)", out)
                    if cn:
                        d["web"].append("%d: TLS cert %s" % (port, cn.group(1)[:60]))
        om = h.findall("os/osmatch")
        if om and proto == "tcp":
            d["os"], d["os_accuracy"] = om[0].get("name"), int(om[0].get("accuracy"))
            oc = om[0].find("osclass")
            if oc is not None:
                d["osclass"] = {"type": oc.get("type"), "vendor": oc.get("vendor"), "osfamily": oc.get("osfamily"),
                                "accuracy": int(oc.get("accuracy", 0))}


def avahi(path, hosts):
    if not os.path.exists(path):
        return
    for line in open(path, errors="replace"):
        f = line.rstrip("\n").split(";", 9)
        if len(f) < 9 or f[0] != "=" or f[2] != "IPv4":
            continue
        d = hosts.get(f[7])
        if not d:
            continue
        txt = {}
        for t in re.findall(r'"((?:[^"\\]|\\.)*)"', f[9] if len(f) > 9 else ""):
            k, _, v = t.partition("=")
            txt[k] = v
        rec = {"svc": f[4], "instance": unescape(f[3]), "txt": txt}
        if rec not in d.setdefault("mdns_records", []):
            d["mdns_records"].append(rec)
        d["mdns_host"] = f[6].removesuffix(".local")


# ---------------------------------------------------------------- deep scans, re-filed per MAC
def scan_time(sd):
    m = re.match(r"^(\d{4})-(\d\d)-(\d\d)(?:_(\d\d)(\d\d))?$", os.path.basename(sd))
    if not m:
        return None
    y, mo, d, hh, mm = (int(x) if x else 0 for x in m.groups())
    return datetime.datetime(y, mo, d, hh, mm).astimezone().astimezone(datetime.timezone.utc)  # dir names are local time


def scan_dirs():
    """Finished sweeps, oldest first (collect.py publishes a directory only when the sweep is over)."""
    out = []
    for d in sorted(glob.glob(os.path.join(ROOT, "scans", "*"))):
        if os.path.isdir(d) and scan_time(d) and os.path.exists(os.path.join(d, "tcp.xml")):
            out.append(d)
    return out


def digest(sd, self_mac=None, self_ip=None):
    """One sweep as {stamp, hosts: {mac: evidence}}. Cached beside the sweep; None if its tcp.xml is unreadable."""
    cache = os.path.join(sd, "by_mac.json")
    c = jload(cache, None)
    if c and c.get("digest_v") == DIGEST_V:
        return c
    hosts = {}
    try:
        nmap_hosts(os.path.join(sd, "tcp.xml"), "tcp", hosts)
    except ET.ParseError:
        return None
    try:
        nmap_hosts(os.path.join(sd, "udp.xml"), "udp", hosts)
    except ET.ParseError:
        pass
    avahi(os.path.join(sd, "mdns.txt"), hosts)
    extra = {k: jload(os.path.join(sd, k + ".json"), {}) for k in ("ssdp", "probes", "kasa", "tuya")}
    by_mac = {}
    for ip, h in hosts.items():
        mac = h.get("mac") or (self_mac if ip == self_ip else None)  # nmap prints no MAC for the scanning host
        if not mac:
            continue
        h["mac"] = mac
        for k, tab in extra.items():
            if tab.get(ip):
                h[k] = tab[ip]
        by_mac[mac] = h
    t = scan_time(sd)
    out = {"digest_v": DIGEST_V, "stamp": stamp(t), "dir": os.path.basename(sd), "hosts": by_mac}
    try:
        jsave(cache, out)
    except OSError:
        pass
    return out


def load_scans(self_mac=None, self_ip=None):
    """Digests of the sweeps inside SCAN_DAYS, newest first."""
    out = []
    for sd in reversed(scan_dirs()):
        t = scan_time(sd)
        if (utcnow() - t).days > SCAN_DAYS:
            break
        d = digest(sd, self_mac, self_ip)
        if d:
            out.append(d)
    return out


# ---------------------------------------------------------------- quick scans
def quick_path(mac):
    return os.path.join(QUICK_DIR, mac.replace(":", "") + ".json")


def quick_load(mac):
    return jload(quick_path(mac), None)


def quick_save(mac, rec):
    jsave(quick_path(mac), dict(rec, mac=mac, stamp=stamp()))


def scan_for(mac, scans):
    """(evidence, stamp, kind) - the newest scan evidence for this MAC, deep or quick; ({}, None, None) if none.
    A deep sweep is the base when there is one; a newer quick look only adds probe answers the sweep lacks."""
    deep = None
    for d in scans:  # newest first: the newest sweep that saw the MAC is the base ...
        h = d["hosts"].get(mac)
        if not h:
            continue
        if deep is None:
            deep = (dict(h), d["stamp"], d["dir"])
            continue
        base = deep[0]  # ... and older sweeps fill what it lacks (a plug that skipped one Kasa discovery, a host
        for k in FILL:  # whose ports were closed that night)
            if h.get(k) and not base.get(k):
                base[k] = h[k]
                if k == "ports":
                    for k2 in ("scripts", "web", "os", "os_accuracy", "osclass"):
                        if h.get(k2):
                            base[k2] = h[k2]
    q = quick_load(mac)
    if q and age_days(q.get("stamp")) > SCAN_DAYS:
        q = None
    if deep and q and q["stamp"] > deep[1]:
        h = dict(deep[0])
        for k in ("probes", "kasa"):
            if q.get(k) and not h.get(k):
                h[k] = q[k]
        if q.get("ports") and not h.get("ports"):
            h.update({k: q[k] for k in ("ports", "scripts", "web") if q.get(k)})
        return h, deep[1], "sweep " + deep[2]
    if deep:
        return deep[0], deep[1], "sweep " + deep[2]
    if q:
        return q, q["stamp"], "quick look"
    return {}, None, None
