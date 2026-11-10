#!/usr/bin/env python3
"""Always-on collector (lan-passive.service): what every device says on the wire, filed under its MAC.

Heard continuously:
  ARP   sender MAC + IP of every request/reply   (-> who holds which address, within seconds of a change)
  DHCP  hostname, vendor class, option list, requested address   (-> OS fingerprint, even with a random MAC)
  mDNS  service instances, their TXT records, the .local host name
  SSDP  Server / NT / USN headers, and the UPnP description the device points at (model name)
Asked for every PROBE_INTERVAL seconds (PASSIVE_PROBE=0 turns the asking off, listening stays):
  one mDNS query for the common service types and one SSDP M-SEARCH, so quiet devices repeat themselves.

Everything is keyed by the Ethernet source MAC. An IP address is only ever an attribute of a MAC, with the
time it was last seen there, so evidence follows a device through lease changes and never sticks to the next
tenant of an address. Writes state/passive.json (atomic) at most every SAVE_EVERY seconds when something changed.
"""
import datetime
import ipaddress
import json
import os
import re
import socket
import threading
import time

import netinfo
from scapy.all import ARP, BOOTP, DHCP, DNS, DNSQR, IP, UDP, Ether, Raw, sendp, sniff  # noqa: E402

ROOT = os.path.dirname(os.path.abspath(__file__))
STATE = os.path.join(ROOT, "state", "passive.json")
IFACE = netinfo.iface()
NET = ipaddress.ip_network(netinfo.subnet())
FILTER = "arp or (udp and (port 67 or port 68 or port 1900 or port 5353))"
DHCP_MSG = {1: "discover", 2: "offer", 3: "request", 4: "decline", 5: "ack", 6: "nak", 7: "release", 8: "inform"}
SAVE_EVERY = int(os.environ.get("PASSIVE_SAVE_EVERY", "15"))
PROBE_INTERVAL = int(os.environ.get("PASSIVE_PROBE", "600"))
FORGET_DAYS = int(os.environ.get("PASSIVE_FORGET_DAYS", "60"))
MAX_NAMES, MAX_TXT, MAX_IPS = 60, 24, 8
SVC = re.compile(r"^(.+)\.(_[a-z0-9-]+\._(?:tcp|udp))\.local$", re.I)
UUID_HOST = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\.local$", re.I)
PROBE_TYPES = ["_services._dns-sd._udp", "_airplay._tcp", "_raop._tcp", "_googlecast._tcp", "_hap._tcp", "_ipp._tcp",
               "_printer._tcp", "_spotify-connect._tcp", "_companion-link._tcp", "_device-info._tcp", "_smb._tcp",
               "_workstation._tcp", "_http._tcp", "_hue._tcp", "_homeconnect._tcp", "_amzn-wplay._tcp", "_sonos._tcp",
               "_matter._tcp", "_matterc._udp", "_esphomelib._tcp", "_shelly._tcp", "_androidtvremote2._tcp",
               "_ssh._tcp", "_rdlink._tcp", "_adisk._tcp", "_roku-rcp._tcp", "_mqtt._tcp", "_miio._udp"]

lock = threading.Lock()
dirty = threading.Event()
data = {"v": 2, "hosts": {}}
ip_owner = {}  # ip -> mac, from the freshest sighting; lets a unicast SSDP reply be filed under the right MAC
upnp_tried = {}  # (mac, location) -> time of the last description fetch


def now():
    return datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def text(v):
    return v.decode(errors="replace") if isinstance(v, bytes) else str(v)


def lan_ip(ip):
    try:
        a = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return a in NET and a not in (NET.network_address, NET.broadcast_address)


def real_mac(mac):
    return bool(mac) and mac not in ("00:00:00:00:00:00", "ff:ff:ff:ff:ff:ff") and not int(mac[:2], 16) & 1


def host(mac, via, ip=None):
    """The record for `mac`, stamped as seen now. Call with the lock held."""
    t = now()
    h = data["hosts"].setdefault(mac, {"first_seen": t})
    h["last_seen"] = t
    h.setdefault("via", {})[via] = t
    if ip and lan_ip(ip):
        ips = h.setdefault("ips", {})
        ips[ip] = t
        if len(ips) > MAX_IPS:
            del ips[min(ips, key=ips.get)]
        h["ip"] = ip
        ip_owner[ip] = mac
    return h


def on_arp(pkt):
    a = pkt[ARP]
    mac = (a.hwsrc or "").lower()
    # the sender fields are the device speaking for itself; a frame relayed for someone else is not that
    if a.op not in (1, 2) or not real_mac(mac) or mac != pkt[Ether].src.lower():
        return
    with lock:
        host(mac, "arp", a.psrc)  # psrc 0.0.0.0 (address probe) still counts as hearing the device
    dirty.set()


def on_dhcp(pkt):
    opts = {o[0]: o[1:] for o in pkt[DHCP].options if isinstance(o, tuple)}
    mt = opts.get("message-type", [None])[0]
    if mt not in (1, 3, 8):  # discover / request / inform come from the client
        return
    mac = ":".join("%02x" % b for b in pkt[BOOTP].chaddr[:6])
    if not real_mac(mac):
        return
    with lock:
        ci = pkt[BOOTP].ciaddr
        h = host(mac, "dhcp", ci if ci and ci != "0.0.0.0" else None)  # ciaddr = an address it is using now
        r = h.setdefault("dhcp", {"count": 0, "types": []})
        r["count"] += 1
        r["last_seen"] = h["last_seen"]
        if DHCP_MSG.get(mt) not in r["types"]:
            r["types"].append(DHCP_MSG.get(mt))
        if "hostname" in opts:
            r["hostname"] = text(opts["hostname"][0])[:64]
        if "vendor_class_id" in opts:
            r["vendor_class"] = text(opts["vendor_class_id"][0])[:64]
        if "param_req_list" in opts:
            r["prl"] = [int(x) for x in opts["param_req_list"]][:64]
        if "requested_addr" in opts:  # not its address yet (the server may refuse), so kept apart from "ip"
            r["requested_ip"] = text(opts["requested_addr"][0])
    dirty.set()


def ssdp_headers(payload):
    h = {}
    for l in payload.decode(errors="replace").split("\r\n")[1:]:
        if ":" in l:
            k, v = l.split(":", 1)
            h[k.strip().lower()] = v.strip()
    return h


def record_ssdp(mac, ip, h):
    """File one SSDP message under `mac`. Returns a description URL worth fetching, or None."""
    if not (h.get("server") or h.get("nt") or h.get("st")):
        return None
    with lock:
        hrec = host(mac, "ssdp", ip)
        r = hrec.setdefault("ssdp", {"server": "", "types": []})
        r["last_seen"] = hrec["last_seen"]
        if h.get("server"):
            r["server"] = h["server"][:160]
        t = h.get("nt") or h.get("st")
        if t and t not in r["types"] and len(r["types"]) < 20:
            r["types"].append(t[:120])
        loc = h.get("location", "")
        m = re.match(r"^http://([\d.]+)(:\d+)?/", loc)
        want = None
        # only from the host that announced it, and at most once a day per device and URL
        if m and m.group(1) == ip and time.time() - upnp_tried.get((mac, loc), 0) > 86400:
            upnp_tried[(mac, loc)] = time.time()
            want = loc
    dirty.set()
    return want


def fetch_upnp(mac, loc):
    import collect  # stdlib-only helpers; imported late so a missing nmap etc. never stops the listener
    try:
        desc = collect.parse_upnp(collect.http_get(loc, timeout=4)[0])
    except Exception:
        return
    if desc:
        with lock:
            r = data["hosts"].get(mac, {}).get("ssdp")
            if r is not None:
                r["description"], r["description_at"] = desc, now()
        dirty.set()


def on_ssdp(pkt):
    if Raw not in pkt:
        return
    mac, ip = pkt[Ether].src.lower(), pkt[IP].src
    if not real_mac(mac):
        return
    loc = record_ssdp(mac, ip, ssdp_headers(bytes(pkt[Raw].load)))
    if loc:
        threading.Thread(target=fetch_upnp, args=(mac, loc), daemon=True).start()


def on_mdns(pkt):
    if DNS not in pkt or pkt[DNS].qr != 1:
        return
    src, mac = pkt[IP].src, pkt[Ether].src.lower()
    if not real_mac(mac):
        return
    names, txt, hostname, foreign = set(), {}, None, False
    d = pkt[DNS]
    for sect, count in (("an", d.ancount), ("ar", d.arcount)):
        recs = getattr(d, sect)
        for i in range(count):
            try:
                rr = recs[i]
            except Exception:
                break
            name = text(rr.rrname).rstrip(".")
            rtype = getattr(rr, "type", None)
            if rtype == 1:  # A
                addr = text(getattr(rr, "rdata", ""))
                if addr == src:
                    hostname = name
                elif lan_ip(addr):
                    foreign = True  # speaking for another host (Bonjour sleep proxy, mDNS reflector)
            if name.endswith(".arpa") or UUID_HOST.match(name):
                continue
            if SVC.match(name) or (name.endswith(".local") and "._" not in name and not name.startswith("_")):
                names.add(name)
            if rtype == 16 and SVC.match(name):  # TXT of one service instance
                kv = txt.setdefault(name, {})
                for t in (rr.rdata if isinstance(rr.rdata, list) else [rr.rdata]):
                    k, sep, v = text(t).partition("=")
                    if sep and k and len(kv) < MAX_TXT:
                        kv[k[:40]] = v[:120]
    with lock:
        h = host(mac, "mdns", src)
        if foreign or not names:
            dirty.set()
            return  # still a sighting of this MAC, but the records are not provably about it
        r = h.setdefault("mdns", {"names": {}, "txt": {}})
        for n in names:
            r["names"][n] = h["last_seen"]
        while len(r["names"]) > MAX_NAMES:  # drop the longest-unheard name, never refuse a new one
            old = min(r["names"], key=r["names"].get)
            del r["names"][old]
            r["txt"].pop(old, None)
        for n, kv in txt.items():
            if kv and n in r["names"]:
                r["txt"][n] = kv
        if hostname and not UUID_HOST.match(hostname):
            r["host"] = hostname.removesuffix(".local")
    dirty.set()


def handle(pkt):
    try:
        if ARP in pkt:
            on_arp(pkt)
        elif DHCP in pkt and BOOTP in pkt:
            on_dhcp(pkt)
        elif UDP in pkt and IP in pkt and 1900 in (pkt[UDP].sport, pkt[UDP].dport):
            on_ssdp(pkt)
        elif UDP in pkt and IP in pkt and 5353 in (pkt[UDP].sport, pkt[UDP].dport):
            on_mdns(pkt)
    except Exception:
        pass  # one malformed packet must never stop the collector


# ---------------------------------------------------------------- asking
def probe_mdns():
    q = None
    for t in PROBE_TYPES:
        rr = DNSQR(qname=t + ".local", qtype="PTR")
        q = rr if q is None else q / rr
    pkt = (Ether(dst="01:00:5e:00:00:fb") / IP(dst="224.0.0.251", ttl=255) / UDP(sport=5353, dport=5353)
           / DNS(rd=0, qd=q))
    sendp(pkt, iface=IFACE, verbose=False)  # answers are multicast: the sniffer files them


def probe_ssdp():
    me = netinfo.ip(IFACE)
    msg = ('M-SEARCH * HTTP/1.1\r\nHOST: 239.255.255.250:1900\r\nMAN: "ssdp:discover"\r\n'
           "MX: 3\r\nST: ssdp:all\r\n\r\n").encode()
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_IF, socket.inet_aton(me))
        s.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 2)
        s.bind((me, 0))
        s.settimeout(1.0)
        for _ in range(2):
            s.sendto(msg, ("239.255.255.250", 1900))
            time.sleep(0.3)
        end = time.time() + 8
        fetch = {}
        while time.time() < end:  # replies come back unicast, often not from port 1900: the sniffer misses those
            try:
                payload, (ip, _) = s.recvfrom(4096)
            except socket.timeout:
                continue
            with lock:
                mac = ip_owner.get(ip)
            if mac:
                loc = record_ssdp(mac, ip, ssdp_headers(payload))
                if loc:
                    fetch[(mac, loc)] = True
    finally:
        s.close()
    for mac, loc in fetch:
        fetch_upnp(mac, loc)


def prober():
    time.sleep(20)  # let the sniffer learn who holds which IP first
    while True:
        for fn in (probe_mdns, probe_ssdp):
            try:
                fn()
            except Exception as e:
                print("probe %s: %s: %s" % (fn.__name__, type(e).__name__, str(e)[:120]), flush=True)
        time.sleep(PROBE_INTERVAL)


# ---------------------------------------------------------------- state
def migrate(old):
    """v1 kept DHCP per MAC but mDNS/SSDP per IP with a MAC stamp. Re-file what carries a MAC; drop the rest."""
    hosts = {}
    for mac, r in (old.get("dhcp") or {}).items():
        t = r.get("last_seen") or now()
        r.pop("ip", None)
        hosts[mac] = {"first_seen": t, "last_seen": t, "via": {"dhcp": t}, "dhcp": r}
    for kind in ("mdns", "ssdp"):
        for ip, r in sorted((old.get(kind) or {}).items(), key=lambda x: x[1].get("last_seen", "")):
            mac, t = r.get("mac"), r.get("last_seen") or now()
            if not mac:
                continue
            h = hosts.setdefault(mac, {"first_seen": t, "last_seen": t, "via": {}})
            h["last_seen"] = max(h["last_seen"], t)
            h["via"][kind] = max(h["via"].get(kind, ""), t)
            if kind == "mdns":
                m = h.setdefault("mdns", {"names": {}, "txt": {}})
                for n in r.get("names", []):
                    if not n.endswith(".arpa") and not UUID_HOST.match(n) and (SVC.match(n) or "._" not in n and not n.startswith("_")):
                        m["names"][n] = t
            else:
                h["ssdp"] = {"server": r.get("server", ""), "types": r.get("types", []), "last_seen": t}
    return {"v": 2, "hosts": hosts}


def forget():
    cut = (datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(days=FORGET_DAYS)).strftime("%Y-%m-%dT%H:%M:%SZ")
    with lock:
        for mac in [m for m, h in data["hosts"].items() if h.get("last_seen", "") < cut]:
            del data["hosts"][mac]


def saver():
    n = 0
    while True:
        time.sleep(SAVE_EVERY)
        n += 1
        if n % 240 == 0:
            forget()
        if dirty.is_set():
            dirty.clear()
            with lock:
                snap = json.dumps(dict(data, updated=now()), indent=1)
            tmp = STATE + ".tmp"
            with open(tmp, "w") as f:
                f.write(snap)
            os.replace(tmp, STATE)


def load():
    if not os.path.exists(STATE):
        return
    try:
        old = json.load(open(STATE))
    except Exception:
        return
    new = old if old.get("v") == 2 else migrate(old)
    data["hosts"] = new.get("hosts", {})
    for mac, h in sorted(data["hosts"].items(), key=lambda x: x[1].get("last_seen", "")):
        if h.get("ip"):
            ip_owner[h["ip"]] = mac  # newest sighting wins
    if old.get("v") != 2:
        dirty.set()


def main():
    os.makedirs(os.path.dirname(STATE), exist_ok=True)
    load()
    threading.Thread(target=saver, daemon=True).start()
    if PROBE_INTERVAL > 0:
        threading.Thread(target=prober, daemon=True).start()
    sniff(iface=IFACE, filter=FILTER, prn=handle, store=False)


if __name__ == "__main__":
    main()
