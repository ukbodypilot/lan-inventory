#!/usr/bin/env python3
"""Daily active fingerprinting sweep. Writes scans/<date>/ and rebuilds web/data.json.

Steps (each bounded, each independent - one failing never stops the rest):
  1 nmap TCP    -sS -O -sV -sC + extra NSE (upnp-info, http-title, ssl-cert, smb-os-discovery, rtsp-methods)
  2 nmap UDP    discovery/management ports + nbstat (NetBIOS names)
  3 mDNS        avahi-browse with TXT records (model identifiers live in the TXT)
  4 SSDP/UPnP   M-SEARCH, then fetch each device description XML
  5 probes      vendor APIs that answer unauthenticated: Hue, Roku, Chromecast, AirPlay
  6 kasa        python-kasa broadcast discovery (TP-Link Kasa/Tapo model)
  7 tuya        tinytuya broadcast discovery
Needs CAP_NET_RAW + CAP_NET_ADMIN (the systemd unit grants them to the user).
"""
import asyncio
import datetime
import json
import os
import re
import socket
import subprocess
import sys
import time
import urllib.request
import xml.etree.ElementTree as ET

import netinfo

ROOT = os.path.dirname(os.path.abspath(__file__))
SUBNET = netinfo.subnet()
IFACE = netinfo.iface()
LOG = []


def log(msg):
    line = "%s %s" % (datetime.datetime.now().strftime("%H:%M:%S"), msg)
    print(line, flush=True)
    LOG.append(line)


def lan_ip():
    return netinfo.ip(IFACE)


def step(name, fn, *a):
    t = time.time()
    try:
        r = fn(*a)
        log("%s ok (%.0fs)%s" % (name, time.time() - t, " - " + str(r) if r else ""))
    except Exception as e:  # keep going; the builder copes with missing files
        log("%s FAILED after %.0fs: %s: %s" % (name, time.time() - t, type(e).__name__, str(e)[:200]))


def run(cmd, timeout, out_path=None):
    p = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
    if out_path:
        open(out_path, "w").write(p.stdout + p.stderr)
    return p


# ---------------------------------------------------------------- nmap
EXTRA_NSE = "default,upnp-info,http-title,http-server-header,ssl-cert,smb-os-discovery,rtsp-methods"


# 1-1024 plus the ports IoT / media / management gear actually uses (nmap's top-1000 misses several)
TCP_PORTS = ("1-1024,1883,1900,2049,2968,3000,3389,5000,5001,5353,5357,5555,5900,6466,6467,6668,7000,7100,8000,8001,"
             "8008,8009,8060,8080,8081,8088,8443,8554,8883,8888,9000,9090,9100,9999,10001,16080,49152-49160,55443,62078")


def nmap_tcp(d):
    run(["nmap", "--privileged", "-sS", "-O", "-sV", "--version-intensity", "7", "-p", TCP_PORTS, "--script", EXTRA_NSE,
         "--osscan-guess", "-T4", "--max-retries", "2", "--host-timeout", "15m", SUBNET,
         "-oX", d + "/tcp.xml"], timeout=3600, out_path=d + "/tcp.log")


def nmap_udp(d):
    run(["nmap", "--privileged", "-sU", "-sV", "-p", "53,67,69,123,137,161,1900,5353,5683,6666,6667,9999,10001",
         "--script", "nbstat,upnp-info,snmp-info", "-T4", "--max-retries", "1", "--host-timeout", "10m", SUBNET,
         "-oX", d + "/udp.xml"], timeout=2400, out_path=d + "/udp.log")


# ---------------------------------------------------------------- mDNS
def mdns(d):
    try:
        p = subprocess.run(["avahi-browse", "-artpk", "--resolve"], capture_output=True, text=True, timeout=150)
        out = p.stdout
    except subprocess.TimeoutExpired as e:
        out = e.stdout.decode(errors="replace") if isinstance(e.stdout, bytes) else (e.stdout or "")
    lines = [l for l in out.splitlines() if l.startswith("=")]
    open(d + "/mdns.txt", "w").write("\n".join(lines) + "\n")
    return "%d records" % len(lines)


# ---------------------------------------------------------------- SSDP / UPnP
def http_get(url, timeout=4, limit=300000, headers=None):
    req = urllib.request.Request(url, headers=headers or {"User-Agent": "lan-inventory/1"})
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return r.read(limit), dict(r.headers)


def strip_ns(tag):
    return tag.split("}", 1)[-1]


def parse_upnp(xml_bytes):
    root = ET.fromstring(xml_bytes)
    dev = next((e for e in root.iter() if strip_ns(e.tag) == "device"), None)
    if dev is None:
        return {}
    out = {}
    for e in dev:
        k = strip_ns(e.tag)
        if k in ("deviceType", "friendlyName", "manufacturer", "modelName", "modelNumber", "modelDescription"):
            out[k] = (e.text or "").strip()[:120]
    out["services"] = sorted({(e.text or "").strip() for e in dev.iter() if strip_ns(e.tag) == "serviceType"})[:12]
    return out


def ssdp(d):
    me = lan_ip()
    msg = ('M-SEARCH * HTTP/1.1\r\nHOST: 239.255.255.250:1900\r\nMAN: "ssdp:discover"\r\n'
           "MX: 3\r\nST: ssdp:all\r\n\r\n").encode()
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_IF, socket.inet_aton(me))
    s.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 2)
    s.bind((me, 0))
    s.settimeout(1.0)
    for _ in range(3):
        s.sendto(msg, ("239.255.255.250", 1900))
        time.sleep(0.3)
    found = {}
    end = time.time() + 10
    while time.time() < end:
        try:
            data, (ip, _) = s.recvfrom(4096)
        except socket.timeout:
            continue
        h = {}
        for line in data.decode(errors="replace").split("\r\n")[1:]:
            if ":" in line:
                k, v = line.split(":", 1)
                h[k.strip().lower()] = v.strip()
        e = found.setdefault(ip, {"server": h.get("server", ""), "st": set(), "location": h.get("location", "")})
        e["st"].add(h.get("st", ""))
        e["server"] = e["server"] or h.get("server", "")
        e["location"] = e["location"] or h.get("location", "")
    s.close()
    out = {}
    for ip, e in found.items():
        rec = {"server": e["server"], "st": sorted(x for x in e["st"] if x)[:15]}
        loc = e["location"]
        m = re.match(r"^http://([\d.]+)(:\d+)?/", loc)
        if m and m.group(1) == ip:  # only fetch descriptions from the host that announced them
            try:
                rec["description"] = parse_upnp(http_get(loc, timeout=4)[0])
            except Exception as ex:
                rec["description_error"] = type(ex).__name__
        out[ip] = rec
    json.dump(out, open(d + "/ssdp.json", "w"), indent=1)
    return "%d hosts" % len(out)


# ---------------------------------------------------------------- vendor probes
def open_ports(d):
    ports = {}
    try:
        for h in ET.parse(d + "/tcp.xml").getroot().findall("host"):
            ip = next((a.get("addr") for a in h.findall("address") if a.get("addrtype") == "ipv4"), None)
            ports[ip] = {int(p.get("portid")) for p in h.findall("ports/port") if p.find("state").get("state") == "open"}
    except Exception:
        pass
    return ports


def probe_host(ip, ports):
    """Unauthenticated vendor APIs on one host (Hue, Roku, Chromecast, AirPlay). Bounded: 3 s per request."""
    import plistlib
    r = {}
    if 80 in ports:
        try:
            j = json.loads(http_get("http://%s/api/0/config" % ip, timeout=3, limit=20000)[0])
            if isinstance(j, dict) and ("bridgeid" in j or "modelid" in j):
                r["hue"] = {k: j.get(k) for k in ("name", "modelid", "swversion", "apiversion", "bridgeid", "datastoreversion")}
        except Exception:
            pass
    if 8060 in ports:  # Roku ECP
        try:
            x = ET.fromstring(http_get("http://%s:8060/query/device-info" % ip, timeout=3, limit=40000)[0])
            r["roku"] = {strip_ns(e.tag): (e.text or "")[:80] for e in x if strip_ns(e.tag) in (
                "vendor-name", "model-name", "model-number", "friendly-device-name", "user-device-name",
                "software-version", "is-tv", "is-stick", "network-type")}
        except Exception:
            pass
    if 8008 in ports:
        try:
            j = json.loads(http_get("http://%s:8008/setup/eureka_info?params=name,build_info,device_info" % ip, timeout=3, limit=40000)[0])
            r["chromecast"] = {"name": j.get("name"), "model": (j.get("device_info") or {}).get("model_name"),
                               "manufacturer": (j.get("device_info") or {}).get("manufacturer"),
                               "build": (j.get("build_info") or {}).get("cast_build_revision")}
        except Exception:
            pass
    for port in (7000, 5000):
        if port in ports and "airplay" not in r:
            try:
                pl = plistlib.loads(http_get("http://%s:%d/info" % (ip, port), timeout=3, limit=200000)[0])
                r["airplay"] = {k: pl.get(k) for k in ("model", "name", "deviceID", "sourceVersion", "manufacturer", "osBuildVersion") if k in pl}
            except Exception:
                pass
    return r


def probes(d):
    res = {}
    for ip, ports in open_ports(d).items():
        r = probe_host(ip, ports)
        if r:
            res[ip] = r
    json.dump(res, open(d + "/probes.json", "w"), indent=1, default=str)
    return "%d hosts answered" % len(res)


# ---------------------------------------------------------------- python-kasa / tinytuya
def kasa(d):
    from kasa import Discover
    out = {}

    async def go():
        devs = await Discover.discover(timeout=6, discovery_timeout=6)
        for ip, dev in devs.items():
            di = getattr(dev, "_discovery_info", None)
            if isinstance(di, dict):
                out[ip] = {k: di.get(k) for k in ("device_model", "model", "device_type", "hw_ver", "sw_ver", "alias") if di.get(k)}
                out[ip]["family"] = str(dev.config.connection_type.device_family)
    asyncio.run(go())
    json.dump(out, open(d + "/kasa.json", "w"), indent=1)
    return "%d devices" % len(out)


def tuya(d):
    import tinytuya
    r = tinytuya.deviceScan(False, 12, False, False) or {}
    out = {ip: {"version": v.get("version"), "productKey": v.get("productKey"), "encrypt": v.get("encrypt")} for ip, v in r.items()}
    json.dump(out, open(d + "/tuya.json", "w"), indent=1)
    return "%d devices" % len(out)


def main():
    stamp = datetime.datetime.now().strftime("%Y-%m-%d_%H%M")
    work = os.path.join(ROOT, "scans", ".work-" + stamp)  # dot-dir: the builder never reads it
    os.makedirs(work, exist_ok=True)
    step("nmap-tcp", nmap_tcp, work)
    step("nmap-udp", nmap_udp, work)
    step("mdns", mdns, work)
    step("ssdp", ssdp, work)
    step("probes", probes, work)
    step("kasa", kasa, work)
    step("tuya", tuya, work)
    open(work + "/collect.log", "w").write("\n".join(LOG) + "\n")
    final = os.path.join(ROOT, "scans", stamp)
    os.rename(work, final)  # publish only when the sweep is over
    log("published " + final)
    subprocess.run([sys.executable, os.path.join(ROOT, "build_report.py")], check=False)


if __name__ == "__main__":
    main()
