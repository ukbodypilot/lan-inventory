"""A short, targeted look at one device, stored under its MAC (state/quick/<mac>.json).

The nightly sweep only sees what is awake at 04:30. This gives a device that has no scan evidence its ports,
banners and vendor-API answers within a pass or two of it appearing: presence.py calls scan_missing() after every
ARP pass (one device per pass, so the pass stays short), and newdevice.py calls look() before it alerts.

  quickscan.py <ip> <mac>     look now, store, print the result
Needs no raw sockets (TCP connect scan).
"""
import json
import os
import subprocess
import sys
import tempfile

import collect
import evidence

ROOT = os.path.dirname(os.path.abspath(__file__))
QUICK_PORTS = ("21,22,23,53,80,135,139,443,445,515,548,554,631,1883,1900,2049,3000,3389,5000,5001,5357,5900,6668,7000,8000,"
               "8008,8009,8060,8080,8081,8443,8888,9100,9999,10001,16080,49152,55443,62078")
RETRY_DAYS = float(os.environ.get("QUICK_RETRY_DAYS", "3"))  # re-look at a device whose last look found nothing


def nmap(ip):
    """~60 s TCP-connect scan of the ports that identify home devices, with service detection."""
    with tempfile.NamedTemporaryFile(suffix=".xml", delete=False) as f:
        path = f.name
    try:
        subprocess.run(["nmap", "-sT", "-sV", "-Pn", "-p", QUICK_PORTS, "-T4", "--host-timeout", "60s", "--max-retries", "1",
                        "--script", "http-title,ssl-cert,upnp-info", "-oX", path, ip],
                       capture_output=True, timeout=90)
        hosts = {}
        evidence.nmap_hosts(path, "tcp", hosts)
        return hosts.get(ip, {})
    except Exception:
        return {}
    finally:
        try:
            os.unlink(path)
        except OSError:
            pass


def kasa_one(ip):
    """TP-Link Kasa/Tapo model for one host, via python-kasa in the venv (callers may run under the system python)."""
    code = ("import asyncio,json,sys\nfrom kasa import Discover\n"
            "async def go():\n d=await Discover.discover_single(sys.argv[1], discovery_timeout=4)\n di=getattr(d,'_discovery_info',None)\n"
            " if isinstance(di,dict):\n  o={k:di.get(k) for k in ('device_model','model','device_type','hw_ver','alias') if di.get(k)}\n"
            "  o['family']=str(d.config.connection_type.device_family)\n  print(json.dumps(o))\nasyncio.run(go())\n")
    py = os.path.join(ROOT, "venv", "bin", "python")
    try:
        r = subprocess.run([py, "-c", code, ip], capture_output=True, text=True, timeout=15)
        return json.loads(r.stdout.strip().splitlines()[-1]) if r.stdout.strip() else None
    except Exception:
        return None


def holds_ip(ip, mac):
    """True if the kernel neighbour table says `mac` is the device answering for `ip` right now. A scan is addressed
    by IP, so it must not run (and be filed under `mac`) if another device holds the address."""
    if not ip:
        return False
    try:
        subprocess.run(["ping", "-c", "1", "-W", "1", ip], capture_output=True, timeout=5)  # fills the neighbour entry
        out = subprocess.run(["ip", "neigh", "show", ip], capture_output=True, text=True, timeout=5).stdout
    except Exception:
        return False
    return mac.lower() in out.lower()


def look(ip, mac, vendor=""):
    """Scan + vendor probes for one device, stored under its MAC. None if `mac` does not hold `ip` right now."""
    mac = mac.lower()
    if not holds_ip(ip, mac):
        return None
    h = nmap(ip)
    rec = {"ip": ip, "ports": h.get("ports", []), "scripts": h.get("scripts", {}), "web": h.get("web", [])}
    rec["probes"] = collect.probe_host(ip, {p["port"] for p in rec["ports"]})
    if "tp-link" in (vendor or "").lower() or 9999 in {p["port"] for p in rec["ports"]}:
        rec["kasa"] = kasa_one(ip)
    if not holds_ip(ip, mac):
        return None  # the address changed hands while we were looking: whose answers these are is unknown
    evidence.quick_save(mac, rec)
    return rec


def scan_missing(presence, online, self_mac, limit=1):
    """Look at up to `limit` online devices that have no scan evidence. `presence` is mac -> record, `online` the
    MACs seen this pass. Newest arrivals first. Returns the MACs looked at."""
    scans = evidence.load_scans()
    done = []
    rl_path = os.path.join(ROOT, "state", "relook.json")
    relook = evidence.jload(rl_path, [])  # devices that renamed themselves (build_report.track_names): ask them again
    for mac in [m for m in relook if m in online and m != self_mac][:limit]:
        r = presence.get(mac) or {}
        if r.get("ip") and look(r["ip"], mac, r.get("vendor", "")) is not None:
            evidence.jsave(rl_path, [m for m in relook if m != mac])
            done.append(mac)
    if done:
        return done
    todo = []
    for mac in online:
        r = presence.get(mac) or {}
        if mac == self_mac or not r.get("ip"):
            continue
        if any(mac in d["hosts"] for d in scans):
            continue
        q = evidence.quick_load(mac)
        if q and (q.get("ports") or evidence.age_days(q.get("stamp")) < RETRY_DAYS):
            continue
        todo.append((r.get("first_seen", ""), mac))
    for _, mac in sorted(todo, reverse=True)[:limit]:
        r = presence[mac]
        rec = look(r["ip"], mac, r.get("vendor", ""))
        if rec is None:  # not reachable at that address now: remember the attempt so one device cannot starve the rest
            evidence.quick_save(mac, {"ip": r["ip"], "ports": [], "unreachable": True})
        done.append(mac)
    return done


if __name__ == "__main__":
    if len(sys.argv) != 3:
        raise SystemExit(__doc__)
    print(json.dumps(look(sys.argv[1], sys.argv[2]), indent=1))
