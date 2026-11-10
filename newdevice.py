"""New-device alerts.

presence.py calls process() after every ARP pass. A MAC that was not in state/presence.json before this pass is "new":
it is marked alert=pending, looked at briefly (short nmap + anything the passive collector overheard, through the same
identification engine as the daily sweep), then alerted on every enabled channel (notify.py). If a channel fails the record
stays pending and is retried on the next pass for up to 24 h. Existing devices never alert (no field = not new).

  newdevice.py --test        send a clearly-labelled test alert through the real channels
  newdevice.py --simulate    show what an alert for a made-up device would say, send nothing

Env: ALERT_RANDOMIZED=0 to stay quiet about randomized (private) MACs, ALERT_MAX_ENRICH (2 devices per pass),
     ALERT_DIGEST_OVER (4: more new devices than this in one pass -> one digest, no enrichment), ALERT_URL (link in the mail).
"""
import datetime
import json
import re
import os
import sys

import build_report
import evidence
import identify
import quickscan
import netinfo
import notify

ROOT = os.path.dirname(os.path.abspath(__file__))
RANDOMIZED = os.environ.get("ALERT_RANDOMIZED", "1") != "0"
MAX_ENRICH = int(os.environ.get("ALERT_MAX_ENRICH", "2"))
DIGEST_OVER = int(os.environ.get("ALERT_DIGEST_OVER", "4"))
GIVE_UP = datetime.timedelta(hours=24)


def now():
    return datetime.datetime.now(datetime.timezone.utc)


def stamp(t=None):
    return (t or now()).strftime("%Y-%m-%dT%H:%M:%SZ")


def describe(ip, mac, enrich=True):
    """Everything we can say about the device right now: dict of display facts."""
    mac = mac.lower()
    rnd = build_report.randomized(mac)
    vendor = "" if rnd else identify.manuf_lookup(mac)
    pv = evidence.passive(mac, evidence.passive_hosts())  # filed by MAC: never a previous tenant of this address
    h = (quickscan.look(ip, mac, vendor) if enrich else None) or {}
    enrich = bool(h)
    ev = {"ports": h.get("ports", []), "scripts": h.get("scripts", {}), "os": None, "osclass": None,
          "mdns_records": pv["mdns_records"], "mdns_host": pv["mdns_host"], "ssdp": pv["ssdp"],
          "probes": h.get("probes") or {}, "kasa": h.get("kasa"), "tuya": None, "dhcp": pv["dhcp"], "vendor": vendor,
          "randomized": rnd, "seed_name": None}
    idn = identify.identify(ev)
    return {"vendor": vendor, "randomized": rnd, "hostname": pv["dhcp"].get("hostname"), "idn": idn,
            "ports": ["%d %s" % (p["port"], p.get("service", "")) for p in h.get("ports", [])][:8],
            "os": None, "scanned": enrich}


SPOKEN_TYPE = {"IoT": "smart home device", "NAS": "network storage drive", "TV": "television", "Access Point": "wifi access point",
               "Media device": "media streamer", "Server": "server computer", "Desktop": "desktop computer", "Laptop": "laptop"}
SUFFIX = re.compile(r"[,.]?\s+(inc|llc|ltd|limited|co|corp|corporation|gmbh|bv|ag|sa|technologies|technology|electronics|systems)\.?\b", re.I)


def short_vendor(v):
    prev = None
    while v and v != prev:
        prev, v = v, SUFFIX.sub("", v).strip(" ,.")
    return v


def a_an(word):
    return ("an " if word[:1].lower() in "aeiou" else "a ") + word


def speak(ip, mac, d):
    """One natural spoken paragraph: what it is, who made it, its name, its OS, where it is, and how sure we are."""
    idn, vendor = d["idn"], short_vendor(d["vendor"])
    typ = SPOKEN_TYPE.get(idn["type"], (idn["type"] or "").lower())
    model = idn["model"]
    parts = ["New device on the network."]
    if model and typ and typ.lower() not in model.lower():
        parts.append("It looks like %s, %s." % (a_an(typ), model))
    elif model:
        parts.append("It looks like %s." % model)
    elif typ and vendor:
        parts.append("It looks like %s made by %s." % (a_an(typ), vendor))
    elif typ:
        parts.append("It looks like %s." % a_an(typ))
    elif vendor:
        parts.append("It was made by %s, but I can't tell what it is yet." % vendor)
    elif d["randomized"]:
        parts.append("It uses a private, randomized address, so I can't tell who made it.")
    else:
        parts.append("I can't tell what it is yet.")
    name = idn["name"] or d["hostname"]
    if name and name.lower() not in (model or "").lower():
        parts.append("It calls itself %s." % name)
    if idn["os_family"]:
        parts.append("It appears to be running %s." % idn["os_family"])
    if d["randomized"] and (model or typ):
        parts.append("It uses a private address.")
    parts.append("Its address ends in %s." % ip.split(".")[-1])
    if idn["confidence"] == "low" and (model or typ):
        parts.append("I'm not very sure about that.")
    parts.append("Details are in your email.")
    return " ".join(parts)


def local_time(iso):
    try:
        t = datetime.datetime.fromisoformat(iso.replace("Z", "+00:00")).astimezone()
        return t.strftime("%Y-%m-%d %I:%M %p %Z").replace(" 0", " ")
    except Exception:
        return iso


def compose(ip, mac, d, first_seen):
    idn = d["idn"]
    what = idn["model"] or idn["type"] or d["vendor"] or ("device with a private (randomized) MAC" if d["randomized"] else "unknown device")
    name = idn["name"] or d["hostname"]
    url = os.environ.get("ALERT_URL") or "http://%s:%s/" % (netinfo.ip(), os.environ.get("LAN_PORT", "8480"))
    lines = ["A device was seen on your network for the first time.", "",
             "What:          %s%s" % (what, " (%s)" % name if name and name != what else ""),
             "IP:            %s" % ip, "MAC:           %s%s" % (mac, "   <- randomized/private address" if d["randomized"] else ""),
             "Manufacturer:  %s" % (d["vendor"] or ("n/a (randomized MAC)" if d["randomized"] else "not in the database")),
             "First seen:    %s" % local_time(first_seen)]
    if idn["type"]:
        lines.append("Looks like:    %s (%s confidence)" % (idn["type"], idn["confidence"]))
    if idn["os_family"] or d["os"]:
        lines.append("OS:            %s" % (idn["os_family"] or d["os"]))
    if d["ports"]:
        lines.append("Open ports:    %s" % ", ".join(d["ports"]))
    if idn["reasons"]:
        lines += ["", "Why we think so:"] + ["  - %s" % r for r in idn["reasons"][:5]]
    lines += ["", "A full fingerprint (OS, models) is taken by the next daily sweep (04:30).",
              "If it is yours, give it a name in findings.json; if not, check your router's client list.", "", "Inventory: " + url]
    subject = "[LAN] New device: %s (%s)" % (what[:50], ip)
    speech = speak(ip, mac, d)
    return subject, "\n".join(lines), speech


def deliver(rec, subject, body, speech):
    """Send on the channels not yet delivered for this record. Failed channels are retried next pass; delivered ones never repeat.
    The record is 'sent' once every configured channel has delivered (and at least one is configured)."""
    res = notify.notify(subject, body, speech, skip=rec.get("alert_done", []))
    done = set(rec.get("alert_done", [])) | {c for c, ok in res.items() if ok}
    rec["alert_done"] = sorted(done)
    if not any(ok is False for ok in res.values()) and (done or rec.get("alert_done")):
        rec["alert"], rec["alert_at"] = "sent", stamp()


def process(state, new_macs):
    """Mark new MACs pending, alert on pending ones. Mutates state records (caller saves state afterwards)."""
    t = now()
    for mac in new_macs:
        state[mac]["alert"] = "pending"
        state[mac]["alert_since"] = stamp(t)
    pending = [m for m, r in state.items() if r.get("alert") == "pending"]
    if not pending:
        return
    for m in list(pending):  # give up on anything stuck for a day; honour the randomized-MAC preference
        r = state[m]
        age = t - datetime.datetime.fromisoformat(r["alert_since"].replace("Z", "+00:00"))
        if age > GIVE_UP:
            r["alert"] = "failed"
            pending.remove(m)
        elif build_report.randomized(m) and not RANDOMIZED:
            r["alert"] = "skipped"
            pending.remove(m)
    if len(pending) > DIGEST_OVER:  # a burst (new router, guests arriving, ARP weirdness): one mail, no probing
        body = ["%d new devices appeared at once:" % len(pending), ""] + [
            "  %-15s %s  %s" % (state[m].get("ip"), m, state[m].get("vendor") or ("(randomized MAC)" if build_report.randomized(m) else "")) for m in pending]
        for m in pending:  # one digest, but delivery is still tracked per device so a retry cannot double-send
            if state[m].get("digest_done") is None:
                state[m]["digest_done"] = False
        if not any(not state[m]["digest_done"] for m in pending):
            return
        res = notify.notify("[LAN] %d new devices" % len(pending), "\n".join(body), "%d new devices on the network." % len(pending))
        if res and not any(ok is False for ok in res.values()) and any(ok for ok in res.values()):
            for m in pending:
                state[m]["alert"], state[m]["digest_done"], state[m]["alert_at"] = "sent", True, stamp()
        return
    for n, mac in enumerate(pending):
        r = state[mac]
        d = describe(r.get("ip", ""), mac, enrich=n < MAX_ENRICH)
        subject, body, speech = compose(r.get("ip", "?"), mac, d, r.get("first_seen") or r["alert_since"])
        deliver(r, subject, body, speech)


def main():
    if "--test" in sys.argv:
        ok = notify.notify("[LAN] TEST alert from lan-inventory", "This is a test of the new-device alert channel.\n"
                           "If you got this, alerts work. No device was involved.", "This is a test of the lan inventory alerts.")
        print("test result:", ok, "(None = channel not configured, skipped)")
        sys.exit(0 if any(ok.values()) and not any(v is False for v in ok.values()) else 1)
    if "--simulate" in sys.argv:  # --simulate [ip mac]  -> full quick look + enrichment of a real device, nothing is sent
        args = [a for a in sys.argv[1:] if not a.startswith("--")]
        ip, mac = (args + ["192.168.1.50", "aa:bb:cc:00:00:01"])[:2] if len(args) < 2 else args[:2]
        d = describe(ip, mac.lower(), enrich=len(args) >= 2)
        s, b, sp = compose(ip, mac.lower(), d, stamp())
        print("SUBJECT:", s, "\nSPEECH :", sp, "\n\n" + b)
        return
    print(__doc__)


if __name__ == "__main__":
    main()
