"""What changed between two router snapshots, as log events (lan_log streams "mesh" and "clients").

router_collect.py calls changes(prev_reads, new_reads) on every run (web every 5 min, TMP hourly). Nodes
and clients are matched by MAC; a node's upstream is compared by the upstream's MAC, because the master's
device_id is inferred on web snapshots and may not equal what TMP reports. A field is only compared when
both snapshots have it, so switching between the web and TMP sources doesn't invent changes.
"""
import base64
import binascii


def _mac(m):
    return (m or "").replace("-", ":").lower()


def _text(s):
    """Deco names are sometimes base64 (custom node names, some client names)."""
    if not s:
        return ""
    if len(s) < 4 or len(s) % 4:  # same test as LC.b64 in console.js
        return s
    try:
        d = base64.b64decode(s, validate=True).decode("utf-8").strip()
        if d and d.isprintable():
            return d
    except (binascii.Error, UnicodeDecodeError, ValueError):
        pass
    return s


def _res(reads, name):
    r = (reads or {}).get(name) or {}
    return r.get("result") if r.get("ok") else None


def nodes(reads):
    """{mac: {...}} with the fields worth tracking."""
    raw = (_res(reads, "device_list") or {}).get("device_list") or []
    mac_by_id = {n.get("device_id"): _mac(n.get("mac")) for n in raw if n.get("device_id")}
    out = {}
    for n in raw:
        mac = _mac(n.get("mac"))
        if not mac:
            continue
        name = _text(n.get("custom_nickname")) if n.get("nickname") == "custom" else (n.get("nickname") or "")
        ct = n.get("connection_type") or []
        bands = [b for b in ct if b != "wired"]
        parent = mac_by_id.get(n.get("parent_device_id"))
        if not parent and n.get("previous"):
            parent = _mac(n["previous"])
        out[mac] = {
            "name": (name or n.get("device_model") or mac).replace("_", " "),
            "model": n.get("device_model"), "ip": n.get("ip") or n.get("device_ip") or None,
            "online": n.get("group_status") == "connected", "master": n.get("role") == "master",
            "upstream": None if n.get("role") == "master" or parent == mac else parent,
            # None: not reported (the master, or an offline node) -- distinct from a real change
            "backhaul": None if n.get("role") == "master" or not ct else ("wired" if "wired" in ct else "wireless"),
            "signal": {b: int((n.get("signal_level") or {}).get(b) or 0) for b in bands} or None,
            "fw": (n.get("software_ver") or "").split(" ")[0] or None,
        }
    return out


def clients(reads, node_names=None):
    """{mac: {...}} for online clients."""
    by_id = {}
    for n in (_res(reads, "device_list") or {}).get("device_list") or []:
        if n.get("device_id"):
            by_id[n["device_id"]] = _mac(n.get("mac"))
    out = {}
    for c in (_res(reads, "client_list") or {}).get("client_list") or []:
        if not c.get("online"):
            continue
        li = c.get("linked_device_info") or {}
        band = next((b for b in li.get("connection_type") or [] if b != "wired"), None)
        name = _text(c.get("name"))
        out[_mac(c.get("mac"))] = {
            "name": "" if name.lower() == "none" else name, "ip": c.get("ip") or None,
            "node": by_id.get(li.get("device_id")),
            "band": "wired" if c.get("wire_type") == "wired" else band,
            "signal": (li.get("signal_strength") or {}).get(band) if band else None,
        }
    return out


def changes(prev_reads, new_reads, same_source=True):
    """[(stream, ev, fields)] describing what changed. Empty if either side has no node list.
    same_source=False (one snapshot from TMP, one from the web interface) skips renames: TMP names a
    preset room by its key ("master_bedroom"), the web interface by its label ("Primary Bedroom")."""
    a, b = nodes(prev_reads), nodes(new_reads)
    if not a or not b:
        return []
    names = {m: n["name"] for m, n in {**a, **b}.items()}
    nm = lambda mac: names.get(mac, mac) if mac else None
    ev = []

    for mac in sorted(set(a) | set(b)):
        o, n = a.get(mac), b.get(mac)
        if o is None:
            ev.append(("mesh", "node_added", {"node": n["name"], "mac": mac, "model": n["model"], "ip": n["ip"]}))
            continue
        if n is None:
            ev.append(("mesh", "node_removed", {"node": o["name"], "mac": mac}))
            continue
        base = {"node": n["name"], "mac": mac}
        if o["online"] != n["online"]:
            ev.append(("mesh", "node_online" if n["online"] else "node_offline", dict(base, ip=n["ip"] or o["ip"])))
        if not n["online"]:
            continue  # an offline node reports no link; don't log its fields going blank
        if same_source and o["name"] != n["name"]:
            ev.append(("mesh", "node_renamed", dict(base, was=o["name"])))
        if o["ip"] and n["ip"] and o["ip"] != n["ip"]:
            ev.append(("mesh", "node_ip", dict(base, was=o["ip"], now=n["ip"])))
        if o["upstream"] and n["upstream"] and o["upstream"] != n["upstream"]:
            ev.append(("mesh", "node_upstream", dict(base, was=nm(o["upstream"]), now=nm(n["upstream"]))))
        if o["backhaul"] and n["backhaul"] and o["backhaul"] != n["backhaul"]:
            ev.append(("mesh", "node_backhaul", dict(base, was=o["backhaul"], now=n["backhaul"], signal=n["signal"])))
        elif n["backhaul"] == "wireless" and o["signal"] and n["signal"] and o["signal"] != n["signal"]:
            ev.append(("mesh", "node_signal", dict(base, was=o["signal"], now=n["signal"])))
        if o["fw"] and n["fw"] and o["fw"] != n["fw"]:
            ev.append(("mesh", "node_firmware", dict(base, was=o["fw"], now=n["fw"])))

    ca, cb = clients(prev_reads), clients(new_reads)
    # Only diff clients when both snapshots mapped clients to nodes (a web snapshot whose per-node
    # lists failed has no node for anyone) -- otherwise every client would look like it moved.
    mapped = lambda cs: any(c["node"] for c in cs.values())
    track_node = mapped(ca) and mapped(cb)
    for mac in sorted(set(ca) | set(cb)):
        o, n = ca.get(mac), cb.get(mac)
        c = n or o
        base = {"client": c["name"] or c["ip"] or mac, "mac": mac, "ip": c["ip"]}
        if o is None:
            ev.append(("clients", "joined", dict(base, node=nm(n["node"]), band=n["band"], signal=n["signal"])))
        elif n is None:
            ev.append(("clients", "left", dict(base, node=nm(o["node"]))))
        else:
            if track_node and o["node"] and n["node"] and o["node"] != n["node"]:
                ev.append(("clients", "roamed", dict(base, was=nm(o["node"]), now=nm(n["node"]), band=n["band"], signal=n["signal"])))
            elif o["band"] and n["band"] and o["band"] != n["band"]:
                ev.append(("clients", "band", dict(base, node=nm(n["node"]), was=o["band"], now=n["band"], signal=n["signal"])))
            if o["ip"] and n["ip"] and o["ip"] != n["ip"]:
                ev.append(("clients", "ip", dict(base, was=o["ip"], now=n["ip"])))
    return ev
