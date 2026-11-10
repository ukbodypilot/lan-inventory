"""Rolling time-series store for router metrics: one SQLite file, state/router_history.sqlite (or HISTORY_DB).

router_collect.py calls record(snapshot) every run (web every 5 min, TMP on demand); router_web.py serves series()
to the router pages' charts and sparklines. Kept for RETENTION_DAYS, matching the
project's 30-day log retention.

  samples(ts INTEGER, metric TEXT, key TEXT, value REAL)

metric / key used today:
  gw_cpu, gw_mem_pct            key ""        gateway node only (that's all device_resource_info reports)
  clients_online, nodes_online  key ""
  node_down, node_up            key node MAC  device_list_speed (TMP only; every 5 min), kB/s (unit unconfirmed). Keyed by
                                              MAC, not IP: node IPs reshuffled on a reboot (2026-10-25)
                                              and a node's sparkline then showed another unit's past.
  client_signal                 key MAC       dBm, wireless clients only
  client_down, client_up        key MAC       client_list_speed
  node_online                   key node MAC  1 = in the mesh (group_status), 0 = not
  node_clients                  key node MAC  online clients on that node (only when clients map to nodes)
  node_wired                    key node MAC  1 = wired backhaul, 0 = wireless (satellites only)
  node_sig_5g, node_sig_24g     key node MAC  backhaul signal level 0-3, wireless-backhaul satellites only
  tmp_port_up                   key ""        1 = control port 20001 accepted a connection (router_collect probe)
  collect_seconds               key full|web  how long a snapshot took
"""
import os
import sqlite3
import time

import router_config

ROOT = os.path.dirname(os.path.abspath(__file__))
# HISTORY_DB (router.env or env) moves it, e.g. onto a tmpfs; relative paths are from this directory
DB = os.path.join(ROOT, router_config.load().get("HISTORY_DB") or os.path.join("state", "router_history.sqlite"))
RETENTION_DAYS = 30


def _db(path=DB):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    con = sqlite3.connect(path, timeout=10)
    con.execute("PRAGMA journal_mode=WAL")
    con.execute("CREATE TABLE IF NOT EXISTS samples (ts INTEGER NOT NULL, metric TEXT NOT NULL, key TEXT NOT NULL, value REAL NOT NULL)")
    con.execute("CREATE INDEX IF NOT EXISTS samples_mkt ON samples (metric, key, ts)")
    return con


def _mac(m):
    return (m or "").replace("-", ":").lower()


def rows_from_snapshot(reads, ts):
    """Turn one router_collect snapshot into (ts, metric, key, value) rows."""
    def res(name):
        r = reads.get(name) or {}
        return r.get("result") if r.get("ok") else None

    rows = []
    nodes = (res("device_list") or {}).get("device_list") or []
    mac_by_id = {n["device_id"]: _mac(n.get("mac")) for n in nodes if n.get("device_id") and n.get("mac")}
    master = next((n["device_id"] for n in nodes if n.get("role") == "master"), None)
    # group_status is mesh membership (what the Deco app shows); inet_status is a separate internet
    # check that can read "offline" on a working node (seen on a just-moved X55, 2026-10-25)
    rows.append((ts, "nodes_online", "", sum(1 for n in nodes if n.get("group_status") == "connected")))
    for n in nodes:
        mac = _mac(n.get("mac"))
        if not mac:
            continue
        on = n.get("group_status") == "connected"
        rows.append((ts, "node_online", mac, 1 if on else 0))
        ct = n.get("connection_type") or []
        if on and ct and n.get("role") != "master":
            rows.append((ts, "node_wired", mac, 1 if "wired" in ct else 0))
            if "wired" not in ct:
                for band, metric in (("band5", "node_sig_5g"), ("band2_4", "node_sig_24g")):
                    if band in ct:
                        rows.append((ts, metric, mac, int((n.get("signal_level") or {}).get(band) or 0)))

    for s in (res("device_list_speed") or {}).get("device_list_speed") or []:
        mac = mac_by_id.get(s.get("device_id"))
        if mac:
            rows.append((ts, "node_down", mac, s.get("down_speed") or 0))
            rows.append((ts, "node_up", mac, s.get("up_speed") or 0))

    for d in (res("device_resource_info") or {}).get("device_list") or []:
        if d.get("device_id") == master or master is None:
            rows.append((ts, "gw_cpu", "", d.get("cpu_usage") or 0))
            if d.get("memory_total"):
                rows.append((ts, "gw_mem_pct", "", round(100.0 * d["memory_usage"] / d["memory_total"], 1)))

    clients = (res("client_list") or {}).get("client_list") or []
    online = [c for c in clients if c.get("online")]
    rows.append((ts, "clients_online", "", len(online)))
    per_node = {}
    for c in online:
        li = c.get("linked_device_info") or {}
        if mac_by_id.get(li.get("device_id")):
            per_node[mac_by_id[li["device_id"]]] = per_node.get(mac_by_id[li["device_id"]], 0) + 1
        band = next(iter(li.get("connection_type") or []), None)
        sig = (li.get("signal_strength") or {}).get(band) if band else None
        if sig:
            rows.append((ts, "client_signal", _mac(c.get("mac")), sig))
    if per_node:  # no mapping at all (a web snapshot whose per-node lists failed): unknown, not 0
        for n in nodes:
            mac = _mac(n.get("mac"))
            if mac and n.get("group_status") == "connected":
                rows.append((ts, "node_clients", mac, per_node.get(mac, 0)))

    for s in (res("client_list_speed") or {}).get("client_list_speed") or []:
        if s.get("down_speed") is None:
            continue
        rows.append((ts, "client_down", _mac(s.get("mac")), s.get("down_speed") or 0))
        rows.append((ts, "client_up", _mac(s.get("mac")), s.get("up_speed") or 0))
    return rows


def record(reads, ts=None, path=DB):
    """Append one snapshot's rows and prune old ones. Returns (rows written, rows in db)."""
    ts = int(ts or time.time())
    rows = rows_from_snapshot(reads, ts)
    con = _db(path)
    with con:
        con.executemany("INSERT INTO samples VALUES (?,?,?,?)", rows)
        con.execute("DELETE FROM samples WHERE ts < ?", (ts - RETENTION_DAYS * 86400,))
    total = con.execute("SELECT COUNT(*) FROM samples").fetchone()[0]
    con.close()
    return len(rows), total


def record_point(metric, key, value, ts=None, path=DB):
    """One extra sample that isn't part of a snapshot (port probe, run time)."""
    con = _db(path)
    with con:
        con.execute("INSERT INTO samples VALUES (?,?,?,?)", (int(ts or time.time()), metric, key, value))
    con.close()


def last(metric, key="", path=DB):
    """(ts, value) of the newest sample, or None."""
    if not os.path.exists(path):
        return None
    con = _db(path)
    row = con.execute("SELECT ts, value FROM samples WHERE metric = ? AND key = ? ORDER BY ts DESC LIMIT 1",
                      (metric, key)).fetchone()
    con.close()
    return tuple(row) if row else None


def series(metric, key=None, since=86400, points=48, path=DB):
    """Bucket-averaged series, oldest first: {key: [[ts, value], ...]}.
    `key` None returns every key for the metric (used by the clients page's sparklines)."""
    if not os.path.exists(path):
        return {}
    now = int(time.time())
    start = now - int(since)
    bucket = max(300, int(since) // max(1, int(points)))
    con = _db(path)
    q = ("SELECT key, (ts / ?) * ? AS b, AVG(value) FROM samples WHERE metric = ? AND ts >= ?"
         + (" AND key = ?" if key is not None else "") + " GROUP BY key, b ORDER BY key, b")
    args = [bucket, bucket, metric, start] + ([key] if key is not None else [])
    out = {}
    for k, b, v in con.execute(q, args):
        out.setdefault(k, []).append([b, round(v, 2)])
    con.close()
    return out
