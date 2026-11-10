#!/usr/bin/env python3
"""Continuous traceroute for the Ping page: one `mtr` round every PING_INTERVAL seconds
to PING_TARGET (router.env, defaults 8.8.8.8 / 2 s), stored per hop in
state/ping_history.sqlite (or PING_DB). A Linux port of the Windows "pingtrace" tool -- mtr --json
replaces its PowerShell probe and the summary below replaces its server.js.

  ping_collect.py            (run by lan-ping.service; loops forever)
  ping_collect.py --once     (one round, printed -- for checking mtr works)

router_web.py imports summary() to serve GET /api/ping.

  rounds(ts REAL, target TEXT, hop INTEGER, ip TEXT NULL, ms REAL NULL)   ip/ms NULL = no reply
  names(ip TEXT PRIMARY KEY, name TEXT, ts REAL)                          reverse-DNS cache
  status(key TEXT PRIMARY KEY, value TEXT)                                counters, last error

History is per target: when the target changes, the old target's rows are dropped, so the
page starts fresh (same as the original).
"""
import concurrent.futures
import json
import os
import socket
import sqlite3
import subprocess
import sys
import time
from collections import Counter

import lan_log
import router_config

ROOT = os.path.dirname(os.path.abspath(__file__))
# PING_DB (router.env or env) moves it, e.g. onto a tmpfs: a round is written every PING_INTERVAL s,
# which makes this the most frequent disk writer in the project. Relative paths are from this directory.
DB = os.path.join(ROOT, router_config.load().get("PING_DB") or os.path.join("state", "ping_history.sqlite"))
KEEP_HOURS = 24
MAX_HOPS = 30
SERIES_ROUNDS = 120
NAME_TTL = 3600       # re-resolve a hop's PTR after this long
NAME_RETRY = 600      # ... or this long, if it had none
OUTAGE_ROUNDS = 3     # consecutive rounds with no reply from the target before it's logged as an outage
ROUTE_ROUNDS = 5      # a new route must hold this many rounds before it's logged (ECMP flaps otherwise)


class Events:
    """Turns the round-by-round results into "ping" log lines: outages, route changes, mtr failures."""

    def __init__(self):
        self.lost = 0             # consecutive rounds without a reply from the target
        self._first_lost = None
        self.outage_since = None
        self.route = None         # last logged (stable) route
        self.cand, self.cand_n = None, 0
        self.fail_since, self.fails = None, 0

    def round_ok(self, target, hops, ts):
        if self.fail_since is not None:
            lan_log.event("ping", "mtr_recovered", target=target, failed_rounds=self.fails,
                          for_s=round(ts - self.fail_since))
            self.fail_since, self.fails = None, 0
        reached = bool(hops) and hops[-1]["ip"] is not None
        if reached:
            if self.outage_since is not None:
                lan_log.event("ping", "outage_end", target=target, lost_rounds=self.lost,
                              for_s=round(ts - self.outage_since))
            self.lost, self.outage_since = 0, None
        else:
            self.lost += 1
            if self.lost == 1:
                self._first_lost = ts
            if self.lost == OUTAGE_ROUNDS:
                self.outage_since = self._first_lost
                # last hop that still answered: where the path broke
                last = next((h for h in reversed(hops) if h["ip"]), None)
                lan_log.event("ping", "outage_start", target=target, last_reply_hop=last and last["hop"],
                              last_reply_ip=last and last["ip"])
        if reached:
            sig = tuple(h["ip"] for h in hops if h["ip"])
            if sig == self.route:
                self.cand, self.cand_n = None, 0
            elif sig == self.cand:
                self.cand_n += 1
                if self.cand_n >= ROUTE_ROUNDS:
                    if self.route is not None:
                        lan_log.event("ping", "route_change", target=target, hops=len(hops),
                                      was=list(self.route), now=list(sig))
                    self.route, self.cand, self.cand_n = sig, None, 0
            else:
                self.cand, self.cand_n = sig, 1

    def round_failed(self, target, exc, ts):
        self.fails += 1
        if self.fail_since is None:
            self.fail_since = ts
            lan_log.event("ping", "mtr_failed", target=target, error=str(exc)[:300])


def _db(path=DB):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    con = sqlite3.connect(path, timeout=10)
    con.execute("PRAGMA journal_mode=WAL")
    con.execute("CREATE TABLE IF NOT EXISTS rounds (ts REAL NOT NULL, target TEXT NOT NULL, hop INTEGER NOT NULL, ip TEXT, ms REAL)")
    con.execute("CREATE INDEX IF NOT EXISTS rounds_tt ON rounds (target, ts)")
    con.execute("CREATE TABLE IF NOT EXISTS names (ip TEXT PRIMARY KEY, name TEXT NOT NULL, ts REAL NOT NULL)")
    con.execute("CREATE TABLE IF NOT EXISTS status (key TEXT PRIMARY KEY, value TEXT)")
    return con


def _settings():
    cfg = router_config.load()
    try:
        interval = max(1.0, float(cfg["PING_INTERVAL"]))
    except ValueError:
        interval = 2.0
    return cfg["PING_TARGET"].strip() or "8.8.8.8", interval


def probe(target, timeout=20):
    """One mtr round -> [{hop, ip, ms}] (ip/ms None for a hop that didn't answer).
    -G1 cuts mtr's default 5 s wait after the last probe; a round takes ~2 s."""
    out = subprocess.run(
        ["mtr", "--json", "-n", "-c", "1", "-G", "1", "-Z", "1", "-m", str(MAX_HOPS), target],
        capture_output=True, text=True, timeout=timeout,
    )
    if out.returncode != 0:
        raise RuntimeError((out.stderr or out.stdout).strip()[:300] or f"mtr exit {out.returncode}")
    hops = []
    for h in json.loads(out.stdout)["report"].get("hubs") or []:
        answered = h.get("host") not in (None, "???") and h.get("Loss%", 100) < 100
        hops.append({"hop": int(h["count"]), "ip": h["host"] if answered else None,
                     "ms": round(float(h["Last"]), 2) if answered else None})
    return hops


def _set_status(con, **kv):
    con.executemany("INSERT INTO status VALUES (?, ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value",
                    [(k, str(v)) for k, v in kv.items()])


def _bump(con, key):
    con.execute("INSERT INTO status VALUES (?, '1') ON CONFLICT(key) DO UPDATE SET value = CAST(value AS INTEGER) + 1", (key,))


def _resolve(ip):
    try:
        return socket.gethostbyaddr(ip)[0]
    except OSError:
        return ""


def _refresh_names(con, pool, ips, pending):
    """Kick off PTR lookups for hops not in the cache (or stale); collect finished ones."""
    now = time.time()
    for ip, fut in list(pending.items()):
        if fut.done():
            con.execute("INSERT OR REPLACE INTO names VALUES (?, ?, ?)", (ip, fut.result(), now))
            del pending[ip]
    cached = {ip: (name, ts) for ip, name, ts in con.execute("SELECT ip, name, ts FROM names")}
    for ip in ips:
        if ip in pending:
            continue
        c = cached.get(ip)
        if c is None or now - c[1] > (NAME_TTL if c[0] else NAME_RETRY):
            pending[ip] = pool.submit(_resolve, ip)


def run():
    con = _db()
    pool = concurrent.futures.ThreadPoolExecutor(max_workers=4)
    pending = {}
    last_prune = 0.0
    current = None
    events = Events()
    while True:
        target, interval = _settings()
        started = time.time()
        if target != current:
            # New target -> fresh history, like the original tool.
            with con:
                con.execute("DELETE FROM rounds WHERE target != ?", (target,))
                _set_status(con, target=target, interval=interval, started=started)
            current = target
            events = Events()
            lan_log.event("ping", "target", target=target, interval=interval)
            print(f"ping_collect: tracing {target} every {interval:g}s", flush=True)
        try:
            hops = probe(target)
            with con:
                con.executemany("INSERT INTO rounds VALUES (?, ?, ?, ?, ?)",
                                [(started, target, h["hop"], h["ip"], h["ms"]) for h in hops])
                _bump(con, "rounds_ok")
                _set_status(con, last_ok=started, last_hops=len(hops))
            _refresh_names(con, pool, {h["ip"] for h in hops if h["ip"]}, pending)
            events.round_ok(target, hops, started)
            con.commit()
        except Exception as exc:  # noqa: BLE001 - a failed round is counted and skipped, never fatal
            with con:
                _bump(con, "rounds_failed")
                _set_status(con, last_error=f"{time.strftime('%H:%M:%S')} {exc}")
            print(f"ping_collect: round failed: {exc}", file=sys.stderr, flush=True)
            events.round_failed(target, exc, started)
        if started - last_prune > 600:
            with con:
                con.execute("DELETE FROM rounds WHERE ts < ?", (started - KEEP_HOURS * 3600,))
            last_prune = started
        time.sleep(max(0.2, interval - (time.time() - started)))


def summary(window=3600, path=DB):
    """Per-hop loss/latency over the last `window` seconds for the current target,
    plus each hop's last SERIES_ROUNDS samples (None = no reply)."""
    target, interval = _settings()
    out = {"target": target, "interval": interval, "window": window, "rounds": 0, "hops": [], "status": {}}
    if not os.path.exists(path):
        return out
    con = _db(path)
    try:
        out["status"] = dict(con.execute("SELECT key, value FROM status"))
        since = time.time() - window
        rows = con.execute("SELECT ts, hop, ip, ms FROM rounds WHERE target = ? AND ts >= ? ORDER BY ts",
                           (target, since)).fetchall()
        names = dict(con.execute("SELECT ip, name FROM names"))
    finally:
        con.close()
    if not rows:
        return out

    stamps = sorted({r[0] for r in rows})
    out["rounds"] = len(stamps)
    last_hop = max(r[1] for r in rows if r[0] == stamps[-1])
    recent = stamps[-SERIES_ROUNDS:]
    recent_idx = {t: i for i, t in enumerate(recent)}

    by = {}
    for ts, hop, ip, ms in rows:
        if hop > last_hop:  # route got shorter since -- drop the stale tail
            continue
        s = by.setdefault(hop, {"sent": 0, "lost": 0, "ips": Counter(), "vals": [], "last": None,
                                "series": [None] * len(recent)})
        s["sent"] += 1
        if ip is None:
            s["lost"] += 1
            s["last"] = None
        else:
            s["ips"][ip] += 1
            s["vals"].append(ms)
            s["last"] = ms
        if ts in recent_idx:
            s["series"][recent_idx[ts]] = ms
    for hop in sorted(by):
        s = by[hop]
        ip = s["ips"].most_common(1)[0][0] if s["ips"] else None
        v = s["vals"]
        out["hops"].append({
            "hop": hop, "ip": ip or "*", "name": names.get(ip, "") if ip else "",
            "ips": len(s["ips"]),
            "sent": s["sent"], "loss": round(100.0 * s["lost"] / s["sent"], 1) if s["sent"] else 0.0,
            "last": s["last"], "avg": round(sum(v) / len(v), 1) if v else None,
            "min": min(v) if v else None, "max": max(v) if v else None,
            "series": s["series"],
        })
    out["first"] = stamps[0]
    out["latest"] = stamps[-1]
    return out


if __name__ == "__main__":
    if "--once" in sys.argv:
        t, _ = _settings()
        print(json.dumps(probe(t), indent=1))
    else:
        run()
