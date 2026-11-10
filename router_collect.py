#!/usr/bin/env python3
"""Periodic read-only Deco snapshot -> web/router.json, for the router page and for
build_report.py to pull extra identification evidence from (router-reported hostname,
band, connection type -- see identify.py's ROUTER_CLIENTS source).

  router_collect.py            full read over TMP (port 20001): hourly (lan-router-full.timer) and
                               "Refresh now" on the router pages; reads paced TMP_READ_GAP s apart (default 1)
  router_collect.py --web-only scheduled (lan-router.timer, every 5 min): web interface (deco_web.py), plus one
                               TMP read of node speeds (the web interface has none) unless TMP_SPEED_READS=0

Runs are serialised by a lock file, so a web snapshot never overwrites a full read it started before.
TMP is read sparingly: on 2026-10-25 port 20001 closed for 45+ min and repeated connection
attempts were suspected of keeping it shut. A web-only snapshot replaces what the web interface reports
(nodes, clients, WAN, CPU/mem) and carries every other read over from the last full read, marked
"stale": true, with that read's time in "full_generated".
"""
import datetime
import fcntl
import json
import os
import sys
import time

import deco_tmp
import deco_web
import lan_log
import router_busy
import router_changes
import router_config
import router_history

ROOT = os.path.dirname(os.path.abspath(__file__))
OUT = os.path.join(ROOT, "web", "router.json")
PORT_STATE = os.path.join(ROOT, "state", "tmp_port.json")
SPEED_STATE = os.path.join(ROOT, "state", "tmp_speed.json")
SPEED_BACKOFF = 3600  # s without speed reads after one is refused or times out

# What the page actually renders; kept smaller than the full READ table so a
# timer isn't hammering every opcode, including the ones nobody
# looks at (messages, scenes, rooms, ...).
SNAPSHOT_READS = [
    "system_info", "wan_lan_status", "device_list", "device_list_speed",
    "client_list", "client_list_speed", "blocked_list", "wifi_bands_info",
    "led_schedule", "dns_servers", "wps", "upnp", "doh", "ddns", "ipv6",
    "internet_backup", "qos_bandwidth", "dpi_qos", "homeshield",
    "access_control_mode", "access_control_white_list", "port_forwarding",
    "reservations", "dhcp_leases", "dhcp_server", "firmware", "mac_clone",
    "device_resource_info", "wireless_link", "speedtest",
]
# Reads a web-only snapshot must not carry over from the last full read (stale rates look current).
NO_CARRY = {"device_list_speed", "client_list_speed"}
# network_quality dropped: it answers error_code=1 on an X55 with no params; reinstate
# once someone works out what it wants.


def _port_seen(up, how):
    """Record whether port 20001 answered: a history point every run, a "tmp" log line on each change."""
    try:
        router_history.record_point("tmp_port_up", "", 1 if up else 0)
    except Exception as exc:  # noqa: BLE001
        print(f"router_collect: history: {exc}", file=sys.stderr)
    try:
        with open(PORT_STATE) as f:
            was = json.load(f)
    except (OSError, ValueError):
        was = None
    now = time.time()
    if was is None or was.get("up") != up:
        if was is not None:
            # seen at 5-min granularity, so durations are +-5 min
            lan_log.event("tmp", "port_up" if up else "port_down", how=how,
                          **{"down_for_s" if up else "up_for_s": round(now - was.get("since", now))})
        tmp = PORT_STATE + ".tmp"
        os.makedirs(os.path.dirname(PORT_STATE), exist_ok=True)
        with open(tmp, "w") as f:
            json.dump({"up": up, "since": now, "how": how}, f)
        os.replace(tmp, PORT_STATE)


def _speed_read(cfg, log):
    """One login, one read (device_list_speed) on port 20001, for the 5-min throughput graph. Replaces the
    plain port probe on those runs, so it adds a login, not a connection. Any refusal or timeout stops
    these reads for SPEED_BACKOFF: repeated connects were suspected of keeping the port shut. Returns the
    read, or None (then the caller probes the port instead)."""
    try:
        with open(SPEED_STATE) as f:
            until = json.load(f).get("until", 0)
    except (OSError, ValueError):
        until = 0
    if cfg.get("TMP_SPEED_READS") == "0" or time.time() < until:
        if until > time.time():
            log["speed"] = f"backing off until {time.strftime('%H:%M', time.localtime(until))}"
        return None
    t0 = time.monotonic()
    try:
        with deco_tmp.DecoClient(cfg["DECO_HOST"], cfg["DECO_EMAIL"], cfg["DECO_ACCTPW"]) as deco:
            res = deco.get("device_list_speed")
        log["speed"] = "ok"
        log["speed_s"] = round(time.monotonic() - t0, 1)
        _port_seen(True, "speed read")
        return {"ok": True, "result": res, "ms": round((time.monotonic() - t0) * 1000)}
    except Exception as exc:  # noqa: BLE001
        log["speed"] = f"failed: {exc}"
        print(f"router_collect: speed read: {exc}", file=sys.stderr)
        if _refused(exc):
            _port_seen(False, "speed read")
            lan_log.event("tmp", "speed_backoff", error=str(exc), for_s=SPEED_BACKOFF)
            os.makedirs(os.path.dirname(SPEED_STATE), exist_ok=True)
            with open(SPEED_STATE, "w") as f:
                json.dump({"until": time.time() + SPEED_BACKOFF, "error": str(exc)}, f)
        elif _timed_out(exc):
            # a slow router is not a shut port: no port_down, no backoff (the next run tries again)
            lan_log.event("tmp", "speed_slow", error=str(exc) or "timeout", after_s=round(time.monotonic() - t0, 1))
        return {"ok": False, "error": str(exc)}


def _float(v, default):
    try:
        return max(0.0, float(v))
    except (TypeError, ValueError):
        return default


def _refused(exc):
    """True if a TMP failure means the port itself is shut (connection refused). A timeout is not
    that: it is a router too busy to answer, see _timed_out."""
    return isinstance(exc, ConnectionRefusedError) or "Errno 111" in str(exc)


def _timed_out(exc):
    return isinstance(exc, TimeoutError) or "timed out" in str(exc) or not str(exc)


def main():
    t_start = time.monotonic()
    trigger = os.environ.get("LAN_TRIGGER", "timer")
    cfg = router_config.load()
    try:
        email, password = cfg["DECO_EMAIL"], cfg["DECO_ACCTPW"]
    except KeyError:
        print("router_collect: DECO_EMAIL/DECO_ACCTPW not set (env or router.env) -- skipping", file=sys.stderr)
        return 0  # not fatal: the rest of lan-inventory should keep working without this

    scheduled = "--web-only" in sys.argv
    try:
        with open(OUT) as f:
            prev = json.load(f)
    except (OSError, ValueError):
        prev = None
    st = router_busy.status()
    tmp_down = "scheduled web snapshot" if scheduled else None
    if st["busy"] and not tmp_down:
        # the TMP port is closed while the router applies a write; the web interface is separate
        tmp_down = f"router busy after '{st['write']}' ({st['phase']})"

    report = {
        "generated": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "host": cfg["DECO_HOST"],
        "reads": {},
        # Tells the frontend which read sections are editable and how -- single
        # source of truth is deco_tmp.SETTINGS, not duplicated in router.html.
        "settings": {
            name: {
                "kind": s.kind, "write": s.write, "add": s.add, "modify": s.modify,
                "remove": s.remove, "id_field": s.id_field, "risk": s.risk, "label": s.label,
                "verified": deco_tmp.WRITE[s.write].verified if s.write else None,
                "add_verified": deco_tmp.WRITE[s.add].verified if s.add else None,
                "modify_verified": deco_tmp.WRITE[s.modify].verified if s.modify else None,
                "remove_verified": deco_tmp.WRITE[s.remove].verified if s.remove else None,
                "tier": deco_tmp.WRITE[s.write or s.add].tier,
                "note": deco_tmp.WRITE[s.write or s.add].note,
            }
            for name, s in deco_tmp.SETTINGS.items()
        },
    }
    report["source"] = "tmp"
    speed = None
    log = {"mode": "web" if scheduled else "full", "trigger": trigger}
    if not tmp_down:
        try:
            t0 = time.monotonic()
            with deco_tmp.DecoClient(cfg["DECO_HOST"], email, password) as deco:
                log["connect_s"] = round(time.monotonic() - t0, 1)
                try:
                    gap = max(0.0, float(cfg["TMP_READ_GAP"]))
                except ValueError:
                    gap = 1.0
                log["gap_s"] = gap
                report["reads"] = deco.snapshot(SNAPSHOT_READS, gap=gap)
            report["full_generated"] = report["generated"]
            _port_seen(True, "full read")
        except Exception as exc:  # noqa: BLE001 - a bad sweep should still write what it has
            tmp_down = str(exc)
            log["tmp_error"] = tmp_down
            print(f"router_collect: TMP: {exc}", file=sys.stderr)
            if _refused(exc):
                _port_seen(False, "full read")
    elif scheduled and not st["busy"]:
        # node speeds for the throughput graph; failing that (off, backing off), one gentle connect
        # (no login), so outages of port 20001 still show up in the history and the "tmp" log
        speed = _speed_read(cfg, log)
        if speed is None:
            _port_seen(router_busy.port_open(cfg["DECO_HOST"]), "probe")
    elif st["busy"]:
        log["skipped_tmp"] = tmp_down

    if tmp_down:
        # Fallback: the local web interface (:80) keeps working when TMP doesn't. Fewer reads
        # (no settings, no per-client node or signal) but the mesh and client list survive.
        try:
            report["reads"] = deco_web.snapshot(cfg["DECO_HOST"], cfg.get("DECO_WEBPW") or password,
                                                 gap=_float(cfg["WEB_READ_GAP"], 1.5), node_ttl=_float(cfg["WEB_NODE_MAP_TTL"], 21600),
                                                 probes=int(_float(cfg["WEB_NODE_PROBES"], 2)))
            report["source"] = "web"
            report["scheduled"] = scheduled
            report["web_login"] = deco_web.LAST.get("login")
            if not scheduled:
                report["full_error"] = tmp_down  # a full read was asked for and refused
            print(f"router_collect: web snapshot ({tmp_down}); login {report['web_login']}", file=sys.stderr)
            log["web_login"] = report["web_login"]
            if speed and speed["ok"]:
                report["reads"]["device_list_speed"] = speed  # mapped to nodes via the web device_list
        except Exception as exc:  # noqa: BLE001
            report["error"] = f"{tmp_down}; web fallback: {exc}"
            log["web_error"] = str(exc)
            print(f"router_collect: web fallback: {exc}", file=sys.stderr)

    if report["reads"]:
        try:
            written, total = router_history.record(report["reads"])
            report["history"] = {"rows_written": written, "rows_total": total}
        except Exception as exc:  # noqa: BLE001 - history is a nice-to-have; the snapshot still matters
            report["history"] = {"error": str(exc)}
            print(f"router_collect: history: {exc}", file=sys.stderr)

    # What changed since the last run (nodes, clients) -> "mesh" / "clients" logs. Before the merge
    # below, so only freshly read sections are compared.
    if report["reads"] and prev and prev.get("reads"):
        try:
            for stream, ev, fields in router_changes.changes(prev["reads"], report["reads"],
                                                           prev.get("source", "tmp") == report["source"]):
                lan_log.event(stream, ev, source=report["source"], **fields)
        except Exception as exc:  # noqa: BLE001 - a diff bug must not cost the snapshot
            print(f"router_collect: changes: {exc}", file=sys.stderr)

    failed = {k: v.get("error") for k, v in report["reads"].items() if not v.get("ok")}
    timed = sorted(((v["ms"], k) for k, v in report["reads"].items() if "ms" in v), reverse=True)
    nodes = router_changes.nodes(report["reads"])
    log.update(source=report["source"] if report["reads"] else None,
               reads_ok=sum(1 for v in report["reads"].values() if v.get("ok")), reads_failed=failed or None,
               slowest=[[k, ms] for ms, k in timed[:3]] or None,
               nodes_online=sum(1 for n in nodes.values() if n["online"]), nodes=len(nodes),
               clients_online=len(router_changes.clients(report["reads"])),
               history_rows=(report.get("history") or {}).get("rows_written"))

    # Carry the last full read's other sections (settings, DHCP, firmware, ...) under the fresh web
    # data. Speeds are not carried: an old rate shown as the current one would be wrong.
    if report["source"] == "web" and report["reads"] and prev and prev.get("reads"):
        for name, v in prev["reads"].items():
            if name not in report["reads"] and name not in NO_CARRY and v.get("ok"):
                report["reads"][name] = dict(v, stale=True)
        report["full_generated"] = prev.get("full_generated") or (prev.get("generated") if prev.get("source", "tmp") == "tmp" else None)

    if not report["reads"]:
        # Nothing read (router refused us, e.g. while a node reboots): keep the last good snapshot
        # so the pages don't go blank, and just record the failed attempt on it.
        if prev and prev.get("reads"):
            prev["error"] = report.get("error", "no reads")
            prev["error_at"] = datetime.datetime.now(datetime.timezone.utc).isoformat()
            report = prev
            log["kept_previous"] = True
    log["seconds"] = round(time.monotonic() - t_start, 1)
    lan_log.event("collect", "snapshot" if log.get("source") else "failed", **log)
    try:
        router_history.record_point("collect_seconds", log["mode"], log["seconds"])
    except Exception:  # noqa: BLE001
        pass
    tmp = OUT + ".tmp"
    with open(tmp, "w") as f:
        json.dump(report, f, indent=2)
    os.replace(tmp, OUT)
    return 0


def locked_main():
    """One collector at a time: a web snapshot that began before a full read finished would load the
    older router.json and then overwrite the full read with it."""
    lock_path = os.path.join(ROOT, "state", "router_collect.lock")
    os.makedirs(os.path.dirname(lock_path), exist_ok=True)
    with open(lock_path, "w") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)  # a full read takes ~45 s; systemd's timeout bounds a stuck one
        return main()


if __name__ == "__main__":
    sys.exit(locked_main())
