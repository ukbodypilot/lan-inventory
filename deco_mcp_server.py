#!/usr/bin/env python3
"""
MCP server exposing the Deco TMP client (deco_tmp.py) as tools for Claude.

Register in Claude Code (project or user .mcp.json):
  {
    "mcpServers": {
      "deco-router": {
        "command": "/home/user/lan-inventory/venv/bin/python3",
        "args": ["/home/user/lan-inventory/deco_mcp_server.py"]
      }
    }
  }

Credentials come from router_config.load() -- same router.env this project's
web server and collector use (DECO_HOST/DECO_EMAIL/DECO_ACCTPW). Nothing is
hardcoded here.

Safety model mirrors deco_tmp.py: reads are always allowed and secrets are
redacted by default; writes marked "unverified" in deco_tmp.WRITE are refused
unless the caller explicitly passes allow_unverified=True, and every write
tool reads back the resulting state rather than trusting the router's ACK.

DECO_MCP_READONLY=1 (for unattended callers, e.g. the radio gateway's hourly check): no writes,
no unredacted read, no 30-read router_snapshot -- single redacted reads plus the two tools below.

network_summary and get_logs read only this project's files (web/router.json, logs/, the ping
DB), never the router, so a diagnosis can use them freely without loading port 20001.
"""
from __future__ import annotations

import contextlib
import datetime
import json
import os
import socket
import time
from typing import Any

from mcp.server.mcpserver import MCPServer
from mcp.server.mcpserver.exceptions import ToolError

import deco_tmp
import lan_log
import ping_collect
import router_busy
import router_changes
import router_config

ROOT = os.path.dirname(os.path.abspath(__file__))
READONLY = os.environ.get("DECO_MCP_READONLY", "").lower() in ("1", "true", "yes")

_DIAG = (
    "For diagnosis (a stream stall, slow or dropped connections), start with network_summary and "
    "get_logs: they read what lan-inventory already recorded (mesh and client changes, ping outages "
    "and route changes, the control port going down, router snapshots) and never touch the router. "
    "Live reads with get_router_data each log in to the router's control port, which has closed for "
    "45+ min after too many connections; use them only for something the summary and logs can't answer."
)
server = MCPServer(
    name="deco-router",
    instructions=(
        "Read-only view of a TP-Link Deco mesh (local, no cloud). " + _DIAG if READONLY else
        "Local control of a TP-Link Deco mesh over its native TMP protocol (no cloud, "
        "no app needed). Reads are always safe. Writes: list_writes marks each one verified (proven "
        "live to change state) or not -- an unverified write may ACK and silently do nothing (this "
        "happened with HomeShield's protection toggle), or do something other than what the field "
        "names suggest. Always read the `after` value returned by a write and tell the user what it "
        "actually shows, not just whether the call succeeded. Every write locks the router for "
        "~60-90 s. " + _DIAG
    ),
)


def _full(fn):
    """Register fn as a tool unless this server runs read-only."""
    return fn if READONLY else server.tool()(fn)


def _client() -> deco_tmp.DecoClient:
    cfg = router_config.load()
    return deco_tmp.DecoClient(cfg["DECO_HOST"], cfg["DECO_EMAIL"], cfg["DECO_ACCTPW"])


@contextlib.contextmanager
def _router():
    """A connected client, with the post-write lockout honoured and failures passed to the model as
    ToolError: any other exception reaches it only as "Error executing tool ..." (MCP SDK v2), so it
    could never learn that a write needs allow_unverified or that the router is busy."""
    try:
        router_busy.check()
        with _client() as deco:
            yield deco
    except ToolError:
        raise
    except Exception as exc:  # noqa: BLE001 - router, network and refusal errors all go to the caller
        raise ToolError(f"{type(exc).__name__}: {exc}") from exc


def _known_read(name: str) -> None:
    if name not in deco_tmp.READ:
        raise ToolError(f"unknown read '{name}'; call list_reads for valid names")


@server.tool()
def list_reads() -> list[str]:
    """List every read-only opcode name this router exposes (client list, Wi-Fi config,
    QoS, port forwarding, DHCP, VPN config, firmware, etc). Use get_router_data to read one."""
    return sorted(deco_tmp.READ)


@server.tool()
def get_router_data(name: str) -> Any:
    """Read one named value from the Deco (see list_reads for valid names). Secrets (VPN
    private keys, Wi-Fi passwords) are redacted unless you pass reveal_secrets via
    get_router_data_unredacted -- ask the user before using that."""
    _known_read(name)
    with _router() as deco:
        return deco.get(name)


@_full
def get_router_data_unredacted(name: str) -> Any:
    """Like get_router_data but includes secrets (e.g. vpn_config's WireGuard private key).
    Only use this when the user specifically needs the secret value, and don't print it
    into a log or file without asking first."""
    _known_read(name)
    with _router() as deco:
        return deco.get(name, reveal_secrets=True)


@_full
def router_snapshot() -> dict:
    """Read every known opcode in one pass (same thing the periodic collector does).
    Slower than get_router_data for a single value; useful when you need a broad look."""
    with _router() as deco:
        return deco.snapshot()


@_full
def list_writes() -> list[dict]:
    """List every write this server can attempt, with its verified/unverified status and
    a note on what's actually known about it. Verified writes have been proven live with a
    before/after read-back; unverified ones are inferred from the opcode-numbering pattern
    and nobody has confirmed what they do."""
    return [
        {"name": name, "opcode": hex(op.code), "verified": op.verified, "note": op.note}
        for name, op in sorted(deco_tmp.WRITE.items())
    ]


@_full
def write_router_setting(name: str, params: dict, allow_unverified: bool = False) -> dict:
    """Write a setting on the Deco (see list_writes for valid names and their verified
    status). Refuses unverified writes unless allow_unverified=True -- check with the user
    before setting that, since an unverified write may silently no-op or do something
    unexpected. Always returns the read-back state after the write (`after`), not just
    whether the router accepted the call; report that value to the user, not just success."""
    if name not in deco_tmp.WRITE:
        raise ToolError(f"unknown write '{name}'; call list_writes for valid names")
    op = deco_tmp.WRITE[name]
    if not op.verified and not allow_unverified:
        # refused before connecting; deco.set() would refuse too, but only after a login
        msg = f"write '{name}' is UNVERIFIED ({op.note}); ask the user, then pass allow_unverified=True to try it anyway"
        lan_log.write("mcp", name, params, False, error=msg)
        raise ToolError(msg)
    read_name = next(
        (r for r, s in deco_tmp.SETTINGS.items()
         if s.write == name or s.add == name or s.modify == name or s.remove == name),
        None,
    )
    try:
        with _router() as deco:
            write_result = deco.set(name, params, confirm=True, allow_unverified=allow_unverified)
            try:
                after = deco.get(read_name) if read_name else None
            except Exception as exc:  # noqa: BLE001 - the write went through; say so, not "failed"
                after = {"read_back_error": f"{type(exc).__name__}: {exc}"}
    except ToolError as exc:
        lan_log.write("mcp", name, params, False, allow_unverified=allow_unverified, error=str(exc))
        raise
    lan_log.write("mcp", name, params, True, allow_unverified=allow_unverified, result=write_result,
                  read_name=read_name, after=after)
    return {"write_result": write_result, "after": after,
            "note": "The router now refuses new connections for ~60-90 s while it applies this; "
                    "further reads/writes fail with 'router is applying a change' until it is back."}



def _when(t):
    return time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(t)) if t else None


def _own_ips() -> set[str]:
    ips = set()
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.connect((router_config.load()["DECO_HOST"], 80))  # UDP: no packet sent, just picks the route
            ips.add(s.getsockname()[0])
    except OSError:
        pass
    return ips


def _load_json(*parts):
    try:
        with open(os.path.join(ROOT, *parts)) as f:
            return json.load(f)
    except (OSError, ValueError):
        return None


@server.tool()
def network_summary(minutes: int = 60) -> dict:
    """Network health over the last `minutes` (max 1440), from what lan-inventory already recorded --
    no router contact. Mesh nodes (offline ones, wireless backhaul and its signal 0-3), WAN address,
    where THIS machine is connected (node, band, signal), end-to-end ping loss and per-hop latency to
    the ping target, whether the router's control port is up or locked after a write, and the notable
    events in the window (node/client changes, ping outages, route changes, port down)."""
    minutes = max(1, min(int(minutes), 1440))
    now = time.time()
    out: dict[str, Any] = {"window_minutes": minutes, "now": _when(now)}

    snap = _load_json("web", "router.json") or {}
    reads = snap.get("reads") or {}
    gen = snap.get("generated")
    try:
        age = round(now - datetime.datetime.fromisoformat(gen).timestamp()) if gen else None
    except ValueError:
        age = None
    out["snapshot"] = {"taken": gen, "age_s": age, "source": snap.get("source"),
                       "last_full_read": snap.get("full_generated"), "error": snap.get("error")}
    nodes = router_changes.nodes(reads)
    names = {m: n["name"] for m, n in nodes.items()}
    out["mesh"] = {
        "online": sum(n["online"] for n in nodes.values()), "total": len(nodes),
        "offline": [n["name"] for n in nodes.values() if not n["online"]],
        "wireless_backhaul": [{"node": n["name"], "upstream": names.get(n["upstream"]), "signal": n["signal"]}
                              for n in nodes.values() if n["online"] and n["backhaul"] == "wireless"],
    }
    wan = ((reads.get("wan_lan_status") or {}).get("result") or {}).get("wan") or {}
    out["wan"] = {k: (wan.get("ip_info") or {}).get(k) for k in ("ip", "gateway")}
    ips = _own_ips()
    me = [dict(c, mac=m, node=names.get(c["node"], c["node"])) for m, c in router_changes.clients(reads).items()
          if c.get("ip") in ips]
    out["this_host"] = me[0] if me else {"ips": sorted(ips), "note": "not in the router's client list"}

    port = _load_json("state", "tmp_port.json") or {}
    busy = router_busy.status()
    out["control_port"] = {"up": port.get("up"), "since": _when(port.get("since")),
                           "locked_after_write": busy["write"] if busy["busy"] else None}

    try:
        p = ping_collect.summary(minutes * 60)
        hops = p.get("hops") or []
        last = hops[-1] if hops else {}
        out["ping"] = {"target": p.get("target"), "rounds": p.get("rounds"),
                       "end_to_end_loss_pct": last.get("loss"), "avg_ms": last.get("avg"), "max_ms": last.get("max"),
                       "hops": [{k: h.get(k) for k in ("hop", "ip", "name", "loss", "avg", "max")} for h in hops],
                       "note": "Judge loss by end_to_end_loss_pct. High loss at a middle hop with little at the "
                               "end is that router rate-limiting replies to probes aimed at it, not lost traffic."}
    except Exception as exc:  # noqa: BLE001
        out["ping"] = {"error": str(exc)}

    evs = lan_log.read(("mesh", "tmp", "ping", "busy", "writes", "clients"), since=minutes * 60, limit=2000)
    mine = {c["mac"] for c in me}
    counts: dict[str, int] = {}
    notable = []
    for e in evs:
        key = f"{e['stream']}.{e['ev']}"
        counts[key] = counts.get(key, 0) + 1
        if e["stream"] != "clients" or e.get("mac") in mine:  # other clients' comings and goings are noise here
            notable.append({k: v for k, v in e.items() if k not in ("t", "stream")} | {"stream": e["stream"]})
    out["events"] = {"counts": counts, "notable": notable[:40]}
    snaps = lan_log.read(("collect",), since=minutes * 60, limit=500)
    out["snapshots"] = {"count": len(snaps), "failed": sum(1 for e in snaps if e["ev"] == "failed"),
                        "slowest_s": max((e.get("seconds") or 0 for e in snaps), default=None)}
    return out


@server.tool()
def get_logs(streams: list[str] | None = None, minutes: int = 60, contains: str | None = None,
             limit: int = 100) -> list[dict]:
    """Events lan-inventory logged, newest first -- no router contact. streams: any of
    collect (each router snapshot: source, failed reads, timings), writes, busy (post-write lockouts),
    tmp (control port up/down), mesh (node online/offline/upstream/backhaul/signal/IP changes),
    clients (joined/left/roamed/band), ping (outage_start/outage_end/route_change/mtr_failed),
    web (failed logins); all if omitted. minutes: how far back (max 43200 = 30 days, the retention).
    contains: case-insensitive text filter, e.g. a MAC or a node name."""
    bad = [x for x in streams or [] if x not in lan_log.STREAMS]
    if bad:
        raise ToolError(f"unknown stream(s) {bad}; valid: {list(lan_log.STREAMS)}")
    return lan_log.read(streams or None, since=max(1, min(int(minutes), 43200)) * 60,
                        limit=max(1, min(int(limit), 1000)), q=contains)


def main() -> None:
    server.run(transport="stdio")


if __name__ == "__main__":
    main()
