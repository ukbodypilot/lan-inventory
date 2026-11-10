"""Post-write lockout for the Deco's TMP port, shared by every process that talks to the router.

Measured 2026-10-25 on the X55 (led_set, probing every 5 s): the write ACKs and reads back fine
within ~3 s, then port 20001 refuses connections from ~8-14 s to ~64-88 s after the write while the
router applies the config. Probing it every 0.5 s keeps it closed longer (connection rate limiting),
so the watcher here probes gently.

  begin(write_name)   called after a write ACKs; starts the watcher thread in this process
  status()            {"busy": bool, "phase", "since", "elapsed", "expected", "retry_after", "write"}
  check()             raises Busy while locked (callers turn it into a 503 / a skipped run)

State lives in state/router_busy.json so router_web.py, router_collect.py (timer) and
deco_mcp_server.py all see the same lock. A dead watcher can't wedge it: every state carries a
hard deadline after which it's ignored.
"""
import json
import os
import socket
import subprocess
import sys
import threading
import time

import lan_log

ROOT = os.path.dirname(os.path.abspath(__file__))
STATE = os.path.join(ROOT, "state", "router_busy.json")
PORT = 20001
PROBE_EVERY = 5          # s; faster probing extends the outage
EXPECTED = 90            # s; typical full outage, for the progress bar
NEVER_CLOSED_AFTER = 25  # s; port never went down -> assume the write didn't need a restart
HARD_CAP = 150           # s; give up waiting regardless
_lock = threading.Lock()


class Busy(RuntimeError):
    def __init__(self, st):
        super().__init__(f"router is applying a change ({st['phase']}); try again in {st['retry_after']} s")
        self.status = st


def _write(st):
    os.makedirs(os.path.dirname(STATE), exist_ok=True)
    tmp = STATE + ".tmp"
    with open(tmp, "w") as f:
        json.dump(st, f)
    os.replace(tmp, STATE)


def status():
    now = time.time()
    try:
        with open(STATE) as f:
            st = json.load(f)
    except (OSError, ValueError):
        st = {}
    busy = bool(st.get("busy")) and now < st.get("deadline", 0)
    out = {"busy": busy, "phase": st.get("phase", "idle") if busy else "idle", "write": st.get("write"),
           "since": st.get("since"), "expected": EXPECTED, "last": st.get("last")}
    if busy:
        out["elapsed"] = round(now - st["since"], 1)
        out["retry_after"] = max(PROBE_EVERY, int(EXPECTED - out["elapsed"]))
    return out


def check():
    st = status()
    if st["busy"]:
        raise Busy(st)


def port_open(host):
    s = socket.socket()
    s.settimeout(2)
    try:
        s.connect((host, PORT))
        return True
    except OSError:
        return False
    finally:
        s.close()


def begin(write_name, host="192.168.2.1", resnapshot=True):
    """Lock now and watch the port in a background thread until the router is back."""
    since = time.time()
    with _lock:
        _write({"busy": True, "phase": "applying", "write": write_name, "since": since, "deadline": since + HARD_CAP})
    lan_log.event("busy", "lock", write=write_name)
    threading.Thread(target=_watch, args=(write_name, host, since, resnapshot), daemon=True).start()


def _watch(write_name, host, since, resnapshot):
    went_down = False
    down_at = None
    outcome = "timeout"
    while time.time() - since < HARD_CAP:
        time.sleep(PROBE_EVERY)
        up = port_open(host)
        elapsed = time.time() - since
        if not up and not went_down:
            went_down = True
            down_at = round(elapsed, 1)
            with _lock:
                _write({"busy": True, "phase": "restarting", "write": write_name, "since": since,
                        "deadline": since + HARD_CAP, "down_at": round(elapsed, 1)})
        elif up and went_down:
            time.sleep(PROBE_EVERY)  # one more probe so a brief flap doesn't release the lock
            if port_open(host):
                outcome = "back"
                break
        elif up and elapsed > NEVER_CLOSED_AFTER:
            outcome = "never_closed"
            break
    took = round(time.time() - since, 1)
    with _lock:
        _write({"busy": False, "phase": "idle", "write": write_name, "since": since, "deadline": 0,
                "last": {"write": write_name, "outcome": outcome, "seconds": took, "at": time.time()}})
    print(f"router_busy: {write_name}: {outcome} after {took}s", flush=True)
    # down_at: s after the ACK that port 20001 closed; seconds: until it was back (or the cap)
    lan_log.event("busy", "release", write=write_name, outcome=outcome, seconds=took, down_at=down_at,
                  closed_s=round(took - down_at, 1) if down_at is not None and outcome == "back" else None)
    if resnapshot:
        # web-only: the write's own read-back already updated its setting in router.json
        # (router_web.py), and TMP is only read when someone asks for it
        subprocess.run([sys.executable, os.path.join(ROOT, "router_collect.py"), "--web-only"], capture_output=True, timeout=120)
