#!/usr/bin/env python3
"""
Serves web/ (the LAN inventory + router pages) and a small write API for the
router page, behind HTTP Basic Auth.

  router_web.py                 (bind/port from LAN_BIND/LAN_PORT, same as before)

Every request needs HTTP Basic Auth (ROUTER_WEB_USER/ROUTER_WEB_PASS from
router_config.py, default user/user -- CHANGE THIS, see router.env). This
covers the whole site, not just the router page, since the inventory page
also has no reason to be open to anyone who can reach the LAN.

Every request is logged (method, path, remote IP, authenticated user, status)
-- deliberately not a `pass`-stub like a tool that bit this project before.
"""
import base64
import http.server
import json
import os
import socketserver
import subprocess
import sys
import threading
import time
import urllib.parse

import deco_tmp
import lan_log
import ping_collect
import router_busy
import router_config
import router_history

ROOT = os.path.dirname(os.path.abspath(__file__))
WEB_DIR = os.path.join(ROOT, "web")

_connect_lock = threading.Lock()  # the router accepts one TMP session at a time
_refresh_lock = threading.Lock()  # one "Refresh now" snapshot at a time
_snapshot_lock = threading.Lock()  # router.json read-modify-write (write read-backs)
SNAPSHOT = os.path.join(WEB_DIR, "router.json")


def _save_readback(read_name, after):
    """Put a write's read-back into router.json, so the pages show it without another TMP read
    (full reads only happen on "Refresh now")."""
    with _snapshot_lock:
        try:
            with open(SNAPSHOT) as f:
                snap = json.load(f)
        except (OSError, ValueError):
            return
        snap.setdefault("reads", {})[read_name] = {"ok": True, "result": after,
                                                   "read_back_at": time.strftime("%Y-%m-%dT%H:%M:%S%z")}
        tmp = SNAPSHOT + ".tmp"
        with open(tmp, "w") as f:
            json.dump(snap, f, indent=2)
        os.replace(tmp, SNAPSHOT)
REDACTED = "***REDACTED***"


def _contains_redacted(obj) -> bool:
    if isinstance(obj, str):
        return REDACTED in obj
    if isinstance(obj, dict):
        return any(_contains_redacted(v) for v in obj.values())
    if isinstance(obj, list):
        return any(_contains_redacted(v) for v in obj)
    return False


def _deco_client(cfg):
    email, password = cfg["DECO_EMAIL"], cfg["DECO_ACCTPW"]
    return deco_tmp.DecoClient(cfg["DECO_HOST"], email, password)


class Handler(http.server.SimpleHTTPRequestHandler):
    def __init__(self, *a, **kw):
        super().__init__(*a, directory=WEB_DIR, **kw)

    # -- logging: print to stdout (captured by the systemd journal), always --
    def log_message(self, fmt, *args):
        sys.stdout.write("%s - %s - %s\n" % (self.client_address[0], self._auth_user or "-", fmt % args))
        sys.stdout.flush()

    # -- auth --------------------------------------------------------------
    _auth_user = None

    def _check_auth(self) -> bool:
        cfg = router_config.load()
        want_user, want_pass = cfg["ROUTER_WEB_USER"], cfg["ROUTER_WEB_PASS"]
        header = self.headers.get("Authorization", "")
        if not header.startswith("Basic "):
            return False
        try:
            raw = base64.b64decode(header[6:]).decode("utf-8", "replace")
            user, _, pw = raw.partition(":")
        except Exception:
            return False
        self._auth_user = user
        ok = bool(want_user) and bool(want_pass) and user == want_user and pw == want_pass
        if not ok:
            # a browser's first request carries no header (handled above); this is a wrong password
            lan_log.event("web", "login_failed", user=user, remote=self.client_address[0], path=self.path[:200])
        # Constant-time-ish is overkill for a LAN tool; correctness (not == "") is what
        # matters here -- the gateway's own "blank password always authenticates" bug
        # is exactly the mistake to not repeat.
        return ok

    def _require_auth(self):
        self.send_response(401)
        self.send_header("WWW-Authenticate", 'Basic realm="lan-inventory"')
        self.send_header("Content-Length", "0")
        self.end_headers()

    # -- routing -------------------------------------------------------------
    def do_GET(self):
        if not self._check_auth():
            return self._require_auth()
        if self.path.startswith("/api/read/"):
            return self._api_read(self.path[len("/api/read/"):])
        if self.path.startswith("/api/history"):
            return self._api_history()
        if self.path.startswith("/api/ping"):
            return self._api_ping()
        if self.path.startswith("/api/busy"):
            return self._send_json(200, dict(ok=True, **router_busy.status()))
        if self.path.startswith("/api/logs"):
            return self._api_logs()
        if self.path.startswith("/api/journal"):
            return self._api_journal()
        return super().do_GET()

    def do_HEAD(self):
        if not self._check_auth():
            return self._require_auth()
        return super().do_HEAD()

    def do_POST(self):
        if not self._check_auth():
            return self._require_auth()
        if self.path == "/api/write":
            return self._api_write()
        if self.path == "/api/refresh":
            return self._api_refresh()
        self.send_error(404)

    # -- JSON helpers --------------------------------------------------------
    def _send_json(self, status, obj):
        body = json.dumps(obj).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _read_json_body(self):
        length = int(self.headers.get("Content-Length", 0))
        if length <= 0 or length > 1_000_000:
            raise ValueError("missing or oversized body")
        return json.loads(self.rfile.read(length))

    # -- history (state/router_history.sqlite, written by router_collect.py) --
    def _api_history(self):
        q = urllib.parse.parse_qs(urllib.parse.urlparse(self.path).query)
        try:
            metric = q["metric"][0]
            key = q.get("key", [None])[0]
            since = min(int(q.get("since", ["86400"])[0]), router_history.RETENTION_DAYS * 86400)
            points = min(int(q.get("points", ["48"])[0]), 500)
        except (KeyError, ValueError) as exc:
            return self._send_json(400, {"ok": False, "error": f"bad query: {exc}"})
        try:
            self._send_json(200, {"ok": True, "series": router_history.series(metric, key, since, points)})
        except Exception as exc:  # noqa: BLE001
            self._send_json(500, {"ok": False, "error": str(exc)})

    # -- ping (state/ping_history.sqlite, written by ping_collect.py) ----------
    def _api_ping(self):
        q = urllib.parse.parse_qs(urllib.parse.urlparse(self.path).query)
        try:
            window = max(60, min(int(q.get("window", ["3600"])[0]), ping_collect.KEEP_HOURS * 3600))
        except ValueError:
            return self._send_json(400, {"ok": False, "error": "bad window"})
        try:
            self._send_json(200, dict(ok=True, **ping_collect.summary(window)))
        except Exception as exc:  # noqa: BLE001
            self._send_json(500, {"ok": False, "error": str(exc)})

    # -- logs (lan_log.py) and the systemd journal, for the Logs page ---------
    def _api_logs(self):
        q = urllib.parse.parse_qs(urllib.parse.urlparse(self.path).query)
        try:
            streams = [x for x in q.get("stream", [""])[0].split(",") if x] or None
            since = max(60, min(int(q.get("since", ["86400"])[0]), lan_log.KEEP_DAYS * 86400))
            limit = max(1, min(int(q.get("limit", ["500"])[0]), 5000))
        except ValueError as exc:
            return self._send_json(400, {"ok": False, "error": f"bad query: {exc}"})
        if streams and any(x not in lan_log.STREAMS for x in streams):
            return self._send_json(400, {"ok": False, "error": "unknown stream"})
        self._send_json(200, {"ok": True, "events": lan_log.read(streams, since, limit, q.get("q", [None])[0]),
                              "streams": list(lan_log.STREAMS), "stats": lan_log.stats()})

    JOURNAL_UNITS = ("lan-inventory", "lan-router", "lan-router-full", "lan-ping")

    def _api_journal(self):
        q = urllib.parse.parse_qs(urllib.parse.urlparse(self.path).query)
        unit = q.get("unit", [""])[0]
        units = [unit] if unit else list(self.JOURNAL_UNITS)
        if any(u not in self.JOURNAL_UNITS for u in units):
            return self._send_json(400, {"ok": False, "error": "unknown unit"})
        try:
            lines = max(1, min(int(q.get("lines", ["300"])[0]), 2000))
        except ValueError:
            return self._send_json(400, {"ok": False, "error": "bad lines"})
        cmd = ["journalctl", "--no-pager", "-q", "-o", "short-iso", "-n", str(lines)]
        for u in units:
            cmd += ["-u", u]
        if q.get("noise", ["0"])[0] != "1":
            # the site's own GETs are most of lan-inventory's journal; hide them unless asked
            cmd += ["--grep", '^(?!.*"(GET|HEAD) )']
        try:
            out = subprocess.run(cmd, capture_output=True, text=True, timeout=15)
        except (OSError, subprocess.TimeoutExpired) as exc:
            return self._send_json(500, {"ok": False, "error": str(exc)})
        # journalctl exits 1 when --grep matches nothing, and with --grep and -n prints newest first
        got = out.stdout.splitlines()
        if "--grep" in cmd:
            got.reverse()
        got.sort(key=lambda l: l[:25])  # ISO time prefix; stable, so same-second lines keep their order
        self._send_json(200, {"ok": True, "lines": got[-lines:],
                              "error": out.stderr.strip()[-300:] or None})

    def _send_busy(self, st):
        """503 while the router is applying a write (router_busy.py); the page shows a countdown bar."""
        body = json.dumps({"ok": False, "error": f"router is applying a change ({st['phase']})", "busy": st}).encode()
        self.send_response(503)
        self.send_header("Content-Type", "application/json")
        self.send_header("Retry-After", str(st.get("retry_after", 10)))
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    # -- "Refresh now": run one snapshot (router_collect.py) right away ------
    def _api_refresh(self):
        st = router_busy.status()
        if st["busy"]:
            return self._send_busy(st)
        if not _refresh_lock.acquire(blocking=False):
            return self._send_json(409, {"ok": False, "error": "a refresh is already running"})
        try:
            started = time.time()
            with _connect_lock:  # keep page writes off the router while the snapshot holds the session
                out = subprocess.run([sys.executable, os.path.join(ROOT, "router_collect.py")],
                                     capture_output=True, text=True, timeout=240,
                                     env=dict(os.environ, LAN_TRIGGER=f"refresh by {self._auth_user}"))
            ok = out.returncode == 0
            try:
                with open(SNAPSHOT) as f:
                    snap = json.load(f)
            except (OSError, ValueError):
                snap = {}
            # source "web" here means the full (TMP) read was refused and the web interface was used
            self._send_json(200 if ok else 500, {"ok": ok, "seconds": round(time.time() - started, 1),
                                                 "source": snap.get("source"), "full_error": snap.get("full_error"),
                                                 "error": None if ok else out.stderr.strip()[-500:]})
        except subprocess.TimeoutExpired:
            self._send_json(504, {"ok": False, "error": "snapshot took longer than 240 s"})
        finally:
            _refresh_lock.release()

    # -- live read (bypasses the periodic snapshot cache) --------------------
    def _api_read(self, name):
        cfg = router_config.load()
        try:
            with _connect_lock, _deco_client(cfg) as deco:
                result = deco.get(name)
            self._send_json(200, {"ok": True, "result": result})
        except router_busy.Busy as exc:
            self._send_busy(exc.status)
        except Exception as exc:  # noqa: BLE001
            self._send_json(500, {"ok": False, "error": str(exc)})

    # -- write -----------------------------------------------------------------
    def _api_write(self):
        try:
            body = self._read_json_body()
            name = body["name"]
            params = body["params"]
            allow_unverified = bool(body.get("allow_unverified", False))
        except Exception as exc:  # noqa: BLE001
            return self._send_json(400, {"ok": False, "error": f"bad request: {exc}"})
        # Reads come back redacted; a page that echoes a whole object back would
        # otherwise set a Wi-Fi/hotspot password to the literal placeholder.
        who = dict(via="web", user=self._auth_user, remote=self.client_address[0], allow_unverified=allow_unverified)
        if _contains_redacted(params):
            lan_log.write(name=name, params=params, ok=False, error="refused: redacted placeholder in params", **who)
            return self._send_json(400, {"ok": False, "error": "params contain a redacted placeholder (" + REDACTED +
                                         "); leave secret fields out of the write"})

        cfg = router_config.load()
        try:
            with _connect_lock, _deco_client(cfg) as deco:
                write_result = deco.set(name, params, confirm=True, allow_unverified=allow_unverified)
                # Read back whatever read name this write corresponds to, so the
                # caller sees the *actual* resulting state, not a trusted ACK.
                read_name = _read_name_for_write(name)
                after = deco.get(read_name) if read_name else None
            if read_name and after is not None:
                _save_readback(read_name, after)
            lan_log.write(name=name, params=params, ok=True, result=write_result, read_name=read_name, after=after, **who)
            self._send_json(200, {"ok": True, "write_result": write_result, "after": after,
                                  "busy": router_busy.status()})
        except router_busy.Busy as exc:
            lan_log.write(name=name, params=params, ok=False, error=f"refused: {exc}", **who)
            self._send_busy(exc.status)
        except Exception as exc:  # noqa: BLE001
            lan_log.write(name=name, params=params, ok=False, error=str(exc), **who)
            self._send_json(400 if isinstance(exc, (KeyError, deco_tmp.DecoError)) else 500,
                             {"ok": False, "error": str(exc), "busy": router_busy.status()})


def _read_name_for_write(write_name: str) -> str | None:
    for read_name, setting in deco_tmp.SETTINGS.items():
        if setting.write == write_name or setting.add == write_name or setting.modify == write_name or setting.remove == write_name:
            return read_name
    return None


class ThreadingServer(socketserver.ThreadingMixIn, http.server.HTTPServer):
    daemon_threads = True


def main():
    cfg = router_config.load()
    if router_config.using_default_web_password(cfg):
        sys.stderr.write(
            "\n"
            "*** router_web: using the DEFAULT login user/user. Anyone on your LAN who can\n"
            "*** reach this page can read and WRITE your router settings. Set ROUTER_WEB_USER\n"
            "*** and ROUTER_WEB_PASS in router.env before leaving this running. ***\n\n"
        )

    bind = os.environ.get("LAN_BIND", "0.0.0.0")
    port = int(os.environ.get("LAN_PORT", "8480"))
    server = ThreadingServer((bind, port), Handler)
    print(f"router_web: serving {WEB_DIR} on {bind}:{port} (Basic Auth user '{cfg['ROUTER_WEB_USER']}')")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
