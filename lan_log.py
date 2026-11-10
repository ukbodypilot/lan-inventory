"""Event logs for diagnosis: one JSON line per event, one file per stream per day, 30 days kept.

  logs/<stream>-YYYY-MM-DD.jsonl     {"ts": "2026-10-25T18:40:02-07:00", "t": 1792978802.1, "ev": "...", ...}

Streams written today:
  collect   one line per router snapshot (mode, source, per-read failures, slowest reads, timings)
  writes    every router write and refused write (who, what, params with secrets scrubbed, ACK, read-back)
  busy      post-write lockout: when it started, how long port 20001 was closed, outcome
  tmp       control port 20001 going down / coming back (probed once per 5-min run)
  mesh      node joined/left, upstream / backhaul / signal / IP / name changes
  clients   client joined, left, moved node (roamed), changed band
  ping      outages to the ping target, route changes, mtr failures
  web       failed logins to this site

Where: LAN_LOG_DIR, else logs/ next to this file. On the reference box logs/ is a tmpfs (RAM),
flushed to disk by the host's daily ram-writeback-flush and on shutdown, so a crash loses at most a
day of these and the SSD sees one copy a day instead of an append every few seconds.

Logging never raises: a full disk or a missing directory must not stop a snapshot or a write.
"""
import datetime
import json
import os
import re
import sys
import time

ROOT = os.path.dirname(os.path.abspath(__file__))
LOG_DIR = os.environ.get("LAN_LOG_DIR") or os.path.join(ROOT, "logs")
KEEP_DAYS = 30
STREAMS = ("collect", "writes", "busy", "tmp", "mesh", "clients", "devices", "ping", "web")
_FILE = re.compile(r"^([a-z]+)-(\d{4}-\d{2}-\d{2})\.jsonl$")
_SECRET = re.compile(r"pass|psk|secret|private|token|key$", re.I)
_last_prune = 0.0


def scrub(obj):
    """Copy of obj with values of secret-looking keys (password, psk, private_key, ...) replaced."""
    if isinstance(obj, dict):
        return {k: ("***" if isinstance(k, str) and _SECRET.search(k) and v not in (None, "") else scrub(v))
                for k, v in obj.items()}
    if isinstance(obj, list):
        return [scrub(v) for v in obj]
    return obj


def event(stream, ev, **fields):
    """Append one event. Returns the record (or None if it could not be written)."""
    now = time.time()
    rec = {"ts": datetime.datetime.fromtimestamp(now).astimezone().isoformat(timespec="seconds"),
           "t": round(now, 3), "ev": ev}
    rec.update(fields)
    path = os.path.join(LOG_DIR, f"{stream}-{time.strftime('%Y-%m-%d', time.localtime(now))}.jsonl")
    try:
        os.makedirs(LOG_DIR, exist_ok=True)
        line = json.dumps(rec, default=str, separators=(",", ":")) + "\n"
        # one write() on an O_APPEND fd: lines from different processes don't interleave
        fd = os.open(path, os.O_WRONLY | os.O_APPEND | os.O_CREAT, 0o644)
        try:
            os.write(fd, line.encode())
        finally:
            os.close(fd)
        _maybe_prune(now)
        return rec
    except OSError as exc:
        print(f"lan_log: {stream}: {exc}", file=sys.stderr)
        return None


def write(via, name, params, ok, *, user=None, remote=None, allow_unverified=False, result=None,
          error=None, read_name=None, after=None):
    """One router write (or refused write) -> "writes". Params and read-back are scrubbed of secrets;
    a long read-back is cut to 4000 characters of JSON."""
    after_s = None
    if after is not None:
        after_s = json.dumps(scrub(after), default=str, separators=(",", ":"))
        if len(after_s) > 4000:
            after_s = after_s[:4000] + "...(cut)"
    return event("writes", "write" if ok else "write_failed", via=via, user=user, remote=remote, name=name,
                 params=scrub(params), allow_unverified=allow_unverified or None, result=scrub(result),
                 error=error, read_back=read_name, after=after_s)


def _maybe_prune(now):
    global _last_prune
    if now - _last_prune < 3600:
        return
    _last_prune = now
    prune(now)


def prune(now=None):
    """Delete day files older than KEEP_DAYS. Returns how many were removed."""
    cutoff = datetime.date.fromtimestamp(now or time.time()) - datetime.timedelta(days=KEEP_DAYS)
    removed = 0
    for name, _stream, day in _files():
        if day < cutoff:
            try:
                os.remove(os.path.join(LOG_DIR, name))
                removed += 1
            except OSError:
                pass
    return removed


def _files():
    try:
        names = os.listdir(LOG_DIR)
    except OSError:
        return []
    out = []
    for n in names:
        m = _FILE.match(n)
        if m:
            try:
                out.append((n, m.group(1), datetime.date.fromisoformat(m.group(2))))
            except ValueError:
                pass
    return sorted(out, key=lambda f: f[2])


def read(streams=None, since=86400, limit=500, q=None):
    """Newest-first events from the given streams (all if None) in the last `since` seconds,
    optionally only those whose JSON contains `q` (case-insensitive)."""
    start = time.time() - since
    first_day = datetime.date.fromtimestamp(start)
    want = set(streams) if streams else None
    ql = q.lower() if q else None
    out = []
    for name, stream, day in reversed(_files()):
        if day < first_day:
            break
        if want and stream not in want:
            continue
        try:
            with open(os.path.join(LOG_DIR, name), errors="replace") as f:
                lines = f.readlines()
        except OSError:
            continue
        for line in lines:
            if ql and ql not in line.lower():
                continue
            try:
                rec = json.loads(line)
            except ValueError:
                continue
            if rec.get("t", 0) >= start:
                rec["stream"] = stream
                out.append(rec)
    out.sort(key=lambda r: r.get("t", 0), reverse=True)
    return out[:limit]


def stats():
    """Per-stream file count, bytes and oldest day, for the Logs page footer."""
    by = {}
    for name, stream, day in _files():
        s = by.setdefault(stream, {"files": 0, "bytes": 0, "oldest": day.isoformat()})
        s["files"] += 1
        try:
            s["bytes"] += os.path.getsize(os.path.join(LOG_DIR, name))
        except OSError:
            pass
    return {"dir": LOG_DIR, "keep_days": KEEP_DAYS, "streams": by}


if __name__ == "__main__":
    # lan_log.py [stream ...]   print the last day's events, oldest first
    for r in reversed(read(sys.argv[1:] or None, limit=10000)):
        print(json.dumps(r, separators=(",", ":")))
