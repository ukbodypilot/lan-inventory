"""Find out what else the Deco's admin web page (:80) can read, for when TMP (port 20001) is gone.

Background: after the Deco firmware update to 1.11.1 (2026-11-18) port 20001 refused every connection,
so everything only TMP carried (per-client signal, reservations, DHCP leases, port forwarding, ...)
froze. The web interface the admin page uses is a LuCI-style API (`admin/<module>?form=<form>`,
see deco_web.py); this script maps it out without guessing paths at the router.

  deco_web_discover.py ui      fetch the admin page and the scripts it loads (unauthenticated static
                               files, paced), extract every admin/...?form=... the UI calls
                               -> state/deco_web_ui_endpoints.json
  deco_web_discover.py probe   send ONE "read" to each endpoint found, over the saved web session
                               (the 5-minute collector's; no extra login when it is still valid),
                               PROBE_GAP s apart, under the collector's lock; stops after
                               MAX_FAILS_IN_A_ROW consecutive transport failures (timeouts, HTTP 5xx)
                               -> state/deco_web_catalog.json (secrets redacted)
  deco_web_discover.py show    summarise the catalog (no router contact)

Both router steps are meant to be run by hand, once, when the router is idle and settled.
"""
import fcntl
import json
import os
import re
import sys
import time
import urllib.parse
import urllib.request

import deco_web
import router_config

ROOT = os.path.dirname(os.path.abspath(__file__))
UI_OUT = os.path.join(ROOT, "state", "deco_web_ui_endpoints.json")
CATALOG = os.path.join(ROOT, "state", "deco_web_catalog.json")
LOCK = os.path.join(ROOT, "state", "router_collect.lock")

UI_GAP = 1.0            # s between static file fetches
UI_MAX_FILES = 60
PROBE_GAP = 5.0         # s between probe reads
MAX_FAILS_IN_A_ROW = 2
# never "read" these even if the UI names them: they act rather than report, or end our session
# matched as whole "_"-separated words of the form name, so "dhcp_setting" stays readable but "lan_set" does not
SKIP_FORMS = re.compile(r"(^|_)(logout|reboot|reset|restore|upgrade|upload|factory|backup|login|keys|auth|password|"
                        r"bind|unbind|remove|delete|del|add|set|apply|save|scan|start|stop|test|speedtest|"
                        r"optimize|block|unblock|led_set)($|_)", re.I)
SECRET_KEYS = re.compile(r"pass|psk|(^|_)key($|_)|secret|token|pwd|(^|_)pin($|_)|cookie|stok|sysauth", re.I)

ENDPOINT_RE = re.compile(r"(admin/[A-Za-z0-9_]+\?form=[A-Za-z0-9_]+)")
SCRIPT_RE = re.compile(r"""(?:src|href)\s*=\s*["']([^"']+\.js)(?:\?[^"']*)?["']|["']([^"'\s]+\.js)["']""")


# ------------------------------------------------------------------ pure helpers (unit-tested)
def extract_endpoints(text):
    """admin/<module>?form=<form> strings named anywhere in a page or script, sorted, unique."""
    return sorted(set(ENDPOINT_RE.findall(text)))


def extract_scripts(text, base_url):
    """Absolute URLs of the .js files a page or script refers to, same host only."""
    host = urllib.parse.urlparse(base_url).netloc
    out = []
    for a, b in SCRIPT_RE.findall(text):
        u = urllib.parse.urljoin(base_url, a or b)
        if urllib.parse.urlparse(u).netloc == host and u not in out:
            out.append(u)
    return out


def probe_worthy(endpoint):
    form = endpoint.split("form=", 1)[1]
    return not SKIP_FORMS.search(form)


def redact(obj):
    """Copy of obj with any value under a secret-looking key replaced (keeps the shape for mapping work)."""
    if isinstance(obj, dict):
        return {k: ("<redacted>" if SECRET_KEYS.search(str(k)) and not isinstance(v, (dict, list)) else redact(v))
                for k, v in obj.items()}
    if isinstance(obj, list):
        return [redact(v) for v in obj]
    return obj


def shape(obj, depth=0):
    """Short description of a result: keys and list lengths, for the summary."""
    if isinstance(obj, dict):
        return "{" + ", ".join(sorted(obj))[:300] + "}"
    if isinstance(obj, list):
        return f"[{len(obj)}] " + (shape(obj[0], depth + 1) if obj and depth < 1 else "")
    return type(obj).__name__


# ------------------------------------------------------------------ router steps
def _get(url, timeout=10):
    req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return r.geturl(), r.read().decode("utf-8", "ignore")


def ui(host):
    start = f"http://{host}/"
    queue, seen, endpoints, files = [start], set(), {}, []
    while queue and len(seen) < UI_MAX_FILES:
        url = queue.pop(0)
        if url in seen:
            continue
        seen.add(url)
        if len(seen) > 1:
            time.sleep(UI_GAP)
        try:
            final, text = _get(url)
        except OSError as exc:
            files.append({"url": url, "error": str(exc)})
            continue
        found = extract_endpoints(text)
        files.append({"url": final, "bytes": len(text), "endpoints": len(found)})
        for e in found:
            endpoints.setdefault(e, url)
        queue += [u for u in extract_scripts(text, final) if u not in seen]
        # the landing page may be a redirect stub pointing at the real UI page
        for m in re.findall(r"""location(?:\.href)?\s*=\s*["']([^"']+)["']|url=([^"'>\s]+)""", text):
            u = urllib.parse.urljoin(final, m[0] or m[1])
            if urllib.parse.urlparse(u).netloc == host and u not in seen:
                queue.append(u)
    out = {"at": time.time(), "files": files, "endpoints": endpoints}
    _save(UI_OUT, out)
    print(f"{len(files)} files, {len(endpoints)} endpoints -> {UI_OUT}")
    return out


def probe(host, password, only=None):
    try:
        with open(UI_OUT) as f:
            endpoints = sorted(json.load(f)["endpoints"])
    except (OSError, ValueError, KeyError):
        sys.exit("run `deco_web_discover.py ui` first")
    todo = [e for e in endpoints if probe_worthy(e) and (not only or re.search(only, e))]
    skipped = [e for e in endpoints if not probe_worthy(e)]
    try:
        with open(CATALOG) as f:
            catalog = json.load(f)
    except (OSError, ValueError):
        catalog = {"reads": {}}
    print(f"{len(todo)} to read, {len(skipped)} skipped as non-reads; {PROBE_GAP:.0f} s apart (~{len(todo) * PROBE_GAP / 60:.0f} min)")
    fails = 0
    with open(LOCK, "w") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)  # never interleave with the collector: both use the saved session
        with deco_web.session(host, password) as web:
            print("session:", deco_web.LAST.get("login"))
            for i, e in enumerate(todo):
                if i:
                    time.sleep(PROBE_GAP)
                t0 = time.monotonic()
                try:
                    res = web.read(e)
                    entry = {"ok": True, "shape": shape(res), "result": redact(res)}
                    fails = 0
                except deco_web.SessionExpired as exc:
                    # deco_web treats any unencrypted error reply as a dropped session; an unknown form can
                    # answer that way too, so check the session with the collector's own cheap read
                    time.sleep(PROBE_GAP)
                    try:
                        web.performance()
                    except deco_web.DecoWebError:
                        print("session really dropped, stopping:", exc)
                        catalog["reads"][e] = {"ok": False, "error": str(exc), "at": time.time()}
                        break
                    entry = {"ok": False, "error": str(exc)[:300], "transport": False, "session_ok_after": True}
                    fails = 0
                except deco_web.DecoWebError as exc:
                    msg = str(exc)
                    transport = "error_code" not in msg  # error_code = router answered "no"; else timeout/HTTP
                    entry = {"ok": False, "error": msg[:300], "transport": transport}
                    fails = fails + 1 if transport else 0
                entry.update(at=time.time(), ms=round((time.monotonic() - t0) * 1000))
                catalog["reads"][e] = entry
                print(f"{'ok ' if entry['ok'] else 'ERR'} {entry['ms']:>6} ms  {e}  {entry.get('shape') or entry.get('error', '')[:100]}")
                _save(CATALOG, catalog)
                if fails >= MAX_FAILS_IN_A_ROW:
                    print(f"{fails} transport failures in a row, stopping so the router can rest")
                    break
    catalog["skipped"] = skipped
    _save(CATALOG, catalog)


def show():
    with open(CATALOG) as f:
        cat = json.load(f)
    for e, v in sorted(cat["reads"].items()):
        print(f"{'ok ' if v['ok'] else 'ERR'} {e:50} {v.get('shape') or v.get('error', '')[:120]}")


def _save(path, obj):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    tmp = path + ".tmp"
    with open(os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600), "w") as f:
        json.dump(obj, f, indent=1)
    os.replace(tmp, path)


if __name__ == "__main__":
    cmd = sys.argv[1] if len(sys.argv) > 1 else ""
    cfg = router_config.load()
    if cmd == "ui":
        ui(cfg["DECO_HOST"])
    elif cmd == "probe":
        probe(cfg["DECO_HOST"], cfg.get("DECO_WEBPW") or cfg["DECO_ACCTPW"], sys.argv[2] if len(sys.argv) > 2 else None)
    elif cmd == "show":
        show()
    else:
        sys.exit(__doc__)
