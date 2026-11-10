"""Deco router credentials and web-UI login, loaded the same way alerts.env works (see notify.py).

Credentials come from, in order:
  1. the environment: DECO_HOST, DECO_EMAIL, DECO_ACCTPW, ROUTER_WEB_USER, ROUTER_WEB_PASS
  2. ./router.env next to this file (KEY=VALUE, git-ignored, mode 600)

PING_TARGET/PING_INTERVAL (default 8.8.8.8 / 2 s) drive ping_collect.py; it re-reads them every
round, so editing router.env retargets the Ping page without a restart.

ROUTER_WEB_USER/ROUTER_WEB_PASS gate the HTTP Basic Auth on the router page and its write API.
If unset anywhere, they default to user/user -- change this in router.env before exposing the
page beyond localhost. router_web.py prints a loud warning on startup while the default is live.
"""
import os
import re

ROOT = os.path.dirname(os.path.abspath(__file__))
KEYS = ("DECO_HOST", "DECO_EMAIL", "DECO_ACCTPW", "ROUTER_WEB_USER", "ROUTER_WEB_PASS",
        "PING_TARGET", "PING_INTERVAL", "DECO_WEBPW", "TMP_READ_GAP", "TMP_SPEED_READS", "WEB_READ_GAP", "WEB_NODE_MAP_TTL", "WEB_NODE_PROBES", "PING_DB",
        "HISTORY_DB")
DEFAULT_WEB_USER = "user"
DEFAULT_WEB_PASS = "user"


def _parse(path):
    out = {}
    try:
        for line in open(path, errors="replace"):
            m = re.match(r"^\s*([A-Z_]+)\s*=\s*(.*)$", line)
            if not m:
                continue
            k, v = m.group(1), m.group(2).strip()
            if k not in KEYS:
                continue
            v = v.split(" #", 1)[0].rstrip()
            if len(v) >= 2 and v[0] == v[-1] and v[0] in "\"'":
                v = v[1:-1]
            out[k] = v
    except OSError:
        pass
    return out


def load():
    cfg = _parse(os.path.join(ROOT, "router.env"))
    for k in KEYS:
        if os.environ.get(k):
            cfg[k] = os.environ[k]
    cfg.setdefault("DECO_HOST", "192.168.2.1")
    cfg.setdefault("ROUTER_WEB_USER", DEFAULT_WEB_USER)
    cfg.setdefault("ROUTER_WEB_PASS", DEFAULT_WEB_PASS)
    cfg.setdefault("PING_TARGET", "8.8.8.8")
    cfg.setdefault("PING_INTERVAL", "2")
    cfg.setdefault("TMP_READ_GAP", "1")  # seconds between reads in a full TMP snapshot
    cfg.setdefault("TMP_SPEED_READS", "1")  # 0 = no node-speed read on the 5-min web runs
    cfg.setdefault("WEB_READ_GAP", "1.5")  # seconds between requests in a web (:80) snapshot
    cfg.setdefault("WEB_NODE_MAP_TTL", "21600")  # seconds before the whole client->node map is rebuilt (one request per node)
    cfg.setdefault("WEB_NODE_PROBES", "2")  # nodes re-asked per 5-min run, rotating; 0 = only rebuilds
    return cfg


def using_default_web_password(cfg=None):
    cfg = cfg or load()
    return cfg["ROUTER_WEB_USER"] == DEFAULT_WEB_USER and cfg["ROUTER_WEB_PASS"] == DEFAULT_WEB_PASS
