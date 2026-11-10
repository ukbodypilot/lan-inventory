"""Alert channels. Email today (Gmail SMTP, the same way the radio gateway sends); more can be added to CHANNELS.

Credentials are never stored in this repo. They come from, in order:
  1. the environment: EMAIL_ADDRESS, EMAIL_APP_PASSWORD, EMAIL_RECIPIENT
  2. a KEY=VALUE file named by ALERT_CONFIG (the gateway's gateway_config.txt works as-is - same keys, same format)
  3. ./alerts.env next to this file
Channels to use: ALERT_CHANNELS (comma list, default "email,voicemonkey"). A channel that is not configured is skipped, not failed.
Voice Monkey (Alexa announcements): VOICEMONKEY_TOKEN and VOICEMONKEY_DEVICES (comma list of Speaker IDs, max 10); VOICEMONKEY_VOICE optional.
"""
import json
import os
import re
import smtplib
import sys
import urllib.error
import urllib.request
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText

ROOT = os.path.dirname(os.path.abspath(__file__))
KEYS = ("EMAIL_ADDRESS", "EMAIL_APP_PASSWORD", "EMAIL_RECIPIENT", "ALERT_CHANNELS",
        "VOICEMONKEY_TOKEN", "VOICEMONKEY_DEVICES", "VOICEMONKEY_VOICE")


def _parse(path):
    """KEY=VALUE lines, quotes stripped, '#' comments removed (same convention as the gateway's config)."""
    out = {}
    try:
        for line in open(path, errors="replace"):
            m = re.match(r"^\s*([A-Z_]+)\s*=\s*(.*)$", line)
            if m and m.group(1) in KEYS:
                v = m.group(2)
                q = re.match(r"""^(["'])(.*?)\1""", v.strip())
                out[m.group(1)] = (q.group(2) if q else v.split("#")[0]).strip()
    except OSError:
        pass
    return out


def config():
    cfg = {}
    for path in (os.path.join(ROOT, "alerts.env"), os.environ.get("ALERT_CONFIG")):
        if path:
            cfg.update({k: v for k, v in _parse(path).items() if v})
    cfg.update({k: os.environ[k] for k in KEYS if os.environ.get(k)})
    return cfg


def send_email(subject, body, cfg=None):
    cfg = cfg or config()
    addr, pw = cfg.get("EMAIL_ADDRESS", ""), cfg.get("EMAIL_APP_PASSWORD", "")
    if not (addr and pw):
        print("[notify] email not configured (EMAIL_ADDRESS / EMAIL_APP_PASSWORD)", file=sys.stderr)
        return False
    to = cfg.get("EMAIL_RECIPIENT") or addr
    msg = MIMEMultipart("alternative")
    msg["From"], msg["To"], msg["Subject"] = addr, to, subject
    msg.attach(MIMEText(body, "plain"))
    html = re.sub(r"((?:https?)://\S+)", r'<a href="\1">\1</a>', body.replace("&", "&amp;").replace("<", "&lt;"))
    msg.attach(MIMEText('<html><body style="font-family:monospace;font-size:14px">%s</body></html>' % html.replace("\n", "<br>\n"), "html"))
    try:
        with smtplib.SMTP_SSL("smtp.gmail.com", 465, timeout=15) as s:  # bounded: 15 s like the gateway
            s.login(addr, pw)
            s.sendmail(addr, to, msg.as_string())
        print("[notify] email sent to %s: %s" % (to, subject))
        return True
    except Exception as e:  # never let a mail problem break the scan cycle; the caller retries later
        print("[notify] email failed: %s: %s" % (type(e).__name__, str(e).replace(pw, "***")[:200]), file=sys.stderr)
        return False


def speakable(text, limit=320):
    """Text that is safe to hand to Alexa. With Alexa voices Voice Monkey passes `speech` through as SSML, and parts of it come
    from the network (device names, banners), so strip anything unusual and XML-escape the rest."""
    t = re.sub(r"[^\w .,'()+/:-]", " ", text or "", flags=re.UNICODE)
    t = re.sub(r"\s+", " ", t).strip()[:limit]
    return t.replace("&", " and ").replace("<", " ").replace(">", " ")


def send_voicemonkey(speech, cfg=None):
    """Announce on the configured Echo Speaker(s). None = not configured (skipped); True/False = sent/failed."""
    cfg = cfg or config()
    token, devices = cfg.get("VOICEMONKEY_TOKEN", ""), cfg.get("VOICEMONKEY_DEVICES", "")
    if not (token and devices):
        return None
    body = {"device": [d.strip() for d in devices.split(",") if d.strip()][:10], "speech": speakable(speech)}
    if cfg.get("VOICEMONKEY_VOICE"):
        body["voice"] = cfg["VOICEMONKEY_VOICE"]
    req = urllib.request.Request("https://api-v3.voicemonkey.io/announce", data=json.dumps(body).encode(), method="POST",
                                 headers={"Authorization": "Bearer " + token, "Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=15) as r:  # bounded, like the email path
            j = json.load(r)
        if j.get("data") == "PARTIAL":
            print("[notify] voicemonkey: only some Speakers answered: %s" % json.dumps(j)[:200], file=sys.stderr)
            return False
        print("[notify] voicemonkey announced on %s" % ",".join(body["device"]))
        return bool(j.get("success"))
    except urllib.error.HTTPError as e:
        try:
            err = json.load(e).get("error", "")
        except Exception:
            err = ""
        print("[notify] voicemonkey failed: HTTP %s %s" % (e.code, str(err).replace(token, "***")[:120]), file=sys.stderr)
        return False  # 401/404 = fix the config; 429 = throttled or quota - the pending retry waits for the next pass
    except Exception as e:
        print("[notify] voicemonkey failed: %s: %s" % (type(e).__name__, str(e).replace(token, "***")[:200]), file=sys.stderr)
        return False


CHANNELS = {"email": lambda subject, body, speech: send_email(subject, body),
            "voicemonkey": lambda subject, body, speech: send_voicemonkey(speech)}


def notify(subject, body, speech=None, skip=()):
    """Send on every enabled channel except `skip` (already delivered). Returns {channel: True | False | None(not configured)}."""
    names = [c.strip() for c in (config().get("ALERT_CHANNELS") or "email,voicemonkey").split(",") if c.strip()]
    out = {}
    for n in names:
        if n in CHANNELS and n not in skip:
            out[n] = CHANNELS[n](subject, body, speech or subject)
    return out
