"""Evidence -> identity. Pure functions, no I/O except loading the lookup databases.

identify(ev) takes one device's merged evidence and returns
  {model, manufacturer, os_family, type, name, confidence, reasons[], type_source, conflict}

Every rule that fires proposes a value for a field together with its source. Sources carry a weight (WEIGHT):
a device answering its own vendor API outweighs a host name, which outweighs the router's guess or the MAC
vendor. For each field the best-supported value wins, agreeing sources add to it, and a strong source that
disagrees with the winner lowers the confidence and is named in the reasons. Rule order does not matter.
"""
import hashlib
import json
import os
import re

HERE = os.path.dirname(os.path.abspath(__file__))
VERSION = 3  # bump when rules change meaning: build_report drops identities cached under an older version

# How far each kind of evidence can be trusted on its own (0-100).
WEIGHT = {
    "hue": 90, "roku": 90, "cast": 90, "airplay": 90, "kasa": 90,  # the device answered its own vendor API
    "mdns": 80, "upnp": 80, "tls": 80, "smb": 75, "tuya": 80, "igd": 95,      # protocol records that carry a model / role
    "web": 60, "dhcp": 55, "hostname": 50, "ports": 50, "amazon": 55,
    "nmap": 40,                                                     # OS-stack guess
    "router": 12, "vendor": 10, "oui": 10,                          # the Deco's own category, the MAC vendor
}
WEAK = 0.6          # a rule marked strong=False counts this much
HIGH, MEDIUM = 75, 30
# A generic type is compatible with (and yields to) the specific ones listed; "IoT" is compatible with anything.
GENERIC = {"IoT": None, "Computer": {"Laptop", "Desktop", "Server"}, "Media device": {"TV", "Speaker"},
           "Access Point": {"Router"}}

GENERIC_NAMES = {"", "(unknown)", "(name not found)", "unknown", "none", "linux", "localhost", "android",
                 "philips hue", "null", "nil", "mac", "iphone", "ipad", "device", "(null)", "n/a", "wlan0", "espressif"}
# Names the Deco invents when a client sent none: "Device_1A2B", "tablet_3C4D", "iot_device_5E6F"
DECO_PLACEHOLDER = re.compile(r"^(device|phone|tablet|pc|laptop|iot_device|entertainment|network_device|other|unknown)_[0-9a-f]{4}$", re.I)

# HomeKit accessory category (TXT ci=) -> our type
HAP_CATEGORY = {2: ("Bridge", "IoT"), 3: ("Fan", "IoT"), 4: ("Garage Door Opener", "IoT"), 5: ("Lightbulb", "Smart Light"),
                6: ("Door Lock", "IoT"), 7: ("Outlet", "Smart Plug"), 8: ("Switch", "Smart Switch"), 9: ("Thermostat", "Thermostat"),
                10: ("Sensor", "IoT"), 11: ("Security System", "IoT"), 12: ("Door", "IoT"), 13: ("Window", "IoT"),
                14: ("Window Covering", "IoT"), 15: ("Programmable Switch", "Smart Switch"), 17: ("IP Camera", "Camera"),
                18: ("Video Doorbell", "Camera"), 19: ("Air Purifier", "Appliance"), 20: ("Heater", "Appliance"),
                21: ("Air Conditioner", "Appliance"), 22: ("Humidifier", "Appliance"), 23: ("Dehumidifier", "Appliance"),
                26: ("Speaker", "Speaker"), 27: ("AirPort", "Access Point"), 28: ("Sprinkler", "IoT"), 29: ("Faucet", "IoT"),
                30: ("Shower", "IoT"), 31: ("Television", "TV"), 32: ("Remote", "IoT"), 33: ("Router", "Router"),
                34: ("Audio Receiver", "Speaker"), 35: ("TV Set Top Box", "Media device"), 36: ("TV Streaming Stick", "Media device")}

# (substring of manufacturer, type) - low confidence, only used when nothing better is known
VENDOR_TYPE = [("Nintendo", "Game console"), ("Ring", "IoT"), ("Philips Lighting", "IoT"), ("Signify", "IoT"), ("ecobee", "Thermostat"), ("Tuya", "IoT"),
               ("Espressif", "IoT"), ("Bouffalo", "IoT"), ("Texas Instruments", "IoT"), ("Chamberlain", "IoT"),
               ("Amazon", "IoT"), ("Raspberry", "Server"), ("Sonos", "Speaker"), ("Roku", "Media device"), ("Nest", "IoT"),
               ("Hikvision", "Camera"), ("Dahua", "Camera"), ("Brother", "Printer"), ("Canon", "Printer"),
               ("Epson", "Printer"), ("Synology", "NAS"), ("QNAP", "NAS"),
               ("Western Digital", "NAS"), ("Ubiquiti", "Network"), ("Netgear", "Network"), ("Cisco", "Network")]

OSCLASS_TYPE = {"printer": "Printer", "storage-misc": "NAS", "webcam": "Camera", "game console": "Game console"}

# The Deco's own "client_type". Measured on this network it is wrong about as often as right (a smart speaker = tablet,
# a TV box = phone, a camera = pc, a game console = phone), so it only ever counts as a low-confidence hint.
DECO_CLIENT_TYPE = {"phone": "Phone", "tablet": "Tablet", "pc": "Computer", "laptop": "Laptop", "desktop": "Desktop",
                    "entertainment": "Media device", "tv": "TV", "game_console": "Game console", "printer": "Printer",
                    "nas": "NAS", "smart_speaker": "Speaker", "smart_plug": "Smart Plug", "camera": "Camera",
                    "router": "Router", "iot_device": "IoT"}

# Device names people (and firmware) choose are evidence of what a thing is: "ringcam-kitchen", "LG_Smart_Laundry2",
# "BRW0123456789AB". Each rule is (regex on a name, type, model or None, label). Kept to patterns that are
# unambiguous. The most specific rule (earliest here) across all of a device's names is the one used.
NAME_HINTS = [
    (r"^ring-?cam|ringcam", "Camera", "Ring camera", "ringcam"),
    (r"^ring-[0-9a-f]{6,}$", "Camera", "Ring camera", "Ring-<id> (Ring camera or doorbell)"),
    (r"^lg[_ -]?smart[_ -]?(laundry|washer|dryer)|smart[_ -]?laundry|^lg[_ -]?(washer|dryer)", "Appliance", "LG smart laundry appliance", "LG smart laundry"),
    (r"coffee[_ -]?maker|coffeemaker", "Appliance", None, "coffee maker"),
    (r"^brw[0-9a-f]{12}$", "Printer", None, "BRW<mac> (Brother printer)"),
    (r"^tesla[_ -]", "Vehicle", None, "Tesla"),
    (r"thunderbolt.*dock|\bdock\b", "Dock", None, "dock"),
    (r"^pura-[0-9a-f]{4}$", "IoT", "Pura smart fragrance diffuser", "Pura-<id>"),
    (r"^deco[-_ ]?(mesh)?[a-z]?\d", "Access Point", None, "Deco mesh unit"),
    (r"macbook", "Laptop", None, "MacBook"),
    (r"\bimac\b|mac[-_ ]?mini|mac[-_ ]?studio|mac[-_ ]?pro", "Desktop", None, "desktop Mac"),
    (r"apple[-_ ]?tv", "TV", None, "Apple TV"),
    (r"homepod", "Speaker", None, "HomePod"),
    (r"^iphone\b|\biphone$", "Phone", None, "iPhone"),
    (r"^ipad\b|\bipad$", "Tablet", None, "iPad"),
    (r"^galaxy[-_ ]?(s|a|z|note)\d|^pixel[-_ ]?\d|\bphone\b", "Phone", None, "phone"),
    (r"roku[-_ ]?tv|tcl.*tv|bravia|smart[-_ ]?tv|(^|[-_ ])tv($|[-_ ])", "TV", None, "TV"),
    (r"roku", "Media device", None, "Roku"),
    (r"fire[-_ ]?(tv|stick)|chromecast", "Media device", None, "streaming stick"),
    (r"google[_ -]?home|nest[_ -]?(mini|hub|audio)", "Speaker", None, "Google/Nest speaker"),
    (r"echo[_ -]?(dot|show|pop)?\b|alexa", "Speaker", None, "Echo/Alexa"),
    (r"\bprinter\b|laserjet|officejet|deskjet|^epson|^canon[_ -]?(mg|ts)", "Printer", None, "printer"),
    (r"(^|[-_ ])(nas|mycloud|mybook)", "NAS", None, "NAS"),
    (r"thermostat|ecobee", "Thermostat", None, "thermostat"),
    (r"doorbell", "Camera", None, "doorbell"),
    (r"(^|[-_ ])(cam|camera)($|[-_ 0-9])", "Camera", None, "camera"),
    (r"playstation|^ps[45]\b|xbox|nintendo|switch-", "Game console", None, "game console"),
    (r"^(desktop|laptop|win)-[0-9a-z]{6,8}$", "Computer", None, "default Windows computer name"),
    (r"^bouffalolab|^bl60[24]", "IoT", None, "Bouffalo Lab Wi-Fi module"),
    (r"^(esp|esp32|esp8266|shelly|tasmota|wiz)[-_]", "IoT", None, "Wi-Fi microcontroller"),
]

_manuf = None
_dhcp_db = None


# ----------------------------------------------------------------- lookup databases
def manuf_lookup(mac):
    """Wireshark manuf: longest match over 36/28/24-bit blocks. Returns long vendor name or ''."""
    global _manuf
    if _manuf is None:
        _manuf = {}
        try:
            for line in open(os.path.join(HERE, "data", "manuf"), errors="replace"):
                if not line.strip() or line.startswith("#"):
                    continue
                f = line.rstrip("\n").split("\t")
                if len(f) < 2:
                    continue
                pre, _, bits = f[0].strip().partition("/")  # columns are space-padded: strip or the digit count is wrong
                try:
                    val = int(pre.replace(":", "").replace("-", ""), 16)
                except ValueError:
                    continue
                nb = int(bits) if bits else 24
                digits = len(pre.replace(":", "").replace("-", ""))
                val >>= (digits * 4 - nb) if digits * 4 > nb else 0
                _manuf[(nb, val)] = (f[2] if len(f) > 2 and f[2] else f[1]).strip()
        except OSError:
            pass
    try:
        n = int(mac.replace(":", ""), 16)
    except (ValueError, AttributeError):
        return ""
    for nb in (36, 28, 24):
        v = _manuf.get((nb, n >> (48 - nb)))
        if v:
            return v
    return ""


def dhcp_db():
    """Old Fingerbank/PacketFence open DHCP fingerprint list -> {prl string: description}."""
    global _dhcp_db
    if _dhcp_db is None:
        _dhcp_db = {}
        try:
            txt = open(os.path.join(HERE, "data", "dhcp_fingerprints.conf"), errors="replace").read()
            for m in re.finditer(r"\[os \d+\]\ndescription=([^\n]*)\n(?:vendor_id=<<EOT\n.*?\nEOT\n)?fingerprints=<<EOT\n(.*?)\nEOT", txt, re.S):
                for fp in m.group(2).split("\n"):
                    _dhcp_db.setdefault(fp.strip(), m.group(1).strip())
        except OSError:
            pass
    return _dhcp_db


def dhcp_os(d):
    """(os_family, why, strong) from a DHCP request: vendor class, hostname, then option-list shape."""
    vc, host, prl = (d.get("vendor_class") or ""), (d.get("hostname") or ""), d.get("prl") or []
    s = ",".join(map(str, prl))
    if "XBOX" in vc.upper():
        return "Xbox OS", "DHCP vendor class %s" % vc, True
    if vc.startswith("android-dhcp"):
        return "Android", "DHCP vendor class %s" % vc, True
    if vc.startswith("MSFT"):
        return "Windows", "DHCP vendor class %s" % vc, True
    if vc.lower().startswith("chromeos"):
        return "ChromeOS", "DHCP vendor class %s" % vc, True
    m = re.match(r"dhcpcd-[\d.]+:Linux-([\d.]+)", vc)
    if m:
        return "Linux", "DHCP vendor class dhcpcd on Linux %s" % m.group(1), True
    if vc.startswith("udhcp"):
        return "Linux (BusyBox)", "DHCP vendor class %s (BusyBox, embedded Linux)" % vc, True
    if re.match(r"(?i)ipad", host):
        return "iPadOS", "DHCP hostname %s" % host, True
    if re.match(r"(?i)iphone", host):
        return "iOS", "DHCP hostname %s" % host, True
    if re.match(r"(?i)(galaxy|pixel|android|sm-)", host):
        return "Android", "DHCP hostname %s" % host, True
    if re.match(r"(?i)(desktop-|laptop-|win-)", host):
        return "Windows", "DHCP hostname %s" % host, True
    if prl:
        if s.startswith("1,121,3,6,15,119,252") or s.startswith("1,121,3,6,15,108,114,119"):
            return "Apple (macOS/iOS)", "DHCP option list %s (Apple pattern)" % s, True
        if s.startswith("1,3,6,15,26,28,51,58,59,43"):
            return "Android", "DHCP option list %s (Android pattern)" % s, True
        if 249 in prl and 33 in prl:
            return "Windows", "DHCP option list %s (Windows pattern)" % s, True
        if s in dhcp_db():  # a 2014 list: a hint, not a measurement
            return dhcp_db()[s], "DHCP option list %s matches Fingerbank (2014) '%s'" % (s, dhcp_db()[s]), False
    return None, None, False


# ----------------------------------------------------------------- helpers
def apple_model(model, name=""):
    """AppleTV14,1 / MacBookPro18,3 / iPhone15,2 / Mac17,5 -> (type, os_family, pretty).
    Apple's newer bare 'MacNN,N' identifiers cover laptops and desktops alike, so the device name decides."""
    m = model or ""
    for pre, typ, osf in (("AppleTV", "TV", "tvOS"), ("AudioAccessory", "Speaker", "audioOS"), ("MacBook", "Laptop", "macOS"),
                          ("Macmini", "Desktop", "macOS"), ("iMac", "Desktop", "macOS"), ("MacPro", "Desktop", "macOS"),
                          ("iPhone", "Phone", "iOS"), ("iPad", "Tablet", "iPadOS"), ("Watch", "Watch", "watchOS")):
        if m.startswith(pre):
            return typ, osf, m
    if re.match(r"^Mac\d", m):
        n = (name or "").lower()
        if "macbook" in n or re.search(r"\b(air|book)\b", n):
            return "Laptop", "macOS", m
        if re.search(r"mini|imac|studio|mac ?pro", n):
            return "Desktop", "macOS", m
        return "Computer", "macOS", m
    return None, None, m


def good_name(n):
    n = (n or "").strip()
    if not n or n.lower() in GENERIC_NAMES or DECO_PLACEHOLDER.match(n):
        return False
    if re.fullmatch(r"(?i)(linux|none|android|localhost|iphone|ipad|mac)[-_ ]?\d{1,2}", n):
        return False  # a generic host name with an mDNS de-duplication suffix
    if re.match(r"^[0-9a-f]{8}-[0-9a-f]{4}-", n.lower()) or re.fullmatch(r"[0-9a-f]{12}", n.lower()):
        return False  # uuid / bare MAC
    if re.fullmatch(r"(?i)mac-[0-9a-f]{6}", n) or (re.fullmatch(r"[A-Z0-9]{10,14}", n) and sum(c.isdigit() for c in n) >= 5):
        return False  # auto-generated / serial-like
    return True


def clean_name(n):
    return re.sub(r"\s+", " ", (n or "").replace("\\032", " ")).strip()[:60]


def norm_name(n):
    return re.sub(r"[^a-z0-9]", "", (n or "").lower())


# Words in a name that say what a thing is, not whose it is. They never make two names agree or disagree.
NAME_NOISE = {"the", "and", "for", "desktop", "laptop", "phone", "iphone", "ipad", "macbook", "mac", "air", "pro", "mini", "neo", "tv",
              "roku", "apple", "android", "galaxy", "pixel", "samsung", "xbox", "one", "echo", "dot", "series", "local", "home", "room",
              "device", "streaming", "stick", "player", "smart", "wifi", "lan"}
# A name that claims a product -> what the hardware must then be (matched against manufacturer, model and OS).
NAME_CLAIMS = [(r"apple ?tv|iphone|ipad|macbook|imac|homepod", r"apple|ios|ipados|macos|tvos|audioos", "an Apple product"),
               (r"chromecast|nest ?(hub|mini|audio)", r"google", "a Google product"),
               (r"fire ?tv|\becho\b", r"amazon", "an Amazon product"),
               (r"\bxbox", r"microsoft|xbox", "an Xbox"),
               (r"playstation|\bps[45]\b", r"sony", "a PlayStation"),
               (r"^(desktop|laptop)-[a-z0-9]{7}$", r"windows|microsoft|^$", "a Windows PC")]


def name_tokens(n, extra=()):
    """The identifying words of a name: lower-case, possessive dropped, product/brand words and numbers left out."""
    n = re.sub(r"\(\d+\.\d+\.\d+\.\d+\)", " ", n or "")
    if re.fullmatch(r"[A-Za-z0-9]+(?:[-_][A-Za-z0-9]+)?[-_](?=[0-9a-fA-F]*\d)[0-9a-fA-F]{4,12}", n.strip()):
        return set()  # "Ring-4021e2", "Pura-2378": a factory name with a serial suffix says nothing about an owner
    n = re.sub(r"(?<=[a-z])([A-Z])", r" \1", n)  # SamsRoku -> Sams Roku
    out = set()
    for t in re.split(r"[^a-z0-9’']+", n.lower()):
        t = re.sub(r"[’']s?$", "", t).replace("’", "").replace("'", "")
        if any(c.isdigit() for c in t) and len(t) < 6:
            continue  # "55in", "bl602": a size or part number, not an identity
        if len(t) >= 3 and not t.isdigit() and t not in NAME_NOISE and t not in extra:
            out.add(t)
    return out


def names_hash(names, vendor="", model="", os_family=""):
    """Changes when a device's names (or the hardware they are judged against) change; keys an AI name reading."""
    return hashlib.sha256(json.dumps([sorted((names or {}).items()), vendor or "", model or "", os_family or ""]).encode()).hexdigest()[:16]


def owner_hint(claims):
    """The owner a possessive name points to ("Sam's Roku", "SamsRoku", "sams-iPad" -> "Sam"), or None. The rule-based
    stand-in until names_ai.py has read the device."""
    for nm in claims.values():
        m = re.match(r"^([A-Za-z]{3,15})[’']s[ -_]", nm) or re.match(r"^([A-Z][a-z]{2,14})s(?=[-_ ]?[A-Z])", nm) \
            or re.match(r"^([A-Za-z]{3,15})s[-_ ](?:i?phone|ipad|mac|air|roku|tv|pc|laptop|watch)", nm, re.I)
        if m and m.group(1).lower() not in NAME_NOISE:
            return m.group(1).capitalize()
    return None


def name_check(claims, manufacturer="", model="", os_family="", dhcp_class=""):
    """Reasons to distrust a device's names, as text; [] when they hang together.
    claims is {where the name came from: name}. Two checks: a name that claims a product the hardware is not, and two
    names that share no identifying word (one device calling itself 'Aiko' here and 'Sam Roku' there)."""
    flags = []
    hw = " ".join(x or "" for x in (manufacturer, model, os_family)).lower()
    osf = (os_family or "").lower() or ("chromeos" if "chromeos" in (dhcp_class or "").lower() else
                                         "android" if "android" in (dhcp_class or "").lower() else "")
    told = set()
    for src, nm in claims.items():
        if nm in told:
            continue
        told.add(nm)
        for pat, need, what in NAME_CLAIMS:
            if not re.search(pat, nm, re.I):
                continue
            if what == "a Windows PC":
                if osf and not re.search(r"windows", osf):
                    flags.append("%s '%s' is a Windows-style name, but the device runs %s" % (src, nm, os_family or osf))
            elif hw.strip() and not re.search(need, hw):
                flags.append("%s '%s' claims %s, but the hardware is %s" % (src, nm, what, model if model and manufacturer.lower() in model.lower() else (manufacturer + " " + (model or "")).strip()))
            break
    extra = name_tokens(" ".join((manufacturer or "", model or "")))
    toks = [(src, nm, name_tokens(nm, extra)) for src, nm in claims.items()]
    toks = [t for t in toks if t[2]]

    def agree(a, b):
        na, nb = norm_name(a[1]), norm_name(b[1])
        return any(t in nb for t in a[2]) or any(t in na for t in b[2])
    done = False
    for x in range(len(toks)):
        for y in range(x + 1, len(toks)):
            if not done and not agree(toks[x], toks[y]):
                flags.append("names disagree: %s is '%s', %s is '%s'" % (toks[x][0], toks[x][1], toks[y][0], toks[y][1]))
                done = True
    return flags


def compatible(a, b):
    """True when two type values do not contradict each other (same, or one is the generic form of the other)."""
    if a == b:
        return True
    for g, s in ((a, b), (b, a)):
        if g in GENERIC and (GENERIC[g] is None or s in GENERIC[g]):
            return True
    return False


class Idn:
    """Collects proposals; resolve() picks the winner per field."""

    def __init__(self):
        self.cand = {f: [] for f in ("model", "manufacturer", "os_family", "type", "name")}  # (value, weight, source, why)
        self.notes = []  # (position, text) for facts that are not a proposal
        self.claims = {}  # where a name came from -> the name, for name_check() and rename detection
        self.n = 0

    def set(self, field, value, why, source, strong=True, weight=None):
        if not value:
            return
        w = weight if weight is not None else WEIGHT.get(source, 20) * (1 if strong else WEAK)
        self.n += 1
        self.cand[field].append((value, w, source, why, self.n))

    def name_candidate(self, n, why, source, weight=None):
        n = clean_name(n)
        if good_name(n):
            self.set("name", n, why, source, weight=weight)
            self.claims.setdefault(why.split(" '")[0], n)

    def note(self, text):
        self.n += 1
        self.notes.append((self.n, text))

    def has(self, field):
        return bool(self.cand[field])

    def pick(self, field):
        """(value, score, top source, runner-up) for one field. Agreeing sources add half their weight."""
        c = self.cand[field]
        if not c:
            return None, 0, None, None
        scores = {}
        for v in {x[0] for x in c}:
            mine = sorted((x for x in c if x[0] == v), key=lambda x: -x[1])
            seen, total = set(), 0
            for x in mine:  # one vote per source
                if x[2] not in seen:
                    total += x[1] if not seen else x[1] * 0.5
                    seen.add(x[2])
            if field == "type":
                # a specific type absorbs support from its compatible generic forms; a generic one is marked down
                for g in {x[0] for x in c if x[0] != v and x[0] in GENERIC and v not in GENERIC and compatible(x[0], v)}:
                    total += max(x[1] for x in c if x[0] == g) * 0.5
            rank = total * 0.8 if field == "type" and v in GENERIC else total
            if field == "model":
                # "3910RW" and "Roku Express+ (3910RW)" are one answer: the fuller string takes the support
                inner = [x for x in c if x[0] != v and x[0].lower() in v.lower()]
                if inner:
                    total = rank = total + 0.5 * max(x[1] for x in inner)
                if any(x[0] != v and v.lower() in x[0].lower() for x in c):
                    rank = total * 0.5
            scores[v] = (total, mine[0][2], mine[0][1], rank)
        order = sorted(scores, key=lambda v: (-scores[v][3], min(x[4] for x in c if x[0] == v)))
        win = order[0]
        rival = None
        if field == "type":
            rival = next((v for v in order[1:] if not compatible(v, win)), None)
        return win, scores[win][0], scores[win][1], (rival, scores[rival][1], scores[rival][2]) if rival else None


# ----------------------------------------------------------------- the engine
def identify(ev):
    i = Idn()
    pr = ev.get("probes") or {}
    ports = {p["port"] for p in ev.get("ports", [])}
    svcs = " ".join("%s %s" % (p.get("service", ""), p.get("product", "")) for p in ev.get("ports", [])).lower()
    scripts = ev.get("scripts") or {}
    mdns = ev.get("mdns_records") or []
    dh = ev.get("dhcp") or {}
    rc = ev.get("router_client") or {}
    vendor = ev.get("vendor") or ""
    names = []  # (name, where it came from) - every name the device goes by, for the name rules below

    # --- 1. vendor-specific unauthenticated APIs and discovery protocols (strongest)
    h = pr.get("hue")
    if h:
        i.set("model", "Philips Hue Bridge (%s)" % h.get("modelid"), "Hue API /api/0/config: modelid %s, firmware %s" % (h.get("modelid"), h.get("swversion")), "hue")
        i.set("type", "IoT", "Hue bridge", "hue")
        i.set("manufacturer", "Signify (Philips Hue)", "", "hue")
        i.name_candidate("Hue Bridge", "", "hue", 40)
    r = pr.get("roku")
    if r:
        mn, vn = r.get("model-name") or "", r.get("vendor-name") or ""
        mdl = (mn if not vn or mn.lower().startswith(vn.lower()) else vn + " " + mn) + (" (%s)" % r["model-number"] if r.get("model-number") and r["model-number"] not in mn else "")
        i.set("model", mdl.strip(), "Roku ECP device-info: %s %s" % (r.get("model-name"), r.get("software-version")), "roku")
        i.set("type", "TV" if r.get("is-tv") == "true" else "Media device", "Roku ECP is-tv=%s" % r.get("is-tv"), "roku")
        i.set("os_family", "Roku OS", "Roku ECP answered", "roku")
        i.name_candidate(r.get("user-device-name") or r.get("friendly-device-name"), "Roku device name", "roku")
    c = pr.get("chromecast")
    if c:
        i.set("model", " ".join(x for x in (c.get("manufacturer"), c.get("model")) if x), "Cast eureka_info: %s" % c.get("model"), "cast")
        i.set("type", "Media device", "Google Cast device", "cast")
        i.name_candidate(c.get("name"), "Cast device name", "cast")
    a = pr.get("airplay")
    if a:
        t, osf, mdl = apple_model(a.get("model"), a.get("name"))
        i.set("model", mdl, "AirPlay /info model %s" % a.get("model"), "airplay", strong=bool(t))  # non-Apple AirPlay receivers give a bare part number
        i.set("type", t, "AirPlay model %s" % a.get("model"), "airplay", strong=t != "Computer")
        i.set("os_family", osf, "AirPlay model %s" % a.get("model"), "airplay")
        i.name_candidate(a.get("name"), "AirPlay device name", "airplay")
        names.append((a.get("name"), "AirPlay name"))
    k = ev.get("kasa")
    if k:
        mdl = k.get("device_model") or k.get("model")
        fam = k.get("family", "")
        typ = "Smart Plug" if "Plug" in fam else "Smart Light" if "Bulb" in fam else "Smart Switch" if "Switch" in fam else "IoT"
        brand = "Tapo" if "Tapo" in fam or "SMART" in fam else "Kasa"
        i.set("model", "TP-Link %s %s" % (brand, mdl), "python-kasa discovery: %s (%s)" % (mdl, k.get("device_type")), "kasa")
        i.set("type", typ, "Kasa device family %s" % fam, "kasa")
        i.set("manufacturer", "TP-Link", "", "kasa")
        i.name_candidate(k.get("alias"), "Kasa alias", "kasa")
    t = ev.get("tuya")
    if t:
        i.set("model", "Tuya device (protocol %s, product %s)" % (t.get("version"), t.get("productKey")), "tinytuya broadcast discovery", "tuya")
        i.set("type", "IoT", "Tuya protocol", "tuya")

    # --- 2. mDNS service records and their TXT keys
    svcset = {m.get("svc", "") for m in mdns}
    for m in mdns:
        svc, txt, inst = m.get("svc", ""), m.get("txt") or {}, m.get("instance", "")
        if svc in ("_ipp._tcp", "_printer._tcp", "_pdl-datastream._tcp", "_ipps._tcp"):
            i.set("type", "Printer", "mDNS %s" % svc, "mdns")
            mdl = txt.get("ty") or txt.get("product", "").strip("()") or (inst if svc != "_ipps._tcp" and re.search(r"[A-Za-z]+[- ]?\d", inst) else "")
            i.set("model", mdl, "mDNS printer %s" % ("TXT ty=%s" % txt["ty"] if txt.get("ty") else "instance %s" % inst), "mdns")
        elif svc == "_hap._tcp":
            cat = HAP_CATEGORY.get(int(txt["ci"])) if txt.get("ci", "").isdigit() else None
            i.set("model", txt.get("md"), "HomeKit TXT md=%s" % txt.get("md"), "mdns")
            if cat:
                i.set("type", cat[1], "HomeKit accessory category '%s'" % cat[0], "mdns")
            else:
                i.note("speaks HomeKit (mDNS _hap)")
            names.append((inst, "HomeKit name"))
        elif svc in ("_airplay._tcp", "_raop._tcp"):
            mdl = txt.get("model") or txt.get("am")
            nm = inst.split("@", 1)[-1]
            t2, osf, pretty = apple_model(mdl, nm)
            if mdl:
                i.set("model", pretty, "AirPlay TXT model=%s" % mdl, "mdns", strong=bool(t2))
                i.set("type", t2, "AirPlay model %s" % mdl, "mdns", strong=t2 != "Computer")
                i.set("os_family", osf, "AirPlay model %s" % mdl, "mdns")
                if not t2 and txt.get("manufacturer"):
                    i.set("manufacturer", txt["manufacturer"], "", "mdns")
            i.name_candidate(nm, "AirPlay service name", "mdns", 65)
            names.append((nm, "AirPlay name"))
        elif svc == "_googlecast._tcp":
            i.set("model", txt.get("md"), "Cast TXT md=%s" % txt.get("md"), "mdns")
            i.set("type", "Media device", "Google Cast service", "mdns")
            i.name_candidate(txt.get("fn"), "Cast friendly name", "mdns")
        elif svc == "_homeconnect._tcp":
            i.set("type", "Appliance", "mDNS _homeconnect (Home Connect appliance)", "mdns")
            i.set("model", re.sub(r"^CoffeeMaker\s+", "Coffee maker ", inst), "mDNS instance %s" % inst, "mdns")
        elif svc == "_hue._tcp":
            i.set("type", "IoT", "mDNS _hue", "mdns")
            i.set("model", "Philips Hue Bridge", "mDNS _hue instance %s" % inst, "mdns", strong=False)
        elif svc in ("_roku-rcp._tcp", "_rsp._tcp"):
            i.set("os_family", "Roku OS", "mDNS %s" % svc, "mdns")
            i.set("type", "Media device", "mDNS %s (Roku)" % svc, "mdns")
        elif svc == "_sonos._tcp":
            i.set("type", "Speaker", "mDNS _sonos", "mdns")
        elif svc in ("_esphomelib._tcp", "_shelly._tcp", "_matter._tcp", "_matterc._udp", "_miio._udp"):
            i.set("type", "IoT", "mDNS %s" % svc, "mdns")
        elif svc == "_androidtvremote2._tcp":
            i.set("type", "Media device", "mDNS Android TV remote service", "mdns")
            i.set("os_family", "Android TV", "mDNS Android TV remote service", "mdns")
        elif svc == "_device-info._tcp" and txt.get("model"):
            t2, osf, pretty = apple_model(txt["model"], inst)
            i.set("model", pretty, "mDNS device-info model=%s" % txt["model"], "mdns")
            i.set("type", t2, "mDNS device-info model %s" % txt["model"], "mdns", strong=t2 != "Computer")
            i.set("os_family", osf, "mDNS device-info model %s" % txt["model"], "mdns")
        elif svc in ("_adisk._tcp", "_afpovertcp._tcp", "_smb._tcp") and ("storage" in svcs or {548, 2049} & ports):
            i.set("type", "NAS", "file-sharing services (mDNS %s)" % svc, "mdns", False)
        elif svc == "_workstation._tcp":
            i.set("os_family", "Linux/Unix", "mDNS _workstation (avahi)", "mdns", False)
        elif svc in ("_companion-link._tcp", "_rdlink._tcp", "_remotepairing._tcp", "_apple-mobdev2._tcp"):
            i.set("manufacturer", "Apple", "mDNS %s (Apple device)" % svc, "mdns")
            i.set("os_family", "Apple (macOS/iOS)", "mDNS %s" % svc, "mdns", False)
        elif svc == "_spotify-connect._tcp":
            i.note("mDNS Spotify Connect receiver")
        if svc in ("_companion-link._tcp", "_device-info._tcp", "_rdlink._tcp", "_smb._tcp", "_googlecast._tcp"):
            names.append((inst, "mDNS name"))
    if "_spotify-connect._tcp" in svcset and "amazon" in vendor.lower() and "_amzn-wplay._tcp" not in svcset:
        i.set("type", "Speaker", "Amazon device that is a Spotify Connect receiver and not a Fire TV: Echo", "amazon")
        i.set("model", "Amazon Echo", "", "amazon", False)

    # --- 2b. the Deco router's client list: its name for the client, its category guess, band / wired
    if rc:
        nm, hn = rc.get("name") or "", dh.get("hostname") or ""
        if nm and good_name(nm):
            # The Deco shows the DHCP host name (cut to 29 chars, punctuation dropped) until someone renames the
            # client in the app. A name that is not just the host name again was typed by a person.
            own = bool(hn) and (norm_name(hn).startswith(norm_name(nm)[:20]) or norm_name(nm) in norm_name(hn))
            if own:
                i.name_candidate(nm, "Deco router's device name for this client", "router", 30)
                names.append((nm, "Deco device name"))
            else:  # typed in the Deco app (or not provably the device's own): shown only when nothing was measured
                i.claims["Deco app label"] = clean_name(nm)
                i.name_candidate(nm, "Deco app label '%s' (may be typed by a person; used only when the device reports no name)" % nm, "router", 3)
        elif nm:
            i.note("Deco router has no real name for it (shows the placeholder '%s')" % nm)
        ct = DECO_CLIENT_TYPE.get(rc.get("client_type"))
        if ct:
            i.set("type", ct, "Deco router files it under '%s' (a weak guess, often wrong)" % rc["client_type"], "router")
        if rc.get("wired"):
            i.note("Deco router: wired (ethernet)")
        elif rc.get("band"):
            i.note("Deco router: wireless, %s%s" % (rc["band"], ", %s dBm" % rc["signal_dbm"] if rc.get("signal_dbm") else ""))
        if rc.get("interface") and rc["interface"] != "main":
            i.note("Deco router: on the %s network" % rc["interface"])

    # --- 3. UPnP / SSDP
    ss = ev.get("ssdp") or {}
    desc = ss.get("description") or {}
    if desc:
        mf, mn, dt = desc.get("manufacturer"), desc.get("modelName"), desc.get("deviceType", "")
        if mn:
            i.set("model", " ".join(x for x in (mf, mn, desc.get("modelNumber")) if x and (x == mn or x not in mn))[:80], "UPnP description: %s %s" % (mf, mn), "upnp")
        if "InternetGatewayDevice" in dt:
            i.set("type", "Router", "UPnP deviceType InternetGatewayDevice", "igd")
        elif "MediaRenderer" in dt:
            i.set("type", "Media device", "UPnP MediaRenderer", "upnp", False)
        elif "MediaServer" in dt:
            i.note("UPnP MediaServer")
        elif "Printer" in dt:
            i.set("type", "Printer", "UPnP printer", "upnp")
        i.set("manufacturer", mf, "", "upnp")
        i.name_candidate(desc.get("friendlyName"), "UPnP friendlyName", "upnp", 60)
        names.append((desc.get("friendlyName"), "UPnP name"))
    srv = ss.get("server") or ""
    sts = " ".join(ss.get("st") or [])
    if "IpBridge" in srv:
        i.set("type", "IoT", "UPnP server header IpBridge (Hue)", "upnp")
    if "roku:ecp" in sts or srv.startswith("Roku"):
        i.set("os_family", "Roku OS", "SSDP announces roku:ecp", "upnp")
        i.set("type", "Media device", "SSDP announces roku:ecp", "upnp", False)
    if "MiniUPnPd" in srv and "TP-LINK" in srv.upper():
        i.set("manufacturer", "TP-Link", "UPnP server header: %s" % srv[:60], "upnp")
    if re.search(r"Linux/([\d.]+)", srv):
        i.set("os_family", "Linux", "UPnP server header: %s" % srv[:60], "upnp", False)
    if "Windows" in srv:
        i.set("os_family", "Windows", "UPnP server header: %s" % srv[:60], "upnp", False)

    # --- 4. nmap scripts
    smb = scripts.get("smb-os-discovery", "")
    mo = re.search(r"OS: ([^\n]+)", smb)
    if mo:
        i.set("os_family", re.sub(r"\s*\(.*", "", mo.group(1)).strip(), "smb-os-discovery: %s" % mo.group(1)[:60], "smb")
    mc = re.search(r"Computer name: ([^\n]+)", smb)
    if mc:
        i.name_candidate(mc.group(1), "SMB computer name", "smb", 60)
    cert = scripts.get("ssl-cert", "")
    if "commonName=tplinkdeco.net" in cert:
        i.set("model", "TP-Link Deco mesh unit", "TLS certificate commonName=tplinkdeco.net", "tls")
        i.set("type", "Access Point", "TP-Link Deco mesh node", "tls")
        i.set("manufacturer", "TP-Link", "", "tls")
    if "organizationName=Philips Hue" in cert:
        i.set("type", "IoT", "TLS certificate organization Philips Hue", "tls")
    if "Allmon3" in scripts.get("http-title", ""):
        i.set("model", "AllStar node (Allmon3 web UI)", "web page title 'Allmon3'", "web")
        i.set("type", "Server", "serves the Allmon3 AllStar monitor", "web", False)
    nb = re.search(r"NetBIOS name: ([^,\n]+)", scripts.get("nbstat", ""))
    if nb:
        i.name_candidate(nb.group(1), "NetBIOS name", "smb", 60)
        names.append((nb.group(1), "NetBIOS name"))

    # --- 5. service fingerprints
    if 62078 in ports:
        i.set("os_family", "Apple OS (iOS/tvOS)", "port 62078 (Apple lockdownd) is open", "ports", False)
    if {9100, 631, 515} & ports:
        i.set("type", "Printer", "printer ports %s open" % sorted({9100, 631, 515} & ports), "ports")
    if {135, 445} <= ports or (3389 in ports and "windows" in svcs):
        i.set("os_family", "Windows", "RPC/SMB ports open", "ports")
        i.set("type", "Computer", "Windows services (135/445)", "ports")
    if {548, 2049} & ports and ("samba" in svcs or "afp" in svcs):
        i.set("type", "NAS", "AFP/NFS + Samba services", "ports")
    if "openwrt" in (ev.get("os") or "").lower() and "uhttpd" in svcs:
        i.set("os_family", "OpenWrt-style firmware", "uHTTPd web server", "ports", False)
    mo = re.search(r"(Debian|Ubuntu|Raspbian)", " ".join(p.get("product", "") for p in ev.get("ports", [])))
    if mo and 22 in ports:
        i.set("os_family", "Linux (%s)" % mo.group(1), "SSH banner mentions %s" % mo.group(1), "ports")
        i.set("type", "Server", "SSH on %s" % mo.group(1), "ports", False)

    # --- 6. DHCP fingerprint (passive) and host names
    if dh:
        osf, why, strong = dhcp_os(dh)
        if osf:
            i.set("os_family", osf, why, "dhcp", strong)
            if osf == "Xbox OS":
                i.set("type", "Game console", why, "dhcp")
            elif osf in ("iOS", "Android") and ev.get("randomized"):
                i.set("type", "Phone", "mobile OS on a randomized MAC", "dhcp", False)
            elif osf in ("Windows", "ChromeOS"):
                i.set("type", "Computer", why, "dhcp", False)
            elif osf == "iPadOS":
                i.set("type", "Tablet", why, "dhcp", False)
        vc = dh.get("vendor_class") or ""
        if vc == "dslforum.org":
            i.note("DHCP vendor class dslforum.org (router / CPE firmware)")
        i.name_candidate(dh.get("hostname"), "DHCP hostname", "dhcp", 50)
        names.append((dh.get("hostname"), "DHCP hostname"))

    # --- 7. nmap OS guess (only meaningful when the host has open ports)
    if ports and ev.get("osclass"):
        oc = ev["osclass"]
        if oc.get("accuracy", 0) >= 95:
            i.set("os_family", oc.get("osfamily"), "nmap OS detection %s%% (%s)" % (oc["accuracy"], ev.get("os")), "nmap")
            t3 = OSCLASS_TYPE.get(oc.get("type"))
            if t3:
                i.set("type", t3, "nmap device class '%s'" % oc.get("type"), "nmap", False)

    # --- 7b. what the device calls itself / what the router or its owner calls it
    names.append((ev.get("mdns_host"), "mDNS hostname"))
    best = None  # most specific rule (earliest in NAME_HINTS) across all of the device's names
    for nm, src in names:
        nm = (nm or "").strip()
        for n, hint in enumerate(NAME_HINTS):
            if nm and re.search(hint[0], nm, re.I):
                if best is None or n < best[0]:
                    best = (n, nm, src, hint)
                break
    if best:
        _, nm, src, (_, typ, model, label) = best
        i.set("type", typ, "name '%s' (%s) suggests %s" % (nm, src, label), "hostname")
        i.set("model", model, "", "hostname", False)

    # --- names from lower-priority sources
    i.name_candidate(ev.get("mdns_host"), "mDNS hostname", "mdns", 45)
    i.name_candidate(ev.get("seed_name"), "name carried over from earlier scan", "oui", 10)

    # --- 8. manufacturer from the OUI, then a vendor-only type guess
    i.set("manufacturer", vendor, "", "oui")
    for sub, typ in VENDOR_TYPE:
        if sub.lower() in vendor.lower():
            i.set("type", typ, "type guessed from manufacturer '%s' only" % vendor, "vendor")
            break

    # --- resolve
    out, reasons = {}, []
    for field in ("model", "manufacturer", "os_family", "type", "name"):
        out[field], score, src, rival = i.pick(field)
        if field == "type":
            tscore, tsrc, trival = score, src, rival
    for field in ("type", "model", "os_family", "name", "manufacturer"):
        for v, w, src, why, n in i.cand[field]:
            if not why:
                continue
            if v == out[field]:
                reasons.append((n, why))
            elif field == "type" and compatible(v, out[field]):
                reasons.append((n, why + " (consistent)"))
            elif field == "type" and w >= 20:
                reasons.append((n, "%s - outweighed, not used" % why))
    reasons += i.notes
    conf = "high" if tscore >= HIGH else "medium" if tscore >= MEDIUM else "low"
    conflict = None
    if trival and trival[2] >= 0.7 * max(x[1] for x in i.cand["type"] if x[0] == out["type"]) and trival[2] >= MEDIUM:
        conflict = "evidence disagrees: %s says %s, %s says %s" % (tsrc, out["type"], trival[1], trival[0])
        conf = {"high": "medium", "medium": "low"}.get(conf, conf)
    seen, ordered = set(), []
    for _, why in sorted(reasons, key=lambda x: x[0]):
        if why not in seen:
            seen.add(why)
            ordered.append(why)
    if conflict:
        ordered.insert(0, conflict)
    name_flags = name_check(i.claims, out["manufacturer"] or "", out["model"] or "", out["os_family"] or "", dh.get("vendor_class") or "")
    ordered = name_flags + ordered
    return {"model": out["model"], "manufacturer": out["manufacturer"], "os_family": out["os_family"], "type": out["type"],
            "type_source": tsrc if out["type"] else None, "name": out["name"], "confidence": conf if out["type"] else "low",
            "reasons": ordered, "conflict": conflict,
            "names": dict(i.claims), "name_flags": name_flags}
