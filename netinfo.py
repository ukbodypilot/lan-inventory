"""Which interface / subnet to scan. Auto-detected from the default route; override with
LAN_IFACE and LAN_SUBNET (e.g. LAN_SUBNET=192.168.1.0/24) in the environment."""
import ipaddress
import os
import re
import subprocess


def _ip(*args):
    return subprocess.check_output(["ip", "-4"] + list(args), text=True)


def iface():
    if os.environ.get("LAN_IFACE"):
        return os.environ["LAN_IFACE"]
    m = re.search(r"default .*?dev (\S+)", _ip("route", "show", "default"))
    if not m:
        raise SystemExit("no default route; set LAN_IFACE")
    return m.group(1)


def cidr(ifc=None):
    m = re.search(r"inet (\d+\.\d+\.\d+\.\d+/\d+)", _ip("-o", "addr", "show", "dev", ifc or iface()))
    if not m:
        raise SystemExit("no IPv4 address on %s" % (ifc or iface()))
    return m.group(1)


def ip(ifc=None):
    return cidr(ifc).split("/")[0]


def subnet(ifc=None):
    if os.environ.get("LAN_SUBNET"):
        return os.environ["LAN_SUBNET"]
    return str(ipaddress.ip_interface(cidr(ifc)).network)


def mac(ifc=None):
    return open("/sys/class/net/%s/address" % (ifc or iface())).read().strip()
