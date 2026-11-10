"""Evidence must follow the MAC, not the IP.  Run: python3 -m unittest discover tests"""
import json
import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import evidence  # noqa: E402

XML = """<nmaprun><host><status state="up"/><address addr="{ip}" addrtype="ipv4"/><address addr="{mac}" addrtype="mac" vendor="V"/>
<ports>{ports}</ports></host></nmaprun>"""
PORT = '<port protocol="tcp" portid="9999"><state state="open"/><service name="kasa"/></port>'


class PerMac(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root, evidence.ROOT = evidence.ROOT, self.tmp.name
        evidence.QUICK_DIR = os.path.join(self.tmp.name, "state", "quick")

    def tearDown(self):
        evidence.ROOT = self.root
        self.tmp.cleanup()

    def sweep(self, name, ip, mac, ports="", **extra):
        d = os.path.join(self.tmp.name, "scans", name)
        os.makedirs(d)
        open(os.path.join(d, "tcp.xml"), "w").write(XML.format(ip=ip, mac=mac.upper(), ports=ports))
        for k, v in extra.items():
            json.dump({ip: v}, open(os.path.join(d, k + ".json"), "w"))

    def test_evidence_follows_mac_across_ip_change_and_fills_gaps(self):
        import datetime
        d1 = (datetime.date.today() - datetime.timedelta(days=2)).isoformat() + "_0430"
        d2 = (datetime.date.today() - datetime.timedelta(days=1)).isoformat() + "_0430"
        self.sweep(d1, "192.168.2.50", "aa:bb:cc:00:00:01", PORT, kasa={"model": "EP10"})
        self.sweep(d2, "192.168.2.77", "aa:bb:cc:00:00:01")           # moved, and silent that night
        scans = evidence.load_scans()
        h, at, kind = evidence.scan_for("aa:bb:cc:00:00:01", scans)
        self.assertEqual(h["ip"], "192.168.2.77")
        self.assertEqual(h["kasa"], {"model": "EP10"})                 # from the older sweep
        self.assertEqual([p["port"] for p in h["ports"]], [9999])
        self.assertIn(d2, kind)

    def test_ip_reuse_does_not_leak(self):
        import datetime
        d1 = (datetime.date.today() - datetime.timedelta(days=1)).isoformat() + "_0430"
        self.sweep(d1, "192.168.2.50", "aa:bb:cc:00:00:01", PORT, kasa={"model": "EP10"})
        h, at, kind = evidence.scan_for("aa:bb:cc:00:00:02", evidence.load_scans())  # whoever holds .50 now
        self.assertEqual((h, at), ({}, None))

    def test_passive_drops_stale_names(self):
        hosts = {"aa:bb:cc:00:00:01": {"mdns": {"names": {"Old._hap._tcp.local": "2020-01-01T00:00:00Z",
                                                            "New._ipp._tcp.local": evidence.stamp(), "box.local": evidence.stamp()},
                                                  "txt": {"New._ipp._tcp.local": {"ty": "Printer 9"}}}}}
        p = evidence.passive("aa:bb:cc:00:00:01", hosts)
        self.assertEqual([(r["svc"], r["txt"]) for r in p["mdns_records"]], [("_ipp._tcp", {"ty": "Printer 9"})])
        self.assertEqual(p["mdns_host"], "box")


if __name__ == "__main__":
    unittest.main()
