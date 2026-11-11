"""SSDP: a query's ST is what the sender looks for, never what it is.  Run: python3 -m unittest discover tests"""
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
try:
    import passive
except Exception:  # scapy missing on a dev box
    passive = None

MAC = "02:00:00:00:00:01"
SEARCH = b"M-SEARCH * HTTP/1.1\r\nHOST: 239.255.255.250:1900\r\nMAN: \"ssdp:discover\"\r\nST: roku:ecp\r\n\r\n"
NOTIFY = b"NOTIFY * HTTP/1.1\r\nNT: urn:schemas-upnp-org:device:MediaRenderer:1\r\nSERVER: Test/1.0\r\n\r\n"
REPLY = b"HTTP/1.1 200 OK\r\nST: roku:ecp\r\nSERVER: Roku/12.0\r\n\r\n"


@unittest.skipIf(passive is None, "scapy not installed")
class SsdpDirection(unittest.TestCase):
    def setUp(self):
        passive.data["hosts"].clear()

    def rec(self, payload):
        passive.record_ssdp(MAC, "192.0.2.10", passive.ssdp_headers(payload))
        return passive.data["hosts"].get(MAC, {})

    def test_msearch_is_not_a_service(self):
        h = self.rec(SEARCH)
        self.assertEqual(h.get("ssdp", {}).get("types", []), [])
        self.assertEqual(h["ssdp_searches"], ["roku:ecp"])

    def test_notify_and_reply_are_services(self):
        self.assertIn("urn:schemas-upnp-org:device:MediaRenderer:1", self.rec(NOTIFY)["ssdp"]["types"])
        self.assertIn("roku:ecp", self.rec(REPLY)["ssdp"]["types"])


if __name__ == "__main__":
    unittest.main()
