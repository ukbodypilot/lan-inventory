"""Offline regression tests for the identification rules.  Run: python3 -m unittest discover tests"""
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import identify  # noqa: E402


def ev(**kw):
    base = {"ports": [], "scripts": {}, "os": None, "osclass": None, "mdns_records": [], "mdns_host": None, "ssdp": {},
            "probes": {}, "kasa": None, "tuya": None, "dhcp": {}, "vendor": "", "randomized": False, "seed_name": None}
    base.update(kw)
    return base


class Rules(unittest.TestCase):
    def test_deco_guess_is_only_a_low_hint(self):
        r = identify.identify(ev(router_client={"name": "Device_7A8B", "client_type": "tablet"}))
        self.assertEqual((r["type"], r["confidence"], r["name"]), ("Tablet", "low", None))

    def test_deco_guess_loses_to_measured_evidence(self):
        r = identify.identify(ev(router_client={"name": "living-room-tv", "client_type": "phone"},
                                 probes={"airplay": {"model": "AppleTV6,2", "name": "Living Room TV"}}))
        self.assertEqual((r["type"], r["confidence"], r["os_family"]), ("TV", "high", "tvOS"))

    def test_placeholder_names_rejected(self):
        for n in ("Device_1A2B", "tablet_3C4D", "iot_device_5E6F", "wlan0"):
            self.assertFalse(identify.good_name(n), n)
        self.assertTrue(identify.good_name("ringcam-garage"))

    def test_roku_with_homekit_is_not_iot(self):
        r = identify.identify(ev(
            probes={"roku": {"vendor-name": "Roku", "model-name": "Roku Express+", "model-number": "3910RW", "is-tv": "false"},
                    "airplay": {"model": "3910RW", "name": "Roku"}},
            mdns_records=[{"svc": "_hap._tcp", "instance": "Roku", "txt": {"md": "3910RW", "ci": "35"}}],
            osclass={"type": "phone", "osfamily": "Android", "accuracy": 97}, ports=[{"port": 8060}], os="Android 9"))
        self.assertEqual((r["type"], r["model"], r["os_family"], r["confidence"]),
                         ("Media device", "Roku Express+ (3910RW)", "Roku OS", "high"))

    def test_homekit_without_category_gives_no_type(self):
        r = identify.identify(ev(mdns_records=[{"svc": "_hap._tcp", "instance": "Thing", "txt": {}}]))
        self.assertIsNone(r["type"])

    def test_ipad_on_private_mac_is_a_tablet(self):
        r = identify.identify(ev(randomized=True, dhcp={"hostname": "iPad", "prl": [1, 121, 3, 6, 15, 119, 252]}))
        self.assertEqual((r["type"], r["os_family"]), ("Tablet", "iPadOS"))

    def test_router_beats_access_point(self):
        r = identify.identify(ev(scripts={"ssl-cert": "commonName=tplinkdeco.net"}, dhcp={"hostname": "deco-X55"},
                                 ssdp={"description": {"deviceType": "urn:schemas-upnp-org:device:InternetGatewayDevice:1",
                                                       "manufacturer": "TP-Link", "modelName": "X55"}}))
        self.assertEqual((r["type"], r["confidence"], r["conflict"]), ("Router", "high", None))

    def test_conflict_lowers_confidence(self):
        r = identify.identify(ev(dhcp={"hostname": "ringcam-porch", "vendor_class": "MSFT 5.0 XBOX"}))
        self.assertIsNotNone(r["conflict"])
        self.assertNotEqual(r["confidence"], "high")

    def test_two_sources_agreeing_reach_high(self):
        r = identify.identify(ev(dhcp={"hostname": "XBOX", "vendor_class": "MSFT 5.0 XBOX"}))
        self.assertEqual((r["type"], r["confidence"]), ("Game console", "high"))

    def test_vendor_only_is_low(self):
        r = identify.identify(ev(vendor="Espressif Inc."))
        self.assertEqual((r["type"], r["confidence"]), ("IoT", "low"))


if __name__ == "__main__":
    unittest.main()
