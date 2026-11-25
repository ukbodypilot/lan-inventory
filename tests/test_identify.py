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

    def test_console_that_is_also_a_media_renderer_does_not_disagree(self):
        r = identify.identify(ev(
            dhcp={"hostname": "GAMEBOX", "vendor_class": "MSFT 5.0 XBOX"}, vendor="Microsoft Corporation",
            ssdp={"description": {"deviceType": "urn:schemas-upnp-org:device:MediaRenderer:1", "friendlyName": "GAMEBOX",
                                  "modelName": "Xbox One", "manufacturer": "Microsoft Corporation"}}))
        self.assertEqual(r["type"], "Game console")
        self.assertIsNone(r["conflict"])

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


class Names(unittest.TestCase):
    def test_two_owners_on_one_device(self):
        f = identify.name_check({"Roku device name": "Aiko", "Deco app label": "Sam Roku", "AirPlay device name": "Roku"}, "Roku")
        self.assertEqual(len(f), 1)
        self.assertIn("names disagree", f[0])

    def test_name_claims_another_product(self):
        f = identify.name_check({"AirPlay device name": "Den Apple TV"}, "Roku", "Roku Express 4K+ (3941X2)", "Roku OS")
        self.assertTrue(any("claims an Apple product" in x for x in f))
        f = identify.name_check({"DHCP hostname": "DESKTOP-AB12CD3"}, "Pegatron", "", "", "chromeos")
        self.assertTrue(any("Windows-style" in x for x in f))

    def test_ordinary_names_pass(self):
        ok = [({"DHCP hostname": "Ring-4021e2", "Deco app label": "ringcam-frontdoor"}, "Texas Instruments", "Ring camera"),
              ({"AirPlay device name": "55in TCL Roku TV", "DHCP hostname": "55TCLRokuTV"}, "TCL", "TCL 55S525"),
              ({"AirPlay device name": "Sam’s MacBook Air", "DHCP hostname": "Sams-Air"}, "Apple, Inc.", "Mac17,4"),
              ({"DHCP hostname": "DESKTOP-AB12CD3", "NetBIOS name": "DESKTOP-AB12CD3"}, "Intel Corporate", "")]
        for claims, man, model in ok:
            self.assertEqual(identify.name_check(claims, man, model, "macOS" if "Mac" in model else ""), [], claims)

    def test_parts_maker_cannot_disprove_a_brand(self):
        self.assertEqual(identify.name_check({"DHCP hostname": "Garage_iPhone"}, "Murata Manufacturing"), [])
        self.assertIn("component", identify.ai_vendor("LG Innotek"))
        self.assertEqual(identify.ai_vendor("Apple, Inc."), "Apple, Inc.")
        f = identify.name_check({"AirPlay device name": "Den Apple TV"}, "Roku", "Roku Express 4K+ (3941X2)", "Roku OS")
        self.assertTrue(f)  # a real brand maker still disproves it

    def test_dock_name_is_a_shared_port_not_a_conflict(self):
        notes = []
        f = identify.name_check({"DHCP hostname": "1AB2CD3-Dell Pro Thunderbolt 4 Smart Dock", "mDNS hostname": "Kestrel"},
                                "Dell Inc.", "", "", "", None, notes)
        self.assertEqual(f, [])
        self.assertTrue(any("dock/adapter" in n for n in notes))

    def test_rename_over_time_is_not_a_conflict(self):
        claims = {"DHCP hostname": "DESKTOP-RT5SKQL", "mDNS hostname": "DESKTOP-ZZ98YX7"}
        notes = []
        when = {"DHCP hostname": ("2026-01-05T03:20:00Z", "2026-01-05T03:24:00Z"), "mDNS hostname": (None, "2026-01-05T01:30:00Z")}
        self.assertEqual(identify.name_check(claims, "", "", "Windows", "MSFT 5.0", when, notes), [])
        self.assertTrue(any("renamed" in n and "ZZ98YX7" in n for n in notes))
        when["mDNS hostname"] = (None, "2026-01-05T03:00:00Z")  # heard while the new name was in use: both at once
        self.assertTrue(identify.name_check(claims, "", "", "Windows", "MSFT 5.0", when))

    def test_dock_name_loses_the_display_name(self):
        i = identify.Idn()
        i.name_candidate("1AB2CD3-Dell Pro Thunderbolt 4 Smart Dock", "DHCP hostname", "dhcp", 50)
        i.name_candidate("Kestrel", "mDNS hostname", "mdns", 45)
        self.assertEqual(i.pick("name")[0], "Kestrel")

    def test_nmap_os_guess_needs_a_tcp_port(self):
        ev = {"ports": [{"port": 5353, "proto": "udp"}], "os": "Aerohive HiveOS 6.1",
              "osclass": {"osfamily": "HiveOS", "accuracy": 97, "type": "WAP"}, "dhcp": {}, "vendor": "Liteon"}
        self.assertNotEqual(identify.identify(ev)["os_family"], "HiveOS")
        ev["ports"].append({"port": 22, "proto": "tcp"})
        self.assertEqual(identify.identify(ev)["os_family"], "HiveOS")


if __name__ == "__main__":
    unittest.main()
