import unittest

import deco_web


class WebExtraTest(unittest.TestCase):
    WLAN = {"is_eg": False,
            "iot": {"host": {"password": "p", "encryption_mode": "wpa2", "ssid": "SW90", "enable": True,
                             "enable_5g": False, "enable_2g": True}},
            "band2_4": {"backhaul": {"channel": 5},
                        "guest": {"password": "g", "ssid": "R3Vlc3Q=", "enable": False},
                        "host": {"password": "h", "ssid": "SG9tZQ==", "channel": 5, "enable": True, "mode": "11n",
                                 "channel_width": "HT20", "enable_hide_ssid": False}},
            "band5_1": {"backhaul": {"channel": 44},
                        "host": {"password": "h", "ssid": "SG9tZQ==", "channel": 0, "enable": True, "mode": "11ac",
                                 "channel_width": "HT80"}}}

    def test_wlan_to_bands_shape(self):
        b = deco_web._wlan_to_bands(self.WLAN)
        self.assertEqual(sorted(b), ["band2_4", "band5_1"])
        self.assertEqual(b["band2_4"]["radio"], {"enable": True, "channel": "5", "hwmode": "11n", "htmode": "HT20"})
        self.assertNotIn("channel", b["band2_4"]["host"])
        self.assertTrue(b["band2_4"]["iot"]["enable"])
        self.assertFalse(b["band5_1"]["iot"]["enable"])
        self.assertNotIn("enable_2g", b["band2_4"]["iot"])

    def test_scrub_removes_every_password(self):
        out = deco_web._scrub(deco_web._wlan_to_bands(self.WLAN))
        self.assertNotIn('"p"', str(out).replace("'", '"'))
        for band in out.values():
            for net in ("host", "guest", "iot"):
                if "password" in band.get(net, {}):
                    self.assertEqual(band[net]["password"], "***REDACTED***")

    def test_ipv6_passthrough(self):
        self.assertEqual(deco_web.EXTRA_READS["ipv6"][2]({"enable_ipv6": False}), {"enable_ipv6": False})


if __name__ == "__main__":
    unittest.main()
