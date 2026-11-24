import unittest

import deco_web_discover as d


class DiscoverTest(unittest.TestCase):
    def test_extract_endpoints(self):
        js = ('url:$.su.url("/admin/client?form=client_list"),x="admin/network?form=wan_ipv4";'
              "y='admin/dhcp?form=reservation&operation=read' admin/client?form=client_list")
        self.assertEqual(d.extract_endpoints(js),
                         ["admin/client?form=client_list", "admin/dhcp?form=reservation", "admin/network?form=wan_ipv4"])

    def test_extract_scripts_same_host_only(self):
        html = ('<script src="js/su.js?v=3"></script><script src="http://evil.example/x.js"></script>'
                '<link href="/css/a.css">"locale/en_US/lan.js"')
        self.assertEqual(d.extract_scripts(html, "http://10.0.0.1/webpages/index.html"),
                         ["http://10.0.0.1/webpages/js/su.js", "http://10.0.0.1/webpages/locale/en_US/lan.js"])

    def test_probe_worthy(self):
        for ok in ("admin/dhcp?form=dhcp_setting", "admin/network?form=address_list", "admin/client?form=client_list"):
            self.assertTrue(d.probe_worthy(ok), ok)
        for no in ("admin/system?form=logout", "admin/device?form=reboot", "admin/firmware?form=upgrade",
                   "admin/client?form=block_add", "admin/wireless?form=wps_start", "admin/lan?form=lan_set"):
            self.assertFalse(d.probe_worthy(no), no)

    def test_module_registry(self):
        reg = {"main": {"controller": "./modules/main/main.js", "view": "./modules/main/main.html"},
               "x": {"controller": "./modules/main/main.js", "models": ["./modules/x/m.js"]}, "n": 3}
        self.assertEqual(d.module_files(reg), ["./modules/main/main.js", "./modules/main/main.html", "./modules/x/m.js"])
        self.assertEqual(d.extract_configs('c.ajax("./config/modules.json",{});c.ajax("./config/a_b.json")'),
                         ["./config/a_b.json", "./config/modules.json"])

    def test_redact(self):
        r = d.redact({"ssid": "Home", "password": "x", "wps_pin": "1", "ping": 5, "port_mapping": [{"key": "k", "a": 1}]})
        self.assertEqual(r, {"ssid": "Home", "password": "<redacted>", "wps_pin": "<redacted>", "ping": 5,
                             "port_mapping": [{"key": "<redacted>", "a": 1}]})


if __name__ == "__main__":
    unittest.main()
