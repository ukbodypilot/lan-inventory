import os
import sqlite3
import tempfile
import unittest

import router_history


class UsageTest(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.TemporaryDirectory()
        self.db = os.path.join(self.dir.name, "h.sqlite")
        router_history._db(self.db).close()

    def tearDown(self):
        self.dir.cleanup()

    def add(self, rows):
        con = sqlite3.connect(self.db)
        with con:
            con.executemany("INSERT INTO samples VALUES (?,?,?,?)", rows)
        con.close()

    def test_rate_held_until_next_sample(self):
        mac = "02:00:00:00:00:01"
        day = 86400 * 100  # a UTC midnight
        self.add([(day + 0, "client_down", mac, 10), (day + 300, "client_down", mac, 20),
                  (day + 600, "client_down", mac, 0),
                  (day + 0, "client_up", mac, 1), (day + 300, "client_up", mac, 1), (day + 600, "client_up", mac, 0)])
        u = router_history.usage(since=86400, path=self.db, now=day + 900, tz_offset=0)
        b = router_history.SPEED_UNIT_BYTES
        self.assertEqual(u[mac], [[day, (10 * 300 + 20 * 300) * b, (300 + 300) * b, 900]])

    def test_long_gap_is_capped(self):
        mac = "02:00:00:00:00:02"
        day = 86400 * 100
        self.add([(day, "client_down", mac, 5), (day + 7200, "client_down", mac, 0)])
        u = router_history.usage(since=86400, path=self.db, now=day + 7300, tz_offset=0)
        self.assertEqual(u[mac][0][1], 5 * router_history.USAGE_MAX_GAP * router_history.SPEED_UNIT_BYTES)

    def test_local_midnight_buckets(self):
        mac = "02:00:00:00:00:03"
        day = 86400 * 100
        off = -8 * 3600  # UTC-8: local midnight is 08:00 UTC
        self.add([(day + 7 * 3600, "client_down", mac, 1), (day + 9 * 3600, "client_down", mac, 1)])
        u = router_history.usage(since=2 * 86400, path=self.db, now=day + 10 * 3600, tz_offset=off)
        self.assertEqual([r[0] for r in u[mac]], [day - 16 * 3600, day + 8 * 3600])


if __name__ == "__main__":
    unittest.main()
