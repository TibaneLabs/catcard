#!/usr/bin/env python3
"""Tests for the health-report decoding in tools/rng_report.py.

    python3 tools/test_rng_report.py

The bytes are the ones `catcard_usb::rng::tests::the_health_report_round_trips` encodes,
so the host's reading and the firmware's writing are checked against one vector.
"""

import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import rng_report as rr  # noqa: E402

# Pool published, present, meeting its policy; two sources counted. The chip passed its
# start-up test; SE2 failed it on a repetition, its last read tripped, three reads so.
VECTOR = bytes([
    1, 0b0111, 2, 2,
    1, 1, 0, 1, 0x00, 0x04, 0, 0,
    3, 2, 1, 2, 96, 0, 3, 0,
])


class Decode(unittest.TestCase):
    def test_the_firmware_vector(self):
        r = rr.decode(VECTOR)
        self.assertTrue(r["published"] and r["pool"] and r["policy_met"])
        self.assertFalse(r["startup_enforced"])
        self.assertEqual(r["hardware_sources_counted"], 2)
        chip, se2 = r["sources"]
        self.assertEqual((chip["source"], chip["startup"], chip["tested"]), ("chip", "passed", 1024))
        self.assertEqual((chip["last_read"], chip["trips"]), ("ok", 0))
        self.assertEqual((se2["source"], se2["startup"], se2["failure"]),
                         ("se2", "FAILED", "repetition count"))
        self.assertEqual((se2["last_read"], se2["trips"]), ("TRIPPED", 3))

    def test_a_truncated_or_foreign_report_is_refused(self):
        with self.assertRaises(ValueError):
            rr.decode(VECTOR[:-1])
        with self.assertRaises(ValueError):
            rr.decode(bytes([2]) + VECTOR[1:])
        with self.assertRaises(ValueError):
            rr.decode(b"")

    def test_an_unpublished_report_says_so(self):
        r = rr.decode(bytes([1, 0, 0, 0]))
        self.assertFalse(r["published"])
        self.assertIn("not reached its menu", rr.render(r))

    def test_the_rendering_names_a_failure(self):
        text = rr.render(rr.decode(VECTOR))
        self.assertIn("FAILED: repetition count", text)
        self.assertIn("MCU TRNG", text)


if __name__ == "__main__":
    unittest.main()
