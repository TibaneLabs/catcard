#!/usr/bin/env python3
"""Tests for the SP 800-90B estimators in tools/trng_assess.py.

    python3 tools/test_trng_assess.py

Statements about what the estimators must say, like the Rust entropy tests: a stuck
source is worth nothing, a uniform one close to eight bits a byte, and on NIST's own
sample the estimators agree with the values NIST's tool documents.

`testdata/nist_rand8_short.bin` is `bin/rand8_short.bin` from NIST's SP 800-90B
reference implementation, <https://github.com/usnistgov/SP800-90B_EntropyAssessment>
(commit 87c104d0ed4cbc96103e7b8b38d6f2c7e0a6b289; SHA-256
17d2eaf9544cd6aea3e245bec362f494376d0b1ca6140c475a35f1ad1f8c2803), and the expected
values are that repository's `cpp/selftest/refdata/rand8_short.res`. It is carried here
unchanged under NIST's notice for that software: "NIST-developed software is provided by
NIST as a public service. You may use, copy, and distribute copies of the software in any
medium, provided that you keep intact this entire notice. [...] Please explicitly
acknowledge the National Institute of Standards and Technology as the source of the
software." The data file is NIST's; acknowledged here.
"""

import hashlib
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import trng_assess as ta  # noqa: E402

HERE = os.path.dirname(os.path.abspath(__file__))
NIST_SAMPLE = os.path.join(HERE, "testdata", "nist_rand8_short.bin")
NIST_SAMPLE_SHA256 = "17d2eaf9544cd6aea3e245bec362f494376d0b1ca6140c475a35f1ad1f8c2803"


def uniform(n, seed=b"catcard/trng-assess/test"):
    """n bytes of SHA-256 counter output: indistinguishable from a uniform source."""
    out = bytearray()
    i = 0
    while len(out) < n:
        out += hashlib.sha256(seed + i.to_bytes(8, "big")).digest()
        i += 1
    return bytes(out[:n])


class Constant(unittest.TestCase):
    def test_a_stuck_source_is_worth_nothing(self):
        for v in (0x00, 0xFF, 0x5A):
            data = bytes([v]) * 10_000
            self.assertEqual(ta.mcv_bytes(data), 0.0)
            est = ta.python_estimate(data)
            self.assertEqual(est["min"], 0.0, f"0x{v:02x}")

    def test_all_zero_bits_and_all_one_bits_have_no_markov_entropy(self):
        self.assertEqual(ta.markov_bits(b"\x00" * 4096), 0.0)
        self.assertEqual(ta.markov_bits(b"\xff" * 4096), 0.0)

    def test_an_alternating_bit_pattern_is_caught_by_markov_not_mcv(self):
        # 0x55 = 01010101: perfectly balanced bits, so the bitstring MCV sees a fair coin;
        # the transitions are certain, which is what the Markov estimate is for.
        data = b"\x55" * 4096
        self.assertGreater(ta.mcv_bits(data), 0.95)
        self.assertLess(ta.markov_bits(data), 0.01)


class Uniform(unittest.TestCase):
    def test_a_uniform_source_scores_close_to_eight_bits_a_byte(self):
        est = ta.python_estimate(uniform(ta.MIN_SAMPLES))
        # With a million samples the 99% upper bound costs a little; well above 7.8.
        self.assertGreater(est["mcv_bytes"], 7.8)
        self.assertLessEqual(est["mcv_bytes"], 8.0)
        self.assertGreater(est["mcv_bits_per_byte"], 7.95)
        self.assertGreater(est["markov_bits_per_byte"], 7.95)
        self.assertLessEqual(est["markov_bits_per_byte"], 8.0)

    def test_a_biased_source_scores_what_its_bias_allows(self):
        # One value takes a quarter of the samples: at most 2 bits a byte by MCV.
        u = uniform(400_000)
        data = bytes(0x42 if i % 4 == 0 else b for i, b in enumerate(u))
        self.assertLess(ta.mcv_bytes(data), 2.0)
        self.assertGreater(ta.mcv_bytes(data), 1.9)


class NistReference(unittest.TestCase):
    """NIST's documented results for its own sample (`refdata/rand8_short.res`)."""

    @classmethod
    def setUpClass(cls):
        with open(NIST_SAMPLE, "rb") as f:
            cls.data = f.read()

    def test_the_sample_is_the_one_nist_published(self):
        self.assertEqual(hashlib.sha256(self.data).hexdigest(), NIST_SAMPLE_SHA256)
        self.assertEqual(len(self.data), 10_000)

    def test_literal_most_common_value(self):
        # "Literal Most Common Value Estimate: min entropy = 7.0104540377360411"
        self.assertAlmostEqual(ta.mcv_bytes(self.data), 7.0104540377360411, places=9)

    def test_bitstring_most_common_value(self):
        # "Bitstring Most Common Value Estimate: min entropy = 0.98338678465915019"
        self.assertAlmostEqual(ta.mcv_bits(self.data), 0.98338678465915019, places=9)

    def test_bitstring_markov(self):
        # "Bitstring Markov Estimate: min entropy = 0.99772497672796534"
        self.assertAlmostEqual(ta.markov_bits(self.data), 0.99772497672796534, places=9)


class NistOutput(unittest.TestCase):
    def test_the_summary_lines_are_parsed(self):
        text = (
            "Running non-IID tests...\n\n"
            "H_original: 7.010454\n"
            "H_bitstring: 0.732612\n"
            "min(H_original, 8 X H_bitstring): 5.860894\n"
        )
        got = ta.parse_nist(text)
        self.assertEqual(got["h_original"], 7.010454)
        self.assertEqual(got["h_bitstring"], 0.732612)
        self.assertEqual(got["assessed"], 5.860894)

    def test_nothing_to_parse_is_none(self):
        self.assertIsNone(ta.parse_nist("Error: could not open file\n"))


if __name__ == "__main__":
    unittest.main()
