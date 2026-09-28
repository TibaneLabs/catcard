#!/usr/bin/env python3
"""Estimate the min-entropy of a raw TRNG capture, per NIST SP 800-90B.

    tools/trng_assess.py captures/q1-se1.bin [more.bin ...]
    tools/trng_assess.py --nist ~/src/SP800-90B_EntropyAssessment captures/*.bin
    tools/trng_assess.py --no-nist captures/q1-chip.bin

A capture is what `tools/trng_capture.py` writes: one 8-bit sample per byte, exactly the
bytes the firmware would have passed to its entropy pool (docs/ENTROPY.md, "Measuring the
sources").

Two assessments, reported side by side:

1. **NIST's reference implementation**, `ea_non_iid` from
   <https://github.com/usnistgov/SP800-90B_EntropyAssessment>, which runs all ten non-IID
   estimators of SP 800-90B §6.3 and is the number that counts. This script does not
   vendor it: point `--nist` (or `$SP800_90B_DIR`) at a checkout and it builds
   `cpp/ea_non_iid` there if it is not built yet (`make -C cpp non_iid`, which needs a C++
   compiler with OpenMP and the libraries its README lists: bzip2, divsufsort, jsoncpp,
   GMP, MPFR). Without one it says how to get it and carries on with (2).

2. **A self-contained partial estimate** in plain Python: the Most Common Value estimate
   (§6.3.1) on the bytes and on their bitstring, and the Markov estimate (§6.3.3) on the
   bitstring. Written from the SP 800-90B text and checked against the values NIST's own
   tool documents for its `rand8_short.bin` sample (`tools/test_trng_assess.py`).

   **This is not a lower bound on the full assessment.** SP 800-90B's figure is the
   *minimum* over all its estimators, so the minimum over a subset of them can only be
   the same or higher. Read it the other way round: it is an upper bound on what the full
   suite will report, so a source that scores low *here* is certainly low, and a source
   that scores well here still needs (1) before its credit rate can rest on it.

Samples: SP 800-90B §3.1.1 asks for at least 1,000,000 samples for a non-IID assessment;
fewer are assessed but flagged.

Conditioned sources: what the device calls a source's raw output is the output of that
chip's RNG, and for the secure elements that is already the output of an internal DRBG.
`--conditioned` runs the NIST tool with `-c` (bitstring only). Assessing conditioned
output measures the output, not the noise underneath it: it catches a stuck, biased or
repeating generator, it cannot certify one.
"""

import argparse
import math
import os
import re
import subprocess
import sys

# SP 800-90B §6.3.1: the upper bound of a 99% confidence interval, Z_(1-0.005).
ZALPHA = 2.5758293035489008

# §3.1.1: the minimum sample count for a non-IID assessment.
MIN_SAMPLES = 1_000_000

POPCOUNT = [bin(i).count("1") for i in range(256)]


def histogram(data):
    """Byte-value counts, 256 of them."""
    # bytes.count per value runs at C speed; 256 passes over a megabyte is still quick.
    return [data.count(bytes([b])) for b in range(256)]


def most_common_value(counts, n):
    """§6.3.1 Most Common Value Estimate over a symbol histogram. Bits per symbol."""
    if n < 2:
        raise ValueError("need at least two samples")
    p_hat = max(counts) / n
    p_u = min(1.0, p_hat + ZALPHA * math.sqrt(p_hat * (1.0 - p_hat) / (n - 1)))
    return -math.log2(p_u)


def mcv_bytes(data):
    """MCV over the 8-bit samples themselves (the tool's "Literal" estimate)."""
    return most_common_value(histogram(data), len(data))


def mcv_bits(data):
    """MCV over the bitstring (the tool's "Bitstring" estimate), per bit."""
    ones = sum(POPCOUNT[b] * c for b, c in enumerate(histogram(data)))
    n = 8 * len(data)
    return most_common_value([n - ones, ones], n)


def _pair_counts():
    """Per byte value: (zeros among its first seven bits, "00" pairs, "10" pairs), for
    the seven bit pairs inside the byte, MSB first."""
    out = []
    for v in range(256):
        bits = [(v >> (7 - j)) & 1 for j in range(8)]
        z = c00 = c10 = 0
        for j in range(7):
            if bits[j] == 0:
                z += 1
                if bits[j + 1] == 0:
                    c00 += 1
            elif bits[j + 1] == 0:
                c10 += 1
        out.append((z, c00, c10))
    return out


PAIRS = _pair_counts()


def markov_bits(data):
    """§6.3.3 Markov Estimate over the bitstring (MSB first, as NIST's tool expands
    bytes), per bit.

    From the transition probabilities, the probability of the most likely 128-bit
    sequence among the six the estimate considers; min-entropy is -log2 of it over 128,
    capped at 1.
    """
    n = 8 * len(data)
    if n < 2:
        raise ValueError("need at least two bits")
    hist = histogram(data)
    # Counts over bits S[0] .. S[n-2] and the pairs (S[i], S[i+1]) that start there.
    c0 = c00 = c10 = 0
    for v, cnt in enumerate(hist):
        if cnt:
            z, a, b = PAIRS[v]
            c0 += z * cnt
            c00 += a * cnt
            c10 += b * cnt
    # The pair across each byte boundary: last bit of one byte, first of the next.
    for i in range(len(data) - 1):
        last = data[i] & 1
        first = data[i + 1] >> 7
        if last == 0:
            c0 += 1
            if first == 0:
                c00 += 1
        elif first == 0:
            c10 += 1
    c1 = n - 1 - c0
    p00 = c00 / c0 if c0 else 0.0
    p01 = 1.0 - p00 if c0 else 0.0
    p10 = c10 / c1 if c1 else 0.0
    p11 = 1.0 - p10 if c1 else 0.0
    if data[-1] & 1 == 0:
        c0 += 1
    p0 = c0 / n
    p1 = 1.0 - p0

    def lg(p):
        return math.log2(p)

    h = 128.0
    cands = []
    if p00 > 0:
        cands.append(-lg(p0) - 127 * lg(p00))
    if p01 > 0 and p10 > 0:
        cands.append(-lg(p0) - 64 * lg(p01) - 63 * lg(p10))
    if p01 > 0 and p11 > 0:
        cands.append(-lg(p0) - lg(p01) - 126 * lg(p11))
    if p10 > 0 and p00 > 0:
        cands.append(-lg(p1) - lg(p10) - 126 * lg(p00))
    if p10 > 0 and p01 > 0:
        cands.append(-lg(p1) - 64 * lg(p10) - 63 * lg(p01))
    if p11 > 0:
        cands.append(-lg(p1) - 127 * lg(p11))
    # -log2(0) never arises above, but a constant source makes p0 or p1 exactly 1, and
    # log2(1) is 0: the candidate is 0 bits, which is the right answer.
    for c in cands:
        h = min(h, c)
    return min(h / 128.0, 1.0)


def python_estimate(data):
    """The partial estimate, as a dict of bits per byte."""
    literal = mcv_bytes(data)
    bit_mcv = mcv_bits(data)
    bit_markov = markov_bits(data)
    return {
        "mcv_bytes": literal,
        "mcv_bits_per_byte": 8 * bit_mcv,
        "markov_bits_per_byte": 8 * bit_markov,
        "min": min(literal, 8 * bit_mcv, 8 * bit_markov),
    }


# -- NIST's reference implementation ---------------------------------------------------

NIST_URL = "https://github.com/usnistgov/SP800-90B_EntropyAssessment"


def find_nist(path):
    """Path to a built `ea_non_iid`, building it in the checkout if needed; None with a
    message on stderr when there is no checkout or it will not build."""
    if not path:
        print(
            f"note: no NIST tool given (--nist or $SP800_90B_DIR); clone {NIST_URL}\n"
            "      and pass its directory for the full SP 800-90B assessment.",
            file=sys.stderr,
        )
        return None
    cpp = os.path.join(path, "cpp")
    exe = os.path.join(cpp, "ea_non_iid")
    if os.access(exe, os.X_OK):
        return exe
    if not os.path.isdir(cpp):
        print(f"note: {path} is not a checkout of {NIST_URL}", file=sys.stderr)
        return None
    print(f"building ea_non_iid in {cpp} ...", file=sys.stderr)
    r = subprocess.run(["make", "-C", cpp, "non_iid"], capture_output=True, text=True)
    if r.returncode != 0 or not os.access(exe, os.X_OK):
        tail = "\n".join((r.stdout + r.stderr).strip().splitlines()[-8:])
        print(
            "note: ea_non_iid did not build. It needs a C++11 compiler with OpenMP and\n"
            "      bzip2, divsufsort, jsoncpp, GMP and MPFR (see its README). Last lines:\n"
            + tail,
            file=sys.stderr,
        )
        return None
    return exe


def run_nist(exe, path, conditioned=False):
    """Run `ea_non_iid` on a capture and return its figures as a dict, or None."""
    args = [exe, "-c" if conditioned else "-i", "-a", path, "8"]
    r = subprocess.run(args, capture_output=True, text=True)
    if r.returncode != 0:
        print(f"note: ea_non_iid failed on {path}:\n{r.stderr.strip()}", file=sys.stderr)
        return None
    return parse_nist(r.stdout)


def parse_nist(text):
    """Pick the summary lines out of `ea_non_iid`'s default output."""
    out = {}
    m = re.search(r"^H_original:\s*([0-9.]+)", text, re.M)
    if m:
        out["h_original"] = float(m.group(1))
    m = re.search(r"^H_bitstring:\s*([0-9.]+)", text, re.M)
    if m:
        out["h_bitstring"] = float(m.group(1))
    m = re.search(r"^min\(H_original, \d+ X H_bitstring\):\s*([0-9.]+)", text, re.M)
    if m:
        out["assessed"] = float(m.group(1))
    m = re.search(r"^h':\s*([0-9.]+)", text, re.M)
    if m:
        # Conditioned (-c): per bit.
        out["h_prime"] = float(m.group(1))
        out["assessed"] = 8 * float(m.group(1))
    return out or None


# -- report -----------------------------------------------------------------------------


def assess(path, exe=None, conditioned=False):
    with open(path, "rb") as f:
        data = f.read()
    print(f"{path}: {len(data)} samples")
    if len(data) < MIN_SAMPLES:
        print(f"  WARNING: fewer than the {MIN_SAMPLES} samples SP 800-90B asks for")
    if len(data) < 2:
        print("  too short to assess")
        return None
    py = python_estimate(data)
    print(f"  MCV, bytes          {py['mcv_bytes']:.4f} bits/byte")
    print(f"  MCV, bitstring      {py['mcv_bits_per_byte']:.4f} bits/byte")
    print(f"  Markov, bitstring   {py['markov_bits_per_byte']:.4f} bits/byte")
    print(f"  partial (min above) {py['min']:.4f} bits/byte  -- an upper bound on the full suite")
    nist = run_nist(exe, path, conditioned) if exe else None
    if nist and "assessed" in nist:
        print(f"  NIST ea_non_iid     {nist['assessed']:.4f} bits/byte  -- the SP 800-90B figure")
    elif exe:
        print("  NIST ea_non_iid     (no result)")
    return {"python": py, "nist": nist}


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("captures", nargs="+", help="capture files, one byte per sample")
    ap.add_argument(
        "--nist",
        default=os.environ.get("SP800_90B_DIR"),
        help="a checkout of usnistgov/SP800-90B_EntropyAssessment (default $SP800_90B_DIR)",
    )
    ap.add_argument("--no-nist", action="store_true", help="the Python estimate only")
    ap.add_argument(
        "--conditioned",
        action="store_true",
        help="the samples are a conditioner's output (NIST tool -c)",
    )
    a = ap.parse_args(argv)
    exe = None if a.no_nist else find_nist(a.nist)
    for p in a.captures:
        assess(p, exe, a.conditioned)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
