#!/usr/bin/env python3
"""Check a CatCard in the ckcc USB mode with stock's own host tool, `ckcc`.

The device must be in Settings -> Hardware On/Off -> USB mode -> ckcc, unlocked, with a
wallet. This runs the `ckcc` command line (the `ckcc-protocol` package) as a black box --
nothing here speaks the protocol itself -- and checks that each answer has the shape the
tool's users rely on:

    ckcc version                  five lines, the second our version
    ckcc xpub                     the master xpub (tpub on testnet)
    ckcc xpub m/84h/0h/0h         an account xpub
    ckcc addr -s m/84h/0h/0h/0/0  an address; the device shows it too (any key clears it)
    ckcc sign PSBT OUT            only with --psbt: approve it on the device

Usage:

    tools/ckcc_check.py [--ckcc PATH] [--psbt FILE] [--serial HEX]
    tools/ckcc_check.py --simulator   # against `cargo run -p catcard-usb --example ckcc_sim`

`--ckcc` defaults to $CKCC, then to the venv beside the repository
(`../work/ckcc-venv/bin/ckcc`), then to `ckcc` on the PATH. On Linux the device needs the
same kind of udev rule CatCard mode does, for `d13e:cc10` (see docs/USB.md).

Exit status 0 when every step passed. See docs/USB.md, "USB modes".
"""
import argparse
import os
import shutil
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))


def default_ckcc():
    env = os.environ.get("CKCC")
    if env:
        return env
    venv = os.path.normpath(os.path.join(HERE, "..", "..", "work", "ckcc-venv", "bin", "ckcc"))
    if os.path.exists(venv):
        return venv
    return shutil.which("ckcc") or "ckcc"


class Check:
    def __init__(self, ckcc, prefix, timeout):
        self.ckcc = ckcc
        self.prefix = prefix
        self.timeout = timeout
        self.failed = 0

    def run(self, *args):
        cmd = [self.ckcc, *self.prefix, *args]
        try:
            p = subprocess.run(cmd, capture_output=True, text=True, timeout=self.timeout)
        except subprocess.TimeoutExpired:
            return None, "timed out"
        except FileNotFoundError:
            sys.exit(f"no ckcc at {self.ckcc!r}: pass --ckcc or set $CKCC")
        return p.returncode, (p.stdout + p.stderr).strip()

    def step(self, name, args, ok):
        rc, out = self.run(*args)
        good = rc == 0 and ok(out)
        print(f"{'ok  ' if good else 'FAIL'} {name}")
        if not good:
            self.failed += 1
            for line in (out or "").splitlines()[-6:]:
                print(f"       {line}")
        return out if good else None


def is_xpub(s):
    s = s.strip().splitlines()[-1] if s.strip() else ""
    return s[:4] in ("xpub", "tpub") and 100 <= len(s) <= 112


def is_address(s):
    lines = [x.strip() for x in s.splitlines() if x.strip()]
    if not lines:
        return False
    a = lines[-1]
    return a.startswith(("bc1", "tb1", "bcrt1")) or a[:1] in ("1", "3", "m", "n", "2")


def main():
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--ckcc", default=default_ckcc(), help="the ckcc executable")
    ap.add_argument("--psbt", help="also sign this PSBT (approve it on the device)")
    ap.add_argument("--serial", help="the device's USB serial, if more than one is attached")
    ap.add_argument("--simulator", action="store_true", help="talk to the ckcc simulator socket")
    ap.add_argument("--timeout", type=int, default=60, help="seconds per command")
    a = ap.parse_args()

    prefix = []
    if a.simulator:
        prefix.append("-x")
    if a.serial:
        prefix += ["-s", a.serial]
    c = Check(a.ckcc, prefix, a.timeout)
    print(f"using {a.ckcc}")

    c.step("version", ["version"], lambda out: len(out.splitlines()) >= 5)
    c.step("master xpub", ["xpub"], is_xpub)
    c.step("account xpub", ["xpub", "m/84h/0h/0h"], is_xpub)
    c.step("address (shown on the device)", ["addr", "-q", "-s", "m/84h/0h/0h/0/0"], is_address)
    if a.psbt:
        with tempfile.TemporaryDirectory() as d:
            out = os.path.join(d, "signed.psbt")
            print("     approve the transaction on the device ...")
            c.step("sign", ["sign", a.psbt, out], lambda _: os.path.getsize(out) > 0)

    print("all passed" if c.failed == 0 else f"{c.failed} failed")
    return 0 if c.failed == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
