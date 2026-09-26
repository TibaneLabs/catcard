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

With --hsm, HSM mode's commands too (Spending Policy -> HSM Mode must be on):

    ckcc hsm                      the status report, as JSON
    ckcc user NAME / auth / -d    make a TOTP user, a dry-run check, delete it
    ckcc hsm-start BAD.json       a policy naming an unknown user: refused, with why
    ckcc hsm-start POLICY.json    only with --simulator, which approves at once: then
                                  hsm says active, local-conf answers, and a user
                                  command is refused as not allowed in HSM mode

On a device the policy is not started: approving it puts the device in HSM mode until
it is powered off, which is the person's call and not a check's.

Usage:

    tools/ckcc_check.py [--ckcc PATH] [--psbt FILE] [--serial HEX] [--hsm]
    tools/ckcc_check.py --simulator [--hsm]   # against `cargo run -p catcard-usb --example ckcc_sim`

`--ckcc` defaults to $CKCC, then to the venv beside the repository
(`../work/ckcc-venv/bin/ckcc`), then to `ckcc` on the PATH. On Linux the device needs the
same kind of udev rule CatCard mode does, for `d13e:cc10` (see docs/USB.md).

Exit status 0 when every step passed. See docs/USB.md, "USB modes".
"""
import argparse
import ast
import json
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


def status(out):
    """`ckcc hsm` prints the report as a Python dict."""
    try:
        return ast.literal_eval(out.strip())
    except (ValueError, SyntaxError):
        return None


def hsm_checks(c, simulator):
    user = "ckccchk"
    c.step("hsm status", ["hsm"], lambda out: isinstance(status(out), dict) and "active" in status(out))
    c.step("new TOTP user", ["user", "-q", user], lambda out: "otpauth://totp/" in out)
    c.step("auth dry run (wrong code)", ["auth", user, "000000"], lambda out: "Problem" in out)
    with tempfile.TemporaryDirectory() as d:
        bad = os.path.join(d, "bad.json")
        with open(bad, "w") as f:
            json.dump({"rules": [{"users": ["no-such-user"]}]}, f)
        rc, out = c.run("hsm-start", bad)
        good = rc != 0 and "Unknown user" in out
        print(f"{'ok  ' if good else 'FAIL'} bad policy refused")
        if not good:
            c.failed += 1
            print(f"       {out}")
        if simulator:
            pol = os.path.join(d, "pol.json")
            with open(pol, "w") as f:
                json.dump({"period": 60, "rules": [{"max_amount": 1000, "local_conf": True, "users": [user]}]}, f)
            psbt = os.path.join(d, "t.psbt")
            with open(psbt, "wb") as f:
                f.write(b"psbt\xff" + b"0" * 64)
            c.step("policy started", ["hsm-start", pol], lambda out: "Approve" in out)
            c.step("hsm active", ["hsm"], lambda out: (status(out) or {}).get("active") is True)
            c.step("local-conf", ["local-conf", psbt], lambda out: any(w.isdigit() and len(w) == 6 for w in out.split()))
            rc, out = c.run("user", "-d", user)
            good = rc != 0 and "Not allowed in HSM mode" in out
            print(f"{'ok  ' if good else 'FAIL'} user commands refused in HSM mode")
            if not good:
                c.failed += 1
                print(f"       {out}")
            return
    c.step("delete user", ["user", "-d", user], lambda out: "Deleted" in out)


def main():
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--ckcc", default=default_ckcc(), help="the ckcc executable")
    ap.add_argument("--psbt", help="also sign this PSBT (approve it on the device)")
    ap.add_argument("--serial", help="the device's USB serial, if more than one is attached")
    ap.add_argument("--simulator", action="store_true", help="talk to the ckcc simulator socket")
    ap.add_argument("--timeout", type=int, default=60, help="seconds per command")
    ap.add_argument("--hsm", action="store_true", help="check the HSM commands too")
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

    if a.hsm:
        hsm_checks(c, a.simulator)

    print("all passed" if c.failed == 0 else f"{c.failed} failed")
    return 0 if c.failed == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
