#!/usr/bin/env python3
"""Drive a CatCard bench build over the debug UART and print what it says.

    sudo python3 -I drive.py [--uart /dev/ttyAMA0] [--gap 0.6] [--wait 2] KEYS...

Each KEYS argument is sent byte by byte with `--gap` seconds between bytes, so every
press gets its screen drawn before the next. Escapes: `\\n` confirm, `\\b` back, and
`U` `D` `L` `R` the navigation pad (see catcard-precursor src/input.rs; needs a build
with the `uart-keys` feature). Prints the firmware's UART output as it arrives, and for
`--wait` seconds after the last key.
"""
import argparse
import os
import select
import subprocess
import sys
import time


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("keys", nargs="*")
    ap.add_argument("--uart", default="/dev/ttyAMA0")
    ap.add_argument("--gap", type=float, default=0.6)
    ap.add_argument("--wait", type=float, default=2.0)
    a = ap.parse_args()
    subprocess.run(["stty", "-F", a.uart, "115200", "raw", "-echo", "cs8", "-cstopb", "-parenb"], check=True)
    fd = os.open(a.uart, os.O_RDWR | os.O_NONBLOCK)

    def drain(until):
        while True:
            left = until - time.time()
            if left <= 0:
                return
            r, _, _ = select.select([fd], [], [], left)
            if r:
                sys.stdout.write(os.read(fd, 4096).decode("utf-8", "replace").replace("\r", ""))
                sys.stdout.flush()

    seq = "".join(a.keys).encode().decode("unicode_escape").encode("latin-1")
    for b in seq:
        os.write(fd, bytes([b]))
        drain(time.time() + a.gap)
    drain(time.time() + a.wait)


if __name__ == "__main__":
    main()
