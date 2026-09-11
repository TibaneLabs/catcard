#!/usr/bin/env python3
"""Check a staged firmware image in a `--dump-ram` dump.

The last thing CatCard does before rebooting into an install is write the image into
PSRAM and publish a recovery header pointing at it. That write is the final irreversible
step of an upgrade and there is no way to see it from the outside, so this reads it back
out of a RAM dump and says whether it is what the bootloader needs.

    ccemu run ... --no-secure-die --dump-ram ram.bin      # stops at the logout call
    tools/emu/psramcheck.py ram.bin --image out/x.bin

`--no-secure-die` matters: it stops the machine at the logout callgate, one instruction
after the header is published and before the reset. Without it the dump is taken after
the reboot, and the emulator refills PSRAM with seeded noise at reset -- so the header is
legitimately gone and the check reports a failure that is about the emulator rather than
about the firmware.
"""
import argparse
import struct
import sys

MAGIC1 = 0xDBCC8350
MAGIC2 = 0xBAFCFBA3
PSRAM_BASE = 0x90000000
HEADER_AT = 0x7FF800          # 2 KB from the end of the 8 MB region


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("dump", help="file written by ccemu --dump-ram")
    ap.add_argument("--image", help="the .bin that should be staged")
    ap.add_argument("--psram-offset", type=lambda v: int(v, 0), default=655360,
                    help="where the psram bank starts in the dump; ccemu prints this")
    a = ap.parse_args()

    with open(a.dump, "rb") as f:
        f.seek(a.psram_offset + HEADER_AT)
        m1, start, size, m2 = struct.unpack("<IIII", f.read(16))
        f.seek(a.psram_offset)
        psram = f.read(8 * 1024 * 1024)

    ok = True
    for name, got, want in (("magic1", m1, MAGIC1), ("magic2", m2, MAGIC2)):
        good = got == want
        ok &= good
        print(f"{name:8} 0x{got:08X}  {'ok' if good else f'expected 0x{want:08X}'}")
    print(f"start    0x{start:08X}")
    print(f"size     {size}")

    if a.image:
        img = open(a.image, "rb").read()
        at = start - PSRAM_BASE
        staged = psram[at:at + len(img)] if 0 <= at < len(psram) else b""
        checks = [
            ("image bytes match", staged == img),
            ("size matches image", size == len(img)),
        ]
        for name, good in checks:
            ok &= good
            print(f"{name:18} {'ok' if good else 'MISMATCH'}")

    print("OK" if ok else "FAILED")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
