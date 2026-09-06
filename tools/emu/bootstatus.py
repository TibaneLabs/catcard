#!/usr/bin/env python3
"""Read CATCARD_BOOT_STATUS out of an emulator RAM dump.

The selftest screen shows the same numbers, but reading them off a framebuffer render
is guesswork — the glyphs are legible as pixel art and ambiguous as data. This is the
measured answer.
"""
import struct, sys

MAGIC = 0xCA7CA2D0


def main(path):
    data = open(path, "rb").read()
    at = data.find(struct.pack("<I", MAGIC))
    if at < 0:
        sys.exit(f"CATCARD_BOOT_STATUS not found in {len(data)} bytes — firmware may not have run")
    _, hal, entropy, bits, dwt = struct.unpack_from("<5I", data, at)
    ok = lambda v: "ok" if v else "FAIL"
    print(f"CATCARD_BOOT_STATUS @ RAM+{at:#x}")
    print(f"  HAL      {ok(hal)}")
    print(f"  DWT      {ok(dwt)}")
    print(f"  entropy  {ok(entropy)}  {bits} credited bits")
    if entropy and bits < 832:
        print("  note: below 832 means a secure-element TRNG did not contribute;")
        print("        256 exactly means neither did. See docs/VALIDATION.md.")
    return 0 if (hal and entropy and dwt) else 1


if __name__ == "__main__":
    sys.exit(main(sys.argv[1]))
