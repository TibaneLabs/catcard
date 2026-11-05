#!/usr/bin/env python3
"""Read what is on a Precursor's memory LCD, over the stock USB debug bridge.

    sudo python3 -I screenshot.py OUT.pbm

Reads the gateware `memlcd` framebuffer (block RAM at 0xB0000000: 336x536, 11 words per
line, LSB leftmost, a set bit white -- see catcard-precursor/src/lcd.rs) and writes it as
a binary PBM, which any image tool opens. Read-only; works whatever firmware is running,
as long as the bridge is up. It shows what the panel was last sent, not a photograph:
anything the gateware adds on the way out (the devboot dashed line) is not in it.
"""
import array
import sys

import usb.core

BASE, W, H, WPL = 0xB0000000, 336, 536, 11


def main():
    dev = usb.core.find(idVendor=0x1209, idProduct=0x5BF0)
    if dev is None:
        sys.exit("Precursor not found on USB")
    dev.set_configuration()
    raw = b""
    total = WPL * H * 4
    for off in range(0, total, 4096):
        n = min(4096, total - off)
        buf = array.array("B", bytes(n))
        a = BASE + off
        if dev.ctrl_transfer(0xC3, 0, a & 0xFFFF, a >> 16, buf, 1000) != n:
            sys.exit("short read")
        raw += buf.tobytes()
    words = array.array("I", raw)          # little-endian host (Pi, x86)
    rows = bytearray()
    for y in range(H):
        line = bytearray(W // 8)
        for x in range(W):
            white = (words[y * WPL + x // 32] >> (x % 32)) & 1
            if not white:                  # PBM: 1 = black, MSB leftmost
                line[x // 8] |= 0x80 >> (x % 8)
        rows += line
    with open(sys.argv[1], "wb") as f:
        f.write(b"P4\n%d %d\n" % (W, H) + bytes(rows))


if __name__ == "__main__":
    main()
