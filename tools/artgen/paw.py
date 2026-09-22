#!/usr/bin/env python3
"""The Q1's paw print, from its PNG into the `PAW_3X` constant in `icons.rs`.

    tools/artgen/paw.py crates/catcard-ui/src/art/paw-right-27x30.png

Prints the Rust constant and an ASCII preview; paste the result into
`crates/catcard-ui/src/icons.rs`.

One bit per pixel: a pixel is ink where the PNG is opaque and dark. The print must stay
27x30 -- three times the 9x10 print the mono panels use -- because the trail, the login
card's rows and the caret are all laid out from that footprint.
"""

import argparse
import pathlib
import sys

from PIL import Image

W, H = 27, 30


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("png", type=pathlib.Path)
    a = ap.parse_args()

    im = Image.open(a.png).convert("RGBA")
    if im.size != (W, H):
        sys.exit(f"{a.png.name} is {im.size[0]}x{im.size[1]}, want {W}x{H}")
    px = list(im.get_flattened_data())
    rows = [
        [
            px[y * W + x][3] > 127 and sum(px[y * W + x][:3]) < 400
            for x in range(W)
        ]
        for y in range(H)
    ]

    bpr = (W + 7) // 8
    data = []
    for r in rows:
        b = [0] * bpr
        for x, v in enumerate(r):
            if v:
                b[x // 8] |= 0x80 >> (x % 8)
        data += b
    for r in rows:
        print("// " + "".join("#" if v else "." for v in r))
    print(f"width {W}, height {H}, bytes_per_row {bpr}, {sum(map(sum, rows))} lit")
    for i in range(0, len(data), 16):
        print("        " + " ".join(f"0x{b:02X}," for b in data[i : i + 16]))


if __name__ == "__main__":
    main()
