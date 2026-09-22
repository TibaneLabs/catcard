#!/usr/bin/env python3
"""The paw print at the Q1's size: 27x30, one bit, facing right.

    tools/artgen/paw.py            # prints the Rust constant and an ASCII preview

The 9x10 print in `icons.rs` is pixel art scaled three times on the Q1, which leaves it
in 3x3 blocks. This draws the same print -- the pad behind, four toes in an arc ahead,
each where the small one has it -- from ellipses at the full 27x30, so the edges are
round and the footprint, and therefore every layout built on it, is unchanged.

Each pixel is set when most of a 4x4 grid of samples inside it falls in a shape, which
keeps the edges from depending on where one sample happens to land.
"""

W, H = 27, 30

# (centre x, centre y, radius x, radius y), in pixels of the 27x30 grid. Placed over the
# 9x10 print's own cells times three: pad in columns 0-5, rows 2-7; outer toes columns
# 5-6, rows 0-1 and 8-9; inner toes columns 7-8, rows 2-3 and 6-7.
PAD = (8.5, 15.0, 8.5, 8.0)
TOES = [
    (17.0, 3.8, 3.5, 3.7),
    (17.0, 26.2, 3.5, 3.7),
    (22.5, 10.0, 3.5, 3.5),
    (22.5, 20.0, 3.5, 3.5),
]


def inside(px, py, shape):
    cx, cy, rx, ry = shape
    return ((px - cx) / rx) ** 2 + ((py - cy) / ry) ** 2 <= 1.0


def pad(px, py):
    """The pad, with a shallow notch in its front edge, as a cat's has."""
    if not inside(px, py, PAD):
        return False
    notch = (PAD[0] + PAD[2] + 1.0, PAD[1], 3.0, 2.5)
    return not inside(px, py, notch)


def on(x, y):
    n = 0
    for sy in range(4):
        for sx in range(4):
            px, py = x + (sx + 0.5) / 4, y + (sy + 0.5) / 4
            if pad(px, py) or any(inside(px, py, t) for t in TOES):
                n += 1
    return n >= 8


def main():
    rows = [[on(x, y) for x in range(W)] for y in range(H)]
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
    print(f"width {W}, height {H}, bytes_per_row {bpr}")
    for i in range(0, len(data), 16):
        print("        " + " ".join(f"0x{b:02X}," for b in data[i : i + 16]))


if __name__ == "__main__":
    main()
