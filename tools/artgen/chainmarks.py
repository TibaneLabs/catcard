#!/usr/bin/env python3
"""Chain marks for the chain picker: a colour icon for the Q1 and a 1-bit one for the OLED.

    tools/artgen/chainmarks.py crates/catcard-ui/src/art/chain-icons \\
        crates/catcard-ui/src/art/chainicons.rs

For each chain, `<TICKER>.png` in the source directory is used if it is there -- 20x20,
RGBA, transparent where the page shows through. A chain with no PNG gets a **placeholder
mark**: its colour as a disc, a white letter on it. The placeholders exist so the picker
works before the real art does; dropping a PNG in and re-running replaces one.

The 1-bit mark is always drawn here, 12x12: the disc with the letter knocked out. A
colour logo thresholded to one bit reads worse than that at twelve pixels.

**The palette is the picker page's**, not the icons' own: index 0 is the list's
background and 15 its ink (amber, as every other list on the device), because the list's
rows and its selection bar are drawn in those two and the icons share the canvas with
them. Slots 1 to 14 are the icons' colours: when the marks bring more than fourteen between
them, which real logos do, they are quantized together to fourteen (`quantize`).
"""

import argparse
import pathlib
import sys

from PIL import Image

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
import deflate  # noqa: E402  -- beside this file

# The list's own ends, from `catcard_ui::st7789::AMBER`.
PAGE_BG = 0x0000
PAGE_INK = 0xFD60

# Ticker, placeholder letter, placeholder colour. The colours are each chain's familiar
# brand colour, near enough to tell them apart; the real marks replace them.
CHAINS = [
    ("BTC", "B", (0xF7, 0x93, 0x1A)),
    ("ETH", "E", (0x62, 0x7E, 0xEA)),
    ("SOL", "S", (0x99, 0x45, 0xFF)),
    ("LTC", "L", (0x34, 0x5D, 0x9D)),
    ("BCH", "C", (0x0A, 0xC1, 0x8E)),
    ("DOGE", "D", (0xC2, 0xA6, 0x33)),
    ("TRX", "T", (0xEB, 0x00, 0x29)),
    ("MONA", "M", (0xB8, 0x86, 0x3B)),
    ("XEP", "X", (0x1B, 0x9A, 0xAA)),
]

SIZE = 20
MONO = 12
WHITE = (0xFF, 0xFF, 0xFF)

# 5x7 capitals, '#' set.
GLYPHS = {
    "B": ["####.", "#...#", "#...#", "####.", "#...#", "#...#", "####."],
    "C": [".###.", "#...#", "#....", "#....", "#....", "#...#", ".###."],
    "D": ["####.", "#...#", "#...#", "#...#", "#...#", "#...#", "####."],
    "E": ["#####", "#....", "#....", "####.", "#....", "#....", "#####"],
    "L": ["#....", "#....", "#....", "#....", "#....", "#....", "#####"],
    "M": ["#...#", "##.##", "#.#.#", "#.#.#", "#...#", "#...#", "#...#"],
    "S": [".####", "#....", "#....", ".###.", "....#", "....#", "####."],
    "T": ["#####", "..#..", "..#..", "..#..", "..#..", "..#..", "..#.."],
    "X": ["#...#", "#...#", ".#.#.", "..#..", ".#.#.", "#...#", "#...#"],
}


def rgb565(c):
    r, g, b = c
    return ((r >> 3) << 11) | ((g >> 2) << 5) | (b >> 3)


def disc(size, x, y):
    c = (size - 1) / 2
    return (x - c) ** 2 + (y - c) ** 2 <= (size / 2) ** 2


def glyph_at(letter, size, scale, x, y):
    rows = GLYPHS[letter]
    gw, gh = 5 * scale, 7 * scale
    ox, oy = (size - gw) // 2, (size - gh) // 2
    gx, gy = x - ox, y - oy
    if not (0 <= gx < gw and 0 <= gy < gh):
        return False
    return rows[gy // scale][gx // scale] == "#"


def placeholder(letter, colour):
    """RGB tuples, None where transparent."""
    px = []
    for y in range(SIZE):
        for x in range(SIZE):
            if not disc(SIZE, x, y):
                px.append(None)
            elif glyph_at(letter, SIZE, 2, x, y):
                px.append(WHITE)
            else:
                px.append(colour)
    return px


# Below this alpha a pixel is page; at or above it, it is the logo's own colour.
#
# A hard edge, not a blend. Blending a downscaled logo's rim onto the page black made
# dozens of dark in-between shades, which the fourteen shared slots could not hold: they
# were mapped to whatever dark slot was nearest -- blue and teal specks round an orange
# coin -- and spent slots a logo's real colours needed. At twenty pixels a clean edge
# reads better than a smooth one drawn in the wrong colours.
ALPHA_CUT = 128


def load(path):
    im = Image.open(path).convert("RGBA")
    if im.size != (SIZE, SIZE):
        sys.exit(f"{path.name} is {im.size[0]}x{im.size[1]}, want {SIZE}x{SIZE}")
    return [None if a < ALPHA_CUT else (r, g, b) for r, g, b, a in im.get_flattened_data()]


def quantize(marks, colours=14, per=3):
    """Bring every mark's colours down to `colours` shared ones.

    The marks share one page palette with fourteen free slots, and real logos -- a
    gradient, a coin's shading -- bring far more than that between them.

    **Per logo first, then together.** One median cut over every pixel spends the slots
    by pixel count, so a logo drawn in thin strokes -- Solana's three bars -- loses its
    signature colour to the big discs around it. So each logo is cut to its own `per`
    colours first, and only then are the closest of those merged, weighted by how many
    pixels use them, until `colours` remain: every logo keeps its dominant colours, and
    what is merged away is what two logos nearly shared anyway.
    """

    def cut(pixels, n):
        strip = Image.new("RGB", (len(pixels), 1))
        strip.putdata(pixels)
        q = strip.quantize(colors=n, method=Image.Quantize.MEDIANCUT, dither=Image.Dither.NONE)
        pal = q.getpalette()
        counts = {}
        for i in q.get_flattened_data():
            counts[i] = counts.get(i, 0) + 1
        return [(tuple(pal[i * 3 : i * 3 + 3]), k) for i, k in counts.items()]

    if len({c for px in marks for c in px if c is not None}) <= colours:
        return marks

    # White is pinned: most of these logos draw their glyph in it, and merged with a
    # neighbour's cream it turns every one of them faintly yellow.
    def snap(c):
        return WHITE if min(c) >= 225 else c

    marks = [[None if c is None else snap(c) for c in px] for px in marks]

    picks = [[WHITE, 1]]  # [colour, weight]; white first, never merged
    for px in marks:
        opaque = [c for c in px if c is not None and c != WHITE]
        if opaque:
            picks += [[c, k] for c, k in cut(opaque, per)]

    def dist(a, b):
        return sum((x - y) ** 2 for x, y in zip(a, b))

    while len(picks) > colours:
        i, j = min(
            ((i, j) for i in range(1, len(picks)) for j in range(i + 1, len(picks))),
            key=lambda ij: dist(picks[ij[0]][0], picks[ij[1]][0]),
        )
        (a, wa), (b, wb) = picks[i], picks[j]
        merged = tuple((x * wa + y * wb) // (wa + wb) for x, y in zip(a, b))
        picks[i] = [merged, wa + wb]
        del picks[j]

    table = [c for c, _ in picks]

    def nearest(c):
        return min(table, key=lambda t: dist(t, c))

    return [[None if c is None else nearest(c) for c in px] for px in marks]


def mono(letter):
    """Rows of bytes, MSB first: the disc with the letter knocked out."""
    bpr = (MONO + 7) // 8
    out = []
    for y in range(MONO):
        row = [0] * bpr
        for x in range(MONO):
            if disc(MONO, x, y) and not glyph_at(letter, MONO, 1, x, y):
                row[x // 8] |= 0x80 >> (x % 8)
        out += row
    return bpr, out


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("src", type=pathlib.Path)
    ap.add_argument("out", type=pathlib.Path)
    a = ap.parse_args()

    sources = []
    for ticker, letter, colour in CHAINS:
        png = a.src / f"{ticker}.png"
        sources.append(load(png) if png.exists() else placeholder(letter, colour))
    sources = quantize(sources)

    slots = {}  # colour -> palette index 1..=14
    marks = []
    for (ticker, letter, colour), px in zip(CHAINS, sources):
        png = a.src / f"{ticker}.png"
        for c in px:
            if c is not None and c not in slots:
                if len(slots) == 14:
                    sys.exit("more than fourteen colours across the marks")
                slots[c] = len(slots) + 1
        packed = bytearray()
        for y in range(SIZE):
            row = [0 if c is None else slots[c] for c in px[y * SIZE : (y + 1) * SIZE]]
            for i in range(0, SIZE, 2):
                packed.append((row[i] << 4) | (row[i + 1] if i + 1 < SIZE else 0))
        marks.append((ticker, png.exists(), deflate.deflate(packed), mono(letter)))

    palette = [PAGE_BG] + [0] * 14 + [PAGE_INK]
    for c, i in slots.items():
        palette[i] = rgb565(c)

    lines = [
        "//! Chain marks for the chain picker: colour for the Q1, 1-bit for the OLED.",
        "//!",
        "//! Generated. Put `<TICKER>.png` (20x20) beside this file and re-run:",
        "//!",
        "//! ```text",
        f"//! tools/artgen/chainmarks.py {a.src} \\",
        f"//!     {a.out}",
        "//! ```",
        "//!",
        "//! A chain without a PNG has a placeholder: its colour as a disc and a letter.",
        "",
        "use super::Bitmap;",
        "use super::indexed::Indexed;",
        "",
        "/// The picker page's palette: the list's background and amber ink at 0 and 15, the",
        "/// marks' colours between.",
        "#[rustfmt::skip]",
        "pub const PALETTE: [u16; 16] = [",
        "    " + ", ".join(f"0x{v:04X}" for v in palette) + ",",
        "];",
        "",
    ]
    for ticker, real, data, (bpr, bits) in marks:
        what = "from its PNG" if real else "a placeholder"
        lines += deflate.rust_array(f"{ticker}_DEFLATED", data)
        lines += [
            f"/// {ticker}, {SIZE}x{SIZE}, {what}.",
            f"pub const {ticker}: Indexed = Indexed {{",
            f"    width: {SIZE},",
            f"    height: {SIZE},",
            "    palette: PALETTE,",
            f"    deflated: &{ticker}_DEFLATED,",
            "};",
            f"/// {ticker}, {MONO}x{MONO}, one bit.",
            "#[rustfmt::skip]",
            f"pub const {ticker}_MONO: Bitmap = Bitmap {{",
            f"    width: {MONO},",
            f"    height: {MONO},",
            f"    bytes_per_row: {bpr},",
            "    pixels: &[" + ", ".join(f"0x{b:02X}" for b in bits) + "],",
            "};",
            "",
        ]
    lines += [
        "/// The colour and 1-bit marks for a ticker, if there are any.",
        "pub fn mark(ticker: &str) -> Option<(&'static Indexed, &'static Bitmap)> {",
        "    Some(match ticker {",
    ]
    for ticker, *_ in marks:
        lines.append(f'        "{ticker}" => (&{ticker}, &{ticker}_MONO),')
    lines += ["        _ => return None,", "    })", "}", ""]
    a.out.write_text("\n".join(lines))
    print(f"{len(marks)} marks, {len(slots)} colours -> {a.out}")


if __name__ == "__main__":
    main()
