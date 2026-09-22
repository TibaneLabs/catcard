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

**Full colour, with alpha.** The colour marks are stored RGBA8888, deflated, and never go
on the 4-bit canvas: the firmware writes them straight to the panel, which takes 16 bits a
pixel, blending each against the row it sits on (`art::rgba`). So a logo keeps every colour
it has and its anti-aliased edge -- nothing is quantized.
"""

import argparse
import pathlib
import sys

from PIL import Image

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
import deflate  # noqa: E402  -- beside this file

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
    ("NMC", "N", (0x18, 0x6C, 0x9D)),
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
    "N": ["#...#", "##..#", "#.#.#", "#.#.#", "#..##", "#...#", "#...#"],
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
    """RGBA tuples: the chain's colour as a disc, a white letter on it."""
    px = []
    for y in range(SIZE):
        for x in range(SIZE):
            if not disc(SIZE, x, y):
                px.append((0, 0, 0, 0))
            elif glyph_at(letter, SIZE, 2, x, y):
                px.append(WHITE + (255,))
            else:
                px.append(colour + (255,))
    return px


def load(path):
    """RGBA tuples, as the PNG has them."""
    im = Image.open(path).convert("RGBA")
    if im.size != (SIZE, SIZE):
        sys.exit(f"{path.name} is {im.size[0]}x{im.size[1]}, want {SIZE}x{SIZE}")
    return list(im.get_flattened_data())


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

    marks = []
    for ticker, letter, colour in CHAINS:
        png = a.src / f"{ticker}.png"
        px = load(png) if png.exists() else placeholder(letter, colour)
        raw = bytes(v for p in px for v in p)
        marks.append((ticker, png.exists(), deflate.deflate(raw), mono(letter)))

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
        '#[cfg(feature = "colour-marks")]',
        "use super::rgba::Rgba;",
        "use crate::scroll::Mark;",
        "",
    ]
    for ticker, real, data, (bpr, bits) in marks:
        what = "from its PNG" if real else "a placeholder"
        lines += ['#[cfg(feature = "colour-marks")]']
        lines += deflate.rust_array(f"{ticker}_DEFLATED", data)
        lines += [
            f"/// {ticker}, {SIZE}x{SIZE}, {what}.",
            '#[cfg(feature = "colour-marks")]',
            f"pub const {ticker}: Rgba = Rgba {{",
            f"    width: {SIZE},",
            f"    height: {SIZE},",
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
    # The mark a row should carry, decided here rather than at the call site: a board
    # whose panel cannot show colour does not have the colour art at all, so this is the
    # only place that can answer without a `cfg` in the menu code.
    lines += [
        "/// The mark for a ticker, in whichever forms this build has.",
        '#[cfg(feature = "colour-marks")]',
        "pub fn mark(ticker: &str) -> Option<Mark<'static>> {",
        "    Some(match ticker {",
    ]
    for ticker, *_ in marks:
        lines.append(
            f'        "{ticker}" => Mark::Art {{ colour: &{ticker}, mono: &{ticker}_MONO }},'
        )
    lines += ["        _ => return None,", "    })", "}", ""]
    lines += [
        "/// The mark for a ticker: one bit, on a board with no colour art baked in.",
        '#[cfg(not(feature = "colour-marks"))]',
        "pub fn mark(ticker: &str) -> Option<Mark<'static>> {",
        "    Some(match ticker {",
    ]
    for ticker, *_ in marks:
        lines.append(f'        "{ticker}" => Mark::Mono(&{ticker}_MONO),')
    lines += ["        _ => return None,", "    })", "}", ""]
    a.out.write_text("\n".join(lines))
    print(f"{len(marks)} marks, full colour -> {a.out}")


if __name__ == "__main__":
    main()
