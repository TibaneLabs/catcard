#!/usr/bin/env python3
"""Marks for a transaction review: one per kind of thing a transaction does.

    tools/artgen/txicons.py crates/catcard-ui/src/art/txicons.rs

A review is a column of cards, and the mark is what makes it readable as a column rather
than as a wall of sentences: the eye finds "there is a transfer and an approval in here"
from the shapes before it reads a word. So these are drawn to differ in *outline* first
and colour second -- the same rule the file marks follow, for the same reason, and on the
mk boards colour is not there at all.

Colour still carries meaning where it exists, and only three meanings:

- **teal** for value moving, which is the ordinary business of a transaction,
- **amber** for authority being given away -- an approval outlives this transaction,
- **red** for something this device could not read.

Drawn at 4x and reduced, like `fileicons.py`, so edges anti-alias against transparency
and the firmware can blend them onto a selected row without a halo.

Needs Pillow.
"""

import argparse
import pathlib
import sys

from PIL import Image, ImageDraw

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
import deflate  # noqa: E402  -- beside this file

SIZE = 20
MONO = 12
OVER = 4

# The device's palette, as the menu icons and the file marks use it.
ORANGE = (0xF2, 0x8C, 0x28, 0xFF)
EMBER = (0xC4, 0x5C, 0x18, 0xFF)
PAPER = (0xE6, 0xEA, 0xF0, 0xFF)
SLATE = (0x63, 0x75, 0x8F, 0xFF)
MIST = (0xB8, 0xC6, 0xD9, 0xFF)
TEAL = (0x62, 0xC3, 0xB0, 0xFF)
DEEP = (0x34, 0x88, 0x78, 0xFF)
GOLD = (0xFF, 0xD4, 0x5C, 0xFF)
RED = (0xE2, 0x4C, 0x4C, 0xFF)
BLOOD = (0xA8, 0x2A, 0x2A, 0xFF)


def canvas():
    im = Image.new("RGBA", (SIZE * OVER, SIZE * OVER), (0, 0, 0, 0))
    return im, ImageDraw.Draw(im)


def s(*v):
    """Coordinates, in icon pixels, scaled to the oversampled canvas."""
    return [x * OVER for x in v]


def coin(d, face=GOLD, edge=(0xD8, 0xA6, 0x3C, 0xFF)):
    """The disc a token amount is drawn on."""
    d.ellipse(s(2, 2, 18, 18), fill=edge)
    d.ellipse(s(3, 3, 17, 17), fill=face)


def draw_send(d):
    # An arrow leaving, on the diagonal a person reads as "out".
    d.line(s(4, 16, 14, 6), fill=DEEP, width=3 * OVER)
    d.polygon(s(16, 4, 16, 12, 8, 4), fill=TEAL)


def draw_token(d):
    coin(d)
    # A band across it, so a token is a coin with something written on it rather than a
    # plain circle -- which at twenty pixels is what a letter would become.
    d.rectangle(s(5, 9, 15, 11), fill=(0x8A, 0x6A, 0x22, 0xFF))
    d.rectangle(s(7, 6, 13, 8), fill=(0xD8, 0xA6, 0x3C, 0xFF))
    d.rectangle(s(7, 12, 13, 14), fill=(0xD8, 0xA6, 0x3C, 0xFF))


def draw_approve(d):
    # A key: what an approval hands over. Amber, because it outlives this transaction.
    d.ellipse(s(2, 6, 10, 14), fill=ORANGE)
    d.ellipse(s(4, 8, 8, 12), fill=(0, 0, 0, 0))
    d.rectangle(s(9, 9, 18, 11), fill=ORANGE)
    d.rectangle(s(14, 11, 16, 14), fill=EMBER)
    d.rectangle(s(17, 11, 18, 13), fill=EMBER)


def draw_nonce(d):
    # A clock: a durable nonce is what buys the time to sign somewhere else.
    d.ellipse(s(2, 2, 18, 18), fill=SLATE)
    d.ellipse(s(4, 4, 16, 16), fill=PAPER)
    d.line(s(10, 10, 10, 5), fill=SLATE, width=OVER)
    d.line(s(10, 10, 14, 12), fill=SLATE, width=OVER)


def draw_budget(d):
    # A gauge, for what the transaction is willing to spend on priority.
    d.pieslice(s(2, 4, 18, 20), 180, 360, fill=SLATE)
    d.pieslice(s(4, 6, 16, 18), 180, 360, fill=PAPER)
    d.line(s(10, 14, 15, 8), fill=EMBER, width=OVER)
    d.ellipse(s(8, 12, 12, 16), fill=SLATE)


def draw_account(d):
    # A new account: a plus, which is what opening one is.
    d.ellipse(s(2, 2, 18, 18), fill=DEEP)
    d.rectangle(s(9, 5, 11, 15), fill=PAPER)
    d.rectangle(s(5, 9, 15, 11), fill=PAPER)


def draw_payer(d):
    # A wallet: who pays the fee.
    d.rounded_rectangle(s(2, 5, 18, 16), radius=OVER, fill=SLATE)
    d.rounded_rectangle(s(2, 5, 18, 9), radius=OVER, fill=MIST)
    d.ellipse(s(12, 9, 16, 13), fill=GOLD)


def draw_signer(d):
    # A pen, for a signature slot: filled or waiting, the screen says which.
    d.polygon(s(3, 17, 5, 12, 7, 15), fill=MIST)
    d.line(s(6, 13, 16, 3), fill=SLATE, width=3 * OVER)
    d.line(s(15, 2, 18, 5), fill=GOLD, width=3 * OVER)


def draw_warning(d):
    # The one that has to be seen from across a room: a red triangle and a bang.
    d.polygon(s(10, 1, 19, 18, 1, 18), fill=BLOOD)
    d.polygon(s(10, 3, 17, 17, 3, 17), fill=RED)
    d.rectangle(s(9, 7, 11, 13), fill=PAPER)
    d.rectangle(s(9, 14, 11, 16), fill=PAPER)


# Kind, the Rust name, what it marks, and how to draw it.
KINDS = [
    ("Send", "value leaving", draw_send),
    ("Token", "a token amount", draw_token),
    ("Approve", "authority handed to somebody else", draw_approve),
    ("Nonce", "a durable nonce being spent", draw_nonce),
    ("Budget", "what the transaction will pay for priority", draw_budget),
    ("Account", "an account being opened", draw_account),
    ("Payer", "who pays the fee", draw_payer),
    ("Signer", "a signature slot", draw_signer),
    ("Warning", "something this device could not read", draw_warning),
]

# The one-bit forms, at the size the OLED draws them. `#` is ink.
#
# Written out rather than reduced: at twelve pixels a threshold of a scaled-down icon
# turns all of these into the same blob, and telling them apart is the entire job.
SILHOUETTES = {
    "Send": [
        "            ",
        "      ##### ",
        "      ##### ",
        "       #### ",
        "      ##### ",
        "     ##  ## ",
        "    ##   ## ",
        "   ##       ",
        "  ##        ",
        " ##         ",
        "            ",
        "            ",
    ],
    "Token": [
        "    ####    ",
        "  ########  ",
        " ##......## ",
        " #..####..# ",
        "##........##",
        "##.######.##",
        "##........##",
        " #..####..# ",
        " ##......## ",
        "  ########  ",
        "    ####    ",
        "            ",
    ],
    "Approve": [
        "            ",
        "   ####     ",
        "  ##..##    ",
        "  #....#    ",
        "  ##..##### ",
        "   #######  ",
        "       #  # ",
        "       ## # ",
        "            ",
        "            ",
        "            ",
        "            ",
    ],
    "Nonce": [
        "    ####    ",
        "  ########  ",
        " ###....### ",
        " ##..#...## ",
        "##...#....##",
        "##...####.##",
        "##........##",
        " ##......## ",
        " ###....### ",
        "  ########  ",
        "    ####    ",
        "            ",
    ],
    "Budget": [
        "            ",
        "    ####    ",
        "  ###..###  ",
        " ##.....### ",
        " #....###.# ",
        "##..###...##",
        "##.###....##",
        "##..##....##",
        "############",
        "            ",
        "            ",
        "            ",
    ],
    "Account": [
        "    ####    ",
        "  ########  ",
        " ####..#### ",
        " ###....### ",
        "###......###",
        "##........##",
        "###......###",
        " ###....### ",
        " ####..#### ",
        "  ########  ",
        "    ####    ",
        "            ",
    ],
    "Payer": [
        "            ",
        "            ",
        " ########## ",
        " #........# ",
        " ########## ",
        " ##########.",
        " #########.#",
        " #########.#",
        " ##########.",
        " ########## ",
        "            ",
        "            ",
    ],
    "Signer": [
        "            ",
        "          ##",
        "         ###",
        "        ### ",
        "       ###  ",
        "      ###   ",
        "     ###    ",
        "    ###     ",
        "  ####      ",
        "  ###       ",
        "  #         ",
        "            ",
    ],
    "Warning": [
        "     ##     ",
        "     ##     ",
        "    ####    ",
        "    #..#    ",
        "   ##..##   ",
        "   ##..##   ",
        "  ###..###  ",
        "  ###..###  ",
        " #### ####  ",
        " ####..#### ",
        "############",
        "############",
    ],
}


def colour_bytes(draw_fn):
    im, d = canvas()
    draw_fn(d)
    im = im.resize((SIZE, SIZE), Image.LANCZOS)
    return bytes(v for px in im.get_flattened_data() for v in px)


def mono_bits(name):
    rows = SILHOUETTES[name]
    if len(rows) != MONO:
        sys.exit(f"{name}: {len(rows)} rows, want {MONO}")
    bpr = (MONO + 7) // 8
    out = []
    for y, row in enumerate(rows):
        if len(row) != MONO:
            sys.exit(f"{name} row {y}: {len(row)} columns, want {MONO}")
        bits = [0] * bpr
        for x in range(MONO):
            if row[x] == "#":
                bits[x // 8] |= 0x80 >> (x % 8)
        out += bits
    return bpr, out


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("out", type=pathlib.Path)
    a = ap.parse_args()

    marks = [
        (name, what, deflate.deflate(colour_bytes(fn)), mono_bits(name))
        for name, what, fn in KINDS
    ]

    lines = [
        "//! What a line of a transaction review is: colour for the Q1, 1-bit for the OLED.",
        "//!",
        "//! Generated. Edit the drawing code and re-run:",
        "//!",
        "//! ```text",
        f"//! tools/artgen/txicons.py {a.out}",
        "//! ```",
        "//!",
        "//! A review is a column of cards, and these are what make it readable as a column:",
        "//! the shapes say what is in the transaction before a word of it is read. They",
        "//! differ in outline first and colour second, because the mk boards have no colour",
        "//! and the answer must be the same there.",
        "//!",
        "//! Where colour is there, it carries three meanings and no more: teal for value",
        "//! moving, amber for authority handed away, red for something this device could",
        "//! not read.",
        "",
        "use super::Bitmap;",
        '#[cfg(feature = "colour-marks")]',
        "use super::rgba::Rgba;",
        "use crate::scroll::Mark;",
        "",
    ]
    for name, what, data, (bpr, bits) in marks:
        upper = name.upper()
        lines += ['#[cfg(feature = "colour-marks")]']
        lines += deflate.rust_array(f"{upper}_DEFLATED", data)
        lines += [
            f"/// {name}: {what}. {SIZE}x{SIZE}, full colour.",
            '#[cfg(feature = "colour-marks")]',
            f"pub const {upper}: Rgba = Rgba {{",
            f"    width: {SIZE},",
            f"    height: {SIZE},",
            f"    deflated: &{upper}_DEFLATED,",
            "};",
            f"/// {name}, {MONO}x{MONO}, one bit.",
            "#[rustfmt::skip]",
            f"pub const {upper}_MONO: Bitmap = Bitmap {{",
            f"    width: {MONO},",
            f"    height: {MONO},",
            f"    bytes_per_row: {bpr},",
            "    pixels: &[" + ", ".join(f"0x{b:02X}" for b in bits) + "],",
            "};",
            "",
        ]

    lines += [
        "/// What a reviewed line is about.",
        "#[derive(Copy, Clone, PartialEq, Eq, Debug)]",
        "pub enum Kind {",
    ]
    for name, what, _, _ in marks:
        lines += [f"    /// {what[0].upper()}{what[1:]}.", f"    {name},"]
    lines += ["}", ""]

    lines += [
        "/// The mark for a kind, in whichever forms this build has.",
        '#[cfg(feature = "colour-marks")]',
        "pub fn mark(kind: Kind) -> Mark<'static> {",
        "    match kind {",
    ]
    for name, *_ in marks:
        u = name.upper()
        lines.append(f"        Kind::{name} => Mark::Art {{ colour: &{u}, mono: &{u}_MONO }},")
    lines += ["    }", "}", ""]
    lines += [
        "/// The mark for a kind: one bit, on a board with no colour art baked in.",
        '#[cfg(not(feature = "colour-marks"))]',
        "pub fn mark(kind: Kind) -> Mark<'static> {",
        "    match kind {",
    ]
    for name, *_ in marks:
        lines.append(f"        Kind::{name} => Mark::Mono(&{name.upper()}_MONO),")
    lines += ["    }", "}", ""]

    a.out.write_text("\n".join(lines))
    print(f"{len(marks)} review marks -> {a.out}")


if __name__ == "__main__":
    main()
