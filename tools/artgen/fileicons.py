#!/usr/bin/env python3
"""File-kind marks for the card browser: colour for the Q1, 1-bit for the OLED.

    tools/artgen/fileicons.py crates/catcard-ui/src/art/fileicons.rs

Unlike the chain marks and the menu grid, these are **drawn here** rather than loaded
from PNGs. There are eight of them, they are the same few shapes -- a page, a folder, a
box -- and a listing shows a column of them at 20 pixels, where what matters is that two
kinds cannot be mistaken for each other at a glance. That is a drawing problem with a
short answer, and keeping the answer in code means the set stays consistent when a kind
is added: one palette, one page shape, one corner fold.

The colour form is drawn at 4x and reduced, so edges are anti-aliased against
transparency the way the chain logos are -- the firmware blends them onto the row itself
(`art::rgba`), so an icon sits on a selected row without a halo.

The 1-bit form is not drawn from the colour one. Twelve pixels is too few for a
threshold of a reduced image to survive: a folder and a page both become a grey blob. So
each one is written out as twelve rows of twelve characters below, where what the OLED
will show is what the source looks like.

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
# Drawn at this multiple and reduced, which is where the anti-aliasing comes from.
OVER = 4

# The palette the menu icons already use, so a listing and the grid look like one
# device. Source: crates/catcard-ui/src/art/menu-icons/palette.txt
ORANGE = (0xF2, 0x8C, 0x28, 0xFF)
EMBER = (0xC4, 0x5C, 0x18, 0xFF)
WHITE = (0xFF, 0xFF, 0xFF, 0xFF)
PAPER = (0xE6, 0xEA, 0xF0, 0xFF)
SLATE = (0x63, 0x75, 0x8F, 0xFF)
MIST = (0xB8, 0xC6, 0xD9, 0xFF)
TEAL = (0x62, 0xC3, 0xB0, 0xFF)
DEEP = (0x34, 0x88, 0x78, 0xFF)
GOLD = (0xFF, 0xD4, 0x5C, 0xFF)
BLUSH = (0xF5, 0xC1, 0xC9, 0xFF)


def canvas():
    im = Image.new("RGBA", (SIZE * OVER, SIZE * OVER), (0, 0, 0, 0))
    return im, ImageDraw.Draw(im)


def s(*v):
    """Coordinates, in icon pixels, scaled to the oversampled canvas."""
    return [x * OVER for x in v]


def page(d, body=PAPER, edge=MIST, fold=MIST):
    """The sheet every document kind is built on: a page with its corner turned."""
    d.polygon(
        s(3, 1, 12, 1, 17, 6, 17, 19, 3, 19),
        fill=body,
        outline=edge,
        width=OVER,
    )
    # The turned corner, as its own darker triangle.
    d.polygon(s(12, 1, 17, 6, 12, 6), fill=fold)


def rule(d, y, x0=6, x1=14, colour=SLATE, weight=1):
    d.rectangle(s(x0, y, x1, y + weight), fill=colour)


def draw_folder(d):
    # The tab, then the body over it, so the two read as one object.
    d.polygon(s(2, 3, 8, 3, 10, 6, 2, 6), fill=EMBER)
    d.rounded_rectangle(s(2, 5, 18, 17), radius=OVER, fill=ORANGE)
    # A lighter lip along the top of the body: the only shading, and what stops the
    # folder reading as a plain orange rectangle at this size.
    d.rectangle(s(3, 6, 17, 7), fill=(0xF8, 0xA8, 0x55, 0xFF))


def draw_image(d):
    d.rounded_rectangle(s(2, 3, 18, 17), radius=OVER, fill=(0x2E, 0x4A, 0x5E, 0xFF))
    d.rounded_rectangle(s(3, 4, 17, 16), radius=OVER // 2, fill=(0x9E, 0xD8, 0xEE, 0xFF))
    d.ellipse(s(5, 6, 8, 9), fill=GOLD)
    # Two hills, the nearer one in front, so the picture is a landscape and not a wedge.
    d.polygon(s(3, 16, 9, 8, 14, 16), fill=DEEP)
    d.polygon(s(8, 16, 13, 10, 17, 16), fill=TEAL)


def draw_text(d):
    page(d)
    for y in (8, 11, 14):
        rule(d, y)
    rule(d, 5, 6, 11)


def draw_transaction(d):
    page(d)
    # An arrow leaving the page: what a transaction does, at a size where a coin glyph
    # would be four grey pixels.
    d.rectangle(s(5, 11, 12, 13), fill=DEEP)
    d.polygon(s(11, 8, 16, 12, 11, 16), fill=TEAL)
    rule(d, 5, 6, 11, MIST)


def draw_signature(d):
    page(d)
    rule(d, 5, 6, 11, MIST)
    rule(d, 8, 6, 13, MIST)
    # A tick, in two strokes.
    d.line(s(6, 13, 9, 16), fill=TEAL, width=2 * OVER)
    d.line(s(9, 16, 15, 9), fill=TEAL, width=2 * OVER)


def draw_firmware(d):
    # A chip: legs first, body over them.
    for y in (6, 10, 14):
        d.rectangle(s(1, y, 4, y + 1), fill=MIST)
        d.rectangle(s(16, y, 19, y + 1), fill=MIST)
    d.rounded_rectangle(s(4, 4, 16, 16), radius=OVER // 2, fill=SLATE)
    d.rounded_rectangle(s(7, 7, 13, 13), radius=OVER // 2, fill=GOLD)


def draw_archive(d):
    # A box, with a band across it: backups arrive as one of these.
    d.polygon(s(2, 6, 10, 2, 18, 6, 10, 10), fill=GOLD)
    d.polygon(s(2, 6, 10, 10, 10, 18, 2, 14), fill=(0xD8, 0xA6, 0x3C, 0xFF))
    d.polygon(s(18, 6, 10, 10, 10, 18, 18, 14), fill=(0xEC, 0xBC, 0x4A, 0xFF))
    d.line(s(6, 4, 14, 16), fill=BLUSH, width=OVER)


def draw_file(d):
    page(d)


# Kind, the Rust name, what it is for, and how to draw it.
KINDS = [
    ("Folder", "a directory", draw_folder),
    ("Image", "a picture the Q1 can show", draw_image),
    ("Text", "something a person can read", draw_text),
    ("Transaction", "a PSBT", draw_transaction),
    ("Signature", "a detached signature", draw_signature),
    ("Firmware", "an image for this device", draw_firmware),
    ("Archive", "a backup or an archive", draw_archive),
    ("File", "anything else", draw_file),
]

# The one-bit forms, at the size the OLED draws them. `#` is ink.
#
# Written out rather than reduced from the colour art: at twelve pixels a threshold of a
# scaled-down icon turns every one of these into the same blob, and the whole point of
# the column is telling them apart.
SILHOUETTES = {
    # Solid, not outlined. At twelve pixels an outline is one pixel of ink around a
    # hole, and on a panel this size that reads as a smudge; a filled shape with the
    # detail knocked *out* of it keeps its outline at a glance.
    "Folder": [
        "            ",
        " #####      ",
        " #####      ",
        " ########## ",
        " ########## ",
        " ########## ",
        " ########## ",
        " ########## ",
        " ########## ",
        " ########## ",
        "            ",
        "            ",
    ],
    "Image": [
        "            ",
        " ########## ",
        " #........# ",
        " #.##.....# ",
        " #.##.....# ",
        " #.......## ",
        " #....##.## ",
        " #...####.# ",
        " #.######## ",
        " ########## ",
        "            ",
        "            ",
    ],
    "Text": [
        "  ######    ",
        "  ######    ",
        "  #######   ",
        "  ########  ",
        "  #......#  ",
        "  ########  ",
        "  #.....##  ",
        "  ########  ",
        "  #......#  ",
        "  ########  ",
        "  #.....##  ",
        "  ########  ",
    ],
    "Transaction": [
        "  ######    ",
        "  ######    ",
        "  #######   ",
        "  ########  ",
        "  ########  ",
        "  ####.###  ",
        "  #####.##  ",
        "  #......#  ",
        "  #####.##  ",
        "  ####.###  ",
        "  ########  ",
        "  ########  ",
    ],
    "Signature": [
        "  ######    ",
        "  ######    ",
        "  #######   ",
        "  ########  ",
        "  #......#  ",
        "  ########  ",
        "  ######.#  ",
        "  #####.##  ",
        "  ##.#.###  ",
        "  ###.####  ",
        "  ########  ",
        "  ########  ",
    ],
    "Firmware": [
        "   #  #  #  ",
        "  ######### ",
        "  ######### ",
        " ########## ",
        "  ##.....## ",
        "  ##.....## ",
        " ###.....## ",
        "  ##.....## ",
        "  ######### ",
        " ########## ",
        "  ######### ",
        "   #  #  #  ",
    ],
    "Archive": [
        "            ",
        "            ",
        "  ########  ",
        " ########## ",
        " ###.##.### ",
        " ###.##.### ",
        " ###.##.### ",
        " ###.##.### ",
        " ###.##.### ",
        " ########## ",
        "            ",
        "            ",
    ],
    "File": [
        "  ######    ",
        "  ######    ",
        "  #######   ",
        "  ########  ",
        "  ########  ",
        "  ########  ",
        "  ########  ",
        "  ########  ",
        "  ########  ",
        "  ########  ",
        "  ########  ",
        "  ########  ",
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
        "//! What a row in the card browser is: colour for the Q1, 1-bit for the OLED.",
        "//!",
        "//! Generated. Edit the drawing code and re-run:",
        "//!",
        "//! ```text",
        f"//! tools/artgen/fileicons.py {a.out}",
        "//! ```",
        "//!",
        "//! Eight kinds, decided from the name by [`Kind::of`]. A listing is a column of",
        "//! these at twenty pixels, so what they have to do is be unmistakable for each",
        "//! other -- which is why the shapes differ in outline and not only in colour.",
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
        "/// What a listed name turns out to be.",
        "#[derive(Copy, Clone, PartialEq, Eq, Debug)]",
        "pub enum Kind {",
    ]
    for name, what, _, _ in marks:
        lines += [f"    /// {what[0].upper()}{what[1:]}.", f"    {name},"]
    lines += ["}", ""]

    lines += [
        "impl Kind {",
        "    /// What a name in a listing looks like.",
        "    ///",
        "    /// By extension, which is all a listing has: nothing has been opened yet, and",
        "    /// opening every file to look at its first bytes would turn scrolling a folder",
        "    /// into reading all of it. A name that lies costs a wrong picture and nothing",
        "    /// else -- whatever acts on the file decides for itself what it is holding.",
        "    pub fn of(name: &str, is_dir: bool) -> Kind {",
        "        if is_dir {",
        "            return Kind::Folder;",
        "        }",
        "        let ext = match name.rsplit_once('.') {",
        "            Some((_, e)) => e,",
        "            None => return Kind::File,",
        "        };",
        "        // Lower-cased into a small buffer: FAT hands back `BACKUP.7Z` as often as",
        "        // `backup.7z`, and an extension longer than this is not one of ours.",
        "        let mut buf = [0u8; 8];",
        "        if ext.len() > buf.len() {",
        "            return Kind::File;",
        "        }",
        "        for (b, c) in buf.iter_mut().zip(ext.bytes()) {",
        "            *b = c.to_ascii_lowercase();",
        "        }",
        "        match &buf[..ext.len()] {",
        '            b"png" | b"jpg" | b"jpeg" | b"gif" | b"bmp" => Kind::Image,',
        '            b"txt" | b"md" | b"log" | b"csv" | b"json" | b"toml" => Kind::Text,',
        '            b"psbt" | b"txn" => Kind::Transaction,',
        '            b"sig" | b"asc" => Kind::Signature,',
        '            b"bin" | b"dfu" => Kind::Firmware,',
        '            b"7z" | b"zip" | b"gz" | b"tar" => Kind::Archive,',
        "            _ => Kind::File,",
        "        }",
        "    }",
        "}",
        "",
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
    print(f"{len(marks)} file marks -> {a.out}")


if __name__ == "__main__":
    main()
