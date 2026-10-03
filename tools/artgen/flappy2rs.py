#!/usr/bin/env python3
"""Bake Flappy Cat's sprites into Rust tables for `catcard_ui::art::flappy`.

    tools/artgen/flappy2rs.py crates/catcard-ui/src/art/flappy-bird-assets \
        crates/catcard-ui/src/art/flappy-cat crates/catcard-ui/src/art/flappy.rs

Scenery, pipes, digits and the banner: the sprites this game uses from
https://github.com/samuelcust/flappy-bird-assets (MIT, (c) 2019 Samuel Custodio), vendored
with their licence and the upstream commit in `UPSTREAM`.

The PNGs are the game's 144x256 art drawn at 2x: every sprite used here splits into
exact 2x2 blocks, so taking the top-left pixel of each block is lossless and lands the
art at its own native resolution -- which on the Q1's 240-row panel is a 200-row
playfield over 40 rows of ground, the original's proportions.

The flying cat is different: `flying-orange-cat-{up,mid,down}-34x24.png` are drawn at 1x,
so they are kept at full size, cropped to the box every frame's opaque pixels fit in. They
were made from a photo of the real cat and read washed out against the game's scenery, so
each of their colours is replaced on the way in (CAT_COLOURS): the fur is pure orange, its
shades full-saturation oranges, cream and off-white pure white, the outline kept. A colour
the table does not name stops the bake rather than slipping through unchanged.

Every sprite shares one RGB565 palette (the set has under 256 colours after RGB565
rounding) and stores one byte per pixel; 0xFF is transparent.

Each sprite keeps its distinct rows once, plus a byte per row saying which of them it is.
The scenery is mostly rows that repeat -- sky, the body of a pipe, the ground's stripes --
so the 45 KB of pixels come to about 15, and a pixel is still one lookup away.

Those 15 KB are then deflated as one stream, about 2.3 KB in flash; the game inflates them
into a heap block when it starts (`unpack`) and returns it when it ends.
"""
import argparse, pathlib, sys, zlib

from deflate import rust_array

from PIL import Image

TRANSPARENT = 0xFF

# The cat PNGs' colours, and what each becomes.
CAT_COLOURS = {
    (33, 23, 19): (33, 23, 19),  # outline
    (59, 36, 24): (59, 36, 24),  # dark outline
    (117, 64, 31): (200, 90, 0),  # stripes: deep orange
    (168, 95, 49): (255, 128, 0),  # fur: pure orange
    (200, 135, 77): (255, 165, 0),  # light fur: light orange
    (217, 121, 120): (255, 120, 150),  # ears and nose: pink
    (229, 197, 141): (255, 255, 255),  # cream: white
    (255, 245, 220): (255, 255, 255),  # off-white: white
    (255, 255, 255): (255, 255, 255),  # white
}

# (Rust name, file, rows to keep at half scale or None for all)
SPRITES = [
    ("BACKGROUND", "background-day.png", 200),
    ("BASE", "base.png", 40),
    ("PIPE", "pipe-green.png", None),
    ("GAME_OVER", "gameover.png", None),
] + [(f"DIGIT_{d}", f"{d}.png", None) for d in range(10)]

# (Rust name, file) at 1x, cropped together.
CATS = [
    ("CAT_UP", "flying-orange-cat-up-34x24.png"),
    ("CAT_MID", "flying-orange-cat-mid-34x24.png"),
    ("CAT_DOWN", "flying-orange-cat-down-34x24.png"),
]


def cat_colour(r, g, b):
    try:
        return CAT_COLOURS[(r, g, b)]
    except KeyError:
        sys.exit(f"cat sprite colour {(r, g, b)} is not in CAT_COLOURS")


def rgb565(r, g, b):
    return ((r >> 3) << 11) | ((g >> 2) << 5) | (b >> 3)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("assets", type=pathlib.Path)
    ap.add_argument("cats", type=pathlib.Path)
    ap.add_argument("out", type=pathlib.Path)
    a = ap.parse_args()

    commit = (a.assets / "UPSTREAM").read_text().split()[1]

    palette = []
    index = {}
    baked = []

    def bake(name, where, file, p, x0, y0, w, h, step, tint=None):
        px = []
        for y in range(h):
            for x in range(w):
                r, g, b, al = p[x0 + step * x, y0 + step * y]
                if al < 128:
                    px.append(TRANSPARENT)
                    continue
                if tint:
                    r, g, b = tint(r, g, b)
                c = rgb565(r, g, b)
                if c not in index:
                    index[c] = len(palette)
                    palette.append(c)
                px.append(index[c])
        baked.append((name, where + file, w, h, px))

    for name, file, keep in SPRITES:
        im = Image.open(a.assets / "sprites" / file).convert("RGBA")
        w, h = im.size[0] // 2, im.size[1] // 2
        if keep is not None:
            h = min(h, keep)
        bake(name, "flappy-bird-assets/sprites/", file, im.load(), 0, 0, w, h, 2)

    cats = [(n, f, Image.open(a.cats / f).convert("RGBA")) for n, f in CATS]
    boxes = [im.getchannel("A").point(lambda v: 255 if v >= 128 else 0).getbbox() for _, _, im in cats]
    x0, y0 = min(b[0] for b in boxes), min(b[1] for b in boxes)
    x1, y1 = max(b[2] for b in boxes), max(b[3] for b in boxes)
    for name, file, im in cats:
        bake(name, "flappy-cat/", file, im.load(), x0, y0, x1 - x0, y1 - y0, 1, cat_colour)
    if len(palette) >= TRANSPARENT:
        sys.exit(f"{len(palette)} colours: too many for one byte with a transparent index")

    # Every sprite's row map and distinct rows, one after another, deflated as one stream.
    # The game inflates it into a heap block when it starts and gives the block back when
    # it ends, so the art costs its compressed size in flash and nothing in RAM otherwise.
    blob = bytearray()
    spans = []
    for name, file, w, h, px in baked:
        rows, uniq = [], []
        for y in range(h):
            row = tuple(px[y * w:(y + 1) * w])
            if row not in uniq:
                uniq.append(row)
            rows.append(uniq.index(row))
        if len(uniq) > 256:
            sys.exit(f"{name} has {len(uniq)} distinct rows: too many for a byte each")
        at_rows = len(blob)
        blob += bytes(rows)
        at_pixels = len(blob)
        for row in uniq:
            blob += bytes(row)
        spans.append((name, file, w, h, at_rows, at_pixels))
    if len(blob) > 0xFFFF:
        sys.exit(f"{len(blob)} bytes unpacked: past what a u16 offset reaches")
    # The full 32 KB window: the device inflates into a buffer that holds the whole
    # output, which is its own history, so no window of its own is needed.
    c = zlib.compressobj(9, zlib.DEFLATED, -15, 9)
    packed = c.compress(bytes(blob)) + c.flush()

    out = []
    out.append("//! Flappy Cat's sprites. Generated by `tools/artgen/flappy2rs.py` -- do not edit.")
    out.append("//!")
    out.append(f"//! Scenery, pipes, digits and the game-over banner: https://github.com/samuelcust/flappy-bird-assets")
    out.append(f"//! at `{commit}`, halved to their native 144x256 scale. MIT License, Copyright (c) 2019")
    out.append("//! Samuel Custodio. The flying cat: `art/flappy-cat/`. See THIRD-PARTY-NOTICES.md.")
    out.append("//!")
    out.append("//! The pixels are in flash deflated, and only there: [`unpack`] inflates them into a")
    out.append("//! buffer the game borrows for as long as it runs, and every [`Sprite`] is a place in")
    out.append("//! that buffer. Sizes are constants, so the layout is settled at compile time.")
    out.append("")
    out.append("/// A sprite: one byte per pixel into [`PALETTE`]; [`TRANSPARENT`] shows through.")
    out.append("///")
    out.append("/// Stored as its distinct rows, each once, and which of them each row of the picture is:")
    out.append("/// the scenery repeats rows far more than it has new ones. Both live in the unpacked")
    out.append("/// [`Art`], at the offsets here.")
    out.append("pub struct Sprite {")
    out.append("    pub width: u16,")
    out.append("    pub height: u16,")
    out.append("    /// Where the `height`-byte row map starts: for each row, which distinct row it is.")
    out.append("    rows: u16,")
    out.append("    /// Where the distinct rows start, `width` bytes each, in the order first used.")
    out.append("    pixels: u16,")
    out.append("}")
    out.append("")
    out.append("impl Sprite {")
    out.append("    /// The palette index at `(x, y)`, [`TRANSPARENT`] included, or `None` outside.")
    out.append("    #[inline(always)]")
    out.append("    pub fn index(&self, art: &Art<'_>, x: usize, y: usize) -> Option<u8> {")
    out.append("        if x >= self.width as usize || y >= self.height as usize {")
    out.append("            return None;")
    out.append("        }")
    out.append("        let row = *art.0.get(self.rows as usize + y)? as usize;")
    out.append("        art.0")
    out.append("            .get(self.pixels as usize + row * self.width as usize + x)")
    out.append("            .copied()")
    out.append("    }")
    out.append("")
    out.append("    /// The RGB565 colour at `(x, y)`, or `None` where it is transparent or outside.")
    out.append("    #[inline(always)]")
    out.append("    pub fn at(&self, art: &Art<'_>, x: usize, y: usize) -> Option<u16> {")
    out.append("        match self.index(art, x, y)? {")
    out.append("            TRANSPARENT => None,")
    out.append("            i => PALETTE.get(i as usize).copied(),")
    out.append("        }")
    out.append("    }")
    out.append("}")
    out.append("")
    out.append("/// The sprites' pixels, unpacked: made only by [`unpack`], so a sprite is never read")
    out.append("/// from a buffer that is short or holds anything else.")
    out.append("pub struct Art<'a>(&'a [u8]);")
    out.append("")
    out.append("/// Bytes [`unpack`] needs to inflate into.")
    out.append(f"pub const UNPACKED_LEN: usize = {len(blob)};")
    out.append("")
    out.append("/// Inflate the sprites into `buf`, which must be at least [`UNPACKED_LEN`] bytes.")
    out.append("///")
    out.append("/// A stream that comes out any other length than the one baked is refused rather than")
    out.append("/// drawn: that is flash that is not what was built.")
    out.append("pub fn unpack(buf: &mut [u8]) -> Result<Art<'_>, compcol::embed::flate::Error> {")
    out.append("    let buf = buf.get_mut(..UNPACKED_LEN).ok_or(compcol::embed::flate::Error::OutputFull)?;")
    out.append("    let n = compcol::embed::flate::inflate(&PACKED[..], compcol::embed::flate::Buffer::new(buf))?;")
    out.append("    if n != UNPACKED_LEN as u64 {")
    out.append("        return Err(compcol::embed::flate::Error::OutputFull);")
    out.append("    }")
    out.append("    Ok(Art(buf))")
    out.append("}")
    out.append("")
    out.append(f"pub const TRANSPARENT: u8 = 0x{TRANSPARENT:02X};")
    out.append("")
    out.append(f"pub const PALETTE: [u16; {len(palette)}] = [")
    for i in range(0, len(palette), 10):
        out.append("    " + " ".join(f"0x{c:04X}," for c in palette[i:i + 10]))
    out.append("];")
    for name, file, w, h, at_rows, at_pixels in spans:
        out.append("")
        out.append(f"/// `art/{file}`, {w}x{h}.")
        out.append(f"pub const {name}: Sprite = Sprite {{")
        out.append(f"    width: {w},")
        out.append(f"    height: {h},")
        out.append(f"    rows: {at_rows},")
        out.append(f"    pixels: {at_pixels},")
        out.append("};")
    out.append("")
    out.append("pub const DIGITS: [Sprite; 10] = [")
    for d in range(10):
        out.append(f"    DIGIT_{d},")
    out.append("];")
    out.append("")
    out.append(f"/// Every sprite's row map and distinct rows, raw deflate: {len(blob)} bytes unpacked.")
    out += rust_array("PACKED", packed)
    stored = len(packed)
    a.out.write_text("\n".join(out) + "\n")
    total = sum(len(b[4]) for b in baked)
    print(f"{len(palette)} colours, {total} pixels in {len(blob)} bytes, {stored} deflated -> {a.out}")


if __name__ == "__main__":
    main()
