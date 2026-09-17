#!/usr/bin/env python3
"""Bake the Flappy Bird sprite set into Rust tables for `catcard_ui::art::flappy`.

    tools/artgen/flappy2rs.py path/to/flappy-bird-assets crates/catcard-ui/src/art/flappy.rs

Source: https://github.com/samuelcust/flappy-bird-assets (MIT, (c) 2019 Samuel Custodio).

The PNGs are the game's 144x256 art drawn at 2x: every sprite used here splits into
exact 2x2 blocks, so taking the top-left pixel of each block is lossless and lands the
art at its own native resolution -- which on the Q1's 240-row panel is a 200-row
playfield over 40 rows of ground, the original's proportions.

Every sprite shares one RGB565 palette (the set has under 256 colours after RGB565
rounding) and stores one byte per pixel; 0xFF is transparent.
"""
import argparse, pathlib, subprocess, sys

from PIL import Image

TRANSPARENT = 0xFF

# (Rust name, file, rows to keep at half scale or None for all)
SPRITES = [
    ("BACKGROUND", "background-day.png", 200),
    ("BASE", "base.png", 40),
    ("PIPE", "pipe-green.png", None),
    ("BIRD_UP", "yellowbird-upflap.png", None),
    ("BIRD_MID", "yellowbird-midflap.png", None),
    ("BIRD_DOWN", "yellowbird-downflap.png", None),
    ("GAME_OVER", "gameover.png", None),
] + [(f"DIGIT_{d}", f"{d}.png", None) for d in range(10)]


def rgb565(r, g, b):
    return ((r >> 3) << 11) | ((g >> 2) << 5) | (b >> 3)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("assets", type=pathlib.Path)
    ap.add_argument("out", type=pathlib.Path)
    a = ap.parse_args()

    commit = subprocess.run(
        ["git", "-C", str(a.assets), "rev-parse", "HEAD"], capture_output=True, text=True
    ).stdout.strip() or "unknown"

    palette = []
    index = {}
    baked = []
    for name, file, keep in SPRITES:
        im = Image.open(a.assets / "sprites" / file).convert("RGBA")
        w, h = im.size[0] // 2, im.size[1] // 2
        if keep is not None:
            h = min(h, keep)
        p = im.load()
        px = []
        for y in range(h):
            for x in range(w):
                r, g, b, al = p[2 * x, 2 * y]
                if al < 128:
                    px.append(TRANSPARENT)
                    continue
                c = rgb565(r, g, b)
                if c not in index:
                    index[c] = len(palette)
                    palette.append(c)
                px.append(index[c])
        baked.append((name, file, w, h, px))
    if len(palette) >= TRANSPARENT:
        sys.exit(f"{len(palette)} colours: too many for one byte with a transparent index")

    out = []
    out.append("//! The Flappy Bird sprite set, at its native 144x256 scale. Generated -- do not edit.")
    out.append("//!")
    out.append(f"//! `tools/artgen/flappy2rs.py` from https://github.com/samuelcust/flappy-bird-assets")
    out.append(f"//! at `{commit}`.")
    out.append("//!")
    out.append("//! MIT License, Copyright (c) 2019 Samuel Custodio. See THIRD-PARTY-NOTICES.md.")
    out.append("")
    out.append("/// A sprite: one byte per pixel into [`PALETTE`], row-major; [`TRANSPARENT`] shows through.")
    out.append("pub struct Sprite {")
    out.append("    pub width: u16,")
    out.append("    pub height: u16,")
    out.append("    pub pixels: &'static [u8],")
    out.append("}")
    out.append("")
    out.append("impl Sprite {")
    out.append("    /// The RGB565 colour at `(x, y)`, or `None` where it is transparent or outside.")
    out.append("    pub fn at(&self, x: usize, y: usize) -> Option<u16> {")
    out.append("        if x >= self.width as usize || y >= self.height as usize {")
    out.append("            return None;")
    out.append("        }")
    out.append("        match self.pixels[y * self.width as usize + x] {")
    out.append("            TRANSPARENT => None,")
    out.append("            i => Some(PALETTE[i as usize]),")
    out.append("        }")
    out.append("    }")
    out.append("}")
    out.append("")
    out.append(f"pub const TRANSPARENT: u8 = 0x{TRANSPARENT:02X};")
    out.append("")
    out.append(f"pub const PALETTE: [u16; {len(palette)}] = [")
    for i in range(0, len(palette), 10):
        out.append("    " + " ".join(f"0x{c:04X}," for c in palette[i:i + 10]))
    out.append("];")
    for name, file, w, h, px in baked:
        out.append("")
        out.append(f"/// `sprites/{file}`, {w}x{h}.")
        out.append(f"pub const {name}: Sprite = Sprite {{")
        out.append(f"    width: {w},")
        out.append(f"    height: {h},")
        out.append("    pixels: &[")
        for i in range(0, len(px), w):
            out.append("        " + " ".join(f"{v}," for v in px[i:i + w]))
        out.append("    ],")
        out.append("};")
    out.append("")
    out.append("pub const DIGITS: [Sprite; 10] = [")
    for d in range(10):
        out.append(f"    DIGIT_{d},")
    out.append("];")
    a.out.write_text("\n".join(out) + "\n")
    total = sum(len(b[4]) for b in baked)
    print(f"{len(palette)} colours, {total} bytes of pixels -> {a.out}")


if __name__ == "__main__":
    main()
