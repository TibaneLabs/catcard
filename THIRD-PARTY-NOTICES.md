# Third-party notices

CatCard is MIT, © Karpeles Lab Inc. It also distributes the material below, whose
licences require their notices to travel with it.

---

## zevv-peep bitmap fonts

`crates/catcard-ui/src/font/peep7x14.rs` and `peep10x20.rs` are converted, unmodified in
glyph content, from `zevv-peep-iso8859-15-07x14.bdf` and `-10x20.bdf`.

By Ico "Zevv" Doornekamp, after Jim Knoble's neep-alt.
Upstream: <https://github.com/netyaroze/zevv-peep>

```
The MIT License (MIT)

Copyright (c) 2007-2012 Zevv

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in
all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
THE SOFTWARE.
```

**This is MIT, not public domain.** The notice above is a condition of distribution, so
it is not optional and must not be dropped when the fonts are.

---

## X11 misc-fixed 4x6

`crates/catcard-ui/src/font/misc4x6.rs` is converted from `4x6.bdf` of the X11
misc-fixed set — contributed by Janne V. Kujala, maintained by Markus Kuhn.

**Public domain.** No notice is required; recorded for provenance.

---

## Cat logo

`crates/catcard-ui/src/art/cat.rs` is rasterised from `cat-logo.svg`, a Karpeles Lab
asset, by `tools/artgen/svg2rs.py`. Not third-party; listed so the provenance of every
generated asset is in one place.

---

## Coldcard developer signing key

`keys/dev-privkey.pem` is the secp256k1 key Coinkite publishes so that anyone can build
firmware a Coldcard bootloader will load. It is public by design and grants no
authenticity — see `keys/README.md`.

---

## Why these fonts

zevv-peep and misc-fixed are the faces a Coldcard renders with, and using them keeps the
device visually familiar. They are **upstream public fonts, not Coinkite assets**: the
glyphs coincide because both projects convert the same freely licensed BDFs, not because
anything was taken from the firmware. Sourced here from upstream and verified
byte-identical to the published files. See `CLEANROOM.md`.
