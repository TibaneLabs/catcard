"""Raw deflate for `Indexed` art: the one encoding both generators emit.

The pixels are packed two to a byte, left pixel high, row after row -- the layout a
`Gray4` canvas uses -- and then deflated with a **512-byte window**, the smallest
deflate allows. The device inflates them straight onto the canvas as they come out
(`crates/catcard-ui/src/art/indexed.rs`), and the only memory that needs beyond the
decoder's own is a history ring the size of that window. On this art a bigger window buys
nothing: the icons deflate to 8,734 bytes with it and 8,818 with the full 32 KB.
"""

import zlib

# 2^9 = 512 bytes. The decoder's ring is sized to this and cannot serve a longer
# back-reference, so the two must change together.
WINDOW_BITS = 9


def deflate(packed):
    c = zlib.compressobj(9, zlib.DEFLATED, -WINDOW_BITS, 9)
    return c.compress(bytes(packed)) + c.flush()


def rust_array(name, data, indent="    "):
    """A `static NAME: [u8; N]` holding `data`, sixteen bytes to a line."""
    out = ["#[rustfmt::skip]", f"static {name}: [u8; {len(data)}] = ["]
    for i in range(0, len(data), 16):
        out.append(indent + " ".join(f"0x{b:02X}," for b in data[i : i + 16]))
    out.append("];")
    return out
