#!/usr/bin/env python3
"""Regenerate crates/catcard-bitstream/src/keyrom-map.bin from Xous's key2bits patch tables.

    python3 -I keyrom-map.py path/to/xous-core/services/root-keys/src/key2bits/patch.rs OUT.bin

The betrusted-soc key ROM is 128 LUT6 primitives placed by LOC constraints in slices
X36Y50..X37Y65 (gateware/keyrom.py). Their INIT bits land in eight configuration frames
of the Spartan-7 bitstream, 0x35e..0x361 and 0x364..0x367, in the first 32 words of each.
Xous's key2bits.py (Apache-2.0, from prjxray's tilegrid and CLBLL segbits) reduced that to
two tables: for each (frame, word, bit) the key ROM (address, bit) it holds. This script
concatenates them unchanged -- frames 862..865 then 868..871, 32 words x 32 bits x
(address, bit) each, 16384 bytes -- so the crate carries data, not Xous code.
"""
import re
import sys

src = open(sys.argv[1]).read()
out = bytearray()
for base in (862, 868):
    m = re.search(r"const PATCH_TABLE_%d: \[u8; 8192\] = \[(.*?)\];" % base, src, re.S)
    body = re.sub(r"//[^\n]*", "", m.group(1))
    vals = [int(x) for x in re.findall(r"\d+", body)]
    assert len(vals) == 8192, len(vals)
    out += bytes(vals)
pairs = {(out[i], out[i + 1]) for i in range(0, len(out), 2)}
assert len(pairs) == 256 * 32, "the map must cover every key ROM bit exactly once"
open(sys.argv[2], "wb").write(out)
print(f"{sys.argv[2]}: {len(out)} bytes")
