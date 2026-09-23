#!/usr/bin/env python3
"""Bake a token table into the firmware, from the JS list the addresses live in.

    tools/tokengen/tokens.py tools/tokengen/tokens.js \\
        crates/catcard-evm/src/tokens.rs

The table's whole job is to turn `0xaf88…5831` into `USDC` and `6` on a screen, so that
"send 12.5 USDC" can be said instead of "send 12500000 of something". That makes every
row a **claim about a contract**, and a wrong row is worse than a missing one: a mislabelled
address would let a hostile contract borrow a familiar name at the exact moment somebody is
deciding whether to sign.

So two rules, both enforced here rather than trusted:

1. **Addresses come from the source file, never from anywhere else.** This script does not
   know any addresses of its own and will not invent one.
2. **A chain is only baked when its id is written down beside it.** The source file names
   chains by slug -- `polygon`, `arbitrum` -- and the id is what a transaction actually
   carries. A slug whose id is not in `CHAIN_IDS` below is skipped with a warning rather
   than guessed at, because guessing it wrong applies one chain's labels to another's
   contracts.

The firmware shows the address on screen whatever this says. The table names it; it never
replaces it.
"""

import argparse
import pathlib
import re
import sys

# Slug -> EIP-155 chain id. Only what is written here gets baked; see rule 2 above.
CHAIN_IDS = {
    "ethereum": 1,
    "optimism": 10,
    "polygon": 137,
    "mantle": 5000,
    "arbitrum": 42161,
    "base": 8453,
    "bsc": 56,
    "avalanche": 43114,
    "gnosis": 100,
}

ENTRY = re.compile(
    r"E\(\s*'([^']+)'\s*,\s*'(0x[0-9a-fA-F]{40})'\s*,\s*(\d+)",
)


def parse(path):
    """[(slug, symbol, address_bytes, decimals)], in the file's own order."""
    src = path.read_text()
    out = []
    # Each `slug: [` opens a block that runs to the matching `],` at the same indent.
    for m in re.finditer(r"^  (\w+):\s*\[(.*?)^  \],", src, re.S | re.M):
        slug, body = m.group(1), m.group(2)
        for sym, addr, dec in ENTRY.findall(body):
            out.append((slug, sym, bytes.fromhex(addr[2:]), int(dec)))
    return out


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("src", type=pathlib.Path)
    ap.add_argument("out", type=pathlib.Path)
    a = ap.parse_args()

    rows = parse(a.src)
    if not rows:
        sys.exit(f"{a.src}: no entries found -- has the format changed?")

    baked, skipped = [], {}
    for slug, sym, addr, dec in rows:
        chain = CHAIN_IDS.get(slug)
        if chain is None:
            skipped[slug] = skipped.get(slug, 0) + 1
            continue
        if len(sym.encode()) > 12:
            sys.exit(f"{sym}: symbol too long for the table")
        baked.append((chain, addr, sym, dec))

    # Sorted by (chain, address) so the firmware can binary-search it.
    baked.sort(key=lambda r: (r[0], r[1]))
    for i in range(1, len(baked)):
        if baked[i][:2] == baked[i - 1][:2]:
            sys.exit(f"duplicate entry for chain {baked[i][0]} address {baked[i][1].hex()}")

    chains = sorted({c for c, *_ in baked})
    lines = [
        "//! Tokens this firmware can name, by chain and contract address.",
        "//!",
        "//! Generated. Edit the source list and re-run:",
        "//!",
        "//! ```text",
        f"//! {a.src.name} -> {a.out}",
        "//! ```",
        "//!",
        "//! **A row here is a claim about a contract**, and the screens treat it as one: the",
        "//! address is shown whether or not it is named, and a name is a label on it rather",
        "//! than a replacement for it. A table that mislabelled an address would let a hostile",
        "//! contract borrow a familiar name at the moment somebody is deciding to sign, which",
        "//! is why the generator refuses to invent either an address or a chain id.",
        "//!",
        f"//! {len(baked)} tokens across {len(chains)} chains"
        f" ({', '.join(str(c) for c in chains)}).",
        "",
        "/// What a contract address turns out to be.",
        "#[derive(Copy, Clone, PartialEq, Eq, Debug)]",
        "pub struct Token {",
        "    /// The ticker, as the chain's own explorers write it.",
        "    pub symbol: &'static str,",
        "    /// Decimal places, for turning the raw amount into the number people use.",
        "    pub decimals: u8,",
        "}",
        "",
        "/// `(chain_id, address, symbol, decimals)`, sorted so it can be searched.",
        "#[rustfmt::skip]",
        f"static TOKENS: [(u64, [u8; 20], &str, u8); {len(baked)}] = [",
    ]
    for chain, addr, sym, dec in baked:
        body = ", ".join(f"0x{b:02X}" for b in addr)
        lines.append(f'    ({chain}, [{body}], "{sym}", {dec}),')
    lines += [
        "];",
        "",
        "/// The token at `address` on `chain_id`, if this build knows it.",
        "///",
        "/// A miss is the ordinary case, not an error: the table is a few dozen well-known",
        "/// contracts, and everything else is shown by address with its amount in raw units.",
        "pub fn lookup(chain_id: u64, address: &[u8; 20]) -> Option<Token> {",
        "    let key = (chain_id, *address);",
        "    let i = TOKENS",
        "        .binary_search_by(|(c, a, _, _)| (*c, *a).cmp(&key))",
        "        .ok()?;",
        "    let (_, _, symbol, decimals) = TOKENS[i];",
        "    Some(Token { symbol, decimals })",
        "}",
        "",
        "/// Whether this build knows any token on `chain_id`.",
        "///",
        "/// For a screen that wants to say \"nothing here is named on this chain\" rather than",
        "/// leaving a person to wonder whether the table was consulted.",
        "pub fn knows_chain(chain_id: u64) -> bool {",
        "    TOKENS.iter().any(|(c, _, _, _)| *c == chain_id)",
        "}",
        "",
    ]
    a.out.write_text("\n".join(lines))
    print(f"{len(baked)} tokens on chains {chains} -> {a.out}")
    for slug, n in sorted(skipped.items()):
        print(f"  skipped {n:3d} on '{slug}': no chain id in CHAIN_IDS", file=sys.stderr)


if __name__ == "__main__":
    main()
