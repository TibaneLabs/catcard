#!/usr/bin/env python3
"""Bake the Solana mint table into the firmware.

    tools/tokengen/mints.py tools/tokengen/solana-tokens.js \\
        crates/catcard-solana/src/mints.rs

The sibling `tokens.py` does the same for EVM chains, and both follow the same two rules:

1. **Addresses come from the source file, never from anywhere else.** Neither script knows
   an address of its own and neither will invent one. How the source file earned its rows
   is written at the top of it.
2. **Everything is stored as raw bytes -- written as base58.** A mint is thirty-two
   bytes, and that is what the image holds: `literal::mint` converts at compile time, so
   the table costs 32 bytes a row and decodes nothing at lookup. The generated file still
   reads as the addresses it came from, which means it can be checked against the source
   list by eye rather than by running something over it -- and an address that is not an
   address stops the build instead of becoming a row nobody looked at.

Decimals are the other half of a row, and the more dangerous half: a token labelled with
the wrong decimal count shows `1000.0` where `0.001` was meant. They are carried from the
source and never assumed.
"""

import argparse
import pathlib
import re
import sys

ALPHABET = b"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"

ENTRY = re.compile(r"M\(\s*'([^']+)'\s*,\s*'([1-9A-HJ-NP-Za-km-z]{32,44})'\s*,\s*(\d+)")


def base58_decode(text):
    """The 32 bytes a Solana mint is, from the way it is written down."""
    n = 0
    for ch in text.encode():
        i = ALPHABET.find(ch)
        if i < 0:
            sys.exit(f"{text}: {chr(ch)!r} is not base58")
        n = n * 58 + i
    raw = n.to_bytes((n.bit_length() + 7) // 8 or 1, "big")
    # Leading '1's are leading zero bytes, which is how an address like
    # `So1111…` keeps its shape.
    pad = len(text) - len(text.lstrip("1"))
    raw = b"\x00" * pad + raw
    if len(raw) != 32:
        sys.exit(f"{text}: decodes to {len(raw)} bytes, not 32")
    return raw


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("src", type=pathlib.Path)
    ap.add_argument("out", type=pathlib.Path)
    a = ap.parse_args()

    rows = []
    for sym, mint, dec in ENTRY.findall(a.src.read_text()):
        if len(sym.encode()) > 12:
            sys.exit(f"{sym}: symbol too long for the table")
        # Decoded here only to sort the table and catch a duplicate. What the firmware
        # uses is the literal below, decoded by the compiler -- this script's decoder is
        # not on the path that decides what a mint is.
        rows.append((base58_decode(mint), sym, int(dec), mint))
    if not rows:
        sys.exit(f"{a.src}: no entries found -- has the format changed?")

    rows.sort(key=lambda r: r[0])
    for i in range(1, len(rows)):
        if rows[i][0] == rows[i - 1][0]:
            sys.exit(f"duplicate mint {rows[i][3]}")

    lines = [
        "//! Solana mints this firmware can name.",
        "//!",
        "//! Generated. Edit the source list and re-run:",
        "//!",
        "//! ```text",
        f"//! tools/tokengen/mints.py {a.src} {a.out}",
        "//! ```",
        "//!",
        "//! **A row here is a claim about a mint**, and the screens treat it as one: the",
        "//! address is shown whether or not it is named, and a name is a label on it rather",
        "//! than a replacement for it. How each row earned its place -- two independent",
        "//! sources agreeing on the address *and* the decimals -- is written at the top of",
        "//! the source list.",
        "//!",
        "//! Written as base58 and **stored as the thirty-two bytes a mint is**:",
        "//! [`crate::literal::mint`] converts at compile time, so this file can be read",
        "//! against the source list by eye while the image holds bytes and decodes",
        f"//! nothing. {len(rows)} mints, {len(rows) * 32} bytes of addresses.",
        "",
        "/// What a mint turns out to be.",
        "#[derive(Copy, Clone, PartialEq, Eq, Debug)]",
        "pub struct Mint {",
        "    /// The ticker, as the chain's own explorers write it.",
        "    pub symbol: &'static str,",
        "    /// Decimal places, for turning the raw amount into the number people use.",
        "    pub decimals: u8,",
        "}",
        "",
        "use crate::literal::mint;",
        "",
        "/// `(mint, symbol, decimals)`, sorted by address so it can be searched.",
        "#[rustfmt::skip]",
        f"static MINTS: [([u8; 32], &str, u8); {len(rows)}] = [",
    ]
    for _raw, sym, dec, text in rows:
        lines.append(f'    (mint("{text}"), "{sym}", {dec}),')
    lines += [
        "];",
        "",
        "/// The mint at `address`, if this build knows it.",
        "///",
        "/// A miss is the ordinary case rather than an error: this is a few dozen mints out",
        "/// of millions, and everything else is shown by address with its amount in raw",
        "/// units -- which is what an unchecked transfer gives anyway.",
        "pub fn lookup(address: &[u8; 32]) -> Option<Mint> {",
        "    let i = MINTS.binary_search_by(|(m, _, _)| m.cmp(address)).ok()?;",
        "    let (_, symbol, decimals) = MINTS[i];",
        "    Some(Mint { symbol, decimals })",
        "}",
        "",
        "/// How many mints this build carries, for a screen that wants to say so.",
        "pub fn known() -> usize {",
        "    MINTS.len()",
        "}",
        "",
        "/// Row `i`: the mint's address and what it is.",
        "///",
        "/// For a walk over every mint this build knows -- which is how an amount in a",
        "/// token account gets a name when the instruction moving it did not carry one.",
        "pub fn at(i: usize) -> Option<([u8; 32], Mint)> {",
        "    let (address, symbol, decimals) = *MINTS.get(i)?;",
        "    Some((address, Mint { symbol, decimals }))",
        "}",
        "",
    ]
    a.out.write_text("\n".join(lines))
    print(f"{len(rows)} mints ({len(rows) * 32} bytes of addresses) -> {a.out}")


if __name__ == "__main__":
    main()
