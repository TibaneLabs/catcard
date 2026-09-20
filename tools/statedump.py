#!/usr/bin/env python3
"""Read a `CATCARD-STATE` dump, as `Debug -> Dump state` writes it.

A dump nobody can open is not a diagnostic, so this is the other half of the feature.
It lists what is in a file, extracts a section, and says what the secret stash holds --
including the BIP-39 words, which is the part that matters when the reason for taking a
dump was that the device will not give them up any other way.

**The file has the seed in it, unencrypted.** Everything here treats it as such: the
words are printed only when asked for, so `--list` on a shared screen does not spill
them.

    statedump.py FILE                     what is in it
    statedump.py FILE --words             the mnemonic, if it holds one
    statedump.py FILE --extract settings out.img

The settings section is a LittleFS2 volume image with 512-byte blocks. `littlefs-python`
or the `lfs` CLI will mount it; the slots inside stay encrypted under keys derived from
the seed, exactly as they sit in the device's flash.
"""

import argparse
import hashlib
import sys

# The marker byte of the secret stash. Source: hw-reference/secret-stash-format.md,
# mirrored by `catcard_callgate::pin::classify_secret`.
MARKER_XPRV = 0x01
# `0x80 | ((entropy_len / 8) - 2)`, so only 16, 24 and 32 bytes have a spelling.
BIP39_LEN = {0x80: 16, 0x81: 24, 0x82: 32}


def read(path):
    """Split a dump into its manifest and its sections."""
    raw = open(path, "rb").read()
    if not raw.startswith(b"CATCARD-STATE "):
        sys.exit(f"{path}: not a CatCard state dump")

    manifest, sections, at = {}, {}, 0
    while at < len(raw):
        end = raw.find(b"\n", at)
        if end < 0:
            break
        line = raw[at:end].decode("ascii", "replace")
        at = end + 1
        if line.startswith("CATCARD-STATE"):
            manifest["format"] = line.split()[-1]
        elif line.startswith("section "):
            _, name, length = line.split()
            length = int(length)
            sections[name] = raw[at : at + length]
            if len(sections[name]) != length:
                sys.exit(f"{path}: section {name} is short: "
                         f"{len(sections[name])} of {length} bytes")
            at += length
        elif " " in line:
            key, value = line.split(" ", 1)
            manifest[key] = value
    return manifest, sections


def words(entropy, wordlist):
    """The BIP-39 mnemonic for `entropy`, given the English wordlist."""
    checksum = hashlib.sha256(entropy).digest()[0] >> (8 - len(entropy) * 8 // 32)
    bits = int.from_bytes(entropy, "big")
    bits = (bits << (len(entropy) * 8 // 32)) | checksum
    total = (len(entropy) * 8 + len(entropy) * 8 // 32) // 11
    return [wordlist[(bits >> (11 * (total - 1 - i))) & 0x7FF] for i in range(total)]


def describe_secret(blob, wordlist=None, reveal=False):
    """What the stash holds, and -- only when asked -- what it is."""
    if not blob or all(b == 0 for b in blob):
        return ["secret:   empty, no wallet stored"]
    marker = blob[0]
    if marker == MARKER_XPRV:
        out = ["secret:   an extended private key (xprv)"]
        if reveal:
            out.append(f"  raw:    {blob[1:].hex()}")
        return out
    if marker in BIP39_LEN:
        n = BIP39_LEN[marker]
        entropy = blob[1 : 1 + n]
        out = [f"secret:   BIP-39, {n * 8} bits, {(n * 8 + n * 8 // 32) // 11} words"]
        if not reveal:
            out.append("  (pass --words to print them)")
        elif wordlist:
            out.append(f"  entropy: {entropy.hex()}")
            out.append("  words:   " + " ".join(words(entropy, wordlist)))
        else:
            out.append(f"  entropy: {entropy.hex()}")
            out.append("  (no wordlist found; entropy is above)")
        return out
    return [f"secret:   unrecognised marker {marker:#04x}", f"  raw:    {blob.hex()}"]


def find_wordlist():
    """The English BIP-39 wordlist, taken from the firmware's own copy.

    Read out of `wordlist.rs` rather than shipped again here: two copies of a list whose
    order *is* the encoding is two chances to have a different one, and the words this
    prints have to be the words the device would have said.
    """
    import pathlib
    import re

    here = pathlib.Path(__file__).resolve().parent.parent
    src = here / "crates" / "catcard-wallet" / "src" / "bip39" / "wordlist.rs"
    if not src.exists():
        return None
    text = src.read_text()
    # Only the array, not the prose around it: the module documents the list's
    # properties in English and those sentences have quoted words in them.
    start = text.find("static ENGLISH")
    if start < 0:
        return None
    body = text[text.index("[", text.index("=", start)) : text.index("];", start)]
    got = re.findall(r'"([a-z]+)"', body)
    return got if len(got) == 2048 else None


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("file")
    ap.add_argument("--words", action="store_true",
                    help="print the mnemonic. It is the wallet: do not do this on a "
                         "machine or a screen you would not trust with the coins.")
    ap.add_argument("--extract", nargs=2, metavar=("SECTION", "OUT"),
                    help="write one section to a file")
    args = ap.parse_args()

    manifest, sections = read(args.file)
    if args.extract:
        name, out = args.extract
        if name not in sections:
            sys.exit(f"no section {name!r}; have {', '.join(sections) or 'none'}")
        open(out, "wb").write(sections[name])
        print(f"wrote {len(sections[name])} bytes to {out}")
        return

    for key in ("format", "board", "version", "xfp"):
        if key in manifest:
            print(f"{key + ':':9} {manifest[key]}")
    print()
    for name, blob in sections.items():
        print(f"{name + ':':9} {len(blob)} bytes")
    print()
    if "secret" in sections:
        for line in describe_secret(sections["secret"], find_wordlist(), args.words):
            print(line)
    if "settings" in sections:
        print("settings: a LittleFS2 image, 512-byte blocks; slots stay encrypted")
        print("  extract it with --extract settings out.img")


if __name__ == "__main__":
    main()
