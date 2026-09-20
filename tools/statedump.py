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
import json
import os
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


# --- the settings slots -------------------------------------------------------------
#
# One slot is a single AES-256-CTR stream over `JSON || zero padding to 4064 ||
# SHA256(that)`, so 4096 bytes. The digest is inside the stream and covers the padding.
#
# Source: hw-reference/settings-nvstore-format.md §2, §3, mirrored by
# `catcard_settings::nvstore`, which is what the device itself runs.
SLOT_LEN = 4096
BODY_LEN = 4064


def slot_key(raw_secret):
    """Six SHA-256 rounds over the **raw 72-byte secret**, not the decoded seed.

    Five that append `b"pad"`, then one plain. Before login there is no secret and the
    key is 32 zero bytes instead; that is what the nickname lives under.
    """
    a, first = b"", True
    for _ in range(5):
        h = hashlib.sha256()
        h.update(raw_secret if first else a)
        h.update(b"pad")
        a, first = h.digest(), False
    return hashlib.sha256(a).digest()


def slot_counter(pos):
    """`pack('<4I', 4, 3, 2, pos)` -- three fixed words, then the slot's own index.

    The index is in the counter so a slot copied to another position does not decrypt.
    """
    return b"".join(x.to_bytes(4, "little") for x in (4, 3, 2, pos))


def decrypt_slot(blob, key, pos):
    """Decrypt one slot and return its JSON text, or raise if the digest disagrees."""
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

    # CTR counts the whole 16-byte block big-endian, which is what `cryptography` does.
    c = Cipher(algorithms.AES(key), modes.CTR(slot_counter(pos)))
    plain = c.decryptor().update(blob)

    body, digest = plain[:BODY_LEN], plain[BODY_LEN:BODY_LEN + 32]
    if hashlib.sha256(body).digest() != digest:
        raise ValueError("digest mismatch -- wrong key, wrong slot index, or damaged")
    return body.rstrip(b"\x00").decode("utf-8", "replace")


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
    ap.add_argument("--out", metavar="DIR",
                    help="with --decrypt, write each slot's JSON there as well as "
                         "printing it, named for the slot and the key that opened it")
    ap.add_argument("--decrypt", nargs="+", metavar="SLOT",
                    help="decrypt settings slots (000.aes ...) pulled out of the "
                         "LittleFS image, using the secret in this dump")
    args = ap.parse_args()

    manifest, sections = read(args.file)
    if args.decrypt:
        secret = sections.get("secret")
        if not secret:
            sys.exit("this dump has no secret section, so there is no key to derive")
        # Every key a slot in this store might be under. A device with a seedvault
        # keeps each vaulted wallet's settings in its own slot under a key derived from
        # *that* wallet's secret, so the main seed opens only its own -- and the vault
        # entries, which carry the raw stash as hex, are what opens the rest. Padded
        # back out to 72 bytes first: the key is six hashes over the whole stash, not
        # over the marker and entropy alone.
        keys = [("main seed", slot_key(secret)), ("pre-login", bytes(32))]
        vault = []
        written = []
        main = None
        for _, k in list(keys):
            for probe in range(16):
                try:
                    main = json.loads(decrypt_slot(
                        open(args.decrypt[0], "rb").read(), k, probe))
                except Exception:
                    continue
                break
            if main:
                break
        for path in args.decrypt:
            try:
                pos = int(os.path.basename(path).split(".")[0], 16)
            except ValueError:
                continue
            for _, k in list(keys):
                try:
                    doc = json.loads(decrypt_slot(open(path, "rb").read(), k, pos))
                except Exception:
                    continue
                for entry in doc.get("seeds", []):
                    if len(entry) >= 2:
                        raw = bytes.fromhex(entry[1]).ljust(72, b"\x00")
                        keys.append((f"vault {entry[0]}", slot_key(raw)))
                        vault.append(entry)
                break
        for path in args.decrypt:
            # The slot's index is in its name and in its counter; they have to agree.
            stem = os.path.basename(path).split(".")[0]
            try:
                pos = int(stem, 16)
            except ValueError:
                sys.exit(f"{path}: cannot read a slot index out of {stem!r}")
            blob = open(path, "rb").read()
            for what, key in keys:
                try:
                    text = decrypt_slot(blob, key, pos)
                except Exception:
                    continue
                print(f"--- {os.path.basename(path)} (slot {pos}, {what} key) ---")
                print(text)
                if args.out:
                    os.makedirs(args.out, exist_ok=True)
                    tag = what.replace(" ", "-")
                    out = os.path.join(args.out, f"{pos:03x}-{tag}.json")
                    # Pretty-printed: these are read by people, and the device's own
                    # copy is compact because it is read by the device.
                    try:
                        body = json.dumps(json.loads(text), indent=2, sort_keys=True)
                    except Exception:
                        body = text
                    with open(out, "w") as fh:
                        fh.write(body + "\n")
                    written.append(out)
                break
            else:
                print(f"--- {os.path.basename(path)}: no key decrypts it ---")

        # A vaulted wallet is a wallet: its stash is right there in the settings, so it
        # decodes the same way the main one does. Behind `--words` for the same reason.
        if args.out and written:
            print(f"\nwrote {len(written)} file(s) to {args.out}/")
        if vault:
            print(f"\n--- seedvault: {len(vault)} wallet(s) ---")
            wl = find_wordlist()
            for entry in vault:
                xfp, hexsecret = entry[0], entry[1]
                label = entry[2] if len(entry) > 2 else ""
                blob = bytes.fromhex(hexsecret)
                if not args.words:
                    n = BIP39_LEN.get(blob[0], 0)
                    count = (n * 8 + n * 8 // 32) // 11 if n else "?"
                    print(f"{xfp}  {count} words  {label}")
                    continue
                for line in describe_secret(blob, wl, True):
                    pass
                n = BIP39_LEN.get(blob[0])
                if n and wl:
                    print(f"{xfp}  {label}")
                    print("   " + " ".join(words(blob[1:1 + n], wl)))
                else:
                    print(f"{xfp}  {label}: not a BIP-39 stash ({hexsecret})")
            if not args.words:
                print("(pass --words to print them)")
            elif args.out:
                os.makedirs(args.out, exist_ok=True)
                out = os.path.join(args.out, "seedvault.txt")
                with open(out, "w") as fh:
                    fh.write("# CatCard seedvault -- THESE ARE THE WALLETS\n")
                    for entry in vault:
                        blob = bytes.fromhex(entry[1])
                        n = BIP39_LEN.get(blob[0])
                        label = entry[2] if len(entry) > 2 else ""
                        got = " ".join(words(blob[1:1 + n], wl)) if (n and wl) else entry[1]
                        fh.write(f"{entry[0]}\t{label}\t{got}\n")
                print(f"wrote {out}")
        return

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
