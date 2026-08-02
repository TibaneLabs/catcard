# Releasing

Not applicable yet — there is nothing to release. Written down now because release
signing decisions are hard to change once users have keys.

## Reproducible builds

A hardware wallet whose binaries cannot be independently reproduced asks users to trust
the person who ran the compiler. The pieces already in place:

- `rust-toolchain.toml` pins the toolchain channel and target.
- `Cargo.lock` is committed.
- `SOURCE_DATE_EPOCH` sets the header timestamp; with it set, two builds of the same
  tree produce byte-identical images.
- `catcard-image` prints the digest it signed, so a rebuild can be checked against a
  published release without access to any key.

Still open: pinning the exact toolchain *version* rather than `stable`, and a container
recipe so the build environment is reproducible too.

## Release signing

Two signatures, for two different questions.

**The dev key (`pubkey_num = 0`)** answers "will this device load it?" — and nothing
else. Every CatCard build is signed with it, because it is the only bootloader key slot
available to third parties. It is public, so it proves nothing about origin.

**A CatCard project key** answers "did this come from the CatCard project?" That key is
not in this repository and must never be. It signs the release artefacts out of band —
a detached signature over the `.bin` and its digest, published alongside.

Users verifying a release should check the project signature. The device cannot: it only
knows the six keys compiled into its bootloader, and none of them are ours.

## Version and timestamp

The header's `version` field holds 7 ASCII characters plus a NUL. The `timestamp` is
packed BCD `YYMMDDHHMMSS` and **must strictly increase** across releases — the bootloader
uses it for downgrade protection.

Because the year is two digits, the format cannot represent anything outside 2000–2099;
`catcard-image` refuses timestamps outside that range rather than silently wrapping.

## `--high-water`

Sets `install_flags & 0x01`, which makes the install record a new anti-downgrade
high-water mark on the device. **Irreversible.** Every older image, including stock
firmware, stops being accepted from then on.

Do not set it on any build users might install while CatCard is incomplete — it would
strand them on a firmware that is not yet a wallet.

## Checklist

1. `cargo t` and `cargo clippy --workspace --all-targets` clean
2. `cargo fw-<board>` for every board
3. Build with `SOURCE_DATE_EPOCH` set; record the digest
4. `catcard-image verify --board <board>` on each artefact
5. Reproduce the build on a second machine; digests must match
6. Sign the artefacts with the project key
7. Publish `.bin`, `.dfu`, digests, project signatures, and the `SOURCE_DATE_EPOCH` used
8. Release notes state plainly that the image is dev-signed and shows the warning screen
