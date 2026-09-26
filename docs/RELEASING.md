# Releasing

Pre-releases are published from tags; nothing here is a finished wallet yet. The signing
decisions below are written down early because they are hard to change once users have
keys.

## Tagging a release

Push a tag named `vX.Y.Z` or `vX.Y.Z-alphaN` / `-betaN` / `-rcN`, on a commit CI has
already passed. `.github/workflows/release.yml` then:

1. checks the tag with `tools/release-version.sh`: its `X.Y.Z` must equal the workspace
   version in `Cargo.toml`, and the version it stamps must fit the header's 7 characters;
2. opens a draft GitHub release (a pre-release when the tag has a suffix);
3. builds the twelve release shapes in parallel -- mk3, mk4-mk5 and Q1, each with every
   chain or Bitcoin-only, each with or without the games (the same twelve CI builds) --
   with `--no-default-features`, runs the crutch-string check, signs with the dev key,
   runs `catcard-image verify`, and attaches each `.dfu`;
4. checks all twelve are there, attaches `SHA256SUMS` and publishes the release.

To rebuild an existing tag -- a shape was missing, or an upload failed -- run the
workflow by hand: `gh workflow run release.yml -f tag=v7.0.0-alpha1`. It builds the
tag's code with the default branch's workflow and the tagged commit's timestamp, so
images already attached come out byte-identical, and it refreshes the release notes.

The tag's suffix is folded to fit the header: `v7.0.0-alpha1` is stamped `7.0.0a1`
(`alpha` -> `a`, `beta` -> `b`, `rc` -> `r`). The firmware reports the same string on
screen and over USB: the build reads it from `CATCARD_VERSION` (`crate::VERSION`), and
refuses to compile if it is longer than 7 characters. `make <board> VERSION=...` sets
both the same way.

The header timestamp is the tagged commit's time (`SOURCE_DATE_EPOCH`), so rebuilding the
tag reproduces its digests, and a later tag on a later commit always carries a later
timestamp.

The workflow covers steps 1-5 and 8-9 of the checklist below. Steps 6 (a second machine)
and 7 (the project key) stay manual, and a release is not a final release until they are
done.

```sh
git tag -a v7.0.0-alpha1 -m "CatCard 7.0.0-alpha1" && git push origin v7.0.0-alpha1
```

## Reproducible builds

A hardware wallet whose binaries cannot be independently reproduced asks users to trust
the person who ran the compiler. The pieces already in place:

- `rust-toolchain.toml` pins the toolchain channel and target.
- `Cargo.lock` is committed.
- `SOURCE_DATE_EPOCH` sets the header timestamp; with it set, two builds of the same
  tree produce byte-identical images.
- `catcard-image` prints the digest it signed, so a rebuild can be checked against a
  published release without access to any key.
- Nothing that reaches the output bytes depends on the ambient environment. In
  particular there is no `rustflags` table in `.cargo/config.toml`: setting `RUSTFLAGS`
  makes cargo ignore that table entirely, so anything in it would produce one binary
  locally and a different one under CI. The linker script is emitted from
  `catcard-fw/build.rs`, which `RUSTFLAGS` cannot override. CI asserts both properties.

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

The device names it: the offer screen adds `SETS ANTI-DOWNGRADE MARK` / `irreversible:
no way back`, and a yes is followed by a second question, as *Destroy seed* asks twice.
See [`FLASHING.md`](FLASHING.md#--high-water).

## Checklist

1. `cargo t` and `cargo clippy --workspace --all-targets` clean
2. `cargo fw-<board>-ship` (or `make <board> SHIP=1`) for every board. **Not** the plain
   `cargo fw-<board>`: that is the bench build, whose default features include key
   injection (a host can press the keys, including the one that approves an install) and
   the memory monitor (a host can read the seed out of RAM). The `-ship` aliases pass
   `--no-default-features`, leaving only the board.
3. Prove the crutches are absent from what step 2 produced, three ways, because the
   feature list is the thing being checked and cannot vouch for itself:
   - `strings -a target/thumbv7em-none-eabihf/release/catcard-fw | grep -niE
     'debug_mem|inject_key|injected|debug memory monitor is enabled'` prints nothing.
     This is the check CI's *No debug monitor, no key injection* step runs
     (`.github/workflows/ci.yml`); a bench build trips it by a couple of dozen lines.
   - Booted, the selftest screen's continue line carries no `[USB KEYS]` and no
     `[KEYS MEM]` marker (`crates/catcard-fw/src/selftest.rs`).
   - Over USB, `Identify`'s capability byte (`tools/usbclient.py hid`) has none of
     `KEY_INJECTION`, `UNLOCK_PIN` or `DEBUG_MEM` set (`catcard_usb::caps`); `UPGRADE`
     and `UPGRADE_PACKED` are the only bits a release should show.
4. Build with `SOURCE_DATE_EPOCH` set; record the digest
5. `catcard-image verify --board <board>` on each artefact; the `install_flags` line
   shows `(HIGH_WATER)` only if [`--high-water`](#--high-water) was meant
6. Reproduce the build on a second machine; digests must match
7. Sign the artefacts with the project key
8. Publish `.bin`, `.dfu`, digests, project signatures, and the `SOURCE_DATE_EPOCH` used
9. Release notes state plainly that the image is dev-signed and shows the warning screen
