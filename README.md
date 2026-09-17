# CatCard

An independent, open-source firmware for Coldcard hardware, written from scratch in
Rust. Bitcoin first, but not Bitcoin-only — see [`docs/ROADMAP.md`](docs/ROADMAP.md).

MIT licensed. Copyright © 2026 Karpeles Lab Inc.

> **Status: pre-hardware.** The wallet crypto (BIP-32/39, addresses, Base58Check,
> Bech32/Bech32m) is implemented and passes the official test vectors. The drivers
> (SPI, SSD1306, keypad, SPI-NOR) and the settings store are written but have **never
> run on a device** — see [`docs/VALIDATION.md`](docs/VALIDATION.md). There is no USB,
> no PSBT and no signing yet. See [`docs/ROADMAP.md`](docs/ROADMAP.md).
>
> Do not put funds on a device running this.

## Why

The stock Coldcard firmware derives its BIP-39 wallet seed from two chained software
PRNGs, not from the hardware TRNG the chip provides. On mk3 the resulting seed has on
the order of 22 bits of real entropy; on mk4 a partial mitigation raises the floor to
about 32. That is the immediate reason this project exists, and it is why the entropy
subsystem is the first thing built here rather than the last. See
[`docs/ENTROPY.md`](docs/ENTROPY.md).

The secondary reason is licensing. The original firmware is MIT **plus the Commons
Clause**, which is not open source. CatCard is MIT-only, which requires that it be
genuinely independent of that source — see [`CLEANROOM.md`](CLEANROOM.md).

## What you get over stock

- **Multi-source RNG.** A seed is drawn from a pool fed by every noise source the board
  has — the STM32 TRNG read directly, the bootloader's own TRNG read, the secure
  elements' TRNGs, and keypress timing — combined with SHA-512 so a weak source can fail
  to help but can never cancel a good one. Each hardware source runs continuous SP 800-90B
  health tests, public values such as the unique ID are credited zero bits, and a pool
  that has not earned its entropy refuses to produce a seed instead of carrying on.
  See [`docs/ENTROPY.md`](docs/ENTROPY.md).
- **No MicroPython.** The whole firmware is Rust, compiled to native code: no
  interpreter, no garbage collector and no heap. Private-key work runs with interrupts
  masked, which the wallet crate enforces through its types, so a host cannot time a
  derivation while it is running.
- **Better keypad responsiveness.** The pad is scanned by native code on every pass of
  the loop rather than through an interpreter. Every key is debounced separately, a key
  held from the previous screen cannot skip the next one, and each press is timestamped
  at its electrical edge (where the board supports it) so the timing feeds the RNG.
- **Improved UI.** Slow operations show a bar that keeps moving. On the OLED boards the
  panel scrolls it by itself, so it moves even while the CPU is shut inside a
  secure-element call. Addresses are shown in a large face and as a QR code, with the
  full address beside it in blocks of four for checking against a wallet. Key hints use
  what is printed on the keys, and one layout engine fits the 128×64 OLED and the Q1's
  320×240 colour screen alike.
- **Optional multichain support.** One firmware, no per-coin apps to install. Chains are
  build options, so a Bitcoin-only image has the other chains' code *absent*, not just
  hidden — a smaller attack surface, not only a smaller menu. The chain registry and
  compile-time selection are in place; Ethereum and Solana are the next chains on
  [`docs/ROADMAP.md`](docs/ROADMAP.md) and are not built yet.
- **Games and cats.** Block Mine and Block Cutter live under Utils (and can be left out
  of a build), and the device boots to a cat.

## What runs on the device today

Reset → cycle counter → 48 MHz clock → hardware TRNG → build an entropy pool from every
noise source the board has → verify the pool meets its policy → bring up the panel →
draw a selftest screen → scan the keypad and echo key presses.

That is the whole firmware. It is a real signed image that a Coldcard bootloader will
accept and boot; it reports whether the device is healthy and proves the display and
keypad work, and does nothing else yet.

## Supported hardware

| board | MCU | firmware base | status |
|---|---|---|---|
| `mk3` | STM32L496RG | `0x0800_8000` | builds; pin map from reference |
| `mk4` | STM32L4S5xx | `0x0802_0000` | builds; pin map inferred |
| `q1` | STM32L4S5xx | `0x0802_0000` | builds; keyboard/SE2/NFC pins mapped, drivers unwritten |

The bootloader below our firmware is protected flash and cannot be replaced. CatCard
builds against its fixed contract: image format, signature, and the callgate ABI for
PIN, secrets and secure-element entropy. The callgate entry point is read from the table
the bootloader publishes at `0x0800_0040` and validated before use — it moves between
bootloader versions, so it must never be hardcoded.

## Build

```sh
rustup target add thumbv7em-none-eabihf   # or just let rust-toolchain.toml do it

cargo t                     # host tests for every portable crate
cargo fw-mk4                # build the firmware
cargo run -p catcard-image -- build \
    target/thumbv7em-none-eabihf/release/catcard-fw \
    --board mk4 --version 7.0.0 \
    --bin out/catcard-mk4.bin --dfu out/catcard-mk4.dfu
```

`catcard-image` flattens the ELF, writes the 128-byte header at offset `0x3F80`, pads
to a 512-byte multiple, signs the double-SHA256 digest with the published developer
key, and wraps the result as DfuSe. Signing with the dev key is what makes an image
loadable by anyone; it also means the device boots it with a 25-second warning and a
red "not genuine" light, and that no dev-signed image is attributable to any author.

Getting it onto hardware: [`docs/FLASHING.md`](docs/FLASHING.md).

## Layout

```
crates/
  catcard-board      board tables: memory maps, pin assignments, peripheral presence
  catcard-fwhdr      signed image header + the digest the bootloader verifies
  catcard-callgate   bootloader callgate ABI (PIN, secrets, SE entropy, DFU)
  catcard-entropy    entropy accumulator, SP 800-90B health tests, HMAC-DRBG
  catcard-wallet     mnemonics, HD derivation, encodings, addresses, transactions,
                     and the chain registry -- one crate, six modules
  catcard-sign       deterministic ECDSA (RFC 6979) and BIP-340 Schnorr
  catcard-pin        the login sequence over callgate 18
  catcard-upgrade    staging and validating a firmware image
  catcard-usb        HID transport framing, descriptors, control transfers
  catcard-flash      SPI-NOR driver
  catcard-settings   authenticated, power-fail-safe settings store
  catcard-hal        STM32L4/L4+ register-level drivers (RNG, SPI, GPIO, DWT, clocks)
  catcard-ui         framebuffer, SSD1306 driver, fonts, text, keypad scanner
  catcard-fw         the firmware binary
tools/
  catcard-image      build, sign, verify and package images
  reference/         independent reference implementations used to cross-check crypto
keys/
  dev-privkey.pem    the published Coldcard developer key (public by design)
```

Everything except `catcard-fw` builds and tests on the host, which is where the
correctness-critical logic lives.

## Documentation

| | |
|---|---|
| [`CLEANROOM.md`](CLEANROOM.md) | what may and may not be consulted, and why |
| [`THIRD-PARTY-NOTICES.md`](THIRD-PARTY-NOTICES.md) | licences that travel with the distribution |
| [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) | crate boundaries and the fixed-vs-ours split |
| [`docs/ENTROPY.md`](docs/ENTROPY.md) | the seed RNG design and the bug it replaces |
| [`docs/HARDWARE-OPEN-ITEMS.md`](docs/HARDWARE-OPEN-ITEMS.md) | unknowns blocking further work |
| [`docs/VALIDATION.md`](docs/VALIDATION.md) | the hardware bring-up plan, in running order |
| [`docs/ROADMAP.md`](docs/ROADMAP.md) | what is next, in order |
| [`docs/FLASHING.md`](docs/FLASHING.md) | the three dev loops |
| [`docs/USB.md`](docs/USB.md) | USB identity and transport decisions |
| [`docs/RELEASING.md`](docs/RELEASING.md) | reproducible builds and release signing |

## Contributing

Read `CLEANROOM.md` first — it is the constraint everything else follows from. New
hardware facts must cite a source and carry a confidence tag; anything unconfirmed
belongs in `docs/HARDWARE-OPEN-ITEMS.md` as well as in the code.
