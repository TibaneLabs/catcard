# CatCard

An independent, open-source firmware for Coldcard hardware, written from scratch in
Rust. Bitcoin first, but not Bitcoin-only — see [`docs/ROADMAP.md`](docs/ROADMAP.md).

MIT licensed. Copyright © 2026 Karpeles Lab Inc.

> **Status: runs on real hardware, not ready for funds.** Dev-signed images install and
> run on every board -- mk3, mk4, mk5 and Q1. The device boots, logs in against the real
> secure element, generates and stores a seed, reads a settings store that stock firmware
> wrote, and takes its own firmware upgrades over USB. Signing, multisig and the Q1's QR
> and NFC transports are written and covered by host tests against the standards' own
> vectors, but have not been exercised end to end on a device.
>
> Do not put funds on a device running this. Keep the words of any seed you let it
> store, and expect to reinstall stock firmware.

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
  interpreter and no garbage collector. Private-key work runs with interrupts masked,
  which the wallet crate enforces through its types, so a host cannot time a derivation
  while it is running.
- **Better keypad responsiveness.** The pad is scanned by native code on every pass of
  the loop rather than through an interpreter. Every key is debounced separately, a key
  held from the previous screen cannot skip the next one, and each press is timestamped
  at its electrical edge (where the board supports it) so the timing feeds the RNG.
- **A drawn UI, not a text one.** Stock is text on amber. Here the menus a person lives
  in -- the main one, Derive, Utils, Sign -- are grids of drawn icons on the Q1, chains
  carry their own logos in full colour, and the screens that wait on the secure element
  show a picture rather than a word. One layout engine fits the 128x64 OLED and the Q1's
  320x240 colour screen alike, so the mono boards get the same shapes at their own size.
- **Login protections.** A scrambled number row and a login countdown, each switched on
  only after it has proved itself on the device, plus Test login. Release builds add a
  kill key and microSD 2FA; development builds leave those out, so a bench unit cannot
  erase itself.
- **Large SD cards.** Cards up to 2 TB (the SDXC ceiling) work, where stock stops at
  32 GB. Reading covers FAT12, FAT16, FAT32 and exFAT, the format most large cards come
  with, and Format writes FAT16, FAT32 or exFAT to suit the card's size, so a new card
  needs no reformatting on a computer first.
- **Optional multichain support.** One firmware, no per-coin apps to install. Chains are
  a build option, so a Bitcoin-only image has the other chains' code *absent*, not just
  hidden — a smaller attack surface, not only a smaller menu. With `MULTICHAIN=1` the
  registry covers Bitcoin, Ethereum, Solana, Litecoin, Bitcoin Cash, Dogecoin, Tron,
  Monacoin, Namecoin and Electra Protocol, each with its own derivations and address
  formats. A multichain build also signs the unified opt-in signature hash
  (`SIGHASH_UNIFIED`, hash type bit `0x20`) where a host asks for it, checked against the
  166 vectors its specification publishes.
- **Games and cats.** Block Mine, Block Cutter and (on the Q1) Flappy Cat live under
  Utils and can be left out of a build, and the device boots to a cat.

## What it does today

- **Login.** Two-part PIN against the bootloader's gate, anti-phishing words, nickname,
  attempt counter; Test login, scrambled keys and a login countdown.
- **Wallets.** Create a seed from the entropy pool (12 or 24 words) or import one, as
  words, an XPRV node or a raw master secret -- all three shapes stock can store;
  passphrase; Import key, which takes words, an XPRV or a WIF key in for the session
  without touching the stored one; Seed XOR split and join; SeedQR, shown and scanned back
  on the Q1; BIP-85 children (words, XPRV,
  WIF, password,
  hex), where the words, XPRV and WIF children can be put in force; a key vault in
  stock's own format, so keys saved by either firmware are readable by the other.
- **Addresses.** An explorer over all four single-sig types, accounts and both chains,
  with QR codes; the account and the starting index typed rather than stepped to; a
  derivation path of your own, shown in every type it could be spent as; a CSV of index,
  path and address to the card; Verify address; registered multisig wallets; the other
  chains' formats on a multichain build.
- **Signing.** PSBT signing for single-sig (P2PKH, P2SH-P2WPKH, P2WPKH and P2TR key
  path) and registered multisig, with the fee shown and capped and change proven by
  re-deriving it. Messages too: typed or read off a text file, signed the legacy way or
  under BIP-322, and a signed file checked against the address it names.
- **Transfer.** USB HID, microSD (browse, format, import, export), firmware upgrade from
  either, and on the Q1 a QR scanner with BBQr and BC-UR. The NFC tag carries three
  things: a fully signed transaction goes out as a link, and a phone that taps the device
  is what sends it -- this hardware has no network of its own; an address from the
  explorer goes out as a `bitcoin:` URI a phone can pay to; and a transaction a phone
  writes to the tag comes in to the same signing screen the card and the camera use.
- **Storage.** An authenticated, power-fail-safe settings store, compatible with the one
  stock writes: a device that has run stock keeps its settings, notes and seed vault.
- **Danger zone.** View the words of the key in force, destroy the seed, or lock a
  loaded key down as the stored one — each labelled at every step.

Stock feature by stock feature, with what is left: [`docs/PARITY.md`](docs/PARITY.md).

## Supported hardware

| board | MCU | firmware base | status |
|---|---|---|---|
| `mk3` | STM32L496RG | `0x0800_8000` | runs; no settings medium wired yet (SPI-NOR) |
| `mk4` | STM32L4S5xx | `0x0802_0000` | runs; installs over USB |
| `mk5` | STM32L4S5xx | `0x0802_0000` | runs; same image as mk4, which the header claims for both |
| `q1` | STM32L4S5xx | `0x0802_0000` | runs; colour screen, keyboard, QR scanner, PSRAM |

The bootloader below our firmware is protected flash and cannot be replaced. CatCard
builds against its fixed contract: image format, signature, and the callgate ABI for
PIN, secrets and secure-element entropy. The callgate entry point is read from the table
the bootloader publishes at `0x0800_0040` and validated before use — it moves between
bootloader versions, so it must never be hardcoded.

Bench units are locked at RDP=2, where a signed image that boots but hangs cannot be
recovered. New low-level work therefore goes behind a Debug menu entry before it goes on
the boot path; see [`docs/VALIDATION.md`](docs/VALIDATION.md).

## Build

```sh
make                  # dev images for every board, into out/
make q1               # just the Q1        -> out/catcard-q1.{bin,dfu}
make mk4-mk5          # one image, both boards
make q1 MULTICHAIN=1  # every chain the registry knows, not just Bitcoin
make q1 SHIP=1        # a real release: the USB debug crutches stripped
make test lint        # host tests / clippy, as CI runs them
```

A default build carries the bench crutches — host key injection, and a peek/poke/jsr
memory monitor — because that is how the device is driven while the firmware is being
built out. **`SHIP=1` is what strips them**, and nothing else should ever be given to
someone else: `usb-debug-mem` reads the seed and the PIN out of RAM and runs arbitrary
code. See [`docs/USB.md`](docs/USB.md).

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
                     PSBT review, multisig, descriptors, and the chain registry
  catcard-sign       deterministic ECDSA (RFC 6979) and BIP-340 Schnorr
  catcard-pin        the login sequence over callgate 18
  catcard-upgrade    staging and validating a firmware image
  catcard-usb        HID transport framing, descriptors, control transfers
  catcard-qr         the Q1's QR scanner protocol
  catcard-bbqr       BBQr: a payload split across QR codes, as stock writes them
  catcard-bcur       BC-UR: the same, plus the registry items wallets exchange
  catcard-sd         SD card bring-up and block reads; FAT12/16/32 and exFAT
  catcard-flash      SPI-NOR driver
  catcard-settings   authenticated, power-fail-safe settings store
  catcard-alloc      a small heap that reports failure instead of panicking
  catcard-kernel     a small preemptive kernel: real tasks, stacks, context switch
  catcard-log        a ring of bytes that outlives whatever wrote it
  catcard-hal        STM32L4/L4+ register-level drivers (RNG, SPI, DMA, GPIO, SDMMC,
                     USART, clocks)
  catcard-ui         framebuffers, SSD1306 and ST7789 drivers, fonts, text, art,
                     menus, keypad and keyboard
  catcard-fw         the firmware binary
tools/
  catcard-image      build, sign, verify and package images
  artgen/            turn art into the indexed and deflated forms the firmware draws
  fontgen/           turn fonts into the tables the renderer walks
  reference/         independent reference implementations used to cross-check crypto
  emu/               the emulator harness, for what can be checked without a device
  usbclient.py       drive a device over USB: install, unlock, read the log
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
| [`docs/SECRETS-AND-SETTINGS.md`](docs/SECRETS-AND-SETTINGS.md) | how secrets and settings are stored, and read back from stock |
| [`docs/MENU.md`](docs/MENU.md) | our menu next to stock's, item by item |
| [`docs/PARITY.md`](docs/PARITY.md) | every stock feature, whether CatCard has it, and the order the gaps close |
| [`docs/HARDWARE-OPEN-ITEMS.md`](docs/HARDWARE-OPEN-ITEMS.md) | unknowns, and what would settle each |
| [`docs/VALIDATION.md`](docs/VALIDATION.md) | the hardware bring-up plan, in running order |
| [`docs/ROADMAP.md`](docs/ROADMAP.md) | what is next, in order |
| [`docs/KERNEL.md`](docs/KERNEL.md) | the task kernel and what runs under it |
| [`docs/PSRAM.md`](docs/PSRAM.md) | the Q1's PSRAM: what owns it and the write rules |
| [`docs/CALLGATE-DMA.md`](docs/CALLGATE-DMA.md) | driving the panel by DMA around a blocking callgate |
| [`docs/FLASHING.md`](docs/FLASHING.md) | the three dev loops |
| [`docs/USB.md`](docs/USB.md) | USB identity, transport, and the debug features a release strips |
| [`docs/RELEASING.md`](docs/RELEASING.md) | reproducible builds and release signing |

## Contributing

Read `CLEANROOM.md` first — it is the constraint everything else follows from. New
hardware facts must cite a source and carry a confidence tag; anything unconfirmed
belongs in `docs/HARDWARE-OPEN-ITEMS.md` as well as in the code. `make test lint` is
what CI runs; a change to the boot path needs a word about how it was tried on a device
that cannot be recovered if it hangs.
