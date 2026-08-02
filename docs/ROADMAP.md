# Roadmap

Ordered by dependency, not by ambition. Each milestone ends with something testable.

## Done

- Workspace, three-board abstraction, generated linker scripts
- Signed image format: header, double-SHA256 digest, secp256k1 signing, DfuSe
- `catcard-image`: build / sign / verify / info / dfuse / boards
- Entropy accumulator, SP 800-90B health tests, HMAC-DRBG ([`ENTROPY.md`](ENTROPY.md))
- STM32 TRNG, HSI48, DWT, GPIO drivers
- Callgate: entry-point discovery from the bootloader info table, the real register
  convention in inline asm, the full `gate 18` ABI
- Boot path: clock → TRNG → entropy pool → policy check
- 150 host tests, clippy clean on host and thumb

## M1 — Prove it runs

The image builds and is signed, but nothing has watched it execute.

- [ ] Install a dev-signed image on real hardware ([`FLASHING.md`](FLASHING.md))
- [ ] Confirm `CATCARD_BOOT_STATUS` shows the TRNG alive and the entropy policy met
- [ ] Confirm the MSI range, then program the PLL (`HARDWARE-OPEN-ITEMS.md`)
- [ ] Panic handler that wipes SRAM before halting — the current `panic-halt` leaves
      whatever was in RAM sitting there

**Exit:** a device boots CatCard and reports a healthy entropy pool.

## M2 — Output and input

- [ ] SPI driver
- [ ] SSD1306 driver over `catcard-ui::Framebuffer` (mk3/mk4)
- [ ] Text rendering: a bitmap font, no dependency on floating point
- [ ] Numpad matrix scan with debounce, scan order shuffled from `domain::UI`
- [ ] Feed keypress timing into the pool as `Source::UserTiming`
- [ ] Selftest screen replacing `selftest::park`

**Exit:** a device shows text and responds to keys. This is where development stops
being blind.

## M3 — Storage

- [ ] SPI-NOR driver: `RDID`, read, page program, 4 KB sector erase
- [ ] Confirm the CS/SCK pins and the part's size (`HARDWARE-OPEN-ITEMS.md`)
- [ ] Settings store: our own format — wear-levelled, authenticated, with a defined
      recovery path from a torn write
- [ ] microSD over SDMMC, FAT32 read/write

**Exit:** settings survive a power cycle; files can be read from and written to a card.

## M4 — Secrets

No longer blocked: the entry address is read from the bootloader's info table.
Everything below now needs hardware rather than more specification.

- [ ] `gate 18` setup / login / fetch_secret against real hardware
- [ ] PIN entry UX, including anti-phishing words (`gate 16`)
- [ ] Seed generation from `EntropyPool`, stored via `gate 18/3`
- [ ] Secure-element entropy via `gate 26` into the pool (code already written)
- [ ] Genuine light; brick and duress handling (both are transparent by design — a
      caller cannot tell a duress login from a real one, and the brickme PIN destroys
      the pairing secret, so `-105 I_AM_BRICK` must be handled everywhere)

**Exit:** a PIN unlocks a seed the device generated itself.

## M5 — Wallet (Bitcoin)

- [ ] BIP-39: wordlist, mnemonic ↔ entropy, passphrase
- [ ] BIP-32 derivation over secp256k1 (constant-time; audit the crate choice)
- [ ] Address derivation and display: P2PKH, P2WPKH, P2SH-P2WPKH, P2TR
- [ ] PSBT (BIP-174) parse, validate, sign, serialise
- [ ] Deterministic nonces (RFC 6979), with `domain::SIGNING` as auxiliary randomness
- [ ] Multisig and output descriptors
- [ ] BIP-85 derived child seeds

**Exit:** the device signs a testnet transaction correctly.

Design note for this milestone: CatCard is intended to support chains beyond Bitcoin,
including ed25519 ones (see "Multi-chain" below). Nothing here should be built in a way
that assumes secp256k1 is the only curve — but the multi-chain design itself is not
settled yet, so M5 ships Bitcoin and leaves the seams rather than speculating on an
abstraction.

## M6 — Host connectivity

- [ ] USB OTG FS device stack
- [ ] Register a VID/PID with pid.codes ([`USB.md`](USB.md))
- [ ] Our own transport: framing, authenticated encryption, replay resistance
- [ ] Host tooling
- [ ] Self-upgrade: receive an image, stage to SPI-NOR, on-screen approval, reboot
      (confirm the staging base first — `HARDWARE-OPEN-ITEMS.md`)

**Exit:** a firmware update over USB, approved on the device.

## Multi-chain — not yet designed

CatCard aims to support coins beyond Bitcoin, including ed25519 chains. The design is
open; this section records only what is already known to constrain it, so M5 does not
paint us into a corner.

- **One seed, many curves.** SLIP-0010 derives ed25519 (and NIST P-256) master keys from
  the same BIP-39 seed, so the secret we hand the bootloader does not need to change.
  Storage is unaffected.
- **ed25519 derivation is hardened-only.** SLIP-0010 defines no non-hardened path for
  ed25519, so there is no xpub-equivalent and no watch-only public derivation. Any
  account/descriptor model that assumes it can hand a host an extended *public* key and
  let it derive addresses is Bitcoin-specific.
- **Signing differs in kind, not just in curve.** EdDSA is deterministic by
  construction; there is no RFC-6979 equivalent to reuse and no nonce to supply. The
  signing interface has to accommodate both rather than being an secp256k1 signature
  with a swapped curve parameter.
- **Unaffected:** the firmware image signature is secp256k1 and fixed by the bootloader.
  Nothing about multi-chain support touches it.

## M7 — Q1

- [ ] Identify the LCD controller and resolution
- [ ] ST77xx driver, colour framebuffer
- [ ] QWERTY keyboard scan (10x6 matrix; pins are in the board table)
- [ ] QR camera, decoding, SeedQR

## Ongoing

- **Security review.** Every milestone that touches secrets needs one before it lands.
- **Reproducible builds.** `SOURCE_DATE_EPOCH` is honoured; the rest of the toolchain
  pinning is [`RELEASING.md`](RELEASING.md).
- **NIST CAVP DRBG vectors** — `TODO(#1)`.
- **Entropy estimation from real captures**, to replace the conservative credit rates
  with measured ones.
- **Constant-time review** of every comparison and arithmetic path that touches key
  material.
