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
- BIP-39: wordlist, entropy ↔ phrase, checksum, PBKDF2 seed — all 24 official English
  vectors pass in both directions
- 179 host tests, clippy clean on host and thumb

## M1 — Prove it runs

The image builds and is signed, but nothing has watched it execute.

- [ ] Install a dev-signed image on real hardware ([`FLASHING.md`](FLASHING.md))
- [ ] Confirm `CATCARD_BOOT_STATUS` shows the TRNG alive and the entropy policy met
- [ ] Confirm the MSI range, then program the PLL (`HARDWARE-OPEN-ITEMS.md`)
- [x] Panic handler that wipes SRAM before halting (delegates to callgate 3, which can
      clear memory it is not running out of)

**Exit:** a device boots CatCard and reports a healthy entropy pool.

## M2 — Output and input

- [x] SPI driver
- [x] SSD1306 driver over `catcard-ui::Framebuffer` (mk3/mk4)
- [x] Text rendering: an 8x8 bitmap font, no floating point, no `core::fmt`
- [x] Selftest screen replacing `selftest::park`
- [x] Numpad matrix scan with debounce, scan order shuffled from `domain::UI`
- [x] Feed keypress timing into the pool as `Source::UserTiming`

Everything ticked above is written but **unvalidated** — no hardware yet. The SPI
pin assignments and the panel's SPI instance are inferred (see
`HARDWARE-OPEN-ITEMS.md`), so the first validation step is confirming the panel
lights up at all.

**Exit:** a device shows text and responds to keys. This is where development stops
being blind.

The selftest screen echoes the last key pressed, so the keypad map and the debounce can
both be checked on hardware without a debugger.

## M3 — Storage

- [x] SPI-NOR driver: `RDID`, read, page program, 4 KB sector erase
- [x] Settings store: authenticated, two-slot, with a defined recovery path from a
      torn write
- [ ] Confirm the CS/SCK pins and the part's size (`HARDWARE-OPEN-ITEMS.md`) — until
      then neither can be wired to a board
- [ ] Derive the settings key from the secure element (currently a caller parameter)
- [ ] Rollback resistance: bind the settings sequence to an SE monotonic counter, so
      physical access cannot restore an older *authentic* slot
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

- [x] BIP-39: wordlist, mnemonic ↔ entropy, passphrase
- [ ] NFKD normalisation, so non-ASCII passphrases work. `Mnemonic::to_seed` currently
      **refuses** them rather than deriving a seed that diverges from every other
      wallet. Needs a normalisation table, or a decision to restrict passphrases.
- [ ] BIP-32 derivation over secp256k1 (constant-time; audit the crate choice)
- [ ] Address derivation and display: P2PKH, P2WPKH, P2SH-P2WPKH, P2TR
- [ ] PSBT (BIP-174) parse, validate, sign, serialise
- [x] Deterministic nonces (RFC 6979); ECDSA with low-S, DER encoding, and BIP-340
      Schnorr for taproot
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

CatCard aims to support coins beyond Bitcoin, including ed25519 chains, **with
non-hardened (soft) derivation**. The design is open; this section records only what is
already known to constrain it, so M5 does not paint us into a corner.

### Non-hardened ed25519

SLIP-0010 is hardened-only, but that is a property of SLIP-0010, not of ed25519.
**BIP32-Ed25519** (Khovratovich & Law, 2017 — the scheme Cardano uses) supports soft
derivation, and it is what CatCard needs to support.

It works by keeping the private key as the *expanded* scalar pair `(kL, kR)` rather than
the 32-byte seed, which makes the keyspace linear enough to tweak:

```
soft:      Z = HMAC-SHA512(c_par, 0x02 || A_par || i)
           kL_i = kL_par + 8*Z_L        A_i = A_par + [8*Z_L]B
           kR_i = kR_par + Z_R  (mod 2^256)
hardened:  Z = HMAC-SHA512(c_par, 0x00 || kL_par||kR_par || i)
```

Because `A_i` is computable from `A_par` alone, an extended *public* key does yield
watch-only derivation — so the account model does **not** have to be Bitcoin-specific.

Three consequences that are cheaper to get right than to retrofit:

- **The signing implementation must accept an extended scalar.** Standard Ed25519
  derives its scalar from the seed by SHA-512 internally; here the scalar arrives
  pre-derived and tweaked. Most ed25519 crates do not expose that, and the ones that do
  put it behind a `hazmat`-style API. This is a crate-selection constraint for M5, not
  an afterthought.
- **Store the BIP-39 entropy, not just the derived seed.** Cardano's Icarus master-key
  generation runs PBKDF2 over the mnemonic *entropy*, not over the 64-byte BIP-39 seed.
  If our secret blob holds only the seed, that derivation is impossible after the fact.
  **Settled:** `catcard_bip39::Mnemonic` stores entropy and renders words on demand, so
  the secret encoding written at M4 carries entropy. Nothing is foreclosed.
- **Master-key generation has incompatible variants.** The original paper, Icarus, and
  Ledger's variant all differ. Whichever we implement has to be named in the UI, because
  picking the wrong one silently produces a valid wallet at the wrong addresses.

Scalar growth is bounded by truncating `Z_L` to 28 bytes, which caps derivation depth —
generously (order 2^20 levels), but it is not unlimited the way BIP-32 is.

### Everything else

- **One seed, many curves.** Both SLIP-0010 and BIP32-Ed25519 derive from BIP-39
  material, so the secret we hand the bootloader stays a single master secret. Storage
  is unaffected beyond the entropy-vs-seed point above.
- **Signing differs in kind, not just in curve.** EdDSA is deterministic by
  construction; there is no RFC-6979 equivalent to reuse and no nonce to supply. The
  signing interface has to accommodate both rather than being an secp256k1 signature
  with a swapped curve parameter.
- **Related but distinct:** Polkadot-style soft derivation uses sr25519/schnorrkel over
  Ristretto — same underlying curve, different signature scheme. Out of scope until
  someone asks for it, but it is a third shape the signing interface may have to take.
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
