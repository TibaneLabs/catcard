# Feature parity with stock

What stock Coldcard firmware does, per `hw-reference/firmware-features.md` (v5.6.2 /
Q1 1.5.2Q), against what CatCard does today, and the order the gaps get closed in.

✅ done · 🟡 partial · ❌ missing · ➖ deliberately different (see the note)

`firmware-features.md` is a capability catalog, not a format reference. Where a feature has
to interoperate -- a file another wallet reads, a blob stock firmware reads back -- the
contract comes from a public standard (BIP, SLIP, PSBT, descriptors) or from the
format documents in `hw-reference/`, never from stock's code (`CLEANROOM.md`).

## Order of work

Dependency first, then what a user needs to hold funds safely:

1. ~~**Wallet export as output descriptors** (BIP-380) to SD~~ -- done: Utils → Export
   wallet, all four single-sig accounts including `tr()`. Nothing can be signed yet at all,
   so taproot is no more of a promise than the other three, and step 2 covers it.
2. ~~**PSBT signing, single-sig**~~ -- written, untested on hardware: P2WPKH, P2SH-P2WPKH,
   P2PKH and P2TR key-path, from a `.psbt` on the card (Ready to Sign picks it up on its
   own when there is one), change proven by re-deriving it, fee shown and capped,
   SIGNED.PSB written back and FINAL.TXN too when nothing further is needed. PSBT v2
   (BIP-370) is named as unsupported rather than misread.
3. ~~**BIP-39 passphrase**~~ -- written, untested on hardware: Settings → Passphrase, typed
   on the keypad or keyboard, shown with the fingerprint and first address of the wallet it
   opens, kept in RAM only, and the main menu says when one is in force.
4. ~~**Address Explorer and Verify Address**~~ -- written, untested on hardware: all four
   types, accounts and both chains in the explorer; Verify address types an address and
   searches this wallet's own derivations for it.
5. **Message signing** -- legacy (BIP-137) written, untested on hardware: Utils → Sign
   message, armoured to SIGNED.TXT. BIP-322 still to do.
6. ~~**BIP-85**~~ -- written, untested on hardware: Utils → Derive child, with 12/24 words,
   XPRV, WIF, a base64 password and 32 bytes of hex, all against the BIP's own vectors.
7. **Settings store** -- in progress: the slot format, the dictionary, the internal-flash
   driver and the LittleFS medium are written and host-tested, and Debug → Settings store
   exercises them under the pre-login key. What is left is the mk3's SPI-NOR medium, using
   the settings for anything, and the re-key when the seed changes.
8. **Multisig and descriptor import**.
9. **Encrypted backup and restore**.
10. **Import paths** beyond words: xprv, raw master secret, Seed XOR, backup file.
11. **Q1 transports**: QR scanner and display (incl. BBQr), NFC.
12. **Trick PINs, login protections, Seed Vault, temporary seeds**.
13. **HSM, Spending Policy, Coldcard Cosign** -- last: they are policy engines on top of
    everything above.

## 1. Standards

| Standard | Stock | CatCard | Where / what is left |
|---|---|---|---|
| BIP-32 | ✅ | ✅ | `catcard-wallet::bip32`, all official vectors |
| BIP-39 | ✅ | 🟡 | words ✅, passphrase ✅ (untested on hardware); NFKD still refused for non-ASCII (`ROADMAP.md` M5) |
| BIP-43/44/49/84 | ✅ | ✅ | paths, addresses, accounts and both chains |
| BIP-45/48 (multisig paths) | ✅ | ❌ | step 8 |
| BIP-67 sorted multisig | ✅ | ❌ | step 8 |
| BIP-85 | ✅ | 🟡 | words, WIF, XPRV, hex, password; the BIP's vectors pass |
| BIP-137 legacy message | ✅ | 🟡 | signed and self-verified; untested on hardware |
| BIP-141/143/144 | ✅ | ✅ | addresses, BIP-143 sighash, witness serialisation, finalise and extract |
| BIP-174 PSBT v0 | ✅ | 🟡 | read and signed (`outscript`); untested on hardware |
| BIP-370 PSBT v2 | ✅ | ❌ | refused by name, not misread |
| BIP-322 | ✅ | ❌ | step 5 |
| BIP-21 URIs | ✅ | 🟡 | address QR carries `bitcoin:` for legacy/nested; no amounts or labels |
| BIP-380/383 descriptors | ✅ | 🟡 | single-sig export ✅ (Utils → Export wallet, BIP-389 `<0;1>`; verified on an mk3 against Address Explorer); import: step 8 |
| SLIP-132 | ✅ | ❌ | read with step 8; export optional |
| SLIP-44 | ✅ | ✅ | coin type in paths |
| BIP-86 taproot | ❌ (EDGE only) | ✅ | addresses, `tr()` export, BIP-341 key-path signing -- beyond parity |
| BIP-93, BIP-129, BIP-388, SLIP-39, SLIP-32 | ❌ | ❌ | beyond parity |

## 2. Seed and entropy

| Feature | Stock | CatCard | Notes |
|---|---|---|---|
| New seed, 12/24 words | ✅ | ✅ | two SEs + MCU TRNG through `EntropyPool` |
| Mandatory user entropy | ✅ | ➖ | offered, never required (`SECRETS-AND-SETTINGS.md`) |
| Dice / coin / key-mash input | ✅ | ❌ | optional extra source; after step 7 |
| View TRNG Words | ✅ | ✅ | Utils |
| Dice-only seed | ✅ | ❌ | |
| Import words (12/18/24) | ✅ | ✅ | |
| Import xprv / raw master / backup / clone / TAPSIGNER / QR | ✅ | ❌ | steps 9-11 |
| Seed XOR split and join | ✅ | ❌ | step 10 |
| BIP-85 | ✅ | 🟡 | words, WIF, XPRV, hex, password; the BIP's vectors pass |
| BIP-39 passphrase | ✅ | 🟡 | Settings → Passphrase, RAM only; untested on hardware |
| Temporary seeds, Seed Vault, Lock Down Seed | ✅ | ❌ | step 12 |
| View seed words, SeedQR | ✅ | ❌ | words at creation only; needs a guarded view |
| Destroy seed | ✅ | ✅ | Settings |

## 3. Addresses

| Feature | Stock | CatCard | Notes |
|---|---|---|---|
| P2PKH, P2WPKH, P2SH-P2WPKH display | ✅ | ✅ | Address Explorer, with QR |
| Taproot display | ✅ | ✅ | Address Explorer |
| Accounts, change chain, start index | ✅ | 🟡 | account and chain keys in the explorer; no custom-path entry |
| Explorer export (CSV, QR, NFC) | ✅ | 🟡 | QR per address only |
| Verify address / ownership | ✅ | 🟡 | Utils → Verify address, 4 types x 3 accounts x 2 chains x 100 |
| Multisig addresses | ✅ | ❌ | step 8 |

## 4. Multisig and descriptors

All ❌ -- step 8 (and step 1 for single-sig descriptor export). Needs the settings store to
remember registered wallets.

## 5. PSBT and signing

| Feature | Stock | CatCard | Notes |
|---|---|---|---|
| Ready to Sign entry | ✅ | ✅ | the card's lone `.psbt`, or a picker |
| Parse, review, sign, write back | ✅ | 🟡 | done; untested on hardware |
| Change validation, fee limit, sighash policy | ✅ | ✅ | change re-derived, 10% cap, SIGHASH_ALL only |
| Finalise to a network transaction | ✅ | ✅ | FINAL.TXN, as hex |
| Batch sign, Sign Text File, USB / NFC / QR entry | ✅ | ❌ | SD first; others with their transports |
| Multisig inputs, foreign inputs, coinjoin | ✅ | ❌ | steps 2 and 8 |

## 6. Message signing and Proof of Reserves

| Feature | Stock | CatCard | Notes |
|---|---|---|---|
| Legacy signed message | ✅ | 🟡 | Utils → Sign message, typed on the device, armoured to SIGNED.TXT |
| Signing a message from a file | ✅ | ❌ | with the other file flows |
| BIP-322, Proof of Reserves | ✅ | ❌ | step 5's remainder |

## 7. Backup, stores and transports

| Feature | Stock | CatCard | Notes |
|---|---|---|---|
| Encrypted backup and restore | ✅ | ❌ | step 9 |
| Clone Coldcard | ✅ | ❌ | after step 9 |
| Secure Notes, WIF store | ✅ | ❌ | after step 7 |
| Wallet export presets | ✅ | 🟡 | descriptor file for the three single-sig accounts; presets that are not standards need a public format |
| microSD | ✅ | ✅ | FAT12/16/32 and exFAT, cards to 2 TB, format |
| Virtual Disk | ✅ | 🟡 | USB Drive serves the SD card; no RAM disk |
| USB | ✅ | ➖ | our own HID protocol (`USB.md`): upgrade, logs, status; no signing yet |
| NFC | ✅ | ❌ | step 11 |
| QR / BBQr | ✅ | ❌ | step 11 (address QR display exists) |
| PushTx, Key Teleport | ✅ | ❌ | after step 11 |

## 8. Security features

| Feature | Stock | CatCard | Notes |
|---|---|---|---|
| Two-part PIN with anti-phishing words | ✅ | ✅ | parts limited to 2-6 digits, as stock requires |
| Set PIN, change PIN | ✅ | ✅ | |
| Test Login | ✅ | ❌ | |
| Brick after 13 attempts | ✅ | ✅ | the bootloader and SE enforce it |
| Trick PINs (duress, brick, wipe, delta...) | ✅ | ❌ | step 12; needs the settings store |
| Scrambled keypad, login countdown, kill key, SD 2FA, nickname, idle timeout | ✅ | ❌ | step 12 |
| Calculator login (Q1) | ✅ | ❌ | |
| HSM mode, Spending Policy, CCC | ✅ | ❌ | step 13 |
| Hobbled mode | ✅ | ❌ | step 12 |
| Secure Logout | ✅ | ✅ | |
| Genuine light | ✅ | ➖ | the bootloader drives it from the image signature; a dev-signed image shows red |
| Paper wallets | ✅ | ❌ | |

## 9. Upgrade, tools, settings

| Feature | Stock | CatCard | Notes |
|---|---|---|---|
| Upgrade from SD, USB | ✅ | ✅ | signature and board checked; stock `.dfu` accepted from SD |
| Upgrade from Virtual Disk | ✅ | ❌ | |
| Downgrade floor | ✅ | ✅ | enforced by the bootloader |
| DFU Upgrade, Bless Firmware | ✅ | ❌ | |
| Reflash GPU (Q1) | ✅ | ❌ | the GPU is only probed and driven |
| List / delete files, format SD | ✅ | 🟡 | browse and format ✅; delete ❌ |
| Verify Sig File | ✅ | ❌ | with step 5 |
| Selftest, Warm Reset, versions | ✅ | 🟡 | selftest in Debug, version and chip in About; no warm reset entry |
| Preferences (units, timeouts, brightness, USB/NFC/VDisk toggles, testnet) | ✅ | ❌ | step 7 |

## 10. Chains

Stock is Bitcoin mainnet, testnet4 and regtest. CatCard's `catcard-wallet::chain` carries the
chain in every address and path; a testnet switch arrives with the settings store (step 7).
Optional multichain support is beyond parity.

## 11. CatCard beyond stock

Not parity items, listed so the table above is not mistaken for the whole picture:
optional multichain, preemptive kernel, multi-source entropy with live analysis, SD cards to
2 TB with exFAT, the GPU busy bar and hardware scrolling, games.
