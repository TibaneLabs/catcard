# Feature parity with stock

What stock Coldcard firmware does, per `hw-reference/firmware-features.md` (v5.6.2 /
Q1 1.5.2Q), against what CatCard does today, and the order the gaps were closed in.

✅ done · 🟡 partial · ❌ missing · ➖ deliberately different (see the note)

✅ means the stock capability is all there in code; "untested on hardware" beside it means
it has passed its host tests and has not yet been run on a device. 🟡 means some of the
stock capability is still missing. Every verdict names the module or crate that proves it.

`firmware-features.md` is a capability catalog, not a format reference. Where a feature has
to interoperate -- a file another wallet reads, a blob stock firmware reads back -- the
contract comes from a public standard (BIP, SLIP, PSBT, descriptors) or from the
format documents in `hw-reference/`, never from stock's code (`CLEANROOM.md`).

## Order of work

Dependency first, then what a user needs to hold funds safely. Written as history: what
each step landed, then what is left.

1. ~~**Wallet export as output descriptors** (BIP-380)~~ -- Utils → Export wallet, all
   four single-sig accounts including `tr()`; verified on an mk3 against the explorer.
2. ~~**PSBT signing, single-sig**~~ -- P2WPKH, P2SH-P2WPKH, P2PKH and P2TR key-path, from
   SD; change re-derived, fee capped, SIGNED.PSB and FINAL.TXN written back.
3. ~~**BIP-39 passphrase**~~ -- Settings → Passphrase, RAM only, fingerprint and first
   address shown before it takes.
4. ~~**Address Explorer and Verify Address**~~ -- four types, accounts, both chains, custom
   path, CSV export; Verify address searches this wallet's derivations.
5. ~~**Message signing**~~ -- Sign → Message / Text file / Verify; legacy (BIP-137) or
   BIP-322 `simple`.
6. ~~**BIP-85**~~ -- Derive → BIP-85: words, XPRV, WIF, password, hex; children put in force.
7. ~~**Settings store**~~ -- stock's nvstore region read and written on mk4/mk5/Q1
   (`catcard-settings`, `crate::settings`); every preference under our own `cat_*` key,
   read once at login (`crate::prefs`). The mk3's SPI-NOR slots are still not wired.
8. ~~**Multisig and descriptor import**~~ -- Utils → Multisig: import, confirm, list, sign.
9. ~~**Encrypted backup and restore**~~ -- `catcard-backup` 7-Zip AES-256; Utils → Backup.
10. ~~**Import paths beyond words**~~ -- XPRV, raw master, Seed XOR, Clone Coldcard,
    TAPSIGNER, backup; Derive → Import key for the session.
11. ~~**Q1 transports**~~ -- scanner and display (BBQr, BC-UR, SeedQR), NFC in and out.
12. ~~**Login protections, Seed Vault, temporary seeds**~~ -- Test login, Scramble keys,
    Login countdown, Kill key and microSD 2FA (release builds), Key vault, Lock down seed.
13. ~~**Storage**~~ -- exFAT and 2 TB cards, card password, whole-card AES-XTS
    (`crate::sdcrypt`), the PSRAM Virtual Disk (`crate::vdisk`) as a target for every
    export, sign and upgrade path; USB protocol encrypted (`catcard-usb::ncry`).
14. ~~**Parity sweep, 2026-09-26**~~ -- coin type follows the network everywhere;
    Verify address over multisig wallets and the WIF store; BC-UR carries the network;
    USB keyboard emulation (`crate::usbkbd`); backup password modes, Verify Backup and
    backup-as-temporary-seed; message signing with address type and path, the Sparrow
    request form, `.sig` sidecars, hashed Verify Sig, QR out, WIF-store Sign MSG and
    Descriptors; Secure Notes write path, TOTP, export and import; last-word checksum
    filter, BIP-85 hex-64, password length and the 9999 cap, key-mash 65, saved
    passphrases, temporary seed generation, TAPSIGNER for the session, blank-device XPRV
    and XOR; PSBT v2 named, SLIP-132 in and out, timelocks, cosigner hand-off, Sighash
    checks Block/Warn, paged outputs, coinjoin fee-unknown; per-wallet multisig exports
    and rename, Coldcard text import, `ccxp` export, Create Airgapped, QR and NFC import,
    unsorted opt-in, censored addresses; PushTx, NFC Sharing switch, NFC Tools, file share,
    signed PSBT back on the tag; upgrade from the Virtual Disk, Format RAM disk, Delete
    PSBTs, View Identity, Bless Firmware, Set High-Water, DFU row, Settings Space, Home
    menu XFP, Calculator login, Help rows. **All of it untested on hardware.**
15. ~~**Wave 2, the seams**~~ -- Notes → Send Password and the main-menu Type Passwords
    (BIP-85 password typed as keystrokes, or a Secure Notes password on the Q1), the BIP-85
    password screen's "type into host", Notes → Apply as BIP-39 Passphrase applying
    directly (`passphrase::apply`), Notes → Sign Note Text through `signmsg::sign_to_file`
    (`crate::usbkbd::send_screen`). Untested on hardware.
16. **What remains, deliberately deferred**: HSM mode and user management; Spending
    Policy, CCC and Hobbled mode; Trick PINs (blocked on gate 22's slot layout,
    `HARDWARE-OPEN-ITEMS.md`); Key Teleport; BIP-322 `full` / `pof` and Proof of
    Reserves; BIP-370 PSBT v2; BIP-21 amounts and labels; bare P2PK; Reflash GPU; the
    factory menu (Bag Me Now / Ship w/o Bag, MCU key slots); the mk3 settings medium;
    Seed XOR joins that mix in the device's own seed or a vault entry; the
    suspicious-change heuristic; altcoin transaction signing beyond ETH and SOL.

## 1. Standards

| Standard | Stock | CatCard | Where / what is left |
|---|---|---|---|
| BIP-32 | ✅ | ✅ | `catcard-wallet::bip32`, all official vectors |
| BIP-39 | ✅ | ➖ | words and passphrase ✅ (`bip39`, `crate::passphrase`; untested on hardware); a non-ASCII passphrase is **refused** (`Error::PassphraseNotAscii`) rather than NFKD-normalised -- the NFKD commit was reverted (`d082b6b`) |
| BIP-43/44/49/84 | ✅ | ✅ | paths, addresses, accounts and both chains; the coin type follows the network in force (`0663d2d`) |
| BIP-45/48 (multisig paths) | ✅ | ✅ | cosigner origins parsed; `ccxp` export writes the `m/45h` and `m/48h/.../{1h,2h}` keys (`multisig::export`); untested on hardware |
| BIP-67 sorted multisig | ✅ | ✅ | `sortedmulti` default; `multi()` only under Multisig → Unsorted Multisig? (`cat_msunsorted`); BIP-383's vectors pass |
| BIP-85 | ✅ | ✅ | words, WIF, XPRV, hex 32/64, password of a chosen length (`bip85`, `crate::derive`); index capped at 9999 until Danger zone → B85 Idx Values (`cat_b85idx`); the BIP's vectors pass; untested on hardware |
| BIP-137 legacy message | ✅ | ✅ | three address types, chosen path (`message`, `crate::signmsg`); untested on hardware |
| BIP-141/143/144 | ✅ | ✅ | addresses, BIP-143 sighash, witness serialisation, finalise and extract |
| BIP-174 PSBT v0 | ✅ | ✅ | read and signed (`psbtview`, `signer`, `outscript`); untested on hardware |
| BIP-370 PSBT v2 | ✅ | ❌ | named and refused, not misread (`signtx::describe`, `UnsupportedPsbtVersion`) |
| BIP-322 | ✅ | 🟡 | `simple` for P2WPKH and taproot key path (`bip322`); `ful`, `pof` and P2WSH refused by name |
| BIP-21 URIs | ✅ | 🟡 | `bitcoin:` out on the NFC tag and the legacy/nested address QR; `?amount=` cut off a scanned one (`crate::verify`); no amount, label or `wallet=` written |
| BIP-380/383 descriptors | ✅ | ✅ | single-sig export (Utils → Export wallet, BIP-389 `<0;1>`); multisig import and per-wallet View / Export / Bitcoin Core (`crate::msimport`, `multisig`) |
| SLIP-132 | ✅ | ✅ | every form read on import (`bip32::serialize::Slip132`); export behind Settings → SLIP-132 export (`cat_slip132`), off by default like stock |
| SLIP-44 | ✅ | ✅ | coin type 0 / 1 from the network (`chain`) |
| BIP-86 taproot | ❌ (EDGE only) | ✅ | addresses, `tr()` export, BIP-341 key-path signing -- beyond parity |
| BIP-93, BIP-129, BIP-388, SLIP-39, SLIP-32 | ❌ | ❌ | beyond parity |

## 2. Seed and entropy

| Feature | Stock | CatCard | Notes |
|---|---|---|---|
| New seed, 12/24 words | ✅ | ✅ | two SEs + MCU TRNG through `EntropyPool` |
| Mandatory user entropy | ✅ | ➖ | offered after the TRNG words, never required (`menu.rs` new-seed flow; `SECRETS-AND-SETTINGS.md`) |
| Dice / coin / key-mash input | ✅ | ✅ | 50 rolls, 128 flips, 65 presses (`catcard-entropy::user::min_symbols`); stock's `sha256(ASCII rolls)` convention, mixed into the pool rather than replacing it |
| View TRNG Words | ✅ | ✅ | Debug → View TRNG Words |
| Dice-only seed | ✅ | ➖ | user entropy adds to the TRNGs, never replaces them (`ENTROPY.md`) |
| Import words (12/18/24) | ✅ | ✅ | length asked first; the last word offered from the checksum-valid set (`531ea2e`) |
| Import xprv / raw master / backup / clone / TAPSIGNER / QR | ✅ | ✅ | Import → XPRV, Clone (`backup::clone_import`), TAPSIGNER (`crate::tapsigner`, `catcard-backup::tapsigner`), Seed XOR; a stored raw master or xprv node is worked in as is; backup via Utils → Backup → Restore; SeedQR through the scanner (`crate::seedqr`); untested on hardware |
| Seed XOR split and join | ✅ | 🟡 | 2--4 parts, deterministic or from the TRNGs, joined under Derive or Import (`crate::seedxor`, `seedxor`); the join reads typed parts only -- the device's own seed and vault entries are not offered as parts |
| BIP-85 | ✅ | ✅ | as §1; words, XPRV and WIF children can be put in force |
| BIP-39 passphrase | ✅ | ✅ | Settings → Passphrase, RAM only; Save to card / Restore saved / delete in `catcard-passphrases.bin` under a key only these words make (`pwsave`, `680d6a8`); NFKD is the ➖ in §1; untested on hardware |
| Temporary seeds, Seed Vault, Lock Down Seed | ✅ | ✅ | Derive → Import key (words, XPRV, WIF, TAPSIGNER, Coldcard backup) and New words for the session; Key vault (`crate::vault`, stock's `seeds` format); Danger zone → Seed tools → Lock down seed |
| View seed words, SeedQR | ✅ | ✅ | Danger zone → Seed tools → View words (xprv or WIF where there are no words); SeedQR Standard and Compact out and back in on the Q1, both shapes' vectors host-tested |
| Destroy seed | ✅ | ✅ | Danger zone → Seed tools → Destroy seed |

## 3. Addresses

| Feature | Stock | CatCard | Notes |
|---|---|---|---|
| P2PKH, P2WPKH, P2SH-P2WPKH display | ✅ | ✅ | Address Explorer, with QR |
| Taproot display | ✅ | ✅ | Address Explorer |
| P2PK (bare pubkey) receive and sign | ✅ | ❌ | no bare-pubkey script anywhere in `catcard-wallet` |
| Accounts, change chain, start index | ✅ | ✅ | stepped with the arrows, or typed: `2` the account, `4` where the walk starts |
| Custom derivation path | ✅ | ✅ | Addresses → Custom path, shown in all four types |
| Explorer export (CSV, QR, NFC) | ✅ | ✅ | `6` offers the card, the Virtual Disk or the tag: CSV of index, path and address, or the address as a `bitcoin:` URI on the tag; QR per address |
| Verify address / ownership | ✅ | ✅ | Addresses → Verify an address, typed or scanned (Q1): the WIF store, 4 types x 3 accounts x 2 chains x 100, then every registered multisig wallet (`crate::verify`); untested on hardware |
| Multisig addresses | ✅ | ✅ | registered wallets past the single-sig types, censored to eight characters each end unless Multisig → Full Address View? (`cat_msfulladdr`, `msimport::CENSORED_COLS`) |

## 4. Multisig and descriptors

| Feature | Stock | CatCard | Notes |
|---|---|---|---|
| Import a wallet from a descriptor file | ✅ | ✅ | Multisig → Import from SD or Virtual Disk, Scan QR (Q1) or the NFC tag (`crate::msimport`); untested on hardware |
| Import as Coldcard text (J1) | ✅ | ✅ | the same Import row reads a setup file (`multisig::coldcard`) |
| Import from a PSBT's keys, trust policy | ✅ | ✅ | Multisig → Trust policy: verify / offer / trust (`cat_mstrust`, `msimport::trust_from_psbt`) |
| Confirm the wallet before storing | ✅ | ✅ | M-of-N, script form, sortedness, every cosigner, whether this device is one; exact duplicates refused, near-duplicates warned |
| List, inspect, rename and delete registered wallets | ✅ | ✅ | Multisig → ‹wallet› → View Details / Rename / Delete; identity is the descriptor's checksum |
| Remember them across a reboot | ✅ | ➖ | our own settings key `ccms`, not stock's `multisig`, whose value schema is undocumented -- a device can hold both |
| Sign a multisig input | ✅ | ✅ | registered or trusted wallets; the rebuilt script must equal the one the coin is locked to; untested on hardware |
| Multisig change recognition | ✅ | ✅ | same rule, plus the shape rules single-sig change obeys |
| Export this device's cosigner keys | ✅ | ✅ | Multisig → Export XPUB (`ccxp-{xfp}.json`); per wallet: Coldcard Export (J1), Electrum Wallet (K), Descriptors → Export / Bitcoin Core (`multisig::export`) |
| Create Airgapped | ✅ | ✅ | format, account, cosigners' `ccxp-*.json` from a file or a BBQr scan, M asked, the wallet stored and its setup file exported |
| Up to 15 cosigners | ✅ | ✅ | `multisig::MAX_COSIGNERS` |
| Unsorted multisig, opt-in | ✅ | ✅ | `cat_msunsorted`, off by default; `multi()` refused at every import path while it is |
| Multisig in Address Explorer | ✅ | ✅ | as §3; no account axis, since the descriptor fixes it |
| Skip Checks?, a descriptor without a checksum | ✅ | ➖ | refused, deliberately (`msimport`); the file another wallet wrote is the thing being checked |

Not available on the mk3, which has no settings store: nothing can be registered there, so
every multisig input is refused.

## 5. PSBT and signing

| Feature | Stock | CatCard | Notes |
|---|---|---|---|
| Ready to Sign entry | ✅ | ✅ | the card's lone `.psbt`, or a picker; SD or the Virtual Disk |
| Parse, review, sign, write back | ✅ | ✅ | outputs paged eight at a time, the Sign key on the last page only (`signtx::PAGE`); untested on hardware |
| Change validation, fee limit | ✅ | 🟡 | change re-derived and proven; the cap is Settings → Max network fee (`cat_fee`: 10% default, 25/50/none); no "suspicious change path" heuristic on top of the proof |
| Sighash policy | ✅ | ✅ | SIGHASH_ALL, or Danger zone → Sighash checks Warn (`cat_sighash`, `signer::SighashPolicy`): a non-ALL type named before the review, consolidation under one still refused; absent on the mk3 |
| Finalise to a network transaction | ✅ | ✅ | FINAL.TXN as hex; a PSBT still short of signatures is handed off to the next cosigner rather than called a failure |
| Batch sign | ✅ | ✅ | Sign → Batch sign: every batch-source `.psbt` on the card, up to `signtx::MAX_BATCH` (8) per pass, one signed file each (`signtx::batch_sign`) |
| Entry over SD / QR / NFC | ✅ | ✅ | SD and Virtual Disk, the Q1 scanner (BBQr, `ur:crypto-psbt`), the NFC tag |
| Entry over USB | ✅ | ➖ | our own HID protocol carries no PSBT (`USB.md`); the stock USB protocol is not spoken |
| Sign Text File | ✅ | ✅ | Sign → Text file (§6) |
| Multisig inputs | ✅ | ✅ | registered or trusted wallets only (§4) |
| Foreign inputs, coinjoin | ✅ | ✅ | signed for what is ours; a foreign input leaves the fee UNKNOWN and says so (`psbtview`, `signtx`) |
| Timelocks | ✅ | ✅ | absolute `nLockTime` and BIP-68 relative locks surfaced, ineffective ones named (`psbtview::timelock`) |
| WIF-store inputs | ✅ | ✅ | a bare key's matching input is signed beside the seed's (`signer::sign_input_with_secret`) |
| PSBT v2 | ✅ | ❌ | §1 |

## 6. Message signing and Proof of Reserves

| Feature | Stock | CatCard | Notes |
|---|---|---|---|
| Legacy signed message | ✅ | ✅ | Sign → Message: format, address type and path asked (default the account's first address); out to SD, the Virtual Disk, BBQr (Q1) or the NFC tag (NFC Tools → Sign Message) |
| Signing a message from a file | ✅ | ✅ | Sign → Text file: a `.txt` or the three-line Sparrow request form (`message::Request`), `<name>-signed.txt` beside it |
| Verify Sig File | ✅ | ✅ | Sign → Verify: a signed `.txt` or an export's `.sig` sidecar, each named file hashed and reported OK / CHANGED / missing (`crate::verifysig`); no wallet needed; "cannot check" for a script it has no interpreter for |
| BIP-322 | ✅ | 🟡 | `simple` only (§1) |
| Proof of Reserves | ✅ | ❌ | deferred with `ful` / `pof` |

## 7. Backup, stores and transports

| Feature | Stock | CatCard | Notes |
|---|---|---|---|
| Encrypted backup and restore | ✅ | ✅ | Utils → Backup: twelve words (default), a typed passphrase, or cleartext asked twice; Verify backup parses and compares the fingerprint (deeper than stock's CRC); Restore, and load for the session from Derive → Import key → Coldcard backup (`crate::backup`, `catcard-backup`); untested on hardware |
| Clone Coldcard | ✅ | ✅ | both halves: `ccbk-start.bin` from the target, `ccbk-clone.bin` from the source (`backup::clone_export` / `clone_import`, `catcard-backup::clone`); untested on hardware |
| Secure Notes & Passwords (Q1) | ✅ | ✅ | notes, passwords with TOTP, edit / delete / sort, export as `notes.json` or password-sealed `notes.7z`, import with merge, Disable Feature, Send Password as USB keystrokes, Apply as BIP-39 Passphrase, Sign Note Text (`crate::notes`, `catcard-settings::notes`, `cat_secnap`); untested on hardware |
| WIF store | ✅ | ✅ | Utils → WIF Store: 30 keys (`wifs::MAX_KEYS`), Reveal, Sign MSG, Descriptors, Delete, Generate, Import, Export All, Clear All (`crate::wifstore`); matching inputs signed (§5) |
| Wallet export presets | ✅ | ✅ | Generic JSON, Sparrow, Cove, Nunchuk, Theya, Bitcoin Safe, Bitcoin Core, Electrum, Blue Wallet, Wasabi, Unchained, Descriptor, Bull Bitcoin, Zeus, Samourai pre/post-mix, Key Expression, Export XPUB, Dump Summary, Address CSV, plus Keystone (`crate::export`, `menu.rs` export rows) |
| microSD | ✅ | ✅ | FAT12/16/32 and exFAT, cards to 2 TB, format, card password, whole-card AES-XTS (`crate::sdcrypt`) |
| Virtual Disk | ✅ | ✅ | PSRAM-backed (`crate::vdisk`), served by USB Drive, gated by Settings → Hardware On/Off; Format RAM disk; every export, sign and upgrade path can target it |
| USB | ✅ | ➖ | our own HID protocol (`USB.md`, `catcard-usb`): upgrade, logs, status, encrypted under `ncry`; a stock host tool does not reach it, and it signs nothing |
| NFC | ✅ | ✅ | signed transaction out as a PushTx link, address out as `bitcoin:`, PSBT in and the signed one back, NFC Tools (sign / verify / multisig / words / file share) all behind NFC Sharing (`crate::nfc`, `catcard-nfc`); untested on hardware |
| QR / BBQr | ✅ | ✅ | the Q1 scans BBQr and BC-UR, signs what it catches, hands the result back as BBQr or `ur:crypto-psbt`, exports `ur:crypto-account` for the network in force (`catcard-bcur`), reads and writes SeedQR, shares any file as BBQr |
| PushTx | ✅ | ✅ | Settings → NFC Push Tx: coldcard.com, mempool.space, custom, disabled (`cat_pushtx`, `catcard_nfc::pushtx`); offered after a transaction finalises, never written unasked |
| Key Teleport (Q1) | ✅ | ❌ | deferred |

## 8. Security features

| Feature | Stock | CatCard | Notes |
|---|---|---|---|
| Two-part PIN with anti-phishing words | ✅ | ✅ | parts limited to 2-6 digits, as stock requires |
| Set PIN, change PIN | ✅ | ✅ | Settings → Login → Change PIN |
| Test Login | ✅ | ✅ | Settings → Login → Test login; refused below four tries left |
| Brick after 13 attempts | ✅ | ✅ | the bootloader and SE enforce it |
| Trick PINs (duress, brick, wipe, delta...) | ✅ | ❌ | blocked on gate 22's slot layout (`HARDWARE-OPEN-ITEMS.md`) |
| Scrambled keypad, login countdown, kill key, SD 2FA, nickname, idle timeout | ✅ | ✅ | all under Settings → Login and Idle timeout (`crate::pinentry`, `crate::guard`, `crate::idle`); kill key and SD 2FA in release builds only (the `dev` feature leaves them out); untested on hardware |
| Calculator login (Q1) | ✅ | ➖ | Settings → Login → Calculator login (`cat_calc`, `pinentry`): the PIN convention is ours -- prefix then `-` then ENTER, suffix then ENTER -- since the reference gives none (`MENU.md`); untested on hardware |
| HSM mode, user management | ✅ | ❌ | deferred |
| Spending Policy, CCC | ✅ | ❌ | deferred |
| Hobbled mode | ✅ | ❌ | deferred |
| Secure Logout | ✅ | ✅ | main menu on the boards without a power button |
| Genuine light | ✅ | ✅ | read on About page 3 (`crate::identity`); Danger zone → Bless Firmware commits this image and turns it green (gate 18/5) |
| Paper wallets | ✅ | ✅ | Utils → Paper wallet: a DRBG key unrelated to the seed, WIF and address with QRs to the card (`crate::paperwallet`); no BIP-38 encryption |
| Address-cache clear | ✅ | ➖ | no cache to clear: every address is re-derived when shown |

## 9. Upgrade, tools, settings

| Feature | Stock | CatCard | Notes |
|---|---|---|---|
| Upgrade from SD, USB, Virtual Disk | ✅ | ✅ | Utils → Upgrade Firmware asks SD or Virtual Disk (`crate::sdupgrade`), and a dropped image is offered on eject; USB through our protocol; signature and board checked, stock `.dfu` unwrapped |
| Downgrade floor | ✅ | ✅ | enforced by the bootloader; Danger zone → Set High-Water raises it (gate 21/2, irreversible, asked three times) |
| Bless Firmware | ✅ | ✅ | Danger zone → Bless Firmware (`identity`) |
| DFU Upgrade | ✅ | ➖ | Danger zone → DFU Upgrade always answers "unavailable on a locked device": the lock flag has no documented encoding and every bench unit is RDP=2, so `enter_dfu` is never called |
| Reflash GPU (Q1) | ✅ | ❌ | the GPU is only probed and driven (`crate::gpu`) |
| List / delete files, format SD, format RAM disk, delete PSBTs | ✅ | ✅ | Utils → Browse SD card (a file offers Delete), Format SD card, Format RAM disk, Delete PSBTs (blank then unlink) (`crate::filemgmt`) |
| Verify Sig File | ✅ | ✅ | Sign → Verify (§6) |
| Selftest, Warm Reset, versions, power off | ✅ | ✅ | Debug → Selftest and Warm Reset; About holds the versions; View Identity is About page 3; the Q1 power button (`crate::power`) |
| Settings store | ✅ | 🟡 | stock's nvstore region read and written on mk4/mk5/Q1 (`catcard-settings::nvstore`, `crate::settings`), Danger zone → Settings Space; the mk3's SPI-NOR slots are not wired, so it has no store (`prefs.rs`) |
| Preferences (units, timeouts, brightness, wrapping, XFP, USB/NFC/VDisk/keyboard toggles, fee, testnet) | ✅ | ➖ | every one offered (`crate::prefs`, `MENU.md`), but under our own `cat_*` keys rather than stock's, whose value shapes are undocumented; a bad value reads as the safe default; absent on the mk3 |
| Factory / provisioning (bag number, Bag Me Now, Ship w/o Bag, MCU key slots) | ✅ | ❌ | the bag number is shown read-only on About page 3; nothing is written |

## 10. Chains

Stock is Bitcoin mainnet, testnet4 and regtest. CatCard's `catcard-wallet::chain` carries the
chain in every address and path; Danger zone → Testnet mode picks it, kept under the wallet's
`chain` key (`catcard_settings::prefs::CHAIN`), and the coin type, address prefixes and
`ur:crypto-account` follow it. Optional multichain support (ETH, SOL, and address display
for the rest) is beyond parity; transaction signing for other altcoins is deferred.

## 11. CatCard beyond stock

Not parity items, listed so the table above is not mistaken for the whole picture:
taproot signing (BIP-86/341), optional multichain with ETH and SOL transaction signing
(`crate::evmtx`, `crate::solanatx`), an encrypted USB channel (`ncry`), whole-card SD
encryption, a preemptive kernel, multi-source entropy with live analysis (Utils → Analyze
RNG), a WIF store that generates keys, a Verify backup that parses rather than CRCs, the
Keystone export, a PNG viewer, the GPU busy bar and hardware scrolling, games.
