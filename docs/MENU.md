# Where our menu sits next to stock's

Measured against `hw-reference/menu-map-mk4-mk5-q1-v5.6.2.md`, which is a clean-room
trace of stock v5.6.2 / v1.5.2Q. The point is not to copy it item for item — we have
fewer features and one deliberate change of shape — but that **someone who knows a
Coldcard should find things where they expect them**, and where they cannot, that it be
on purpose and written down.

Three kinds of entry below: ✅ same place as stock, 🔀 deliberately different, and ❌ a
divergence we have not decided about yet.

## The main menu

Stock's is a list of up to nine items; ours is a 3×2 grid of icons on the Q1 and the same
six names as a list on the mono boards. That is the deliberate change of shape, so the
question for each item is only whether it is *reachable where a stock user would look*.

| Ours | Stock | |
|---|---|---|
| `Sign` → `Scan` (Q1), `From SD`, `By NFC`, `Message`, `Text file`, `Verify` | `Ready To Sign`; `NFC Tools` → `Sign PSBT`; `File Management` → `Sign Text File`, `Verify Sig File` | 🔀 one entry for everything signable, asking where it comes from; stock scatters the four. A PSBT that is a BIP-322 proof of reserves (one 0-sat `OP_RETURN` output, input 0 spending `to_spend`) gets the proof review instead of the spend review, from every source: the message is typed and checked against input 0, the screen says the address, the UTXO count and total and that nothing is spent, every input of ours is signed under `SIGHASH_ALL` only, the signed PSBT is written as usual and -- when every input was ours -- the finalised proof is written as `PROOF.TXT` (`<name>-proof.txt` in a batch), an armoured signed message whose signature is `pof` + the finalised PSBT |
| `Addresses` | `Address Explorer` | 🔀 shorter, to fit a tile. Stock's `Account Number` and `Start Idx` rows are keys on the address screen here (`2` and `4`), because that screen holds the state they change; `Custom Path` is a row on the list, as it is in stock. Sharing the address on screen -- the QR (confirm) and `6` → `Share by NFC` -- asks whether to attach an amount (typed in the display units) and a label, and then emits a BIP-21 `bitcoin:` URI; the bare address stays the default |
| `Notes` (Q1, `cat_secnap`) | `Secure Notes & Passwords` (Q1, `secnap`) | 🔀 shorter; the same gate under our own key -- the tile appears once the feature is turned on from Settings → `Secure notes`, and goes with `Disable Feature`. Notes, passwords (with TOTP codes), edit / delete / sort, export to SD or Virtual Disk as `notes.json` or a password-sealed `notes.7z`, import with merge. Per item: `Sign Note Text` goes through the same signer as Sign → `Message` (format, address type and path asked) and writes `<title>-signed.txt`; `Send Password` types the item into the host over Keyboard EMU (Enter offered, asked before a keystroke goes out, refused in one line while the keyboard is off or no host is listening); `Apply as BIP-39 Passphrase` applies it as a typed passphrase is applied -- fingerprint and first address shown, RAM only, no save-to-card offer |
| `Utils` | `Advanced/Tools` | ❌ different word for the same drawer |
| `Settings` | `Settings` | ✅ |
| `Scan QR` (Q1, blank device) | `Scan Any QR Code` (Q1, `has_qr`) | 🔀 a tile only on a blank device; with a wallet, the QR key opens the scanner from any menu |
| `Logout` (mk3/mk4/mk5) | `Secure Logout` (`not has_battery`) | ✅ same gate: a device with a power button does not need a menu entry to stop |
| `Help` | `Help` (mk4/mk5 only, `not has_qwerty`) | 🔀 on every board, and on Settings and Utils too; one short screen each, in our words |
| — | `Passphrase` (top level, shortcut `p`) | ❌ ours is in Settings; a stock user looks for it on the main menu |
| `Type Passwords` (`cat_kbemu` on) | `Type Passwords` (`emu` **and** `has_secrets`) | ✅ same gate, same place on the mono boards' list (before Settings); on the Q1 it is a seventh tile, alone on the grid's second page, rather than a row inside Notes -- stock's row is BIP-85 password typing, which is not a Notes feature and exists on boards without Notes. A BIP-85 password child (length and index asked as under Derive → `BIP-85`) is typed into the host and never shown; on the Q1 with Secure Notes on, the notes' password items are offered beside it |
| — | `Seed Vault`, `Start HSM Mode` | not implemented |
| `[XFP]` / `<XFP>` header row (mk4/mk5) | `<XFP>` / `[XFP]` header item (`hmx`) | 🔀 on the mono boards the row appears when another key is in force, or always with Settings → `Home menu XFP` (own key `cat_xfp`); the Q1 names the wallet in its status bar on every screen instead |

On a device with no seed, stock's top menu is `New Seed Words` / `Import Existing` /
`Migrate Coldcard` / … / `Advanced/Tools` / `Settings`. Ours puts `New` and `Import` in
the two tiles whose jobs do not exist yet (Sign and Addresses), which is the same idea in
the grid's shape. `Notes` is dropped there too, as stock drops it: no seed, no notes.

`Import` holds stock's Import Existing: `Words` (12/18/24 asked first, and the last word
offered from the checksum-valid set alone, as stock does), `Clone`, `TAPSIGNER` (stored,
or used for this session only), `XPRV` (stored as the master, in the stash's own node
shape) and `Seed XOR` (joined, then offered for keeping). Stock's `Restore Backup` row is
`Utils` → `Backup` here.

## Settings

| Ours | Stock | |
|---|---|---|
| `Login` → `Change PIN` | `Login Settings` → `Change Main PIN` | ✅ |
| `Login` → `Nickname` | `Login Settings` → `Set Nickname` | ✅ |
| `Login` → `Test login` | `Login Settings` → `Test Login Now` | ✅ a wrong PIN counts, as in stock; refused with fewer than 4 tries left |
| `Login` → `Scramble keys` | `Login Settings` → `Scramble Keys` (`rngk`) | 🔀 stored as our own `cat_rngk` until stock's value format is known; switched on only after a test login with the row shuffled |
| `Login` → `Login countdown` | `Login Settings` → `Login Countdown` (`lgto`) | 🔀 stored as our own `cat_lgto` (minutes), same 5 min–28 day range; a 10 s sample runs before it is saved |
| `Login` → `Kill key` (release builds) | `Login Settings` → `Kill Key` (`kbtn`) | 🔀 own key `cat_kbtn`; a digit, armed only after a test login shows the PIN lacks it; fast wipe `[I]` |
| `Login` → `MicroSD 2FA` (release builds) | `Login Settings` → `MicroSD 2FA` (`sd2fa`) | 🔀 own key `cat_sd2fa` and card file `catcard.2fa`; a token read back before it is enrolled |
| — | `Trick PINs` | blocked: gate 22's slot layout is not in the reference (HARDWARE-OPEN-ITEMS) |
| `Spending Policy` → `Single-Signer` → `Edit Policy...`, `Word Check`, `Allow Notes` (Q1), `Related Keys`, `Last Violation`, `Remove Policy`, `Test Drive`, `ACTIVATE` | `Advanced/Tools` → `Spending Policy` → `Single-Signer` → the same (§SP1) | 🔀 a setting rather than a tool, beside Multisig; root wallet only, since the policy lives in the stored wallet's file. Stock's rows in stock's order; the enable story first. Own key `cat_sssp`, one JSON object (§"Spending Policy and hobbled mode" below) |
| `Spending Policy` → `Single-Signer` → `Edit Policy...` → `Max Magnitude`, `Limit Velocity`, `Whitelist Addresses` → `Scan QR` (Q1) / `Import from File` / ‹each address› / `Clear Whitelist`, `Web 2FA` | `SpendingPolicyMenu` (§SP-POL) | 🔀 stock's rows; the magnitude is asked as whole BTC then satoshis; `Web 2FA` is present and answers "needs the Web 2FA spec" (HARDWARE-OPEN-ITEMS) |
| `Spending Policy` → `Co-Sign Multisig (CCC)` | `Spending Policy` → `Co-Sign Multisig (CCC)` | ❌ the row answers "a later wave" |
| `Login` → `Calculator login` (Q1) | `Login Settings` → `Calculator Login` (`calc`) | 🔀 own key `cat_calc`; on only after a test login through the calculator screen. The PIN convention is ours (below) -- the reference says "enter PIN as a formula" and no more |

Kill key and MicroSD 2FA erase the seed on their own, so **development builds leave them
out** (the `dev` feature, on by default; `SHIP=1` drops it): no bench unit can lose its seed
to one. `make lint` still type-checks them through the release-shape clippy runs.
| `Passphrase` → `Enter passphrase`, `Restore saved` | *(top level in stock)* → `Edit Phrase`, `Restore Saved` | ❌ drawer as above; also under Derive. Once applied, `Save to card?` seals it to `catcard-passphrases.bin` (our own format: AES-256-GCM under an HMAC of the seed's entropy, so only these words open it); `Restore saved` lists entries by the fingerprint they open, applies one with the same fingerprint-and-address check as typing (and stock's warning when the fingerprint is not the saved one), or deletes it |
| `Multisig` | `Multisig Wallets` (`has_secrets`) | ✅ same drawer, same gate; the rows below follow stock's §MS |
| `Multisig` → ‹wallet› → `View Details`, `Rename`, `Delete`, `Coldcard Export`, `Electrum Wallet`, `Descriptors` → `View Descriptor` / `Export` / `Bitcoin Core` | `make_ms_wallet_menu` | ✅ same rows; the Coldcard (J1) and Electrum (K) exports are offered for BIP-67 wallets only, as stock does; every export goes to the card, the Virtual Disk or (Q1) BBQr, signed at our cosigner path when this device is a member |
| `Multisig` → `Import` | `Import` | 🔀 one row reads a descriptor file **or** a Coldcard setup file (J1) from the card or the Virtual Disk; also reached from Scan QR (Q1) and the NFC tag. Exact duplicates are refused, near-duplicates (same keys in another shape, or the same name) warned and asked |
| `Multisig` → `Export XPUB` | `Export XPUB` | ✅ `ccxp-{xfp}.json` (L), account asked |
| `Multisig` → `Create Airgapped` | `Create Airgapped` | ✅ format, account, then cosigners' `ccxp-*.json` from a file or (Q1) a BBQr scan, our key added last, M asked, the wallet stored and its setup file exported |
| `Multisig` → `Trust policy` | `Trust PSBT?` | 🔀 own key `cat_mstrust`; verify / offer / trust |
| `Multisig` → `Unsorted Multisig?` | `Unsorted Multisig?` | 🔀 own key `cat_msunsorted`; off by default, and a `multi()` wallet is refused at every import path while it is |
| `Multisig` → `Full Address View?` | `Full Address View?` | 🔀 own key `cat_msfulladdr`; off by default, and the Address Explorer then shows a registered wallet's addresses as eight characters at each end |
| — | `Skip Checks?` | not implemented |
| `Idle timeout` | `Idle Timeout` (`idle_to`, `batt_to`, in seconds) | 🔀 own keys `cat_idle` / `cat_bidle`, in **minutes** -- a separate key rather than the same name in another unit; same off/1/2/5/15/30/60 range, with the Q1's battery value asked first. Honoured by `crate::idle`, which logs out through the same callgate as the power button |
| `Display units` | `Display Units` (`rz`) | 🔀 own key `cat_units` (`btc`/`mbtc`/`bits`/`sats`) rather than stock's decimal count; the rows show the same amount written four ways. Honoured by `crate::signtx::btc`, the only place that turns satoshis into text |
| `Max network fee` | `Max Network Fee` (`fee_limit`) | 🔀 own key `cat_fee` (percent, or `none`); 10% default, 25%, 50%, or no cap -- which is asked twice and warned, and which no unreadable value can ever become |
| `Hardware On/Off` → `USB port`, `Virtual Disk`, `Keyboard EMU`, `NFC Sharing` | `Hardware On/Off` (`du` = disable-USB, `vidsk`, `nfc`, keyboard-emu) | 🔀 own keys `cat_usb` / `cat_vdsk` / `cat_kbemu` / `cat_nfc`; the USB and disk ones written as *enable* rather than stock's *disable*; **only the switches this firmware really obeys** -- the port is a real soft-disconnect, the disk gates Utils → USB Drive (which also refuses while the port is off), the keyboard adds a boot-protocol USB keyboard interface beside the wallet's and re-enumerates (off by default; `docs/USB.md`), and NFC Sharing gates every tag use (`crate::nfc::enabled`): off, each entry point says so in one line and the tag is neither written nor read. The mk3 lists the two it can honour, `USB port` and `Keyboard EMU` |
| `SLIP-132 export` | the per-export "(2)" SLIP-132 toggle on Export XPUB / wallet exports | 🔀 one setting, own key `cat_slip132`, off by default like stock's; on, the generic JSON carries `_pub` (ypub/zpub/Ypub/Zpub) beside the classic xpub. Electrum's file is SLIP-132 regardless; descriptors stay classic. SLIP-132 keys are always *read* on import |
| `NFC Push Tx` → `coldcard.com`, `mempool.space`, `Custom URL`, `Disabled` | `NFC Push Tx` → the `PUSHTX_SUPPLIERS`, `Custom URL...`, `Disable` (`ptxurl`) | 🔀 own key `cat_pushtx`; stock's rows and order, with coldcard.com the default and off an explicit choice. The link is the public PushTx format (`catcard_nfc::pushtx`), warned about on the way in as stock does, and offered -- never written unasked -- after a transaction finalises |
| `Menu wrapping` | `Menu Wrapping` (`wa`) | 🔀 own key `cat_wrap`; the cursor comes round at the ends of a list (`catcard_ui::scroll`) |
| `Secure notes` (Q1) | `Advanced/Tools` → `Secure Notes & Passwords` (Q1) | 🔀 under Settings rather than the tools drawer: it is where the feature is switched on (the opt-in story, `cat_secnap`) and switched back on after `Disable Feature`; with it on, the same screen the main-menu `Notes` tile opens |
| `Danger zone` → `Seed tools` → `View words` | `Advanced/Tools` → `Danger Zone` → `Seed Functions` → `View Seed Words` | 🔀 Danger zone under Settings rather than Advanced/Tools; also shows an XPRV or WIF key, which have no words |
| `Danger zone` → `Seed tools` → `Destroy seed` | `… Seed Functions` → `Destroy Seed` | ✅ |
| `Danger zone` → `Seed tools` → `Lock down seed` | `… Seed Functions` → `Lock Down Seed` (`is_tmp`) | ✅ same gate; a words key or an XPRV, stored in the stash's own node shape -- not a WIF key |
| `Danger zone` → `B85 Idx Values` | `Danger Zone` → `B85 Idx Values` | ✅ own key `cat_b85idx`; the BIP-85 index is capped at 9999 until this lifts it to 2^31-1, after a warning |
| Derive → `XOR split`, `XOR join` | `… Seed Functions` → `Seed XOR` | 🔀 with the other ways to reach a wallet; `XOR join` is also `Import` → `Seed XOR` on a blank device |
| Derive → `Import key` → `Words`, `XPRV`, `WIF key`, `TAPSIGNER` | `Temporary Seed` → `Import Words`, `Import XPRV`, `Tapsigner Backup` | ✅ in force for the session, nothing stored; `Lock down seed` keeps one |
| Derive → `New words` | `Temporary Seed` → `Generate Words` → `12 Words` / `24 Words` | ✅ the same generator as `New`, same entropy sources and optional dice/coin/mash, into the session rather than the slot |
| `Danger zone` → `Seed tools` → `SeedQR` | `… Seed Functions` → `Export SeedQR` | ✅ Q1 only; both shapes, Standard and Compact, and the scanner reads either back |
| `Danger zone` → `Sighash checks` | `Danger Zone` → `Sighash Checks` (Block / Warn) | ✅ own key `cat_sighash`, default Block; Warn is asked twice. Under Warn a non-ALL sighash on our input is named (input and type) on a warning before the review, a consolidation under one is still refused, and the signature is made over the digest the type defines |
| `Danger zone` → `Set High-Water` | `… Danger Zone` → `Set High-Water` | ✅ **irreversible**: gate 21/2 records this build's timestamp as the floor; shown, asked three times, refused when the mark is already at or above this build |
| `Danger zone` → `Bless Firmware` | `… Danger Zone` → `Bless Firmware` | ✅ gate 18/5 on the logged-in struct: commits this image's checksum and turns the genuine light green |
| `Danger zone` → `DFU Upgrade` | `FactoryMenu` → `DFU Upgrade` | 🔀 always answers "unavailable on a locked device": the lock flag (gate 19/2) has no documented encoding, so the state is never *positively* open, and `enter_dfu` is never called. Use Upgrade Firmware |
| `Danger zone` → `Settings Space` | `… Danger Zone` → `Settings Space` | ✅ slots in use and bytes in files, against the region |
| — | `Debug Functions`, `I Am Developer.`, `Seed Vault` toggle, `Wipe HSM Policy`, caches, `AE Start Index`, `MCU Key Slots`, `Wipe LFS`, `Nuke Device` | not implemented, or elsewhere |
| `About` → page 3 | `Advanced/Tools` → `View Identity` | 🔀 different name and drawer; the third About page is the identity: firmware and build time, hardware, bootloader version string, SE presence, bag number (read only), master fingerprint, the genuine light's raw reading, the high-water mark. The serial the gate exposes is the STM32 UID on page 2 |
| `Debug` | `Advanced/Tools` → `Danger Zone` / `I Am Developer.` | 🔀 asked for here deliberately |
| `Debug` → `Warm Reset` | `I Am Developer.` → `Warm Reset`; `Danger Zone` → `Debug Functions` → `Warm Reset` | ✅ same drawer; ours asks first and says the PIN is asked for again |
| `Home menu XFP` (mk3/mk4/mk5) | `Buried Settings` → `Home Menu XFP` (`hmx`: Only Tmp / Always Show) | 🔀 flat, like Menu wrapping; own key `cat_xfp`. Not on the Q1, whose bar always names the wallet |
| — | `Buried Settings` → the rest | not implemented; `Menu wrapping` is above |
| *(Hardware On/Off → `Keyboard EMU`)* | `Keyboard EMU` (top-level Settings row; adds `Type Passwords`) | 🔀 under Hardware On/Off with the other USB switches; used by the main menu's `Type Passwords`, Notes → `Send Password` and the BIP-85 password child's "type into host" (Confirm on its screen), all through one screen that offers Enter and asks before typing |
| `Debug` → `Keyboard EMU test` | `Debug Functions` → `Keyboard Test` | 🔀 stock's tests the device's own keys; ours types a fixed line into the host to prove the emulated keyboard |

Every preference above is kept in the **wallet in force's own** settings file, under our
own `cat_*` key rather than stock's -- the reference names stock's keys but not the shape
of their values, and a value written in a shape stock misread could log a stock device out
every minute or leave it with no fee cap. Each is read once at login (`crate::prefs`) and
any unreadable or out-of-range value reads as the safe default. On the mk3 the same file
lives in the SPI-NOR's thirty-two slots (`catcard_settings::norslots`), so the rows are
there too; what the mk3 lacks is what its hardware lacks -- `Virtual Disk` and `NFC
Sharing` under Hardware On/Off, `NFC Push Tx`, `Kill key` / `MicroSD 2FA` (the fast wipe,
callgate 23, is mk4+), `Chains` only in a multichain build, and `Debug → Settings to SD`.

## Utils (stock: Advanced/Tools)

| Ours | Stock | |
|---|---|---|
| `Export wallet` | `Export Wallet` | 🔀 Generic JSON and the six vendors that read it, plus Descriptor, Key Expression, Export XPUB, Dump Summary, Address CSV (stock writes that one from the explorer; it is here too because it is an export). Still to write: Bitcoin Core (B), Electrum + Blue Wallet (C), Wasabi (D), Unchained (E), and the account-numbered descriptor variants — Bull Bitcoin, Zeus, Samourai pre/post-mix (F) |
| *(Derive → `BIP-85`)* | `Derive Seeds (BIP-85)` | 🔀 under Derive, not here: the same list -- words, XPRV, WIF, a password of a chosen length, 32 or 64 bytes hex -- and the words, XPRV and WIF children can be put in force from it; a password child can be typed into the host (stock's "(6) = type over USB") while Keyboard EMU is on |
| `Browse SD card`, `Format` | `File Management` → `List Files`, `Format SD Card`, `Format RAM Disk` | ❌ stock nests these; ours are flat. `Format` is one row for every medium: it asks which -- the SD card (slot A or B on the Q1) or the Virtual Disk where the board has one -- and a board with a single slot and no Virtual Disk (mk3) goes straight to the card. Selecting a file in the listing offers `Delete file` — asked first, and irreversible; the file picker used mid-signing does not offer it |
| `Browse SD card` → a file → `Share by NFC`, `Share as BBQr` | `File Management` → `NFC File Share`, `BBQr File Share`, `QR File Share` | 🔀 reached from the file rather than from a drawer that then asks for one; the card or the Virtual Disk, bounded by the tag (8 kB, "too large" otherwise); BBQr on the Q1 types the file (`P` for a PSBT, `U` for text, `B` for anything else). No plain `QR File Share`: BBQr is the one animated format here |
| `NFC Tools` → `Sign PSBT`, `Show Address`, `Sign Message`, `Verify Sig File`, `File Share`, `Import Multisig`, `Push Transaction`, `Import Words` | `NFC Tools` → the same, plus `Verify Address`; `Temporary Seed` → `Import Words` → `Import via NFC` | 🔀 stock's drawer, less `Verify Address` (the explorer verifies and shares from the address it shows) and with the words import in it rather than under Temporary Seed. Sign Message puts the armoured signature back on the tag; a signed PSBT that is not yet final comes back on the tag too; Import Multisig hands what arrived straight to the importer, recognised by the one detector the scanner and the card use; every row refuses in one line while NFC Sharing is off |
| *(Sign → Message, Text file, Verify; Addresses → Verify an address)* | `File Management` → `Sign Text File`, `Verify Sig File`; `NFC Tools` → `Verify Address` | 🔀 message signing and checking under the one Sign; verify an address sits with the addresses it checks, rather than in a tag drawer — the tag is reached from whichever screen has something to put on it. `Message` and `Text file` ask the address type -- the four single-key types, or a registered multisig wallet (mk4/mk5/Q1), which signs a cosigner's share -- then the format from those the type allows (legacy / BIP-322 simple / BIP-322 full; nested segwit has legacy and full, taproot simple and full) and the path (default: the first address of the matching account on the network in force, or a custom one), and the confirmation screen names the format chosen; `Text file` reads the three-line request form (message, path, address format) Sparrow and stock's docs use, and writes `<name>-signed.txt` beside it; on the Q1 a scanned text offers `Sign as message` and the result can be shown as BBQr. `Verify` reads a signed `.txt` or an export's `.sig` sidecar, hashing each file the sidecar names and reporting OK / CHANGED / missing per file before the signature verdict; it reads legacy, BIP-322 simple, full and proof-of-reserves signatures (a proof's verdict says how many UTXOs and their total; a multisig cosigner's share reports "cosigner 1 of M" rather than a verdict) |
| `USB Drive` | `Settings` → `Hardware On/Off` → `Virtual Disk` | ❌ different drawer -- but the switch is stock's: with `Virtual Disk` (or the USB port) off, this refuses to start |
| `Analyze RNG`, `Games` | — | 🔀 ours alone; `View TRNG Words` is a Debug entry now |
| `Delete PSBTs` | `Settings` → `Delete PSBTs` (toggle) and `File Management` | 🔀 an action, not a toggle: lists the `*.psbt`, `*.txn`, `SIGNED.PSB`, `FINAL.TXN` files in the root of the chosen storage, asks, overwrites each with zeros to its length, then unlinks it |
| `Upgrade Firmware` | `Upgrade Firmware` → `From MicroSD`, `From VirtDisk` | ✅ stock's own name, in stock's drawer; asks SD card or Virtual Disk, then browses for the `.dfu`. No `Show Version` under it: About has that |
| `Help` | — | 🔀 what the drawer holds, in one screen |
| `Backup` → `Save backup`, `Verify backup`, `Restore backup`, `Clone Coldcard` | `Backup` → `Backup System`, `Verify Backup`, `Restore Backup`, `Clone Coldcard` | ✅ same drawer, same four rows. Save offers stock's three protections — twelve words (the default), a typed passphrase, or cleartext (asked twice, never the default) — and writes `backup-<XFP>.7z` to the card or the Virtual Disk. Verify decrypts, parses and compares the fingerprint against the wallet in force without changing anything; ours goes further than stock's CRC-only check. Restore and Verify read from either storage and detect a cleartext file rather than asking for a password. A backup can also be loaded for the session only, from Derive → `Import key` → `Coldcard backup` (stock's Temporary Seed → Coldcard Backup) |
| `WIF Store` → per key: `Reveal WIF`, `Sign MSG`, `Descriptors`, `Delete key`; `Generate new key`, `Import from SD`, `Export All`, `Clear All` | `WIF Store` → per key: `Detail`, `Descriptors`, `Addresses`, `Sign MSG`, `Delete`; `Import WIF`, `Export All`, `Clear All` | ✅ same drawer and rows; the addresses are on the key's own screen rather than a row under it, and `Generate new key` is ours. `Sign MSG` signs legacy as the chosen address type; `Descriptors` are `wpkh` / `sh(wpkh)` / `pkh` over the public key with BIP-380 checksums; `Export All` writes the keys in plain text behind two warnings; `Clear All` asks twice and cannot be undone |
| *(Derive → `Import key`, `New words`)* | `Temporary Seed` | 🔀 under Derive, with the other ways to change the key in force |
| — | `Paper Wallets`, `Danger Zone` | not implemented, or elsewhere |
| *(Settings → `Spending Policy`)* | `Spending Policy` | 🔀 a setting here, not a tool; see the Settings table |

`Upgrade Firmware` has no icon, so on the Q1 it is the one cell that shows its name
alone — and, as the seventh entry, it is alone on the grid's second page.

## What to do about the ❌ rows

`Scan QR` works: the module is configured once at boot and slept, and the LAMP key
lights its illumination while held, as stock does when idle. The wire protocol is in
`catcard-qr`, tested against the reference's own worked example.

They are not all worth fixing. The tile labels are short because a 107-pixel cell holds
ten characters of the face they are drawn in, and `Advanced/Tools` is eighteen. But
`Passphrase`, `Destroy seed` and `Upgrade Firmware` are the three where a stock user
would genuinely hunt, and the last two matter most: one destroys a wallet and the other
replaces the firmware.

`Upgrade Firmware` is done: it was `Debug` → `Install from SD`, which is a drawer a
stock user has no reason to open, and it is now `Utils` → `Upgrade Firmware` under
stock's own name. It is the widest tile label on the Q1, which is the cost of using
stock's wording and worth paying for the one entry that replaces the firmware.

## Questions a computer asks (over USB)

Not menu rows: screens that take over whatever is showing, the way a USB upgrade offer
does, when a computer asks inside the encrypted channel (`docs/USB.md` §"Host-wallet
commands"). They appear once the device is unlocked, from the main menu's loop; Cancel
at any step answers the computer "declined". Stock has no equivalent -- its USB protocol
is not implemented here and was not studied.

| Screen | What it asks | |
|---|---|---|
| `Computer asks` → `for this wallet's addresses. Share?` | yes / no, then the **account** (the Address Explorer's field; empty is 0), then on a multichain build **`Chains`**: this wallet's chains in Settings → Chains order, each with its logo and an on/off box, all on to begin with; OK flips a row where it stands (the same toggle list Settings → Chains draws), and `Share these` under the list goes on; then `Share these?` with the account and the number of chains | 🔀 never asks for address types: every script type a UTXO chain supports goes, each with its account xpub; an account chain sends its one address and key. What was shared is remembered for that USB session only |
| `Computer asks` → `you to sign a <chain> transaction` | yes / no, then **the ordinary review** for the chain -- the same screens as Sign from SD, QR or NFC (Bitcoin's with Spending Policy, fee cap, sighash policy and the proof-of-reserves review; EVM's with the signing address added; Solana's) | 🔀 only the keys the computer listed, under accounts shared this session, can sign; an input of ours it did not list stays unsigned and the review says so. After signing, no destination question: `Sent back` `to the computer` |

## Spending Policy and hobbled mode

Stock's single-signer Spending Policy (SSSP) is a per-transaction **magnitude** cap, a
**velocity** limit in blocks, an address **whitelist** and optionally web-2FA; once
`ACTIVATE`d the device is **hobbled** -- signing and addresses only -- and an SE2 trick
PIN is the way back (firmware-features.md §8; help-and-warning-screens.md §12). Ours is
the same feature over our own storage, with these points decided where the reference is
silent, each marked `[I]` in the code:

- **Storage.** One JSON object under our own `cat_sssp` key in the *stored* wallet's
  settings file: `mag` (satoshis, 0 = no cap), `vel` (blocks, 0 = off), `last` (the height
  of the last allowed spend), `words`, `notes`, `okeys`, `active`, `addrs` (at most 25, the
  bound stock gives its whitelist), `viol` (the last refusal). A value under the key that
  will not read is **damaged**, never "off": the device is hobbled and signs nothing until
  the unlock code takes it out. The engine and every bound are host-tested in
  `catcard-settings::policy`.
- **Enforcement at signing** (`policy::enforce`, before the review). Magnitude compares
  what leaves the wallet, change excluded (the review's `Sending` figure). Whitelist means
  every non-change output with value pays a listed address (bech32 compared case-blind; an
  `OP_RETURN` with no value is not a payment). Velocity is measured by the transaction's
  own `nLockTime` when it names a **block height** -- the anti-fee-sniping convention every
  wallet follows, and the number stock's "block-height velocity" has to be measured by on
  a device with no chain; a PSBT with no height lock, or a time lock, is refused under a
  velocity limit rather than measured against a guess. The height of an allowed spend is
  recorded **before** the signature is made, so a transaction that then fails to sign has
  still used its window. A refusal names the rule, is shown, and is recorded as
  `Last Violation`.
- **Hobbled mode** is a filter over the ordinary menus (`policy::hobbled_row`, host-tested
  over the labels), not a second tree. Main: `Sign`, `Addresses`, `Scan QR`, `Utils`,
  `Settings`, `Help`, `Logout`; `Notes` under Allow Notes; `Derive` and `Type Passwords`
  under Related Keys. Utils: the file, export, card and NFC rows, `Upgrade Firmware` and
  `Help`; `WIF Store` under Related Keys; no `Backup`, no `Encrypt card`. Settings: `About`
  and `Help`, and `Passphrase` under Related Keys -- stock's hobbled menu has no Settings
  drawer at all; ours keeps the two rows that write nothing. Derive (Related Keys):
  `Passphrase`, `Import key`, `New words`, `Key vault`, `Back to root`; no BIP-85, no XOR.
  Under the menus, `settings::save_wallet` **refuses every wallet-settings key** while
  hobbled except the policy's own object and a file's identity keys, so a row the filter
  missed (Notes' edit screens, the WIF store's inner rows) still cannot change anything.
- **The unlock code is CatCard's own mechanism.** Stock's escape is a gate-22 trick PIN,
  whose slot layout the reference does not give (HARDWARE-OPEN-ITEMS); this will move to
  gate 22 when it is known. Ours: a code of the PIN's own shape (`prefix-suffix`, four to
  twelve digits), chosen at `ACTIVATE`, kept as PBKDF2-HMAC-SHA256 (50 000 rounds, random
  16-byte salt) under `cat_sssp_unlock` in the pre-login blob. At the PIN prompt -- the pad
  or the Q1 calculator -- the typed halves are checked against it **before** gate 18: a
  match says nothing, gives a fresh prompt for the main PIN, and the session boots
  un-hobbled with the policy suspended (`Settings → Spending Policy` then offers
  `Remove Policy`); anything else is the PIN attempt it looks like, so a guess burns one of
  the thirteen as a trick-PIN guess does. The code is probed against the bootloader at
  enrolment so it cannot be the main PIN (one attempt spent, restored by the next login,
  as Test login does), and matches at most once per boot as a second guard. Activation
  **without** a code is allowed after stock's warning and a second confirmation: no way
  back but destroying the seed. A policy with no rule set cannot be activated.
- **Test Drive** hobbles the session with `EXIT TEST DRIVE` last on the main menu; the
  policy is enforced but records neither a violation nor a spend height, and nothing is
  written as active.
- **Word Check**, when on, asks the first and last seed words before the policy is
  changed, a toggle flipped, or the policy removed; the words are compared inside
  `keywork::run`, both of them whatever the first says. It cannot be turned on for a wallet
  with no words.
- **Web 2FA** is not implemented: its enrolment and verification protocol is not in the
  reference. The row is present and says so. CCC is a later wave.

## Calculator login (Q1)

With `Settings → Login → Calculator login` on, the screen before the PIN is a working
integer calculator (`+ - * /`, parentheses, ENTER evaluates, DELETE erases). The
reference says stock "enters the PIN as a formula" and no more, so the convention is ours:

1. type the **prefix** digits followed by `-` (SYMBOL+q on the Q1's keyboard), then ENTER.
   A dangling minus is a syntax error to a calculator, so no sum ever reaches this step.
   The two anti-phishing words appear where an answer would;
2. type the **suffix** digits alone, then ENTER.

Any other line is a sum, and a sum typed while the words are up drops the pending prefix
(a fresh setup, nothing spent). A wrong PIN says so on the answer line with the tries
left; the count also appears at the bottom from then on, as on the PIN pad. It is *not*
`prefix-suffix` on one line: that is a subtraction, and a calculator that spent an
attempt on every subtraction would brick itself in thirteen sums. The setting goes on
only after a successful test login through the calculator, like Scramble keys. The kill
key (release builds) is honoured for suffix digits only, the one place the screen knows
a digit is a PIN digit.

## Pairing a computer (USB)

Not a menu row: a screen a host brings up. When a host pairs the encrypted USB channel
(`docs/USB.md`, "The encrypted channel"), the device shows a six-digit code and asks —
"Pair with this computer?" over the code on the Q1; the code in the large face with the
question under it on the mono boards — with yes / no. The host tool prints the same code.
Compare them: the same code on both means no relay in between; a different one means say
no. Both people have to say yes for the session to pair, it is done afresh on every
connection, and nothing is remembered — there is no "Paired computers" list.

It takes the screen from wherever the main loop is, the way the firmware-upgrade offer
does (an offer on the screen is answered first). Only after the PIN; one prompt at a time;
it goes away on its own after two minutes, or when the host gives up. Stock has no
equivalent: its USB channel is not paired.

**Pairing blocked** is the other screen a host can bring up: a computer took device keys
and dropped three handshakes without revealing its own, which is what a relay re-rolling
the code looks like. It says how many attempts were abandoned; OK or Cancel dismisses it
and lets pairing go on, and until then every pairing attempt is refused. An honest host
only causes it by crashing mid-handshake.
