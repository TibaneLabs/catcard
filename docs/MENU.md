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
| `Sign` → `Scan` (Q1), `From SD`, `By NFC`, `Message`, `Text file`, `Verify` | `Ready To Sign`; `NFC Tools` → `Sign PSBT`; `File Management` → `Sign Text File`, `Verify Sig File` | 🔀 one entry for everything signable, asking where it comes from; stock scatters the four |
| `Addresses` | `Address Explorer` | 🔀 shorter, to fit a tile. Stock's `Account Number` and `Start Idx` rows are keys on the address screen here (`2` and `4`), because that screen holds the state they change; `Custom Path` is a row on the list, as it is in stock |
| `Notes` (Q1, `cat_secnap`) | `Secure Notes & Passwords` (Q1, `secnap`) | 🔀 shorter; the same gate under our own key -- the tile appears once the feature is turned on from Settings → `Secure notes`, and goes with `Disable Feature`. Notes, passwords (with TOTP codes), edit / delete / sort, export to SD or Virtual Disk as `notes.json` or a password-sealed `notes.7z`, import with merge, Sign Note Text. No `Send Password` yet: no USB keyboard interface |
| `Utils` | `Advanced/Tools` | ❌ different word for the same drawer |
| `Settings` | `Settings` | ✅ |
| `Scan QR` (Q1, blank device) | `Scan Any QR Code` (Q1, `has_qr`) | 🔀 a tile only on a blank device; with a wallet, the QR key opens the scanner from any menu |
| `Logout` (mk3/mk4/mk5) | `Secure Logout` (`not has_battery`) | ✅ same gate: a device with a power button does not need a menu entry to stop |
| — | `Passphrase` (top level, shortcut `p`) | ❌ ours is in Settings; a stock user looks for it on the main menu |
| — | `Type Passwords`, `Seed Vault`, `Start HSM Mode` | not implemented |
| — | `<XFP>` header item | 🔀 ours is in the status bar instead, always visible |

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
| — | `Calculator Login` | not implemented |

Kill key and MicroSD 2FA erase the seed on their own, so **development builds leave them
out** (the `dev` feature, on by default; `SHIP=1` drops it): no bench unit can lose its seed
to one. `make lint` still type-checks them through the release-shape clippy runs.
| `Passphrase` → `Enter passphrase`, `Restore saved` | *(top level in stock)* → `Edit Phrase`, `Restore Saved` | ❌ drawer as above; also under Derive. Once applied, `Save to card?` seals it to `catcard-passphrases.bin` (our own format: AES-256-GCM under an HMAC of the seed's entropy, so only these words open it); `Restore saved` lists entries by the fingerprint they open, applies one with the same fingerprint-and-address check as typing (and stock's warning when the fingerprint is not the saved one), or deletes it |
| `Multisig` | `Multisig Wallets` (`has_secrets`) | ✅ same drawer, same gate |
| `Idle timeout` | `Idle Timeout` (`idle_to`, `batt_to`, in seconds) | 🔀 own keys `cat_idle` / `cat_bidle`, in **minutes** -- a separate key rather than the same name in another unit; same off/1/2/5/15/30/60 range, with the Q1's battery value asked first. Honoured by `crate::idle`, which logs out through the same callgate as the power button |
| `Display units` | `Display Units` (`rz`) | 🔀 own key `cat_units` (`btc`/`mbtc`/`bits`/`sats`) rather than stock's decimal count; the rows show the same amount written four ways. Honoured by `crate::signtx::btc`, the only place that turns satoshis into text |
| `Max network fee` | `Max Network Fee` (`fee_limit`) | 🔀 own key `cat_fee` (percent, or `none`); 10% default, 25%, 50%, or no cap -- which is asked twice and warned, and which no unreadable value can ever become |
| `Hardware On/Off` → `USB port`, `Virtual Disk`, `Keyboard EMU`, `NFC Sharing` | `Hardware On/Off` (`du` = disable-USB, `vidsk`, `nfc`, keyboard-emu) | 🔀 own keys `cat_usb` / `cat_vdsk` / `cat_kbemu` / `cat_nfc`; the USB and disk ones written as *enable* rather than stock's *disable*; **only the switches this firmware really obeys** -- the port is a real soft-disconnect, the disk gates Utils → USB Drive (which also refuses while the port is off), the keyboard adds a boot-protocol USB keyboard interface beside the wallet's and re-enumerates (off by default; `docs/USB.md`), and NFC Sharing gates every tag use (`crate::nfc::enabled`): off, each entry point says so in one line and the tag is neither written nor read |
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
| — | the rest of `Danger Zone` | not implemented |
| `About` | `Advanced/Tools` → `View Identity` | ❌ different name, different drawer |
| `Debug` | `Advanced/Tools` → `Danger Zone` / `I Am Developer.` | 🔀 asked for here deliberately |
| `Debug` → `Warm Reset` | `I Am Developer.` → `Warm Reset`; `Danger Zone` → `Debug Functions` → `Warm Reset` | ✅ same drawer; ours asks first and says the PIN is asked for again |
| — | `Buried Settings` | not implemented |
| *(Hardware On/Off → `Keyboard EMU`)* | `Keyboard EMU` (top-level Settings row; adds `Type Passwords`) | 🔀 under Hardware On/Off with the other USB switches; the typing screens that use it (`Send Password`, BIP-85 passwords) are theirs to add |
| `Debug` → `Keyboard EMU test` | `Debug Functions` → `Keyboard Test` | 🔀 stock's tests the device's own keys; ours types a fixed line into the host to prove the emulated keyboard |

Every preference above is kept in the **wallet in force's own** settings file, under our
own `cat_*` key rather than stock's -- the reference names stock's keys but not the shape
of their values, and a value written in a shape stock misread could log a stock device out
every minute or leave it with no fee cap. Each is read once at login (`crate::prefs`) and
any unreadable or out-of-range value reads as the safe default. The mk3 has no settings
store, so these rows are absent there rather than present and inert.

## Utils (stock: Advanced/Tools)

| Ours | Stock | |
|---|---|---|
| `Export wallet` | `Export Wallet` | 🔀 Generic JSON and the six vendors that read it, plus Descriptor, Key Expression, Export XPUB, Dump Summary, Address CSV (stock writes that one from the explorer; it is here too because it is an export). Still to write: Bitcoin Core (B), Electrum + Blue Wallet (C), Wasabi (D), Unchained (E), and the account-numbered descriptor variants — Bull Bitcoin, Zeus, Samourai pre/post-mix (F) |
| *(Derive → `BIP-85`)* | `Derive Seeds (BIP-85)` | 🔀 under Derive, not here: the same list -- words, XPRV, WIF, a password of a chosen length, 32 or 64 bytes hex -- and the words, XPRV and WIF children can be put in force from it |
| `Browse SD card`, `Format SD card` | `File Management` → `List Files`, `Format SD Card` | ❌ stock nests these; ours are flat. Selecting a file in the listing offers `Delete file` — asked first, and irreversible; the file picker used mid-signing does not offer it |
| `Browse SD card` → a file → `Share by NFC`, `Share as BBQr` | `File Management` → `NFC File Share`, `BBQr File Share`, `QR File Share` | 🔀 reached from the file rather than from a drawer that then asks for one; the card or the Virtual Disk, bounded by the tag (8 kB, "too large" otherwise); BBQr on the Q1 types the file (`P` for a PSBT, `U` for text, `B` for anything else). No plain `QR File Share`: BBQr is the one animated format here |
| `NFC Tools` → `Sign PSBT`, `Show Address`, `Sign Message`, `Verify Sig File`, `File Share`, `Import Multisig`, `Push Transaction`, `Import Words` | `NFC Tools` → the same, plus `Verify Address`; `Temporary Seed` → `Import Words` → `Import via NFC` | 🔀 stock's drawer, less `Verify Address` (the explorer verifies and shares from the address it shows) and with the words import in it rather than under Temporary Seed. Sign Message puts the armoured signature back on the tag; a signed PSBT that is not yet final comes back on the tag too; Import Multisig writes what arrived to the card and opens the importer on it (a text-taking importer is pending); every row refuses in one line while NFC Sharing is off |
| *(Sign → Message, Text file, Verify; Addresses → Verify an address)* | `File Management` → `Sign Text File`, `Verify Sig File`; `NFC Tools` → `Verify Address` | 🔀 message signing and checking under the one Sign; verify an address sits with the addresses it checks, rather than in a tag drawer — the tag is reached from whichever screen has something to put on it. `Message` and `Text file` ask the format (legacy / BIP-322), the address type and the path (default: the first address of the matching account on the network in force, or a custom one); `Text file` reads the three-line request form (message, path, address format) Sparrow and stock's docs use, and writes `<name>-signed.txt` beside it; on the Q1 a scanned text offers `Sign as message` and the result can be shown as BBQr. `Verify` reads a signed `.txt` or an export's `.sig` sidecar, hashing each file the sidecar names and reporting OK / CHANGED / missing per file before the signature verdict |
| `USB Drive` | `Settings` → `Hardware On/Off` → `Virtual Disk` | ❌ different drawer -- but the switch is stock's: with `Virtual Disk` (or the USB port) off, this refuses to start |
| `Analyze RNG`, `Games` | — | 🔀 ours alone; `View TRNG Words` is a Debug entry now |
| `Upgrade Firmware` | `Upgrade Firmware` → `From MicroSD` | ✅ stock's own name, in stock's drawer; ours installs from the card and has no `Show Version` or `From VirtDisk` under it |
| `Backup` → `Save backup`, `Verify backup`, `Restore backup`, `Clone Coldcard` | `Backup` → `Backup System`, `Verify Backup`, `Restore Backup`, `Clone Coldcard` | ✅ same drawer, same four rows. Save offers stock's three protections — twelve words (the default), a typed passphrase, or cleartext (asked twice, never the default) — and writes `backup-<XFP>.7z` to the card or the Virtual Disk. Verify decrypts, parses and compares the fingerprint against the wallet in force without changing anything; ours goes further than stock's CRC-only check. Restore and Verify read from either storage and detect a cleartext file rather than asking for a password. A backup can also be loaded for the session only, from Derive → `Import key` → `Coldcard backup` (stock's Temporary Seed → Coldcard Backup) |
| `WIF Store` (mk4/mk5/Q1) → per key: `Reveal WIF`, `Sign MSG`, `Descriptors`, `Delete key`; `Generate new key`, `Import from SD`, `Export All`, `Clear All` | `WIF Store` → per key: `Detail`, `Descriptors`, `Addresses`, `Sign MSG`, `Delete`; `Import WIF`, `Export All`, `Clear All` | ✅ same drawer and rows; the addresses are on the key's own screen rather than a row under it, and `Generate new key` is ours. `Sign MSG` signs legacy as the chosen address type; `Descriptors` are `wpkh` / `sh(wpkh)` / `pkh` over the public key with BIP-380 checksums; `Export All` writes the keys in plain text behind two warnings; `Clear All` asks twice and cannot be undone |
| *(Derive → `Import key`, `New words`)* | `Temporary Seed` | 🔀 under Derive, with the other ways to change the key in force |
| — | `Paper Wallets`, `Spending Policy`, `Danger Zone` | not implemented, or elsewhere |

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
