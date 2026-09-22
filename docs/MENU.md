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
| `Sign` → `Scan` (Q1), `From SD`, `By NFC`, `Message` | `Ready To Sign`; `NFC Tools` → `Sign PSBT`; `File Management` → `Sign Text File` | 🔀 one entry for everything signable, asking where it comes from; stock scatters the three |
| `Addresses` | `Address Explorer` | 🔀 shorter, to fit a tile. Stock's `Account Number` and `Start Idx` rows are keys on the address screen here (`2` and `4`), because that screen holds the state they change; `Custom Path` is a row on the list, as it is in stock |
| `Notes` (Q1) | `Secure Notes & Passwords` (Q1, `secnap`) | 🔀 shorter; stock also gates on the `secnap` setting, which we do not read yet |
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
| `Passphrase` | *(top level in stock)* | ❌ see above; also under Derive |
| `Multisig` | `Multisig Wallets` (`has_secrets`) | ✅ same drawer, same gate |
| `Idle timeout` | `Idle Timeout` (`idle_to`, `batt_to`, in seconds) | 🔀 own keys `cat_idle` / `cat_bidle`, in **minutes** -- a separate key rather than the same name in another unit; same off/1/2/5/15/30/60 range, with the Q1's battery value asked first. Honoured by `crate::idle`, which logs out through the same callgate as the power button |
| `Display units` | `Display Units` (`rz`) | 🔀 own key `cat_units` (`btc`/`mbtc`/`bits`/`sats`) rather than stock's decimal count; the rows show the same amount written four ways. Honoured by `crate::signtx::btc`, the only place that turns satoshis into text |
| `Max network fee` | `Max Network Fee` (`fee_limit`) | 🔀 own key `cat_fee` (percent, or `none`); 10% default, 25%, 50%, or no cap -- which is asked twice and warned, and which no unreadable value can ever become |
| `Hardware On/Off` → `USB port`, `Virtual Disk` | `Hardware On/Off` (`du` = disable-USB, `vidsk`, plus NFC / keyboard-emu rows) | 🔀 own keys `cat_usb` / `cat_vdsk`, written as *enable* rather than stock's *disable*; **only the two switches this firmware really obeys** -- the port is a real soft-disconnect, the disk gates Utils → USB Drive (which also refuses while the port is off). NFC and keyboard emulation are not offered, because nothing here would honour them |
| `Menu wrapping` | `Menu Wrapping` (`wa`) | 🔀 own key `cat_wrap`; the cursor comes round at the ends of a list (`catcard_ui::scroll`) |
| `Danger zone` → `Seed tools` → `View words` | `Advanced/Tools` → `Danger Zone` → `Seed Functions` → `View Seed Words` | 🔀 Danger zone under Settings rather than Advanced/Tools; also shows an XPRV or WIF key, which have no words |
| `Danger zone` → `Seed tools` → `Destroy seed` | `… Seed Functions` → `Destroy Seed` | ✅ |
| `Danger zone` → `Seed tools` → `Lock down seed` | `… Seed Functions` → `Lock Down Seed` (`is_tmp`) | ✅ same gate; words keys only -- an XPRV root is not usable here yet |
| Derive → `XOR split`, `XOR join` | `… Seed Functions` → `Seed XOR` | 🔀 with the other ways to reach a wallet |
| `Danger zone` → `Seed tools` → `SeedQR` | `… Seed Functions` → `Export SeedQR` | ✅ Q1 only; both shapes, Standard and Compact, and the scanner reads either back |
| — | the rest of `Danger Zone` | not implemented |
| `About` | `Advanced/Tools` → `View Identity` | ❌ different name, different drawer |
| `Debug` | `Advanced/Tools` → `Danger Zone` / `I Am Developer.` | 🔀 asked for here deliberately |
| `Debug` → `Warm Reset` | `I Am Developer.` → `Warm Reset`; `Danger Zone` → `Debug Functions` → `Warm Reset` | ✅ same drawer; ours asks first and says the PIN is asked for again |
| — | `NFC Push Tx`, `Keyboard EMU`, `Buried Settings` | not implemented |

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
| *(Derive → `BIP-85`)* | `Derive Seeds (BIP-85)` | 🔀 under Derive, not here: the same list, and the words, XPRV and WIF children can be put in force from it |
| `Browse SD card`, `Format SD card` | `File Management` → `List Files`, `Format SD Card` | ❌ stock nests these; ours are flat. Selecting a file in the listing offers `Delete file` — asked first, and irreversible; the file picker used mid-signing does not offer it |
| *(Sign → Message; Addresses → Verify an address)* | `File Management` → `Sign Text File`; `NFC Tools` → `Verify Address` | 🔀 message signing under the one Sign; verify sits with the addresses it checks, rather than in a tag drawer — the tag is reached from whichever screen has something to put on it |
| `USB Drive` | `Settings` → `Hardware On/Off` → `Virtual Disk` | ❌ different drawer -- but the switch is stock's: with `Virtual Disk` (or the USB port) off, this refuses to start |
| `Analyze RNG`, `Games` | — | 🔀 ours alone; `View TRNG Words` is a Debug entry now |
| `Upgrade Firmware` | `Upgrade Firmware` → `From MicroSD` | ✅ stock's own name, in stock's drawer; ours installs from the card and has no `Show Version` or `From VirtDisk` under it |
| — | `Backup`, `Temporary Seed`, `Paper Wallets`, `WIF Store`, `Spending Policy`, `Danger Zone` | not implemented, or elsewhere |

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
