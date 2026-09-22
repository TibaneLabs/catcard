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
| `Sign` → `Scan` (Q1), `From SD`, `Message` | `Ready To Sign`; `NFC Tools` → `Sign PSBT`; `File Management` → `Sign Text File` | 🔀 one entry for everything signable, asking where it comes from; stock scatters the three |
| `Addresses` | `Address Explorer` | 🔀 shorter, to fit a tile |
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
| `Danger zone` → `Seed tools` → `View words` | `Advanced/Tools` → `Danger Zone` → `Seed Functions` → `View Seed Words` | 🔀 Danger zone under Settings rather than Advanced/Tools; also shows an XPRV or WIF key, which have no words |
| `Danger zone` → `Seed tools` → `Destroy seed` | `… Seed Functions` → `Destroy Seed` | ✅ |
| `Danger zone` → `Seed tools` → `Lock down seed` | `… Seed Functions` → `Lock Down Seed` (`is_tmp`) | ✅ same gate; words keys only -- an XPRV root is not usable here yet |
| Derive → `XOR split`, `XOR join` | `… Seed Functions` → `Seed XOR` | 🔀 with the other ways to reach a wallet |
| — | `… Seed Functions` → `Export SeedQR`; the rest of `Danger Zone` | not implemented |
| `About` | `Advanced/Tools` → `View Identity` | ❌ different name, different drawer |
| `Debug` | `Advanced/Tools` → `Danger Zone` / `I Am Developer.` | 🔀 asked for here deliberately |
| `Debug` → `Warm Reset` | `I Am Developer.` → `Warm Reset`; `Danger Zone` → `Debug Functions` → `Warm Reset` | ✅ same drawer; ours asks first and says the PIN is asked for again |
| — | `Hardware On/Off`, `Display Units`, `Max Network Fee`, `Idle Timeout`, `NFC Push Tx`, `Keyboard EMU`, `Buried Settings` | not implemented |

## Utils (stock: Advanced/Tools)

| Ours | Stock | |
|---|---|---|
| `Export wallet` | `Export Wallet` | 🔀 Generic JSON and the six vendors that read it, plus Descriptor, Key Expression, Export XPUB, Dump Summary. Still to write: Bitcoin Core (B), Electrum + Blue Wallet (C), Wasabi (D), Unchained (E), and the account-numbered descriptor variants — Bull Bitcoin, Zeus, Samourai pre/post-mix (F) |
| *(Derive → `BIP-85`)* | `Derive Seeds (BIP-85)` | 🔀 under Derive, not here: the same list, and the words, XPRV and WIF children can be put in force from it |
| `Browse SD card`, `Format SD card` | `File Management` → `List Files`, `Format SD Card` | ❌ stock nests these; ours are flat. Selecting a file in the listing offers `Delete file` — asked first, and irreversible; the file picker used mid-signing does not offer it |
| *(Sign → Message; Addresses → Verify an address)* | `File Management` → `Sign Text File`; `NFC Tools` → `Verify Address` | 🔀 message signing under the one Sign; verify with the addresses it checks, as we have no NFC |
| `USB Drive` | `Settings` → `Hardware On/Off` → `Virtual Disk` | ❌ different drawer |
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
