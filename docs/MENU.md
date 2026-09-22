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
| `Sign` | `Ready To Sign` | 🔀 shorter, to fit a tile |
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
| `Passphrase` | *(top level in stock)* | ❌ see above |
| `Multisig` | `Multisig Wallets` (`has_secrets`) | ✅ same drawer, same gate |
| `Destroy seed` | `Advanced/Tools` → `Danger Zone` → `Destroy Seed` | ❌ ours is two steps shallower than stock's, on the most destructive entry we have |
| `About` | `Advanced/Tools` → `View Identity` | ❌ different name, different drawer |
| `Debug` | `Advanced/Tools` → `Danger Zone` / `I Am Developer.` | 🔀 asked for here deliberately |
| — | `Hardware On/Off`, `Display Units`, `Max Network Fee`, `Idle Timeout`, `NFC Push Tx`, `Keyboard EMU`, `Buried Settings` | not implemented |

## Utils (stock: Advanced/Tools)

| Ours | Stock | |
|---|---|---|
| `Export wallet` | `Export Wallet` | 🔀 Generic JSON and the six vendors that read it, plus Descriptor, Key Expression, Export XPUB, Dump Summary. Still to write: Bitcoin Core (B), Electrum + Blue Wallet (C), Wasabi (D), Unchained (E), and the account-numbered descriptor variants — Bull Bitcoin, Zeus, Samourai pre/post-mix (F) |
| *(Derive → `BIP-85`)* | `Derive Seeds (BIP-85)` | 🔀 under Derive, not here: the same list, and the words, XPRV and WIF children can be put in force from it |
| `Browse SD card`, `Format SD card` | `File Management` → `List Files`, `Format SD Card` | ❌ stock nests these; ours are flat |
| `Sign message`, `Verify address` | `File Management` → `Sign Text File`; `NFC Tools` → `Verify Address` | ❌ flat here, nested there |
| `USB Drive` | `Settings` → `Hardware On/Off` → `Virtual Disk` | ❌ different drawer |
| `Analyze RNG`, `View TRNG Words`, `Games` | — | 🔀 ours alone |
| — | `Backup`, `Upgrade Firmware`, `Temporary Seed`, `Paper Wallets`, `WIF Store`, `Spending Policy`, `Danger Zone` | not implemented, or elsewhere |

`Upgrade Firmware` is worth noting: stock has it under Advanced/Tools, ours is
`Debug` → `Install from SD`. ❌

## What to do about the ❌ rows

`Scan QR` works: the module is configured once at boot and slept, and the LAMP key
lights its illumination while held, as stock does when idle. The wire protocol is in
`catcard-qr`, tested against the reference's own worked example.

They are not all worth fixing. The tile labels are short because a 107-pixel cell holds
ten characters of the face they are drawn in, and `Advanced/Tools` is eighteen. But
`Passphrase`, `Destroy seed` and `Upgrade Firmware` are the three where a stock user
would genuinely hunt, and the last two matter most: one destroys a wallet and the other
replaces the firmware.
