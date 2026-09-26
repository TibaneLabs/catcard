//! The main menu, and the debug screens under it.
//!
//! This exists because of how the first hardware bring-up went. The device booted,
//! drew its screen, took a PIN — and then sat on a status line that said `usb down`
//! and nothing else. Every fact that would have identified the fault in a minute was
//! in a register the firmware could read and had no way to show: whether the USB
//! supply came up, what the OTG core thought its state was, what the system clock
//! actually is. The diagnosis took a round trip through a reference manual and a
//! rebuild, and the rebuild could not be installed, because the only channel for
//! installing it was the thing that was broken.
//!
//! So the rule here is: **show the register, not a verdict about it.** A screen that
//! says "USB: failed" is worth very little; one that says `PWR_CR2 0000_0000` says
//! which write did not land. Every debug screen below prints raw values next to the
//! names they have in the reference manual, so what is on the glass can be compared
//! against RM0432 directly.
//!
//! Navigation follows the arrows **printed on the keypad**: `5` up, `7` left, `8` down,
//! `9` right. So `5`/`8` move the cursor, `9` and `y` both select, and `7` and `x` both
//! go back.
//!
//! That is a fact about the hardware rather than a convention worth arguing over — the
//! legend is on the keys, in front of whoever is holding the device, and a menu that
//! moves some other way is simply wrong about the thing it is running on.
//!
//! The list scrolls rather than being capped at what fits. An earlier version drew a
//! fixed number of rows and silently dropped the rest, which hid the last item entirely.
//! A menu that cannot outgrow the panel is the property worth having here, not a shorter
//! menu.

use core::fmt::Write as _;

use catcard_callgate::Callgate;
use catcard_callgate::abi::LogoutMode;
use catcard_entropy::HmacDrbg;
use catcard_ui::Mono128x64;
use catcard_ui::font::misc4x6;
use catcard_ui::keypad::{Event, KEYS, Key};

use crate::keypad::Keypad;
use crate::ui::Ui;
use catcard_ui::text::draw_text;

use crate::{BootReport, display, keypad::GpioMatrix, usbtask};

/// A line of debug text: a full body line on the widest panel (44 columns of 7x14 across
/// the Q1), which also covers `NAME 0000_0000`.
type Line = heapless::String<48>;

/// Body rows a list or info screen shows on this board's panel and layout.
const MAX_LINES: usize = display::ROWS;
/// Characters of body text that fit on a log line, as [`info`] draws them.
const LOG_COLS: usize = display::LOG_COLS;

// Scrolling is what keeps a long menu honest, so the old "must fit on the panel"
// assertions are gone. This one stays: every scroll calculation below assumes there is
// a window to scroll, and a zero- or one-row window makes `top` meaningless.
const _: () = assert!(MAX_LINES >= 2, "the panel must fit at least two menu rows");

/// Where we are. Flat rather than a stack: the tree is two deep, and a stack would be
/// state to get wrong for no gain.
#[derive(Copy, Clone, PartialEq, Eq)]
enum Screen {
    Main,
    About,
    /// About's second page: the STM32 itself.
    AboutChip,
    /// Install a firmware image from the card. Reached from `Utils` -> `Upgrade
    /// Firmware`, where a stock user looks for it.
    SdInstall,
    /// Debug: restart the device through the bootloader, after asking.
    WarmReset,
    /// Debug: the settings volume and the seed, to a card, in the clear. Bench builds
    /// only, like the restore it pairs with.
    #[cfg(all(not(feature = "board-mk3"), feature = "usb-debug-mem"))]
    DumpState,
    /// Debug: a settings image the host staged in PSRAM, written back over the region.
    #[cfg(all(not(feature = "board-mk3"), feature = "usb-debug-mem"))]
    RestoreSettings,
    /// Debug: what the scanner answers, per rate, in raw bytes.
    #[cfg(feature = "board-q1")]
    QrProbe,
    /// Debug: the DMA-driven bar, run around a real callgate before it goes on the
    /// boot path.
    #[cfg(feature = "board-q1")]
    SweepTest,
    Debug,
    Usb,
    Clocks,
    Psram,
    PsramProbe,
    /// SPI-NOR flash probe (mk3): show the JEDEC id and size.
    Sflash,
    Sd,
    Boot,
    Selftest,
    Keypad,
    /// The UI DRBG's diagnostic counters: how many times it has been (re)seeded, and how
    /// much it has generated.
    PrngStatus,
    /// The RTC registers, resampled about thirty times a second.
    Rtc,
    /// The scheduler's live state, once the menu itself runs as a kernel task.
    Kernel,
    ScrollTest,
    Colours,
    Logs,
    SaveLog,
    Utils,
    AnalyzeRng,
    UsbDrive,
    /// Generate a single-use paper wallet, unrelated to the device seed, to microSD.
    #[cfg(not(feature = "board-mk3"))]
    PaperWallet,
    ViewTrngWords,
    /// Debug: write a fixed URL to the NFC tag and hold the screen.
    #[cfg(not(feature = "board-mk3"))]
    NfcTest,
    AddressExplorer,
    /// One of the exports that is neither the generic JSON nor a plain key: Bitcoin
    /// Core, Electrum, Wasabi, Unchained or a single-signature descriptor. By its row in
    /// [`EXPORT_ITEMS`], which [`ONE_OFFS`] turns into a format and a filename.
    ExportOne(u8),
    /// Which wallet the device works in: the root, a passphrase, a BIP-85 child.
    KeyMenu,
    /// Acting on one row of the Derive menu.
    KeyPick(u8),
    /// The passphrase screen, opened from Derive rather than from Settings.
    KeyPassphrase,
    /// Seed XOR: the wallet in force, cut into parts that XOR back to it.
    XorSplit,
    /// Seed XOR: parts typed back in, and the seed they make put in force.
    XorJoin,
    /// The Seed Vault: keys kept in the settings, and the one in force.
    #[cfg(not(feature = "board-mk3"))]
    KeyVault,
    /// The export drawer: which shape of the same keys to write out.
    ExportMenu,
    /// Which account level to export a plain xpub from.
    XpubMenu,
    /// That level, by its row in [`XPUB_ITEMS`].
    Xpub(u8),
    /// The BIP-48 cosigner key expressions on their own.
    ExportKeyExpr,
    /// The generic JSON, by its row in [`EXPORT_ITEMS`] -- which decides the filename
    /// and nothing else.
    GenericJson(u8),
    /// Every account's first few addresses, to check against a watch-only wallet.
    DumpSummary,
    /// This device's account keys as one `ur:crypto-account` code.
    #[cfg(all(feature = "board-q1", feature = "multichain"))]
    AccountUr,
    /// Every enabled chain's account as one `ur:crypto-multi-accounts` code.
    #[cfg(feature = "multichain")]
    Keystone,
    /// A run of one account's receive addresses, written to the card as CSV.
    AddressCsv,
    BrowseSd,
    /// What card is in the slot: its CID (manufacturer, product, serial, date), capacity
    /// and filesystem. Read-only — brings the card up but writes nothing.
    CardDetails,
    /// Format the SD card to the SD standard (MBR + FAT16/FAT32/exFAT by capacity).
    FormatSd,
    /// The SD card's own controller password lock (CMD42): set, change, remove, unlock,
    /// or force-erase. Needs no settings store, so it is on every board with a slot.
    CardPassword,
    /// Device-bound, whole-card AES-128-XTS encryption of the SD card: encrypt in place,
    /// unlock for the session, or remove. Keeps per-card parameters in the settings store,
    /// so it needs one -- absent on the mk3.
    #[cfg(not(feature = "board-mk3"))]
    CardEncrypt,
    /// Write or read the encrypted backup file.
    BackupMenu,
    /// Write the wallet to the card, encrypted under twelve fresh words.
    BackupSave,
    /// Put a wallet back from a backup file on the card.
    BackupRestore,
    /// Where a transaction or a message to sign comes from.
    SignMenu,
    /// Sign a partially-signed transaction (PSBT) picked from the SD card.
    SignPsbt,
    /// Sign every PSBT on the card in one pass, writing a signed file per source.
    BatchSign,
    /// Take a transaction in through the NFC tag: mark it, wait for a phone to write, and
    /// offer whatever arrived.
    #[cfg(not(feature = "board-mk3"))]
    SignNfc,
    /// Sign a typed message with one of this wallet's keys.
    SignMessage,
    /// Sign the text in a file on the card, and write the signature beside it.
    SignTextFile,
    /// Check a signed-message file from the card against the address it names.
    VerifySig,
    /// Type a BIP-39 passphrase, opening a second wallet from the same words.
    Passphrase,
    /// Debug: exercise the settings store on internal flash.
    #[cfg(not(feature = "board-mk3"))]
    SettingsStore,
    /// The registered multisig wallets: what is stored, and importing or removing one.
    #[cfg(not(feature = "board-mk3"))]
    Multisig,
    /// The WIF store: individual private keys, listed, viewed, generated, imported and
    /// deleted, each able to sign a matching input. Needs the settings store.
    #[cfg(not(feature = "board-mk3"))]
    WifStore,
    /// Typing the nickname shown before the PIN prompt.
    #[cfg(not(feature = "board-mk3"))]
    Nickname,
    /// Copying the settings region to a card, before anything writes to it.
    #[cfg(not(feature = "board-mk3"))]
    SettingsToSd,
    /// The before-login nickname screen, drawn from the menu so it can be looked at.
    #[cfg(not(feature = "board-mk3"))]
    NickPreview,
    /// Secure Notes & Passwords, read out of the settings blob. Q1 only: stock writes
    /// them where there is a keyboard to type them on.
    #[cfg(feature = "board-q1")]
    Notes,
    /// Wipe the cached PIN/secret and reboot to the PIN prompt.
    SecureLogout,
    /// The Games submenu.
    #[cfg(feature = "games")]
    Games,
    /// The Block Mine game.
    #[cfg(feature = "games")]
    BlockMine,
    /// The Block Cutter game.
    #[cfg(feature = "games")]
    BlockCutter,
    /// Flappy Cat, on the Q1's self-scrolling panel.
    #[cfg(all(feature = "games", feature = "board-q1"))]
    FlappyCat,
    /// Reading a QR code with the Q1's scanner.
    #[cfg(feature = "board-q1")]
    ScanQr,
    /// Choosing how long a new seed should be.
    NewSeedMenu,
    /// Generating one, of this many words.
    NewSeed(u8),
    /// How to import a seed: typed words, a Coldcard clone, or a TAPSIGNER backup.
    ImportMenu,
    /// Restoring a seed: word count is not asked, the owner types until done.
    ImportSeed,
    /// Write the wallet as a clone file, answering another Coldcard's start file.
    CloneExport,
    /// Import a wallet from a clone file, publishing a start file first.
    CloneImport,
    /// Import a wallet from a TAPSIGNER `.aes` backup and its key.
    TapsignerImport,
    /// Device settings: the login submenu and, when a seed exists, destroying it.
    Settings,
    /// Login settings, currently just changing the main PIN.
    Login,
    /// Settings that show or change secrets, apart from the rest so none is one press
    /// away by accident.
    DangerZone,
    /// Choose the Bitcoin network: mainnet, testnet4 or regtest. In the Danger Zone
    /// because it changes every address, xpub and path the device shows.
    #[cfg(not(feature = "board-mk3"))]
    TestnetMode,
    /// Which chains this wallet offers, and in what order.
    #[cfg(all(feature = "multichain", not(feature = "board-mk3")))]
    ChainSettings,
    /// Danger zone: tools that work on the seed itself.
    SeedTools,
    /// Show the key in force: its words, or its XPRV or WIF.
    ViewWords,
    /// Show the key in force as a SeedQR, for a camera to read.
    #[cfg(feature = "board-q1")]
    SeedQrShow,
    /// Store the key in force as the device's seed, replacing the one it held.
    LockDown,
    /// Changing the main PIN.
    ChangePin,
    /// Type the PIN as at login, and be told whether it is right.
    TestLogin,
    /// Shuffle the number row at login.
    #[cfg(not(feature = "board-mk3"))]
    ScrambleKeys,
    /// Wait a chosen time after a correct PIN.
    #[cfg(not(feature = "board-mk3"))]
    LoginCountdown,
    /// Release builds only: a digit that erases the seed at login.
    #[cfg(all(not(feature = "dev"), not(feature = "board-mk3")))]
    KillKey,
    /// Release builds only: a login needs an enrolled microSD card.
    #[cfg(all(not(feature = "dev"), not(feature = "board-mk3")))]
    Sd2fa,
    /// How long with no key before the device logs itself out.
    #[cfg(not(feature = "board-mk3"))]
    IdleTimeout,
    /// BTC, mBTC, bits or sats, wherever an amount is shown.
    #[cfg(not(feature = "board-mk3"))]
    DisplayUnits,
    /// The largest share of a transaction that may go to fees.
    #[cfg(not(feature = "board-mk3"))]
    MaxFee,
    /// The submenu holding the two hardware switches.
    #[cfg(not(feature = "board-mk3"))]
    Hardware,
    /// Whether the device presents itself to a host over USB at all.
    #[cfg(not(feature = "board-mk3"))]
    UsbPort,
    /// Whether the device may re-enumerate as a USB disk.
    #[cfg(not(feature = "board-mk3"))]
    VirtualDisk,
    /// Whether the menu cursor comes round at the ends of a list.
    #[cfg(not(feature = "board-mk3"))]
    MenuWrap,
    /// The Q1 LCD backlight level. Q1-only: the mono boards have no backlight to dim.
    #[cfg(feature = "board-q1")]
    Brightness,
    WipeSeed,
    /// Factory reset: clear the PIN to a zero-length value and reboot to blank.
    FactoryReset,
}

/// The main menu of a device that holds a wallet.
///
/// A device with a seed has no "New wallet" or "Import seed": both would destroy the
/// wallet it already holds, so they live only in the blank ordering. "Destroy seed" is not
/// here either -- it moved into Settings, behind its warnings. The first item is "Ready to
/// Sign": a wallet exists, so the thing worth doing is signing a transaction the host has
/// staged to the SD card.
/// The six things the main menu offers, in the order the Q1 lays them out: the top row
/// is what a wallet is *for*, the bottom row is the device itself.
///
/// The same six on every board -- the Q1 draws them as a grid of icons and the mono
/// panels as a list, which is a difference of layout and not of structure. Everything
/// diagnostic lives under Settings rather than beside them; a main menu is for the
/// handful of things a person came to do.
const MAIN_ITEMS: &[&str] = &[
    "Sign",
    "Addresses",
    #[cfg(feature = "board-q1")]
    "Notes",
    "Utils",
    // Which wallet the device is working in -- the root, a passphrase, a BIP-85 child.
    // Stock reaches the same thing through Settings; it is a cell of its own here
    // because everything else on this screen is *about* whichever key it selects, and
    // a person switching wallets should not have to go looking in a settings list.
    "Derive",
    "Settings",
    // Stock gates Secure Logout on `not has_battery`: a device with a power button does
    // not need a menu entry to stop, and the USB-powered boards have no other way to end
    // a session than pulling the cable.
    // Source: hw-reference/menu-map-mk4-mk5-q1-v5.6.2.md §B3 [C]
    #[cfg(not(feature = "board-q1"))]
    "Logout",
];
/// The blank device's version: the two ways to get a wallet, in the two cells whose
/// jobs do not exist yet.
///
/// Nothing to sign without a seed, and no addresses to explore either -- an Address
/// Explorer on a blank device is a screen that can only apologise. So those two cells
/// carry New and Import instead, which is the whole of what a blank device is for.
const MAIN_ITEMS_BLANK: &[&str] = &[
    "New",
    "Import",
    // No seed, so no notes to read: stock shows nothing of the sort on a blank device.
    #[cfg(feature = "board-q1")]
    "Scan QR",
    "Utils",
    "Settings",
    #[cfg(not(feature = "board-q1"))]
    "Logout",
];

impl Screen {
    /// The row a screen was opened on, for the variants that carry one.
    ///
    /// **Next to the enum on purpose.** This used to live beside the dispatch, and a
    /// variant added with a payload but not added here silently acted on row zero --
    /// which is not a crash, it is the *first* row, doing something plausible. Two
    /// screens shipped that way: BIP-85 did nothing, and every one-off wallet export
    /// quietly exported nothing, because row zero of each happens to be a case its
    /// handler returns early on.
    ///
    /// So it sits where a variant is written, and the catch-all returns a row no
    /// payload-carrying screen should ever be reading.
    fn row(self) -> u8 {
        match self {
            Screen::NewSeed(w)
            | Screen::Xpub(w)
            | Screen::GenericJson(w)
            | Screen::ExportOne(w)
            | Screen::KeyPick(w) => w,
            _ => 0,
        }
    }
}

/// The main menu, ordered for the device in front of you.
fn main_items(no_seed: bool) -> &'static [&'static str] {
    if no_seed {
        return MAIN_ITEMS_BLANK;
    }
    #[cfg(not(feature = "board-q1"))]
    if !crate::key::is_root() {
        return main_items_with_key();
    }
    MAIN_ITEMS
}

/// [`MAIN_ITEMS`] with the wallet in force named at the top, as `[0123ABCD]`.
///
/// **For the boards with no status bar.** The Q1 says this along its top edge on every
/// screen; mk4 and mk5 have sixty-four rows of monochrome and no room for a bar, so the
/// only place to put it is the menu -- which is where stock puts it too, as a header
/// item that selects the same thing this one does.
///
/// It matters more here than on the Q1, not less: without it there is nothing anywhere
/// to distinguish a passphrase wallet from the one whose words are written down, and
/// the first sign of being in the wrong one is an export that names a stranger.
///
/// Source: hw-reference/menu-map-mk4-mk5-q1-v5.6.2.md §B3 "XFP header item" [C]
#[cfg(not(feature = "board-q1"))]
fn main_items_with_key() -> &'static [&'static str] {
    use core::fmt::Write as _;

    /// The row's text, which has to outlive the call: a menu is a slice of `&'static`.
    static mut ROW: heapless::String<12> = heapless::String::new();
    /// The list handed back, rebuilt each time because the fingerprint can change.
    static mut ITEMS: [&str; 1 + MAIN_ITEMS.len()] = [""; 1 + MAIN_ITEMS.len()];

    // SAFETY: foreground only. The menu is redrawn from one place and holds no borrow
    // of either across a rebuild.
    unsafe {
        let row = &mut *core::ptr::addr_of_mut!(ROW);
        row.clear();
        match crate::pubkeys::known_fingerprint() {
            // Square brackets, as stock spells a wallet that is not the master.
            Some([a, b, c, d]) => {
                let _ = write!(row, "[{a:02X}{b:02X}{c:02X}{d:02X}]");
            }
            // Somewhere other than the root, but nothing has derived its fingerprint
            // yet. Name the kind rather than invent a number.
            None => {
                let _ = write!(row, "[{}]", crate::key::label());
            }
        }
        let items = &mut *core::ptr::addr_of_mut!(ITEMS);
        items[0] = row.as_str();
        items[1..].copy_from_slice(MAIN_ITEMS);
        &items[..]
    }
}

/// Settings on a device with a seed. The seed tools, "Destroy seed" among them, are in
/// the Danger zone, which a blank device does not have.
const SETTINGS_ITEMS: &[&str] = &[
    "Login",
    "Passphrase",
    // Stock keeps the wallet registry in Settings, gated on there being a seed, rather
    // than beside the one-shot tools. Source: hw-reference/menu-map-mk4-mk5-q1-v5.6.2.md
    // §SET "Multisig Wallets (has_secrets)" [C]
    #[cfg(not(feature = "board-mk3"))]
    "Multisig",
    // The preferences, in stock's own order and under stock's own names, all of them
    // kept in the wallet's own settings file -- which the mk3's medium is not wired up
    // for, so on that board the rows are simply not there rather than being there and
    // doing nothing. Source: hw-reference/menu-map-mk4-mk5-q1-v5.6.2.md §SET [C]
    #[cfg(not(feature = "board-mk3"))]
    "Idle timeout",
    #[cfg(not(feature = "board-mk3"))]
    "Display units",
    #[cfg(not(feature = "board-mk3"))]
    "Max network fee",
    #[cfg(not(feature = "board-mk3"))]
    "Hardware On/Off",
    #[cfg(not(feature = "board-mk3"))]
    "Menu wrapping",
    // The colour panel's backlight level. Q1-only: the mono boards have no backlight PWM.
    // Source: hw-reference/firmware-features.md §9 "LCD brightness on battery" [C]
    #[cfg(feature = "board-q1")]
    "LCD brightness",
    // Which chains this wallet offers, and in what order. Only where there is more than
    // one chain to order, and only where there is a settings file to keep the answer in.
    #[cfg(all(feature = "multichain", not(feature = "board-mk3")))]
    "Chains",
    "Danger zone",
    // About and Debug sit here rather than on the main menu: both answer "what is this
    // device", which is a question about the device and not one of the six things a
    // person came to do.
    "About",
    "Debug",
];
const SETTINGS_ITEMS_BLANK: &[&str] = &[
    // Login and its nickname are here on a blank device too: both belong to the device
    // rather than to a wallet, and the nickname is stored under the pre-login key, which
    // exists either way.
    "Login", "About", "Debug",
];

/// The settings menu for the device in front of you.
fn settings_items(no_seed: bool) -> &'static [&'static str] {
    if no_seed {
        SETTINGS_ITEMS_BLANK
    } else {
        SETTINGS_ITEMS
    }
}

/// Settings that show or change secrets. Stock calls it the same, and keeps its seed
/// functions there. Source: hw-reference/menu-map-mk4-mk5-q1-v5.6.2.md §SET [C]
const DANGER_ITEMS: &[&str] = &[
    "Seed tools",
    // Which Bitcoin network the device derives and shows addresses for. Stock keeps it
    // here, in the Danger Zone, because switching it changes every address, xpub and
    // default path. The mk3 has no settings store to keep the choice, so the row is left
    // out there. Source: hw-reference/firmware-features.md §10 [C].
    #[cfg(not(feature = "board-mk3"))]
    "Testnet mode",
];
/// Tools that work on the seed itself, in stock's order. Stock's Seed XOR is here too;
/// ours is under Derive.
/// Source: hw-reference/menu-map-mk4-mk5-q1-v5.6.2.md §DZ "Seed Functions" [C]
const SEED_TOOLS_ITEMS: &[&str] = &[
    "View words",
    // Beside the words and behind the same warning, because it is the same secret in a
    // different alphabet. Q1 only: it is the board with a camera-readable panel and the
    // scanner that reads one back.
    #[cfg(feature = "board-q1")]
    "SeedQR",
    "Destroy seed",
];
/// The same while some other key is in force, which can be locked down in its place.
/// Stock gates the row the same way (`is_tmp`).
const SEED_TOOLS_ITEMS_LOADED: &[&str] = &[
    "View words",
    #[cfg(feature = "board-q1")]
    "SeedQR",
    "Destroy seed",
    "Lock down seed",
];

fn seed_tools_items() -> &'static [&'static str] {
    if crate::key::in_force() == crate::key::Source::Root {
        SEED_TOOLS_ITEMS
    } else {
        SEED_TOOLS_ITEMS_LOADED
    }
}

/// Login settings. Just the PIN today; a place for login-related settings to grow.
/// Login settings.
///
/// The nickname belongs here rather than beside it: it is shown *during* login, before
/// the PIN, so it is part of what logging in looks like rather than a preference about
/// the device.
const LOGIN_ITEMS: &[&str] = &[
    "Change PIN",
    "Test login",
    #[cfg(not(feature = "board-mk3"))]
    "Nickname",
    // Both live in the pre-login settings, which the mk3 has no medium for.
    #[cfg(not(feature = "board-mk3"))]
    "Scramble keys",
    #[cfg(not(feature = "board-mk3"))]
    "Login countdown",
    // They erase the seed on their own, so a development build -- which every bench unit
    // runs -- does not have them. See `crate::guard`.
    #[cfg(all(not(feature = "dev"), not(feature = "board-mk3")))]
    "Kill key",
    #[cfg(all(not(feature = "dev"), not(feature = "board-mk3")))]
    "MicroSD 2FA",
];
/// The hardware a preference can actually switch off.
///
/// **Only what the firmware really obeys.** Stock's own Hardware On/Off page lists the
/// NFC tag and the front LED beside these two; ours does not, because nothing here would
/// honour those rows yet and a switch that does nothing is worse than a missing one. Each
/// row below names the code that answers it: `crate::usbtask::set_port` for the port, the
/// USB Drive screen for the disk.
/// Source: hw-reference/menu-map-mk4-mk5-q1-v5.6.2.md §SET "Hardware On/Off" [C]
#[cfg(not(feature = "board-mk3"))]
const HARDWARE_ITEMS: &[&str] = &["USB port", "Virtual Disk"];

/// How long a new seed should be.
///
/// Twenty-four first, and under the cursor when the menu opens. Twelve is a sound
/// 128-bit seed and stock offers both, but on a device whose whole argument is the
/// quality of its entropy, the stronger option should be the default one.
///
/// The word count travels in [`Screen::NewSeed`], so adding another length here needs
/// only a matching arm in [`step`].
const NEW_SEED_ITEMS: &[&str] = &["24 words", "12 words"];

/// The ways a blank device gets a wallet from somewhere else.
///
/// "Words" is the plain BIP-39 restore; "Clone" migrates from another Coldcard with no
/// memorized password; "TAPSIGNER" decrypts a card's `.aes` backup. Dispatched by name in
/// [`step`], so appending a fourth needs only a matching arm.
const IMPORT_ITEMS: &[&str] = &["Words", "Clone", "TAPSIGNER"];

/// The tool drawer, stock's `Advanced/Tools`.
///
/// `Upgrade Firmware` is last, and last on purpose: it is stock's own name for the entry,
/// which is the whole reason it is here rather than under Debug, and putting it at the end
/// leaves the six cells that have art as the Q1's first grid page. It has no icon of its
/// own, so the grid draws its name alone -- see `draw_grid` -- on a page of its own.
/// Source: hw-reference/menu-map-mk4-mk5-q1-v5.6.2.md §ADV "Upgrade Firmware" [C]
#[cfg(feature = "games")]
const UTILS_ITEMS: &[&str] = &[
    "Analyze RNG",
    "USB Drive",
    "Export wallet",
    "Backup",
    #[cfg(not(feature = "board-mk3"))]
    "Paper wallet",
    "Browse SD card",
    "Card details",
    "Format SD card",
    // The SD card's own CMD42 password lock. No settings store, so it is on every board
    // with a slot, mk3 included. Source: SD Physical Layer Simplified Spec, "Lock Card" [C]
    "Card password",
    // Device-bound whole-card AES-128-XTS encryption. Keeps per-card parameters in the
    // settings, so it needs the store: not on the mk3.
    #[cfg(not(feature = "board-mk3"))]
    "Encrypt card",
    "Games",
    // Individual private keys, kept in the settings; needs the store, so not on the mk3.
    // Source: hw-reference/firmware-features.md §7 "WIF Store" [C]
    #[cfg(not(feature = "board-mk3"))]
    "WIF Store",
    "Upgrade Firmware",
];
#[cfg(not(feature = "games"))]
const UTILS_ITEMS: &[&str] = &[
    "Analyze RNG",
    "USB Drive",
    "Export wallet",
    // Stock's `Advanced/Tools` → `Backup`, in the drawer this firmware calls Utils.
    // Source: hw-reference/menu-map-mk4-mk5-q1-v5.6.2.md §AT [C]
    "Backup",
    // Stock's `Advanced/Tools` → `Paper Wallets`. Gated off mk3 (no `choose`, scarce
    // flash). Source: hw-reference/firmware-features.md §8 "paper wallets" [C]
    #[cfg(not(feature = "board-mk3"))]
    "Paper wallet",
    "Browse SD card",
    "Card details",
    "Format SD card",
    // The SD card's own CMD42 password lock. No settings store, so it is on every board
    // with a slot, mk3 included. Source: SD Physical Layer Simplified Spec, "Lock Card" [C]
    "Card password",
    // Device-bound whole-card AES-128-XTS encryption. Keeps per-card parameters in the
    // settings, so it needs the store: not on the mk3.
    #[cfg(not(feature = "board-mk3"))]
    "Encrypt card",
    // Individual private keys, kept in the settings; needs the store, so not on the mk3.
    // Source: hw-reference/firmware-features.md §7 "WIF Store" [C]
    #[cfg(not(feature = "board-mk3"))]
    "WIF Store",
    "Upgrade Firmware",
];

/// The two halves of the backup file, together rather than in separate drawers: one
/// writes it and the other reads it, and the words that open it are the same thing.
///
/// Restore is here on a blank device too -- Utils is on the blank main menu -- which is
/// the only place a device with no wallet can get one from a file.
const BACKUP_ITEMS: &[&str] = &["Save backup", "Restore backup", "Clone Coldcard"];

/// The shapes the same keys can be written in.
///
/// Stock names fifteen wallets here and five of them -- Sparrow, Cove, Nunchuk, Theya,
/// Bitcoin Safe -- take the generic JSON unchanged, so the list is far shorter than it
/// looks. What is here is what this firmware can write from what it knows; the
/// wallet-specific files are the rest of that work.
const EXPORT_ITEMS: &[&str] = &[
    "Generic JSON",
    "Sparrow",
    "Cove",
    "Nunchuk",
    "Fully Noded",
    "Theya",
    "Bitcoin Safe",
    "Bitcoin Core",
    "Electrum Wallet",
    "Blue Wallet",
    "Wasabi Wallet",
    "Unchained",
    "Descriptor",
    "Bull Bitcoin",
    "Zeus",
    "Samourai Postmix",
    "Samourai Premix",
    "Key Expression",
    "Export XPUB",
    // The BC-UR account structure, as one code. Not a file: a UR is a QR format, and
    // the software that reads one is pointing a camera rather than reading a card.
    #[cfg(all(feature = "board-q1", feature = "multichain"))]
    "Account (UR)",
    // Every enabled chain at once, as a wallet's "sync with your hardware wallet"
    // expects it. The Bitcoin exports above are one chain each; this is the multichain
    // answer, and the only one that gets somebody's Solana and Ethereum accounts across
    // in the same scan.
    #[cfg(feature = "multichain")]
    "Keystone",
    "Dump Summary",
    // Addresses rather than keys: the file a watch-only wallet's owner checks against, or
    // hands to whoever is paying them, without either side needing an xpub.
    // Source: hw-reference/firmware-features.md §3 "Address Explorer ... export (CSV)" [C]
    "Address CSV",
];

/// The filename each Format A entry writes under.
///
/// The bytes are identical across all of them; only the name differs, because the
/// software that reads one looks for its own. Stock lower-cases the menu label and
/// keeps the spaces, which is why `fully noded-export.json` has one in it.
const GENERIC_JSON_NAMES: &[(&str, &str)] = &[
    ("Generic JSON", "/coldcard-export.json"),
    ("Sparrow", "/sparrow-export.json"),
    ("Cove", "/cove-export.json"),
    ("Nunchuk", "/nunchuk-export.json"),
    ("Fully Noded", "/fully noded-export.json"),
    ("Theya", "/theya-export.json"),
    ("Bitcoin Safe", "/bitcoin safe-export.json"),
];

/// Where the thing to sign comes from. The scanner is the Q1's; the mono boards have no
/// camera, so they have no row for one. The tag is on every board past the mk3.
///
/// The last two are the message pair: a text file on the card signed, and a signed file
/// checked. `Verify` is the one row here that touches no key -- a signature is public --
/// so it asks for no PIN, although it lives behind the same menu as the rest: it is a
/// thing done with signatures, and that is where someone will look for it.
const SIGN_ITEMS: &[&str] = &[
    #[cfg(feature = "board-q1")]
    "Scan",
    "From SD",
    // Signing every transaction on the card in one pass, each still reviewed on its own.
    "Batch sign",
    #[cfg(not(feature = "board-mk3"))]
    "By NFC",
    "Message",
    "Text file",
    "Verify",
];

/// Ways to change the wallet in force, from the root.
///
/// `XOR split` is here with them although it changes nothing: it is about which wallet
/// the words on the table belong to, which is the question this menu answers, and an
/// owner looking for Seed XOR looks where the key lives rather than in a tool drawer.
const KEY_ITEMS_ROOT: &[&str] = &[
    "Passphrase",
    "BIP-85",
    "Import key",
    "XOR split",
    "XOR join",
    #[cfg(not(feature = "board-mk3"))]
    "Key vault",
];
/// The same, from anywhere else: there is now somewhere to go back to.
const KEY_ITEMS_DERIVED: &[&str] = &[
    "Back to root",
    "Passphrase",
    "BIP-85",
    "Import key",
    "XOR split",
    "XOR join",
    #[cfg(not(feature = "board-mk3"))]
    "Key vault",
];

/// The rows this menu has, which depend on where the device already is.
///
/// `Back to root` appears only when it would do something. A row that is always there
/// and sometimes inert teaches an owner to ignore it, and this is the row that says
/// which wallet they are in.
fn key_items() -> &'static [&'static str] {
    if crate::key::is_root() {
        KEY_ITEMS_ROOT
    } else {
        KEY_ITEMS_DERIVED
    }
}

/// Which level to export a plain xpub from, in stock's order.
const XPUB_ITEMS: &[&str] = &[
    "Segwit (BIP-84)",
    "Classic (BIP-44)",
    "P2WPKH/P2SH (49)",
    "Master XPUB",
    "Current XFP",
];

/// The games in the Games submenu.
#[cfg(feature = "games")]
#[cfg(not(feature = "board-q1"))]
const GAMES_ITEMS: &[&str] = &["Block Mine", "Block Cutter"];
/// Flappy Cat needs the Q1's panel to scroll itself.
#[cfg(feature = "board-q1")]
#[cfg(feature = "games")]
const GAMES_ITEMS: &[&str] = &["Block Mine", "Block Cutter", "Flappy Cat"];
const DEBUG_ITEMS: &[&str] = &[
    // The TRNG's raw output as words: for checking the generator, not for keeping.
    "View TRNG Words",
    #[cfg(not(feature = "board-mk3"))]
    "NFC test",
    #[cfg(all(not(feature = "board-mk3"), feature = "usb-debug-mem"))]
    "Dump state",
    #[cfg(all(not(feature = "board-mk3"), feature = "usb-debug-mem"))]
    "Restore settings",
    #[cfg(feature = "board-q1")]
    "QR probe",
    #[cfg(feature = "board-q1")]
    "Sweep test",
    "USB",
    "Clocks",
    "RTC",
    "Kernel",
    "Scroll test",
    "PSRAM",
    "SPI-NOR",
    "Boot report",
    "Selftest",
    "Keypad",
    "PRNG status",
    "microSD",
    "Logs",
    "Save log to SD",
    "Colours",
    // The two rows that end the session, together at the bottom: one restarts the device,
    // the other clears the PIN. Both ask first, and only one of them is irreversible.
    // Stock keeps its `Warm Reset` in the developer drawer too.
    // Source: hw-reference/menu-map-mk4-mk5-q1-v5.6.2.md §D4 "Warm Reset" [C]
    "Warm Reset",
    "Factory Reset",
    #[cfg(not(feature = "board-mk3"))]
    "Settings store",
    #[cfg(not(feature = "board-mk3"))]
    "Settings to SD",
    #[cfg(not(feature = "board-mk3"))]
    "Nickname screen",
    #[cfg(feature = "board-q1")]
    "Secure notes",
];

/// Run the menu. Never returns.
///
/// Also the idle loop: USB is polled here, and a staged upgrade takes over the screen
/// wherever the user happens to be. Keeping one loop means there is no menu screen that
/// quietly stops serving the host.
pub fn run(session: Session<'_>) -> ! {
    let Session {
        gate,
        login,
        panel,
        matrix,
        drbg,
        protocol,
        report,
        no_seed,
        mut pool,
    } = session;
    let mut screen = Screen::Main;
    let mut showing_offer = false;
    // A transfer in flight owns the screen: last percentage drawn, so it repaints only
    // when it moves.
    let mut receiving: Option<u8> = None;
    let mut redraw = true;
    let mut v = View {
        report,
        last_key: None,
        keys_seen: 0,
        drbg_stats: drbg.stats(),
        drbg_sample: None,
        menu: MenuScreen::new(),
        raw_kn: None,
        raw_held: 0,
        rtc: RtcWatch::default(),
        kernel_pace: Pace::default(),
        no_seed,
    };

    // About thirty frames a second. Taken from the running clock rather than assumed, so
    // a board on a different HCLK still redraws at the same rate.
    // SAFETY: reads RCC.
    let frame_cycles = unsafe { catcard_hal::clock::hclk_hz() } / 30;

    let mut pad = Keypad::new();
    // One bundle for the session. Every screen takes this instead of four
    // separate borrows, and the keypad inside it is the single scanner whose
    // retained state is what makes a still-held key read as held.
    let mut ui = Ui {
        panel,
        pad: &mut pad,
        matrix,
        drbg,
        protocol,
    };
    let mut events = [Event::Pressed(Key::Cancel); KEYS];
    let mut keys: heapless::Vec<Key, { KEYS + 1 }> = heapless::Vec::new();

    // This wallet's own preferences, before the first frame: the idle timeout has to be
    // armed without anyone asking for it, the USB switch has to be honoured before a host
    // is answered, and menu wrapping decides how the very first keypress behaves.
    //
    // One key derivation, paid here while the owner is already waiting for the menu, and
    // cached for the session -- so every per-wallet screen after this is free. Skipped on
    // a device with no wallet, which has no file to read and no key to read it with.
    if !no_seed {
        crate::prefs::load(gate, login, ui.panel, "Settings");
    }

    loop {
        if redraw && !showing_offer && receiving.is_none() {
            // On the PRNG-status screen, draw a fresh 32-bit sample first so the counters
            // snapshotted just below include that generate call. Done only here, so no
            // other screen advances the DRBG just by being shown.
            if screen == Screen::PrngStatus {
                let mut b = [0u8; 4];
                v.drbg_sample = ui
                    .drbg
                    .generate(&mut b)
                    .ok()
                    .map(|()| u32::from_be_bytes(b));
            }
            // Snapshot the DRBG's counters so the PRNG-status screen shows the current
            // numbers; cheap and side-effect-free on any other screen.
            v.drbg_stats = ui.drbg.stats();
            draw(ui.panel, screen, &v);
            redraw = false;
        }

        let _ = usbtask::pump();
        display::idle(ui.panel);

        // The RTC screen redraws on a clock rather than on input: it is showing something
        // that changes on its own, and the whole question it answers is whether it does.
        if screen == Screen::Rtc && v.rtc.sample(frame_cycles) {
            redraw = true;
        }
        if screen == Screen::Kernel && v.kernel_pace.due(frame_cycles) {
            redraw = true;
        }

        // The tester repaints on raw matrix state, not on events: the keys that produce
        // no event are exactly the ones it is needed for.
        if screen == Screen::Keypad {
            let (kn, held) = (ui.pad.last_pressed(), ui.pad.held_mask());
            if kn != v.raw_kn || held != v.raw_held {
                v.raw_kn = kn;
                v.raw_held = held;
                redraw = true;
            }
        }

        crate::pinentry::pressed_keys(ui.pad, ui.matrix, ui.drbg, &mut events, &mut keys);

        // An upgrade that passed inspection is waiting on a person, wherever they are.
        //
        // **Checked after the keys are read, not before.** With USB serviced by its own
        // task, the offer can become pending between a check made earlier in this loop
        // and the key read -- and a host approving over USB injects its Confirm the moment
        // the offer's reply arrives. That Confirm was then read with no offer showing and
        // dispatched to whichever menu item was selected, while the install waited forever.
        //
        // Ordering closes it without a lock: the offer is marked pending before its reply
        // goes out, and the host injects only after the reply. So by the time an injected
        // key has been read, the offer is already pending, and this check routes the key
        // to it. Single-threaded it is equally correct, since pump, read and check still
        // happen in order.
        // An image arriving over USB takes the screen for as long as it is arriving: it
        // says what is happening, how far along it is, and that cancel stops it. Stock does
        // the same, and the alternative -- a device that looks idle while a host writes a
        // megabyte into it -- tells its owner nothing.
        if let Some((done, total)) = usbtask::receiving() {
            let pct = if total == 0 {
                0
            } else {
                ((done as u64 * 100) / total as u64) as u8
            };
            if receiving != Some(pct) {
                if receiving.is_none() && screen == Screen::Colours {
                    display::wipe(ui.panel);
                }
                receiving = Some(pct);
                let mut note = Line::new();
                let _ = write!(note, "{} of {} KB", done / 1024, total / 1024);
                let mut hint = Line::new();
                let _ = write!(hint, "{} to reject", display::CANCEL_KEY);
                display::draw(ui.panel, |c| {
                    let lines = [note.clone(), hint.clone()];
                    catcard_ui::widgets::info(c, &display::LAYOUT, "Receiving", &lines);
                    catcard_ui::splash::draw_progress(c, pct);
                });
            }
        } else if receiving.is_some() {
            receiving = None;
            redraw = true;
        }

        if let Some(a) = usbtask::pending() {
            if !showing_offer {
                if screen == Screen::Colours {
                    display::wipe(ui.panel);
                }
                crate::session::show_offer(ui.panel, &a);
                showing_offer = true;
            }
        } else if showing_offer {
            showing_offer = false;
            redraw = true;
        }

        for key in keys.iter() {
            // While an image is arriving, the only question on the screen is whether to
            // let it finish. Cancel stops it and releases the staging medium; everything
            // else is swallowed, so a keypress cannot reach the menu underneath a screen
            // that is not showing it.
            if receiving.is_some() {
                if matches!(key, Key::Cancel) {
                    usbtask::abandon();
                    receiving = None;
                    redraw = true;
                    message(ui.panel, "Rejected", "the transfer was", "stopped");
                    wait_for_any_key(&mut ui);
                }
                continue;
            }
            if showing_offer {
                match key {
                    Key::Confirm => {
                        // An image that sets the anti-downgrade mark is asked about
                        // twice, as Destroy seed is: the first yes was on a screen that
                        // also said the version and the key, and one question is what
                        // people press through. The offer is re-read after the answer
                        // and must still be the one that was shown -- a host can replace
                        // it while the question is up, and a yes to this question is a
                        // yes to *that* image, not to whatever arrived since.
                        if let Some(a) = usbtask::pending()
                            && crate::session::sets_high_water(&a)
                        {
                            ask(
                                ui.panel,
                                "Really install?",
                                "sets anti-downgrade",
                                "mark: no way back",
                            );
                            if !confirmed(&mut ui) || usbtask::pending().as_ref() != Some(&a) {
                                usbtask::decline();
                                showing_offer = false;
                                redraw = true;
                                continue;
                            }
                        }
                        match usbtask::approve() {
                            Ok(region) => {
                                message(ui.panel, "Installing", "do not disconnect", "");
                                crate::staging::install(gate, login, ui.panel, region);
                                // `install` only returns when the install did *not*
                                // happen, and what it painted says why. Redrawing the
                                // menu over it without waiting threw that away, which is
                                // how a refusal came to look like a device that had
                                // simply stopped.
                                wait_for_any_key(&mut ui);
                                showing_offer = false;
                                redraw = true;
                            }
                            Err(why) => {
                                crate::catlog!("install: commit refused: {:?}", why);
                                message(
                                    ui.panel,
                                    "Not installed",
                                    crate::sdupgrade::describe(why),
                                    "any key to go back",
                                );
                                wait_for_any_key(&mut ui);
                                showing_offer = false;
                                redraw = true;
                            }
                        }
                    }
                    Key::Cancel => {
                        usbtask::decline();
                        showing_offer = false;
                        redraw = true;
                    }
                    Key::Digit(_) => {}
                    Key::Char(_) | Key::Qr => {}
                }
                continue;
            }

            let prev_key = v.last_key;
            v.last_key = Some(*key);
            v.keys_seen = v.keys_seen.saturating_add(1);
            redraw = true;

            // The live debug screens (keypad tester, PRNG status) stay open and repaint on
            // each key instead of leaving on the first. `x` returns to Debug -- and on the
            // keypad tester it takes two `x` in a row, so a single `x` still registers as a
            // key to test. Every other key just refreshes the numbers above.
            if matches!(
                screen,
                Screen::Keypad | Screen::PrngStatus | Screen::Rtc | Screen::Kernel
            ) {
                // `0` arms the keypad edge path by hand, on a board where the boot path
                // leaves it masked. If it misbehaves the cure is a power cycle: nothing
                // here is persisted, which is the whole reason it is offered from a screen
                // rather than done at boot.
                if screen == Screen::Keypad && *key == Key::Digit(0) {
                    let (_, armed, _) = crate::keypad::edge_stats();
                    if armed {
                        ui.matrix.disarm_edge_now();
                        crate::catlog!("keypad: edge entropy masked by hand");
                    } else {
                        let ok = ui.matrix.arm_edge_now();
                        crate::catlog!(
                            "keypad: edge entropy {}",
                            if ok {
                                "armed by hand"
                            } else {
                                "refused (storm guard)"
                            }
                        );
                    }
                    redraw = true;
                }
                let leave = match screen {
                    Screen::Keypad => *key == Key::Cancel && prev_key == Some(Key::Cancel),
                    _ => *key == Key::Cancel,
                };
                if leave {
                    v.reset_menu();
                    screen = Screen::Debug;
                }
                continue;
            }

            // Cursor movement first: it stays on this screen, so it never reaches the
            // transition table below. The menu owns what moving means.
            // On the grid, left and right move between columns. Everywhere else they
            // are in and out, which `step` normalises to confirm and cancel -- so the
            // grid has to claim them before that happens, or the main menu would act on
            // a cell the moment someone tried to move to the next one.
            #[cfg(feature = "board-q1")]
            let sideways =
                is_grid(screen, v.blank()) && matches!(key, Key::Digit(7) | Key::Digit(9));
            #[cfg(not(feature = "board-q1"))]
            let sideways = false;
            if let Some(items) = items_of(screen, v.blank())
                && (matches!(key, Key::Digit(5) | Key::Digit(8) | Key::Digit(0)) || sideways)
            {
                v.menu.key(&mut ui, screen, items, *key);
                continue;
            }

            let next = step(screen, *key, v.menu.cursor, v.blank());
            // Anything that takes over the panel is a row in the action table rather than
            // a branch here: which routine runs, where the menu lands afterwards, and
            // whether the secret slot has to be re-read. This was seventeen
            // `if next == Screen::X` blocks, each spelling out `reset_menu` / `screen =` /
            // `break` again -- three chances per action to name the wrong screen, and no
            // way to see the whole set at once.
            let words = next.row();
            if let Some(action) = action_for(next) {
                {
                    let mut act = Act {
                        gate,
                        login,
                        ui: &mut ui,
                        pool: pool.as_deref_mut(),
                        words,
                    };
                    (action.run)(&mut act);
                }
                // A wallet that now exists -- or no longer does -- reorders the main menu.
                // Re-read the slot from the login rather than assuming the flow ran to
                // completion: it can be declined or refused at several points.
                //
                // This is the weaker of the two answers: the flag is settled at login and
                // a write does not clear it (see `key::no_stored_wallet`), so whatever the
                // flow saw in the slot wins over it. Kept because it is the only answer
                // for a flow that changed the slot without looking at it afterwards.
                if action.seed_may_change {
                    v.no_seed = matches!(login.step(), catcard_pin::Step::In { zero_secret: true });
                    if v.no_seed != crate::key::no_stored_wallet(v.no_seed) {
                        crate::catlog!(
                            "seed: the login flag still says none; the slot says otherwise"
                        );
                    }
                }
                if let Some(back) = action.back {
                    v.reset_menu();
                    screen = back;
                }
                break;
            }
            if next != screen {
                // A new list starts at the top. Carrying a cursor between menus of
                // different lengths is how you land on an item nobody chose.
                v.reset_menu();
                // Entering a live debug screen: clear the key trail so the keypad tester
                // opens on "press any key" rather than the `y` that selected it, and its
                // count starts at zero.
                if matches!(next, Screen::Keypad | Screen::PrngStatus) {
                    v.last_key = None;
                    v.keys_seen = 0;
                }
                // A fresh watch, so "seconds seen" counts from opening the screen
                // rather than from boot.
                if next == Screen::Rtc {
                    v.rtc = RtcWatch::default();
                }
            }
            // The colour chart painted the panel directly, behind the canvas and its row
            // cache, so the next frame has to go out whole or the chart stays under it.
            if screen == Screen::Colours && next != Screen::Colours {
                display::wipe(ui.panel);
            }
            screen = next;
        }
    }
}

/// What a full-screen action is handed.
///
/// The actions have four different argument lists between them -- some want the gate,
/// some the login too, one the entropy pool, one a word count -- and a table can hold
/// only one signature. Bundling them lets each row be the call itself instead of an
/// adapter function, and a fifth thing added later does not touch every row.
struct Act<'a, 'u> {
    gate: &'a Callgate,
    login: &'a mut catcard_pin::Login,
    ui: &'a mut Ui<'u>,
    /// The boot entropy pool. `None` on a device whose pool never met its policy, which
    /// is a refusal to generate a seed rather than a reason to use something weaker.
    pool: Option<&'a mut catcard_entropy::EntropyPool>,
    /// The word count carried by `Screen::NewSeed(n)`, or the row a list screen's
    /// variant carries ([`Screen::row`]); zero for every other action.
    words: u8,
}

/// A screen that takes over the panel, runs to completion, and hands back to a menu.
#[derive(Copy, Clone)]
struct Action {
    /// Runs it.
    run: fn(&mut Act<'_, '_>),
    /// Where the menu lands when it returns, cursor at the top. `None` goes back to the
    /// menu it was opened from with the cursor left on the row that opened it.
    back: Option<Screen>,
    /// Re-read the secret slot afterwards: this action can create or destroy a wallet,
    /// and that reorders the main menu.
    seed_may_change: bool,
}

/// The action table: every screen that is a routine rather than a list.
///
/// `None` means the screen is a menu or an info page, which the run loop draws and
/// leaves on a key -- no routine to call.
fn action_for(screen: Screen) -> Option<Action> {
    fn to(run: fn(&mut Act<'_, '_>), back: Screen) -> Action {
        Action {
            run,
            back: Some(back),
            seed_may_change: false,
        }
    }
    /// Back to whichever menu opened it, cursor still on the row it was on.
    fn returns(run: fn(&mut Act<'_, '_>)) -> Action {
        Action {
            run,
            back: None,
            seed_may_change: false,
        }
    }
    /// For the three that can leave the device holding a different wallet than before.
    fn reseeds(run: fn(&mut Act<'_, '_>), back: Screen) -> Action {
        Action {
            run,
            back: Some(back),
            seed_may_change: true,
        }
    }

    Some(match screen {
        // Back to Utils, which is where it is now reached from: a screen's way out
        // belongs to the way in.
        Screen::SdInstall => to(|a| install_from_card(a.gate, a.login, a.ui), Screen::Utils),
        Screen::WarmReset => to(|a| warm_reset(a.gate, a.login, a.ui), Screen::Debug),
        #[cfg(all(feature = "multichain", not(feature = "board-mk3")))]
        Screen::ChainSettings => to(|a| chain_settings(a.gate, a.login, a.ui), Screen::Settings),
        #[cfg(all(not(feature = "board-mk3"), feature = "usb-debug-mem"))]
        Screen::DumpState => to(
            |a| crate::statedump::screen(a.gate, a.login, a.ui),
            Screen::Debug,
        ),
        #[cfg(all(not(feature = "board-mk3"), feature = "usb-debug-mem"))]
        Screen::RestoreSettings => to(
            |a| crate::restore::screen(a.gate, a.login, a.ui),
            Screen::Debug,
        ),
        #[cfg(feature = "board-q1")]
        Screen::QrProbe => to(|a| crate::qrscan::probe(a.ui), Screen::Debug),
        #[cfg(feature = "board-q1")]
        Screen::SweepTest => to(|a| sweep_test(a.gate, a.login, a.ui), Screen::Debug),
        Screen::SaveLog => to(|a| save_log_to_card(a.ui), Screen::Debug),
        Screen::Logs => to(
            |a| {
                page_through(a.ui, "Logs", &LogLines, false, &display::LAYOUT, false);
            },
            Screen::Debug,
        ),
        Screen::AnalyzeRng => to(|a| analyze_rng(a.gate, a.ui), Screen::Utils),
        Screen::UsbDrive => to(|a| usb_drive(a.ui), Screen::Utils),
        #[cfg(not(feature = "board-mk3"))]
        Screen::PaperWallet => to(
            |a| crate::paperwallet::create(a.ui, a.pool.take()),
            Screen::Utils,
        ),
        Screen::ViewTrngWords => to(|a| view_trng_words(a.gate, a.ui), Screen::Debug),
        #[cfg(not(feature = "board-mk3"))]
        Screen::NfcTest => to(|a| crate::nfc::probe_screen(a.ui), Screen::Debug),
        Screen::AddressExplorer => returns(|a| addresses(a.gate, a.login, a.ui)),
        Screen::ExportOne(_) => to(
            |a| export_one(a.gate, a.login, a.ui, a.words),
            Screen::ExportMenu,
        ),
        Screen::ExportKeyExpr => to(
            |a| export_key_expression(a.gate, a.login, a.ui),
            Screen::ExportMenu,
        ),
        Screen::KeyPick(_) => to(
            |a| choose_key(a.gate, a.login, a.ui, a.words),
            Screen::KeyMenu,
        ),
        Screen::DumpSummary => to(|a| dump_summary(a.gate, a.login, a.ui), Screen::ExportMenu),
        #[cfg(feature = "multichain")]
        Screen::Keystone => to(
            |a| export_keystone(a.gate, a.login, a.ui),
            Screen::ExportMenu,
        ),
        #[cfg(all(feature = "board-q1", feature = "multichain"))]
        Screen::AccountUr => to(
            |a| export_account_ur(a.gate, a.login, a.ui),
            Screen::ExportMenu,
        ),
        Screen::AddressCsv => to(
            |a| export_address_csv(a.gate, a.login, a.ui),
            Screen::ExportMenu,
        ),
        Screen::Xpub(_) => to(
            |a| export_xpub(a.gate, a.login, a.ui, a.words),
            Screen::XpubMenu,
        ),
        Screen::GenericJson(_) => to(
            |a| export_generic_json(a.gate, a.login, a.ui, a.words),
            Screen::ExportMenu,
        ),
        Screen::BrowseSd => to(
            |a| {
                browse_files(a.ui);
            },
            Screen::Utils,
        ),
        Screen::FormatSd => to(|a| format_sd(a.ui), Screen::Utils),
        Screen::CardPassword => to(|a| card_password(a.ui), Screen::Utils),
        #[cfg(not(feature = "board-mk3"))]
        Screen::CardEncrypt => to(
            |a| crate::sdcrypt::screen(a.gate, a.login, a.ui),
            Screen::Utils,
        ),
        Screen::BackupSave => to(
            |a| crate::backup::save(a.gate, a.login, a.ui),
            Screen::BackupMenu,
        ),
        // A restore replaces the stored secret, so the session has to re-read it.
        Screen::BackupRestore => reseeds(
            |a| crate::backup::restore(a.gate, a.login, a.ui),
            Screen::BackupMenu,
        ),
        // Export reads the wallet out; it does not change the stored secret.
        Screen::CloneExport => to(
            |a| crate::backup::clone_export(a.gate, a.login, a.ui),
            Screen::BackupMenu,
        ),
        Screen::SignPsbt => to(
            |a| crate::signtx::sign_psbt(a.gate, a.login, a.ui),
            Screen::SignMenu,
        ),
        Screen::BatchSign => to(
            |a| crate::signtx::batch_sign(a.gate, a.login, a.ui),
            Screen::SignMenu,
        ),
        #[cfg(not(feature = "board-mk3"))]
        Screen::SignNfc => to(
            |a| crate::nfc::receive_screen(a.gate, a.login, a.ui),
            Screen::SignMenu,
        ),
        Screen::SignMessage => to(
            |a| crate::signmsg::screen(a.gate, a.login, a.ui),
            Screen::SignMenu,
        ),
        Screen::SignTextFile => to(
            |a| crate::signmsg::text_file(a.gate, a.login, a.ui),
            Screen::SignMenu,
        ),
        // No key, no login: checking a signature is arithmetic on public values.
        Screen::VerifySig => to(|a| crate::verifysig::screen(a.ui), Screen::SignMenu),
        Screen::Passphrase => to(
            |a| crate::passphrase::screen(a.gate, a.login, a.ui),
            Screen::Settings,
        ),
        // The same screen, reached from `Derive` -- and going back there rather than
        // to Settings. A screen's way out belongs to the way in, and this one has two.
        Screen::KeyPassphrase => to(
            |a| crate::passphrase::screen(a.gate, a.login, a.ui),
            Screen::KeyMenu,
        ),
        Screen::XorSplit => to(
            |a| crate::seedxor::split(a.gate, a.login, a.ui, a.pool.take()),
            Screen::KeyMenu,
        ),
        // A join can leave a seed stored where there was none, which is the one thing
        // that reorders the main menu.
        Screen::XorJoin => reseeds(
            |a| crate::seedxor::join(a.gate, a.login, a.ui),
            Screen::KeyMenu,
        ),
        #[cfg(not(feature = "board-mk3"))]
        Screen::KeyVault => to(
            |a| crate::vault::screen(a.gate, a.login, a.ui),
            Screen::KeyMenu,
        ),
        Screen::SecureLogout => to(|a| secure_logout(a.gate, a.login, a.ui), Screen::Main),
        // Both take the CPU for good once they start; they return only to refuse a
        // second start when the kernel is already running.
        Screen::ScrollTest => to(|a| scroll_test(a.ui), Screen::Debug),
        #[cfg(not(feature = "board-mk3"))]
        Screen::SettingsStore => to(
            |a| crate::settings::inspect(a.gate, a.login, a.ui),
            Screen::Debug,
        ),
        #[cfg(not(feature = "board-mk3"))]
        #[cfg(not(feature = "board-mk3"))]
        Screen::Nickname => to(|a| crate::settings::edit_nickname(a.ui), Screen::Settings),
        #[cfg(feature = "board-q1")]
        // A main-menu tile on a blank device, and the QR key from any menu.
        Screen::ScanQr => returns(|a| crate::qrscan::screen(a.gate, a.login, a.ui)),
        #[cfg(not(feature = "board-mk3"))]
        Screen::Multisig => to(
            |a| crate::msimport::manage(a.gate, a.login, a.ui),
            Screen::Utils,
        ),
        #[cfg(not(feature = "board-mk3"))]
        Screen::WifStore => to(
            |a| crate::wifstore::manage(a.gate, a.login, a.ui),
            Screen::Utils,
        ),
        #[cfg(not(feature = "board-mk3"))]
        Screen::SettingsToSd => to(|a| crate::settings::backup_to_card(a.ui), Screen::Debug),
        #[cfg(not(feature = "board-mk3"))]
        Screen::NickPreview => to(
            |a| crate::settings::show_nickname_screen(a.ui),
            Screen::Debug,
        ),
        #[cfg(feature = "board-q1")]
        Screen::Notes => to(|a| crate::notes::view(a.gate, a.login, a.ui), Screen::Debug),
        #[cfg(feature = "games")]
        Screen::BlockMine => to(|a| crate::game::block_mine(a.ui), Screen::Games),
        #[cfg(feature = "games")]
        Screen::BlockCutter => to(|a| crate::game::block_cutter(a.ui), Screen::Games),
        #[cfg(all(feature = "games", feature = "board-q1"))]
        Screen::FlappyCat => to(|a| crate::flappy::flappy_cat(a.ui), Screen::Games),
        Screen::NewSeed(_) => reseeds(
            |a| new_seed(a.gate, a.login, a.ui, a.pool.as_deref_mut(), a.words),
            Screen::Main,
        ),
        Screen::ImportSeed => reseeds(|a| import_seed(a.gate, a.login, a.ui), Screen::Main),
        // Both put a seed on a blank device, so the session re-reads the slot afterwards.
        Screen::CloneImport => reseeds(
            |a| crate::backup::clone_import(a.gate, a.login, a.ui),
            Screen::Main,
        ),
        Screen::TapsignerImport => reseeds(
            |a| crate::tapsigner::import(a.gate, a.login, a.ui),
            Screen::Main,
        ),
        Screen::WipeSeed => reseeds(
            |a| {
                wipe_seed(a.gate, a.login, a.ui);
            },
            Screen::Main,
        ),
        Screen::ChangePin => to(|a| change_pin_screen(a.gate, a.login, a.ui), Screen::Login),
        Screen::TestLogin => to(|a| test_login_screen(a.gate, a.login, a.ui), Screen::Login),
        #[cfg(not(feature = "board-mk3"))]
        Screen::ScrambleKeys => to(
            |a| scramble_keys_screen(a.gate, a.login, a.ui),
            Screen::Login,
        ),
        #[cfg(not(feature = "board-mk3"))]
        Screen::LoginCountdown => to(|a| login_countdown_screen(a.ui), Screen::Login),
        #[cfg(all(not(feature = "dev"), not(feature = "board-mk3")))]
        Screen::KillKey => to(
            |a| crate::guard::kill_key_screen(a.gate, a.login, a.ui),
            Screen::Login,
        ),
        #[cfg(all(not(feature = "dev"), not(feature = "board-mk3")))]
        Screen::Sd2fa => to(|a| crate::guard::sd2fa_screen(a.ui), Screen::Login),
        #[cfg(not(feature = "board-mk3"))]
        Screen::IdleTimeout => to(
            |a| idle_timeout_screen(a.gate, a.login, a.ui),
            Screen::Settings,
        ),
        #[cfg(not(feature = "board-mk3"))]
        Screen::DisplayUnits => to(
            |a| display_units_screen(a.gate, a.login, a.ui),
            Screen::Settings,
        ),
        #[cfg(not(feature = "board-mk3"))]
        Screen::MaxFee => to(|a| max_fee_screen(a.gate, a.login, a.ui), Screen::Settings),
        #[cfg(not(feature = "board-mk3"))]
        Screen::UsbPort => to(|a| usb_port_screen(a.gate, a.login, a.ui), Screen::Hardware),
        #[cfg(not(feature = "board-mk3"))]
        Screen::VirtualDisk => to(
            |a| virtual_disk_screen(a.gate, a.login, a.ui),
            Screen::Hardware,
        ),
        #[cfg(not(feature = "board-mk3"))]
        Screen::MenuWrap => to(
            |a| menu_wrap_screen(a.gate, a.login, a.ui),
            Screen::Settings,
        ),
        #[cfg(not(feature = "board-mk3"))]
        Screen::TestnetMode => to(
            |a| testnet_mode_screen(a.gate, a.login, a.ui),
            Screen::DangerZone,
        ),
        #[cfg(feature = "board-q1")]
        Screen::Brightness => to(
            |a| brightness_screen(a.gate, a.login, a.ui),
            Screen::Settings,
        ),
        Screen::ViewWords => to(|a| view_words(a.gate, a.login, a.ui), Screen::SeedTools),
        #[cfg(feature = "board-q1")]
        Screen::SeedQrShow => to(
            |a| crate::seedqr::export(a.gate, a.login, a.ui),
            Screen::SeedTools,
        ),
        Screen::LockDown => to(|a| lock_down(a.gate, a.login, a.ui), Screen::SeedTools),
        Screen::FactoryReset => to(
            |a| factory_reset_screen(a.gate, a.login, a.ui),
            Screen::Debug,
        ),
        _ => return None,
    })
}

/// Secure logout: drop the MCU's copy of the secret, then hand over to the bootloader.
///
/// On this hardware the secret lives only in MCU SRAM -- the secure element re-runs the
/// full PIN key-stretch on every secret read, so there is no persistent SE session to
/// end, and clearing the MCU's copy is what de-authorises. Zeroize the login struct (its
/// cached PIN and any secret material) first, then callgate 3 wipes *all* SRAM and
/// reboots to the PIN prompt, so nothing survives to the next boot.
fn secure_logout(gate: &Callgate, login: &mut catcard_pin::Login, ui: &mut Ui<'_>) -> ! {
    use zeroize::Zeroize;

    login.zeroize();
    message(ui.panel, "Secure Logout", "wiping memory", "");
    // SAFETY: nothing after this runs; the bootloader clears SRAM.
    unsafe { gate.logout(LogoutMode::LogoutAndReboot) }
}

/// Restart the device, cleanly, after asking.
///
/// The bootloader's own restart: `LogoutMode::LogoutAndReboot` wipes SRAM and comes back
/// at the PIN prompt, which is exactly what pulling the cable does and nothing more. It is
/// not the sort of reset that keeps the session -- so the question says the PIN will be
/// asked for again rather than leaving someone to find that out.
///
/// Nothing stored is touched: no seed, no settings, no PIN. That is why this one asks once
/// where `Factory Reset` two rows below asks twice.
///
/// The login struct is zeroized first, as [`secure_logout`] does. The bootloader clears
/// SRAM on the way through, so this is belt and braces -- and it costs nothing on a path
/// that is about to stop running code.
fn warm_reset(gate: &Callgate, login: &mut catcard_pin::Login, ui: &mut Ui<'_>) {
    use zeroize::Zeroize;

    ask(
        ui.panel,
        "Warm reset?",
        "the device reboots",
        "and asks for the PIN",
    );
    if !confirmed(ui) {
        return;
    }
    crate::catlog!("menu: warm reset");
    login.zeroize();
    message(ui.panel, "Rebooting", "", "");
    // SAFETY: nothing after this runs; the bootloader clears SRAM and restarts the CPU.
    unsafe { gate.logout(LogoutMode::LogoutAndReboot) }
}

/// Change the main PIN, and say what happened.
fn change_pin_screen(gate: &Callgate, login: &mut catcard_pin::Login, ui: &mut Ui<'_>) {
    use crate::pinentry::ChangePin;

    match crate::pinentry::change_pin(gate, ui.panel, ui.matrix, ui.drbg, login) {
        ChangePin::Changed => {
            crate::catlog!("pin: changed");
            message(ui.panel, "PIN changed", "logged in with", "the new PIN");
            wait_for_any_key(ui);
        }
        // Nothing was written; the session is untouched.
        ChangePin::Cancelled => {}
        ChangePin::Mismatch => {
            message(ui.panel, "Not changed", "the two entries", "did not match");
            wait_for_any_key(ui);
        }
        // The change was refused (usually a wrong current PIN); the session is no longer
        // valid, so reboot to a fresh login with the unchanged PIN.
        ChangePin::Refused => {
            crate::catlog!("pin: change refused, rebooting");
            message(ui.panel, "Not changed", "rebooting", "");
            // SAFETY: nothing after this runs.
            unsafe { gate.logout(LogoutMode::LogoutAndReboot) }
        }
    }
}

/// Factory reset: clear the PIN back to blank, behind two confirmations.
fn factory_reset_screen(gate: &Callgate, login: &mut catcard_pin::Login, ui: &mut Ui<'_>) {
    use crate::pinentry::FactoryReset;

    // Destructive and irreversible: it clears the PIN back to blank. Ask twice, the same
    // as destroying a wallet, before even collecting the PIN.
    let go = {
        ask(
            ui.panel,
            "Factory reset?",
            "the PIN is CLEARED",
            "device back to blank",
        );
        confirmed(ui) && {
            ask(ui.panel, "Really reset?", "this cannot be", "undone");
            confirmed(ui)
        }
    };
    if !go {
        return;
    }
    match crate::pinentry::factory_reset(gate, ui.panel, ui.matrix, ui.drbg, login) {
        // The device is blank now; reboot straight into the first-run flow.
        FactoryReset::Wiped => {
            crate::catlog!("pin: factory reset, rebooting blank");
            message(ui.panel, "Reset done", "rebooting", "");
            // SAFETY: nothing after this runs.
            unsafe { gate.logout(LogoutMode::LogoutAndReboot) }
        }
        // A wrong current PIN (or another failure) leaves the session invalid, so reboot
        // to a fresh login with the unchanged PIN.
        FactoryReset::Refused => {
            crate::catlog!("pin: factory reset refused, rebooting");
            message(ui.panel, "Not reset", "rebooting", "");
            // SAFETY: nothing after this runs.
            unsafe { gate.logout(LogoutMode::LogoutAndReboot) }
        }
        // Backed out during PIN entry; nothing changed.
        FactoryReset::Cancelled => {}
    }
}

/// Where a key takes us. Returns the next screen.
fn step(screen: Screen, key: Key, cursor: usize, no_seed: bool) -> Screen {
    // The right arrow goes in and the left arrow comes out, the same as `y` and `x`.
    // Normalising here keeps every screen below written in terms of two actions rather
    // than four keys, so a screen cannot accidentally honour one and forget the other.
    let key = match key {
        Key::Digit(9) => Key::Confirm,
        Key::Digit(7) => Key::Cancel,
        k => k,
    };
    // The QR key opens the scanner from any menu, and the scanner comes back to it.
    #[cfg(feature = "board-q1")]
    if key == Key::Qr && items_of(screen, no_seed).is_some() {
        return Screen::ScanQr;
    }
    match screen {
        // Dispatched by name rather than by cursor index, because this list reorders:
        // a device with no seed puts "New wallet" first. An index table silently points
        // at the wrong entry the moment the order changes, and the entry it used to
        // reach by falling through was Reboot.
        Screen::Main => match (key, main_items(no_seed).get(cursor).copied()) {
            // A wallet is present: the first cell signs a transaction from the SD card.
            (Key::Confirm, Some("Sign")) => Screen::SignMenu,
            // The first two cells on a blank device, where there is nothing to sign and
            // nothing to explore.
            (Key::Confirm, Some("New")) => Screen::NewSeedMenu,
            (Key::Confirm, Some("Import")) => Screen::ImportMenu,
            #[cfg(feature = "board-q1")]
            (Key::Confirm, Some("Scan QR")) => Screen::ScanQr,
            (Key::Confirm, Some("Addresses")) => Screen::AddressExplorer,
            #[cfg(feature = "board-q1")]
            (Key::Confirm, Some("Notes")) => Screen::Notes,
            (Key::Confirm, Some("Utils")) => Screen::Utils,
            (Key::Confirm, Some("Derive")) => Screen::KeyMenu,
            // The first row when a wallet other than the root is in force: it names the
            // one you are in, and selecting it is how you leave.
            (Key::Confirm, Some(name)) if name.starts_with('[') => Screen::KeyMenu,
            (Key::Confirm, Some("Settings")) => Screen::Settings,
            // Handled in `run`, where the login struct is in scope to be zeroized first.
            (Key::Confirm, Some("Logout")) => Screen::SecureLogout,
            _ => Screen::Main,
        },
        // By name again, for the same reason as Main: the list is short today and the
        // count is what the next screen acts on, so an index table would be one
        // reordering away from generating the wrong length of seed.
        Screen::NewSeedMenu => match (key, NEW_SEED_ITEMS.get(cursor).copied()) {
            (Key::Confirm, Some("24 words")) => Screen::NewSeed(24),
            (Key::Confirm, Some("12 words")) => Screen::NewSeed(12),
            (Key::Cancel, _) => Screen::Main,
            _ => Screen::NewSeedMenu,
        },
        // By name, like the menus above it: the list is short and reorder-safe.
        Screen::ImportMenu => match (key, IMPORT_ITEMS.get(cursor).copied()) {
            (Key::Confirm, Some("Words")) => Screen::ImportSeed,
            (Key::Confirm, Some("Clone")) => Screen::CloneImport,
            (Key::Confirm, Some("TAPSIGNER")) => Screen::TapsignerImport,
            (Key::Cancel, _) => Screen::Main,
            _ => Screen::ImportMenu,
        },
        Screen::Settings => match (key, settings_items(no_seed).get(cursor).copied()) {
            #[cfg(not(feature = "board-mk3"))]
            (Key::Confirm, Some("Multisig")) => Screen::Multisig,
            (Key::Confirm, Some("About")) => Screen::About,
            (Key::Confirm, Some("Debug")) => Screen::Debug,
            (Key::Confirm, Some("Login")) => Screen::Login,
            (Key::Confirm, Some("Passphrase")) => Screen::Passphrase,
            (Key::Confirm, Some("Danger zone")) => Screen::DangerZone,
            #[cfg(all(feature = "multichain", not(feature = "board-mk3")))]
            (Key::Confirm, Some("Chains")) => Screen::ChainSettings,
            #[cfg(not(feature = "board-mk3"))]
            (Key::Confirm, Some("Idle timeout")) => Screen::IdleTimeout,
            #[cfg(not(feature = "board-mk3"))]
            (Key::Confirm, Some("Display units")) => Screen::DisplayUnits,
            #[cfg(not(feature = "board-mk3"))]
            (Key::Confirm, Some("Max network fee")) => Screen::MaxFee,
            #[cfg(not(feature = "board-mk3"))]
            (Key::Confirm, Some("Hardware On/Off")) => Screen::Hardware,
            #[cfg(not(feature = "board-mk3"))]
            (Key::Confirm, Some("Menu wrapping")) => Screen::MenuWrap,
            #[cfg(feature = "board-q1")]
            (Key::Confirm, Some("LCD brightness")) => Screen::Brightness,
            (Key::Cancel, _) => Screen::Main,
            _ => Screen::Settings,
        },
        #[cfg(not(feature = "board-mk3"))]
        Screen::Hardware => match (key, HARDWARE_ITEMS.get(cursor).copied()) {
            (Key::Confirm, Some("USB port")) => Screen::UsbPort,
            (Key::Confirm, Some("Virtual Disk")) => Screen::VirtualDisk,
            (Key::Cancel, _) => Screen::Settings,
            _ => Screen::Hardware,
        },
        Screen::DangerZone => match (key, DANGER_ITEMS.get(cursor).copied()) {
            (Key::Confirm, Some("Seed tools")) => Screen::SeedTools,
            #[cfg(not(feature = "board-mk3"))]
            (Key::Confirm, Some("Testnet mode")) => Screen::TestnetMode,
            (Key::Cancel, _) => Screen::Settings,
            _ => Screen::DangerZone,
        },
        Screen::SeedTools => match (key, seed_tools_items().get(cursor).copied()) {
            (Key::Confirm, Some("View words")) => Screen::ViewWords,
            #[cfg(feature = "board-q1")]
            (Key::Confirm, Some("SeedQR")) => Screen::SeedQrShow,
            (Key::Confirm, Some("Destroy seed")) => Screen::WipeSeed,
            (Key::Confirm, Some("Lock down seed")) => Screen::LockDown,
            (Key::Cancel, _) => Screen::DangerZone,
            _ => Screen::SeedTools,
        },
        // The export drawer. Its rows were briefly handled inside `Utils`, where none of
        // them can ever be selected -- so Confirm fell through to the catch-all and put
        // people in the Debug menu.
        Screen::KeyMenu => match (key, key_items().get(cursor).copied()) {
            (Key::Confirm, Some("Passphrase")) => Screen::KeyPassphrase,
            (Key::Confirm, Some("XOR split")) => Screen::XorSplit,
            (Key::Confirm, Some("XOR join")) => Screen::XorJoin,
            #[cfg(not(feature = "board-mk3"))]
            (Key::Confirm, Some("Key vault")) => Screen::KeyVault,
            (Key::Confirm, Some(_)) => Screen::KeyPick(cursor as u8),
            (Key::Cancel, _) => Screen::Main,
            _ => Screen::KeyMenu,
        },
        Screen::SignMenu => match (key, SIGN_ITEMS.get(cursor).copied()) {
            #[cfg(feature = "board-q1")]
            (Key::Confirm, Some("Scan")) => Screen::ScanQr,
            (Key::Confirm, Some("From SD")) => Screen::SignPsbt,
            (Key::Confirm, Some("Batch sign")) => Screen::BatchSign,
            #[cfg(not(feature = "board-mk3"))]
            (Key::Confirm, Some("By NFC")) => Screen::SignNfc,
            (Key::Confirm, Some("Message")) => Screen::SignMessage,
            (Key::Confirm, Some("Text file")) => Screen::SignTextFile,
            (Key::Confirm, Some("Verify")) => Screen::VerifySig,
            (Key::Cancel, _) => Screen::Main,
            _ => Screen::SignMenu,
        },
        Screen::KeyPick(_) => Screen::KeyMenu,
        Screen::XorSplit | Screen::XorJoin => Screen::KeyMenu,
        Screen::LockDown => Screen::SeedTools,
        #[cfg(not(feature = "board-mk3"))]
        Screen::KeyVault => Screen::KeyMenu,
        Screen::ExportMenu => match (key, EXPORT_ITEMS.get(cursor).copied()) {
            (Key::Confirm, Some(name)) if generic_json_file(name).is_some() => {
                Screen::GenericJson(cursor as u8)
            }
            (Key::Confirm, Some(name)) if one_off(name).is_some() => {
                Screen::ExportOne(cursor as u8)
            }
            (Key::Confirm, Some("Key Expression")) => Screen::ExportKeyExpr,
            (Key::Confirm, Some("Export XPUB")) => Screen::XpubMenu,
            #[cfg(all(feature = "board-q1", feature = "multichain"))]
            (Key::Confirm, Some("Account (UR)")) => Screen::AccountUr,
            #[cfg(feature = "multichain")]
            (Key::Confirm, Some("Keystone")) => Screen::Keystone,
            (Key::Confirm, Some("Dump Summary")) => Screen::DumpSummary,
            (Key::Confirm, Some("Address CSV")) => Screen::AddressCsv,
            (Key::Cancel, _) => Screen::Utils,
            _ => Screen::ExportMenu,
        },
        Screen::XpubMenu => match key {
            Key::Confirm => Screen::Xpub(cursor as u8),
            Key::Cancel => Screen::ExportMenu,
            _ => Screen::XpubMenu,
        },
        Screen::Login => match (key, LOGIN_ITEMS.get(cursor).copied()) {
            (Key::Confirm, Some("Change PIN")) => Screen::ChangePin,
            (Key::Confirm, Some("Test login")) => Screen::TestLogin,
            #[cfg(not(feature = "board-mk3"))]
            (Key::Confirm, Some("Scramble keys")) => Screen::ScrambleKeys,
            #[cfg(not(feature = "board-mk3"))]
            (Key::Confirm, Some("Login countdown")) => Screen::LoginCountdown,
            #[cfg(all(not(feature = "dev"), not(feature = "board-mk3")))]
            (Key::Confirm, Some("Kill key")) => Screen::KillKey,
            #[cfg(all(not(feature = "dev"), not(feature = "board-mk3")))]
            (Key::Confirm, Some("MicroSD 2FA")) => Screen::Sd2fa,
            #[cfg(not(feature = "board-mk3"))]
            (Key::Confirm, Some("Nickname")) => Screen::Nickname,
            (Key::Cancel, _) => Screen::Settings,
            _ => Screen::Login,
        },
        // The splash: any key but cancel turns to the chip page, which any key but cancel
        // leaves. Cancel steps back a page.
        Screen::About => match key {
            Key::Cancel => Screen::Main,
            _ => Screen::AboutChip,
        },
        Screen::AboutChip => match key {
            Key::Cancel => Screen::About,
            _ => Screen::Main,
        },
        Screen::Utils => match (key, UTILS_ITEMS.get(cursor).copied()) {
            (Key::Confirm, Some("Analyze RNG")) => Screen::AnalyzeRng,
            (Key::Confirm, Some("USB Drive")) => Screen::UsbDrive,
            #[cfg(not(feature = "board-mk3"))]
            (Key::Confirm, Some("Paper wallet")) => Screen::PaperWallet,
            (Key::Confirm, Some("Export wallet")) => Screen::ExportMenu,
            (Key::Confirm, Some("Backup")) => Screen::BackupMenu,
            (Key::Confirm, Some("Browse SD card")) => Screen::BrowseSd,
            (Key::Confirm, Some("Card details")) => Screen::CardDetails,
            (Key::Confirm, Some("Format SD card")) => Screen::FormatSd,
            (Key::Confirm, Some("Card password")) => Screen::CardPassword,
            #[cfg(not(feature = "board-mk3"))]
            (Key::Confirm, Some("Encrypt card")) => Screen::CardEncrypt,
            #[cfg(feature = "games")]
            (Key::Confirm, Some("Games")) => Screen::Games,
            #[cfg(not(feature = "board-mk3"))]
            (Key::Confirm, Some("WIF Store")) => Screen::WifStore,
            (Key::Confirm, Some("Upgrade Firmware")) => Screen::SdInstall,
            (Key::Cancel, _) => Screen::Main,
            _ => Screen::Utils,
        },
        Screen::BackupMenu => match (key, BACKUP_ITEMS.get(cursor).copied()) {
            (Key::Confirm, Some("Save backup")) => Screen::BackupSave,
            (Key::Confirm, Some("Restore backup")) => Screen::BackupRestore,
            (Key::Confirm, Some("Clone Coldcard")) => Screen::CloneExport,
            (Key::Cancel, _) => Screen::Utils,
            _ => Screen::BackupMenu,
        },
        #[cfg(feature = "games")]
        Screen::Games => match (key, GAMES_ITEMS.get(cursor).copied()) {
            (Key::Confirm, Some("Block Mine")) => Screen::BlockMine,
            (Key::Confirm, Some("Block Cutter")) => Screen::BlockCutter,
            #[cfg(feature = "board-q1")]
            (Key::Confirm, Some("Flappy Cat")) => Screen::FlappyCat,
            (Key::Cancel, _) => Screen::Utils,
            _ => Screen::Games,
        },
        // By name, like Main: the list reorders -- Install from SD sat at the top of it
        // until it moved to Utils -- and an index table would silently point at the wrong
        // entry.
        Screen::Debug => match (key, DEBUG_ITEMS.get(cursor).copied()) {
            (Key::Confirm, Some("View TRNG Words")) => Screen::ViewTrngWords,
            #[cfg(not(feature = "board-mk3"))]
            (Key::Confirm, Some("NFC test")) => Screen::NfcTest,
            #[cfg(all(not(feature = "board-mk3"), feature = "usb-debug-mem"))]
            (Key::Confirm, Some("Dump state")) => Screen::DumpState,
            #[cfg(all(not(feature = "board-mk3"), feature = "usb-debug-mem"))]
            (Key::Confirm, Some("Restore settings")) => Screen::RestoreSettings,
            #[cfg(feature = "board-q1")]
            (Key::Confirm, Some("QR probe")) => Screen::QrProbe,
            #[cfg(feature = "board-q1")]
            (Key::Confirm, Some("Sweep test")) => Screen::SweepTest,
            (Key::Confirm, Some("USB")) => Screen::Usb,
            (Key::Confirm, Some("Clocks")) => Screen::Clocks,
            (Key::Confirm, Some("RTC")) => Screen::Rtc,
            (Key::Confirm, Some("Kernel")) => Screen::Kernel,
            (Key::Confirm, Some("Scroll test")) => Screen::ScrollTest,
            #[cfg(not(feature = "board-mk3"))]
            (Key::Confirm, Some("Settings store")) => Screen::SettingsStore,
            #[cfg(not(feature = "board-mk3"))]
            (Key::Confirm, Some("Settings to SD")) => Screen::SettingsToSd,
            #[cfg(not(feature = "board-mk3"))]
            (Key::Confirm, Some("Nickname screen")) => Screen::NickPreview,
            #[cfg(not(feature = "board-mk3"))]
            #[cfg(feature = "board-q1")]
            (Key::Confirm, Some("Secure notes")) => Screen::Notes,
            (Key::Confirm, Some("PSRAM")) => Screen::Psram,
            (Key::Confirm, Some("SPI-NOR")) => Screen::Sflash,
            (Key::Confirm, Some("Boot report")) => Screen::Boot,
            (Key::Confirm, Some("Selftest")) => Screen::Selftest,
            (Key::Confirm, Some("Keypad")) => Screen::Keypad,
            (Key::Confirm, Some("PRNG status")) => Screen::PrngStatus,
            (Key::Confirm, Some("microSD")) => Screen::Sd,
            (Key::Confirm, Some("Logs")) => Screen::Logs,
            (Key::Confirm, Some("Save log to SD")) => Screen::SaveLog,
            (Key::Confirm, Some("Colours")) => Screen::Colours,
            (Key::Confirm, Some("Warm Reset")) => Screen::WarmReset,
            (Key::Confirm, Some("Factory Reset")) => Screen::FactoryReset,
            (Key::Cancel, _) => Screen::Main,
            _ => Screen::Debug,
        },
        // The probe is reached by pressing the tick on the PSRAM screen, never by
        // arriving there. An unmapped read faults and a fault needs a power cycle, so
        // the risk is worth taking deliberately and not by navigation.
        Screen::Psram => match key {
            Key::Confirm => Screen::PsramProbe,
            _ => Screen::Debug,
        },
        // Card details is an info screen reached from Utils, so any key returns there
        // rather than to the Debug fallback below.
        Screen::CardDetails => Screen::Utils,
        // Every info screen leaves on any key, back to the drawer it was opened from.
        //
        // A **menu** that reaches here has simply forgotten to say what its keys do, and
        // sending it to Debug is how the export drawer put people in the Debug menu
        // instead of exporting anything. A menu with no arm stays where it is: a screen
        // that does nothing is a bug someone can describe, and one that moves them
        // somewhere else is a bug they cannot.
        other if items_of(other, no_seed).is_some() => other,
        _ => Screen::Debug,
    }
}

/// What the menu runs on: the peripherals it drives and the state it reports.
///
/// A struct rather than eight positional arguments, which is one transposed pair away
/// from driving the wrong thing.
pub struct Session<'a> {
    pub gate: &'a Callgate,
    /// The logged-in PIN struct. `gate 18/7` authorises an upgrade through it, and only
    /// a logged-in one carries the signature that call requires.
    pub login: &'a mut catcard_pin::Login,
    pub panel: &'a mut display::Panel,
    pub matrix: &'a mut GpioMatrix,
    pub drbg: &'a mut HmacDrbg,
    /// The protocol DRBG, for secrets that leave the device. See [`Ui::protocol`].
    pub protocol: &'a mut HmacDrbg,
    pub report: &'a BootReport,
    /// Whether the secret slot is still empty, as the bootloader reported it at login.
    pub no_seed: bool,
    /// The boot entropy pool, moved out of the report so it can be drawn from.
    ///
    /// `None` on a device whose pool never met its policy — which is a refusal to
    /// generate a seed, not a reason to look for entropy somewhere weaker.
    pub pool: Option<&'a mut catcard_entropy::EntropyPool>,
}

/// Everything a screen needs to draw itself.
///
/// Grouped rather than passed one by one: these travel together through the loop, and a
/// call taking eight positional arguments is one transposed pair away from drawing the
/// wrong thing without the compiler noticing.
struct View<'a> {
    report: &'a BootReport,
    last_key: Option<Key>,
    keys_seen: u32,
    /// A snapshot of the UI DRBG's diagnostic counters, refreshed before each draw so the
    /// PRNG-status screen shows current numbers.
    drbg_stats: catcard_entropy::DrbgStats,
    /// A fresh 32-bit draw from the UI DRBG, taken only when the PRNG-status screen is
    /// about to be drawn. `None` if the draw errored (only possible past the reseed
    /// interval). Advancing the DRBG to show a sample is exactly what it is for.
    drbg_sample: Option<u32>,
    /// The list screen's own state: where the cursor is and how far the view is scrolled.
    menu: MenuScreen,
    /// The last raw matrix position pressed, and which positions are held, for the
    /// keypad tester. Raw rather than decoded: the modifiers, the lamp and the two
    /// hardware keys decode to nothing, and a tester that showed only decoded keys made
    /// them look dead on the one screen meant to tell dead from unmapped.
    raw_kn: Option<usize>,
    raw_held: u64,
    /// The RTC debug screen's sampler.
    rtc: RtcWatch,
    /// The kernel status screen's repaint pacer.
    kernel_pace: Pace,
    /// The bootloader's answer at login: no secret has been written to the slot.
    no_seed: bool,
}

impl View<'_> {
    /// A fresh scroll position for a new list: cursor at the top, view unscrolled.
    fn reset_menu(&mut self) {
        self.menu.reset();
    }

    /// Whether the menu should lead with making a wallet rather than using one.
    ///
    /// Two sources, and either saying "nothing here" is enough. The bootloader's flag
    /// reports whether a secret was ever *written*; a seed destroyed since leaves the slot
    /// zeroed with that flag still set, and a device in that state was offering Sign and
    /// Addresses for a wallet it did not have. What the firmware has read out of the slot
    /// settles it where it has looked.
    ///
    /// A key loaded for the session is a wallet either way, so neither applies then.
    fn blank(&self) -> bool {
        crate::key::no_stored_wallet(self.no_seed) && crate::key::loaded().is_none()
    }
}

/// A list screen: the cursor and scroll offset that survive a keypress.
///
/// These lived on [`View`] as two loose fields that one block of the run loop moved
/// inline, so the only thing able to drive a menu was that block. Owned by the screen,
/// a menu answers a key the way [`DocScreen`] does -- the shape a run loop can hand
/// events to rather than reach into.
///
/// The `ScrollView` is rebuilt per draw and per key rather than stored. It borrows both
/// the item slice and the note, and the note is a [`Line`] built on the caller's stack by
/// [`menu_head`] -- so a stored view would borrow a local. Rebuilding is what `draw_menu`
/// always did.
#[derive(Copy, Clone)]
struct MenuScreen {
    /// Index of the item under the cursor, in the id space `build_menu_view` gives its
    /// rows -- the item's position, with title and note rows carrying no id.
    cursor: usize,
    /// Pixel scroll offset, kept across redraws so the highlight pushes the view at the
    /// edges rather than the view snapping to the cursor each frame.
    off: usize,
}

impl MenuScreen {
    const fn new() -> Self {
        Self { cursor: 0, off: 0 }
    }

    /// Start a new list at the top. Carrying a cursor between menus of different lengths
    /// is how you land on an item nobody chose.
    fn reset(&mut self) {
        *self = Self::new();
    }

    fn draw(&self, panel: &mut display::Panel, screen: Screen, no_seed: bool) {
        let items = items_of(screen, no_seed).unwrap_or(&[]);
        #[cfg(feature = "board-q1")]
        if is_grid_items(items) {
            return draw_grid(panel, items, self.cursor, self.off);
        }
        let (title, note) = menu_head(screen);
        let view = build_menu_view(title, note.as_str(), items, self.off, self.cursor);
        // Through the marks path, like every other screen that renders a document: a
        // list menu can carry a colour mark too, and one drawn plain would leave its
        // space empty.
        #[cfg(feature = "board-q1")]
        display::draw_with_marks(panel, &view, |c| catcard_ui::scroll::render(c, &view));
        #[cfg(not(feature = "board-q1"))]
        display::draw(panel, |c| catcard_ui::scroll::render(c, &view));
    }

    /// Take a movement key (`0`, `5` or `8`) and animate where it lands.
    ///
    /// The move runs through the scroll view so the highlight travels within the panel
    /// and only pushes the view at an edge, and so pressing past the first or last item
    /// keeps scrolling to reveal the title.
    fn key(&mut self, ui: &mut Ui<'_>, screen: Screen, items: &[&str], k: Key) {
        #[cfg(feature = "board-q1")]
        if is_grid_items(items) {
            self.cursor = grid_move(self.cursor, items.len(), k);
            // The window follows only as far as it must, which is the same rule the list
            // below follows going down: `off` is the leftmost column on screen, and the
            // cursor moves inside it until it reaches an edge.
            let was = self.off;
            self.off = catcard_ui::grid::window(self.cursor, items.len(), self.off);
            let moved = self.off.abs_diff(was);
            if moved >= catcard_ui::grid::COLS {
                // A jump that changes every column -- `0` back to the start from deep in
                // the strip. The panel's own scroll is a whole screen wide, so it tells
                // the truth only when a whole screen's worth is what changed.
                slide_grid(ui.panel, items, self.cursor, self.off, self.off > was);
            } else {
                // One column, or none. Redrawn rather than slid: a screen-wide slide for
                // a third of a screen's movement is the picture travelling further than
                // the key asked for, which is what the list avoids by simply redrawing.
                draw_grid(ui.panel, items, self.cursor, self.off);
            }
            return;
        }
        let (title, note) = menu_head(screen);
        let mut view = build_menu_view(title, note.as_str(), items, self.off, self.cursor);
        let old = view.off();
        match k {
            // `0` jumps back to the top, the arrows move one row.
            Key::Digit(0) => view.to_top(),
            Key::Digit(8) => view.move_cursor(true),
            _ => view.move_cursor(false),
        }
        if let Some(id) = view.selected() {
            self.cursor = id as usize;
        }
        let new_off = view.off();
        // Animate the move, then let the loop's redraw paint the settled frame.
        glide_view(ui.panel, &mut view, old, new_off);
        self.off = new_off;
    }
}

/// Whether a menu is drawn as the icon grid rather than as a list.
///
/// **The grid is the Q1's view of an ordinary menu, not a set of special screens.** It
/// used to be four named ones; naming them meant a new menu of tools was a list until
/// somebody remembered, and a menu that lost an icon stayed a grid with a hole in it.
/// The rule now is the one that was always meant: a menu every entry of which has art is
/// pictures, and a menu with a wordy entry in it is a list. Drawing the icons is what
/// turns one into the other.
///
/// A list is still the right shape for most of them -- fifteen settings are words, and
/// six words in boxes are harder to read than six words in a column, not easier.
#[cfg(feature = "board-q1")]
fn is_grid_items(items: &[&str]) -> bool {
    !items.is_empty() && items.iter().all(|l| grid_icon(l).is_some())
}

/// As [`is_grid_items`], for a screen whose items are not already in hand.
#[cfg(feature = "board-q1")]
fn is_grid(screen: Screen, no_seed: bool) -> bool {
    items_of(screen, no_seed).is_some_and(is_grid_items)
}

/// Where a movement key takes the grid cursor.
///
/// The arithmetic is [`catcard_ui::grid::step`], which is where it can be tested against
/// a strip of pages; this is only the key mapping.
#[cfg(feature = "board-q1")]
fn grid_move(cursor: usize, len: usize, k: Key) -> usize {
    use catcard_ui::grid::Dir;
    let dir = match k {
        Key::Digit(0) => Dir::Home,
        Key::Digit(8) => Dir::Down,
        Key::Digit(5) => Dir::Up,
        Key::Digit(9) => Dir::Right,
        Key::Digit(7) => Dir::Left,
        _ => return cursor,
    };
    catcard_ui::grid::step(cursor, len, dir)
}

/// A menu as a grid of icons, six to a page.
///
/// The page is the one the cursor is on, so moving down off the bottom row turns to the
/// next and up off the top row turns back -- the same keys, no new ones to learn. A menu
/// longer than a page says which page it is on, under the middle column.
#[cfg(feature = "board-q1")]
/// The art a grid cell shows for a label, if that label has any.
///
/// **This is also what decides whether a menu is a grid at all.** A menu every one of
/// whose entries answers here is drawn as pictures on the Q1; one with an entry that
/// does not stays a list. So adding a grid is drawing its icons, and a half-drawn set
/// never produces a screen of named empty boxes.
#[cfg(feature = "board-q1")]
fn grid_icon(label: &str) -> Option<&'static catcard_ui::art::indexed::Indexed> {
    use catcard_ui::art::menuicons as art;
    Some(match label {
        // The main menu.
        "Sign" => &art::SIGN,
        "New" => &art::NEW_PASSPHRASE,
        "Import" => &art::IMPORT_PASSPHRASE,
        "Addresses" => &art::ADDRESS_LIST,
        "Notes" => &art::NOTES,
        "Utils" => &art::UTILS,
        "Settings" => &art::SETTINGS,
        "Scan QR" => &art::SCAN_QR_CODE,
        "Derive" => &art::DERIVE_KEY,
        // The Derive grid.
        "Back to root" => &art::RETURN_ROOT_KEY,
        "Passphrase" => &art::DERIVE_PASSPHRASE,
        "BIP-85" => &art::DERIVE_BIP85_INDEX,
        "Import key" => &art::IMPORT_PASSPHRASE,
        "XOR split" => &art::XOR_SPLIT,
        "XOR join" => &art::XOR_JOIN,
        "Key vault" => &art::KEY_VAULT,
        // The Sign grid.
        "Scan" => &art::SIGN_QR,
        "From SD" => &art::SIGN_SD,
        // Batch reuses the SD icon: it is the same source, done for every file at once.
        "Batch sign" => &art::SIGN_SD,
        "By NFC" => &art::SIGN_NFC,
        "Message" => &art::SIGN_TEXT,
        "Text file" => &art::SIGN_TEXT_FILE,
        "Verify" => &art::VERIFY_SIGNATURE,
        // The Utils grid.
        "Analyze RNG" => &art::ANALYZE_RNG,
        "USB Drive" => &art::USB_DRIVE,
        "Export wallet" => &art::EXPORT_WALLET,
        "Browse SD card" => &art::MICROSD_BROWSE,
        "Format SD card" => &art::MICROSD_FORMAT,
        // The card-access icon: the CMD42 lock is about who may read the card at all.
        "Card password" => &art::MICROSD_ACCESS,
        "Games" => &art::GAMES,
        "Backup" => &art::BACKUP,
        "Upgrade Firmware" => &art::FIRMWARE_UPGRADE,
        // Only the boards with no power button still offer this.
        "Logout" => &art::LOGOUT,
        _ => return None,
    })
}

/// Paint one page of a menu's icons onto a surface.
///
/// No header row: the Q1 has a status bar, and it already names the wallet in force and
/// shows its fingerprint. A second copy on the grid would be the same answer twice, in
/// the screen with the least room for it. (The boards with no bar put the row in the
/// menu instead -- see `main_items`.)
#[cfg(feature = "board-q1")]
fn grid_frame(c: &mut display::Surface<'_>, items: &[&str], cursor: usize, off: usize) {
    use catcard_ui::grid::{CELLS, Cell, ROWS};
    let (col, row) = catcard_ui::grid::place(cursor);
    let mut cells: heapless::Vec<Cell<'_>, CELLS> = heapless::Vec::new();
    for label in items.iter().skip(off * ROWS).take(CELLS) {
        let _ = cells.push(Cell {
            label,
            icon: grid_icon(label),
        });
    }
    // Where the cursor is *within the window*, counted the way the window is filled:
    // down each column in turn.
    let within = col.saturating_sub(off) * ROWS + row;
    catcard_ui::grid::render_page(
        c,
        display::LAYOUT.title,
        display::LAYOUT.body,
        &cells,
        within,
        off,
        items.len(),
    );
}

/// Draw a menu as pages of icons, with the page the cursor is on showing.
///
/// The art's own palette, not the text ramp: this screen is pictures.
#[cfg(feature = "board-q1")]
fn draw_grid(panel: &mut display::Panel, items: &[&str], cursor: usize, off: usize) {
    display::draw_with(panel, &catcard_ui::art::menuicons::PALETTE, |c| {
        grid_frame(c, items, cursor, off)
    });
}

/// Draw the page the cursor has moved to, sliding it in from the side it is on.
///
/// The pages are laid out side by side, so a page change is a movement along a strip
/// and is shown as one -- by the panel's own scrolling, which costs one command a frame
/// rather than a redraw a frame.
#[cfg(feature = "board-q1")]
fn slide_grid(panel: &mut display::Panel, items: &[&str], cursor: usize, off: usize, right: bool) {
    display::slide_frame(panel, &catcard_ui::art::menuicons::PALETTE, right, |c| {
        grid_frame(c, items, cursor, off)
    });
}

/// The list on this screen, if it is a menu.
fn items_of(screen: Screen, no_seed: bool) -> Option<&'static [&'static str]> {
    match screen {
        Screen::Main => Some(main_items(no_seed)),
        Screen::Debug => Some(DEBUG_ITEMS),
        Screen::Utils => Some(UTILS_ITEMS),
        Screen::BackupMenu => Some(BACKUP_ITEMS),
        Screen::SignMenu => Some(SIGN_ITEMS),
        Screen::NewSeedMenu => Some(NEW_SEED_ITEMS),
        Screen::ImportMenu => Some(IMPORT_ITEMS),
        Screen::Settings => Some(settings_items(no_seed)),
        Screen::Login => Some(LOGIN_ITEMS),
        #[cfg(not(feature = "board-mk3"))]
        Screen::Hardware => Some(HARDWARE_ITEMS),
        Screen::DangerZone => Some(DANGER_ITEMS),
        Screen::SeedTools => Some(seed_tools_items()),
        Screen::KeyMenu => Some(key_items()),
        Screen::ExportMenu => Some(EXPORT_ITEMS),
        Screen::XpubMenu => Some(XPUB_ITEMS),
        #[cfg(feature = "games")]
        Screen::Games => Some(GAMES_ITEMS),
        _ => None,
    }
}

/// Draw whichever screen we are on.
fn draw(panel: &mut display::Panel, screen: Screen, v: &View<'_>) {
    match screen {
        // Every list screen renders the same way; the title and note come from
        // `menu_head`, the single place they are defined.
        Screen::Main
        | Screen::KeyMenu
        | Screen::Utils
        | Screen::SignMenu
        | Screen::NewSeedMenu
        | Screen::ImportMenu
        | Screen::Debug
        | Screen::Settings
        | Screen::Login
        | Screen::DangerZone
        | Screen::SeedTools
        | Screen::ExportMenu
        | Screen::BackupMenu
        | Screen::XpubMenu => draw_menu(panel, screen, v),
        #[cfg(not(feature = "board-mk3"))]
        Screen::Hardware => draw_menu(panel, screen, v),
        #[cfg(feature = "games")]
        Screen::Games => draw_menu(panel, screen, v),
        Screen::About => about_screen(panel),
        Screen::AboutChip => chip_screen(panel),
        Screen::Usb => usb_screen(panel),
        Screen::Clocks => clock_screen(panel),
        Screen::Psram => psram_screen(panel),
        Screen::Sflash => sflash_screen(panel),
        Screen::PsramProbe => psram_probe(panel),
        Screen::Boot => boot_screen(panel, v.report),
        Screen::Selftest => crate::selftest::screen(v.report, panel),
        Screen::Keypad => keypad_screen(panel, v.last_key, v.keys_seen, v.raw_kn, v.raw_held),
        Screen::PrngStatus => prng_screen(panel, v.drbg_stats, v.drbg_sample),
        Screen::Rtc => rtc_screen(panel, &v.rtc),
        // Handled in `run`: the scroll test owns the panel until it hands back.
        Screen::ScrollTest => {}
        #[cfg(not(feature = "board-mk3"))]
        Screen::SettingsStore
        | Screen::Nickname
        | Screen::SettingsToSd
        | Screen::Multisig
        | Screen::WifStore
        | Screen::NickPreview => {}
        #[cfg(feature = "board-q1")]
        Screen::Notes | Screen::ScanQr => {}
        Screen::Kernel => kernel_screen(panel),
        Screen::Colours => colours_screen(panel),
        Screen::Sd => sd_screen(panel),
        Screen::CardDetails => card_details_screen(panel),
        // Handled in `run`: it pages itself, and owns the keypad while it does.
        Screen::Logs => {}
        // Handled in `run`; never drawn.
        Screen::SaveLog => {}
        // Handled in `run`: it drives the panel itself in a tight loop.
        Screen::AnalyzeRng => {}
        // Handled in `run`: it takes over USB and needs the keypad to leave.
        Screen::UsbDrive => {}
        // Handled in `run`: it prompts, generates and writes the card itself.
        #[cfg(not(feature = "board-mk3"))]
        Screen::PaperWallet => {}
        Screen::ViewTrngWords => {}
        #[cfg(not(feature = "board-mk3"))]
        Screen::NfcTest => {}
        // Handled in `run`: it fetches the secret and drives its own paging loop.
        #[cfg(feature = "multichain")]
        Screen::Keystone => {}
        #[cfg(all(feature = "board-q1", feature = "multichain"))]
        Screen::AccountUr => {}
        Screen::AddressExplorer
        | Screen::ExportOne(_)
        | Screen::ExportKeyExpr
        | Screen::DumpSummary
        | Screen::AddressCsv
        | Screen::Xpub(_)
        | Screen::GenericJson(_)
        | Screen::Passphrase
        | Screen::KeyPassphrase => {}
        // Handled in `run`: it lists the SD card and drives its own loop.
        Screen::BrowseSd => {}
        // Handled in `run`: both drive their own screens -- the words, the progress bar
        // for the key derivation, and the card.
        Screen::BackupSave | Screen::BackupRestore => {}
        // Handled in `run`: it confirms, brings up the card, and drives the panel itself.
        Screen::FormatSd => {}
        // Handled in `run`: it brings up the card and drives its own menu and prompts.
        Screen::CardPassword => {}
        // Handled in `run`: it brings up the card and drives its own menu, prompts and
        // (for encrypt/remove) the full-card rewrite.
        #[cfg(not(feature = "board-mk3"))]
        Screen::CardEncrypt => {}
        // Handled in `run`: it runs the file picker and drives the panel itself.
        Screen::SignPsbt
        | Screen::BatchSign
        | Screen::SignMessage
        | Screen::SignTextFile
        | Screen::VerifySig => {}
        // Handled in `run`: it drives the tag and the panel itself.
        #[cfg(not(feature = "board-mk3"))]
        Screen::SignNfc => {}
        // Handled in `run`: it zeroizes the login and calls the bootloader; never drawn.
        Screen::SecureLogout => {}
        // Handled in `run`: it needs the keypad, which the drawing half does not have.
        Screen::SdInstall => {}
        // Handled in `run`: it asks, then calls the bootloader; never drawn.
        Screen::WarmReset => {}
        // Handled in `run`: it drives its own screen, because moving a row is a key the
        // list screens do not have.
        #[cfg(all(feature = "multichain", not(feature = "board-mk3")))]
        Screen::ChainSettings => {}
        // Handled in `run`: it derives, which needs the login struct.
        Screen::KeyPick(_) => {}
        // Handled in `run`: both drive their own screens from the keypad.
        Screen::XorSplit | Screen::XorJoin => {}
        #[cfg(not(feature = "board-mk3"))]
        Screen::KeyVault => {}
        #[cfg(all(not(feature = "board-mk3"), feature = "usb-debug-mem"))]
        Screen::DumpState => {}
        #[cfg(all(not(feature = "board-mk3"), feature = "usb-debug-mem"))]
        Screen::RestoreSettings => {}
        #[cfg(feature = "board-q1")]
        Screen::QrProbe => {}
        #[cfg(feature = "board-q1")]
        Screen::SweepTest => {}
        // Handled in `run`: it asks questions and shows words, so it drives the panel
        // and the keypad itself.
        Screen::NewSeed(_) => {}
        // Handled in `run`: it reads words from the keypad and drives the panel itself.
        Screen::ImportSeed => {}
        // Handled in `run`: each drives its own file picker, key entry and progress.
        Screen::CloneExport | Screen::CloneImport | Screen::TapsignerImport => {}
        // Handled in `run`: it drives the PIN-entry screens itself.
        Screen::ChangePin => {}
        // Handled in `run`: the game drives the panel in its own loop.
        #[cfg(feature = "games")]
        Screen::BlockMine => {}
        #[cfg(feature = "games")]
        Screen::BlockCutter => {}
        #[cfg(all(feature = "games", feature = "board-q1"))]
        Screen::FlappyCat => {}
        // Handled in `run`: it asks twice and drives the panel itself.
        Screen::WipeSeed => {}
        Screen::ViewWords | Screen::LockDown | Screen::TestLogin => {}
        // Handled in `run`: it asks, picks a shape and draws a symbol full-screen.
        #[cfg(feature = "board-q1")]
        Screen::SeedQrShow => {}
        #[cfg(not(feature = "board-mk3"))]
        Screen::ScrambleKeys | Screen::LoginCountdown => {}
        // Handled in `run`: each asks its question through `pick_row` and drives the
        // panel itself.
        #[cfg(not(feature = "board-mk3"))]
        Screen::IdleTimeout
        | Screen::DisplayUnits
        | Screen::MaxFee
        | Screen::UsbPort
        | Screen::VirtualDisk
        | Screen::MenuWrap
        | Screen::TestnetMode => {}
        // Handled in `run`: picks a level through `pick_row` and drives the panel itself.
        #[cfg(feature = "board-q1")]
        Screen::Brightness => {}
        #[cfg(all(not(feature = "dev"), not(feature = "board-mk3")))]
        Screen::KillKey | Screen::Sd2fa => {}
        // Handled in `run`: it confirms, collects the PIN, and drives the panel itself.
        Screen::FactoryReset => {}
    }
}

/// The title and note line for a menu screen -- the single place each is defined, used by
/// both the draw path and the arrow handler so the two never diverge. The note is owned so
/// a screen that wants a dynamic one can build it here.
fn menu_head(screen: Screen) -> (&'static str, Line) {
    let mut note = Line::new();
    let title = match screen {
        Screen::Main => {
            // Another wallet looks exactly like the root otherwise, and the difference
            // is which coins the device can spend. Say so where it is always visible.
            if !crate::key::is_root() {
                let _ = note.push_str(crate::key::label());
            }
            "CatCard"
        }
        Screen::Utils => "Utils",
        Screen::BackupMenu => {
            let _ = note.push_str("the whole wallet, in one file");
            "Backup"
        }
        Screen::NewSeedMenu => {
            let _ = note.push_str("how many words?");
            "New wallet"
        }
        Screen::ImportMenu => {
            let _ = note.push_str("where from?");
            "Import seed"
        }
        Screen::Debug => "Debug",
        Screen::KeyMenu => {
            let _ = note.push_str(if crate::key::is_root() {
                "working in the root wallet"
            } else {
                crate::key::label()
            });
            "Derive"
        }
        Screen::ExportMenu => {
            let _ = note.push_str("the same keys, several shapes");
            "Export wallet"
        }
        Screen::XpubMenu => {
            let _ = note.push_str("one account key, as text");
            "Export XPUB"
        }
        Screen::SignMenu => {
            let _ = note.push_str("what to sign, and from where");
            "Sign"
        }
        Screen::Settings => "Settings",
        Screen::Login => "Login",
        #[cfg(not(feature = "board-mk3"))]
        Screen::Hardware => {
            let _ = note.push_str("only what the firmware obeys");
            "Hardware On/Off"
        }
        Screen::DangerZone => {
            let _ = note.push_str("these show or change secrets");
            "Danger zone"
        }
        Screen::SeedTools => "Seed tools",
        #[cfg(feature = "games")]
        Screen::Games => "Games",
        _ => "",
    };
    (title, note)
}

/// Build the scroll view for a menu: a title, an optional small note, then the items --
/// each carrying its index as its `menu_item` id, wrapped, so a long label stays one
/// selectable row. Positioned on `cursor` at the persisted scroll `off`.
fn build_menu_view<'a>(
    title: &'a str,
    note: &'a str,
    items: &'a [&'a str],
    off: usize,
    cursor: usize,
) -> catcard_ui::scroll::ScrollView<'a> {
    use catcard_ui::scroll::{Line as DLine, ScrollView};

    let mut lines: heapless::Vec<DLine, 40> = heapless::Vec::new();
    let _ = lines.push(DLine::title(title));
    if !note.is_empty() {
        let _ = lines.push(DLine::body(note).small().centered());
    }
    for (i, item) in items.iter().enumerate() {
        let _ = lines.push(DLine::item(item, i as u32).wrapped());
    }
    let mut view = ScrollView::build(&lines, display::SCREEN_W, display::SCREEN_H, display::FONTS);
    // Menu wrapping, from the owner's settings. Set here rather than inside the scroll
    // view's constructor because the preference is a property of this device, and
    // `catcard-ui` is a library that knows nothing about settings.
    view.set_wrap(crate::prefs::current().menu_wrap);
    view.set_off(off);
    view.select(cursor as u32);
    view
}

/// Draw a menu screen: the larger font, the selected row an inverted bar, scrolled to the
/// view's persisted offset.
fn draw_menu(panel: &mut display::Panel, screen: Screen, v: &View<'_>) {
    v.menu.draw(panel, screen, v.blank());
}

/// A titled screen of raw values, left-aligned, leaving on any key.
pub(crate) fn info(panel: &mut display::Panel, title: &str, lines: &[Line]) {
    display::draw(panel, |c| {
        catcard_ui::widgets::info(c, &display::LAYOUT, title, lines);
    });
}

/// `NAME 0000_0000`, grouped like the reference manual prints registers.
fn reg_line(name: &str, v: u32) -> Line {
    let mut s = Line::new();
    let _ = write!(s, "{name} {:04x}_{:04x}", v >> 16, v & 0xFFFF);
    s
}

/// USB: did the peripheral come up, is the host talking, and what does the core think.
fn usb_screen(panel: &mut display::Panel) {
    // The fourth field is an outbox that has not drained -- a reply we owe the host --
    // not a staged image. It used to be labelled "staged" here, which said the device
    // was holding firmware when it was holding a reply. The staged image is a separate
    // question, asked below.
    let (configured, rx, tx, queued) = usbtask::stats();
    let fault = usbtask::init_fault();

    let mut lines: heapless::Vec<Line, MAX_LINES> = heapless::Vec::new();

    let mut l = Line::new();
    let _ = write!(
        l,
        "state {}{}",
        if configured { "configured" } else { "down" },
        if fault.is_empty() { "" } else { " " }
    );
    let _ = l.push_str(fault);
    let _ = lines.push(l);

    let mut l = Line::new();
    let _ = write!(l, "in {rx}  out {tx}{}", if queued { "  txq" } else { "" });
    let _ = lines.push(l);

    // The supply and its clock gate, which is where the first hardware failure lived.
    // SAFETY: reads only.
    unsafe {
        let cr2 = catcard_hal::clock::pwr_cr2();
        let mut l = Line::new();
        let _ = write!(
            l,
            "USV {}  PWREN {}",
            (cr2 >> 10) & 1,
            (catcard_hal::clock::apb1enr1() >> 28) & 1
        );
        let _ = lines.push(l);
    }

    match usbtask::otg_regs() {
        Some(r) => {
            let _ = lines.push(reg_line("GINTSTS", r[0]));
            let _ = lines.push(reg_line("DCTL   ", r[5]));
        }
        None => {
            let mut l = Line::new();
            let _ = write!(l, "core not initialised");
            let _ = lines.push(l);
        }
    }

    // Resets seen / self-heal re-inits / OUT-endpoint arms. `rst` climbing with `state
    // down` means the host keeps resetting and we keep dropping it; `re` climbing means
    // the self-heal is firing.
    //
    // "staged" rides on this line rather than its own: the mono panel fits exactly six
    // rows and this screen already uses all six, so a seventh would be dropped by the
    // ignored `push` and the board with the least room would lose it silently.
    let (resets, reinits, rearms) = usbtask::recovery_counts();
    let mut l = Line::new();
    let _ = write!(
        l,
        "rst {resets} re {reinits} arm {rearms}{}",
        if usbtask::has_pending() {
            "  staged"
        } else {
            ""
        }
    );
    let _ = lines.push(l);

    info(panel, "USB", &lines);
}

/// Clocks: the MSI range every cycle-count delay in this firmware is calibrated against.
fn clock_screen(panel: &mut display::Panel) {
    let mut lines: heapless::Vec<Line, MAX_LINES> = heapless::Vec::new();
    // SAFETY: reads only.
    unsafe {
        let cr = catcard_hal::clock::rcc_cr();
        let khz = catcard_hal::clock::msi_range_khz(cr);

        let mut l = Line::new();
        let _ = write!(l, "MSI {}.{:03} MHz", khz / 1000, khz % 1000);
        let _ = lines.push(l);

        let mut l = Line::new();
        let _ = write!(
            l,
            "HSI48 {}  PLL {}",
            u8::from(catcard_hal::clock::hsi48_ready()),
            (cr >> 25) & 1
        );
        let _ = lines.push(l);

        let _ = lines.push(reg_line("RCC_CR ", cr));
        let _ = lines.push(reg_line("AHB3EN ", catcard_hal::clock::ahb3enr()));
    }
    info(panel, "Clocks", &lines);
}

/// PSRAM: says the thing our own code knows and the hardware cannot be asked.
fn psram_screen(panel: &mut display::Panel) {
    let mut lines: heapless::Vec<Line, MAX_LINES> = heapless::Vec::new();
    match catcard_board::BOARD.psram {
        None => {
            let mut l = Line::new();
            let _ = write!(l, "none on this board");
            let _ = lines.push(l);
        }
        Some(p) => {
            let mut l = Line::new();
            let _ = write!(l, "base {:04x}_0000", p.base >> 16);
            let _ = lines.push(l);

            let mut l = Line::new();
            let _ = write!(l, "we never configure OCTOSPI");
            let _ = lines.push(l);

            // Whether that matters is the open question: the bootloader maps PSRAM to
            // read a staged image, and may leave it mapped.
            let mut l = Line::new();
            let _ = write!(l, "press ok to write+read back");
            let _ = lines.push(l);

            let mut l = Line::new();
            let _ = write!(l, "(hangs if not mapped)");
            let _ = lines.push(l);

            // SAFETY: reads only.
            let _ = lines.push(reg_line("AHB3EN ", unsafe {
                catcard_hal::clock::ahb3enr()
            }));
        }
    }
    info(panel, "PSRAM", &lines);
}

/// Write a word to PSRAM and read it back.
///
/// **The question this answers is whether an upgrade can work at all.** The bootloader
/// installs from PSRAM, so it configures OCTOSPI to read one at boot; if it leaves that
/// mapping in place for the firmware, staging works with no driver of ours. If it does
/// not, every upgrade this device accepts writes into nothing.
///
/// A read of an unmapped region faults rather than returning a value, and the fault
/// needs a power cycle — so **the device hanging on this screen is itself the answer**,
/// and says the mapping is not inherited.
///
/// Writes into the staging area, which holds nothing unless an upgrade is in flight.
fn psram_probe(panel: &mut display::Panel) {
    let Some(p) = catcard_board::BOARD.psram else {
        message(panel, "PSRAM", "none on this board", "");
        return;
    };
    // Every 4 KB across the whole region, each word holding its own offset. One word at one
    // address only proves the region answers; a staged firmware fills megabytes of it, and
    // an image that stages "successfully" and then hashes wrong is what a region that stops
    // holding data part way through looks like from the outside.
    const STEP: u32 = 4 * 1024;
    let stamp = |off: u32| off ^ 0xCA7C_A2D0;

    message(panel, "Probing PSRAM", "hangs if unmapped", "");
    // SAFETY: the region `BoardSpec` describes as memory-mapped PSRAM, aligned, nothing
    // else using it while the menu is up. An unmapped region faults, which is the result
    // being measured -- hence the screen above.
    let (first_bad, alias) = unsafe {
        let base = p.base as *mut u32;
        let mut off = 0u32;
        while off < p.len {
            core::ptr::write_volatile(base.byte_add(off as usize), stamp(off));
            off += STEP;
        }
        // Read every one back only after all of them are written: a write that lands
        // somewhere else shows up here and not in an immediate read-back.
        let mut first_bad = None;
        let mut off = 0u32;
        while off < p.len {
            if core::ptr::read_volatile(base.byte_add(off as usize)) != stamp(off) {
                first_bad = Some(off);
                break;
            }
            off += STEP;
        }
        // Aliasing: if the window is smaller than the region claims, an address high up
        // is the same cell as one low down, and writing one changes the other.
        core::ptr::write_volatile(base, 0x1111_1111);
        let mut alias = None;
        let mut probe = 64 * 1024;
        while probe < p.len {
            core::ptr::write_volatile(base.byte_add(probe as usize), 0x2222_2222);
            if core::ptr::read_volatile(base) != 0x1111_1111 {
                alias = Some(probe);
                break;
            }
            probe *= 2;
        }
        (first_bad, alias)
    };

    let mut lines: heapless::Vec<Line, MAX_LINES> = heapless::Vec::new();
    let mut l = Line::new();
    let _ = write!(l, "region {} KB", p.len / 1024);
    let _ = lines.push(l);
    let mut l = Line::new();
    match first_bad {
        None => {
            let _ = write!(l, "all {} KB hold data", p.len / 1024);
        }
        Some(off) => {
            let _ = write!(l, "first bad at {:#x}", off);
        }
    }
    let _ = lines.push(l);
    let mut l = Line::new();
    match alias {
        None => {
            let _ = write!(l, "no aliasing");
        }
        Some(off) => {
            let _ = write!(l, "aliases base at {:#x}", off);
        }
    }
    let _ = lines.push(l);
    crate::catlog!(
        "psram: len {} first_bad {:?} alias {:?}",
        p.len,
        first_bad,
        alias
    );
    info(panel, "PSRAM probe", &lines);
}

/// SPI-NOR probe: bring up the flash and show its JEDEC id and size.
///
/// This is the first thing to check on an mk3 -- a plausible id (Macronix `C2 20 14`, a
/// 1 MB MX25L8006E) proves the SPI2 pins, the PB9 chip-select and the clock are all right.
/// Boards with no SPI-NOR (mk4/mk5/Q1) say so.
fn sflash_screen(panel: &mut display::Panel) {
    let mut lines: heapless::Vec<Line, MAX_LINES> = heapless::Vec::new();
    if catcard_board::BOARD.sflash.is_none() {
        let mut l = Line::new();
        let _ = write!(l, "none on this board");
        let _ = lines.push(l);
        info(panel, "SPI-NOR", &lines);
        return;
    }

    // SAFETY: this screen is the only SPI-NOR user; SPI2 and its pins belong to the
    // sflash alone, and the menu waits for this to return before it can be chosen again.
    match unsafe { crate::nor::init() } {
        Some(mut nor) => match nor.jedec_id() {
            Ok(id) => {
                let mut l = Line::new();
                let _ = write!(
                    l,
                    "id {:02x} {:02x} {:02x}",
                    id.manufacturer, id.memory_type, id.capacity
                );
                let _ = lines.push(l);
                let mut l = Line::new();
                let _ = write!(l, "size {} KB", nor.size() / 1024);
                let _ = lines.push(l);
            }
            Err(_) => {
                let mut l = Line::new();
                let _ = write!(l, "no response");
                let _ = lines.push(l);
            }
        },
        None => {
            let mut l = Line::new();
            let _ = write!(l, "probe failed");
            let _ = lines.push(l);
        }
    }
    info(panel, "SPI-NOR", &lines);
}

/// What bring-up found, in the same words the selftest screen used.
fn boot_screen(panel: &mut display::Panel, report: &BootReport) {
    let mut lines: heapless::Vec<Line, MAX_LINES> = heapless::Vec::new();

    let mut l = Line::new();
    let _ = write!(l, "HAL {}", if report.hal.is_ok() { "ok" } else { "FAIL" });
    let _ = lines.push(l);

    let mut l = Line::new();
    let _ = write!(l, "DWT {}", if report.dwt_running { "ok" } else { "FAIL" });
    let _ = lines.push(l);

    let mut l = Line::new();
    match report.entropy {
        Ok(bits) => {
            let _ = write!(l, "entropy ok {bits} bit");
        }
        Err(_) => {
            let _ = write!(l, "entropy BELOW POLICY");
        }
    }
    let _ = lines.push(l);

    let mut l = Line::new();
    // What it is running on, and what it was built for, when those differ.
    let running = crate::running_board();
    let _ = if running == crate::BOARD_NAME {
        write!(l, "board {running}")
    } else {
        write!(l, "board {running} (built {})", crate::BOARD_NAME)
    };
    let _ = lines.push(l);
    info(panel, "Boot", &lines);
}

/// Which key the firmware decoded, which is the question a mirrored pad raises.
fn keypad_screen(
    panel: &mut display::Panel,
    last: Option<Key>,
    seen: u32,
    raw_kn: Option<usize>,
    held: u64,
) {
    let mut lines: heapless::Vec<Line, MAX_LINES> = heapless::Vec::new();

    let mut l = Line::new();
    match last {
        Some(Key::Digit(d)) => {
            let _ = write!(l, "last  {d}");
        }
        Some(Key::Confirm) => {
            let _ = write!(l, "last  y");
        }
        Some(Key::Cancel) => {
            let _ = write!(l, "last  x");
        }
        None => {
            let _ = write!(l, "press any key");
        }
        Some(Key::Qr) => {
            let _ = write!(l, "last  QR");
        }
        Some(Key::Char(c)) => {
            let _ = write!(l, "last  {}", c as char);
        }
    }
    let _ = lines.push(l);

    // The raw matrix position, which every physical key produces -- including the ones
    // that decode to nothing (SYM, LAMP, NFC, QR). This is what makes the tester able to
    // tell a key that is wired but unmapped from a key that is not wired at all.
    let mut l = Line::new();
    match raw_kn {
        Some(kn) => {
            let _ = write!(l, "kn {kn}  held {}", held.count_ones());
        }
        None => {
            let _ = write!(l, "kn -");
        }
    }
    let _ = lines.push(l);

    let mut l = Line::new();
    let _ = write!(l, "count {seen}");
    let _ = lines.push(l);

    // The edge path: whether the hard falling-edge interrupt is armed, how many edges it
    // has taken, and whether the storm guard shut it off. On a board where it is not armed
    // at boot this is the screen that arms it -- with a power cycle as the undo.
    let (edges, armed, storm) = crate::keypad::edge_stats();
    let mut l = Line::new();
    let _ = write!(
        l,
        "edges {edges} {}",
        if storm {
            "STORM, off"
        } else if armed {
            "armed"
        } else {
            "off"
        }
    );
    let _ = lines.push(l);

    let mut l = Line::new();
    let _ = l.push_str(if armed {
        "0 masks edges"
    } else {
        "0 arms edges"
    });
    let _ = lines.push(l);

    let mut l = Line::new();
    let _ = write!(l, "x twice  back");
    let _ = lines.push(l);
    info(panel, "Keypad", &lines);
}

/// The UI DRBG's diagnostic counters. This is the generator behind the keypad scan
/// shuffle and every UI random draw; it is topped up (reseeded) on each physical keypress
/// with the edge-timed cycle counter and RTC, so `seeded`/`reseeds` climb as keys are
/// pressed. It is never the wallet-seed generator -- that is `EntropyPool`, which has no
/// draw API at all. Counters only; no generator state is shown.
/// A repaint pacer: says yes once per `period` cycles, and immediately the first time.
///
/// One of these instead of each self-refreshing screen carrying its own copy of the same
/// three lines. The first frame is never delayed, so a screen is painted the moment it
/// opens rather than a frame later.
#[derive(Copy, Clone, Default)]
struct Pace {
    last: u32,
    started: bool,
}

impl Pace {
    fn due(&mut self, period: u32) -> bool {
        let now = catcard_hal::dwt::cycles();
        // `wrapping_sub` because DWT_CYCCNT wraps every 2^32 cycles, far longer than a frame.
        if self.started && now.wrapping_sub(self.last) < period {
            return false;
        }
        self.last = now;
        self.started = true;
        true
    }
}

/// What the RTC debug screen shows: the three registers, resampled on a clock.
///
/// **Nothing here initialises or writes the RTC.** The point of the screen is to show how
/// the *bootloader* left it, so every value is read exactly as found -- `snapshot` is pure
/// reads, and the only RCC write anywhere near the RTC is the APB read gate that bring-up
/// already opened, which lets the CPU see the registers without configuring the peripheral.
#[derive(Copy, Clone, Default)]
struct RtcWatch {
    /// `[SSR, TR, DR]`, in the order the shadow registers require.
    snap: [u32; 3],
    pace: Pace,
}

impl RtcWatch {
    /// Resample if `period` cycles have passed. Returns whether it did.
    fn sample(&mut self, period: u32) -> bool {
        if !self.pace.due(period) {
            return false;
        }
        // SAFETY: three register reads, in the order the shadow registers require (SSR,
        // TR, DR -- reading DR unlocks the shadow). The APB read gate was opened during
        // bring-up; nothing here writes.
        self.snap = unsafe { catcard_hal::rtc::snapshot() };
        true
    }
}

/// The scheduler, live: ticks, switches, recovered time, and each task's stack depth.
///
/// Only meaningful with the menu itself running as a kernel task (Debug -> Kernel UI):
/// starting the kernel any other way replaces the menu, so nothing would be left to draw
/// this. Without the kernel it says so rather than showing a column of zeros.
fn kernel_screen(panel: &mut display::Panel) {
    let mut lines: heapless::Vec<Line, MAX_LINES> = heapless::Vec::new();
    if !catcard_kernel::running() {
        let mut l = Line::new();
        let _ = l.push_str("not running");
        let _ = lines.push(l);
        let mut l = Line::new();
        let _ = l.push_str("start: Kernel UI");
        let _ = lines.push(l);
        info(panel, "Kernel", &lines);
        return;
    }

    let mut l = Line::new();
    let _ = write!(
        l,
        "t {} sw {}",
        catcard_kernel::ticks(),
        catcard_kernel::switches()
    );
    let _ = lines.push(l);

    // `chk` is the per-switch guard check (Debug -> Self-tests); off on every boot.
    let mut l = Line::new();
    let _ = write!(
        l,
        "rec {} fp {} chk {}",
        catcard_kernel::recovered(),
        catcard_kernel::fp_saves(),
        if catcard_kernel::guard_checks() {
            "on"
        } else {
            "off"
        }
    );
    let _ = lines.push(l);

    for i in 0..catcard_kernel::count().min(MAX_LINES - 2) {
        let id = catcard_kernel::TaskId(i);
        let mut l = Line::new();
        let _ = write!(
            l,
            "{} {}/{} {}",
            catcard_kernel::name(id),
            catcard_kernel::high_water(id),
            catcard_kernel::stack_len(id),
            if catcard_kernel::stack_ok(id) {
                "ok"
            } else {
                "OVERFLOW"
            }
        );
        let _ = lines.push(l);
    }

    info(panel, "Kernel", &lines);
}

/// Two BCD digits as a number. The RTC stores its time and date this way.
/// Source: RM0432 §RTC, `RTC_TR`/`RTC_DR` field layout [C]
fn bcd2(v: u32) -> u32 {
    ((v >> 4) & 0xf) * 10 + (v & 0xf)
}

/// The RTC as the bootloader left it: the raw registers, and what they decode to.
///
/// Read-only, and deliberately so -- see [`RtcWatch`]. A device that has never had its
/// clock set still shows something here, because the RTC counts from whenever it started,
/// not from a wall-clock epoch.
fn rtc_screen(panel: &mut display::Panel, w: &RtcWatch) {
    let [ssr, tr, dr] = w.snap;
    let mut lines: heapless::Vec<Line, MAX_LINES> = heapless::Vec::new();

    // The sub-second down-counter, reloaded from the synchronous prescaler each second.
    // The one that moves fastest, so it is the one that shows the RTC is running at all.
    let mut l = Line::new();
    let _ = write!(l, "SSR  {ssr:#010x}  {ssr}");
    let _ = lines.push(l);

    // Source: RM0432 §RTC -- TR is seconds[6:0], minutes[14:8], hours[21:16], all BCD.
    let mut l = Line::new();
    let _ = write!(
        l,
        "TR   {tr:#010x}  {:02}:{:02}:{:02}",
        bcd2((tr >> 16) & 0x3f),
        bcd2((tr >> 8) & 0x7f),
        bcd2(tr & 0x7f)
    );
    let _ = lines.push(l);

    // Source: RM0432 §RTC -- DR is day[5:0], month[12:8], year[23:16], all BCD.
    let mut l = Line::new();
    let _ = write!(
        l,
        "DR   {dr:#010x}  {:02}-{:02}-{:02}",
        bcd2((dr >> 16) & 0xff),
        bcd2((dr >> 8) & 0x1f),
        bcd2(dr & 0x3f)
    );
    let _ = lines.push(l);

    info(panel, "RTC", &lines);
}

fn prng_screen(panel: &mut display::Panel, s: catcard_entropy::DrbgStats, sample: Option<u32>) {
    let mut lines: heapless::Vec<Line, MAX_LINES> = heapless::Vec::new();

    let mut l = Line::new();
    let _ = write!(l, "UI HMAC-SHA256");
    let _ = lines.push(l);

    // A fresh 32-bit draw, redrawn on every key. Shown at the top so it is the first thing
    // that changes when you press a key -- alongside the reseed count climbing.
    let mut l = Line::new();
    match sample {
        Some(x) => {
            let _ = write!(l, "out  {x:08x}");
        }
        None => {
            let _ = write!(l, "out  --------");
        }
    }
    let _ = lines.push(l);

    // Total seedings counts the boot instantiation plus every reseed.
    let mut l = Line::new();
    let _ = write!(l, "seeded  {}", s.seedings);
    let _ = lines.push(l);

    let mut l = Line::new();
    let _ = write!(l, "reseeds {}", s.reseeds);
    let _ = lines.push(l);

    let mut l = Line::new();
    let _ = write!(l, "gen     {}", s.generates);
    let _ = lines.push(l);

    let mut l = Line::new();
    let _ = write!(l, "since rs {}", s.since_reseed);
    let _ = lines.push(l);

    info(panel, "PRNG status", &lines);
}

/// Colours: a chart of what the panel can show -- bars, the full ramp of each channel,
/// and a hue sweep. It fills the whole LCD, not the UI's window; any key leaves, and the
/// menu wipes the panel on the way out.
#[cfg(feature = "board-q1")]
fn colours_screen(panel: &mut display::Panel) {
    if panel.draw_colour_chart().is_err() {
        crate::catlog!("colours: chart write failed");
    }
}

/// Colours, on a panel that has two of them.
#[cfg(not(feature = "board-q1"))]
fn colours_screen(panel: &mut display::Panel) {
    let mut lines: heapless::Vec<Line, MAX_LINES> = heapless::Vec::new();
    for text in [
        "mono OLED: black and white",
        "only -- nothing to chart",
        "any key  back",
    ] {
        let mut l = Line::new();
        let _ = l.push_str(text);
        let _ = lines.push(l);
    }
    info(panel, "Colours", &lines);
}

/// Read a firmware off the card, ask, and install it.
///
/// Blocking on purpose. It draws what it is doing at each step because the steps are
/// slow — bringing a card up, then moving a quarter of a megabyte through a 512-byte
/// buffer — and a screen that does not change is how a working device looks broken.
///
/// The approval is the same question the USB path asks, in the same words, and the
/// install is the same two calls: `commit` publishes the recovery header, then the
/// bootloader does the rest on the next boot.
fn install_from_card(gate: &Callgate, login: &mut catcard_pin::Login, ui: &mut Ui<'_>) {
    use crate::sdupgrade::{Outcome, stage_from_card};

    // Pick the firmware from the card by browsing for a .dfu, rather than guessing at a
    // fixed name. Cancelling the browser cancels the install.
    let chosen = browse_sd(ui, "Pick a .dfu", Some("dfu"), Browse::File);
    let Some(chosen) = chosen else {
        return;
    };

    crate::catlog!("sd: staging the chosen firmware");
    // A bar rather than "please wait": the length is known before the first byte is read,
    // and a megabyte through a 512-byte buffer takes long enough that a still screen reads
    // as a hung device. It also says *where* a real hang happened, which is worth having.
    // Two passes over the image -- reading it in, then digesting it to verify -- so the
    // caption says which one is running rather than the bar appearing to restart.
    let mut shown = u8::MAX;
    let mut pass = 0u8;
    let mut tick = |done: u32, total: u32| {
        if done == 0 {
            pass += 1;
            shown = u8::MAX;
        }
        let pct = if total == 0 {
            100
        } else {
            ((done as u64 * 100) / total as u64) as u8
        };
        if pct == shown {
            return;
        }
        shown = pct;
        let mut note = Line::new();
        let _ = write!(note, "{} of {} KB", done / 1024, total / 1024);
        let mut wait = Line::new();
        let _ = write!(
            wait,
            "{}",
            if pass > 1 {
                "checking signature"
            } else {
                "reading"
            }
        );
        display::draw(ui.panel, |c| {
            let lines = [wait.clone(), note.clone()];
            catcard_ui::widgets::info(c, &display::LAYOUT, "Reading card", &lines);
            catcard_ui::splash::draw_progress(c, pct);
        });
    };
    let (staged, approval) =
        match stage_from_card(catcard_hal::sdmmc::Slot::A, Some(&chosen), &mut tick) {
            Outcome::Offered(s, a) => (s, a),
            Outcome::Failed(why) => {
                crate::catlog!("sd: {}", why);
                message(ui.panel, "No upgrade", why, "any key to go back");
                wait_for_any_key(ui);
                return;
            }
        };

    offer_and_install(gate, login, ui, staged, approval);
}

/// Inspect an image already sitting in `area`, ask, and install it.
///
/// For a transport that placed its parts itself: the QR scanner writes each one to its
/// own offset as it is caught, so by the time this runs the bytes are there and only
/// the checking is left.
///
/// **Raw image only.** A DfuSe container puts the image a couple of hundred bytes into
/// the file, and shifting it down in the staging area afterwards would mean reading that
/// memory back while still writing it -- the one thing that reliably corrupts it. A
/// container is refused with the reason rather than staged wrong.
///
/// Q1 only, because the scanner is: it is the only transport that places its own parts.
#[cfg(feature = "board-q1")]
pub(crate) fn install_staged_image(
    gate: &Callgate,
    login: &mut catcard_pin::Login,
    ui: &mut Ui<'_>,
    area: crate::staging::Area,
    len: u32,
) {
    use catcard_upgrade::Staged;

    const HEAD: &str = "Install";

    let mut staged = match Staged::begin(area, &catcard_board::BOARD, len) {
        Ok(s) => s,
        Err(why) => {
            crate::catlog!("install: image size refused: {:?}", why);
            message(
                ui.panel,
                HEAD,
                crate::sdupgrade::describe(why),
                "any key to go back",
            );
            wait_for_any_key(ui);
            return;
        }
    };
    // The transport counted the parts, so it is the thing that knows this is whole --
    // the highest offset written says nothing about holes before it.
    staged.placed_all();

    // A container would have been staged at the wrong offset. Caught here, where the
    // answer is a sentence, rather than by the bootloader, where it is `-112`.
    let mut head = [0u8; 8];
    if staged.sample(0, &mut head).is_ok() && head.starts_with(b"DfuSe") {
        message(
            ui.panel,
            HEAD,
            "send the .bin, not the .dfu",
            "any key to go back",
        );
        wait_for_any_key(ui);
        return;
    }

    // One pass over the staging area to digest it, then the signature. Scattered parts
    // could not be hashed as they arrived, so this is the only place the image is read
    // as a whole -- and it is affordable exactly because the transport took minutes.
    let mut shown = u8::MAX;
    let mut tick = |done: u32, total: u32| {
        let pct = if total == 0 {
            100
        } else {
            ((done as u64 * 100) / total as u64) as u8
        };
        if pct == shown {
            return;
        }
        shown = pct;
        let mut note = Line::new();
        let _ = write!(note, "{} of {} KB", done / 1024, total / 1024);
        display::draw(ui.panel, |c| {
            let mut wait = Line::new();
            let _ = write!(wait, "checking signature");
            let lines = [wait, note.clone()];
            catcard_ui::widgets::info(c, &display::LAYOUT, HEAD, &lines);
            catcard_ui::splash::draw_progress(c, pct);
        });
    };
    let approval = match staged.inspect_with(crate::own_header().as_ref(), &mut tick) {
        Ok(a) => a,
        Err(why) => {
            crate::catlog!("install: image refused: {:?}", why);
            message(
                ui.panel,
                "No upgrade",
                crate::sdupgrade::describe(why),
                "any key to go back",
            );
            wait_for_any_key(ui);
            return;
        }
    };

    offer_and_install(gate, login, ui, staged, approval);
}

/// Show what was staged, and install it if the owner says so.
///
/// Shared by every way an image arrives, because the question and the two calls that
/// follow it must not differ by route: an image that came in over QR is authorised by
/// the same `commit` and the same `gate 18/7` as one that came off a card, and a person
/// is asked the same thing in the same words.
fn offer_and_install<A>(
    gate: &Callgate,
    login: &mut catcard_pin::Login,
    ui: &mut Ui<'_>,
    staged: catcard_upgrade::Staged<'_, A>,
    approval: catcard_upgrade::Approval,
) where
    A: catcard_upgrade::StagingArea,
    A::Error: Into<catcard_upgrade::StorageError>,
{
    crate::session::show_offer(ui.panel, &approval);

    let mut events = [Event::Pressed(Key::Cancel); KEYS];
    let mut keys: heapless::Vec<Key, { KEYS + 1 }> = heapless::Vec::new();
    loop {
        crate::pinentry::pressed_keys(ui.pad, ui.matrix, ui.drbg, &mut events, &mut keys);
        for k in keys.iter() {
            match k {
                Key::Confirm => {
                    // The same second question the USB path asks, for the same image
                    // property; see there. Here the approval is ours by value, so there
                    // is nothing to re-check after the answer.
                    if crate::session::sets_high_water(&approval) {
                        ask(
                            ui.panel,
                            "Really install?",
                            "sets anti-downgrade",
                            "mark: no way back",
                        );
                        if !confirmed(ui) {
                            return;
                        }
                    }
                    // `commit` publishes the recovery header and can refuse for a reason
                    // worth naming -- this device losing the bytes rather than a bad
                    // image being the one that matters.
                    match staged.commit(approval) {
                        Ok(region) => {
                            message(ui.panel, "Installing", "do not disconnect", "");
                            crate::staging::install(gate, login, ui.panel, region);
                        }
                        Err(why) => {
                            crate::catlog!("install: commit refused: {:?}", why);
                            message(
                                ui.panel,
                                "Not installed",
                                crate::sdupgrade::describe(why),
                                "any key to go back",
                            );
                        }
                    }
                    wait_for_any_key(ui);
                    return;
                }
                Key::Cancel => return,
                Key::Digit(_) => {}
                Key::Char(_) | Key::Qr => {}
            }
        }
        display::idle(ui.panel);
    }
}

/// Write the current log to the card as `/CATCARD.LOG`.
///
/// The other half of the log story: `Debug -> Logs` shows it on the glass and USB pages
/// it out, and this drops it somewhere it can be read on another machine -- which is the
/// channel that survives a device that will not enumerate and a panel that will not draw.
///
/// Blocking, and it says which step it stopped at rather than "failed", so a bad card, a
/// full card and a filesystem it cannot mount tell themselves apart. Nothing here is
/// irreversible -- at worst it leaves a short file behind.
fn save_log_to_card(ui: &mut Ui<'_>) {
    crate::catlog!("sd: saving log");
    card_wait(ui.panel, "Saving log", "writing to the card");

    // Snapshot the log before touching anything else, so what lands on the card is the
    // state at the moment it was asked for, not a log with this function's own steps in
    // it.
    let mut buf = [0u8; crate::logbuf::LOG_LEN];
    let n = crate::logbuf::read(0, &mut buf);

    match write_card_file("/CATCARD.LOG", &buf[..n]) {
        Ok(()) => {
            crate::catlog!("sd: wrote {} bytes to /CATCARD.LOG", n);
            message(ui.panel, "Log saved", "/CATCARD.LOG", "any key to go back");
        }
        Err(why) => {
            crate::catlog!("sd: log save failed: {}", why);
            message(ui.panel, "Save failed", why, "any key to go back");
        }
    }
    wait_for_any_key(ui);
}

/// Bring the card up, mount it, and write `bytes` to `path`, replacing whatever it held.
///
/// Split from the screen so each step is one `?`, and the reason it stopped rides out on
/// the `Err` for the caller to show and log -- the step is what tells a bad card apart
/// from a full one or a filesystem it cannot mount.
pub(crate) fn write_card_file(path: &str, bytes: &[u8]) -> Result<(), &'static str> {
    let mut vol = mount_card()?;
    write_into(&mut vol, path, bytes)?;
    vol.flush().map_err(|_| "flush failed")
}

/// The card, mounted, as every writer here wants it.
///
/// Split out because an export writes two files -- the export and its detached signature
/// -- and has to look at what is already there before it picks a name. Mounting once and
/// doing all three against the same volume is both faster and the only way the numbering
/// can be right: a name checked under one mount and written under another is a name that
/// could have been taken in between.
pub(crate) fn mount_card() -> Result<CardVolume, &'static str> {
    // Mount FAT or exFAT; `why` carries the specific bring-up failure out of the closure.
    let mut why: &'static str = "card error";
    let vol: catcard_sd::AnyVolume<_, 512> = catcard_sd::AnyVolume::mount_with(|| {
        // SAFETY: nothing else has claimed SDMMC1 or its pins, and the menu waits for this
        // to return before it can be chosen again.
        let mut dev = match unsafe { catcard_hal::sdmmc::Sdmmc::init(&catcard_board::BOARD) } {
            Ok(d) => d,
            Err(_) => {
                why = "controller failed";
                return Err(());
            }
        };
        #[allow(unused_mut)]
        let mut card = match catcard_sd::init(&mut dev) {
            Ok(c) => c,
            Err(catcard_sd::Error::NoCard) => {
                why = "no card in slot";
                return Err(());
            }
            Err(e) => {
                crate::catlog!("sd: card would not start: {:?}", e);
                why = "card would not start";
                return Err(());
            }
        };
        // Transparent decryption: if this card was unlocked this session, every read and
        // write through the mounted volume now decrypts/encrypts. A plaintext card is
        // untouched. mk3 has no such feature.
        #[cfg(not(feature = "board-mk3"))]
        crate::sdcrypt::apply_to(&mut card);
        Ok(catcard_sd::Sectors::new(dev, card))
    })
    .map_err(|e| match e {
        catcard_sd::MountError::Device => why,
        catcard_sd::MountError::NoFilesystem => "not FAT or exFAT",
    })?;
    Ok(vol)
}

/// The mounted card, spelled out once so it can be passed around.
pub(crate) type CardVolume =
    catcard_sd::AnyVolume<catcard_sd::Sectors<catcard_hal::sdmmc::Sdmmc>, 512>;

/// Write `bytes` to `path` on an already-mounted volume, replacing what was there.
///
/// Generic over the backing [`SectorDriver`](catcard_sd::fat::SectorDriver) so the same
/// writer serves the card and the PSRAM-backed Virtual Disk: the sign flow reuses it to
/// drop a signed PSBT on whichever the owner chose.
pub(crate) fn write_into<D: catcard_sd::fat::SectorDriver>(
    vol: &mut catcard_sd::AnyVolume<D, 512>,
    path: &str,
    bytes: &[u8],
) -> Result<(), &'static str> {
    let mut file = vol
        .open_or_create_file(path)
        .map_err(|_| "could not open file")?;
    file.write_all(vol, bytes).map_err(|_| "write failed")?;
    // Trim any tail from a longer earlier file, so it holds exactly these bytes.
    file.set_len(vol, bytes.len() as u64)
        .map_err(|_| "truncate failed")?;
    file.flush(vol).map_err(|_| "flush failed")
}

/// How much of a streamed file is held in memory at once. One chunk is a few rows of a
/// CSV, which is all the stack this costs however long the file becomes.
pub(crate) const CARD_CHUNK: usize = 512;
/// The buffer [`write_card_chunks`] hands its producer.
pub(crate) type CardChunk = heapless::String<CARD_CHUNK>;

/// Write a file the caller produces a piece at a time, and answer with its length.
///
/// The other shape of [`write_card_file`], for output whose size is decided by how much
/// of it the owner asked for rather than by a buffer: an address export of 250 rows is
/// twenty kilobytes, and a stack frame that large on a board with 192 KB of SRAM is how
/// the menu's own stack gets eaten. `next` fills the buffer it is handed and returns
/// false when there is nothing left; each fill is written as it arrives, so what is held
/// at once is one [`CARD_CHUNK`].
///
/// The producer runs with the card mounted, so it must not show a screen, wait for a key
/// or reach the seed -- everything it needs has to be in hand before the call.
pub(crate) fn write_card_chunks(
    path: &str,
    next: &mut dyn FnMut(&mut CardChunk) -> bool,
) -> Result<u64, &'static str> {
    let mut vol = mount_card()?;
    let mut file = vol
        .open_or_create_file(path)
        .map_err(|_| "could not open file")?;
    let mut chunk = CardChunk::new();
    let mut written: u64 = 0;
    loop {
        chunk.clear();
        if !next(&mut chunk) {
            break;
        }
        if chunk.is_empty() {
            continue;
        }
        file.write_all(&mut vol, chunk.as_bytes())
            .map_err(|_| "write failed")?;
        written += chunk.len() as u64;
    }
    // Trim any tail from a longer earlier file, so it holds exactly what was produced.
    file.set_len(&mut vol, written)
        .map_err(|_| "truncate failed")?;
    file.flush(&mut vol).map_err(|_| "flush failed")?;
    vol.flush().map_err(|_| "flush failed")?;
    Ok(written)
}

/// Longest file name a browser row keeps; longer names are truncated for display (the
/// marquee still scrolls what is kept).
const BROWSE_NAME_MAX: usize = 64;
/// Most entries one directory shows; beyond this the listing stops (rare on a wallet card).
const BROWSE_ENTRIES: usize = 48;
/// Longest path the browser tracks as it descends.
pub(crate) const BROWSE_PATH_MAX: usize = 160;
/// The id the "Parent" row carries; real entries carry their (small) index.
const BROWSE_PARENT: u32 = u32::MAX;

/// Push onto a reserved `Vec`, dropping the item if that would grow past the
/// reservation.
///
/// `heapless::Vec::push` returns a `Result` and this screen threw it away: a folder with
/// more entries than it tracks showed the first of them. An allocating `Vec` **aborts**
/// instead, which on this device means the panic handler -- so the same bound is kept
/// explicitly. Nothing here ever reallocates either, which is what makes the reservation
/// the whole of what this screen asks the heap for.
fn push_within<T>(v: &mut alloc::vec::Vec<T>, item: T) {
    if v.len() < v.capacity() {
        v.push(item);
    }
}

/// One directory entry as the browser holds it, copied out of the lending `DirEntry`.
struct BrowseEntry {
    name: heapless::String<BROWSE_NAME_MAX>,
    is_dir: bool,
    len: u64,
}

/// Whether `name`'s extension equals `ext`, case-insensitively.
fn ext_matches(name: &str, ext: &str) -> bool {
    match name.rsplit_once('.') {
        Some((_, e)) => e.eq_ignore_ascii_case(ext),
        None => false,
    }
}

/// Drop the last `/segment` of a path, leaving the parent (or root, the empty string).
fn pop_segment(path: &mut heapless::String<BROWSE_PATH_MAX>) {
    match path.rfind('/') {
        Some(i) => path.truncate(i),
        None => path.clear(),
    }
}

/// What the file-detail screen was asked for.
enum FileChoice {
    /// Back to the listing, with the card untouched.
    None,
    /// Use this file: only offered while the browser is picking one.
    Pick,
    /// Delete it: only offered while the browser is a viewer, and asked again before
    /// anything is written.
    Delete,
    /// Show it: a picture, on the one board with a screen that can.
    #[cfg(feature = "board-q1")]
    View,
}

/// What the browser is for.
#[derive(Copy, Clone, PartialEq, Eq)]
pub(crate) enum Browse {
    /// Look around. A file shows its details, and can be deleted from there.
    View,
    /// Choose a file, whose full path comes back.
    File,
    /// Choose a folder to put something in; the path that comes back is a directory.
    Folder,
}

/// The id the "use this folder" row carries, out of the way of any entry's index.
const BROWSE_USE_FOLDER: u32 = BROWSE_PARENT - 1;

/// The ids the detail screen's rows carry. Named rather than counted, because which
/// rows are there depends on the file and on the board.
const FILE_DELETE_ROW: u32 = 0;
#[cfg(feature = "board-q1")]
const FILE_VIEW_ROW: u32 = 1;

/// Show a file's details, and offer what can be done with it from here.
///
/// Picking and deleting are deliberately not both on offer. A browser opened to choose a
/// `.psbt` is part-way through signing something, and a delete row under the cursor there
/// is one keypress from removing the file the host just wrote; the viewer -- `Utils` ->
/// `Browse SD card` -- is where a file gets deleted.
///
/// Stock reaches a file listing through `File Management` -> `List Files`.
/// Source: hw-reference/menu-map-mk4-mk5-q1-v5.6.2.md §D2 [C]. That the listing is also
/// where a file is deleted is [I]: the map names the drawer, not its per-file actions.
fn file_info(
    ui: &mut Ui<'_>,
    name: &str,
    len: u64,
    pick: bool,
    // Only the SD card can be viewed: the PNG viewer mounts the card itself, so it is not
    // offered while browsing the Virtual Disk. Unused where there is no viewer at all.
    #[cfg_attr(not(feature = "board-q1"), allow(unused_variables))] allow_view: bool,
) -> FileChoice {
    use catcard_ui::scroll::Line as DLine;
    let mut sz = Line::new();
    let _ = write!(sz, "{len} bytes");
    let mut lines: heapless::Vec<DLine, 6> = heapless::Vec::new();
    let _ = lines.push(DLine::title("File"));
    let _ = lines.push(DLine::body(name).wrapped());
    let _ = lines.push(DLine::body(&sz).small());
    if pick {
        let _ = lines.push(DLine::body("y = select this").centered());
    } else {
        // Showing it comes before removing it: it is the harmless one, and it is what
        // somebody who opened a picture was probably after.
        #[cfg(feature = "board-q1")]
        if allow_view && crate::pngview::is_png(name) {
            let _ = lines.push(DLine::item("View", FILE_VIEW_ROW));
        }
        let _ = lines.push(DLine::item("Delete file", FILE_DELETE_ROW));
    }
    match show_doc(ui, &lines, false, false) {
        // With a selectable row present the screen is a menu, so Confirm arrives as
        // `Selected` and never as `Confirmed`; the two arms cannot both fire.
        DocExit::Confirmed if pick => FileChoice::Pick,
        DocExit::Selected(FILE_DELETE_ROW) => FileChoice::Delete,
        #[cfg(feature = "board-q1")]
        DocExit::Selected(FILE_VIEW_ROW) => FileChoice::View,
        _ => FileChoice::None,
    }
}

/// Delete one file off the card, behind a confirmation.
///
/// **Irreversible, and labelled as such.** A card has no trash: the directory entry goes
/// and the clusters go back to the free list, so the question names the file and says the
/// delete cannot be undone. The volume is flushed before anyone is told it worked -- a
/// delete that lives only in the driver's cache is a file that comes back on the next
/// mount, which is the one claim this screen must never make wrongly.
fn delete_browse_file<D: catcard_sd::fat::SectorDriver>(
    ui: &mut Ui<'_>,
    vol: &mut catcard_sd::AnyVolume<D, 512>,
    path: &str,
    name: &str,
    refused: &str,
) {
    ask(ui.panel, "Delete file?", name, "cannot be undone");
    if !confirmed(ui) {
        return;
    }
    match vol.remove_file(path).and_then(|()| vol.flush()) {
        Ok(()) => {
            crate::catlog!("browse: deleted {}", path);
            message(ui.panel, "Deleted", name, "any key to go back");
        }
        Err(()) => {
            crate::catlog!("browse: could not delete {}", path);
            message(ui.panel, "Not deleted", refused, "any key to go back");
        }
    }
    wait_for_any_key(ui);
}

/// A generic microSD file browser.
///
/// Lists a directory as icon + name rows (folders, files, and a "Parent" row when not at
/// the root), each selectable; a name too wide for the panel marquees while selected.
/// Descending into a folder re-lists it; Cancel or "Parent" goes up, and Cancel at the
/// root leaves. Selecting a file shows its details. When `pick` is set, that detail screen
/// offers to choose the file and the chosen full path is returned; otherwise the browser
/// is a viewer and returns `None`. `filter`, when set, hides files without that extension
/// (folders always show), which is how the caller narrows to `.dfu`, `.psbt`, and so on.
///
/// [`Browse::Folder`] picks a place rather than a thing: every listing gains a row that
/// takes the folder it is showing, and the root counts as one.
///
/// A mount or read failure is reported with the step it stopped at, so a missing card, a
/// filesystem it cannot mount (exFAT, today) and a read error tell themselves apart.
/// A browser message with `head`'s medium named, then a wait for a key.
fn browse_fail(ui: &mut Ui<'_>, head: &str, why: &str) {
    message(ui.panel, head, why, "any key to go back");
    wait_for_any_key(ui);
}

/// The standalone file browser under `Utils`. On a board with PSRAM it first asks which
/// storage to look at; a board without one (mk3) goes straight to the card.
fn browse_files(ui: &mut Ui<'_>) {
    #[cfg(not(feature = "board-mk3"))]
    if catcard_board::BOARD.psram.is_some() {
        let Some(pick) = choose(
            ui,
            "Browse Files",
            "look at which storage?",
            &["SD card", "Virtual Disk (in PSRAM)"],
        ) else {
            return;
        };
        if pick == 0 {
            browse_sd(ui, "SD card", None, Browse::View);
        } else {
            browse_vdisk(ui, "Virtual Disk", None, Browse::View);
        }
        return;
    }
    browse_sd(ui, "SD card", None, Browse::View);
}

/// Browse the microSD card. Mounts it (FAT or exFAT), then walks it with [`browse_volume`].
pub(crate) fn browse_sd(
    ui: &mut Ui<'_>,
    title: &str,
    filter: Option<&str>,
    mode: Browse,
) -> Option<heapless::String<BROWSE_PATH_MAX>> {
    let vol = match mount_card() {
        Ok(v) => v,
        Err(why) => {
            browse_fail(ui, "SD card", why);
            return None;
        }
    };
    // The PNG viewer is a card-only affair (it re-mounts the card itself), so it is on
    // offer here and nowhere else.
    let allow_view = cfg!(feature = "board-q1");
    browse_volume(
        ui,
        vol,
        title,
        filter,
        mode,
        "SD card",
        allow_view,
        "the card refused",
        &mut || mount_card(),
    )
}

/// Browse the PSRAM-backed Virtual Disk. Formats an uninitialised region first (there is
/// nothing on it to lose), mounts it, then walks it with [`browse_volume`].
#[cfg(not(feature = "board-mk3"))]
pub(crate) fn browse_vdisk(
    ui: &mut Ui<'_>,
    title: &str,
    filter: Option<&str>,
    mode: Browse,
) -> Option<heapless::String<BROWSE_PATH_MAX>> {
    if let Err(why) = crate::vdisk::ensure_formatted() {
        browse_fail(ui, "Virtual Disk", why);
        return None;
    }
    let vol = match crate::vdisk::mount() {
        Ok(v) => v,
        Err(why) => {
            browse_fail(ui, "Virtual Disk", why);
            return None;
        }
    };
    // No viewer on the disk: the PNG viewer mounts the card, not this.
    browse_volume(
        ui,
        vol,
        title,
        filter,
        mode,
        "Virtual Disk",
        false,
        "the disk refused",
        &mut || crate::vdisk::mount(),
    )
}

/// The browser loop over an already-mounted volume, whatever backs it.
///
/// The shared body of [`browse_sd`] and [`browse_vdisk`]: it lists a directory, lets the
/// cursor descend and go back, and on a file offers its details (pick, delete, and — for
/// the card only — view). `head` names the medium in messages, `refused` is what a failed
/// delete says, `allow_view` gates the viewer, and `remount` produces a fresh mount for
/// the viewer to hand the bus back to.
#[allow(clippy::too_many_arguments)]
fn browse_volume<D: catcard_sd::fat::SectorDriver>(
    ui: &mut Ui<'_>,
    mut vol: catcard_sd::AnyVolume<D, 512>,
    title: &str,
    filter: Option<&str>,
    mode: Browse,
    head: &'static str,
    allow_view: bool,
    refused: &'static str,
    #[cfg_attr(not(feature = "board-q1"), allow(unused_variables))]
    remount: &mut dyn FnMut() -> Result<catcard_sd::AnyVolume<D, 512>, &'static str>,
) -> Option<heapless::String<BROWSE_PATH_MAX>> {
    let pick = matches!(mode, Browse::File);

    let mut path: heapless::String<BROWSE_PATH_MAX> = heapless::String::new();
    // **On the heap, not on the stack.** Forty-eight entries of a 64-byte name is four
    // kilobytes, and the row list built from them below is three more -- on a screen
    // reached from a menu that is itself several frames deep. That was survivable while
    // the menu ran as a kernel task, which has a 32 KiB stack with a guard on it; it is
    // not survivable on the polled path taken when cancel is held at boot, where the
    // menu runs on the main stack -- what SRAM1 has left over after `.bss`, with no
    // guard and nothing watching. It overflowed there into the keypad's own state, and
    // announced itself by lighting SYM and CAPS on a Q1 nobody was typing on.
    //
    // `try_reserve_exact` rather than `Vec::with_capacity`: the allocating collections
    // abort when they cannot grow, and on this device aborting means the panic handler
    // wipes the screen and stops. A browser that cannot get its memory says so instead.
    let mut entries: alloc::vec::Vec<BrowseEntry> = alloc::vec::Vec::new();
    if entries.try_reserve_exact(BROWSE_ENTRIES).is_err() {
        browse_fail(ui, head, "not enough memory to list a folder");
        return None;
    }

    loop {
        // List the current directory, copying each entry the callback is handed (its name
        // is borrowed from the lending iterator, so it must be copied out here).
        entries.clear();
        let listing_ok = vol
            .enumerate(&path, |name, is_dir, len| {
                if let Some(ext) = filter
                    && !is_dir
                    && !ext_matches(name, ext)
                {
                    return;
                }
                // Bounded by the reservation above, so pushing never reallocates and
                // never aborts: a folder with more than this many entries shows the
                // first `BROWSE_ENTRIES` of them, as it did before.
                if entries.len() == BROWSE_ENTRIES {
                    return;
                }
                let mut nm = heapless::String::new();
                for c in name.chars() {
                    if nm.push(c).is_err() {
                        break;
                    }
                }
                push_within(
                    &mut entries,
                    BrowseEntry {
                        name: nm,
                        is_dir,
                        len,
                    },
                );
            })
            .is_ok();

        // Build the listing as a menu document and run it. Scoped so `lines` -- which
        // borrows `path` (the title) and `entries` (the names) -- is dropped before the
        // navigation below mutates `path`.
        let exit = {
            use catcard_ui::scroll::Line as DLine;
            let header: &str = if path.is_empty() { title } else { &path };
            // As `entries`: on the heap, and fallibly. Rebuilt each pass round the
            // loop, so the block is taken and given back with the listing rather than
            // held for as long as the browser is open.
            let mut lines: alloc::vec::Vec<DLine> = alloc::vec::Vec::new();
            if lines.try_reserve_exact(BROWSE_ENTRIES + 3).is_err() {
                browse_fail(ui, head, "not enough memory to draw a folder");
                return None;
            }
            push_within(&mut lines, DLine::title(header));
            if !path.is_empty() {
                push_within(
                    &mut lines,
                    DLine::item("Parent", BROWSE_PARENT).with_icon(&catcard_ui::icons::BACK),
                );
            }
            // First, so a folder chosen at a glance is one press: the row is about the
            // listing on screen, not about anything in it.
            if mode == Browse::Folder {
                push_within(
                    &mut lines,
                    DLine::item("Save here", BROWSE_USE_FOLDER)
                        .with_icon(&catcard_ui::icons::FOLDER),
                );
            }
            if !listing_ok {
                push_within(&mut lines, DLine::body("(could not read)").centered());
            } else if entries.is_empty() {
                push_within(&mut lines, DLine::body("(empty)").centered());
            }
            for (i, e) in entries.iter().enumerate() {
                // What the name says it is, as a picture: in colour where the panel can
                // show one, as a 12x12 silhouette where it cannot. A row is easier to
                // find by shape than by reading the end of its name.
                use catcard_ui::art::fileicons::{Kind, mark};
                push_within(
                    &mut lines,
                    DLine::item(&e.name, i as u32).with_mark(mark(Kind::of(&e.name, e.is_dir))),
                );
            }
            show_doc(ui, &lines, false, false)
        };

        match exit {
            // Back out one level, or leave the browser at the root.
            DocExit::Cancelled | DocExit::Confirmed => {
                if path.is_empty() {
                    return None;
                }
                pop_segment(&mut path);
            }
            DocExit::Selected(BROWSE_USE_FOLDER) => {
                // The root is a folder like any other, and it is spelled "/".
                let mut here: heapless::String<BROWSE_PATH_MAX> = heapless::String::new();
                let _ = here.push_str(if path.is_empty() { "/" } else { &path });
                return Some(here);
            }
            DocExit::Selected(BROWSE_PARENT) => pop_segment(&mut path),
            DocExit::Selected(idx) => {
                let e = &entries[idx as usize];
                if e.is_dir {
                    let _ = path.push('/');
                    let _ = path.push_str(&e.name);
                } else {
                    let mut full: heapless::String<BROWSE_PATH_MAX> = heapless::String::new();
                    let _ = full.push_str(&path);
                    let _ = full.push('/');
                    let _ = full.push_str(&e.name);
                    match file_info(ui, &e.name, e.len, pick, allow_view) {
                        FileChoice::Pick => return Some(full),
                        // The listing is rebuilt at the top of this loop, so what is on
                        // the glass after a delete is what is on the medium -- including
                        // the case where the delete was refused and nothing moved.
                        FileChoice::Delete => {
                            delete_browse_file(ui, &mut vol, &full, &e.name, refused)
                        }
                        // The viewer mounts the card itself, so this volume is dropped
                        // for the duration rather than lent: two mounts of one card at
                        // once is not something the driver promises. `remount` brings the
                        // same medium back afterwards.
                        #[cfg(feature = "board-q1")]
                        FileChoice::View => {
                            let path = full.clone();
                            drop(vol);
                            crate::pngview::view(ui, &path);
                            vol = match remount() {
                                Ok(v) => v,
                                Err(why) => {
                                    browse_fail(ui, head, why);
                                    return None;
                                }
                            };
                        }
                        FileChoice::None => {}
                    }
                }
            }
        }
    }
}

// --- Analyze RNG ------------------------------------------------------------------
//
// A live look at the secure-element TRNGs -- the RNGs this whole project exists to
// distrust. SE1 and SE2 are sampled separately through callgate 26 and each gets its
// own half of the screen: a header with its Shannon entropy (bits per byte -- 8.00 is
// ideal, a number well below it is the failure this screen is for) and running byte
// count, over a framed field that renders that element's own recent bytes as raw bits.
// It should look like static; a source that is stuck or biased stops looking random,
// and keeping the two streams apart is the point -- a fault in one element must not be
// hidden by the other's good bytes.
//
// The bit fields refresh every frame (as fast as the elements deliver); the entropy
// figures are recomputed on a ~5 Hz timer so the digits are readable rather than a blur.

/// Split-view geometry: one framed bit field per source, stacked -- SE1, SE2, then the
/// STM32's own TRNG. Each field is `RNG_FW` x `RNG_FH` pixels with its inner top-left at
/// (`RNG_FX`, `RNG_FIELD_Y[i]`), a header line eight pixels above it, and the three share
/// the 64-pixel height in equal bands.
const RNG_FX: usize = 2;
const RNG_FW: usize = 122;
const RNG_FH: usize = 11;
/// Inner top of each source's field. Bands of 20 px: header at `y-8`, frame `y-1`, field
/// `y..y+RNG_FH`, bottom border `y+RNG_FH`. The last ends at 59, inside 64.
const RNG_FIELD_Y: [usize; 3] = [8, 28, 48];
/// Sources shown, in band order.
const RNG_SOURCES: usize = 3;
/// Bytes backing one field: one bit per pixel, rounded up. Each source has its own.
const RNG_RING: usize = (RNG_FW * RNG_FH).div_ceil(8);

/// `log2` for `f32`, no libm: split `x = m * 2^e` from the IEEE bits, then `log2(m)`
/// via the `atanh` series for `ln`. Good to a few thousandths over `m in [1, 2)`, which
/// is far finer than a 2-decimal entropy readout needs. `x` must be > 0.
fn flog2(x: f32) -> f32 {
    let bits = x.to_bits();
    let e = ((bits >> 23) & 0xff) as i32 - 127;
    // Force the exponent to 0 so the mantissa reads back as m in [1, 2).
    let m = f32::from_bits((bits & 0x007f_ffff) | 0x3f80_0000);
    let t = (m - 1.0) / (m + 1.0);
    let t2 = t * t;
    // ln(m) = 2*(t + t^3/3 + t^5/5 + t^7/7 + ...)
    let ln_m = 2.0 * t * (1.0 + t2 / 3.0 + (t2 * t2) / 5.0 + (t2 * t2 * t2) / 7.0);
    e as f32 + ln_m * core::f32::consts::LOG2_E
}

/// Shannon entropy of a byte histogram, in bits per byte (0..=8).
///
/// `H = log2(n) - (1/n) * sum(c_i * log2(c_i))` over the non-empty bins -- the same as
/// `-sum(p_i log2 p_i)`, rearranged so it divides once instead of per bin.
fn shannon_bits(hist: &[u32; 256], total: u64) -> f32 {
    if total == 0 {
        return 0.0;
    }
    let n = total as f32;
    let mut acc = 0.0f32;
    for &c in hist.iter() {
        if c > 0 {
            let cf = c as f32;
            acc += cf * flog2(cf);
        }
    }
    (flog2(n) - acc / n).clamp(0.0, 8.0)
}

/// Degrees of freedom for a 256-bin byte histogram, and the standard deviation of the
/// chi-squared distribution at that df (`sqrt(2*df)`), for reading a statistic as a
/// rough number of sigmas.
const CHI2_DF: f32 = 255.0;
const CHI2_SD: f32 = 22.5832; // sqrt(510)

/// Pearson chi-squared goodness-of-fit statistic for a byte histogram against a uniform
/// distribution, over 255 degrees of freedom.
///
/// `X^2 = sum((c_i - e)^2 / e)` with `e = n/256`, rearranged to `256 * sum(c_i^2)/n - n`
/// so it needs one pass and one divide. Its expected value for a uniform source is the
/// degrees of freedom (255) and does not depend on `n`, so it stays comparable as the
/// histogram is rescaled. A value far above 255 means the bytes are not uniform -- the
/// failure this screen exists to catch; one far below is its own kind of wrong (too even
/// to be random). `flog2`/`shannon_bits` measure disorder; this measures the shape.
fn chi2_uniform(hist: &[u32; 256], total: u64) -> f32 {
    if total == 0 {
        return 0.0;
    }
    let mut sum_sq = 0u64;
    for &c in hist.iter() {
        sum_sq += (c as u64) * (c as u64);
    }
    let n = total as f32;
    256.0 * (sum_sq as f32) / n - n
}

/// A short verdict for a chi-squared value: how many standard deviations it sits from the
/// mean a uniform source would give. Deliberately generous -- a healthy source wanders a
/// little frame to frame, a broken one misses by hundreds of sigma, so a wide "ok" band
/// avoids crying wolf without hiding a real failure.
fn chi2_verdict(chi2: f32) -> &'static str {
    let z = ((chi2 - CHI2_DF) / CHI2_SD).abs();
    if z < 4.0 {
        "ok"
    } else if z < 8.0 {
        "chk"
    } else {
        "BAD"
    }
}

/// A large count in a couple of characters, for the narrow left column.
fn compact(n: u64) -> Line {
    let mut s = Line::new();
    let _ = if n < 1000 {
        write!(s, "{n}")
    } else if n < 1_000_000 {
        write!(s, "{}k", n / 1000)
    } else {
        write!(s, "{}M", n / 1_000_000)
    };
    s
}

/// Draw one secure element's own view: a header (label, entropy, running count) above a
/// framed field of that element's recent bytes as raw bits. `field_y` is the field's
/// inner top; the header sits two rows above it. `exit_hint` adds the "x=exit" note to
/// the right of this header (shown once, on the top view).
#[allow(clippy::too_many_arguments)]
fn draw_se_view(
    fb: &mut Mono128x64,
    field_y: usize,
    label: &str,
    h_text: &str,
    chi2: f32,
    count: u64,
    ring: &[u8; RNG_RING],
    exit_hint: bool,
) {
    let f = &misc4x6::FONT;
    let hy = field_y - 8;
    draw_text(fb, f, 1, hy, label);
    // Shannon entropy (bits/byte), chi-squared value with its verdict, and byte count.
    let mut stat = Line::new();
    let _ = write!(
        stat,
        "H{h_text} X{} {} n{}",
        compact(chi2 as u64),
        chi2_verdict(chi2),
        compact(count)
    );
    draw_text(fb, f, 16, hy, &stat);
    if exit_hint {
        draw_text(fb, f, 104, hy, "x=exit");
    }
    // A thin frame, then this source's bytes one bit per pixel. Laid out column by
    // column with the newest bits entering at the right, so the write head sweeps
    // right-to-left down the field rather than top-to-bottom across it.
    fb.rect(
        RNG_FX - 1,
        field_y - 1,
        RNG_FX + RNG_FW + 1,
        field_y + RNG_FH + 1,
        true,
    );
    for col in 0..RNG_FW {
        for row in 0..RNG_FH {
            let bit = (RNG_FW - 1 - col) * RNG_FH + row;
            let on = (ring[bit / 8] >> (bit % 8)) & 1 == 1;
            fb.set(RNG_FX + col, field_y + row, on);
        }
    }
}

/// Live RNG analyzer. Blocks, driving the panel itself; `x` (or the left arrow) exits.
fn analyze_rng(gate: &Callgate, ui: &mut Ui<'_>) {
    use crate::trng::Kind;

    // Three bands: up to two of the board's other generators, then the chip's own TRNG,
    // which every board has and which is the one the mk3's pool actually runs on. The
    // bands come from the same source list boot and New wallet draw from, so this screen
    // shows what a seed is made of rather than its own idea of the board.
    let others: heapless::Vec<Kind, 4> = crate::trng::kinds()
        .into_iter()
        .filter(|&k| k != Kind::Chip)
        .collect();
    let bands: [Option<Kind>; RNG_SOURCES] = [
        others.first().copied(),
        others.get(1).copied(),
        Some(Kind::Chip),
    ];
    let mut trngs = crate::trng::Trngs::new(Some(gate));

    // Everything below is kept per source, so a fault in one is never masked by another:
    // its own histogram (for entropy), its own bounded total, its own lifetime count (for
    // the readout), and its own ring of recent bytes (for the bits).
    let mut hist = [[0u32; 256]; RNG_SOURCES];
    let mut total = [0u64; RNG_SOURCES];
    let mut seen = [0u64; RNG_SOURCES];
    let mut ring = [[0u8; RNG_RING]; RNG_SOURCES];
    let mut ring_at = [0usize; RNG_SOURCES];

    // Recompute the entropy figures at ~5 Hz so the digits are readable.
    // SAFETY: reads the RCC config only.
    let hz = unsafe { catcard_hal::clock::hclk_hz() };
    let period = (hz / 5).max(1);
    let mut last_h = catcard_hal::dwt::cycles();
    let mut h_text: [Line; RNG_SOURCES] = core::array::from_fn(|_| Line::new());
    for h in h_text.iter_mut() {
        let _ = h.push_str("--");
    }
    let mut chi2 = [0.0f32; RNG_SOURCES];

    let mut events = [Event::Pressed(Key::Cancel); KEYS];
    let mut keys: heapless::Vec<Key, { KEYS + 1 }> = heapless::Vec::new();

    loop {
        // One call per source per frame: at most 32 bytes each, and each field is sized
        // so a few frames turn it over completely. USB is polled here, not interrupt-
        // driven, and the frame is dominated by waiting on the elements, so it is pumped
        // before every blocking read (the read runs in the bootloader and cannot itself
        // be interrupted) and once more after the flush below. Pumping only once a frame
        // would leave the bus deaf through the slow parts -- which is most of the frame.
        // 32 bytes a band a frame: what a secure element answers per call, and a small
        // enough read that the far faster chip does not swamp the frame.
        for (i, kind) in bands.iter().enumerate() {
            let Some(kind) = kind else { continue };
            let _ = usbtask::pump();
            let mut buf = [0u8; 32];
            if let Some(n) = trngs.read(*kind, &mut buf) {
                for &b in &buf[..n] {
                    seen[i] += 1;
                    hist[i][b as usize] += 1;
                    total[i] += 1;
                    ring[i][ring_at[i]] = b;
                    ring_at[i] = (ring_at[i] + 1) % RNG_RING;
                }
            }
        }

        // Keep each source's counts (and so its f32 sums) bounded, and let the measure
        // stay adaptive: halving every bin preserves the ratios that entropy depends on.
        for i in 0..RNG_SOURCES {
            if total[i] >= (1 << 20) {
                total[i] = 0;
                for c in hist[i].iter_mut() {
                    *c >>= 1;
                    total[i] += *c as u64;
                }
            }
        }

        let now = catcard_hal::dwt::cycles();
        if now.wrapping_sub(last_h) >= period {
            last_h = now;
            for i in 0..RNG_SOURCES {
                h_text[i].clear();
                let _ = write!(h_text[i], "{:.2}", shannon_bits(&hist[i], total[i]));
                chi2[i] = chi2_uniform(&hist[i], total[i]);
            }
        }

        let mut fb = Mono128x64::new();
        for (i, kind) in bands.iter().enumerate() {
            let Some(kind) = kind else {
                // A band this board has nothing for says so, instead of an empty field that
                // looks like a dead generator.
                let f = &misc4x6::FONT;
                let y = RNG_FIELD_Y[i] - 8;
                draw_text(&mut fb, f, 1, y, "--");
                draw_text(&mut fb, f, 16, y, "no other generator here");
                if i == 0 {
                    draw_text(&mut fb, f, 104, y, "x=exit");
                }
                continue;
            };
            draw_se_view(
                &mut fb,
                RNG_FIELD_Y[i],
                kind.label(),
                &h_text[i],
                chi2[i],
                seen[i],
                &ring[i],
                i == 0, // the exit hint sits on the first band only
            );
        }
        display::show_mono(ui.panel, &fb);
        let _ = usbtask::pump();

        crate::pinentry::pressed_keys(ui.pad, ui.matrix, ui.drbg, &mut events, &mut keys);
        if keys
            .iter()
            .any(|k| matches!(k, Key::Cancel | Key::Digit(7)))
        {
            return;
        }
    }
}

/// Draw a seed from the hardware TRNGs and show its words -- a verification tool, not a
/// wallet. Nothing is stored; it lets the owner see the elements and the chip TRNG
/// produce fresh, varied words, which is the whole point of this project. Shown through
/// the same large-font, emissions-scrambled pager the real backup uses.
fn view_trng_words(gate: &Callgate, ui: &mut Ui<'_>) {
    use catcard_entropy::EntropyPool;
    use catcard_wallet::bip39::Mnemonic;
    use zeroize::Zeroize;

    // A fresh pool, filled only from the hardware sources -- no boot material, no user
    // entropy -- so the words are exactly what the TRNGs produce right now.
    let mut pool = EntropyPool::new(crate::entropy_policy());

    // The same collection effort as generating a real seed, from the same sources: a full
    // byte target from each, and a pause so the counts are legible. A "watch the generator
    // work" screen that finished in a blink would be reading a handful of bytes and calling
    // it done -- which is exactly the shortcut this project exists to replace, so it is not
    // one this screen is allowed to take either.
    const TARGET: usize = 512;
    const MAX_PASSES: usize = 160;
    const STEP_PAUSE_CYCLES: u32 = 4_000_000;

    let mut trngs = crate::trng::Trngs::new(Some(gate));
    let mut read: heapless::Vec<(crate::trng::Kind, usize), 4> =
        crate::trng::kinds().iter().map(|&k| (k, 0usize)).collect();
    for _ in 0..MAX_PASSES {
        if read.iter().all(|&(_, n)| n >= TARGET) {
            break;
        }
        for entry in read.iter_mut() {
            if entry.1 >= TARGET {
                continue;
            }
            let _ = usbtask::pump();
            let mut buf = [0u8; 64];
            if let Some(n) = trngs.read(entry.0, &mut buf)
                && n > 0
            {
                pool.add(entry.0.source(), &buf[..n]);
                entry.1 += n;
            }
            buf.zeroize();
        }

        let mut counts = Line::new();
        for (i, &(kind, n)) in read.iter().enumerate() {
            let _ = write!(
                counts,
                "{}{} {n}",
                if i > 0 { " " } else { "" },
                kind.label()
            );
        }
        let mut bits = Line::new();
        let _ = write!(bits, "{} bits", pool.credited_bits());
        message(ui.panel, "Reading TRNGs", &counts, &bits);
        catcard_hal::dwt::delay_cycles(STEP_PAUSE_CYCLES);
    }

    if pool.check().is_err() {
        message(
            ui.panel,
            "TRNG words",
            "TRNG check failed",
            "any key to go back",
        );
        wait_for_any_key(ui);
        return;
    }

    let mut entropy = [0u8; 32];
    // Masked: these words are only displayed, never a device key, but it is the same draw
    // and the same encoding a wallet goes through, and one rule is easier to keep than two.
    let mnemonic = crate::keywork::run(|kw| {
        let drawn = pool.draw(&mut entropy);
        let m = drawn
            .ok()
            .and_then(|()| Mnemonic::from_entropy(&entropy, kw).ok());
        entropy.zeroize();
        m
    });
    let Some(mnemonic) = mnemonic else {
        message(
            ui.panel,
            "TRNG words",
            "could not draw",
            "any key to go back",
        );
        wait_for_any_key(ui);
        return;
    };

    // Verification only -- never stored -- but scramble the emissions all the same, since
    // these are valid seed words on screen.
    let texts = word_texts(&mnemonic);
    let mut lines: heapless::Vec<catcard_ui::scroll::Line, 27> = heapless::Vec::new();
    let _ = lines.push(catcard_ui::scroll::Line::title("TRNG words"));
    let _ = lines.push(
        catcard_ui::scroll::Line::body("not saved")
            .small()
            .centered(),
    );
    for s in &texts {
        let _ = lines.push(catcard_ui::scroll::Line::body(s).secret());
    }
    show_doc(ui, &lines, true, false);
}

/// Write `s` into `out`, eliding the middle to `...` when it is wider than `cols`.
///
/// The start and end survive because those are the parts an eye actually checks against a
/// watch-only wallet; the dropped middle is the part nobody reads character by character.
/// The strings this is used on -- bech32 and base58 addresses -- are ASCII, so byte
/// offsets are character offsets and the slicing is on boundaries.
fn ellipsize_middle(s: &str, cols: usize, out: &mut Line) {
    // Fits as-is, or too narrow for an elision to leave anything useful: show the head.
    if s.len() <= cols || cols < 7 {
        let _ = out.push_str(&s[..s.len().min(cols.max(1))]);
        return;
    }
    let keep = cols - 3; // three columns go to the "..."
    let head = keep.div_ceil(2); // the front gets the odd character
    let tail = keep - head;
    let _ = out.push_str(&s[..head]);
    let _ = out.push_str("...");
    let _ = out.push_str(&s[s.len() - tail..]);
}

/// Walk the receive addresses of the stored wallet.
///
/// BIP-84 native segwit (`m/84'/0'/0'/0/i`) on mainnet -- the modern default -- one
/// address at a time, the down arrow forward and the up arrow back, as the pager does. The
/// point of showing them here is verification: an owner can check that an address the
/// device displays matches what a watch-only wallet derives from the same account, before
/// trusting it with funds.
///
/// The secret is fetched, turned into a master key, and reduced to the external-chain key
/// once; only the final `/i` step runs per address. The seed and the secret are wiped as
/// soon as that key exists -- nothing secret outlives the setup, and the chain key kept
/// here is a public-derivation parent, not the seed.
/// PBKDF2 rounds run between two redraws of the busy bar.
///
/// The whole stretch is 2048 rounds and takes about 1.7 s on an mk4, so 64 rounds is
/// roughly 50 ms of masked work per frame -- fast enough that the bar reads as moving,
/// long enough that the redraws stay a small fraction of the job. It is a fixed number by
/// design: a slice length that varied with the seed is exactly what the masking is for.
const STRETCH_SLICE: u32 = 64;

/// The address types the explorer walks, in the order the left/right arrows move through
/// them. Native segwit leads because it is what this wallet derives by default.
const PROTOCOLS: [catcard_wallet::address::AddressKind; 4] = [
    catcard_wallet::address::AddressKind::P2wpkh,
    catcard_wallet::address::AddressKind::P2tr,
    catcard_wallet::address::AddressKind::P2shP2wpkh,
    catcard_wallet::address::AddressKind::P2pkh,
];

/// What to call each on screen.
fn kind_name(kind: catcard_wallet::address::AddressKind) -> &'static str {
    use catcard_wallet::address::AddressKind;
    match kind {
        AddressKind::P2wpkh => "Native segwit",
        AddressKind::P2tr => "Taproot",
        AddressKind::P2shP2wpkh => "Nested segwit",
        AddressKind::P2pkh => "Legacy",
    }
}

/// `m/purpose'/0'/0'/0` as an extended **public** key: the receive chain every address of
/// that type hangs off.
///
/// Public on purpose. Receive addresses are non-hardened children of this level, so they
/// derive from the public key alone -- which means the private keys can all be dropped
/// before the masked region closes, and the browsing loop afterwards holds no key material
/// and needs no masking at all.
/// One level at a time, with `busy` ticked between them: each hardened step is an
/// HMAC-SHA512 and a point multiplication, about a tenth of a second of masked work, so the
/// four of them are a visible pause and the bar should keep moving across it.
/// The account-level chain key for `kind`, account `account`, chain `chain`
/// (0 receive, 1 change): `m/{purpose}h/0h/{account}h/{chain}`.
///
/// Only the public half comes back, so the caller can walk addresses without holding key
/// material.
pub(crate) fn chain_key(
    master: &catcard_wallet::bip32::ExtendedPrivKey,
    kind: catcard_wallet::address::AddressKind,
    account: u32,
    chain: u32,
    busy: &mut Working<'_>,
    panel: &mut display::Panel,
) -> Option<catcard_wallet::bip32::ExtendedPubKey> {
    use catcard_wallet::bip32::ChildNumber;
    let steps = [
        ChildNumber::hardened(kind.bip44_purpose()).ok()?,
        ChildNumber::hardened(0).ok()?,
        ChildNumber::hardened(account).ok()?,
        ChildNumber::normal(chain).ok()?,
    ];
    public_at(master, &steps, busy, panel)
}

/// The first account's receive chain, `m/{purpose}h/0h/0h/0`.
fn receive_chain(
    master: &catcard_wallet::bip32::ExtendedPrivKey,
    kind: catcard_wallet::address::AddressKind,
    busy: &mut Working<'_>,
    panel: &mut display::Panel,
) -> Option<catcard_wallet::bip32::ExtendedPubKey> {
    chain_key(master, kind, 0, 0, busy, panel)
}

/// The extended public key at `steps` below `master`.
///
/// The intermediate private keys never leave this function; each masked region derives the
/// next level and drops the previous one, and the last hop keeps only the public half.
/// Splitting the path this way exposes which level is running -- a fixed, published shape
/// -- and nothing about the key.
pub(crate) fn public_at(
    master: &catcard_wallet::bip32::ExtendedPrivKey,
    steps: &[catcard_wallet::bip32::ChildNumber],
    busy: &mut Working<'_>,
    panel: &mut display::Panel,
) -> Option<catcard_wallet::bip32::ExtendedPubKey> {
    let (first, rest) = steps.split_first()?;
    let mut here = crate::keywork::run(|kw| master.derive_child(*first, kw).ok())?;
    for step in rest {
        busy.tick(panel);
        here = crate::keywork::run(|kw| here.derive_child(*step, kw).ok())?;
    }
    busy.tick(panel);
    Some(crate::keywork::run(|kw| here.to_extended_pub(kw)))
}

/// Which way of asking the panel to scroll by itself actually moves the bar.
///
/// The busy bar crosses a secure-element call only if the panel controller scrolls it
/// unaided, and that has not been seen working on every board. Three labelled phases, two
/// seconds each, with the CPU doing nothing that could draw:
///
/// 1. the SSD1306 scroll setup this firmware sends today (six parameters);
/// 2. the longer form some SSD1306-family controllers take, with start and end columns;
/// 3. the CPU-ticked bar, as a control that must always move.
///
/// Whichever moves decides what `scroll_busy_bar` sends. A full redraw between phases puts
/// the panel back in a known state whatever the previous command did.
fn scroll_test(ui: &mut Ui<'_>) {
    #[cfg(not(feature = "board-q1"))]
    {
        use catcard_ui::DisplayBus;
        // SAFETY: reads RCC only.
        let per_ms = (unsafe { catcard_hal::clock::hclk_hz() } / 1000).max(1);
        let hold = |ms: u32| catcard_hal::dwt::delay_cycles(ms * per_ms);

        let phases: [(&str, &[u8]); 2] = [
            (
                "1 of 3: short form",
                &[0x2E, 0x26, 0x00, 7, 0x07, 7, 0x00, 0xFF, 0x2F],
            ),
            (
                "2 of 3: long form",
                &[0x2E, 0x26, 0x00, 7, 0x07, 7, 0x00, 0x00, 0x7F, 0x2F],
            ),
        ];
        for (label, bytes) in phases {
            display::draw(ui.panel, |c| {
                catcard_ui::widgets::working(c, &display::LAYOUT, "Scroll test", label, 0);
            });
            let _ = ui.panel.bus_mut().command(bytes);
            crate::catlog!("scroll test: {}", label);
            hold(2000);
        }
        let mut busy = Working::new(ui.panel, "Scroll test", "3 of 3: CPU ticks");
        for _ in 0..40 {
            hold(50);
            busy.tick(ui.panel);
        }
        message(
            ui.panel,
            "Scroll test",
            "which moved?",
            "any key to go back",
        );
        wait_for_any_key(ui);
    }
    #[cfg(feature = "board-q1")]
    {
        // The GPU co-processor's bar: the screen is drawn, the bus handed over, and the CPU
        // then does nothing that could draw for three seconds, as in a callgate call.
        // SAFETY: reads RCC only.
        let per_ms = (unsafe { catcard_hal::clock::hclk_hz() } / 1000).max(1);
        message(ui.panel, "Scroll test", "GPU bar, 3 seconds", "");
        display::scroll_busy_bar(ui.panel);
        crate::catlog!("scroll test: gpu bar");
        catcard_hal::dwt::delay_cycles(3000 * per_ms);
        message(
            ui.panel,
            "Scroll test",
            "did a bar move at the bottom?",
            "any key for the LCD scroll",
        );
        wait_for_any_key(ui);
        lcd_scroll_test(ui);
    }
}

/// The ST7789's own scrolling, on the Q1: which way it moves the picture, whether it wraps
/// cleanly, and which edge a fixed area holds still.
///
/// Two phases over a striped test card: the whole panel scrolled two lines a frame for two
/// full turns, then the same with the first 40 lines fixed. Each step waits for the tear
/// pulse. Then the panel is put back and the next frame sent whole.
#[cfg(feature = "board-q1")]
fn lcd_scroll_test(ui: &mut Ui<'_>) {
    use catcard_ui::st7789::{BARS, WIDTH, rgb565};

    message(ui.panel, "LCD scroll", "watch the stripes", "");
    // A card that shows direction and wrap: stripes 32 lines wide, a red line on memory
    // line 0 and a white one on line 319, and a wedge pointing towards higher lines.
    for i in 0..WIDTH / 32 {
        let _ = ui
            .panel
            .fill_rect(i * 32, 150, 32, 90, BARS[i % BARS.len()]);
    }
    let _ = ui.panel.fill_rect(0, 100, 3, 140, rgb565(31, 0, 0));
    let _ = ui
        .panel
        .fill_rect(WIDTH - 3, 100, 3, 140, catcard_ui::st7789::WHITE);
    for step in 0..20 {
        let _ = ui.panel.fill_rect(
            10 + step * 2,
            110 + step,
            2,
            40 - 2 * step,
            rgb565(0, 63, 0),
        );
    }

    let mut missed = 0u32;
    for (label, fixed_first, steps) in [
        ("whole panel", 0usize, 320usize),
        ("first 40 fixed", 40, 140),
    ] {
        crate::catlog!("lcd scroll: {}", label);
        let _ = ui.panel.set_scroll_area(fixed_first, 0);
        for n in 0..steps {
            if !display::wait_tear() {
                missed += 1;
            }
            let _ = ui
                .panel
                .set_scroll_start(fixed_first + (n * 2) % (WIDTH - fixed_first));
        }
        let _ = ui.panel.set_scroll_start(0);
    }
    display::end_scroll(ui.panel);
    crate::catlog!("lcd scroll: done, {} tear pulses missed", missed);
    message(
        ui.panel,
        "LCD scroll",
        "which way did it move?",
        "which side stayed still?",
    );
    wait_for_any_key(ui);
}

/// The screen for a wait the CPU cannot draw through: a callgate call, where interrupts are
/// masked and the firewall resets the CPU if one lands inside.
///
/// On an OLED the bar goes up and the controller keeps it moving (see
/// [`display::scroll_busy_bar`]). On the Q1 the text goes up without a bar of ours, and the
/// GPU co-processor draws its own moving one along the bottom -- or, where it is not in use,
/// nothing does: a bar that sits still for two seconds claims progress that is not being
/// shown, which is worse than a plain line saying what the device is waiting for.
pub(crate) fn blocking_screen(panel: &mut display::Panel, head: &str, note: &str) {
    #[cfg(not(feature = "board-q1"))]
    {
        display::draw(panel, |c| {
            catcard_ui::widgets::working(c, &display::LAYOUT, head, note, 0);
        });
        display::scroll_busy_bar(panel);
    }
    #[cfg(feature = "board-q1")]
    {
        message(panel, head, note, "");
        if display::GPU_BAR_ON_BLOCKING {
            display::scroll_busy_bar(panel);
        }
    }
}

/// The screen for reading the seed out of the secure element: the cat, reading.
///
/// Every screen that needs the seed waits on the same thing -- callgate 18/4, about 1.6 s
/// with the CPU inside the bootloader -- so they all wait on the same picture rather than
/// each on a line of text of its own. On the Q1 that is the reading cat in the middle of
/// the page and the blue sweep along the bottom, which is safe around exactly this call
/// (docs/CALLGATE-DMA.md, watched working 2026-09-22). Elsewhere it is the plain
/// [`blocking_screen`].
///
/// Only for a wait that *is* the seed read. Before a callgate that draws for itself --
/// logout, wipe -- the sweep would leave the bootloader a bus that is not its own.
pub(crate) fn reading_seed(panel: &mut display::Panel, head: &str) {
    #[cfg(feature = "board-q1")]
    if !seed_wait(panel, head, "reading the seed") && display::GPU_BAR_ON_BLOCKING {
        display::scroll_busy_bar(panel);
    }
    #[cfg(not(feature = "board-q1"))]
    blocking_screen(panel, head, "reading seed");
}

/// A page with one picture in the middle: `head` above it, `note` below, the bottom rows
/// left clear for the sweep.
#[cfg(feature = "board-q1")]
pub(crate) fn icon_page(
    panel: &mut display::Panel,
    art: &catcard_ui::art::indexed::Indexed,
    head: &str,
    note: &str,
) {
    use catcard_ui::canvas::Canvas as _;
    use catcard_ui::text::{centred, draw_text};

    let (title, body) = (display::LAYOUT.title, display::LAYOUT.body);
    display::draw_field_page(panel, |c| {
        c.clear();
        draw_text(c, title, centred(title, head, c.width()), 12, head);
        // In the middle of what is left above the sweep, which takes the bottom rows.
        let (w, h) = (art.width as usize, art.height as usize);
        let room = c.height().saturating_sub(catcard_ui::sweep::H);
        let x = c.width().saturating_sub(w) / 2;
        let y = room.saturating_sub(h) / 2;
        catcard_ui::art::indexed::draw_indexed(c, art, x, y);
        draw_text(c, body, centred(body, note, c.width()), y + h + 10, note);
    });
}

/// The screen while the microSD card is read or written: the cat with the card.
///
/// Drawn before the card is touched. On the mono panels, the plain message.
pub(crate) fn card_wait(panel: &mut display::Panel, head: &str, note: &str) {
    #[cfg(feature = "board-q1")]
    icon_page(
        panel,
        &catcard_ui::art::menuicons::MICROSD_ACCESS,
        head,
        note,
    );
    #[cfg(not(feature = "board-q1"))]
    message(panel, head, note, "");
}

/// The seed-wait page -- the reading cat, `head` above, `note` below -- and the sweep
/// under it, carried on from the last one if the glass still shows it. False if the
/// sweep could not start.
///
/// One page for every stage of getting at the seed, reading it and stretching it alike,
/// so going from one to the next changes the caption and nothing else: the bar keeps
/// moving from where it was.
#[cfg(feature = "board-q1")]
pub(crate) fn seed_wait(panel: &mut display::Panel, head: &str, note: &str) -> bool {
    display::keep_sweep();
    icon_page(panel, &catcard_ui::art::menuicons::READING_SEED, head, note);
    display::start_sweep(panel)
}

/// The screen shown while something slow runs: a heading, a note, and a bar that moves.
///
/// The bar is the whole point. Every computation behind one of these screens runs with
/// interrupts masked, so the panel cannot repaint while a slice of it is in flight -- and a
/// device that holds one frame for two seconds is a device the owner reads as crashed.
/// Nothing here knows how far along the work is; it only knows that it was asked to tick,
/// which is exactly what it shows.
pub(crate) struct Working<'a> {
    head: &'a str,
    note: Line,
    phase: u32,
    /// The DMA sweep is supplying the motion, so a tick has nothing to draw -- and
    /// drawing would stop the sweep it is meant to be showing.
    swept: bool,
}

impl<'a> Working<'a> {
    /// Draw the first frame. `note` is formatted by the caller, so a screen can say which
    /// address type it is deriving without this owning that vocabulary.
    pub(crate) fn new(panel: &mut display::Panel, head: &'a str, note: &str) -> Self {
        let mut w = Self {
            head,
            note: Line::new(),
            phase: 0,
            swept: false,
        };
        let _ = w.note.push_str(note);
        w.draw(panel);
        w
    }

    /// The same, for a stage of getting at the seed: the seed-wait page and the sweep,
    /// carrying on from the screen before (see [`reading_seed`]). If the sweep cannot
    /// start, it is [`Working::new`] and its ticking bar.
    pub(crate) fn seed(panel: &mut display::Panel, head: &'a str, note: &str) -> Self {
        #[cfg(feature = "board-q1")]
        if seed_wait(panel, head, note) {
            let mut w = Self {
                head,
                note: Line::new(),
                phase: 0,
                swept: true,
            };
            let _ = w.note.push_str(note);
            return w;
        }
        Self::new(panel, head, note)
    }

    /// Advance the bar one step and redraw.
    pub(crate) fn tick(&mut self, panel: &mut display::Panel) {
        if self.swept {
            return;
        }
        self.phase = self.phase.wrapping_add(1);
        self.draw(panel);
    }

    fn draw(&self, panel: &mut display::Panel) {
        let (head, note, phase) = (self.head, self.note.as_str(), self.phase);
        display::draw(panel, |c| {
            catcard_ui::widgets::working(c, &display::LAYOUT, head, note, phase);
        });
    }
}

/// The two faces the QR screen offers its text, largest first.
pub(crate) fn qr_faces() -> (
    &'static dyn catcard_ui::face::Face,
    &'static dyn catcard_ui::face::Face,
) {
    (display::FONTS.body, display::FONTS.small)
}

/// Show an address as a QR code beside the address itself, until a key is pressed.
///
/// The QR is for a wallet to scan; the text beside it, in blocks of four, is for a person to
/// compare against what their wallet shows. Both carry the same characters: the text is the
/// payload minus the BIP-21 scheme, upper-cased bech32 included, so what is read out loud is
/// what was encoded. [`address::qr_payload`] decides the payload's shape -- upper-case and
/// bare for bech32, `bitcoin:` and untouched for base58.
///
/// Encoding is `anyd`'s heap-free path, so nothing here allocates. The one choice left is
/// error correction: M, dropping to L only where M would leave one pixel a module on this
/// panel and L would not. On a 64-row OLED that is the difference between a symbol a phone
/// reads and a grey square.
///
/// Version 8 is the largest symbol the buffers hold: 49 modules, already more than a 64-row
/// panel can draw at one pixel each and far more than any address needs.
fn address_qr(ui: &mut Ui<'_>, address: &str, kind: catcard_wallet::address::AddressKind) {
    address_qr_of(ui, address, kind.is_bech32())
}

/// As [`address_qr`], for an address with no single-signature kind to name it by.
fn address_qr_of(ui: &mut Ui<'_>, address: &str, bech32: bool) {
    use catcard_wallet::address;

    let mut payload = [0u8; address::MAX_QR_PAYLOAD];
    let Some(payload) = address::qr_payload_of(address, bech32, &mut payload) else {
        message(ui.panel, "QR", "address not encodable", "");
        wait_for_any_key(ui);
        return;
    };
    let shown = address::qr_address(payload);
    qr_screen(ui, payload, shown);
}

/// A QR of `payload` beside `shown` in blocks of four, until a key is pressed.
///
/// The drawing half of [`address_qr_of`], for a payload that is not a Bitcoin URI: every
/// other chain's address goes in as it is written, which is what its wallets scan.
pub(crate) fn qr_screen(ui: &mut Ui<'_>, payload: &str, shown: &str) {
    qr_screen_bytes(ui, payload.as_bytes(), shown);
}

/// The same, for a payload that is not text.
///
/// A QR symbol carries bytes; only the *mode* it picks to carry them cares whether they
/// are characters. `anyd` chooses that mode from the bytes -- numeric for all-digits,
/// byte mode for anything else -- which is exactly what the two SeedQR shapes need, and
/// what a `&str` signature cannot express: Compact SeedQR is raw entropy, and entropy is
/// not UTF-8.
///
/// An empty `shown` draws the symbol alone, as large as the panel allows. That is the
/// right choice for a secret: the text column beside an address is there for a person to
/// read back, and a seed is not something to put on the glass twice.
pub(crate) fn qr_screen_bytes(ui: &mut Ui<'_>, payload: &[u8], shown: &str) {
    use anyd::codes::qr::{EcLevel, QrEncoder, Version};

    const MAX_VERSION: Version = match Version::new(8) {
        Some(v) => v,
        None => unreachable!(),
    };
    const BUF: usize = QrEncoder::buffer_len(MAX_VERSION);

    // Wiped on every way out: for a SeedQR these hold the seed's digits and its symbol,
    // and this frame is reused by whatever screen comes next.
    let mut scratch = zeroize::Zeroizing::new([0u8; BUF]);
    let mut storage = zeroize::Zeroizing::new([0u8; BUF]);
    let encoder = QrEncoder::new();
    // Pixels per module this level would get, or 0 if it does not encode or does not fit.
    // Scoped so the two buffers are reused rather than held twice over.
    let pixels = |level, scratch: &mut [u8; BUF], storage: &mut [u8; BUF]| {
        encoder
            .encode_text_into(payload, level, scratch, storage)
            .ok()
            .and_then(|(grid, _)| {
                catcard_ui::widgets::qr_text_fit(
                    qr_faces(),
                    display::FONTS.gap,
                    grid.width(),
                    shown.len(),
                    display::SCREEN_W,
                    display::SCREEN_H,
                )
            })
            .map_or(0, |fit| fit.scale)
    };

    let medium = pixels(EcLevel::M, &mut scratch, &mut storage);
    let level = if medium > 1 || pixels(EcLevel::L, &mut scratch, &mut storage) <= medium {
        EcLevel::M
    } else {
        EcLevel::L
    };

    let Ok((grid, _meta)) = encoder.encode_text_into(payload, level, &mut *scratch, &mut *storage)
    else {
        // Whatever it was -- an address, a key expression, a seed -- it did not fit the
        // largest symbol these buffers hold. Naming the caller's payload here would be a
        // guess: this function is shown more than addresses now.
        message(ui.panel, "QR", "too long to encode", "");
        wait_for_any_key(ui);
        return;
    };

    let mut drawn = false;
    // **Greys, not the amber.** A QR is read by a camera rather than by a person, and a
    // scanner wants dark modules on a light field -- the closer to white, the more
    // contrast it has to work with. The amber ramp is right for every screen someone
    // reads and wrong for the two that get photographed, this and `qrshow`.
    display::draw_with(ui.panel, &catcard_ui::st7789::GREYS, |c| {
        drawn = catcard_ui::widgets::qr_with_text(
            c,
            qr_faces(),
            display::FONTS.gap,
            grid.width(),
            |x, y| grid.get(x, y),
            shown,
        )
        .is_some()
            // No arrangement fits the text: the symbol alone still beats nothing, since it
            // is the half a wallet reads.
            || catcard_ui::widgets::qr(c, grid.width(), |x, y| grid.get(x, y));
    });
    if !drawn {
        message(ui.panel, "QR", "too big for this panel", "");
    }
    wait_for_any_key(ui);
}

use catcard_wallet::address::AddressKind;

/// The exports that are one file each and are not the generic JSON.
///
/// Nine menu rows over five formats. What varies between rows of the same format is the
/// filename, which address types the row offers, and -- for Samourai, whose two entries
/// *are* two account numbers -- the account. Everything else is in [`crate::export`].
///
/// Source: hw-reference/wallet-export-formats.md §"Summary table" [C].
const ONE_OFFS: &[OneOff] = &[
    OneOff {
        item: "Bitcoin Core",
        file: "/bitcoin-core.txt",
        format: Format::BitcoinCore,
        types: &[],
        account: 0,
    },
    OneOff {
        item: "Electrum Wallet",
        file: "/new-electrum.json",
        format: Format::Electrum,
        types: SINGLE_SIG,
        account: 0,
    },
    OneOff {
        item: "Blue Wallet",
        file: "/new-blue.json",
        format: Format::Electrum,
        types: SINGLE_SIG,
        account: 0,
    },
    OneOff {
        item: "Wasabi Wallet",
        file: "/new-wasabi.json",
        format: Format::Wasabi,
        types: &[],
        account: 0,
    },
    // The one filename with the fingerprint in it, so the `{}` is filled in later.
    OneOff {
        item: "Unchained",
        file: "/unchained-{}.json",
        format: Format::Unchained,
        types: &[],
        account: 0,
    },
    OneOff {
        item: "Descriptor",
        file: "/descriptor.txt",
        format: Format::Descriptor,
        types: SINGLE_SIG,
        account: 0,
    },
    OneOff {
        item: "Bull Bitcoin",
        file: "/bull-bitcoin.txt",
        format: Format::Descriptor,
        types: &[(AddressKind::P2wpkh, "Segwit P2WPKH")],
        account: 0,
    },
    OneOff {
        item: "Zeus",
        file: "/zeus-export.txt",
        format: Format::Descriptor,
        types: &[
            (AddressKind::P2wpkh, "Segwit P2WPKH"),
            (AddressKind::P2shP2wpkh, "P2SH-Segwit"),
        ],
        account: 0,
    },
    // Samourai's two pools are two fixed accounts near the top of the unhardened range.
    // They are not prompted for, because using a different number would not be a
    // Samourai export any more.
    OneOff {
        item: "Samourai Postmix",
        file: "/samourai-post-mix.txt",
        format: Format::Descriptor,
        types: &[(AddressKind::P2wpkh, "Segwit P2WPKH")],
        account: 2_147_483_646,
    },
    OneOff {
        item: "Samourai Premix",
        file: "/samourai-pre-mix.txt",
        format: Format::Descriptor,
        types: &[(AddressKind::P2wpkh, "Segwit P2WPKH")],
        account: 2_147_483_645,
    },
];

/// The three script types a single-signature export can be asked for, in stock's order.
const SINGLE_SIG: &[(AddressKind, &str)] = &[
    (AddressKind::P2wpkh, "Segwit P2WPKH"),
    (AddressKind::P2pkh, "Classic P2PKH"),
    (AddressKind::P2shP2wpkh, "P2SH-Segwit"),
];

/// One row of [`ONE_OFFS`].
struct OneOff {
    /// The menu label, which is how a row is found.
    item: &'static str,
    /// The filename, with `{}` standing in for the master fingerprint where a format
    /// puts it in the name.
    file: &'static str,
    format: Format,
    /// The address types offered on a submenu. Empty means the format fixes it.
    types: &'static [(AddressKind, &'static str)],
    account: u32,
}

/// Which writer in [`crate::export`] a row uses.
#[derive(Copy, Clone, PartialEq, Eq)]
enum Format {
    BitcoinCore,
    /// Electrum's, which Blue Wallet also reads.
    Electrum,
    Wasabi,
    Unchained,
    /// A single-signature output descriptor: Descriptor, Bull Bitcoin, Zeus, Samourai.
    Descriptor,
}

impl Format {
    /// What a reader should be told this payload is, when it goes out as a QR.
    fn filetype(self) -> catcard_bbqr::FileType {
        match self {
            // Bitcoin Core's is prose with two JSON blobs quoted inside it, and the
            // descriptor formats are one line of text. Neither parses as JSON.
            Format::BitcoinCore | Format::Descriptor => catcard_bbqr::FileType::UNICODE,
            Format::Electrum | Format::Wasabi | Format::Unchained => catcard_bbqr::FileType::JSON,
        }
    }
}

/// The row of [`ONE_OFFS`] a menu label names, if it names one.
fn one_off(label: &str) -> Option<&'static OneOff> {
    ONE_OFFS.iter().find(|o| o.item == label)
}

/// Which script type to export, when the row offers more than one.
#[cfg(feature = "board-q1")]
fn pick_type(
    ui: &mut Ui<'_>,
    head: &str,
    many: &[(AddressKind, &'static str)],
) -> Option<AddressKind> {
    let mut names: heapless::Vec<&str, 4> = heapless::Vec::new();
    for (_, name) in many {
        let _ = names.push(name);
    }
    choose(ui, head, "address type", &names).map(|at| many[at].0)
}

/// The first one offered, which is native segwit on every row that offers a choice.
///
/// mk3 and mk4 have no in-action chooser, and adding one for this would be a keypad
/// menu on a four-line screen. The rows are ordered with the type nearly everyone wants
/// first, so taking it is the right default rather than an arbitrary one -- and a person
/// who needs one of the others can get it from the generic JSON, which carries all three.
#[cfg(not(feature = "board-q1"))]
fn pick_type(
    _ui: &mut Ui<'_>,
    _head: &str,
    many: &[(AddressKind, &'static str)],
) -> Option<AddressKind> {
    many.first().map(|(kind, _)| *kind)
}

/// Build and offer one of the exports in [`ONE_OFFS`].
///
/// The rows share this because the difference between them is data, not code: pick the
/// script type if the row offers a choice, derive, write, offer. Adding a wallet that
/// wants one of these five formats under a different name is a row in the table.
fn export_one(gate: &Callgate, login: &mut catcard_pin::Login, ui: &mut Ui<'_>, which: u8) {
    let Some(label) = EXPORT_ITEMS.get(which as usize).copied() else {
        return;
    };
    let Some(row) = one_off(label) else {
        return;
    };

    // The script type first, before the PIN: backing out of a submenu should not have
    // cost an unlock.
    let kind = match row.types {
        [] => AddressKind::P2wpkh,
        [(only, _)] => *only,
        many => match pick_type(ui, label, many) {
            Some(kind) => kind,
            None => return,
        },
    };

    let Some(master) = unlock_master(gate, login, ui, label) else {
        return;
    };
    let fingerprint = crate::keywork::run(|kw| master.fingerprint(kw));

    let mut text: heapless::String<{ crate::export::MAX_LEN }> = heapless::String::new();
    let mut busy = Working::new(ui.panel, label, "deriving accounts");
    let built = match row.format {
        Format::BitcoinCore => {
            crate::export::bitcoin_core(&master, row.account, &mut busy, ui.panel, &mut text)
        }
        Format::Electrum => {
            crate::export::electrum(&master, kind, row.account, &mut busy, ui.panel, &mut text)
        }
        Format::Wasabi => crate::export::wasabi(&master, &mut busy, ui.panel, &mut text),
        Format::Unchained => {
            crate::export::unchained(&master, row.account, &mut busy, ui.panel, &mut text)
        }
        // One multipath line covering both chains, which is stock's default and the
        // only form the four vendor rows use.
        Format::Descriptor => crate::export::ss_descriptor(
            &master,
            kind,
            row.account,
            true,
            &mut busy,
            ui.panel,
            &mut text,
        ),
    };
    if built.is_none() {
        message(ui.panel, label, "derivation failed", "any key to go back");
        wait_for_any_key(ui);
        return;
    }
    // Each format names the key its signature comes from; they are not the same key.
    let signing = match row.format {
        Format::BitcoinCore => {
            crate::export::Signing::account(84, row.account, AddressKind::P2wpkh)
        }
        Format::Electrum | Format::Descriptor => {
            crate::export::Signing::account(kind.bip44_purpose(), row.account, kind)
        }
        Format::Wasabi => crate::export::Signing::account(84, 0, AddressKind::P2wpkh),
        Format::Unchained => crate::export::Signing::cosigner(row.account),
    };
    let signer = signer_for(master, signing);

    let [a, b, c, d] = fingerprint;
    let mut file: heapless::String<32> = heapless::String::new();
    match row.file.split_once("{}") {
        Some((head, tail)) => {
            let _ = write!(file, "{head}{a:02X}{b:02X}{c:02X}{d:02X}{tail}");
        }
        None => {
            let _ = file.push_str(row.file);
        }
    }
    offer_export(
        ui,
        label,
        &file,
        text.as_bytes(),
        row.format.filetype(),
        signer,
    );
}

/// The file a Format A row writes under, if that row is one.
fn generic_json_file(label: &str) -> Option<&'static str> {
    GENERIC_JSON_NAMES
        .iter()
        .find(|(name, _)| *name == label)
        .map(|(_, file)| *file)
}

/// The generic JSON export, under whichever vendor's filename was chosen.
///
/// Seven menu rows, one file. The bytes do not differ between them -- only the name,
/// because each piece of software looks for its own and finding nothing is the failure
/// people report as "it does not work with my wallet".
fn export_generic_json(
    gate: &Callgate,
    login: &mut catcard_pin::Login,
    ui: &mut Ui<'_>,
    which: u8,
) {
    const HEAD: &str = "Export wallet";
    let Some(label) = EXPORT_ITEMS.get(which as usize).copied() else {
        return;
    };
    let Some(file) = generic_json_file(label) else {
        return;
    };
    let Some(master) = unlock_master(gate, login, ui, label) else {
        return;
    };

    let mut text: heapless::String<{ crate::export::MAX_LEN }> = heapless::String::new();
    let mut busy = Working::new(ui.panel, label, "deriving accounts");
    // Account zero: the number stock prompts for, and the one every wallet defaults to.
    let built = crate::export::generic_json(&master, 0, &mut busy, ui.panel, &mut text);
    if built.is_none() {
        message(ui.panel, HEAD, "derivation failed", "any key to go back");
        wait_for_any_key(ui);
        return;
    }
    let signer = signer_for(
        master,
        crate::export::Signing::account(44, 0, AddressKind::P2pkh),
    );
    offer_export(
        ui,
        label,
        file,
        text.as_bytes(),
        catcard_bbqr::FileType::JSON,
        signer,
    );
}

/// One account's extended public key, as plain text.
///
/// The simplest export there is, and the one a watch-only wallet asks for when it wants
/// to be told a key rather than handed a file it has to parse. The row chosen says which
/// level: the three single-signature purposes, the master key itself, or just the
/// fingerprint.
fn export_xpub(gate: &Callgate, login: &mut catcard_pin::Login, ui: &mut Ui<'_>, which: u8) {
    use catcard_wallet::bip32::ChildNumber;

    const HEAD: &str = "Export XPUB";
    // The rows of `XPUB_ITEMS`, in order. `None` is the master key, which is not
    // derived at all, and the last row writes the fingerprint on its own.
    let purpose = match which {
        0 => Some(84),
        1 => Some(44),
        2 => Some(49),
        3 => None,
        _ => None,
    };
    let fingerprint_only = which == 4;

    let Some(master) = unlock_master(gate, login, ui, HEAD) else {
        return;
    };
    let fingerprint = crate::keywork::run(|kw| master.fingerprint(kw));
    let [a, b, c, d] = fingerprint;

    let mut text: heapless::String<256> = heapless::String::new();
    if fingerprint_only {
        let _ = writeln!(text, "{a:02X}{b:02X}{c:02X}{d:02X}");
    } else {
        let mut busy = Working::new(ui.panel, HEAD, "deriving");
        let key = match purpose {
            // The master key itself, which is not derived at all.
            None => Some(crate::keywork::run(|kw| master.to_extended_pub(kw))),
            Some(p) => {
                let steps = [
                    ChildNumber::hardened(p),
                    ChildNumber::hardened(0),
                    ChildNumber::hardened(0),
                ];
                match steps {
                    [Ok(p), Ok(coin), Ok(acct)] => {
                        public_at(&master, &[p, coin, acct], &mut busy, ui.panel)
                    }
                    _ => None,
                }
            }
        };
        let mut xpub = [0u8; catcard_wallet::bip32::serialize::MAX_BASE58_LEN];
        let Some(len) = key.and_then(|k| k.write_base58(&mut xpub).ok()) else {
            message(ui.panel, HEAD, "derivation failed", "any key to go back");
            wait_for_any_key(ui);
            return;
        };
        let _ = writeln!(text, "{}", core::str::from_utf8(&xpub[..len]).unwrap_or(""));
    }
    // Stock shows this one only as a QR and never writes a file, so it names no signing
    // derivation. BIP-44's first receive key is what the other text exports use.
    let signer = signer_for(
        master,
        crate::export::Signing::account(44, 0, AddressKind::P2pkh),
    );

    // Named for what it holds, so a card with several on it is still readable.
    let mut path: heapless::String<24> = heapless::String::new();
    let what = match (fingerprint_only, purpose) {
        (true, _) => "XFP",
        (_, None) => "MASTER",
        (_, Some(p)) => match p {
            84 => "BIP84",
            44 => "BIP44",
            _ => "BIP49",
        },
    };
    let _ = write!(path, "/{a:02X}{b:02X}{c:02X}{d:02X}-{what}.TXT");
    offer_export(
        ui,
        HEAD,
        &path,
        text.as_bytes(),
        catcard_bbqr::FileType::UNICODE,
        signer,
    );
}

/// Export this device's account keys as one `ur:crypto-account` code.
///
/// # What a wallet gets, and why in one code
///
/// Every other row here writes a *file*: JSON, a descriptor, an xpub as text. This
/// writes the structure BCR-2020-015 defines for exactly this job -- the master
/// fingerprint and the account-level extended key for each standard script type, so
/// the software on the other side picks the one it wants instead of the owner being
/// asked which script they are using before they know what the wallet will ask for.
/// [C] BCR-2020-015 §Abstract
///
/// The seven derivations are the ones that BCR tabulates for Bitcoin mainnet, account
/// zero. [C] BCR-2020-015 §Introduction. Account zero and mainnet are not a limit of
/// the format -- they are what every other export on this device uses, and an account
/// picker here would be a second place to get that answer wrong.
///
/// # Q1 only, and QR only
///
/// A UR is a QR format. There is no card here because there is nothing sensible to
/// write: the bytes are CBOR, which no wallet reads off a card, and the text form is
/// the code itself. The mono boards have no screen to draw it on.
#[cfg(feature = "board-q1")]
#[cfg(feature = "multichain")]
fn export_account_ur(gate: &Callgate, login: &mut catcard_pin::Login, ui: &mut Ui<'_>) {
    use catcard_bcur::registry::Kind;

    const HEAD: &str = "Account (UR)";
    /// Room for the whole account. The published seven-descriptor example is 776
    /// bytes; this is twice that, which is still a fraction of what the code it feeds
    /// will take as characters.
    const ROOM: usize = 2048;

    let Some(master) = unlock_master(gate, login, ui, HEAD) else {
        return;
    };
    // Big-endian, because that is how BIP-32 numbers a fingerprint and how the BCR's
    // own vectors encode one: `37b5eed4` as the integer 934670036. [C] BCR-2020-015
    let fingerprint = u32::from_be_bytes(crate::keywork::run(|kw| master.fingerprint(kw)));

    let Some(mut mem) = crate::heap::take(ROOM) else {
        message(ui.panel, HEAD, "not enough memory", "any key to go back");
        wait_for_any_key(ui);
        return;
    };

    let mut busy = Working::new(ui.panel, HEAD, "deriving accounts");
    let built = build_account_ur(&master, fingerprint, mem.bytes(), &mut busy, ui);
    // The key goes before the screen does: an animation stands there until somebody
    // walks up to it, and nothing after this point needs a private key.
    drop(master);

    let Some(len) = built else {
        message(ui.panel, HEAD, "derivation failed", "any key to go back");
        wait_for_any_key(ui);
        return;
    };
    let message = &mem.bytes()[..len];
    crate::qrshow::animate_bcur(ui, HEAD, Kind::Account.written_as(), message);
}

/// Derive each account key and write the `crypto-account` into `out`.
///
/// Split out so the key is dropped at one place in the caller rather than at each of
/// the half-dozen ways this can fail.
#[cfg(feature = "board-q1")]
#[cfg(feature = "multichain")]
fn build_account_ur(
    master: &catcard_wallet::bip32::ExtendedPrivKey,
    fingerprint: u32,
    out: &mut [u8],
    busy: &mut Working<'_>,
    ui: &mut Ui<'_>,
) -> Option<usize> {
    use catcard_bcur::registry::{Descriptor, account};
    use catcard_wallet::bip32::ChildNumber;

    /// The deepest of the standard paths is BIP-48's four levels.
    const DEPTH: usize = 4;

    let mut enc = account::Encoder::new(out, fingerprint, account::STANDARD.len() as u32).ok()?;
    for (script, path) in account::STANDARD {
        let mut steps: heapless::Vec<ChildNumber, DEPTH> = heapless::Vec::new();
        for &index in path {
            steps.push(ChildNumber::hardened(index).ok()?).ok()?;
        }
        let xpub = public_at(master, &steps, busy, ui.panel)?;
        let d = Descriptor::account_key(
            script,
            path,
            fingerprint,
            // Big-endian, as BIP-32 numbers a fingerprint and as the BCR's vectors
            // encode one. [C] BCR-2020-007 §"Example/Test Vector 2"
            u32::from_be_bytes(xpub.parent_fingerprint),
            xpub.public_key,
            xpub.chain_code,
        )
        .ok()?;
        enc.push(d.script, &d.key).ok()?;
    }
    enc.finish().ok()
}

/// Every enabled chain's account, as one `crypto-multi-accounts` code.
///
/// What a wallet reads when it offers to "sync with your hardware wallet". One code, one
/// key per chain, so somebody sets up Ethereum and Solana and Bitcoin in one scan
/// instead of three -- which is the difference between a device people use for
/// everything and one they use for the chain they set up first.
///
/// # Which key each chain gets
///
/// The node a wallet can derive addresses under, and the level of it depends on what
/// kind of chain it is:
///
/// - **Account-model** (EVM, Tron): `m/44'/coin'/0'/0`, the change node, because that is
///   what those wallets derive `/0`, `/1`, `/2` under.
/// - **UTXO** (Bitcoin and its family): `m/44'/coin'/0'`, the account node, under which a
///   wallet derives both the receive and change chains itself.
/// - **ed25519** (Solana): the account key itself at `m/44'/coin'/0'/0'`. SLIP-0010 has
///   no public derivation, so there is no node to hand over -- the key *is* the account,
///   and the wallet base58s it into the address.
///
/// A chain whose scheme this cannot express is left out rather than approximated, and
/// the screen says how many went in.
#[cfg(feature = "multichain")]
fn export_keystone(gate: &Callgate, login: &mut catcard_pin::Login, ui: &mut Ui<'_>) {
    use catcard_bcur::registry::{Kind, hdkey, multi};
    use catcard_wallet::bip32::ChildNumber;
    use catcard_wallet::chain::{Encoding, Scheme};

    const HEAD: &str = "Keystone";

    // Every chain the owner has enabled, which on a build with one chain is that one.
    let order = crate::chains::enabled(gate, login, ui);

    // The account keys accumulate in a heap block, not on the stack. An `HdKey` is a few
    // hundred bytes, so `chains::MAX` of them is several kilobytes; carrying that on the UI
    // task's stack, on top of the BIP-32 derivation frames, overran the 32 KB stack and
    // tripped the stack guard. The encoder reads them straight out of the block as a
    // `&[HdKey]`, so the block and the encode output are the only two live allocations.
    let Some(mut store) =
        crate::heap::take(crate::chains::MAX * core::mem::size_of::<hdkey::HdKey>())
    else {
        message(ui.panel, HEAD, "not enough memory", "any key to go back");
        wait_for_any_key(ui);
        return;
    };
    let mut keys = HdKeyStore::new(store.bytes());

    // The secp256k1 chains, from the BIP-32 master. Derived a level at a time with the
    // bar moving between steps, which is what keeps a dozen accounts from looking like a
    // device that has stopped.
    let Some(master) = unlock_master(gate, login, ui, HEAD) else {
        return;
    };
    let fingerprint = u32::from_be_bytes(crate::keywork::run(|kw| master.fingerprint(kw)));
    {
        let mut busy = Working::new(ui.panel, HEAD, "deriving accounts");
        for chain in order.iter() {
            if chain.scheme != Scheme::Bip32 {
                continue;
            }
            // An account-model chain's wallet derives under the change node; a UTXO
            // wallet derives both chains under the account node.
            let account_model = chain
                .formats
                .first()
                .is_some_and(|f| matches!(f.encoding, Encoding::Evm | Encoding::Tron));
            let mut steps: heapless::Vec<ChildNumber, 4> = heapless::Vec::new();
            let Ok(purpose) = ChildNumber::hardened(44) else {
                continue;
            };
            let Ok(coin) = ChildNumber::hardened(chain.coin_type_on(crate::prefs::network()))
            else {
                continue;
            };
            let Ok(account) = ChildNumber::hardened(0) else {
                continue;
            };
            let _ = steps.push(purpose);
            let _ = steps.push(coin);
            let _ = steps.push(account);
            if account_model {
                let Ok(change) = ChildNumber::normal(0) else {
                    continue;
                };
                let _ = steps.push(change);
            }
            let Some(xpub) = public_at(&master, &steps, &mut busy, ui.panel) else {
                continue;
            };
            let Some(key) = hdkey_for(chain, &steps, fingerprint, &xpub) else {
                continue;
            };
            keys.push(key);
        }
    }
    // The private key goes before anything else happens: what follows is a screen that
    // stands there until somebody walks up to it.
    drop(master);

    // The ed25519 chains, which need the seed rather than the BIP-32 master. One more
    // stretch, and only if any such chain is enabled -- which on a Bitcoin-only build is
    // never, and there the derivation is not compiled at all.
    #[cfg(feature = "multichain")]
    let wants_ed = order.iter().any(|c| c.scheme == Scheme::Slip10Ed25519);
    #[cfg(not(feature = "multichain"))]
    let wants_ed = false;
    #[cfg(feature = "multichain")]
    if wants_ed {
        // The closure pushes into the same heap-backed accumulator the secp256k1 pass
        // filled, so there is one set of keys on the way to the encoder rather than a
        // second `HdKey` vector built beside the first while both are live.
        let got = with_seed(gate, login, ui.panel, HEAD, |seed, kw| {
            for chain in order.iter() {
                if chain.scheme != Scheme::Slip10Ed25519 {
                    continue;
                }
                let path = [44, chain.coin_type_on(crate::prefs::network()), 0, 0];
                let Some(node) = catcard_wallet::slip10::derive(seed, &path, kw) else {
                    continue;
                };
                let Some(key) = ed25519_hdkey(chain, &path, fingerprint, &node.public_key(kw))
                else {
                    continue;
                };
                keys.push(key);
            }
            Some(())
        });
        let _ = got;
    }
    let _ = wants_ed;

    if keys.is_empty() {
        message(ui.panel, HEAD, "no chain to export", "any key to go back");
        wait_for_any_key(ui);
        return;
    }

    const DEVICE: &str = "CatCard";
    let Some(mut mem) = crate::heap::take(multi::encoded_len(keys.len(), DEVICE.len())) else {
        message(ui.panel, HEAD, "not enough memory", "any key to go back");
        wait_for_any_key(ui);
        return;
    };
    let Ok(len) = multi::encode(fingerprint, keys.as_slice(), DEVICE, mem.bytes()) else {
        message(ui.panel, HEAD, "could not encode", "any key to go back");
        wait_for_any_key(ui);
        return;
    };
    crate::catlog!("keystone: {} accounts, {} bytes", keys.len(), len);
    let body = &mem.bytes()[..len];
    crate::qrshow::animate_bcur(ui, HEAD, Kind::MultiAccounts.written_as(), body);
}

/// A fixed-capacity accumulator of `HdKey`s that lives in a heap block instead of on the
/// stack.
///
/// `export_keystone` gathers up to `chains::MAX` account keys before handing the slice to
/// `multi::encode`. An `HdKey` is a few hundred bytes, so that many on the stack -- on top
/// of the derivation frames -- overran the UI task's 32 KB stack. This holds them in a
/// `heap::take` block instead: the encoder still sees them as a `&[HdKey]`.
#[cfg(feature = "multichain")]
struct HdKeyStore<'a> {
    slots: &'a mut [core::mem::MaybeUninit<catcard_bcur::registry::hdkey::HdKey>],
    len: usize,
}

#[cfg(feature = "multichain")]
impl<'a> HdKeyStore<'a> {
    /// Wrap a heap block's bytes as room for as many whole `HdKey`s as they hold.
    fn new(bytes: &'a mut [u8]) -> Self {
        use catcard_bcur::registry::hdkey::HdKey;
        // `heap::take` returns a 4-aligned block and an `HdKey`'s alignment is 4 on this
        // 32-bit target, so the cast below is well aligned. Assert it rather than assume it.
        const _: () = assert!(core::mem::align_of::<HdKey>() <= 4);
        let count = bytes.len() / core::mem::size_of::<HdKey>();
        // SAFETY: the block is 4-aligned (see the assert) and `count` slots of
        // `size_of::<HdKey>()` bytes fit within its length. `MaybeUninit` needs no
        // initialisation, and `len` below tracks which slots actually hold a key, so no
        // uninitialised `HdKey` is ever read.
        let slots = unsafe {
            core::slice::from_raw_parts_mut(
                bytes.as_mut_ptr().cast::<core::mem::MaybeUninit<HdKey>>(),
                count,
            )
        };
        HdKeyStore { slots, len: 0 }
    }

    /// Append a key. Full is a no-op: the block is sized for `chains::MAX` and the caller
    /// never walks more chains than that, so it cannot overflow in practice.
    fn push(&mut self, key: catcard_bcur::registry::hdkey::HdKey) {
        if self.len < self.slots.len() {
            self.slots[self.len].write(key);
            self.len += 1;
        }
    }

    fn len(&self) -> usize {
        self.len
    }

    fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// The keys pushed so far.
    fn as_slice(&self) -> &[catcard_bcur::registry::hdkey::HdKey] {
        use catcard_bcur::registry::hdkey::HdKey;
        // SAFETY: `push` initialised slots `0..len` and hands out no interior mutability,
        // so those slots hold valid `HdKey`s for as long as `self` is borrowed.
        unsafe { core::slice::from_raw_parts(self.slots.as_ptr().cast::<HdKey>(), self.len) }
    }
}

#[cfg(feature = "multichain")]
impl Drop for HdKeyStore<'_> {
    fn drop(&mut self) {
        for slot in &mut self.slots[..self.len] {
            // SAFETY: slots `0..len` were initialised by `push`; each is dropped once,
            // here, before the block's bytes go back to the heap.
            unsafe { slot.assume_init_drop() };
        }
    }
}

/// One secp256k1 chain's entry: the node, its path, and what to call it.
#[cfg(feature = "multichain")]
fn hdkey_for(
    chain: &catcard_wallet::chain::Chain,
    steps: &[catcard_wallet::bip32::ChildNumber],
    fingerprint: u32,
    xpub: &catcard_wallet::bip32::ExtendedPubKey,
) -> Option<catcard_bcur::registry::hdkey::HdKey> {
    use catcard_bcur::registry::hdkey::{Component, HdKey, KeyPath};

    let mut key = HdKey::of(&xpub.public_key).ok()?;
    key.chain_code = Some(xpub.chain_code);
    // Big-endian, as BIP-32 numbers a fingerprint and as the BCR's vectors encode one.
    key.parent_fingerprint = Some(u32::from_be_bytes(xpub.parent_fingerprint));
    let mut path: heapless::Vec<Component, 8> = heapless::Vec::new();
    for step in steps {
        let _ = path.push(if step.is_hardened() {
            Component::hardened(step.index())
        } else {
            Component::normal(step.index())
        });
    }
    key.origin = KeyPath::new(fingerprint, &path).ok();
    key.name = heapless::String::try_from(chain.name).ok();
    Some(key)
}

/// One ed25519 chain's entry: the account key itself, and the hardened path it is at.
#[cfg(feature = "multichain")]
#[cfg(feature = "multichain")]
fn ed25519_hdkey(
    chain: &catcard_wallet::chain::Chain,
    path: &[u32],
    fingerprint: u32,
    public: &[u8; 32],
) -> Option<catcard_bcur::registry::hdkey::HdKey> {
    use catcard_bcur::registry::hdkey::{Component, HdKey, KeyPath};

    let mut key = HdKey::of(public).ok()?;
    // No chain code: SLIP-0010 over ed25519 has no public derivation, so there is
    // nothing a holder of this key could derive from it, and saying otherwise would
    // invite a wallet to try.
    let mut steps: heapless::Vec<Component, 8> = heapless::Vec::new();
    for &index in path {
        let _ = steps.push(Component::hardened(index));
    }
    key.origin = KeyPath::new(fingerprint, &steps).ok();
    key.name = heapless::String::try_from(chain.name).ok();
    Some(key)
}

/// The BIP-48 cosigner keys on their own.
///
/// A key expression is not a wallet: it is this device's share of one. The full export
/// carries these among the descriptors, and a coordinator that wants only this should
/// not have to be sent the rest.
fn export_key_expression(gate: &Callgate, login: &mut catcard_pin::Login, ui: &mut Ui<'_>) {
    use catcard_wallet::bip32::ChildNumber;

    const HEAD: &str = "Key Expression";
    const COSIGNER: [(u32, &str); 2] = [(2, "P2WSH"), (1, "P2SH-P2WSH")];

    let Some(master) = unlock_master(gate, login, ui, HEAD) else {
        return;
    };
    let fingerprint = crate::keywork::run(|kw| master.fingerprint(kw));
    let [a, b, c, d] = fingerprint;

    let mut text: heapless::String<512> = heapless::String::new();
    let _ = write!(
        text,
        "# CatCard cosigner keys (BIP-48), master fingerprint {a:02x}{b:02x}{c:02x}{d:02x}\n\
         # Give one to the coordinator; it is a key, not a wallet.\n"
    );
    let mut busy = Working::new(ui.panel, HEAD, "deriving");
    for (script, name) in COSIGNER {
        busy.tick(ui.panel);
        let steps = [
            ChildNumber::hardened(48),
            ChildNumber::hardened(0),
            ChildNumber::hardened(0),
            ChildNumber::hardened(script),
        ];
        let [Ok(purpose), Ok(coin), Ok(acct), Ok(form)] = steps else {
            continue;
        };
        let Some(key) = public_at(&master, &[purpose, coin, acct, form], &mut busy, ui.panel)
        else {
            continue;
        };
        let mut xpub = [0u8; catcard_wallet::bip32::serialize::MAX_BASE58_LEN];
        let Ok(xlen) = key.write_base58(&mut xpub) else {
            continue;
        };
        let _ = write!(
            text,
            "# {name}, m/48h/0h/0h/{script}h\n[{a:02x}{b:02x}{c:02x}{d:02x}/48h/0h/0h/{script}h]{}/<0;1>/*\n",
            core::str::from_utf8(&xpub[..xlen]).unwrap_or("")
        );
    }
    // Format G's multisig and custom-path rows sign classic, and these are the BIP-48
    // cosigner keys, so the signature comes from the P2WSH leg.
    let signer = signer_for(master, crate::export::Signing::cosigner(0));

    let mut path: heapless::String<24> = heapless::String::new();
    let _ = write!(path, "/{a:02X}{b:02X}{c:02X}{d:02X}-KEYS.TXT");
    offer_export(
        ui,
        HEAD,
        &path,
        text.as_bytes(),
        catcard_bbqr::FileType::UNICODE,
        signer,
    );
}

/// The first few addresses of every account, to check a watch-only wallet against.
///
/// The point of it is comparison: a wallet that has been given the right keys shows
/// these same addresses, and one that has been given the wrong ones does not. So the
/// file is written to be read beside a screen, not parsed.
fn dump_summary(gate: &Callgate, login: &mut catcard_pin::Login, ui: &mut Ui<'_>) {
    use catcard_wallet::address::AddressKind;
    use catcard_wallet::bip32::ChildNumber;

    const HEAD: &str = "Dump Summary";
    const SHOWN: u32 = 5;
    const ACCOUNTS: [(AddressKind, &str); 4] = [
        (AddressKind::P2wpkh, "Native segwit"),
        (AddressKind::P2shP2wpkh, "Nested segwit"),
        (AddressKind::P2pkh, "Legacy"),
        (AddressKind::P2tr, "Taproot"),
    ];

    let Some(master) = unlock_master(gate, login, ui, HEAD) else {
        return;
    };
    let fingerprint = crate::keywork::run(|kw| master.fingerprint(kw));
    let [a, b, c, d] = fingerprint;

    let mut text: heapless::String<2048> = heapless::String::new();
    let _ = write!(
        text,
        "# CatCard summary, master fingerprint {a:02x}{b:02x}{c:02x}{d:02x}\n\
         # The first {SHOWN} receive addresses of each account. A watch-only wallet\n\
         # given the right keys shows these same addresses.\n"
    );
    let mut busy = Working::new(ui.panel, HEAD, "deriving addresses");
    for (kind, name) in ACCOUNTS {
        busy.tick(ui.panel);
        let steps = [
            ChildNumber::hardened(kind.bip44_purpose()),
            ChildNumber::hardened(0),
            ChildNumber::hardened(0),
        ];
        let [Ok(p), Ok(coin), Ok(acct)] = steps else {
            continue;
        };
        let _ = write!(text, "\n# {name}, m/{}h/0h/0h\n", kind.bip44_purpose());
        // The account key once, then the chain below it -- which is unhardened, so the
        // addresses come from the public key and the seed is not touched again.
        let Some(account) = public_at(&master, &[p, coin, acct], &mut busy, ui.panel) else {
            continue;
        };
        for i in 0..SHOWN {
            busy.tick(ui.panel);
            let Some((chain, index)) = ChildNumber::normal(0).ok().zip(ChildNumber::normal(i).ok())
            else {
                continue;
            };
            // No `keywork::run` here: below the account everything is unhardened, so
            // this is public-key arithmetic and the seed is not involved.
            let Some(line) = (|| {
                let leaf = account.derive_child(chain).ok()?.derive_child(index).ok()?;
                let mut buf = [0u8; catcard_wallet::address::MAX_ADDRESS_LEN];
                let n = catcard_wallet::address::encode(
                    kind,
                    crate::prefs::network(),
                    &leaf.public_key,
                    &mut buf,
                )
                .ok()?;
                let mut s: heapless::String<96> = heapless::String::new();
                let _ = write!(s, ".../0/{i}  {}", core::str::from_utf8(&buf[..n]).ok()?);
                Some(s)
            })() else {
                continue;
            };
            let _ = writeln!(text, "{line}");
        }
    }
    let signer = signer_for(
        master,
        crate::export::Signing::account(44, 0, AddressKind::P2pkh),
    );

    let mut path: heapless::String<24> = heapless::String::new();
    let _ = write!(path, "/{a:02X}{b:02X}{c:02X}{d:02X}-SUMMARY.TXT");
    offer_export(
        ui,
        HEAD,
        &path,
        text.as_bytes(),
        catcard_bbqr::FileType::UNICODE,
        signer,
    );
}

/// Derive → Import key: take a key in from outside and work in it for this session.
///
/// Nothing is stored: the stored seed is untouched, and a reboot comes up in it again.
/// That is what makes this safe to offer beside the wallet in use -- and what makes
/// Danger zone → Seed tools → Lock down seed the deliberate second step for someone who
/// meant to replace the stored one.
///
/// Returns whether a key is now in force; the caller names it.
fn import_key(ui: &mut Ui<'_>) -> bool {
    use catcard_wallet::bip32::ExtendedPrivKey;
    use zeroize::Zeroize as _;
    const HEAD: &str = "Import key";

    let Some(row) = pick_row(ui, HEAD, "for this session", &["Words", "XPRV", "WIF key"]) else {
        return false;
    };
    match row {
        0 => {
            message(ui.panel, HEAD, "enter each word,", "then y y to finish");
            wait_for_any_key(ui);
            let Some(mnemonic) = read_phrase(ui) else {
                return false;
            };
            let mut what = Line::new();
            let _ = write!(what, "{} words, checksum ok", mnemonic.word_count());
            ask(ui.panel, "Work in this?", &what, "the stored seed stays");
            if !confirmed(ui) {
                return false;
            }
            if !crate::key::set_temporary(mnemonic.entropy(), "Words") {
                message(ui.panel, HEAD, "that seed length", "is not usable");
                wait_for_any_key(ui);
                return false;
            }
            true
        }
        1 => {
            let Some(entry) = crate::passphrase::read(ui, "XPRV") else {
                return false;
            };
            // Parsed inside the masked region: what it decodes to is a private key.
            let parsed = crate::keywork::run(|kw| {
                ExtendedPrivKey::from_base58(entry.as_str().trim(), kw)
                    .ok()
                    .map(|key| (key.chain_code, *key.secret_bytes()))
            });
            let Some((chain_code, mut secret)) = parsed else {
                message(ui.panel, HEAD, "not an xprv", "check what was typed");
                wait_for_any_key(ui);
                return false;
            };
            let loaded = crate::key::set_temporary_xprv(&chain_code, &secret, "XPRV");
            secret.zeroize();
            if !loaded {
                message(ui.panel, HEAD, "that key is not usable", "");
                wait_for_any_key(ui);
            }
            loaded
        }
        _ => {
            let Some(entry) = crate::passphrase::read(ui, "WIF key") else {
                return false;
            };
            let mut raw = [0u8; 40];
            let decoded =
                catcard_wallet::encoding::base58::decode_check(entry.as_str().trim(), &mut raw);
            // A mainnet key, compressed or not: `0x80`, the scalar, and the compression
            // byte where the key is used compressed. Every address this device shows is
            // from a compressed key, so an uncompressed WIF is refused rather than shown
            // against addresses its owner would not recognise.
            let loaded = match decoded {
                Ok(34) if raw[0] == 0x80 && raw[33] == 0x01 => {
                    let mut key = [0u8; 32];
                    key.copy_from_slice(&raw[1..33]);
                    let ok = crate::key::set_temporary_wif(&key, "WIF");
                    key.zeroize();
                    ok
                }
                Ok(33) if raw[0] == 0x80 => {
                    message(ui.panel, HEAD, "uncompressed WIF", "not supported");
                    wait_for_any_key(ui);
                    raw.zeroize();
                    return false;
                }
                _ => false,
            };
            raw.zeroize();
            if !loaded {
                message(ui.panel, HEAD, "not a mainnet WIF", "check what was typed");
                wait_for_any_key(ui);
            }
            loaded
        }
    }
}

/// Act on one row of [`KEY_ITEMS`]: change the wallet the device works in.
///
/// The new wallet's fingerprint is shown before anything else uses it. That is the
/// whole safety property of this screen: every passphrase and every BIP-85 index gives
/// a *valid* wallet, so there is nothing for the device to reject and a mistyped index
/// is not an error -- it is a different, empty wallet that behaves perfectly normally.
/// Naming the one you landed in is the only defence there is.
fn choose_key(gate: &Callgate, login: &mut catcard_pin::Login, ui: &mut Ui<'_>, which: u8) {
    use crate::key::Source;

    const HEAD: &str = "Derive";
    let Some(row) = key_items().get(which as usize).copied() else {
        return;
    };

    let was = crate::key::in_force();
    match row {
        "Back to root" => crate::key::to_root(),
        // A key from outside, for this session: words, a node, or a single key. Stock's
        // Temporary Seed, which it reaches from its own menu.
        // Source: hw-reference/menu-map-mk4-mk5-q1-v5.6.2.md §S1 [C]
        "Import key" => {
            if !import_key(ui) {
                return;
            }
        }
        "BIP-85" => {
            use crate::derive::Chosen;
            let Some(child) = crate::derive::bip85(gate, login, ui) else {
                return;
            };
            // A words child is loaded by its place in the tree and derived again when
            // needed; an XPRV or WIF child is its key, held for the session.
            let loaded = match &child {
                Chosen::Words { words, index } => {
                    crate::key::set(Source::Bip85 {
                        words: *words,
                        index: *index,
                    });
                    true
                }
                Chosen::Xprv { chain_code, key } => {
                    crate::key::set_temporary_xprv(chain_code, key, "BIP85 XPRV")
                }
                Chosen::Wif { key } => crate::key::set_temporary_wif(key, "BIP85 WIF"),
            };
            drop(child);
            if !loaded {
                message(ui.panel, HEAD, "that key is not usable", "unchanged");
                wait_for_any_key(ui);
                return;
            }
        }
        _ => return,
    }

    // A single key has no master to take a fingerprint of. What names it instead is its
    // own: the first four bytes of its hash160, which is what BIP-32 would call this key's
    // fingerprint if it were a node. It keeps no settings file.
    if let Some(key) = crate::key::temporary_wif() {
        let fp = crate::keywork::run(|kw| {
            catcard_wallet::bip32::public_key_of(key, kw)
                .map(|pk| catcard_wallet::bip32::hash160(&pk))
        });
        let Some(id) = fp else {
            crate::key::set(was);
            message(ui.panel, HEAD, "that key is not usable", "unchanged");
            wait_for_any_key(ui);
            return;
        };
        let [a, b, c, d] = [id[0], id[1], id[2], id[3]];
        let mut said: heapless::String<24> = heapless::String::new();
        let _ = write!(said, "{a:02X}{b:02X}{c:02X}{d:02X}");
        // The label, never the fingerprint: the log is readable by any host.
        crate::catlog!("key: now WIF ({})", crate::key::label());
        #[cfg(feature = "board-q1")]
        crate::pubkeys::note_fingerprint(Some([a, b, c, d]));
        message(ui.panel, HEAD, &said, crate::key::label());
        wait_for_any_key(ui);
        return;
    }

    // Derive it now, so the fingerprint on screen is this wallet's and not a promise.
    // A failure puts the old selection back rather than leaving the device somewhere
    // neither the owner nor the status bar can name.
    match master_quietly(gate, login, ui.panel, HEAD) {
        Ok(master) => {
            let [a, b, c, d] = crate::keywork::run(|kw| master.fingerprint(kw));
            drop(master);
            let mut said: heapless::String<24> = heapless::String::new();
            let _ = write!(said, "{a:02X}{b:02X}{c:02X}{d:02X}");
            crate::catlog!("key: now ({})", crate::key::label());
            #[cfg(not(feature = "board-mk3"))]
            crate::settings::open_wallet(gate, login, ui.panel, HEAD, [a, b, c, d]);
            message(ui.panel, HEAD, &said, crate::key::label());
        }
        Err(why) => {
            crate::key::set(was);
            message(ui.panel, HEAD, why, "unchanged");
        }
    }
    wait_for_any_key(ui);
}

/// Debug: run the DMA-driven bar around a real callgate, to be watched.
///
/// `fetch_secret` is callgate 18/4, which holds the CPU inside the bootloader with
/// interrupts masked for about as long as a PIN check does -- the exact condition the bar
/// exists for, and one that leaves SPI1, the LCD and DMA alone (docs/CALLGATE-DMA.md).
/// What comes back is zeroized at once. Then another second and a half with the CPU free,
/// so the motion can be seen for longer than the call lasts.
#[cfg(feature = "board-q1")]
fn sweep_test(gate: &Callgate, login: &mut catcard_pin::Login, ui: &mut Ui<'_>) {
    use zeroize::Zeroize as _;
    const HEAD: &str = "Sweep test";

    message(ui.panel, HEAD, "a blue bar should move", "along the bottom");
    let started = display::start_sweep(ui.panel);
    crate::catlog!("sweep: test started: {}", started);
    if !started {
        message(ui.panel, HEAD, "it did not start", "see the log");
        wait_for_any_key(ui);
        return;
    }
    let pin_gate = crate::pinentry::BootloaderGate::new(gate);
    // SAFETY: reads RCC only.
    let per_ms = (unsafe { catcard_hal::clock::hclk_hz() } / 1000).max(1);
    let t0 = catcard_hal::dwt::cycles();
    let fetched = login.fetch_secret(&pin_gate);
    let ms = catcard_hal::dwt::cycles().wrapping_sub(t0) / per_ms;
    let ok = match fetched {
        Ok(mut s) => {
            s.zeroize();
            true
        }
        Err(_) => false,
    };
    // SAFETY: reads RCC only.
    unsafe { catcard_hal::dwt::delay_ms(1500) };
    crate::catlog!("sweep: callgate 18/4 took {} ms, ok {}", ms, ok);
    // Drawing stops it and gives SPI1 back.
    message(ui.panel, HEAD, "did the bar move?", "any key to go back");
    wait_for_any_key(ui);
}

/// A one-question list, returning the row chosen.
///
/// For a choice made *inside* an action, where turning it into another `Screen` would
/// mean unwinding and redoing whatever the action has already derived. Works on every
/// board, unlike [`choose`], because a document renders at whatever size the panel is.
pub(crate) fn pick_row(ui: &mut Ui<'_>, head: &str, note: &str, items: &[&str]) -> Option<usize> {
    use catcard_ui::scroll::Line as DLine;
    let mut lines: heapless::Vec<DLine, 20> = heapless::Vec::new();
    let _ = lines.push(DLine::title(head));
    if !note.is_empty() {
        let _ = lines.push(DLine::body(note).small());
    }
    for (i, s) in items.iter().enumerate() {
        let _ = lines.push(DLine::item(s, i as u32));
    }
    match show_doc(ui, &lines, false, false) {
        DocExit::Selected(i) => Some(i as usize),
        _ => None,
    }
}

/// The index of a BIP-85 child, typed.
///
/// **Typed, not stepped.** The index used to be nudged one at a time with two arrow keys,
/// which is fine for child 3 and useless for the birthday or the year people actually
/// use -- and the arrows on the numpad boards are digit keys, so a field that took both
/// could not tell them apart.
///
/// Both halves of the choice are on screen: `what` (the kind of child) as a row that is
/// not live, the index under it with the caret. An empty field is index zero, which is the
/// child almost everyone means, so the common case is one press of the accept key.
pub(crate) fn ask_index(ui: &mut Ui<'_>, head: &str, what: &str) -> Option<u32> {
    ask_number(ui, head, Some(("child", what)), "index", "")
}

/// [`ask_index`] with the rows named by the caller.
///
/// The BIP-85 screen asks for the index of a *child*, and shows which kind of child above
/// the field. The address explorer asks for an account number and for the index its walk
/// starts at: one number, no context row, and "child" would be a word borrowed from a
/// different screen. So both labels travel with the caller, and `above` is `None` where
/// there is nothing to say above the field.
///
/// `note`, when it is not empty, replaces the "digits, then accept" footer: the place to
/// say what an empty field means here.
pub(crate) fn ask_number(
    ui: &mut Ui<'_>,
    head: &str,
    above: Option<(&str, &str)>,
    value_label: &str,
    note: &str,
) -> Option<u32> {
    use catcard_ui::canvas::Canvas as _;
    use catcard_ui::field::{self, Accept, Field, Input};
    use catcard_ui::text::{centred, draw_text};

    /// The path's last element is hardened, so the range is 0 to 2^31 - 1: ten digits.
    const MAX_DIGITS: usize = 10;
    const LIMIT: u32 = 0x7FFF_FFFF;
    let top_y = display::FIELD_TOP;

    let mut input = Input::<MAX_DIGITS>::new(Accept::Digits, MAX_DIGITS);
    // Sized for what the index can hold, ten digits, not for the width of the panel --
    // or for the kind above it, where that is longer. Both rows say so because the card
    // is one box and takes its widest row.
    let width = MAX_DIGITS.max(above.map_or(0, |(_, what)| what.len()));
    let mut events = [Event::Pressed(Key::Cancel); KEYS];
    let mut keys: heapless::Vec<Key, { KEYS + 1 }> = heapless::Vec::new();
    // Said only once it has happened, so the screen is not shouting a rule at someone
    // who has not broken it.
    let mut complaint = "";

    loop {
        // The rows are built and drawn inside a block of their own: a `Vec` of them has a
        // `Drop`, so its borrow of the input would otherwise run to the end of the loop
        // body -- where the keys typing into that input are read.
        {
            // Two rows where there is context to show, one where there is not: a card
            // with an empty row on it reads as a field that failed to draw.
            let mut fields: heapless::Vec<Field<'_>, 2> = heapless::Vec::new();
            if let Some((label, what)) = above {
                let _ = fields.push(Field::text(label, what).max(width));
            }
            let _ = fields.push(
                Field::text(value_label, input.as_str())
                    .max(width)
                    .live(true),
            );
            let body = display::LAYOUT.body;
            let foot = match (complaint.is_empty(), note.is_empty()) {
                (false, _) => complaint,
                (true, false) => note,
                (true, true) => "digits, then accept",
            };
            display::draw_field_page(ui.panel, |c| {
                c.clear();
                let hx = centred(body, head, c.width());
                draw_text(
                    c,
                    body,
                    hx,
                    top_y.saturating_sub(body.line_height() + 6),
                    head,
                );
                let below = field::stack(
                    c,
                    &display::LAYOUT,
                    top_y,
                    &fields,
                    display::FIELD_SKIN,
                    true,
                );
                let fx = centred(body, foot, c.width());
                draw_text(c, body, fx, below + 6, foot);
            });
        }
        wait_for_release(ui);

        let mut redraw = false;
        while !redraw {
            let _ = usbtask::pump();
            crate::pinentry::pressed_keys(ui.pad, ui.matrix, ui.drbg, &mut events, &mut keys);
            for k in keys.iter() {
                match k {
                    // Nothing typed is index zero: the child almost everyone means.
                    Key::Confirm => match (input.is_empty(), input.value()) {
                        (true, _) => return Some(0),
                        (_, Some(v)) if v <= LIMIT => return Some(v),
                        // Out of range, or more digits than a u32 holds. Refused rather
                        // than clamped: a clamped index is a different wallet, and the
                        // only person who finds out is the one who lost theirs.
                        _ => {
                            complaint = "too big: max 2147483647";
                            redraw = true;
                        }
                    },
                    Key::Cancel => {
                        if !input.backspace() {
                            return None;
                        }
                        complaint = "";
                        redraw = true;
                    }
                    Key::Digit(d) => {
                        if !input.put((b'0' + d) as char) {
                            complaint = "ten digits is the most";
                        }
                        redraw = true;
                    }
                    // A keyboard's letters, which this field does not take. `put`
                    // refuses them; saying so beats a key that appears to do nothing.
                    Key::Qr => {}
                    Key::Char(c) => {
                        if !input.put(*c as char) {
                            complaint = "digits only";
                        }
                        redraw = true;
                    }
                }
            }
            if !redraw {
                display::idle(ui.panel);
            }
        }
    }
}

/// Ask which of `items` to use, or `None` if the user backs out.
///
/// A small list with a cursor, for a choice made **inside** an action rather than by
/// navigating to it. The export destination is one: by the time it is asked, the keys
/// have been derived and the payload exists, so turning it into another `Screen` would
/// mean deriving them again on the way back.
///
/// The Q1's scan offers what it read this way, the NFC receive screen does the same, and
/// the SD card-password screen picks its operation with it -- the last of which is on the
/// mk3 too, so this is no longer gated off that board.
pub(crate) fn choose(ui: &mut Ui<'_>, head: &str, note: &str, items: &[&str]) -> Option<usize> {
    use catcard_ui::menu::Scroll;

    let mut cursor = 0usize;
    let mut events = [Event::Pressed(Key::Cancel); KEYS];
    let mut keys: heapless::Vec<Key, { KEYS + 1 }> = heapless::Vec::new();
    loop {
        display::draw(ui.panel, |c| {
            catcard_ui::widgets::menu(
                c,
                &display::LAYOUT,
                head,
                note,
                items,
                Scroll { cursor, top: 0 },
            );
        });
        wait_for_release(ui);
        loop {
            let _ = usbtask::pump();
            crate::pinentry::pressed_keys(ui.pad, ui.matrix, ui.drbg, &mut events, &mut keys);
            let mut moved = false;
            for k in keys.iter() {
                match k {
                    Key::Confirm => return Some(cursor),
                    Key::Cancel => return None,
                    // The same two keys that move every other list here.
                    Key::Digit(8) if cursor + 1 < items.len() => {
                        cursor += 1;
                        moved = true;
                    }
                    Key::Digit(5) if cursor > 0 => {
                        cursor -= 1;
                        moved = true;
                    }
                    _ => {}
                }
            }
            if moved {
                break;
            }
            display::idle(ui.panel);
        }
    }
}

/// Where an export should go.
///
/// Stock offers QR, NFC and the card for every export, and the choice matters more than
/// it looks: a card is the only one that leaves a file behind, and a QR is the only one
/// that needs nothing but a phone. The device with no card in it and no cable is the
/// case this exists for.
#[cfg(feature = "board-q1")]
fn offer_export(
    ui: &mut Ui<'_>,
    head: &str,
    file: &str,
    body: &[u8],
    kind: catcard_bbqr::FileType,
    signer: Option<Signer>,
) {
    // A list, not a yes/no. Three destinations that are not ranked -- a card for a
    // computer, BBQr for wallets that read it, BC-UR for everything else -- and cancel
    // means none of them rather than one of them.
    const WAYS: &[&str] = &["SD card", "BBQr", "BC-UR"];
    // The signature is a card-only thing: a QR carries the same bytes and no signature,
    // because there is nowhere alongside it to put one. So every path but the card drops
    // the key first, before a screen that stays up until someone walks away from it.
    match choose(ui, head, "how to export", WAYS) {
        Some(0) => write_export(ui, head, file, body, signer),
        Some(1) => {
            drop(signer);
            crate::qrshow::animate_bbqr(ui, head, body, kind);
        }
        #[cfg(feature = "multichain")]
        Some(2) => {
            drop(signer);
            crate::qrshow::animate_bytes_ur(ui, head, body);
        }
        _ => drop(signer),
    }
}

/// mk3 and mk4 have no scanner and no screen for this; the card is the only way out.
#[cfg(not(feature = "board-q1"))]
fn offer_export(
    ui: &mut Ui<'_>,
    head: &str,
    file: &str,
    body: &[u8],
    _kind: catcard_bbqr::FileType,
    signer: Option<Signer>,
) {
    write_export(ui, head, file, body, signer);
}

/// Write an export to the card and say how it went.
///
/// The same three outcomes every time -- written, refused, or the card was not there --
/// said the same way, because an export that fails differently each time is one nobody
/// can help with.
fn write_export(ui: &mut Ui<'_>, head: &str, path: &str, body: &[u8], signer: Option<Signer>) {
    card_wait(ui.panel, head, "writing to the card");
    match write_card_export(path, body, signer) {
        Ok(name) => {
            // The kind and the size, not the name: one export's name carries the
            // fingerprint, and the log is readable by any host.
            crate::catlog!("export: wrote {} bytes ({})", body.len(), head);
            message(ui.panel, "Exported", &name[1..], "any key to go back");
        }
        Err(why) => {
            let (phase, sta, detail) = catcard_hal::sdmmc::last_failure::get();
            crate::catlog!(
                "export: failed: {}; sd last {} sta {:08x} detail {}",
                why,
                catcard_hal::sdmmc::last_failure::name(phase),
                sta,
                detail
            );
            message(ui.panel, "Export failed", why, "any key to go back");
        }
    }
    wait_for_any_key(ui);
}

/// The longest export filename, with room for a collision number.
pub(crate) const EXPORT_NAME_MAX: usize = 40;

/// Write an export and, when there is a key for it, its detached signature.
///
/// Returns the name actually used, which is not always the one asked for.
///
/// **Nothing is overwritten.** If `path` is taken the file goes to `base-2.ext`, then
/// `base-3.ext` and so on. Stock does this and it matters more here than it looks: two
/// exports of the same wallet at different accounts, or of two different wallets, land on
/// the same filename, and silently replacing the first one destroys a file someone may
/// have been about to use.
///
/// Source: hw-reference/wallet-export-formats.md §"Filenames, output channels, and
/// signing" [C] -- including that the first collision yields `-2`, not `-1`.
pub(crate) fn write_card_export(
    path: &str,
    body: &[u8],
    signer: Option<Signer>,
) -> Result<heapless::String<EXPORT_NAME_MAX>, &'static str> {
    let mut vol = mount_card()?;

    let name = unused_name(&mut vol, path)?;

    write_into(&mut vol, &name, body)?;

    // The signature covers the name that was actually used, so it is built here rather
    // than by the caller: the caller does not know yet what the file will be called.
    if let Some(signer) = signer {
        let basename = name.strip_prefix('/').unwrap_or(&name);
        let mut armoured: heapless::String<{ crate::export::MAX_SIG_LEN }> =
            heapless::String::new();
        crate::export::signature_file(
            &signer.master,
            &signer.signing,
            body,
            basename,
            &mut armoured,
        )?;
        let stem = name.rsplit_once('.').map(|(s, _)| s).unwrap_or(&name);
        let mut sig_name: heapless::String<EXPORT_NAME_MAX> = heapless::String::new();
        write!(sig_name, "{stem}.sig").map_err(|_| "name too long")?;
        write_into(&mut vol, &sig_name, armoured.as_bytes())?;
    }

    vol.flush().map_err(|_| "flush failed")?;
    Ok(name)
}

/// The first name of this shape that nothing on the card is using.
///
/// `base.ext`, then `base-2.ext`, `base-3.ext`. Bounded, because an unbounded search on
/// a card with a corrupt directory would spin forever, and a hundred files under one
/// name is already more than anyone has.
fn unused_name(
    vol: &mut CardVolume,
    path: &str,
) -> Result<heapless::String<EXPORT_NAME_MAX>, &'static str> {
    let (stem, ext) = match path.rsplit_once('.') {
        Some((stem, ext)) => (stem, ext),
        None => (path, ""),
    };
    let mut name: heapless::String<EXPORT_NAME_MAX> = heapless::String::new();
    name.push_str(path).map_err(|_| "name too long")?;
    for n in 2..100 {
        if vol.open_file(&name).is_err() {
            return Ok(name);
        }
        name.clear();
        write!(name, "{stem}-{n}").map_err(|_| "name too long")?;
        if !ext.is_empty() {
            write!(name, ".{ext}").map_err(|_| "name too long")?;
        }
    }
    Err("too many of those already")
}

/// Write several pieces to one new file, in order, and return the name used.
///
/// For a payload that is not one buffer and could not be: the settings region is half a
/// megabyte of memory-mapped flash, so it goes to the card as a slice over the flash
/// itself rather than through a copy this device has nowhere to put.
///
/// Not mk3: its settings are raw SPI-NOR slots, not a region that can be sliced, and
/// the state dump is compiled out there for the same reason. Bench builds only, with
/// the dump: it is the only caller.
#[cfg(all(not(feature = "board-mk3"), feature = "usb-debug-mem"))]
pub(crate) fn write_card_parts(
    path: &str,
    parts: &[&[u8]],
) -> Result<heapless::String<EXPORT_NAME_MAX>, &'static str> {
    let mut vol = mount_card()?;
    let name = unused_name(&mut vol, path)?;
    let mut file = vol
        .open_or_create_file(&name)
        .map_err(|_| "could not open file")?;
    for part in parts {
        file.write_all(&mut vol, part).map_err(|_| "write failed")?;
    }
    file.flush(&mut vol).map_err(|_| "flush failed")?;
    vol.flush().map_err(|_| "flush failed")?;
    Ok(name)
}

/// The seed, kept just long enough to sign an export's detached signature.
///
/// It exists because the signature covers the filename, and the filename is only settled
/// once the card has been looked at -- so the key cannot be finished with before the
/// destination is known. It goes no further than that: [`offer_export`] drops it the
/// moment a QR destination is chosen, because an animation stays up until someone walks
/// away from it and a master key should not be waiting in RAM for that.
pub(crate) struct Signer {
    master: catcard_wallet::bip32::ExtendedPrivKey,
    signing: crate::export::Signing,
}

/// Pair a master key with where its export's signature comes from.
///
/// `None` if the derivation could not even be described, which leaves the export
/// unsigned rather than unwritten: a file without its sidecar is still the file someone
/// asked for.
fn signer_for(
    master: catcard_wallet::bip32::ExtendedPrivKey,
    signing: Option<crate::export::Signing>,
) -> Option<Signer> {
    Some(Signer {
        master,
        signing: signing?,
    })
}

/// The stored BIP-39 wallet's master key, for a screen titled `head`: the secret fetched,
/// the words stretched into a seed, the seed into the master key -- with the screen saying
/// what is happening at each step.
///
/// `None` once the user has been told why not: the secret could not be read, the slot holds
/// no BIP-39 wallet (and which kind it does hold), or derivation failed. The returned key
/// zeroizes itself when dropped; hold it only as long as the screen needs it.
pub(crate) fn unlock_master(
    gate: &Callgate,
    login: &mut catcard_pin::Login,
    ui: &mut Ui<'_>,
    head: &str,
) -> Option<catcard_wallet::bip32::ExtendedPrivKey> {
    match master_quietly(gate, login, ui.panel, head) {
        Ok(master) => Some(master),
        Err(why) => {
            message(ui.panel, head, why, "any key to go back");
            wait_for_any_key(ui);
            None
        }
    }
}

/// What the secure element's slot holds.
///
/// Three shapes, all of them a wallet: the words' entropy, a BIP-32 node, or a raw master
/// secret. Stock writes all three (hw-reference/secret-stash-format.md §Layout [C]), so a
/// device that has run stock can arrive with any of them, and a firmware that understood
/// only the first said "not yet" to a wallet it was holding.
pub(crate) enum Stored {
    /// BIP-39 entropy: the only shape with words to write down.
    Words { entropy: [u8; 32], len: usize },
    /// A node. It *is* the master -- nothing to stretch, and no words.
    Xprv { chain_code: [u8; 32], key: [u8; 32] },
    /// Bytes fed straight into BIP-32's master step.
    Raw { bytes: [u8; 64], len: usize },
}

impl Drop for Stored {
    fn drop(&mut self) {
        use zeroize::Zeroize as _;
        match self {
            Stored::Words { entropy, .. } => entropy.zeroize(),
            Stored::Xprv { chain_code, key } => {
                chain_code.zeroize();
                key.zeroize();
            }
            Stored::Raw { bytes, .. } => bytes.zeroize(),
        }
    }
}

impl Stored {
    /// What a screen calls this, for a refusal that names what is there.
    fn what(&self) -> &'static str {
        match self {
            Stored::Words { .. } => "these words",
            Stored::Xprv { .. } => "an XPRV",
            Stored::Raw { .. } => "a raw master",
        }
    }
}

/// The BIP-39 entropy of the wallet in force, with a progress screen.
///
/// The secret the secure element holds, or -- when a BIP-85 child is in force -- that
/// child's own entropy, which is a different seed derived from the same backup. Not the
/// master key and not the passphrase: this is the *words*, which is what a seed backup,
/// a split or a word list is made of. A wallet with no words -- a loaded XPRV or WIF key,
/// a stored node or raw master -- says so.
///
/// Its own function because two things want it and they must not disagree:
/// [`master_quietly`], which stretches it into a key, and Seed XOR, which cuts it up.
pub(crate) fn seed_entropy(
    gate: &Callgate,
    login: &mut catcard_pin::Login,
    panel: &mut display::Panel,
    head: &str,
) -> Result<([u8; 32], usize), &'static str> {
    use crate::key::Loaded;

    // A key the owner brought in for this session is the wallet, and it is already
    // here: nothing to fetch, and no child to derive -- it is not a child of anything.
    match crate::key::loaded() {
        Some(Loaded::Words) => {
            let mut ent = [0u8; 32];
            let temp = crate::key::temporary().ok_or("no key loaded")?;
            ent[..temp.len()].copy_from_slice(temp);
            return Ok((ent, temp.len()));
        }
        Some(Loaded::Xprv) => return Err("an XPRV has no words"),
        Some(Loaded::Wif) => return Err("a WIF key has no words"),
        None => {}
    }

    // The wallet in force may not be the one the secure element holds: a BIP-85 child
    // is a separate seed derived from the same backup, and every screen has to land in
    // the same one.
    //
    // Source: hw-reference/menu-map-mk4-mk5-q1-v5.6.2.md §S1 [C]
    if let crate::key::Source::Bip85 { words, index } = crate::key::in_force() {
        let master = bip85_parent(gate, login, panel, head)?;
        let mut busy = Working::seed(panel, head, "deriving the key");
        let child = crate::keywork::run(|kw| {
            let (child, len) = catcard_wallet::bip85::words_entropy(&master, words, index, kw)
                .map_err(|_| "that child does not derive")?;
            let mut ent = [0u8; 32];
            ent[..len].copy_from_slice(&child.as_bytes()[..len]);
            Ok::<([u8; 32], usize), &'static str>((ent, len))
        });
        busy.tick(panel);
        return child;
    }

    match root_stored(gate, login, panel, head)? {
        Stored::Words { entropy, len } => Ok((entropy, len)),
        // Both are wallets this firmware can work in; neither has words to hand back.
        other => Err(match other {
            Stored::Xprv { .. } => "the stored key is an XPRV: no words",
            _ => "the stored key is raw: no words",
        }),
    }
}

/// What the secure element holds, whatever shape it is in.
///
/// The reading-seed screen first, then the fetch -- one callgate call during which the
/// bootloader runs the PIN key-stretch inside the secure element, about 1.6 s on an mk4,
/// with the CPU unable to repaint.
fn root_stored(
    gate: &Callgate,
    login: &mut catcard_pin::Login,
    panel: &mut display::Panel,
    head: &str,
) -> Result<Stored, &'static str> {
    use zeroize::Zeroize;

    reading_seed(panel, head);
    let pin_gate = crate::pinentry::BootloaderGate::new(gate);
    let mut secret = login
        .fetch_secret(&pin_gate)
        .map_err(|_| "could not read seed")?;
    let stored = stored_from_secret(&secret);
    secret.zeroize();
    stored
}

/// Classify an already-fetched secret into what it holds, **without fetching**.
///
/// The marker-byte classification and the `note_stored_seed` bookkeeping that
/// [`root_stored`] does once it has the bytes -- pulled out so a caller that has fetched
/// the stash for another reason (the login-time prime, which fetches once and derives both
/// the settings key and the fingerprint from it) reaches the identical `Stored` without a
/// second `fetch_secret`. The bytes are copied into the `Stored`, which owns and wipes
/// them; the caller still owns and must wipe the `secret` it passed in.
pub(crate) fn stored_from_secret(
    secret: &[u8; catcard_callgate::pin::SECRET_LEN],
) -> Result<Stored, &'static str> {
    use catcard_callgate::pin::{
        SecretKind, bip39_entropy, classify_secret, raw_master, xprv_parts,
    };

    // Copied out so the secret can be wiped at once, and classified by its marker byte:
    // what the slot holds decides what every screen above can offer.
    let stored = if let Some(e) = bip39_entropy(secret).filter(|e| e.len() <= 32) {
        let mut entropy = [0u8; 32];
        entropy[..e.len()].copy_from_slice(e);
        Some(Stored::Words {
            entropy,
            len: e.len(),
        })
    } else if let Some((chain_code, key)) = xprv_parts(secret) {
        Some(Stored::Xprv {
            chain_code: *chain_code,
            key: *key,
        })
    } else if let Some(raw) = raw_master(secret).filter(|r| r.len() <= 64) {
        let mut bytes = [0u8; 64];
        bytes[..raw.len()].copy_from_slice(raw);
        Some(Stored::Raw {
            bytes,
            len: raw.len(),
        })
    } else {
        None
    };
    let kind = classify_secret(secret);

    // Empty means the slot holds nothing, whatever the login's flag said: a destroyed
    // seed leaves zeros behind with the flag still set.
    crate::key::note_stored_seed(!matches!(kind, SecretKind::Empty));
    match stored {
        Some(stored) => {
            crate::catlog!("wallet: stored secret is {:?}", kind);
            Ok(stored)
        }
        None => {
            crate::catlog!("wallet: secret is {:?}, not a wallet", kind);
            Err(match kind {
                SecretKind::Empty => "no wallet stored",
                _ => "unknown wallet type",
            })
        }
    }
}

/// BIP-39 entropy to its BIP-32 master **with no passphrase**, inside the masked region.
pub(crate) fn plain_master(
    entropy: &[u8],
    kw: &catcard_wallet::KeyWork,
) -> Result<catcard_wallet::bip32::ExtendedPrivKey, &'static str> {
    use catcard_wallet::bip32::ExtendedPrivKey;
    use catcard_wallet::bip39::{Mnemonic, SEED_LEN};
    use zeroize::Zeroize;

    let root = Mnemonic::from_entropy(entropy, kw).map_err(|_| "seed did not decode")?;
    let mut seed = [0u8; SEED_LEN];
    root.to_seed("", &mut seed, kw)
        .map_err(|_| "key derivation failed")?;
    let master = ExtendedPrivKey::from_seed(&seed, crate::prefs::network(), kw)
        .map_err(|_| "key derivation failed");
    seed.zeroize();
    master
}

/// The stored wallet's master key, **without** its passphrase, whichever shape it is in.
///
/// The key every BIP-85 child comes from, and what a screen wants when it needs the root
/// rather than the wallet in force. The passphrase belongs to the wallet finally in force,
/// not to the path taken to reach it -- applying it on the way down as well would give a
/// wallet nothing else agrees with.
pub(crate) fn root_master(
    gate: &Callgate,
    login: &mut catcard_pin::Login,
    panel: &mut display::Panel,
    head: &str,
) -> Result<catcard_wallet::bip32::ExtendedPrivKey, &'static str> {
    use catcard_wallet::bip32::ExtendedPrivKey;

    let stored = root_stored(gate, login, panel, head)?;
    let net = crate::prefs::network();
    let mut busy = Working::seed(panel, head, "deriving the key");
    let master = crate::keywork::run(|kw| match &stored {
        Stored::Words { entropy, len } => plain_master(&entropy[..*len], kw),
        // The node is the master already: no stretch, and nothing to derive it from. The
        // scalar is still checked: a stash that reads back as no usable key is reported,
        // not carried to the first derivation to abort there.
        Stored::Xprv { chain_code, key } => {
            ExtendedPrivKey::root_from_parts(net, *chain_code, *key, kw)
                .map_err(|_| "the stored key is not usable")
        }
        Stored::Raw { bytes, len } => {
            ExtendedPrivKey::from_seed(&bytes[..*len], net, kw).map_err(|_| "key derivation failed")
        }
    });
    busy.tick(panel);
    master
}

/// The key every BIP-85 child comes from: the root's master, without the passphrase.
///
/// The root rather than the key in force, so a child shown is the child [`seed_entropy`]
/// loads, and the same one again from any wallet the owner is in.
pub(crate) fn bip85_parent(
    gate: &Callgate,
    login: &mut catcard_pin::Login,
    panel: &mut display::Panel,
    head: &str,
) -> Result<catcard_wallet::bip32::ExtendedPrivKey, &'static str> {
    root_master(gate, login, panel, head)
}

/// The wallet in force's master key, with a progress screen but no dialogs.
///
/// The same work as [`unlock_master`] without the part that needs a person: it reports
/// why it could not rather than saying so and waiting for a key. For callers that are not
/// a screen -- warming the status bar's fingerprint after login, where a message box
/// would be an interruption nobody asked for, and a key wait would stall the device
/// behind a question about something the owner never requested.
///
/// A loaded XPRV, and a stored node or raw master, **are** the master: there is nothing to
/// stretch and no passphrase to apply, so one in force is refused rather than silently
/// ignored. A loaded WIF key has no master at all: every HD screen stops here, with the
/// reason, rather than inventing a chain code to derive something nobody else would find.
pub(crate) fn master_quietly(
    gate: &Callgate,
    login: &mut catcard_pin::Login,
    panel: &mut display::Panel,
    head: &str,
) -> Result<catcard_wallet::bip32::ExtendedPrivKey, &'static str> {
    use crate::key::{Loaded, Source};
    use catcard_wallet::bip32::ExtendedPrivKey;
    let net = crate::prefs::network();
    match crate::key::loaded() {
        Some(Loaded::Xprv) => {
            let (chain_code, key) = crate::key::temporary_xprv().ok_or("no key loaded")?;
            return crate::keywork::run(|kw| {
                ExtendedPrivKey::root_from_parts(net, *chain_code, *key, kw)
            })
            .map_err(|_| "the loaded key is not usable");
        }
        Some(Loaded::Wif) => return Err("a WIF key is not HD"),
        _ => {}
    }
    // The stored wallet itself, which may have no words to stretch. A BIP-85 child or a
    // loaded seed always has them, and goes the long way round.
    if crate::key::in_force() == Source::Root {
        let stored = root_stored(gate, login, panel, head)?;
        return master_from_stored(stored, panel, head);
    }
    with_seed(gate, login, panel, head, |seed, kw| {
        ExtendedPrivKey::from_seed(seed, net, kw).ok()
    })
}

/// Derive the root wallet's master key from an already-classified [`Stored`], with a
/// progress screen and no dialogs -- the passphrase guard and the three derivations that
/// [`master_quietly`] runs once the fetch has been classified.
///
/// Pulled out of [`master_quietly`] so a caller that already holds a `Stored` from one
/// fetch (the login-time prime) reaches the identical master without a second
/// `fetch_secret`. The Words arm stretches through the passphrase in force via
/// [`stretch_words`], exactly as before; each secret-bearing arm wipes its bytes once the
/// node is made.
pub(crate) fn master_from_stored(
    stored: Stored,
    panel: &mut display::Panel,
    head: &str,
) -> Result<catcard_wallet::bip32::ExtendedPrivKey, &'static str> {
    use catcard_wallet::bip32::ExtendedPrivKey;
    use zeroize::Zeroize as _;

    let net = crate::prefs::network();
    if !matches!(stored, Stored::Words { .. }) && crate::passphrase::is_set() {
        // A BIP-39 passphrase changes the seed words stretch to. There are no words
        // here, so a passphrase would change nothing -- and a wallet that ignored one
        // silently is a wallet the owner did not choose.
        return Err(match stored.what() {
            "an XPRV" => "no passphrase on an XPRV",
            _ => "no passphrase on a raw master",
        });
    }
    match stored {
        Stored::Words { mut entropy, len } => {
            stretch_words(panel, head, &mut entropy, len, |seed, kw| {
                ExtendedPrivKey::from_seed(seed, net, kw).ok()
            })
        }
        // The arrays are `Copy`, so these bindings are copies of the secret that
        // `Stored`'s Drop never sees; each is wiped once the node has been made.
        Stored::Xprv {
            mut chain_code,
            mut key,
        } => {
            let node = crate::keywork::run(|kw| {
                ExtendedPrivKey::root_from_parts(net, chain_code, key, kw)
            });
            chain_code.zeroize();
            key.zeroize();
            node.map_err(|_| "the stored key is not usable")
        }
        Stored::Raw { mut bytes, len } => {
            let node = crate::keywork::run(|kw| ExtendedPrivKey::from_seed(&bytes[..len], net, kw));
            bytes.zeroize();
            node.map_err(|_| "key derivation failed")
        }
    }
}

/// Run `then` on the wallet in force's BIP-39 seed -- the 64 bytes the words and the
/// passphrase stretch to -- inside the masked region, and return what it returns.
///
/// The seed never leaves: `then` runs in the same `keywork::run` that finishes the
/// stretch, and the seed is wiped before it returns. Every key there is comes from these
/// 64 bytes, and most of them from the BIP-32 master ([`master_quietly`]); SLIP-0010
/// chains such as Solana start again from the seed itself, which is why this exists.
pub(crate) fn with_seed<T>(
    gate: &Callgate,
    login: &mut catcard_pin::Login,
    panel: &mut display::Panel,
    head: &str,
    then: impl FnOnce(&[u8; catcard_wallet::bip39::SEED_LEN], &catcard_wallet::KeyWork) -> Option<T>,
) -> Result<T, &'static str> {
    let (mut ent, ent_len) = seed_entropy(gate, login, panel, head)?;
    stretch_words(panel, head, &mut ent, ent_len, then)
}

/// Stretch `entropy`'s words into the BIP-39 seed, through the passphrase in force, and
/// run `then` on it inside the same masked region. The entropy and the seed are both gone
/// before this returns.
///
/// Turning the words into a seed is PBKDF2-HMAC-SHA512 run 2048 times -- about a second of
/// hashing by design. That is far too long to hold one frame, so it runs in slices: masked
/// while a slice is in flight, the sweep moving underneath. The slices end at round counts
/// fixed here, never at anything derived from the seed, so what a watching host can see is
/// the iteration count BIP-39 publishes.
fn stretch_words<T>(
    panel: &mut display::Panel,
    head: &str,
    entropy: &mut [u8; 32],
    len: usize,
    then: impl FnOnce(&[u8; catcard_wallet::bip39::SEED_LEN], &catcard_wallet::KeyWork) -> Option<T>,
) -> Result<T, &'static str> {
    use catcard_wallet::bip39::{Mnemonic, SEED_LEN, Stretch};
    use zeroize::Zeroize;

    let mut busy = Working::seed(panel, head, "stretching the seed");
    let stretch = crate::keywork::run(|kw| {
        let mnemonic = Mnemonic::from_entropy(&entropy[..len], kw);
        entropy.zeroize();
        let Ok(mnemonic) = mnemonic else {
            return Err("seed did not decode");
        };
        // The BIP-39 passphrase in force, if any: it is part of the seed, so every screen
        // that derives from it follows it without asking.
        Stretch::begin(&mnemonic, crate::passphrase::active(), kw)
            .map_err(|_| "key derivation failed")
    });
    stretch.and_then(|mut stretch| {
        while !crate::keywork::run(|kw| stretch.step(STRETCH_SLICE, kw)) {
            busy.tick(panel);
        }
        crate::keywork::run(|kw| {
            let mut seed = [0u8; SEED_LEN];
            stretch.finish(&mut seed, kw);
            let out = then(&seed, kw);
            seed.zeroize();
            out.ok_or("key derivation failed")
        })
    })
}

/// Addresses: a list first -- the chains on a multichain build, "Browse addresses" on a
/// Bitcoin-only one -- and "Verify an address" last. Then that chain's addresses, or the
/// question.
///
/// Bitcoin keeps its own explorer, registered multisig wallets and all. Every other chain
/// gets [`chain_explorer`], which walks the formats its registry entry lists. Leaving an
/// explorer comes back to the list, and leaving the list leaves.
///
/// Verify sits here rather than among the tools: it answers "is this address mine?",
/// which is the question someone is asking when they open Addresses. Stock has it only
/// under NFC Tools (hw-reference/menu-map-mk4-mk5-q1-v5.6.2.md §ADV [C]), which this
/// firmware does not have.
fn addresses(gate: &Callgate, login: &mut catcard_pin::Login, ui: &mut Ui<'_>) {
    if crate::key::loaded() == Some(crate::key::Loaded::Wif) {
        return wif_addresses(gate, login, ui);
    }
    loop {
        match pick_addresses(gate, login, ui) {
            None => return,
            Some(AddressPick::Verify) => crate::verify::screen(gate, login, ui),
            Some(AddressPick::Custom) => custom_path(gate, login, ui),
            #[cfg(feature = "multichain")]
            Some(AddressPick::Chain(chain))
                if chain.id != catcard_wallet::chain::ChainId::Bitcoin =>
            {
                chain_explorer(gate, login, ui, chain)
            }
            Some(AddressPick::Chain(_)) => address_explorer(gate, login, ui),
        }
    }
}

/// What the Addresses list chose.
enum AddressPick {
    // Read only where there is more than Bitcoin to tell apart.
    Chain(
        #[cfg_attr(not(feature = "multichain"), allow(dead_code))]
        &'static catcard_wallet::chain::Chain,
    ),
    Verify,
    /// The address at a path the owner writes out themselves.
    Custom,
}

/// Most chains the Addresses list shows.
const CHAINS_LISTED: usize = 16;
#[cfg(feature = "multichain")]
const _: () = assert!(CHAINS_LISTED >= crate::chains::MAX);

/// The id the "Verify an address" row carries: past any chain's index.
const VERIFY_ROW: u32 = 1000;
/// The id the "Custom path" row carries.
const CUSTOM_PATH_ROW: u32 = 1001;

/// The Addresses list: the chains, or Bitcoin alone, then "Custom path" and "Verify an
/// address".
fn pick_addresses(
    gate: &Callgate,
    login: &mut catcard_pin::Login,
    ui: &mut Ui<'_>,
) -> Option<AddressPick> {
    use catcard_ui::scroll::Line as DLine;

    #[cfg(feature = "multichain")]
    let chains = crate::chains::enabled(gate, login, ui);
    #[cfg(not(feature = "multichain"))]
    let chains: &[&'static catcard_wallet::chain::Chain] = {
        let _ = (gate, login);
        &[&catcard_wallet::chain::BITCOIN]
    };
    // The title, every chain a build can list, and the two rows under them.
    let mut lines: heapless::Vec<DLine, { CHAINS_LISTED + 3 }> = heapless::Vec::new();
    let _ = lines.push(DLine::title("Addresses"));
    #[cfg(feature = "multichain")]
    for (i, c) in chains.iter().enumerate() {
        let _ = lines.push(chain_row(c, i as u32));
    }
    #[cfg(not(feature = "multichain"))]
    let _ = lines.push(DLine::item("Browse addresses", 0).large());
    // Under the chains, because it is not one: a path the owner writes out reaches any
    // key this seed has, whichever account or purpose it sits under.
    // Source: hw-reference/menu-map-mk4-mk5-q1-v5.6.2.md §AE "Custom Path" [C]
    let _ = lines.push(DLine::item("Custom path", CUSTOM_PATH_ROW).large());
    let _ = lines.push(DLine::item("Verify an address", VERIFY_ROW).large());
    match show_doc(ui, &lines, false, false) {
        DocExit::Selected(VERIFY_ROW) => Some(AddressPick::Verify),
        DocExit::Selected(CUSTOM_PATH_ROW) => Some(AddressPick::Custom),
        DocExit::Selected(i) => chains.get(i as usize).map(|c| AddressPick::Chain(c)),
        _ => None,
    }
}

/// Which chains this wallet offers, and in what order.
///
/// One screen doing two jobs, because they are the same decision: a chain that is off is
/// simply not in the list, and where a chain sits decides where it appears in every
/// picker afterwards. So the list on screen *is* the stored list, with the chains that
/// are off shown underneath it rather than hidden -- turning one on has to be possible
/// from the same place.
///
/// `OK` turns the row under the cursor on or off, `7` and `9` move it, and `X` saves and
/// leaves. Saving on the way out rather than per keypress is deliberate: reordering a
/// list is several presses that only mean something together, and a write per press
/// would put five versions of a half-finished order through the settings store.
///
/// **The one refusal is an empty list.** A stored list naming nothing reads back as
/// "absent", which means *every* chain -- so turning them all off would silently turn
/// them all on at the next read.
#[cfg(all(feature = "multichain", not(feature = "board-mk3")))]
fn chain_settings(gate: &Callgate, login: &mut catcard_pin::Login, ui: &mut Ui<'_>) {
    use catcard_ui::scroll::Line as DLine;

    let mut order = crate::chains::order(gate, login, ui);
    let start = order.clone();
    let mut cursor = 0usize;
    let mut off = 0usize;

    let mut events = [Event::Pressed(Key::Cancel); KEYS];
    let mut keys: heapless::Vec<Key, { KEYS + 1 }> = heapless::Vec::new();
    loop {
        // The rows, rebuilt each frame: the labels borrow these, so they have to outlive
        // the view and the view is rebuilt whenever anything moves.
        let mut labels: heapless::Vec<heapless::String<24>, { crate::chains::MAX }> =
            heapless::Vec::new();
        for (c, on) in order.iter() {
            let mut row: heapless::String<24> = heapless::String::new();
            let _ = row.push_str(c.name);
            // A row says what it is, not what pressing OK would do: "off" under the
            // cursor must not read as an invitation to turn something off that is
            // already off.
            let _ = row.push_str(if *on { "" } else { "  (off)" });
            let _ = labels.push(row);
        }

        {
            let mut lines: heapless::Vec<DLine, { crate::chains::MAX + 3 }> = heapless::Vec::new();
            let _ = lines.push(DLine::title("Chains"));
            // **Named by what is printed on the key, not by what it decodes to.** Both
            // boards send `Digit(7)` and `Digit(9)` here -- the Q1 from its arrow keys,
            // the numpad boards from 7 and 9 -- and both have arrows printed on those
            // keys. So the hint says the arrows, which is what somebody is looking at.
            let _ = lines.push(DLine::body("OK on/off   < > move").small().centered());
            for (i, (c, _)) in order.iter().enumerate() {
                let mut line = DLine::item(&labels[i], i as u32).large();
                if let Some(mark) = catcard_ui::art::chainicons::mark(c.ticker) {
                    line = line.with_mark(mark);
                }
                let _ = lines.push(line);
            }
            let mut view = catcard_ui::scroll::ScrollView::build(
                &lines,
                display::SCREEN_W,
                display::SCREEN_H,
                display::FONTS,
            );
            view.set_off(off);
            view.select(cursor as u32);
            // The same one-pass path every list takes, so a chain's logo reaches the
            // panel inside the frame rather than after it.
            #[cfg(feature = "board-q1")]
            display::draw_with_marks(ui.panel, &view, |c| catcard_ui::scroll::render(c, &view));
            #[cfg(not(feature = "board-q1"))]
            display::draw(ui.panel, |c| catcard_ui::scroll::render(c, &view));
            off = view.off();
        }

        wait_for_release(ui);
        let mut moved = false;
        while !moved {
            let _ = usbtask::pump();
            crate::pinentry::pressed_keys(ui.pad, ui.matrix, ui.drbg, &mut events, &mut keys);
            if keys.is_empty() {
                display::idle(ui.panel);
                continue;
            }
            let last = order.len().saturating_sub(1);
            match keys[0] {
                Key::Digit(5) => cursor = cursor.saturating_sub(1),
                Key::Digit(8) => cursor = (cursor + 1).min(last),
                // Move the row itself, and follow it with the cursor: the thing being
                // dragged should stay under the finger doing the dragging.
                Key::Digit(7) if cursor > 0 => {
                    order.swap(cursor, cursor - 1);
                    cursor -= 1;
                }
                Key::Digit(9) if cursor < last => {
                    order.swap(cursor, cursor + 1);
                    cursor += 1;
                }
                Key::Confirm => {
                    if let Some(row) = order.get_mut(cursor) {
                        row.1 = !row.1;
                    }
                }
                Key::Cancel => {
                    let changed = order.len() != start.len()
                        || order
                            .iter()
                            .zip(start.iter())
                            .any(|((a, x), (b, y))| a.id != b.id || x != y);
                    if !changed {
                        return;
                    }
                    match crate::chains::save(gate, login, ui, &order) {
                        Ok(()) => return,
                        Err(why) => {
                            message(ui.panel, "Chains", why, "nothing was saved");
                            wait_for_any_key(ui);
                        }
                    }
                }
                _ => continue,
            }
            moved = true;
        }
    }
}

/// One chain's row: its mark and its name. The logo in full colour on the Q1, written to
/// the panel past the canvas; the one-bit mark on the OLED.
#[cfg(feature = "multichain")]
fn chain_row(c: &catcard_wallet::chain::Chain, id: u32) -> catcard_ui::scroll::Line<'static> {
    use catcard_ui::art::chainicons;
    use catcard_ui::scroll::Line as DLine;
    let mut line = DLine::item(c.name, id).large();
    // Whichever forms this build has: a board whose panel cannot show colour does not
    // carry the colour art at all, so `mark` answers with the one-bit form and the row
    // says nothing about which board it is on.
    if let Some(mark) = chainicons::mark(c.ticker) {
        line = line.with_mark(mark);
    }
    line
}

/// Addresses for a loaded WIF key: one key, so one address per format -- no accounts, no
/// indices, nothing below it. On a multichain build, the chain first, as for any wallet.
fn wif_addresses(gate: &Callgate, login: &mut catcard_pin::Login, ui: &mut Ui<'_>) {
    let Some(key) = crate::key::temporary_wif() else {
        return;
    };
    let Some(pubkey) = crate::keywork::run(|kw| catcard_wallet::bip32::public_key_of(key, kw))
    else {
        message(
            ui.panel,
            "Addresses",
            "that key is not usable",
            "any key to go back",
        );
        wait_for_any_key(ui);
        return;
    };
    #[cfg(feature = "multichain")]
    loop {
        let offered = crate::chains::enabled(gate, login, ui).len();
        let Some(chain) = pick_chain(gate, login, ui) else {
            return;
        };
        single_key_addresses(ui, chain, &pubkey);
        if offered <= 1 {
            return;
        }
    }
    #[cfg(not(feature = "multichain"))]
    {
        let _ = (gate, login);
        single_key_addresses(ui, &catcard_wallet::chain::BITCOIN, &pubkey);
    }
}

/// One key's address in each of `chain`'s formats, a row each; choosing one shows its QR.
///
/// secp256k1 only: a WIF key is a secp256k1 scalar, so a chain whose addresses are
/// ed25519 keys (Solana) has none for it, and says so.
fn single_key_addresses(
    ui: &mut Ui<'_>,
    chain: &catcard_wallet::chain::Chain,
    pubkey: &[u8; catcard_wallet::address::PUBKEY_LEN],
) {
    use catcard_ui::scroll::Line as DLine;
    use catcard_wallet::chain::{Encoding, address};

    type Addr = heapless::String<{ address::MAX_LEN }>;
    let mut shown: heapless::Vec<(&str, Addr), 6> = heapless::Vec::new();
    for f in chain
        .formats
        .iter()
        .filter(|f| f.encoding != Encoding::Solana)
    {
        let mut buf = [0u8; address::MAX_LEN];
        let Ok(n) =
            address::from_secp256k1(chain, f.encoding, crate::prefs::network(), pubkey, &mut buf)
        else {
            continue;
        };
        let mut text = Addr::new();
        let _ = text.push_str(core::str::from_utf8(&buf[..n]).unwrap_or(""));
        let _ = shown.push((f.label, text));
    }
    if shown.is_empty() {
        message(
            ui.panel,
            chain.name,
            "a WIF key has no",
            "address on this chain",
        );
        wait_for_any_key(ui);
        return;
    }
    loop {
        let mut lines: heapless::Vec<DLine, 16> = heapless::Vec::new();
        let _ = lines.push(DLine::title(chain.name));
        let _ = lines.push(DLine::body("one key: no accounts").small());
        for (i, (label, text)) in shown.iter().enumerate() {
            let _ = lines.push(DLine::item(label, i as u32));
            let _ = lines.push(DLine::body(text.as_str()).small().wrapped());
        }
        match show_doc(ui, &lines, false, false) {
            DocExit::Selected(i) => {
                if let Some((_, text)) = shown.get(i as usize) {
                    qr_screen(ui, text.as_str(), text.as_str());
                }
            }
            _ => return,
        }
    }
}

/// Which chain, from the wallet in force's list, a row each: for a WIF key's addresses,
/// which have no verify row. With only one chain on the list there is nothing to ask.
#[cfg(feature = "multichain")]
fn pick_chain(
    gate: &Callgate,
    login: &mut catcard_pin::Login,
    ui: &mut Ui<'_>,
) -> Option<&'static catcard_wallet::chain::Chain> {
    use catcard_ui::scroll::Line as DLine;

    let chains = crate::chains::enabled(gate, login, ui);
    if chains.len() <= 1 {
        return chains.first().copied();
    }
    let mut lines: heapless::Vec<DLine, { crate::chains::MAX + 1 }> = heapless::Vec::new();
    let _ = lines.push(DLine::title("Addresses"));
    for (i, c) in chains.iter().enumerate() {
        let _ = lines.push(chain_row(c, i as u32));
    }
    match show_doc(ui, &lines, false, false) {
        DocExit::Selected(i) => chains.get(i as usize).copied(),
        _ => None,
    }
}

/// Solana addresses derived per seed stretch. SLIP-0010 has no public derivation, so
/// every address needs the seed; eight at a time makes paging through them cost one
/// stretch per eight rather than one per step.
#[cfg(feature = "multichain")]
const SOLANA_BATCH: usize = 8;

/// The ed25519 public keys of Solana accounts `first..first + SOLANA_BATCH`, at
/// `m/44'/501'/{i}'/0'` -- the path Phantom and Solflare use.
#[cfg(feature = "multichain")]
fn solana_batch(
    gate: &Callgate,
    login: &mut catcard_pin::Login,
    ui: &mut Ui<'_>,
    coin: u32,
    first: u32,
) -> Option<[[u8; 32]; SOLANA_BATCH]> {
    let got = with_seed(gate, login, ui.panel, "Addresses", |seed, kw| {
        let mut out = [[0u8; 32]; SOLANA_BATCH];
        for (i, slot) in out.iter_mut().enumerate() {
            let node = catcard_wallet::slip10::derive(seed, &[44, coin, first + i as u32, 0], kw)?;
            *slot = node.public_key(kw);
        }
        Some(out)
    });
    match got {
        Ok(keys) => Some(keys),
        Err(why) => {
            message(ui.panel, "Addresses", why, "any key to go back");
            wait_for_any_key(ui);
            None
        }
    }
}

/// One chain's addresses, other than Bitcoin's: its formats, accounts and indices.
///
/// The same screen and keys as Bitcoin's explorer, with the axes a chain does not have
/// left out: no change chain for account-model chains (Ethereum, Tron, Solana), and no
/// account axis for Solana, whose account *is* the index.
/// One of the other chains' addresses, from `start` on, written to the card.
///
/// Its own function rather than a branch of the key handler: the row producer runs with
/// the card mounted, and what it may touch -- one already-derived public key and the
/// chain's own encoder -- is easier to see when it is not four levels inside a `match`.
#[cfg(feature = "multichain")]
fn export_other_chain_csv(
    ui: &mut Ui<'_>,
    chain: &'static catcard_wallet::chain::Chain,
    format: catcard_wallet::chain::Format,
    account: u32,
    change: u32,
    start: u32,
    chain_key: &catcard_wallet::bip32::ExtendedPubKey,
) {
    use catcard_wallet::bip32::ChildNumber;
    use catcard_wallet::chain::address as caddr;

    let Some(count) = ask_row_count(ui, chain.name) else {
        return;
    };
    let file = address_csv_name();
    write_address_csv(ui, chain.name, file.as_str(), start, count, &mut |index| {
        let leaf = chain_key
            .derive_child(ChildNumber::normal(index).ok()?)
            .ok()?;
        let mut out = [0u8; caddr::MAX_LEN];
        let n = caddr::from_secp256k1(
            chain,
            format.encoding,
            crate::prefs::network(),
            &leaf.public_key,
            &mut out,
        )
        .ok()?;
        let mut text = AddrText::new();
        text.push_str(core::str::from_utf8(&out[..n]).ok()?).ok()?;
        Some((
            bip44_path(
                format.purpose,
                chain.coin_type_on(crate::prefs::network()),
                account,
                change,
                index,
            )?,
            text,
        ))
    });
}

#[cfg(feature = "multichain")]
fn chain_explorer(
    gate: &Callgate,
    login: &mut catcard_pin::Login,
    ui: &mut Ui<'_>,
    chain: &'static catcard_wallet::chain::Chain,
) {
    use catcard_wallet::bip32::{ChildNumber, ExtendedPubKey};
    use catcard_wallet::chain::{Encoding, address as caddr};

    let formats = chain.formats;
    let cols = catcard_ui::scroll::text_cols(
        &display::FONTS,
        catcard_ui::scroll::Size::Body,
        display::SCREEN_W,
    );
    let (mut fmt, mut account, mut change, mut index) = (0usize, 0u32, 0u32, 0u32);
    let mut cached: Option<(usize, u32, u32, ExtendedPubKey)> = None;
    let mut refused_at: Option<(usize, u32)> = None;
    let mut sol: Option<(u32, [[u8; 32]; SOLANA_BATCH])> = None;
    let mut events = [Event::Pressed(Key::Cancel); KEYS];
    let mut keys: heapless::Vec<Key, { KEYS + 1 }> = heapless::Vec::new();

    loop {
        let f = formats[fmt.min(formats.len() - 1)];
        let mut buf = [0u8; caddr::MAX_LEN];
        let mut path = Line::new();
        let addr: Option<usize> = match f.encoding {
            Encoding::Solana => {
                let _ = write!(
                    path,
                    "m/44h/{}h/{index}h/0h",
                    chain.coin_type_on(crate::prefs::network())
                );
                let first = index - index % SOLANA_BATCH as u32;
                if !matches!(sol, Some((at, _)) if at == first) {
                    sol = solana_batch(
                        gate,
                        login,
                        ui,
                        chain.coin_type_on(crate::prefs::network()),
                        first,
                    )
                    .map(|k| (first, k));
                    if sol.is_none() {
                        return;
                    }
                }
                sol.as_ref().and_then(|(at, keys)| {
                    caddr::from_ed25519(chain, &keys[(index - at) as usize], &mut buf).ok()
                })
            }
            _ => {
                // The account key once, from this session or the seed; then the public
                // steps, which need no key material and no masking.
                if !matches!(cached, Some((a, b, c, _)) if (a, b, c) == (fmt, account, change)) {
                    let acct = (refused_at != Some((fmt, account)))
                        .then(|| {
                            crate::pubkeys::account_key_at(
                                gate,
                                login,
                                ui,
                                "Addresses",
                                f.purpose,
                                chain.coin_type_on(crate::prefs::network()),
                                account,
                            )
                        })
                        .flatten();
                    refused_at = acct.is_none().then_some((fmt, account));
                    cached = acct
                        .and_then(|k| {
                            ChildNumber::normal(change)
                                .ok()
                                .and_then(|c| k.derive_child(c).ok())
                        })
                        .map(|k| (fmt, account, change, k));
                }
                let _ = write!(
                    path,
                    "m/{}h/{}h/{account}h/{change}/{index}",
                    f.purpose,
                    chain.coin_type_on(crate::prefs::network())
                );
                cached.as_ref().map(|(_, _, _, k)| *k).and_then(|k| {
                    ChildNumber::normal(index)
                        .ok()
                        .and_then(|c| k.derive_child(c).ok())
                        .and_then(|k| {
                            caddr::from_secp256k1(
                                chain,
                                f.encoding,
                                crate::prefs::network(),
                                &k.public_key,
                                &mut buf,
                            )
                            .ok()
                        })
                })
            }
        };

        let mut shown = Line::new();
        match addr {
            Some(n) => ellipsize_middle(
                core::str::from_utf8(&buf[..n]).unwrap_or(""),
                cols,
                &mut shown,
            ),
            None => {
                let _ = shown.push_str("(no address)");
            }
        }
        let utxo = matches!(f.encoding, Encoding::Utxo(_));
        let solana = f.encoding == Encoding::Solana;
        let mut key_hint = Line::new();
        let _ = write!(
            key_hint,
            "{} QR   {} back",
            display::CONFIRM_KEY,
            display::CANCEL_KEY
        );
        let axes = match (utxo, solana) {
            (true, _) => {
                if change == 0 {
                    "1/3 account  0 change chain"
                } else {
                    "1/3 account  0 receive chain"
                }
            }
            (false, true) => "",
            (false, false) => "1/3 account",
        };

        let mut doc: heapless::Vec<catcard_ui::scroll::Line, 10> = heapless::Vec::new();
        let _ = doc.push(catcard_ui::scroll::Line::title(chain.name));
        if formats.len() > 1 {
            let _ = doc.push(catcard_ui::scroll::Line::body(f.label).small());
        }
        let _ = doc.push(catcard_ui::scroll::Line::body(path.as_str()).small());
        let _ = doc.push(catcard_ui::scroll::Line::body(shown.as_str()));
        let _ = doc.push(catcard_ui::scroll::Line::body("up/down address").small());
        if formats.len() > 1 {
            let _ = doc.push(catcard_ui::scroll::Line::body("left/right type").small());
        }
        if !axes.is_empty() {
            let _ = doc.push(catcard_ui::scroll::Line::body(axes).small());
        }
        // The typed axes, as on Bitcoin's explorer. Solana has no account axis to type
        // into -- its account *is* the index -- and no export, because every one of its
        // addresses needs the seed again and a file of them would be a screen full of
        // unlock prompts.
        let _ = doc.push(
            catcard_ui::scroll::Line::body(match solana {
                true => "4 start idx",
                false => "2 account  4 start idx  6 to card",
            })
            .small(),
        );
        let _ = doc.push(catcard_ui::scroll::Line::body(key_hint.as_str()).small());
        let view = catcard_ui::scroll::ScrollView::build(
            &doc,
            display::SCREEN_W,
            display::SCREEN_H,
            display::FONTS,
        );
        display::draw(ui.panel, |c| catcard_ui::scroll::render(c, &view));

        wait_for_release(ui);
        'wait: loop {
            let _ = usbtask::pump();
            crate::pinentry::pressed_keys(ui.pad, ui.matrix, ui.drbg, &mut events, &mut keys);
            for k in keys.iter() {
                match k {
                    Key::Cancel => return,
                    // The address as it is written, which is what that chain's wallets
                    // scan: no URI scheme is invented for it.
                    Key::Confirm => {
                        if let Some(n) = addr {
                            let text = core::str::from_utf8(&buf[..n]).unwrap_or("");
                            qr_screen(ui, text, text);
                        }
                        break 'wait;
                    }
                    Key::Digit(8) => {
                        index = index.saturating_add(1);
                        break 'wait;
                    }
                    Key::Digit(5) => {
                        index = index.saturating_sub(1);
                        break 'wait;
                    }
                    Key::Digit(9) if formats.len() > 1 => {
                        fmt = (fmt + 1) % formats.len();
                        index = 0;
                        break 'wait;
                    }
                    Key::Digit(7) if formats.len() > 1 => {
                        fmt = (fmt + formats.len() - 1) % formats.len();
                        index = 0;
                        break 'wait;
                    }
                    Key::Digit(3) if !solana => {
                        account = account.saturating_add(1);
                        index = 0;
                        break 'wait;
                    }
                    Key::Digit(1) if !solana => {
                        account = account.saturating_sub(1);
                        index = 0;
                        break 'wait;
                    }
                    // The account and the start index typed, as on Bitcoin's explorer.
                    Key::Digit(2) if !solana => {
                        if let Some(n) =
                            ask_number(ui, chain.name, None, "account", "empty is account 0")
                        {
                            account = n;
                            index = 0;
                        }
                        break 'wait;
                    }
                    Key::Digit(4) => {
                        if let Some(n) =
                            ask_number(ui, chain.name, None, "start", "empty starts at 0")
                        {
                            index = n;
                        }
                        break 'wait;
                    }
                    // This chain's addresses from here on, to the card. Not offered for
                    // Solana: SLIP-0010 has no public derivation, so each row would need
                    // the seed again.
                    Key::Digit(6) if !solana => {
                        if let Some(chain_key) = cached.as_ref().map(|(_, _, _, k)| *k) {
                            export_other_chain_csv(
                                ui, chain, f, account, change, index, &chain_key,
                            );
                        }
                        break 'wait;
                    }
                    Key::Digit(0) if utxo => {
                        change = 1 - change;
                        index = 0;
                        break 'wait;
                    }
                    _ => {}
                }
            }
            display::idle(ui.panel);
        }
    }
}

/// Characters a written-out path can take: every level of `MAX_PATH_DEPTH` as ten digits
/// and a hardened marker, after the leading `m`.
const PATH_CHARS: usize = catcard_wallet::bip32::MAX_PATH_DEPTH * 12 + 1;
/// A path as it is shown and as it is typed.
type PathText = heapless::String<PATH_CHARS>;
/// Characters the longest address of any chain this build carries can take. Bitcoin's
/// bech32 limit is the shorter of the two; a row producer is shared with the other
/// chains, so the buffer is sized for whichever is longer rather than for Bitcoin.
const ADDR_CHARS: usize = {
    let bitcoin = catcard_wallet::address::MAX_ADDRESS_LEN;
    let other = catcard_wallet::chain::address::MAX_LEN;
    if other > bitcoin { other } else { bitcoin }
};
/// One address as a row producer hands it over.
type AddrText = heapless::String<ADDR_CHARS>;

/// Why a typed path was refused, in the words of the screen that shows it. Only a board
/// with a keyboard can type a path wrong: the guided build cannot produce one.
#[cfg(feature = "board-q1")]
fn describe_path_error(e: catcard_wallet::bip32::path::ParseError, out: &mut Line) {
    use catcard_wallet::bip32::path::ParseError as E;
    out.clear();
    let _ = match e {
        E::Empty => write!(out, "type a path, or x to go back"),
        // `position` counts from the first step, and a person counts from one.
        E::EmptyStep { position } => write!(out, "level {} is empty", position + 1),
        E::BadStep { position } => write!(out, "level {} is not a number", position + 1),
        E::IndexTooLarge { position } => write!(out, "level {} is over 2147483647", position + 1),
        E::TooDeep => write!(
            out,
            "{} levels is the most",
            catcard_wallet::bip32::MAX_PATH_DEPTH
        ),
    };
}

/// Type a derivation path on a board with a keyboard.
///
/// **Typed here, built a level at a time on the numpad boards** (the other `ask_path`
/// below). The choice is the keyboard: a Q1 has `/`, `h` and the digits under the owner's
/// fingers, so `m/48h/0h/0h/2h/0/5` is one line of typing and the whole path is visible
/// while it is checked. A numpad has ten digits and two keys, no separator and no letter,
/// so the same path would have to be spelled through a mode of its own -- which is what
/// the guided build is, without inventing a meaning for a digit key.
///
/// Parsing is `DerivationPath`'s own, so what is accepted here is exactly what the rest
/// of the firmware derives from, and the complaint names the level that was wrong.
#[cfg(feature = "board-q1")]
fn ask_path(ui: &mut Ui<'_>, head: &str) -> Option<catcard_wallet::bip32::DerivationPath> {
    use catcard_ui::canvas::Canvas as _;
    use catcard_ui::field::{self, Accept, Field, Input};
    use catcard_ui::text::{centred, draw_text};

    let top_y = display::FIELD_TOP;
    let mut input = Input::<PATH_CHARS>::new(Accept::Text, PATH_CHARS);
    let mut events = [Event::Pressed(Key::Cancel); KEYS];
    let mut keys: heapless::Vec<Key, { KEYS + 1 }> = heapless::Vec::new();
    let mut complaint = Line::new();

    loop {
        // Two lines: a path with six levels does not fit one, and a path shown half-way
        // is a path nobody can check.
        let fields = [Field::text("path", input.as_str()).lines(2).live(true)];
        let body = display::LAYOUT.body;
        let foot = if complaint.is_empty() {
            "m/48h/0h/0h/2h/0/5"
        } else {
            complaint.as_str()
        };
        display::draw_field_page(ui.panel, |c| {
            c.clear();
            let hx = centred(body, head, c.width());
            draw_text(
                c,
                body,
                hx,
                top_y.saturating_sub(body.line_height() + 6),
                head,
            );
            let below = field::stack(
                c,
                &display::LAYOUT,
                top_y,
                &fields,
                display::FIELD_SKIN,
                true,
            );
            let fx = centred(body, foot, c.width());
            draw_text(c, body, fx, below + 6, foot);
        });
        wait_for_release(ui);

        let mut redraw = false;
        while !redraw {
            let _ = usbtask::pump();
            crate::pinentry::pressed_keys(ui.pad, ui.matrix, ui.drbg, &mut events, &mut keys);
            for k in keys.iter() {
                match k {
                    Key::Confirm => match input.as_str().parse() {
                        Ok(path) => return Some(path),
                        Err(e) => {
                            describe_path_error(e, &mut complaint);
                            redraw = true;
                        }
                    },
                    Key::Cancel => {
                        if !input.backspace() {
                            return None;
                        }
                        complaint.clear();
                        redraw = true;
                    }
                    Key::Qr => {}
                    // The number row means digits, as it does in every other field on
                    // this board; the arrow keys arrive as digits too, which is the
                    // price of the shared keypad model and is documented in `qwerty`.
                    Key::Digit(d) => {
                        input.put((b'0' + d) as char);
                        complaint.clear();
                        redraw = true;
                    }
                    Key::Char(c) => {
                        input.put(*c as char);
                        complaint.clear();
                        redraw = true;
                    }
                }
            }
            if !redraw {
                display::idle(ui.panel);
            }
        }
    }
}

/// Build a derivation path a level at a time, on a board with no keyboard.
///
/// **Guided rather than Q1-only.** Stock builds a path this way on every board it runs
/// on (hw-reference/menu-map-mk4-mk5-q1-v5.6.2.md §AE "Custom Path → KeypathMenu" [C]),
/// and a screen that exists on one board of three is a screen an owner cannot be told
/// about. What it costs is two presses of accept per level; what it avoids is giving a
/// digit key a second meaning inside a field where every digit is already a digit.
///
/// Each level is added by its own row, so hardened and normal are separate choices
/// rather than a modifier -- `0` and `0h` are different keys, and a menu that made the
/// difference a toggle would make it a thing to misread.
#[cfg(not(feature = "board-q1"))]
fn ask_path(ui: &mut Ui<'_>, head: &str) -> Option<catcard_wallet::bip32::DerivationPath> {
    use catcard_wallet::bip32::{ChildNumber, DerivationPath, MAX_PATH_DEPTH};

    let mut path = DerivationPath::MASTER;
    loop {
        let mut shown = PathText::new();
        let _ = write!(shown, "{path}");
        let room = path.len() < MAX_PATH_DEPTH;
        // The rows that would do nothing are not offered: "add a level" on a full path
        // and "remove" on `m` are both rows that can only refuse.
        let mut items: heapless::Vec<&str, 4> = heapless::Vec::new();
        if room {
            let _ = items.push("Add /n");
            let _ = items.push("Add /nh");
        }
        if !path.is_empty() {
            let _ = items.push("Remove last");
        }
        let _ = items.push("Use this path");
        let row = pick_row(ui, head, shown.as_str(), &items)?;
        match items[row] {
            "Add /n" | "Add /nh" => {
                let hardened = items[row] == "Add /nh";
                let label = if hardened { "level h" } else { "level" };
                let Some(index) = ask_number(ui, head, None, label, "digits, then accept") else {
                    continue;
                };
                let child = if hardened {
                    ChildNumber::hardened(index)
                } else {
                    ChildNumber::normal(index)
                };
                // Both refusals are already impossible here -- `ask_number` caps at
                // 2^31 - 1 and the rows above check the depth -- so this says so by
                // dropping the level rather than by claiming it was added.
                if let Ok(child) = child {
                    let _ = path.push(child);
                }
            }
            "Remove last" => {
                let steps: heapless::Vec<ChildNumber, MAX_PATH_DEPTH> = path.iter().collect();
                path = DerivationPath::from_slice(&steps[..steps.len() - 1])
                    .unwrap_or(DerivationPath::MASTER);
            }
            _ => return Some(path),
        }
    }
}

/// The address at a path the owner chose, in each type it could be spent as.
///
/// **Every type, not the one the path implies.** A purpose level is a convention and not
/// a commitment: `m/48h/0h/0h/2h/0/5` is a multisig cosigner path, and the same public
/// key has a legacy, a nested, a native segwit and a taproot address, all of them real.
/// Guessing one from the path is how a wallet ends up showing an address nobody can spend
/// from -- the rule `catcard_wallet::address` states about `bip44_purpose` -- so the four
/// are listed and the owner says which one they meant.
///
/// One unlock, one walk. A custom path can be hardened at any level, so unlike the
/// explorer's walk it cannot come out of a cached account key; it is derived once, and
/// every format below comes from that one public key.
fn custom_path(gate: &Callgate, login: &mut catcard_pin::Login, ui: &mut Ui<'_>) {
    use catcard_ui::scroll::Line as DLine;
    use catcard_wallet::address;
    use catcard_wallet::bip32::{ChildNumber, MAX_PATH_DEPTH};

    const HEAD: &str = "Custom path";

    let Some(path) = ask_path(ui, HEAD) else {
        return;
    };
    let Some(master) = unlock_master(gate, login, ui, HEAD) else {
        return;
    };
    let steps: heapless::Vec<ChildNumber, MAX_PATH_DEPTH> = path.iter().collect();
    let mut busy = Working::new(ui.panel, HEAD, "deriving");
    let key = if steps.is_empty() {
        // `m` itself: the master's own public key, which `public_at` cannot walk to
        // because there is no step to take.
        Some(crate::keywork::run(|kw| master.to_extended_pub(kw)))
    } else {
        public_at(&master, &steps, &mut busy, ui.panel)
    };
    drop(master);
    let Some(key) = key else {
        message(
            ui.panel,
            HEAD,
            "that path did not derive",
            "any key to go back",
        );
        wait_for_any_key(ui);
        return;
    };

    let mut shown = PathText::new();
    let _ = write!(shown, "{path}");
    // The kind travels with its address, not the row number: a type that would not
    // encode is left out, and a row index read back against `PROTOCOLS` would then name
    // the wrong one -- which is a QR of one address labelled as another.
    let mut addresses: heapless::Vec<(address::AddressKind, AddrText), { PROTOCOLS.len() }> =
        heapless::Vec::new();
    for kind in PROTOCOLS {
        let mut buf = [0u8; address::MAX_ADDRESS_LEN];
        let Ok(n) = address::encode(kind, crate::prefs::network(), &key.public_key, &mut buf)
        else {
            continue;
        };
        let mut text = AddrText::new();
        let _ = text.push_str(core::str::from_utf8(&buf[..n]).unwrap_or(""));
        let _ = addresses.push((kind, text));
    }
    if addresses.is_empty() {
        message(
            ui.panel,
            HEAD,
            "no address at that path",
            "any key to go back",
        );
        wait_for_any_key(ui);
        return;
    }

    loop {
        let mut lines: heapless::Vec<DLine, { 2 + 2 * PROTOCOLS.len() }> = heapless::Vec::new();
        let _ = lines.push(DLine::title(HEAD));
        let _ = lines.push(DLine::body(shown.as_str()).small().wrapped());
        for (i, (kind, text)) in addresses.iter().enumerate() {
            let _ = lines.push(DLine::item(kind_name(*kind), i as u32));
            let _ = lines.push(DLine::body(text.as_str()).small().wrapped());
        }
        match show_doc(ui, &lines, false, false) {
            DocExit::Selected(i) => {
                if let Some((kind, text)) = addresses.get(i as usize) {
                    address_qr(ui, text.as_str(), *kind);
                }
            }
            _ => return,
        }
    }
}

/// Row counts the address export offers.
///
/// Bounded, and bounded by a choice rather than by a buffer: a card write that takes a
/// minute with nothing on the glass is one an owner pulls the card out of. Two hundred
/// and fifty rows is a watch-only wallet's usual look-ahead window and the most this
/// offers.
const CSV_COUNTS: [u32; 4] = [10, 25, 50, 250];
const CSV_COUNT_ROWS: [&str; 4] = ["10 addresses", "25 addresses", "50 addresses", "250"];

/// A worst-case row -- a ten-digit index, the deepest path, the longest address, all
/// quoted -- has to fit one chunk, or it would be written short and the file would carry
/// half an address that still looks like one.
const _: () = assert!(
    12 + 1 + (PATH_CHARS + 2) + 1 + (ADDR_CHARS + 2) + 2 <= CARD_CHUNK,
    "a CSV row must fit one card chunk"
);

fn ask_row_count(ui: &mut Ui<'_>, head: &str) -> Option<u32> {
    let row = pick_row(ui, head, "how many to write", &CSV_COUNT_ROWS)?;
    CSV_COUNTS.get(row).copied()
}

/// Write `count` addresses from `start` to the card as CSV, and say how many landed.
///
/// `row` is asked for one index at a time and answers with the path and the address
/// there, or `None` for an index that has none -- a child number that lands on an
/// unusable scalar, which is vanishingly rare and must leave a gap rather than a wrong
/// line. It runs with the card mounted, so it derives and nothing else: the key it works
/// from is in the caller's hand before this is called, and no seed is reached here.
fn write_address_csv(
    ui: &mut Ui<'_>,
    head: &str,
    file: &str,
    start: u32,
    count: u32,
    row: &mut dyn FnMut(u32) -> Option<(catcard_wallet::bip32::DerivationPath, AddrText)>,
) {
    use catcard_wallet::csv;

    card_wait(ui.panel, head, "writing to the card");
    let mut at: u32 = 0;
    let mut rows: u32 = 0;
    let written = write_card_chunks(file, &mut |chunk| {
        if at == 0 {
            at = 1;
            return csv::write_header(chunk).is_ok();
        }
        while at <= count {
            let index = start.saturating_add(at - 1);
            at += 1;
            if let Some((path, address)) = row(index) {
                if csv::write_address_row(chunk, index, &path, address.as_str()).is_err() {
                    return false;
                }
                rows += 1;
                return true;
            }
        }
        false
    });
    match written {
        Ok(bytes) => {
            crate::catlog!(
                "addresses: wrote {} rows, {} bytes to {}",
                rows,
                bytes,
                file
            );
            let mut said = Line::new();
            let _ = write!(said, "{rows} addresses written");
            message(ui.panel, "Exported", said.as_str(), file);
        }
        Err(why) => {
            crate::catlog!("addresses: export failed: {}", why);
            message(ui.panel, "Export failed", why, "any key to go back");
        }
    }
    wait_for_any_key(ui);
}

/// The file an address export is written to: this wallet's, by its fingerprint, so two
/// wallets' exports do not overwrite each other on one card.
fn address_csv_name() -> heapless::String<24> {
    let mut path = heapless::String::new();
    match crate::pubkeys::known_fingerprint() {
        Some([a, b, c, d]) => {
            let _ = write!(path, "/{a:02X}{b:02X}{c:02X}{d:02X}-ADDRS.CSV");
        }
        // Nothing has derived a fingerprint this session, which cannot happen on the way
        // out of a screen that has shown an address -- but a name is needed either way.
        None => {
            let _ = path.push_str("/ADDRESSES.CSV");
        }
    }
    path
}

/// The path `m/{purpose}h/{coin}h/{account}h/{chain}/{index}` as a parsed path, for the
/// CSV's path column.
fn bip44_path(
    purpose: u32,
    coin: u32,
    account: u32,
    chain: u32,
    index: u32,
) -> Option<catcard_wallet::bip32::DerivationPath> {
    use catcard_wallet::bip32::{ChildNumber, DerivationPath};
    let steps = [
        ChildNumber::hardened(purpose).ok()?,
        ChildNumber::hardened(coin).ok()?,
        ChildNumber::hardened(account).ok()?,
        ChildNumber::normal(chain).ok()?,
        ChildNumber::normal(index).ok()?,
    ];
    DerivationPath::from_slice(&steps).ok()
}

/// Export addresses below a chain key that is already in hand: the explorer's `6` key and
/// the export drawer's row both end here.
///
/// `chain_key` is the extended *public* key at `m/{purpose}h/{coin}h/{account}h/{chain}`,
/// so every row is one unhardened step and no seed is touched however many are asked for.
fn export_chain_csv(
    ui: &mut Ui<'_>,
    head: &str,
    run: AddressRun,
    chain_key: &catcard_wallet::bip32::ExtendedPubKey,
) {
    use catcard_wallet::address;
    use catcard_wallet::bip32::ChildNumber;

    let Some(count) = ask_row_count(ui, head) else {
        return;
    };
    let file = address_csv_name();
    write_address_csv(ui, head, file.as_str(), run.start, count, &mut |index| {
        let leaf = chain_key
            .derive_child(ChildNumber::normal(index).ok()?)
            .ok()?;
        let mut buf = [0u8; address::MAX_ADDRESS_LEN];
        let n = address::encode(
            run.kind,
            crate::prefs::network(),
            &leaf.public_key,
            &mut buf,
        )
        .ok()?;
        let mut text = AddrText::new();
        text.push_str(core::str::from_utf8(&buf[..n]).ok()?).ok()?;
        Some((
            bip44_path(
                run.kind.bip44_purpose(),
                run.coin,
                run.account,
                run.chain,
                index,
            )?,
            text,
        ))
    });
}

/// Which addresses an export is of: the type, and the numbers that name the key they hang
/// under. Together rather than as five arguments, because every one of them is a small
/// integer and a caller that swapped two would export a different wallet's addresses
/// under this one's name.
#[derive(Copy, Clone)]
struct AddressRun {
    kind: catcard_wallet::address::AddressKind,
    /// SLIP-44 coin type. Zero here: Bitcoin's explorer and the export drawer are the
    /// two callers, and the other chains build their own rows.
    coin: u32,
    account: u32,
    /// 0 receive, 1 change.
    chain: u32,
    /// The first index written.
    start: u32,
}

/// Export drawer → Address CSV: pick a type, an account and a start, and write the
/// receive addresses from there.
///
/// Receive addresses only. The change chain is derivable from the same key and is on the
/// explorer's `6` key when it is what is on screen, but a file handed to someone else so
/// they can pay this wallet should not carry the addresses its change goes to.
fn export_address_csv(gate: &Callgate, login: &mut catcard_pin::Login, ui: &mut Ui<'_>) {
    use catcard_wallet::bip32::ChildNumber;

    const HEAD: &str = "Address CSV";

    let names: heapless::Vec<&str, { PROTOCOLS.len() }> =
        PROTOCOLS.iter().map(|k| kind_name(*k)).collect();
    let Some(row) = pick_row(ui, HEAD, "which address type", &names) else {
        return;
    };
    let kind = PROTOCOLS[row];
    let Some(account) = ask_number(ui, HEAD, None, "account", "empty is account 0") else {
        return;
    };
    let Some(start) = ask_number(ui, HEAD, None, "start", "empty starts at 0") else {
        return;
    };
    let Some(account_key) = crate::pubkeys::account_key(gate, login, ui, HEAD, kind, account)
    else {
        return;
    };
    let Some(chain_key) = ChildNumber::normal(0)
        .ok()
        .and_then(|c| account_key.derive_child(c).ok())
    else {
        message(ui.panel, HEAD, "that account did not", "derive a chain key");
        wait_for_any_key(ui);
        return;
    };
    export_chain_csv(
        ui,
        HEAD,
        AddressRun {
            kind,
            coin: 0,
            account,
            chain: 0,
            start,
        },
        &chain_key,
    );
}

fn address_explorer(gate: &Callgate, login: &mut catcard_pin::Login, ui: &mut Ui<'_>) {
    use catcard_wallet::address;
    use catcard_wallet::bip32::ChildNumber;

    // No master key is held here at all. Account keys come from `pubkeys`, which derives
    // one from the seed the first time this session asks and keeps the public half after
    // that -- so re-entering this screen, or moving back to an account already seen, costs
    // nothing instead of the ~2.6 s the secure element and BIP-39 want. Below the account
    // everything is unhardened, so the chain and the index need no private key.
    // Registered multisig wallets sit past the single-signature types on the same axis.
    // Their addresses come out of the wallet record, not out of this seed: that is the
    // point of looking at them here, since an address a cosigner cannot reproduce is one
    // nobody can spend from.
    #[cfg(not(feature = "board-mk3"))]
    let wallets = crate::msimport::registered(gate, login, ui.panel);
    #[cfg(feature = "board-mk3")]
    let wallets: &[catcard_wallet::multisig::Multisig] = &[];
    let entries = PROTOCOLS.len() + wallets.len();
    // The chain key for the type, account and chain on screen, kept so that walking the
    // index does not redo the one unhardened step each frame.
    let mut cached: Option<(usize, u32, u32, catcard_wallet::bip32::ExtendedPubKey)> = None;
    // The account whose unlock the owner declined, if any. Asking again on the next frame
    // would be a prompt they cannot get past; asking again once they move to a different
    // type or account is them asking for it.
    let mut refused_at: Option<(usize, u32)> = None;

    // How many characters of the address fit on one line **in the large face**, asked of the
    // renderer rather than worked out from the panel width: it keeps a gutter for the scroll
    // arrows and clips text at it, so one column too many leaves the last glyph sliced down
    // the middle -- and half a character at the end of an address is indistinguishable from
    // a different one. The address is longer than the line either way, so it is shown
    // start...end (see `ellipsize_middle`): the two ends are what an eye compares against a
    // watch-only wallet, and one clean line beats a wrap.
    let cols = catcard_ui::scroll::text_cols(
        &display::FONTS,
        catcard_ui::scroll::Size::Body,
        display::SCREEN_W,
    );
    let mut index: u32 = 0;
    let mut proto = 0usize;
    let mut account: u32 = 0;
    let mut chain: u32 = 0;
    let mut events = [Event::Pressed(Key::Cancel); KEYS];
    let mut keys: heapless::Vec<Key, { KEYS + 1 }> = heapless::Vec::new();
    loop {
        // Past the single-signature types, `proto` names a registered wallet instead.
        let wallet = proto
            .checked_sub(PROTOCOLS.len())
            .and_then(|i| wallets.get(i));
        // Only read when `wallet` is none; clamped so the index cannot leave the table.
        let kind = PROTOCOLS[proto.min(PROTOCOLS.len() - 1)];
        let mut buf = [0u8; address::MAX_ADDRESS_LEN];
        let mut path = Line::new();
        let mut title: heapless::String<24> = heapless::String::new();

        let addr = if let Some(wallet) = wallet {
            // No derivation of ours: the wallet's own cosigner records build the script,
            // and the address is that script's. Public throughout, so no masked region.
            let _ = write!(title, "{}-of-{} multisig", wallet.m, wallet.n());
            let _ = write!(path, ".../{chain}/{index}");
            let mut spk = [0u8; 34];
            wallet
                .script_pubkey(chain, index, &mut spk)
                .ok()
                .and_then(|n| address::from_script(&spk[..n], crate::prefs::network(), &mut buf))
        } else {
            // First time this type, account and chain are asked for: take the account key
            // -- from this session, or from the seed if this is the first ask -- and step
            // once to the chain. That step is public and quick; the seed is what is slow,
            // and `pubkeys` pays for it at most once per account.
            if !matches!(cached, Some((p, a, c, _)) if (p, a, c) == (proto, account, chain)) {
                let account_key = (refused_at != Some((proto, account)))
                    .then(|| {
                        crate::pubkeys::account_key(gate, login, ui, "Addresses", kind, account)
                    })
                    .flatten();
                refused_at = account_key.is_none().then_some((proto, account));
                cached = account_key
                    .and_then(|acct| {
                        ChildNumber::normal(chain)
                            .ok()
                            .and_then(|c| acct.derive_child(c).ok())
                    })
                    .map(|key| (proto, account, chain, key));
            }
            let _ = title.push_str(kind_name(kind));
            let _ = write!(
                path,
                "m/{}h/0h/{account}h/{chain}/{index}",
                kind.bip44_purpose()
            );
            // Public derivation from the chain's extended public key: no private key is
            // involved, so this needs no masked region and costs the host nothing to
            // watch. The index moves with the type, so the same position can be compared
            // across them.
            cached.as_ref().map(|(_, _, _, k)| *k).and_then(|chain| {
                ChildNumber::normal(index)
                    .ok()
                    .and_then(|c| chain.derive_child(c).ok())
                    .and_then(|k| {
                        address::encode(kind, crate::prefs::network(), &k.public_key, &mut buf).ok()
                    })
            })
        };
        let mut shown = Line::new();
        match addr {
            Some(n) => {
                let s = core::str::from_utf8(&buf[..n]).unwrap_or("");
                ellipsize_middle(s, cols, &mut shown);
            }
            // A child index that lands on an invalid scalar is vanishingly rare, but the
            // screen must not lie about it: show a gap rather than a wrong address.
            None => {
                let _ = shown.push_str("(no address)");
            }
        }
        // Name the keys the way the owner sees them. `5`/`8`/`7`/`9` is what the firmware
        // reads, but the keypad prints arrows on those keys and the Q1 has real arrow keys,
        // so digits here would send someone hunting for a number that is not the point.
        //
        // `2` is a digit and stays one: it is not on an axis, and the boards that have an
        // NFC tag print a plain `2` on that key.
        let mut key_hint = Line::new();
        let _ = write!(
            key_hint,
            "{} QR   {} back",
            display::CONFIRM_KEY,
            display::CANCEL_KEY
        );
        #[cfg(not(feature = "board-mk3"))]
        let _ = write!(key_hint, "   6 export");

        // The address in the large face, everything else in the small one. It is the only
        // thing on the screen worth reading carefully, and the elision costs less than the
        // squint did -- the whole of it, in blocks of four, is one keypress away.
        let mut doc: heapless::Vec<catcard_ui::scroll::Line, 10> = heapless::Vec::new();
        let _ = doc.push(catcard_ui::scroll::Line::title(title.as_str()));
        let _ = doc.push(catcard_ui::scroll::Line::body(path.as_str()).small());
        let _ = doc.push(catcard_ui::scroll::Line::body(shown.as_str()));
        let _ = doc.push(catcard_ui::scroll::Line::body("up/down address").small());
        let _ = doc.push(catcard_ui::scroll::Line::body("left/right type").small());
        // A multisig wallet has no account axis here: the account is fixed by the
        // descriptor its cosigners agreed on, so offering to change it would be offering
        // a different wallet's addresses under this one's name.
        let _ = doc.push(
            catcard_ui::scroll::Line::body(match (wallet.is_some(), chain) {
                (true, 0) => "0 change chain",
                (true, _) => "0 receive chain",
                (false, 0) => "1/3 account  0 change chain",
                (false, _) => "1/3 account  0 receive chain",
            })
            .small(),
        );
        // The typed axes, on the three digits the arrows and the chain do not already
        // use. `2` and `4` are what stock's "Account Number" and "Start Idx" rows do --
        // type the number instead of stepping to it, which is the difference between
        // reaching account 100 in one screen and in a hundred presses.
        // Source: hw-reference/menu-map-mk4-mk5-q1-v5.6.2.md §AE [C]
        let _ = doc.push(
            catcard_ui::scroll::Line::body(if wallet.is_some() {
                "4 start idx"
            } else {
                "2 account  4 start idx  6 to card"
            })
            .small(),
        );
        let _ = doc.push(catcard_ui::scroll::Line::body(key_hint.as_str()).small());
        let view = catcard_ui::scroll::ScrollView::build(
            &doc,
            display::SCREEN_W,
            display::SCREEN_H,
            display::FONTS,
        );
        display::draw(ui.panel, |c| catcard_ui::scroll::render(c, &view));

        wait_for_release(ui);
        'wait: loop {
            let _ = usbtask::pump();
            crate::pinentry::pressed_keys(ui.pad, ui.matrix, ui.drbg, &mut events, &mut keys);
            for k in keys.iter() {
                match k {
                    Key::Cancel => return,
                    // The address as a QR: what the owner came here to compare against a
                    // watch-only wallet, without reading out 42 characters.
                    Key::Confirm => {
                        if let Some(n) = addr {
                            let text = core::str::from_utf8(&buf[..n]).unwrap_or("");
                            match wallet {
                                Some(w) => address_qr_of(
                                    ui,
                                    text,
                                    w.kind == catcard_wallet::multisig::Kind::P2wsh,
                                ),
                                None => address_qr(ui, text, kind),
                            }
                        }
                        break 'wait;
                    }
                    Key::Digit(8) => {
                        index = index.saturating_add(1);
                        break 'wait;
                    }
                    Key::Digit(5) => {
                        index = index.saturating_sub(1);
                        break 'wait;
                    }
                    // Left and right walk the address types, wrapping both ways.
                    Key::Digit(9) => {
                        proto = (proto + 1) % entries;
                        index = 0;
                        break 'wait;
                    }
                    Key::Digit(7) => {
                        proto = (proto + entries - 1) % entries;
                        index = 0;
                        break 'wait;
                    }
                    // Accounts are separate wallets under one seed; the chain is receive or
                    // change. Both restart the index, because address 5 of one account has
                    // nothing to do with address 5 of another.
                    Key::Digit(3) if wallet.is_none() => {
                        account = account.saturating_add(1);
                        index = 0;
                        break 'wait;
                    }
                    Key::Digit(1) if wallet.is_none() => {
                        account = account.saturating_sub(1);
                        index = 0;
                        break 'wait;
                    }
                    // The account typed rather than stepped to, which is what stock's
                    // "Account Number" row does: account 100 is one screen away instead
                    // of a hundred presses, and the number is read back before it is
                    // used. Source: hw-reference/menu-map-mk4-mk5-q1-v5.6.2.md §AE [C]
                    Key::Digit(2) if wallet.is_none() => {
                        if let Some(n) =
                            ask_number(ui, "Addresses", None, "account", "empty is account 0")
                        {
                            account = n;
                            index = 0;
                        }
                        break 'wait;
                    }
                    // Where the walk starts, stock's "Start Idx". The same axis the
                    // up/down keys move, reached in one go -- checking the address a
                    // wallet is showing at index 312 is the case this exists for.
                    Key::Digit(4) => {
                        if let Some(n) =
                            ask_number(ui, "Addresses", None, "start", "empty starts at 0")
                        {
                            index = n;
                        }
                        break 'wait;
                    }
                    // What is on screen, written out from here on.
                    // Getting what is on screen *out*: to a file, or onto the tag. Both
                    // live behind one key because every digit is spoken for -- the ten
                    // are the four axes, the two typed values and this -- and because
                    // they are the same question asked of two media.
                    Key::Digit(6) => {
                        #[cfg(not(feature = "board-mk3"))]
                        {
                            let rows: &[&str] = &["CSV to card", "Share by NFC"];
                            match pick_row(ui, "Export", "what is on screen", rows) {
                                Some(1) => {
                                    if let Some(n) = addr {
                                        let text = core::str::from_utf8(&buf[..n]).unwrap_or("");
                                        crate::nfc::share_address(ui, text);
                                    }
                                    break 'wait;
                                }
                                Some(_) => {}
                                None => break 'wait,
                            }
                        }
                        match (wallet, cached.as_ref().map(|(_, _, _, k)| *k)) {
                            (None, Some(chain_key)) => export_chain_csv(
                                ui,
                                "Addresses",
                                AddressRun {
                                    kind,
                                    coin: 0,
                                    account,
                                    chain,
                                    start: index,
                                },
                                &chain_key,
                            ),
                            // A registered wallet's addresses have no one path: each
                            // cosigner reaches them from their own seed by their own
                            // path, so the column the file wants does not exist here.
                            (Some(_), _) => {
                                message(
                                    ui.panel,
                                    "Addresses",
                                    "each cosigner derives these",
                                    "by a path of their own",
                                );
                                wait_for_any_key(ui);
                            }
                            // No chain key: the unlock was declined, and the screen is
                            // already showing "(no address)".
                            (None, None) => {}
                        }
                        break 'wait;
                    }
                    Key::Digit(0) => {
                        chain = 1 - chain;
                        index = 0;
                        break 'wait;
                    }
                    _ => {}
                }
            }
            display::idle(ui.panel);
        }
    }
}

/// Block until no key is held.
///
/// Every screen that waits for a press calls this first, and it is not a nicety. A key
/// still down from the *previous* screen is reported the moment the next screen starts
/// waiting, so one long press walks through several screens in a row -- which is how a
/// page of seed words went past before it could be read, and why the fix belongs here
/// rather than in the screens.
///
/// `held_count` is the debounced state of the pad, so this asks what is physically down
/// instead of inferring it from events. Scanning still has to run while its events are
/// thrown away: the scan is what updates that state.
/// The wallet's first native-segwit receive address, `m/84h/0h/0h/0/0`.
///
/// What identifies a wallet to its owner: a fingerprint is four bytes of hex, an address is
/// the thing they can compare with their watch-only wallet. `None` if it did not derive.
pub(crate) fn first_receive_address(
    master: &catcard_wallet::bip32::ExtendedPrivKey,
    busy: &mut Working<'_>,
    panel: &mut display::Panel,
) -> Option<heapless::String<{ catcard_wallet::address::MAX_ADDRESS_LEN }>> {
    use catcard_wallet::address::{self, AddressKind};
    use catcard_wallet::bip32::ChildNumber;

    let chain = receive_chain(master, AddressKind::P2wpkh, busy, panel)?;
    let key = chain.derive_child(ChildNumber::normal(0).ok()?).ok()?;
    let mut buf = [0u8; address::MAX_ADDRESS_LEN];
    let n = address::encode(
        AddressKind::P2wpkh,
        crate::prefs::network(),
        &key.public_key,
        &mut buf,
    )
    .ok()?;
    let mut out = heapless::String::new();
    out.push_str(core::str::from_utf8(&buf[..n]).ok()?).ok()?;
    Some(out)
}

pub(crate) fn wait_for_release(ui: &mut Ui<'_>) {
    let mut events = [Event::Pressed(Key::Cancel); KEYS];
    let mut keys: heapless::Vec<Key, { KEYS + 1 }> = heapless::Vec::new();
    loop {
        let _ = usbtask::pump();
        crate::pinentry::pressed_keys(ui.pad, ui.matrix, ui.drbg, &mut events, &mut keys);
        if ui.pad.held_count() == 0 {
            return;
        }
        display::idle(ui.panel);
    }
}

/// Show a scrolling document and wait for a decision: true on confirm, false on cancel.
///
/// Up and down scroll it, as they do everywhere else. For a screen whose content may not
/// fit -- a transaction's destinations -- where the answer must not be given before the
/// whole of it can be read: until the bottom of the document has been on screen, confirm
/// pages down instead of answering, the rule [`DocScreen`] applies with `require_end`.
/// A host that put the output it wanted signed below the fold would otherwise have it
/// signed by an owner who confirmed what they could see. Cancel is taken at any position.
pub(crate) fn scroll_choice(
    ui: &mut Ui<'_>,
    view: &mut catcard_ui::scroll::ScrollView<'_>,
) -> bool {
    let mut events = [Event::Pressed(Key::Cancel); KEYS];
    let mut keys: heapless::Vec<Key, { KEYS + 1 }> = heapless::Vec::new();
    loop {
        display::draw(ui.panel, |c| catcard_ui::scroll::render(c, view));
        wait_for_release(ui);
        'wait: loop {
            let _ = usbtask::pump();
            crate::pinentry::pressed_keys(ui.pad, ui.matrix, ui.drbg, &mut events, &mut keys);
            for k in keys.iter() {
                let (down, step) = match k {
                    Key::Confirm if view.at_end() => return true,
                    // Not read to the end yet: a page forward, never an answer.
                    Key::Confirm => (true, view.line_step()),
                    Key::Cancel => return false,
                    Key::Digit(8) => (true, 1),
                    Key::Digit(5) => (false, 1),
                    // An unused key. Keep waiting rather than repainting the same frame,
                    // as `show_doc` does with `DocFlow::Ignored`.
                    _ => continue,
                };
                let before = view.off();
                view.scroll(down, step);
                // Only a view that actually moved is worth a frame. At either end of the
                // document the key changes nothing, and repainting would also re-run
                // `wait_for_release` for no reason.
                if view.off() != before {
                    break 'wait;
                }
            }
            display::idle(ui.panel);
        }
    }
}

/// Whether cancel is being pressed, without waiting for it.
///
/// For a screen that is busy with something of its own and still has to be escapable --
/// a scan that runs until it sees a code. Everything else here waits for a key; this
/// asks and carries on, so the loop it sits in stays the screen's.
///
/// The QR scan and the NFC receive screen both wait this way: one until a code is read,
/// the other until a phone writes to the tag.
#[cfg(not(feature = "board-mk3"))]
pub(crate) fn cancel_pressed(ui: &mut Ui<'_>) -> bool {
    let mut events = [Event::Pressed(Key::Cancel); KEYS];
    let mut keys: heapless::Vec<Key, { KEYS + 1 }> = heapless::Vec::new();
    let _ = usbtask::pump();
    crate::pinentry::pressed_keys(ui.pad, ui.matrix, ui.drbg, &mut events, &mut keys);
    keys.iter().any(|k| matches!(k, Key::Cancel))
}

pub(crate) fn wait_for_any_key(ui: &mut Ui<'_>) {
    wait_for_release(ui);
    let mut events = [Event::Pressed(Key::Cancel); KEYS];
    let mut keys: heapless::Vec<Key, { KEYS + 1 }> = heapless::Vec::new();
    loop {
        // Service USB while this message is up, for the same reason as the main loop:
        // a polled bus that no one pumps is a device the host cannot reach.
        let _ = usbtask::pump();
        crate::pinentry::pressed_keys(ui.pad, ui.matrix, ui.drbg, &mut events, &mut keys);
        if !keys.is_empty() {
            return;
        }
        display::idle(ui.panel);
    }
}

/// Wait for a yes or a no.
///
/// Any other key keeps waiting. This is asked before something irreversible, and "a key
/// was pressed" is not consent — [`wait_for_any_key`] is the one that takes anything.
pub(crate) fn confirmed(ui: &mut Ui<'_>) -> bool {
    // The key that brought us to this question must not also answer it. That matters
    // most here: one of the questions this asks destroys a stored wallet.
    wait_for_release(ui);
    let mut events = [Event::Pressed(Key::Cancel); KEYS];
    let mut keys: heapless::Vec<Key, { KEYS + 1 }> = heapless::Vec::new();
    loop {
        let _ = usbtask::pump();
        crate::pinentry::pressed_keys(ui.pad, ui.matrix, ui.drbg, &mut events, &mut keys);
        for k in keys.iter() {
            match k {
                Key::Confirm => return true,
                Key::Cancel => return false,
                Key::Digit(_) => {}
                Key::Char(_) | Key::Qr => {}
            }
        }
        display::idle(ui.panel);
    }
}

/// A yes/no question, with the keys named the way this board labels them.
pub(crate) fn ask(panel: &mut display::Panel, head: &str, a: &str, b: &str) {
    use catcard_ui::canvas::Canvas;
    use catcard_ui::icons;
    display::draw(panel, |c| {
        catcard_ui::widgets::message(c, &display::LAYOUT, head, a, b);
        let f = display::LAYOUT.body;
        let gap = 3 * f.advance(b' ');
        let total = icons::key_hint_width(f, display::CONFIRM, "yes")
            + gap
            + icons::key_hint_width(f, display::CANCEL, "no");
        let mut x = c.width().saturating_sub(total) / 2;
        let y = c.height().saturating_sub(f.line_height() + 2);
        x = icons::draw_key_hint(c, f, x, y, display::CONFIRM, "yes") + gap;
        icons::draw_key_hint(c, f, x, y, display::CANCEL, "no");
    });
}

/// What the entropy screens report.
///
/// A struct because seven numbers passed positionally is one transposed pair away from
/// telling someone their wallet has more entropy behind it than it does.
struct Gathered {
    /// Bytes each of this board's sources has answered with during *this* generation.
    read: heapless::Vec<(crate::trng::Kind, usize), 4>,
    /// Credited bits and distinct hardware TRNGs the pool counts right now (this includes
    /// what boot already collected -- the chip, the elements and startup timing).
    bits: u32,
    chips: u32,
    /// What this board's policy demands before a seed may be drawn at all.
    need_bits: u32,
    need_chips: u32,
}

impl Gathered {
    fn lines(&self, out: &mut heapless::Vec<Line, 6>) {
        for &(kind, n) in &self.read {
            let mut l = Line::new();
            // A source mixed in but not trusted to count says so, rather than letting its
            // bytes read as if they carried the seed.
            let _ = write!(
                l,
                "{:<3}  read {n:5} bytes{}",
                kind.label(),
                if kind.credited() { "" } else { " mixed" }
            );
            let _ = out.push(l);
        }
        let mut l = Line::new();
        let _ = write!(l, "chips  {} of {} needed", self.chips, self.need_chips);
        let _ = out.push(l);
        let mut l = Line::new();
        let _ = write!(l, "total {:5} / {} bits", self.bits, self.need_bits);
        let _ = out.push(l);
    }
}

fn gathering(panel: &mut display::Panel, g: &Gathered, pct: u8) {
    let mut lines: heapless::Vec<Line, 6> = heapless::Vec::new();
    g.lines(&mut lines);
    display::draw(panel, |c| {
        catcard_ui::widgets::info(c, &display::LAYOUT, "Collecting entropy", &lines);
        catcard_ui::splash::draw_progress(c, pct);
    });
}

/// What was collected, and whether the policy is actually satisfied.
///
/// Shown before the seed is drawn and acknowledged with a key, so the numbers behind a
/// wallet are seen once by the person who will own it. `passed` is the pool's own
/// verdict from `check()`, not an assumption that the loop above did its job.
fn entropy_report(panel: &mut display::Panel, g: &Gathered, passed: bool) {
    let mut lines: heapless::Vec<Line, 6> = heapless::Vec::new();
    g.lines(&mut lines);
    info(
        panel,
        if passed {
            // Just the verdict, like the failure title: "Entropy OK, any key" is 19
            // characters and the 7px title font clips the last one on a 128px panel
            // ("...any ke"). The screen waits for a key regardless.
            "Entropy OK"
        } else {
            "NOT ENOUGH ENTROPY"
        },
        &lines,
    );
}

/// Fold a finished run into the pool and show what it was worth.
///
/// The digest prefix on this screen is the point of matching the published convention:
/// the owner wrote their rolls down, and `printf '%s' 4316... | sha256sum` on any machine
/// produces the same 32 bytes, so they can check the device used *their* rolls and not
/// something of its own. Unlike stock, where that digest **is** the seed, here it is one
/// contribution among the TRNGs' -- so showing a prefix of it, or recomputing it on a
/// computer that turns out to be compromised, does not hand anyone the wallet.
/// Source: <https://coldcard.com/docs/verifying-dice-roll-math/> [C]
fn mix_user_run(
    ui: &mut Ui<'_>,
    pool: &mut catcard_entropy::EntropyPool,
    run: &catcard_entropy::UserSymbols,
) {
    let noun = run.alphabet().noun();
    let n = run.count();
    let bits = pool.add_user(run);
    crate::catlog!("seed: user {} {} = {} bits", n, noun, bits);

    let d = run.digest();
    let mut lines: heapless::Vec<Line, 6> = heapless::Vec::new();
    let mut l = Line::new();
    let _ = write!(l, "{n} {noun}, +{bits} bits");
    let _ = lines.push(l);
    let mut l = Line::new();
    let _ = write!(l, "sha256 of your {noun}:");
    let _ = lines.push(l);
    let mut l = Line::new();
    let _ = write!(
        l,
        "{:02x}{:02x}{:02x}{:02x} {:02x}{:02x}{:02x}{:02x}",
        d[0], d[1], d[2], d[3], d[4], d[5], d[6], d[7]
    );
    let _ = lines.push(l);
    info(ui.panel, "Mixed in", &lines);
    wait_for_any_key(ui);
}

/// Collect a run of symbols the owner types -- dice faces, coin sides, a keypad mash --
/// and fold it into the pool.
///
/// Two things are credited on different footings, and the distinction is the point. The
/// press *timing* goes in the instant a key lands and is always kept: a human's intervals
/// are unpredictable even when their choices are not. The *values* are credited only when
/// the run clears its gate -- long enough and not dominated by one symbol -- because a
/// short or lopsided run is a pattern the pool must not count. The screen shows both
/// numbers as they are entered: how many symbols, and what they are worth by keyspace
/// (`log2(6)` a roll, so 50 rolls is 129 bits).
///
/// Neither is ever a precondition for a seed. The pool has already met its policy from
/// the hardware TRNGs or it refused outright, and [`EntropyPool::add_user`] cannot
/// replace what is in it -- so this only ever tops up.
///
/// [`EntropyPool::add_user`]: catcard_entropy::EntropyPool::add_user
fn collect_symbols(
    ui: &mut Ui<'_>,
    pool: &mut catcard_entropy::EntropyPool,
    alphabet: catcard_entropy::Alphabet,
) {
    use catcard_entropy::Alphabet;
    use catcard_entropy::user::Rejected;

    let (title, prompt) = match alphabet {
        Alphabet::Dice => ("Roll dice", "keys 1-6 = one roll"),
        Alphabet::Coin => ("Flip a coin", "0=tails 1=heads"),
        Alphabet::Keypad => ("Mash digits", "any digits"),
    };
    let mut run = catcard_entropy::UserSymbols::new(alphabet);
    let mut events = [Event::Pressed(Key::Cancel); KEYS];
    let mut keys: heapless::Vec<Key, { KEYS + 1 }> = heapless::Vec::new();
    // Why the last press was not taken, or why a `y` was not accepted. Cleared on the
    // next press, so it reads as an answer to what was just done.
    let mut warn: Option<Line> = None;
    loop {
        let mut a = Line::new();
        let _ = write!(
            a,
            "{} {}, {} bits",
            run.count(),
            alphabet.noun(),
            run.worth_bits()
        );
        let mut hint = Line::new();
        if let Some(w) = &warn {
            hint = w.clone();
        } else if run.count() == 0 {
            let _ = write!(hint, "{prompt}");
        } else if run.weakness().is_none() {
            let _ = write!(hint, "y=use these");
        } else {
            let _ = write!(hint, "more, then y");
        }
        message(ui.panel, title, &a, &hint);

        wait_for_release(ui);
        loop {
            let _ = usbtask::pump();
            crate::pinentry::pressed_keys(ui.pad, ui.matrix, ui.drbg, &mut events, &mut keys);
            if !keys.is_empty() {
                break;
            }
            display::idle(ui.panel);
        }
        warn = None;
        for k in keys.iter() {
            // Every press, whatever key it was and whether or not its value is kept: the
            // cycle counter at a human's press is real if small entropy, and it is the
            // one contribution here that a stuck die cannot spoil.
            pool.add_timing(catcard_hal::dwt::cycles());
            match k {
                Key::Confirm => match run.weakness() {
                    // Too short or too lopsided to count: say which, and keep collecting
                    // rather than credit it. Refusing is the safety property here too.
                    Some(w) => {
                        let mut l = Line::new();
                        let _ = write!(l, "{w}");
                        warn = Some(l);
                    }
                    None => {
                        mix_user_run(ui, pool, &run);
                        return;
                    }
                },
                // Cancel abandons this mode. The timing already mixed stays -- it cannot
                // be unmixed and does no harm -- the values do not; they were never
                // credited, and `run` zeroizes on the way out.
                Key::Cancel => return,
                Key::Digit(d) => {
                    // ASCII, because ASCII is what the digest convention hashes.
                    match run.push(b'0' + d) {
                        Ok(()) => {}
                        Err(Rejected::Full) => {
                            let mut l = Line::new();
                            let _ = write!(l, "that is plenty, y");
                            warn = Some(l);
                        }
                        // A key outside the alphabet (a 7 while rolling a d6) is not a
                        // roll and must not be hashed as one.
                        Err(Rejected::NotInAlphabet) => {
                            let mut l = Line::new();
                            let _ = write!(l, "{prompt}");
                            warn = Some(l);
                        }
                    }
                }
                Key::Char(_) | Key::Qr => {}
            }
        }
    }
}

/// Offer the owner the choice, once the hardware has been collected: this device's own
/// entropy, or that combined with entropy they supplied themselves.
///
/// It is a genuine choice rather than a step, and "device only" is a complete answer --
/// the pool has already met its policy or it refused outright, so none of these can
/// rescue a bad device and none of them is needed by a good one. What they do offer is
/// the one thing a distrustful owner cannot get any other way: material the firmware
/// could not have predicted, in a form they can check afterwards.
fn add_user_entropy(ui: &mut Ui<'_>, pool: &mut catcard_entropy::EntropyPool) {
    use catcard_entropy::Alphabet;

    let mut events = [Event::Pressed(Key::Cancel); KEYS];
    let mut keys: heapless::Vec<Key, { KEYS + 1 }> = heapless::Vec::new();
    loop {
        message(
            ui.panel,
            "Add your own?",
            "1=dice 2=coin 3=mash",
            "y=device only",
        );
        wait_for_release(ui);
        loop {
            let _ = usbtask::pump();
            crate::pinentry::pressed_keys(ui.pad, ui.matrix, ui.drbg, &mut events, &mut keys);
            if !keys.is_empty() {
                break;
            }
            display::idle(ui.panel);
        }
        // Take the first meaningful key of the batch, then redraw the menu.
        let mut done = false;
        for k in keys.iter() {
            match k {
                Key::Confirm | Key::Cancel => {
                    done = true;
                    break;
                }
                Key::Digit(1) => {
                    collect_symbols(ui, pool, Alphabet::Dice);
                    break;
                }
                Key::Digit(2) => {
                    collect_symbols(ui, pool, Alphabet::Coin);
                    break;
                }
                Key::Digit(3) => {
                    collect_symbols(ui, pool, Alphabet::Keypad);
                    break;
                }
                Key::Digit(_) => {}
                Key::Char(_) | Key::Qr => {}
            }
        }
        if done {
            return;
        }
    }
}

/// Create a wallet: draw entropy, store it, verify it, and show the words once.
///
/// The order is the point. The secret is written **and read back before any word reaches
/// the screen**, because words shown for a seed the secure element did not keep are
/// worse than no words at all — someone copies them down and believes they have a
/// backup of a wallet that does not exist.
///
/// User-supplied entropy -- dice, coin flips, a keypad mash -- is *offered* after the
/// hardware collection, as a choice rather than a step; see [`add_user_entropy`]. It is
/// never *required*, and it never replaces anything: the pool has already met its policy
/// or it refuses outright, and a handful of rolls cannot rescue a device whose TRNGs are
/// unhealthy. A seed made with 50 rolls is the seed that would have been made without
/// them, stirred further. See `docs/SECRETS-AND-SETTINGS.md` and `docs/ENTROPY.md`.
// Eight arguments, and clippy is right to say so. Four of them -- panel, pad, matrix,
// drbg -- are the same cluster every action screen drags around, and the remedy is the
// one this file already uses for `Session` and `View`: give them a struct. That is a
// refactor across every screen here rather than a change to this function, so it is
// deferred deliberately and not because the lint is wrong.
#[allow(clippy::too_many_arguments)]
fn new_seed(
    gate: &Callgate,
    login: &mut catcard_pin::Login,
    ui: &mut Ui<'_>,
    pool: Option<&mut catcard_entropy::EntropyPool>,
    words: u8,
) {
    use catcard_wallet::bip39::Mnemonic;
    use zeroize::Zeroize;

    // How much entropy those words carry: 32 bytes for 24, 16 for 12. Anything else is
    // a caller bug rather than a user one, and 24 is the safe way to be wrong.
    let entropy_len = match words {
        12 => 16,
        _ => 32,
    };

    // No pool means it never met its policy at boot. That is a refusal.
    let Some(pool) = pool else {
        message(
            ui.panel,
            "No entropy",
            "the pool missed its",
            "policy at boot",
        );
        wait_for_any_key(ui);
        return;
    };

    // Overwriting a wallet that already exists is the destructive case, and this is the
    // only warning anyone gets. Asked of `key::stored_wallet`, which is the bootloader's
    // flag *and* what the slot turned out to hold: the flag alone says "in use" about a
    // slot whose seed was destroyed, and warning about a wallet that is not there
    // teaches an owner to press through the one warning that matters.
    if crate::key::stored_wallet(login) {
        ask(
            ui.panel,
            "Wallet exists",
            "a new seed DESTROYS",
            "the one stored now",
        );
        if !confirmed(ui) {
            return;
        }
    }
    let mut what = Line::new();
    let _ = write!(what, "{words} words, from this");
    ask(ui.panel, "Create wallet?", &what, "device's own TRNGs");
    if !confirmed(ui) {
        return;
    }

    // Fresh noise from both secure elements, on top of what the boot pool already
    // holds. The boot pool has met its policy or we would not be here; this is added
    // material, not a substitute for it.
    //
    // It goes through `EntropyPool` rather than into a hash of its own, because the
    // pool is what runs the health tests, keeps the sources domain-separated and
    // credits them. A side digest would mix the same bytes twice while skipping all
    // three. An element that fails its health test is mixed in but credited nothing and
    // not counted -- so if too few healthy sources remain, `draw` below refuses, which is
    // the intended outcome; a single bad element cannot by itself block a healthy pool.
    // How long to hold each step on screen. Legibility only: thirty-two counts that
    // flash past in a blink show nothing, and nobody can check a number they cannot
    // read. It contributes no entropy and must never be mistaken for doing so.
    const STEP_PAUSE_CYCLES: u32 = 4_000_000;

    let policy = crate::entropy_policy();
    let kinds = crate::trng::kinds();
    let mut g = Gathered {
        read: kinds.iter().map(|&k| (k, 0usize)).collect(),
        bits: pool.credited_bits(),
        chips: pool.hardware_sources(),
        need_bits: policy.min_bits,
        need_chips: policy.min_hw_sources,
    };

    // Every source this board can read, the same number of *bytes* from each -- not the
    // same number of turns. SE2 produces about a quarter as fast as SE1, so taking turns in
    // lockstep once collected `SE1 512 B, SE2 128 B`, which reads like a broken element and
    // is really a slower one. The chip TRNG is part of this on every board: it once sat
    // inside a check for the mk4+ callgate, and on mk3 a wallet was generated without a
    // single fresh byte from it.
    const TARGET: usize = 512;
    // Bounded, because a source that never answers must not hang a wallet. At SE2's
    // observed rate 512 bytes wants roughly 64 turns; this leaves room and still ends.
    const MAX_PASSES: usize = 160;

    let mut trngs = crate::trng::Trngs::new(Some(gate));
    // A source can decline two ways: `Some(0)` is "nothing ready", `None` a refusal.
    // Counted apart so a generation is a measurement rather than an inference.
    let mut tries = [0usize; 4];
    let mut empty = [0usize; 4];
    let mut failed = [0usize; 4];

    gathering(ui.panel, &g, 0);
    for _ in 0..MAX_PASSES {
        if g.read.iter().all(|&(_, n)| n >= TARGET) {
            break;
        }
        for (i, entry) in g.read.iter_mut().enumerate() {
            let (kind, n) = (entry.0, &mut entry.1);
            if *n >= TARGET {
                continue;
            }
            let _ = usbtask::pump();
            let mut buf = [0u8; 64];
            tries[i] += 1;
            match trngs.read(kind, &mut buf) {
                Some(got) if got > 0 => {
                    pool.add(kind.source(), &buf[..got]);
                    *n += got;
                }
                Some(_) => empty[i] += 1,
                None => failed[i] += 1,
            }
            buf.zeroize();
        }
        g.bits = pool.credited_bits();
        g.chips = pool.hardware_sources();
        let got: usize = g.read.iter().map(|&(_, n)| n.min(TARGET)).sum();
        let pct = got * 100 / (TARGET * g.read.len().max(1));
        gathering(ui.panel, &g, pct.min(100) as u8);
        catcard_hal::dwt::delay_cycles(STEP_PAUSE_CYCLES);
    }
    for (i, &(kind, n)) in g.read.iter().enumerate() {
        crate::catlog!(
            "seed: {} {}B/{}t {}e {}f",
            kind.label(),
            n,
            tries[i],
            empty[i],
            failed[i]
        );
    }

    // With the hardware collected, offer the owner the choice: this device's entropy, or
    // this device's combined with dice, coin flips or a keypad mash of their own. It is
    // optional -- the pool has already met its policy from the TRNGs -- and only ever
    // tops up, but it costs nothing and lets a distrustful owner add material the
    // firmware could not have predicted.
    add_user_entropy(ui, pool);

    // The pool's own verdict, not ours: enough credited bits from enough healthy hardware
    // TRNGs. A failed source counted for neither, so this is where too few healthy sources
    // becomes visible, before any word is shown.
    let passed = pool.check().is_ok();
    // The user's turn may have added bits; the report shows what the draw will rest on.
    g.bits = pool.credited_bits();
    g.chips = pool.hardware_sources();
    crate::catlog!(
        "seed: {} bits from {} chips, policy {}",
        g.bits,
        g.chips,
        if passed { "ok" } else { "FAILED" }
    );
    entropy_report(ui.panel, &g, passed);
    wait_for_any_key(ui);

    // Exactly as much as those words carry, rather than 256 bits with half thrown away.
    // Stock draws a full seed and truncates for twelve words; the pool can be asked for
    // the length actually wanted, and a draw that is all used is easier to reason about
    // than one that is half discarded.
    let mut entropy = [0u8; 32];
    // The draw is the moment the wallet's key comes into existence, so it runs masked
    // together with everything computed from it: nothing a host can time happens between
    // the entropy appearing and its being encoded. A refusal is reported only once the
    // region has closed.
    let made = crate::keywork::run(|kw| {
        let out = pool.draw(&mut entropy[..entropy_len]).map(|()| {
            (
                catcard_callgate::pin::encode_bip39(&entropy[..entropy_len]),
                Mnemonic::from_entropy(&entropy[..entropy_len], kw),
            )
        });
        entropy.zeroize();
        out
    });
    let (encoded, mnemonic) = match made {
        Ok(pair) => pair,
        Err(e) => {
            // The pool refusing is the entropy design working as intended, so report
            // which way it refused rather than a generic failure.
            crate::catlog!("seed: pool refused");
            let mut l = Line::new();
            let _ = write!(l, "{e}");
            info(ui.panel, "Refused", &[l]);
            wait_for_any_key(ui);
            return;
        }
    };

    let (Ok(mut secret), Ok(mnemonic)) = (encoded, mnemonic) else {
        // Both accept 16 and 32 bytes, which is all `entropy_len` can be, so this is
        // unreachable today. It is written out rather than unwrapped because this is
        // the one function that holds a wallet, and a panic here would carry the seed
        // to the panic screen with it.
        message(ui.panel, "Failed", "could not encode", "that seed length");
        wait_for_any_key(ui);
        return;
    };

    // Words first, the quiz second, the secure element last.
    //
    // That order is the safe one, and it is worth being explicit about why, because the
    // obvious ordering is the wrong way round. Commit first and a power loss between
    // the write and the words leaves a wallet in the element that nobody has a backup
    // of. Commit last and the same power loss leaves nothing at all: the user starts
    // again and draws fresh words, having lost only their time.
    //
    // A failed quiz is therefore free. No wallet exists yet, so it costs nothing to
    // send them back to the list rather than discarding twenty-four hand-written words
    // over one mistaken key.
    loop {
        show_words(ui, &mnemonic);
        if quiz(ui, &mnemonic) {
            break;
        }
        ask(ui.panel, "Not confirmed", "read them again", "and retry?");
        if !confirmed(ui) {
            secret.zeroize();
            crate::catlog!("seed: words not confirmed, nothing stored");
            message(ui.panel, "Nothing stored", "no wallet was", "created");
            wait_for_any_key(ui);
            return;
        }
    }

    message(ui.panel, "Applying", "do not disconnect", "");
    // `Login` is driven through the `PinGate` seam, so that the same sequencing runs
    // against a model on the host and the callgate here.
    let pin_gate = crate::pinentry::BootloaderGate::new(gate);
    let outcome = login.set_secret(&pin_gate, &secret);
    if let Err(f) = outcome {
        secret.zeroize();
        crate::catlog!("seed: store failed");
        message(ui.panel, "Not stored", why_failed(f), "any key to go back");
        wait_for_any_key(ui);
        return;
    }

    // Read it back. The words are already written down by this point, so a slot that
    // did not keep them has to be reported rather than assumed good.
    let kept = login.verify_secret(&pin_gate, &secret).unwrap_or(false);
    secret.zeroize();
    if !kept {
        crate::catlog!("seed: read-back mismatch");
        message(
            ui.panel,
            "Not stored",
            "the slot did not keep",
            "what was written",
        );
        wait_for_any_key(ui);
        return;
    }

    crate::catlog!("seed: stored, {} words", mnemonic.word_count());
    message(
        ui.panel,
        "Wallet created",
        "keep those words",
        "somewhere safe",
    );
    wait_for_any_key(ui);
}

/// The outcome of entering one word during a restore.
enum WordPick {
    /// The chosen word, as its BIP-39 wordlist index.
    Word(u16),
    /// Back up to the previous word (or, at the first word, abandon the restore).
    Back,
    /// Finished entering words (OK pressed twice on an empty word).
    Finish,
}

/// The phone-keypad digit a BIP-39 letter sits on, or 0 for a non-letter.
///
/// Standard T9: 2 abc, 3 def, 4 ghi, 5 jkl, 6 mno, 7 pqrs, 8 tuv, 9 wxyz. The wordlist is
/// built so a four-letter prefix identifies a word, which is what makes typing letters on
/// a numeric pad workable -- a few digits narrow 2048 words to a short list.
fn letter_key(b: u8) -> u8 {
    match b {
        b'a'..=b'c' => b'2',
        b'd'..=b'f' => b'3',
        b'g'..=b'i' => b'4',
        b'j'..=b'l' => b'5',
        b'm'..=b'o' => b'6',
        b'p'..=b's' => b'7',
        b't'..=b'v' => b'8',
        b'w'..=b'z' => b'9',
        _ => 0,
    }
}

/// True if `word`'s leading letters map, under T9, onto the typed digit prefix.
fn word_matches(word: &str, typed: &str) -> bool {
    let wb = word.as_bytes();
    let tb = typed.as_bytes();
    wb.len() >= tb.len()
        && wb.iter().zip(tb).all(|(&w, &t)| {
            // A letter typed on a keyboard stands for itself. A digit is the numpad's
            // way of naming the group of letters that share a key, which is still how
            // the mono boards reach them -- and both may appear in one prefix, since
            // nothing stops a Q1 owner typing a digit.
            if t.is_ascii_lowercase() {
                w == t
            } else {
                letter_key(w) == t
            }
        })
}

/// Read one BIP-39 word on the numeric keypad, T9 style.
///
/// Two modes, kept separate because the digit keys mean different things in each and a
/// screen that used them for both at once could not tell a letter from a cursor move:
///
/// - **Type**: keys 2-9 spell the word's letters; `x` deletes the last, or backs out of
///   the word when nothing is typed; `y` opens the candidate list once there is one.
/// - **Pick**: the arrow keys (5/8) move a cursor over the matching words; `y` chooses,
///   `x` returns to typing to add or remove a letter.
///
/// The word is never guessed for the user: even a single match is confirmed from the list
/// so what lands in the seed is what they saw and chose.
///
/// On an empty word, pressing `y` twice returns [`WordPick::Finish`] -- the "I have entered
/// all my words" signal, since the count is not asked up front.
fn read_word(ui: &mut Ui<'_>, num: usize) -> WordPick {
    use catcard_wallet::bip39::wordlist::ENGLISH;
    // Enough to hold the candidates once a couple of letters have narrowed the list; the
    // pick screen is only offered when the true count is within this.
    const CAND_MAX: usize = 64;

    let mut typed: heapless::String<8> = heapless::String::new();
    // One `y` on an empty word arms the finish; a second confirms it. Any other key clears
    // it, so a stray press cannot end the seed early.
    let mut armed = false;
    let mut events = [Event::Pressed(Key::Cancel); KEYS];
    let mut keys: heapless::Vec<Key, { KEYS + 1 }> = heapless::Vec::new();

    loop {
        // Candidates for the current digit prefix. `count` is the true total; `cands`
        // stops filling at its capacity, so the pick screen is gated on `count`.
        let mut cands: heapless::Vec<u16, CAND_MAX> = heapless::Vec::new();
        let mut count = 0usize;
        if !typed.is_empty() {
            for (i, w) in ENGLISH.iter().enumerate() {
                if word_matches(w, &typed) {
                    count += 1;
                    let _ = cands.push(i as u16);
                }
            }
        }

        // --- Type screen ---
        let mut title = Line::new();
        let _ = write!(title, "Word {num}");
        let mut lines: heapless::Vec<Line, 8> = heapless::Vec::new();
        // Two lines either way, so the screen below is laid out the same on both.
        #[cfg(feature = "board-q1")]
        {
            let mut l = Line::new();
            let _ = l.push_str("type the word");
            let _ = lines.push(l);
            let _ = lines.push(Line::new());
        }
        #[cfg(not(feature = "board-q1"))]
        {
            let mut l = Line::new();
            let _ = l.push_str("2abc 3def 4ghi 5jkl");
            let _ = lines.push(l);
            let mut l = Line::new();
            let _ = l.push_str("6mno 7pqrs 8tuv 9wxyz");
            let _ = lines.push(l);
        }
        let _ = lines.push(Line::new());
        let mut l = Line::new();
        let _ = write!(l, "keys: {typed}");
        let _ = lines.push(l);
        let mut l = Line::new();
        if armed {
            let _ = l.push_str("y again: finish");
        } else if typed.is_empty() {
            let _ = l.push_str("type, or y y = done");
        } else if count == 0 {
            let _ = l.push_str("no match, x=del");
        } else {
            let _ = write!(l, "{count} match, y=list");
        }
        let _ = lines.push(l);
        info(ui.panel, &title, &lines);

        wait_for_release(ui);
        let mut open_list = false;
        'type_wait: loop {
            let _ = usbtask::pump();
            crate::pinentry::pressed_keys(ui.pad, ui.matrix, ui.drbg, &mut events, &mut keys);
            for k in keys.iter() {
                match k {
                    // A letter key.
                    Key::Digit(d @ 2..=9) => {
                        armed = false;
                        let _ = typed.push((b'0' + d) as char);
                        break 'type_wait;
                    }
                    // 0 and 1 carry no letters; ignore them rather than mis-spell.
                    Key::Digit(_) => {}
                    Key::Cancel => {
                        armed = false;
                        if typed.pop().is_none() {
                            return WordPick::Back;
                        }
                        break 'type_wait;
                    }
                    Key::Confirm => {
                        if !typed.is_empty() {
                            if count > 0 && count <= CAND_MAX {
                                open_list = true;
                                break 'type_wait;
                            }
                        } else if armed {
                            // Second `y` on an empty word: that is the end of the seed.
                            return WordPick::Finish;
                        } else {
                            armed = true;
                            break 'type_wait;
                        }
                    }
                    // A letter, on a board with a keyboard. Typed straight in: the digit
                    // legend below is the numpad's way of reaching the same letters.
                    Key::Qr => {}
                    Key::Char(c @ b'a'..=b'z') => {
                        armed = false;
                        let _ = typed.push(*c as char);
                        break 'type_wait;
                    }
                    // Upper case, punctuation and space are not in any BIP-39 word.
                    Key::Char(_) => {}
                }
            }
            display::idle(ui.panel);
        }
        if !open_list {
            continue;
        }

        // --- Pick screen --- a scrollable menu of the candidate words, each carrying its
        // index into `cands` as the id.
        let mut lines: heapless::Vec<catcard_ui::scroll::Line, CAND_MAX> = heapless::Vec::new();
        let _ = lines.push(catcard_ui::scroll::Line::title("Pick the word"));
        for (pos, &ci) in cands.iter().enumerate() {
            let _ = lines.push(catcard_ui::scroll::Line::item(
                ENGLISH[ci as usize],
                pos as u32,
            ));
        }
        match show_doc(ui, &lines, false, false) {
            DocExit::Selected(pos) => return WordPick::Word(cands[pos as usize]),
            // Back to typing, keeping what was entered so a letter can be added or removed.
            DocExit::Cancelled | DocExit::Confirmed => continue,
        }
    }
}

/// A short reason for a phrase that would not parse, for the error screen.
fn parse_error(e: catcard_wallet::bip39::Error) -> &'static str {
    use catcard_wallet::bip39::Error;
    match e {
        Error::BadChecksum => "checksum is wrong",
        Error::BadWordCount { .. } => "wrong number of words",
        Error::UnknownWord { .. } => "a word is not valid",
        _ => "could not read the seed",
    }
}

/// What the owner chose in the fix-the-seed editor.
enum EditChoice {
    /// Re-enter the word at this position.
    Edit(usize),
    /// Append another word.
    Add,
    /// Discard the whole entry.
    Cancel,
}

/// The ids the editor's non-word rows carry; word rows carry their position, always small.
const EDIT_ADD: u32 = u32::MAX;
const EDIT_CANCEL: u32 = u32::MAX - 1;

/// Show the entered words as a menu so the owner can fix one, add another, or discard.
fn edit_menu(ui: &mut Ui<'_>, idx: &[u16]) -> EditChoice {
    use catcard_ui::scroll::Line as DLine;
    use catcard_wallet::bip39::wordlist::ENGLISH;

    // The words themselves, as text: wiped when the screen leaves, whichever way.
    let mut texts = zeroize::Zeroizing::new(heapless::Vec::<Line, 24>::new());
    for (pos, &i) in idx.iter().enumerate() {
        let mut s = Line::new();
        let _ = write!(s, "{:2}  {}", pos + 1, ENGLISH[i as usize]);
        let _ = texts.push(s);
    }
    let mut lines: heapless::Vec<DLine, 28> = heapless::Vec::new();
    let _ = lines.push(DLine::title("Fix the seed"));
    for (pos, s) in texts.iter().enumerate() {
        let _ = lines.push(DLine::item(s, pos as u32));
    }
    let _ = lines.push(DLine::item("+ add a word", EDIT_ADD));
    let _ = lines.push(DLine::item("x discard all", EDIT_CANCEL));

    match show_doc(ui, &lines, false, false) {
        DocExit::Selected(EDIT_ADD) => EditChoice::Add,
        DocExit::Selected(EDIT_CANCEL) => EditChoice::Cancel,
        DocExit::Selected(pos) => EditChoice::Edit(pos as usize),
        // Backing out of the editor discards, same as the explicit row.
        DocExit::Cancelled | DocExit::Confirmed => EditChoice::Cancel,
    }
}

/// Type a BIP-39 phrase on the keypad, and do not hand it back until it checks out.
///
/// The count is not asked: the owner types each word and presses `y` twice to end. The
/// checksum is the whole safety story -- a phrase is a wallet, so nothing is returned
/// until [`Mnemonic::parse`] rebuilds the entropy and verifies it. A phrase that does
/// not check out drops the owner into [`edit_menu`]: the words as a list to fix in
/// place, add to, or discard, re-tested after each change.
///
/// `None` if the owner backed out, in which case the caller says what was not done.
pub(crate) fn read_phrase(ui: &mut Ui<'_>) -> Option<catcard_wallet::bip39::Mnemonic> {
    use catcard_wallet::bip39::{Mnemonic, wordlist::ENGLISH};

    // The phrase as word indices -- the seed, in another spelling. Zeroizing, so every way
    // out of this function wipes the whole buffer, a popped word's slot included.
    let mut idx = zeroize::Zeroizing::new(heapless::Vec::<u16, 24>::new());

    // Enter words until the owner signals the end. `Back` steps to the previous word;
    // backing off the first word abandons the restore.
    loop {
        match read_word(ui, idx.len() + 1) {
            WordPick::Word(i) => {
                if idx.push(i).is_err() {
                    // 24 words is the most a phrase can be; stop taking more and verify.
                    break;
                }
            }
            // Backing off the first word abandons the phrase.
            WordPick::Back => {
                idx.pop()?;
            }
            WordPick::Finish => break,
        }
    }

    // Verify, and until it checks out let the owner fix it. Each pass reparses the phrase.
    Some(loop {
        let mut phrase: heapless::String<256> = heapless::String::new();
        for (n, &i) in idx.iter().enumerate() {
            if n > 0 {
                let _ = phrase.push(' ');
            }
            let _ = phrase.push_str(ENGLISH[i as usize]);
        }
        // Parsing rebuilds the entropy and checks its checksum: private-key work, masked.
        let parsed = crate::keywork::run(|kw| Mnemonic::parse(&phrase, kw));
        // SAFETY: zeroing then clearing the phrase's own bytes; the empty buffer that
        // remains is trivially valid UTF-8.
        let raw = unsafe { phrase.as_mut_vec() };
        raw.iter_mut().for_each(|b| *b = 0);
        raw.clear();

        match parsed {
            Ok(m) => break m,
            Err(e) => {
                message(ui.panel, "Bad seed", parse_error(e), "any key to fix");
                wait_for_any_key(ui);
                match edit_menu(ui, &idx) {
                    EditChoice::Edit(pos) => {
                        if let WordPick::Word(i) = read_word(ui, pos + 1) {
                            idx[pos] = i;
                        }
                    }
                    EditChoice::Add => {
                        if idx.len() < 24
                            && let WordPick::Word(i) = read_word(ui, idx.len() + 1)
                        {
                            let _ = idx.push(i);
                        }
                    }
                    EditChoice::Cancel => return None,
                }
            }
        }
    })
}

/// Restore a wallet from a written-down BIP-39 phrase, typed on the keypad.
///
/// The count is not asked: the owner types each word and presses `y` twice to end. The
/// checksum is the whole safety story -- a restore stores whatever it is given, so nothing
/// is committed until [`Mnemonic::parse`] rebuilds the entropy and verifies the checksum.
/// A phrase that does not check out drops the owner into [`edit_menu`]: the words shown as
/// a list to fix in place, add to, or discard, and the checksum is re-tested after each
/// change. Only once it checks out is the import offered and stored.
///
/// The same write-then-read-back-then-claim order as [`new_seed`], and for the same
/// reason: a slot that did not keep the words must be reported, not assumed.
fn import_seed(gate: &Callgate, login: &mut catcard_pin::Login, ui: &mut Ui<'_>) {
    fn cancelled(ui: &mut Ui<'_>) {
        message(ui.panel, "Import cancelled", "nothing was", "stored");
        wait_for_any_key(ui);
    }

    // Overwriting an in-use wallet is the destructive case; this is the only warning.
    // As in `new_seed`: the slot's contents, not the flag alone.
    if crate::key::stored_wallet(login) {
        ask(
            ui.panel,
            "Wallet exists",
            "a restore DESTROYS",
            "the one stored now",
        );
        if !confirmed(ui) {
            return;
        }
    }
    message(
        ui.panel,
        "Import seed",
        "enter each word,",
        "then y y to finish",
    );
    wait_for_any_key(ui);

    let Some(mnemonic) = read_phrase(ui) else {
        cancelled(ui);
        return;
    };

    // It checks out: offer to complete, then store.
    let mut what = Line::new();
    let _ = write!(what, "{} words, checksum ok", mnemonic.word_count());
    ask(ui.panel, "Restore this?", &what, "y to store it");
    if !confirmed(ui) {
        cancelled(ui);
        return;
    }

    if !store_seed(gate, login, ui, mnemonic.entropy()) {
        return;
    }

    crate::catlog!("seed: restored, {} words", mnemonic.word_count());
    message(ui.panel, "Wallet restored", "your seed is", "now stored");
    wait_for_any_key(ui);
}

/// Write `entropy` into the secure element as the device's seed, and check it stuck.
///
/// The committing half of every restore -- typed words, a joined split, a scanned SeedQR
/// -- so that they cannot drift apart in the one place where drifting apart loses a
/// wallet. Returns whether the slot now holds this seed; it has already said why if not.
///
/// **Write, read back, then claim.** A slot that did not keep what was written has to be
/// reported rather than assumed: the owner is about to put the device in a drawer and
/// the paper in a safe, and "stored" is the last thing they will be told before that.
///
/// The caller says what it was -- restored, joined, scanned -- since only it knows.
pub(crate) fn store_seed(
    gate: &Callgate,
    login: &mut catcard_pin::Login,
    ui: &mut Ui<'_>,
    entropy: &[u8],
) -> bool {
    use zeroize::Zeroize as _;

    let Ok(mut secret) = catcard_callgate::pin::encode_bip39(entropy) else {
        message(ui.panel, "Failed", "could not encode", "that seed");
        wait_for_any_key(ui);
        return false;
    };

    message(ui.panel, "Applying", "do not disconnect", "");
    let pin_gate = crate::pinentry::BootloaderGate::new(gate);
    if let Err(f) = login.set_secret(&pin_gate, &secret) {
        secret.zeroize();
        crate::catlog!("seed: store failed");
        message(ui.panel, "Not stored", why_failed(f), "any key to go back");
        wait_for_any_key(ui);
        return false;
    }
    let kept = login.verify_secret(&pin_gate, &secret).unwrap_or(false);
    secret.zeroize();
    if !kept {
        crate::catlog!("seed: store read-back mismatch");
        message(
            ui.panel,
            "Not stored",
            "the slot did not keep",
            "what was written",
        );
        wait_for_any_key(ui);
        return false;
    }
    // The stored slot holds a wallet now, whatever the menu last believed.
    crate::key::note_stored_seed(true);
    true
}

/// Ask for some of the words back, before anything is committed.
///
/// The only evidence the device ever gets that the words were written down rather than
/// paged past. It runs before the secret reaches the element, so failing it costs
/// nothing: no wallet exists yet and the caller offers the list again.
///
/// Decoys come from the same wordlist as the answer, so nothing about the shape or
/// rarity of an option narrows it down, and the three are shuffled by the DRBG rather
/// than placed — the correct one must not sit in a predictable slot.
///
/// Returns false on a wrong answer or a cancel; the caller stores nothing either way.
fn quiz(ui: &mut Ui<'_>, m: &catcard_wallet::bip39::Mnemonic) -> bool {
    use catcard_wallet::bip39::wordlist::{ENGLISH, WORD_COUNT};
    const ASKS: usize = 3;
    const CHOICES: usize = 3;

    let total = m.word_count();
    for _ in 0..ASKS {
        // A DRBG failure means it wants reseeding. Refusing is the only safe answer: a
        // quiz whose questions are predictable proves nothing.
        let Ok(pos) = ui.drbg.below(total as u32) else {
            return false;
        };
        let pos = pos as usize;
        let Some(correct) = m.words().nth(pos) else {
            return false;
        };

        let mut choices = [correct; CHOICES];
        for i in 1..CHOICES {
            loop {
                let Ok(pick) = ui.drbg.below(WORD_COUNT as u32) else {
                    return false;
                };
                let w = ENGLISH[pick as usize];
                // Distinct from the answer and from the other decoys, or the question
                // has two right answers or fewer than three options.
                if w != correct && !choices[..i].contains(&w) {
                    choices[i] = w;
                    break;
                }
            }
        }
        let _ = ui.drbg.shuffle(&mut choices);

        let mut lines: heapless::Vec<Line, { CHOICES + 1 }> = heapless::Vec::new();
        for (i, w) in choices.iter().enumerate() {
            let mut l = Line::new();
            let _ = write!(l, "{}  {w}", i + 1);
            let _ = lines.push(l);
        }
        let mut hint = Line::new();
        let _ = hint.push_str("y = skip");
        let _ = lines.push(hint);
        let mut title = Line::new();
        let _ = write!(title, "Which is word {}?", pos + 1);

        // Loop this one question so a declined skip re-asks it rather than failing.
        loop {
            info(ui.panel, &title, &lines);
            match read_choice(ui, CHOICES) {
                Choice::Pick(i) if choices[i] == correct => break,
                // A wrong pick or a cancel fails the quiz -- the caller offers the list
                // again, and nothing is stored yet, so it costs only time.
                Choice::Pick(_) | Choice::Cancel => return false,
                Choice::Skip => {
                    ask(
                        ui.panel,
                        "Skip the check?",
                        "store without",
                        "confirming words?",
                    );
                    if confirmed(ui) {
                        return true;
                    }
                    // Declined: ask this question again.
                }
            }
        }
    }
    true
}

/// What a person did at a quiz question.
enum Choice {
    /// Picked numbered option `0..n`.
    Pick(usize),
    /// Pressed `y` -- asking to skip the check.
    Skip,
    /// Backed out.
    Cancel,
}

/// Wait for one of `n` numbered choices, a skip (`y`), or a cancel (`x`).
fn read_choice(ui: &mut Ui<'_>, n: usize) -> Choice {
    wait_for_release(ui);
    let mut events = [Event::Pressed(Key::Cancel); KEYS];
    let mut keys: heapless::Vec<Key, { KEYS + 1 }> = heapless::Vec::new();
    loop {
        let _ = usbtask::pump();
        crate::pinentry::pressed_keys(ui.pad, ui.matrix, ui.drbg, &mut events, &mut keys);
        for k in keys.iter() {
            match k {
                Key::Cancel => return Choice::Cancel,
                Key::Confirm => return Choice::Skip,
                Key::Digit(d) if *d >= 1 && (*d as usize) <= n => {
                    return Choice::Pick(*d as usize - 1);
                }
                _ => {}
            }
        }
        display::idle(ui.panel);
    }
}

/// Format the SD card to the SD standard: one MBR partition filling the card, holding the
/// filesystem its capacity tier calls for -- FAT16 up to 2 GB, FAT32 up to 32 GB, exFAT
/// above. This erases everything on the card, so it asks twice, and shows what it is about
/// to write first.
fn format_sd(ui: &mut Ui<'_>) {
    use catcard_hal::sdmmc::Sdmmc;

    // SAFETY: nothing else has claimed SDMMC1 or its pins; this screen is its only user and
    // the menu waits for it to return before it can be chosen again.
    let mut dev = match unsafe { Sdmmc::init(&catcard_board::BOARD) } {
        Ok(d) => d,
        Err(_) => {
            message(ui.panel, "Format SD", "no SD controller", "press a key");
            wait_any_key(ui);
            return;
        }
    };
    let card = match catcard_sd::init(&mut dev) {
        Ok(c) => c,
        Err(catcard_sd::Error::NoCard) => {
            message(ui.panel, "Format SD", "no card in slot", "press a key");
            wait_any_key(ui);
            return;
        }
        Err(e) => {
            crate::catlog!("sd: card would not start: {:?}", e);
            message(ui.panel, "Format SD", "card would not start", "press a key");
            wait_any_key(ui);
            return;
        }
    };

    // Which filesystem the card's size calls for, shown before anyone commits.
    let fs = catcard_sd::format::standard_fs(card.blocks as u64);
    let mut summary = Line::new();
    let _ = write!(summary, "{} MiB  {}", card.mib(), fs.name());
    ask(
        ui.panel,
        "Format SD card?",
        summary.as_str(),
        "ERASES everything",
    );
    if !confirmed(ui) {
        return;
    }
    ask(
        ui.panel,
        "Really format?",
        "all data is lost",
        "cannot be undone",
    );
    if !confirmed(ui) {
        return;
    }

    // A volume serial from the UI DRBG, so two cards do not come out sharing one.
    let mut id = [0u8; 4];
    let _ = ui.drbg.generate(&mut id);
    let volume_id = u32::from_le_bytes(id);

    message(ui.panel, "Formatting", "do not remove card", "");
    let sectors = catcard_sd::Sectors::new(dev, card);
    match catcard_sd::format::format(sectors, volume_id, "CATCARD") {
        Ok(fs) => {
            let mut done = Line::new();
            let _ = write!(done, "{} ready", fs.name());
            message(ui.panel, "Formatted", done.as_str(), "press a key");
        }
        Err(catcard_sd::format::FormatError::TooSmall) => {
            message(ui.panel, "Not formatted", "card too small", "press a key")
        }
        Err(catcard_sd::format::FormatError::Io(_)) => message(
            ui.panel,
            "Not formatted",
            "card write failed",
            "press a key",
        ),
        Err(catcard_sd::format::FormatError::Layout(_)) => message(
            ui.panel,
            "Not formatted",
            "size not supported",
            "press a key",
        ),
    }
    wait_any_key(ui);
}

/// Read one card password, capped at the card's own 16-byte limit.
///
/// The returned [`Entry`] is the caller's to [`Entry::clear`] on every path -- it holds the
/// password in the clear until then. `None` means cancelled or refused (empty, or too long).
///
/// [`Entry`]: catcard_ui::textentry::Entry
/// [`Entry::clear`]: catcard_ui::textentry::Entry::clear
fn read_card_pwd(ui: &mut Ui<'_>, prompt: &str) -> Option<catcard_ui::textentry::Entry> {
    let mut entry = crate::passphrase::read(ui, prompt)?;
    // Byte length, not character count: the card's `PWDS_LEN` counts bytes, so a short
    // string of multi-byte characters can still be too long for it.
    if entry.is_empty() || entry.as_str().len() > catcard_sd::MAX_LOCK_PWD {
        message(
            ui.panel,
            "Card password",
            "1 to 16 characters",
            "press a key",
        );
        wait_any_key(ui);
        entry.clear();
        return None;
    }
    Some(entry)
}

/// The SD card's own controller-level password lock (CMD42 / LOCK_UNLOCK).
///
/// **Not** encryption of the data: this is the card controller's lock. A card locked this
/// way refuses every read and write until it is unlocked with the password, and most
/// computer card readers cannot drive CMD42 at all -- so a card locked here is effectively
/// unreadable off this device. Forgetting the password leaves only force-erase (total data
/// loss) as a way back.
///
/// The password is typed each time and **never stored on the device**: it lives in an
/// [`Entry`](catcard_ui::textentry::Entry) that is wiped on every path out, and the driver
/// copies it into a `Zeroizing` buffer of its own. Needs no settings store, so it is on
/// every board with a slot, the mk3 included.
fn card_password(ui: &mut Ui<'_>) {
    use catcard_hal::sdmmc::Sdmmc;
    use catcard_sd::LockOp;
    const HEAD: &str = "Card password";

    // SAFETY: nothing else has claimed SDMMC1 or its pins; this screen is its only user
    // and the menu waits for it to return before it can be chosen again.
    let mut dev = match unsafe { Sdmmc::init(&catcard_board::BOARD) } {
        Ok(d) => d,
        Err(_) => {
            message(ui.panel, HEAD, "no SD controller", "press a key");
            wait_any_key(ui);
            return;
        }
    };
    // A locked card still answers identification -- it refuses only data transfers -- so
    // bring-up succeeds on one, which is what lets "Unlock card" be offered at all.
    match catcard_sd::init(&mut dev) {
        Ok(_) => {}
        Err(catcard_sd::Error::NoCard) => {
            message(ui.panel, HEAD, "no card in slot", "press a key");
            wait_any_key(ui);
            return;
        }
        Err(e) => {
            crate::catlog!("sd: card would not start: {:?}", e);
            message(ui.panel, HEAD, "card would not start", "press a key");
            wait_any_key(ui);
            return;
        }
    }

    const WHAT: &[&str] = &[
        "Set password",
        "Change password",
        "Remove password",
        "Unlock card",
        "Force-erase",
    ];
    let Some(pick) = choose(ui, HEAD, "SD hardware lock", WHAT) else {
        return;
    };

    match pick {
        // Set: a fresh password, entered twice so a slip does not lock the card to a
        // password nobody knows.
        0 => {
            ask(
                ui.panel,
                "Set card password?",
                "locks card to this device",
                "readers can't use it",
            );
            if !confirmed(ui) {
                return;
            }
            let Some(mut first) = read_card_pwd(ui, "New password") else {
                return;
            };
            let Some(mut again) = read_card_pwd(ui, "Repeat password") else {
                first.clear();
                return;
            };
            if first.as_str() != again.as_str() {
                first.clear();
                again.clear();
                message(ui.panel, HEAD, "did not match", "press a key");
                wait_any_key(ui);
                return;
            }
            let op = LockOp::SetPassword(first.as_str().as_bytes());
            run_lock_op(ui, &mut dev, op, "Setting password", "password set");
            first.clear();
            again.clear();
        }
        // Change: clear the old password, then set the new. Two CMD42s -- the card is left
        // with no password if the new one never goes on, rather than with both half-applied.
        1 => {
            let Some(mut old) = read_card_pwd(ui, "Old password") else {
                return;
            };
            let Some(mut new) = read_card_pwd(ui, "New password") else {
                old.clear();
                return;
            };
            let Some(mut again) = read_card_pwd(ui, "Repeat new") else {
                old.clear();
                new.clear();
                return;
            };
            if new.as_str() != again.as_str() {
                old.clear();
                new.clear();
                again.clear();
                message(ui.panel, HEAD, "did not match", "press a key");
                wait_any_key(ui);
                return;
            }
            message(ui.panel, HEAD, "changing password", "do not remove card");
            let cleared =
                catcard_sd::lock_unlock(&mut dev, LockOp::ClearPassword(old.as_str().as_bytes()));
            old.clear();
            match cleared {
                Ok(()) => {
                    let op = LockOp::SetPassword(new.as_str().as_bytes());
                    run_lock_op(ui, &mut dev, op, "Setting password", "password changed");
                }
                Err(e) => {
                    crate::catlog!("sd: CMD42 CLR_PWD failed: {:?}", e);
                    message(ui.panel, HEAD, "wrong password?", "press a key");
                    wait_any_key(ui);
                }
            }
            new.clear();
            again.clear();
        }
        // Remove: clear a known password, leaving the card usable by any reader again.
        2 => {
            let Some(mut pwd) = read_card_pwd(ui, "Password") else {
                return;
            };
            let op = LockOp::ClearPassword(pwd.as_str().as_bytes());
            run_lock_op(ui, &mut dev, op, "Removing password", "password removed");
            pwd.clear();
        }
        // Unlock: open a locked card for this session. The password stays set, so the card
        // locks again when it next loses power; "Remove" is how it is cleared for good.
        3 => {
            let Some(mut pwd) = read_card_pwd(ui, "Password") else {
                return;
            };
            let op = LockOp::Unlock(pwd.as_str().as_bytes());
            run_lock_op(ui, &mut dev, op, "Unlocking", "card unlocked");
            pwd.clear();
        }
        // Force-erase: the forgotten-password recovery. Wipes the password AND every byte
        // on the card, cannot be undone, and is never a default -- two confirmations.
        4 => {
            ask(
                ui.panel,
                "Force-erase card?",
                "ERASES all data",
                "the only recovery",
            );
            if !confirmed(ui) {
                return;
            }
            ask(
                ui.panel,
                "Really force-erase?",
                "everything is lost",
                "cannot be undone",
            );
            if !confirmed(ui) {
                return;
            }
            run_lock_op(ui, &mut dev, LockOp::ForceErase, "Erasing", "card erased");
        }
        _ => {}
    }
}

/// Run one CMD42 operation and report the outcome, then wait for a key.
///
/// The password inside `op` is already framed by the caller; this only issues it and puts
/// a word on the screen. A card that refuses -- a wrong password, a card that does not
/// support locking -- is "card refused it" rather than a driver error nobody can read.
fn run_lock_op(
    ui: &mut Ui<'_>,
    dev: &mut catcard_hal::sdmmc::Sdmmc,
    op: catcard_sd::LockOp<'_>,
    working: &str,
    ok: &str,
) {
    message(ui.panel, "Card password", working, "do not remove card");
    match catcard_sd::lock_unlock(dev, op) {
        Ok(()) => message(ui.panel, "Card password", ok, "press a key"),
        Err(e) => {
            crate::catlog!("sd: CMD42 failed: {:?}", e);
            message(ui.panel, "Card password", "card refused it", "press a key");
        }
    }
    wait_any_key(ui);
}

/// Destroy the stored seed.
///
/// `gate 18/3` with `change::SECRET` and seventy-two zero bytes: the same call that
/// stores a wallet, pointed at nothing. Stock uses the bootloader's `fast_wipe`
/// (gate 23), which is not in our ABI and which also resets the device — so nothing
/// could confirm the result. This path can be *checked*, and is: the slot is read back
/// before anyone is told their seed is gone, because that is the one claim this screen
/// must never make wrongly.
///
/// The PIN survives. This erases the wallet, not the device.
///
/// Returns whether the slot is empty afterwards.
fn wipe_seed(gate: &Callgate, login: &mut catcard_pin::Login, ui: &mut Ui<'_>) -> bool {
    use zeroize::Zeroize;

    // Nothing to destroy is worth saying, rather than going through the motions and
    // reporting success for a wallet that never existed -- or for one already destroyed,
    // which the flag alone still calls in use.
    if !crate::key::stored_wallet(login) {
        message(ui.panel, "No wallet", "there is no seed", "to destroy");
        wait_for_any_key(ui);
        return true;
    }

    // Twice, because one question is what people press through. The first says what is
    // lost; the second says it does not come back.
    ask(
        ui.panel,
        "Destroy wallet?",
        "the seed is ERASED",
        "from this device",
    );
    if !confirmed(ui) {
        return false;
    }
    ask(
        ui.panel,
        "Really destroy?",
        "only your words can",
        "ever bring it back",
    );
    if !confirmed(ui) {
        return false;
    }

    message(ui.panel, "Erasing", "do not disconnect", "");
    let mut empty = [0u8; catcard_callgate::pin::SECRET_LEN];
    let pin_gate = crate::pinentry::BootloaderGate::new(gate);
    if let Err(f) = login.set_secret(&pin_gate, &empty) {
        crate::catlog!("wipe: store failed");
        message(ui.panel, "Not erased", why_failed(f), "any key to go back");
        wait_for_any_key(ui);
        return false;
    }

    let bytes_zeroed = login.verify_secret(&pin_gate, &empty).unwrap_or(false);
    empty.zeroize();
    if bytes_zeroed {
        // What the menu asks: the slot holds nothing now, whatever the flag below says.
        crate::key::note_stored_seed(false);
    }

    // Two different questions, and only the second is the device's own opinion.
    //
    // `verify_secret` compares what `gate 18/4` hands back, and the bootloader
    // XOR-masks the slot with `otp_key` going in and coming out
    // (`hw-reference/secure-elements.md` §"PIN → secret flow"). Writing zeros and
    // reading zeros therefore round-trips through the same mask: it proves the write
    // landed, and says nothing about whether the element now counts as empty. What the
    // menu and the next boot actually consult is ZERO_SECRET, so that is what decides
    // the wording here.
    //
    // This distinction is not theoretical. An earlier version checked only the bytes,
    // reported "Wallet erased", and the entry was back after a reboot -- the one wrong
    // answer this screen must never give.
    let flag_empty = matches!(login.step(), catcard_pin::Step::In { zero_secret: true });
    crate::catlog!(
        "wipe: bytes {} flag {}",
        if bytes_zeroed { "zeroed" } else { "MISMATCH" },
        if flag_empty { "EMPTY" } else { "IN USE" }
    );

    match (bytes_zeroed, flag_empty) {
        (true, true) => message(ui.panel, "Wallet erased", "no seed is stored", ""),
        // The write was taken and the slot still counts as used. That is what this
        // bootloader does -- the flag records that a secret was written, not that one is
        // there -- so the seed is gone and the device says so, with the difference named.
        (true, false) => message(
            ui.panel,
            "Wallet erased",
            "zeros were written; the",
            "slot still counts as used",
        ),
        _ => message(ui.panel, "Not erased", "the slot did not", "take the write"),
    }
    wait_for_any_key(ui);
    flag_empty
}

/// Why a gate operation refused, in words that fit a line.
fn why_failed(f: catcard_pin::Failure) -> &'static str {
    match f {
        catcard_pin::Failure::NeedsSetup => "login went stale",
        catcard_pin::Failure::MustWait => "the gate wants a wait",
        catcard_pin::Failure::ImageRefused => "the gate refused it",
        catcard_pin::Failure::Gate(_) => "the callgate failed",
        catcard_pin::Failure::Code(_) => "the bootloader refused",
    }
}

/// Danger zone → Seed tools → View words: the key in force, as its backup is written.
///
/// Words for a words wallet -- the root, a BIP-85 child, a loaded or joined seed -- paged
/// as when it was made. A loaded XPRV or WIF key has no words, so it is shown as what it
/// is, the xprv or WIF string. Asked first, because the whole point of the screen is to
/// put the secret on the glass, and anyone looking over a shoulder gets it too.
fn view_words(gate: &Callgate, login: &mut catcard_pin::Login, ui: &mut Ui<'_>) {
    use crate::key::Loaded;
    use catcard_ui::scroll::Line as DLine;
    use zeroize::Zeroize as _;
    const HEAD: &str = "View words";

    ask(ui.panel, HEAD, "shows your secret", "check nobody can see");
    if !confirmed(ui) {
        return;
    }

    match crate::key::loaded() {
        Some(kind @ (Loaded::Xprv | Loaded::Wif)) => {
            // At most an xprv: 111 characters.
            let mut buf = [0u8; 120];
            let written = if kind == Loaded::Xprv {
                let Some(master) = unlock_master(gate, login, ui, HEAD) else {
                    return;
                };
                crate::keywork::run(|kw| master.write_base58(&mut buf, kw).ok())
            } else {
                // Base58 over the key itself: private-key work, masked like the xprv
                // above, so nothing runs in the middle of it.
                crate::keywork::run(|kw| {
                    crate::key::temporary_wif()
                        .and_then(|key| catcard_wallet::bip85::encode_wif(key, &mut buf, kw).ok())
                })
            };
            let Some(n) = written else {
                buf.zeroize();
                message(ui.panel, HEAD, "could not write it", "any key to go back");
                wait_for_any_key(ui);
                return;
            };
            let text = core::str::from_utf8(&buf[..n]).unwrap_or("");
            let (title, note) = if kind == Loaded::Xprv {
                ("XPRV", "no words: this is the key")
            } else {
                ("WIF key", "no words: this is the key")
            };
            let lines = [
                DLine::title(title),
                DLine::body(note).small(),
                DLine::body(text).secret().wrapped(),
            ];
            show_doc(ui, &lines, true, true);
            buf.zeroize();
        }
        _ => {
            let (mut ent, len) = match seed_entropy(gate, login, ui.panel, HEAD) {
                Ok(got) => got,
                // A stored node or raw master is a wallet with no words. Show what it is
                // instead of refusing: this screen's job is to put the key in front of its
                // owner, and for those the key is the backup.
                Err(why) => return stored_key_shown(gate, login, ui, why),
            };
            let words = crate::keywork::run(|kw| {
                catcard_wallet::bip39::Mnemonic::from_entropy(&ent[..len], kw)
            });
            ent.zeroize();
            let Ok(words) = words else {
                message(ui.panel, HEAD, "seed did not decode", "any key to go back");
                wait_for_any_key(ui);
                return;
            };
            crate::catlog!("view words: {} words shown", words.words().count());
            show_words(ui, &words);
            // The words are half of a passphrase wallet. Said after, so it is the last
            // thing on screen rather than scrolled past.
            if crate::passphrase::is_set() {
                message(
                    ui.panel,
                    HEAD,
                    "and your passphrase:",
                    "it is not in the words",
                );
                wait_for_any_key(ui);
            }
        }
    }
}

/// Settings → Login → Test login.
fn test_login_screen(gate: &Callgate, login: &mut catcard_pin::Login, ui: &mut Ui<'_>) {
    const HEAD: &str = "Test login";
    ask(ui.panel, HEAD, "a wrong PIN here", "counts as a wrong PIN");
    if !confirmed(ui) {
        return;
    }
    #[cfg(not(feature = "board-mk3"))]
    let scramble = crate::settings::scramble_keys();
    #[cfg(feature = "board-mk3")]
    let scramble = false;
    let outcome = crate::pinentry::test_login(gate, ui.panel, ui.matrix, ui.drbg, login, scramble);
    say_test(ui, HEAD, outcome);
}

/// Say how a test login went. True if the PIN was right.
pub(crate) fn say_test(ui: &mut Ui<'_>, head: &str, outcome: crate::pinentry::TestLogin) -> bool {
    use crate::pinentry::TestLogin;
    let mut n: heapless::String<24> = heapless::String::new();
    let (a, b, right) = match outcome {
        TestLogin::Correct { .. } => ("PIN is correct", "", true),
        TestLogin::Cancelled => return false,
        TestLogin::Wrong { attempts_left } => {
            let _ = write!(n, "{attempts_left} tries left");
            ("Wrong PIN", n.as_str(), false)
        }
        TestLogin::TooFewTries { attempts_left } => {
            let _ = write!(n, "only {attempts_left} tries left");
            (n.as_str(), "not spending one", false)
        }
        TestLogin::Failed => ("could not check it", "see the log", false),
    };
    crate::catlog!("test login: {}", if right { "correct" } else { a });
    message(ui.panel, head, a, b);
    wait_for_any_key(ui);
    right
}

/// Settings → Login → Scramble keys.
///
/// **On only after a test login with the keys shuffled succeeds.** A scrambled row that
/// typed something other than it showed would spend an attempt at every login; proving it
/// on this device, with this PIN, before it is saved is what keeps the setting from ever
/// being the thing that locks the owner out. Off needs no proof.
#[cfg(not(feature = "board-mk3"))]
fn scramble_keys_screen(gate: &Callgate, login: &mut catcard_pin::Login, ui: &mut Ui<'_>) {
    const HEAD: &str = "Scramble keys";
    let on = crate::settings::scramble_keys();
    let note = if on { "now on" } else { "now off" };
    let Some(row) = pick_row(ui, HEAD, note, &["On", "Off"]) else {
        return;
    };
    match (row, on) {
        (0, false) => {
            ask(
                ui.panel,
                HEAD,
                "log in once to try it:",
                "the keys will be shuffled",
            );
            if !confirmed(ui) {
                return;
            }
            let outcome =
                crate::pinentry::test_login(gate, ui.panel, ui.matrix, ui.drbg, login, true);
            if !say_test(ui, HEAD, outcome) {
                message(ui.panel, HEAD, "left off", "");
            } else if crate::settings::save_scramble(ui, true) {
                message(ui.panel, HEAD, "on", "from the next login");
            } else {
                message(ui.panel, HEAD, "could not save", "still off");
            }
        }
        (1, true) => {
            if crate::settings::save_scramble(ui, false) {
                message(ui.panel, HEAD, "off", "from the next login");
            } else {
                message(ui.panel, HEAD, "could not save", "still on");
            }
        }
        _ => message(ui.panel, HEAD, "unchanged", ""),
    }
    wait_for_any_key(ui);
}

/// The countdowns offered, stock's range: five minutes to twenty-eight days.
#[cfg(not(feature = "board-mk3"))]
const COUNTDOWN_ROWS: &[&str] = &[
    "Off",
    "5 minutes",
    "15 minutes",
    "30 minutes",
    "1 hour",
    "2 hours",
    "4 hours",
    "8 hours",
    "12 hours",
    "1 day",
    "2 days",
    "3 days",
    "1 week",
    "2 weeks",
    "4 weeks",
];
#[cfg(not(feature = "board-mk3"))]
const COUNTDOWN_MINUTES: [u32; 15] = [
    0, 5, 15, 30, 60, 120, 240, 480, 720, 1440, 2880, 4320, 10080, 20160, 40320,
];
#[cfg(not(feature = "board-mk3"))]
const _: () = assert!(COUNTDOWN_ROWS.len() == COUNTDOWN_MINUTES.len());

/// Settings → Login → Login countdown.
///
/// Every login from then on waits this long after the PIN, and **nothing skips it** -- that
/// is what it is for. So it is asked twice, and before it is saved a ten-second sample runs
/// on this device: the same code the login will run, seen to finish.
#[cfg(not(feature = "board-mk3"))]
fn login_countdown_screen(ui: &mut Ui<'_>) {
    const HEAD: &str = "Login countdown";
    let now = crate::settings::login_countdown();
    let mut note: heapless::String<24> = heapless::String::new();
    let _ = match now {
        Some(m) => write!(note, "now {m} min"),
        None => write!(note, "now off"),
    };
    let Some(row) = pick_row(ui, HEAD, &note, COUNTDOWN_ROWS) else {
        return;
    };
    let minutes = COUNTDOWN_MINUTES[row];
    if minutes == 0 {
        if now.is_none() {
            message(ui.panel, HEAD, "already off", "");
        } else if crate::settings::save_countdown(ui, None) {
            message(ui.panel, HEAD, "off", "from the next login");
        } else {
            message(ui.panel, HEAD, "could not save", "unchanged");
        }
        wait_for_any_key(ui);
        return;
    }

    ask(ui.panel, HEAD, "every login waits", COUNTDOWN_ROWS[row]);
    if !confirmed(ui) {
        return;
    }
    ask(
        ui.panel,
        "Nothing skips it",
        "not even power:",
        "it starts again",
    );
    if !confirmed(ui) {
        return;
    }
    crate::pinentry::countdown(ui.panel, ui.matrix, ui.drbg, 10);
    if crate::settings::save_countdown(ui, Some(minutes)) {
        message(ui.panel, HEAD, COUNTDOWN_ROWS[row], "from the next login");
    } else {
        message(ui.panel, HEAD, "could not save", "unchanged");
    }
    wait_for_any_key(ui);
}

/// Save one preference and say whether it took.
///
/// Every chooser below ends here, so "saved" and "could not save" read the same wherever
/// they come from -- and so that no screen can put a value in force that did not reach
/// the flash. [`crate::prefs::save`] applies `next` only on a successful write.
#[cfg(not(feature = "board-mk3"))]
fn save_pref(
    gate: &Callgate,
    login: &mut catcard_pin::Login,
    ui: &mut Ui<'_>,
    head: &str,
    // The settings key and the text to store under it, together because neither is any
    // use without the other and a pair is harder to transpose than two adjacent `&str`.
    (key, value): (&str, &str),
    next: crate::prefs::Prefs,
    now: &str,
) {
    let raw = crate::prefs::quoted(value);
    if crate::prefs::save(gate, login, ui, head, (key, raw.as_str()), next) {
        message(ui.panel, head, now, "saved");
    } else {
        message(ui.panel, head, "could not save", "unchanged");
    }
    wait_for_any_key(ui);
}

/// The quiet periods offered, stock's own range.
/// Source: hw-reference/menu-map-mk4-mk5-q1-v5.6.2.md §SET "Idle Timeout" [C]
#[cfg(not(feature = "board-mk3"))]
const IDLE_ROWS: &[&str] = &[
    "Off",
    "1 minute",
    "2 minutes",
    "5 minutes",
    "15 minutes",
    "30 minutes",
    "60 minutes",
];
#[cfg(not(feature = "board-mk3"))]
const IDLE_MINUTES: [u32; 7] = [0, 1, 2, 5, 15, 30, 60];
#[cfg(not(feature = "board-mk3"))]
const _: () = assert!(IDLE_ROWS.len() == IDLE_MINUTES.len());

/// The same list for the battery, where the first row defers to the USB-power value
/// rather than switching the timeout off. A device on its battery is the one most likely
/// to be away from its owner, so "off on battery" is not something this offers: see
/// [`catcard_settings::prefs::battery_idle_minutes`].
#[cfg(feature = "board-q1")]
const BATTERY_IDLE_ROWS: &[&str] = &[
    "Same as USB power",
    "1 minute",
    "2 minutes",
    "5 minutes",
    "15 minutes",
    "30 minutes",
    "60 minutes",
];
#[cfg(feature = "board-q1")]
const _: () = assert!(BATTERY_IDLE_ROWS.len() == IDLE_MINUTES.len());

/// Settings → Idle timeout.
///
/// After this long with no key pressed -- from any screen, not just this menu -- the
/// device hands back to the bootloader, which wipes SRAM and asks for the PIN again. The
/// note says what is in force now, because "off" and "60 minutes" look identical on a
/// device that has simply not been left alone yet.
#[cfg(not(feature = "board-mk3"))]
fn idle_timeout_screen(gate: &Callgate, login: &mut catcard_pin::Login, ui: &mut Ui<'_>) {
    const HEAD: &str = "Idle timeout";
    let now = crate::prefs::current();

    // On a board with a battery, which of the two values is being set. Asked first, so
    // the value list below is the same list either way.
    #[cfg(feature = "board-q1")]
    let on_battery = {
        let mut note: Line = Line::new();
        let _ = match (now.idle_minutes, now.battery_idle_minutes) {
            (None, _) => write!(note, "now off"),
            (Some(m), None) => write!(note, "now {m} min, both"),
            (Some(m), Some(b)) => write!(note, "now {m} min, {b} on battery"),
        };
        match pick_row(ui, HEAD, &note, &["On USB power", "On battery"]) {
            Some(row) => row == 1,
            None => return,
        }
    };
    #[cfg(not(feature = "board-q1"))]
    let on_battery = false;

    #[cfg(feature = "board-q1")]
    let rows = if on_battery {
        BATTERY_IDLE_ROWS
    } else {
        IDLE_ROWS
    };
    #[cfg(not(feature = "board-q1"))]
    let rows = IDLE_ROWS;
    let current = if on_battery {
        now.battery_idle_minutes
    } else {
        now.idle_minutes
    };

    let mut note: Line = Line::new();
    let _ = match current {
        Some(m) => write!(note, "now {m} min"),
        None if on_battery => write!(note, "now as USB power"),
        None => write!(note, "now off"),
    };
    let Some(row) = pick_row(ui, HEAD, &note, rows) else {
        return;
    };
    let minutes = IDLE_MINUTES[row];
    let chosen = (minutes > 0).then_some(minutes);
    if chosen == current {
        message(ui.panel, HEAD, "unchanged", rows[row]);
        wait_for_any_key(ui);
        return;
    }

    // Stored as text either way: an empty string is "no value here", which reads back as
    // off for the main timeout and as "follow the main one" for the battery. One shape,
    // one reader, no second encoding to get wrong.
    let mut value: heapless::String<8> = heapless::String::new();
    if let Some(m) = chosen {
        let _ = write!(value, "{m}");
    }
    let (key, next) = if on_battery {
        (
            catcard_settings::prefs::BATT_IDLE,
            crate::prefs::Prefs {
                battery_idle_minutes: chosen,
                ..now
            },
        )
    } else {
        (
            catcard_settings::prefs::IDLE,
            crate::prefs::Prefs {
                idle_minutes: chosen,
                ..now
            },
        )
    };
    save_pref(gate, login, ui, HEAD, (key, &value), next, rows[row]);
}

/// Settings → Display units.
///
/// The rows show the same amount written four ways rather than naming the four units,
/// because the question is what the signing screen will look like and the answer is on
/// the row. Honoured by `crate::signtx::btc`, the only place in this firmware that turns
/// satoshis into text.
#[cfg(not(feature = "board-mk3"))]
fn display_units_screen(gate: &Callgate, login: &mut catcard_pin::Login, ui: &mut Ui<'_>) {
    use catcard_settings::prefs::Units;
    const HEAD: &str = "Display units";
    /// The sample the rows are drawn with: about an eighth of a bitcoin, so every unit
    /// shows a whole part and a fraction rather than a row of zeroes.
    const SAMPLE: u64 = 12_345_678;

    let now = crate::prefs::current();
    let mut texts: heapless::Vec<heapless::String<24>, 4> = heapless::Vec::new();
    for u in Units::ALL {
        let mut t: heapless::String<24> = heapless::String::new();
        let _ = u.write(SAMPLE, &mut t);
        let _ = texts.push(t);
    }
    let rows: heapless::Vec<&str, 4> = texts.iter().map(|t| t.as_str()).collect();

    let mut note: Line = Line::new();
    let _ = write!(note, "now {}", now.units.label());
    let Some(row) = pick_row(ui, HEAD, &note, &rows) else {
        return;
    };
    let chosen = Units::ALL[row];
    if chosen == now.units {
        message(ui.panel, HEAD, "unchanged", chosen.label());
        wait_for_any_key(ui);
        return;
    }
    save_pref(
        gate,
        login,
        ui,
        HEAD,
        (catcard_settings::prefs::UNITS, chosen.code()),
        crate::prefs::Prefs {
            units: chosen,
            ..now
        },
        chosen.label(),
    );
}

/// The caps offered, in the order [`catcard_settings::prefs::FeeCap::CHOICES`] lists them.
#[cfg(not(feature = "board-mk3"))]
const FEE_ROWS: &[&str] = &["10% (default)", "25%", "50%", "No cap"];

/// Settings → Max network fee.
///
/// The cap the PSBT review already enforces: a transaction whose fee is a larger share of
/// what it sends is refused outright, before anything is signed. Raising it is a
/// preference; **removing it is a warned choice**, asked twice, because with no cap a
/// transaction can pay its entire value to miners and the review will still sign it.
#[cfg(not(feature = "board-mk3"))]
fn max_fee_screen(gate: &Callgate, login: &mut catcard_pin::Login, ui: &mut Ui<'_>) {
    use catcard_settings::prefs::FeeCap;
    const HEAD: &str = "Max network fee";

    let now = crate::prefs::current();
    let mut note: Line = Line::new();
    let _ = match now.fee_cap {
        FeeCap::Percent(p) => write!(note, "now {p}% of the amount"),
        FeeCap::None => write!(note, "now NO CAP"),
    };
    let Some(row) = pick_row(ui, HEAD, &note, FEE_ROWS) else {
        return;
    };
    let chosen = FeeCap::CHOICES[row];
    if chosen == now.fee_cap {
        message(ui.panel, HEAD, "unchanged", FEE_ROWS[row]);
        wait_for_any_key(ui);
        return;
    }
    // Never a default, and never one press away: the only setting here that can cost its
    // owner the whole of a transaction.
    if chosen == FeeCap::None {
        ask(
            ui.panel,
            HEAD,
            "remove the fee cap?",
            "no fee will be refused",
        );
        if !confirmed(ui) {
            return;
        }
        ask(
            ui.panel,
            "No cap",
            "a transaction could pay",
            "all of itself to miners",
        );
        if !confirmed(ui) {
            return;
        }
    }
    let value = catcard_settings::prefs::fee_cap_value(chosen);
    save_pref(
        gate,
        login,
        ui,
        HEAD,
        (catcard_settings::prefs::FEE_CAP, &value),
        crate::prefs::Prefs {
            fee_cap: chosen,
            ..now
        },
        FEE_ROWS[row],
    );
}

/// On/Off for a hardware switch: what was chosen, or `None` if it was cancelled or is
/// already what it is.
#[cfg(not(feature = "board-mk3"))]
fn pick_switch(ui: &mut Ui<'_>, head: &str, on: bool) -> Option<bool> {
    let note = if on { "now on" } else { "now off" };
    let want = pick_row(ui, head, note, &["On", "Off"])? == 0;
    if want == on {
        message(ui.panel, head, "unchanged", note);
        wait_for_any_key(ui);
        return None;
    }
    Some(want)
}

/// Settings → Hardware On/Off → USB port.
///
/// Off is a real soft-disconnect: the host sees the device unplug, and nothing is
/// enumerated, answered or injected until it is switched back on. **It can only be
/// switched off from this screen**, which is what makes it safe to offer -- the
/// preference lives under the wallet's key, so it is not read until after the PIN, and a
/// locked device always enumerates.
#[cfg(not(feature = "board-mk3"))]
fn usb_port_screen(gate: &Callgate, login: &mut catcard_pin::Login, ui: &mut Ui<'_>) {
    const HEAD: &str = "USB port";
    let now = crate::prefs::current();
    let Some(want) = pick_switch(ui, HEAD, now.usb_port) else {
        return;
    };
    if !want {
        ask(
            ui.panel,
            HEAD,
            "no host can reach it",
            "until this is back on",
        );
        if !confirmed(ui) {
            return;
        }
    }
    save_pref(
        gate,
        login,
        ui,
        HEAD,
        (
            catcard_settings::prefs::USB_PORT,
            if want { "1" } else { "0" },
        ),
        crate::prefs::Prefs {
            usb_port: want,
            ..now
        },
        if want { "on" } else { "off" },
    );
}

/// Settings → Hardware On/Off → Virtual Disk.
///
/// Whether this device may ever present itself to a host as a USB disk. Honoured by the
/// USB Drive screen under Utils, the one place that re-enumerates as mass storage: with
/// this off that screen refuses to start, so the card is never exposed.
#[cfg(not(feature = "board-mk3"))]
fn virtual_disk_screen(gate: &Callgate, login: &mut catcard_pin::Login, ui: &mut Ui<'_>) {
    const HEAD: &str = "Virtual Disk";
    let now = crate::prefs::current();
    let Some(want) = pick_switch(ui, HEAD, now.virtual_disk) else {
        return;
    };
    save_pref(
        gate,
        login,
        ui,
        HEAD,
        (
            catcard_settings::prefs::VIRTUAL_DISK,
            if want { "1" } else { "0" },
        ),
        crate::prefs::Prefs {
            virtual_disk: want,
            ..now
        },
        if want { "on" } else { "off" },
    );
}

/// Settings → Menu wrapping.
///
/// Whether the cursor comes round the other side at the ends of a list. Off is what every
/// menu here did before the setting existed: pressing past the last item keeps scrolling
/// to reveal the title.
#[cfg(not(feature = "board-mk3"))]
fn menu_wrap_screen(gate: &Callgate, login: &mut catcard_pin::Login, ui: &mut Ui<'_>) {
    const HEAD: &str = "Menu wrapping";
    let now = crate::prefs::current();
    let Some(want) = pick_switch(ui, HEAD, now.menu_wrap) else {
        return;
    };
    save_pref(
        gate,
        login,
        ui,
        HEAD,
        (
            catcard_settings::prefs::MENU_WRAP,
            if want { "1" } else { "0" },
        ),
        crate::prefs::Prefs {
            menu_wrap: want,
            ..now
        },
        if want { "on" } else { "off" },
    );
}

/// Danger zone → Testnet mode.
///
/// Picks the Bitcoin network the whole device works in: mainnet (BTC), testnet4 (XTN) or
/// regtest (XRT). The choice reaches everything -- every address shown, every xpub
/// exported, and the coin type in every default path -- so a change is warned before it
/// is stored, and mainnet is the default a fresh device comes up in.
///
/// Source: hw-reference/firmware-features.md §10 [C]; wallet-export-formats.md
/// §"Chain parameters" [C].
#[cfg(not(feature = "board-mk3"))]
fn testnet_mode_screen(gate: &Callgate, login: &mut catcard_pin::Login, ui: &mut Ui<'_>) {
    use catcard_settings::prefs::Chain;
    const HEAD: &str = "Testnet mode";

    let now = crate::prefs::current();
    let rows: [&str; Chain::ALL.len()] = [
        Chain::Mainnet.long_name(),
        Chain::Testnet.long_name(),
        Chain::Regtest.long_name(),
    ];
    let mut note: Line = Line::new();
    let _ = write!(note, "now {}", now.net.long_name());
    let Some(row) = pick_row(ui, HEAD, &note, &rows) else {
        return;
    };
    let chosen = Chain::ALL[row];
    if chosen == now.net {
        message(ui.panel, HEAD, "unchanged", chosen.long_name());
        wait_for_any_key(ui);
        return;
    }
    // Never quiet: the choice changes every address, xpub and path the device shows, so
    // the owner is told exactly that first -- switching to a testnet and switching back
    // both move every address, so any change is warned, not only leaving mainnet.
    ask(ui.panel, HEAD, "changes every address", chosen.long_name());
    if !confirmed(ui) {
        return;
    }
    save_pref(
        gate,
        login,
        ui,
        HEAD,
        (catcard_settings::prefs::CHAIN, chosen.ticker()),
        crate::prefs::Prefs { net: chosen, ..now },
        chosen.long_name(),
    );
}

/// The backlight levels offered, brightest first. Values are percentages stored under
/// [`catcard_settings::prefs::BACKLIGHT`]; the labels double as the rows.
#[cfg(feature = "board-q1")]
const BRIGHTNESS_ROWS: &[&str] = &["100% (default)", "75%", "50%", "25%"];
/// The percent each [`BRIGHTNESS_ROWS`] row stores, in the same order.
#[cfg(feature = "board-q1")]
const BRIGHTNESS_LEVELS: [u8; 4] = [100, 75, 50, 25];

/// Settings → LCD brightness (Q1).
///
/// The colour panel's backlight level. Persisted per wallet and applied through
/// [`crate::prefs`], which drives [`crate::display::set_backlight`] on save and again on
/// the next login. Full brightness is the default.
///
/// **Variable dimming is limited by an open hardware item:** the PWM timer/channel behind
/// `BL_ENABLE=PE3` is not established from the sanctioned references, so today the panel is
/// simply lit for any chosen level and the value is stored for when that mapping is
/// confirmed. See `docs/HARDWARE-OPEN-ITEMS.md` and [`crate::display::set_backlight`]. No
/// zero/off row is offered: a dark panel is one the owner cannot see to turn back up.
#[cfg(feature = "board-q1")]
fn brightness_screen(gate: &Callgate, login: &mut catcard_pin::Login, ui: &mut Ui<'_>) {
    const HEAD: &str = "LCD brightness";
    let now = crate::prefs::current();
    let mut note: Line = Line::new();
    let _ = write!(note, "now {}%", now.backlight_percent);
    let Some(row) = pick_row(ui, HEAD, &note, BRIGHTNESS_ROWS) else {
        return;
    };
    let chosen = BRIGHTNESS_LEVELS[row];
    if chosen == now.backlight_percent {
        message(ui.panel, HEAD, "unchanged", BRIGHTNESS_ROWS[row]);
        wait_for_any_key(ui);
        return;
    }
    let value = catcard_settings::prefs::backlight_value(chosen);
    save_pref(
        gate,
        login,
        ui,
        HEAD,
        (catcard_settings::prefs::BACKLIGHT, &value),
        crate::prefs::Prefs {
            backlight_percent: chosen,
            ..now
        },
        BRIGHTNESS_ROWS[row],
    );
}

/// Danger zone → Seed tools → Lock down seed: the key in force becomes the stored seed.
///
/// **Irreversible.** The seed the secure element held is overwritten, and with it goes
/// the only way this device had to reach that wallet -- its vault and settings included,
/// which stay on flash under a key nothing here can make any more. So it is asked twice,
/// as Destroy seed is, and the second question says what brings the old seed back.
///
/// Words store as their entropy and a loaded XPRV as a node, which is what the stash has
/// shapes for and what this firmware comes up in. A WIF key has no stash form at all, so
/// it is refused. The passphrase is not stored, as it never is.
fn lock_down(gate: &Callgate, login: &mut catcard_pin::Login, ui: &mut Ui<'_>) {
    use crate::key::{Loaded, Source};
    use zeroize::Zeroize as _;
    const HEAD: &str = "Lock down seed";

    let refused = match crate::key::loaded() {
        Some(Loaded::Wif) => Some(("a WIF key cannot be", "a stored seed")),
        _ if crate::key::in_force() == Source::Root => Some(("this already is", "the stored seed")),
        _ => None,
    };
    if let Some((a, b)) = refused {
        message(ui.panel, HEAD, a, b);
        wait_for_any_key(ui);
        return;
    }

    // The stash to write, and the fingerprint the stored wallet will have: its own,
    // without any passphrase, which is the root this device will come up in.
    let made = if let Some((chain_code, key)) = crate::key::temporary_xprv() {
        // A node stores as a node: the stash has a shape for it, and this firmware now
        // comes up in one (`root_stored`).
        use catcard_wallet::bip32::ExtendedPrivKey;
        // A node whose key is no usable scalar has nothing to store: it falls through to
        // "could not encode", the same as a stash the callgate cannot spell. The
        // fingerprint is network-independent, but the node is built for the network in
        // force so nothing downstream sees a mainnet node under a testnet wallet.
        let fp = crate::keywork::run(|kw| {
            ExtendedPrivKey::root_from_parts(crate::prefs::network(), *chain_code, *key, kw)
                .ok()
                .map(|m| m.fingerprint(kw))
        });
        fp.map(|fp| (catcard_callgate::pin::encode_xprv(chain_code, key), fp))
    } else {
        let (mut ent, len) = match seed_entropy(gate, login, ui.panel, HEAD) {
            Ok(got) => got,
            Err(why) => {
                message(ui.panel, HEAD, why, "any key to go back");
                wait_for_any_key(ui);
                return;
            }
        };
        let secret = catcard_callgate::pin::encode_bip39(&ent[..len]);
        let mut busy = Working::seed(ui.panel, HEAD, "checking the key");
        let fp = crate::keywork::run(|kw| plain_master(&ent[..len], kw).map(|m| m.fingerprint(kw)));
        busy.tick(ui.panel);
        ent.zeroize();
        match (secret, fp) {
            (Ok(secret), Ok(fp)) => Some((secret, fp)),
            _ => None,
        }
    };
    let Some((mut secret, [a, b, c, d])) = made else {
        message(ui.panel, HEAD, "could not encode", "that key");
        wait_for_any_key(ui);
        return;
    };
    let mut said: heapless::String<24> = heapless::String::new();
    let _ = write!(said, "{a:02X}{b:02X}{c:02X}{d:02X}");

    if crate::passphrase::is_set() && crate::key::temporary_xprv().is_none() {
        ask(
            ui.panel,
            HEAD,
            "stores the WORDS only",
            "your passphrase is not in them",
        );
        if !confirmed(ui) {
            secret.zeroize();
            return;
        }
    }
    ask(ui.panel, "Replace stored seed?", "with", &said);
    if !confirmed(ui) {
        secret.zeroize();
        return;
    }
    ask(
        ui.panel,
        "Really replace?",
        "only the old words can",
        "ever bring it back",
    );
    if !confirmed(ui) {
        secret.zeroize();
        return;
    }

    message(ui.panel, "Storing", "do not disconnect", "");
    let pin_gate = crate::pinentry::BootloaderGate::new(gate);
    let stored = login.set_secret(&pin_gate, &secret);
    // Read back before anyone is told it worked, as Destroy seed does: the next unlock is
    // too late to find out the words on the table are not the ones stored.
    let kept = stored.is_ok() && login.verify_secret(&pin_gate, &secret).unwrap_or(false);
    secret.zeroize();
    match stored {
        Ok(_) if kept => {
            // Once stored it *is* the root. Keeping the loaded selection would be the same
            // wallet under two names.
            crate::key::to_root();
            #[cfg(feature = "board-q1")]
            crate::pubkeys::note_fingerprint(Some([a, b, c, d]));
            crate::catlog!("lockdown: the loaded key is the stored seed");
            message(ui.panel, "Locked down", &said, "is the stored seed");
        }
        Ok(_) => {
            crate::catlog!("lockdown: stored but did not read back");
            message(
                ui.panel,
                "Not confirmed",
                "it did not read back",
                "check View words",
            );
        }
        Err(f) => {
            crate::catlog!("lockdown: store failed");
            message(ui.panel, "Not stored", why_failed(f), "any key to go back");
        }
    }
    wait_for_any_key(ui);
}

/// View words, where the wallet in force has none: the master as an xprv, which for a
/// stored node or raw master is what its owner writes down.
fn stored_key_shown(
    gate: &Callgate,
    login: &mut catcard_pin::Login,
    ui: &mut Ui<'_>,
    why: &'static str,
) {
    use catcard_ui::scroll::Line as DLine;
    use zeroize::Zeroize as _;
    const HEAD: &str = "View words";

    let Ok(master) = master_quietly(gate, login, ui.panel, HEAD) else {
        message(ui.panel, HEAD, why, "any key to go back");
        wait_for_any_key(ui);
        return;
    };
    let mut buf = [0u8; 120];
    let written = crate::keywork::run(|kw| master.write_base58(&mut buf, kw).ok());
    drop(master);
    let Some(n) = written else {
        buf.zeroize();
        message(ui.panel, HEAD, "could not write it", "any key to go back");
        wait_for_any_key(ui);
        return;
    };
    let text = core::str::from_utf8(&buf[..n]).unwrap_or("");
    let lines = [
        DLine::title("XPRV"),
        DLine::body(why).small(),
        DLine::body(text).secret().wrapped(),
    ];
    show_doc(ui, &lines, true, true);
    buf.zeroize();
}

/// Show the words: when a wallet is made, and from Danger zone → Seed tools.
///
/// Paged rather than flashed past: ENTER moves forward and only means "done" once the
/// last word has been on screen. The previous version advanced on *any* key, which is
/// how a held key walked through a page of someone's backup before they could read it.
pub(crate) fn show_words(ui: &mut Ui<'_>, m: &catcard_wallet::bip39::Mnemonic) {
    let texts = word_texts(m);
    let mut lines: heapless::Vec<catcard_ui::scroll::Line, 26> = heapless::Vec::new();
    let _ = lines.push(catcard_ui::scroll::Line::title("Write these down"));
    for s in &texts {
        // Secret, so each word carries the ragged sensitive-line marker.
        let _ = lines.push(catcard_ui::scroll::Line::body(s).secret());
    }
    // `require_end`: Confirm will not finish until every word has been on screen.
    show_doc(ui, &lines, true, true);
}

/// The numbered words of a mnemonic as `"NN  word"` strings, for a document.
fn word_texts(m: &catcard_wallet::bip39::Mnemonic) -> heapless::Vec<Line, 24> {
    let mut out = heapless::Vec::new();
    for (i, w) in m.words().enumerate() {
        let mut s = Line::new();
        let _ = write!(s, "{:2}  {w}", i + 1);
        let _ = out.push(s);
    }
    out
}

/// The splash as an "about" page: cat logo, wordmark, and version, held until a key.
fn about_screen(panel: &mut display::Panel) {
    #[cfg(feature = "board-q1")]
    {
        use catcard_ui::art::tibane::LOGO;
        display::draw_with_palette(panel, &LOGO.palette, |c| {
            catcard_ui::splash::draw_colour(c, &LOGO, crate::VERSION, 100, &display::LAYOUT)
        });
    }
    #[cfg(not(feature = "board-q1"))]
    display::draw(panel, |c| catcard_ui::splash::draw(c, crate::VERSION, 100));
}

/// The STM32 in this device: part, silicon revision, flash, and where on which wafer the
/// die was cut, from the factory unique ID.
fn chip_screen(panel: &mut display::Panel) {
    let mut lines: heapless::Vec<Line, 6> = heapless::Vec::new();
    // SAFETY: reads of always-mapped ID registers, each checked on a locked unit first.
    let (uid, (dev, rev), kb) = unsafe {
        (
            catcard_hal::uid::read(),
            catcard_hal::uid::idcode(),
            catcard_hal::uid::flash_size_kb(),
        )
    };
    let die = catcard_hal::uid::Die::from_uid(&uid);
    // Part numbers from the boards' BOMs. Source: platform.md §1 [C]
    let part = match catcard_board::BOARD.mcu {
        catcard_board::spec::Mcu::Stm32L496 => "STM32L496RGT6",
        catcard_board::spec::Mcu::Stm32L4S5 => "STM32L4S5VIT6",
    };
    let _ = lines.push(Line::try_from(part).unwrap_or_default());
    let mut l = Line::new();
    let _ = write!(l, "ID {:03X} rev {:04X}, {} KB", dev, rev, kb);
    let _ = lines.push(l);
    let mut l = Line::new();
    let _ = l.push_str("Lot ");
    for c in die.lot() {
        let _ = l.push(c);
    }
    let _ = write!(l, ", wafer {}", die.wafer);
    let _ = lines.push(l);
    let mut l = Line::new();
    let _ = write!(l, "Die X {}, Y {}", die.x, die.y);
    let _ = lines.push(l);
    let mut l = Line::new();
    let _ = l.push_str("UID ");
    for b in uid {
        let _ = write!(l, "{:02X}", b);
    }
    let _ = lines.push(l);
    info(panel, "STM32", &lines);
}

/// The log, as lines for the pager.
///
/// The on-device twin of the USB `ReadLog`: the same ring, shown to whoever is holding
/// the device rather than paged to a host.
///
/// Long entries are **wrapped** at the panel's column count rather than clipped, which
/// does make the line count depend on the board -- a Q1 fits 44 columns, a mono panel
/// 31. That is fine for a log, where the reader wants the whole line and there is no
/// scroll position to carry between panels; the sink clips instead, for the reasons in
/// `catcard_ui::pager`.
///
/// The buffer is walked once per window and only the visible lines are rendered, so the
/// cost does not grow with how far down the reader has scrolled. Counting continues
/// after the sink is full, because the pager needs the total to know there is more.
struct LogLines;

impl catcard_ui::pager::LineSource for LogLines {
    fn fill(&self, from: usize, sink: &mut catcard_ui::pager::LineSink) -> usize {
        let mut buf = [0u8; crate::logbuf::LOG_LEN];
        let n = crate::logbuf::read(0, &mut buf);
        let mut total = 0usize;
        let mut line = Line::new();
        let mut push = |line: &mut Line, total: &mut usize| {
            if *total >= from {
                let _ = sink.push(line.as_str());
            }
            line.clear();
            *total += 1;
        };
        for &b in &buf[..n] {
            if b == b'\n' {
                push(&mut line, &mut total);
            } else {
                // Our own text, but a stray byte would derail `push`, so anything
                // outside printable ASCII shows as a dot rather than a gap.
                let c = if (0x20..0x7f).contains(&b) {
                    b as char
                } else {
                    '.'
                };
                let _ = line.push(c);
                if line.len() == LOG_COLS {
                    push(&mut line, &mut total);
                }
            }
        }
        if !line.is_empty() {
            push(&mut line, &mut total);
        }
        total
    }
}

/// How a scrollable document screen ([`show_doc`]) ended.
pub(crate) enum DocExit {
    /// A menu row was chosen; carries its `menu_item` id.
    Selected(u32),
    /// A reading screen was confirmed (Confirm on a document with no selectable lines).
    Confirmed,
    /// The user backed out.
    Cancelled,
}

/// Idle beats between marquee steps for an over-long selected name -- how fast it scrolls
/// sideways. One `IDLE_PAUSE_CYCLES` beat is the loop's natural tick.
const MARQUEE_BEATS: u32 = 8;

/// Animate a scroll view's offset from `from` to `to` on boards that animate, rendering the
/// intermediate frames. The final frame at exactly `to` is left to the caller's next draw,
/// so this only ever paints the in-between steps. On boards that don't animate it just
/// leaves the view at `to`.
fn glide_view(
    panel: &mut display::Panel,
    view: &mut catcard_ui::scroll::ScrollView<'_>,
    from: usize,
    to: usize,
) {
    if display::SMOOTH_SCROLL && from != to {
        let frames = display::GLIDE_FRAMES as isize;
        let (a, b) = (from as isize, to as isize);
        for f in 1..frames {
            let off = (a + (b - a) * f / frames).max(0) as usize;
            view.set_off(off);
            // With its marks: drawn plain, every glide frame would drop the logos and
            // the list would scroll with blank holes where they belong.
            #[cfg(feature = "board-q1")]
            display::draw_with_marks(panel, view, |c| catcard_ui::scroll::render(c, view));
            #[cfg(not(feature = "board-q1"))]
            display::draw(panel, |c| catcard_ui::scroll::render(c, view));
            let _ = usbtask::pump();
            catcard_hal::dwt::delay_cycles(display::GLIDE_PAUSE_CYCLES);
        }
    }
    view.set_off(to);
}

/// Show a scrollable document ([`catcard_ui::scroll`]) and drive it from the keypad.
///
/// A reading screen (no selectable lines) scrolls with `5`/`8` and leaves on Confirm or
/// Cancel. A menu (some line carries a `menu_item`) moves a cursor with `5`/`8` and returns
/// the chosen id on Confirm. `require_end`, for the seed backup, refuses Confirm on a
/// reading screen until the bottom has been on screen -- the "read every word" gate the old
/// pager enforced. `scramble` turns on the ragged sensitive-line marker.
pub(crate) fn show_doc(
    ui: &mut Ui<'_>,
    lines: &[catcard_ui::scroll::Line<'_>],
    scramble: bool,
    require_end: bool,
) -> DocExit {
    run_doc(ui, lines, scramble, require_end, true)
}

/// [`show_doc`] for a list whose last rows are actions: the cursor never wraps.
///
/// With the menu-wrapping preference on, up from the first row lands on the last
/// selectable one. On a transaction review that row is "Sign it", one key from the top
/// of a list the owner has not read. A review list is not a menu to be crossed quickly,
/// so it ignores the preference and stops at both ends.
#[cfg(all(feature = "multichain", not(feature = "board-mk3")))]
pub(crate) fn show_doc_nowrap(ui: &mut Ui<'_>, lines: &[catcard_ui::scroll::Line<'_>]) -> DocExit {
    run_doc(ui, lines, false, false, false)
}

/// The document loop behind [`show_doc`] and [`show_doc_nowrap`]. `wrap` is whether the
/// menu-wrapping preference is allowed to apply at all.
fn run_doc(
    ui: &mut Ui<'_>,
    lines: &[catcard_ui::scroll::Line<'_>],
    scramble: bool,
    require_end: bool,
    wrap: bool,
) -> DocExit {
    let mut screen = DocScreen::new(ui, lines, scramble, require_end, wrap);
    let mut events = [Event::Pressed(Key::Cancel); KEYS];
    let mut keys: heapless::Vec<Key, { KEYS + 1 }> = heapless::Vec::new();
    loop {
        screen.draw(ui);
        wait_for_release(ui);
        // A tick counter so a selected, over-long name marquees while nothing is pressed.
        let mut beat = 0u32;
        'wait: loop {
            let _ = usbtask::pump();
            crate::pinentry::pressed_keys(ui.pad, ui.matrix, ui.drbg, &mut events, &mut keys);
            if keys.is_empty() {
                // Advance the marquee every few idle beats when the selection overflows,
                // redrawing only then so a static screen still never re-flushes.
                if screen.needs_marquee() {
                    beat = beat.wrapping_add(1);
                    if beat.is_multiple_of(MARQUEE_BEATS) && screen.tick_marquee() {
                        screen.draw(ui);
                    }
                }
                display::idle(ui.panel);
                continue;
            }
            for k in keys.iter() {
                match screen.key(ui, *k) {
                    DocFlow::Done(exit) => return exit,
                    // The view moved: leave the wait so the outer loop repaints the
                    // settled frame.
                    DocFlow::Redraw => break 'wait,
                    // Nothing happened -- an unused digit, or Confirm on a menu row that
                    // is not selectable. Keep waiting rather than repainting, which would
                    // also re-run `wait_for_release` and swallow the next press.
                    DocFlow::Ignored => {}
                }
            }
        }
    }
}

/// A scrollable document as a screen: it owns its view and takes one key at a time.
///
/// Split out of [`show_doc`] so the same screen can be driven two ways. Today every
/// caller drives it blocking, through `show_doc`. What this makes possible is the other
/// way: a run loop that hands it one key at a time and keeps pumping USB -- and noticing
/// staged upgrade offers -- in between. That matters most for the seed backup, which
/// blocks on a person copying down 24 words while `usbtask::pending()` goes unread.
///
/// Everything that has to survive a keypress is here; `show_doc` keeps only the keypad
/// plumbing.
struct DocScreen<'a> {
    view: catcard_ui::scroll::ScrollView<'a>,
    /// Some line is selectable, so `5`/`8` move a cursor instead of scrolling.
    is_menu: bool,
    /// Refuse Confirm until the last line has been on screen: the seed backup's gate.
    require_end: bool,
}

/// What one key did to a [`DocScreen`].
///
/// Three outcomes, not two: an ignored key must not repaint, because a repaint also
/// re-runs `wait_for_release` and would eat the press that follows.
enum DocFlow {
    /// Nothing changed; keep waiting.
    Ignored,
    /// The view moved; repaint the settled frame.
    Redraw,
    /// The screen is finished.
    Done(DocExit),
}

impl<'a> DocScreen<'a> {
    fn new(
        ui: &mut Ui<'_>,
        lines: &'a [catcard_ui::scroll::Line<'a>],
        scramble: bool,
        require_end: bool,
        wrap: bool,
    ) -> Self {
        let mut view = catcard_ui::scroll::ScrollView::build(
            lines,
            display::SCREEN_W,
            display::SCREEN_H,
            display::FONTS,
        );
        if scramble {
            let mut b = [0u8; 4];
            let _ = ui.drbg.generate(&mut b);
            view = view.with_scramble(catcard_ui::pager::Scramble::new(u32::from_le_bytes(b)));
        }
        let is_menu = view.is_menu();
        // A document with selectable rows is a menu, and wraps like one; a reading screen
        // has no cursor to bring round, so the setting cannot affect it. A caller that
        // refuses wrapping (`wrap` false) has action rows at the bottom; see `show_doc_nowrap`.
        view.set_wrap(wrap && is_menu && crate::prefs::current().menu_wrap);
        Self {
            view,
            is_menu,
            require_end,
        }
    }

    fn draw(&self, ui: &mut Ui<'_>) {
        // Full-colour marks go out inside the frame, not after it; see `draw_with_marks`.
        #[cfg(feature = "board-q1")]
        display::draw_with_marks(ui.panel, &self.view, |c| {
            catcard_ui::scroll::render(c, &self.view)
        });
        #[cfg(not(feature = "board-q1"))]
        display::draw(ui.panel, |c| catcard_ui::scroll::render(c, &self.view));
    }

    fn needs_marquee(&self) -> bool {
        self.view.needs_marquee()
    }

    fn tick_marquee(&mut self) -> bool {
        self.view.tick_marquee()
    }

    /// Move the view and animate from where it was to where it lands.
    fn glide(&mut self, ui: &mut Ui<'_>, f: impl FnOnce(&mut catcard_ui::scroll::ScrollView<'a>)) {
        let old = self.view.off();
        f(&mut self.view);
        let new = self.view.off();
        glide_view(ui.panel, &mut self.view, old, new);
    }

    /// Take one key.
    fn key(&mut self, ui: &mut Ui<'_>, k: Key) -> DocFlow {
        match k {
            // The up/down arrows: move a menu cursor, or scroll a reading screen.
            Key::Digit(0) => {
                self.glide(ui, |v| v.to_top());
                DocFlow::Redraw
            }
            Key::Digit(5) => {
                let menu = self.is_menu;
                self.glide(ui, move |v| {
                    if menu {
                        v.move_cursor(false);
                    } else {
                        v.scroll(false, v.line_step());
                    }
                });
                DocFlow::Redraw
            }
            Key::Digit(8) => {
                let menu = self.is_menu;
                self.glide(ui, move |v| {
                    if menu {
                        v.move_cursor(true);
                    } else {
                        v.scroll(true, v.line_step());
                    }
                });
                DocFlow::Redraw
            }
            Key::Confirm => {
                if self.is_menu {
                    match self.view.selected() {
                        Some(id) => DocFlow::Done(DocExit::Selected(id)),
                        // A menu with nothing selectable under the cursor: not an exit.
                        None => DocFlow::Ignored,
                    }
                } else if self.require_end && !self.view.at_end() {
                    // Not read to the end yet: page down instead of finishing.
                    self.glide(ui, |v| v.scroll(true, v.line_step()));
                    DocFlow::Redraw
                } else {
                    DocFlow::Done(DocExit::Confirmed)
                }
            }
            Key::Cancel => DocFlow::Done(DocExit::Cancelled),
            Key::Digit(_) => DocFlow::Ignored,
            Key::Char(_) | Key::Qr => DocFlow::Ignored,
        }
    }
}

/// Show something longer than the screen, and let it be read.
///
/// `5` and `8` are the arrow keys; CANCEL leaves and returns false.
///
/// `require_end` is for the seed backup. Until the last line has been on screen, ENTER
/// pages forward instead of finishing — so the familiar "press to continue" still works
/// and still cannot skip a word. Once the end is showing, ENTER means done.
fn page_through<S: catcard_ui::pager::LineSource + ?Sized>(
    ui: &mut Ui<'_>,
    title: &str,
    src: &S,
    require_end: bool,
    layout: &catcard_ui::widgets::Layout<'_>,
    scramble: bool,
) -> bool {
    use catcard_ui::pager::{LineSink, Pager, paged};

    // Rows depend on the body face, which the words layout enlarges, so compute them
    // from the layout rather than the fixed default.
    let rows = layout.pager_rows(display::SCREEN_H);
    // One random seed for the whole viewing, so the emissions scramble is stable per
    // line (it scrolls with the text) yet different each time the page is opened.
    let scr = scramble.then(|| {
        let mut b = [0u8; 4];
        let _ = ui.drbg.generate(&mut b);
        catcard_ui::pager::Scramble::new(u32::from_le_bytes(b))
    });
    let mut p = Pager::new();
    let mut events = [Event::Pressed(Key::Cancel); KEYS];
    let mut keys: heapless::Vec<Key, { KEYS + 1 }> = heapless::Vec::new();

    loop {
        let mut sink = LineSink::new(rows);
        let total = src.fill(p.top, &mut sink);
        // The log grows while it is being read, so the window can end up past the end.
        // Re-fill rather than draw a window that does not match where we think we are.
        let clamped = p.clamped(total, rows);
        if clamped != p {
            p = clamped;
            continue;
        }
        display::draw(ui.panel, |c| paged(c, layout, title, &sink, p, total, scr));

        wait_for_release(ui);
        loop {
            let _ = usbtask::pump();
            crate::pinentry::pressed_keys(ui.pad, ui.matrix, ui.drbg, &mut events, &mut keys);
            let mut moved = false;
            for k in keys.iter() {
                match k {
                    Key::Cancel | Key::Digit(7) => return false,
                    Key::Confirm | Key::Digit(9) => {
                        if !require_end || p.at_end(total, rows) {
                            return true;
                        }
                        p = p.page(total, rows, true);
                        moved = true;
                    }
                    Key::Digit(5) => {
                        p = p.step(total, rows, false);
                        moved = true;
                    }
                    Key::Digit(8) => {
                        p = p.step(total, rows, true);
                        moved = true;
                    }
                    Key::Digit(_) => {}
                    Key::Char(_) | Key::Qr => {}
                }
            }
            if moved {
                break;
            }
            display::idle(ui.panel);
        }
    }
}

/// microSD: does a card come up, and what does the controller say if not.
///
/// Brings the controller up and runs the card's bring-up conversation on the spot. This
/// screen is where the SD driver is first exercised at all — the emulator models the
/// SDMMC command registers and no data path, so nothing below `catcard_sd` has ever run
/// against anything. `STA` is on screen for that reason: a failure here should say which
/// step failed and what the controller thought, not just "no".
fn sd_screen(panel: &mut display::Panel) {
    use catcard_hal::sdmmc::Sdmmc;
    let mut lines: heapless::Vec<Line, MAX_LINES> = heapless::Vec::new();

    // SAFETY: nothing else has claimed SDMMC1 or its pins; this screen is the only user.
    let dev = unsafe { Sdmmc::init(&catcard_board::BOARD) };
    let mut dev = match dev {
        Ok(d) => d,
        Err(e) => {
            let mut l = Line::new();
            let _ = write!(l, "controller: {}", describe_sd(&e));
            let _ = lines.push(l);
            let mut l = Line::new();
            let _ = write!(l, "clock gate or base wrong");
            let _ = lines.push(l);
            info(panel, "microSD", &lines);
            return;
        }
    };

    let mut l = Line::new();
    let _ = write!(
        l,
        "slot: {}",
        if catcard_sd::Transport::card_present(&dev) {
            "card detected"
        } else {
            "empty"
        }
    );
    let _ = lines.push(l);

    match catcard_sd::init(&mut dev) {
        Ok(card) => {
            let mut l = Line::new();
            let _ = write!(l, "{} MiB  rca {:04x}", card.mib(), card.rca);
            let _ = lines.push(l);

            let mut l = Line::new();
            let _ = write!(
                l,
                "{}  {} bit",
                match card.addressing {
                    catcard_sd::Addressing::BlockAddressed => "SDHC",
                    catcard_sd::Addressing::ByteAddressed => "SDSC",
                },
                if card.wide { 4 } else { 1 }
            );
            let _ = lines.push(l);

            // One block, to prove the data path and not only the command path.
            let mut block = [0u8; catcard_sd::BLOCK_LEN];
            let mut l = Line::new();
            match catcard_sd::read_block(&mut dev, &card, 0, &mut block) {
                // The MBR/boot signature, which every formatted card carries.
                Ok(()) if block[510] == 0x55 && block[511] == 0xAA => {
                    let _ = write!(l, "block 0 ok (55 aa)");
                }
                Ok(()) => {
                    let _ = write!(l, "block 0 read, no 55aa");
                }
                Err(e) => {
                    let _ = write!(l, "read: {}", describe_sd(&e));
                }
            }
            let _ = lines.push(l);

            // The write path, without changing the card: block 1 read, then written back
            // as it was. On a partitioned card it sits in the gap before the first
            // partition, which nothing uses; either way its contents do not change.
            let mut l = Line::new();
            match catcard_sd::read_block(&mut dev, &card, 1, &mut block)
                .and_then(|()| catcard_sd::write_block(&mut dev, &card, 1, &block))
            {
                Ok(()) => {
                    let _ = write!(l, "block 1 rewrite ok");
                }
                Err(e) => {
                    let (phase, sta, detail) = catcard_hal::sdmmc::last_failure::get();
                    let _ = write!(l, "rewrite: {}", describe_sd(&e));
                    crate::catlog!(
                        "sd: block 1 rewrite failed: {} sta {:08x} detail {}",
                        catcard_hal::sdmmc::last_failure::name(phase),
                        sta,
                        detail
                    );
                    let _ = lines.push(l);
                    l = Line::new();
                    let _ = write!(
                        l,
                        "{} {:x}",
                        catcard_hal::sdmmc::last_failure::name(phase),
                        detail
                    );
                    let _ = lines.push(l);
                    l = Line::new();
                    let _ = write!(l, "at STA {:08x}", sta);
                }
            }
            let _ = lines.push(l);
        }
        Err(e) => {
            let mut l = Line::new();
            let _ = write!(l, "init: {}", describe_sd(&e));
            let _ = lines.push(l);
        }
    }

    let _ = lines.push(reg_line("STA    ", dev.status()));
    info(panel, "microSD", &lines);
}

/// Utils → "Card details": what card is in the slot, from its CID, and how it is
/// formatted.
///
/// Read-only with respect to the card. It brings the controller and card up to read the
/// CID and capacity, then mounts the volume purely to learn its filesystem type; nothing
/// is ever written. The CID decode lives in `catcard_sd::cid`; here we only lay it out on
/// the six lines this panel has.
fn card_details_screen(panel: &mut display::Panel) {
    use catcard_hal::sdmmc::Sdmmc;
    let mut lines: heapless::Vec<Line, MAX_LINES> = heapless::Vec::new();

    // Phase 1: bring the card up and read its identity, then drop the controller so the
    // filesystem probe below can claim SDMMC1 for itself.
    let card = {
        // SAFETY: nothing else has claimed SDMMC1 or its pins; this screen is the only user.
        let mut dev = match unsafe { Sdmmc::init(&catcard_board::BOARD) } {
            Ok(d) => d,
            Err(e) => {
                let mut l = Line::new();
                let _ = write!(l, "controller: {}", describe_sd(&e));
                let _ = lines.push(l);
                info(panel, "Card details", &lines);
                return;
            }
        };
        match catcard_sd::init(&mut dev) {
            Ok(c) => c,
            Err(e) => {
                let mut l = Line::new();
                let _ = write!(l, "card: {}", describe_sd(&e));
                let _ = lines.push(l);
                info(panel, "Card details", &lines);
                return;
            }
        }
    };

    let cid = card.cid();

    // Manufacturer: the name if the small table knows the MID, else the raw byte.
    let mut l = Line::new();
    match cid.mid_name() {
        Some(name) => {
            let _ = write!(l, "{}", name);
        }
        None => {
            let _ = write!(l, "mfr {:#04x}", cid.mid());
        }
    }
    let _ = lines.push(l);

    // Product name (five ASCII bytes) and revision major.minor. Non-printable bytes are
    // shown as '?' so a garbled CID cannot smuggle control characters onto the screen.
    let mut l = Line::new();
    for &b in &cid.pnm() {
        let c = if b.is_ascii_graphic() || b == b' ' {
            b as char
        } else {
            '?'
        };
        let _ = l.push(c);
    }
    let (maj, min) = cid.prv();
    let _ = write!(l, " r{}.{}", maj, min);
    let _ = lines.push(l);

    // Serial number, hex — the stable per-card identifier.
    let mut l = Line::new();
    let _ = write!(l, "SN {:08x}", cid.psn());
    let _ = lines.push(l);

    // Manufacture date, year-month.
    let mut l = Line::new();
    let _ = write!(l, "made {}-{:02}", cid.mdt_year(), cid.mdt_month());
    let _ = lines.push(l);

    // Capacity in MiB, plus the marketing GB (10^9 bytes) the card's own label uses.
    let mut l = Line::new();
    let bytes = card.blocks as u64 * catcard_sd::BLOCK_LEN as u64;
    let gb = (bytes + 500_000_000) / 1_000_000_000;
    let _ = write!(l, "{} MiB (~{} GB)", card.mib(), gb);
    let _ = lines.push(l);

    // Filesystem: mount FAT then exFAT only to name the format. This re-initialises the
    // card (the phase-1 controller was dropped above); it stays read-only.
    let mut why = "card error";
    let mount: Result<catcard_sd::AnyVolume<_, 512>, _> = catcard_sd::AnyVolume::mount_with(|| {
        // SAFETY: the phase-1 controller was dropped; nothing else holds SDMMC1 now.
        let mut dev = match unsafe { Sdmmc::init(&catcard_board::BOARD) } {
            Ok(d) => d,
            Err(_) => {
                why = "controller failed";
                return Err(());
            }
        };
        let card = match catcard_sd::init(&mut dev) {
            Ok(c) => c,
            Err(_) => {
                why = "would not start";
                return Err(());
            }
        };
        Ok(catcard_sd::Sectors::new(dev, card))
    });
    let mut l = Line::new();
    match mount {
        Ok(vol) => {
            let fs = match &vol {
                // FAT12/16/32 come straight from the mounted volume's geometry.
                catcard_sd::AnyVolume::Fat(v) => match v.kind() {
                    catcard_sd::fat::FatKind::Fat12 => "FAT12",
                    catcard_sd::fat::FatKind::Fat16 => "FAT16",
                    catcard_sd::fat::FatKind::Fat32 => "FAT32",
                },
                catcard_sd::AnyVolume::Exfat(_) => "exFAT",
            };
            let _ = write!(l, "format {}", fs);
        }
        Err(catcard_sd::MountError::NoFilesystem) => {
            let _ = write!(l, "no filesystem");
        }
        Err(catcard_sd::MountError::Device) => {
            let _ = write!(l, "fs: {}", why);
        }
    }
    let _ = lines.push(l);

    info(panel, "Card details", &lines);
}

/// An SD error in the few characters a line has.
fn describe_sd(e: &catcard_sd::Error) -> &'static str {
    use catcard_sd::Error as E;
    match e {
        E::NoCard => "no card",
        E::Timeout { .. } => "timeout",
        E::BadResponse { .. } => "bad response",
        E::Unusable => "unusable card",
        E::InitTimeout => "never ready",
        E::BadCsd => "bad CSD",
        E::DataError { .. } => "data error",
        E::Peripheral => "peripheral",
        E::ReadOnly => "read only",
        E::Busy => "card stayed busy",
        E::Unsupported => "not done here",
    }
}

/// Draw up to three lines and return.
/// Block until any key is pressed. For the error notices below, which would otherwise be
/// overwritten by the menu redraw the instant this returns.
fn wait_any_key(ui: &mut Ui<'_>) {
    wait_for_release(ui);
    let mut events = [Event::Pressed(Key::Cancel); KEYS];
    let mut keys: heapless::Vec<Key, { KEYS + 1 }> = heapless::Vec::new();
    loop {
        crate::pinentry::pressed_keys(ui.pad, ui.matrix, ui.drbg, &mut events, &mut keys);
        if !keys.is_empty() {
            return;
        }
        catcard_hal::dwt::delay_cycles(66_000);
    }
}

/// Expose the SD card to the host as a USB mass-storage drive, until `x` is pressed.
///
/// While this screen is up the device re-enumerates as a disk -- its HID wallet protocol
/// is gone until it leaves -- and serves Bulk-Only Transport against the card. On `x` it
/// switches its identity back and returns. Reached only from `Utils`, which is behind the
/// PIN, so the card is never exposed on a locked device.
fn usb_drive(ui: &mut Ui<'_>) {
    // The two hardware switches, honoured here because this is the only place in the
    // firmware that re-enumerates as mass storage. Off means nothing is ever put on the
    // bus -- refused before a controller is even brought up, so there is no window in
    // which the device is a disk.
    //
    // **The port is checked as well as the disk.** This screen re-attaches the core
    // itself, so a device whose owner had switched USB off would otherwise come back onto
    // the bus here -- as a disk, which is the last thing that switch was set for.
    let prefs = crate::prefs::current();
    if !prefs.virtual_disk || !prefs.usb_port {
        let why = if prefs.usb_port {
            "Virtual Disk is off"
        } else {
            "the USB port is off"
        };
        message(ui.panel, "USB Drive", why, "see Hardware On/Off");
        wait_any_key(ui);
        return;
    }

    usb_drive_choose(ui);
}

/// Pick which storage the USB drive exposes, then bring it up.
///
/// SD slot A is always on offer; a slot B only where the board has two (Q1); the Virtual
/// Disk only where there is PSRAM to back it. A board with one SD slot and no PSRAM (mk3)
/// has one option, so it skips the chooser and exposes the card exactly as it always did.
fn usb_drive_choose(ui: &mut Ui<'_>) {
    use catcard_hal::sdmmc::Slot;

    let has_slot_b = catcard_board::BOARD.sdmmc.slot_b.is_some();
    #[cfg(not(feature = "board-mk3"))]
    let has_vdisk = catcard_board::BOARD.psram.is_some();
    #[cfg(feature = "board-mk3")]
    let has_vdisk = false;

    // One option: no chooser, straight to the card -- today's behaviour on a single-slot
    // board without a Virtual Disk.
    if !has_slot_b && !has_vdisk {
        usb_drive_sd(ui, Slot::A);
        return;
    }

    // Build the chooser. The kind rides alongside each label so the labels can differ
    // between boards without the match caring how many there were.
    const KIND_SD_A: u8 = 0;
    const KIND_SD_B: u8 = 1;
    const KIND_VDISK: u8 = 2;
    let mut labels: heapless::Vec<&str, 3> = heapless::Vec::new();
    let mut kinds: heapless::Vec<u8, 3> = heapless::Vec::new();
    let _ = labels.push(if has_slot_b {
        "SD card - slot A (top)"
    } else {
        "SD card"
    });
    let _ = kinds.push(KIND_SD_A);
    if has_slot_b {
        let _ = labels.push("SD card - slot B (bottom)");
        let _ = kinds.push(KIND_SD_B);
    }
    if has_vdisk {
        let _ = labels.push("Virtual Disk (in PSRAM)");
        let _ = kinds.push(KIND_VDISK);
    }

    let Some(pick) = choose(ui, "USB Drive", "share which storage?", &labels) else {
        return;
    };
    match kinds[pick] {
        KIND_SD_A => usb_drive_sd(ui, Slot::A),
        KIND_SD_B => usb_drive_sd(ui, Slot::B),
        #[cfg(not(feature = "board-mk3"))]
        KIND_VDISK => usb_drive_vdisk(ui),
        _ => {}
    }
}

/// Bring up the card in `slot`, put it on the bus, and serve it until the screen is left.
fn usb_drive_sd(ui: &mut Ui<'_>, slot: catcard_hal::sdmmc::Slot) {
    use catcard_hal::sdmmc::Sdmmc;

    // SAFETY: nothing else has claimed SDMMC1 or its pins; this screen is its only user
    // and the menu waits for it to return before it can be chosen again.
    let mut dev = match unsafe { Sdmmc::init_slot(&catcard_board::BOARD, slot) } {
        Ok(d) => d,
        Err(_) => {
            message(ui.panel, "USB Drive", "no SD controller", "press a key");
            wait_any_key(ui);
            return;
        }
    };
    #[allow(unused_mut)]
    let mut card = match catcard_sd::init(&mut dev) {
        Ok(c) => c,
        Err(catcard_sd::Error::NoCard) => {
            message(ui.panel, "USB Drive", "no card in slot", "press a key");
            wait_any_key(ui);
            return;
        }
        Err(e) => {
            crate::catlog!("sd: card would not start: {:?}", e);
            message(ui.panel, "USB Drive", "card would not start", "press a key");
            wait_any_key(ui);
            return;
        }
    };
    // If this card is unlocked, the whole USB drive is served decrypted: the host sees
    // the plaintext filesystem, and everything it writes is re-encrypted, because the MSC
    // path bottoms out in the same `read_block`/`write_block` the FS path does.
    #[cfg(not(feature = "board-mk3"))]
    crate::sdcrypt::apply_to(&mut card);

    message(
        ui.panel,
        "USB Drive",
        "SD card is on USB",
        "press x to eject",
    );
    let mut backend = crate::msc_drive::SdBlocks::new(&mut dev, &card);
    serve_usb_drive(ui, &mut backend);
}

/// Bring up the Virtual Disk, put it on the bus, and serve it until the screen is left.
///
/// Formats the region first only if it holds no filesystem yet — a fresh boot, or one an
/// upgrade overwrote — silently, since there is nothing there to lose. A disk that
/// already mounts is exposed as it is, with whatever was staged on it earlier.
#[cfg(not(feature = "board-mk3"))]
fn usb_drive_vdisk(ui: &mut Ui<'_>) {
    let Some(mut disk) = crate::vdisk::Vdisk::take() else {
        message(ui.panel, "USB Drive", "no PSRAM for a disk", "press a key");
        wait_any_key(ui);
        return;
    };
    if let Err(why) = crate::vdisk::ensure_formatted() {
        crate::catlog!("vdisk: {}", why);
        message(ui.panel, "Virtual Disk", why, "press a key");
        wait_any_key(ui);
        return;
    }

    message(
        ui.panel,
        "USB Drive",
        "Virtual Disk is on USB",
        "press x to eject",
    );
    serve_usb_drive(ui, &mut disk);
}

/// Re-enumerate as a disk, serve `backend` over Bulk-Only Transport until `x` (or a host
/// eject), then switch the identity back. The pad is scanned once every so many transport
/// spins -- often enough to feel a key, rarely enough not to swamp the pipe.
fn serve_usb_drive(ui: &mut Ui<'_>, backend: &mut dyn crate::msc_drive::BlockDev) {
    crate::usbtask::msc_enter();

    let mut events = [Event::Pressed(Key::Cancel); KEYS];
    let mut keys: heapless::Vec<Key, { KEYS + 1 }> = heapless::Vec::new();
    let mut spins: u32 = 0;
    crate::msc_drive::run(backend, || {
        spins = spins.wrapping_add(1);
        if !spins.is_multiple_of(16384) {
            return false;
        }
        crate::pinentry::pressed_keys(ui.pad, ui.matrix, ui.drbg, &mut events, &mut keys);
        keys.contains(&Key::Cancel)
    });

    crate::usbtask::msc_exit();
}

pub(crate) fn message(panel: &mut display::Panel, head: &str, a: &str, b: &str) {
    display::draw(panel, |c| {
        catcard_ui::widgets::message(c, &display::LAYOUT, head, a, b);
    });
}

/// The same screen, in red, for the one kind of thing that is not a notification.
///
/// **A whole screen rather than a red word.** Text colour on this panel is a level
/// through a ramp, so a single red line among grey ones would fringe every glyph edge
/// with whatever that ramp's middle happened to be -- and a warning nobody notices is
/// worse than no warning, because it was counted as having been given. A screen with its
/// own ramp is unmissable and anti-aliases correctly, and it costs one palette.
///
/// On a board without colour this is [`message`], which is the honest degradation: the
/// words are the warning there, and they are the same words.
///
/// Built only where something raises one: a transaction review, which is a multichain
/// build. A Bitcoin PSBT's refusals are reasons rather than alarms -- it says which rule
/// stopped it and that rule is the same every time.
#[cfg(all(feature = "multichain", not(feature = "board-mk3")))]
pub(crate) fn alarm(panel: &mut display::Panel, head: &str, a: &str, b: &str) {
    #[cfg(feature = "board-q1")]
    display::draw_with(panel, &catcard_ui::st7789::ALARM, |c| {
        catcard_ui::widgets::message(c, &display::LAYOUT, head, a, b);
    });
    #[cfg(not(feature = "board-q1"))]
    message(panel, head, a, b);
}
