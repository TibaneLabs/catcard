//! Help: one short document per screen, saying what each of its rows does.
//!
//! Stock puts a `Help` row on its top menus for the boards without a keyboard. The mono
//! boards here keep that: a `Help` row on the main, Settings and Utils menus, opening the
//! three documents below that exist on every board.
//!
//! **The Q1 has no Help row.** Help there is the strip along the foot of every screen that
//! has some (`catcard_ui::helpstrip`): `TAB` then ENTER, or `?`, opens the document for the
//! screen it is on. So every menu has one -- the table that says which is `menu::menu_of`,
//! where a menu cannot be listed without its help -- and the full-screen features reached
//! from a menu arm theirs for as long as they run ([`arm`]). Those extra documents are
//! built only for the Q1 ([`Topic`] is `()` elsewhere), so they cost the mk3's flash
//! nothing.
//!
//! Each is a document in this firmware's own words -- the reference catalogues stock's
//! screens by gist, and this says the same kind of thing about *our* rows, which are not
//! stock's. One line per row, plain, saying what it does and which ones bite.
//!
//! Source: hw-reference/menu-map-mk4-mk5-q1-v5.6.2.md §B1/B2 "Help" [C];
//! help-and-warning-screens.md (purpose: equivalent guidance, not stock's prose) [C].

use catcard_ui::scroll::Line as DLine;

use crate::menu;
use crate::ui::Ui;

/// A help document: its title line, then one small wrapped line per row it explains.
pub(crate) type Doc = &'static [DLine<'static>];

/// The help a screen's strip opens. A document on the Q1; nothing on the boards whose
/// help is a menu row, so the table that pairs every menu with one costs them nothing.
#[cfg(feature = "board-q1")]
pub(crate) type Topic = Doc;
#[cfg(not(feature = "board-q1"))]
pub(crate) type Topic = ();

/// A document from a title and its lines.
macro_rules! doc {
    ($head:literal, [$($line:literal),* $(,)?]) => {
        &[DLine::title($head), $(DLine::body($line).small().wrapped()),*]
    };
}

/// A [`Topic`]: the document on the Q1, `()` on the other boards.
macro_rules! topic {
    ($(#[$m:meta])* $name:ident = $head:literal, [$($line:literal),* $(,)?]) => {
        $(#[$m])*
        #[cfg(feature = "board-q1")]
        pub(crate) const $name: Topic = doc!($head, [$($line),*]);
        $(#[$m])*
        #[cfg(not(feature = "board-q1"))]
        pub(crate) const $name: Topic = ();
    };
}

/// A help document only the Q1 has: a full-screen feature's, which its strip opens.
macro_rules! feature {
    ($(#[$m:meta])* $name:ident = $head:literal, [$($line:literal),* $(,)?]) => {
        $(#[$m])*
        #[cfg(feature = "board-q1")]
        pub(crate) const $name: Doc = doc!($head, [$($line),*]);
    };
}

/// Show a help document, and wait until it is dismissed.
///
/// Straight from the constant: no list is built on the stack for it.
#[inline(never)]
pub(crate) fn show(ui: &mut Ui<'_>, doc: Doc) {
    let _ = menu::show_doc(ui, doc, false, false);
}

// ---------------------------------------------------------------------------------------
// The three every board has: the mono boards' Help rows open these.
// ---------------------------------------------------------------------------------------

/// The main menu: what each cell is for.
const MAIN_DOC: Doc = doc!(
    "Help",
    [
        "Sign: approve a transaction from the card, disk, QR or NFC; sign or verify a message or a text file.",
        "Addresses: list this wallet's addresses and verify one you were given.",
        "Notes: your secure notes and passwords, once turned on in Settings.",
        "Utils: exports, backup, files on the card and disk, USB drive, firmware upgrade.",
        "Derive: which wallet is in force -- root, passphrase, BIP-85 child, XOR, vault.",
        "Settings: login, preferences, multisig, the danger zone, About.",
        "Type Passwords: type a BIP-85 password into the computer; shown while the keyboard is on.",
        "A wallet's fingerprint is shown when another key than the root is in force.",
        "Nothing here sends a transaction: a signed file still has to be broadcast elsewhere.",
    ]
);

/// Settings: what each row changes, and which ones bite.
const SETTINGS_DOC: Doc = doc!(
    "Settings help",
    [
        "Login: change or test the PIN, nickname, scrambled keys, countdown, calculator login.",
        "Passphrase: a BIP-39 passphrase opens a different wallet from the same words.",
        "Multisig: the wallets this device co-signs for.",
        "Spending Policy: limits on what this device will sign, and HSM mode.",
        "Idle timeout, display units, max fee, SLIP-132, menu wrapping, brightness: preferences kept per wallet.",
        "Hardware On/Off: the USB port, the Virtual Disk, the keyboard and NFC.",
        "Secure notes, Chains: turn notes on; choose and order the coins this wallet offers.",
        "Danger zone: the seed words, network, and the bootloader rows -- Set High-Water is irreversible.",
        "About: version, chip, and this device's identity as the bootloader reports it.",
        "Debug: diagnostics for a bench; Warm Reset restarts the device.",
    ]
);

/// Utils: the tool drawer.
const UTILS_DOC: Doc = doc!(
    "Utils help",
    [
        "Analyze RNG: what the random sources are producing, measured.",
        "USB Drive: share the card or the Virtual Disk with the computer; a firmware left on the disk is offered on eject.",
        "Export wallet: public keys and descriptors for wallet software. Never the seed.",
        "Backup: the whole wallet in one encrypted file, restoring one, and moving it to another device.",
        "Paper wallet: a new single-use key, written to the card, unrelated to your seed.",
        "Browse files: what is on the card or the Virtual Disk.",
        "SD card: the card's details, its password lock, and encryption to this device.",
        "Format: erase and re-create the microSD, or the Virtual Disk.",
        "Delete PSBTs: blank and remove spent transactions from the card or disk.",
        "Games: something to do that touches no key.",
        "WIF Store: single private keys kept outside the seed.",
        "NFC Tools: everything a phone can pass in or out by tapping.",
        "Upgrade Firmware: install a signed image from the card or the Virtual Disk.",
    ]
);

/// The main menu's help, where a Help row opens it.
pub(crate) fn main(ui: &mut Ui<'_>) {
    show(ui, MAIN_DOC);
}

/// Settings' help, where a Help row opens it.
pub(crate) fn settings(ui: &mut Ui<'_>) {
    show(ui, SETTINGS_DOC);
}

/// Utils' help, where a Help row opens it.
pub(crate) fn utils(ui: &mut Ui<'_>) {
    show(ui, UTILS_DOC);
}

#[cfg(feature = "board-q1")]
pub(crate) const MAIN: Topic = MAIN_DOC;
#[cfg(not(feature = "board-q1"))]
pub(crate) const MAIN: Topic = ();
#[cfg(feature = "board-q1")]
pub(crate) const SETTINGS: Topic = SETTINGS_DOC;
#[cfg(not(feature = "board-q1"))]
pub(crate) const SETTINGS: Topic = ();
#[cfg(feature = "board-q1")]
pub(crate) const UTILS: Topic = UTILS_DOC;
#[cfg(not(feature = "board-q1"))]
pub(crate) const UTILS: Topic = ();

// ---------------------------------------------------------------------------------------
// The rest of the menus: the Q1's strip opens these.
// ---------------------------------------------------------------------------------------

topic!(
    /// The main menu of a device with no wallet yet.
    MAIN_BLANK = "Help",
    [
        "New: make a wallet from this device's own random sources, 24 or 12 words.",
        "Import: bring in a wallet you already have -- words, a Coldcard clone, a TAPSIGNER backup, an XPRV, Seed XOR, Codex32.",
        "Scan QR: read a code with the scanner -- seed words, a teleport, a file.",
        "Utils: restore a backup file, files on the card, USB drive, firmware upgrade.",
        "Settings: the PIN and nickname, About, and diagnostics.",
    ]
);

topic!(
    /// Settings on a device with no wallet.
    SETTINGS_BLANK = "Settings help",
    [
        "Login: change or test the PIN, the nickname shown before it, scrambled keys, countdown.",
        "About: version, chip, and this device's identity as the bootloader reports it.",
        "Debug: diagnostics for a bench; Warm Reset restarts the device.",
    ]
);

topic!(
    /// Sign: where the thing to sign comes from.
    SIGN = "Sign help",
    [
        "Scan: read a transaction or a message from a QR code.",
        "From SD: pick a PSBT on the card or the Virtual Disk, review it, and write the signed file beside it.",
        "Batch sign: every PSBT on the card in one pass, each still reviewed on its own.",
        "By NFC: a phone taps a transaction in, and the signed one back out.",
        "Message: type a message and sign it with one of this wallet's addresses.",
        "Text file: sign the message in a text file on the card.",
        "Verify: check a signed message against the address it names. Uses no key.",
        "Every signature shows what it spends and where it goes first; CANCEL refuses it.",
    ]
);

topic!(
    /// Derive: which wallet is in force.
    DERIVE = "Derive help",
    [
        "Back to root: return to the wallet your seed words make.",
        "Passphrase: add a BIP-39 passphrase; each passphrase is a different wallet.",
        "BIP-85: a child seed, password or key made from this one, by index.",
        "Import key: work in a wallet typed or scanned in, for this session only.",
        "New words: a fresh seed for this session only, until you store it.",
        "XOR split: cut the words in force into parts that all have to come back together.",
        "XOR join: type the parts back in to work in the wallet they make.",
        "Codex32: split this wallet into BIP-93 shares, any K of which bring it back; or recover, import or make one for this session.",
        "Key vault: keys kept in this device's settings, to switch to later.",
        "A wallet other than the root shows its fingerprint in the bar at the top.",
    ]
);

topic!(
    /// Backup: the encrypted wallet file.
    BACKUP = "Backup help",
    [
        "Save backup: the whole wallet to the card, encrypted under twelve new words you write down.",
        "Verify backup: open a backup file and check it is readable and is this wallet.",
        "Restore backup: put a wallet back from a backup file and its words.",
        "Clone Coldcard: move this wallet to another Coldcard through the card.",
        "Key Teleport: send a seed, a backup or a PSBT to another Q1 by QR, or receive one.",
    ]
);

topic!(
    /// Export wallet: the shapes the same public keys come in.
    EXPORT = "Export help",
    [
        "Every row writes public keys only: what a wallet app needs to watch and build transactions. Never the seed.",
        "Generic JSON, Sparrow, Cove, Nunchuk, Fully Noded, Theya, Bitcoin Safe: the same file under the name each app looks for.",
        "Bitcoin Core, Electrum, Blue Wallet, Wasabi, Unchained, Bull Bitcoin, Zeus, Samourai: each app's own format.",
        "Descriptor: this wallet as an output descriptor, for any app that takes one.",
        "Key Expression: the multisig co-signer keys, for setting up a shared wallet.",
        "Export XPUB: one account key as text.",
        "Account (UR), Keystone: accounts as a QR code for a phone wallet to scan.",
        "Dump Summary: every account's first addresses, to compare with your wallet app.",
        "Address CSV: a run of receive addresses to the card, as a spreadsheet.",
    ]
);

topic!(
    /// Export XPUB: which account level.
    XPUB = "XPUB help",
    [
        "Segwit (BIP-84): the native segwit account key, for bc1q addresses.",
        "Classic (BIP-44): the legacy account key, for 1... addresses.",
        "P2WPKH/P2SH (49): the wrapped segwit account key, for 3... addresses.",
        "Master XPUB: the top of the tree. Anyone with it can see every account.",
        "Current XFP: this wallet's fingerprint, the eight characters that name it.",
    ]
);

topic!(
    /// New wallet: how many words.
    NEW_SEED = "New wallet help",
    [
        "24 words: 256 bits from this device's random sources. The stronger choice.",
        "12 words: 128 bits. Still sound; easier to write down.",
        "The words are the wallet: whoever has them can spend. Write them on paper, never into a computer.",
    ]
);

topic!(
    /// Import seed: where from.
    IMPORT = "Import help",
    [
        "Words: type your BIP-39 seed words; the device knows when the last one is in.",
        "Clone: take a wallet from another Coldcard through the card.",
        "TAPSIGNER: open a TAPSIGNER backup with the Backup Password printed on the card.",
        "XPRV: type in an extended private key and keep it as this device's wallet.",
        "Seed XOR: join the parts of a split seed back into the words they make.",
        "Codex32: import a BIP-93 secret, recover one from its shares, or generate a new one.",
    ]
);

topic!(
    /// Login: how a session starts.
    LOGIN = "Login help",
    [
        "Change PIN: the main PIN. Forget it and the wallet is gone with it.",
        "Trick PINs: other PINs that open a decoy wallet, erase the seed or brick the device.",
        "Test login: type the PIN as at login and be told whether it is right.",
        "Nickname: a name shown before the PIN, so you know it is your device.",
        "Scramble keys: the digits move at every login, so a watcher learns nothing from where you press.",
        "Login countdown: wait a set time after a correct PIN before the wallet opens.",
        "Calculator login: the login screen looks like a calculator.",
        "Kill key, MicroSD 2FA: a digit that erases the seed at login; a login that needs a card.",
    ]
);

topic!(
    /// Hardware On/Off: the switches.
    HARDWARE = "Hardware help",
    [
        "USB mode: off, or which protocol a computer can use to talk to this device.",
        "Virtual Disk: whether the device can appear as a disk to the computer.",
        "Keyboard EMU: whether it can also type into the computer, for passwords.",
        "Security key: a FIDO2/U2F login key for websites, made from this wallet's seed.",
        "NFC Sharing: whether a phone can tap anything in or out at all.",
        "Off is off: the firmware refuses what a switch turns off.",
    ]
);

topic!(
    /// NFC Tools: the tag.
    #[cfg(not(feature = "board-mk3"))]
    NFC_TOOLS = "NFC help",
    [
        "Sign PSBT: a phone taps a transaction in; the signed one goes back the same way.",
        "Show Address: an address from this wallet, for a phone to read.",
        "Sign Message: a message tapped in, signed with this wallet.",
        "Verify Sig File: check a signed message a phone taps in.",
        "File Share: pass a file from the card to a phone.",
        "Import Multisig: a multisig wallet's setup, tapped in.",
        "Push Transaction: send a signed transaction to a phone to broadcast.",
        "Import Words: seed words, tapped in.",
    ]
);

topic!(
    /// Danger zone.
    DANGER = "Danger zone help",
    [
        "Seed tools: see the words, show them as a QR, destroy them, or keep another key in their place.",
        "Testnet mode: a test network instead of real bitcoin. Every address changes.",
        "B85 Idx Values: allow BIP-85 indexes past 9999.",
        "Sighash checks: refuse or only warn about unusual signature types.",
        "Set High-Water: stop older firmware from ever being installed. Irreversible.",
        "Settings Space: how full the settings are.",
        "Bless Firmware: accept this firmware as genuine, which changes the light.",
        "DFU Upgrade: not offered on this firmware; it says why.",
        "Wipe HSM Policy: remove a stored HSM policy.",
    ]
);

topic!(
    /// Seed tools.
    SEED_TOOLS = "Seed tools help",
    [
        "View words: the words of the key in force. Anyone who sees them can spend.",
        "SeedQR: the same words as a QR code, for another device's camera.",
        "Destroy seed: erase the seed from this device, after asking twice.",
        "Lock down seed: keep the key in force as this device's seed, replacing the one it held.",
    ]
);

topic!(
    /// Debug: the bench drawer.
    DEBUG = "Debug help",
    [
        "Nothing here is needed to use a wallet: these are for checking the device itself.",
        "View TRNG Words: raw output of the random source as words -- to look at, not to keep.",
        "NFC, Keyboard EMU, QR probe, Sweep test: exercise one part of the device and show what it did.",
        "USB, Clocks, RTC, Kernel, memory rows, Boot report, Selftest: what the device reports about itself.",
        "Keypad, Colours, Scroll test: check the keys and the screen.",
        "PRNG status, microSD, Logs, Save log: counters, the card, and the log.",
        "Warm Reset: restart the device. Factory Reset: clear the PIN and all settings.",
        "Settings store, Settings to SD, Dump or Restore: bench copies of the settings.",
        "Nickname screen, Secure notes: look at those screens as they are drawn.",
    ]
);

topic!(
    /// Games.
    #[cfg(feature = "games")]
    GAMES = "Games help",
    [
        "Block Mine, Block Cutter, Flappy Cat: games. They touch no key and no setting.",
        "CANCEL leaves a game.",
    ]
);

// ---------------------------------------------------------------------------------------
// Full-screen features reached from a menu: armed while they run.
// ---------------------------------------------------------------------------------------

feature!(
    /// Key Teleport.
    KEY_TELEPORT = "Key Teleport help",
    [
        "Receive: show this device's code and password, then scan the sender's code.",
        "Send: scan the receiver's code, type its password, pick what to send, and show the code that carries it.",
        "Multisig PSBT: send a transaction to a co-signer of a multisig wallet you share.",
        "Both passwords travel separately from the codes: never send them the same way.",
    ]
);

feature!(
    /// Utils -> SD card.
    SD_CARD = "SD card help",
    [
        "The top of the screen is the card in the slot: its maker, size and format.",
        "Card password: lock or unlock the card itself, with a password it keeps.",
        "Encryption: encrypt the card to this device, unlock it for this session, or remove it.",
    ]
);

feature!(
    /// Settings -> Spending Policy.
    SPENDING_POLICY = "Policy help",
    [
        "Single-Signer: limits on what this wallet signs -- amount, velocity, where it may send -- and a mode with fewer menus.",
        "Co-Sign Multisig (CCC): this device as one key of a multisig that signs only within its limits.",
        "HSM Mode: let a computer ask for signatures, within a stored policy, with no one at the keys.",
        "User Management: the people and passwords an HSM policy knows.",
        "Start HSM Mode: enter HSM mode with the stored policy.",
    ]
);

feature!(
    /// Login -> Trick PINs.
    TRICK_PINS = "Trick PINs help",
    [
        "Each row is a PIN that does something other than open your wallet. ! marks one that erases or bricks.",
        "Add New Trick: a PIN that opens a decoy wallet, erases the seed, or bricks the device.",
        "Add If Wrong: stock's wrong-PIN trap, explained -- not offered here.",
        "Delete All: remove every trick PIN.",
    ]
);

feature!(
    /// Derive -> Key vault.
    KEY_VAULT = "Key vault help",
    [
        "Keep the current key: store the key in force in this device's settings.",
        "Each row is a kept key: work in it, rename it, or forget it.",
    ]
);

feature!(
    /// Utils -> WIF Store.
    WIF_STORE = "WIF Store help",
    [
        "Single private keys, kept in this device's settings, outside the seed.",
        "Pick one to reveal it, sign a message with it, see its descriptors, or delete it.",
        "Generate new key, Import from SD, Export All, Clear All: the whole store. A deleted key is gone unless written down.",
    ]
);

feature!(
    /// Main -> Notes.
    NOTES = "Notes help",
    [
        "Notes and passwords kept encrypted in this device's settings.",
        "Pick one to read or edit it, see or send a password, or show its TOTP code.",
        "New Note, New Password, Import, Export All: add, bring in or write out. Disable Feature hides the tile.",
    ]
);

feature!(
    /// Settings -> Hardware On/Off -> Security key.
    SECURITY_KEY = "Security key help",
    [
        "On / Off: whether computers see this wallet's FIDO2 / U2F security key.",
        "Passkeys: logins kept on this device for sites that sign in without a username. Pick one to delete it.",
        "The security-key PIN is set and changed from the browser, and asked on this screen. Only a reset from the browser removes it, with every passkey.",
    ]
);

feature!(
    /// Settings -> Multisig.
    MULTISIG = "Multisig help",
    [
        "The multisig wallets this device co-signs for, and importing or removing one.",
        "Import one from the card or a phone before signing for it: its setup says which keys belong.",
    ]
);

// ---------------------------------------------------------------------------------------
// Arming: which help a full-screen feature's lists offer while it runs.
// ---------------------------------------------------------------------------------------

/// The help the lists on screen offer now, if a feature armed one.
#[cfg(feature = "board-q1")]
static mut ARMED: Option<Doc> = None;

/// The help armed now: what a selectable document's strip opens (`menu::DocScreen`).
#[cfg(feature = "board-q1")]
pub(crate) fn armed() -> Option<Doc> {
    // SAFETY: foreground only, single core; nothing arms or reads it from an interrupt.
    unsafe { *core::ptr::addr_of!(ARMED) }
}

/// Arm `topic` until the guard goes out of scope, when whatever was armed before is back.
///
/// `None` disarms: the signing review does, so a transaction is never reviewed under a
/// strip that explains some other screen.
#[cfg(feature = "board-q1")]
#[must_use = "the help is disarmed again when this is dropped"]
pub(crate) fn arm(topic: Option<Doc>) -> Armed {
    // SAFETY: as in `armed`.
    let was = unsafe { core::ptr::replace(core::ptr::addr_of_mut!(ARMED), topic) };
    Armed(was)
}

/// What [`arm`] replaced, put back on drop.
#[cfg(feature = "board-q1")]
pub(crate) struct Armed(Option<Doc>);

#[cfg(feature = "board-q1")]
impl Drop for Armed {
    fn drop(&mut self) {
        // SAFETY: as in `armed`.
        unsafe { *core::ptr::addr_of_mut!(ARMED) = self.0 };
    }
}
