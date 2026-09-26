//! Trick PINs: Settings → Login → Trick PINs, what a trick login does, and delta mode.
//!
//! A trick PIN is typed at the ordinary PIN prompt. Its effect -- erase the seed, brick
//! the device, open a decoy wallet -- happens inside the bootloader before the login
//! answers, and the login then reports success as the real PIN would
//! (`hw-reference/trick-pin-slot-format.md` §2). The PINs, their flags and any duress
//! wallet live in the second secure element, fourteen slots, managed through gate 22
//! (`catcard_callgate::trick`, `catcard_pin::trick`). **mk4 and later**: the mk3 has no
//! second secure element, and this module is not built for it.
//!
//! # What this firmware stores
//!
//! Nothing sensitive. The list the menu shows is `slot:flags:arg` per trick, in the stored
//! wallet's own encrypted settings file ([`catcard_settings::prefs::TRICK_PINS`]) --
//! **never a PIN**, where stock's list keeps them. So the list names each trick by its slot
//! and what it does; a trick is found again by typing its PIN (Add New Trick recovers a
//! hidden one, as stock does).
//!
//! # A trick session cannot manage tricks
//!
//! From a session a trick PIN opened, **every** gate 22 call makes the bootloader erase
//! the real seed first (§4). The firmware cannot tell a duress session from a real one --
//! that is the point of one -- so gate 22 is only ever called from an explicit action on
//! these screens, never while merely opening the list, which comes from the settings
//! file: a duress session has another wallet's file, and sees no tricks.
//!
//! # Delta mode
//!
//! A delta PIN logs into the **real** wallet. Everything works, except that every
//! signature is spoiled ([`catcard_wallet::signer::spoil_new_signature`]) and any attempt to
//! reveal the seed erases it instead ([`seed_reveal`], the one predicate every such screen
//! calls). This firmware honours a delta trick at login but cannot *create* one: see
//! `catcard_pin::trick::Behaviour`.
//!
//! Source: hw-reference/trick-pin-slot-format.md [C]; menu-map-mk4-mk5-q1-v5.6.2.md §TP
//! [C]; help-and-warning-screens.md §11 [C] (every explanation below is a paraphrase).

use catcard_callgate::Callgate;
use catcard_callgate::abi::TrickOp;
use catcard_callgate::trick::{self as slots, TrickSlot, tc};
use catcard_pin::trick::{self as meaning, Behaviour, Effect, Record};
use catcard_ui::scroll::Line as Row;
use core::fmt::Write as _;
use zeroize::Zeroize as _;

use crate::menu::{self, DocExit};
use crate::pinentry::BootloaderGate;
use crate::ui::Ui;

const HEAD: &str = "Trick PINs";

// ---------------------------------------------------------------------------------------
// The session: delta mode
// ---------------------------------------------------------------------------------------

/// This session was opened by a delta-mode trick PIN. Foreground only, single core; set
/// once at login and never cleared -- the session ends with a reboot.
static mut DELTA: bool = false;

/// Whether this session is in delta mode: the real wallet, opened by a trick PIN.
pub(crate) fn delta_mode() -> bool {
    // SAFETY: foreground only, single core; written once at login.
    unsafe { *core::ptr::addr_of!(DELTA) }
}

/// Every screen that would show the seed -- its words, a SeedQR, a backup, a split --
/// calls this first. In delta mode it erases the seed and resets, and does not return;
/// otherwise it does nothing.
///
/// One predicate for every such screen, so a new one cannot forget half of the rule.
/// Source: help-and-warning-screens.md §11 "Delta Mode selection" [C] ("wipes if the
/// attacker tries to reveal the words")
pub(crate) fn seed_reveal(gate: &Callgate) {
    if delta_mode() {
        crate::catlog!("trick: seed reveal in delta mode; wiping");
        // SAFETY: the reason delta mode exists; nothing after this runs.
        unsafe { gate.fast_wipe(catcard_callgate::abi::FastWipe::Silent) }
    }
}

/// What the login loop does after a successful login, given what it reported.
pub(crate) enum AfterLogin {
    /// Carry on to the menu. `look_blank`: show the device as one with no wallet.
    Continue { look_blank: bool },
    /// Ask for the PIN again: the policy unlock, or a countdown that has run.
    Reprompt,
}

/// Act on a successful login. Called for every one, real or trick, and says nothing on
/// screen that a real login would not -- except the countdown, which is the trick.
///
/// Source: trick-pin-slot-format.md §2 [C]; menu-map-mk4-mk5-q1-v5.6.2.md §(A) [C] (the
/// policy unlock prompts for the main PIN; a countdown trick runs a countdown and then
/// re-prompts).
pub(crate) fn after_login(
    gate: &Callgate,
    panel: &mut crate::display::Panel,
    matrix: &mut crate::keypad::GpioMatrix,
    drbg: &mut catcard_entropy::HmacDrbg,
    login: &catcard_pin::Login,
) -> AfterLogin {
    let Some((flags, arg)) = login.reported_trick() else {
        return AfterLogin::Continue { look_blank: false };
    };
    // Not the flags themselves: the log is readable over USB, and "a trick" is already
    // more than a person watching should learn. The effect is what the code acts on.
    match meaning::effect(flags, arg) {
        Effect::None => AfterLogin::Continue { look_blank: false },
        Effect::Delta => {
            // SAFETY: foreground only, before the menu exists.
            unsafe { *core::ptr::addr_of_mut!(DELTA) = true };
            AfterLogin::Continue { look_blank: false }
        }
        Effect::LookBlank => AfterLogin::Continue { look_blank: true },
        Effect::PolicyUnlock => {
            crate::policy::note_unlock_code();
            AfterLogin::Reprompt
        }
        Effect::Countdown { minutes } => {
            crate::pinentry::countdown(panel, matrix, drbg, u64::from(minutes) * 60);
            AfterLogin::Reprompt
        }
        // The bootloader reboots itself for this one; reaching here means it did not.
        // SAFETY: a reboot, before the menu, with nothing to keep.
        Effect::Reboot => unsafe {
            gate.logout(catcard_callgate::abi::LogoutMode::LogoutAndReboot)
        },
    }
}

// ---------------------------------------------------------------------------------------
// The list, as the settings file keeps it
// ---------------------------------------------------------------------------------------

type Records = heapless::Vec<Record, { meaning::MAX_RECORDS }>;

/// The tricks this firmware made, from the stored wallet's file. Empty when there is no
/// file or no list: a list is only labels.
fn read_records(
    gate: &Callgate,
    login: &mut catcard_pin::Login,
    ui: &mut Ui<'_>,
) -> Result<Records, &'static str> {
    use catcard_settings::json::Doc;
    use catcard_settings::store::{self, SCRATCH};
    let key = crate::settings::wallet_key(gate, login, ui.panel, HEAD)?;
    let mut held = crate::heap::take(SCRATCH).ok_or("no memory")?;
    let buf = held.bytes();
    // SAFETY: the region is mapped and readable; nothing is written.
    let mut files =
        unsafe { crate::settings::Files::mount_read_only() }.map_err(|_| "no settings store")?;
    let n = store::read(&mut files, &key, buf).unwrap_or(0);
    let doc = Doc::parse(&buf[..n]).unwrap_or_default();
    let text = doc
        .get(catcard_settings::prefs::TRICK_PINS)
        .and_then(|v| v.strip_prefix('"')?.strip_suffix('"'))
        .unwrap_or("");
    Ok(meaning::parse(text))
}

/// Write the list back. True when it landed.
fn save_records(
    gate: &Callgate,
    login: &mut catcard_pin::Login,
    ui: &mut Ui<'_>,
    records: &[Record],
) -> bool {
    use catcard_settings::store::SCRATCH;
    let mut text: heapless::String<{ meaning::RECORDS_TEXT_LEN }> = heapless::String::new();
    if !meaning::render(records, &mut text) {
        return false;
    }
    let mut raw: heapless::String<{ meaning::RECORDS_TEXT_LEN + 2 }> = heapless::String::new();
    let _ = write!(raw, "\"{text}\"");
    menu::blocking_screen(ui.panel, HEAD, "saving");
    let (Some(mut doc_held), Some(mut seal_held)) =
        (crate::heap::take(SCRATCH), crate::heap::take(SCRATCH))
    else {
        return false;
    };
    crate::settings::save_wallet(
        gate,
        login,
        ui,
        HEAD,
        (catcard_settings::prefs::TRICK_PINS, &raw),
        doc_held.bytes(),
        seal_held.bytes(),
    )
    .is_ok()
}

// ---------------------------------------------------------------------------------------
// Gate 22, through the session's login
// ---------------------------------------------------------------------------------------

/// A PIN typed for a trick, `prefix-suffix`, wiped on drop.
struct TypedPin {
    buf: [u8; slots::TRICK_PIN_MAX],
    len: usize,
}

impl Drop for TypedPin {
    fn drop(&mut self) {
        self.buf.zeroize();
    }
}

impl TypedPin {
    fn as_bytes(&self) -> &[u8] {
        &self.buf[..self.len]
    }
}

/// Collect a PIN for a trick: prefix (its words shown), suffix. Checked for shape and
/// against the main PIN -- which costs nothing, the session holds it -- before anything
/// is asked of the secure element.
fn ask_pin(gate: &Callgate, login: &catcard_pin::Login, ui: &mut Ui<'_>) -> Option<TypedPin> {
    let (prefix, suffix) =
        crate::pinentry::collect_trick_pin(gate, ui.panel, ui.matrix, ui.drbg, login)?;
    let mut pin = TypedPin {
        buf: [0; slots::TRICK_PIN_MAX],
        len: 0,
    };
    let (p, s) = (prefix.as_bytes(), suffix.as_bytes());
    let n = p.len() + 1 + s.len();
    if n > pin.buf.len() {
        return None;
    }
    pin.buf[..p.len()].copy_from_slice(p);
    pin.buf[p.len()] = catcard_pin::SEPARATOR;
    pin.buf[p.len() + 1..n].copy_from_slice(s);
    pin.len = n;
    if !meaning::pin_shape_ok(pin.as_bytes()) {
        say(ui, "2 to 6 digits", "each side of the dash");
        return None;
    }
    // help-and-warning-screens.md §11 "Non-unique trick PIN" [C]
    if login.is_current_pin(pin.as_bytes()) {
        say(ui, "that is the main PIN", "every PIN must differ");
        return None;
    }
    Some(pin)
}

/// Gate 22/1 for `pin`: `Some(slot)` when a trick has it, `None` when none does; the
/// empty-page mask either way. `Err` when the gate would not answer.
fn look_up(
    gate: &Callgate,
    login: &mut catcard_pin::Login,
    ui: &mut Ui<'_>,
    pin: &TypedPin,
) -> Result<(Option<TrickSlot>, u32), &'static str> {
    menu::blocking_screen(ui.panel, HEAD, "checking");
    let g = BootloaderGate::new(gate);
    let mut s = TrickSlot::lookup(pin.as_bytes()).map_err(|_| "PIN too long")?;
    let rv = login
        .trick_request(&g, TrickOp::GetByPin, &mut s)
        .map_err(|_| "the secure element refused")?;
    let blank = s.blank_slots & ((1 << slots::NUM_TRICKS) - 1);
    crate::catlog!("trick: lookup {}, blank {:#06x}", rv, blank);
    Ok(((rv == 0 && s.slot().is_some()).then_some(s), blank))
}

/// Gate 22/2. True when the bootloader took it.
fn save_slot(
    gate: &Callgate,
    login: &mut catcard_pin::Login,
    ui: &mut Ui<'_>,
    slot: &mut TrickSlot,
) -> bool {
    menu::blocking_screen(ui.panel, HEAD, "saving");
    let g = BootloaderGate::new(gate);
    matches!(login.trick_request(&g, TrickOp::Save, slot), Ok(0))
}

/// The duress wallet's secret for a trick with `flags`/`arg`, derived from the stored
/// wallet: BIP-85 words at the index `arg` names, or the BIP-85 XPRV child. Into
/// `slot.xdata`, in the layout §3.5 gives.
fn fill_duress(
    gate: &Callgate,
    login: &mut catcard_pin::Login,
    ui: &mut Ui<'_>,
    slot: &mut TrickSlot,
) -> Result<(), &'static str> {
    let flags = slot.tc_flags;
    let arg = slot.tc_arg;
    if !meaning::is_duress(flags) {
        return Ok(());
    }
    let master = menu::master_quietly(gate, login, ui.panel, HEAD)?;
    menu::blocking_screen(ui.panel, HEAD, "deriving");
    let xdata = &mut slot.xdata;
    crate::keywork::run(|kw| {
        use catcard_wallet::bip85;
        if flags & tc::XPRV_WALLET != 0 {
            let child = bip85::xprv(&master, u32::from(arg), kw).map_err(|_| "no such child")?;
            xdata[..32].copy_from_slice(&child.chain_code);
            xdata[32..].copy_from_slice(child.secret_bytes());
        } else {
            let (words, index) = meaning::duress_words(arg).ok_or("unknown wallet")?;
            let (e, len) =
                bip85::words_entropy(&master, words, index, kw).map_err(|_| "no such child")?;
            xdata[..len].copy_from_slice(&e.as_bytes()[..len]);
        }
        Ok(())
    })
}

// ---------------------------------------------------------------------------------------
// Settings → Login → Trick PINs
// ---------------------------------------------------------------------------------------

/// The Trick PINs menu.
///
/// Source: menu-map-mk4-mk5-q1-v5.6.2.md §TP [C]
pub(crate) fn screen(gate: &Callgate, login: &mut catcard_pin::Login, ui: &mut Ui<'_>) {
    // A delta session would learn which PIN is the fake from this list, and the
    // bootloader erases the seed on gate 22 from such a session anyway.
    seed_reveal(gate);
    // Stock: `Not Available` with a temporary seed; the list and the duress wallets
    // belong to the stored wallet, without a passphrase.
    if !crate::key::is_root() {
        say(ui, "not available here", "back to the master first");
        return;
    }
    // Stock: a true PIN and a seed must exist first (§11 "Add trick PIN with no real
    // PIN/seed yet").
    if !crate::key::stored_wallet(login) {
        say(ui, "needs a stored seed", "and a PIN first");
        return;
    }
    loop {
        let records = match read_records(gate, login, ui) {
            Ok(r) => r,
            Err(why) => {
                say(ui, why, "");
                return;
            }
        };
        let mut labels: heapless::Vec<heapless::String<24>, { meaning::MAX_RECORDS }> =
            heapless::Vec::new();
        for r in &records {
            let mut s = heapless::String::new();
            let _ = write!(s, "#{} {}", r.slot, meaning::describe(r.flags, r.arg));
            if meaning::irreversible(r.flags) {
                let _ = s.push_str(" !");
            }
            let _ = labels.push(s);
        }
        let mut items: heapless::Vec<&str, { meaning::MAX_RECORDS + 3 }> = heapless::Vec::new();
        for l in &labels {
            let _ = items.push(l.as_str());
        }
        let _ = items.push("Add New Trick");
        let _ = items.push("Add If Wrong");
        if !records.is_empty() {
            let _ = items.push("Delete All");
        }
        let note = if records.is_empty() {
            "none set up yet"
        } else {
            "! = erases or bricks"
        };
        let Some(row) = menu::pick_row(ui, HEAD, note, &items) else {
            return;
        };
        match items.get(row).copied() {
            Some("Add New Trick") => add_new(gate, login, ui, &records),
            Some("Add If Wrong") => add_if_wrong(ui),
            Some("Delete All") => delete_all(gate, login, ui, &records),
            Some(_) => {
                if let Some(r) = records.get(row).copied() {
                    one_trick(gate, login, ui, &records, r);
                }
            }
            None => return,
        }
    }
}

/// A one-screen explanation, confirmed or not. `irreversible` puts the warning first and
/// asks a second time -- every trick that destroys something is asked twice.
fn explain(ui: &mut Ui<'_>, title: &str, body: &str, irreversible: Option<&str>) -> bool {
    let mut rows: heapless::Vec<Row, 5> = heapless::Vec::new();
    let _ = rows.push(Row::title(title));
    if let Some(what) = irreversible {
        let _ = rows.push(Row::body("IRREVERSIBLE").centered());
        let _ = rows.push(Row::body(what).wrapped());
    }
    let _ = rows.push(Row::body(body).wrapped());
    let _ = rows.push(Row::body("ENTER to go on; CANCEL to go back.").small());
    if !matches!(menu::show_doc(ui, &rows, false, true), DocExit::Confirmed) {
        return false;
    }
    if irreversible.is_some() {
        menu::ask(
            ui.panel,
            title,
            "IRREVERSIBLE when typed.",
            "Really arm this?",
        );
        return menu::confirmed(ui);
    }
    true
}

const ERASES: &str = "Typing this PIN erases the seed on this device. Only a backup brings it \
                      back.";
const BRICKS: &str = "Typing this PIN destroys the device: it will never work again, and \
                      nothing can undo that.";

/// Pick a behaviour, each explained before it is armed. `None` if backed out.
///
/// Source: help-and-warning-screens.md §11 "Choose a trick-PIN behavior", "Wipe-seed
/// sub-options", "Duress-wallet type", "Countdown sub-options" [C]
fn pick_behaviour(
    gate: &Callgate,
    login: &mut catcard_pin::Login,
    ui: &mut Ui<'_>,
) -> Option<Behaviour> {
    const TOP: &[&str] = &[
        "Brick Self",
        "Wipe Seed",
        "Duress Wallet",
        "Login Countdown",
        "Look Blank",
        "Just Reboot",
        "Delta Mode",
        "Policy Unlock",
        "Policy Unlock & Wipe",
    ];
    loop {
        let row = menu::pick_row(ui, "Add New Trick", "what the PIN does", TOP)?;
        let picked = match TOP[row] {
            "Brick Self" => explain(
                ui,
                "Brick Self",
                "The device bricks itself the moment this PIN is entered. Nothing is shown.",
                Some(BRICKS),
            )
            .then_some(Behaviour::BrickSelf),
            "Wipe Seed" => pick_wipe(gate, login, ui),
            "Duress Wallet" => pick_duress(gate, login, ui, false),
            "Login Countdown" => pick_countdown(ui),
            "Look Blank" => explain(
                ui,
                "Look Blank",
                "The device acts as though it holds no wallet: a new device waiting for a \
                 seed. The real seed is not touched, and the real PIN still opens it.",
                None,
            )
            .then_some(Behaviour::LookBlank),
            "Just Reboot" => explain(
                ui,
                "Just Reboot",
                "The device simply restarts, as though the power went. Nothing is changed.",
                None,
            )
            .then_some(Behaviour::JustReboot),
            "Delta Mode" => {
                explain_delta_unavailable(ui);
                None
            }
            "Policy Unlock" => explain(
                ui,
                "Policy Unlock",
                "For the Spending Policy: this PIN, then the main PIN, returns the device \
                 to normal for that session so the policy can be changed or removed. \
                 Anyone who has both can do that.",
                None,
            )
            .then_some(Behaviour::PolicyUnlock { wipe: false }),
            "Policy Unlock & Wipe" => explain(
                ui,
                "Unlock & Wipe",
                "As Policy Unlock, but the seed is erased first: the policy is lifted on a \
                 device that no longer holds the wallet.",
                Some(ERASES),
            )
            .then_some(Behaviour::PolicyUnlock { wipe: true }),
            _ => None,
        };
        if picked.is_some() {
            return picked;
        }
    }
}

fn explain_delta_unavailable(ui: &mut Ui<'_>) {
    let rows = [
        Row::title("Delta Mode"),
        Row::body(
            "Logs into the REAL wallet with a PIN that differs from the main one only in \
             its last digits. Most things work, but every signature is bad, and trying to \
             see the seed erases it.",
        )
        .wrapped(),
        Row::body(
            "Not offered here yet: how the real PIN's digits are stored in the trick is \
             not known, and a wrong guess would spend a PIN attempt every time it was \
             used. A delta PIN set up by other firmware still works.",
        )
        .wrapped(),
        Row::body("Any key to go back.").small(),
    ];
    let _ = menu::show_doc(ui, &rows, false, false);
}

fn pick_wipe(
    gate: &Callgate,
    login: &mut catcard_pin::Login,
    ui: &mut Ui<'_>,
) -> Option<Behaviour> {
    const ROWS: &[&str] = &[
        "Wipe & Reboot",
        "Silent Wipe",
        "Wipe -> Wallet",
        "Wipe & Stop",
    ];
    let row = menu::pick_row(ui, "Wipe Seed", "then what", ROWS)?;
    match ROWS[row] {
        "Wipe & Reboot" => explain(
            ui,
            "Wipe & Reboot",
            "The seed is erased and the device restarts, with nothing said.",
            Some(ERASES),
        )
        .then_some(Behaviour::WipeReboot),
        "Silent Wipe" => explain(
            ui,
            "Silent Wipe",
            "The seed is erased, and the PIN is answered as a wrong one would be.",
            Some(ERASES),
        )
        .then_some(Behaviour::WipeSilent),
        "Wipe -> Wallet" => pick_duress(gate, login, ui, true),
        "Wipe & Stop" => explain(
            ui,
            "Wipe & Stop",
            "The seed is erased, then the device logs in to what is left: no wallet.",
            Some(ERASES),
        )
        .then_some(Behaviour::WipeStop),
        _ => None,
    }
}

/// A duress wallet: BIP-85 #1-#3, as many words as the stored seed, or the XPRV one.
fn pick_duress(
    gate: &Callgate,
    login: &mut catcard_pin::Login,
    ui: &mut Ui<'_>,
    wipe: bool,
) -> Option<Behaviour> {
    // "Matching real word count" (§11): twelve for a twelve-word seed, else 24.
    let words = match menu::seed_entropy(gate, login, ui.panel, HEAD) {
        Ok((mut e, len)) => {
            e.zeroize();
            if len == 16 { 12 } else { 24 }
        }
        Err(_) => 24,
    };
    let mut rows: heapless::Vec<&str, 4> = heapless::Vec::new();
    let _ = rows.push("BIP-85 Wallet #1");
    let _ = rows.push("BIP-85 Wallet #2");
    let _ = rows.push("BIP-85 Wallet #3");
    if !wipe {
        let _ = rows.push("XPRV Wallet");
    }
    let note = if words == 12 {
        "12 words, like yours"
    } else {
        "24 words"
    };
    let row = menu::pick_row(ui, "Duress Wallet", note, &rows)?;
    let (title, body) = if row == 3 {
        (
            "XPRV Wallet",
            "Logs into a decoy wallet held as an XPRV (BIP-85 XPRV child 1001 of your \
             seed). Put some funds in it so it looks real. Not the same decoy as stock's \
             older XPRV duress wallet.",
        )
    } else {
        (
            "Duress Wallet",
            "Logs into a decoy wallet: a BIP-85 child of your seed, so it can be \
             recreated from your backup. Put some funds in it so it looks real. Nothing \
             else happens.",
        )
    };
    let b = if row == 3 {
        Behaviour::DuressXprv
    } else if wipe {
        Behaviour::WipeToDuress {
            words,
            n: row as u16 + 1,
        }
    } else {
        Behaviour::Duress {
            words,
            n: row as u16 + 1,
        }
    };
    explain(ui, title, body, wipe.then_some(ERASES)).then_some(b)
}

/// Stock's countdown lengths, minutes. Source: menu-map-mk3-v4.2.0.md "Countdown Time"
/// [C] (5 minutes to 28 days).
const COUNTDOWNS: &[(&str, u16)] = &[
    ("5 minutes", 5),
    ("15 minutes", 15),
    ("30 minutes", 30),
    ("1 hour", 60),
    ("2 hours", 120),
    ("4 hours", 240),
    ("8 hours", 480),
    ("12 hours", 720),
    ("24 hours", 1440),
    ("48 hours", 2880),
    ("3 days", 4320),
    ("1 week", 10080),
    ("28 days", 40320),
];

fn pick_countdown(ui: &mut Ui<'_>) -> Option<Behaviour> {
    const ROWS: &[&str] = &["Just Countdown", "Wipe, Countdown", "Countdown & Brick"];
    let row = menu::pick_row(ui, "Login Countdown", "shows a countdown", ROWS)?;
    let wipe = match ROWS[row] {
        "Just Countdown" => {
            if !explain(
                ui,
                "Just Countdown",
                "Shows a login countdown, then asks for the PIN again. Nothing else \
                 happens.",
                None,
            ) {
                return None;
            }
            false
        }
        "Wipe, Countdown" => {
            if !explain(
                ui,
                "Wipe, Countdown",
                "The seed is erased as the PIN is entered, then a login countdown runs, \
                 then the PIN is asked for again.",
                Some(ERASES),
            ) {
                return None;
            }
            true
        }
        _ => {
            let rows = [
                Row::title("Countdown & Brick"),
                Row::body(
                    "Not offered here yet: how a brick that waits for the countdown is \
                     stored is not known, and a brick that fired at once would be a \
                     different trick from the one asked for.",
                )
                .wrapped(),
                Row::body("Any key to go back.").small(),
            ];
            let _ = menu::show_doc(ui, &rows, false, false);
            return None;
        }
    };
    let names: heapless::Vec<&str, 13> = COUNTDOWNS.iter().map(|(n, _)| *n).collect();
    let i = menu::pick_row(ui, "Countdown", "how long", &names)?;
    Some(Behaviour::Countdown {
        minutes: COUNTDOWNS[i].1,
        wipe,
    })
}

/// Add New Trick: behaviour, PIN, summary, save.
///
/// Source: help-and-warning-screens.md §11 "Non-unique trick PIN", "Save the new trick
/// PIN" [C]
fn add_new(gate: &Callgate, login: &mut catcard_pin::Login, ui: &mut Ui<'_>, records: &Records) {
    let Some(b) = pick_behaviour(gate, login, ui) else {
        return;
    };
    let Some((flags, arg)) = b.encode() else {
        return;
    };
    if let Some(r) = add_with(gate, login, ui, records, flags, arg) {
        let mut line: heapless::String<24> = heapless::String::new();
        let _ = write!(line, "saved in slot {}", r.slot);
        say(ui, meaning::describe(flags, arg), &line);
    }
}

/// Take a PIN for a trick of `flags`/`arg`, check it, find it a slot, derive its wallet,
/// confirm, save it and list it. The record on success. Shared with the Spending
/// Policy's ACTIVATE, which adds its unlock this way.
pub(crate) fn add_with(
    gate: &Callgate,
    login: &mut catcard_pin::Login,
    ui: &mut Ui<'_>,
    records: &[Record],
    flags: u16,
    arg: u16,
) -> Option<Record> {
    let pin = ask_pin(gate, login, ui)?;
    let (found, blank) = match look_up(gate, login, ui, &pin) {
        Ok(x) => x,
        Err(why) => {
            say(ui, why, "");
            return None;
        }
    };
    let mut list: Records = records.iter().copied().collect();
    if let Some(s) = found {
        let slot = s.slot()? as u8;
        if list.iter().any(|r| r.slot == slot) {
            say(ui, "already a trick PIN", "every PIN must differ");
            return None;
        }
        // A hidden trick: stock recovers it rather than refusing (§11).
        let r = Record {
            slot,
            flags: s.tc_flags,
            arg: s.tc_arg,
        };
        drop(s);
        let _ = list.push(r);
        if save_records(gate, login, ui, &list) {
            say(ui, "a hidden trick:", "listed again");
        }
        return None;
    }
    // The bootloader's empty-page mask, less anything the list says is in use -- a page
    // the list claims is someone's, even if the mask disagrees, is not taken.
    let free = blank & !meaning::used_mask(&list);
    let Some(slot) = slots::first_free(free, flags) else {
        say(ui, "no room left", "a wallet takes 2-3 slots");
        return None;
    };

    let mut s = TrickSlot::lookup(pin.as_bytes()).ok()?;
    s.slot_num = slot as i32;
    s.tc_flags = flags;
    s.tc_arg = arg;
    if let Err(why) = fill_duress(gate, login, ui, &mut s) {
        say(ui, why, "");
        return None;
    }

    // The summary, with the PIN, before anything is written.
    let mut pin_line: heapless::String<24> = heapless::String::new();
    let _ = write!(
        pin_line,
        "PIN {}",
        core::str::from_utf8(pin.as_bytes()).unwrap_or("?")
    );
    let effect = meaning::describe(flags, arg);
    let rows = [
        Row::title("Save this trick?"),
        Row::body(pin_line.as_str()).secret(),
        Row::body(effect),
        Row::body(if flags & tc::BRICK != 0 {
            "IRREVERSIBLE: bricks the device."
        } else if flags & tc::WIPE != 0 {
            "IRREVERSIBLE: erases the seed."
        } else {
            "Changes nothing when saved."
        })
        .wrapped(),
        Row::body("ENTER saves; CANCEL does not.").small(),
    ];
    let ok = matches!(menu::show_doc(ui, &rows, false, true), DocExit::Confirmed);
    pin_line.zeroize();
    if !ok {
        return None;
    }
    if !save_slot(gate, login, ui, &mut s) {
        say(ui, "the secure element", "did not take it");
        return None;
    }
    drop(s);
    // Read back, so a slot the element did not keep is not listed as though it were.
    match look_up(gate, login, ui, &pin) {
        Ok((Some(back), _)) if back.slot() == Some(slot) && back.tc_flags == flags => {}
        _ => {
            say(ui, "saved, but it did not", "read back: check it");
            return None;
        }
    }
    let r = Record {
        slot: slot as u8,
        flags,
        arg,
    };
    let _ = list.push(r);
    if !save_records(gate, login, ui, &list) {
        // The trick is in force; only its label is missing. Typing its PIN in Add New
        // Trick lists it again.
        say(ui, "saved; the list was not", "re-add the PIN to list it");
    }
    Some(r)
}

/// Add If Wrong: stock's wrong-PIN trap. Explained, and refused.
fn add_if_wrong(ui: &mut Ui<'_>) {
    let rows = [
        Row::title("Add If Wrong"),
        Row::body(
            "Fires an action after a number of wrong PINs. Whatever is set here, the \
             device always bricks after 13 wrong PINs.",
        )
        .wrapped(),
        Row::body(
            "Not offered here yet: how the secure element tells this rule from a trick PIN \
             is not known.",
        )
        .wrapped(),
        Row::body("Any key to go back.").small(),
    ];
    let _ = menu::show_doc(ui, &rows, false, false);
}

/// One trick: what it does, and Activate Wallet / Change PIN / Hide Trick / Delete Trick.
///
/// Source: menu-map-mk4-mk5-q1-v5.6.2.md §TP `pin_submenu` [C]
fn one_trick(
    gate: &Callgate,
    login: &mut catcard_pin::Login,
    ui: &mut Ui<'_>,
    records: &Records,
    r: Record,
) {
    let mut head: heapless::String<24> = heapless::String::new();
    let _ = write!(head, "#{} {}", r.slot, meaning::describe(r.flags, r.arg));
    let what = if r.flags & tc::BRICK != 0 {
        BRICKS
    } else if r.flags & tc::WIPE != 0 {
        ERASES
    } else {
        "Nothing is destroyed when this PIN is typed."
    };
    let mut items: heapless::Vec<&str, 4> = heapless::Vec::new();
    if meaning::is_duress(r.flags) {
        let _ = items.push("Activate Wallet");
    }
    let _ = items.push("Change PIN");
    if r.flags & tc::DELTA_MODE == 0 {
        let _ = items.push("Hide Trick");
    }
    let _ = items.push("Delete Trick");

    let mut rows: heapless::Vec<Row, 8> = heapless::Vec::new();
    let _ = rows.push(Row::title(head.as_str()));
    let _ = rows.push(Row::body(what).wrapped().small());
    for (i, s) in items.iter().enumerate() {
        let _ = rows.push(Row::item(s, i as u32));
    }
    let DocExit::Selected(i) = menu::show_doc(ui, &rows, false, false) else {
        return;
    };
    match items.get(i as usize).copied() {
        Some("Activate Wallet") => activate(gate, login, ui, r),
        Some("Change PIN") => change_pin(gate, login, ui, r),
        Some("Hide Trick") => hide(gate, login, ui, records, r),
        Some("Delete Trick") => delete(gate, login, ui, records, r),
        _ => {}
    }
}

/// Load the duress wallet for this session, to put funds in it or spend as it.
///
/// Source: help-and-warning-screens.md §11 "Activate a trick/duress wallet" [C]
fn activate(gate: &Callgate, login: &mut catcard_pin::Login, ui: &mut Ui<'_>, r: Record) {
    use crate::key::Source;
    if !explain(
        ui,
        "Activate Wallet",
        "Works in this trick's decoy wallet until you go back to the master or restart: \
         to fund it, or to see what someone with its PIN would see.",
        None,
    ) {
        return;
    }
    let was = crate::key::in_force();
    if r.flags & tc::XPRV_WALLET != 0 {
        let mut s = TrickSlot::new();
        s.tc_flags = r.flags;
        s.tc_arg = r.arg;
        if fill_duress(gate, login, ui, &mut s).is_err() {
            say(ui, "that wallet will not", "derive");
            return;
        }
        let cc: [u8; 32] = s.xdata[..32].try_into().unwrap_or([0; 32]);
        let key: [u8; 32] = s.xdata[32..].try_into().unwrap_or([0; 32]);
        let ok = crate::key::set_temporary_xprv(&cc, &key, "Duress");
        let (mut cc, mut key) = (cc, key);
        cc.zeroize();
        key.zeroize();
        if !ok {
            say(ui, "that key is not usable", "unchanged");
            return;
        }
    } else {
        let Some((words, index)) = meaning::duress_words(r.arg) else {
            say(ui, "unknown wallet", "");
            return;
        };
        crate::key::set(Source::Bip85 { words, index });
    }
    menu::announce_key(gate, login, ui, "Duress Wallet", was);
}

/// Give a trick a new PIN: same slot, same effect, same wallet.
fn change_pin(gate: &Callgate, login: &mut catcard_pin::Login, ui: &mut Ui<'_>, r: Record) {
    if !explain(
        ui,
        "Change PIN",
        "The trick keeps its slot and what it does; only the PIN that fires it changes.",
        meaning::irreversible(r.flags).then_some(if r.flags & tc::BRICK != 0 {
            BRICKS
        } else {
            ERASES
        }),
    ) {
        return;
    }
    let Some(pin) = ask_pin(gate, login, ui) else {
        return;
    };
    match look_up(gate, login, ui, &pin) {
        Ok((None, _)) => {}
        Ok((Some(_), _)) => {
            say(ui, "already a trick PIN", "every PIN must differ");
            return;
        }
        Err(why) => {
            say(ui, why, "");
            return;
        }
    }
    let Ok(mut s) = TrickSlot::lookup(pin.as_bytes()) else {
        return;
    };
    s.slot_num = i32::from(r.slot);
    s.tc_flags = r.flags;
    s.tc_arg = r.arg;
    if let Err(why) = fill_duress(gate, login, ui, &mut s) {
        say(ui, why, "");
        return;
    }
    if save_slot(gate, login, ui, &mut s) {
        say(ui, "PIN changed", "");
    } else {
        say(ui, "the secure element", "did not take it");
    }
}

/// Take a trick off the list; it stays in force.
///
/// Source: help-and-warning-screens.md §11 "Hide a trick PIN" [C]
fn hide(
    gate: &Callgate,
    login: &mut catcard_pin::Login,
    ui: &mut Ui<'_>,
    records: &Records,
    r: Record,
) {
    let caveat = if meaning::is_policy_unlock(r.flags, r.arg) {
        "Only you will know it exists: forget the PIN and the policy can never be \
         lifted."
    } else {
        "It keeps working. To see it here again, add the same PIN as a new trick."
    };
    if !explain(
        ui,
        "Hide Trick",
        caveat,
        meaning::irreversible(r.flags).then_some(if r.flags & tc::BRICK != 0 {
            BRICKS
        } else {
            ERASES
        }),
    ) {
        return;
    }
    let list: Records = records
        .iter()
        .copied()
        .filter(|x| x.slot != r.slot)
        .collect();
    if save_records(gate, login, ui, &list) {
        say(ui, "hidden", "still in force");
    } else {
        say(ui, "could not save", "");
    }
}

/// Remove a trick from the secure element and the list.
///
/// Source: help-and-warning-screens.md §11 "Delete a trick PIN" [C]
fn delete(
    gate: &Callgate,
    login: &mut catcard_pin::Login,
    ui: &mut Ui<'_>,
    records: &Records,
    r: Record,
) {
    if meaning::is_duress(r.flags) {
        menu::ask(
            ui.panel,
            "Delete Trick",
            "moved the funds off",
            "its wallet?",
        );
        if !menu::confirmed(ui) {
            return;
        }
    }
    if meaning::is_policy_unlock(r.flags, r.arg) {
        menu::ask(
            ui.panel,
            "Delete Trick",
            "the policy can then",
            "never be changed",
        );
        if !menu::confirmed(ui) {
            return;
        }
    }
    menu::ask(
        ui.panel,
        "Delete Trick",
        "remove this trick",
        "and its PIN?",
    );
    if !menu::confirmed(ui) {
        return;
    }
    let Some(mask) = slots::blank_mask(r.slot as usize, r.flags) else {
        return;
    };
    let mut s = TrickSlot::blanking(mask);
    if !save_slot(gate, login, ui, &mut s) {
        say(ui, "the secure element", "did not take it");
        return;
    }
    let list: Records = records
        .iter()
        .copied()
        .filter(|x| x.slot != r.slot)
        .collect();
    if save_records(gate, login, ui, &list) {
        say(ui, "trick deleted", "");
    } else {
        say(ui, "deleted; the list", "was not saved");
    }
}

/// Remove every trick, and the list. **Irreversible**: every duress wallet's slot is
/// gone with it.
///
/// Source: help-and-warning-screens.md §11 "Remove ALL trick PINs" [C]
fn delete_all(
    gate: &Callgate,
    login: &mut catcard_pin::Login,
    ui: &mut Ui<'_>,
    records: &[Record],
) {
    if !explain(
        ui,
        "Delete All",
        "Every trick PIN is removed, hidden ones too.",
        Some("Every trick, and every duress wallet's place in the secure element, is gone."),
    ) {
        return;
    }
    if records
        .iter()
        .any(|r| meaning::is_policy_unlock(r.flags, r.arg))
    {
        menu::ask(
            ui.panel,
            "Delete All",
            "the policy can then",
            "never be changed",
        );
        if !menu::confirmed(ui) {
            return;
        }
    }
    if records.iter().any(|r| meaning::is_duress(r.flags)) {
        menu::ask(
            ui.panel,
            "Delete All",
            "moved the funds off",
            "the duress wallets?",
        );
        if !menu::confirmed(ui) {
            return;
        }
    }
    menu::blocking_screen(ui.panel, HEAD, "removing");
    let g = BootloaderGate::new(gate);
    let mut s = TrickSlot::new();
    if !matches!(login.trick_request(&g, TrickOp::ClearAll, &mut s), Ok(0)) {
        say(ui, "the secure element", "refused");
        return;
    }
    if save_records(gate, login, ui, &[]) {
        say(ui, "all tricks removed", "");
    } else {
        say(ui, "removed; the list", "was not saved");
    }
}

// ---------------------------------------------------------------------------------------
// The Spending Policy's escape
// ---------------------------------------------------------------------------------------

/// Whether the list holds a policy unlock.
pub(crate) fn has_policy_unlock(
    gate: &Callgate,
    login: &mut catcard_pin::Login,
    ui: &mut Ui<'_>,
) -> bool {
    read_records(gate, login, ui)
        .is_ok_and(|rs| rs.iter().any(|r| meaning::is_policy_unlock(r.flags, r.arg)))
}

/// Add the policy's unlock PIN, from ACTIVATE. True when one is in place.
pub(crate) fn add_policy_unlock(
    gate: &Callgate,
    login: &mut catcard_pin::Login,
    ui: &mut Ui<'_>,
) -> bool {
    if !crate::key::is_root() || !crate::key::stored_wallet(login) {
        return false;
    }
    let Ok(records) = read_records(gate, login, ui) else {
        return false;
    };
    if records
        .iter()
        .any(|r| meaning::is_policy_unlock(r.flags, r.arg))
    {
        return true;
    }
    let Some((flags, arg)) = (Behaviour::PolicyUnlock { wipe: false }).encode() else {
        return false;
    };
    add_with(gate, login, ui, &records, flags, arg).is_some()
}

/// Remove every listed policy unlock, from Remove Policy: stock forgets the bypass PIN
/// with the policy. A hidden one stays; it lifts nothing once there is no policy.
pub(crate) fn remove_policy_unlock(
    gate: &Callgate,
    login: &mut catcard_pin::Login,
    ui: &mut Ui<'_>,
) -> bool {
    let Ok(records) = read_records(gate, login, ui) else {
        return false;
    };
    let mut keep: Records = heapless::Vec::new();
    for r in &records {
        if meaning::is_policy_unlock(r.flags, r.arg) {
            let Some(mask) = slots::blank_mask(r.slot as usize, r.flags) else {
                continue;
            };
            let mut s = TrickSlot::blanking(mask);
            if !save_slot(gate, login, ui, &mut s) {
                return false;
            }
        } else {
            let _ = keep.push(*r);
        }
    }
    keep.len() == records.len() || save_records(gate, login, ui, &keep)
}

fn say(ui: &mut Ui<'_>, a: &str, b: &str) {
    menu::message(ui.panel, HEAD, a, b);
    menu::wait_for_any_key(ui);
}
