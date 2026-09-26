//! The Single-Signer Spending Policy, in force: hobbled mode, the check before signing,
//! the unlock code, and the screens that set it up.
//!
//! The rules themselves -- what the policy holds, what it refuses, which rows survive
//! hobbled mode -- are [`catcard_settings::policy`], where a host can test them. This
//! module is what the firmware does with them:
//!
//! - **At login**, [`load`] reads the root wallet's policy and decides the session's
//!   [`Mode`]: hobbled when the policy is active, suspended when the unlock code was typed
//!   at the PIN prompt, off otherwise.
//! - **Every menu** asks [`row_allowed`] before showing a row, so hobbled mode is one
//!   filter over the ordinary menus and not a second tree.
//! - **Every wallet-settings save** asks [`hobbled`] first (`crate::settings::save_wallet`)
//!   and refuses anything but the policy's own object.
//! - **Before signing**, [`enforce`] judges the transaction against the policy and refuses
//!   it with the reason, which is recorded as the last violation.
//!
//! # The policy belongs to the root wallet
//!
//! It is read from and written to the **stored** wallet's settings file whatever key is in
//! force, so a passphrase wallet opened under Related Keys is judged by the same policy
//! and cannot carry a different one. The screens that change it are offered in the root
//! wallet only, where the cached settings key is the right one and `save_wallet` writes
//! the right file; the one write from elsewhere -- recording a spend or a violation under
//! a related key -- goes to the root file by its own key.
//!
//! # Test Drive
//!
//! Hobbled for the session, nothing written: the mode is [`Mode::TestDrive`], the main
//! menu carries `EXIT TEST DRIVE`, and the policy is enforced at signing but records
//! neither a violation nor a spend height, so a trial leaves no trace in the policy.
//!
//! # Not CCC, not Web 2FA
//!
//! Co-signing (CCC) is a later wave. Web 2FA's enrolment and verification protocol is not
//! in the reference (docs/HARDWARE-OPEN-ITEMS.md), so its row is present and says so.

use catcard_settings::policy::{self as engine, Allow, Menu};

/// How the session stands with the policy.
///
/// On the mk3 only `Off` is ever constructed: there is no store to hold a policy.
#[cfg_attr(feature = "board-mk3", allow(dead_code))]
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub(crate) enum Mode {
    /// No active policy.
    Off,
    /// The policy is active and in force: the hobbled menus, the check at signing.
    Hobbled,
    /// Hobbled for this session only; nothing persists.
    TestDrive,
    /// The policy is active but the unlock code was typed at login: full menus, no check,
    /// and the configuration screen offers Remove Policy.
    Suspended,
    /// Something is under the policy's key and it will not read. Hobbled, and nothing
    /// signs; the unlock code is the way out.
    Damaged,
}

/// The session's standing, and the allowances the hobbled filter needs.
struct State {
    mode: Mode,
    allow: Allow,
    /// The unlock code was typed at the PIN prompt this boot.
    unlock_typed: bool,
}

static mut STATE: State = State {
    mode: Mode::Off,
    allow: Allow {
        notes: false,
        related_keys: false,
    },
    unlock_typed: false,
};

fn state() -> &'static State {
    // SAFETY: foreground only, single core: written by `load` and the screens below, read
    // by the menus between them; nothing holds a borrow across a write.
    unsafe { &*core::ptr::addr_of!(STATE) }
}

#[cfg_attr(feature = "board-mk3", allow(dead_code))]
fn set(mode: Mode, allow: Allow) {
    // SAFETY: as in `state`.
    unsafe {
        let s = &mut *core::ptr::addr_of_mut!(STATE);
        s.mode = mode;
        s.allow = allow;
    }
    crate::catlog!(
        "policy: {} (notes {}, related keys {})",
        mode_name(mode),
        allow.notes,
        allow.related_keys
    );
}

#[cfg_attr(feature = "board-mk3", allow(dead_code))]
fn mode_name(mode: Mode) -> &'static str {
    match mode {
        Mode::Off => "off",
        Mode::Hobbled => "HOBBLED",
        Mode::TestDrive => "test drive",
        Mode::Suspended => "suspended for this session",
        Mode::Damaged => "DAMAGED, hobbled",
    }
}

/// The PIN prompt matched the unlock code. Remembered until [`load`] reads the policy.
pub(crate) fn note_unlock_code() {
    // SAFETY: as in `state`; called from the PIN prompt, before the menu exists.
    unsafe { (*core::ptr::addr_of_mut!(STATE)).unlock_typed = true };
    crate::catlog!("policy: unlock code typed");
}

/// Whether the unlock code has already been taken this boot. The PIN prompt checks this
/// so a code that happened to equal the main PIN cannot match forever: the second time
/// the same digits are typed they go to the bootloader.
pub(crate) fn unlock_typed() -> bool {
    state().unlock_typed
}

#[cfg_attr(feature = "board-mk3", allow(dead_code))]
pub(crate) fn mode() -> Mode {
    state().mode
}

/// Whether the hobbled filter applies: an active policy, a test drive, or a damaged one.
pub(crate) fn hobbled() -> bool {
    matches!(
        state().mode,
        Mode::Hobbled | Mode::TestDrive | Mode::Damaged
    )
}

pub(crate) fn test_driving() -> bool {
    state().mode == Mode::TestDrive
}

/// Whether a menu row is offered right now: every row when not hobbled, else what the
/// policy's filter keeps.
pub(crate) fn row_allowed(menu: Menu, label: &str) -> bool {
    !hobbled() || engine::hobbled_row(menu, label, state().allow)
}

pub(crate) use imp::*;

#[cfg(not(feature = "board-mk3"))]
mod imp {
    use super::{Mode, mode, set, state};
    use catcard_callgate::Callgate;
    use catcard_settings::json::Doc;
    use catcard_settings::policy::{self as engine, Allow, Checker, Out, Policy, Read, Violation};
    use catcard_settings::store::{self, SCRATCH};
    use catcard_ui::scroll::Line as Row;
    use catcard_wallet::psbtview::{self, timelock};
    use core::fmt::Write as _;
    use outscript::psbt::Psbt;
    use zeroize::Zeroize as _;

    use crate::menu::{self, DocExit, WordPick};
    use crate::ui::Ui;

    const HEAD: &str = "Spending Policy";

    // -----------------------------------------------------------------------------------
    // Login
    // -----------------------------------------------------------------------------------

    /// Read the root wallet's policy and put the session in its mode. From the menu's
    /// start-up, once the settings key is warm.
    ///
    /// A store that cannot be read at all -- no key, no mount, no memory -- reads as off,
    /// as every other preference does: the failure is the device's, not the policy's, and
    /// it is logged. A policy that is *there* and will not read is [`Mode::Damaged`].
    pub(crate) fn load(gate: &Callgate, login: &mut catcard_pin::Login, ui: &mut Ui<'_>) {
        let typed = state().unlock_typed;
        let read = {
            let Some(mut held) = crate::heap::take(SCRATCH) else {
                crate::catlog!("policy: no memory to read it; off");
                set(Mode::Off, Allow::default());
                return;
            };
            match read_root(gate, login, ui.panel, held.bytes()) {
                Ok(r) => r,
                Err(why) => {
                    crate::catlog!("policy: not read ({}); off", why);
                    set(Mode::Off, Allow::default());
                    return;
                }
            }
        };
        let (mode, allow) = match read {
            Read::Absent => (Mode::Off, Allow::default()),
            Read::Policy(p) if p.active => {
                let allow = Allow {
                    notes: p.allow_notes,
                    related_keys: p.related_keys,
                };
                (
                    if typed {
                        Mode::Suspended
                    } else {
                        Mode::Hobbled
                    },
                    allow,
                )
            }
            // Not active: an unlock code typed against nothing is nothing.
            Read::Policy(_) => (Mode::Off, Allow::default()),
            Read::Damaged => (
                if typed {
                    Mode::Suspended
                } else {
                    Mode::Damaged
                },
                Allow::default(),
            ),
        };
        set(mode, allow);
        // The one thing said out loud: the PIN prompt itself says nothing when the code
        // matches, so the owner learns here that it took.
        if mode == Mode::Suspended {
            menu::message(
                ui.panel,
                HEAD,
                "unlocked for this session",
                "Settings > Spending Policy",
            );
            menu::wait_for_any_key(ui);
        }
    }

    /// Leave Test Drive: the main menu's `EXIT TEST DRIVE`.
    pub(crate) fn exit_test_drive(ui: &mut Ui<'_>) {
        if mode() == Mode::TestDrive {
            set(Mode::Off, Allow::default());
            menu::message(ui.panel, HEAD, "test drive over", "nothing was changed");
            menu::wait_for_any_key(ui);
        }
    }

    // -----------------------------------------------------------------------------------
    // Reading and writing the root wallet's policy
    // -----------------------------------------------------------------------------------

    /// The root wallet's settings key: the cached one while the root is in force, a
    /// fetch otherwise.
    fn root_settings_key(
        gate: &Callgate,
        login: &mut catcard_pin::Login,
        panel: &mut crate::display::Panel,
    ) -> Result<catcard_settings::nvstore::Key, &'static str> {
        if crate::key::is_root() {
            crate::settings::wallet_key(gate, login, panel, HEAD)
        } else {
            crate::settings::root_key(gate, login, panel, HEAD)
        }
    }

    /// The root wallet's policy, read through `buf` (one [`SCRATCH`]).
    fn read_root(
        gate: &Callgate,
        login: &mut catcard_pin::Login,
        panel: &mut crate::display::Panel,
        buf: &mut [u8],
    ) -> Result<Read, &'static str> {
        let key = root_settings_key(gate, login, panel)?;
        // SAFETY: the region is mapped and readable; nothing is written through this.
        let mut files = unsafe { crate::settings::Files::mount_read_only() }
            .map_err(|_| "no settings store")?;
        let n = store::read(&mut files, &key, buf).unwrap_or(0);
        let doc = Doc::parse(&buf[..n]).unwrap_or_default();
        Ok(engine::read(&doc))
    }

    /// Read, change, write: the policy as stored, `edit` applied, saved back. Every
    /// failure is said on screen; true only when the write landed.
    ///
    /// A damaged or absent policy is edited from the defaults, which is how Remove Policy
    /// clears a damaged one. Three scratch leases at most, never four: the read buffer
    /// is given back before the two the save needs are taken.
    fn update_root(
        gate: &Callgate,
        login: &mut catcard_pin::Login,
        ui: &mut Ui<'_>,
        edit: impl FnOnce(&mut Policy) -> Result<(), &'static str>,
    ) -> bool {
        let mut policy = {
            let Some(mut held) = crate::heap::take(SCRATCH) else {
                say(ui, "no memory");
                return false;
            };
            match read_root(gate, login, ui.panel, held.bytes()) {
                Ok(Read::Policy(p)) => p,
                Ok(Read::Absent | Read::Damaged) => Policy::default(),
                Err(why) => {
                    say(ui, why);
                    return false;
                }
            }
        };
        if let Err(why) = edit(&mut policy) {
            say(ui, why);
            return false;
        }
        let Some(mut text_held) = crate::heap::take(SCRATCH) else {
            say(ui, "no memory");
            return false;
        };
        let Some(raw) = policy.render(text_held.bytes()) else {
            say(ui, "policy too large");
            return false;
        };
        if write_root(gate, login, ui, raw) {
            true
        } else {
            say(ui, "could not save");
            false
        }
    }

    /// Write the rendered policy object into the root wallet's file.
    fn write_root(
        gate: &Callgate,
        login: &mut catcard_pin::Login,
        ui: &mut Ui<'_>,
        raw: &str,
    ) -> bool {
        let (Some(mut doc_held), Some(mut seal_held)) =
            (crate::heap::take(SCRATCH), crate::heap::take(SCRATCH))
        else {
            return false;
        };
        if crate::key::is_root() {
            return crate::settings::save_wallet(
                gate,
                login,
                ui,
                HEAD,
                (engine::KEY, raw),
                doc_held.bytes(),
                seal_held.bytes(),
            )
            .is_ok();
        }
        // Another key is in force: the root file by its own key, the object alone.
        let Ok(key) = crate::settings::root_key(gate, login, ui.panel, HEAD) else {
            return false;
        };
        menu::blocking_screen(ui.panel, HEAD, "saving");
        // SAFETY: foreground only; the caller holds the display while this runs.
        let Ok(mut files) = (unsafe { crate::settings::Files::mount() }) else {
            return false;
        };
        let choose = ui.drbg.below(crate::settings::SLOT_COUNT).unwrap_or(0);
        match store::set_many(
            &mut files,
            &key,
            &[(engine::KEY, raw)],
            choose,
            doc_held.bytes(),
            seal_held.bytes(),
        ) {
            Ok(slot) => {
                crate::catlog!("policy: saved to {:03x}.aes (root file)", slot);
                true
            }
            Err(e) => {
                crate::catlog!("policy: save failed: {:?}", e);
                false
            }
        }
    }

    // -----------------------------------------------------------------------------------
    // Enforcement
    // -----------------------------------------------------------------------------------

    /// Judge a transaction before its review. True to go on; false once the refusal has
    /// been shown. Off and suspended sessions pass without reading anything.
    ///
    /// The whitelist walk derives the change keys of every output, so it runs masked a
    /// page at a time, as the review does; the totals come from the summary the review
    /// was built from, so what is judged is exactly what would have been shown.
    pub(crate) fn enforce(
        gate: &Callgate,
        login: &mut catcard_pin::Login,
        ui: &mut Ui<'_>,
        psbt: &Psbt<'_>,
        owner: &psbtview::Owner<'_>,
        summary: &psbtview::Summary,
    ) -> bool {
        let mode = mode();
        match mode {
            Mode::Off | Mode::Suspended => return true,
            Mode::Damaged => {
                refuse(ui, Violation::Damaged, false);
                return false;
            }
            Mode::Hobbled | Mode::TestDrive => {}
        }
        let policy = {
            let Some(mut held) = crate::heap::take(SCRATCH) else {
                say(ui, "no memory");
                return false;
            };
            match read_root(gate, login, ui.panel, held.bytes()) {
                Ok(Read::Policy(p)) => p,
                Ok(Read::Absent | Read::Damaged) => {
                    refuse(ui, Violation::Damaged, false);
                    return false;
                }
                Err(why) => {
                    say(ui, why);
                    return false;
                }
            }
        };

        // The height the transaction names, if it names one. A time lock is not a
        // height and is not turned into one.
        let height = match timelock::absolute(psbt) {
            Some(timelock::Locktime {
                lock: timelock::Absolute::Height(h),
                ..
            }) => Some(h),
            _ => None,
        };

        let mut checker = Checker::new(&policy);
        if !policy.whitelist.is_empty() {
            let network = crate::prefs::network();
            let accounts = &summary.accounts[..summary.account_count];
            let wallets = &summary.wallets[..summary.wallet_count];
            let blank = psbtview::Destination {
                index: 0,
                amount: 0,
                change: false,
                address: [0; catcard_wallet::address::MAX_ADDRESS_LEN],
                address_len: 0,
            };
            let mut page = [blank; 4];
            let mut start = 0usize;
            let mut busy = menu::Working::new(ui.panel, HEAD, "checking the policy");
            loop {
                let got = crate::keywork::run(|kw| {
                    psbtview::destinations_from(
                        psbt, owner, network, accounts, wallets, start, &mut page, kw,
                    )
                });
                for d in &page[..got] {
                    checker.output(Out {
                        index: d.index,
                        amount: d.amount,
                        change: d.change,
                        address: d.address(),
                    });
                }
                busy.tick(ui.panel);
                if got < page.len() {
                    break;
                }
                start += got;
            }
        }
        let verdict = checker.finish(summary.sending, height);
        let persist = mode == Mode::Hobbled;
        match verdict {
            Ok(allowed) => {
                crate::catlog!("policy: allowed, height {:?}", allowed.record_height);
                // The spend's height goes down before the signature is made, not after:
                // a transaction that then fails to sign has still used its window,
                // which is the conservative side. `[I]`
                if let Some(h) = allowed.record_height
                    && persist
                    && !update_root(gate, login, ui, |p| {
                        p.last_height = h;
                        Ok(())
                    })
                {
                    say(ui, "could not record the spend");
                    return false;
                }
                true
            }
            Err(v) => {
                crate::catlog!("policy: REFUSED: {}", v.describe());
                if persist {
                    let text = v.describe();
                    let _ = update_root(gate, login, ui, |p| {
                        p.violation = text.clone();
                        Ok(())
                    });
                }
                refuse(ui, v, mode == Mode::TestDrive);
                false
            }
        }
    }

    /// Say why a transaction was refused.
    fn refuse(ui: &mut Ui<'_>, v: Violation, test_drive: bool) {
        let text = v.describe();
        menu::message(
            ui.panel,
            if test_drive {
                "Policy (test drive)"
            } else {
                "Policy refused"
            },
            &text,
            "not signed",
        );
        menu::wait_for_any_key(ui);
    }

    // -----------------------------------------------------------------------------------
    // Settings -> Spending Policy
    // -----------------------------------------------------------------------------------

    /// Settings -> Spending Policy: stock's SpendingPolicySubMenu, of which this wave has
    /// the single-signer half.
    /// Source: hw-reference/menu-map-mk4-mk5-q1-v5.6.2.md §ADV "Spending Policy" [C]
    pub(crate) fn screen(gate: &Callgate, login: &mut catcard_pin::Login, ui: &mut Ui<'_>) {
        loop {
            let Some(row) =
                menu::pick_row(ui, HEAD, "", &["Single-Signer", "Co-Sign Multisig (CCC)"])
            else {
                return;
            };
            match row {
                0 => single_signer(gate, login, ui),
                _ => say(ui, "CCC is a later wave"),
            }
        }
    }

    /// The SSSPConfigMenu, in stock's order.
    /// Source: hw-reference/menu-map-mk4-mk5-q1-v5.6.2.md §SP1 [C]
    fn single_signer(gate: &Callgate, login: &mut catcard_pin::Login, ui: &mut Ui<'_>) {
        const H: &str = "Single-Signer";
        loop {
            let Some(policy) = current(gate, login, ui) else {
                return;
            };
            let mut rows: heapless::Vec<&str, 9> = heapless::Vec::new();
            let mut note: heapless::String<40> = heapless::String::new();
            if policy.active {
                let _ = note.push_str(if mode() == Mode::Suspended {
                    "ACTIVE, unlocked this session"
                } else {
                    "ACTIVE"
                });
            } else if !engine_has_any(&policy) {
                // First time: the enable story, once, before the rows.
                if !enable_story(ui) {
                    return;
                }
            }
            let _ = rows.push("Edit Policy...");
            let _ = rows.push(if policy.word_check {
                "Word Check: on"
            } else {
                "Word Check: off"
            });
            #[cfg(feature = "board-q1")]
            let _ = rows.push(if policy.allow_notes {
                "Allow Notes: on"
            } else {
                "Allow Notes: off"
            });
            let _ = rows.push(if policy.related_keys {
                "Related Keys: on"
            } else {
                "Related Keys: off"
            });
            if !policy.violation.is_empty() {
                let _ = rows.push("Last Violation");
            }
            let _ = rows.push("Remove Policy");
            if !policy.active {
                let _ = rows.push("Test Drive");
                let _ = rows.push("ACTIVATE");
            }
            let Some(row) = menu::pick_row(ui, H, &note, &rows) else {
                return;
            };
            // The three that change the session's mode leave the screen once they have.
            let mut done = false;
            match rows[row] {
                "Edit Policy..." => edit_policy(gate, login, ui),
                l if l.starts_with("Word Check") => toggle_word_check(gate, login, ui, &policy),
                l if l.starts_with("Allow Notes") => {
                    toggle(gate, login, ui, &policy, Toggle::Notes);
                }
                l if l.starts_with("Related Keys") => {
                    toggle(gate, login, ui, &policy, Toggle::RelatedKeys);
                }
                "Last Violation" => {
                    menu::message(ui.panel, "Last Violation", &policy.violation, "");
                    menu::wait_for_any_key(ui);
                }
                "Remove Policy" => done = remove(gate, login, ui, &policy),
                "Test Drive" => done = test_drive(ui, &policy),
                "ACTIVATE" => done = activate(gate, login, ui, &policy),
                _ => {}
            }
            if done {
                return;
            }
        }
    }

    /// Whether anything has ever been set: the enable story is for a fresh policy only.
    fn engine_has_any(p: &Policy) -> bool {
        p.has_rules() || p.word_check || p.allow_notes || p.related_keys || p.active
    }

    /// The policy as stored, or the defaults; `None` when the store cannot be read, which
    /// the screen has said.
    fn current(gate: &Callgate, login: &mut catcard_pin::Login, ui: &mut Ui<'_>) -> Option<Policy> {
        let Some(mut held) = crate::heap::take(SCRATCH) else {
            say(ui, "no memory");
            return None;
        };
        match read_root(gate, login, ui.panel, held.bytes()) {
            Ok(Read::Policy(p)) => Some(p),
            Ok(Read::Absent) => Some(Policy::default()),
            Ok(Read::Damaged) => {
                say(ui, "policy unreadable: shown as defaults");
                Some(Policy::default())
            }
            Err(why) => {
                say(ui, why);
                None
            }
        }
    }

    /// Stock's enable story: what a policy does and what hobbled mode costs.
    /// Source: hw-reference/help-and-warning-screens.md §12 "Enable Spending Policy" [C]
    fn enable_story(ui: &mut Ui<'_>) -> bool {
        let rows = [
            Row::title("Spending Policy"),
            Row::body(
                "A policy blocks signing unless the transaction meets its rules: a size \
                 cap, a rate limit in blocks, a whitelist of destinations.",
            )
            .wrapped(),
            Row::body(
                "While it is ACTIVE the device is hobbled: signing and addresses only, \
                 no seed, no backup, no settings.",
            )
            .wrapped(),
            Row::body(
                "An unlock code, chosen at ACTIVATE, is the way back. Without one, only \
                 destroying the seed is.",
            )
            .wrapped(),
            Row::body("ENTER to set one up; CANCEL to leave.")
                .small()
                .wrapped(),
        ];
        matches!(menu::show_doc(ui, &rows, false, true), DocExit::Confirmed)
    }

    // -----------------------------------------------------------------------------------
    // The toggles
    // -----------------------------------------------------------------------------------

    #[derive(Copy, Clone)]
    enum Toggle {
        Notes,
        RelatedKeys,
    }

    /// Word Check, explained first as stock does; turning it on needs a words wallet,
    /// and turning it off is itself a change the check guards.
    /// Source: hw-reference/help-and-warning-screens.md §12 "Sub-option toggles" [C]
    fn toggle_word_check(
        gate: &Callgate,
        login: &mut catcard_pin::Login,
        ui: &mut Ui<'_>,
        policy: &Policy,
    ) {
        let on = !policy.word_check;
        if on {
            let rows = [
                Row::title("Word Check"),
                Row::body(
                    "Changing or removing the policy will also ask for the first and \
                     last words of the seed.",
                )
                .wrapped(),
                Row::body("ENTER turns it on.").small(),
            ];
            if !matches!(menu::show_doc(ui, &rows, false, true), DocExit::Confirmed) {
                return;
            }
            // A wallet with no words cannot answer the check.
            match menu::seed_entropy(gate, login, ui.panel, HEAD) {
                Ok((mut ent, _)) => ent.zeroize(),
                Err(_) => {
                    say(ui, "this wallet has no seed words");
                    return;
                }
            }
        } else if !word_check_passes(gate, login, ui, policy) {
            return;
        }
        update_root(gate, login, ui, |p| {
            p.word_check = on;
            Ok(())
        });
    }

    fn toggle(
        gate: &Callgate,
        login: &mut catcard_pin::Login,
        ui: &mut Ui<'_>,
        policy: &Policy,
        which: Toggle,
    ) {
        let (title, text, now) = match which {
            Toggle::Notes => (
                "Allow Notes",
                "Secure Notes & Passwords stay readable while hobbled; nothing can be \
                 added or changed.",
                policy.allow_notes,
            ),
            Toggle::RelatedKeys => (
                "Related Keys",
                "Passphrase wallets, temporary seeds and the vault stay reachable while \
                 hobbled, under the same policy.",
                policy.related_keys,
            ),
        };
        let rows = [
            Row::title(title),
            Row::body(text).wrapped(),
            Row::body(if now {
                "ENTER turns it off."
            } else {
                "ENTER turns it on."
            })
            .small(),
        ];
        if !matches!(menu::show_doc(ui, &rows, false, true), DocExit::Confirmed) {
            return;
        }
        if !word_check_passes(gate, login, ui, policy) {
            return;
        }
        update_root(gate, login, ui, |p| {
            match which {
                Toggle::Notes => p.allow_notes = !now,
                Toggle::RelatedKeys => p.related_keys = !now,
            }
            Ok(())
        });
    }

    /// The Word Check, where the policy asks for it: the first and last seed words,
    /// compared inside the masked region against the words the seed makes. True when
    /// the check is off or the words matched. One try; a miss is a refusal.
    fn word_check_passes(
        gate: &Callgate,
        login: &mut catcard_pin::Login,
        ui: &mut Ui<'_>,
        policy: &Policy,
    ) -> bool {
        if !policy.word_check {
            return true;
        }
        let Ok((mut ent, len)) = menu::seed_entropy(gate, login, ui.panel, HEAD) else {
            say(ui, "no seed words to check");
            return false;
        };
        let Some(count) = catcard_wallet::bip39::words_for_entropy(len) else {
            ent.zeroize();
            say(ui, "no seed words to check");
            return false;
        };
        menu::message(
            ui.panel,
            "Word Check",
            "type the first and",
            "last seed words",
        );
        menu::wait_for_any_key(ui);
        let WordPick::Word(first) = menu::read_word(ui, 1, None) else {
            ent.zeroize();
            return false;
        };
        let WordPick::Word(last) = menu::read_word(ui, count, None) else {
            ent.zeroize();
            return false;
        };
        // Both words compared whatever the first says: one XOR fold, no early exit.
        let ok = crate::keywork::run(|kw| {
            let Ok(m) = catcard_wallet::bip39::Mnemonic::from_entropy(&ent[..len], kw) else {
                return false;
            };
            let mut idx = [0u16; catcard_wallet::bip39::MAX_WORDS];
            let n = m.word_indices(&mut idx);
            n == count && ((idx[0] ^ first) | (idx[n - 1] ^ last)) == 0
        });
        ent.zeroize();
        if !ok {
            say(ui, "words did not match");
        }
        ok
    }

    // -----------------------------------------------------------------------------------
    // Edit Policy (SP-POL)
    // -----------------------------------------------------------------------------------

    /// The SpendingPolicyMenu: magnitude, velocity, whitelist, Web 2FA.
    /// Source: hw-reference/menu-map-mk4-mk5-q1-v5.6.2.md §SP-POL [C]
    fn edit_policy(gate: &Callgate, login: &mut catcard_pin::Login, ui: &mut Ui<'_>) {
        const H: &str = "Edit Policy";
        loop {
            let Some(policy) = current(gate, login, ui) else {
                return;
            };
            if !word_check_passes(gate, login, ui, &policy) {
                return;
            }
            let mut mag: heapless::String<40> = heapless::String::new();
            let _ = mag.push_str("Max Magnitude: ");
            if policy.magnitude == 0 {
                let _ = mag.push_str("none");
            } else {
                btc(policy.magnitude, &mut mag);
            }
            let mut vel: heapless::String<40> = heapless::String::new();
            let _ = if policy.velocity == 0 {
                write!(vel, "Limit Velocity: off")
            } else {
                write!(vel, "Limit Velocity: {} blocks", policy.velocity)
            };
            let mut wl: heapless::String<40> = heapless::String::new();
            let _ = write!(wl, "Whitelist Addresses ({})", policy.whitelist.len());
            let rows = [mag.as_str(), vel.as_str(), wl.as_str(), "Web 2FA: off"];
            let Some(row) = menu::pick_row(ui, H, "", &rows) else {
                return;
            };
            match row {
                0 => set_magnitude(gate, login, ui, &policy),
                1 => set_velocity(gate, login, ui, &policy),
                2 => whitelist(gate, login, ui),
                _ => {
                    // The enrolment and verification protocol is not in the reference.
                    // docs/HARDWARE-OPEN-ITEMS.md "Web 2FA" `[?]`
                    say(ui, "needs the Web 2FA spec");
                }
            }
        }
    }

    /// The cap, asked as whole bitcoin then satoshis: two fields that fit the digit
    /// prompt, rather than one that would overflow it past forty-two coins. Zero is no
    /// cap, and turns velocity off with it, as stock says.
    /// Source: hw-reference/help-and-warning-screens.md §12 "Set magnitude cap to zero" [C]
    fn set_magnitude(
        gate: &Callgate,
        login: &mut catcard_pin::Login,
        ui: &mut Ui<'_>,
        policy: &Policy,
    ) {
        const H: &str = "Max Magnitude";
        let Some(whole) = menu::ask_number(
            ui,
            H,
            Some(("cap", "per transaction")),
            "BTC",
            "0 is no cap",
        ) else {
            return;
        };
        if whole > 21_000_000 {
            say(ui, "more than there is");
            return;
        }
        let Some(sats) =
            menu::ask_number(ui, H, Some(("plus", "satoshis")), "sat", "empty is none")
        else {
            return;
        };
        if sats >= 100_000_000 {
            say(ui, "satoshis run to 99999999");
            return;
        }
        let cap = u64::from(whole) * 100_000_000 + u64::from(sats);
        if cap == 0 && policy.velocity > 0 {
            menu::message(ui.panel, H, "no cap: velocity", "is turned off too");
            menu::wait_for_any_key(ui);
        }
        update_root(gate, login, ui, |p| {
            p.magnitude = cap;
            if cap == 0 {
                p.velocity = 0;
            }
            Ok(())
        });
    }

    /// The velocity, in blocks; zero is off. Needs a cap, which is set to one bitcoin
    /// when there is none, as stock does.
    /// Source: hw-reference/help-and-warning-screens.md §12 "Enable velocity with no
    /// magnitude" [C]
    fn set_velocity(
        gate: &Callgate,
        login: &mut catcard_pin::Login,
        ui: &mut Ui<'_>,
        policy: &Policy,
    ) {
        const H: &str = "Limit Velocity";
        let Some(blocks) =
            menu::ask_number(ui, H, Some(("one spend", "per")), "blocks", "0 is off")
        else {
            return;
        };
        if blocks > engine::MAX_VELOCITY {
            say(ui, "at most a year of blocks");
            return;
        }
        if blocks > 0 && policy.magnitude == 0 {
            menu::message(
                ui.panel,
                H,
                "velocity needs a cap:",
                "set to 1 BTC to start",
            );
            menu::wait_for_any_key(ui);
        }
        update_root(gate, login, ui, |p| {
            p.velocity = blocks;
            if blocks > 0 && p.magnitude == 0 {
                p.magnitude = engine::DEFAULT_VELOCITY_MAGNITUDE;
            }
            Ok(())
        });
    }

    /// `n` satoshis as bitcoin, trailing zeros trimmed.
    fn btc(n: u64, out: &mut heapless::String<40>) {
        let whole = n / 100_000_000;
        let frac = n % 100_000_000;
        if frac == 0 {
            let _ = write!(out, "{whole} BTC");
            return;
        }
        let mut digits: heapless::String<8> = heapless::String::new();
        let _ = write!(digits, "{frac:08}");
        let trimmed = digits.trim_end_matches('0');
        let _ = write!(out, "{whole}.{trimmed} BTC");
    }

    // -----------------------------------------------------------------------------------
    // The whitelist
    // -----------------------------------------------------------------------------------

    /// SPAddrWhitelist: scan (Q1), import from a file, each address, clear.
    /// Source: hw-reference/menu-map-mk4-mk5-q1-v5.6.2.md §SP-POL "Whitelist Addresses" [C]
    fn whitelist(gate: &Callgate, login: &mut catcard_pin::Login, ui: &mut Ui<'_>) {
        const H: &str = "Whitelist";
        loop {
            let Some(policy) = current(gate, login, ui) else {
                return;
            };
            let mut shown: heapless::Vec<heapless::String<24>, { engine::MAX_WHITELIST }> =
                heapless::Vec::new();
            let mut rows: heapless::Vec<&str, { engine::MAX_WHITELIST + 4 }> = heapless::Vec::new();
            #[cfg(feature = "board-q1")]
            let _ = rows.push("Scan QR");
            let _ = rows.push("Import from File");
            let fixed = rows.len();
            for a in &policy.whitelist {
                let mut s: heapless::String<24> = heapless::String::new();
                if a.len() <= 20 {
                    let _ = s.push_str(a);
                } else {
                    let _ = write!(s, "{}..{}", &a[..8], &a[a.len() - 8..]);
                }
                let _ = shown.push(s);
            }
            for s in &shown {
                let _ = rows.push(s.as_str());
            }
            if policy.whitelist.is_empty() {
                let _ = rows.push("(none yet)");
            } else {
                let _ = rows.push("Clear Whitelist");
            }
            let Some(row) = menu::pick_row(ui, H, "destinations allowed", &rows) else {
                return;
            };
            match rows[row] {
                #[cfg(feature = "board-q1")]
                "Scan QR" => scan_address(gate, login, ui),
                "Import from File" => import_file(gate, login, ui),
                "(none yet)" => {}
                "Clear Whitelist" => {
                    menu::ask(ui.panel, H, "forget every", "whitelisted address?");
                    if menu::confirmed(ui) {
                        update_root(gate, login, ui, |p| {
                            p.whitelist.clear();
                            Ok(())
                        });
                    }
                }
                _ => {
                    let i = row - fixed;
                    if let Some(a) = policy.whitelist.get(i) {
                        let rows = [
                            Row::title("Whitelisted"),
                            Row::body(a).wrapped(),
                            Row::body("ENTER removes it; CANCEL keeps it.").small(),
                        ];
                        if matches!(menu::show_doc(ui, &rows, false, false), DocExit::Confirmed) {
                            update_root(gate, login, ui, |p| {
                                if i < p.whitelist.len() {
                                    p.whitelist.remove(i);
                                }
                                Ok(())
                            });
                        }
                    }
                }
            }
        }
    }

    /// Add one address, saying why not. The scanner's path; the file import adds many.
    #[cfg(feature = "board-q1")]
    fn add(gate: &Callgate, login: &mut catcard_pin::Login, ui: &mut Ui<'_>, text: &str) {
        let mut why: Option<&'static str> = None;
        let ok = update_root(gate, login, ui, |p| {
            p.add_address(text).map_err(|e| {
                why = Some(e.text());
                e.text()
            })
        });
        if ok {
            let mut line: heapless::String<40> = heapless::String::new();
            let _ = write!(line, "added ({} chars)", text.trim().len());
            menu::message(ui.panel, "Whitelist", &line, "");
            menu::wait_for_any_key(ui);
        }
    }

    /// Addresses from a text file on the card or the Virtual Disk, one per line, added
    /// until the list is full; the count and the first refusal are reported.
    fn import_file(gate: &Callgate, login: &mut catcard_pin::Login, ui: &mut Ui<'_>) {
        const H: &str = "Import addresses";
        let Some(storage) = menu::pick_storage(ui, H) else {
            return;
        };
        let Some(path) =
            menu::browse_storage(ui, storage, "Pick a .txt", Some("txt"), menu::Browse::File)
        else {
            return;
        };
        let Some(mut held) = crate::heap::take(SCRATCH) else {
            say(ui, "no memory");
            return;
        };
        let buf = held.bytes();
        let n = match crate::signtx::read_source_file(storage, &path, buf) {
            Ok(n) => n,
            Err(why) => {
                say(ui, why);
                return;
            }
        };
        let Ok(text) = core::str::from_utf8(&buf[..n]) else {
            say(ui, "not a text file");
            return;
        };
        let mut added = 0usize;
        let mut first_refusal: Option<&'static str> = None;
        let ok = update_root(gate, login, ui, |p| {
            for line in text.lines() {
                let line = line.trim();
                if line.is_empty() || line.starts_with('#') {
                    continue;
                }
                match p.add_address(line) {
                    Ok(()) => added += 1,
                    Err(e) => {
                        if first_refusal.is_none() {
                            first_refusal = Some(e.text());
                        }
                        if e == engine::AddError::Full {
                            break;
                        }
                    }
                }
            }
            if added == 0 {
                Err(first_refusal.unwrap_or("no addresses in the file"))
            } else {
                Ok(())
            }
        });
        if ok {
            let mut line: heapless::String<40> = heapless::String::new();
            let _ = write!(line, "{added} added");
            menu::message(ui.panel, H, &line, first_refusal.unwrap_or(""));
            menu::wait_for_any_key(ui);
        }
    }

    /// One address from the scanner (Q1).
    #[cfg(feature = "board-q1")]
    fn scan_address(gate: &Callgate, login: &mut catcard_pin::Login, ui: &mut Ui<'_>) {
        use crate::qrscan::{self, Next};
        let mut got: heapless::String<{ engine::MAX_ADDRESS + 16 }> = heapless::String::new();
        let outcome = qrscan::scan_many(ui, "Scan address", &mut |_, line| {
            got.clear();
            if let Ok(t) = core::str::from_utf8(line) {
                let _ = got.push_str(catcard_wallet::address::qr_address(t));
            }
            Next::Done
        });
        if outcome.is_err() || got.is_empty() {
            return;
        }
        add(gate, login, ui, got.as_str());
    }

    // -----------------------------------------------------------------------------------
    // Test Drive, ACTIVATE, Remove Policy
    // -----------------------------------------------------------------------------------

    /// Hobbled for the session, nothing written.
    /// Source: hw-reference/help-and-warning-screens.md §12 "Test Drive" [C]
    fn test_drive(ui: &mut Ui<'_>, policy: &Policy) -> bool {
        let rows = [
            Row::title("Test Drive"),
            Row::body(
                "Preview hobbled mode with this policy until EXIT TEST DRIVE on the main \
                 menu, or the next login. Nothing is saved.",
            )
            .wrapped(),
            Row::body("CONTINUE? ENTER for yes.").small(),
        ];
        if !matches!(menu::show_doc(ui, &rows, false, true), DocExit::Confirmed) {
            return false;
        }
        set(
            Mode::TestDrive,
            Allow {
                notes: policy.allow_notes,
                related_keys: policy.related_keys,
            },
        );
        true
    }

    /// Lock the policy in. With an unlock code, or -- after the warning -- without one.
    /// Source: hw-reference/help-and-warning-screens.md §12 "Activate / lock in the
    /// policy" [C]; that the code is chosen here rather than at enable `[I]`
    fn activate(
        gate: &Callgate,
        login: &mut catcard_pin::Login,
        ui: &mut Ui<'_>,
        policy: &Policy,
    ) -> bool {
        const H: &str = "ACTIVATE";
        if !policy.has_rules() {
            say(ui, "no rule is set: nothing to enforce");
            return false;
        }
        if !word_check_passes(gate, login, ui, policy) {
            return false;
        }
        menu::ask(ui.panel, H, "set an unlock code", "to get back out?");
        let with_code = menu::confirmed(ui);
        let mut record: heapless::String<{ engine::UNLOCK_RECORD_LEN }> = heapless::String::new();
        if with_code {
            let Some(text) = enrol_unlock_code(gate, login, ui) else {
                return false;
            };
            let _ = record.push_str(&text);
        } else {
            // No way back but the seed.
            let rows = [
                Row::title("No unlock code"),
                Row::body(
                    "With no unlock code there is NO WAY to change or remove this policy \
                     except destroying the seed and loading it again.",
                )
                .wrapped(),
                Row::body("ENTER accepts that; CANCEL goes back.").small(),
            ];
            if !matches!(menu::show_doc(ui, &rows, false, true), DocExit::Confirmed) {
                return false;
            }
            menu::ask(ui.panel, H, "really: no way back", "but a new seed?");
            if !menu::confirmed(ui) {
                return false;
            }
        }
        let rows = [
            Row::title("Lock in the policy?"),
            Row::body("The device is hobbled from now: signing and addresses only.").wrapped(),
            Row::body(if with_code {
                "To get back: type the unlock code at the PIN prompt, then the main PIN, \
                 then the seed words if Word Check is on."
            } else {
                "There is no way back but destroying the seed."
            })
            .wrapped(),
            Row::body("CONTINUE? ENTER for yes.").small(),
        ];
        if !matches!(menu::show_doc(ui, &rows, false, true), DocExit::Confirmed) {
            return false;
        }
        // The record before the flag: a device that lost power between the two has a
        // code and no policy, which is nothing; the other order would be a policy with
        // no way out that nobody chose.
        if with_code && !crate::settings::save_unlock_record(ui, &record) {
            say(ui, "could not save the code");
            return false;
        }
        if !update_root(gate, login, ui, |p| {
            p.active = true;
            p.violation.clear();
            Ok(())
        }) {
            return false;
        }
        set(
            Mode::Hobbled,
            Allow {
                notes: policy.allow_notes,
                related_keys: policy.related_keys,
            },
        );
        menu::message(ui.panel, H, "policy is ACTIVE", "device is hobbled");
        menu::wait_for_any_key(ui);
        true
    }

    /// Choose the unlock code: both halves twice, then a probe against the bootloader so
    /// it cannot be the main PIN -- a code that were would match at every login and the
    /// owner could never get in. The probe spends one PIN attempt when the code is not
    /// the PIN (the normal case), restored by the next successful login, exactly as
    /// Test login does; refused when few attempts remain. Returns the record to store.
    fn enrol_unlock_code(
        gate: &Callgate,
        login: &mut catcard_pin::Login,
        ui: &mut Ui<'_>,
    ) -> Option<heapless::String<{ engine::UNLOCK_RECORD_LEN }>> {
        use crate::pinentry::{self, PinProbe};
        const H: &str = "Unlock code";
        menu::message(
            ui.panel,
            H,
            "a prefix and a suffix,",
            "typed like a PIN; not the PIN",
        );
        menu::wait_for_any_key(ui);
        let (prefix, suffix) = pinentry::collect_unlock_code(ui.panel, ui.matrix, ui.drbg)?;
        let mut code: heapless::Vec<u8, 16> = heapless::Vec::new();
        let _ = code.extend_from_slice(prefix.as_bytes());
        let _ = code.push(b'-');
        let _ = code.extend_from_slice(suffix.as_bytes());
        if !engine::unlock_code_ok(&code) {
            code.zeroize();
            say(ui, "4 to 12 digits in all");
            return None;
        }
        menu::message(ui.panel, H, "checking it is not", "the PIN (spends 1 try)");
        menu::wait_for_any_key(ui);
        match pinentry::probe_main_pin(gate, ui.panel, login, prefix.as_bytes(), suffix.as_bytes())
        {
            PinProbe::NotMainPin { attempts_left } => {
                crate::catlog!("policy: code probed, {} attempts left", attempts_left);
            }
            PinProbe::IsMainPin => {
                code.zeroize();
                say(ui, "that is the main PIN: choose another");
                return None;
            }
            PinProbe::TooFewTries { attempts_left } => {
                code.zeroize();
                let mut line: heapless::String<40> = heapless::String::new();
                let _ = write!(line, "only {attempts_left} tries left");
                menu::message(ui.panel, H, &line, "log in again first");
                menu::wait_for_any_key(ui);
                return None;
            }
            PinProbe::Failed => {
                code.zeroize();
                say(ui, "could not check the code");
                return None;
            }
        }
        // The salt from the protocol generator: a value that leaves the device (into the
        // flash) and must not be guessable from anything on the screen.
        let mut salt = [0u8; engine::UNLOCK_SALT_LEN];
        if ui.protocol.generate(&mut salt).is_err() {
            code.zeroize();
            say(ui, "no randomness for the salt");
            return None;
        }
        menu::blocking_screen(ui.panel, H, "stretching");
        let mut buf = [0u8; engine::UNLOCK_RECORD_LEN];
        let record = engine::render_unlock(&code, &salt, engine::UNLOCK_ROUNDS, &mut buf);
        code.zeroize();
        let record = record?;
        let mut out: heapless::String<{ engine::UNLOCK_RECORD_LEN }> = heapless::String::new();
        out.push_str(record).ok()?;
        Some(out)
    }

    /// Forget the policy and the unlock code. Behind the Word Check where it is on.
    /// Source: hw-reference/help-and-warning-screens.md §12 "Remove Policy" [C]
    fn remove(
        gate: &Callgate,
        login: &mut catcard_pin::Login,
        ui: &mut Ui<'_>,
        policy: &Policy,
    ) -> bool {
        const H: &str = "Remove Policy";
        if !word_check_passes(gate, login, ui, policy) {
            return false;
        }
        menu::ask(ui.panel, H, "forget the policy", "and the unlock code?");
        if !menu::confirmed(ui) {
            return false;
        }
        if !update_root(gate, login, ui, |p| {
            *p = Policy::default();
            Ok(())
        }) {
            return false;
        }
        if !crate::settings::save_unlock_record(ui, "") {
            say(ui, "policy removed; code not cleared");
        }
        set(Mode::Off, Allow::default());
        menu::message(ui.panel, H, "policy removed", "device is unrestricted");
        menu::wait_for_any_key(ui);
        true
    }

    fn say(ui: &mut Ui<'_>, what: &str) {
        menu::message(ui.panel, HEAD, what, "any key to go back");
        menu::wait_for_any_key(ui);
    }
}

/// The mk3 has no settings store, so it can hold no policy: nothing loads, nothing is
/// enforced, and the screens do not exist.
#[cfg(feature = "board-mk3")]
mod imp {
    use catcard_callgate::Callgate;
    use catcard_wallet::psbtview;
    use outscript::psbt::Psbt;

    use crate::ui::Ui;

    pub(crate) fn load(_gate: &Callgate, _login: &mut catcard_pin::Login, _ui: &mut Ui<'_>) {}

    pub(crate) fn enforce(
        _gate: &Callgate,
        _login: &mut catcard_pin::Login,
        _ui: &mut Ui<'_>,
        _psbt: &Psbt<'_>,
        _owner: &psbtview::Owner<'_>,
        _summary: &psbtview::Summary,
    ) -> bool {
        true
    }
}
