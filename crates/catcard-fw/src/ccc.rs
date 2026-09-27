//! Coldcard Co-Sign (CCC): key C on the device, its screens, and the co-signature.
//!
//! Key C is a second, independent BIP-39 seed kept in the root wallet's settings. It is one
//! of the keys of a 2-of-N multisig -- key A is this device's own seed, key B a backup held
//! elsewhere -- and it signs only a transaction that meets its spending policy. Within the
//! policy this device alone spends (A + C); outside it, A needs B.
//! Source: hw-reference/ccc-key-storage.md [C]; help-and-warning-screens.md §12 "CCC" [C];
//! menu-map-mk4-mk5-q1-v5.6.2.md §SP2 [C]
//!
//! [`catcard_settings::ccc`] is the stored value (stock's own `ccc` key, in stock's exact
//! shape), the co-signing decision and the challenge count, all tested on the host. This
//! module is what the device does with them:
//!
//! - **Settings -> Spending Policy -> Co-Sign Multisig (CCC)**, [`screen`]: enable (make,
//!   type or pick key C), then the CCCConfigMenu -- the policy (the single-signer editor,
//!   shared), Export CCC XPUBs, the wallets key C is in and Build 2-of-N, Load Key C,
//!   Remove CCC. Behind key C's words once key C exists.
//! - **Signing**, [`decide`]: a spend from a registered wallet key C is in is judged
//!   against key C's policy; key C signs beside this device's key only when it passes, and
//!   otherwise the owner is told why and may sign without it.
//!
//! # Key C's words are the lock
//!
//! Anyone at the unlocked device can read the settings, so what guards the policy is key
//! C's phrase: changing, removing or exporting anything needs all of it typed back
//! ([`challenge`]), compared as the whole re-encoded key -- not a fingerprint, not the first
//! and last words (that is the single-signer Word Check, a different thing). Three wrong
//! phrases in a session restart the device. Key C kept in the Seed Vault defeats this, and
//! the screens say so.
//!
//! # Root wallet only
//!
//! Key C lives in the root wallet's settings, and every screen and co-signature here
//! requires the root wallet in force: a temporary seed or a passphrase wallet has no CCC,
//! as stock's `is_not_tmp` has it.
//!
//! Key C's words, entropy and master key are secrets: they are only touched inside
//! [`crate::keywork::run`], wiped after use, and never logged.

use catcard_callgate::Callgate;
use catcard_callgate::abi::LogoutMode;
use catcard_settings::ccc::{self as engine, Ccc, Read, SECRET_LEN};
use catcard_settings::policy::{Checker, MAX_VIOLATION, Policy};
use catcard_settings::store::SCRATCH;
use catcard_ui::scroll::Line as Row;
use catcard_wallet::bip32::ExtendedPrivKey;
use catcard_wallet::psbtview;
use core::fmt::Write as _;
use outscript::psbt::Psbt;
use zeroize::{Zeroize as _, Zeroizing};

use crate::menu::{self, DocExit};
use crate::ui::Ui;

const HEAD: &str = "Co-Sign (CCC)";

/// Wrong key-C phrases typed this session; see [`engine::challenge`]. Cleared by the
/// restart it leads to.
static mut FAILS: u8 = 0;

type Xfp = heapless::String<8>;
type Violation = heapless::String<MAX_VIOLATION>;

fn xfp_hex(fp: [u8; 4]) -> Xfp {
    let mut s = Xfp::new();
    let [a, b, c, d] = fp;
    let _ = write!(s, "{a:02X}{b:02X}{c:02X}{d:02X}");
    s
}

// ---------------------------------------------------------------------------------------
// Reading and writing
// ---------------------------------------------------------------------------------------

/// Key C's record in a heap block, empty: where [`read_now`] puts what it reads.
///
/// The record is three kilobytes -- key C's policy is a whole whitelist -- and it used to
/// be returned by value through every frame between the signing review and the store,
/// each of which kept its own copy. Here each keeps a pointer.
fn blank() -> Option<crate::heap::Owned<Read>> {
    Some(crate::heap::room()?.fill(Read::Absent))
}

/// Key C and the last co-signing refusal, as the root wallet's settings hold them, read
/// through `buf` (one [`SCRATCH`]) into `out` and `viol`. The caller has checked the root
/// wallet is in force.
fn read_now(
    gate: &Callgate,
    login: &mut catcard_pin::Login,
    panel: &mut crate::display::Panel,
    buf: &mut [u8],
    out: &mut Read,
    viol: &mut Violation,
) -> Result<(), &'static str> {
    let key = crate::settings::wallet_key(gate, login, panel, HEAD)?;
    let n = crate::settings::read_slot(&key, buf)?;
    decode(&buf[..n], out, viol)
}

/// Key C's record and the last refusal out of a settings object.
///
/// A leaf of its own: the parse and the record as it is built are gone when it returns.
#[inline(never)]
fn decode(json: &[u8], out: &mut Read, viol: &mut Violation) -> Result<(), &'static str> {
    let doc = crate::settings::parse_doc(json).ok_or("not enough memory")?;
    viol.clear();
    if let Some(t) = doc.get_str(engine::VIOLATION_KEY) {
        let _ = viol.push_str(t);
    }
    engine::read_into(&doc, out);
    Ok(())
}

/// [`read_now`] with its own lease; `None` once the screen has said why not.
fn load(
    gate: &Callgate,
    login: &mut catcard_pin::Login,
    ui: &mut Ui<'_>,
) -> Option<(crate::heap::Owned<Read>, Violation)> {
    let (Some(mut held), Some(mut read)) = (crate::heap::take(SCRATCH), blank()) else {
        say(ui, "not enough memory");
        return None;
    };
    let mut viol = Violation::new();
    match read_now(gate, login, ui.panel, held.bytes(), &mut read, &mut viol) {
        Ok(()) => Some((read, viol)),
        Err(why) => {
            drop((held, read));
            say(ui, why);
            None
        }
    }
}

/// Write one key's JSON text into the root wallet's settings.
fn write_value(
    gate: &Callgate,
    login: &mut catcard_pin::Login,
    ui: &mut Ui<'_>,
    pair: (&str, &str),
) -> bool {
    let (Some(mut doc), Some(mut seal)) = (crate::heap::take(SCRATCH), crate::heap::take(SCRATCH))
    else {
        return false;
    };
    crate::settings::save_wallet(gate, login, ui, HEAD, pair, doc.bytes(), seal.bytes()).is_ok()
}

/// Store `c` under stock's `ccc` key.
fn save(gate: &Callgate, login: &mut catcard_pin::Login, ui: &mut Ui<'_>, c: &Ccc) -> bool {
    let Some(mut text) = crate::heap::take(SCRATCH) else {
        say(ui, "not enough memory");
        return false;
    };
    let Some(raw) = c.render(text.bytes()) else {
        say(ui, "too large to store");
        return false;
    };
    if write_value(gate, login, ui, (engine::KEY, raw)) {
        true
    } else {
        say(ui, "could not save");
        false
    }
}

/// Read key C, change it, write it back; true when the write landed.
fn update(
    gate: &Callgate,
    login: &mut catcard_pin::Login,
    ui: &mut Ui<'_>,
    edit: impl FnOnce(&mut Ccc) -> Result<(), &'static str>,
) -> bool {
    let Some((mut read, _)) = load(gate, login, ui) else {
        return false;
    };
    let Read::Ccc(c) = &mut *read else {
        drop(read);
        say(ui, "no key C to change");
        return false;
    };
    if let Err(why) = edit(c) {
        drop(read);
        say(ui, why);
        return false;
    }
    save(gate, login, ui, c)
}

/// The CCC policy, for the shared editor (`crate::policy`, SP-POL), in a heap block of
/// its own.
pub(crate) fn current_policy(
    gate: &Callgate,
    login: &mut catcard_pin::Login,
    ui: &mut Ui<'_>,
) -> Option<crate::heap::Owned<Policy>> {
    let (read, _) = load(gate, login, ui)?;
    let Read::Ccc(c) = &*read else {
        drop(read);
        say(ui, "no key C");
        return None;
    };
    let Some(mut out) = crate::heap::room().map(|r| r.fill(Policy::default())) else {
        drop(read);
        say(ui, "not enough memory");
        return None;
    };
    copy_policy(&mut out, &c.policy);
    Some(out)
}

/// `dst = src.clone()`, field by field: a derived `clone_from` builds the whole policy on
/// the stack first and copies it over.
fn copy_policy(dst: &mut Policy, src: &Policy) {
    let Policy {
        magnitude,
        velocity,
        last_height,
        word_check,
        allow_notes,
        related_keys,
        active,
        whitelist,
        violation,
    } = src;
    dst.magnitude = *magnitude;
    dst.velocity = *velocity;
    dst.last_height = *last_height;
    dst.word_check = *word_check;
    dst.allow_notes = *allow_notes;
    dst.related_keys = *related_keys;
    dst.active = *active;
    dst.whitelist.clear();
    for a in whitelist {
        // The same capacity on both sides: never refused.
        let _ = dst.whitelist.push(a.clone());
    }
    dst.violation.clear();
    let _ = dst.violation.push_str(violation);
}

/// Change the CCC policy, for the shared editor.
pub(crate) fn update_policy(
    gate: &Callgate,
    login: &mut catcard_pin::Login,
    ui: &mut Ui<'_>,
    edit: impl FnOnce(&mut Policy) -> Result<(), &'static str>,
) -> bool {
    update(gate, login, ui, |c| edit(&mut c.policy))
}

// ---------------------------------------------------------------------------------------
// Key C's secret
// ---------------------------------------------------------------------------------------

/// Key C's entropy, copied out of `c` inside the masked region. Wiped when dropped.
fn entropy_of(c: &Ccc) -> (Zeroizing<[u8; 32]>, usize) {
    let mut ent = Zeroizing::new([0u8; 32]);
    let len = crate::keywork::run(|_| {
        let e = c.entropy();
        ent[..e.len()].copy_from_slice(e);
        e.len()
    });
    (ent, len)
}

/// Key C's BIP-32 master, from its words with no passphrase: key C is its own seed, and the
/// wallet's passphrase is the wallet's. Stretched in slices with the screen moving.
fn master_from(
    panel: &mut crate::display::Panel,
    head: &str,
    ent: &mut [u8; 32],
    len: usize,
) -> Result<ExtendedPrivKey, &'static str> {
    let net = crate::prefs::network();
    menu::stretch_phrase(panel, head, ent, len, "", |seed, kw| {
        ExtendedPrivKey::from_seed(seed, net, kw).ok()
    })
}

/// Key C's master, from the stored value.
fn master_of(
    c: &Ccc,
    panel: &mut crate::display::Panel,
    head: &str,
) -> Result<ExtendedPrivKey, &'static str> {
    let (mut ent, len) = entropy_of(c);
    master_from(panel, head, &mut ent, len)
}

/// A phrase's entropy as the secret-stash encoding, inside the masked region.
fn encode(entropy: &[u8]) -> Option<Zeroizing<[u8; SECRET_LEN]>> {
    crate::keywork::run(|_| {
        let mut raw = catcard_callgate::pin::encode_bip39(entropy).ok()?;
        let out = Zeroizing::new(raw);
        raw.zeroize();
        Some(out)
    })
}

// ---------------------------------------------------------------------------------------
// Signing
// ---------------------------------------------------------------------------------------

/// Key C, ready to sign beside this device's key.
pub(crate) struct CoSigner {
    pub(crate) master: ExtendedPrivKey,
    pub(crate) fingerprint: [u8; 4],
}

/// What the signing screen does about key C.
pub(crate) enum Decision {
    /// Sign with this device's key only: key C is not in the wallet being spent, or the
    /// owner chose to sign without it.
    Alone,
    /// Sign with this device's key and key C.
    CoSign(CoSigner),
    /// The owner would not sign without the co-signature.
    Refused,
}

/// Decide whether key C co-signs the transaction the review just showed.
///
/// Engaged only when the root wallet is in force, key C is stored, and a registered
/// multisig wallet the inputs spend from has key C as a cosigner. Then key C's policy
/// judges it: a review warning or a Web 2FA rule refuses outright, then the whitelist,
/// the magnitude and the velocity -- the single-signer engine's rules over the same
/// outputs and totals the review showed. Passing records the height (before the signature,
/// as the single-signer policy does); failing records the reason and offers to sign
/// without the co-signature.
/// Source: hw-reference/ccc-key-storage.md §3 "CCC signing gate" [C];
/// help-and-warning-screens.md §7 "CCC / 2FA during signing" [C]
pub(crate) fn decide(
    gate: &Callgate,
    login: &mut catcard_pin::Login,
    ui: &mut Ui<'_>,
    psbt: &Psbt<'_>,
    owner: &psbtview::Owner<'_>,
    summary: &psbtview::Summary,
) -> Decision {
    let spent = &summary.wallets[..summary.wallet_count];
    // No multisig in the spend, or not the root wallet: nothing to read.
    if spent.is_empty() || !crate::key::is_root() {
        return Decision::Alone;
    }
    // Judged with key C's record in scope; only what signing needs leaves it.
    let (verdict, fingerprint, mut ent, len) = {
        let (Some(mut held), Some(mut read)) = (crate::heap::take(SCRATCH), blank()) else {
            crate::catlog!("ccc: no memory to read key C");
            return Decision::Alone;
        };
        let mut viol = Violation::new();
        let found = read_now(gate, login, ui.panel, held.bytes(), &mut read, &mut viol);
        let c = match (found, &*read) {
            (Ok(()), Read::Ccc(c)) => c,
            (Ok(()), Read::Damaged) => {
                crate::catlog!("ccc: key C's record will not read; not co-signing");
                menu::message(
                    ui.panel,
                    "Co-sign",
                    "key C's record is damaged",
                    "signing without it",
                );
                menu::wait_for_any_key(ui);
                return Decision::Alone;
            }
            _ => return Decision::Alone,
        };
        drop(held);
        let involved = spent
            .iter()
            .any(|&i| owner.wallets.get(i).is_some_and(|w| w.involves(c.xfp)));
        if !involved {
            return Decision::Alone;
        }
        crate::catlog!("ccc: spend involves key C; checking its policy");
        let warnings = summary.odd_count > 0 || summary.fee_warn;
        let verdict = c.precheck(warnings).and_then(|()| {
            let mut checker = Checker::new(&c.policy);
            crate::policy::check_outputs(ui, psbt, owner, summary, &c.policy, &mut checker);
            engine::finish(
                c,
                checker,
                summary.sending,
                crate::policy::lock_height(psbt),
            )
        });
        let (ent, len) = entropy_of(c);
        (verdict, c.xfp, ent, len)
    };

    match verdict {
        Ok(cosign) => {
            crate::catlog!("ccc: policy met, height {:?}", cosign.record_height);
            if let Some(h) = cosign.record_height
                && !update(gate, login, ui, |c| {
                    if h > c.policy.last_height {
                        c.policy.last_height = h;
                    }
                    Ok(())
                })
            {
                return without(ui, "could not record the spend");
            }
            match master_from(ui.panel, "Co-sign", &mut ent, len) {
                Ok(master) => Decision::CoSign(CoSigner {
                    master,
                    fingerprint,
                }),
                Err(why) => without(ui, why),
            }
        }
        Err(v) => {
            let text = v.describe();
            crate::catlog!("ccc: policy REFUSED: {}", text.as_str());
            let mut quoted: heapless::String<{ MAX_VIOLATION + 2 }> = heapless::String::new();
            let _ = write!(quoted, "\"{}\"", text.as_str());
            if !write_value(gate, login, ui, (engine::VIOLATION_KEY, &quoted)) {
                crate::catlog!("ccc: refusal not recorded");
            }
            without(ui, &text)
        }
    }
}

/// Key C will not sign: say why, and ask whether to sign without it.
fn without(ui: &mut Ui<'_>, why: &str) -> Decision {
    let rows = [
        Row::title("No co-signature"),
        Row::body(why).wrapped(),
        Row::body(
            "Key C will not sign this. This device can still add its own signature; the \
             transaction then needs key B as well.",
        )
        .wrapped(),
        Row::body("ENTER signs without key C; CANCEL signs nothing.")
            .small()
            .wrapped(),
    ];
    match menu::show_doc(ui, &rows, false, true) {
        DocExit::Confirmed => Decision::Alone,
        _ => Decision::Refused,
    }
}

// ---------------------------------------------------------------------------------------
// Settings -> Spending Policy -> Co-Sign Multisig (CCC)
// ---------------------------------------------------------------------------------------

/// The CCC row: enable when there is no key C, the configuration behind key C's words
/// when there is. `pool` is the boot entropy pool, for generating key C.
/// Source: hw-reference/menu-map-mk4-mk5-q1-v5.6.2.md §ADV "Co-Sign Multisig (CCC)"
/// (`is_not_tmp`), §SP2 [C]
#[inline(never)]
pub(crate) fn screen(
    gate: &Callgate,
    login: &mut catcard_pin::Login,
    ui: &mut Ui<'_>,
    pool: Option<&mut catcard_entropy::EntropyPool>,
) {
    if !crate::key::is_root() {
        say(ui, "not in a temporary seed");
        return;
    }
    let Some((read, _)) = load(gate, login, ui) else {
        return;
    };
    // The record goes back to the heap before anything below reads it again.
    let passed = match &*read {
        Read::Ccc(c) => Some(challenge(gate, login, ui, c)),
        Read::Absent | Read::Damaged => None,
    };
    let absent = matches!(*read, Read::Absent);
    drop(read);
    match passed {
        Some(true) => config(gate, login, ui),
        Some(false) => {}
        None if absent => {
            if enable(gate, login, ui, pool) {
                config(gate, login, ui);
            }
        }
        None => damaged(gate, login, ui),
    }
}

/// Stock's enable story, then key C from one of three places, then stored.
/// Source: hw-reference/help-and-warning-screens.md §12 "Enable CCC", "Provide key C" [C]
#[inline(never)]
fn enable(
    gate: &Callgate,
    login: &mut catcard_pin::Login,
    ui: &mut Ui<'_>,
    pool: Option<&mut catcard_entropy::EntropyPool>,
) -> bool {
    let rows = [
        Row::title("Co-Sign Multisig"),
        Row::body(
            "Adds a second seed, key C, to this device. Key C signs only transactions \
             that meet a spending policy you set.",
        )
        .wrapped(),
        Row::body(
            "It is one key of a 2-of-3 multisig: A is this device's seed, B a backup key \
             kept elsewhere, C the policy key. Within the policy this device spends \
             alone; outside it, A needs B.",
        )
        .wrapped(),
        Row::body(
            "The policy cannot be seen or changed without key C's words. Lose them and \
             the policy is locked for good.",
        )
        .wrapped(),
        Row::body("ENTER to set it up; CANCEL to leave.")
            .small()
            .wrapped(),
    ];
    if !matches!(menu::show_doc(ui, &rows, false, true), DocExit::Confirmed) {
        return false;
    }
    let Some(secret) = provide_key_c(gate, login, ui, pool) else {
        return false;
    };
    install(gate, login, ui, &secret)
}

/// Generate a fresh 12-word key C, type 12 or 24 words, or take one from the Seed Vault.
/// Source: hw-reference/help-and-warning-screens.md §12 "Provide key C" [C]
fn provide_key_c(
    gate: &Callgate,
    login: &mut catcard_pin::Login,
    ui: &mut Ui<'_>,
    pool: Option<&mut catcard_entropy::EntropyPool>,
) -> Option<Zeroizing<[u8; SECRET_LEN]>> {
    let mut rows: heapless::Vec<&str, 4> = heapless::Vec::new();
    let _ = rows.push("New 12 words");
    let _ = rows.push("Import 12 words");
    let _ = rows.push("Import 24 words");
    if crate::vault::count(gate, login, ui) > 0 {
        let _ = rows.push("From Seed Vault");
    }
    let row = menu::pick_row(ui, "Key C", "where key C comes from", &rows)?;
    match rows[row] {
        "New 12 words" => menu::new_key_c(gate, login, ui, pool, 12),
        "Import 12 words" | "Import 24 words" => {
            let n = if row == 1 { 12 } else { 24 };
            let m = menu::read_phrase_of(ui, Some(n))?;
            encode(m.entropy())
        }
        _ => {
            let picked = crate::vault::pick_part(gate, login, ui, "Key C")?;
            let got = crate::keywork::run(|kw| {
                picked
                    .entropy(kw)
                    .ok()
                    .and_then(|e| catcard_callgate::pin::encode_bip39(e).ok())
                    .map(|mut raw| {
                        let out = Zeroizing::new(raw);
                        raw.zeroize();
                        out
                    })
            });
            if got.is_none() {
                say(ui, "that entry is not seed words");
            }
            got
        }
    }
}

/// Key C's fingerprint and master xpub, and the value stored. Refuses key C that is this
/// device's own seed: a co-signer that is the same key is no second signature at all.
fn install(
    gate: &Callgate,
    login: &mut catcard_pin::Login,
    ui: &mut Ui<'_>,
    secret: &[u8; SECRET_LEN],
) -> bool {
    let Some(words) = engine::words_of(secret) else {
        say(ui, "not a seed phrase");
        return false;
    };
    let mut ent = Zeroizing::new([0u8; 32]);
    let len = words * 4 / 3;
    crate::keywork::run(|_| ent[..len].copy_from_slice(&secret[1..1 + len]));
    let master = match master_from(ui.panel, "Key C", &mut ent, len) {
        Ok(m) => m,
        Err(why) => {
            say(ui, why);
            return false;
        }
    };
    let (fp, public) =
        crate::keywork::run(|kw| (master.fingerprint(kw), master.to_extended_pub(kw)));
    drop(master);
    let mut buf = [0u8; catcard_wallet::bip32::serialize::MAX_BASE58_LEN];
    let Some(xpub) = public
        .write_base58(&mut buf)
        .ok()
        .and_then(|n| core::str::from_utf8(&buf[..n]).ok())
    else {
        say(ui, "could not write key C's xpub");
        return false;
    };
    if crate::pubkeys::fingerprint(gate, login, ui, HEAD) == Some(fp) {
        say(ui, "key C must be another seed");
        return false;
    }
    let Some(c) = Ccc::new(secret, fp, xpub) else {
        say(ui, "key C cannot be stored");
        return false;
    };
    if !save(gate, login, ui, &c) {
        return false;
    }
    crate::catlog!("ccc: key C stored");
    let who = xfp_hex(fp);
    menu::message(
        ui.panel,
        "Key C saved",
        &who,
        "policy: 1 BTC per 144 blocks",
    );
    menu::wait_for_any_key(ui);
    true
}

/// Key C's words, to open the configuration. All of them, compared as the whole key;
/// three wrong phrases in a session restart the device. Key C in the Seed Vault skips the
/// words, with the warning that it defeats them.
/// Source: hw-reference/ccc-key-storage.md §1.4(a) [C]; help-and-warning-screens.md §12
/// "Modify CCC settings later", "Word challenge failure" [C]
fn challenge(gate: &Callgate, login: &mut catcard_pin::Login, ui: &mut Ui<'_>, c: &Ccc) -> bool {
    let who = xfp_hex(c.xfp);
    if crate::vault::holds(gate, login, ui, &who) {
        let rows = [
            Row::title("Key C in the vault"),
            Row::body(
                "Key C is in the Seed Vault, so its words are not asked. Delete it from \
                 the vault once you are done: while it is there, anyone with the PIN can \
                 change the policy.",
            )
            .wrapped(),
            Row::body("ENTER to go on; CANCEL to leave.").small(),
        ];
        return matches!(menu::show_doc(ui, &rows, false, true), DocExit::Confirmed);
    }
    let n = c.word_count();
    let mut line: heapless::String<24> = heapless::String::new();
    let _ = write!(line, "type all {n} words");
    menu::ask(ui.panel, "Key C's words", &line, "of key C to go on");
    if !menu::confirmed(ui) {
        return false;
    }
    let Some(m) = menu::read_phrase_of(ui, Some(n)) else {
        return false;
    };
    let matched = crate::keywork::run(|_| match catcard_callgate::pin::encode_bip39(m.entropy()) {
        Ok(mut typed) => {
            let ok = c.matches(&typed);
            typed.zeroize();
            ok
        }
        Err(_) => false,
    });
    drop(m);
    // SAFETY: foreground only, single core; nothing else touches the count.
    let fails = unsafe { &mut *core::ptr::addr_of_mut!(FAILS) };
    match engine::challenge(matched, fails) {
        engine::Challenge::Pass => true,
        engine::Challenge::Wrong { left } => {
            crate::catlog!("ccc: wrong key C words, {} left", left);
            let mut l: heapless::String<32> = heapless::String::new();
            let _ = write!(l, "{left} more before restart");
            menu::message(ui.panel, "Wrong words", "that is not key C", &l);
            menu::wait_for_any_key(ui);
            false
        }
        engine::Challenge::Shutdown => {
            crate::catlog!("ccc: third wrong key C phrase; restarting");
            menu::message(ui.panel, "Wrong words", "three times:", "restarting");
            use zeroize::Zeroize as _;
            login.zeroize();
            // SAFETY: nothing after this runs; the bootloader clears SRAM and restarts.
            unsafe { crate::gatecall::logout(gate, LogoutMode::LogoutAndReboot) }
        }
    }
}

/// Key C's record will not read: say so, and offer only to remove it.
#[inline(never)]
fn damaged(gate: &Callgate, login: &mut catcard_pin::Login, ui: &mut Ui<'_>) {
    let rows = [
        Row::title("Key C damaged"),
        Row::body(
            "The stored co-signing key will not read, so nothing is co-signed. Removing \
             it lets CCC be set up again.",
        )
        .wrapped(),
    ];
    let _ = menu::show_doc(ui, &rows, false, false);
    if menu::pick_row(ui, HEAD, "", &["Remove CCC"]) == Some(0) {
        remove(gate, login, ui, None);
    }
}

/// The CCCConfigMenu, in stock's order.
/// Source: hw-reference/menu-map-mk4-mk5-q1-v5.6.2.md §SP2 [C]
#[inline(never)]
fn config(gate: &Callgate, login: &mut catcard_pin::Login, ui: &mut Ui<'_>) {
    const IDENT: u32 = 1000;
    const VIOL: u32 = 1001;
    const POLICY: u32 = 1002;
    const EXPORT: u32 = 1003;
    const BUILD: u32 = 1004;
    const LOAD: u32 = 1005;
    const REMOVE: u32 = 1006;

    loop {
        let (xfp, viol) = match load(gate, login, ui) {
            Some((read, viol)) => match &*read {
                Read::Ccc(c) => (c.xfp, viol),
                Read::Absent | Read::Damaged => return,
            },
            None => return,
        };
        let related = crate::msimport::involving(gate, login, ui, xfp);
        let mut ident: heapless::String<24> = heapless::String::new();
        let _ = write!(ident, "[{}] Co-Signing", xfp_hex(xfp));

        let exit = {
            let mut rows: heapless::Vec<Row, { 10 + catcard_settings::wallets::MAX_WALLETS }> =
                heapless::Vec::new();
            let _ = rows.push(Row::title("Co-Sign (CCC)"));
            let _ = rows.push(Row::item(ident.as_str(), IDENT));
            if !viol.is_empty() {
                let _ = rows.push(Row::item("Last Violation", VIOL));
            }
            let _ = rows.push(Row::item("Spending Policy", POLICY));
            let _ = rows.push(Row::item("Export CCC XPUBs", EXPORT));
            let _ = rows.push(Row::body("Multisig Wallets").small());
            for (i, (label, _)) in related.iter().enumerate() {
                let _ = rows.push(Row::item(label.as_str(), i as u32));
            }
            let _ = rows.push(Row::item("Build 2-of-N", BUILD));
            let _ = rows.push(Row::item("Load Key C", LOAD));
            let _ = rows.push(Row::item("Remove CCC", REMOVE));
            menu::show_doc(ui, &rows, false, false)
        };

        match exit {
            DocExit::Selected(IDENT) => ident_screen(gate, login, ui),
            DocExit::Selected(VIOL) => {
                menu::message(ui.panel, "Last Violation", &viol, "");
                menu::wait_for_any_key(ui);
            }
            DocExit::Selected(POLICY) => {
                crate::policy::edit_policy(crate::policy::Target::Ccc, gate, login, ui)
            }
            DocExit::Selected(EXPORT) => export(gate, login, ui),
            DocExit::Selected(BUILD) => build(gate, login, ui),
            DocExit::Selected(LOAD) => {
                if load_temporary(gate, login, ui) {
                    return;
                }
            }
            DocExit::Selected(REMOVE) => {
                if remove(gate, login, ui, Some(xfp)) {
                    return;
                }
            }
            DocExit::Selected(i) if (i as usize) < related.len() => {
                crate::msimport::open(gate, login, ui, &related[i as usize].1);
            }
            _ => {
                // Leaving with key C still in the vault: the reminder stock gives.
                // Source: hw-reference/help-and-warning-screens.md §12 "Exit config with
                // key C still in Vault" [C]
                if crate::vault::holds(gate, login, ui, &xfp_hex(xfp)) {
                    menu::message(
                        ui.panel,
                        "Key C in the vault",
                        "delete it from the vault",
                        "or the policy is open",
                    );
                    menu::wait_for_any_key(ui);
                }
                return;
            }
        }
    }
}

/// `[XFP] Co-Signing`: which key C this is, and its policy at a glance.
fn ident_screen(gate: &Callgate, login: &mut catcard_pin::Login, ui: &mut Ui<'_>) {
    let Some((read, _)) = load(gate, login, ui) else {
        return;
    };
    let Read::Ccc(c) = &*read else {
        return;
    };
    let mut fp: heapless::String<32> = heapless::String::new();
    let _ = write!(fp, "Key C: {} ({} words)", xfp_hex(c.xfp), c.word_count());
    let mut cap: heapless::String<48> = heapless::String::new();
    if c.policy.magnitude == 0 {
        let _ = cap.push_str("No magnitude cap");
    } else {
        let whole = c.policy.magnitude / 100_000_000;
        let frac = c.policy.magnitude % 100_000_000;
        let _ = write!(cap, "At most {whole}.{frac:08} BTC per transaction");
    }
    let mut vel: heapless::String<48> = heapless::String::new();
    if c.policy.velocity == 0 {
        let _ = vel.push_str("No velocity limit");
    } else {
        let _ = write!(vel, "One spend per {} blocks", c.policy.velocity);
    }
    let mut wl: heapless::String<48> = heapless::String::new();
    let _ = write!(wl, "{} whitelisted address(es)", c.policy.whitelist.len());
    let rows = [
        Row::title("Co-Signing"),
        Row::body(&fp).wrapped(),
        Row::body(c.xpub.as_str()).small().wrapped(),
        Row::body(&cap).wrapped(),
        Row::body(&vel).wrapped(),
        Row::body(&wl).wrapped(),
        Row::body(if c.web2fa.is_empty() {
            ""
        } else {
            "Web 2FA was set on another firmware: this one never co-signs under it."
        })
        .small()
        .wrapped(),
    ];
    let _ = menu::show_doc(ui, &rows, false, false);
}

/// Export CCC XPUBs: the `ccxp` file for key C, as the Multisig screen's Export XPUB writes
/// this device's -- account asked, `ccxp-{C_XFP}.json`, to a card, the Virtual Disk or a
/// code.
/// Source: hw-reference/ccc-key-storage.md §2 [C]
fn export(gate: &Callgate, login: &mut catcard_pin::Login, ui: &mut Ui<'_>) {
    const H: &str = "Export CCC XPUBs";
    let Some(account) = menu::ask_number(ui, H, None, "account", "empty is account 0") else {
        return;
    };
    let Some((read, _)) = load(gate, login, ui) else {
        return;
    };
    let Read::Ccc(c) = &*read else {
        return;
    };
    let master = match master_of(c, ui.panel, H) {
        Ok(m) => m,
        Err(why) => return say(ui, why),
    };
    drop(read);
    crate::msimport::export_xpubs_of(ui, H, master, account);
}

/// Build 2-of-N: key A, key C and at least one other device's key, registered here.
/// Source: hw-reference/help-and-warning-screens.md §12 "Build 2-of-N with CCC" [C];
/// ccc-key-storage.md §5 [C]
fn build(gate: &Callgate, login: &mut catcard_pin::Login, ui: &mut Ui<'_>) {
    let rows = [
        Row::title("Build 2-of-N"),
        Row::body(
            "Makes a multisig wallet of this device (key A), key C, and at least one \
             other device (key B). Two signatures spend: A and C within the policy, or \
             either with B.",
        )
        .wrapped(),
        Row::body(
            "Have the other device's XPUB export (ccxp-*.json) ready on a card or as a \
             QR code.",
        )
        .wrapped(),
        Row::body("ENTER to go on; CANCEL to leave.").small(),
    ];
    if !matches!(menu::show_doc(ui, &rows, false, true), DocExit::Confirmed) {
        return;
    }
    let Some((read, _)) = load(gate, login, ui) else {
        return;
    };
    let Read::Ccc(c) = &*read else {
        return;
    };
    let master = match master_of(c, ui.panel, "Build 2-of-N") {
        Ok(m) => m,
        Err(why) => return say(ui, why),
    };
    drop(read);
    crate::msimport::create_cosign(gate, login, ui, &master);
}

/// Load Key C as a temporary seed: the whole device on key C until reboot. One way:
/// CCC's settings are not reachable from inside it.
/// Source: hw-reference/help-and-warning-screens.md §12 "Load key C as temporary seed" [C]
fn load_temporary(gate: &Callgate, login: &mut catcard_pin::Login, ui: &mut Ui<'_>) -> bool {
    let rows = [
        Row::title("Load Key C"),
        Row::body(
            "Works in key C as a temporary seed, with every feature, until reboot. Key C \
             then signs anything, with no policy.",
        )
        .wrapped(),
        Row::body("One way: CCC's settings cannot be reached from inside it. Reboot to come back.")
            .wrapped(),
        Row::body("ENTER to load; CANCEL to leave.").small(),
    ];
    if !matches!(menu::show_doc(ui, &rows, false, true), DocExit::Confirmed) {
        return false;
    }
    let Some((read, _)) = load(gate, login, ui) else {
        return false;
    };
    let Read::Ccc(c) = &*read else {
        return false;
    };
    let (ent, len) = entropy_of(c);
    drop(read);
    let was = crate::key::in_force();
    // Source: hw-reference/ccc-key-storage.md §1.3 "origin='Key C from CCC'" [C]
    let loaded = crate::key::set_temporary(&ent[..len], "Key C from CCC");
    drop(ent);
    if !loaded {
        say(ui, "that seed length is not usable");
        return false;
    }
    menu::announce_key(gate, login, ui, "Key C", was);
    true
}

/// Remove CCC: key C and its policy are forgotten. Then, as a second step that needs `4`,
/// the multisig wallets key C is in may go too.
/// Source: hw-reference/help-and-warning-screens.md §12 "Remove CCC" [C]
fn remove(
    gate: &Callgate,
    login: &mut catcard_pin::Login,
    ui: &mut Ui<'_>,
    xfp: Option<[u8; 4]>,
) -> bool {
    let rows = [
        Row::title("Remove CCC"),
        Row::body(
            "Key C and its spending policy will be forgotten. This device can then only \
             partially sign the co-signed wallets: spending needs key B.",
        )
        .wrapped(),
        Row::body("This cannot be undone here: only key C's words bring it back.").wrapped(),
        Row::body("ENTER removes key C; CANCEL keeps it.").small(),
    ];
    if !matches!(menu::show_doc(ui, &rows, false, true), DocExit::Confirmed) {
        return false;
    }
    let related = match xfp {
        Some(fp) => crate::msimport::involving(gate, login, ui, fp),
        None => heapless::Vec::new(),
    };
    let mut delete_wallets = false;
    if !related.is_empty() {
        let mut count: heapless::String<40> = heapless::String::new();
        let _ = write!(
            count,
            "Also delete the {} multisig wallet(s) key C is in?",
            related.len()
        );
        let rows = [
            Row::title("Related wallets"),
            Row::body(&count).wrapped(),
            Row::body(
                "Funds in them may be affected: without their setup files this device \
                 cannot sign for them again.",
            )
            .wrapped(),
            Row::body("ENTER to answer.").small(),
        ];
        let _ = menu::show_doc(ui, &rows, false, false);
        menu::message(
            ui.panel,
            "Related wallets",
            "4 deletes them",
            "CANCEL keeps them",
        );
        delete_wallets = menu::confirmed_by_digit(ui, 4);
    }
    // Key C first: a power cut between the two leaves wallets without a key C, which
    // sign partially, rather than a key C whose wallets are gone.
    if !write_value(gate, login, ui, (engine::KEY, "null")) {
        say(ui, "could not remove key C");
        return false;
    }
    let _ = write_value(gate, login, ui, (engine::VIOLATION_KEY, "\"\""));
    crate::catlog!("ccc: key C removed");
    if delete_wallets {
        for (_, sum) in &related {
            if let Err(why) = crate::msimport::remove(gate, login, ui, sum) {
                crate::catlog!("ccc: wallet {} not deleted: {}", sum.as_str(), why);
            }
        }
    }
    menu::message(ui.panel, "Remove CCC", "key C is gone", "");
    menu::wait_for_any_key(ui);
    true
}

fn say(ui: &mut Ui<'_>, what: &str) {
    menu::message(ui.panel, HEAD, what, "any key to go back");
    menu::wait_for_any_key(ui);
}
