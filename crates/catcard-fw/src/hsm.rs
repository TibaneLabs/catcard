//! HSM mode: unattended signing under a policy, over the ckcc USB protocol.
//!
//! The rules -- the policy file, every bound, how a transaction is judged, the velocity
//! clock, the users' codes -- are [`catcard_settings::hsm`] and
//! [`catcard_settings::hsmusers`], where a host tests them. This module is what the
//! firmware does with them:
//!
//! - **Starting.** A policy arrives over USB (`hsms` after an upload), or is the one
//!   stored at `/hsm-policy.json`, from the menu or -- with `boot_to_hsm` -- at login. It
//!   is validated against this device's users and multisig wallets, explained on screen,
//!   and approved by the person: a new policy twice, the second time by a digit picked at
//!   random. Source: hsm-policy-format.md §4, help-and-warning-screens.md §13 [C]
//! - **Running.** [`run`] replaces the menus with a status screen (approved, refused, what
//!   is left of the period, the local code being typed) and serves the ckcc jobs with
//!   nobody asked: `crate::ckcc`'s unattended path calls [`judge_tx`], [`approve_message`]
//!   and the `may_share_*` checks. Signing still goes through `crate::signtx`, so every
//!   check it makes -- the fee cap, the sighash rules, delta-mode spoiling -- still applies.
//! - **Leaving.** A power cycle, the host's `logo`, a hundred refusals (the device logs
//!   out), or -- only with `boot_to_hsm`, only in the first 60 seconds after power-on --
//!   the boot code typed on the keypad. Source: §3.1, §3.2, §4 [C]
//!
//! # Irreversible
//!
//! A policy with `boot_to_hsm` puts every login straight into HSM mode. The only way back
//! to the menus is its code, typed within a minute of power-on; a code that is not six
//! digits can never be typed, and such a device never leaves HSM mode again. A stored
//! boot-to-HSM policy that no longer loads stops the device at login rather than let it
//! run unprotected (§1.5). Both are said on the approval screens, asked about separately,
//! and never a default: they come only from a policy file someone wrote.
//!
//! # What this firmware does not do
//!
//! No Storage Locker (`gslr`), no microSD audit log, no `ATTEST` whitelists and no BIP-322
//! proofs in HSM mode -- see `catcard_settings::hsm` and `docs/USB.md`. Stock's
//! `supports_hsm` is false on the Q1; this firmware offers HSM mode there too, because the
//! Q1 speaks the same ckcc protocol.

use core::fmt::Write as _;

use catcard_callgate::Callgate;
use catcard_settings::hsm::{self as engine, Policy};
use catcard_settings::hsmusers::{self as users, User};
use catcard_settings::json::Doc;
use catcard_settings::store::{self, SCRATCH};
use catcard_ui::keypad::{Event, KEYS, Key};
use catcard_ui::scroll::Line;
use catcard_wallet::psbtview;
use outscript::psbt::Psbt;
use zeroize::Zeroize as _;

use crate::ckcc::Answer;
use crate::display;
use crate::menu;
use crate::ui::Ui;

const HEAD: &str = "HSM Mode";

/// Users one read holds: stock's maximum.
const USERS: usize = users::MAX_USERS;

// ---------------------------------------------------------------------------------------
// The clock
// ---------------------------------------------------------------------------------------

/// Milliseconds since boot, from the kernel's tick, carried past its 32-bit wrap.
/// The velocity period and the boot escape are both measured in uptime: the device has no
/// wall clock. Source: hsm-policy-format.md §3.4 [C]
static mut CLOCK: (u32, u64) = (0, 0);

fn now_ms() -> u64 {
    let t = catcard_kernel::ticks();
    // SAFETY: foreground only -- the UI task is the one caller -- and the pair is read and
    // written within this block.
    unsafe {
        let c = &mut *core::ptr::addr_of_mut!(CLOCK);
        let d = t.wrapping_sub(c.0);
        c.0 = t;
        c.1 += u64::from(d) * u64::from(catcard_kernel::TICK_MS);
        c.1
    }
}

fn now_s() -> u64 {
    now_ms() / 1000
}

// ---------------------------------------------------------------------------------------
// The state of HSM mode
// ---------------------------------------------------------------------------------------

/// HSM mode, while it runs. A few hundred bytes here; the policy text is on the heap.
struct Active {
    /// The canonical policy text.
    text: crate::heap::Block,
    len: usize,
    hash: heapless::String<64>,
    rt: engine::Runtime,
    /// The key behind `next_local_code`. Source: §3.2 [C]
    key: [u8; engine::LOCAL_KEY_LEN],
    /// Digits being typed on the status screen.
    typing: heapless::String<{ engine::LOCAL_PIN_LENGTH }>,
    /// The code typed and sent, waiting for the next PSBT.
    entered: Option<heapless::String<{ engine::LOCAL_PIN_LENGTH }>>,
    /// Users' authentications queued for the next PSBT ([`Pending`]).
    pending: Option<crate::heap::Block>,
    pending_len: usize,
    /// A hundredth refusal: log out once the reply has gone.
    shutdown: bool,
}

impl Drop for Active {
    fn drop(&mut self) {
        self.key.zeroize();
        // SAFETY: zeros keep both strings valid UTF-8.
        unsafe { self.typing.as_mut_vec().zeroize() };
        if let Some(e) = self.entered.as_mut() {
            // SAFETY: as above.
            unsafe { e.as_mut_vec().zeroize() };
        }
    }
}

/// HSM mode's state while it runs, in a heap block -- `None` the rest of the time.
///
/// It was a 416-byte resident static (in `.data`, since `None` of it is not all zeros),
/// under the Q1's boot stack for the device's whole life to serve a mode almost no device
/// ever enters. What it holds is the policy's counters, the local-code nonce the host is
/// shown anyway (`next_local_code`), and codes typed for the next PSBT; `Active`'s own drop
/// wipes the last two and the block is wiped again as it is freed.
static mut ACTIVE: Option<crate::heap::Owned<Active>> = None;

/// Run `f` on HSM mode's state, if it is running.
fn with<R>(f: impl FnOnce(&mut Active) -> R) -> Option<R> {
    // SAFETY: foreground only: HSM mode's state belongs to the UI task, and nothing holds
    // a borrow of it across this call.
    unsafe { (*core::ptr::addr_of_mut!(ACTIVE)).as_mut().map(|a| f(a)) }
}

/// The request whose PSBT is being judged: its SHA-256, for the local code and the
/// password users. Set by `crate::ckcc` around the signing flow.
static mut REQUEST: Option<[u8; 32]> = None;

/// Name the PSBT the next [`judge_tx`] is about, or clear it.
pub(crate) fn note_request(sha: Option<[u8; 32]>) {
    // SAFETY: foreground only; written and read on the UI task.
    unsafe { *core::ptr::addr_of_mut!(REQUEST) = sha };
}

fn request() -> Option<[u8; 32]> {
    // SAFETY: as above.
    unsafe { *core::ptr::addr_of!(REQUEST) }
}

/// Whether a policy file is on the flash, as last looked at: stock's
/// `hsm_policy_available`, which decides the menu rows.
static POLICY_STORED: core::sync::atomic::AtomicBool = core::sync::atomic::AtomicBool::new(false);

pub(crate) fn policy_stored() -> bool {
    POLICY_STORED.load(core::sync::atomic::Ordering::Relaxed)
}

fn look_for_policy() -> bool {
    // SAFETY: the region is mapped and readable; nothing is written.
    let found = unsafe { crate::settings::Files::mount_read_only() }
        .ok()
        .and_then(|mut f| f.file_len(engine::POLICY_PATH))
        .is_some();
    POLICY_STORED.store(found, core::sync::atomic::Ordering::Relaxed);
    found
}

/// Whether HSM mode can be offered: the stored wallet is in force (no passphrase, no
/// temporary seed) and no spending policy has the device hobbled.
/// Source: menu-map-mk4-mk5-q1-v5.6.2.md "`hsm_available()` -- has_real_secret()" [C]
pub(crate) fn available() -> bool {
    crate::key::is_root() && !crate::policy::hobbled()
}

// ---------------------------------------------------------------------------------------
// Users and wallets, as the policy is checked against them
// ---------------------------------------------------------------------------------------

/// Read this wallet's users out of its settings into `doc`.
fn read_users<'d>(
    gate: &Callgate,
    login: &mut catcard_pin::Login,
    panel: &mut display::Panel,
    doc: &'d mut [u8],
    out: &mut [User<'d>],
) -> Result<usize, &'static str> {
    let key = crate::settings::wallet_key(gate, login, panel, HEAD)?;
    // SAFETY: the region is mapped and readable; nothing is written.
    let mut files =
        unsafe { crate::settings::Files::mount_read_only() }.map_err(|_| "no settings store")?;
    let n = store::read(&mut files, &key, doc).unwrap_or(0);
    let doc: &'d [u8] = doc;
    let parsed = Doc::parse(&doc[..n]).unwrap_or_default();
    Ok(users::list(&parsed, out))
}

/// Write `list` back as the users.
fn save_users(
    gate: &Callgate,
    login: &mut catcard_pin::Login,
    ui: &mut Ui<'_>,
    list: &[User<'_>],
) -> Result<(), &'static str> {
    let (Some(mut text), Some(mut doc), Some(mut seal)) = (
        crate::heap::take(SCRATCH),
        crate::heap::take(SCRATCH),
        crate::heap::take(SCRATCH),
    ) else {
        return Err("not enough memory");
    };
    let n = users::render(list, text.bytes()).map_err(users::Error::text)?;
    let t = core::str::from_utf8(&text.bytes()[..n]).map_err(|_| "not text")?;
    crate::settings::save_wallet(
        gate,
        login,
        ui,
        HEAD,
        (users::KEY, t),
        doc.bytes(),
        seal.bytes(),
    )
}

const NO_USER: User<'static> = User {
    name: "",
    mode: 0,
    secret: "",
    counter: 0,
};

/// The registered multisig wallets' names that a rule could name: twenty characters or
/// fewer. Source: hsm-policy-format.md §1.4 `wallet` [C]
type WalletNames = heapless::Vec<(usize, heapless::String<{ 4 * engine::WALLET_LEN.1 }>), 8>;

fn wallet_names(
    gate: &Callgate,
    login: &mut catcard_pin::Login,
    panel: &mut display::Panel,
) -> WalletNames {
    let mut names = WalletNames::new();
    crate::msimport::for_each_name(gate, login, panel, |at, name| {
        let mut s = heapless::String::new();
        if s.push_str(name).is_ok() {
            let _ = names.push((at, s));
        }
    });
    names
}

/// This device, as a policy is checked against it.
struct Device<'a> {
    users: &'a [User<'a>],
    wallets: &'a WalletNames,
}

impl engine::Env for Device<'_> {
    fn user_exists(&self, name: &str) -> bool {
        self.users.iter().any(|u| u.name == name)
    }
    fn wallets_named(&self, name: &str) -> usize {
        self.wallets.iter().filter(|(_, n)| n == name).count()
    }
    fn address_ok(&self, addr: &str) -> bool {
        catcard_settings::policy::valid_address(addr)
    }
}

// ---------------------------------------------------------------------------------------
// Starting
// ---------------------------------------------------------------------------------------

/// Where the policy comes from.
enum Source {
    /// Just uploaded: `len` bytes in the staging memory.
    Upload(crate::ckcc::Store, u32),
    /// `/hsm-policy.json`.
    Stored,
}

/// Why HSM mode did not start, said once.
struct NotStarted(heapless::String<120>);

impl NotStarted {
    fn new(why: &str) -> Self {
        let mut s = heapless::String::new();
        for c in why.chars() {
            if s.push(c).is_err() {
                break;
            }
        }
        Self(s)
    }
}

/// A policy validated, in canonical form, ready to approve.
struct Checked {
    text: crate::heap::Block,
    len: usize,
    boots: bool,
}

/// Read and validate the policy, and write its canonical form. Source: §1, §4 [C]
///
/// The refusal carries its sentence by value: it is made once, on the way to a screen.
#[allow(clippy::result_large_err)]
fn check(
    gate: &Callgate,
    login: &mut catcard_pin::Login,
    ui: &mut Ui<'_>,
    source: Source,
) -> Result<Checked, (NotStarted, bool)> {
    let fail = |why: &str, cant_fail: bool| Err((NotStarted::new(why), cant_fail));
    if !catcard_kernel::running() {
        return fail("no clock on this build", false);
    }
    // The text: in the staging memory for an upload, read off the flash otherwise.
    let mut held: Option<crate::hostwallet::HostBuf> = None;
    let mut read: Option<crate::heap::Block> = None;
    let (at, len) = match source {
        Source::Upload(store, len) => match store.into_host_buf() {
            Some((b, at)) => {
                held = Some(b);
                (at, len as usize)
            }
            None => return fail("no memory for the policy", false),
        },
        Source::Stored => {
            // SAFETY: the region is mapped and readable; nothing is written.
            let mut files = match unsafe { crate::settings::Files::mount_read_only() } {
                Ok(f) => f,
                Err(_) => return fail("no settings store", false),
            };
            let Some(n) = files.file_len(engine::POLICY_PATH) else {
                return fail("no policy stored", false);
            };
            if n > engine::MAX_CANONICAL {
                return fail("stored policy too large", false);
            }
            let Some(mut b) = crate::heap::take(n.max(1)) else {
                return fail("not enough memory", false);
            };
            match files.read_file(engine::POLICY_PATH, b.bytes()) {
                Ok(Some(got)) if got == n => {}
                _ => return fail("the stored policy will not read", false),
            }
            read = Some(b);
            (0, n)
        }
    };
    let bytes: &[u8] = match (held.as_mut(), read.as_mut()) {
        (Some(h), _) => match h.bytes().get(at..at + len) {
            Some(b) => b,
            None => return fail("policy too large", false),
        },
        (None, Some(r)) => &r.bytes()[..len],
        (None, None) => return fail("no policy", false),
    };
    let Ok(text) = core::str::from_utf8(bytes) else {
        return fail("the policy is not text", false);
    };
    // Read before the full parse: a policy that asks to boot into HSM mode must not
    // fall back to the menus because it will not load. Source: §1.5 `cant_fail` [C]
    let cant_fail = Doc::parse(text.as_bytes())
        .ok()
        .and_then(|d| d.get("boot_to_hsm"))
        .is_some_and(|v| v != "null" && v != "false" && v != "\"\"");

    // Checked against this device.
    let Some(mut udoc) = crate::heap::take(SCRATCH) else {
        return fail("not enough memory", cant_fail);
    };
    let mut list = [NO_USER; USERS];
    let n = match read_users(gate, login, ui.panel, udoc.bytes(), &mut list) {
        Ok(n) => n,
        Err(why) => return fail(why, cant_fail),
    };
    let wallets = wallet_names(gate, login, ui.panel);
    let env = Device {
        users: &list[..n],
        wallets: &wallets,
    };
    let policy = match Policy::load(text, &env) {
        Ok(p) => p,
        Err(r) => {
            let mut why: heapless::String<120> = heapless::String::new();
            let _ = write!(why, "{r}");
            crate::catlog!("hsm: policy refused: {}", why.as_str());
            return fail(&why, cant_fail);
        }
    };
    let boots = policy.boots_to_hsm();
    // Canonical, then kept in a block of its own size. The canonical form is never much
    // longer than what it came from: what it adds per rule is the whitelist options and
    // `min_users` spelled out, well inside a hundred bytes.
    let room = (len + 100 * engine::MAX_RULES + 256).min(engine::MAX_CANONICAL);
    let Some(mut big) = crate::heap::take(room) else {
        return fail("not enough memory", cant_fail);
    };
    let clen = match policy.write(big.bytes()) {
        Ok(n) => n,
        Err(p) => return fail(p.text(), cant_fail),
    };
    drop(policy);
    drop(held);
    drop(read);
    let Some(mut kept) = crate::heap::take(clen.max(1)) else {
        return fail("not enough memory", cant_fail);
    };
    kept.bytes()[..clen].copy_from_slice(&big.bytes()[..clen]);
    drop(big);
    Ok(Checked {
        text: kept,
        len: clen,
        boots,
    })
}

/// The canonical text of a checked or running policy, as a view.
fn view(text: &mut crate::heap::Block, len: usize) -> Option<Policy<'_>> {
    let t = core::str::from_utf8(&text.bytes()[..len]).ok()?;
    Policy::load(t, &engine::Trusted).ok()
}

/// A formatter over a byte slice, for the explanation.
struct Out<'a> {
    buf: &'a mut [u8],
    n: usize,
}

impl core::fmt::Write for Out<'_> {
    fn write_str(&mut self, s: &str) -> core::fmt::Result {
        let end = self.n + s.len();
        let dst = self.buf.get_mut(self.n..end).ok_or(core::fmt::Error)?;
        dst.copy_from_slice(s.as_bytes());
        self.n = end;
        Ok(())
    }
}

/// The approval screens: the policy explained, then -- for a new one -- the last chance
/// with its hash and a digit picked at random, and for boot-to-HSM a question of its own.
/// Source: help-and-warning-screens.md §13 [C]; hsm-policy-format.md §4 "strict_escape"
/// digits `12346` [C]
fn approve(ui: &mut Ui<'_>, checked: &mut Checked, new_file: bool) -> bool {
    let Some(mut words) = crate::heap::take(8 * 1024) else {
        menu::message(ui.panel, HEAD, "not enough memory", "any key");
        menu::wait_for_any_key(ui);
        return false;
    };
    let (n, whole, boots, typeable) = {
        let Some(policy) = view(&mut checked.text, checked.len) else {
            return false;
        };
        let mut out = Out {
            buf: words.bytes(),
            n: 0,
        };
        let whole = policy.explain(&mut out).is_ok();
        let n = out.n;
        (n, whole, policy.boots_to_hsm(), policy.boot_code_typeable())
    };
    let text = core::str::from_utf8(&words.bytes()[..n]).unwrap_or("");
    let mut lines: heapless::Vec<Line<'_>, 64> = heapless::Vec::new();
    let _ = lines.push(Line::title(if new_file {
        "New HSM policy"
    } else {
        "HSM policy"
    }));
    // A policy is approved only as a whole: one whose explanation does not fit the screen's
    // budget is not offered, rather than approved on the rules that happened to fit.
    let mut fits = whole;
    for par in text.split('\n').filter(|p| !p.is_empty()) {
        if lines.push(Line::body(par).wrapped()).is_err() {
            fits = false;
            break;
        }
    }
    if !fits || lines.is_full() {
        drop(lines);
        menu::message(ui.panel, HEAD, "policy too long", "to show: not offered");
        menu::wait_for_any_key(ui);
        return false;
    }
    let _ = lines.push(
        Line::body("Entering HSM mode is one-way until power off. OK to enable, X to refuse.")
            .small()
            .wrapped(),
    );
    if !matches!(
        menu::show_doc(ui, &lines, false, true),
        menu::DocExit::Confirmed
    ) {
        return false;
    }
    drop(lines);
    drop(words);

    if boots {
        let body = if typeable {
            "Every login will go straight into HSM mode, with no menus. The only way back is \
             its boot code, typed within 60 seconds of power-on (OK sends it)."
        } else {
            "IRREVERSIBLE: every login will go straight into HSM mode, and its boot code is \
             not all digits, so it can never be typed. This device would NEVER leave HSM \
             mode again."
        };
        let lines = [
            Line::title("BOOT TO HSM"),
            Line::body(body).wrapped(),
            Line::body("Press 4 to accept, X to refuse.")
                .small()
                .wrapped(),
        ];
        draw_doc(ui, &lines);
        if !menu::confirmed_by_digit(ui, 4) {
            return false;
        }
    }

    if new_file {
        // Last chance: the hash, and a digit the person has to read to press.
        let hash = Policy::hash(&checked.text.bytes()[..checked.len]);
        const DIGITS: [u8; 5] = [1, 2, 3, 4, 6];
        let digit = DIGITS[ui.drbg.below(DIGITS.len() as u32).unwrap_or(0) as usize];
        let mut press: heapless::String<48> = heapless::String::new();
        let _ = write!(press, "Press {digit} to enable, X to refuse.");
        let lines = [
            Line::title("Last chance"),
            Line::body(
                "This NEW policy lets this device sign transactions that meet it with no \
                 further approval from anyone here.",
            )
            .wrapped(),
            Line::body("Policy hash:").small(),
            Line::body(hash.as_str()).small().wrapped(),
            Line::body(&press).wrapped(),
        ];
        draw_doc(ui, &lines);
        if !menu::confirmed_by_digit(ui, digit) {
            return false;
        }
    }
    true
}

/// Draw a still document, for a question answered by a key the caller waits for.
fn draw_doc(ui: &mut Ui<'_>, lines: &[Line<'_>]) {
    use catcard_ui::scroll::{ScrollView, render};
    let view = ScrollView::build(lines, display::SCREEN_W, display::SCREEN_H, display::FONTS);
    display::draw(ui.panel, |c| render(c, &view));
}

/// Put HSM mode in force. `new_file` writes the policy to the flash first; `precharge`
/// counts every velocity limit as spent (a boot-to-HSM start). Source: §4 `activate` [C]
fn activate(
    ui: &mut Ui<'_>,
    checked: Checked,
    new_file: bool,
    precharge: bool,
) -> Result<(), &'static str> {
    let Checked { mut text, len, .. } = checked;
    // The state's room first, so a heap that cannot spare it stops this before the
    // policy is written rather than leaving one stored that never ran.
    let room = crate::heap::room::<Active>().ok_or("not enough memory")?;
    if new_file {
        // SAFETY: foreground only; the caller holds the display while this runs.
        let mut files =
            unsafe { crate::settings::Files::mount() }.map_err(|_| "no settings store")?;
        files
            .write_file(engine::POLICY_PATH, &text.bytes()[..len])
            .map_err(|_| "could not save the policy")?;
        POLICY_STORED.store(true, core::sync::atomic::Ordering::Relaxed);
    }
    let mut key = [0u8; engine::LOCAL_KEY_LEN];
    ui.drbg.generate(&mut key).map_err(|_| "no randomness")?;
    let hash = Policy::hash(&text.bytes()[..len]);
    let now = now_s();
    let mut rt = engine::Runtime::new();
    if precharge && let Some(p) = view(&mut text, len) {
        rt.precharge(&p, now);
    }
    let active = Active {
        text,
        len,
        hash,
        rt,
        key,
        typing: heapless::String::new(),
        entered: None,
        pending: None,
        pending_len: 0,
        shutdown: false,
    };
    key.zeroize();
    // SAFETY: foreground only; nothing borrows the state across this write.
    unsafe { *core::ptr::addr_of_mut!(ACTIVE) = Some(room.fill(active)) };
    crate::ckcc::set_hsm_active(true);
    // The commands stay answered for as long as HSM mode runs, as stock sets `hsmcmd`
    // when it boots into it. Source: §4 [C]
    crate::ckcc::set_hsm_commands(true);
    // Unattended: an idle logout would end it. `[I]`: the reference does not say, but a
    // mode meant to run with nobody at the keypad cannot time out on the keypad.
    crate::idle::arm(None);
    crate::catlog!("hsm: ACTIVE ({} B policy)", len);
    Ok(())
}

/// Leave HSM mode for the menus: the boot escape. Source: §3.2 [C]
fn deactivate() {
    // SAFETY: foreground only.
    unsafe { *core::ptr::addr_of_mut!(ACTIVE) = None };
    crate::ckcc::set_hsm_active(false);
    crate::ckcc::set_hsm_commands(crate::prefs::current().hsm_commands);
    crate::idle::arm(crate::prefs::current().idle_minutes);
    crate::catlog!("hsm: left by the boot code");
}

fn say(ui: &mut Ui<'_>, a: &str, b: &str) {
    menu::message(ui.panel, HEAD, a, b);
    menu::wait_for_any_key(ui);
}

/// `hsms`: check the policy and answer the host; then, if it passed, ask the person.
pub(crate) fn start_from_host(
    gate: &Callgate,
    login: &mut catcard_pin::Login,
    ui: &mut Ui<'_>,
    ticket: u32,
    upload: Option<(crate::ckcc::Store, u32)>,
) {
    let done = |a: Answer| crate::usbtask::ck_finish(ticket, a);
    if !available() {
        return done(Answer::Failed("HSM needs the stored wallet in force"));
    }
    let new_file = upload.is_some();
    let source = match upload {
        Some((store, len)) => Source::Upload(store, len),
        None => Source::Stored,
    };
    let mut checked = match check(gate, login, ui, source) {
        Ok(c) => c,
        Err((why, _)) => {
            // Stock raises for a bad upload, so the host hears why. Source: §1.5 [C]
            let mut r = heapless::Vec::new();
            let mut tmp = [0u8; 160];
            let n = catcard_usb::ckcc::reply::err(&mut tmp, &why.0).unwrap_or(0);
            let _ = r.extend_from_slice(&tmp[..n]);
            return done(Answer::Reply(r));
        }
    };
    // Answered now: the person is asked next, and the host watches `hsts`.
    done(Answer::Okay);
    if !approve(ui, &mut checked, new_file) {
        say(ui, "not started", "the computer can see");
        return;
    }
    if let Err(why) = activate(ui, checked, new_file, false) {
        say(ui, "not started", why);
    }
}

/// Main menu → Start HSM Mode: the stored policy, explained and approved.
pub(crate) fn start_screen(gate: &Callgate, login: &mut catcard_pin::Login, ui: &mut Ui<'_>) {
    if !available() {
        return say(ui, "needs the stored wallet", "no passphrase in force");
    }
    let mut checked = match check(gate, login, ui, Source::Stored) {
        Ok(c) => c,
        Err((why, _)) => {
            menu::message(ui.panel, "Cannot start HSM", &why.0, "any key");
            menu::wait_for_any_key(ui);
            return;
        }
    };
    if crate::usbtask::usb_mode() != catcard_settings::prelogin::UsbMode::Ckcc {
        menu::ask(
            ui.panel,
            HEAD,
            "USB mode is not ckcc:",
            "no computer can use it. Go on?",
        );
        if !menu::confirmed(ui) {
            return;
        }
    }
    if !approve(ui, &mut checked, false) {
        return;
    }
    if let Err(why) = activate(ui, checked, false, false) {
        say(ui, "not started", why);
    }
}

/// At login, from the menu's start-up, when a policy is stored: stock offers it at every
/// boot. One with `boot_to_hsm` goes straight into HSM mode with no question, and one of
/// those that will not load stops the device rather than run unprotected; any other is
/// explained and offered, and refusing it leads to the menus. The HSM commands are
/// answered for the session either way, as stock sets `hsmcmd` here.
/// Source: hsm-policy-format.md §1.5, §4 "Boot" [C]
#[inline(never)]
pub(crate) fn at_login(gate: &Callgate, login: &mut catcard_pin::Login, ui: &mut Ui<'_>) {
    if !look_for_policy() || !crate::key::is_root() {
        return;
    }
    crate::ckcc::set_hsm_commands(true);
    match check(gate, login, ui, Source::Stored) {
        Ok(checked) if checked.boots => {
            if let Err(why) = activate(ui, checked, false, true) {
                fatal(gate, ui, why);
            }
        }
        Ok(mut checked) => {
            if approve(ui, &mut checked, false)
                && let Err(why) = activate(ui, checked, false, false)
            {
                say(ui, "not started", why);
            }
        }
        Err((why, true)) => fatal(gate, ui, &why.0),
        Err((why, false)) => {
            menu::message(ui.panel, "Cannot start HSM", &why.0, "any key");
            menu::wait_for_any_key(ui);
        }
    }
}

/// The stored policy must boot into HSM mode and cannot: say so and stop. The device logs
/// out with this on the screen; every login will end here again until the policy loads.
/// Source: §1.5 `show_fatal_error` + `show_logout(1)` [C]
fn fatal(gate: &Callgate, ui: &mut Ui<'_>, why: &str) -> ! {
    crate::catlog!("hsm: FATAL: boot-to-HSM policy will not start: {}", why);
    let lines = [
        Line::title("HSM policy failed"),
        Line::body("This device must start in HSM mode and its policy will not load:").wrapped(),
        Line::body(why).small().wrapped(),
        Line::body("Stopped rather than run without it.").wrapped(),
    ];
    draw_doc(ui, &lines);
    // SAFETY: nothing after this runs; the bootloader wipes SRAM and keeps the screen.
    unsafe { gate.logout(catcard_callgate::abi::LogoutMode::KeepScreen) }
}

// ---------------------------------------------------------------------------------------
// Running
// ---------------------------------------------------------------------------------------

/// HSM mode's screen, in place of the menus. Returns only when the boot code was typed.
/// Source: §3.5, help-and-warning-screens.md §13 "During HSM operation" [C]
#[inline(never)]
pub(crate) fn run(gate: &Callgate, login: &mut catcard_pin::Login, ui: &mut Ui<'_>) {
    let mut events = [Event::Pressed(Key::Cancel); KEYS];
    let mut keys: heapless::Vec<Key, { KEYS + 1 }> = heapless::Vec::new();
    let mut last = 0u64;
    let mut beat = 0u32;
    let mut dirty = true;
    loop {
        let _ = crate::usbtask::pump();
        crate::pinentry::pressed_keys(ui.pad, ui.matrix, ui.drbg, &mut events, &mut keys);
        for k in keys.iter() {
            let digit = match k {
                Key::Digit(d) => Some(*d),
                Key::Char(c) if c.is_ascii_digit() => Some(c - b'0'),
                _ => None,
            };
            let left = match (k, digit) {
                (_, Some(d)) => type_digit(d),
                (Key::Confirm, None) => submit(),
                (Key::Cancel, None) => {
                    let _ = with(|a| a.typing.clear());
                    false
                }
                _ => false,
            };
            dirty = true;
            if left {
                deactivate();
                return;
            }
        }
        // Nothing but the policy answers here: an image offered in CatCard mode, or a
        // CatCard-mode computer's question, is turned down.
        if crate::usbtask::pending().is_some() {
            crate::usbtask::decline();
        }
        if crate::usbtask::host_waiting()
            && let Some(t) = crate::usbtask::host_take()
        {
            crate::usbtask::host_finish(
                t.ticket,
                crate::hostwallet::Outcome::Refused("Not allowed in HSM mode"),
            );
        }
        if crate::ckcc::pending() {
            crate::ckcc::serve(gate, login, ui);
            dirty = true;
        }
        if with(|a| a.shutdown).unwrap_or(false) {
            crate::catlog!("hsm: {} refusals: logging out", engine::MAX_REFUSALS);
            // The refusal's reply leaves first, as a `logo`'s does.
            for _ in 0..50 {
                let _ = crate::usbtask::pump();
                // SAFETY: reads RCC; the clocks have been up since boot.
                unsafe { catcard_hal::dwt::delay_ms(10) };
            }
            let lines = [
                Line::title("HSM MODE"),
                Line::body("Too many refusals: logging out.").wrapped(),
            ];
            draw_doc(ui, &lines);
            login.zeroize();
            // SAFETY: nothing after this runs; the bootloader wipes SRAM.
            unsafe { gate.logout(catcard_callgate::abi::LogoutMode::Logout) }
        }
        let now = now_ms();
        if dirty || now.saturating_sub(last) >= 1000 {
            if now.saturating_sub(last) >= 1000 {
                beat = beat.wrapping_add(1);
            }
            draw_status(ui, beat);
            last = now;
            dirty = false;
        }
        display::idle(ui.panel);
    }
}

/// One digit typed. True when it completed the boot code in time.
fn type_digit(d: u8) -> bool {
    let full = with(|a| {
        if a.typing.len() >= engine::LOCAL_PIN_LENGTH {
            a.typing.clear();
        }
        let _ = a.typing.push((b'0' + d) as char);
        a.typing.len() == engine::LOCAL_PIN_LENGTH
    })
    .unwrap_or(false);
    full && submit()
}

/// The digits typed, sent: the boot escape in its first minute, the local code otherwise.
/// True when HSM mode is to be left. Source: §3.2 [C]
fn submit() -> bool {
    let uptime = now_s();
    with(|a| {
        if a.typing.is_empty() {
            return false;
        }
        let typed = core::mem::take(&mut a.typing);
        if uptime < engine::BOOT_LOCKOUT_S {
            let t = core::str::from_utf8(&a.text.bytes()[..a.len]).unwrap_or("");
            if let Ok(p) = Policy::load(t, &engine::Trusted) {
                let mut buf = [0u8; 4 * engine::BOOT_LEN.1];
                if p.boot_to_hsm(&mut buf) == Some(typed.as_str()) {
                    return true;
                }
            }
        }
        a.entered = Some(typed);
        false
    })
    .unwrap_or(false)
}

/// The status screen: approved, refused, the period, the code field, a heartbeat. Never an
/// amount. Source: §3.5 [C]
fn draw_status(ui: &mut Ui<'_>, beat: u32) {
    let now = now_s();
    let mut approved: heapless::String<24> = heapless::String::new();
    let mut refused: heapless::String<24> = heapless::String::new();
    let mut period: heapless::String<32> = heapless::String::new();
    let mut code: heapless::String<32> = heapless::String::new();
    let queued = with(|a| {
        let _ = write!(approved, "Approved: {}", a.rt.approvals % 10_000);
        let _ = write!(refused, "Refused: {}", a.rt.refusals);
        let t = core::str::from_utf8(&a.text.bytes()[..a.len]).unwrap_or("");
        let p = Policy::load(t, &engine::Trusted)
            .ok()
            .and_then(|p| p.period);
        let _ = period.push_str("Period left: ");
        match a.rt.time_left(p, now) {
            engine::TimeLeft::NoPeriod => {
                let _ = period.push_str("n/a");
            }
            engine::TimeLeft::NotStarted => {
                let _ = period.push_str("--");
            }
            engine::TimeLeft::Seconds(s) if s >= 3600 => {
                let _ = write!(period, "{}h {}m", s / 3600, (s % 3600) / 60);
            }
            engine::TimeLeft::Seconds(s) => {
                let _ = write!(period, "{}m {}s", s / 60, s % 60);
            }
        }
        let _ = code.push_str("Code: ");
        let _ = code.push_str(&a.typing);
        for _ in a.typing.len()..engine::LOCAL_PIN_LENGTH {
            let _ = code.push('_');
        }
        a.entered.is_some()
    })
    .unwrap_or(false);
    // A sweep back and forth, so a frozen device is told from a quiet one.
    const W: u32 = 11;
    let pos = {
        let p = beat % (2 * (W - 1));
        if p < W { p } else { 2 * (W - 1) - p }
    };
    let mut sweep: heapless::String<{ W as usize }> = heapless::String::new();
    for i in 0..W {
        let _ = sweep.push(if i == pos { 'o' } else { '.' });
    }
    let ckcc = crate::usbtask::usb_mode() == catcard_settings::prelogin::UsbMode::Ckcc;
    let mut lines: heapless::Vec<Line<'_>, 8> = heapless::Vec::new();
    let _ = lines.push(Line::title("HSM MODE"));
    let _ = lines.push(Line::body(&approved));
    let _ = lines.push(Line::body(&refused));
    let _ = lines.push(Line::body(&period));
    let _ = lines.push(Line::body(&code));
    if queued {
        let _ = lines.push(Line::body("code sent for the next").small());
    }
    if !ckcc {
        let _ = lines.push(Line::body("USB mode is not ckcc").small());
    }
    let _ = lines.push(Line::body(&sweep).centered());
    draw_doc(ui, &lines);
}

// ---------------------------------------------------------------------------------------
// Judging
// ---------------------------------------------------------------------------------------

/// A refusal outside the rules (a BIP-322 proof): counted and kept, as stock's `refuse`.
pub(crate) fn refuse_request(why: &str) {
    crate::catlog!("hsm: REFUSED: {}", why);
    let _ = with(|a| a.shutdown |= a.rt.refuse(why));
}

/// Whether a message may be signed at `path`, counted either way.
/// Source: §3.1 `approve_msg_sign`, §1.3 `msg_paths` [C]
pub(crate) fn approve_message(path: &[u32]) -> bool {
    with(|a| {
        let t = core::str::from_utf8(&a.text.bytes()[..a.len]).unwrap_or("");
        let ok = Policy::load(t, &engine::Trusted).is_ok_and(|p| p.msg_paths.allows(path));
        if ok {
            a.rt.approve();
        } else {
            a.shutdown |= a.rt.refuse("message signing not allowed on that path");
        }
        ok
    })
    .unwrap_or(false)
}

fn paths_allow(pick: impl FnOnce(&Policy<'_>) -> bool) -> bool {
    with(|a| {
        let t = core::str::from_utf8(&a.text.bytes()[..a.len]).unwrap_or("");
        Policy::load(t, &engine::Trusted).is_ok_and(|p| pick(&p))
    })
    .unwrap_or(false)
}

/// `xpub`: the master always, anything else only as `share_xpubs` allows. Source: §1.3 [C]
pub(crate) fn may_share_xpub(path: &[u32]) -> bool {
    path.is_empty() || paths_allow(|p| p.share_xpubs.allows(path))
}

/// `show`: only as `share_addrs` allows. Source: §1.3 [C]
pub(crate) fn may_share_address(path: &[u32]) -> bool {
    paths_allow(|p| p.share_addrs.allows(path))
}

/// `p2sh`: only with `p2sh` in `share_addrs`. Source: §1.3 [C]
pub(crate) fn may_share_p2sh() -> bool {
    paths_allow(|p| p.share_addrs.has_literal("p2sh"))
}

/// Judge a transaction the review has summarised: the local code, the warnings, the users,
/// then the rules. `Err` when refused -- counted, and kept as the last refusal.
/// Source: hsm-policy-format.md §3.1 [C]
pub(crate) fn judge_tx(
    gate: &Callgate,
    login: &mut catcard_pin::Login,
    ui: &mut Ui<'_>,
    psbt: &Psbt<'_>,
    owner: &psbtview::Owner<'_>,
    summary: &psbtview::Summary,
) -> Result<(), ()> {
    let mut why: engine::Reasons = engine::Reasons::new();
    let verdict = judge_inner(gate, login, ui, psbt, owner, summary, &mut why);
    match verdict {
        Ok(rule) => {
            crate::catlog!("hsm: approved by rule {}", rule + 1);
            let _ = with(|a| a.rt.approve());
            Ok(())
        }
        Err(()) => {
            refuse_request(&why);
            Err(())
        }
    }
}

#[allow(clippy::too_many_arguments)]
fn judge_inner(
    gate: &Callgate,
    login: &mut catcard_pin::Login,
    ui: &mut Ui<'_>,
    psbt: &Psbt<'_>,
    owner: &psbtview::Owner<'_>,
    summary: &psbtview::Summary,
    why: &mut engine::Reasons,
) -> Result<usize, ()> {
    let mut fail = |w: &str| {
        why.clear();
        let _ = why.push_str(w);
        Err(())
    };
    let Some(sha) = request() else {
        return fail("no request to judge");
    };
    // The local code is used up by every PSBT, whatever else happens. Source: §3.1 step 2
    let mut fresh = [0u8; engine::LOCAL_KEY_LEN];
    if ui.drbg.generate(&mut fresh).is_err() {
        return fail("no randomness");
    }
    let local_ok = with(|a| {
        let typed = a.entered.take();
        let ok = typed
            .as_deref()
            .is_some_and(|t| engine::local_code_matches(t, &a.key, &sha));
        a.key = fresh;
        ok
    })
    .unwrap_or(false);
    fresh.zeroize();
    // So is the queue of users' codes: each was sent for this PSBT or is stale now.
    // Source: §2.4 "consumed atomically" [C]
    let pending = with(|a| {
        let len = core::mem::take(&mut a.pending_len);
        a.pending.take().map(|b| (b, len))
    })
    .flatten();

    // The policy, copied out for the judging: the flows below take the heap too.
    let Some((mut text, len)) = with(|a| {
        let mut b = crate::heap::take(a.len.max(1))?;
        b.bytes()[..a.len].copy_from_slice(&a.text.bytes()[..a.len]);
        Some((b, a.len))
    })
    .flatten() else {
        return fail("not enough memory");
    };
    let Some(policy) = view(&mut text, len) else {
        return fail("policy unreadable");
    };

    // Every output, for the whitelists and the patterns. Each page derives change keys.
    let mut judge = engine::Judge::new(&policy);
    let network = crate::prefs::network();
    // The inputs' accounts, wallets and highest index, as the review's own pages use them:
    // change far past the inputs is flagged only with the index known.
    let spent = summary.spent();
    let mut page = [psbtview::Destination::BLANK; 4];
    let mut start = 0usize;
    let mut own_outputs = 0usize;
    let mut unusual = 0usize;
    loop {
        let got = crate::keywork::run(|kw| {
            psbtview::destinations_with(psbt, owner, network, &spent, start, &mut page, kw)
        });
        for d in &page[..got] {
            judge.output(d.amount, d.change, d.address());
            if d.change {
                own_outputs += 1;
                if d.unusual.is_some() {
                    unusual += 1;
                }
            }
        }
        if got < page.len() {
            break;
        }
        start += got;
    }

    // Warnings: what the review would have put on the screen. Source: §3.1 step 3 [C];
    // which of this firmware's findings count as warnings is `[I]` -- see docs/USB.md.
    #[allow(unused_mut)]
    let mut warnings = usize::from(summary.fee_warn)
        + usize::from(!summary.fee_known)
        + usize::from(summary.odd_total > 0)
        + unusual;
    #[cfg(feature = "multichain")]
    {
        warnings += usize::from(summary.opted_in);
    }
    if warnings > 0 && !policy.warnings_ok {
        why.clear();
        let _ = write!(why, "has {warnings} warning(s)");
        return Err(());
    }
    // Ours, whatever `warnings_ok` says: an unknown fee lets our coins leave as fee with
    // no rule seeing them, and nobody is here to look at the number.
    if !summary.fee_known {
        return fail("fee unknown: an input's amount is not proven");
    }

    // The users queued for this PSBT, all of them checked. Source: §2.4 [C]
    let mut udoc = None;
    let mut list = [NO_USER; USERS];
    let mut n = 0;
    let mut passed = 0u32;
    if let Some((mut queue, qlen)) = pending
        && qlen > 0
    {
        let Some(block) = udoc.insert(crate::heap::take(SCRATCH)).as_mut() else {
            return fail("not enough memory");
        };
        n = match read_users(gate, login, ui.panel, block.bytes(), &mut list) {
            Ok(n) => n,
            Err(w) => return fail(w),
        };
        let checked = check_pending(gate, login, ui, &sha, &queue.bytes()[..qlen], &list[..n]);
        queue.bytes().zeroize();
        match checked {
            Ok(mask) => passed = mask,
            Err(w) => {
                why.clear();
                let _ = why.push_str(&w);
                return Err(());
            }
        }
    }
    let given: heapless::Vec<&str, USERS> = list[..n]
        .iter()
        .enumerate()
        .filter(|(i, _)| passed & (1 << i) != 0)
        .map(|(_, u)| u.name)
        .collect();

    // Which wallet spends.
    let mut multi: heapless::String<{ 4 * engine::WALLET_LEN.1 }> = heapless::String::new();
    let spender = if summary.wallet_count == 0 && summary.single_sig_ours > 0 {
        engine::Spender::Single
    } else if summary.wallet_count == 1 && summary.single_sig_ours == 0 {
        let at = summary.wallets[0];
        for (i, n) in wallet_names(gate, login, ui.panel) {
            if i == at {
                multi = n;
            }
        }
        if multi.is_empty() {
            engine::Spender::Other
        } else {
            engine::Spender::Multi(&multi)
        }
    } else {
        engine::Spender::Other
    };

    let facts = engine::Facts {
        inputs: summary.inputs,
        outputs: summary.outputs,
        own_inputs: summary.ours,
        own_outputs,
        own_in: summary.own_in,
        own_out: summary.change,
        // What leaves this wallet: paid out, or -- when that is larger -- spent by our
        // inputs and not come back, which counts our share of the fee. Stock charges the
        // outputs alone; this is never less. `[I]`
        sending: summary
            .sending
            .max(summary.own_in.saturating_sub(summary.change)),
        spender,
        users: &given,
        local_ok,
    };
    let now = now_s();
    match with(|a| judge.verdict(&facts, &mut a.rt, now, why)).flatten() {
        Some(rule) => Ok(rule),
        None => Err(()),
    }
}

// ---------------------------------------------------------------------------------------
// Users' authentications
// ---------------------------------------------------------------------------------------

/// One queued `user` request, as bytes in the pending block:
/// `[name_len][name][token_len][token][totp_time u32 LE]`.
const ENTRY_MAX: usize = 1 + crate::ckcc::NAME_BYTES + 1 + 32 + 4;

/// Walk the queued entries.
fn each_pending(buf: &[u8], mut f: impl FnMut(&str, &[u8], u32)) {
    let mut at = 0;
    while at < buf.len() {
        let nl = usize::from(buf[at]);
        let Some(name) = buf.get(at + 1..at + 1 + nl) else {
            return;
        };
        let tl_at = at + 1 + nl;
        let Some(&tl) = buf.get(tl_at) else { return };
        let tl = usize::from(tl);
        let Some(token) = buf.get(tl_at + 1..tl_at + 1 + tl) else {
            return;
        };
        let t_at = tl_at + 1 + tl;
        let Some(time) = buf.get(t_at..t_at + 4) else {
            return;
        };
        let time = u32::from_le_bytes([time[0], time[1], time[2], time[3]]);
        f(core::str::from_utf8(name).unwrap_or(""), token, time);
        at = t_at + 4;
    }
}

/// `user` in HSM mode: queued for the next PSBT, replacing any earlier one for the same
/// name. Source: §2.4 `pending_auth` [C]
fn queue_auth(totp_time: u32, name: &str, token: &[u8]) -> Answer {
    with(|a| {
        if a.pending.is_none() {
            a.pending = crate::heap::take(USERS * ENTRY_MAX);
            a.pending_len = 0;
        }
        let Some(block) = a.pending.as_mut() else {
            return Answer::Failed("Out of RAM");
        };
        let buf = block.bytes();
        // Rebuilt without this name's earlier entry, in a block of its own: three
        // kilobytes is too much for the stack under the signing flow.
        let Some(mut fresh) = crate::heap::take(USERS * ENTRY_MAX) else {
            return Answer::Failed("Out of RAM");
        };
        let kept = fresh.bytes();
        let mut k = 0;
        let mut count = 0;
        each_pending(&buf[..a.pending_len], |n, t, time| {
            if n != name && k + 2 + n.len() + t.len() + 4 <= kept.len() {
                kept[k] = n.len() as u8;
                kept[k + 1..k + 1 + n.len()].copy_from_slice(n.as_bytes());
                let at = k + 1 + n.len();
                kept[at] = t.len() as u8;
                kept[at + 1..at + 1 + t.len()].copy_from_slice(t);
                kept[at + 1 + t.len()..at + 5 + t.len()].copy_from_slice(&time.to_le_bytes());
                k = at + 5 + t.len();
                count += 1;
            }
        });
        if count >= USERS {
            return Answer::Failed("Too many users queued");
        }
        let need = 2 + name.len() + token.len() + 4;
        if k + need > kept.len() {
            return Answer::Failed("Too many users queued");
        }
        kept[k] = name.len() as u8;
        kept[k + 1..k + 1 + name.len()].copy_from_slice(name.as_bytes());
        let at = k + 1 + name.len();
        kept[at] = token.len() as u8;
        kept[at + 1..at + 1 + token.len()].copy_from_slice(token);
        kept[at + 1 + token.len()..at + 5 + token.len()].copy_from_slice(&totp_time.to_le_bytes());
        k = at + 5 + token.len();
        // The old queue goes back to the heap wiped.
        a.pending = Some(fresh);
        a.pending_len = k;
        Answer::Okay
    })
    .unwrap_or(Answer::Failed("HSM not active"))
}

/// Check every queued authentication against `list` and record the counters they used.
/// Any that fails refuses the transaction. The users that passed come back as bits of
/// their places in `list`. Source: §2.3, §2.4 [C]
fn check_pending(
    gate: &Callgate,
    login: &mut catcard_pin::Login,
    ui: &mut Ui<'_>,
    sha: &[u8; 32],
    queue: &[u8],
    list: &[User<'_>],
) -> Result<u32, heapless::String<80>> {
    let text = |s: &str| {
        let mut t = heapless::String::new();
        for c in s.chars() {
            if t.push(c).is_err() {
                break;
            }
        }
        t
    };
    let mut updated = [NO_USER; USERS];
    let n = list.len().min(USERS);
    updated[..n].copy_from_slice(&list[..n]);
    let mut passed = 0u32;
    let mut problem: Option<heapless::String<80>> = None;
    each_pending(queue, |name, token, time| {
        if problem.is_some() {
            return;
        }
        let Some(at) = list[..n].iter().position(|u| u.name == name) else {
            let mut t = text(name);
            let _ = t.push_str(": unknown user");
            problem = Some(t);
            return;
        };
        match users::check(&list[at], token, time, Some(sha)) {
            Ok(counter) => {
                updated[at].counter = counter;
                passed |= 1 << at;
            }
            Err(r) => {
                let mut t = text(name);
                let _ = t.push_str(": ");
                let _ = t.push_str(r.text());
                problem = Some(t);
            }
        }
    });
    // A code used is used, whatever the rules then say -- and whatever another user's
    // code said: recorded before either refuses.
    if updated[..n] != list[..n]
        && save_users(gate, login, ui, &updated[..n]).is_err()
        && problem.is_none()
    {
        return Err(text("could not record the codes used"));
    }
    if let Some(p) = problem {
        return Err(p);
    }
    Ok(passed)
}

/// `user`: queued in HSM mode; outside it, checked at once and answered with what stock
/// would say -- nothing when it passes. Source: usb-ckcc-protocol.md §4.2 [C]
pub(crate) fn user_auth(
    gate: &Callgate,
    login: &mut catcard_pin::Login,
    ui: &mut Ui<'_>,
    totp_time: u32,
    name: &str,
    token: &crate::ckcc::Token,
) -> Answer {
    if crate::ckcc::hsm_active() {
        return queue_auth(totp_time, name, token.bytes());
    }
    let Some(mut udoc) = crate::heap::take(SCRATCH) else {
        return Answer::Failed("Out of RAM");
    };
    let mut list = [NO_USER; USERS];
    let n = match read_users(gate, login, ui.panel, udoc.bytes(), &mut list) {
        Ok(n) => n,
        Err(why) => return Answer::Failed(why),
    };
    // A dry run: the counter is not moved.
    let said = match list[..n].iter().find(|u| u.name == name) {
        None => users::Refused::UnknownUser.text(),
        Some(u) => match users::check(u, token.bytes(), totp_time, None) {
            Ok(_) => "",
            Err(r) => r.text(),
        },
    };
    Answer::reply(|b| catcard_usb::ckcc::reply::asci(b, said.as_bytes()))
}

/// `nwur`: make a user, answer with what the host is to show, then -- when asked -- show
/// the enrolment QR. Source: hsm-policy-format.md §2, usb-ckcc-protocol.md §4.2 [C]
pub(crate) fn new_user(
    gate: &Callgate,
    login: &mut catcard_pin::Login,
    ui: &mut Ui<'_>,
    ticket: u32,
    raw_mode: u8,
    name: &str,
    secret: Option<users::Secret>,
) {
    let done = |a: Answer| crate::usbtask::ck_finish(ticket, a);
    let show_qr = raw_mode & users::AUTH_SHOW_QR != 0;
    let mode = raw_mode & !users::AUTH_SHOW_QR;
    if let Err(e) = users::check_name(name) {
        return done(Answer::Failed(e.text()));
    }
    if !matches!(mode, users::AUTH_TOTP | users::AUTH_HOTP | users::AUTH_HMAC) {
        return done(Answer::Failed(users::Error::BadMode.text()));
    }
    // What is stored, and what the host is told.
    let mut told: heapless::String<{ users::MAX_SECRET_B32 }> = heapless::String::new();
    let stored = match secret {
        Some(s) => {
            if !users::secret_len_ok(mode, s.bytes().len()) {
                return done(Answer::Failed(users::Error::BadSecret.text()));
            }
            if mode != users::AUTH_HMAC {
                told = s.base32();
            }
            s
        }
        None => {
            let mut raw = [0u8; users::PICKED_OTP_LEN];
            if ui.drbg.generate(&mut raw).is_err() {
                return done(Answer::Failed("no randomness"));
            }
            let picked = users::Secret::new(&raw);
            raw.zeroize();
            let Some(picked) = picked else {
                return done(Answer::Failed("no randomness"));
            };
            if mode == users::AUTH_HMAC {
                // A password for a person to type: the picked bytes in base32, sixteen
                // characters. `[I]`: the reference does not say how stock picks one; any
                // text works, since the host hashes whatever it is given the same way.
                told = picked.base32();
                users::password_key(told.as_bytes(), crate::session::serial())
            } else {
                told = picked.base32();
                picked
            }
        }
    };
    let b32 = stored.base32();
    let Some(mut udoc) = crate::heap::take(SCRATCH) else {
        return done(Answer::Failed("Out of RAM"));
    };
    let mut list = [NO_USER; USERS];
    let n = match read_users(gate, login, ui.panel, udoc.bytes(), &mut list) {
        Ok(n) => n,
        Err(why) => return done(Answer::Failed(why)),
    };
    let mut more = [NO_USER; USERS + 1];
    let new = User {
        name,
        mode,
        secret: &b32,
        counter: 0,
    };
    let m = match users::with_added(&list[..n], new, &mut more) {
        Ok(m) => m,
        Err(e) => return done(Answer::Failed(e.text())),
    };
    let saved = save_users(gate, login, ui, &more[..m]);
    let kind = new.kind();
    drop(udoc);
    let mut b32 = b32;
    // SAFETY: zeros keep the string valid UTF-8.
    unsafe { b32.as_mut_vec().zeroize() };
    if let Err(why) = saved {
        // SAFETY: as above.
        unsafe { told.as_mut_vec().zeroize() };
        return done(Answer::Failed(why));
    }
    crate::catlog!("hsm: user {} made ({})", name, kind);
    done(Answer::reply(|b| {
        catcard_usb::ckcc::reply::asci(b, told.as_bytes())
    }));
    if show_qr {
        let mut uri: heapless::String<200> = heapless::String::new();
        let payload: &str = if mode == users::AUTH_HMAC {
            told.as_str()
        } else {
            let mut issuer: heapless::String<40> = heapless::String::new();
            let _ = write!(issuer, "CatCard {}", crate::session::serial());
            let _ = users::otpauth_uri(mode, name, &told, &issuer, &mut uri);
            uri.as_str()
        };
        menu::message(ui.panel, "New user", name, "scan the code next");
        menu::wait_for_any_key(ui);
        menu::qr_screen(ui, payload, "");
        // SAFETY: zeros keep the strings valid UTF-8.
        unsafe { uri.as_mut_vec().zeroize() };
    }
    // SAFETY: as above.
    unsafe { told.as_mut_vec().zeroize() };
}

/// `rmur`: delete a user. Not in HSM mode (the USB gate refuses it first). Answered the
/// same whether the user was there: the host says "deleted, if it was there".
pub(crate) fn remove_user(
    gate: &Callgate,
    login: &mut catcard_pin::Login,
    ui: &mut Ui<'_>,
    name: &str,
) -> Answer {
    let Some(mut udoc) = crate::heap::take(SCRATCH) else {
        return Answer::Failed("Out of RAM");
    };
    let mut list = [NO_USER; USERS];
    let n = match read_users(gate, login, ui.panel, udoc.bytes(), &mut list) {
        Ok(n) => n,
        Err(why) => return Answer::Failed(why),
    };
    let mut left = [NO_USER; USERS];
    match users::without(&list[..n], name, &mut left) {
        Ok(m) => match save_users(gate, login, ui, &left[..m]) {
            Ok(()) => {
                crate::catlog!("hsm: user {} deleted by the computer", name);
                Answer::Okay
            }
            Err(why) => Answer::Failed(why),
        },
        Err(_) => Answer::Okay,
    }
}

/// `hsts`: the status report as JSON. Source: hsm-policy-format.md §3.5 [C]
pub(crate) fn status(gate: &Callgate, login: &mut catcard_pin::Login, ui: &mut Ui<'_>) -> Answer {
    // Room in one reply: the largest message less the opcode and a v3 tag.
    const ROOM: usize = catcard_usb::ckcc::MAX_MSG_LEN - 4;
    let Some(mut out) = crate::heap::take(ROOM) else {
        return Answer::Failed("Out of RAM");
    };
    let stored = if crate::ckcc::hsm_active() {
        true
    } else {
        look_for_policy()
    };
    // The users' names, unless the policy keeps them private.
    let private = with(|a| {
        let t = core::str::from_utf8(&a.text.bytes()[..a.len]).unwrap_or("");
        Policy::load(t, &engine::Trusted).is_ok_and(|p| p.priv_over_ux)
    })
    .unwrap_or(true);
    let mut udoc = if private {
        None
    } else {
        crate::heap::take(SCRATCH)
    };
    let mut list = [NO_USER; USERS];
    let n = match udoc.as_mut() {
        Some(d) => read_users(gate, login, ui.panel, d.bytes(), &mut list).unwrap_or(0),
        None => 0,
    };
    let names: heapless::Vec<&str, USERS> = list[..n].iter().map(|u| u.name).collect();
    let uptime = now_s();
    let written = with(|a| {
        let Active {
            text,
            len,
            hash,
            rt,
            key,
            pending,
            pending_len,
            ..
        } = a;
        let t = core::str::from_utf8(&text.bytes()[..*len]).unwrap_or("");
        let policy = Policy::load(t, &engine::Trusted).ok()?;
        let mut queued = 0;
        if let Some(p) = pending.as_mut() {
            each_pending(&p.bytes()[..*pending_len], |_, _, _| queued += 1);
        }
        let time_left = rt.time_left(policy.period, uptime);
        let next = engine::local_key_text(key);
        let mut max = 1024;
        loop {
            let st = engine::Status {
                active: true,
                policy_available: true,
                running: Some(engine::Running {
                    policy: &policy,
                    hash,
                    runtime: rt,
                    next_local_code: &next,
                    uptime,
                    time_left,
                    users: &names,
                    pending_auth: queued,
                    summary_max: max,
                }),
            };
            match st.write(out.bytes()) {
                Ok(n) => return Some(n),
                Err(_) if max > 0 => max /= 2,
                Err(_) => return None,
            }
        }
    });
    let n = match written {
        Some(Some(n)) => n,
        // Running, and even the counters would not fit: said, never reported as idle.
        Some(None) => return Answer::Failed("status too long"),
        None => {
            let st = engine::Status {
                active: false,
                policy_available: stored,
                running: None,
            };
            match st.write(out.bytes()) {
                Ok(n) => n,
                Err(_) => return Answer::Failed("status too long"),
            }
        }
    };
    Answer::Asci(out, n)
}

// ---------------------------------------------------------------------------------------
// Menus
// ---------------------------------------------------------------------------------------

/// Settings → Spending Policy → HSM Mode: whether the HSM commands are answered over USB
/// (stock's `hsmcmd`). Off by default. Source: menu-map-mk4-mk5-q1-v5.6.2.md §ADV [C]
pub(crate) fn commands_screen(gate: &Callgate, login: &mut catcard_pin::Login, ui: &mut Ui<'_>) {
    const H: &str = "HSM Mode";
    let now = crate::prefs::current();
    let note = if now.hsm_commands {
        "now enabled"
    } else {
        "now off (default)"
    };
    let Some(row) = menu::pick_row(ui, H, note, &["Default Off", "Enable"]) else {
        return;
    };
    let on = row == 1;
    if on == now.hsm_commands {
        return;
    }
    if on {
        menu::ask(
            ui.panel,
            H,
            "lets a computer set up",
            "users and HSM policies",
        );
        if !menu::confirmed(ui) {
            return;
        }
    }
    let next = crate::prefs::Prefs {
        hsm_commands: on,
        ..now
    };
    let raw = if on { "\"1\"" } else { "\"0\"" };
    if !crate::prefs::save(
        gate,
        login,
        ui,
        H,
        (catcard_settings::prefs::HSM_COMMANDS, raw),
        next,
    ) {
        say(ui, "not saved", "any key");
    }
}

/// Settings → Spending Policy → User Management: the users, and deleting one.
/// Source: menu-map-mk4-mk5-q1-v5.6.2.md §U, help-and-warning-screens.md "Users" [C]
pub(crate) fn users_screen(gate: &Callgate, login: &mut catcard_pin::Login, ui: &mut Ui<'_>) {
    const H: &str = "User Management";
    loop {
        // The list is read, shown and let go before anything is changed: deleting takes
        // settings buffers of its own.
        let (name, kind) = {
            let Some(mut udoc) = crate::heap::take(SCRATCH) else {
                return say(ui, "not enough memory", "any key");
            };
            let mut list = [NO_USER; USERS];
            let n = match read_users(gate, login, ui.panel, udoc.bytes(), &mut list) {
                Ok(n) => n,
                Err(why) => return say(ui, why, "any key"),
            };
            if n == 0 {
                let lines = [
                    Line::title(H),
                    Line::body("(no users yet)"),
                    Line::body(
                        "Users and their secrets are made by a computer over USB: ckcc user.",
                    )
                    .small()
                    .wrapped(),
                ];
                let _ = menu::show_doc(ui, &lines, false, false);
                return;
            }
            let mut note: heapless::String<24> = heapless::String::new();
            let _ = write!(note, "{n} user(s):");
            let rows: heapless::Vec<&str, USERS> = list[..n].iter().map(|u| u.name).collect();
            let Some(pick) = menu::pick_row(ui, H, &note, &rows) else {
                return;
            };
            let user = list[pick];
            let mut name: heapless::String<{ crate::ckcc::NAME_BYTES }> = heapless::String::new();
            let _ = name.push_str(user.name);
            (name, user.kind())
        };
        let Some(0) = menu::pick_row(ui, &name, kind, &["Delete User"]) else {
            continue;
        };
        menu::ask(ui.panel, "Delete User", &name, "its codes stop working");
        if !menu::confirmed(ui) {
            continue;
        }
        match remove_user(gate, login, ui, &name) {
            Answer::Okay => say(ui, "deleted", &name),
            Answer::Failed(why) => say(ui, "not deleted", why),
            _ => {}
        }
    }
}

/// Settings → Danger zone → Wipe HSM Policy: remove the stored policy file.
/// Source: menu-map-mk4-mk5-q1-v5.6.2.md §DZ "Wipe HSM Policy" [C]
pub(crate) fn wipe_screen(ui: &mut Ui<'_>) {
    const H: &str = "Wipe HSM Policy";
    if !look_for_policy() {
        menu::message(ui.panel, H, "no HSM policy", "is stored");
        menu::wait_for_any_key(ui);
        return;
    }
    menu::ask(ui.panel, H, "remove the stored", "HSM policy?");
    if !menu::confirmed(ui) {
        return;
    }
    // SAFETY: foreground only; the caller holds the display while this runs.
    let result = unsafe { crate::settings::Files::mount() }
        .map_err(|_| ())
        .and_then(|mut f| f.remove_file(engine::POLICY_PATH).map_err(|_| ()));
    look_for_policy();
    match result {
        Ok(()) => say(ui, "removed", "any key"),
        Err(()) => say(ui, "not removed", "the store would not write"),
    }
}
