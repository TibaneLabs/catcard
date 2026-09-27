//! The FIDO2 security key: a browser asks, the person at the device answers.
//!
//! The protocol is `catcard-fido`'s and host-tested there; this module is the glue, in
//! the same two halves as [`crate::hostwallet`]:
//!
//! - [`Desk`] lives in the USB task. It feeds the security key's reports to the CTAPHID
//!   state machine, answers what needs neither keys nor a person (`GetInfo`, U2F
//!   `VERSION`, every malformed request) on the spot, and queues the rest for the UI task
//!   with the buffer the request arrived in. While a request is out, the state machine's
//!   keepalives tell the host it is still being worked on -- `UPNEEDED` while the
//!   question is on the screen.
//! - [`serve`] runs on the UI task when the menu loop sees a request waiting
//!   ([`pending`]), after the keys have been read, like every other host question. It
//!   derives the wallet's FIDO master if this session has not yet ([`with_master`]), asks
//!   the person when the protocol says to, signs, and hands the answer back.
//!
//! # The wallet in force is the identity
//!
//! Keys come from the BIP-32 master node of whatever wallet is in force -- the stored
//! seed, a passphrase on it, a BIP-85 child, a loaded key -- through
//! `catcard_fido::keys`. Every question on the screen names that wallet, because a
//! passphrase wallet is a different security key and a person registering with the
//! wrong one would find their login gone when they next open the other.
//!
//! The derived master (64 bytes, which say nothing about the wallet's own keys) is kept
//! for the session once made: fetching the seed and stretching the words costs seconds
//! -- 1.6 s of secure-element key-stretch on an mk4 before PBKDF2's 2048 rounds -- and a
//! browser's silent probes (U2F check-only, `up:false`) would pay it every time. It is
//! wiped with every other derived cache when the wallet in force changes
//! (`crate::pubkeys::forget`), and on a reset.
//!
//! # The PIN and the passkeys
//!
//! The security-key PIN (CTAP2 clientPIN, typed in the browser) is kept **per wallet**,
//! like the generation: `cat_fidopin` in the wallet's own encrypted settings holds its
//! 16-byte hash and the retries left ([`UiEnv::pin`], [`UiEnv::save_pin`]). The token a
//! PIN buys, the key-agreement keys and the "three wrong in a row" count are RAM only
//! ([`SESSION`]): unplugging is the power cycle CTAP asks for.
//!
//! Passkeys (discoverable credentials) are a file of their own in the internal-flash
//! volume, one per wallet and generation, sealed under keys made from the FIDO master
//! (`catcard_fido::passkeys`); the mk3 has no such volume and keeps none. A request
//! reads the file into one heap block, at most 14 KB, and writes it back when it changed.

use catcard_callgate::Callgate;
use catcard_fido::ctap2::{self, Ask, Caps, Env, Note, Presence};
use catcard_fido::hid::{self, Ctaphid, Event};
use catcard_fido::keys::Master;
#[cfg(not(feature = "board-mk3"))]
use catcard_fido::passkeys;
use catcard_fido::passkeys::Passkeys;
use catcard_fido::pin::{self, PinRecord, Session, perm};
use catcard_fido::u2f;
use catcard_ui::keypad::{Event as KeyEvent, KEYS, Key};
use catcard_wallet::KeyWork;
use core::fmt::Write as _;
use core::sync::atomic::{AtomicBool, AtomicU8, Ordering};

use crate::heap::Block;
use crate::ui::Ui;
use crate::{display, menu, usbtask};

const HEAD: &str = "Security key";

/// How long a question waits for the person before answering
/// `CTAP2_ERR_USER_ACTION_TIMEOUT`.
///
/// The wait belongs to the browser: the site's WebAuthn `timeout` runs there, and when it
/// ends -- or the person cancels in the browser -- the host sends CTAPHID CANCEL, which
/// closes the question at once. CTAP sets no duration for the authenticator's own give-up.
/// So this is only a backstop for a host that goes quiet without cancelling: a minute,
/// the owner's choice -- long enough to read the site and answer, short enough that an
/// abandoned question does not hold the screen. Nothing counts it down on the screen.
/// Source: CTAP 2.1 §8.2 `CTAP2_ERR_USER_ACTION_TIMEOUT` [C]
const PRESENCE_MS: u32 = 60_000;

/// How long a request may wait for the UI task to take it -- the person may be deep in
/// another flow -- before it is answered as timed out.
const QUEUE_MS: u32 = 30_000;

/// How long a U2F press counts for the site it was given for: the host re-sends the
/// command about every quarter second after `SW_CONDITIONS_NOT_SATISFIED`.
const U2F_GRANT_MS: u32 = 10_000;

/// A reset is refused this long after the security key was presented to the host.
/// Source: CTAP 2.1 §6.6 "authenticatorReset ... within 10 seconds of powering up" [C];
/// the interface appears after login, which is this device's "powering up" as far as a
/// host can tell.
const RESET_WINDOW_MS: u32 = 10_000;

/// Milliseconds from the kernel's tick; wraps, and every comparison here is a wrapping
/// difference.
pub(crate) fn now_ms() -> u32 {
    catcard_kernel::ticks().wrapping_mul(catcard_kernel::TICK_MS)
}

/// The firmware version as `INIT` reports it: major, minor, build.
const VERSION3: [u8; 3] = {
    const fn num(s: &str) -> u8 {
        let b = s.as_bytes();
        let mut v: u32 = 0;
        let mut i = 0;
        while i < b.len() {
            v = v * 10 + (b[i] - b'0') as u32;
            i += 1;
        }
        if v > 255 { 255 } else { v as u8 }
    }
    [
        num(env!("CARGO_PKG_VERSION_MAJOR")),
        num(env!("CARGO_PKG_VERSION_MINOR")),
        num(env!("CARGO_PKG_VERSION_PATCH")),
    ]
};

// ---------------------------------------------------------------------------------------
// The USB task's half
// ---------------------------------------------------------------------------------------

/// A request handed to the UI task: the command (`CBOR` or `MSG`) and its bytes.
pub(crate) struct Taken {
    pub ticket: u32,
    pub cmd: u8,
    pub len: usize,
    pub buf: Block,
}

enum Job {
    Idle,
    Queued {
        ticket: u32,
        cmd: u8,
        len: usize,
        buf: Block,
        since: u32,
    },
    /// On the UI task. `dead` once the host resynced or the bus reset: the answer, when
    /// it comes, goes nowhere.
    Taken {
        ticket: u32,
        dead: bool,
    },
}

/// The security key's state in the USB task. Idle and empty unless the switch is on.
pub(crate) struct Desk {
    hid: Ctaphid,
    /// The transaction buffer, while the USB task holds it. Leased from the heap when a
    /// report arrives and given back as soon as nothing is in flight.
    buf: Option<Block>,
    job: Job,
    ticket: u32,
    out: [u8; hid::PACKET],
    out_ready: bool,
    wink: bool,
}

impl Desk {
    pub(crate) const fn new() -> Self {
        Self {
            hid: Ctaphid::new(VERSION3),
            buf: None,
            job: Job::Idle,
            ticket: 0,
            out: [0; hid::PACKET],
            out_ready: false,
            wink: false,
        }
    }

    /// A bus reset, a re-enumeration or the switch going off: everything in flight is
    /// void. A request on the screen finishes into nothing.
    pub(crate) fn reset(&mut self) {
        self.hid.reset();
        self.buf = None;
        self.out_ready = false;
        self.wink = false;
        self.job = match core::mem::replace(&mut self.job, Job::Idle) {
            Job::Taken { ticket, .. } => Job::Taken { ticket, dead: true },
            _ => Job::Idle,
        };
    }

    fn job_out(&self) -> bool {
        !matches!(self.job, Job::Idle)
    }

    /// One report from the security key's OUT endpoint.
    pub(crate) fn feed(&mut self, report: &[u8; hid::PACKET], now: u32, unlocked: bool) {
        if self.buf.is_none() && !self.job_out() {
            self.buf = crate::heap::take(hid::MAX_MSG);
        }
        let ev = match &mut self.buf {
            Some(b) => self.hid.feed(report, b.bytes(), now),
            None => self.hid.feed(report, &mut [], now),
        };
        match ev {
            Event::Request { cmd, len, .. } => self.request(cmd, len, now, unlocked),
            Event::Wink => self.wink = true,
            Event::Abandoned => {
                self.job = match core::mem::replace(&mut self.job, Job::Idle) {
                    Job::Taken { ticket, .. } => Job::Taken { ticket, dead: true },
                    _ => Job::Idle,
                };
            }
            Event::Cancel | Event::None => {}
        }
    }

    fn request(&mut self, cmd: u8, len: usize, now: u32, unlocked: bool) {
        let Some(mut b) = self.buf.take() else {
            self.hid.fail(hid::err::OTHER);
            return;
        };
        let bytes = b.bytes();
        // What needs neither keys nor a person is answered here, at once.
        let quick = if cmd == hid::cmd::CBOR && bytes[0] == ctap2::command::GET_INFO {
            Some(ctap2::get_info(bytes, &caps()))
        } else if cmd == hid::cmd::MSG {
            let mut small = [0u8; 8];
            u2f::immediate(&bytes[..len], &mut small).inspect(|&n| {
                bytes[..n].copy_from_slice(&small[..n]);
            })
        } else {
            None
        };
        // No PIN, no keys: refused without a question.
        let quick = quick.or_else(|| (!unlocked).then(|| refuse(cmd, bytes, false)));
        if let Some(n) = quick {
            self.buf = Some(b);
            self.hid.respond(n);
            return;
        }
        self.ticket = self.ticket.wrapping_add(1);
        self.job = Job::Queued {
            ticket: self.ticket,
            cmd,
            len,
            buf: b,
            since: now,
        };
    }

    /// Time passing: keepalives, timeouts, and the next report to send.
    pub(crate) fn tick(&mut self, now: u32) {
        self.hid.tick(now);
        if let Job::Queued { since, .. } = self.job
            && now.wrapping_sub(since) >= QUEUE_MS
            && let Job::Queued { cmd, mut buf, .. } = core::mem::replace(&mut self.job, Job::Idle)
        {
            crate::catlog!("fido: a request waited too long for the screen");
            let n = refuse(cmd, buf.bytes(), true);
            self.buf = Some(buf);
            self.hid.respond(n);
        }
        if !self.out_ready {
            let ready = match &mut self.buf {
                Some(b) => self.hid.next_packet(b.bytes(), &mut self.out),
                None => self.hid.next_packet(&[], &mut self.out),
            };
            self.out_ready = ready;
        }
        if self.hid.idle() && !self.job_out() && !self.out_ready {
            self.buf = None;
        }
    }

    /// The next report for the security key's IN endpoint, if one is ready.
    pub(crate) fn packet(&self) -> Option<&[u8; hid::PACKET]> {
        self.out_ready.then_some(&self.out)
    }

    /// The report from [`packet`](Self::packet) went out.
    pub(crate) fn sent(&mut self) {
        self.out_ready = false;
    }

    pub(crate) fn busy(&self) -> bool {
        self.out_ready || !self.hid.idle()
    }

    pub(crate) fn waiting(&self) -> bool {
        matches!(self.job, Job::Queued { .. }) || self.wink
    }

    pub(crate) fn take(&mut self) -> Option<Taken> {
        if !matches!(self.job, Job::Queued { .. }) {
            return None;
        }
        let Job::Queued {
            ticket,
            cmd,
            len,
            buf,
            ..
        } = core::mem::replace(&mut self.job, Job::Idle)
        else {
            return None;
        };
        self.job = Job::Taken {
            ticket,
            dead: false,
        };
        Some(Taken {
            ticket,
            cmd,
            len,
            buf,
        })
    }

    /// Whether request `ticket` is still wanted: on the screen, not withdrawn, not
    /// cancelled.
    pub(crate) fn alive(&self, ticket: u32) -> bool {
        matches!(self.job, Job::Taken { ticket: t, dead: false } if t == ticket)
            && self.hid.processing().is_some()
            && !self.hid.cancelled()
    }

    /// Whether the host sent `CANCEL` for request `ticket`.
    pub(crate) fn cancelled(&self, ticket: u32) -> bool {
        matches!(self.job, Job::Taken { ticket: t, .. } if t == ticket) && self.hid.cancelled()
    }

    pub(crate) fn set_status(&mut self, upneeded: bool) {
        self.hid.set_status(if upneeded {
            hid::status::UPNEEDED
        } else {
            hid::status::PROCESSING
        });
    }

    /// The UI task's answer to `ticket`: `len` bytes at the start of `buf`.
    pub(crate) fn finish(&mut self, ticket: u32, buf: Block, len: usize) {
        match self.job {
            Job::Taken { ticket: t, dead } if t == ticket => {
                self.job = Job::Idle;
                if !dead {
                    self.buf = Some(buf);
                    self.hid.respond(len);
                }
            }
            // Not ours to answer any more; the block goes back to the heap.
            _ => {}
        }
    }

    pub(crate) fn take_wink(&mut self) -> bool {
        core::mem::take(&mut self.wink)
    }
}

/// A refusal written over a request: CTAP2's status byte, or U2F's status word.
fn refuse(cmd: u8, bytes: &mut [u8], timed_out: bool) -> usize {
    if cmd == hid::cmd::CBOR {
        bytes[0] = if timed_out {
            ctap2::status::USER_ACTION_TIMEOUT
        } else {
            ctap2::status::OPERATION_DENIED
        };
        1
    } else {
        bytes[..2].copy_from_slice(&u2f::sw::CONDITIONS_NOT_SATISFIED.to_be_bytes());
        2
    }
}

// ---------------------------------------------------------------------------------------
// The UI task's half
// ---------------------------------------------------------------------------------------

/// The session's FIDO master and the generation it was made at. Foreground (UI task)
/// only.
static mut MASTER: Option<(Master, u32)> = None;

/// A U2F press given on the screen: register or sign-in, for which site, until when.
static mut U2F_GRANT: Option<(bool, [u8; 32], u32)> = None;
/// A U2F question to put on the screen once the refusal has gone back.
static mut U2F_ASK: Option<(bool, [u8; 32])> = None;

/// The PIN/UV auth protocols' state from power-up to power-off: key-agreement keys, the
/// one pinUvAuthToken, the consecutive-mismatch count, and the stateful commands'
/// cursor. Foreground (UI task) only; a few hundred bytes of `.bss`.
static mut SESSION: Session = Session::new();

/// Whether the wallet in force has a PIN, as GetInfo's `clientPin` says it. Read by the
/// USB task, which answers GetInfo on the spot; written from the foreground.
static PIN_SET: AtomicBool = AtomicBool::new(false);

/// Passkeys the wallet in force can still store, [`UNKNOWN`] until its file was read
/// this session. GetInfo's `remainingDiscoverableCredentials`.
static REMAINING: AtomicU8 = AtomicU8::new(UNKNOWN);
const UNKNOWN: u8 = 0xFF;

/// Whether this board keeps passkeys: the file lives in the internal-flash volume, which
/// the mk3 does not have.
#[cfg(not(feature = "board-mk3"))]
const PASSKEYS: bool = true;
#[cfg(feature = "board-mk3")]
const PASSKEYS: bool = false;

/// What GetInfo says now.
pub(crate) fn caps() -> Caps {
    Caps {
        pin_set: PIN_SET.load(Ordering::Relaxed),
        rk: PASSKEYS,
        remaining: match REMAINING.load(Ordering::Relaxed) {
            UNKNOWN => None,
            n => Some(n),
        },
    }
}

/// The wallet in force has (or has not) a PIN: from its preferences, at login and at
/// every save.
pub(crate) fn set_pin_known(set: bool) {
    PIN_SET.store(set, Ordering::Relaxed);
}

/// Forget the derived master and any U2F press: the wallet in force changed, or the
/// security key was reset.
pub(crate) fn forget() {
    // SAFETY: foreground only; nothing holds a borrow of either across this call.
    unsafe {
        *core::ptr::addr_of_mut!(MASTER) = None;
        *core::ptr::addr_of_mut!(U2F_GRANT) = None;
        *core::ptr::addr_of_mut!(U2F_ASK) = None;
        // A token bought with the last wallet's PIN answers for nothing now.
        (*core::ptr::addr_of_mut!(SESSION)).forget_wallet();
    }
    REMAINING.store(UNKNOWN, Ordering::Relaxed);
}

/// Whether a security-key request (or a wink) is waiting for the screen.
pub(crate) fn pending() -> bool {
    usbtask::fido_waiting()
}

/// Take the waiting request and answer it. The menu loop calls this the way it calls
/// `hostwallet::serve`: after the keys were read, and redraws when it returns.
///
/// Never inlined: the menu loop's own frame is on the UI task's stack for the whole
/// session, and a request's buffers and parse state belong on it only while one is
/// being answered.
#[inline(never)]
pub(crate) fn serve(gate: &Callgate, login: &mut catcard_pin::Login, ui: &mut Ui<'_>) {
    if usbtask::fido_take_wink() {
        wink(ui);
    }
    let Some(t) = usbtask::fido_take() else {
        return;
    };
    let ticket = t.ticket;
    let mut req = t.buf;
    // The answer is built in a block of its own, so the request can be read while it is
    // written. Without one, the request's own block carries the refusal back.
    let Some(mut out) = crate::heap::take(hid::MAX_MSG) else {
        crate::catlog!("fido: no memory for an answer");
        let n = refuse(t.cmd, req.bytes(), false);
        usbtask::fido_finish(ticket, req, n);
        return;
    };
    let n = {
        let mut env = UiEnv {
            gate,
            login,
            ui,
            ticket: Some(ticket),
        };
        let request = &req.bytes()[..t.len];
        if t.cmd == hid::cmd::CBOR {
            // SAFETY: foreground only; nothing else borrows the session while a request
            // is answered, and the borrow ends with this call.
            let session = unsafe { &mut *core::ptr::addr_of_mut!(SESSION) };
            ctap2::handle(request, out.bytes(), session, &mut env)
        } else {
            u2f::handle(request, out.bytes(), &mut env)
        }
    };
    drop(req);
    usbtask::fido_status(false);
    usbtask::fido_finish(ticket, out, n);

    // A U2F command that needed a press was refused just now, as U2F requires; the host
    // is already retrying. Ask here, where the answer can take its time.
    // SAFETY: foreground only.
    let ask = unsafe { (*core::ptr::addr_of_mut!(U2F_ASK)).take() };
    if let Some((register, app)) = ask {
        let mut env = UiEnv {
            gate,
            login,
            ui,
            ticket: None,
        };
        let q = if register {
            Ask::U2fRegister { app: &app }
        } else {
            Ask::U2fSignIn { app: &app }
        };
        if env.presence(q) == Presence::Allowed {
            // SAFETY: foreground only.
            unsafe {
                *core::ptr::addr_of_mut!(U2F_GRANT) =
                    Some((register, app, now_ms().wrapping_add(U2F_GRANT_MS)));
            }
        }
    }
}

/// `CTAPHID_WINK`: say on the screen which device the computer means.
fn wink(ui: &mut Ui<'_>) {
    menu::message(ui.panel, HEAD, "the computer is", "pointing at this one");
    let until = now_ms().wrapping_add(1_500);
    while now_ms().wrapping_sub(until) > u32::MAX / 2 {
        let _ = usbtask::pump();
        display::idle(ui.panel);
    }
}

/// The device, as the protocol sees it from the UI task.
struct UiEnv<'a, 'b> {
    gate: &'a Callgate,
    login: &'a mut catcard_pin::Login,
    ui: &'a mut Ui<'b>,
    /// The request being answered, or `None` for the U2F question asked after its answer
    /// went back.
    ticket: Option<u32>,
}

/// Printable ASCII only, at most `max` characters: a site and an account name come from
/// the host, and a control character or a thousand-character name is the host's to send
/// and not the screen's to draw.
fn sanitised<const N: usize>(s: &str, max: usize) -> heapless::String<N> {
    let mut out: heapless::String<N> = heapless::String::new();
    for (i, c) in s.chars().enumerate() {
        if i >= max.min(N - 3) {
            let _ = out.push_str("...");
            break;
        }
        let _ = out.push(if (' '..='~').contains(&c) { c } else { '?' });
    }
    out
}

/// The wallet in force, as a question names it: its kind and, when known, fingerprint.
fn wallet_line() -> heapless::String<40> {
    let mut s: heapless::String<40> = heapless::String::new();
    let _ = write!(s, "Wallet: {}", crate::key::label());
    if let Some(fp) = crate::pubkeys::known_fingerprint() {
        let _ = write!(s, " {:02X}{:02X}{:02X}{:02X}", fp[0], fp[1], fp[2], fp[3]);
    }
    s
}

/// One question to the person: the action, what it is about, the fine print, and what
/// each answer does. [`UiEnv::ask`] lays it out with the board's own key marks -- the
/// moulded tick and cross on the numpad boards, ENTER and CANCEL on the Q1 -- so no
/// question names a key itself.
struct Question<'a> {
    head: &'a str,
    /// The page's main line: the site. Empty when the computer did not say (U2F).
    main: &'a str,
    small: heapless::Vec<&'a str, 4>,
    /// What the yes key does: "allow".
    yes: &'a str,
    /// What cancel does: "refuse".
    no: &'a str,
}

impl<'a> Question<'a> {
    fn new(head: &'a str, main: &'a str, small: &[&'a str], yes: &'a str, no: &'a str) -> Self {
        let mut v = heapless::Vec::new();
        for l in small {
            let _ = v.push(*l);
        }
        Question {
            head,
            main,
            small: v,
            yes,
            no,
        }
    }
}

impl UiEnv<'_, '_> {
    fn alive(&self) -> bool {
        self.ticket.is_none_or(usbtask::fido_alive)
    }

    fn gone(&self) -> Presence {
        match self.ticket {
            Some(t) if usbtask::fido_cancelled(t) => Presence::Cancelled,
            _ => Presence::Denied,
        }
    }

    /// Put `q` on the screen and wait for `yes` or cancel, a bounded time.
    ///
    /// Every board shows it as an approval page ([`catcard_ui::approval`]): with the
    /// security-key picture on the Q1, without on the 64-row panels. It never scrolls,
    /// so the answers are always on it. `yes` is the key that says yes, and the page
    /// shows that key as the board marks it.
    fn ask(&mut self, q: &Question<'_>, yes: Key) -> Presence {
        if crate::ckcc::hsm_active() {
            return Presence::Denied;
        }
        if !self.alive() {
            return self.gone();
        }
        if self.ticket.is_some() {
            usbtask::fido_status(true);
        }
        let yes_mark = match yes {
            Key::Digit(7) => catcard_ui::icons::KeyMark::Word("7"),
            _ => display::CONFIRM,
        };
        let page = catcard_ui::approval::Approval {
            head: q.head,
            #[cfg(feature = "board-q1")]
            art: Some(&catcard_ui::art::menuicons::SECURE_KEY),
            #[cfg(not(feature = "board-q1"))]
            art: None,
            main: q.main,
            small: &q.small,
            yes: (yes_mark, q.yes),
            no: (display::CANCEL, q.no),
        };
        display::draw_field_page(self.ui.panel, |c| {
            catcard_ui::approval::draw(c, &display::FONTS, &page)
        });
        menu::wait_for_release(self.ui);
        let started = now_ms();
        let mut events = [KeyEvent::Pressed(Key::Cancel); KEYS];
        let mut keys: heapless::Vec<Key, { KEYS + 1 }> = heapless::Vec::new();
        let answer = 'ask: loop {
            let _ = usbtask::pump();
            if !self.alive() {
                break self.gone();
            }
            if now_ms().wrapping_sub(started) >= PRESENCE_MS {
                break Presence::Timeout;
            }
            crate::pinentry::pressed_keys(
                self.ui.pad,
                self.ui.matrix,
                self.ui.drbg,
                &mut events,
                &mut keys,
            );
            for k in keys.iter() {
                if *k == Key::Cancel {
                    break 'ask Presence::Denied;
                }
                if *k == yes {
                    break 'ask Presence::Allowed;
                }
            }
            display::idle(self.ui.panel);
        };
        if self.ticket.is_some() {
            usbtask::fido_status(false);
        }
        crate::idle::note_progress();
        answer
    }

    /// The two-question reset. See [`Env::reset`].
    #[inline(never)]
    fn reset_asked(&mut self) -> u8 {
        let wallet = wallet_line();
        let q1 = Question::new(
            "Reset security key?",
            "Every site this wallet registered with stops accepting it.",
            &["This cannot be undone.", wallet.as_str()],
            "reset",
            "keep it",
        );
        match self.ask(&q1, Key::Confirm) {
            Presence::Allowed => {}
            p => return p.refusal(),
        }
        let q2 = Question::new(
            "Are you sure?",
            "Logins made with this wallet's security key are lost for good.",
            &[],
            "reset",
            "keep it",
        );
        match self.ask(&q2, Key::Digit(7)) {
            Presence::Allowed => {}
            p => return p.refusal(),
        }
        let now = crate::prefs::current();
        // An unreadable generation is replaced by a random one: any number the wallet
        // used before is as likely as any other, which is to say not at all.
        let next = match now.fido_gen {
            Some(g) => match g.checked_add(1) {
                Some(n) => n,
                None => return ctap2::status::NOT_ALLOWED,
            },
            None => {
                let mut b = [0u8; 4];
                if self.ui.drbg.generate(&mut b).is_err() {
                    return ctap2::status::OTHER;
                }
                u32::from_le_bytes(b)
            }
        };
        // The passkey file is named from the old generation's master: find it before
        // the generation moves, remove it after.
        #[cfg(not(feature = "board-mk3"))]
        let old_file = self.with_master(|m, kw| passkey_path(&m.passkey_key(kw)));
        let value = catcard_settings::prefs::fido_generation_value(next);
        let raw = crate::prefs::quoted(&value);
        // The new generation and the cleared PIN in one write: never one without the
        // other. Source: CTAP 2.1 §6.6 (a reset clears the PIN and every credential) [C]
        let saved = crate::prefs::save_many(
            self.gate,
            self.login,
            self.ui,
            HEAD,
            &[
                (catcard_settings::prefs::FIDO_GEN, raw.as_str()),
                (catcard_settings::prefs::FIDO_PIN, "\"\""),
            ],
            crate::prefs::Prefs {
                fido_gen: Some(next),
                fido_pin: false,
                ..now
            },
        );
        forget();
        if !saved {
            return ctap2::status::OTHER;
        }
        crate::catlog!("fido: reset to generation {}, PIN cleared", next);
        // The old file is sealed under a key the new generation cannot make, so it is
        // already unreadable; removing it gives the space back.
        #[cfg(not(feature = "board-mk3"))]
        if let Some(path) = old_file {
            let gone = write_passkey_file(&path, None).is_ok();
            crate::catlog!("fido: old passkeys removed: {}", gone);
        }
        ctap2::status::OK
    }
}

impl Env for UiEnv<'_, '_> {
    // Out of line: its strings are a few hundred bytes of frame that a request only
    // needs while the question is up.
    #[inline(never)]
    fn presence(&mut self, ask: Ask<'_>) -> Presence {
        let wallet = wallet_line();
        let mut site: heapless::String<67> = heapless::String::new();
        let mut account: heapless::String<67> = heapless::String::new();
        let mut yes = "allow";
        let (what, note): (&str, &str) = match ask {
            Ask::Register {
                rp_id,
                user_name,
                display_name,
                excluded,
                resident,
            } => {
                site = sanitised(rp_id, 64);
                let who = user_name.or(display_name).unwrap_or("");
                if !who.is_empty() {
                    let name: heapless::String<60> = sanitised(who, 56);
                    let _ = write!(account, "as {name}");
                }
                if excluded {
                    yes = "tell the site";
                    (
                        "Already registered",
                        "This wallet already has a login here.",
                    )
                } else if resident {
                    ("Register", "Saved on this device as a passkey.")
                } else {
                    ("Register", "")
                }
            }
            Ask::SignIn { rp_id, known } => {
                site = sanitised(rp_id, 64);
                if known {
                    ("Sign in", "")
                } else {
                    yes = "tell the site";
                    ("Sign in", "This wallet has no login here.")
                }
            }
            Ask::U2fRegister { .. } => ("Register", "Older U2F request: the site is not named."),
            Ask::U2fSignIn { .. } => ("Sign in", "Older U2F request: the site is not named."),
            Ask::Select => ("Security key", "The computer asks which key to use."),
            Ask::SetPin => {
                let _ = site.push_str("Set security key PIN?");
                (
                    "Security key",
                    "The browser will ask for it to use this key.",
                )
            }
            Ask::ChangePin => {
                let _ = site.push_str("Change security key PIN?");
                ("Security key", "The old PIN is checked first.")
            }
            Ask::UsePin { rp_id, permissions } => {
                if let Some(rp) = rp_id {
                    site = sanitised(rp, 64);
                }
                let what = if permissions & perm::CM != 0 {
                    "Manage passkeys"
                } else if permissions == perm::MC {
                    "Register"
                } else if permissions == perm::GA {
                    "Sign in"
                } else {
                    "Use security key"
                };
                (what, "With the PIN typed on the computer.")
            }
        };
        // The action is the heading, the site is what the question is about, and the
        // account, the wallet and the keys are the fine print.
        let mut small: heapless::Vec<&str, 4> = heapless::Vec::new();
        for l in [account.as_str(), note, wallet.as_str()] {
            if !l.is_empty() {
                let _ = small.push(l);
            }
        }
        let q = Question {
            head: what,
            main: site.as_str(),
            small,
            yes,
            no: "refuse",
        };
        self.ask(&q, Key::Confirm)
    }

    fn master_do(&mut self, f: &mut dyn FnMut(&Master, &KeyWork)) -> bool {
        let Some(generation) = crate::prefs::current().fido_gen else {
            crate::catlog!("fido: this wallet's generation is unreadable; reset to use it");
            return false;
        };
        // SAFETY: foreground only; the borrow ends within this block.
        let cached =
            unsafe { matches!(&*core::ptr::addr_of!(MASTER), Some((_, g)) if *g == generation) };
        if !cached {
            if !self.alive() {
                return false;
            }
            let root = match menu::master_quietly(self.gate, self.login, self.ui.panel, HEAD) {
                Ok(m) => m,
                Err(why) => {
                    crate::catlog!("fido: no wallet to answer with: {}", why);
                    return false;
                }
            };
            let m = crate::keywork::run(|kw| Master::derive(&root, generation, kw));
            drop(root);
            // SAFETY: foreground only.
            unsafe { *core::ptr::addr_of_mut!(MASTER) = Some((m, generation)) };
        }
        // SAFETY: foreground only; set just above or earlier this session, and nothing
        // else runs on this task while `f` does.
        let Some((m, _)) = (unsafe { (*core::ptr::addr_of!(MASTER)).as_ref() }) else {
            return false;
        };
        crate::keywork::run(|kw| f(m, kw));
        true
    }

    fn random(&mut self, out: &mut [u8]) -> bool {
        self.ui.drbg.generate(out).is_ok()
    }

    fn masked<R>(&mut self, f: impl FnOnce(&KeyWork) -> R) -> R {
        crate::keywork::run(f)
    }

    fn now_ms(&mut self) -> u32 {
        now_ms()
    }

    fn caps(&mut self) -> Caps {
        caps()
    }

    fn pin(&mut self) -> Option<PinRecord> {
        use catcard_settings::prefs::FidoPin;
        let got = read_pin(self.gate, self.login, self.ui.panel);
        let rec = match &got {
            Ok(FidoPin::Unset) => None,
            Ok(FidoPin::Set { retries, hash }) => Some(PinRecord {
                retries: *retries,
                hash: *hash,
            }),
            // Unreadable, or the settings would not open: blocked, never "no PIN".
            Ok(FidoPin::Unreadable) | Err(_) => {
                crate::catlog!("fido: the PIN record will not read; treated as blocked");
                Some(PinRecord {
                    retries: 0,
                    hash: [0; 16],
                })
            }
        };
        set_pin_known(rec.is_some());
        rec
    }

    fn save_pin(&mut self, rec: &PinRecord) -> bool {
        let value = catcard_settings::prefs::fido_pin_value(rec.retries, &rec.hash);
        let mut raw: zeroize::Zeroizing<heapless::String<40>> =
            zeroize::Zeroizing::new(heapless::String::new());
        let _ = raw.push('"');
        let _ = raw.push_str(value.as_str());
        let _ = raw.push('"');
        let now = crate::prefs::current();
        crate::prefs::save(
            self.gate,
            self.login,
            self.ui,
            HEAD,
            (catcard_settings::prefs::FIDO_PIN, raw.as_str()),
            crate::prefs::Prefs {
                fido_pin: true,
                ..now
            },
        )
    }

    fn passkeys_do(&mut self, f: &mut dyn FnMut(&mut Passkeys<'_>) -> bool) -> Result<(), u8> {
        #[cfg(feature = "board-mk3")]
        {
            let _ = f;
            Err(ctap2::status::OTHER)
        }
        #[cfg(not(feature = "board-mk3"))]
        {
            let key = self
                .with_master(|m, kw| m.passkey_key(kw))
                .ok_or(ctap2::status::OPERATION_DENIED)?;
            let mut iv = [0u8; 16];
            if !self.random(&mut iv) {
                return Err(ctap2::status::OTHER);
            }
            passkey_file(&key, &iv, f)
        }
    }

    fn note(&mut self, n: &Note<'_>) {
        log_note(n);
    }

    #[inline(never)]
    fn reset(&mut self) -> u8 {
        if now_ms().wrapping_sub(usbtask::fido_since()) > RESET_WINDOW_MS {
            crate::catlog!("fido: reset refused, outside the ten-second window");
            return ctap2::status::NOT_ALLOWED;
        }
        self.reset_asked()
    }

    fn u2f_presence(&mut self, register: bool, app: &[u8; 32]) -> bool {
        // SAFETY: foreground only.
        unsafe {
            let grant = &mut *core::ptr::addr_of_mut!(U2F_GRANT);
            if let Some((r, a, until)) = *grant
                && r == register
                && a == *app
                && until.wrapping_sub(now_ms()) <= U2F_GRANT_MS
            {
                *grant = None;
                return true;
            }
            *core::ptr::addr_of_mut!(U2F_ASK) = Some((register, *app));
        }
        false
    }
}

/// The wallet's PIN record, read from its settings. Its own frame: the slot read and the
/// parse are kilobytes, and a PIN request goes on to ECDH and a settings write.
#[inline(never)]
fn read_pin(
    gate: &Callgate,
    login: &mut catcard_pin::Login,
    panel: &mut display::Panel,
) -> Result<catcard_settings::prefs::FidoPin, &'static str> {
    use catcard_settings::store::SCRATCH;
    let key = crate::settings::wallet_key(gate, login, panel, HEAD)?;
    let mut held = crate::heap::take(SCRATCH).ok_or("no memory")?;
    let buf = held.bytes();
    let n = crate::settings::read_slot(&key, buf)?;
    let doc = crate::settings::parse_doc(&buf[..n]).ok_or("no memory")?;
    Ok(catcard_settings::prefs::fido_pin(&doc))
}

/// The passkey file's path in the internal-flash volume: `/fido-` and the sixteen hex
/// digits the key names it by. Ours; stock has no such file.
#[cfg(not(feature = "board-mk3"))]
fn passkey_path(key: &passkeys::PasskeyKey) -> heapless::String<32> {
    let mut s: heapless::String<32> = heapless::String::new();
    let _ = s.push_str("/fido-");
    for b in key.name {
        let _ = write!(s, "{b:02x}");
    }
    let _ = s.push_str(".pk");
    s
}

/// Open this wallet's passkey file in a heap block, run `f`, and write the file back if
/// it changed (removing it when nothing is left). The block holds what is there plus room
/// for one more, at most [`passkeys::MAX_FILE`], and is wiped when it goes back.
#[cfg(not(feature = "board-mk3"))]
#[inline(never)]
fn passkey_file(
    key: &passkeys::PasskeyKey,
    iv: &[u8; 16],
    f: &mut dyn FnMut(&mut Passkeys<'_>) -> bool,
) -> Result<(), u8> {
    use passkeys::CAPACITY;
    const FAIL: u8 = ctap2::status::OTHER;
    let path = passkey_path(key);
    let (mut block, len) = read_passkey_file(&path)?;
    let buf = block.bytes();
    let opened = match len {
        None => Passkeys::empty(buf),
        Some(n) => Passkeys::open(key, buf, n),
    };
    let mut list = opened.map_err(|e| {
        crate::catlog!("fido: the passkey file will not open: {:?}", e);
        FAIL
    })?;
    let changed = f(&mut list);
    let left = list.len();
    REMAINING.store((CAPACITY - left) as u8, Ordering::Relaxed);
    if changed {
        let n = passkeys::seal_file(buf, key, iv);
        write_passkey_file(&path, (left > 0).then_some(&buf[..n]))?;
    }
    Ok(())
}

/// The passkey file read into a heap block with room for one more passkey, and its
/// length (`None`: no file yet). A leaf of its own: the mount is kilobytes of frame.
#[cfg(not(feature = "board-mk3"))]
#[inline(never)]
fn read_passkey_file(path: &str) -> Result<(crate::heap::Block, Option<usize>), u8> {
    use passkeys::{CAPACITY, REC_LEN, file_len};
    const FAIL: u8 = ctap2::status::OTHER;
    // SAFETY: the region is mapped and readable; nothing is written through this.
    let mut files = unsafe { crate::settings::Files::mount_read_only() }.map_err(|_| FAIL)?;
    let len = files.file_len(path);
    let count = len.map_or(0, |n| n.saturating_sub(file_len(0)) / REC_LEN);
    let size = file_len((count + 1).min(CAPACITY));
    if len.is_some_and(|n| n > size) {
        crate::catlog!("fido: the passkey file is too large to be ours");
        return Err(FAIL);
    }
    let Some(mut block) = crate::heap::take(size) else {
        crate::catlog!("fido: no memory for the passkeys ({} B)", size);
        return Err(FAIL);
    };
    if let Some(n) = len
        && !matches!(files.read_file(path, block.bytes()), Ok(Some(got)) if got == n)
    {
        crate::catlog!("fido: the passkey file will not read");
        return Err(FAIL);
    }
    Ok((block, len))
}

/// Write the sealed file, or remove it when `bytes` is `None` (nothing left). A leaf of
/// its own, like [`read_passkey_file`].
#[cfg(not(feature = "board-mk3"))]
#[inline(never)]
fn write_passkey_file(path: &str, bytes: Option<&[u8]>) -> Result<(), u8> {
    // SAFETY: foreground only; the caller holds the display while this runs.
    let mut files = unsafe { crate::settings::Files::mount() }.map_err(|_| ctap2::status::OTHER)?;
    let written = match bytes {
        Some(b) => files.write_file(path, b),
        None => files.remove_file(path),
    };
    written.map_err(|_| {
        crate::catlog!("fido: the passkey file could not be written");
        ctap2::status::OTHER
    })
}

/// One line in the log per request: what, which site, how it ended. Never a PIN, a hash,
/// a token, a key or a user id.
#[inline(never)]
fn log_note(n: &Note<'_>) {
    use ctap2::{command as c, status as s};
    let what = match n.command {
        c::MAKE_CREDENTIAL => "makeCredential",
        c::GET_ASSERTION => "getAssertion",
        c::GET_NEXT_ASSERTION => "getNextAssertion",
        c::CLIENT_PIN => match n.sub {
            Some(pin::sub::GET_PIN_RETRIES) => "clientPin getPinRetries",
            Some(pin::sub::GET_KEY_AGREEMENT) => "clientPin getKeyAgreement",
            Some(pin::sub::SET_PIN) => "clientPin setPIN",
            Some(pin::sub::CHANGE_PIN) => "clientPin changePIN",
            Some(pin::sub::GET_PIN_TOKEN) => "clientPin getPinToken",
            Some(pin::sub::GET_TOKEN_USING_PIN) => "clientPin getPinUvAuthToken",
            _ => "clientPin",
        },
        c::CREDENTIAL_MANAGEMENT | c::CREDENTIAL_MANAGEMENT_PRE => match n.sub {
            Some(1) => "credMgmt metadata",
            Some(2) | Some(3) => "credMgmt enumerateRPs",
            Some(4) | Some(5) => "credMgmt enumerateCredentials",
            Some(6) => "credMgmt deleteCredential",
            Some(7) => "credMgmt updateUser",
            _ => "credMgmt",
        },
        c::RESET => "reset",
        c::SELECTION => "selection",
        _ => "unknown command",
    };
    let asks = matches!(
        n.command,
        c::MAKE_CREDENTIAL | c::GET_ASSERTION | c::GET_NEXT_ASSERTION | c::RESET | c::SELECTION
    );
    let outcome = match n.status {
        s::OK if asks => "allowed",
        s::OK => "ok",
        s::OPERATION_DENIED => "refused on the device",
        s::KEEPALIVE_CANCEL => "cancelled by host",
        s::USER_ACTION_TIMEOUT => "timed out",
        s::PUAT_REQUIRED => "refused (PIN required)",
        s::PIN_NOT_SET => "refused (no PIN set)",
        s::PIN_INVALID => "wrong PIN",
        s::PIN_BLOCKED => "refused (PIN blocked, reset needed)",
        s::PIN_AUTH_BLOCKED => "refused (unplug to try again)",
        s::PIN_AUTH_INVALID => "refused (token not valid)",
        s::PIN_POLICY_VIOLATION => "refused (PIN too short or too long)",
        s::NO_CREDENTIALS => "no credentials",
        s::CREDENTIAL_EXCLUDED => "already registered",
        s::KEY_STORE_FULL => "refused (passkeys full)",
        s::NOT_ALLOWED => "not allowed",
        _ => "refused",
    };
    let mut line: heapless::String<160> = heapless::String::new();
    let _ = write!(line, "fido: {what}");
    if let Some(rp) = n.rp_id {
        let rp: heapless::String<67> = sanitised(rp, 64);
        let _ = write!(line, " rp={rp}");
    }
    if matches!(n.command, c::MAKE_CREDENTIAL | c::GET_ASSERTION) {
        let _ = write!(line, " rk={} uv={}", n.rk as u8, n.uv as u8);
    }
    if let Some(found) = n.found {
        let _ = write!(line, " found={found}");
    }
    let _ = write!(line, " -> {outcome}");
    match n.pin {
        Some(pin::Outcome::Token { retries, .. }) | Some(pin::Outcome::Wrong { retries }) => {
            let _ = write!(line, " ({retries} left)");
        }
        Some(pin::Outcome::Retries(r)) => {
            let _ = write!(line, " ({r})");
        }
        _ => {}
    }
    if n.status != s::OK {
        let _ = write!(line, " [{:#04x}]", n.status);
    }
    crate::catlog!("{}", line.as_str());
}

// ---------------------------------------------------------------------------------------
// Settings -> Hardware On/Off -> Security key
// ---------------------------------------------------------------------------------------

/// Settings -> Hardware On/Off -> Security key: the switch, and (where the board keeps
/// them) this wallet's passkeys.
///
/// There is no "remove PIN" here: CTAP has no way to remove a PIN but a reset, and a PIN
/// that the device could drop on its own would protect nothing. The PIN is set and
/// changed from the browser, and cleared -- with every passkey -- only by a reset.
pub(crate) fn switch_screen(gate: &Callgate, login: &mut catcard_pin::Login, ui: &mut Ui<'_>) {
    #[cfg(not(feature = "board-mk3"))]
    {
        let now = crate::prefs::current();
        let mut note: heapless::String<32> = heapless::String::new();
        let _ = write!(
            note,
            "now {}, PIN {}",
            if now.fido { "on" } else { "off" },
            if now.fido_pin { "set" } else { "not set" }
        );
        match menu::pick_row(ui, HEAD, note.as_str(), &["On / Off", "Passkeys"]) {
            Some(0) => {}
            Some(_) => return passkeys_screen(gate, login, ui),
            None => return,
        }
    }
    switch(gate, login, ui);
}

/// The switch. Per wallet, read after the PIN like `Keyboard EMU`, so a locked device
/// never offers a security key and each wallet decides for itself; switching it re-
/// enumerates at once.
fn switch(gate: &Callgate, login: &mut catcard_pin::Login, ui: &mut Ui<'_>) {
    let now = crate::prefs::current();
    if usbtask::usb_mode() != catcard_settings::prelogin::UsbMode::CatCard {
        menu::message(ui.panel, HEAD, "works in CatCard", "USB mode only");
        menu::wait_for_any_key(ui);
    }
    let Some(want) = menu::pick_switch(ui, HEAD, now.fido) else {
        return;
    };
    if want {
        menu::ask(
            ui.panel,
            HEAD,
            "computers see a FIDO key",
            "it re-enumerates now",
        );
        if !menu::confirmed(ui) {
            return;
        }
    }
    menu::save_pref(
        gate,
        login,
        ui,
        HEAD,
        (catcard_settings::prefs::FIDO, if want { "1" } else { "0" }),
        crate::prefs::Prefs { fido: want, ..now },
        if want { "on" } else { "off" },
    );
}

/// Bytes of one passkey's row: the site and the account, printable ASCII.
#[cfg(not(feature = "board-mk3"))]
const LABEL: usize = 48;

/// Settings -> Hardware On/Off -> Security key -> Passkeys: this wallet's passkeys, one
/// row each (site and account), and deleting one with the approval page.
///
/// The list is the standard document list; its rows and their text are leased from the
/// heap for as long as it is on the screen, so fifty passkeys cost the UI task's stack
/// nothing.
#[cfg(not(feature = "board-mk3"))]
#[inline(never)]
fn passkeys_screen(gate: &Callgate, login: &mut catcard_pin::Login, ui: &mut Ui<'_>) {
    use catcard_ui::scroll::Line as Row;
    const TITLE: &str = "Passkeys";
    loop {
        let Some(mut labels) = crate::heap::take(passkeys::CAPACITY * LABEL) else {
            menu::message(ui.panel, TITLE, "not enough memory", "to list them");
            menu::wait_for_any_key(ui);
            return;
        };
        let mut n = 0;
        let read = {
            let text = labels.bytes();
            let mut env = UiEnv {
                gate,
                login,
                ui: &mut *ui,
                ticket: None,
            };
            env.passkeys(|p| {
                n = p.len();
                for i in 0..n {
                    let Some(r) = p.get(i) else { continue };
                    let mut l: heapless::String<LABEL> = heapless::String::new();
                    let site: heapless::String<36> = sanitised(r.rp_id.as_str(), 32);
                    let who = if r.name.is_empty() {
                        r.display_name.as_str()
                    } else {
                        r.name.as_str()
                    };
                    let who: heapless::String<24> = sanitised(who, 20);
                    let _ = write!(l, "{site} {who}");
                    let slot = &mut text[i * LABEL..(i + 1) * LABEL];
                    slot.fill(0);
                    slot[..l.len()].copy_from_slice(l.as_bytes());
                }
                ((), false)
            })
        };
        if read.is_err() {
            menu::message(ui.panel, TITLE, "could not read", "this wallet's passkeys");
            menu::wait_for_any_key(ui);
            return;
        }
        if n == 0 {
            menu::message(ui.panel, TITLE, "no passkeys", "for this wallet");
            menu::wait_for_any_key(ui);
            return;
        }
        let pick = {
            let Some(room) =
                crate::heap::room::<heapless::Vec<Row<'_>, { passkeys::CAPACITY + 1 }>>()
            else {
                menu::message(ui.panel, TITLE, "not enough memory", "to list them");
                menu::wait_for_any_key(ui);
                return;
            };
            let mut rows = room.fill(heapless::Vec::new());
            let _ = rows.push(Row::title(TITLE));
            let text = labels.bytes();
            for (i, chunk) in text.chunks(LABEL).take(n).enumerate() {
                let len = chunk.iter().position(|&b| b == 0).unwrap_or(LABEL);
                let s = core::str::from_utf8(&chunk[..len]).unwrap_or("?");
                let _ = rows.push(Row::item(s, i as u32));
            }
            match menu::show_doc(ui, &rows, false, false) {
                menu::DocExit::Selected(i) => i as usize,
                _ => return,
            }
        };
        drop(labels);
        delete_passkey(gate, login, ui, pick);
    }
}

/// Ask, on the approval page, whether to delete passkey `index`, and delete it.
#[cfg(not(feature = "board-mk3"))]
#[inline(never)]
fn delete_passkey(gate: &Callgate, login: &mut catcard_pin::Login, ui: &mut Ui<'_>, index: usize) {
    let mut env = UiEnv {
        gate,
        login,
        ui,
        ticket: None,
    };
    let Ok(Some(rec)) = env.passkeys(|p| (p.get(index), false)) else {
        return;
    };
    let site: heapless::String<36> = sanitised(rec.rp_id.as_str(), 32);
    let mut account: heapless::String<67> = heapless::String::new();
    let who = if rec.name.is_empty() {
        rec.display_name.as_str()
    } else {
        rec.name.as_str()
    };
    if !who.is_empty() {
        let name: heapless::String<60> = sanitised(who, 56);
        let _ = write!(account, "as {name}");
    }
    let wallet = wallet_line();
    let mut small: heapless::Vec<&str, 4> = heapless::Vec::new();
    for l in [
        account.as_str(),
        "The site will not find this login here again.",
        wallet.as_str(),
    ] {
        if !l.is_empty() {
            let _ = small.push(l);
        }
    }
    let q = Question {
        head: "Delete passkey?",
        main: site.as_str(),
        small,
        yes: "delete",
        no: "keep",
    };
    if env.ask(&q, Key::Confirm) != Presence::Allowed {
        return;
    }
    let nonce = rec.nonce;
    let rp = rec.rp_id_hash;
    let done = env.passkeys(|p| match p.find(&rp, &nonce) {
        Some(i) => {
            p.remove(i);
            (true, true)
        }
        None => (false, false),
    });
    let said = match done {
        Ok(true) => {
            crate::catlog!("fido: passkey deleted on the device");
            "deleted"
        }
        _ => "could not delete it",
    };
    menu::message(env.ui.panel, "Passkeys", said, site.as_str());
    menu::wait_for_any_key(env.ui);
}
