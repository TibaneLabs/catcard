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

use catcard_callgate::Callgate;
use catcard_fido::ctap2::{self, Ask, Env, Presence};
use catcard_fido::hid::{self, Ctaphid, Event};
use catcard_fido::keys::Master;
use catcard_fido::u2f;
use catcard_ui::keypad::{Event as KeyEvent, KEYS, Key};
use catcard_wallet::KeyWork;
use core::fmt::Write as _;

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
            Some(ctap2::get_info(bytes))
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

/// Forget the derived master and any U2F press: the wallet in force changed, or the
/// security key was reset.
pub(crate) fn forget() {
    // SAFETY: foreground only; nothing holds a borrow of either across this call.
    unsafe {
        *core::ptr::addr_of_mut!(MASTER) = None;
        *core::ptr::addr_of_mut!(U2F_GRANT) = None;
        *core::ptr::addr_of_mut!(U2F_ASK) = None;
    }
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
            ctap2::handle(request, out.bytes(), &mut env)
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
        let value = catcard_settings::prefs::fido_generation_value(next);
        let raw = crate::prefs::quoted(&value);
        let saved = crate::prefs::save(
            self.gate,
            self.login,
            self.ui,
            HEAD,
            (catcard_settings::prefs::FIDO_GEN, raw.as_str()),
            crate::prefs::Prefs {
                fido_gen: Some(next),
                ..now
            },
        );
        forget();
        if saved {
            crate::catlog!("fido: reset to generation {}", next);
            ctap2::status::OK
        } else {
            ctap2::status::OTHER
        }
    }
}

impl Env for UiEnv<'_, '_> {
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

    fn with_master<R>(&mut self, f: impl FnOnce(&Master, &KeyWork) -> R) -> Option<R> {
        let Some(generation) = crate::prefs::current().fido_gen else {
            crate::catlog!("fido: this wallet's generation is unreadable; reset to use it");
            return None;
        };
        // SAFETY: foreground only; the borrow ends within this block.
        let cached =
            unsafe { matches!(&*core::ptr::addr_of!(MASTER), Some((_, g)) if *g == generation) };
        if !cached {
            if !self.alive() {
                return None;
            }
            let root = match menu::master_quietly(self.gate, self.login, self.ui.panel, HEAD) {
                Ok(m) => m,
                Err(why) => {
                    crate::catlog!("fido: no wallet to answer with: {}", why);
                    return None;
                }
            };
            let m = crate::keywork::run(|kw| Master::derive(&root, generation, kw));
            drop(root);
            // SAFETY: foreground only.
            unsafe { *core::ptr::addr_of_mut!(MASTER) = Some((m, generation)) };
        }
        // SAFETY: foreground only; set just above or earlier this session, and nothing
        // else runs on this task while `f` does.
        let m = unsafe { &(*core::ptr::addr_of!(MASTER)).as_ref()?.0 };
        Some(crate::keywork::run(|kw| f(m, kw)))
    }

    fn random(&mut self, out: &mut [u8]) -> bool {
        self.ui.drbg.generate(out).is_ok()
    }

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

// ---------------------------------------------------------------------------------------
// Settings -> Hardware On/Off -> Security key
// ---------------------------------------------------------------------------------------

/// The switch. Per wallet, read after the PIN like `Keyboard EMU`, so a locked device
/// never offers a security key and each wallet decides for itself; switching it re-
/// enumerates at once.
pub(crate) fn switch_screen(gate: &Callgate, login: &mut catcard_pin::Login, ui: &mut Ui<'_>) {
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
