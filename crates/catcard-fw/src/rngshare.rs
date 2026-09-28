//! A paired computer reading this device's random sources: `RngSample` and `RngHealth`.
//!
//! Present in every build, answered only inside a paired session (`usbtask` checks the
//! channel before it gets here). The samples come from the one reader the bench's
//! `DebugTrng` uses ([`crate::rngread`]); what this adds is who may ask and how often:
//!
//! - **The person at the device says yes, once per session**, before the first chunk
//!   leaves: an approval page asked from the main menu loop, never over another screen or
//!   inside a flow. No, or no answer within a minute, refuses every chunk for the rest of
//!   the session. A new session -- unpairing, pairing again, a bus reset, an unplug --
//!   asks afresh. The list of sources and the health report need no answer: neither
//!   carries a sample.
//! - **The secure elements are read only so often** ([`catcard_usb::rng::SeBudget`]): each
//!   read may write their EEPROM.
//!
//! The health report is a snapshot the UI task publishes from the menu loop
//! ([`publish`]): the pool lives in that task's frame and is never handed to the USB task.
//! What the snapshot holds is [`catcard_usb::rng::Health`] -- verdicts and counts, never a
//! byte or anything of the pool's state.

use catcard_ui::keypad::{Event as KeyEvent, KEYS, Key};
use catcard_usb::Status;
use catcard_usb::rng::{self, Consent, ConsentGate, Health, SourceHealth};

use crate::rngread::{self, Origin};
use crate::ui::Ui;
use crate::{display, menu, usbtask};

/// How long the question waits for an answer. The same minute a security key gives a
/// person to touch it.
const ASK_MS: u32 = 60_000;

/// What the USB task and the UI task share: the session's consent, and the last health
/// snapshot.
struct Shared {
    consent: ConsentGate,
    health: Health,
}

static mut SHARED: Shared = Shared {
    consent: ConsentGate::new(),
    health: Health {
        flags: 0,
        hw_sources: 0,
        count: 0,
        sources: [None; rng::MAX_SOURCES],
    },
};

fn with<R>(f: impl FnOnce(&mut Shared) -> R) -> R {
    cortex_m::interrupt::free(|_| {
        // SAFETY: the only reference to `SHARED`, taken with interrupts masked on a
        // single core, so the USB task and the UI task never hold one at the same time.
        let s = unsafe { &mut *core::ptr::addr_of_mut!(SHARED) };
        f(s)
    })
}

/// `RngSample` inside paired session `session` (USB task). Writes the reply body into
/// `out` (at least [`rng::REPLY_LEN`] bytes).
pub fn sample(session: u32, payload: &[u8], out: &mut [u8]) -> (Status, usize) {
    if out.len() < rng::REPLY_LEN {
        return (Status::Busy, 0);
    }
    let (source, len) = match rng::parse_request(payload) {
        Ok(rng::Request::List) => return (Status::Ok, rngread::list(out)),
        Ok(rng::Request::Chunk { source, len }) => (source, len),
        Err(st) => return (st, 0),
    };
    match with(|s| s.consent.request(session)) {
        Consent::Granted => rngread::request(Origin::Paired(session), source, len, out),
        Consent::Refused => (Status::Declined, 0),
        Consent::Unasked | Consent::Asking => {
            out[0] = rng::wait::ASKING;
            (Status::NotNow, 1)
        }
    }
}

/// `RngHealth` (USB task): the last snapshot [`publish`] left.
pub fn health(out: &mut [u8]) -> (Status, usize) {
    if out.len() < Health::MAX_LEN {
        return (Status::Busy, 0);
    }
    let h = with(|s| s.health);
    (Status::Ok, h.encode(out))
}

/// The paired session ended (USB task): forget its answer, take its question off the
/// screen, and drop any chunk being read for it.
pub fn session_ended() {
    with(|s| s.consent.end());
    rngread::session_ended();
}

/// Publish the pool's health for the USB task (menu loop, UI task). `pool` is `None` when
/// the boot pool never met its policy. Cheap enough for every pass of the loop: a few
/// comparisons per source, no hashing, no reads.
#[inline(never)]
pub fn publish(pool: Option<&catcard_entropy::EntropyPool>) {
    use catcard_entropy::{HealthError, Startup};
    use rng::health as h;
    let mut report = Health {
        flags: h::PUBLISHED,
        ..Health::default()
    };
    if let Some(p) = pool {
        report.flags |= h::POOL;
        if p.check().is_ok() {
            report.flags |= h::POLICY_MET;
        }
        if p.startup_enforced() {
            report.flags |= h::STARTUP_ENFORCED;
        }
        report.hw_sources = p.hardware_sources().min(u8::MAX as u32) as u8;
    }
    let failure = |e: HealthError| match e {
        HealthError::Repetition { .. } => h::REPETITION,
        HealthError::AdaptiveProportion { .. } => h::ADAPTIVE,
        HealthError::Constant { .. } => h::CONSTANT,
        HealthError::TooShort { .. } => h::TOO_SHORT,
    };
    for kind in crate::trng::kinds() {
        let mut line = SourceHealth {
            source: rngread::wire_id(kind),
            startup: h::UNTESTED,
            failure: h::NONE,
            last: h::NOT_READ,
            tested: 0,
            trips: 0,
        };
        if let Some(st) = pool.and_then(|p| p.status(kind.source())) {
            (line.startup, line.failure, line.tested) = match st.startup {
                Startup::Pending { tested } => {
                    (h::PENDING, h::NONE, tested.min(u16::MAX as usize) as u16)
                }
                Startup::Passed => (
                    h::PASSED,
                    h::NONE,
                    catcard_entropy::STARTUP_SAMPLES.min(u16::MAX as usize) as u16,
                ),
                Startup::Failed(e) => (h::FAILED, failure(e), 0),
            };
            line.last = match st.last_ok {
                None => h::NOT_READ,
                Some(true) => h::OK,
                Some(false) => h::TRIPPED,
            };
            line.trips = st.trips.min(u16::MAX as u32) as u16;
        }
        report.push(line);
    }
    with(|s| s.health = report);
}

/// Whether a paired computer's question is waiting for the screen.
pub fn pending() -> bool {
    with(|s| s.consent.to_ask()).is_some()
}

/// Ask the person, and record the answer (menu loop, after the keys were read, the way
/// it calls `fido::serve`). Never inlined, so the page's frame is on the UI task's stack
/// only while it is showing.
#[inline(never)]
pub fn serve(ui: &mut Ui<'_>) {
    let Some(session) = with(|s| s.consent.to_ask()) else {
        return;
    };
    // HSM mode answers no computer's question by hand.
    if crate::ckcc::hsm_active() {
        with(|s| s.consent.answer(session, false));
        return;
    }
    let small: [&str; 2] = [
        "Never your seed or keys; these bytes are not used for any wallet.",
        "Asked once while this computer stays paired.",
    ];
    let page = catcard_ui::approval::Approval {
        head: "Share RNG samples?",
        // The Utils grid's Analyze RNG picture: the same subject, looked at from a
        // computer instead.
        #[cfg(feature = "board-q1")]
        art: Some(&catcard_ui::art::menuicons::ANALYZE_RNG),
        #[cfg(not(feature = "board-q1"))]
        art: None,
        main: "Raw bytes from this device's random generators, for the paired computer.",
        small: &small,
        yes: (display::CONFIRM, "share"),
        no: (display::CANCEL, "refuse"),
    };
    display::draw_field_page(ui.panel, |c| {
        catcard_ui::approval::draw(c, &display::FONTS, &page)
    });
    menu::wait_for_release(ui);
    let started = crate::fido::now_ms();
    let mut events = [KeyEvent::Pressed(Key::Cancel); KEYS];
    let mut keys: heapless::Vec<Key, { KEYS + 1 }> = heapless::Vec::new();
    let yes = 'ask: loop {
        let _ = usbtask::pump();
        // The session went away (unpaired, unplugged): nothing left to answer.
        if !with(|s| s.consent.still_asking(session)) {
            crate::idle::note_progress();
            return;
        }
        if crate::fido::now_ms().wrapping_sub(started) >= ASK_MS {
            break false;
        }
        crate::pinentry::pressed_keys(ui.pad, ui.matrix, ui.drbg, &mut events, &mut keys);
        for k in keys.iter() {
            match *k {
                Key::Cancel => break 'ask false,
                Key::Confirm => break 'ask true,
                _ => {}
            }
        }
        display::idle(ui.panel);
    };
    with(|s| s.consent.answer(session, yes));
    crate::catlog!(
        "rngshare: session {} {}",
        session,
        if yes { "shares samples" } else { "refused" }
    );
    crate::idle::note_progress();
}
