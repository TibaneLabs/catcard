//! The USB service: reports in, replies out, and the firmware upgrade behind them.
//!
//! Polled from every screen's loop rather than from an interrupt. Everything a host asks
//! for is answered here except the one thing a host must not be able to decide on its
//! own — whether an upgrade is installed. That waits for a person at the device, which is
//! why [`pending`] exists rather than the commit happening inline.
//!
//! # The peripheral comes up early; the operations do not
//!
//! USB is brought up during bring-up, before the PIN prompt, because a host presents the
//! cable and starts enumerating within milliseconds of power and will not wait for
//! someone to type a PIN. A device that only appears after unlocking looks broken.
//!
//! Enumerating discloses nothing — a name, an ID, a serial number that is already the
//! USB serial. **Upgrades are what needs the PIN**, and they are refused with `NotNow`
//! until [`set_unlocked`] is called. Someone holding the device therefore cannot replace
//! its firmware without also being able to open it.
//!
//! # One peripheral, one task
//!
//! Held in a static because that is what it is: there is one OTG core, and every screen
//! has to be able to service it without the task being threaded through each of them.
//! The boot path is single-threaded and nothing here runs in interrupt context.

use catcard_board::BOARD;
use catcard_hal::otg::{Event, Otg};
use catcard_upgrade::psram::PsramArea;
use catcard_upgrade::{Approval, Reject, Staged};
use catcard_usb::{FrameError, Opcode, Reassembler, Status, Writer, PROTOCOL_VERSION, REPORT_LEN};

use crate::VERSION;

/// What the task is in the middle of.
enum Stage {
    Idle,
    /// An image is arriving.
    Receiving(Staged<'static, PsramArea>),
    /// An image arrived and passed inspection; the user has not yet been asked.
    Offered {
        staged: Staged<'static, PsramArea>,
        approval: Approval,
    },
    /// The user approved. The session loop will reboot into the bootloader.
    Approved,
}

pub struct UsbTask {
    otg: Otg,
    /// Keys a host has pressed, waiting to be read by whichever screen is up.
    ///
    /// One deep. A host driving the UI is doing it a keystroke at a time and waiting to
    /// see the result; queueing more would let it run ahead of the screen it is
    /// answering, which is how a confirmation gets pressed before it is read.
    #[cfg(feature = "usb-key-injection")]
    injected: Option<u8>,
    /// Reports taken from the host, and replies handed back. Shown on the idle screen
    /// because the emulator decodes that screen to text, which makes it the only
    /// diagnostic channel this firmware has that needs no debugger.
    rx_count: u32,
    tx_count: u32,
    frame_errors: u32,
    last_status: u16,
    /// Whether the PIN has been entered. Gates the upgrade opcodes only.
    unlocked: bool,
    /// Whether the device has no PIN set at all.
    blank: bool,
    frames: Reassembler,
    stage: Stage,
    /// A reply waiting for FIFO room. Held rather than dropped, because a reply the host
    /// never receives leaves it waiting for a message that is not coming.
    outbox: [u8; REPORT_LEN],
    outbox_len: usize,
    reply: Option<ReplyState>,
}

/// A response being sent out, frame by frame.
struct ReplyState {
    status: Status,
    body: [u8; 64],
    len: usize,
    sent: bool,
}

impl UsbTask {
    /// Bring USB up.
    ///
    /// # Safety
    /// Call once. Takes the OTG peripheral and PA11/PA12, and needs the 48 MHz clock
    /// already running.
    pub unsafe fn init(serial: &'static str) -> Option<Self> {
        // SAFETY: the caller promises this is the only initialisation.
        let otg = match unsafe { Otg::init(BOARD.usb.dm, BOARD.usb.dp, serial) } {
            Ok(otg) => otg,
            Err(e) => {
                // Keep the reason. Discarding it left a device that said "usb down" and
                // nothing else, which is indistinguishable from a host that never
                // spoke -- and on hardware there is no debugger to ask instead.
                set_init_fault(match e {
                    catcard_hal::otg::Error::UsbSupplyNotValid => "vddusb",
                    catcard_hal::otg::Error::CoreStuck => "core",
                });
                return None;
            }
        };
        Some(Self {
            otg,
            #[cfg(feature = "usb-key-injection")]
            injected: None,
            rx_count: 0,
            tx_count: 0,
            frame_errors: 0,
            last_status: 0,
            unlocked: false,
            blank: false,
            frames: Reassembler::new(),
            stage: Stage::Idle,
            outbox: [0; REPORT_LEN],
            outbox_len: 0,
            reply: None,
        })
    }

    /// The PIN has been entered; upgrades may now be offered.
    pub fn set_unlocked(&mut self) {
        self.unlocked = true;
    }

    /// Report whether the device is still waiting to be given a first PIN.
    pub fn set_blank(&mut self, blank: bool) {
        self.blank = blank;
    }

    /// An upgrade the user should be asked about, if there is one.
    pub fn pending(&self) -> Option<&Approval> {
        match &self.stage {
            Stage::Offered { approval, .. } => Some(approval),
            _ => None,
        }
    }

    /// The user approved the staged upgrade.
    ///
    /// **This is the irreversible step.** It publishes the marker the bootloader reads
    /// on the next boot, after which rebooting installs the image over the running
    /// firmware. It does not itself reboot: the caller does that, so the last act is
    /// visible where the decision was made.
    pub fn approve(&mut self) -> Result<catcard_upgrade::Region, Reject> {
        let stage = core::mem::replace(&mut self.stage, Stage::Idle);
        let Stage::Offered { staged, approval } = stage else {
            return Err(Reject::Incomplete { have: 0, want: 0 });
        };
        let region = staged.commit(approval)?;
        self.stage = Stage::Approved;
        Ok(region)
    }

    /// The user declined. The staged image is dropped without being marked.
    pub fn decline(&mut self) {
        self.stage = Stage::Idle;
        self.begin_reply(Status::Declined, &[]);
    }

    /// Service USB once.
    ///
    /// # Safety
    /// Exclusive access to OTG_FS.
    pub unsafe fn poll(&mut self) -> bool {
        // SAFETY: as documented.
        unsafe {
            // Push any reply that is waiting for FIFO room before taking more in.
            self.drain_outbox();

            let event = self.otg.poll();
            match event {
                Event::Reset => {
                    // A cable event voids anything in flight. A half-received image
                    // must not be resumable across a reset -- the host would have to be
                    // trusted about where it left off.
                    self.frames.reset();
                    if !matches!(self.stage, Stage::Approved) {
                        self.stage = Stage::Idle;
                    }
                    self.reply = None;
                }
                Event::Report => {
                    self.rx_count = self.rx_count.saturating_add(1);
                    let mut report = [0u8; REPORT_LEN];
                    report.copy_from_slice(&self.otg.rx);
                    self.otg.receive_next();
                    self.on_report(&report);
                    // Push the reply now rather than leaving it for the next poll.
                    // A key that makes the firmware leave its polling loop for a
                    // callgate call -- choosing a PIN, fetching the anti-phishing
                    // words, logging in -- would otherwise strand its own
                    // acknowledgement in the outbox for the length of a secure element
                    // operation. The host cannot tell that from a device that died.
                    self.drain_outbox();
                }
                _ => {}
            }
            event != Event::Idle || self.outbox_len > 0
        }
    }

    /// # Safety
    /// Exclusive access to OTG_FS.
    unsafe fn drain_outbox(&mut self) {
        // SAFETY: as documented.
        unsafe {
            if self.outbox_len > 0 && self.otg.send(&self.outbox) {
                self.tx_count = self.tx_count.saturating_add(1);
                self.outbox_len = 0;
                self.next_reply_frame();
            }
        }
    }

    fn on_report(&mut self, report: &[u8; REPORT_LEN]) {
        let progress = match self.frames.feed(report) {
            Ok(p) => p,
            Err(e) => {
                // Framing is broken, so nothing that follows can be trusted. Drop any
                // partial image rather than trying to resynchronise onto it.
                self.frames.reset();
                self.frame_errors = self.frame_errors.saturating_add(1);
                if !matches!(self.stage, Stage::Approved) {
                    self.stage = Stage::Idle;
                }
                self.begin_reply(
                    Status::BadRequest,
                    &[matches!(e, FrameError::OutOfSequence { .. }) as u8],
                );
                return;
            }
        };

        if let Some(msg) = progress.started {
            match Opcode::from_u16(msg.opcode) {
                Some(Opcode::UpgradeOffer | Opcode::UpgradeCommit) if !self.unlocked => {
                    // Enumerating is free; rewriting the firmware is not. Refusing here
                    // rather than at the screen means a locked device never even stages
                    // an image.
                    self.frames.reset();
                    self.begin_reply(Status::NotNow, &[]);
                    return;
                }
                Some(Opcode::UpgradeOffer) if BOARD.psram.is_none() => {
                    // Say so on the first frame rather than after 256 KB have crossed
                    // the wire, and say which of the several reasons it is.
                    self.frames.reset();
                    self.refuse(Reject::NoStagingArea);
                    return;
                }
                Some(Opcode::UpgradeOffer) => {
                    match Staged::begin(psram_area(), &BOARD, msg.total) {
                        Ok(s) => self.stage = Stage::Receiving(s),
                        Err(r) => {
                            self.frames.reset();
                            self.refuse(r);
                            return;
                        }
                    }
                }
                Some(_) => {}
                None => {
                    self.frames.reset();
                    self.begin_reply(Status::UnknownOpcode, &msg.opcode.to_le_bytes());
                    return;
                }
            }
        }

        // Image bytes go straight to staging as they arrive; nothing is buffered.
        if let Stage::Receiving(staged) = &mut self.stage {
            let at = staged.received();
            if let Err(r) = staged.write(at, progress.payload) {
                self.frames.reset();
                self.refuse(r);
                return;
            }
        }

        if !progress.complete {
            return;
        }

        // The message is whole. `started` is set on the first frame, so for a
        // single-frame message it is still in hand; for a long one the opcode is
        // whichever stage we are in.
        let opcode = progress.started.and_then(|m| Opcode::from_u16(m.opcode));
        match opcode {
            // One page of the log. The upgrade state goes in as a line rather than as a
            // field, so there is one place to look rather than two.
            Some(Opcode::ReadLog) => {
                let offset = if progress.payload.len() >= 4 {
                    u32::from_le_bytes([
                        progress.payload[0],
                        progress.payload[1],
                        progress.payload[2],
                        progress.payload[3],
                    ]) as usize
                } else {
                    0
                };
                let mut body = [0u8; 64];
                body[..4].copy_from_slice(&(crate::logbuf::len() as u32).to_le_bytes());
                body[4] = if crate::logbuf::wrapped() {
                    catcard_usb::log_flags::WRAPPED
                } else {
                    0
                };
                // A page has to fit one frame: a reply's first frame carries
                // `START_PAYLOAD` bytes, and anything past that is dropped by the writer
                // while the header still promises it -- which reads as a device that
                // stopped answering.
                let end = catcard_usb::START_PAYLOAD.min(body.len());
                let n = crate::logbuf::read(offset, &mut body[5..end]);
                self.begin_reply(Status::Ok, &body[..5 + n]);
            }
            Some(Opcode::Ping) => {
                let n = progress.payload.len().min(64);
                let mut body = [0u8; 64];
                body[..n].copy_from_slice(&progress.payload[..n]);
                self.begin_reply(Status::Ok, &body[..n]);
            }
            Some(Opcode::Identify) => self.identify(),
            #[cfg(feature = "usb-key-injection")]
            Some(Opcode::InjectKey) => match progress.payload.first() {
                Some(&k)
                    if k <= 9 || k == catcard_usb::KEY_CANCEL || k == catcard_usb::KEY_CONFIRM =>
                {
                    self.injected = Some(k);
                    self.begin_reply(Status::Ok, &[]);
                }
                _ => self.begin_reply(Status::BadRequest, &[]),
            },
            #[cfg(not(feature = "usb-key-injection"))]
            Some(Opcode::InjectKey) => self.begin_reply(Status::UnknownOpcode, &[]),
            Some(Opcode::UpgradeCommit) => {
                // A host can ask, but only the device can answer. Approval happens at
                // the screen; until then this is simply not the time.
                self.begin_reply(Status::NotNow, &[]);
            }
            Some(Opcode::UpgradeOffer) | None => self.finish_offer(),
        }
    }

    /// The image is fully staged: inspect it and tell the host what we found.
    fn finish_offer(&mut self) {
        let Stage::Receiving(mut staged) = core::mem::replace(&mut self.stage, Stage::Idle) else {
            return;
        };
        let running = crate::own_header();
        match staged.inspect(running.as_ref()) {
            Ok(approval) => {
                let mut body = [0u8; 64];
                let n = describe(&approval, &mut body);
                crate::catlog!(
                    "usb: offered {} bytes, verified {}, older {}",
                    approval.length,
                    approval.is_verified(),
                    approval.older_than_running
                );
                self.stage = Stage::Offered { staged, approval };
                self.begin_reply(Status::Ok, &body[..n]);
            }
            Err(r) => self.refuse(r),
        }
    }

    fn identify(&mut self) {
        // Fixed layout rather than a text blob, so a host does not have to parse prose:
        //   [0..2] protocol version
        //   [2]    device state, see `catcard_usb::state`
        //   [3]    capabilities, see `catcard_usb::caps`
        //   [4..]  board name length, then the name
        //   then   version string length, then the version
        let mut body = [0u8; 64];
        let mut at = 0;
        body[at..at + 2].copy_from_slice(&PROTOCOL_VERSION.to_le_bytes());
        at += 2;
        // Which screen a host is answering. `unlocked` alone was not enough: a device
        // that is not unlocked is either asking for a PIN or asking to be given one,
        // and those need different keys.
        body[at] = (if self.unlocked {
            catcard_usb::state::UNLOCKED
        } else {
            0
        }) | (if self.blank {
            catcard_usb::state::BLANK
        } else {
            0
        });
        at += 1;
        // What this build will accept, so a host does not have to discover it by being
        // refused -- and so an operator can see whether key injection is compiled in.
        body[at] = if cfg!(feature = "usb-key-injection") {
            catcard_usb::caps::KEY_INJECTION
        } else {
            0
        } | if BOARD.psram.is_some() {
            catcard_usb::caps::UPGRADE
        } else {
            0
        };
        at += 1;
        for s in [crate::running_board(), VERSION] {
            let b = s.as_bytes();
            let n = b.len().min(31);
            body[at] = n as u8;
            body[at + 1..at + 1 + n].copy_from_slice(&b[..n]);
            at += 1 + n;
        }
        self.begin_reply(Status::Ok, &body[..at]);
    }

    fn refuse(&mut self, reason: Reject) {
        let mut body = [0u8; 64];
        let n = describe_reject(&reason, &mut body);
        self.begin_reply(Status::Refused, &body[..n]);
    }

    fn begin_reply(&mut self, status: Status, body: &[u8]) {
        self.last_status = status as u16;
        let mut buf = [0u8; 64];
        // Clamped to what a single frame carries, not to the report size. The reply
        // writer emits one frame and marks the reply sent, so a longer body loses its
        // tail while the frame header still declares the full length -- and a host that
        // believes the header waits for a continuation that is never coming. That is
        // indistinguishable from a device that died, which is how it was found.
        let n = body.len().min(catcard_usb::START_PAYLOAD);
        buf[..n].copy_from_slice(&body[..n]);
        self.reply = Some(ReplyState {
            status,
            body: buf,
            len: n,
            sent: false,
        });
        self.next_reply_frame();
    }

    /// Move the next frame of the current reply into the outbox.
    fn next_reply_frame(&mut self) {
        let Some(r) = &mut self.reply else { return };
        if r.sent {
            self.reply = None;
            return;
        }
        let mut w = Writer::response(r.status, &r.body[..r.len]);
        // One frame, because `begin_reply` clamps a body to what one carries. The loop
        // shape is kept so a multi-frame reply later cannot silently lose its tail.
        if w.next(&mut self.outbox) {
            self.outbox_len = REPORT_LEN;
            r.sent = true;
        } else {
            self.reply = None;
        }
    }
}

/// Claim the PSRAM staging region.
fn psram_area() -> PsramArea {
    // SAFETY: mk4 and Q1 have PSRAM memory-mapped and nothing else in this firmware uses
    // its upper half. On a board without PSRAM this is never reached -- `UsbTask` is only
    // constructed where `BOARD.psram` is `Some`.
    let psram = BOARD.psram.expect("no PSRAM on this board");
    unsafe { PsramArea::claim(&psram) }
}

/// Summarise an approval for the host, without a formatter.
fn describe(a: &Approval, out: &mut [u8; 64]) -> usize {
    out[0] = a.is_verified() as u8;
    out[1..5].copy_from_slice(&a.length.to_le_bytes());
    out[5..13].copy_from_slice(&a.header.timestamp);
    out[13..21].copy_from_slice(&a.header.version);
    out[21] = a.header.pubkey_num as u8;
    out[22] = a.older_than_running as u8;
    23
}

/// Name a refusal in one byte, plus whatever detail fits.
fn describe_reject(r: &Reject, out: &mut [u8; 64]) -> usize {
    out[0] = match r {
        Reject::Length { .. } => 1,
        Reject::TooBigToStage { .. } => 2,
        Reject::OutOfOrder { .. } => 3,
        Reject::PastEnd { .. } => 4,
        Reject::Incomplete { .. } => 5,
        Reject::NotAnImage => 6,
        Reject::BadHeader(_) => 7,
        Reject::WrongBoard { .. } => 8,
        Reject::BadSignature => 10,
        Reject::StorageFault { .. } => 11,
        Reject::NoStagingArea => 12,
    };
    1
}

// ---------------------------------------------------------------------------
// The singleton
// ---------------------------------------------------------------------------

static mut TASK: Option<UsbTask> = None;

/// Bring USB up, if this board can host it.
///
/// # Safety
/// Call once, after the 48 MHz clock is running and before any call to [`pump`].
pub unsafe fn init(serial: &'static str) {
    // Deliberately not gated on having somewhere to stage an image. It used to be, and
    // the effect was that a board without PSRAM -- mk3 -- brought up no USB at all: no
    // enumeration, no diagnostics, no injected keys. That is the same condition that
    // stranded an mk4 whose transceiver never powered on, except guaranteed rather than
    // accidental. A device that cannot be upgraded is precisely the one worth being
    // able to reach, so it enumerates and refuses the offer instead.
    // SAFETY: single-threaded bring-up; this is the only writer and no reader exists
    // until it returns.
    unsafe {
        let task = UsbTask::init(serial);
        core::ptr::addr_of_mut!(TASK).write(task);
    }
}

/// Service USB. Safe to call from anywhere in the foreground.
/// How long to pause between polls of the USB core.
///
/// **Measured, not derived.** Polling with nothing between the polls delivers no reports
/// at all — not slowly, not at all — which is not behaviour the reference describes.
/// Bracketed under the emulator at the reset-default 4 MHz, where a USB frame is 1 ms
/// and so 4,000 cycles:
///
/// ```text
///        0 cycles                no reports at all
///    4,000  (~1 frame)           no reports at all
///   16,000  (~4 frames)          a two-frame ping succeeds
///   33,000  (~8 frames)          a two-frame ping succeeds; a 256 KB transfer
///                                returned a malformed report (`kind 0`)
///   66,000 (~16 frames)          ping, identify, 256 KB and 987 KB, repeatedly
/// ```
///
/// **The middle two are not "working" values.** They were called that on the strength
/// of a two-frame ping, which is far too small a sample to judge a link by: at 33,000 a
/// real transfer came back corrupted rather than absent, which is the worse failure of
/// the two. Only 66,000 has carried a firmware image.
///
/// It costs throughput — 987 KB takes 72 seconds — and that is the right trade for the
/// one operation on this device that overwrites its own firmware.
///
/// A corrupted report rather than a missing one also hints the fault may be ours: the
/// IN endpoint is enabled and then filled, which is the documented order, but a core
/// that transmits before the FIFO write lands would send exactly this. A longer pause
/// would mask that. Worth an oscilloscope before trusting the mechanism.
///
/// **`VALIDATION.md` says an emulator run does not settle anything the reference marks
/// `[I]`, and this is squarely that** — so it is carried as a measured number and
/// revisited on hardware.
pub const IDLE_PAUSE_CYCLES: u32 = 66_000;

/// Service USB. Safe to call from anywhere in the foreground.
///
/// Returns whether anything happened, so a caller can decide how hard to spin.
pub fn pump() -> bool {
    let Some(t) = task() else { return false };
    // SAFETY: the task owns OTG_FS for the life of the firmware, and nothing runs in
    // interrupt context.
    let busy = unsafe { t.poll() };
    publish_status(t);
    busy
}

/// The OTG endpoint registers, for the debug screen.
///
/// `[GINTSTS, DAINT, DOEPCTL, DOEPTSIZ, DIEPCTL, DCTL]`. On hardware there is no RAM
/// dump to read these out of, so the screen is the only place they can be seen.
pub fn otg_regs() -> Option<[u32; 6]> {
    // SAFETY: single-threaded boot path; the task owns OTG_FS and this only reads.
    task().map(|t| unsafe { t.otg.debug_regs() })
}

/// Why USB did not come up, as a word that fits on the screen. Empty if it did.
static mut INIT_FAULT: &str = "";

fn set_init_fault(why: &'static str) {
    // SAFETY: written once during bring-up, before anything else can read it; the boot
    // path is single-threaded and no interrupt touches it.
    unsafe { *core::ptr::addr_of_mut!(INIT_FAULT) = why }
}

/// Why USB did not come up, or `""`.
pub fn init_fault() -> &'static str {
    // SAFETY: as above -- written once, read after.
    unsafe { *core::ptr::addr_of!(INIT_FAULT) }
}

/// The task, if USB came up.
///
/// # Panics
/// Never. Returns `None` on a board without USB or where the core would not start.
fn task() -> Option<&'static mut UsbTask> {
    // SAFETY: the boot path is single-threaded, nothing here runs in interrupt context,
    // and no two of these references are live at once -- every caller uses it and drops
    // it within one statement.
    unsafe { (*core::ptr::addr_of_mut!(TASK)).as_mut() }
}

/// Tell a host whether the device has a PIN at all.
pub fn set_blank(blank: bool) {
    if let Some(t) = task() {
        t.set_blank(blank);
    }
}

/// Let the host offer upgrades, now that the PIN has been entered.
pub fn unlocked() {
    if let Some(t) = task() {
        t.set_unlocked();
    }
}

/// An upgrade waiting to be approved at the screen.
pub fn pending() -> Option<Approval> {
    task().and_then(|t| t.pending().cloned())
}

/// Approve the staged upgrade, publishing the bootloader's marker.
pub fn approve() -> Result<catcard_upgrade::Region, Reject> {
    match task() {
        Some(t) => t.approve(),
        None => Err(Reject::NotAnImage),
    }
}

/// Decline it, leaving nothing staged.
pub fn decline() {
    if let Some(t) = task() {
        t.decline();
    }
}

/// Counters mirrored into RAM, where a dump can read them.
///
/// The screen is the natural place for this and it works — but only when the emulator
/// drives USB itself. In socket mode it emits no screens at all, which is exactly the
/// mode a real host protocol has to be debugged in. So the same numbers go somewhere
/// `--dump-ram` can reach.
///
/// `#[used]` and `#[no_mangle]` keep it in the image and findable by name at
/// `opt-level = "s"` with LTO, the same as the boot status.
#[no_mangle]
#[used]
pub static mut CATCARD_USB_STATUS: UsbStatus = UsbStatus {
    magic: USB_STATUS_MAGIC,
    configured: 0,
    reports_in: 0,
    replies_out: 0,
    outbox_pending: 0,
    frame_errors: 0,
    staged_bytes: 0,
    last_status: 0,
    regs: [0; 6],
    rearms: 0,
};

pub const USB_STATUS_MAGIC: u32 = 0xCA7C_05B0;

#[repr(C)]
pub struct UsbStatus {
    pub magic: u32,
    pub configured: u32,
    pub reports_in: u32,
    pub replies_out: u32,
    pub outbox_pending: u32,
    pub frame_errors: u32,
    pub staged_bytes: u32,
    /// The last status code we answered with, so a refusal is visible without a screen.
    pub last_status: u32,
    /// `[GINTSTS, DAINT, DOEPCTL(out), DOEPTSIZ(out), DIEPCTL(in)]`.
    pub regs: [u32; 6],
    /// Times the OUT endpoint has been armed.
    pub rearms: u32,
}

/// Copy the counters into the dumpable static.
fn publish_status(t: &UsbTask) {
    let s = UsbStatus {
        magic: USB_STATUS_MAGIC,
        configured: t.otg.is_configured() as u32,
        reports_in: t.rx_count,
        replies_out: t.tx_count,
        outbox_pending: t.outbox_len as u32,
        frame_errors: t.frame_errors,
        staged_bytes: match &t.stage {
            Stage::Receiving(s) => s.received(),
            Stage::Offered { staged, .. } => staged.received(),
            _ => 0,
        },
        last_status: t.last_status as u32,
        // SAFETY: the task owns OTG_FS; these are plain register reads.
        regs: unsafe { t.otg.debug_regs() },
        rearms: t.otg.rearms,
    };
    // SAFETY: single-threaded foreground, and this is the only writer.
    unsafe { core::ptr::write_volatile(core::ptr::addr_of_mut!(CATCARD_USB_STATUS), s) };
}

/// USB state, for the idle screen.
///
/// `(configured, reports in, replies out, a reply is queued)`. Four numbers is enough to
/// tell "the host is not talking to us" from "we are not answering" from "we answered
/// and it did not go out", which are three very different bugs that look identical from
/// the outside.
pub fn stats() -> (bool, u32, u32, bool) {
    match task() {
        Some(t) => (
            t.otg.is_configured(),
            t.rx_count,
            t.tx_count,
            t.outbox_len > 0,
        ),
        None => (false, 0, 0, false),
    }
}

/// A key a host has pressed, if any. Consumes it.
///
/// Returns `None` on a build without `usb-key-injection`, so every caller compiles
/// either way and the feature is one line in `Cargo.toml` rather than a thread through
/// the UI.
pub fn take_injected_key() -> Option<catcard_ui::keypad::Key> {
    #[cfg(not(feature = "usb-key-injection"))]
    {
        None
    }
    #[cfg(feature = "usb-key-injection")]
    {
        use catcard_ui::keypad::Key;
        let t = task()?;
        let k = t.injected.take()?;
        Some(match k {
            catcard_usb::KEY_CANCEL => Key::Cancel,
            catcard_usb::KEY_CONFIRM => Key::Confirm,
            d => Key::Digit(d),
        })
    }
}

/// Whether this build accepts injected keys, for the screen to say so.
pub const KEY_INJECTION: bool = cfg!(feature = "usb-key-injection");
