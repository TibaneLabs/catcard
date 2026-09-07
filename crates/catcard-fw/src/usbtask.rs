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

use crate::{BOARD_NAME, VERSION};

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
    /// Whether the PIN has been entered. Gates the upgrade opcodes only.
    unlocked: bool,
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
        let otg = unsafe { Otg::init(BOARD.usb.dm, BOARD.usb.dp, serial) }.ok()?;
        Some(Self {
            otg,
            unlocked: false,
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
    pub fn approve(&mut self) -> Result<(), Reject> {
        let stage = core::mem::replace(&mut self.stage, Stage::Idle);
        let Stage::Offered { staged, approval } = stage else {
            return Err(Reject::Incomplete { have: 0, want: 0 });
        };
        staged.commit(approval)?;
        self.stage = Stage::Approved;
        Ok(())
    }

    /// The user declined. The staged image is dropped without being marked.
    pub fn decline(&mut self) {
        self.stage = Stage::Idle;
        self.begin_reply(Status::Declined, &[]);
    }

    /// Service USB once. Returns whether anything happened.
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
                    let mut report = [0u8; REPORT_LEN];
                    report.copy_from_slice(&self.otg.rx);
                    self.otg.receive_next();
                    self.on_report(&report);
                }
                _ => {}
            }
            event != Event::Idle
        }
    }

    /// # Safety
    /// Exclusive access to OTG_FS.
    unsafe fn drain_outbox(&mut self) {
        // SAFETY: as documented.
        unsafe {
            if self.outbox_len > 0 && self.otg.send(&self.outbox) {
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
            Some(Opcode::Ping) => {
                let n = progress.payload.len().min(64);
                let mut body = [0u8; 64];
                body[..n].copy_from_slice(&progress.payload[..n]);
                self.begin_reply(Status::Ok, &body[..n]);
            }
            Some(Opcode::Identify) => self.identify(),
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
                self.stage = Stage::Offered { staged, approval };
                self.begin_reply(Status::Ok, &body[..n]);
            }
            Err(r) => self.refuse(r),
        }
    }

    fn identify(&mut self) {
        // Fixed layout rather than a text blob, so a host does not have to parse prose:
        //   [0..2] protocol version
        //   [2]    board name length, then the name
        //   then   version string length, then the version
        let mut body = [0u8; 64];
        let mut at = 0;
        body[at..at + 2].copy_from_slice(&PROTOCOL_VERSION.to_le_bytes());
        at += 2;
        for s in [BOARD_NAME, VERSION] {
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
        let mut buf = [0u8; 64];
        let n = body.len().min(64);
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
        // Replies are at most 64 bytes, so they always fit one frame. The loop shape is
        // kept so a longer reply later cannot silently lose its tail.
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
    22
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
        Reject::Downgrade => 9,
        Reject::BadSignature => 10,
        Reject::StorageFault { .. } => 11,
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
    if BOARD.psram.is_none() {
        // Nowhere to stage an upgrade, so nothing to serve.
        return;
    }
    // SAFETY: single-threaded bring-up; this is the only writer and no reader exists
    // until it returns.
    unsafe {
        let task = UsbTask::init(serial);
        core::ptr::addr_of_mut!(TASK).write(task);
    }
}

/// Consecutive polls that found nothing, for the idle backoff.
static mut QUIET: u32 = 0;

/// Polls of nothing before we stop spinning at full speed.
const QUIET_BEFORE_BACKOFF: u32 = 256;
/// How long to pause between polls once quiet. Short enough to be invisible against a
/// 1 ms USB frame, long enough to stop the loop reading a register a million times a
/// second for no reason.
const BACKOFF_CYCLES: u32 = 400;

/// Service USB. Safe to call from anywhere in the foreground.
///
/// Backs off when idle. A poll loop with no pause in it reads `GINTSTS` continuously
/// and burns the core at full tilt for as long as the device is switched on and doing
/// nothing, which is the normal state of a wallet. The pause is far shorter than the
/// 1 ms between USB frames, so it costs no throughput; the counter resets the moment
/// anything happens, and a transfer runs at full speed.
pub fn pump() {
    let Some(t) = task() else { return };
    // SAFETY: the task owns OTG_FS for the life of the firmware, and nothing runs in
    // interrupt context.
    let busy = unsafe { t.poll() };
    // SAFETY: single-threaded foreground; this is the only accessor.
    let quiet = unsafe { &mut *core::ptr::addr_of_mut!(QUIET) };
    if busy {
        *quiet = 0;
    } else {
        *quiet = quiet.saturating_add(1);
        if *quiet > QUIET_BEFORE_BACKOFF {
            catcard_hal::dwt::delay_cycles(BACKOFF_CYCLES);
        }
    }
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
pub fn approve() -> Result<(), Reject> {
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
