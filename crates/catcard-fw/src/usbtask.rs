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

use core::sync::atomic::{AtomicBool, Ordering};

use catcard_board::BOARD;
use catcard_hal::otg::{Event, Otg};
use catcard_upgrade::{Approval, Reject, Staged};

use crate::staging;
use catcard_usb::{FrameError, Opcode, PROTOCOL_VERSION, REPORT_LEN, Reassembler, Status, Writer};

use crate::VERSION;
#[cfg(feature = "usb-debug-mem")]
use crate::debug_mem;

/// What the task is in the middle of.
enum Stage {
    Idle,
    /// An image is arriving.
    Receiving(Staged<'static, staging::Area>),
    /// An image arrived and passed inspection; the user has not yet been asked.
    Offered {
        staged: Staged<'static, staging::Area>,
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
    /// A whole PIN a host has submitted with [`Opcode::UnlockPin`], waiting for the
    /// login loop to drive it through the gate. `prefix-suffix` ASCII, unparsed.
    #[cfg(feature = "usb-key-injection")]
    unlock_pin: Option<heapless::Vec<u8, 33>>,
    /// Reports taken from the host, and replies handed back. Shown on the idle screen
    /// because the emulator decodes that screen to text, which makes it the only
    /// diagnostic channel this firmware has that needs no debugger.
    rx_count: u32,
    tx_count: u32,
    frame_errors: u32,
    last_status: u16,
    /// Consecutive polls seen while not configured. When it crosses
    /// [`USB_STUCK_POLLS`] the core is re-initialised: enumeration that never completes
    /// -- a host that attached before we were ready, a core wedged by a callgate landing
    /// mid-enumeration -- only recovers from a fresh core reset, not from more polling.
    /// Reset to zero the moment the host configures us, so a working link never triggers
    /// it and it costs a healthy device nothing.
    stuck: u32,
    /// Whether the host has *ever* configured us. The self-heal below is only for the
    /// boot-time enumeration wedge -- a core that never reaches "configured" the first
    /// time -- so once it has, the self-heal is switched off for good. Leaving it armed
    /// meant a device whose bus later goes idle/suspended (and, on the mk3 L496 OTG,
    /// appears to signal a bus reset when it does) would keep re-`reinit`-ing, and each
    /// `reinit` runs a blocking `core_reset` that stalls the foreground -- which on mk3
    /// starved the keypad scan enough to look dead. A once-enumerated core does not need
    /// re-healing; a real later disconnect is the host's to re-drive.
    ever_configured: bool,
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
    /// Bulk-OUT packets the OTG interrupt has received in mass-storage mode, waiting for
    /// the transport loop to consume them. Empty and idle in polled HID mode.
    msc_rx: MscRx,
}

/// A single-producer/single-consumer ring of received bulk-OUT packets: the OTG interrupt
/// fills it, the [`msc_poll`] foreground drains it. Sized to hold more than a 512-byte
/// block's eight packets so a burst arriving while the foreground is mid-SD-write is
/// absorbed; when it does fill, the interrupt stops re-arming the endpoint (the host is
/// NAKed) until the foreground drains a slot -- back-pressure, not loss.
struct MscRx {
    buf: [[u8; REPORT_LEN]; MSC_RXQ],
    len: [u8; MSC_RXQ],
    head: usize,
    tail: usize,
}

/// Slots in the mass-storage receive ring.
const MSC_RXQ: usize = 20;

impl MscRx {
    const fn new() -> Self {
        Self {
            buf: [[0; REPORT_LEN]; MSC_RXQ],
            len: [0; MSC_RXQ],
            head: 0,
            tail: 0,
        }
    }

    fn is_empty(&self) -> bool {
        self.head == self.tail
    }

    fn is_full(&self) -> bool {
        (self.head + 1) % MSC_RXQ == self.tail
    }

    fn clear(&mut self) {
        self.head = 0;
        self.tail = 0;
    }

    /// Producer (interrupt). The caller has checked the ring is not full.
    fn push(&mut self, data: &[u8]) {
        let n = data.len().min(REPORT_LEN);
        self.buf[self.head][..n].copy_from_slice(&data[..n]);
        self.len[self.head] = n as u8;
        self.head = (self.head + 1) % MSC_RXQ;
    }

    /// Consumer (foreground). Copies the oldest packet into `out`, or `None` if empty.
    fn pop(&mut self, out: &mut [u8]) -> Option<usize> {
        if self.is_empty() {
            return None;
        }
        let n = (self.len[self.tail] as usize).min(out.len());
        out[..n].copy_from_slice(&self.buf[self.tail][..n]);
        self.tail = (self.tail + 1) % MSC_RXQ;
        Some(n)
    }
}

/// Whether the USB Drive screen drives mass storage from the OTG interrupt (true) or the
/// foreground poll (false). HID is polled either way.
///
/// **Polled for now.** In interrupt mode the EP0 control transfers -- including the whole
/// enumeration -- are serviced only by the OTG ISR, and on hardware that path never
/// answered them: the host re-enumerated the drive but timed out reading its device
/// descriptor. The polled path drives `otg.poll()` (control *and* bulk) from the
/// foreground loop, exactly like the HID path that enumerates reliably, so it is the
/// working transport. The interrupt path stays behind this toggle until its EP0 servicing
/// is sorted out.
const MSC_INTERRUPTS: bool = false;

/// How long to hold the soft-disconnect when switching USB identity (HID <-> mass storage),
/// so the host debounces the disconnect and re-enumerates. A few milliseconds is enough by
/// the USB spec; 20 ms leaves margin across host controllers.
const REENUM_DETACH_MS: u32 = 20;

/// A response being sent out, frame by frame.
/// A reply in flight, possibly spanning several frames.
///
/// The body is held rather than a live `Writer`, because a writer borrows the payload and
/// would make this self-referential. The framing state travels alongside it so each
/// `next_reply_frame` resumes where the last left off. Sized for a bulk peek: a debug
/// read that could only return one frame would not be worth having.
struct ReplyState {
    status: Status,
    body: [u8; REPLY_MAX],
    len: usize,
    /// Framing progress: bytes sent, next sequence number, whether the START frame went.
    sent: usize,
    seq: u8,
    started: bool,
}

/// Largest reply body. Enough for a useful peek without making the task struct heavy.
const REPLY_MAX: usize = 512;

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
            #[cfg(feature = "usb-key-injection")]
            unlock_pin: None,
            rx_count: 0,
            tx_count: 0,
            frame_errors: 0,
            last_status: 0,
            unlocked: false,
            blank: false,
            stuck: 0,
            ever_configured: false,
            frames: Reassembler::new(),
            stage: Stage::Idle,
            outbox: [0; REPORT_LEN],
            outbox_len: 0,
            reply: None,
            msc_rx: MscRx::new(),
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
                    led::saw_traffic();
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

            // Self-heal a core that will not enumerate. Enumeration only ever completes
            // during a foreground poll loop; if it has not after `USB_STUCK_POLLS`
            // consecutive not-configured polls, the core is wedged (attached but not
            // enumerating a late reset) and a fresh core reset is the only thing that
            // recovers it. A configured link resets the counter, so this is free for a
            // healthy device and only ever fires when USB is genuinely down.
            if self.otg.is_configured() {
                self.stuck = 0;
                self.ever_configured = true;
            } else if !self.ever_configured {
                // Only heal the *first* enumeration. After the host has configured us once,
                // a later un-configured stretch is idle/suspend or a real unplug, not a
                // wedge -- re-`reinit`-ing there only churns and blocks the foreground.
                self.stuck = self.stuck.saturating_add(1);
                if self.stuck >= USB_STUCK_POLLS {
                    self.stuck = 0;
                    // SAFETY: the task owns OTG_FS for the life of the firmware; already
                    // inside this function's `unsafe` block.
                    self.otg.reinit();
                }
            }

            event != Event::Idle || self.outbox_len > 0
        }
    }

    /// Service the OTG core from interrupt context -- mass-storage mode only.
    ///
    /// Drains every pending event in one entry: the interrupt is level-triggered on the
    /// OR of the unmasked sources, so leaving one pending re-fires at once. A received
    /// bulk-OUT / CBW packet is queued for the transport loop and the OUT endpoint
    /// re-armed only while the ring has room (back-pressure otherwise); enumeration and
    /// resets are answered in place by [`poll`](Self::poll). The SD card is never touched
    /// here -- that is the foreground's work and far too long for an interrupt.
    ///
    /// # Safety
    /// Runs as the OTG interrupt handler; the foreground touches the core only inside
    /// `interrupt::free`, so the handler and the foreground never alias the task.
    unsafe fn service_irq(&mut self) {
        // SAFETY: as documented.
        unsafe {
            loop {
                match self.otg.poll() {
                    Event::Report => {
                        // The endpoint is armed only while the ring has room, so a Report
                        // should always fit. Guard anyway: never overwrite an unread slot.
                        // If it is somehow full, drop the packet and leave the endpoint
                        // un-armed -- the host recovers via reset -- rather than corrupt
                        // the ring. Copy out first: `report` borrows the core.
                        if !self.msc_rx.is_full() {
                            let mut pkt = [0u8; REPORT_LEN];
                            let n = {
                                let rx = self.otg.report();
                                let n = rx.len().min(REPORT_LEN);
                                pkt[..n].copy_from_slice(&rx[..n]);
                                n
                            };
                            self.msc_rx.push(&pkt[..n]);
                            // Re-arm only while there is still room for the next packet.
                            if !self.msc_rx.is_full() {
                                self.otg.receive_next();
                            }
                        }
                    }
                    // A bus reset voids anything queued: a fresh CBW must not be read as
                    // the tail of an abandoned transfer.
                    Event::Reset => self.msc_rx.clear(),
                    Event::Idle => break,
                }
            }
        }
    }

    /// # Safety
    /// Exclusive access to OTG_FS.
    unsafe fn drain_outbox(&mut self) {
        // SAFETY: as documented.
        unsafe {
            if self.outbox_len > 0 && self.otg.send(&self.outbox) {
                self.tx_count = self.tx_count.saturating_add(1);
                led::saw_traffic();
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
                Some(Opcode::UpgradeOffer) => {
                    // Claim the board's staging area (PSRAM on mk4/mk5/Q1, SPI-NOR on mk3).
                    // `None` -- no medium, or the SPI-NOR did not answer -- is refused on
                    // this first frame rather than after 256 KB have crossed the wire.
                    // Drop whatever this task was holding first: a host re-offering after
                    // a failed attempt is the same holder coming back, not a second one.
                    // Anything *else* holding the medium -- a card image waiting on the
                    // approval screen -- is refused, which is the point.
                    self.stage = Stage::Idle;
                    let area = match staging::area() {
                        Ok(a) => a,
                        Err(why) => {
                            self.frames.reset();
                            self.refuse(match why {
                                staging::Unavailable::NoMedium => Reject::NoStagingArea,
                                staging::Unavailable::Busy => Reject::StagingBusy,
                            });
                            return;
                        }
                    };
                    match Staged::begin(area, &BOARD, msg.total) {
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
                // `at` is the stage's own count and the payload is what just arrived, so a
                // storage fault here means the region itself was not what `begin` checked.
                crate::catlog!(
                    "upgrade: write failed at {} len {}",
                    at,
                    progress.payload.len()
                );
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
            #[cfg(feature = "usb-debug-mem")]
            Some(Opcode::DebugPeek) => {
                let p = progress.payload;
                if p.len() < 6 {
                    self.begin_reply(Status::BadRequest, &[]);
                } else {
                    let addr = u32::from_le_bytes([p[0], p[1], p[2], p[3]]);
                    let (width, count) = (p[4], p[5]);
                    let mut body = [0u8; REPLY_MAX];
                    match debug_mem::peek(addr, width, count, &mut body) {
                        Some(n) => {
                            crate::catlog!("peek {:#010x} w{} x{}", addr, width, count);
                            self.begin_reply(Status::Ok, &body[..n]);
                        }
                        None => self.begin_reply(Status::BadRequest, &[]),
                    }
                }
            }
            #[cfg(feature = "usb-debug-mem")]
            Some(Opcode::DebugPoke) => {
                let p = progress.payload;
                if p.len() < 5 {
                    self.begin_reply(Status::BadRequest, &[]);
                } else {
                    let addr = u32::from_le_bytes([p[0], p[1], p[2], p[3]]);
                    let width = p[4];
                    match debug_mem::poke(addr, width, &p[5..]) {
                        true => {
                            crate::catlog!("poke {:#010x} w{} +{}", addr, width, p.len() - 5);
                            self.begin_reply(Status::Ok, &[]);
                        }
                        false => self.begin_reply(Status::BadRequest, &[]),
                    }
                }
            }
            #[cfg(feature = "usb-debug-mem")]
            Some(Opcode::DebugJsr) => {
                let p = progress.payload;
                if p.len() < 8 {
                    self.begin_reply(Status::BadRequest, &[]);
                } else {
                    let addr = u32::from_le_bytes([p[0], p[1], p[2], p[3]]);
                    let arg = u32::from_le_bytes([p[4], p[5], p[6], p[7]]);
                    // Logged BEFORE the call: if it does not return, this is the last
                    // thing in the log, which is exactly what says what was run.
                    crate::catlog!("jsr {:#010x} arg {:#010x}", addr, arg);
                    let ret = debug_mem::jsr(addr, arg);
                    crate::catlog!("jsr returned {:#010x}", ret);
                    self.begin_reply(Status::Ok, &ret.to_le_bytes());
                }
            }
            #[cfg(feature = "usb-debug-mem")]
            Some(Opcode::DebugSd) => {
                let (phase, sta, dcount) = sd_diag();
                let mut body = [0u8; 9];
                body[0] = phase;
                body[1..5].copy_from_slice(&sta.to_le_bytes());
                body[5..9].copy_from_slice(&dcount.to_le_bytes());
                self.begin_reply(Status::Ok, &body);
            }
            #[cfg(not(feature = "usb-debug-mem"))]
            Some(Opcode::DebugPeek | Opcode::DebugPoke | Opcode::DebugJsr | Opcode::DebugSd) => {
                self.begin_reply(Status::UnknownOpcode, &[]);
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
            #[cfg(feature = "usb-key-injection")]
            Some(Opcode::UnlockPin) => {
                // Stash it; the login loop consumes it and answers with the UNLOCKED
                // state bit on the next Identify. Ok here means only "accepted".
                let p = progress.payload;
                if p.is_empty() || p.len() > 33 {
                    self.begin_reply(Status::BadRequest, &[]);
                } else {
                    let mut v = heapless::Vec::new();
                    let _ = v.extend_from_slice(p);
                    self.unlock_pin = Some(v);
                    self.begin_reply(Status::Ok, &[]);
                }
            }
            #[cfg(not(feature = "usb-key-injection"))]
            Some(Opcode::UnlockPin) => self.begin_reply(Status::UnknownOpcode, &[]),
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
            Err(r) => {
                // Say what the image claimed and what the staging area actually holds. A
                // bare "BadSignature" covers a corrupt transfer, a staging area that lost
                // bytes and an image that really is not signed -- and the difference is
                // the whole diagnosis. The SD path has said this for a while; the USB path
                // refusing in silence is what turned one afternoon into two.
                if let Some(h) = staged.header() {
                    crate::catlog!(
                        "usb: image claims key {} len {} hw_compat {:#x}",
                        h.pubkey_num,
                        h.firmware_length,
                        h.hw_compat
                    );
                }
                if let Ok(d) = staged.digest() {
                    crate::catlog!(
                        "usb: staged digest {:02x}{:02x}{:02x}{:02x}, {} bytes received",
                        d[0],
                        d[1],
                        d[2],
                        d[3],
                        staged.received()
                    );
                }
                let mut head = [0u8; 8];
                if staged.sample(0, &mut head).is_ok() {
                    crate::catlog!(
                        "usb: staged head {:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
                        head[0],
                        head[1],
                        head[2],
                        head[3],
                        head[4],
                        head[5],
                        head[6],
                        head[7]
                    );
                }
                self.refuse(r)
            }
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
            catcard_usb::caps::KEY_INJECTION | catcard_usb::caps::UNLOCK_PIN
        } else {
            0
        } | if staging::has_staging() {
            catcard_usb::caps::UPGRADE
        } else {
            0
        } | if cfg!(feature = "usb-debug-mem") {
            catcard_usb::caps::DEBUG_MEM
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
        // The host gets a one-byte code; the details -- an offset, a length, which key --
        // were thrown away. They are exactly what a refused install needs to be diagnosed,
        // and the log is where a host can read them back.
        crate::catlog!("upgrade: refused {:?}", reason);
        let mut body = [0u8; 64];
        let n = describe_reject(&reason, &mut body);
        self.begin_reply(Status::Refused, &body[..n]);
    }

    fn begin_reply(&mut self, status: Status, body: &[u8]) {
        self.last_status = status as u16;
        let mut buf = [0u8; REPLY_MAX];
        // A reply may span several frames now, so a body is clamped only to the buffer,
        // not to one frame. (It used to be clamped to one frame because the reply writer
        // was rebuilt each frame and never advanced -- fixed by carrying its state.)
        let n = body.len().min(REPLY_MAX);
        buf[..n].copy_from_slice(&body[..n]);
        self.reply = Some(ReplyState {
            status,
            body: buf,
            len: n,
            sent: 0,
            seq: 0,
            started: false,
        });
        self.next_reply_frame();
    }

    /// Move the next frame of the current reply into the outbox.
    fn next_reply_frame(&mut self) {
        let Some(r) = &mut self.reply else { return };
        // Resume from the saved framing state rather than rebuilding at frame zero, which
        // is what capped every reply at one frame. The writer borrows the body only for
        // this call, so nothing is self-referential.
        let mut w = Writer::resume(r.status, &r.body[..r.len], r.sent, r.seq, r.started);
        if w.next(&mut self.outbox) {
            self.outbox_len = REPORT_LEN;
            let (sent, seq, started) = w.state();
            r.sent = sent;
            r.seq = seq;
            r.started = started;
        } else {
            self.reply = None;
        }
    }
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
        Reject::StagingBusy => 13,
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
    // The activity light, on the boards that have one. Set up here rather than in
    // bring-up because it is USB's, and because a light that blinks before USB exists
    // would be reporting something it cannot know.
    // SAFETY: single-threaded bring-up; the pin belongs to the LED alone.
    unsafe { led::init() };
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

/// Consecutive not-configured polls before the USB core is re-initialised. At roughly
/// one poll per [`IDLE_PAUSE_CYCLES`] in the foreground loops this is on the order of a
/// second -- long enough that a real enumeration (tens of ms) always finishes first, so
/// the re-init only fires when the link is genuinely stuck.
const USB_STUCK_POLLS: u32 = 1_500;

/// Service USB. Safe to call from anywhere in the foreground.
///
/// Returns whether anything happened, so a caller can decide how hard to spin.
///
/// **Once a USB service task exists, this does nothing.** Every waiting loop in the menu
/// calls it, and under the kernel those loops would otherwise poll the core concurrently
/// with the task that now owns it. So [`start_service`] turns every one of those call
/// sites into a no-op at once, and only [`service`] polls.
pub fn pump() -> bool {
    if SERVICE.load(Ordering::Relaxed) {
        return false;
    }
    poll_once()
}

/// Whether a dedicated task services USB, making [`pump`] a no-op everywhere else.
static SERVICE: AtomicBool = AtomicBool::new(false);

/// Whether the USB Drive screen has the core in mass-storage mode. It drives the transport
/// itself through the `msc_*` functions, and a HID poll from the service task in the
/// meantime would take its packets.
static MSC_ACTIVE: AtomicBool = AtomicBool::new(false);

/// Hand USB to a dedicated task. Irreversible, like the kernel it runs under.
pub fn start_service() {
    SERVICE.store(true, Ordering::Relaxed);
}

/// The USB service task's loop body: poll the core, then tick the activity light and the
/// power button.
///
/// This is the payoff of a dedicated task. Under [`pump`], the light and -- more to the
/// point -- the power button only responded while whatever screen was up happened to be
/// waiting; a screen busy computing silenced both. Here they run every scheduling round,
/// whatever the menu is doing.
pub fn service() -> bool {
    poll_once()
}

fn poll_once() -> bool {
    let busy = if MSC_ACTIVE.load(Ordering::Relaxed) {
        false
    } else {
        with_task(|t| {
            // SAFETY: the task owns OTG_FS for the life of the firmware, and the scheduler
            // lock `with_task` holds keeps every other task out.
            let busy = unsafe { t.poll() };
            publish_status(t);
            busy
        })
        .unwrap_or(false)
    };
    led::tick();
    // The power button rides here for the same reason the activity light does: this is
    // the one place that runs no matter which screen is up -- the PIN prompt and the seed
    // backup included.
    crate::power::tick();
    busy
}

/// The USB activity light.
///
/// `USB_ACTIVE` is a plain GPIO with no hardware activity detection behind it, so the
/// firmware has to blink it or it stays dark — which is exactly what ours did. Three
/// pieces are needed and the reference is explicit that missing any one leaves the
/// light off: configure the pin, raise a flag on real traffic, and tick.
///
/// Stock runs the tick off a 150 ms soft timer. Ours is polled instead, because our USB
/// is: [`tick`] is called from [`pump`], and every screen that waits pumps. The cost of
/// that choice is that a screen which stopped pumping would freeze the light mid-blink,
/// so the idle branch drives the pin **low** rather than leaving it wherever it landed.
///
/// Source: usb.md §"USB activity LED" [C]
mod led {
    use catcard_board::BOARD;
    use catcard_hal::gpio::{self, Mode, OutputType, Pull, Speed};
    use core::sync::atomic::{AtomicBool, AtomicU32, Ordering};

    /// Traffic happened since the last tick. Set at the RX and TX counters, so it
    /// tracks packets that actually moved rather than polls that found nothing.
    static SAW: AtomicBool = AtomicBool::new(false);
    /// Cycle count at the last tick, and the period in cycles. Zero period means the
    /// board has no LED, or it has not been set up.
    static LAST: AtomicU32 = AtomicU32::new(0);
    static PERIOD: AtomicU32 = AtomicU32::new(0);
    /// What the pin is currently driven to, so a toggle does not need to read it back.
    static LIT: AtomicBool = AtomicBool::new(false);

    /// Note that a packet moved. Cheap enough to call on every one.
    pub fn saw_traffic() {
        SAW.store(true, Ordering::Relaxed);
    }

    /// Configure the pin and start the timer.
    ///
    /// # Safety
    /// Single-threaded bring-up; the pin belongs to the LED alone, which the board
    /// table's pin-conflict test enforces.
    pub unsafe fn init() {
        let Some(pin) = BOARD.usb_active else { return };
        // SAFETY: as documented; forwarding the board's own pin assignment.
        unsafe {
            gpio::enable_port(pin.port);
            gpio::configure(
                pin,
                Mode::Output,
                OutputType::PushPull,
                Pull::None,
                Speed::Low,
            );
            gpio::write(pin, false);
        }
        // 150 ms in cycles, from the clock the bootloader actually left running rather
        // than an assumed one. SAFETY: reads RCC.
        let hz = unsafe { catcard_hal::clock::hclk_hz() };
        PERIOD.store((hz / 1000).saturating_mul(150).max(1), Ordering::Relaxed);
        LAST.store(catcard_hal::dwt::cycles(), Ordering::Relaxed);
        LIT.store(false, Ordering::Relaxed);
    }

    /// Toggle if traffic happened in this window, otherwise go dark.
    pub fn tick() {
        let period = PERIOD.load(Ordering::Relaxed);
        if period == 0 {
            return;
        }
        let Some(pin) = BOARD.usb_active else { return };
        let now = catcard_hal::dwt::cycles();
        if now.wrapping_sub(LAST.load(Ordering::Relaxed)) < period {
            return;
        }
        LAST.store(now, Ordering::Relaxed);

        // Read *and clear*: the light reports the window just gone, not everything since
        // boot, which is what makes it go out when the host stops talking.
        let lit = if SAW.swap(false, Ordering::Relaxed) {
            !LIT.load(Ordering::Relaxed)
        } else {
            false
        };
        LIT.store(lit, Ordering::Relaxed);
        // SAFETY: `init` configured this pin as an output and nothing else drives it.
        unsafe { gpio::write(pin, lit) };
    }
}

/// Attach USB to the bus.
///
/// [`init`] brings the core up soft-disconnected; this presents it to the host. Call it
/// only from a loop that then services USB by calling [`pump`] -- so the host's first
/// enumeration is answered immediately rather than lost to a blocking callgate. Safe to
/// call more than once. No-op if USB never came up.
pub fn attach() {
    // SAFETY: the task owns OTG_FS for the life of the firmware; the lock excludes other
    // tasks and nothing runs in interrupt context.
    with_task(|t| unsafe { t.otg.attach() });
}

// ---------------------------------------------------------------------------
// Mass-storage mode
//
// Used only by the USB Drive screen: it switches the device's identity to a USB disk,
// runs the Bulk-Only Transport loop against the SD card, and switches back on exit. The
// HID protocol is unavailable for the duration -- the device is a drive, not a wallet.
// ---------------------------------------------------------------------------

/// The OTG_FS interrupt, dispatched from [`crate::interrupts`]. Services the core in
/// mass-storage mode; it is enabled only while the USB Drive screen is open.
pub fn on_otg_interrupt() {
    // Not `with_task`: an interrupt cannot take the scheduler lock, and the lock would not
    // exclude it anyway. Its own guarantee is the one below.
    if let Some(t) = task_from_isr() {
        // SAFETY: interrupt context. The foreground touches the core only inside
        // `interrupt::free`, so this handler is the sole accessor while it runs.
        unsafe { t.service_irq() };
    }
}

/// Re-enumerate as a USB mass-storage device, and (in interrupt mode) hand the transport
/// to the OTG interrupt.
pub fn msc_enter() {
    // Stand the service task down before the core changes identity under it.
    MSC_ACTIVE.store(true, Ordering::Relaxed);
    with_task(|t| {
        // SAFETY: the task owns OTG_FS; the lock excludes other tasks, interrupt still off.
        unsafe {
            t.msc_rx.clear();
            t.otg.set_mode(catcard_usb::control::DeviceMode::Msc);
            // Force the host to re-enumerate: drop off the bus, hold long enough for it to
            // register the disconnect, then reconfigure and re-attach so it reads the new
            // mass-storage descriptors. Without the detach it keeps the cached HID device
            // and never sees the drive appear.
            t.otg.detach();
            catcard_hal::dwt::delay_ms(REENUM_DETACH_MS);
            t.otg.reinit();
            if MSC_INTERRUPTS {
                // Open the core's gate, then the NVIC line. From here the handler drives
                // the transport and the foreground reaches the core only through the
                // `msc_*` functions below, each inside `interrupt::free`.
                t.otg.enable_interrupts();
                crate::interrupts::enable_otg();
            }
        }
    });
}

/// Re-enumerate back as the HID wallet device, returning to fully polled operation.
pub fn msc_exit() {
    with_task(|t| {
        // SAFETY: as in `msc_enter`.
        unsafe {
            if MSC_INTERRUPTS {
                // Shut the line first, so no handler runs during the switch; HID never
                // re-opens it.
                crate::interrupts::disable_otg();
                t.otg.disable_interrupts();
            }
            t.otg.set_mode(catcard_usb::control::DeviceMode::Hid);
            // Re-enumerate back to the HID wallet the same way: a visible disconnect, a
            // pause, then re-attach with the HID descriptors.
            t.otg.detach();
            catcard_hal::dwt::delay_ms(REENUM_DETACH_MS);
            t.otg.reinit();
        }
    });
    // Only once the core is back to HID may the service task poll it again.
    MSC_ACTIVE.store(false, Ordering::Relaxed);
}

/// Take the next bulk-OUT packet in mass-storage mode. In interrupt mode this drains the
/// ring the handler fills, re-opening the endpoint if the ring had backed up; in polled
/// mode it services the core inline. `None` if nothing is waiting.
pub fn msc_poll(out: &mut [u8]) -> Option<usize> {
    if MSC_INTERRUPTS {
        // Keep the handler out while we touch the shared ring and the core.
        cortex_m::interrupt::free(|_| {
            with_task(|t| {
                let was_full = t.msc_rx.is_full();
                let got = t.msc_rx.pop(out);
                if got.is_some() && was_full {
                    // A slot opened after back-pressure; let the host send the next packet.
                    // SAFETY: interrupts masked here, so the handler cannot also re-arm; the
                    // task owns OTG_FS.
                    unsafe { t.otg.receive_next() };
                }
                got
            })
            .flatten()
        })
    } else {
        with_task(|t| {
            // SAFETY: polled mode -- no interrupt context; the task owns OTG_FS.
            unsafe {
                if matches!(t.otg.poll(), Event::Report) {
                    let n = {
                        let rx = t.otg.report();
                        let n = rx.len().min(out.len());
                        out[..n].copy_from_slice(&rx[..n]);
                        n
                    };
                    t.otg.receive_next();
                    return Some(n);
                }
            }
            None
        })
        .flatten()
    }
}

/// Send one bulk-IN packet (up to 64 bytes). Returns false if the endpoint is busy or the
/// FIFO is full; retry after another [`msc_poll`]. Wrapped so it never races the handler.
pub fn msc_send(data: &[u8]) -> bool {
    let send = |t: &mut UsbTask| unsafe { t.otg.bulk_send(data) };
    if MSC_INTERRUPTS {
        cortex_m::interrupt::free(|_| with_task(send).unwrap_or(false))
    } else {
        with_task(send).unwrap_or(false)
    }
}

/// Whether the host issued a Bulk-Only Mass Storage Reset that the transport loop has
/// not yet acted on. Peeks without clearing, so a data phase can bail early.
pub fn msc_reset_pending() -> bool {
    if MSC_INTERRUPTS {
        cortex_m::interrupt::free(|_| with_task(|t| t.otg.msc_reset_pending()).unwrap_or(false))
    } else {
        with_task(|t| t.otg.msc_reset_pending()).unwrap_or(false)
    }
}

/// Read and clear the mass-storage reset flag, once the transport loop has abandoned
/// whatever it was doing and is ready for the next CBW.
pub fn msc_take_reset() -> bool {
    if MSC_INTERRUPTS {
        cortex_m::interrupt::free(|_| with_task(|t| t.otg.take_msc_reset()).unwrap_or(false))
    } else {
        with_task(|t| t.otg.take_msc_reset()).unwrap_or(false)
    }
}

/// Bring-up SD read probe: init the card and read block 0, logging every step so the SD
/// data path can be debugged over USB (`sddiag:` lines via [`Opcode::ReadLog`]) rather
/// than only on the panel. Returns `(phase, sta, dcount)`: phase 0 controller-init
/// failed, 1 card-init failed, 2 CMD17 failed, 3 read failed, 4 read ok.
#[cfg(feature = "usb-debug-mem")]
fn sd_diag() -> (u8, u32, u32) {
    use catcard_board::BOARD;
    use catcard_sd::{Response, Transport};

    // SAFETY: on a device under test nothing else touches SDMMC1 or the slot; this
    // bring-up probe is the only user for the length of the call.
    let mut dev = match unsafe { catcard_hal::sdmmc::Sdmmc::init(&BOARD) } {
        Ok(d) => d,
        Err(_) => {
            crate::catlog!("sddiag: controller init FAIL");
            return (0, 0, 0);
        }
    };
    crate::catlog!("sddiag: ctrl up present={}", Transport::card_present(&dev));
    let card = match catcard_sd::init(&mut dev) {
        Ok(c) => c,
        Err(_) => {
            crate::catlog!("sddiag: card init FAIL sta={:#010x}", dev.status());
            return (1, dev.status(), dev.dcount());
        }
    };
    crate::catlog!(
        "sddiag: blocks={} wide={} block_addr={}",
        card.blocks,
        card.wide,
        matches!(card.addressing, catcard_sd::Addressing::BlockAddressed)
    );

    // Read block 0 by hand so CMD17's response and the data path are each visible.
    dev.arm_block_read();
    crate::catlog!(
        "sddiag: armed sta={:#010x} dcount={}",
        dev.status(),
        dev.dcount()
    );
    let r1 = match dev.command(17, 0, Response::Short) {
        Ok(r) => r[0],
        Err(_) => {
            crate::catlog!("sddiag: CMD17 FAIL sta={:#010x}", dev.status());
            return (2, dev.status(), dev.dcount());
        }
    };
    crate::catlog!(
        "sddiag: cmd17 r1={:#010x} sta={:#010x} dcount={}",
        r1,
        dev.status(),
        dev.dcount()
    );

    let mut blk = [0u8; catcard_sd::BLOCK_LEN];
    let (phase, sta, dcount) = match dev.read_data(&mut blk) {
        Ok(()) => {
            crate::catlog!(
                "sddiag: read OK 55aa={} sta={:#010x}",
                blk[510] == 0x55 && blk[511] == 0xAA,
                dev.status()
            );
            (4, dev.status(), dev.dcount())
        }
        Err(_) => {
            crate::catlog!(
                "sddiag: read FAIL sta={:#010x} dcount={}",
                dev.status(),
                dev.dcount()
            );
            return (3, dev.status(), dev.dcount());
        }
    };

    // Write-path probe. Read a near-end block (almost certainly free space) and write the
    // SAME bytes straight back, logging the write's STA. Safe: a failed write never
    // programs the card, and a successful one rewrites identical content.
    {
        let tb = card.blocks.saturating_sub(2);
        let arg = match card.addressing {
            catcard_sd::Addressing::BlockAddressed => tb,
            catcard_sd::Addressing::ByteAddressed => {
                tb.saturating_mul(catcard_sd::BLOCK_LEN as u32)
            }
        };
        let mut wbuf = [0u8; catcard_sd::BLOCK_LEN];
        dev.arm_block_read();
        if dev.command(17, arg, Response::Short).is_ok() && dev.read_data(&mut wbuf).is_ok() {
            dev.arm_block_write();
            match dev.command(24, arg, Response::Short) {
                Ok(r) => crate::catlog!(
                    "sddiag: wtest cmd24 r1={:#010x} sta={:#010x}",
                    r[0],
                    dev.status()
                ),
                Err(_) => crate::catlog!("sddiag: wtest CMD24 FAIL sta={:#010x}", dev.status()),
            }
            match dev.write_data(&wbuf) {
                Ok(()) => crate::catlog!("sddiag: wtest write OK sta={:#010x}", dev.status()),
                Err(_) => crate::catlog!(
                    "sddiag: wtest write FAIL sta={:#010x} dcount={}",
                    dev.status(),
                    dev.dcount()
                ),
            }
        } else {
            crate::catlog!("sddiag: wtest setup read failed, skipped");
        }
    }

    // Prove the whole read path, not just one block: mount the FAT volume, which reads
    // the boot sector and walks the FAT across many blocks.
    match catcard_sd::fat::Volume::<_, 512>::mount_auto(catcard_sd::Sectors::new(dev, card)) {
        Ok(_) => crate::catlog!("sddiag: FAT mount OK"),
        Err(_) => crate::catlog!("sddiag: FAT mount FAIL (block read works, fs did not)"),
    }
    (phase, sta, dcount)
}

/// The OTG endpoint registers, for the debug screen.
///
/// `[GINTSTS, DAINT, DOEPCTL, DOEPTSIZ, DIEPCTL, DCTL]`. On hardware there is no RAM
/// dump to read these out of, so the screen is the only place they can be seen.
pub fn otg_regs() -> Option<[u32; 6]> {
    // SAFETY: single-threaded boot path; the task owns OTG_FS and this only reads.
    with_task(|t| unsafe { t.otg.debug_regs() })
}

/// `(resets, reinits, rearms)` for the debug screen, or zeros before USB is up.
pub fn recovery_counts() -> (u32, u32, u32) {
    with_task(|t| t.otg.recovery_counts()).unwrap_or((0, 0, 0))
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
/// Run `f` with the USB task, or `None` if USB never came up.
///
/// **The only way the task is reached from a task.** It used to be a function returning
/// `&'static mut`, which was sound only while the firmware was single-threaded. Under the
/// kernel the menu and the USB service task are both live, and two `&mut` to the same
/// struct across a preemption is exactly the bug. Here the reference cannot escape the
/// closure, and the closure runs under [`catcard_kernel::without_preemption`], so no other
/// task can be inside at the same time -- by construction, not by care.
///
/// The OTG interrupt is the one accessor the lock does not exclude; see [`task_from_isr`].
fn with_task<R>(f: impl FnOnce(&mut UsbTask) -> R) -> Option<R> {
    catcard_kernel::without_preemption(|| {
        // SAFETY: the scheduler lock excludes every other task, and the only other accessor
        // -- the OTG interrupt -- runs only in mass-storage interrupt mode, where every
        // foreground caller additionally holds `interrupt::free`.
        unsafe { (*core::ptr::addr_of_mut!(TASK)).as_mut() }.map(f)
    })
}

/// The task, for the OTG interrupt handler alone.
///
/// An interrupt cannot take the scheduler lock, and it would not exclude one anyway. The
/// handler is safe for the reason it always was: OTG_FS is disabled except while the USB
/// Drive screen is open, and there every task-side caller wraps its access in
/// `interrupt::free`, so the handler and a task never hold the reference at once.
fn task_from_isr() -> Option<&'static mut UsbTask> {
    // SAFETY: as above.
    unsafe { (*core::ptr::addr_of_mut!(TASK)).as_mut() }
}

/// Tell a host whether the device has a PIN at all.
pub fn set_blank(blank: bool) {
    with_task(|t| t.set_blank(blank));
}

/// Let the host offer upgrades, now that the PIN has been entered.
pub fn unlocked() {
    with_task(|t| t.set_unlocked());
}

/// An upgrade waiting to be approved at the screen.
pub fn pending() -> Option<Approval> {
    with_task(|t| t.pending().cloned()).flatten()
}

/// Whether an upgrade is staged and waiting, without copying it.
///
/// [`pending`] clones a whole `FirmwareHeader` and its signature -- fine for the run
/// loop, which wants the thing itself once per frame, but wasteful for a caller that
/// only asks whether something is there.
pub fn has_pending() -> bool {
    with_task(|t| t.pending().is_some()).unwrap_or(false)
}

/// Approve the staged upgrade, publishing the bootloader's marker.
pub fn approve() -> Result<catcard_upgrade::Region, Reject> {
    with_task(|t| t.approve()).unwrap_or(Err(Reject::NotAnImage))
}

/// Decline it, leaving nothing staged.
pub fn decline() {
    with_task(|t| t.decline());
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
#[unsafe(no_mangle)]
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
    with_task(|t| {
        (
            t.otg.is_configured(),
            t.rx_count,
            t.tx_count,
            t.outbox_len > 0,
        )
    })
    .unwrap_or((false, 0, 0, false))
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
        let k = with_task(|t| t.injected.take()).flatten()?;
        Some(match k {
            catcard_usb::KEY_CANCEL => Key::Cancel,
            catcard_usb::KEY_CONFIRM => Key::Confirm,
            d => Key::Digit(d),
        })
    }
}

/// A whole PIN a host has submitted over USB, if any. Consumes it.
///
/// `None` without `usb-key-injection`, so the login loop calls it unconditionally.
pub fn take_unlock_pin() -> Option<heapless::Vec<u8, 33>> {
    #[cfg(not(feature = "usb-key-injection"))]
    {
        None
    }
    #[cfg(feature = "usb-key-injection")]
    {
        with_task(|t| t.unlock_pin.take()).flatten()
    }
}

/// Whether this build accepts injected keys, for the screen to say so.
pub const KEY_INJECTION: bool = cfg!(feature = "usb-key-injection");
