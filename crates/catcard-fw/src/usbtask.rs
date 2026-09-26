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
use catcard_entropy::HmacDrbg;
use catcard_usb::{
    FrameError, Opcode, PROTOCOL_VERSION, REPORT_LEN, Reassembler, Status, Writer, ncry,
};
use zeroize::Zeroize;

use crate::VERSION;
#[cfg(feature = "usb-debug-mem")]
use crate::debug_mem;

/// What the task is in the middle of.
// The unpacking variant is about a kilobyte larger than the rest: a deflate decoder
// carries its current block's code tables, and they have to survive between USB frames.
// Boxing is what clippy suggests and there is no allocator, so the choice is where the
// kilobyte lives, not whether it exists. It lives here, in the task's own static, rather
// than in a second static that would cost the same and be further from what uses it.
#[allow(clippy::large_enum_variant)]
enum Stage {
    Idle,
    /// An image is arriving.
    Receiving(Staged<'static, staging::Area>),
    /// A deflated image is arriving; each block is inflated and staged as it completes.
    /// It becomes [`Stage::Receiving`] at the end, so everything past the transfer --
    /// inspection, the offer, the approval -- is the one path.
    Unpacking {
        staged: Staged<'static, staging::Area>,
        unpack: crate::unpack::Unpack,
    },
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
    /// The encrypted channel, once a host has completed the pairing handshake
    /// ([`Opcode::PairCommit`], [`Opcode::PairReveal`]), and what the device keeps for
    /// that session. Closed until then, and torn down on any authentication failure or
    /// bus reset. It carries commands only once [paired](ncry::Session::paired): the
    /// device user accepted the code and the host's sealed `PairConfirm` authenticated.
    chan: ncry::Channel<crate::hostwallet::SessionState>,
    /// A sealed request that spans frames, gathered whole before it is opened. A heap
    /// block rather than a buffer in this struct: it is a kilobyte that is almost never
    /// in use, and this struct is a static.
    ncry_rx: Option<(crate::heap::Block, usize)>,
    /// Host-wallet requests: addresses and signatures a computer asked for.
    host: crate::hostwallet::Desk,
    /// A handshake between `PairCommit` and `PairReveal`: the device's ephemeral key and
    /// the host's commitment.
    handshake: Option<ncry::Responder>,
    /// Counts pairing prompts, so an answer given on the screen applies to the prompt
    /// that was shown and not to one that replaced it.
    pair_id: u32,
    /// The last pairing ended with the device user saying no. A host polling with a sealed
    /// `PairConfirm` then hears `Declined` rather than a bare `NotNow`.
    pair_declined: bool,
    /// The limits on pairing attempts: a cooldown on every device key handed out, and a
    /// block after handshakes are dropped unrevealed. See [`ncry::PairGuard`].
    pair_guard: ncry::PairGuard,
    /// DWT reading at the previous pairing tick, for the prompt deadline.
    pair_clock: u32,
    /// CPU cycles per millisecond, taken with the DRBG at boot. Zero means no clock to
    /// bound a prompt with, and then pairing is refused rather than left unbounded.
    cycles_per_ms: u32,
    /// Ephemeral-key source for the channel handshake, installed from the entropy pool at
    /// boot ([`install_drbg`]). `None` in recovery, where the pool never came up and the
    /// channel is simply not offered.
    drbg: Option<HmacDrbg>,
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

/// Largest body a command inside the encrypted channel may answer with: the reply, less
/// its two-byte status and the tag the seal adds. A body sized to `REPLY_MAX` itself
/// would be cut off by `begin_reply` after sealing, tag and all.
const INNER_MAX: usize = REPLY_MAX - 2 - ncry::TAG_LEN;

/// Longest board name or version string an `Identify` reply carries; longer ones are cut.
const IDENTIFY_STRING_MAX: usize = 31;

/// Bytes an `Identify` body can need: the four fixed bytes, then two length-prefixed
/// strings. `identify` writes into a buffer of exactly this size, so it cannot overrun
/// it whatever the strings are.
const IDENTIFY_MAX: usize = 4 + 2 * (1 + IDENTIFY_STRING_MAX);

// The body has to fit the reply buffer, or `begin_reply` would silently cut it.
const _: () = assert!(IDENTIFY_MAX <= REPLY_MAX);

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
            chan: ncry::Channel::new(),
            ncry_rx: None,
            host: crate::hostwallet::Desk::new(),
            handshake: None,
            pair_id: 0,
            pair_declined: false,
            pair_guard: ncry::PairGuard::new(),
            pair_clock: 0,
            cycles_per_ms: 0,
            drbg: None,
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
    /// How far a transfer in flight has got: `(received, total)`.
    ///
    /// `None` when nothing is arriving. The screen uses this to say so and to offer a way
    /// out: a megabyte over this link is not instant, and a device that looks asleep while
    /// a host writes to it tells its owner nothing about what is happening.
    pub fn receiving(&self) -> Option<(u32, u32)> {
        match &self.stage {
            // Both ways an image arrives. A compressed one counts in *image* bytes
            // rather than wire bytes: what somebody is watching is the thing being
            // installed, and a bar that stopped at seventy per cent because the image
            // deflated well would be measuring the wrong thing.
            Stage::Receiving(staged) | Stage::Unpacking { staged, .. } => {
                Some((staged.received(), staged.length()))
            }
            _ => None,
        }
    }

    /// Abandon a transfer in flight, releasing the staging medium.
    ///
    /// The host is not told: it is mid-message and nothing is listening for a reply. It
    /// finds out when its next frame is refused, which is the honest order -- the owner
    /// said no before the host finished asking.
    pub fn abandon(&mut self) {
        if self.transferring() {
            crate::catlog!("upgrade: transfer cancelled at the screen");
            self.drop_transfer();
            self.frames.reset();
        }
    }

    /// Whether an image is still arriving.
    fn transferring(&self) -> bool {
        matches!(self.stage, Stage::Receiving(_) | Stage::Unpacking { .. })
    }

    /// Whether an image is waiting for the person at the device, or has been approved
    /// and its marker published. Neither is the host's to replace.
    fn answer_pending(&self) -> bool {
        matches!(self.stage, Stage::Offered { .. } | Stage::Approved)
    }

    /// Drop a transfer in flight, if that is what the task holds, releasing the staging
    /// medium. **Only a transfer.** An offer waiting for its answer and a published
    /// approval stay exactly where they are: every path that used to write
    /// `Stage::Idle` unconditionally let a host clear the approval screen by starting
    /// a new message, or pull a staged image out from under the marker that names it.
    fn drop_transfer(&mut self) {
        if self.transferring() {
            self.stage = Stage::Idle;
        }
    }

    /// Take the transfer in flight out of the task, leaving it idle -- or `None`, leaving
    /// the stage untouched, when what it holds is not a transfer. See
    /// [`drop_transfer`](Self::drop_transfer) for why the distinction matters.
    fn take_transfer(&mut self) -> Option<Stage> {
        self.transferring()
            .then(|| core::mem::replace(&mut self.stage, Stage::Idle))
    }
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
        // Take the offer only if that is what is here. Replacing whatever was here
        // would turn a second Confirm into an idle task with the marker still published.
        if !matches!(self.stage, Stage::Offered { .. }) {
            return Err(Reject::Incomplete { have: 0, want: 0 });
        }
        let stage = core::mem::replace(&mut self.stage, Stage::Idle);
        let Stage::Offered { staged, approval } = stage else {
            return Err(Reject::Incomplete { have: 0, want: 0 });
        };
        let region = staged.commit(approval)?;
        self.stage = Stage::Approved;
        Ok(region)
    }

    /// The bootloader refused the approved image, and its marker has been retracted.
    ///
    /// Nothing is staged any more, so the task goes back to idle. Left in `Approved` it
    /// would refuse every later offer with `NotNow` for the rest of the session, waiting
    /// for a reboot that is not coming. Only `Approved` is touched: anything else here
    /// is not this install's.
    ///
    /// Not on mk3, whose install is a reboot and never returns to refuse anything.
    #[cfg(not(feature = "board-mk3"))]
    pub fn install_refused(&mut self) {
        if matches!(self.stage, Stage::Approved) {
            self.stage = Stage::Idle;
        }
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
        // The pairing prompt's deadline runs whatever the host is doing, including
        // nothing.
        self.pair_tick();
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
                    // And the frame already staged for the wire. The reply it belongs to
                    // is gone; sending its one frame into the new session would hand the
                    // host a START frame for a message it never asked for.
                    self.reply = None;
                    self.outbox_len = 0;
                    // And the encrypted session with it: whoever is on the bus after a
                    // reset has not proved it is whoever negotiated the last one. What
                    // that session was shown goes too, and a host question on the screen
                    // ends -- the same rule as an upgrade offer.
                    self.ncry_rx = None;
                    // A handshake cut by the reset never showed its code; it counts as
                    // dropped, or a relay that can reset the bus would re-roll for free.
                    if self.handshake.take().is_some() {
                        self.pair_guard.dropped();
                    }
                    self.end_session(true);
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
                // partial image rather than trying to resynchronise onto it. Only a
                // partial one: an offer already on the screen was whole when it got
                // there, and a bad frame from the host is not an answer to it.
                self.frames.reset();
                self.frame_errors = self.frame_errors.saturating_add(1);
                self.drop_transfer();
                self.ncry_rx = None;
                self.begin_reply(
                    Status::BadRequest,
                    &[matches!(e, FrameError::OutOfSequence { .. }) as u8],
                );
                return;
            }
        };

        // The packed offer eats a four-byte length off the front of its first frame, so
        // what reaches the staging area below is not always what arrived.
        let mut payload = progress.payload;

        if let Some(msg) = progress.started {
            match Opcode::from_u16(msg.opcode) {
                Some(Opcode::UpgradeOffer | Opcode::UpgradePacked | Opcode::UpgradeCommit)
                    if !self.unlocked =>
                {
                    // Enumerating is free; rewriting the firmware is not. Refusing here
                    // rather than at the screen means a locked device never even stages
                    // an image.
                    self.frames.reset();
                    self.begin_reply(Status::NotNow, &[]);
                    return;
                }
                Some(Opcode::UpgradeOffer | Opcode::UpgradePacked)
                    if self.answer_pending() || self.host.pending() =>
                {
                    // An image is already on the screen waiting for the person at the
                    // device, or has been approved and its marker published. A second
                    // offer replaces neither: the first would let a host clear a question
                    // it is not entitled to answer, the second would pull the image out
                    // from under the marker that names it. `NotNow` is the same answer a
                    // commit gets before approval, and it means the same thing -- wait
                    // for the device. The answer arrives as `Declined`, or as the reboot
                    // that installs.
                    self.frames.reset();
                    crate::catlog!("upgrade: offer refused, one is already waiting for an answer");
                    self.begin_reply(Status::NotNow, &[]);
                    return;
                }
                Some(Opcode::UpgradeOffer) => {
                    // Claim the board's staging area (PSRAM on mk4/mk5/Q1, SPI-NOR on mk3).
                    // `None` -- no medium, or the SPI-NOR did not answer -- is refused on
                    // this first frame rather than after 256 KB have crossed the wire.
                    // Drop a transfer this task was still receiving first: a host
                    // re-offering after a failed attempt is the same holder coming back,
                    // not a second one. Anything *else* holding the medium -- a card image
                    // waiting on the approval screen -- is refused, which is the point.
                    self.drop_transfer();
                    let area = match staging::area() {
                        Ok(a) => a,
                        Err(why) => {
                            self.frames.reset();
                            self.refuse(no_staging(why));
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
                Some(Opcode::UpgradePacked) => {
                    // A deflated image. The wire carries the compressed bytes, so
                    // `msg.total` is not the image's length: the first four bytes of the
                    // payload are, and they are what the signature was computed over.
                    //
                    // They must arrive whole in this first frame. A frame holds 56 bytes
                    // of payload after the header, and an image is thousands of frames,
                    // so the only way to split an eight-byte prefix across two of them is
                    // to be sending something that is not an image.
                    self.drop_transfer();
                    let Some(head) = payload.first_chunk::<8>() else {
                        self.frames.reset();
                        self.begin_reply(Status::BadRequest, &[]);
                        return;
                    };
                    let want = u32::from_le_bytes([head[0], head[1], head[2], head[3]]);
                    // The size of the blocks the host chose. It travels with the image
                    // because both ends used to hard-code it separately, and when they
                    // drifted the upload failed part way through with a frame error and
                    // the actual reason -- a block too big for the slab -- was never
                    // reported at all.
                    let block = u32::from_le_bytes([head[4], head[5], head[6], head[7]]);
                    payload = &payload[8..];

                    let area = match staging::area() {
                        Ok(a) => a,
                        Err(why) => {
                            self.frames.reset();
                            self.refuse(no_staging(why));
                            return;
                        }
                    };
                    // `begin` checks the declared length against the staging area and the
                    // bootloader's floor before a single compressed byte is decoded, so
                    // an absurd length costs nothing.
                    match Staged::begin(area, &BOARD, want) {
                        Ok(staged) => {
                            // The inflate slab comes from the heap, and may not be
                            // there. That is not a refusal of the image: the same one
                            // sent uncompressed needs no slab, so the host is told to
                            // do exactly that rather than being left to guess.
                            let Some(unpack) = crate::unpack::Unpack::begin(want, block) else {
                                crate::catlog!(
                                    "upgrade: {} byte blocks refused (slab {}), or no heap for one; \
                                     asking for it uncompressed",
                                    block,
                                    catcard_upgrade::packed::BLOCK
                                );
                                self.frames.reset();
                                self.begin_reply(Status::RetryUncompressed, &[]);
                                return;
                            };
                            self.stage = Stage::Unpacking { staged, unpack };
                        }
                        Err(r) => {
                            self.frames.reset();
                            self.refuse(r);
                            return;
                        }
                    }
                }
                Some(Opcode::NcryMsg)
                    if msg.total as usize > catcard_usb::START_PAYLOAD
                        && msg.total as usize <= ncry::RECORD_MAX =>
                {
                    // A sealed request longer than one frame -- a chunk of an upload. It
                    // is gathered whole into a block of its own and opened only once it
                    // is complete: nothing in it is used until the whole record has
                    // authenticated. Bounded by `RECORD_MAX`, so the block is too.
                    match crate::heap::take(ncry::RECORD_MAX) {
                        Some(block) => self.ncry_rx = Some((block, 0)),
                        None => {
                            self.frames.reset();
                            self.begin_reply(Status::Busy, &[]);
                            return;
                        }
                    }
                }
                Some(_) if msg.total as usize > catcard_usb::START_PAYLOAD => {
                    // Only an image spans frames; every other request fits its START
                    // frame. A longer one would complete with no opcode in hand and
                    // fall into the offer path, which is not where it belongs, so it is
                    // refused here, on its first frame, and the reassembler is cleared
                    // so the rest of it is `NoMessage` errors rather than an image.
                    self.frames.reset();
                    self.begin_reply(Status::BadRequest, &[]);
                    return;
                }
                Some(_) => {}
                None => {
                    self.frames.reset();
                    self.begin_reply(Status::UnknownOpcode, &msg.opcode.to_le_bytes());
                    return;
                }
            }
        }

        // A sealed record spanning frames is gathered, and opened when it is whole.
        if let Some((block, at)) = &mut self.ncry_rx {
            let end = *at + payload.len();
            match block.bytes().get_mut(*at..end) {
                Some(dst) => {
                    dst.copy_from_slice(payload);
                    *at = end;
                }
                None => {
                    self.ncry_rx = None;
                    self.frames.reset();
                    self.begin_reply(Status::BadRequest, &[]);
                    return;
                }
            }
            if progress.complete
                && let Some((mut block, n)) = self.ncry_rx.take()
            {
                self.handle_ncry_record(&mut block.bytes()[..n]);
            }
            return;
        }

        // Image bytes go straight to staging as they arrive; nothing is buffered. The
        // deflated path buffers one block, which is the whole of what it buffers.
        if let Stage::Unpacking { staged, unpack } = &mut self.stage {
            if let Err(r) = unpack.feed(staged, payload) {
                crate::catlog!("upgrade: unpack failed at {}", staged.received());
                self.frames.reset();
                self.refuse(r);
                return;
            }
        } else if let Stage::Receiving(staged) = &mut self.stage {
            let at = staged.received();
            if let Err(r) = staged.write(at, payload) {
                // `at` is the stage's own count and the payload is what just arrived, so a
                // storage fault here means the region itself was not what `begin` checked.
                crate::catlog!("upgrade: write failed at {} len {}", at, payload.len());
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
                let mut body = [0u8; 64];
                let n = Self::readlog_body(progress.payload, &mut body);
                self.begin_reply(Status::Ok, &body[..n]);
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
            #[cfg(feature = "usb-debug-mem")]
            Some(Opcode::DebugSdRaw) => {
                let mut body = [0u8; REPLY_MAX];
                match sd_raw(progress.payload, &mut body) {
                    Some(n) => self.begin_reply(Status::Ok, &body[..n]),
                    None => self.begin_reply(Status::BadRequest, &[]),
                }
            }
            #[cfg(not(feature = "usb-debug-mem"))]
            Some(
                Opcode::DebugPeek
                | Opcode::DebugPoke
                | Opcode::DebugJsr
                | Opcode::DebugSd
                | Opcode::DebugSdRaw,
            ) => {
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
            // Encrypted-channel only: in the clear these do not exist, as the debug ones
            // do not exist inside it.
            Some(
                Opcode::HostAddresses
                | Opcode::HostSignBegin
                | Opcode::HostSignData
                | Opcode::HostSignCommit
                | Opcode::HostResult
                | Opcode::HostAbort,
            ) => self.begin_reply(Status::UnknownOpcode, &[]),
            Some(Opcode::PairCommit) => self.pair_commit(progress.payload),
            Some(Opcode::PairReveal) => self.pair_reveal(progress.payload),
            // Only ever sealed: in the clear it would be a confirmation anyone could send.
            Some(Opcode::PairConfirm) => self.begin_reply(Status::BadRequest, &[]),
            Some(Opcode::PairAbort) => self.pair_abort(),
            Some(Opcode::NcryMsg) => self.handle_ncry_msg(progress.payload),
            Some(Opcode::UpgradeOffer | Opcode::UpgradePacked) | None => self.finish_offer(),
        }
    }

    /// Whether the encrypted channel is paired: the device user accepted the code and the
    /// host's sealed `PairConfirm` authenticated. What gates every command that needs an
    /// authenticated host.
    pub fn paired(&self) -> bool {
        self.chan.session().is_some_and(ncry::Session::paired)
    }

    /// Whether a handshake has produced a session that is not paired yet: the prompt is up,
    /// or the device user answered and the host has not confirmed. Only one at a time.
    fn pairing_in_progress(&self) -> bool {
        self.chan.session().is_some_and(|s| !s.paired())
    }

    /// `PairCommit`: the host commits to its ephemeral key; answer with the device's.
    fn pair_commit(&mut self, payload: &[u8]) {
        let Ok(commit) = <&[u8; ncry::COMMIT_LEN]>::try_from(payload) else {
            self.begin_reply(Status::BadRequest, &[]);
            return;
        };
        // Pairing opens a channel for wallet commands, so it waits for the PIN the same
        // way an upgrade does. Before it the answer is "not now", not "no".
        if !self.unlocked {
            self.begin_reply(Status::NotNow, &[]);
            return;
        }
        // One pairing at a time: a second handshake while a code is on the screen would
        // change the code under the person reading it.
        if self.pairing_in_progress() {
            self.begin_reply(Status::Busy, &[]);
            return;
        }
        // No entropy source means no channel -- recovery, where the pool never came up --
        // and no clock means no deadline for the prompt, which is refused rather than
        // left unbounded.
        let has_clock = self.cycles_per_ms > 0;
        let Some(drbg) = self.drbg.as_mut().filter(|_| has_clock) else {
            self.begin_reply(Status::NotNow, &[]);
            return;
        };
        // The ephemeral scalar is protocol randomness from the HMAC-DRBG, never the raw
        // pool and never anything key-derived. A DRBG that cannot produce is a dead
        // channel, not a weak one: refuse rather than fall back to a lesser source.
        // Every device key is an attempt, charged whether or not a code is ever shown: a
        // relay sees the candidate code the moment it holds the key, so a limit on shown
        // codes alone would let it discard silent handshakes by the thousand. Checked
        // after the conditions above, so a "not now" costs the host nothing.
        match self.pair_guard.begin() {
            Ok(()) => {}
            Err(ncry::Refusal::Cooling) => {
                self.begin_reply(Status::Busy, &[]);
                return;
            }
            Err(ncry::Refusal::Locked) => {
                crate::catlog!("ncry: pairing blocked after abandoned handshakes");
                self.begin_reply(
                    Status::Refused,
                    b"pairing blocked: acknowledge it on the device",
                );
                return;
            }
        }
        let mut scalar = [0u8; ncry::KEY_LEN];
        if drbg.generate(&mut scalar).is_err() {
            self.begin_reply(Status::BadRequest, &[]);
            return;
        }
        let hs = ncry::Responder::new(&scalar, commit);
        scalar.zeroize();
        // A fresh handshake replaces any prior session outright, so a host that lost its
        // keys can always start over -- by pairing again, in front of the person.
        self.end_session(false);
        self.pair_declined = false;
        let dev_pub = *hs.public_key();
        self.handshake = Some(hs);
        self.begin_reply(Status::Ok, &dev_pub);
    }

    /// `PairReveal`: the host's public key, which must match its commitment. On success
    /// the code goes up on the screen and the session waits to be paired.
    fn pair_reveal(&mut self, payload: &[u8]) {
        let Ok(host_pub) = <&[u8; ncry::KEY_LEN]>::try_from(payload) else {
            self.begin_reply(Status::BadRequest, &[]);
            return;
        };
        if !self.unlocked {
            self.begin_reply(Status::NotNow, &[]);
            return;
        }
        // A reveal is used once: the handshake is taken whatever the outcome.
        let Some(hs) = self.handshake.take() else {
            self.begin_reply(Status::NotNow, &[]);
            return;
        };
        match hs.reveal(host_pub) {
            Ok(session) => {
                self.pair_id = self.pair_id.wrapping_add(1);
                self.pair_guard.revealed();
                self.chan.install(session);
                crate::catlog!("ncry: pairing code shown, waiting for the user");
                self.begin_reply(Status::Ok, &[]);
            }
            Err(e) => {
                crate::catlog!("ncry: pairing refused: {:?}", e);
                // A reveal that missed its commitment is a dropped handshake, and counts.
                self.pair_guard.dropped();
                self.begin_reply(Status::BadRequest, &[]);
            }
        }
    }

    /// End the encrypted session, and everything bound to it.
    ///
    /// The channel's own per-session state (what the host was shown) is dropped by the
    /// channel; the host-wallet desk drops what it held for that session.
    fn end_session(&mut self, bus_reset: bool) {
        self.chan.close();
        self.host.session_ended(bus_reset);
    }

    /// A sealed request that fitted one frame: copied off the frame, then opened.
    fn handle_ncry_msg(&mut self, payload: &[u8]) {
        let mut buf = [0u8; catcard_usb::START_PAYLOAD];
        let n = payload.len().min(buf.len());
        buf[..n].copy_from_slice(&payload[..n]);
        self.handle_ncry_record(&mut buf[..n]);
        buf.zeroize();
    }

    /// `PairAbort`: the host gave up. Tear down whatever there is.
    fn pair_abort(&mut self) {
        if self.chan.is_open() || self.handshake.is_some() {
            crate::catlog!("ncry: host abandoned the session");
        }
        if self.handshake.take().is_some() {
            // Abandoned before the reveal: no code was ever shown for it.
            self.pair_guard.dropped();
        }
        self.end_session(false);
        self.begin_reply(Status::Ok, &[]);
    }

    /// The pairing prompt the screen should show, if one is waiting on the device user.
    pub fn pair_prompt(&self) -> Option<PairPrompt> {
        self.chan
            .session()
            .filter(|s| s.awaiting_user())
            .map(|s| PairPrompt {
                id: self.pair_id,
                code: s.code(),
            })
    }

    /// Whether pairing is blocked after abandoned handshakes, and how many: the screen
    /// says so until the person dismisses it.
    pub fn pair_blocked(&self) -> Option<u8> {
        self.pair_guard.locked()
    }

    /// The person saw the warning and let pairing go on.
    pub fn pair_unblock(&mut self) {
        crate::catlog!("ncry: pairing block dismissed on the device");
        self.pair_guard.dismiss();
    }

    /// The device user answered prompt `id`. An answer to a prompt that is no longer the
    /// one waiting -- it timed out, or the host abandoned it -- changes nothing.
    pub fn pair_answer(&mut self, id: u32, accept: bool) {
        if id != self.pair_id || self.pair_prompt().is_none() {
            return;
        }
        if accept {
            if let Some(s) = self.chan.session_mut() {
                s.accept();
            }
            if self.paired() {
                self.pair_guard.paired();
            }
            crate::catlog!(
                "ncry: user accepted the code{}",
                if self.paired() { "; paired" } else { "" }
            );
        } else {
            crate::catlog!("ncry: user rejected the code");
            self.end_session(false);
            self.pair_declined = true;
        }
    }

    /// Count time against the pairing deadline and the cooldown.
    ///
    /// Measured from the DWT counter the way the idle timeout measures it: each tick adds
    /// the gap since the last, clamped to a second, so a counter that wrapped under a long
    /// masked stretch under-counts -- the prompt stays a little longer, never shorter.
    fn pair_tick(&mut self) {
        if self.cycles_per_ms == 0 {
            return;
        }
        let now = catcard_hal::dwt::cycles();
        let prev = core::mem::replace(&mut self.pair_clock, now);
        let gap = (now.wrapping_sub(prev) / self.cycles_per_ms).min(1_000);
        self.pair_guard.tick(gap);
        if let Some(s) = self.chan.session_mut()
            && s.wait(gap)
        {
            crate::catlog!("ncry: pairing timed out");
            self.end_session(false);
        }
    }

    /// Open a sealed request, dispatch the command inside it, and seal the reply.
    ///
    /// Any failure tears the session down: a channel that has seen one forged, corrupt or
    /// wrongly sized record is not one to keep trusting, and the host can renegotiate.
    fn handle_ncry_record(&mut self, record: &mut [u8]) {
        if !self.chan.is_open() {
            // No channel to open it with. `NotNow`, not `BadRequest`: the host has to
            // pair first, and this says so without looking like a framing bug. `Declined`
            // when the device user just refused the code, so a host polling with
            // `PairConfirm` can say why.
            let status = if self.pair_declined {
                Status::Declined
            } else {
                Status::NotNow
            };
            self.begin_reply(status, &[]);
            return;
        }
        let plain = match self.chan.open_record(record) {
            Ok(p) => p,
            Err(_) => {
                self.end_session(false);
                self.begin_reply(Status::BadRequest, &[]);
                return;
            }
        };

        // The plaintext is an ordinary request: `[u16 opcode][payload]`.
        let inner_op = u16::from_le_bytes([plain[0], plain[1]]);
        // Until the session is paired the only record it carries is `PairConfirm`.
        let admit = match self.chan.session_mut() {
            Some(session) => session.admit(inner_op),
            None => ncry::Admit::Refuse,
        };
        // Build the reply straight into the seal buffer: two bytes of status, then the
        // body written in place, then the tag -- all inside one reply's worth, so nothing
        // `begin_reply` holds is cut off.
        let mut sealed = [0u8; REPLY_MAX];
        let (status, n) = match admit {
            ncry::Admit::Dispatch => {
                self.inner_dispatch(inner_op, &plain[2..], &mut sealed[2..2 + INNER_MAX])
            }
            // `NotNow` while the device user is still looking at the code: ask again.
            ncry::Admit::Confirm if self.paired() => {
                self.pair_guard.paired();
                (Status::Ok, 0)
            }
            ncry::Admit::Confirm => (Status::NotNow, 0),
            ncry::Admit::Refuse => {
                plain.zeroize();
                crate::catlog!("ncry: sealed {:#06x} before pairing; torn down", inner_op);
                self.end_session(false);
                self.begin_reply(Status::BadRequest, &[]);
                return;
            }
        };
        plain.zeroize();
        sealed[..2].copy_from_slice(&(status as u16).to_le_bytes());
        match self.chan.seal_record(&mut sealed, 2 + n) {
            Ok(len) => self.begin_reply(Status::Ok, &sealed[..len]),
            Err(_) => {
                self.end_session(false);
                self.begin_reply(Status::BadRequest, &[]);
            }
        }
        sealed.zeroize();
    }

    /// Handle a command that arrived inside the encrypted channel, writing its reply body
    /// into `out` and returning `(inner status, length)`.
    ///
    /// A deliberately narrow set: the commands whose payloads are worth hiding, plus a
    /// round-trip check. The bulk upgrade opcodes and the bench debug ones are not
    /// reachable here -- an upgrade streams and is public, and the debug monitor is a
    /// bring-up crutch that gains nothing from a channel.
    fn inner_dispatch(&mut self, opcode: u16, payload: &[u8], out: &mut [u8]) -> (Status, usize) {
        match Opcode::from_u16(opcode) {
            Some(
                op @ (Opcode::HostAddresses
                | Opcode::HostSignBegin
                | Opcode::HostSignData
                | Opcode::HostSignCommit
                | Opcode::HostResult
                | Opcode::HostAbort),
            ) => {
                if !self.chan.host_wallet_allowed() {
                    return (Status::UnknownOpcode, 0);
                }
                let upgrade_busy = self.transferring() || self.answer_pending();
                let cx = crate::hostwallet::Cx {
                    session: self.chan.id(),
                    exposed: self.chan.state().map_or(&[][..], |s| &s.exposed[..]),
                    unlocked: self.unlocked,
                    upgrade_busy,
                };
                self.host.dispatch(op, payload, out, &cx)
            }
            Some(Opcode::Ping) => {
                let n = payload.len().min(out.len());
                out[..n].copy_from_slice(&payload[..n]);
                (Status::Ok, n)
            }
            Some(Opcode::Identify) => (Status::Ok, self.identify_body(out)),
            Some(Opcode::ReadLog) => (Status::Ok, Self::readlog_body(payload, out)),
            _ => (Status::UnknownOpcode, 0),
        }
    }

    /// One page of the log: `[u32 total][u8 flags][bytes]`, at most a frame's worth.
    fn readlog_body(req: &[u8], body: &mut [u8]) -> usize {
        let offset = if req.len() >= 4 {
            u32::from_le_bytes([req[0], req[1], req[2], req[3]]) as usize
        } else {
            0
        };
        body[..4].copy_from_slice(&(crate::logbuf::len() as u32).to_le_bytes());
        body[4] = if crate::logbuf::wrapped() {
            catcard_usb::log_flags::WRAPPED
        } else {
            0
        };
        // A page has to fit one frame: a reply's first frame carries `START_PAYLOAD`
        // bytes, and anything past that is dropped by the writer while the header still
        // promises it -- which reads as a device that stopped answering.
        let end = catcard_usb::START_PAYLOAD.min(body.len());
        let n = crate::logbuf::read(offset, &mut body[5..end]);
        5 + n
    }

    /// The image is fully staged: inspect it and tell the host what we found.
    fn finish_offer(&mut self) {
        // A deflated image becomes an ordinary staged one here: the last block has been
        // inflated and written, so from this line on there is nothing left that knows
        // the transfer was compressed. `finish` is what refuses a transfer that stopped
        // short -- the staging area's tail would otherwise be whatever the last upload
        // left in it, and that is what would be installed.
        //
        // Only a transfer is taken out of the stage here. Replacing the stage
        // unconditionally meant a completed message that was not a transfer -- a
        // multi-frame Ping, before one was refused on its first frame -- threw away an
        // offer waiting on the screen, or an approval whose marker was already
        // published.
        let mut transfer = self.take_transfer();
        if let Some(Stage::Unpacking { staged, unpack }) = transfer {
            match unpack.finish() {
                Ok(()) => transfer = Some(Stage::Receiving(staged)),
                Err(r) => {
                    self.refuse(r);
                    return;
                }
            }
        }

        let Some(Stage::Receiving(mut staged)) = transfer else {
            return;
        };
        let running = crate::own_header();
        match staged.inspect(running.as_ref()) {
            Ok(approval) => {
                let mut body = [0u8; 64];
                let n = describe(&approval, &mut body);
                crate::catlog!(
                    "usb: offered {} bytes, verified {}, older {}, high-water {}",
                    approval.length,
                    approval.is_verified(),
                    approval.older_than_running,
                    crate::session::sets_high_water(&approval)
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
                // What the verification itself judged, against what the staging area
                // says now. The same bytes read twice giving two answers is a read
                // fault; the same answer twice is an image that is genuinely not signed.
                if let Reject::RamStoreFailed { sent, read } = &r {
                    crate::catlog!(
                        "usb: STAGING RAM FAILED -- sent {:02x}{:02x}{:02x}{:02x}, read back {:02x}{:02x}{:02x}{:02x}",
                        sent[0],
                        sent[1],
                        sent[2],
                        sent[3],
                        read[0],
                        read[1],
                        read[2],
                        read[3]
                    );
                }
                if let Reject::BadSignature { digest, sig } = &r {
                    crate::catlog!(
                        "usb: verify used digest {:02x}{:02x}{:02x}{:02x} sig {:02x}{:02x}{:02x}{:02x}",
                        digest[0],
                        digest[1],
                        digest[2],
                        digest[3],
                        sig[0],
                        sig[1],
                        sig[2],
                        sig[3]
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
        let mut body = [0u8; IDENTIFY_MAX];
        let at = self.identify_body(&mut body);
        self.begin_reply(Status::Ok, &body[..at]);
    }

    /// Write the `Identify` reply body into `body` and return its length. Shared by the
    /// plaintext handler and the encrypted channel, so the two never disagree on what the
    /// device says it is.
    fn identify_body(&self, body: &mut [u8]) -> usize {
        // Fixed layout rather than a text blob, so a host does not have to parse prose:
        //   [0..2] protocol version
        //   [2]    device state, see `catcard_usb::state`
        //   [3]    capabilities, see `catcard_usb::caps`
        //   [4..]  board name length, then the name
        //   then   version string length, then the version
        //
        // Sized for the layout, not to a round number: four fixed bytes and two strings
        // of up to `IDENTIFY_STRING_MAX` each with their length byte is 68, and a 64-byte
        // body with a long version and board name wrote four bytes past its end. A reply
        // can span frames, so the extra frame costs nothing.
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
            // The compressed offer reaches the same staging area through the same
            // checks, so it is available exactly when staging is.
            catcard_usb::caps::UPGRADE | catcard_usb::caps::UPGRADE_PACKED
        } else {
            0
        } | if cfg!(feature = "usb-debug-mem") {
            catcard_usb::caps::DEBUG_MEM
        } else {
            0
        } | if self.drbg.is_some() {
            // The host-wallet commands only ever run on a paired session, so they are
            // advertised exactly when pairing is.
            catcard_usb::caps::PAIRING | catcard_usb::caps::HOST_WALLET
        } else {
            0
        };
        at += 1;
        for s in [crate::running_board(), VERSION] {
            let b = s.as_bytes();
            let n = b.len().min(IDENTIFY_STRING_MAX);
            body[at] = n as u8;
            body[at + 1..at + 1 + n].copy_from_slice(&b[..n]);
            at += 1 + n;
        }
        at
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

/// Why an offer could not claim the staging medium, said in the log before it is said
/// on the wire.
///
/// The wire has one byte for this and `StagingBusy` is all it can carry, which is enough
/// for a host to stop but not enough for a person to know what to do. On a PSRAM board
/// the holder may not be another image at all -- it may be a transaction being signed or
/// a QR being read -- so the log says which and the host still gets its byte.
fn no_staging(why: staging::Unavailable) -> Reject {
    match why {
        staging::Unavailable::NoMedium => Reject::NoStagingArea,
        staging::Unavailable::Busy => {
            #[cfg(not(feature = "board-mk3"))]
            if let Some(who) = crate::psram::holder() {
                crate::catlog!("upgrade: refused an offer, the PSRAM has {}", who.what());
            }
            Reject::StagingBusy
        }
    }
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
        Reject::BadSignature { .. } => 10,
        // Distinct from a bad signature: the image was fine and we lost it.
        Reject::RamStoreFailed { .. } => 14,
        Reject::StorageFault { .. } => 11,
        Reject::NoStagingArea => 12,
        Reject::StagingBusy => 13,
        Reject::Unpackable(_) => 15,
        Reject::Unaligned { .. } => 16,
        Reject::Sealed => 17,
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
    let busy = if MSC_ACTIVE.load(Ordering::Relaxed) || !PORT_ON.load(Ordering::Relaxed) {
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
    // And the idle timeout for the same reason again: a timeout that only counted while
    // the main menu happened to be up would be a timeout that never fires on the screen
    // an unattended device is most likely to be left on.
    crate::idle::tick();
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
/// call more than once. No-op if USB never came up, or while the owner has the port
/// switched off.
pub fn attach() {
    if !PORT_ON.load(Ordering::Relaxed) {
        return;
    }
    // SAFETY: the task owns OTG_FS for the life of the firmware; the lock excludes other
    // tasks and nothing runs in interrupt context.
    with_task(|t| unsafe { t.otg.attach() });
}

/// Whether the owner has the USB port switched on. On until a wallet's settings say
/// otherwise; see [`crate::prefs`].
static PORT_ON: AtomicBool = AtomicBool::new(true);

/// Switch the USB port on or off, as the `Hardware On/Off` setting asks.
///
/// **Off is a real soft-disconnect, not a pretence.** The core drops off the bus, so the
/// host sees the device unplug and there is nothing left to enumerate, answer or inject a
/// keypress through; [`poll_once`] stops servicing it as well, so no report is read even
/// if something did arrive. The peripheral stays initialised, because switching back on
/// has to work without a reboot -- and because a device that could not re-attach would be
/// a device whose owner had permanently removed its only remote channel.
///
/// The port comes up attached at boot and is only switched off once the wallet's settings
/// have been read, which is after the PIN: a preference kept under a key derived from the
/// seed cannot be consulted any earlier. So a locked device always enumerates, which is
/// what keeps a unit with a dead screen reachable.
pub fn set_port(on: bool) {
    if PORT_ON.swap(on, Ordering::Relaxed) == on {
        return;
    }
    crate::catlog!("usb: port switched {}", if on { "on" } else { "off" });
    // SAFETY: as in `attach` -- the task owns OTG_FS and the lock excludes other tasks.
    with_task(|t| unsafe {
        if on {
            t.otg.attach();
        } else {
            t.otg.detach();
        }
    });
}

// ---------------------------------------------------------------------------
// Keyboard emulation
//
// The `Keyboard EMU` switch. On, the HID identity is a composite -- the wallet's own
// interface exactly as before, plus a boot-protocol keyboard on its own IN endpoint --
// and `usbkbd::type_text` sends keystrokes through it. The wallet interface keeps its
// number and endpoints, so no host tool is affected by the switch either way.
// ---------------------------------------------------------------------------

/// Whether the owner has keyboard emulation on. Off until a wallet's settings say so:
/// a device that can type into its host is the surprising state, never the default.
static KBD_ON: AtomicBool = AtomicBool::new(false);

/// Whether the `Keyboard EMU` switch is on.
///
pub fn keyboard_on() -> bool {
    KBD_ON.load(Ordering::Relaxed)
}

/// Switch keyboard emulation on or off, as the `Hardware On/Off` setting asks.
///
/// The descriptor set is fixed for the life of an enumeration, so a change means the
/// host has to enumerate again: a visible disconnect, a pause, and a re-attach with the
/// new configuration -- the same dance the USB Drive screen does. Only while the host is
/// looking, though: with the port off there is nothing to re-present, and [`set_port`]
/// brings up whatever identity is current when it comes back; in mass-storage mode the
/// flag simply waits for [`msc_exit`] to re-enumerate as HID.
///
/// Read from the wallet's settings after the PIN, like the port switch, so a locked
/// device never enumerates a keyboard.
pub fn set_keyboard(on: bool) {
    if KBD_ON.swap(on, Ordering::Relaxed) == on {
        return;
    }
    crate::catlog!("usb: keyboard emulation {}", if on { "on" } else { "off" });
    let presenting = PORT_ON.load(Ordering::Relaxed) && !MSC_ACTIVE.load(Ordering::Relaxed);
    // SAFETY: the task owns OTG_FS and the lock excludes other tasks; interrupts are
    // off outside mass-storage mode, which `presenting` rules out.
    with_task(|t| unsafe {
        t.otg.set_keyboard(on);
        if presenting {
            t.otg.detach();
            catcard_hal::dwt::delay_ms(REENUM_DETACH_MS);
            t.otg.reinit();
        }
    });
}

/// What became of one keyboard report.
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub enum KbdSend {
    /// In the endpoint's FIFO, for the host's next IN token.
    Sent,
    /// The host has not taken the previous report yet, or the FIFO has no room; try
    /// again after a moment.
    Busy,
    /// There is no keyboard to send through: the switch or the port is off, the device
    /// is a disk right now, USB never came up, or no host has configured it.
    Unavailable,
}

/// Whether a keyboard report could go out right now, without sending one.
pub fn kbd_ready() -> bool {
    if !keyboard_on() || !PORT_ON.load(Ordering::Relaxed) || MSC_ACTIVE.load(Ordering::Relaxed) {
        return false;
    }
    with_task(|t| t.otg.is_configured() && t.otg.keyboard_present()).unwrap_or(false)
}

/// Offer one boot-keyboard report to the host. Never blocks; see [`KbdSend`].
pub fn kbd_send(report: &catcard_usb::kbd::Report) -> KbdSend {
    if !kbd_ready() {
        return KbdSend::Unavailable;
    }
    with_task(|t| {
        // SAFETY: the task owns OTG_FS and the lock excludes other tasks; not in
        // mass-storage mode (`kbd_ready` checked), so no interrupt touches the core.
        if unsafe { t.otg.kbd_send(report.as_bytes()) } {
            led::saw_traffic();
            KbdSend::Sent
        } else {
            KbdSend::Busy
        }
    })
    .unwrap_or(KbdSend::Unavailable)
}

/// Whether the last keyboard report is still waiting for the host to take it. `false`
/// when there is no keyboard at all: nothing is pending on an endpoint that is not open.
pub fn kbd_busy() -> bool {
    if !kbd_ready() {
        return false;
    }
    // SAFETY: a register read under the task lock.
    with_task(|t| unsafe { t.otg.kbd_busy() }).unwrap_or(false)
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

/// The card the raw bridge is talking to, kept between commands.
///
/// **Kept, because the card's state is the point.** `CMD16` sets a block length that the
/// next command relies on; `CMD7` leaves the card selected; a lock/unlock sequence is
/// three commands that only mean something in order. Initialising per request would
/// reset all of that and the bridge could only ever ask one-command questions.
#[cfg(feature = "usb-debug-mem")]
static mut BRIDGE: Option<(catcard_hal::sdmmc::Sdmmc, catcard_sd::Card)> = None;

/// Run one raw command against the card, and write the reply into `out`.
///
/// Request: `[u8 cmd][u8 flags][u16 len][u32 arg]` then the outgoing data, if any.
/// Reply: `[u8 status][u8 reserved][u16 len][u32 resp0..3]` then the incoming data.
///
/// `status` is 0 for a command the card answered and 1 for one it did not; a card that
/// answers with an error in its response word is still an answer, and reporting it as a
/// transport failure would hide exactly what a probe is looking for.
#[cfg(feature = "usb-debug-mem")]
fn sd_raw(req: &[u8], out: &mut [u8]) -> Option<usize> {
    use catcard_board::BOARD;
    use catcard_sd::{Response, Transport};

    let head = req.first_chunk::<8>()?;
    let cmd = head[0];
    let flags = head[1];
    let len = u16::from_le_bytes([head[2], head[3]]) as usize;
    let arg = u32::from_le_bytes([head[4], head[5], head[6], head[7]]);
    let resp = match flags & 0b11 {
        0 => Response::None,
        1 => Response::Short,
        _ => Response::Long,
    };
    let to_host = flags & 0b100 != 0;
    let to_card = flags & 0b1000 != 0;
    // A transfer's length is an exponent in the controller, so only powers of two can be
    // asked for, and the reply carries twelve bytes of header inside one message. 256 is
    // the largest power of two that leaves room -- enough for every register a probe
    // wants (a CID is in the response words, an SD status is 64 bytes, a lock structure
    // is 16). A whole 512-byte block is what the drive and `DebugSd` are for.
    const DATA_MAX: usize = 256;
    if (to_host || to_card) && (len == 0 || !len.is_power_of_two() || len > DATA_MAX) {
        return None;
    }
    if to_card && req.len() < 8 + len {
        return None;
    }

    // SAFETY: foreground only, single core. The bridge owns SDMMC1 for as long as it is
    // open, and nothing else on a bring-up build touches the slot.
    let held = unsafe { &mut *core::ptr::addr_of_mut!(BRIDGE) };
    if held.is_none() {
        // SAFETY: as above.
        let mut dev = unsafe { catcard_hal::sdmmc::Sdmmc::init(&BOARD) }.ok()?;
        let card = catcard_sd::init(&mut dev).ok()?;
        crate::catlog!("sdraw: card up, {} blocks, wide={}", card.blocks, card.wide);
        *held = Some((dev, card));
    }
    let (dev, _card) = held.as_mut()?;

    // A length the controller cannot express is refused before the command goes out, and
    // reported the way a failed command is: the host asked for a transfer that cannot
    // happen, so no command is sent either.
    let armed = if to_host {
        dev.arm_data(len, true)
    } else if to_card {
        dev.arm_data(len, false)
    } else {
        Ok(())
    };
    let answer = armed.and_then(|()| dev.command(cmd, arg, resp));
    let (status, words) = match answer {
        Ok(words) => (0u8, words),
        Err(_) => (1u8, [0u32; 4]),
    };

    let mut data = 0usize;
    if status == 0 && to_card {
        if dev.write_short(&req[8..8 + len]).is_err() {
            return None;
        }
    } else if status == 0 && to_host {
        let room = out.get_mut(12..12 + len)?;
        if dev.read_short(room).is_err() {
            return None;
        }
        data = len;
    }

    let head = out.get_mut(..12)?;
    head[0] = status;
    head[1] = 0;
    head[2..4].copy_from_slice(&(data as u16).to_le_bytes());
    for (i, w) in words.iter().enumerate() {
        head[4 + i * 4..8 + i * 4].copy_from_slice(&w.to_le_bytes());
    }
    // Only the first response word is meaningful for a short response, and all four for
    // a long one; the host knows which it asked for.
    Some(12 + data)
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

/// Install the ephemeral-key source for the encrypted channel.
///
/// Called once from the boot sequence with a DRBG spawned from the entropy pool under its
/// own domain. Until then, and in recovery where no pool exists, `PairCommit` is refused.
///
/// Takes the clock rate with it: the pairing prompt's deadline is counted on the DWT
/// counter, and a board where that counter is not running gets no pairing at all rather
/// than a prompt that could wait forever.
pub fn install_drbg(drbg: HmacDrbg) {
    // SAFETY: reads RCC; the clocks are up by the time the boot path installs this.
    let per_ms = unsafe { catcard_hal::clock::hclk_hz() } / 1_000;
    let per_ms = if catcard_hal::dwt::is_running() {
        per_ms
    } else {
        0
    };
    with_task(|t| {
        t.drbg = Some(drbg);
        t.cycles_per_ms = per_ms;
        t.pair_clock = catcard_hal::dwt::cycles();
    });
}

/// A pairing code waiting on the device user. `id` names the prompt, so an answer is
/// applied to the one that was shown.
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub struct PairPrompt {
    pub id: u32,
    pub code: u32,
}

/// The pairing prompt the screen should be showing, if any.
pub fn pair_prompt() -> Option<PairPrompt> {
    with_task(|t| t.pair_prompt()).flatten()
}

/// The device user answered the pairing prompt `id`.
pub fn pair_answer(id: u32, accept: bool) {
    with_task(|t| t.pair_answer(id, accept));
}

/// Pairing is blocked after this many handshakes were abandoned; the screen should say so.
pub fn pair_blocked() -> Option<u8> {
    with_task(|t| t.pair_blocked()).flatten()
}

/// The person dismissed the pairing-blocked warning.
pub fn pair_unblock() {
    with_task(|t| t.pair_unblock());
}

/// Whether a computer's question (addresses, a signature) is waiting for the screen.
pub fn host_waiting() -> bool {
    with_task(|t| t.host.waiting()).unwrap_or(false)
}

/// Take the computer's question for the screen. It stays "on the screen" for the host
/// until [`host_finish`].
pub(crate) fn host_take() -> Option<crate::hostwallet::Taken> {
    with_task(|t| t.host.take()).flatten()
}

/// Whether the question `ticket` is still wanted: on the screen, and its session open.
pub(crate) fn host_alive(ticket: u32) -> bool {
    with_task(|t| t.host.on_screen(ticket) && t.chan.is_current(ticket)).unwrap_or(false)
}

/// Hand the person's answer to `ticket` back for the host to fetch.
pub(crate) fn host_finish(ticket: u32, outcome: crate::hostwallet::Outcome) {
    with_task(|t| {
        let open = t.chan.is_current(ticket);
        t.host.finish(ticket, outcome, open);
    });
}

/// Record what the session `ticket` was shown, replacing what it was shown before.
/// False when that session has already ended.
pub(crate) fn host_expose(ticket: u32, list: &[catcard_wallet::hostkeys::Exposed]) -> bool {
    with_task(|t| match t.chan.state_mut(ticket) {
        Some(st) => {
            st.exposed.clear();
            for e in list {
                let _ = st.exposed.push(*e);
            }
            true
        }
        None => false,
    })
    .unwrap_or(false)
}

/// The wallet in force changed: what the open session was shown describes the old one.
pub(crate) fn host_forget_wallet() {
    with_task(|t| {
        let id = t.chan.id();
        if let Some(st) = t.chan.state_mut(id) {
            st.exposed.clear();
        }
    });
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
/// How far a transfer in flight has got, for the screen that shows it.
pub fn receiving() -> Option<(u32, u32)> {
    with_task(|t| t.receiving()).flatten()
}

/// Abandon a transfer in flight, from the screen showing it.
pub fn abandon() {
    with_task(|t| t.abandon());
}

pub fn decline() {
    with_task(|t| t.decline());
}

/// The approved install was refused by the bootloader and its marker retracted; the
/// task may take offers again.
#[cfg(not(feature = "board-mk3"))]
pub fn install_refused() {
    with_task(|t| t.install_refused());
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
