//! The **ckcc** USB mode: stock Coldcard's USB identity and host protocol, so the host
//! tools that already exist for it -- the `ckcc` command line, HWI, Sparrow -- work with
//! this device unchanged.
//!
//! The owner chooses it at Settings → Hardware On/Off → `USB mode`; the default is CatCard's
//! own protocol. The wire format is [`catcard_usb::ckcc`], written from
//! `hw-reference/usb-ckcc-protocol.md`; this module is what each request *does*, and it
//! does it by calling the flows the firmware already has. See `docs/USB.md`, "USB modes".
//!
//! # Two halves on two tasks, as for the host-wallet commands
//!
//! [`Desk`] lives in the USB task. It takes reports, opens the session, parses requests
//! and answers what can be answered without a key or a person: `vers`, `ping`, `ncry`,
//! `upld`, `sha2`, `dwld`, the polls. It never derives, signs or waits.
//!
//! Everything that needs the seed or the person is a [`Job`], handed to the UI task by
//! [`serve`] -- called from the menu loop where the upgrade offer and the host-wallet
//! questions are, after the keys are read. Two shapes:
//!
//! - **Answered later** (`mitm`, `xpub`, `show`, `msck`): stock answers these in one round
//!   trip, so the reply is held back until the UI task has derived what it needs. The host
//!   waits on its read, as it would for stock's own delay.
//! - **Polled** (`stxn`/`stok`, `smsg`/`smok`, `pass`/`pwok`): the request is answered
//!   `okay` at once and the host polls until the person has decided, exactly as stock.
//!
//! A firmware upload is recognised when its last block arrives and handed to the same
//! approval screen a CatCard-mode upgrade offer uses (`usbtask::Stage::Offered`).
//!
//! # What is not here
//!
//! Key injection, the debug monitor, pairing and the host-wallet opcodes are CatCard-mode
//! only. Backup over USB, stock's factory opcodes and the miniscript ones stock itself
//! does not dispatch are answered with the protocol's own errors. `docs/USB.md` lists
//! every opcode and what it gets.
//!
//! # HSM mode
//!
//! The HSM opcodes (`hsms`, `hsts`, `gslr`, `nwur`, `rmur`, `user`) are jobs like the rest,
//! answered by `crate::hsm` on the UI task. While HSM mode runs, [`Desk`] lets through only
//! stock's whitelist, uploads only PSBTs, and [`serve`] answers every job by the policy
//! instead of a person: nothing waits on a key. See `docs/USB.md`, "HSM mode".

use core::fmt::Write as _;

use catcard_callgate::Callgate;
use catcard_upgrade::StagingArea as _;
use catcard_usb::ckcc::{self as wire, Fram, Link, NcryError, Request, Rx, RxEvent, Tx, reply};
use catcard_wallet::address::AddressKind;
use catcard_wallet::bip32::{ChildNumber, MAX_PATH_DEPTH};
use zeroize::Zeroize;

use crate::hostwallet::HostBuf;
use crate::menu;
use crate::ui::Ui;

/// Tickets for ckcc jobs carry this bit, so `usbtask::host_alive` -- which a signing flow
/// asks whether its computer is still there -- can tell them from host-wallet tickets.
pub(crate) const TICKET_BIT: u32 = 0x8000_0000;

/// The message buffer: the largest v3 message, which also holds the largest reply (a
/// 2048-byte `dwld` block with its tag).
const BUF_LEN: usize = wire::MAX_WIRE_LEN;
const _: () = assert!(4 + wire::MAX_BLK_LEN + wire::TAG_LEN <= BUF_LEN);

/// Largest `enrl` file stock accepts. Source: usb-ckcc-protocol.md §3.7 [C]
const ENROLL_MAX: u32 = 4000;
/// Smallest `stxn` stock accepts. Source: usb-ckcc-protocol.md §3.3 [C]
const TXN_MIN: u32 = 50;
/// Longest BIP-39 passphrase `pass` takes: `0 < len < 100`. Source: §3.8 [C]
const PASS_MAX: usize = 99;

/// The largest upload: stock's `MAX_UPLOAD_LEN` on mk4/mk5 (2 × 2 MiB), capped by what
/// this board can stage. Source: usb-ckcc-protocol.md §3.2 [C]
const MAX_UPLOAD: u32 = 4 << 20;

/// The mk3's largest non-image upload: its signing buffers. Anything larger goes to the
/// SPI-NOR staging area and can only be a firmware image.
#[cfg(feature = "board-mk3")]
const MK3_HEAP_UPLOAD: u32 = 16 * 1024;

/// Characters of a base58 extended key, with room.
const XPUB_LEN: usize = 112;

/// Largest PSBT: what HSM mode lets an upload be. Source: usb-ckcc-protocol.md §3.2
/// `MAX_TXN_LEN` on Mk4/5 [C]
const MAX_TXN_LEN: u32 = 2 << 20;

/// Longest username a request may carry, in bytes: sixteen characters of UTF-8.
/// Source: hsm-policy-format.md §2.1 `MAX_USERNAME_LEN` [C]
pub(crate) const NAME_BYTES: usize = 4 * catcard_settings::hsmusers::MAX_USERNAME_LEN;

// ---------------------------------------------------------------------------------------
// What the UI task learns once per wallet
// ---------------------------------------------------------------------------------------

/// The wallet as `ncry`, `vers`, `blkc` and `bagi` describe it. Public values only; kept
/// so the USB task can answer those at once.
pub(crate) struct Identity {
    /// Master fingerprint, as stock sends it (little-endian `u32` of the four bytes).
    /// Zero, with an empty xpub, when there is no wallet.
    xfp: u32,
    xpub: heapless::String<XPUB_LEN>,
    testnet: bool,
    bootloader: heapless::String<40>,
    bag: heapless::String<32>,
}

/// A derivation path from the host, checked for shape.
#[derive(Clone, Copy)]
pub(crate) struct Path {
    steps: [u32; MAX_PATH_DEPTH],
    depth: u8,
}

impl Path {
    fn parse(s: &str) -> Option<Self> {
        let mut steps = [0u32; MAX_PATH_DEPTH];
        let depth = wire::parse_path(s, &mut steps)? as u8;
        Some(Self { steps, depth })
    }

    fn children(&self) -> heapless::Vec<ChildNumber, MAX_PATH_DEPTH> {
        self.steps[..self.depth as usize]
            .iter()
            .map(|s| ChildNumber(*s))
            .collect()
    }

    fn text(&self) -> heapless::String<{ 2 + MAX_PATH_DEPTH * 12 }> {
        let mut t = heapless::String::new();
        let _ = t.push('m');
        for s in &self.steps[..self.depth as usize] {
            let _ = write!(t, "/{}", s & 0x7FFF_FFFF);
            if s & 0x8000_0000 != 0 {
                let _ = t.push('h');
            }
        }
        t
    }
}

/// A BIP-39 passphrase from the host, wiped when dropped.
pub(crate) struct Secret(heapless::String<PASS_MAX>);

impl Drop for Secret {
    fn drop(&mut self) {
        // SAFETY: every byte written is 0, which keeps the string valid UTF-8.
        unsafe { self.0.as_mut_vec().zeroize() };
    }
}

/// A `user` request's token -- a six-digit code, or a password's HMAC -- wiped when
/// dropped. Source: usb-ckcc-protocol.md §4.2, 6 to 32 bytes [C]
pub(crate) struct Token {
    bytes: [u8; 32],
    len: usize,
}

impl Token {
    fn new(b: &[u8]) -> Option<Self> {
        let (lo, hi) = catcard_settings::hsmusers::TOKEN_LEN;
        if !(lo..=hi).contains(&b.len()) {
            return None;
        }
        let mut bytes = [0u8; 32];
        bytes[..b.len()].copy_from_slice(b);
        Some(Self {
            bytes,
            len: b.len(),
        })
    }

    #[cfg_attr(feature = "board-mk3", allow(dead_code))]
    pub(crate) fn bytes(&self) -> &[u8] {
        &self.bytes[..self.len]
    }
}

impl Drop for Token {
    fn drop(&mut self) {
        self.bytes.zeroize();
    }
}

/// Where an upload is kept.
pub(crate) enum Store {
    /// PSRAM, through the staging driver's aligned stores, over a `Host` lease.
    #[cfg(not(feature = "board-mk3"))]
    Psram(crate::staging::Area),
    /// A small upload on the mk3: its signing buffers' worth, from the heap.
    #[cfg(feature = "board-mk3")]
    Heap(crate::heap::Block),
    /// A large upload on the mk3: the SPI-NOR staging area, where only a firmware image
    /// is any use.
    #[cfg(feature = "board-mk3")]
    Nor(crate::staging::Area),
}

impl Store {
    /// Claim somewhere for an upload of `total` bytes.
    fn take(total: u32) -> Result<Self, &'static str> {
        #[cfg(not(feature = "board-mk3"))]
        {
            let lease = crate::psram::take(crate::psram::Use::Host)
                .map_err(crate::psram::Unavailable::message)?;
            let area = crate::staging::area_from(lease).map_err(|_| "no memory for this")?;
            if total > area.capacity() {
                return Err("File too big");
            }
            Ok(Store::Psram(area))
        }
        #[cfg(feature = "board-mk3")]
        {
            if total <= MK3_HEAP_UPLOAD {
                return crate::heap::take(total as usize)
                    .map(Store::Heap)
                    .ok_or("Out of RAM");
            }
            let area = crate::staging::area().map_err(|_| "busy: the staging area")?;
            if total > area.capacity() {
                return Err("File too big");
            }
            Ok(Store::Nor(area))
        }
    }

    fn write(&mut self, offset: u32, data: &[u8]) -> Result<(), ()> {
        match self {
            #[cfg(not(feature = "board-mk3"))]
            Store::Psram(a) => a.write(offset, data).map_err(|_| ()),
            #[cfg(feature = "board-mk3")]
            Store::Nor(a) => a.write(offset, data).map_err(|_| ()),
            #[cfg(feature = "board-mk3")]
            Store::Heap(b) => {
                let at = offset as usize;
                b.bytes()
                    .get_mut(at..at + data.len())
                    .ok_or(())?
                    .copy_from_slice(data);
                Ok(())
            }
        }
    }

    fn read(&mut self, offset: u32, out: &mut [u8]) -> Result<(), ()> {
        match self {
            #[cfg(not(feature = "board-mk3"))]
            Store::Psram(a) => a.read(offset, out).map_err(|_| ()),
            #[cfg(feature = "board-mk3")]
            Store::Nor(a) => a.read(offset, out).map_err(|_| ()),
            #[cfg(feature = "board-mk3")]
            Store::Heap(b) => {
                let at = offset as usize;
                out.copy_from_slice(b.bytes().get(at..at + out.len()).ok_or(())?);
                Ok(())
            }
        }
    }

    /// The bytes as a signing flow takes them: the memory, and where the upload starts in
    /// it. `None` for the mk3's SPI-NOR, which holds only images.
    pub(crate) fn into_host_buf(self) -> Option<(HostBuf, usize)> {
        match self {
            #[cfg(not(feature = "board-mk3"))]
            Store::Psram(a) => {
                let at = a.image_at();
                Some((HostBuf::Psram(a.into_lease()), at))
            }
            #[cfg(feature = "board-mk3")]
            Store::Heap(b) => Some((HostBuf::Heap(b), 0)),
            #[cfg(feature = "board-mk3")]
            Store::Nor(_) => None,
        }
    }

    /// The staging area, if this upload is in one -- for a firmware image.
    fn into_area(self) -> Option<crate::staging::Area> {
        match self {
            #[cfg(not(feature = "board-mk3"))]
            Store::Psram(a) => Some(a),
            #[cfg(feature = "board-mk3")]
            Store::Nor(a) => Some(a),
            #[cfg(feature = "board-mk3")]
            Store::Heap(_) => None,
        }
    }
}

// ---------------------------------------------------------------------------------------
// Jobs: what the UI task is asked to do
// ---------------------------------------------------------------------------------------

/// Work for the UI task.
// The HSM jobs are built on every board and answered only where there is HSM mode.
#[cfg_attr(feature = "board-mk3", allow(dead_code))]
pub(crate) enum Job {
    /// Sign the session key with the master key, for the host's MitM check.
    Mitm([u8; 32]),
    /// The extended public key at a path.
    Xpub(Path),
    /// Show a single-key address on the screen, and send it.
    Show { kind: AddressKind, path: Path },
    /// Whether a registered multisig wallet matches M, N and the XOR of its fingerprints.
    MultisigCheck { m: u32, n: u32, xor: u32 },
    /// Show a registered multisig wallet's address: the `p2sh` arguments, already checked
    /// for shape, in a heap block of their own.
    P2sh {
        args: crate::heap::Block,
        len: usize,
    },
    /// Review and sign the uploaded PSBT.
    SignTx {
        store: Store,
        len: u32,
        sha: [u8; 32],
        finalize: bool,
    },
    /// Sign a text message with the key at `path`.
    SignMsg {
        kind: AddressKind,
        path: Path,
        msg: heapless::Vec<u8, { wire::MSG_SIGNING_MAX_LENGTH }>,
    },
    /// Put a BIP-39 passphrase in force.
    Passphrase(Secret),
    /// Register the multisig wallet in the uploaded file.
    Enroll { store: Store, len: u32 },
    /// Log out (`logo`) or restart (`rebo`), once the reply has gone.
    Logout { reboot: bool },
    /// `hsms`: check a policy -- the uploaded one, or the stored one -- answer, then put
    /// it in front of the person.
    HsmStart { upload: Option<(Store, u32)> },
    /// `hsts`: the status report.
    HsmStatus,
    /// `nwur`: make a user. `secret` is `None` when the device is to pick it.
    NewUser {
        mode: u8,
        name: heapless::String<NAME_BYTES>,
        secret: Option<catcard_settings::hsmusers::Secret>,
    },
    /// `rmur`.
    RemoveUser { name: heapless::String<NAME_BYTES> },
    /// `user`: queued for the next PSBT in HSM mode, checked at once outside it.
    UserAuth {
        totp_time: u32,
        name: heapless::String<NAME_BYTES>,
        token: Token,
    },
}

/// Which poll a finished job answers.
#[derive(Copy, Clone, PartialEq, Eq)]
enum Kind {
    /// Answered later, on the request itself.
    Held,
    SignTx,
    SignMsg,
    Pass,
    /// Answered `okay` and never polled for (`enrl`, `logo`, `rebo`).
    Quiet,
}

/// How the UI task answered.
pub(crate) enum Answer {
    /// A whole reply for a held request: `asci`/`biny`/`int1`/`err_` and its body.
    Reply(heapless::Vec<u8, 160>),
    /// `stok`'s result: the signed PSBT (or finished transaction) at `off`, `len` bytes.
    Signed {
        buf: HostBuf,
        off: usize,
        len: usize,
        sha: [u8; 32],
    },
    /// `smok`'s result.
    MsgSigned {
        address: heapless::String<{ catcard_wallet::address::MAX_ADDRESS_LEN }>,
        sig: [u8; 65],
    },
    /// `pwok`'s result: the new wallet's master xpub.
    Xpub(heapless::String<XPUB_LEN>),
    /// The person said no: `refu`.
    Refused,
    /// It could not be done: `err_` + why.
    Failed(&'static str),
    /// Done, nothing to say.
    Okay,
    /// An `asci` reply too long for [`Answer::Reply`]: the status report. `len` bytes of
    /// text in the block.
    #[cfg_attr(feature = "board-mk3", allow(dead_code))]
    Asci(crate::heap::Block, usize),
}

impl Answer {
    pub(crate) fn reply(build: impl FnOnce(&mut [u8]) -> Option<usize>) -> Self {
        let mut v = heapless::Vec::new();
        let mut tmp = [0u8; 160];
        match build(&mut tmp) {
            Some(n) => {
                let _ = v.extend_from_slice(&tmp[..n]);
                Answer::Reply(v)
            }
            None => Answer::Failed("Reply too long"),
        }
    }
}

/// A polled job's outcome, kept until the host polls for it. The signed file itself is
/// kept apart, in [`ResultFile`], for `dwld`.
enum Done {
    Strx {
        len: u32,
        sha: [u8; 32],
    },
    Smrx {
        address: heapless::String<{ catcard_wallet::address::MAX_ADDRESS_LEN }>,
        sig: [u8; 65],
    },
    Asci(heapless::String<XPUB_LEN>),
    Refused,
    Failed(&'static str),
    Okay,
}

enum Slot {
    Idle,
    Queued { ticket: u32, kind: Kind, job: Job },
    OnScreen { ticket: u32, kind: Kind },
    Done { kind: Kind, done: Done },
}

/// The signed result `dwld` reads back: file number 1.
struct ResultFile {
    buf: HostBuf,
    off: usize,
    len: usize,
}

/// A reply being framed out.
struct Out {
    len: usize,
    enc: bool,
    tx: Tx,
}

/// What the rest of the USB task needs from a report.
pub(crate) struct Cx<'a> {
    /// The PIN has been entered.
    pub unlocked: bool,
    /// Protocol randomness, for `ncry`'s ephemeral key. `None` in recovery.
    pub drbg: Option<&'a mut catcard_entropy::HmacDrbg>,
    /// A firmware image is waiting for the person, or approved: `rebo` must not reset.
    pub upgrade_pending: bool,
}

/// What the USB task must do after a report.
// The offer is moved straight into `usbtask::Stage`, which is as large; there is no
// allocator to box it into, and it lives on the stack for one call.
#[allow(clippy::large_enum_variant)]
pub(crate) enum Action {
    None,
    /// A firmware image arrived and inspected: put it in front of the person.
    Offer(
        catcard_upgrade::Staged<'static, crate::staging::Area>,
        catcard_upgrade::Approval,
    ),
}

// ---------------------------------------------------------------------------------------
// The USB task's half
// ---------------------------------------------------------------------------------------

pub(crate) struct Desk {
    link: Link,
    rx: Rx,
    /// The message buffer, taken from the heap when a message starts and given back once
    /// its reply has gone.
    buf: Option<crate::heap::Block>,
    /// A message arrived with no buffer to take it: its reports are dropped until the last
    /// one, and it is answered `busy`.
    dropping: bool,
    /// A short reply built without the heap: `busy`, with room for a tag.
    small: [u8; 4 + wire::TAG_LEN],
    small_len: usize,
    out: Option<Out>,
    /// A held request owed its reply: the job's ticket, and whether it came encrypted.
    owed: Option<(u32, bool)>,
    upload: wire::Upload,
    store: Option<Store>,
    result: Option<ResultFile>,
    slot: Slot,
    ident: Option<Identity>,
    next_ticket: u32,
    /// The header the upload in progress carried at `HEADER_OFFSET`, if it got that far.
    header: Option<[u8; catcard_fwhdr::HEADER_LEN]>,
}

/// Whether the spending policy has the device hobbled, as the UI task last saw it.
/// Mirrored rather than read from `crate::policy` because that state is the UI task's.
static HOBBLED: core::sync::atomic::AtomicBool = core::sync::atomic::AtomicBool::new(false);

fn hobbled() -> bool {
    HOBBLED.load(core::sync::atomic::Ordering::Relaxed)
}

/// Whether HSM mode is running. Set by `crate::hsm` on the UI task, read here by the USB
/// task's gate and by the flows that must not wait on a person while it runs. Never set on
/// the mk3, which has no HSM mode.
static HSM_ACTIVE: core::sync::atomic::AtomicBool = core::sync::atomic::AtomicBool::new(false);

/// Whether the HSM commands are answered: the owner's Spending Policy → HSM Mode switch
/// (`cat_hsmcmd`), or HSM mode itself running.
static HSM_COMMANDS: core::sync::atomic::AtomicBool = core::sync::atomic::AtomicBool::new(false);

/// Whether HSM mode is running: nothing may wait on a person, and the USB whitelist is in
/// force. False on the mk3.
pub(crate) fn hsm_active() -> bool {
    HSM_ACTIVE.load(core::sync::atomic::Ordering::Relaxed)
}

/// Put HSM mode's state where the USB task and the flows can see it. `crate::hsm` only.
#[cfg_attr(feature = "board-mk3", allow(dead_code))]
pub(crate) fn set_hsm_active(on: bool) {
    HSM_ACTIVE.store(on, core::sync::atomic::Ordering::Relaxed);
}

/// The owner's HSM commands switch, as the preferences read it.
pub(crate) fn set_hsm_commands(on: bool) {
    HSM_COMMANDS.store(on, core::sync::atomic::Ordering::Relaxed);
}

fn hsm_commands() -> bool {
    HSM_COMMANDS.load(core::sync::atomic::Ordering::Relaxed)
}

impl Desk {
    pub(crate) fn new() -> Self {
        Self {
            link: Link::new(),
            rx: Rx::new(),
            buf: None,
            dropping: false,
            small: [0; 4 + wire::TAG_LEN],
            small_len: 0,
            out: None,
            owed: None,
            upload: wire::Upload::new(),
            store: None,
            result: None,
            slot: Slot::Idle,
            ident: None,
            next_ticket: 0,
            header: None,
        }
    }

    /// A bus reset, a mode switch, or a new session: everything bound to the link goes.
    ///
    /// A job the person has on the screen is ended too, as a bus reset ends an upgrade
    /// offer: its flow sees [`alive`](Self::alive) go false and stops, and its answer is
    /// dropped.
    pub(crate) fn reset(&mut self) {
        self.link = Link::new();
        self.rx.reset();
        self.buf = None;
        self.dropping = false;
        self.small_len = 0;
        self.out = None;
        self.owed = None;
        self.upload.clear();
        self.store = None;
        self.result = None;
        self.header = None;
        self.slot = Slot::Idle;
    }

    /// Forget the wallet's identity: it changed (a passphrase, a temporary seed).
    pub(crate) fn forget_identity(&mut self) {
        self.ident = None;
    }

    /// Whether the UI task has something to do: a job, or the identity to learn.
    pub(crate) fn waiting(&self, unlocked: bool) -> bool {
        matches!(self.slot, Slot::Queued { .. }) || (unlocked && self.ident.is_none())
    }

    pub(crate) fn needs_identity(&self, unlocked: bool) -> bool {
        unlocked && self.ident.is_none()
    }

    pub(crate) fn set_identity(&mut self, ident: Identity) {
        self.ident = Some(ident);
    }

    /// The master xpub learnt, if the wallet has one.
    pub(crate) fn identity_xpub(&self) -> Option<heapless::String<XPUB_LEN>> {
        self.ident
            .as_ref()
            .filter(|i| i.xfp != 0)
            .map(|i| i.xpub.clone())
    }

    /// Hand the queued job to the UI task.
    pub(crate) fn take(&mut self) -> Option<(u32, Job)> {
        match core::mem::replace(&mut self.slot, Slot::Idle) {
            Slot::Queued { ticket, kind, job } => {
                self.slot = Slot::OnScreen { ticket, kind };
                Some((ticket, job))
            }
            other => {
                self.slot = other;
                None
            }
        }
    }

    /// Whether the job `ticket` is still wanted.
    pub(crate) fn alive(&self, ticket: u32) -> bool {
        matches!(self.slot, Slot::OnScreen { ticket: t, .. } if t == ticket)
    }

    /// The UI task's answer to `ticket`. Dropped if the job was abandoned meanwhile.
    pub(crate) fn finish(&mut self, ticket: u32, answer: Answer) {
        let Slot::OnScreen { ticket: t, kind } = self.slot else {
            return;
        };
        if t != ticket {
            return;
        }
        self.slot = Slot::Idle;
        match kind {
            Kind::Held => {
                let Some((owed, enc)) = self.owed else {
                    return;
                };
                if owed != ticket || self.out.is_some() {
                    return;
                }
                self.owed = None;
                let Some(buf) = self.buffer() else {
                    return;
                };
                let n = match answer {
                    Answer::Reply(r) => {
                        buf[..r.len()].copy_from_slice(&r);
                        r.len()
                    }
                    Answer::Asci(mut text, len) => {
                        let body = &text.bytes()[..len];
                        reply::asci(buf, body).unwrap_or(0)
                    }
                    Answer::Failed(why) => reply::err(buf, why).unwrap_or(0),
                    Answer::Refused => reply::refused(buf).unwrap_or(0),
                    _ => reply::okay(buf).unwrap_or(0),
                };
                self.send(n, enc);
            }
            Kind::Quiet => {}
            _ => {
                let done = match answer {
                    Answer::Signed { buf, off, len, sha } => {
                        // The file stays for `dwld`; the poll needs its length and digest.
                        self.result = Some(ResultFile { buf, off, len });
                        Done::Strx {
                            len: len as u32,
                            sha,
                        }
                    }
                    Answer::MsgSigned { address, sig } => Done::Smrx { address, sig },
                    Answer::Xpub(x) => Done::Asci(x),
                    Answer::Refused => Done::Refused,
                    Answer::Failed(why) => Done::Failed(why),
                    Answer::Okay | Answer::Reply(_) | Answer::Asci(..) => Done::Okay,
                };
                self.slot = Slot::Done { kind, done };
            }
        }
    }

    // ---- reports in --------------------------------------------------------------------

    /// Take one report from the host.
    pub(crate) fn feed(&mut self, report: &[u8; wire::REPORT_LEN], cx: &mut Cx<'_>) -> Action {
        if self.link.is_dead() {
            // Stock's USB task stops after a v3 failure; only a new bus session helps.
            return Action::None;
        }
        // A new message: the host has stopped waiting for anything before it. A reply still
        // owed to a held request is abandoned now, before this message's bytes land in the
        // buffer that reply would have been written into -- and any reply still going out
        // with it.
        if self.rx.pending() == 0 && !self.dropping {
            self.owed = None;
            self.out = None;
            self.small_len = 0;
        }
        // A message starting: lend it a buffer.
        if self.rx.pending() == 0 && !self.dropping && self.buf.is_none() {
            self.buf = crate::heap::take(BUF_LEN);
            if self.buf.is_none() {
                self.dropping = true;
            }
        }
        if self.dropping {
            let f = report[0];
            if f & wire::flag::LAST != 0 {
                self.dropping = false;
                if f & wire::flag::LEN_MASK == 0 {
                    return Action::None;
                }
                crate::catlog!("ckcc: no memory for a message; answered busy");
                self.link.desync();
                self.small_len = reply::busy(&mut self.small).unwrap_or(0);
                self.out = Some(Out {
                    len: self.small_len,
                    enc: false,
                    tx: Tx::new(),
                });
            }
            return Action::None;
        }
        let max = self.link.max_wire();
        let Some(block) = self.buf.as_mut() else {
            return Action::None;
        };
        let ev = self.rx.feed(report, block.bytes(), max);
        match ev {
            Ok(RxEvent::More) => Action::None,
            Ok(RxEvent::Reset) => {
                // Source: usb-ckcc-protocol.md §1.4 -- clears the upload, no reply [C]
                self.upload.clear();
                self.store = None;
                self.buf = None;
                Action::None
            }
            Err(f) => {
                self.framing(f);
                Action::None
            }
            Ok(RxEvent::Message { len, encrypted }) => self.message(len, encrypted, cx),
        }
    }

    fn framing(&mut self, f: Fram) {
        crate::catlog!("ckcc: framing error {}", f.reason());
        self.link.failed();
        let Some(buf) = self.buffer() else { return };
        let n = reply::fram(buf, f.reason()).unwrap_or(0);
        // Sent in the clear: whatever went wrong, it went wrong before a message could be
        // trusted to have been encrypted.
        self.send(n, false);
    }

    fn buffer(&mut self) -> Option<&mut [u8]> {
        if self.buf.is_none() {
            self.buf = crate::heap::take(BUF_LEN);
        }
        self.buf.as_mut().map(|b| &mut b.bytes()[..BUF_LEN])
    }

    /// Seal (when the request was encrypted) and start framing the reply in the buffer.
    fn send(&mut self, len: usize, enc: bool) {
        if len == 0 {
            return;
        }
        let len = if enc {
            let Some(block) = self.buf.as_mut() else {
                return;
            };
            match self.link.seal(&mut block.bytes()[..BUF_LEN], len) {
                Ok(n) => n,
                Err(_) => {
                    self.link.failed();
                    return;
                }
            }
        } else {
            len
        };
        self.out = Some(Out {
            len,
            enc,
            tx: Tx::new(),
        });
    }

    /// The next report of the reply in flight, if any. Gives the buffer back when the
    /// last report has gone and nothing else is waiting on it.
    pub(crate) fn next_report(&mut self, out: &mut [u8; wire::REPORT_LEN]) -> bool {
        let Some(o) = self.out.as_mut() else {
            return false;
        };
        let more = if self.small_len > 0 {
            o.tx.next(&self.small[..o.len], o.enc, out)
        } else {
            match self.buf.as_mut() {
                Some(b) => o.tx.next(&b.bytes()[..o.len], o.enc, out),
                None => false,
            }
        };
        if !more {
            self.out = None;
            self.small_len = 0;
            if self.owed.is_none() && self.rx.pending() == 0 {
                // Wiped on the way back to the heap: it held decrypted requests.
                self.buf = None;
            }
        }
        more
    }

    fn message(&mut self, len: usize, enc: bool, cx: &mut Cx<'_>) -> Action {
        // A new request while one was held: the host gave up on it. Its answer, when it
        // comes, goes nowhere.
        self.owed = None;
        let opened = {
            let Some(block) = self.buf.as_mut() else {
                return Action::None;
            };
            self.link.open(&mut block.bytes()[..BUF_LEN], len, enc)
        };
        let plen = match opened {
            Ok(n) => n,
            Err(f) => {
                self.framing(f);
                return Action::None;
            }
        };
        let mut action = Action::None;
        let n = self.dispatch(plen, enc, cx, &mut action);
        if let Some(n) = n {
            self.send(n, enc);
        }
        action
    }

    /// Queue a job, or say why not. `None` while another is in hand.
    fn queue(&mut self, kind: Kind, job: Job) -> Option<u32> {
        if !matches!(self.slot, Slot::Idle | Slot::Done { .. }) {
            return None;
        }
        self.next_ticket = self.next_ticket.wrapping_add(1) & !TICKET_BIT;
        let ticket = self.next_ticket | TICKET_BIT;
        self.slot = Slot::Queued { ticket, kind, job };
        Some(ticket)
    }

    /// Answer one request. The plaintext is at the start of the buffer; the reply is
    /// written over it. `None` when the reply is held for the UI task.
    fn dispatch(
        &mut self,
        plen: usize,
        enc: bool,
        cx: &mut Cx<'_>,
        action: &mut Action,
    ) -> Option<usize> {
        let mut block = self.buf.take()?;
        let n = self.dispatch_in(&mut block.bytes()[..BUF_LEN], plen, enc, cx, action);
        self.buf = Some(block);
        n
    }

    fn dispatch_in(
        &mut self,
        buf: &mut [u8],
        plen: usize,
        enc: bool,
        cx: &mut Cx<'_>,
        action: &mut Action,
    ) -> Option<usize> {
        // Requests borrow the buffer; replies overwrite it. So each arm takes what it
        // needs out of the request before it writes. `msg` is a copy of the fixed-size
        // arguments that are needed afterwards, never of bulk data.
        let (head, _) = buf.split_at_mut(plen);
        let parsed = Request::parse(head);
        let req = match parsed {
            Err(f) => {
                self.link.failed();
                return reply::fram(buf, f.reason());
            }
            Ok(Err(bad)) => return reply::err(buf, bad.text()),
            Ok(Ok(r)) => r,
        };

        // Gates. Source: usb-ckcc-protocol.md §2.7, §4.3 [C]
        let must_encrypt = matches!(
            req,
            Request::Xpub(_) | Request::Mitm | Request::Passphrase(_) | Request::Download { .. }
        );
        if must_encrypt && !enc {
            return reply::err(buf, "must encrypt");
        }
        let free_before_pin = matches!(
            req,
            Request::Version | Request::Ping(_) | Request::Ncry { .. } | Request::Chain
        );
        if !cx.unlocked && !free_before_pin {
            return reply::err(buf, "Not ready: enter the PIN on the device");
        }
        // HSM mode: stock's whitelist, and nothing else. Source: §4.3 `HSM_WHITELIST` [C]
        let hsm = hsm_active();
        if hsm && !req.allowed_in_hsm() {
            return reply::err(buf, "Not allowed in HSM mode");
        }
        let hobbled_refuses = matches!(
            req,
            Request::Enroll { .. }
                | Request::Backup
                | Request::Dfu
                | Request::Passphrase(_)
                | Request::PassphrasePoll
                | Request::Restore { .. }
        ) || matches!(req, Request::Bag(a) if !a.is_empty())
            || req.is_hsm_command();
        if hobbled_refuses && hobbled() {
            // Stock lets `pass` through when the policy's `okeys` allows it; this
            // firmware's policy has no such allowance, so it is refused like the rest.
            return reply::err(buf, "Spending policy in effect");
        }
        // The HSM commands, only with the owner's switch on -- or in HSM mode, which that
        // switch or the policy itself put the device in. Source: §4.3 `HSM_DISABLE_CMDS` [C]
        if req.is_hsm_command() && !hsm && !hsm_commands() {
            return reply::err(buf, "HSM commands disabled");
        }

        // On the mk3 a large upload sits in the SPI-NOR the settings store shares, and it
        // is no use unless it was an image -- which is recognised on its last block. So it
        // is let go as soon as the host moves on to anything but uploading and checking.
        #[cfg(feature = "board-mk3")]
        if !matches!(req, Request::Upload { .. } | Request::Sha)
            && matches!(self.store, Some(Store::Nor(_)))
        {
            self.store = None;
        }

        match req {
            Request::Logout | Request::Reboot => {
                let reboot = matches!(req, Request::Reboot);
                // `rebo` while an image waits for its answer does nothing: the approval
                // screen is what installs. Source: §3.1 [C]
                if !(reboot && cx.upgrade_pending) {
                    let _ = self.queue(Kind::Quiet, Job::Logout { reboot });
                }
                reply::okay(buf)
            }
            Request::Version => self.version(buf),
            Request::Ping(_) => {
                // Echo in place: `biny` goes where the opcode was.
                buf[..4].copy_from_slice(b"biny");
                Some(plen)
            }
            Request::Ncry { version, host_pub } => {
                let host_pub = *host_pub;
                self.ncry(buf, version, &host_pub, cx)
            }
            Request::Mitm => {
                let Some(key) = self.link.session_key().copied() else {
                    return reply::err(buf, "no key");
                };
                if self.ident.as_ref().is_some_and(|i| i.xfp == 0) {
                    return reply::err(buf, "No secrets yet");
                }
                self.hold(buf, enc, Job::Mitm(key))
            }
            Request::Chain => {
                let testnet = self.ident.as_ref().is_some_and(|i| i.testnet);
                reply::asci(buf, if testnet { b"XTN" } else { b"BTC" })
            }
            Request::Bag(new) => {
                if !new.is_empty() {
                    // Stock writes the bag number once, at the factory.
                    return reply::err(buf, "Not allowed");
                }
                let mut bag = heapless::String::<32>::new();
                if let Some(i) = &self.ident {
                    let _ = bag.push_str(&i.bag);
                }
                reply::asci(buf, bag.as_bytes())
            }
            Request::Upload {
                offset,
                total,
                data,
            } => {
                let data_len = data.len();
                let r = self.upload_block(offset, total, 12, data_len, buf, action);
                match r {
                    Ok(()) => reply::int1(buf, offset),
                    Err(why) => reply::err(buf, why),
                }
            }
            Request::Download {
                offset,
                length,
                file,
            } => self.download(buf, offset, length, file),
            Request::Sha => {
                let d = self.upload.digest();
                reply::biny(buf, &d)
            }
            Request::SignTx { len, flags, sha } => {
                let sha = *sha;
                self.sign_tx(buf, len, flags, sha)
            }
            Request::SignTxPoll => self.poll(buf, Kind::SignTx),
            Request::SignMsg {
                addr_fmt,
                path,
                msg,
            } => {
                let Some(kind) = kind_of(addr_fmt) else {
                    return reply::err(buf, "Unsupported address format");
                };
                if kind == AddressKind::P2tr {
                    // Stock's legacy message signature has no taproot header, and this is
                    // the format the host reads back.
                    return reply::err(buf, "Taproot message signing not supported");
                }
                let Some(path) = Path::parse(path) else {
                    return reply::err(buf, "Bad path");
                };
                if msg.is_empty() || msg.len() > wire::MSG_SIGNING_MAX_LENGTH {
                    return reply::err(buf, "Message too long");
                }
                let mut m = heapless::Vec::new();
                let _ = m.extend_from_slice(msg);
                match self.queue(Kind::SignMsg, Job::SignMsg { kind, path, msg: m }) {
                    Some(_) => reply::okay(buf),
                    None => reply::busy(buf),
                }
            }
            Request::SignMsgPoll => self.poll(buf, Kind::SignMsg),
            Request::Xpub(p) => {
                let Some(path) = Path::parse(p) else {
                    return reply::err(buf, "Bad path");
                };
                // The master key is known already; anything else is derived.
                if path.depth == 0
                    && let Some(i) = self.ident.as_ref().filter(|i| i.xfp != 0)
                {
                    let x = i.xpub.clone();
                    return reply::asci(buf, x.as_bytes());
                }
                self.hold(buf, enc, Job::Xpub(path))
            }
            Request::Show { addr_fmt, path } => {
                // An older host's taproot code. Source: §3.6 [C]
                let fmt = if addr_fmt == wire::af::P2TR_OLD {
                    wire::af::P2TR
                } else {
                    addr_fmt
                };
                if fmt & wire::af::SCRIPT != 0 {
                    return reply::err(buf, "Use p2sh for scripts");
                }
                let Some(kind) = kind_of(fmt) else {
                    return reply::err(buf, "Unsupported address format");
                };
                let Some(path) = Path::parse(path) else {
                    return reply::err(buf, "Bad path");
                };
                self.hold(buf, enc, Job::Show { kind, path })
            }
            Request::P2sh(a) => {
                if let Err(bad) = wire::P2sh::parse(a) {
                    return reply::err(buf, bad.text());
                }
                let len = a.len();
                let Some(mut args) = crate::heap::take(len) else {
                    return reply::err(buf, "Out of RAM");
                };
                args.bytes()[..len].copy_from_slice(a);
                self.hold(buf, enc, Job::P2sh { args, len })
            }
            Request::MultisigCheck { m, n, xfp_xor } => {
                self.hold(buf, enc, Job::MultisigCheck { m, n, xor: xfp_xor })
            }
            Request::Enroll { len, sha } => {
                let sha = *sha;
                if !(101..=ENROLL_MAX).contains(&len) {
                    return reply::err(buf, "Bad length");
                }
                if let Err(why) = self.whole_upload(len, &sha) {
                    return reply::err(buf, why);
                }
                let Some(store) = self.store.take() else {
                    return reply::err(buf, "Nothing uploaded");
                };
                match self.queue(Kind::Quiet, Job::Enroll { store, len }) {
                    Some(_) => reply::okay(buf),
                    None => reply::busy(buf),
                }
            }
            Request::Passphrase(p) => {
                let Ok(text) = core::str::from_utf8(p) else {
                    return reply::err(buf, "Bad passphrase");
                };
                // Printable ASCII, no tab or newline, 1..=99 bytes. Source: §3.8 [C]
                if text.is_empty()
                    || text.len() > PASS_MAX
                    || !text.bytes().all(|b| (0x20..0x7F).contains(&b))
                {
                    return reply::err(buf, "Bad passphrase");
                }
                let mut s = heapless::String::new();
                let _ = s.push_str(text);
                let secret = Secret(s);
                // The copy in the request buffer is wiped with it when the reply is
                // written over it and the block goes back.
                match self.queue(Kind::Pass, Job::Passphrase(secret)) {
                    Some(_) => reply::okay(buf),
                    None => reply::busy(buf),
                }
            }
            Request::PassphrasePoll => self.poll(buf, Kind::Pass),
            // HSM. Source: usb-ckcc-protocol.md §4 [C]; what each does is `crate::hsm`.
            Request::HsmStart(args) => {
                let upload = match args {
                    None => None,
                    Some((len, sha)) => {
                        let sha = *sha;
                        if !wire::HSM_POLICY_LEN.contains(&len) {
                            return reply::err(buf, "Bad length");
                        }
                        if let Err(why) = self.whole_upload(len, &sha) {
                            return reply::err(buf, why);
                        }
                        let Some(store) = self.store.take() else {
                            return reply::err(buf, "Nothing uploaded");
                        };
                        Some((store, len))
                    }
                };
                self.hold(buf, enc, Job::HsmStart { upload })
            }
            Request::HsmStatus => self.hold(buf, enc, Job::HsmStatus),
            // The Storage Locker: no policy this firmware accepts allows a read (see
            // `catcard_settings::hsm`), and stock answers it only in HSM mode.
            Request::StorageLocker => reply::err(
                buf,
                if hsm {
                    "Storage Locker not supported"
                } else {
                    "HSM not active"
                },
            ),
            Request::NewUser { mode, name, secret } => {
                let Some(name) = name_of(name) else {
                    return reply::err(buf, "Bad username");
                };
                let secret = if secret.is_empty() {
                    None
                } else {
                    match catcard_settings::hsmusers::Secret::new(secret) {
                        Some(s) => Some(s),
                        None => return reply::err(buf, "Bad secret length"),
                    }
                };
                self.hold(buf, enc, Job::NewUser { mode, name, secret })
            }
            Request::RemoveUser { name } => {
                let Some(name) = name_of(name) else {
                    return reply::err(buf, "Bad username");
                };
                self.hold(buf, enc, Job::RemoveUser { name })
            }
            Request::UserAuth {
                totp_time,
                name,
                token,
            } => {
                let Some(name) = name_of(name) else {
                    return reply::err(buf, "Bad username");
                };
                let Some(token) = Token::new(token) else {
                    return reply::err(buf, "Bad token length");
                };
                self.hold(
                    buf,
                    enc,
                    Job::UserAuth {
                        totp_time,
                        name,
                        token,
                    },
                )
            }
            // Not in this firmware: backup and restore over USB (the card does both), and
            // stock's factory DFU entry, which a locked bench unit could not take anyway.
            // Answered as stock answers a command it does not have.
            Request::Backup
            | Request::BackupPoll
            | Request::Restore { .. }
            | Request::Dfu
            | Request::NotDispatched(_)
            | Request::Unknown(_) => {
                if self.link.is_bound() {
                    // A bound (v2/v3) session that sends a command it should not have is
                    // ended, as stock ends it. Source: §3.10 "bound self-destruct" [C]
                    crate::catlog!("ckcc: unknown command on a bound link; logging out");
                    let _ = self.queue(Kind::Quiet, Job::Logout { reboot: false });
                }
                reply::err(buf, "Unknown cmd")
            }
        }
    }

    /// Hold the request for the UI task.
    fn hold(&mut self, buf: &mut [u8], enc: bool, job: Job) -> Option<usize> {
        match self.queue(Kind::Held, job) {
            Some(ticket) => {
                self.owed = Some((ticket, enc));
                None
            }
            None => reply::busy(buf),
        }
    }

    /// `vers`: date, version, bootloader, date-and-version, hardware. Source: §3.1 [C]
    fn version(&self, buf: &mut [u8]) -> Option<usize> {
        let mut t: heapless::String<120> = heapless::String::new();
        let stamp = crate::own_header()
            .map(|h| catcard_fwhdr::format_timestamp(&h.timestamp))
            .unwrap_or(*b"20??-??-?? ??:??");
        let date = core::str::from_utf8(&stamp[..10]).unwrap_or("?");
        let hhmm = [stamp[11], stamp[12], stamp[14], stamp[15]];
        let boot = self
            .ident
            .as_ref()
            .map(|i| i.bootloader.as_str())
            .unwrap_or("unknown");
        let _ = write!(
            t,
            "{}\n{}\n{}\n{}T{}-v{}\n{}",
            date,
            crate::VERSION,
            boot,
            date,
            core::str::from_utf8(&hhmm).unwrap_or("0000"),
            crate::VERSION,
            crate::running_board()
        );
        reply::asci(buf, t.as_bytes())
    }

    /// `ncry`: a new session. Source: §2.1 [C]
    fn ncry(
        &mut self,
        buf: &mut [u8],
        version: u32,
        host_pub: &[u8; 64],
        cx: &mut Cx<'_>,
    ) -> Option<usize> {
        let Some(drbg) = cx.drbg.as_deref_mut() else {
            return reply::err(buf, "no entropy");
        };
        let mut scalar = [0u8; 32];
        if drbg.generate(&mut scalar).is_err() {
            return reply::err(buf, "no entropy");
        }
        let got = self.link.handshake(version, host_pub, &scalar);
        scalar.zeroize();
        match got {
            Ok(dev_pub) => {
                let (xfp, xpub) = match &self.ident {
                    Some(i) => (i.xfp, i.xpub.clone()),
                    None => (0, heapless::String::new()),
                };
                reply::mypb(buf, &dev_pub, xfp, xpub.as_bytes())
            }
            Err(NcryError::Fram(f)) => {
                self.link.failed();
                reply::fram(buf, f.reason())
            }
            Err(NcryError::BadKey) => reply::err(buf, "Bad pubkey"),
        }
    }

    /// One `upld` block: checked, then stored. On the last block of an image, the image
    /// is inspected and offered.
    fn upload_block(
        &mut self,
        offset: u32,
        total: u32,
        data_at: usize,
        data_len: usize,
        buf: &mut [u8],
        action: &mut Action,
    ) -> Result<(), &'static str> {
        let data = &buf[data_at..data_at + data_len];
        self.upload.check(offset, total, data_len, MAX_UPLOAD)?;
        if offset == 0 {
            // Under the spending policy only a PSBT may be uploaded. Source: §3.2 [C]
            if hobbled() && !data.starts_with(b"psbt\xff") {
                return Err("Spending policy in effect");
            }
            // And in HSM mode: a binary PSBT, no larger than one. Source: §3.2 [C]
            if hsm_active() && (!data.starts_with(b"psbt\xff") || total > MAX_TXN_LEN) {
                return Err("Not allowed in HSM mode");
            }
            // A new file: whatever was held for the last one goes first, so its memory
            // is free to take.
            self.store = None;
            self.result = None;
            self.header = None;
            self.store = Some(Store::take(total)?);
        }
        let Some(store) = self.store.as_mut() else {
            return Err("Out of order");
        };
        store.write(offset, data).map_err(|_| "Storage fault")?;
        self.upload.accept(offset, total, data);
        // The image's header, as it goes past, for recognising the image at its end.
        use catcard_fwhdr::{HEADER_LEN, HEADER_OFFSET};
        let (at, end) = (offset as usize, offset as usize + data.len());
        if at <= HEADER_OFFSET && end >= HEADER_OFFSET + HEADER_LEN {
            let mut h = [0u8; HEADER_LEN];
            h.copy_from_slice(&data[HEADER_OFFSET - at..HEADER_OFFSET - at + HEADER_LEN]);
            self.header = Some(h);
        }
        if self.upload.complete()
            && let Some((staged, approval)) = self.firmware(offset, data)?
        {
            *action = Action::Offer(staged, approval);
        }
        Ok(())
    }

    /// If the block just stored finished a firmware image, inspect it and hand it back.
    ///
    /// The host tool sends the image, then the image's 128-byte header again after it,
    /// raising the total by 128 (observed from `ckcc upgrade`; see `docs/USB.md`). So the
    /// upload is an image when its last block is 128 bytes that repeat the header the
    /// image carried at `HEADER_OFFSET` -- which was kept, in RAM, as it went past. Nothing
    /// is read back from the staging medium to decide: a read placed among PSRAM writes is
    /// what corrupts it (`catcard_upgrade::psram`), and more writes may follow.
    ///
    /// `Ok(None)`: not an image, keep the upload. `Err`: an image, refused -- the host is
    /// told on this block, so it does not go on to ask for the reboot that would install.
    #[allow(clippy::type_complexity)]
    fn firmware(
        &mut self,
        offset: u32,
        data: &[u8],
    ) -> Result<
        Option<(
            catcard_upgrade::Staged<'static, crate::staging::Area>,
            catcard_upgrade::Approval,
        )>,
        &'static str,
    > {
        use catcard_fwhdr::HEADER_LEN;
        let is_image = offset >= catcard_fwhdr::MIN_FIRMWARE_LENGTH
            && data.len() == HEADER_LEN
            && self.header.as_ref().is_some_and(|h| h[..] == *data);
        if !is_image {
            return Ok(None);
        }
        if hobbled() {
            crate::catlog!("ckcc: firmware upload refused under the spending policy");
            return Err("Spending policy in effect");
        }
        let area = self
            .store
            .take()
            .and_then(Store::into_area)
            .ok_or("Nowhere to stage it")?;
        let mut staged = catcard_upgrade::Staged::begin(area, &catcard_board::BOARD, offset)
            .map_err(|r| {
                crate::catlog!("ckcc: image refused: {:?}", r);
                crate::sdupgrade::describe(r)
            })?;
        staged.stored_elsewhere();
        match staged.inspect(crate::own_header().as_ref()) {
            Ok(a) => {
                crate::catlog!("ckcc: firmware image {} bytes offered", offset);
                Ok(Some((staged, a)))
            }
            Err(r) => {
                crate::catlog!("ckcc: image refused: {:?}", r);
                Err(crate::sdupgrade::describe(r))
            }
        }
    }

    /// The whole upload is `len` bytes and digests to `sha`.
    fn whole_upload(&self, len: u32, sha: &[u8; 32]) -> Result<(), &'static str> {
        if self.store.is_none() || !self.upload.complete() || self.upload.total() != len {
            return Err("Nothing uploaded");
        }
        if self.upload.digest() != *sha {
            return Err("Checksum");
        }
        Ok(())
    }

    /// `stxn`: review and sign what was uploaded. Source: §3.3 [C]
    fn sign_tx(&mut self, buf: &mut [u8], len: u32, flags: u32, sha: [u8; 32]) -> Option<usize> {
        let flags = flags & wire::stxn::MASK;
        if flags & (wire::stxn::VISUALIZE | wire::stxn::SIGNED) != 0 {
            return reply::err(buf, "Visualize not supported");
        }
        if len <= TXN_MIN {
            return reply::err(buf, "Too short");
        }
        if let Err(why) = self.whole_upload(len, &sha) {
            return reply::err(buf, why);
        }
        if !matches!(self.slot, Slot::Idle | Slot::Done { .. }) {
            return reply::busy(buf);
        }
        let store = self.store.take()?;
        self.result = None;
        match self.queue(
            Kind::SignTx,
            Job::SignTx {
                store,
                len,
                sha,
                finalize: flags & wire::stxn::FINALIZE != 0,
            },
        ) {
            Some(_) => reply::okay(buf),
            None => reply::busy(buf),
        }
    }

    /// `stok` / `smok` / `pwok`. Source: §3.9 [C]
    fn poll(&mut self, buf: &mut [u8], want: Kind) -> Option<usize> {
        match &self.slot {
            Slot::Queued { kind, .. } | Slot::OnScreen { kind, .. } if *kind == want => {
                return reply::okay(buf);
            }
            Slot::Done { kind, .. } if *kind == want => {}
            _ => return reply::err(buf, "No active request"),
        }
        let Slot::Done { done, .. } = core::mem::replace(&mut self.slot, Slot::Idle) else {
            return reply::err(buf, "No active request");
        };
        match done {
            Done::Strx { len, sha } => reply::strx(buf, len, &sha),
            Done::Smrx { address, sig } => reply::smrx(buf, address.as_bytes(), &sig),
            Done::Asci(x) => reply::asci(buf, x.as_bytes()),
            Done::Refused => reply::refused(buf),
            Done::Failed(why) => reply::err(buf, why),
            Done::Okay => reply::okay(buf),
        }
    }

    /// `dwld`: a block of the signed result. Only file 1, the result the last `stok`
    /// named, is readable -- never the upload area or anything else. Source: §3.2 [C]
    fn download(&mut self, buf: &mut [u8], offset: u32, length: u32, file: u32) -> Option<usize> {
        if file != 1 {
            return reply::err(buf, "Not allowed");
        }
        let Some(r) = self.result.as_mut() else {
            return reply::err(buf, "Nothing to download");
        };
        let length = (length as usize).min(wire::MAX_BLK_LEN);
        let start = offset as usize;
        let Some(end) = start.checked_add(length).filter(|e| *e <= r.len) else {
            return reply::err(buf, "Past end");
        };
        let src = &r.buf.bytes()[r.off + start..r.off + end];
        reply::biny(buf, src)
    }
}

/// A username off the wire, as text that fits.
fn name_of(b: &[u8]) -> Option<heapless::String<NAME_BYTES>> {
    let s = core::str::from_utf8(b).ok()?;
    let mut n = heapless::String::new();
    n.push_str(s).ok()?;
    Some(n)
}

/// The single-key address type an `AF_*` code names.
fn kind_of(fmt: u32) -> Option<AddressKind> {
    use wire::af;
    Some(match fmt {
        af::CLASSIC => AddressKind::P2pkh,
        af::P2WPKH => AddressKind::P2wpkh,
        af::P2WPKH_P2SH => AddressKind::P2shP2wpkh,
        af::P2TR => AddressKind::P2tr,
        _ => return None,
    })
}

// ---------------------------------------------------------------------------------------
// The UI task's half
// ---------------------------------------------------------------------------------------

const HEAD: &str = "Computer";

/// Whether the ckcc mode has work for the screen. Called from the menu loop every frame,
/// so it is also where the spending policy's state is mirrored for the USB task.
pub(crate) fn pending() -> bool {
    HOBBLED.store(
        crate::policy::hobbled(),
        core::sync::atomic::Ordering::Relaxed,
    );
    crate::usbtask::ck_waiting()
}

/// Do whatever the ckcc mode is waiting on. Called from the menu loop when [`pending`].
pub(crate) fn serve(gate: &Callgate, login: &mut catcard_pin::Login, ui: &mut Ui<'_>) {
    if crate::usbtask::ck_needs_identity() {
        learn_identity(gate, login, ui);
        return;
    }
    let Some((ticket, job)) = crate::usbtask::ck_take() else {
        return;
    };
    // HSM mode: the policy answers, not a person.
    #[cfg(not(feature = "board-mk3"))]
    if hsm_active() {
        return unattended(gate, login, ui, ticket, job);
    }
    match job {
        Job::Logout { reboot } => {
            use catcard_callgate::abi::LogoutMode;
            crate::catlog!(
                "ckcc: computer asked to {}",
                if reboot { "reboot" } else { "log out" }
            );
            // Long enough for the `okay` to leave: stock waits half a second too.
            for _ in 0..50 {
                let _ = crate::usbtask::pump();
                // SAFETY: reads RCC; the clocks have been up since boot.
                unsafe { catcard_hal::dwt::delay_ms(10) };
            }
            login.zeroize();
            menu::message(ui.panel, HEAD, "logged out", "");
            let mode = if reboot {
                LogoutMode::LogoutAndReboot
            } else {
                LogoutMode::Logout
            };
            // SAFETY: nothing after this runs; the bootloader wipes SRAM.
            unsafe { gate.logout(mode) }
        }
        Job::Mitm(key) => {
            let a = mitm(gate, login, ui, &key);
            crate::usbtask::ck_finish(ticket, a);
        }
        Job::Xpub(path) => {
            let a = xpub(gate, login, ui, &path);
            crate::usbtask::ck_finish(ticket, a);
        }
        Job::Show { kind, path } => show(gate, login, ui, ticket, kind, &path, true),
        Job::MultisigCheck { m, n, xor } => {
            let a = multisig_check(gate, login, ui, m, n, xor);
            crate::usbtask::ck_finish(ticket, a);
        }
        Job::P2sh { args, len } => p2sh(gate, login, ui, ticket, args, len, true),
        Job::SignTx {
            store,
            len,
            sha,
            finalize,
        } => {
            let a = sign_tx(gate, login, ui, ticket, store, len, &sha, finalize);
            let said = said(&a);
            crate::usbtask::ck_finish(ticket, a);
            after(ui, said);
        }
        Job::SignMsg { kind, path, msg } => {
            let a = sign_msg(gate, login, ui, ticket, kind, &path, &msg);
            let said = said(&a);
            crate::usbtask::ck_finish(ticket, a);
            after(ui, said);
        }
        Job::Passphrase(secret) => {
            let a = passphrase(gate, login, ui, secret);
            crate::usbtask::ck_finish(ticket, a);
        }
        Job::Enroll { store, len } => {
            enroll(gate, login, ui, store, len);
            crate::usbtask::ck_finish(ticket, Answer::Okay);
        }
        #[cfg(not(feature = "board-mk3"))]
        Job::HsmStart { upload } => crate::hsm::start_from_host(gate, login, ui, ticket, upload),
        #[cfg(not(feature = "board-mk3"))]
        Job::HsmStatus => {
            let a = crate::hsm::status(gate, login, ui);
            crate::usbtask::ck_finish(ticket, a);
        }
        #[cfg(not(feature = "board-mk3"))]
        Job::NewUser { mode, name, secret } => {
            crate::hsm::new_user(gate, login, ui, ticket, mode, &name, secret)
        }
        #[cfg(not(feature = "board-mk3"))]
        Job::RemoveUser { name } => {
            let a = crate::hsm::remove_user(gate, login, ui, &name);
            crate::usbtask::ck_finish(ticket, a);
        }
        #[cfg(not(feature = "board-mk3"))]
        Job::UserAuth {
            totp_time,
            name,
            token,
        } => {
            let a = crate::hsm::user_auth(gate, login, ui, totp_time, &name, &token);
            crate::usbtask::ck_finish(ticket, a);
        }
        // Never queued on the mk3: its gate answers them first.
        #[cfg(feature = "board-mk3")]
        Job::HsmStart { .. }
        | Job::HsmStatus
        | Job::NewUser { .. }
        | Job::RemoveUser { .. }
        | Job::UserAuth { .. } => {
            crate::usbtask::ck_finish(ticket, Answer::Failed("HSM commands disabled"))
        }
    }
}

/// A job in HSM mode: answered by the policy, with nothing on the screen that waits.
///
/// What a person would have been asked is asked of `crate::hsm` instead -- signing by the
/// rules, messages by `msg_paths`, keys and addresses by `share_xpubs` / `share_addrs` --
/// and everything the USB gate should not have let through is refused again here.
/// Source: hsm-policy-format.md §3.1, usb-ckcc-protocol.md §3.6, §4.3 [C]
#[cfg(not(feature = "board-mk3"))]
fn unattended(
    gate: &Callgate,
    login: &mut catcard_pin::Login,
    ui: &mut Ui<'_>,
    ticket: u32,
    job: Job,
) {
    const DENIED: &str = "Not allowed in HSM mode";
    let done = |a: Answer| crate::usbtask::ck_finish(ticket, a);
    match job {
        Job::Logout { reboot: false } => {
            use catcard_callgate::abi::LogoutMode;
            crate::catlog!("ckcc: computer asked to log out of HSM mode");
            for _ in 0..50 {
                let _ = crate::usbtask::pump();
                // SAFETY: reads RCC; the clocks have been up since boot.
                unsafe { catcard_hal::dwt::delay_ms(10) };
            }
            login.zeroize();
            // SAFETY: nothing after this runs; the bootloader wipes SRAM.
            unsafe { gate.logout(LogoutMode::Logout) }
        }
        Job::Mitm(key) => done(mitm(gate, login, ui, &key)),
        Job::Xpub(path) => {
            if crate::hsm::may_share_xpub(&path.steps[..path.depth as usize]) {
                done(xpub(gate, login, ui, &path));
            } else {
                done(Answer::Failed(DENIED));
            }
        }
        Job::Show { kind, path } => {
            if crate::hsm::may_share_address(&path.steps[..path.depth as usize]) {
                show(gate, login, ui, ticket, kind, &path, false);
            } else {
                done(Answer::Failed(DENIED));
            }
        }
        Job::P2sh { args, len } => {
            if crate::hsm::may_share_p2sh() {
                p2sh(gate, login, ui, ticket, args, len, false);
            } else {
                done(Answer::Failed(DENIED));
            }
        }
        Job::MultisigCheck { m, n, xor } => done(multisig_check(gate, login, ui, m, n, xor)),
        Job::SignTx {
            store,
            len,
            sha,
            finalize,
        } => {
            let a = sign_tx(gate, login, ui, ticket, store, len, &sha, finalize);
            // Refused before the rules were reached (not a PSBT, a fee over the cap, ...):
            // counted as a refusal all the same, as stock's `refuse` counts every one.
            if let Answer::Failed(why) = &a {
                crate::hsm::refuse_request(why);
            }
            done(a);
        }
        Job::SignMsg { kind, path, msg } => {
            let a = sign_msg(gate, login, ui, ticket, kind, &path, &msg);
            if let Answer::Failed(why) = &a {
                crate::hsm::refuse_request(why);
            }
            done(a);
        }
        Job::HsmStatus => done(crate::hsm::status(gate, login, ui)),
        Job::UserAuth {
            totp_time,
            name,
            token,
        } => done(crate::hsm::user_auth(
            gate, login, ui, totp_time, &name, &token,
        )),
        Job::Logout { reboot: true }
        | Job::Passphrase(_)
        | Job::Enroll { .. }
        | Job::HsmStart { .. }
        | Job::NewUser { .. }
        | Job::RemoveUser { .. } => done(Answer::Failed(DENIED)),
    }
}

/// What the last screen of a signing flow says.
#[derive(Copy, Clone)]
enum Said {
    Sent,
    Declined,
    Failed(&'static str),
}

fn said(a: &Answer) -> Said {
    match a {
        Answer::Signed { .. } | Answer::MsgSigned { .. } => Said::Sent,
        Answer::Failed(why) => Said::Failed(why),
        _ => Said::Declined,
    }
}

fn after(ui: &mut Ui<'_>, said: Said) {
    match said {
        Said::Sent => menu::message(ui.panel, "Sent back", "to the computer", ""),
        Said::Declined => menu::message(ui.panel, "Declined", "computer was told", ""),
        Said::Failed(why) => menu::message(ui.panel, "Not sent", why, "computer was told"),
    }
    menu::wait_for_any_key(ui);
}

/// The master key, quietly: the working screen only, no dialogs.
fn master(
    gate: &Callgate,
    login: &mut catcard_pin::Login,
    ui: &mut Ui<'_>,
) -> Result<catcard_wallet::bip32::ExtendedPrivKey, &'static str> {
    menu::master_quietly(gate, login, ui.panel, HEAD)
}

/// Derive the wallet's public identity once per wallet: what `ncry` and `vers` report.
fn learn_identity(gate: &Callgate, login: &mut catcard_pin::Login, ui: &mut Ui<'_>) {
    let mut ident = Identity {
        xfp: 0,
        xpub: heapless::String::new(),
        testnet: !matches!(
            crate::prefs::network(),
            catcard_wallet::bip32::Network::Mainnet
        ),
        bootloader: heapless::String::new(),
        bag: heapless::String::new(),
    };
    let mut ver = [0u8; 64];
    // SAFETY: a 64-byte buffer, the documented minimum; the call masks interrupts.
    if let Ok(n) = unsafe { gate.bootloader_version(&mut ver) } {
        let s = core::str::from_utf8(&ver[..n.min(ver.len())]).unwrap_or("");
        let s = s.trim_end_matches('\0');
        let _ = ident.bootloader.push_str(&s[..s.len().min(40)]);
    }
    let mut bag = [0u8; 32];
    // SAFETY: the documented 32-byte buffer; read only; interrupts masked in the call.
    if unsafe { gate.bag_number(&mut bag) }.is_ok() {
        for b in bag.iter().take_while(|b| b.is_ascii_graphic()) {
            let _ = ident.bag.push(*b as char);
        }
    }
    // A device with no wallet -- or one whose wallet is not HD -- has no identity to give,
    // and says so the way stock does: fingerprint zero and no xpub.
    if let Ok(m) = master(gate, login, ui) {
        let (fp, n, x) = crate::keywork::run(|kw| {
            let fp = m.fingerprint(kw);
            let mut x = [0u8; XPUB_LEN];
            let n = m.to_extended_pub(kw).write_base58(&mut x).unwrap_or(0);
            (fp, n, x)
        });
        drop(m);
        ident.xfp = u32::from_le_bytes(fp);
        let _ = ident
            .xpub
            .push_str(core::str::from_utf8(&x[..n]).unwrap_or(""));
    }
    crate::catlog!("ckcc: identity learnt (wallet {})", ident.xfp != 0);
    crate::usbtask::ck_set_identity(ident);
}

/// `mitm`: the session key, signed by the master key. Source: §2.8 [C]
fn mitm(
    gate: &Callgate,
    login: &mut catcard_pin::Login,
    ui: &mut Ui<'_>,
    key: &[u8; 32],
) -> Answer {
    let m = match master(gate, login, ui) {
        Ok(m) => m,
        Err(why) => return Answer::Failed(why),
    };
    let sig = crate::keywork::run(|kw| {
        catcard_wallet::message::sign_raw_digest(key, m.secret_bytes(), kw)
    });
    drop(m);
    match sig {
        Ok(sig) => Answer::reply(|b| reply::biny(b, &sig)),
        Err(_) => Answer::Failed("Signing failed"),
    }
}

/// The extended public key at `path`, and the leaf's public key for an address.
fn derive(
    gate: &Callgate,
    login: &mut catcard_pin::Login,
    ui: &mut Ui<'_>,
    path: &Path,
) -> Result<catcard_wallet::bip32::ExtendedPubKey, &'static str> {
    let m = master(gate, login, ui)?;
    let steps = path.children();
    let key = if steps.is_empty() {
        crate::keywork::run(|kw| m.to_extended_pub(kw))
    } else {
        let mut busy = menu::Working::new(ui.panel, HEAD, "deriving");
        menu::public_at(&m, &steps, &mut busy, ui.panel).ok_or("Derivation failed")?
    };
    drop(m);
    Ok(key)
}

fn xpub(gate: &Callgate, login: &mut catcard_pin::Login, ui: &mut Ui<'_>, path: &Path) -> Answer {
    match derive(gate, login, ui, path) {
        Ok(k) => {
            let mut x = [0u8; XPUB_LEN];
            match k.write_base58(&mut x) {
                Ok(n) => Answer::reply(|b| reply::asci(b, &x[..n])),
                Err(_) => Answer::Failed("Encoding failed"),
            }
        }
        Err(why) => Answer::Failed(why),
    }
}

/// `show`: the address goes back at once, and stays on the screen until a key.
fn show(
    gate: &Callgate,
    login: &mut catcard_pin::Login,
    ui: &mut Ui<'_>,
    ticket: u32,
    kind: AddressKind,
    path: &Path,
    on_screen: bool,
) {
    let key = match derive(gate, login, ui, path) {
        Ok(k) => k,
        Err(why) => return crate::usbtask::ck_finish(ticket, Answer::Failed(why)),
    };
    let mut a = [0u8; catcard_wallet::address::MAX_ADDRESS_LEN];
    let n = match catcard_wallet::address::encode(
        kind,
        crate::prefs::network(),
        &key.public_key,
        &mut a,
    ) {
        Ok(n) => n,
        Err(_) => return crate::usbtask::ck_finish(ticket, Answer::Failed("Address failed")),
    };
    crate::usbtask::ck_finish(ticket, Answer::reply(|b| reply::asci(b, &a[..n])));
    // In HSM mode nobody is at the screen to clear it.
    if !on_screen {
        return;
    }
    let addr = core::str::from_utf8(&a[..n]).unwrap_or("?");
    let p = path.text();
    use catcard_ui::scroll::Line;
    let lines = [
        Line::title("Address"),
        Line::body(addr).wrapped(),
        Line::body(&p).small().wrapped(),
        Line::body("sent to the computer").small(),
    ];
    let _ = menu::show_doc(ui, &lines, false, false);
}

/// `msck`: is there a registered wallet with this M, N and fingerprint XOR?
fn multisig_check(
    gate: &Callgate,
    login: &mut catcard_pin::Login,
    ui: &mut Ui<'_>,
    m: u32,
    n: u32,
    xor: u32,
) -> Answer {
    let found = crate::msimport::registered(gate, login, ui.panel)
        .iter()
        .any(|w| {
            let x = w
                .cosigners()
                .iter()
                .fold(0u32, |acc, c| acc ^ u32::from_le_bytes(c.fingerprint));
            u32::from(w.m) == m && w.n() as u32 == n && x == xor
        });
    Answer::reply(|b| reply::int1(b, found as u32))
}

/// `p2sh`: a registered multisig wallet's address, found from what the host sent and
/// checked against it -- the address goes back only if the wallet's own script at that
/// branch and index is byte for byte the script the host named. Then it is shown.
///
/// The host lists each cosigner's fingerprint and full path in script order. A wallet
/// matches when it has the same M, N and script form, every listed key is one of its
/// cosigners (fingerprint, and a path that is that cosigner's origin plus two unhardened
/// steps), the two steps are the same pair for every key, and its script there equals the
/// host's. Nothing a host sends is shown as an address of this wallet otherwise.
fn p2sh(
    gate: &Callgate,
    login: &mut catcard_pin::Login,
    ui: &mut Ui<'_>,
    ticket: u32,
    mut args: crate::heap::Block,
    len: usize,
    on_screen: bool,
) {
    use catcard_wallet::multisig::{Kind as MsKind, MAX_SCRIPT};
    const H: u32 = 0x8000_0000;
    let done = |a: Answer| crate::usbtask::ck_finish(ticket, a);
    let Ok(req) = wire::P2sh::parse(&args.bytes()[..len]) else {
        return done(Answer::Failed("Bad arguments"));
    };
    let kind = match req.addr_fmt {
        wire::af::P2SH => MsKind::P2sh,
        wire::af::P2WSH => MsKind::P2wsh,
        wire::af::P2WSH_P2SH => MsKind::P2shP2wsh,
        _ => return done(Answer::Failed("Unsupported address format")),
    };
    let wallets = crate::msimport::registered(gate, login, ui.panel);
    let mut found: Option<(usize, u32, u32)> = None;
    'wallets: for (at, w) in wallets.iter().enumerate() {
        if w.m != req.m || w.n() != usize::from(req.n) || w.kind != kind {
            continue;
        }
        let mut pair: Option<(u32, u32)> = None;
        for i in 0..usize::from(req.n) {
            let mut path = [0u32; wire::P2SH_PATH_MAX];
            let Some((xfp, depth)) = req.cosigner(i, &mut path) else {
                continue 'wallets;
            };
            let fp = xfp.to_le_bytes();
            let ours = w.cosigners().iter().any(|c| {
                c.fingerprint == fp
                    && depth == c.origin_len + 2
                    && path[..c.origin_len] == c.origin[..c.origin_len]
            });
            if !ours || depth < 2 {
                continue 'wallets;
            }
            let here = (path[depth - 2], path[depth - 1]);
            if here.0 & H != 0 || here.1 & H != 0 || pair.is_some_and(|p| p != here) {
                continue 'wallets;
            }
            pair = Some(here);
        }
        let Some((branch, index)) = pair else {
            continue;
        };
        let mut script = [0u8; MAX_SCRIPT];
        match w.script(branch, index, &mut script) {
            Ok(n) if script[..n] == *req.script => {
                found = Some((at, branch, index));
                break;
            }
            _ => {}
        }
    }
    let Some((at, branch, index)) = found else {
        return done(Answer::Failed("Multisig wallet not registered"));
    };
    let Some(w) = wallets.get(at) else {
        return done(Answer::Failed("Multisig wallet not registered"));
    };
    let mut spk = [0u8; 40];
    let mut a = [0u8; catcard_wallet::address::MAX_ADDRESS_LEN];
    let n = match w.script_pubkey(branch, index, &mut spk).ok().and_then(|k| {
        catcard_wallet::address::from_script(&spk[..k], crate::prefs::network(), &mut a)
    }) {
        Some(n) => n,
        None => return done(Answer::Failed("Address failed")),
    };
    let (m, total) = (w.m, w.n());
    done(Answer::reply(|b| reply::asci(b, &a[..n])));
    if !on_screen {
        return;
    }
    let addr = core::str::from_utf8(&a[..n]).unwrap_or("?");
    let mut what: heapless::String<40> = heapless::String::new();
    let _ = write!(what, "{m}-of-{total} multisig, {branch}/{index}");
    use catcard_ui::scroll::Line;
    let lines = [
        Line::title("Address"),
        Line::body(addr).wrapped(),
        Line::body(&what).small().wrapped(),
        Line::body("sent to the computer").small(),
    ];
    let _ = menu::show_doc(ui, &lines, false, false);
}

/// `stxn`: the ordinary review, with every key of ours allowed to sign, the result back
/// to the computer.
#[allow(clippy::too_many_arguments)]
fn sign_tx(
    gate: &Callgate,
    login: &mut catcard_pin::Login,
    ui: &mut Ui<'_>,
    ticket: u32,
    store: Store,
    len: u32,
    sha: &[u8; 32],
    finalize: bool,
) -> Answer {
    let Some((mut held, at)) = store.into_host_buf() else {
        return Answer::Failed("Not a transaction");
    };
    let len = len as usize;
    // The bytes are read again here, where they are acted on, and must still be what the
    // host named: stock's guard against the upload changing under the check.
    // Source: usb-ckcc-protocol.md §3.3 [C]
    {
        use purecrypto::hash::{Digest, Sha256};
        let Some(tx) = held.bytes().get(at..at + len) else {
            return Answer::Failed("Checksum");
        };
        if Sha256::digest(tx)[..] != sha[..] {
            return Answer::Failed("Checksum");
        }
    }
    // In HSM mode the policy is asked instead of a person, inside the review
    // (`crate::hsm::judge_tx`), against this request's digest.
    #[cfg(not(feature = "board-mk3"))]
    let unattended = hsm_active();
    #[cfg(feature = "board-mk3")]
    let unattended = false;
    if !unattended {
        menu::ask(
            ui.panel,
            "Computer asks",
            "you to sign a",
            "Bitcoin transaction",
        );
        if !menu::confirmed(ui) {
            return Answer::Refused;
        }
    }
    if !crate::usbtask::host_alive(ticket) {
        return Answer::Refused;
    }
    #[cfg(not(feature = "board-mk3"))]
    crate::hsm::note_request(unattended.then_some(*sha));
    let outcome = crate::signtx::host_sign(gate, login, ui, held, at, len, &[], ticket, true);
    #[cfg(not(feature = "board-mk3"))]
    crate::hsm::note_request(None);
    match outcome {
        crate::hostwallet::Outcome::Declined => Answer::Refused,
        crate::hostwallet::Outcome::Refused(why) => Answer::Failed(why),
        crate::hostwallet::Outcome::Ready { mut buf, off, len } => {
            // `[2][psbt version][u32 len][psbt][u32 len][tx]`: take the PSBT, or the
            // finished transaction when the host asked for one and there is one.
            let (at, n) = {
                let b = &buf.bytes()[off..off + len];
                let Some(result) = pick_result(b, finalize) else {
                    return Answer::Failed("Result lost");
                };
                result
            };
            use purecrypto::hash::{Digest, Sha256};
            let mut sha = [0u8; 32];
            sha.copy_from_slice(&Sha256::digest(&buf.bytes()[off + at..off + at + n]));
            Answer::Signed {
                buf,
                off: off + at,
                len: n,
                sha,
            }
        }
    }
}

/// Where the file the host asked for sits in a Bitcoin host-wallet result.
fn pick_result(b: &[u8], finalize: bool) -> Option<(usize, usize)> {
    if b.first() != Some(&2) {
        return None;
    }
    let u32_at = |i: usize| -> Option<usize> {
        Some(u32::from_le_bytes(b.get(i..i + 4)?.try_into().ok()?) as usize)
    };
    let psbt_len = u32_at(2)?;
    let psbt = (6, psbt_len);
    let tx_at = 6 + psbt_len;
    let tx_len = u32_at(tx_at)?;
    if b.len() < tx_at + 4 + tx_len {
        return None;
    }
    Some(if finalize && tx_len > 0 {
        (tx_at + 4, tx_len)
    } else {
        psbt
    })
}

/// `smsg`: the ordinary message-signing confirmation, legacy format.
fn sign_msg(
    gate: &Callgate,
    login: &mut catcard_pin::Login,
    ui: &mut Ui<'_>,
    ticket: u32,
    kind: AddressKind,
    path: &Path,
    msg: &[u8],
) -> Answer {
    let Ok(text) = core::str::from_utf8(msg) else {
        return Answer::Failed("Message is not text");
    };
    let Ok(dpath) = catcard_wallet::bip32::DerivationPath::from_slice(&path.children()) else {
        return Answer::Failed("Bad path");
    };
    if !crate::usbtask::host_alive(ticket) {
        return Answer::Refused;
    }
    // HSM mode: `msg_paths` decides, and nobody is asked. Source: hsm-policy-format.md
    // §1.3 `msg_paths`, §3.1 `approve_msg_sign` [C]
    #[cfg(not(feature = "board-mk3"))]
    let ask = if hsm_active() {
        if !crate::hsm::approve_message(&path.steps[..path.depth as usize]) {
            return Answer::Refused;
        }
        false
    } else {
        true
    };
    #[cfg(feature = "board-mk3")]
    let ask = true;
    match crate::signmsg::sign_for_host(gate, login, ui, text, kind, dpath, ask) {
        Some((address, sig)) => Answer::MsgSigned { address, sig },
        None => Answer::Refused,
    }
}

/// `pass`: the passphrase screen's own confirmation, and the new wallet's xpub back.
fn passphrase(
    gate: &Callgate,
    login: &mut catcard_pin::Login,
    ui: &mut Ui<'_>,
    secret: Secret,
) -> Answer {
    menu::ask(ui.panel, "Computer asks", "to apply a BIP-39", "passphrase");
    if !menu::confirmed(ui) {
        return Answer::Refused;
    }
    if !crate::passphrase::apply(gate, login, ui, &secret.0) {
        return Answer::Refused;
    }
    drop(secret);
    // The identity went with the old wallet; learn the new one, and answer with it.
    learn_identity(gate, login, ui);
    match crate::usbtask::ck_identity_xpub() {
        Some(x) => Answer::Xpub(x),
        None => Answer::Failed("No xpub"),
    }
}

/// `enrl`: the ordinary multisig import review, from the uploaded file.
fn enroll(
    gate: &Callgate,
    login: &mut catcard_pin::Login,
    ui: &mut Ui<'_>,
    store: Store,
    len: u32,
) {
    let len = len as usize;
    let Some(mut text) = crate::heap::take(len) else {
        menu::message(ui.panel, HEAD, "not enough memory", "any key");
        menu::wait_for_any_key(ui);
        return;
    };
    {
        let mut store = store;
        if store.read(0, &mut text.bytes()[..len]).is_err() {
            return;
        }
    }
    let Ok(s) = core::str::from_utf8(&text.bytes()[..len]) else {
        menu::message(ui.panel, HEAD, "that file is not text", "any key");
        menu::wait_for_any_key(ui);
        return;
    };
    crate::msimport::from_text(gate, login, ui, s);
}

// ---------------------------------------------------------------------------------------
// Settings → Hardware On/Off → USB mode
// ---------------------------------------------------------------------------------------

/// Settings → Hardware On/Off → `USB mode`: Off, ckcc or CatCard, for the whole device.
///
/// Kept in the pre-login settings, so it holds before the PIN too. Switching re-enumerates
/// at once; holding Cancel at power-on still gets the CatCard protocol whatever this says.
pub(crate) fn usb_mode_screen(ui: &mut Ui<'_>) {
    use catcard_settings::prelogin::UsbMode;
    const H: &str = "USB mode";
    const MODES: [UsbMode; 3] = [UsbMode::CatCard, UsbMode::Ckcc, UsbMode::Off];
    let now = crate::usbtask::usb_mode();
    let note = match now {
        UsbMode::CatCard => "now CatCard",
        UsbMode::Ckcc => "now ckcc",
        UsbMode::Off => "now off",
    };
    let Some(row) = menu::pick_row(ui, H, note, &["CatCard", "ckcc (Coldcard tools)", "Off"])
    else {
        return;
    };
    let want = MODES[row];
    if want == now {
        menu::message(ui.panel, H, "unchanged", note);
        menu::wait_for_any_key(ui);
        return;
    }
    let (a, b) = match want {
        UsbMode::Ckcc => ("computers will see it", "as a Coldcard"),
        UsbMode::Off => ("no host can reach it", "until this is back on"),
        UsbMode::CatCard => ("CatCard's own protocol", "it re-enumerates now"),
    };
    menu::ask(ui.panel, H, a, b);
    if !menu::confirmed(ui) {
        return;
    }
    if !crate::settings::save_usb_mode(ui, want) {
        menu::message(ui.panel, H, "not saved", "any key to go back");
        menu::wait_for_any_key(ui);
        return;
    }
    crate::usbtask::set_usb_mode(want, true);
    menu::message(ui.panel, H, "saved", want.word());
    menu::wait_for_any_key(ui);
}
