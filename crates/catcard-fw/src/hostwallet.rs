//! A computer asks for addresses, or for a signature; a person at the device decides.
//!
//! The same shape as a USB firmware upgrade: the host asks, the device puts the question
//! on its own screen, the person answers there, and the host polls for the outcome. The
//! host never answers anything itself, and cannot withdraw a question once the device has
//! it -- only the person, or a bus reset, ends it.
//!
//! # Two halves on two tasks
//!
//! [`Desk`] lives in the USB task and answers the opcodes: it takes an upload, checks a
//! sign request against what this session was shown, queues the question, and pages the
//! result out. It never derives, signs, or waits. The question itself is answered on the
//! UI task by [`serve`], which the menu calls when [`crate::usbtask::host_waiting`] says
//! there is one -- checked after the keys are read, the way the upgrade offer is, so a
//! key cannot reach the menu underneath a question that has just arrived.
//!
//! The handover is by value under the USB task's lock: [`crate::usbtask::host_take`]
//! moves the request (and the memory it arrived in) out of the desk and leaves it
//! `OnScreen`; [`crate::usbtask::host_finish`] moves the outcome back in. Nothing is
//! shared while either side works on it.
//!
//! # What a session may reach
//!
//! Only inside the encrypted channel, and only what the person showed that session: a
//! sign request's keys must each sit below an account path the person agreed to share, on
//! the chain the request names ([`catcard_wallet::hostkeys`]). The list lives in the
//! channel's per-session state, so a new handshake, a teardown, or a bus reset drops it.
//! Whether a session may use any of this at all is one method,
//! [`catcard_usb::ncry::Channel::host_wallet_allowed`].
//!
//! Wire layouts: [`catcard_usb::hostwallet`] and `docs/USB.md` §"Host-wallet commands".

use core::fmt::Write as _;

use catcard_callgate::Callgate;
use catcard_usb::Status;
use catcard_usb::hostwallet::{self as wire, busy, stage};
use catcard_wallet::chain::{self, ChainId, Encoding};
use catcard_wallet::hostkeys::{self, Exposed, KeyPath};

use crate::menu;
use crate::ui::Ui;

/// Accounts one session can have been shown: every format of every chain a build
/// carries (21 today), with room.
pub(crate) const MAX_EXPOSED: usize = 24;

/// What the device keeps for one encrypted session, dropped with it.
#[derive(Default)]
pub(crate) struct SessionState {
    /// The accounts the person agreed to show this session, most recent approval only.
    pub exposed: heapless::Vec<Exposed, MAX_EXPOSED>,
}

/// Largest sign upload the mk3 takes: the size of its signing buffers.
#[cfg(feature = "board-mk3")]
const MK3_UPLOAD: usize = 16 * 1024;

/// Room for the address reply. The worst case today -- every format of every chain, each
/// UTXO one with a 111-character xpub -- is about 4.5 KB; the writer refuses rather than
/// truncates past this.
const ADDRESSES_MAX: usize = 6 * 1024;

/// Memory holding an upload or a result: the PSRAM lease on a board with PSRAM, a heap
/// block on the mk3 (and for the address reply everywhere).
pub(crate) enum HostBuf {
    #[cfg(not(feature = "board-mk3"))]
    Psram(crate::psram::Lease),
    Heap(crate::heap::Block),
}

impl HostBuf {
    pub(crate) fn bytes(&mut self) -> &mut [u8] {
        match self {
            #[cfg(not(feature = "board-mk3"))]
            HostBuf::Psram(l) => l.bytes(),
            HostBuf::Heap(b) => b.bytes(),
        }
    }
}

/// What the person is asked.
pub(crate) enum Ask {
    Addresses,
    /// `len` bytes of sign blob at the start of `buf`, already checked once.
    Sign {
        chain: ChainId,
        buf: HostBuf,
        len: usize,
    },
}

/// A request handed to the UI task: the session it belongs to, and the question.
pub(crate) struct Taken {
    pub ticket: u32,
    pub ask: Ask,
}

/// How a question ended.
pub(crate) enum Outcome {
    Declined,
    Refused(&'static str),
    /// `len` result bytes at `off` in `buf`.
    Ready {
        buf: HostBuf,
        off: usize,
        len: usize,
    },
}

enum State {
    Idle,
    Uploading {
        owner: u32,
        chain: ChainId,
        total: usize,
        got: usize,
        buf: HostBuf,
    },
    Queued {
        owner: u32,
        ask: Ask,
    },
    OnScreen {
        owner: u32,
    },
    Done {
        owner: u32,
        outcome: Outcome,
    },
}

/// What the USB task needs to know about the rest of the device to answer.
pub(crate) struct Cx<'a> {
    /// The id of the open session the request arrived on.
    pub session: u32,
    /// What that session was shown.
    pub exposed: &'a [Exposed],
    pub unlocked: bool,
    /// An upgrade is arriving, waiting for its answer, or approved.
    pub upgrade_busy: bool,
}

/// The USB task's half: one request at a time.
pub(crate) struct Desk {
    state: State,
}

/// Whether this build signs for `chain`. Everything else is refused by name.
pub(crate) fn signs(chain: ChainId) -> bool {
    match chain {
        ChainId::Bitcoin => true,
        #[cfg(all(feature = "multichain", not(feature = "board-mk3")))]
        ChainId::Ethereum | ChainId::Solana => true,
        _ => false,
    }
}

/// A chain's name, for a refusal a host will show someone.
fn chain_name(chain: ChainId) -> &'static str {
    match chain {
        ChainId::Bitcoin => "Bitcoin",
        ChainId::Ethereum => "Ethereum",
        ChainId::Solana => "Solana",
        ChainId::Litecoin => "Litecoin",
        ChainId::Dogecoin => "Dogecoin",
        ChainId::BitcoinCash => "Bitcoin Cash",
        ChainId::Monacoin => "Monacoin",
        ChainId::ElectraProtocol => "Electra Protocol",
        ChainId::Tron => "Tron",
        ChainId::Namecoin => "Namecoin",
    }
}

/// Write `text` as a refusal body, and return `(Refused, length)`.
fn refuse(out: &mut [u8], text: &str) -> (Status, usize) {
    let n = text.len().min(wire::REASON_MAX).min(out.len());
    out[..n].copy_from_slice(&text.as_bytes()[..n]);
    (Status::Refused, n)
}

/// `Refused` with "<chain> <what>".
fn refuse_chain(out: &mut [u8], chain: ChainId, what: &str) -> (Status, usize) {
    let mut s: heapless::String<{ wire::REASON_MAX }> = heapless::String::new();
    let _ = write!(s, "{} {}", chain_name(chain), what);
    refuse(out, &s)
}

fn one(out: &mut [u8], status: Status, byte: u8) -> (Status, usize) {
    out[0] = byte;
    (status, 1)
}

impl Desk {
    pub(crate) const fn new() -> Self {
        Self { state: State::Idle }
    }

    /// The stage a host polling from session `session` is told.
    fn stage_for(&self, session: u32) -> u8 {
        let (owner, s) = match &self.state {
            State::Idle => return stage::NOTHING,
            State::Uploading { owner, .. } => (*owner, stage::UPLOADING),
            State::Queued { owner, .. } => (*owner, stage::QUEUED),
            State::OnScreen { owner } => (*owner, stage::ON_SCREEN),
            State::Done { owner, .. } => (*owner, stage::NOTHING),
        };
        if owner == session {
            s
        } else {
            stage::OTHER_SESSION
        }
    }

    /// Whether a question is queued for the screen or on it. An upgrade offer waits
    /// behind one, as one waits behind an upgrade offer.
    pub(crate) fn pending(&self) -> bool {
        matches!(self.state, State::Queued { .. } | State::OnScreen { .. })
    }

    /// The session that owned whatever is here has ended: a new handshake, a teardown,
    /// or a bus reset.
    ///
    /// An upload and an unfetched result are dropped -- nobody can finish or fetch them
    /// now -- and so is a question still queued, which the person has not seen. A
    /// question already on the screen stays there unless the bus was reset: a new host
    /// cannot clear a question it is not entitled to answer, and its answer is dropped
    /// when it comes. A bus reset ends it, as it ends an upgrade offer; the screen notices
    /// at its next step ([`crate::usbtask::host_alive`]).
    pub(crate) fn session_ended(&mut self, bus_reset: bool) {
        match self.state {
            State::OnScreen { .. } if !bus_reset => {}
            State::Idle => {}
            _ => self.state = State::Idle,
        }
    }

    /// Answer one host-wallet opcode, writing the reply body into `out`.
    pub(crate) fn dispatch(
        &mut self,
        op: catcard_usb::Opcode,
        payload: &[u8],
        out: &mut [u8],
        cx: &Cx<'_>,
    ) -> (Status, usize) {
        use catcard_usb::Opcode as Op;
        match op {
            Op::HostAddresses => self.addresses(payload, out, cx),
            Op::HostSignBegin => self.begin(payload, out, cx),
            Op::HostSignData => self.data(payload, out, cx),
            Op::HostSignCommit => self.commit(payload, out, cx),
            Op::HostResult => self.result(payload, out, cx),
            Op::HostAbort => self.abort(payload, out, cx),
            _ => (Status::UnknownOpcode, 0),
        }
    }

    /// Whether a new question can be taken: unlocked, nothing else in hand, no upgrade.
    fn refuse_new(&self, out: &mut [u8], cx: &Cx<'_>, restart_ok: bool) -> Option<(Status, usize)> {
        if !cx.unlocked {
            return Some(one(out, Status::NotNow, busy::LOCKED));
        }
        let free = match &self.state {
            State::Idle => true,
            // A host restarting its own upload is the same holder coming back.
            State::Uploading { owner, .. } => restart_ok && *owner == cx.session,
            _ => false,
        };
        if !free || cx.upgrade_busy {
            return Some(one(out, Status::NotNow, busy::BUSY));
        }
        None
    }

    fn addresses(&mut self, p: &[u8], out: &mut [u8], cx: &Cx<'_>) -> (Status, usize) {
        if wire::decode_empty(p).is_err() {
            return (Status::BadRequest, 0);
        }
        if let Some(r) = self.refuse_new(out, cx, false) {
            return r;
        }
        crate::catlog!("host: addresses asked for");
        self.state = State::Queued {
            owner: cx.session,
            ask: Ask::Addresses,
        };
        (Status::Ok, 0)
    }

    fn begin(&mut self, p: &[u8], out: &mut [u8], cx: &Cx<'_>) -> (Status, usize) {
        let Ok(b) = wire::SignBegin::decode(p) else {
            return (Status::BadRequest, 0);
        };
        if let Some(r) = self.refuse_new(out, cx, true) {
            return r;
        }
        // Drop the host's own earlier upload before claiming memory for this one.
        self.state = State::Idle;
        let chain = match chain::resolve(u16::from(b.chain)) {
            Ok(c) => c.id,
            Err(chain::Unsupported::UnknownChain { .. }) => return refuse(out, "unknown chain"),
            Err(chain::Unsupported::NotInThisBuild { id }) => {
                return refuse_chain(out, id, "is not in this build");
            }
        };
        if !signs(chain) {
            return refuse_chain(out, chain, "cannot be signed here");
        }
        // Nothing shown on this chain means no key could pass: say so before the upload
        // rather than after it.
        if !cx.exposed.iter().any(|e| e.chain == chain) {
            return refuse_chain(out, chain, "was not shared this session");
        }
        let total = b.length as usize;
        let buf = match claim(total) {
            Ok(buf) => buf,
            Err(why) => return refuse(out, why),
        };
        crate::catlog!("host: sign upload of {} bytes opened", total);
        self.state = State::Uploading {
            owner: cx.session,
            chain,
            total,
            got: 0,
            buf,
        };
        out[..4].copy_from_slice(&(wire::DATA_MAX as u32).to_le_bytes());
        (Status::Ok, 4)
    }

    fn data(&mut self, p: &[u8], out: &mut [u8], cx: &Cx<'_>) -> (Status, usize) {
        let Ok(d) = wire::SignData::decode(p) else {
            return (Status::BadRequest, 0);
        };
        let st = self.stage_for(cx.session);
        let State::Uploading {
            owner,
            total,
            got,
            buf,
            ..
        } = &mut self.state
        else {
            return one(out, Status::NotNow, st);
        };
        if *owner != cx.session {
            return one(out, Status::NotNow, stage::OTHER_SESSION);
        }
        // In order, and not past the declared end. A chunk out of place is refused and
        // the upload kept: the host can send the right one.
        let end = *got + d.bytes.len();
        if d.offset as usize != *got || end > *total {
            return (Status::BadRequest, 0);
        }
        buf.bytes()[*got..end].copy_from_slice(d.bytes);
        *got = end;
        out[..4].copy_from_slice(&(end as u32).to_le_bytes());
        (Status::Ok, 4)
    }

    fn commit(&mut self, p: &[u8], out: &mut [u8], cx: &Cx<'_>) -> (Status, usize) {
        if wire::decode_empty(p).is_err() {
            return (Status::BadRequest, 0);
        }
        let st = self.stage_for(cx.session);
        match &self.state {
            State::Uploading {
                owner, total, got, ..
            } if *owner == cx.session => {
                if got != total {
                    return (Status::BadRequest, 0);
                }
            }
            _ => return one(out, Status::NotNow, st),
        }
        let State::Uploading {
            owner,
            chain,
            total,
            mut buf,
            ..
        } = core::mem::replace(&mut self.state, State::Idle)
        else {
            return one(out, Status::NotNow, st);
        };
        // Everything that can be judged without a key is judged here, so a request that
        // cannot be signed never reaches anybody's screen. From here on any refusal
        // drops the upload with it.
        let verdict = check_blob(&buf.bytes()[..total], chain, cx.exposed);
        if let Err(why) = verdict {
            crate::catlog!("host: sign request refused: {}", why);
            return refuse(out, why);
        }
        crate::catlog!("host: sign request queued ({})", chain_name(chain));
        self.state = State::Queued {
            owner,
            ask: Ask::Sign {
                chain,
                buf,
                len: total,
            },
        };
        (Status::Ok, 0)
    }

    fn result(&mut self, p: &[u8], out: &mut [u8], cx: &Cx<'_>) -> (Status, usize) {
        let Ok(offset) = wire::decode_offset(p) else {
            return (Status::BadRequest, 0);
        };
        let st = self.stage_for(cx.session);
        let State::Done { owner, outcome } = &mut self.state else {
            return one(out, Status::NotNow, st);
        };
        if *owner != cx.session {
            return one(out, Status::NotNow, stage::OTHER_SESSION);
        }
        let (status, n, release) = match outcome {
            Outcome::Declined => (Status::Declined, 0, true),
            Outcome::Refused(why) => {
                let (s, n) = refuse(out, why);
                (s, n, true)
            }
            Outcome::Ready { buf, off, len } => {
                let result = &buf.bytes()[*off..*off + *len];
                match wire::page(result, offset, out) {
                    Ok((n, last)) => (Status::Ok, n, last),
                    Err(_) => (Status::BadRequest, 0, false),
                }
            }
        };
        if release {
            // Fetched to the end: the memory goes back, and the next question can come.
            self.state = State::Idle;
        }
        (status, n)
    }

    fn abort(&mut self, p: &[u8], out: &mut [u8], cx: &Cx<'_>) -> (Status, usize) {
        if wire::decode_empty(p).is_err() {
            return (Status::BadRequest, 0);
        }
        let st = self.stage_for(cx.session);
        match &self.state {
            State::Idle => (Status::Ok, 0),
            State::Uploading { owner, .. } | State::Done { owner, .. } if *owner == cx.session => {
                crate::catlog!("host: dropped at the host's request");
                self.state = State::Idle;
                (Status::Ok, 0)
            }
            // Queued, on the screen, or somebody else's: not the host's to take back.
            _ => one(out, Status::NotNow, st),
        }
    }

    // ---- the UI task's side, through `usbtask` ----------------------------------------

    pub(crate) fn waiting(&self) -> bool {
        matches!(self.state, State::Queued { .. })
    }

    /// Move the queued question out, leaving it on the screen.
    pub(crate) fn take(&mut self) -> Option<Taken> {
        if !self.waiting() {
            return None;
        }
        let State::Queued { owner, ask } = core::mem::replace(&mut self.state, State::Idle) else {
            return None;
        };
        self.state = State::OnScreen { owner };
        Some(Taken { ticket: owner, ask })
    }

    /// Whether the question `ticket` is still on the screen: not ended by a bus reset.
    pub(crate) fn on_screen(&self, ticket: u32) -> bool {
        matches!(self.state, State::OnScreen { owner } if owner == ticket)
    }

    /// The person answered `ticket`. The answer is kept for the host only if the session
    /// that asked is still the one open; otherwise nobody can fetch it and it is dropped
    /// here, releasing its memory.
    pub(crate) fn finish(&mut self, ticket: u32, outcome: Outcome, still_open: bool) {
        if !self.on_screen(ticket) {
            return;
        }
        self.state = if still_open {
            State::Done {
                owner: ticket,
                outcome,
            }
        } else {
            State::Idle
        };
    }
}

/// Claim memory for a sign upload of `total` bytes, or say why not.
fn claim(total: usize) -> Result<HostBuf, &'static str> {
    #[cfg(feature = "board-mk3")]
    {
        if total > MK3_UPLOAD {
            return Err("too big for this board");
        }
        crate::heap::take(total)
            .map(HostBuf::Heap)
            .ok_or("not enough memory now")
    }
    #[cfg(not(feature = "board-mk3"))]
    {
        let mut lease = crate::psram::take(crate::psram::Use::Host)
            .map_err(crate::psram::Unavailable::message)?;
        // The signing layout: the transaction and a second buffer take three eighths
        // each, the result the last quarter. See `crate::signtx::host_sign`.
        if total > upload_cap(lease.bytes().len()) {
            return Err("too big for this board");
        }
        Ok(HostBuf::Psram(lease))
    }
}

/// The largest upload a PSRAM lease of `lease` bytes takes: one signing buffer's worth.
#[cfg(not(feature = "board-mk3"))]
pub(crate) fn upload_cap(lease: usize) -> usize {
    ((lease - result_len(lease)) / 2) & !3
}

/// The result area at the end of a PSRAM lease of `lease` bytes.
#[cfg(not(feature = "board-mk3"))]
pub(crate) fn result_len(lease: usize) -> usize {
    (lease / 4) & !3
}

/// Check a whole sign blob against its chain and what this session was shown.
fn check_blob(bytes: &[u8], chain: ChainId, exposed: &[Exposed]) -> Result<(), &'static str> {
    let blob = wire::SignBlob::decode(bytes).map_err(|_| "malformed sign request")?;
    if u16::from(blob.chain) != chain.as_u16() {
        return Err("chain differs from the one announced");
    }
    let keys = keys_of(&blob)?;
    match hostkeys::check(exposed, chain, &keys) {
        Ok(()) => {}
        Err(hostkeys::Refused::NoKeys) => return Err("no key listed"),
        Err(hostkeys::Refused::NotExposed { .. }) => {
            return Err("a key is not under an account shared this session");
        }
    }
    match chain {
        // One sender, one signature: an EVM transaction has exactly one signer.
        ChainId::Ethereum if keys.len() != 1 => Err("an EVM transaction takes one key"),
        // SLIP-0010 derives hardened steps only.
        ChainId::Solana if keys.iter().any(|k| !k.fully_hardened()) => {
            Err("a Solana key path must be hardened throughout")
        }
        _ => Ok(()),
    }
}

/// The keys a blob lists, as the wallet crate's paths.
pub(crate) fn keys_of(
    blob: &wire::SignBlob<'_>,
) -> Result<heapless::Vec<KeyPath, { wire::MAX_KEYS }>, &'static str> {
    let mut keys = heapless::Vec::new();
    for k in blob.keys() {
        let p = KeyPath::new(k.steps()).ok_or("key path too deep")?;
        keys.push(p).map_err(|_| "too many keys")?;
    }
    Ok(keys)
}

// ---------------------------------------------------------------------------------------
// The UI task's half
// ---------------------------------------------------------------------------------------

/// What a signing flow leaves for the host, and where.
///
/// The sink the signing screens write to instead of a card, a QR or a tag. On a PSRAM
/// board it is a fixed region at the end of the lease the upload arrived in; on the mk3 it
/// is a heap block taken when the size is known.
pub(crate) struct HostOut<'a> {
    region: Option<&'a mut [u8]>,
    block: Option<crate::heap::Block>,
    len: usize,
    /// The keys the request listed: the only ones that may sign.
    pub keys: &'a [KeyPath],
    ticket: u32,
    end: End,
    /// A line for the "sent back" screen: how complete the result is.
    pub note: heapless::String<40>,
}

#[derive(Copy, Clone)]
enum End {
    Nothing,
    Declined,
    Refused(&'static str),
    Written,
}

impl<'a> HostOut<'a> {
    pub(crate) fn new(region: Option<&'a mut [u8]>, keys: &'a [KeyPath], ticket: u32) -> Self {
        Self {
            region,
            block: None,
            len: 0,
            keys,
            ticket,
            end: End::Nothing,
            note: heapless::String::new(),
        }
    }

    /// Whether the computer that asked is still there to take the answer.
    pub(crate) fn wanted(&self) -> bool {
        crate::usbtask::host_alive(self.ticket)
    }

    /// The flow stopped for a reason the host should be told. The first reason sticks.
    pub(crate) fn refuse(&mut self, why: &'static str) {
        if matches!(self.end, End::Nothing) {
            self.end = End::Refused(why);
        }
    }

    /// The person said no.
    pub(crate) fn decline(&mut self) {
        if matches!(self.end, End::Nothing) {
            self.end = End::Declined;
        }
    }

    /// `n` bytes to write the result into.
    pub(crate) fn room(&mut self, n: usize) -> Result<&mut [u8], &'static str> {
        if let Some(r) = self.region.as_deref_mut() {
            return r.get_mut(..n).ok_or("result too large for this board");
        }
        let block = crate::heap::take(n).ok_or("not enough memory for the result")?;
        let b = self.block.insert(block);
        Ok(&mut b.bytes()[..n])
    }

    /// The result is the first `n` bytes of [`room`](Self::room).
    pub(crate) fn wrote(&mut self, n: usize) {
        self.len = n;
        self.end = End::Written;
    }

    /// End the flow: how it ended, and the heap block holding the result if one was
    /// taken. Releases the borrow of the fixed region, so the memory it is in can move.
    pub(crate) fn finish(self) -> Finished {
        set_note(&self.note);
        Finished {
            end: self.end,
            len: self.len,
            block: self.block,
        }
    }
}

/// A [`HostOut`] once the flow is over.
pub(crate) struct Finished {
    end: End,
    len: usize,
    block: Option<crate::heap::Block>,
}

/// Turn a finished flow into an outcome. `held` is the upload's memory, which the result
/// sits in at `off` when it went into the fixed region.
pub(crate) fn outcome_of(done: Finished, held: Option<HostBuf>, off: usize) -> Outcome {
    let Finished { end, len, block } = done;
    match end {
        End::Written => match (block, held) {
            (Some(b), _) => Outcome::Ready {
                buf: HostBuf::Heap(b),
                off: 0,
                len,
            },
            (None, Some(buf)) => Outcome::Ready { buf, off, len },
            (None, None) => Outcome::Refused("result lost"),
        },
        End::Refused(why) => Outcome::Refused(why),
        End::Declined | End::Nothing => Outcome::Declined,
    }
}

/// The last result's note, for the screen that says it went back. Held here rather than
/// threaded through every signing flow's return value.
static mut NOTE: heapless::String<40> = heapless::String::new();

fn set_note(s: &str) {
    // SAFETY: UI task only; the write finishes within this statement.
    let note = unsafe { &mut *core::ptr::addr_of_mut!(NOTE) };
    note.clear();
    let _ = note.push_str(s);
}

fn take_note() -> heapless::String<40> {
    // SAFETY: UI task only; the borrow ends within this statement.
    let note = unsafe { &mut *core::ptr::addr_of_mut!(NOTE) };
    core::mem::take(note)
}

/// Answer the question a host is waiting on, if there is one. Called by the menu loop.
pub(crate) fn serve(gate: &Callgate, login: &mut catcard_pin::Login, ui: &mut Ui<'_>) {
    let Some(t) = crate::usbtask::host_take() else {
        return;
    };
    let ticket = t.ticket;
    let outcome = match t.ask {
        Ask::Addresses => addresses(gate, login, ui, ticket),
        Ask::Sign { chain, buf, len } => sign(gate, login, ui, ticket, chain, buf, len),
    };
    let sent = matches!(outcome, Outcome::Ready { .. });
    let refused = match &outcome {
        Outcome::Refused(why) => Some(*why),
        _ => None,
    };
    let alive = crate::usbtask::host_alive(ticket);
    // Handed back before the last screen, so the host is not kept waiting on a keypress.
    crate::usbtask::host_finish(ticket, outcome);
    let note = take_note();
    if !alive {
        menu::message(ui.panel, "Computer gone", "nothing was sent", "");
    } else if sent {
        menu::message(ui.panel, "Sent back", "to the computer", note.as_str());
    } else if let Some(why) = refused {
        crate::catlog!("host: refused: {}", why);
        menu::message(ui.panel, "Not sent", why, "computer was told");
    } else {
        menu::message(ui.panel, "Declined", "computer was told", "");
    }
    menu::wait_for_any_key(ui);
}

/// Whether the question is still wanted. When it is not, the flow stops quietly: the
/// last screen in [`serve`] says what happened.
fn alive(ticket: u32) -> bool {
    crate::usbtask::host_alive(ticket)
}

// ---- addresses ------------------------------------------------------------------------

fn addresses(
    gate: &Callgate,
    login: &mut catcard_pin::Login,
    ui: &mut Ui<'_>,
    ticket: u32,
) -> Outcome {
    const HEAD: &str = "Addresses";
    menu::ask(
        ui.panel,
        "Computer asks",
        "for this wallet's",
        "addresses. Share?",
    );
    if !menu::confirmed(ui) || !alive(ticket) {
        return Outcome::Declined;
    }
    // The account, typed: the Address Explorer's own field.
    let Some(account) = menu::ask_number(ui, HEAD, None, "account", "empty is account 0") else {
        return Outcome::Declined;
    };
    if !alive(ticket) {
        return Outcome::Declined;
    }

    #[cfg(feature = "multichain")]
    let picked = match pick_chains(gate, login, ui) {
        Some(p) => p,
        None => return Outcome::Declined,
    };
    #[cfg(not(feature = "multichain"))]
    let picked: heapless::Vec<&'static chain::Chain, 1> = {
        let mut v = heapless::Vec::new();
        let _ = v.push(&chain::BITCOIN);
        v
    };
    if !alive(ticket) {
        return Outcome::Declined;
    }

    let mut a: heapless::String<24> = heapless::String::new();
    let _ = write!(a, "account {account}");
    let mut b: heapless::String<24> = heapless::String::new();
    let _ = write!(
        b,
        "{} chain{}",
        picked.len(),
        if picked.len() == 1 { "" } else { "s" }
    );
    menu::ask(ui.panel, "Share these?", &a, &b);
    if !menu::confirmed(ui) || !alive(ticket) {
        return Outcome::Declined;
    }

    match build_addresses(gate, login, ui, account, &picked) {
        Ok((block, len, exposed)) => {
            if !crate::usbtask::host_expose(ticket, &exposed) {
                return Outcome::Declined;
            }
            let mut n: heapless::String<40> = heapless::String::new();
            let _ = write!(n, "account {account}");
            set_note(&n);
            Outcome::Ready {
                buf: HostBuf::Heap(block),
                off: 0,
                len,
            }
        }
        Err(why) => Outcome::Refused(why),
    }
}

/// The chains to share, from the wallet's own list: every one on to begin with, each
/// toggled with Confirm, and the last row to go on. Cancel declines.
#[cfg(feature = "multichain")]
fn pick_chains(
    gate: &Callgate,
    login: &mut catcard_pin::Login,
    ui: &mut Ui<'_>,
) -> Option<heapless::Vec<&'static chain::Chain, { crate::chains::MAX }>> {
    let order = crate::chains::enabled(gate, login, ui);
    let mut on: heapless::Vec<bool, { crate::chains::MAX }> = heapless::Vec::new();
    for _ in order.iter() {
        let _ = on.push(true);
    }
    loop {
        let mut labels: heapless::Vec<heapless::String<24>, { crate::chains::MAX + 1 }> =
            heapless::Vec::new();
        for (c, o) in order.iter().zip(on.iter()) {
            let mut row: heapless::String<24> = heapless::String::new();
            let _ = write!(row, "[{}] {}", if *o { "x" } else { " " }, c.name);
            let _ = labels.push(row);
        }
        let mut go: heapless::String<24> = heapless::String::new();
        let _ = go.push_str("Share the ticked");
        let _ = labels.push(go);
        let rows: heapless::Vec<&str, { crate::chains::MAX + 1 }> =
            labels.iter().map(|s| s.as_str()).collect();
        let chosen = menu::choose(ui, "Chains", "OK ticks, last row goes on", &rows)?;
        if chosen < order.len() {
            on[chosen] = !on[chosen];
            continue;
        }
        let picked: heapless::Vec<&'static chain::Chain, { crate::chains::MAX }> = order
            .iter()
            .zip(on.iter())
            .filter(|(_, o)| **o)
            .map(|(c, _)| *c)
            .collect();
        if picked.is_empty() {
            menu::message(ui.panel, "Chains", "tick at least one", "any key");
            menu::wait_for_any_key(ui);
            continue;
        }
        return Some(picked);
    }
}

/// The wire's code for how an address is written.
fn format_code(e: Encoding) -> u8 {
    use catcard_wallet::address::AddressKind as K;
    match e {
        Encoding::Utxo(K::P2pkh) => wire::format::P2PKH,
        Encoding::Utxo(K::P2shP2wpkh) => wire::format::P2SH_P2WPKH,
        Encoding::Utxo(K::P2wpkh) => wire::format::P2WPKH,
        Encoding::Utxo(K::P2tr) => wire::format::P2TR,
        Encoding::Evm => wire::format::EVM,
        Encoding::Tron => wire::format::TRON,
        Encoding::Solana => wire::format::SOLANA,
    }
}

type Built = (
    crate::heap::Block,
    usize,
    heapless::Vec<Exposed, MAX_EXPOSED>,
);

/// Derive and encode every entry: for each chain, one per format it has.
///
/// One unlock of the master for every secp256k1 account, derived a level at a time with
/// the bar moving; one seed stretch more if Solana is among them (SLIP-0010 starts from
/// the seed, not the master). Only public keys leave the masked regions.
fn build_addresses(
    gate: &Callgate,
    login: &mut catcard_pin::Login,
    ui: &mut Ui<'_>,
    account: u32,
    picked: &[&'static chain::Chain],
) -> Result<Built, &'static str> {
    use catcard_wallet::bip32::ChildNumber;
    use catcard_wallet::chain::address as caddr;
    const HEAD: &str = "Addresses";

    let network = crate::prefs::network();
    let mut block = crate::heap::take(ADDRESSES_MAX).ok_or("not enough memory")?;
    let mut exposed: heapless::Vec<Exposed, MAX_EXPOSED> = heapless::Vec::new();

    let Some(master) = menu::unlock_master(gate, login, ui, HEAD) else {
        return Err("the wallet could not be opened");
    };
    let fingerprint = crate::keywork::run(|kw| master.fingerprint(kw));
    let mut w = wire::AddressWriter::new(block.bytes(), fingerprint, account)
        .map_err(|_| "not enough memory")?;
    let mut solana: Option<(&'static chain::Chain, hostkeys::AccountView)> = None;
    {
        let mut busy = menu::Working::new(ui.panel, HEAD, "deriving accounts");
        for c in picked {
            for f in c.formats {
                let v = hostkeys::view(c, *f, network, account).ok_or("account out of range")?;
                if f.encoding == Encoding::Solana {
                    solana = Some((c, v));
                    continue;
                }
                let steps = v.account.map(ChildNumber);
                let key = menu::public_at(&master, &steps, &mut busy, ui.panel)
                    .ok_or("derivation failed")?;
                // The first address, publicly: `.../0/0` from the account key.
                let leaf = key
                    .derive_child(ChildNumber::ZERO)
                    .and_then(|k| k.derive_child(ChildNumber::ZERO))
                    .map_err(|_| "derivation failed")?;
                let mut addr = [0u8; caddr::MAX_LEN];
                let an = caddr::from_secp256k1(c, f.encoding, network, &leaf.public_key, &mut addr)
                    .map_err(|_| "could not write an address")?;
                let utxo = hostkeys::is_utxo(f);
                let mut xpub = [0u8; catcard_wallet::bip32::serialize::MAX_BASE58_LEN];
                let xn = if utxo {
                    key.write_base58(&mut xpub)
                        .map_err(|_| "could not write a key")?
                } else {
                    0
                };
                w.push(&wire::Entry {
                    shape: if utxo {
                        wire::shape::UTXO
                    } else {
                        wire::shape::ACCOUNT
                    },
                    chain: c.id.as_u16() as u8,
                    format: format_code(f.encoding),
                    account_path: wire::Path::new(&v.account).ok_or("bad path")?,
                    address_path: wire::Path::new(v.address.steps()).ok_or("bad path")?,
                    xpub: &xpub[..xn],
                    address: &addr[..an],
                    pubkey: &leaf.public_key,
                })
                .map_err(|_| "too many addresses to send")?;
                let _ = exposed.push(Exposed {
                    chain: c.id,
                    account: v.account,
                });
                busy.tick(ui.panel);
            }
        }
    }
    drop(master);

    #[cfg(feature = "multichain")]
    if let Some((c, v)) = solana {
        const H: u32 = catcard_wallet::bip32::HARDENED_OFFSET;
        let mut path = [0u32; 4];
        for (slot, s) in path.iter_mut().zip(v.address.steps()) {
            *slot = s & !H;
        }
        let key = menu::with_seed(gate, login, ui.panel, HEAD, |seed, kw| {
            catcard_wallet::slip10::derive(seed, &path, kw).map(|n| n.public_key(kw))
        })?;
        let mut addr = [0u8; caddr::MAX_LEN];
        let an =
            caddr::from_ed25519(c, &key, &mut addr).map_err(|_| "could not write an address")?;
        w.push(&wire::Entry {
            shape: wire::shape::ACCOUNT,
            chain: c.id.as_u16() as u8,
            format: wire::format::SOLANA,
            account_path: wire::Path::new(&v.account).ok_or("bad path")?,
            address_path: wire::Path::new(v.address.steps()).ok_or("bad path")?,
            xpub: &[],
            address: &addr[..an],
            pubkey: &key,
        })
        .map_err(|_| "too many addresses to send")?;
        let _ = exposed.push(Exposed {
            chain: c.id,
            account: v.account,
        });
    }
    #[cfg(not(feature = "multichain"))]
    let _ = solana;

    let len = w.finish();
    crate::catlog!("host: {} bytes of addresses for account {}", len, account);
    Ok((block, len, exposed))
}

// ---- signing --------------------------------------------------------------------------

fn sign(
    gate: &Callgate,
    login: &mut catcard_pin::Login,
    ui: &mut Ui<'_>,
    ticket: u32,
    chain: ChainId,
    mut buf: HostBuf,
    len: usize,
) -> Outcome {
    // Read again for use: the USB task checked it, and this is where it is acted on.
    let (keys, tx_at, tx_len) = {
        let Ok(blob) = wire::SignBlob::decode(&buf.bytes()[..len]) else {
            return Outcome::Refused("malformed sign request");
        };
        match keys_of(&blob) {
            Ok(k) => (k, blob.tx_at, blob.tx.len()),
            Err(why) => return Outcome::Refused(why),
        }
    };

    let mut b: heapless::String<24> = heapless::String::new();
    let _ = write!(b, "{} transaction", chain_name(chain));
    menu::ask(ui.panel, "Computer asks", "you to sign a", &b);
    if !menu::confirmed(ui) || !alive(ticket) {
        return Outcome::Declined;
    }

    match chain {
        ChainId::Bitcoin => {
            crate::signtx::host_sign(gate, login, ui, buf, tx_at, tx_len, &keys, ticket)
        }
        #[cfg(all(feature = "multichain", not(feature = "board-mk3")))]
        ChainId::Ethereum => {
            crate::evmtx::host_sign(gate, login, ui, buf, tx_at, tx_len, &keys[0], ticket)
        }
        #[cfg(all(feature = "multichain", not(feature = "board-mk3")))]
        ChainId::Solana => {
            crate::solanatx::host_sign(gate, login, ui, buf, tx_at, tx_len, &keys, ticket)
        }
        _ => {
            drop(buf);
            Outcome::Refused("this chain does not sign here")
        }
    }
}
