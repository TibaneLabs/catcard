//! A computer asks for addresses, for one address by its path, or for a signature over a
//! transaction or a message; a person at the device decides.
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
//! sign request's keys must each sit below an account path the person agreed to share, or
//! be a key whose address was shared by its path, on the chain the request names
//! ([`catcard_wallet::hostkeys`]). Both lists live in the channel's per-session state
//! ([`SessionState`]), so a new handshake, a teardown, or a bus reset drops them.
//! Whether a session may use any of this at all is one method,
//! [`catcard_usb::ncry::Channel::host_wallet_allowed`].
//!
//! # The one thing a session can be given ahead of time
//!
//! Asked for an address by its path, the person may tick "Allow during session". From
//! then until the session ends, the same session's requests for an address by path are
//! answered without a question ([`SessionState::paths_allowed`]). That is all it covers:
//! one public key and its address at a time, never an extended key, and never a
//! signature -- every signature is still reviewed on this screen.
//!
//! Wire layouts: [`catcard_usb::hostwallet`] and `docs/USB.md` §"Host-wallet commands".

use core::fmt::Write as _;

use catcard_callgate::Callgate;
use catcard_usb::Status;
use catcard_usb::hostwallet::{self as wire, busy, stage};
use catcard_wallet::chain::{self, ChainId, Encoding};
use catcard_wallet::hostkeys::{self, Exposed, KeyPath, Shared};

use crate::menu;
use crate::ui::Ui;

/// Accounts one session can have been shown: every format of every chain a build
/// carries (21 today), with room.
pub(crate) const MAX_EXPOSED: usize = 24;

/// Keys one session can have been shown by path and still name in a sign request. The
/// oldest is forgotten when one more arrives: a host that wants to sign with a key asks
/// for its address first, and does not need the seventeenth one back.
pub(crate) const MAX_SHARED: usize = 16;

/// What the device keeps for one encrypted session, dropped with it.
#[derive(Default)]
pub(crate) struct SessionState {
    /// The accounts the person agreed to show this session, most recent approval only.
    pub exposed: heapless::Vec<Exposed, MAX_EXPOSED>,
    /// The keys whose addresses were shared by path. On the heap, and only once there is
    /// one: this struct sits in the USB task's static for the life of the device, and a
    /// list most sessions never use is not worth its bytes of `.bss` there.
    shared: Option<crate::heap::Leased<heapless::Vec<Shared, MAX_SHARED>>>,
    /// The person ticked "Allow during session": an address asked for by its path is
    /// shared without a question. Nothing else is allowed by it.
    pub paths_allowed: bool,
}

impl SessionState {
    /// The keys shared by path, oldest first.
    pub(crate) fn shared(&self) -> &[Shared] {
        self.shared.as_ref().map_or(&[], |v| &v[..])
    }

    /// Remember that `key`'s address was shared. False only when there is no memory for
    /// the list, in which case nothing was recorded.
    pub(crate) fn share(&mut self, key: Shared) -> bool {
        if self.shared.is_none() {
            self.shared = crate::heap::Leased::new(heapless::Vec::new()).ok();
        }
        let Some(list) = self.shared.as_mut() else {
            return false;
        };
        if list.contains(&key) {
            return true;
        }
        if list.is_full() {
            list.remove(0);
        }
        list.push(key).is_ok()
    }

    /// The wallet in force changed: everything here described the old one, the
    /// allowance included -- it was given for that wallet's addresses.
    pub(crate) fn forget(&mut self) {
        self.exposed.clear();
        self.shared = None;
        self.paths_allowed = false;
    }
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
    /// The one address at `path`, written as `encoding`.
    AddressAt {
        chain: ChainId,
        encoding: Encoding,
        path: KeyPath,
        /// Put it on the screen to be compared, whatever the session is allowed.
        show: bool,
    },
    /// `len` bytes of message at the start of `text`, to be signed by the key at `path`.
    Message {
        chain: ChainId,
        how: MessageHow,
        path: KeyPath,
        text: crate::heap::Block,
        len: usize,
    },
}

/// How a message is signed: what the request's `format` and `scheme` came to.
#[derive(Copy, Clone)]
pub(crate) enum MessageHow {
    /// One of the Bitcoin formats, as an address of `kind`.
    Bitcoin {
        kind: catcard_wallet::address::AddressKind,
        format: crate::signmsg::Format,
    },
    /// EIP-191 `personal_sign`.
    #[cfg(all(feature = "multichain", not(feature = "board-mk3")))]
    Evm,
}

impl MessageHow {
    /// The wire's code for it ([`wire::scheme`]).
    fn scheme(self) -> u8 {
        use crate::signmsg::Format as F;
        match self {
            MessageHow::Bitcoin { format, .. } => match format {
                F::Legacy => wire::scheme::BIP137,
                F::Bip322 => wire::scheme::BIP322,
                F::Bip322Full => wire::scheme::BIP322_FULL,
            },
            #[cfg(all(feature = "multichain", not(feature = "board-mk3")))]
            MessageHow::Evm => wire::scheme::EIP191,
        }
    }
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
    /// The accounts that session was shown.
    pub exposed: &'a [Exposed],
    /// The keys whose addresses it was given by path.
    pub shared: &'a [Shared],
    /// Whether it may have an address by its path without a question.
    pub paths_allowed: bool,
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

/// Whether this build signs messages for `chain`. Everything else is refused by name.
pub(crate) fn signs_messages(chain: ChainId) -> bool {
    match chain {
        ChainId::Bitcoin => true,
        #[cfg(all(feature = "multichain", not(feature = "board-mk3")))]
        ChainId::Ethereum => true,
        _ => false,
    }
}

/// What a message request's `format` and `scheme` come to on `chain`, or why they do not
/// fit. The chain is one [`signs_messages`] said yes to.
fn message_how(chain: ChainId, format: u8, scheme: u8) -> Result<MessageHow, &'static str> {
    use crate::signmsg::Format as F;
    use catcard_wallet::address::AddressKind as K;
    match chain {
        ChainId::Bitcoin => {
            let kind = match format {
                wire::format::P2PKH => K::P2pkh,
                wire::format::P2SH_P2WPKH => K::P2shP2wpkh,
                wire::format::P2WPKH => K::P2wpkh,
                wire::format::P2TR => K::P2tr,
                _ => return Err("not a Bitcoin address format"),
            };
            let format = match scheme {
                wire::scheme::BIP137 => F::Legacy,
                wire::scheme::BIP322 => F::Bip322,
                wire::scheme::BIP322_FULL => F::Bip322Full,
                _ => return Err("not a Bitcoin message scheme"),
            };
            if !crate::signmsg::allows(kind, format) {
                return Err("that scheme does not fit that address type");
            }
            Ok(MessageHow::Bitcoin { kind, format })
        }
        #[cfg(all(feature = "multichain", not(feature = "board-mk3")))]
        ChainId::Ethereum => {
            if format != wire::format::EVM {
                return Err("not an EVM address format");
            }
            if scheme != wire::scheme::EIP191 {
                return Err("not an EVM message scheme");
            }
            Ok(MessageHow::Evm)
        }
        _ => Err("this chain does not sign messages here"),
    }
}

/// Why `message` cannot be signed under `how`, before any key is touched: not text the
/// screen shows faithfully, or too long for the scheme.
fn message_unshowable(how: MessageHow, message: &[u8]) -> Option<&'static str> {
    match how {
        MessageHow::Bitcoin { .. } => match core::str::from_utf8(message) {
            Ok(text) => crate::signmsg::unshowable(text),
            Err(_) => Some("plain ASCII only"),
        },
        #[cfg(all(feature = "multichain", not(feature = "board-mk3")))]
        MessageHow::Evm => catcard_evm::personal::text(message)
            .err()
            .map(catcard_evm::personal::Unshowable::why),
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
            Op::HostAddressAt => self.address_at(payload, out, cx),
            Op::HostSignMessage => self.message(payload, out, cx),
            Op::HostInfo => self.info(payload, out, cx),
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

    fn address_at(&mut self, p: &[u8], out: &mut [u8], cx: &Cx<'_>) -> (Status, usize) {
        let Ok(req) = wire::AddressAt::decode(p) else {
            return (Status::BadRequest, 0);
        };
        if let Some(r) = self.refuse_new(out, cx, false) {
            return r;
        }
        let c = match chain::resolve(u16::from(req.chain)) {
            Ok(c) => c,
            Err(chain::Unsupported::UnknownChain { .. }) => return refuse(out, "unknown chain"),
            Err(chain::Unsupported::NotInThisBuild { id }) => {
                return refuse_chain(out, id, "is not in this build");
            }
        };
        // The chain's own list is the rule: a format it does not have is not written.
        let Some(f) = c
            .formats
            .iter()
            .find(|f| format_code(f.encoding) == req.format)
        else {
            return refuse_chain(out, c.id, "has no such address format");
        };
        let Some(path) = KeyPath::new(req.path.steps()) else {
            return (Status::BadRequest, 0);
        };
        // SLIP-0010 derives hardened steps only.
        if f.encoding == Encoding::Solana && !path.fully_hardened() {
            return refuse(out, "a Solana key path must be hardened throughout");
        }
        crate::catlog!("host: one {} address asked for", c.name);
        self.state = State::Queued {
            owner: cx.session,
            ask: Ask::AddressAt {
                chain: c.id,
                encoding: f.encoding,
                path,
                show: req.flags & wire::ask::SHOW != 0,
            },
        };
        (Status::Ok, 0)
    }

    fn message(&mut self, p: &[u8], out: &mut [u8], cx: &Cx<'_>) -> (Status, usize) {
        let Ok(req) = wire::SignMessage::decode(p) else {
            return (Status::BadRequest, 0);
        };
        if let Some(r) = self.refuse_new(out, cx, false) {
            return r;
        }
        let chain = match chain::resolve(u16::from(req.chain)) {
            Ok(c) => c.id,
            Err(chain::Unsupported::UnknownChain { .. }) => return refuse(out, "unknown chain"),
            Err(chain::Unsupported::NotInThisBuild { id }) => {
                return refuse_chain(out, id, "is not in this build");
            }
        };
        if !signs_messages(chain) {
            return refuse_chain(out, chain, "messages cannot be signed here");
        }
        // Everything that can be judged without a key is judged here, as for a
        // transaction: a request that cannot be signed reaches nobody's screen.
        let how = match message_how(chain, req.format, req.scheme) {
            Ok(how) => how,
            Err(why) => return refuse(out, why),
        };
        let Some(path) = KeyPath::new(req.path.steps()) else {
            return (Status::BadRequest, 0);
        };
        if hostkeys::check(cx.exposed, cx.shared, chain, &[path]).is_err() {
            return refuse(out, "the key was not shared this session");
        }
        if let Some(why) = message_unshowable(how, req.message) {
            return refuse(out, why);
        }
        let len = req.message.len();
        let Some(mut text) = crate::heap::take(len) else {
            return refuse(out, "not enough memory now");
        };
        text.bytes()[..len].copy_from_slice(req.message);
        crate::catlog!(
            "host: {} message of {} bytes queued",
            chain_name(chain),
            len
        );
        self.state = State::Queued {
            owner: cx.session,
            ask: Ask::Message {
                chain,
                how,
                path,
                text,
                len,
            },
        };
        (Status::Ok, 0)
    }

    /// `HostInfo`: what this build answers and what the session has, and nothing of the
    /// wallet's. Answered whatever else is in hand, and while locked.
    fn info(&mut self, p: &[u8], out: &mut [u8], cx: &Cx<'_>) -> (Status, usize) {
        if wire::decode_empty(p).is_err() {
            return (Status::BadRequest, 0);
        }
        let mut session = 0;
        if cx.paths_allowed {
            session |= wire::session::PATHS_ALLOWED;
        }
        if !cx.exposed.is_empty() || !cx.shared.is_empty() {
            session |= wire::session::SHARED;
        }
        let features = wire::feature::ADDRESS_AT | wire::feature::SIGN_MESSAGE;
        let Ok(mut w) = wire::InfoWriter::new(out, features, session) else {
            return (Status::BadRequest, 0);
        };
        for c in chain::SUPPORTED {
            let mut can = wire::can::ADDRESSES;
            if signs(c.id) {
                can |= wire::can::SIGN;
            }
            if signs_messages(c.id) {
                can |= wire::can::MESSAGES;
            }
            let formats: heapless::Vec<u8, 8> = c
                .formats
                .iter()
                .take(8)
                .map(|f| format_code(f.encoding))
                .collect();
            // A reply that ran out of room says what fitted; the count is what was written.
            if w.push(c.id.as_u16() as u8, can, &formats).is_err() {
                break;
            }
        }
        (Status::Ok, w.finish())
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
        if !cx.exposed.iter().any(|e| e.chain == chain)
            && !cx.shared.iter().any(|s| s.chain == chain)
        {
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
        let verdict = check_blob(&buf.bytes()[..total], chain, cx.exposed, cx.shared);
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
fn check_blob(
    bytes: &[u8],
    chain: ChainId,
    exposed: &[Exposed],
    shared: &[Shared],
) -> Result<(), &'static str> {
    let blob = wire::SignBlob::decode(bytes).map_err(|_| "malformed sign request")?;
    if u16::from(blob.chain) != chain.as_u16() {
        return Err("chain differs from the one announced");
    }
    let keys = keys_of(&blob)?;
    match hostkeys::check(exposed, shared, chain, &keys) {
        Ok(()) => {}
        Err(hostkeys::Refused::NoKeys) => return Err("no key listed"),
        Err(hostkeys::Refused::NotExposed { .. }) => {
            return Err("a key was not shared this session");
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
    keys_into(blob, &mut keys)?;
    Ok(keys)
}

/// [`keys_of`], into a list that already lives somewhere -- the signing flow keeps it in a
/// heap block, under a review that is the deepest the UI's stack goes.
fn keys_into(
    blob: &wire::SignBlob<'_>,
    keys: &mut heapless::Vec<KeyPath, { wire::MAX_KEYS }>,
) -> Result<(), &'static str> {
    keys.clear();
    for k in blob.keys() {
        let p = KeyPath::new(k.steps()).ok_or("key path too deep")?;
        keys.push(p).map_err(|_| "too many keys")?;
    }
    Ok(())
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
    /// Every derived key of ours may sign, `keys` notwithstanding: a ckcc-mode host,
    /// whose protocol lists no keys (`crate::ckcc`). Stored WIF keys still never do.
    pub every_key: bool,
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
            every_key: false,
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
#[inline(never)]
pub(crate) fn serve(gate: &Callgate, login: &mut catcard_pin::Login, ui: &mut Ui<'_>) {
    let Some(t) = crate::usbtask::host_take() else {
        return;
    };
    let ticket = t.ticket;
    // `quiet`: the answer was one the session had been allowed ahead of time, so nobody
    // was asked and nobody is told -- a screen waiting for a key here would hold up the
    // next such request behind a keypress the allowance was given to spare.
    let (outcome, quiet) = match t.ask {
        Ask::Addresses => (addresses(gate, login, ui, ticket), false),
        Ask::Sign { chain, buf, len } => (sign(gate, login, ui, ticket, chain, buf, len), false),
        Ask::AddressAt {
            chain,
            encoding,
            path,
            show,
        } => address_at(gate, login, ui, ticket, chain, encoding, &path, show),
        Ask::Message {
            chain,
            how,
            path,
            text,
            len,
        } => (
            message(gate, login, ui, ticket, chain, how, &path, text, len),
            false,
        ),
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
    if quiet && sent && alive {
        return;
    }
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

#[inline(never)]
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

/// The chains to share, from the wallet's own list, each drawn as every chain list here
/// draws it -- its logo and its name -- with an on/off box. All on to begin with; OK flips
/// a row where it stands, and the row under the list goes on. Cancel declines.
// Every chain the wallet can list fits in one toggle list.
#[cfg(feature = "multichain")]
const _: () = assert!(crate::chains::MAX <= menu::TOGGLE_MAX);

#[cfg(feature = "multichain")]
#[inline(never)]
fn pick_chains(
    gate: &Callgate,
    login: &mut catcard_pin::Login,
    ui: &mut Ui<'_>,
) -> Option<heapless::Vec<&'static chain::Chain, { crate::chains::MAX }>> {
    let order = crate::chains::enabled(gate, login, ui);
    let mut rows: heapless::Vec<menu::Toggle<'static>, { crate::chains::MAX }> =
        heapless::Vec::new();
    for (i, c) in order.iter().enumerate() {
        let _ = rows.push(menu::Toggle {
            line: menu::chain_row(c, i as u32),
            on: true,
        });
    }
    loop {
        menu::toggle_list(ui, "Chains", "OK on/off", &mut rows, "Share these")?;
        let picked: heapless::Vec<&'static chain::Chain, { crate::chains::MAX }> = order
            .iter()
            .zip(rows.iter())
            .filter(|(_, r)| r.on)
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

#[inline(never)]
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
    let Some(mut keys) = crate::heap::room().map(|r| r.fill(heapless::Vec::new())) else {
        return Outcome::Refused("not enough memory");
    };
    let (tx_at, tx_len) = {
        let Ok(blob) = wire::SignBlob::decode(&buf.bytes()[..len]) else {
            return Outcome::Refused("malformed sign request");
        };
        match keys_into(&blob, &mut keys) {
            Ok(()) => (blob.tx_at, blob.tx.len()),
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
            crate::signtx::host_sign(gate, login, ui, buf, tx_at, tx_len, &keys, ticket, false)
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

// ---- one address, by its path ----------------------------------------------------------

/// Room for a path as text: `m`, then up to eight steps of ten digits, a slash and an `h`.
const PATH_TEXT: usize = 1 + hostkeys::MAX_DEPTH * 12;

/// A path as a person reads it: `m/84h/0h/0h/0/3`.
fn path_text(path: &KeyPath) -> heapless::String<PATH_TEXT> {
    const H: u32 = catcard_wallet::bip32::HARDENED_OFFSET;
    let mut s = heapless::String::new();
    let _ = s.push('m');
    for step in path.steps() {
        let _ = write!(s, "/{}{}", step & !H, if step & H != 0 { "h" } else { "" });
    }
    s
}

/// What one of `chain`'s formats is called on a screen.
fn format_label(c: &chain::Chain, encoding: Encoding) -> &'static str {
    c.formats
        .iter()
        .find(|f| f.encoding == encoding)
        .map_or("", |f| f.label)
}

/// The answer to `HostAddressAt`, and whether it was given without anybody being asked.
#[allow(clippy::too_many_arguments)]
#[inline(never)]
fn address_at(
    gate: &Callgate,
    login: &mut catcard_pin::Login,
    ui: &mut Ui<'_>,
    ticket: u32,
    chain: ChainId,
    encoding: Encoding,
    path: &KeyPath,
    show: bool,
) -> (Outcome, bool) {
    use catcard_ui::scroll::Line;
    let Ok(c) = chain::resolve(chain.as_u16()) else {
        return (Outcome::Refused("this chain is not in this build"), false);
    };
    let shown = path_text(path);
    let allowed = crate::usbtask::host_paths_allowed(ticket);
    if !allowed {
        // The question: which chain, which kind of address, which key. Read to its end
        // before it can be answered.
        let mut what: heapless::String<48> = heapless::String::new();
        let _ = write!(what, "{} address at", c.name);
        let lines = [
            Line::title("Computer asks"),
            Line::body("for the").small(),
            Line::body(&what).wrapped(),
            Line::body(&shown).wrapped(),
            Line::body(format_label(c, encoding)).small().wrapped(),
        ];
        if !asked(ui, &lines) || !alive(ticket) {
            return (Outcome::Declined, false);
        }
        // Then how far the yes goes. The cursor starts on "Share it": the box is an extra,
        // and one OK must never tick it.
        let mut rows = [menu::Toggle {
            line: Line::item("Allow during session", 0),
            on: false,
        }];
        if menu::toggle_list_from(ui, "Share address", "", &mut rows, "Share it", true).is_none()
            || !alive(ticket)
        {
            return (Outcome::Declined, false);
        }
        if rows[0].on {
            if !crate::usbtask::host_allow_paths(ticket) {
                return (Outcome::Declined, false);
            }
            crate::catlog!("host: addresses by path allowed for this session");
        }
    }

    let derived = match derive_at(gate, login, ui, c, encoding, path) {
        Ok(d) => d,
        Err(why) => return (Outcome::Refused(why), false),
    };
    let address = core::str::from_utf8(&derived.address[..derived.address_len]).unwrap_or("?");
    if show {
        // On the screen to be compared with the computer's, allowance or not: this is the
        // one request whose point is that a person looks.
        let lines = [
            Line::title("Address"),
            Line::body(address).wrapped(),
            Line::body(&shown).small().wrapped(),
            Line::body("Same as the computer shows?").small().wrapped(),
        ];
        if !asked(ui, &lines) || !alive(ticket) {
            return (Outcome::Declined, false);
        }
    }

    // What was shared is what may sign later -- recorded before the host can have it.
    let key = Shared { chain, key: *path };
    match crate::usbtask::host_share(ticket, key) {
        Some(true) => {}
        Some(false) => return (Outcome::Refused("not enough memory"), false),
        None => return (Outcome::Declined, false),
    }
    let Some(wpath) = wire::Path::new(path.steps()) else {
        return (Outcome::Refused("bad path"), false);
    };
    let reply = wire::AddressReply {
        fingerprint: derived.fingerprint,
        chain: chain.as_u16() as u8,
        format: format_code(encoding),
        path: wpath,
        address: &derived.address[..derived.address_len],
        pubkey: &derived.pubkey[..derived.pubkey_len],
    };
    const ROOM: usize = 8 + (1 + 4 * hostkeys::MAX_DEPTH) + 1 + caddr_max() + 1 + 33;
    let Some(mut block) = crate::heap::take(ROOM) else {
        return (Outcome::Refused("not enough memory"), false);
    };
    let Ok(len) = reply.encode(block.bytes()) else {
        return (Outcome::Refused("could not write the address"), false);
    };
    crate::catlog!("host: one {} address shared", c.name);
    set_note(c.name);
    (
        Outcome::Ready {
            buf: HostBuf::Heap(block),
            off: 0,
            len,
        },
        allowed && !show,
    )
}

/// Longest address any chain here writes.
const fn caddr_max() -> usize {
    catcard_wallet::chain::address::MAX_LEN
}

/// A document the person answers: OK at its end is yes, cancel is no.
#[inline(never)]
fn asked(ui: &mut Ui<'_>, lines: &[catcard_ui::scroll::Line<'_>]) -> bool {
    use catcard_ui::scroll::ScrollView;
    let mut view = ScrollView::build(
        lines,
        crate::display::SCREEN_W,
        crate::display::SCREEN_H,
        crate::display::FONTS,
    );
    menu::scroll_choice(ui, &mut view)
}

/// One key's public half, its address, and the wallet it belongs to.
struct Derived {
    fingerprint: [u8; 4],
    address: [u8; caddr_max()],
    address_len: usize,
    pubkey: [u8; 33],
    pubkey_len: usize,
}

/// Derive the key at `path` and write its address as `encoding`. Only the public key
/// leaves the masked regions.
#[inline(never)]
fn derive_at(
    gate: &Callgate,
    login: &mut catcard_pin::Login,
    ui: &mut Ui<'_>,
    c: &'static chain::Chain,
    encoding: Encoding,
    path: &KeyPath,
) -> Result<Derived, &'static str> {
    use catcard_wallet::bip32::ChildNumber;
    use catcard_wallet::chain::address as caddr;
    const HEAD: &str = "Address";

    let Some(master) = menu::unlock_master(gate, login, ui, HEAD) else {
        return Err("the wallet could not be opened");
    };
    let mut d = Derived {
        fingerprint: crate::keywork::run(|kw| master.fingerprint(kw)),
        address: [0; caddr_max()],
        address_len: 0,
        pubkey: [0; 33],
        pubkey_len: 0,
    };
    if encoding != Encoding::Solana {
        let mut steps: heapless::Vec<ChildNumber, { hostkeys::MAX_DEPTH }> = heapless::Vec::new();
        for s in path.steps() {
            let _ = steps.push(ChildNumber(*s));
        }
        let key = {
            let mut busy = menu::Working::new(ui.panel, HEAD, "deriving");
            menu::public_at(&master, &steps, &mut busy, ui.panel).ok_or("derivation failed")?
        };
        drop(master);
        d.address_len = caddr::from_secp256k1(
            c,
            encoding,
            crate::prefs::network(),
            &key.public_key,
            &mut d.address,
        )
        .map_err(|_| "could not write an address")?;
        d.pubkey = key.public_key;
        d.pubkey_len = 33;
        return Ok(d);
    }
    drop(master);

    // Solana: SLIP-0010 from the seed, not from the master (and hardened all the way,
    // which the USB task checked).
    #[cfg(feature = "multichain")]
    {
        const H: u32 = catcard_wallet::bip32::HARDENED_OFFSET;
        let mut steps: heapless::Vec<u32, { hostkeys::MAX_DEPTH }> = heapless::Vec::new();
        for s in path.steps() {
            let _ = steps.push(s & !H);
        }
        let key = menu::with_seed(gate, login, ui.panel, HEAD, |seed, kw| {
            catcard_wallet::slip10::derive(seed, &steps, kw).map(|n| n.public_key(kw))
        })?;
        d.address_len = caddr::from_ed25519(c, &key, &mut d.address)
            .map_err(|_| "could not write an address")?;
        d.pubkey[..32].copy_from_slice(&key);
        d.pubkey_len = 32;
        Ok(d)
    }
    #[cfg(not(feature = "multichain"))]
    {
        let _ = (c, d);
        Err("this chain is not in this build")
    }
}

// ---- messages -------------------------------------------------------------------------

#[allow(clippy::too_many_arguments)]
#[inline(never)]
fn message(
    gate: &Callgate,
    login: &mut catcard_pin::Login,
    ui: &mut Ui<'_>,
    ticket: u32,
    chain: ChainId,
    how: MessageHow,
    path: &KeyPath,
    mut text: crate::heap::Block,
    len: usize,
) -> Outcome {
    // Read again for use: the USB task checked it, and this is where it is acted on.
    let bytes = &text.bytes()[..len];
    if let Some(why) = message_unshowable(how, bytes) {
        return Outcome::Refused(why);
    }
    let Ok(body) = core::str::from_utf8(bytes) else {
        return Outcome::Refused("plain ASCII only");
    };

    let mut b: heapless::String<24> = heapless::String::new();
    let _ = write!(b, "{} message", chain_name(chain));
    menu::ask(ui.panel, "Computer asks", "you to sign a", &b);
    if !menu::confirmed(ui) || !alive(ticket) {
        return Outcome::Declined;
    }

    // The scheme's own review -- the text, the address that signs, the path, and how --
    // and its own check of the signature before anything is handed back.
    let done: Result<Outcome, Outcome> = match how {
        MessageHow::Bitcoin { kind, format } => {
            bitcoin_message(gate, login, ui, how, path, body, kind, format)
        }
        #[cfg(all(feature = "multichain", not(feature = "board-mk3")))]
        MessageHow::Evm => crate::evmtx::host_sign_message(gate, login, ui, body, path, ticket)
            .and_then(|(address, sig)| message_result(chain, how, path, address.as_bytes(), &sig)),
    };
    let outcome = match done {
        Ok(o) | Err(o) => o,
    };
    if matches!(outcome, Outcome::Ready { .. }) {
        if !alive(ticket) {
            return Outcome::Declined;
        }
        crate::catlog!("host: {} message signed", chain_name(chain));
        set_note("signed message");
    }
    outcome
}

/// A Bitcoin message, through the screens and the self-check `crate::signmsg` has.
#[allow(clippy::too_many_arguments)]
#[inline(never)]
fn bitcoin_message(
    gate: &Callgate,
    login: &mut catcard_pin::Login,
    ui: &mut Ui<'_>,
    how: MessageHow,
    path: &KeyPath,
    body: &str,
    kind: catcard_wallet::address::AddressKind,
    format: crate::signmsg::Format,
) -> Result<Outcome, Outcome> {
    use catcard_wallet::bip32::{ChildNumber, DerivationPath};
    let mut steps: heapless::Vec<ChildNumber, { hostkeys::MAX_DEPTH }> = heapless::Vec::new();
    for s in path.steps() {
        let _ = steps.push(ChildNumber(*s));
    }
    let dpath = DerivationPath::from_slice(&steps).map_err(|_| Outcome::Refused("bad path"))?;
    // `None` is the person saying no, or a failure the screen has already explained.
    let signed = crate::signmsg::sign_for_computer(gate, login, ui, body, kind, dpath, format)
        .ok_or(Outcome::Declined)?;
    message_result(
        ChainId::Bitcoin,
        how,
        path,
        signed.address.as_bytes(),
        signed.armoured.as_bytes(),
    )
}

/// The message result, in a heap block of its own.
fn message_result(
    chain: ChainId,
    how: MessageHow,
    path: &KeyPath,
    address: &[u8],
    signature: &[u8],
) -> Result<Outcome, Outcome> {
    let wpath = wire::Path::new(path.steps()).ok_or(Outcome::Refused("bad path"))?;
    let reply = wire::MessageReply {
        chain: chain.as_u16() as u8,
        scheme: how.scheme(),
        path: wpath,
        address,
        signature,
    };
    let room = wire::MessageReply::max_len(address.len(), signature.len());
    let mut block = crate::heap::take(room).ok_or(Outcome::Refused("not enough memory"))?;
    let len = reply
        .encode(block.bytes())
        .map_err(|_| Outcome::Refused("result too large"))?;
    Ok(Outcome::Ready {
        buf: HostBuf::Heap(block),
        off: 0,
        len,
    })
}
