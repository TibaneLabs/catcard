//! CTAPHID: FIDO messages over 64-byte HID reports.
//!
//! ```text
//! initialization packet            continuation packet
//!   0..4   CID (big-endian)          0..4   CID
//!   4      CMD | 0x80                4      SEQ (0..=0x7F)
//!   5..7   BCNT (big-endian)         5..64  data (59 bytes)
//!   7..64  data (57 bytes)
//! ```
//!
//! A message is one command and up to [`MAX_MSG`] bytes, cut into an initialization
//! packet and as many continuation packets as it needs, numbered from 0. Every channel
//! (CID) is one host application; `0xFFFFFFFF` is the broadcast channel, used only to ask
//! for a channel of one's own with `INIT`.
//! Source: FIDO CTAP 2.1 §11.2.4 "Message and packet structure" [C]
//!
//! # What this module owns, and what it does not
//!
//! Framing, reassembly and the channel rules, all host-tested: which CID may say what,
//! when a channel is busy, when a message has taken too long, and when a keepalive is due.
//! The message bytes live in a buffer the **caller** owns and passes in on every call --
//! the firmware leases it from the heap for the length of a transaction -- so this state
//! machine is a few dozen bytes and holds nothing secret.
//!
//! What a finished `CBOR` or `MSG` message *means* is not decided here: [`feed`] reports
//! it as [`Event::Request`], the caller works it out (possibly on another task, possibly
//! after asking a person), and [`respond`] frames the answer. Until then the channel is
//! **processing**: [`tick`] sends a `KEEPALIVE` every [`KEEPALIVE_MS`], a `CANCEL` on
//! that channel is noted for the caller, and anything else from any channel is answered
//! `ERR_CHANNEL_BUSY`.
//!
//! # Nothing a host sends can hang or panic this
//!
//! Every malformed packet has an answer: an `ERROR` frame on the sender's channel, or --
//! for a stray continuation, which the spec says to ignore -- nothing. Every wait is
//! bounded by the caller's clock: a message that stops arriving halfway is dropped after
//! [`MSG_TIMEOUT_MS`] with `ERR_MSG_TIMEOUT`.
//!
//! [`feed`]: Ctaphid::feed
//! [`respond`]: Ctaphid::respond
//! [`tick`]: Ctaphid::tick

/// Every report is 64 bytes, both ways, with no report ID.
/// Source: CTAP 2.1 §11.2.2 "Protocol structure and data framing" -- HID_RPT_SIZE 64 [C]
pub const PACKET: usize = 64;
/// Data bytes in an initialization packet: 64 less CID, CMD and BCNT.
pub const INIT_DATA: usize = PACKET - 7;
/// Data bytes in a continuation packet: 64 less CID and SEQ.
pub const CONT_DATA: usize = PACKET - 5;

/// The longest message accepted or sent. The same number is reported as `maxMsgSize` in
/// `authenticatorGetInfo`; 1024 is also what a platform assumes when an authenticator
/// says nothing. Source: CTAP 2.1 §6.4 "maxMsgSize ... default 1024" [C]
pub const MAX_MSG: usize = 1024;

/// The broadcast channel. Source: CTAP 2.1 §11.2.3 [C]
pub const BROADCAST: u32 = 0xFFFF_FFFF;

/// A message that has not finished arriving this long after its last packet is dropped
/// with `ERR_MSG_TIMEOUT`. The spec names the error, not the figure; three seconds is
/// generous for a transport that moves a packet a millisecond. [I]
pub const MSG_TIMEOUT_MS: u32 = 3000;

/// While a request is processing, a `KEEPALIVE` goes out this often.
/// Source: CTAP 2.1 §11.2.9.2.1 "CTAPHID_KEEPALIVE ... sent every 100ms" [C]
pub const KEEPALIVE_MS: u32 = 100;

/// Command codes, without the 0x80 bit that marks an initialization packet.
/// Source: CTAP 2.1 §11.2.9.1, §11.2.9.2 [C]
pub mod cmd {
    pub const PING: u8 = 0x01;
    pub const MSG: u8 = 0x03;
    pub const LOCK: u8 = 0x04;
    pub const INIT: u8 = 0x06;
    pub const WINK: u8 = 0x08;
    pub const CBOR: u8 = 0x10;
    pub const CANCEL: u8 = 0x11;
    pub const KEEPALIVE: u8 = 0x3B;
    pub const ERROR: u8 = 0x3F;
}

/// `CTAPHID_ERROR` codes. Source: CTAP 2.1 §11.2.9.1.6 [C]
pub mod err {
    pub const INVALID_CMD: u8 = 0x01;
    pub const INVALID_PAR: u8 = 0x02;
    pub const INVALID_LEN: u8 = 0x03;
    pub const INVALID_SEQ: u8 = 0x04;
    pub const MSG_TIMEOUT: u8 = 0x05;
    pub const CHANNEL_BUSY: u8 = 0x06;
    pub const LOCK_REQUIRED: u8 = 0x0A;
    pub const INVALID_CHANNEL: u8 = 0x0B;
    pub const OTHER: u8 = 0x7F;
}

/// `KEEPALIVE` status bytes. Source: CTAP 2.1 §11.2.9.2.1 [C]
pub mod status {
    pub const PROCESSING: u8 = 1;
    pub const UPNEEDED: u8 = 2;
}

/// `INIT` capability flags. Source: CTAP 2.1 §11.2.9.1.3 [C]
pub mod caps {
    /// Answers `WINK`.
    pub const WINK: u8 = 0x01;
    /// Answers `CBOR` (CTAP2).
    pub const CBOR: u8 = 0x04;
    /// Does **not** answer `MSG`. Never set here: this device speaks U2F too.
    pub const NMSG: u8 = 0x08;
}

/// The CTAPHID protocol version `INIT` reports. Source: CTAP 2.1 §11.2.9.1.3 [C]
pub const PROTOCOL_VERSION: u8 = 2;

/// What one packet amounted to.
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub enum Event {
    /// Nothing for the caller: a packet was taken, answered here, or ignored.
    None,
    /// A whole `CBOR` or `MSG` message is in the buffer's first `len` bytes. The channel
    /// is processing from now until [`Ctaphid::respond`] (or a resync).
    Request { cid: u32, cmd: u8, len: usize },
    /// `WINK`: show the person which device this is. Already answered.
    Wink,
    /// The processing channel sent `CANCEL`. [`Ctaphid::cancelled`] is now true.
    Cancel,
    /// A channel re-sent `INIT` while its request was processing: the request is void and
    /// its answer, when it comes, is dropped.
    Abandoned,
}

#[derive(Copy, Clone, Debug)]
struct Rx {
    cid: u32,
    cmd: u8,
    total: usize,
    got: usize,
    seq: u8,
    last: u32,
}

#[derive(Copy, Clone, Debug)]
struct Proc {
    cid: u32,
    cmd: u8,
    status: u8,
    last_keepalive: u32,
    cancelled: bool,
}

/// Where an outgoing message's bytes are.
#[derive(Copy, Clone, Debug)]
enum Src {
    /// The caller's buffer, `len` bytes.
    Buf(usize),
    /// An inline short reply: `INIT`'s 17 bytes, an error or keepalive byte.
    Small([u8; SMALL], usize),
}

const SMALL: usize = 17;

#[derive(Copy, Clone, Debug)]
struct Out {
    cid: u32,
    cmd: u8,
    src: Src,
    sent: usize,
    seq: u8,
    started: bool,
}

/// Short replies waiting behind whatever is being sent.
const QUEUE: usize = 4;

/// The CTAPHID state machine. See the module notes.
pub struct Ctaphid {
    next_cid: u32,
    rx: Option<Rx>,
    proc: Option<Proc>,
    out: Option<Out>,
    queue: [Option<Out>; QUEUE],
    /// Build numbers `INIT` reports: major, minor, build.
    version: [u8; 3],
    /// Channels handed out since the counter last wrapped: every CID from 1 below
    /// `next_cid` is one a host was given. Once it wraps, every non-zero CID is.
    wrapped: bool,
}

impl Ctaphid {
    pub const fn new(version: [u8; 3]) -> Self {
        Self {
            next_cid: 1,
            rx: None,
            proc: None,
            out: None,
            queue: [None; QUEUE],
            version,
            wrapped: false,
        }
    }

    /// Forget every message in flight, as a bus reset or a withdrawn interface must.
    /// Channels handed out stay valid: a host that kept its CID across a re-enumeration
    /// is answered rather than told its channel does not exist.
    pub fn reset(&mut self) {
        self.rx = None;
        self.proc = None;
        self.out = None;
        self.queue = [None; QUEUE];
    }

    /// Whether nothing is arriving, processing or waiting to be sent: the caller may give
    /// its buffer back.
    pub fn idle(&self) -> bool {
        self.rx.is_none()
            && self.proc.is_none()
            && self.out.is_none()
            && self.queue.iter().all(Option::is_none)
    }

    /// Whether the caller's buffer holds something this machine still needs: a message
    /// arriving, or an answer being sent from it. A processing request's buffer is the
    /// caller's to do with as it likes until it responds.
    pub fn needs_buffer(&self) -> bool {
        self.rx.is_some()
            || matches!(
                self.out,
                Some(Out {
                    src: Src::Buf(_),
                    ..
                })
            )
    }

    /// The processing request's channel and command, if one is.
    pub fn processing(&self) -> Option<(u32, u8)> {
        self.proc.map(|p| (p.cid, p.cmd))
    }

    /// Whether the processing channel has sent `CANCEL`.
    pub fn cancelled(&self) -> bool {
        self.proc.is_some_and(|p| p.cancelled)
    }

    /// Set what the keepalives say: [`status::PROCESSING`] or [`status::UPNEEDED`].
    pub fn set_status(&mut self, s: u8) {
        if let Some(p) = &mut self.proc {
            p.status = s;
        }
    }

    fn valid_channel(&self, cid: u32) -> bool {
        cid != 0 && cid != BROADCAST && (self.wrapped || cid < self.next_cid)
    }

    fn allocate(&mut self) -> u32 {
        let cid = self.next_cid;
        self.next_cid = self.next_cid.wrapping_add(1);
        if self.next_cid == BROADCAST || self.next_cid == 0 {
            self.next_cid = 1;
            self.wrapped = true;
        }
        cid
    }

    fn push_small(&mut self, cid: u32, cmd: u8, data: &[u8]) {
        let mut b = [0u8; SMALL];
        let n = data.len().min(SMALL);
        b[..n].copy_from_slice(&data[..n]);
        let o = Out {
            cid,
            cmd,
            src: Src::Small(b, n),
            sent: 0,
            seq: 0,
            started: false,
        };
        // Bounded: a host flooding the device with errors loses the excess replies, not
        // the device its memory. The first one it caused is still answered.
        if let Some(slot) = self.queue.iter_mut().find(|s| s.is_none()) {
            *slot = Some(o);
        }
    }

    fn error(&mut self, cid: u32, code: u8) {
        self.push_small(cid, cmd::ERROR, &[code]);
    }

    /// Take one report from the host.
    ///
    /// `buf` is where a message is assembled: at least [`MAX_MSG`] bytes while the caller
    /// can receive, or empty while it cannot (its buffer is out being worked on), in which
    /// case a new message is answered `ERR_CHANNEL_BUSY`. `now` is milliseconds on any
    /// clock that wraps.
    pub fn feed(&mut self, pkt: &[u8; PACKET], buf: &mut [u8], now: u32) -> Event {
        let cid = u32::from_be_bytes([pkt[0], pkt[1], pkt[2], pkt[3]]);
        if pkt[4] & 0x80 == 0 {
            return self.cont(cid, pkt, buf, now);
        }
        let command = pkt[4] & 0x7F;
        let bcnt = u16::from_be_bytes([pkt[5], pkt[6]]) as usize;

        if cid == 0 {
            self.error(cid, err::INVALID_CHANNEL);
            return Event::None;
        }
        if command == cmd::INIT {
            return self.init(cid, bcnt, &pkt[7..15]);
        }
        // Only INIT may use the broadcast channel, and only a channel handed out exists.
        if !self.valid_channel(cid) {
            self.error(cid, err::INVALID_CHANNEL);
            return Event::None;
        }
        if command == cmd::CANCEL {
            // No reply of its own: the cancelled request answers, with
            // CTAP2_ERR_KEEPALIVE_CANCEL. A CANCEL for nothing is ignored.
            // Source: CTAP 2.1 §11.2.9.1.5 [C]
            if let Some(p) = &mut self.proc
                && p.cid == cid
            {
                p.cancelled = true;
                return Event::Cancel;
            }
            return Event::None;
        }
        if self.proc.is_some() {
            self.error(cid, err::CHANNEL_BUSY);
            return Event::None;
        }
        if let Some(rx) = self.rx {
            if rx.cid == cid {
                // A new message on a channel still sending the last one: the host lost
                // track. Drop both rather than splice them.
                self.rx = None;
                self.error(cid, err::INVALID_SEQ);
            } else {
                self.error(cid, err::CHANNEL_BUSY);
            }
            return Event::None;
        }
        // The buffer is still sending an answer, or is out being worked on.
        if self.needs_buffer() || buf.is_empty() {
            self.error(cid, err::CHANNEL_BUSY);
            return Event::None;
        }
        if bcnt > MAX_MSG || bcnt > buf.len() {
            self.error(cid, err::INVALID_LEN);
            return Event::None;
        }
        let n = bcnt.min(INIT_DATA);
        buf[..n].copy_from_slice(&pkt[7..7 + n]);
        if n == bcnt {
            return self.complete(cid, command, bcnt, now);
        }
        self.rx = Some(Rx {
            cid,
            cmd: command,
            total: bcnt,
            got: n,
            seq: 0,
            last: now,
        });
        Event::None
    }

    fn cont(&mut self, cid: u32, pkt: &[u8; PACKET], buf: &mut [u8], now: u32) -> Event {
        let Some(mut rx) = self.rx else {
            // "Spurious continuation packets ... shall be ignored." [C] §11.2.4
            return Event::None;
        };
        if rx.cid != cid {
            return Event::None;
        }
        let seq = pkt[4];
        if seq != rx.seq || buf.len() < rx.total {
            self.rx = None;
            self.error(cid, err::INVALID_SEQ);
            return Event::None;
        }
        let n = (rx.total - rx.got).min(CONT_DATA);
        buf[rx.got..rx.got + n].copy_from_slice(&pkt[5..5 + n]);
        rx.got += n;
        rx.seq = rx.seq.wrapping_add(1);
        rx.last = now;
        if rx.got == rx.total {
            self.rx = None;
            return self.complete(cid, rx.cmd, rx.total, now);
        }
        // Sequence numbers run 0..=0x7F; a message that would need more packets than that
        // cannot be framed. MAX_MSG keeps well inside it.
        const _: () = assert!(INIT_DATA + 128 * CONT_DATA > MAX_MSG);
        self.rx = Some(rx);
        Event::None
    }

    fn init(&mut self, cid: u32, bcnt: usize, nonce: &[u8]) -> Event {
        // INIT carries exactly an 8-byte nonce. Source: CTAP 2.1 §11.2.9.1.3 [C]
        if bcnt != 8 {
            self.error(cid, err::INVALID_LEN);
            return Event::None;
        }
        let mut abandoned = false;
        let (reply_on, new_cid) = if cid == BROADCAST {
            (BROADCAST, self.allocate())
        } else if self.valid_channel(cid) {
            // A resync on a channel the host already holds: whatever that channel was
            // doing is over. Its answer, if one is being worked out, is dropped.
            if self.rx.is_some_and(|r| r.cid == cid) {
                self.rx = None;
            }
            if self.proc.is_some_and(|p| p.cid == cid) {
                self.proc = None;
                abandoned = true;
            }
            if self.out.is_some_and(|o| o.cid == cid) {
                self.out = None;
            }
            (cid, cid)
        } else {
            self.error(cid, err::INVALID_CHANNEL);
            return Event::None;
        };
        let mut r = [0u8; SMALL];
        r[..8].copy_from_slice(nonce);
        r[8..12].copy_from_slice(&new_cid.to_be_bytes());
        r[12] = PROTOCOL_VERSION;
        r[13..16].copy_from_slice(&self.version);
        r[16] = caps::WINK | caps::CBOR;
        self.push_small(reply_on, cmd::INIT, &r);
        if abandoned {
            Event::Abandoned
        } else {
            Event::None
        }
    }

    fn complete(&mut self, cid: u32, command: u8, len: usize, now: u32) -> Event {
        match command {
            // The payload comes back as it went: it is already in the buffer.
            cmd::PING => {
                self.out = Some(Out {
                    cid,
                    cmd: cmd::PING,
                    src: Src::Buf(len),
                    sent: 0,
                    seq: 0,
                    started: false,
                });
                Event::None
            }
            cmd::WINK => {
                if len != 0 {
                    self.error(cid, err::INVALID_LEN);
                    return Event::None;
                }
                self.push_small(cid, cmd::WINK, &[]);
                Event::Wink
            }
            cmd::CBOR | cmd::MSG => {
                // A CBOR message is at least its command byte; an APDU at least its
                // four-byte header. Anything shorter never reaches the caller.
                if (command == cmd::CBOR && len == 0) || (command == cmd::MSG && len < 4) {
                    self.error(cid, err::INVALID_LEN);
                    return Event::None;
                }
                self.proc = Some(Proc {
                    cid,
                    cmd: command,
                    status: status::PROCESSING,
                    last_keepalive: now,
                    cancelled: false,
                });
                Event::Request {
                    cid,
                    cmd: command,
                    len,
                }
            }
            // LOCK is optional and not offered: nothing here needs a host to hold the
            // device to itself. Source: CTAP 2.1 §11.2.9.2.2 "optional" [C]
            _ => {
                self.error(cid, err::INVALID_CMD);
                Event::None
            }
        }
    }

    /// Time passing: drop a message that stopped arriving, and keep the host told that a
    /// request is still being worked on.
    pub fn tick(&mut self, now: u32) {
        if let Some(rx) = self.rx
            && now.wrapping_sub(rx.last) >= MSG_TIMEOUT_MS
        {
            self.rx = None;
            self.error(rx.cid, err::MSG_TIMEOUT);
        }
        if let Some(p) = self.proc
            && now.wrapping_sub(p.last_keepalive) >= KEEPALIVE_MS
            && self.out.is_none()
            && self.queue.iter().all(Option::is_none)
        {
            self.push_small(p.cid, cmd::KEEPALIVE, &[p.status]);
            if let Some(p) = &mut self.proc {
                p.last_keepalive = now;
            }
        }
    }

    /// The processing request's answer is in the buffer's first `len` bytes: send it.
    ///
    /// Returns false, sending nothing, when there is no request to answer -- it was
    /// abandoned by a resync or a reset while it was being worked out -- or when `len`
    /// is more than a message may carry.
    pub fn respond(&mut self, len: usize) -> bool {
        let Some(p) = self.proc.take() else {
            return false;
        };
        if len > MAX_MSG {
            self.error(p.cid, err::OTHER);
            return false;
        }
        self.out = Some(Out {
            cid: p.cid,
            cmd: p.cmd,
            src: Src::Buf(len),
            sent: 0,
            seq: 0,
            started: false,
        });
        true
    }

    /// End the processing request with a CTAPHID error rather than an answer.
    pub fn fail(&mut self, code: u8) {
        if let Some(p) = self.proc.take() {
            self.error(p.cid, code);
        }
    }

    /// The next report to send, if there is one. `buf` is the same buffer [`feed`] and
    /// [`respond`] were given. Unused bytes are zero, never what the report held before.
    ///
    /// [`feed`]: Self::feed
    /// [`respond`]: Self::respond
    pub fn next_packet(&mut self, buf: &[u8], pkt: &mut [u8; PACKET]) -> bool {
        if self.out.is_none() {
            // Short replies go between messages, never inside one.
            let Some(i) = self.queue.iter().position(Option::is_some) else {
                return false;
            };
            self.out = self.queue[i].take();
            // Keep the queue in arrival order.
            self.queue[i..].rotate_left(1);
        }
        let Some(o) = &mut self.out else {
            return false;
        };
        let data: &[u8] = match &o.src {
            Src::Buf(n) => match buf.get(..*n) {
                Some(d) => d,
                // The caller's buffer went away mid-message: nothing sensible to send.
                None => {
                    self.out = None;
                    return false;
                }
            },
            Src::Small(b, n) => &b[..*n],
        };
        pkt.fill(0);
        pkt[..4].copy_from_slice(&o.cid.to_be_bytes());
        if !o.started {
            let n = data.len().min(INIT_DATA);
            pkt[4] = o.cmd | 0x80;
            pkt[5..7].copy_from_slice(&(data.len() as u16).to_be_bytes());
            pkt[7..7 + n].copy_from_slice(&data[..n]);
            o.sent = n;
            o.started = true;
        } else {
            let n = (data.len() - o.sent).min(CONT_DATA);
            pkt[4] = o.seq;
            pkt[5..5 + n].copy_from_slice(&data[o.sent..o.sent + n]);
            o.sent += n;
            o.seq = o.seq.wrapping_add(1);
        }
        if o.sent >= data.len() {
            self.out = None;
        }
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn init_pkt(cid: u32, command: u8, data: &[u8], bcnt: usize) -> [u8; PACKET] {
        let mut p = [0u8; PACKET];
        p[..4].copy_from_slice(&cid.to_be_bytes());
        p[4] = command | 0x80;
        p[5..7].copy_from_slice(&(bcnt as u16).to_be_bytes());
        let n = data.len().min(INIT_DATA);
        p[7..7 + n].copy_from_slice(&data[..n]);
        p
    }

    fn cont_pkt(cid: u32, seq: u8, data: &[u8]) -> [u8; PACKET] {
        let mut p = [0u8; PACKET];
        p[..4].copy_from_slice(&cid.to_be_bytes());
        p[4] = seq;
        p[5..5 + data.len()].copy_from_slice(data);
        p
    }

    /// Send a whole message as a host would.
    fn send(
        h: &mut Ctaphid,
        buf: &mut [u8],
        cid: u32,
        command: u8,
        data: &[u8],
        now: u32,
    ) -> Event {
        let mut ev = h.feed(&init_pkt(cid, command, data, data.len()), buf, now);
        let mut at = INIT_DATA.min(data.len());
        let mut seq = 0;
        while at < data.len() {
            let n = (data.len() - at).min(CONT_DATA);
            ev = h.feed(&cont_pkt(cid, seq, &data[at..at + n]), buf, now);
            at += n;
            seq += 1;
        }
        ev
    }

    /// Read back every queued message as `(cid, cmd, payload)`.
    fn drain(h: &mut Ctaphid, buf: &[u8]) -> Vec<(u32, u8, Vec<u8>)> {
        let mut out = Vec::new();
        let mut pkt = [0u8; PACKET];
        let mut cur: Option<(u32, u8, usize, Vec<u8>, u8)> = None;
        while h.next_packet(buf, &mut pkt) {
            let cid = u32::from_be_bytes([pkt[0], pkt[1], pkt[2], pkt[3]]);
            if pkt[4] & 0x80 != 0 {
                assert!(cur.is_none(), "a new message before the last one finished");
                let total = u16::from_be_bytes([pkt[5], pkt[6]]) as usize;
                let n = total.min(INIT_DATA);
                cur = Some((cid, pkt[4] & 0x7F, total, pkt[7..7 + n].to_vec(), 0));
            } else {
                let c = cur.as_mut().expect("continuation with no message");
                assert_eq!(c.0, cid);
                assert_eq!(pkt[4], c.4, "sequence");
                c.4 += 1;
                let n = (c.2 - c.3.len()).min(CONT_DATA);
                c.3.extend_from_slice(&pkt[5..5 + n]);
            }
            if let Some(c) = &cur
                && c.3.len() == c.2
            {
                let c = cur.take().unwrap();
                out.push((c.0, c.1, c.3));
            }
        }
        assert!(cur.is_none(), "a message was left half sent");
        out
    }

    fn channel(h: &mut Ctaphid, buf: &mut [u8]) -> u32 {
        let nonce = [1, 2, 3, 4, 5, 6, 7, 8];
        assert_eq!(send(h, buf, BROADCAST, cmd::INIT, &nonce, 0), Event::None);
        let r = drain(h, buf);
        assert_eq!(r.len(), 1);
        let (cid, c, data) = &r[0];
        assert_eq!((*cid, *c), (BROADCAST, cmd::INIT));
        assert_eq!(data.len(), 17);
        assert_eq!(&data[..8], &nonce);
        u32::from_be_bytes([data[8], data[9], data[10], data[11]])
    }

    #[test]
    fn init_on_broadcast_hands_out_a_channel_and_echoes_the_nonce() {
        let mut h = Ctaphid::new([7, 0, 1]);
        let mut buf = [0u8; MAX_MSG];
        let nonce = [9u8, 8, 7, 6, 5, 4, 3, 2];
        send(&mut h, &mut buf, BROADCAST, cmd::INIT, &nonce, 0);
        let r = drain(&mut h, &buf);
        let d = &r[0].2;
        assert_eq!(&d[..8], &nonce);
        let cid = u32::from_be_bytes([d[8], d[9], d[10], d[11]]);
        assert!(cid != 0 && cid != BROADCAST);
        assert_eq!(d[12], 2, "CTAPHID protocol version");
        assert_eq!(&d[13..16], &[7, 0, 1]);
        // WINK and CBOR; NMSG clear because MSG (U2F) is answered.
        assert_eq!(d[16], caps::WINK | caps::CBOR);
        // A second INIT hands out a different channel.
        let other = channel(&mut h, &mut buf);
        assert_ne!(other, cid);
    }

    #[test]
    fn a_long_message_reassembles_and_a_ping_echoes_it_back_across_packets() {
        let mut h = Ctaphid::new([0; 3]);
        let mut buf = [0u8; MAX_MSG];
        let cid = channel(&mut h, &mut buf);
        let data: Vec<u8> = (0..MAX_MSG).map(|i| (i * 7) as u8).collect();
        assert_eq!(
            send(&mut h, &mut buf, cid, cmd::PING, &data, 0),
            Event::None
        );
        let r = drain(&mut h, &buf);
        assert_eq!(r, vec![(cid, cmd::PING, data)]);
    }

    #[test]
    fn a_cbor_request_is_handed_over_and_the_answer_framed_back() {
        let mut h = Ctaphid::new([0; 3]);
        let mut buf = [0u8; MAX_MSG];
        let cid = channel(&mut h, &mut buf);
        let req: Vec<u8> = (0..200).map(|i| i as u8).collect();
        let ev = send(&mut h, &mut buf, cid, cmd::CBOR, &req, 0);
        assert_eq!(
            ev,
            Event::Request {
                cid,
                cmd: cmd::CBOR,
                len: 200
            }
        );
        assert_eq!(&buf[..200], &req[..]);
        assert_eq!(h.processing(), Some((cid, cmd::CBOR)));
        buf[..3].copy_from_slice(&[0x00, 0xa0, 0x00]);
        assert!(h.respond(2));
        assert_eq!(
            drain(&mut h, &buf),
            vec![(cid, cmd::CBOR, vec![0x00, 0xa0])]
        );
        assert!(h.idle());
    }

    #[test]
    fn keepalives_run_every_100ms_while_processing_and_say_what_is_awaited() {
        let mut h = Ctaphid::new([0; 3]);
        let mut buf = [0u8; MAX_MSG];
        let cid = channel(&mut h, &mut buf);
        send(&mut h, &mut buf, cid, cmd::CBOR, &[0x01], 1000);
        h.tick(1050);
        assert!(drain(&mut h, &buf).is_empty(), "not yet");
        h.tick(1100);
        assert_eq!(
            drain(&mut h, &buf),
            vec![(cid, cmd::KEEPALIVE, vec![status::PROCESSING])]
        );
        h.set_status(status::UPNEEDED);
        h.tick(1150);
        assert!(drain(&mut h, &buf).is_empty());
        h.tick(1200);
        assert_eq!(
            drain(&mut h, &buf),
            vec![(cid, cmd::KEEPALIVE, vec![status::UPNEEDED])]
        );
        // The clock may wrap under it.
        let mut h = Ctaphid::new([0; 3]);
        let cid = channel(&mut h, &mut buf);
        send(&mut h, &mut buf, cid, cmd::CBOR, &[0x01], u32::MAX - 20);
        h.tick(90);
        assert_eq!(drain(&mut h, &buf).len(), 1);
    }

    #[test]
    fn another_channel_is_told_busy_while_one_is_processing() {
        let mut h = Ctaphid::new([0; 3]);
        let mut buf = [0u8; MAX_MSG];
        let a = channel(&mut h, &mut buf);
        let b = channel(&mut h, &mut buf);
        send(&mut h, &mut buf, a, cmd::CBOR, &[0x04], 0);
        assert_eq!(
            send(&mut h, &mut buf, b, cmd::CBOR, &[0x04], 0),
            Event::None
        );
        assert_eq!(
            drain(&mut h, &buf),
            vec![(b, cmd::ERROR, vec![err::CHANNEL_BUSY])]
        );
        // So is the same channel, if it sends anything but CANCEL or INIT.
        send(&mut h, &mut buf, a, cmd::PING, &[1], 0);
        assert_eq!(
            drain(&mut h, &buf),
            vec![(a, cmd::ERROR, vec![err::CHANNEL_BUSY])]
        );
        // INIT on the broadcast channel is still answered: a new application can always
        // get a channel.
        channel(&mut h, &mut buf);
        assert_eq!(h.processing(), Some((a, cmd::CBOR)));
    }

    #[test]
    fn cancel_is_noted_for_the_processing_channel_and_ignored_otherwise() {
        let mut h = Ctaphid::new([0; 3]);
        let mut buf = [0u8; MAX_MSG];
        let a = channel(&mut h, &mut buf);
        let b = channel(&mut h, &mut buf);
        assert_eq!(send(&mut h, &mut buf, a, cmd::CANCEL, &[], 0), Event::None);
        send(&mut h, &mut buf, a, cmd::CBOR, &[0x01], 0);
        assert_eq!(send(&mut h, &mut buf, b, cmd::CANCEL, &[], 0), Event::None);
        assert!(!h.cancelled());
        assert_eq!(
            send(&mut h, &mut buf, a, cmd::CANCEL, &[], 0),
            Event::Cancel
        );
        assert!(h.cancelled());
        // CANCEL itself has no reply; the request answers.
        assert!(drain(&mut h, &buf).is_empty());
    }

    #[test]
    fn a_resync_abandons_the_request_and_drops_its_answer() {
        let mut h = Ctaphid::new([0; 3]);
        let mut buf = [0u8; MAX_MSG];
        let a = channel(&mut h, &mut buf);
        send(&mut h, &mut buf, a, cmd::CBOR, &[0x01], 0);
        let ev = send(&mut h, &mut buf, a, cmd::INIT, &[0; 8], 0);
        assert_eq!(ev, Event::Abandoned);
        let r = drain(&mut h, &buf);
        assert_eq!(r.len(), 1);
        assert_eq!((r[0].0, r[0].1), (a, cmd::INIT));
        assert_eq!(&r[0].2[8..12], &a.to_be_bytes(), "same channel back");
        assert!(
            !h.respond(1),
            "the answer to an abandoned request goes nowhere"
        );
        assert!(drain(&mut h, &buf).is_empty());
    }

    #[test]
    fn sequence_errors_and_stray_continuations() {
        let mut h = Ctaphid::new([0; 3]);
        let mut buf = [0u8; MAX_MSG];
        let a = channel(&mut h, &mut buf);
        // A continuation with nothing open is ignored, silently.
        assert_eq!(h.feed(&cont_pkt(a, 0, &[1]), &mut buf, 0), Event::None);
        assert!(drain(&mut h, &buf).is_empty());
        // A skipped sequence number ends the message with ERR_INVALID_SEQ.
        h.feed(&init_pkt(a, cmd::PING, &[0; 57], 200), &mut buf, 0);
        h.feed(&cont_pkt(a, 1, &[0; 59]), &mut buf, 0);
        assert_eq!(
            drain(&mut h, &buf),
            vec![(a, cmd::ERROR, vec![err::INVALID_SEQ])]
        );
        // And the channel is usable again.
        send(&mut h, &mut buf, a, cmd::PING, &[5], 0);
        assert_eq!(drain(&mut h, &buf), vec![(a, cmd::PING, vec![5])]);
        // A new message on the channel mid-message is an error too.
        h.feed(&init_pkt(a, cmd::PING, &[0; 57], 200), &mut buf, 0);
        h.feed(&init_pkt(a, cmd::PING, &[1], 1), &mut buf, 0);
        assert_eq!(
            drain(&mut h, &buf),
            vec![(a, cmd::ERROR, vec![err::INVALID_SEQ])]
        );
        // Another channel starting while one is mid-message is told busy, and the first
        // one's message still completes.
        let b = channel(&mut h, &mut buf);
        h.feed(&init_pkt(a, cmd::PING, &[3; 57], 60), &mut buf, 0);
        h.feed(&init_pkt(b, cmd::PING, &[1], 1), &mut buf, 0);
        h.feed(&cont_pkt(b, 0, &[9; 59]), &mut buf, 0);
        h.feed(&cont_pkt(a, 0, &[3; 3]), &mut buf, 0);
        assert_eq!(
            drain(&mut h, &buf),
            vec![
                (a, cmd::PING, vec![3; 60]),
                (b, cmd::ERROR, vec![err::CHANNEL_BUSY])
            ]
        );
    }

    #[test]
    fn a_message_that_stops_arriving_times_out() {
        let mut h = Ctaphid::new([0; 3]);
        let mut buf = [0u8; MAX_MSG];
        let a = channel(&mut h, &mut buf);
        h.feed(&init_pkt(a, cmd::PING, &[0; 57], 100), &mut buf, 10);
        h.tick(10 + MSG_TIMEOUT_MS - 1);
        assert!(drain(&mut h, &buf).is_empty());
        h.tick(10 + MSG_TIMEOUT_MS);
        assert_eq!(
            drain(&mut h, &buf),
            vec![(a, cmd::ERROR, vec![err::MSG_TIMEOUT])]
        );
        assert!(h.idle());
    }

    #[test]
    fn bad_channels_lengths_and_commands_are_errors() {
        let mut h = Ctaphid::new([0; 3]);
        let mut buf = [0u8; MAX_MSG];
        // Channel 0, a channel never handed out, and a non-INIT on broadcast.
        send(&mut h, &mut buf, 0, cmd::PING, &[1], 0);
        send(&mut h, &mut buf, 0x1234, cmd::PING, &[1], 0);
        send(&mut h, &mut buf, BROADCAST, cmd::PING, &[1], 0);
        assert_eq!(
            drain(&mut h, &buf),
            vec![
                (0, cmd::ERROR, vec![err::INVALID_CHANNEL]),
                (0x1234, cmd::ERROR, vec![err::INVALID_CHANNEL]),
                (BROADCAST, cmd::ERROR, vec![err::INVALID_CHANNEL]),
            ]
        );
        let a = channel(&mut h, &mut buf);
        // Too long, INIT of the wrong length, an unknown command, LOCK, an empty CBOR, a
        // three-byte APDU.
        h.feed(&init_pkt(a, cmd::PING, &[], MAX_MSG + 1), &mut buf, 0);
        h.feed(&init_pkt(BROADCAST, cmd::INIT, &[0; 7], 7), &mut buf, 0);
        send(&mut h, &mut buf, a, 0x55, &[], 0);
        send(&mut h, &mut buf, a, cmd::LOCK, &[5], 0);
        send(&mut h, &mut buf, a, cmd::CBOR, &[], 0);
        let r = drain(&mut h, &buf);
        assert_eq!(
            r,
            vec![
                (a, cmd::ERROR, vec![err::INVALID_LEN]),
                (BROADCAST, cmd::ERROR, vec![err::INVALID_LEN]),
                (a, cmd::ERROR, vec![err::INVALID_CMD]),
                (a, cmd::ERROR, vec![err::INVALID_CMD]),
            ],
            "the queue holds four; the fifth error is dropped, not the device"
        );
        send(&mut h, &mut buf, a, cmd::MSG, &[0, 3, 0], 0);
        assert_eq!(
            drain(&mut h, &buf),
            vec![(a, cmd::ERROR, vec![err::INVALID_LEN])]
        );
    }

    #[test]
    fn wink_is_answered_and_reported() {
        let mut h = Ctaphid::new([0; 3]);
        let mut buf = [0u8; MAX_MSG];
        let a = channel(&mut h, &mut buf);
        assert_eq!(send(&mut h, &mut buf, a, cmd::WINK, &[], 0), Event::Wink);
        assert_eq!(drain(&mut h, &buf), vec![(a, cmd::WINK, vec![])]);
    }

    #[test]
    fn with_no_buffer_to_receive_into_a_new_message_is_told_busy() {
        let mut h = Ctaphid::new([0; 3]);
        let mut buf = [0u8; MAX_MSG];
        let a = channel(&mut h, &mut buf);
        send(&mut h, &mut [], a, cmd::PING, &[1], 0);
        assert_eq!(
            drain(&mut h, &buf),
            vec![(a, cmd::ERROR, vec![err::CHANNEL_BUSY])]
        );
        // INIT needs no buffer.
        send(&mut h, &mut [], BROADCAST, cmd::INIT, &[0; 8], 0);
        assert_eq!(drain(&mut h, &buf).len(), 1);
    }

    #[test]
    fn random_packets_never_panic() {
        // Not a fuzzer, but every byte of the header varied over a fixed stream.
        let mut h = Ctaphid::new([0; 3]);
        let mut buf = [0u8; MAX_MSG];
        let mut x: u32 = 0x1234_5678;
        let mut out = [0u8; PACKET];
        for i in 0..20_000u32 {
            let mut p = [0u8; PACKET];
            for b in p.iter_mut() {
                x ^= x << 13;
                x ^= x >> 17;
                x ^= x << 5;
                *b = x as u8;
            }
            // Keep some on real channels so reassembly paths run.
            if i % 3 == 0 {
                p[..4].copy_from_slice(&1u32.to_be_bytes());
            }
            if i % 7 == 0 {
                p[..4].copy_from_slice(&BROADCAST.to_be_bytes());
            }
            let ev = h.feed(&p, &mut buf, i);
            if let Event::Request { .. } = ev {
                h.respond((i as usize) % 50);
            }
            h.tick(i);
            while h.next_packet(&buf, &mut out) {}
        }
    }
}
