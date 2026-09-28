//! Raw random-source samples and the source health report, over USB.
//!
//! Two transports carry the same samples. The bench one, [`Opcode::DebugTrng`], is
//! plaintext and exists only in a bench build. The paired one, [`Opcode::RngSample`], is
//! answered only inside a paired [`Opcode::NcryMsg`] session, exists in every build, and
//! asks the person at the device once per session before the first chunk leaves. Both
//! share the wire shapes here and one reader in the firmware (`trngcap`).
//!
//! What is here is what does not need the hardware: the request and reply shapes, the
//! once-per-session consent, the secure elements' read allowance, and the health report's
//! encoding. The firmware supplies the reads and the screen.
//!
//! [`Opcode::DebugTrng`]: crate::Opcode::DebugTrng
//! [`Opcode::RngSample`]: crate::Opcode::RngSample
//! [`Opcode::NcryMsg`]: crate::Opcode::NcryMsg

use crate::Status;

/// Largest chunk one request returns: fourteen of the secure elements' 32-byte answers,
/// which keeps the reply (with its 8-byte header) inside the USB task's 512-byte reply,
/// and inside a sealed reply's body too.
pub const CHUNK_MAX: usize = 448;

/// Bytes ahead of the data in a chunk: `[u8 source][u8 flags][u16 n][u32 chunk]`.
pub const HEADER: usize = 8;

/// The largest body a sample reply has.
pub const REPLY_LEN: usize = HEADER + CHUNK_MAX;

/// Wire numbers of the sources. Fixed: a host keeps captures by them.
pub mod source {
    /// The MCU's own TRNG.
    pub const CHIP: u8 = 1;
    /// SE1 through callgate 26 (mk4 and later).
    pub const SE1: u8 = 2;
    /// SE2 through callgate 26 (mk4 and later).
    pub const SE2: u8 = 3;
    // 4 was the bootloader's read (callgate 17). Retired, not reused: an old capture file
    // must never be mistaken for a new source.
    /// SE1's `Random` over its raw single-wire bus (mk3).
    pub const SE1_WIRE: u8 = 5;
}

/// Bits in the flags byte of a chunk.
pub mod flags {
    /// The source produced fewer bytes than asked within the read bound.
    pub const SHORT: u8 = 1 << 0;
    /// The source refused a read (a callgate error, a dead bus). The chunk ends there.
    pub const REFUSED: u8 = 1 << 1;
    /// Paired only: this chunk spent the last of a secure element's read allowance
    /// ([`SE_CALLS_PER_SESSION`](super::SE_CALLS_PER_SESSION),
    /// [`SE_CALLS_PER_BOOT`](super::SE_CALLS_PER_BOOT)). Asking again is `Refused`.
    pub const LIMIT: u8 = 1 << 2;
}

/// The one-byte body of a paired `NotNow`: why the chunk is not there yet.
pub mod wait {
    /// The device is reading it; ask again.
    pub const READING: u8 = 1;
    /// The person at the device has not answered the question yet; ask again.
    pub const ASKING: u8 = 2;
}

/// The one-byte body of a paired `Refused` for a source this board has.
pub mod limit {
    /// This session has spent its reads of that secure element.
    pub const SESSION: u8 = 1;
    /// This power-up has spent its reads of that secure element.
    pub const BOOT: u8 = 2;
}

/// A sample request, parsed.
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub enum Request {
    /// Empty payload: what this board has.
    List,
    /// `[u8 source][u16 len]`: `len` bytes (1..=[`CHUNK_MAX`]) from `source`.
    Chunk { source: u8, len: u16 },
}

/// Parse a sample request. `Err` is the status to answer with.
pub fn parse_request(p: &[u8]) -> Result<Request, Status> {
    if p.is_empty() {
        return Ok(Request::List);
    }
    if p.len() != 3 {
        return Err(Status::BadRequest);
    }
    let len = u16::from_le_bytes([p[1], p[2]]);
    if len == 0 || len as usize > CHUNK_MAX {
        return Err(Status::BadRequest);
    }
    Ok(Request::Chunk { source: p[0], len })
}

/// The list reply: `[u16 chunk_max][u8 count][u8 source]...`. Returns its length; `out`
/// must hold `3 + sources.len()` bytes.
pub fn list_body(sources: &[u8], out: &mut [u8]) -> usize {
    out[..2].copy_from_slice(&(CHUNK_MAX as u16).to_le_bytes());
    out[2] = sources.len() as u8;
    out[3..3 + sources.len()].copy_from_slice(sources);
    3 + sources.len()
}

/// The header of a chunk reply.
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub struct Chunk {
    pub source: u8,
    pub flags: u8,
    /// Bytes of data after the header.
    pub n: u16,
    /// Counts chunks the device has read since power-up, over both transports.
    pub number: u32,
}

impl Chunk {
    /// Write the header into `out[..HEADER]`.
    pub fn write(&self, out: &mut [u8]) {
        out[0] = self.source;
        out[1] = self.flags;
        out[2..4].copy_from_slice(&self.n.to_le_bytes());
        out[4..8].copy_from_slice(&self.number.to_le_bytes());
    }

    /// Read a chunk reply's header, checking the data it promises is there.
    pub fn read(body: &[u8]) -> Option<Self> {
        if body.len() < HEADER {
            return None;
        }
        let c = Chunk {
            source: body[0],
            flags: body[1],
            n: u16::from_le_bytes([body[2], body[3]]),
            number: u32::from_le_bytes([body[4], body[5], body[6], body[7]]),
        };
        (c.n as usize <= CHUNK_MAX && body.len() == HEADER + c.n as usize).then_some(c)
    }
}

// --- consent -------------------------------------------------------------------------------

/// Where the question to the person stands, for one paired session.
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub enum Consent {
    /// Nobody has asked for a chunk in this session yet.
    Unasked,
    /// The question is waiting for the person at the device.
    Asking,
    /// They said yes: chunks may leave for the rest of this session.
    Granted,
    /// They said no, or did not answer: every chunk request in this session is refused.
    Refused,
}

/// The once-per-session question: "share samples of this device's random generators?"
///
/// Keyed by the session's number, so a new session -- after unpairing, a new pairing, a
/// bus reset or an unplug -- always starts [`Consent::Unasked`], whatever the last one
/// was told. [`end`](Self::end) also forgets at once, so a question still on the screen
/// for a session that has gone is taken down rather than answered.
#[derive(Copy, Clone, Debug)]
pub struct ConsentGate {
    session: u32,
    state: Consent,
}

impl Default for ConsentGate {
    fn default() -> Self {
        Self::new()
    }
}

impl ConsentGate {
    pub const fn new() -> Self {
        Self {
            session: 0,
            state: Consent::Unasked,
        }
    }

    /// A chunk was asked for in session `id` (never zero: the channel numbers sessions
    /// from one). Returns what to do with it; an unasked session starts asking.
    pub fn request(&mut self, id: u32) -> Consent {
        if id == 0 {
            return Consent::Refused;
        }
        if self.session != id {
            self.session = id;
            self.state = Consent::Unasked;
        }
        if self.state == Consent::Unasked {
            self.state = Consent::Asking;
        }
        self.state
    }

    /// The session whose question is waiting for the screen, if one is.
    pub fn to_ask(&self) -> Option<u32> {
        (self.state == Consent::Asking && self.session != 0).then_some(self.session)
    }

    /// Whether session `id`'s question is still waiting: false once it is answered, or
    /// the session has ended or been replaced.
    pub fn still_asking(&self, id: u32) -> bool {
        self.to_ask() == Some(id)
    }

    /// The person's answer for session `id`. Ignored unless that session's question is
    /// the one waiting; returns whether it was taken.
    pub fn answer(&mut self, id: u32, yes: bool) -> bool {
        if !self.still_asking(id) {
            return false;
        }
        self.state = if yes {
            Consent::Granted
        } else {
            Consent::Refused
        };
        true
    }

    /// The session ended: forget it, answered or not.
    pub fn end(&mut self) {
        *self = Self::new();
    }
}

// --- the secure elements' read allowance ---------------------------------------------------

/// Reads of one secure element a paired session may make.
///
/// A secure element's `Random` may write its EEPROM: the ATECC508A updates its stored RNG
/// seed "once after every power-up or sleep/wake cycle" (DS20005927A §3.3.2) [C], the 608
/// family is sold as compatible with it [I], and the mk3's own bus driver sleeps the chip
/// after every read -- so on mk3 each read is a wake, and a seed write. Callgate 26 does
/// not say which mode it uses or whether it sleeps the chip [?], and the DS28C36's public
/// datasheet does not say whether its RNG touches EEPROM [?]. Until those are known, each
/// read is counted as one EEPROM write: 128 of them is 0.03% of the ATECC's rated 400,000
/// cycles and 0.13% of the DS28C36's 100,000. See docs/HARDWARE-OPEN-ITEMS.md.
///
/// Counted in calls, not bytes, because a call is what could wear: SE2 answers 8 bytes a
/// call and declines some calls, and a declined call may still have woken it.
pub const SE_CALLS_PER_SESSION: u16 = 128;

/// Reads of one secure element all paired sessions together may make per power-up.
pub const SE_CALLS_PER_BOOT: u16 = 256;

/// The secure elements' allowance: reads spent, per power-up and in the current session.
///
/// Two slots: SE1 (by the callgate or its own bus, the same chip) and SE2. Only the
/// paired transport spends it; the bench one is a bench build's own business.
#[derive(Copy, Clone, Debug)]
pub struct SeBudget {
    boot: [u16; 2],
    session: u32,
    in_session: [u16; 2],
}

impl Default for SeBudget {
    fn default() -> Self {
        Self::new()
    }
}

impl SeBudget {
    pub const fn new() -> Self {
        Self {
            boot: [0; 2],
            session: 0,
            in_session: [0; 2],
        }
    }

    fn enter(&mut self, id: u32) {
        if self.session != id {
            self.session = id;
            self.in_session = [0; 2];
        }
    }

    /// Reads session `id` may still make of slot `se` (0 SE1, 1 SE2), or the [`limit`]
    /// reason when none are left.
    pub fn allowance(&mut self, id: u32, se: usize) -> Result<u16, u8> {
        self.enter(id);
        let boot = SE_CALLS_PER_BOOT.saturating_sub(self.boot[se]);
        let session = SE_CALLS_PER_SESSION.saturating_sub(self.in_session[se]);
        match (boot, session) {
            (0, _) => Err(limit::BOOT),
            (_, 0) => Err(limit::SESSION),
            (b, s) => Ok(b.min(s)),
        }
    }

    /// Count `calls` reads made of slot `se` for session `id`. Counted whether or not the
    /// session is still there to collect them: the reads happened.
    pub fn spend(&mut self, id: u32, se: usize, calls: u16) {
        self.boot[se] = self.boot[se].saturating_add(calls);
        if self.session == id {
            self.in_session[se] = self.in_session[se].saturating_add(calls);
        }
    }
}

// --- the health report ---------------------------------------------------------------------

/// The health report's wire codes.
///
/// ```text
/// [u8 version=1][u8 pool flags][u8 hardware sources counted][u8 count]
/// then per source, 8 bytes:
///   [u8 source][u8 start-up][u8 failure][u8 last read][u16 tested][u16 trips]
/// ```
pub mod health {
    /// The report's layout version.
    pub const VERSION: u8 = 1;
    /// Bytes ahead of the sources.
    pub const HEAD: usize = 4;
    /// Bytes per source.
    pub const PER_SOURCE: usize = 8;

    /// The user interface has published a snapshot at all. Without it every other field
    /// is zero and means nothing: the device has not reached its menu since power-up.
    pub const PUBLISHED: u8 = 1 << 0;
    /// There is a boot entropy pool: it met its policy at power-up. Without one, no
    /// wallet can be made this session.
    pub const POOL: u8 = 1 << 1;
    /// The pool meets its policy now (enough credited bits from enough distinct hardware
    /// sources); whether a New wallet would be allowed to draw.
    pub const POLICY_MET: u8 = 1 << 2;
    /// The start-up test is enforced on this pool (a New wallet has run): a hardware
    /// source counts only once its start-up test has passed.
    pub const STARTUP_ENFORCED: u8 = 1 << 3;

    /// Start-up test: still collecting its window; `tested` bytes have passed.
    pub const PENDING: u8 = 0;
    /// Start-up test passed.
    pub const PASSED: u8 = 1;
    /// Start-up test failed: this source counts for nothing until power-off.
    pub const FAILED: u8 = 2;
    /// Not a source the pool health-tests (SE1's raw bus on mk3: mixed, credited zero).
    pub const UNTESTED: u8 = 3;

    /// Why a test tripped: nothing has.
    pub const NONE: u8 = 0;
    /// The repetition count test (a stuck source).
    pub const REPETITION: u8 = 1;
    /// The adaptive proportion test (one value far too common).
    pub const ADAPTIVE: u8 = 2;
    /// A whole read was one repeated value (all zero, all 0xff).
    pub const CONSTANT: u8 = 3;
    /// A read too short to test.
    pub const TOO_SHORT: u8 = 4;

    /// Last read: the pool has not read this source yet.
    pub const NOT_READ: u8 = 0;
    /// Last read passed the continuous tests.
    pub const OK: u8 = 1;
    /// Last read tripped a continuous test (and was credited nothing).
    pub const TRIPPED: u8 = 2;
}

/// One source's line in the health report. Every field is a verdict or a count of
/// verdicts, never a byte the source produced.
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub struct SourceHealth {
    pub source: u8,
    /// [`health::PENDING`], [`health::PASSED`], [`health::FAILED`] or
    /// [`health::UNTESTED`].
    pub startup: u8,
    /// What failed the start-up test, [`health::NONE`] if it has not failed.
    pub failure: u8,
    /// [`health::NOT_READ`], [`health::OK`] or [`health::TRIPPED`].
    pub last: u8,
    /// Bytes that have passed the start-up window so far (while pending), saturating.
    pub tested: u16,
    /// Reads that tripped a continuous test since power-up, saturating.
    pub trips: u16,
}

/// Most sources a board has.
pub const MAX_SOURCES: usize = 4;

/// The health report: what the pool says about its sources, and nothing of the pool.
#[derive(Copy, Clone, PartialEq, Eq, Debug, Default)]
pub struct Health {
    /// [`health::PUBLISHED`] and the pool bits.
    pub flags: u8,
    /// Distinct hardware sources the pool counts now.
    pub hw_sources: u8,
    pub count: u8,
    pub sources: [Option<SourceHealth>; MAX_SOURCES],
}

impl Health {
    /// Add a source's line; ignored past [`MAX_SOURCES`].
    pub fn push(&mut self, s: SourceHealth) {
        if let Some(slot) = self.sources.get_mut(self.count as usize) {
            *slot = Some(s);
            self.count += 1;
        }
    }

    /// Bytes [`encode`](Self::encode) needs at most.
    pub const MAX_LEN: usize = health::HEAD + MAX_SOURCES * health::PER_SOURCE;

    /// Write the report; returns its length. `out` must hold [`Self::MAX_LEN`].
    pub fn encode(&self, out: &mut [u8]) -> usize {
        out[0] = health::VERSION;
        out[1] = self.flags;
        out[2] = self.hw_sources;
        let mut n = health::HEAD;
        let mut count = 0u8;
        for s in self.sources.iter().flatten() {
            let o = &mut out[n..n + health::PER_SOURCE];
            o[0] = s.source;
            o[1] = s.startup;
            o[2] = s.failure;
            o[3] = s.last;
            o[4..6].copy_from_slice(&s.tested.to_le_bytes());
            o[6..8].copy_from_slice(&s.trips.to_le_bytes());
            n += health::PER_SOURCE;
            count += 1;
        }
        out[3] = count;
        n
    }

    /// Read a report back (hosts and tests).
    pub fn decode(b: &[u8]) -> Option<Self> {
        if b.len() < health::HEAD || b[0] != health::VERSION {
            return None;
        }
        let count = b[3] as usize;
        if count > MAX_SOURCES || b.len() != health::HEAD + count * health::PER_SOURCE {
            return None;
        }
        let mut h = Health {
            flags: b[1],
            hw_sources: b[2],
            ..Health::default()
        };
        for o in b[health::HEAD..].chunks_exact(health::PER_SOURCE) {
            h.push(SourceHealth {
                source: o[0],
                startup: o[1],
                failure: o[2],
                last: o[3],
                tested: u16::from_le_bytes([o[4], o[5]]),
                trips: u16::from_le_bytes([o[6], o[7]]),
            });
        }
        Some(h)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_request_is_list_or_one_bounded_chunk() {
        assert_eq!(parse_request(&[]), Ok(Request::List));
        assert_eq!(
            parse_request(&[2, 0x20, 0x00]),
            Ok(Request::Chunk {
                source: 2,
                len: 0x20
            })
        );
        let max = (CHUNK_MAX as u16).to_le_bytes();
        assert!(parse_request(&[1, max[0], max[1]]).is_ok());
        let over = (CHUNK_MAX as u16 + 1).to_le_bytes();
        assert_eq!(
            parse_request(&[1, over[0], over[1]]),
            Err(Status::BadRequest)
        );
        assert_eq!(parse_request(&[1, 0, 0]), Err(Status::BadRequest));
        assert_eq!(parse_request(&[1, 1]), Err(Status::BadRequest));
        assert_eq!(parse_request(&[1, 1, 0, 0]), Err(Status::BadRequest));
    }

    #[test]
    fn the_list_says_the_chunk_size_and_the_sources() {
        let mut out = [0u8; 8];
        let n = list_body(&[source::SE1, source::SE2, source::CHIP], &mut out);
        assert_eq!(&out[..n], &[0xC0, 0x01, 3, 2, 3, 1]);
    }

    #[test]
    fn a_chunk_fits_a_sealed_reply() {
        // 512-byte reply, less the inner status and the 16-byte tag.
        assert!(REPLY_LEN <= 512 - 2 - crate::ncry::TAG_LEN);
    }

    #[test]
    fn a_chunk_header_round_trips_and_checks_its_length() {
        let c = Chunk {
            source: source::SE2,
            flags: flags::SHORT | flags::LIMIT,
            n: 5,
            number: 0x0102_0304,
        };
        let mut body = [0u8; HEADER + 5];
        c.write(&mut body);
        assert_eq!(&body[..HEADER], &[3, 5, 5, 0, 4, 3, 2, 1]);
        assert_eq!(Chunk::read(&body), Some(c));
        assert_eq!(Chunk::read(&body[..HEADER + 4]), None, "data cut short");
        assert_eq!(Chunk::read(&body[..4]), None);
    }

    #[test]
    fn the_person_is_asked_once_per_session() {
        let mut g = ConsentGate::new();
        assert_eq!(g.to_ask(), None);
        assert_eq!(g.request(7), Consent::Asking);
        assert_eq!(g.to_ask(), Some(7));
        // Asking again does not ask twice.
        assert_eq!(g.request(7), Consent::Asking);
        assert!(g.answer(7, true));
        assert_eq!(g.to_ask(), None);
        assert_eq!(g.request(7), Consent::Granted);
        assert_eq!(g.request(7), Consent::Granted);
    }

    #[test]
    fn a_refusal_holds_for_the_rest_of_the_session() {
        let mut g = ConsentGate::new();
        g.request(3);
        assert!(g.answer(3, false));
        for _ in 0..3 {
            assert_eq!(g.request(3), Consent::Refused);
        }
        assert_eq!(g.to_ask(), None, "never asked again in that session");
    }

    #[test]
    fn a_new_session_is_asked_afresh() {
        let mut g = ConsentGate::new();
        g.request(1);
        g.answer(1, true);
        // Unplug, pair again: a new session number.
        assert_eq!(g.request(2), Consent::Asking);
        g.answer(2, false);
        assert_eq!(g.request(3), Consent::Asking);
        // And an explicit end forgets too.
        g.answer(3, true);
        g.end();
        assert_eq!(g.request(3), Consent::Asking);
    }

    #[test]
    fn an_answer_for_a_gone_session_is_not_taken() {
        let mut g = ConsentGate::new();
        g.request(4);
        g.end();
        assert!(!g.still_asking(4), "the screen takes the question down");
        assert!(!g.answer(4, true));
        assert_eq!(g.request(5), Consent::Asking);
        assert!(!g.answer(4, true), "an old session's answer");
        assert!(g.still_asking(5));
    }

    #[test]
    fn session_zero_is_never_granted() {
        let mut g = ConsentGate::new();
        assert_eq!(g.request(0), Consent::Refused);
        assert_eq!(g.to_ask(), None);
    }

    #[test]
    fn the_allowance_runs_out_per_session_then_per_boot() {
        let mut b = SeBudget::new();
        assert_eq!(b.allowance(1, 0), Ok(SE_CALLS_PER_SESSION));
        b.spend(1, 0, SE_CALLS_PER_SESSION);
        assert_eq!(b.allowance(1, 0), Err(limit::SESSION));
        // The other secure element has its own.
        assert_eq!(b.allowance(1, 1), Ok(SE_CALLS_PER_SESSION));
        // A new session starts a new session allowance, within the boot's.
        assert_eq!(
            b.allowance(2, 0),
            Ok(SE_CALLS_PER_SESSION.min(SE_CALLS_PER_BOOT - SE_CALLS_PER_SESSION))
        );
        b.spend(2, 0, SE_CALLS_PER_BOOT - SE_CALLS_PER_SESSION);
        assert_eq!(b.allowance(3, 0), Err(limit::BOOT));
        assert_eq!(b.allowance(3, 1), Ok(SE_CALLS_PER_SESSION));
    }

    #[test]
    fn reads_for_a_session_that_went_away_still_count_for_the_boot() {
        let mut b = SeBudget::new();
        b.allowance(1, 1).unwrap();
        b.allowance(2, 1).unwrap();
        b.spend(1, 1, 10);
        assert_eq!(b.allowance(2, 1), Ok(SE_CALLS_PER_SESSION));
        b.spend(2, 1, SE_CALLS_PER_BOOT - 10);
        assert_eq!(b.allowance(2, 1), Err(limit::BOOT));
    }

    #[test]
    fn the_health_report_round_trips() {
        let mut h = Health {
            flags: health::PUBLISHED | health::POOL | health::POLICY_MET,
            hw_sources: 2,
            ..Health::default()
        };
        h.push(SourceHealth {
            source: source::CHIP,
            startup: health::PASSED,
            failure: health::NONE,
            last: health::OK,
            tested: 1024,
            trips: 0,
        });
        h.push(SourceHealth {
            source: source::SE2,
            startup: health::FAILED,
            failure: health::REPETITION,
            last: health::TRIPPED,
            tested: 96,
            trips: 3,
        });
        let mut out = [0u8; Health::MAX_LEN];
        let n = h.encode(&mut out);
        assert_eq!(n, health::HEAD + 2 * health::PER_SOURCE);
        assert_eq!(&out[..4], &[1, 0b0111, 2, 2]);
        assert_eq!(&out[4..12], &[1, 1, 0, 1, 0x00, 0x04, 0, 0]);
        assert_eq!(Health::decode(&out[..n]), Some(h));
        assert_eq!(Health::decode(&out[..n - 1]), None);
    }

    #[test]
    fn a_report_holds_at_most_four_sources() {
        let mut h = Health::default();
        let s = SourceHealth {
            source: 1,
            startup: 0,
            failure: 0,
            last: 0,
            tested: 0,
            trips: 0,
        };
        for _ in 0..6 {
            h.push(s);
        }
        assert_eq!(h.count as usize, MAX_SOURCES);
        let mut out = [0u8; Health::MAX_LEN];
        assert_eq!(h.encode(&mut out), Health::MAX_LEN);
    }
}
