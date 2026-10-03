//! One protocol message on the wire: the envelope, and the file it travels in.
//!
//! ```text
//!  off  len  field
//!    0    4  magic "CTSm"
//!    4    1  format version (3)
//!    5    1  protocol: 1 create together (keygen), 2 sign
//!    6    8  session id
//!   14    1  round (0 = commitments, 1 = identities)
//!   15    1  from: member number, 1..=n
//!   16    1  to: member number, or 0 for everyone
//!   17    4  payload length, little-endian
//!   21    L  payload
//! 21+L   64  signature: ECDSA secp256k1, r || s, low-S, by the sender's session key
//! ```
//!
//! The format is ours (docs/TSS.md, "Members, sessions, messages"); nothing outside
//! CatCard reads it. Every field before the signature is signed, and so is the
//! session's *roster digest* -- which is not sent: both ends compute it from the
//! identity keys of rounds 0 and 1, so a message only verifies inside the exact group
//! whose code the user compared. Rounds 0 and 1 are signed with the sender's identity
//! key over a roster digest of zeros (there is no roster yet): round 1 carries the key,
//! and the round-0 signature is checked once it has arrived.
//!
//! Payloads:
//!
//! - round 0: the sender's commitment to its identity key, 32 bytes (`crate::code`);
//! - round 1: the sender's compressed identity public key, 33 bytes, then the 32
//!   random bytes that open its commitment;
//! - later rounds: a count, then per tsslib message its instance, type code and
//!   payload in tsslib's binary encoding (`tsslib::wire`). Addressed to one member (`to != 0`), the payload is
//!   encrypted to that member first (see `crate::identity`): a DKG's round-1 unicasts
//!   are Shamir shares, and an SD card is read by whoever holds it.

use alloc::format;
use alloc::string::String;
use alloc::vec::Vec;
use purecrypto::hash::{Digest, Sha256};

/// First four bytes of every envelope.
pub const MAGIC: [u8; 4] = *b"CTSm";
/// The envelope format this crate writes and reads. 2: round 0 split into commitments
/// (round 0) and identities (round 1), protocol rounds from 2. 3: tsslib's messages in
/// its binary encoding rather than re-encoded JSON. Older versions were never deployed
/// and are refused ([`Refused::Version`]).
pub const VERSION: u8 = 3;
/// The round of identity commitments.
pub const COMMIT_ROUND: u8 = 0;
/// The round that opens the commitments: identity keys.
pub const REVEAL_ROUND: u8 = 1;
/// The first round of the protocol proper, after the session code is confirmed.
pub const FIRST_PROTOCOL_ROUND: u8 = 2;
/// Bytes before the payload.
pub const HEADER_LEN: usize = 21;
/// The trailing signature.
pub const SIG_LEN: usize = 64;
/// A session id.
pub const SESSION_ID_LEN: usize = 8;
/// Largest payload accepted. A 9-member signing round of 16 inputs stays far below it;
/// it only bounds what a corrupt length field can ask for.
pub const MAX_PAYLOAD: usize = 4 << 20;

/// Domain separation for the signed digest.
const SIGN_DOMAIN: &[u8] = b"CatCard TSS message v1\0";

/// Which protocol a session runs.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum Protocol {
    /// Create together: DKLs23 distributed key generation.
    Keygen = 1,
    /// Sign: DKLs23 threshold ECDSA.
    Sign = 2,
}

impl Protocol {
    fn from_byte(b: u8) -> Option<Self> {
        match b {
            1 => Some(Protocol::Keygen),
            2 => Some(Protocol::Sign),
            _ => None,
        }
    }
}

/// Why a message was not taken. None of these change the session: the same bytes can
/// be offered again (and refused again), and the right message is still accepted.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum Refused {
    /// Not an envelope, cut short, or with trailing bytes.
    Malformed,
    /// An envelope of a format version this build does not read.
    Version,
    /// Another protocol than this session's.
    WrongProtocol,
    /// Another session's id.
    WrongSession,
    /// The sender is not a member of this session.
    UnknownMember,
    /// Sent by this member: a reflected copy of our own message.
    FromSelf,
    /// Addressed to another member.
    NotForMe,
    /// A round this protocol does not have.
    BadRound,
    /// No signature.
    Unsigned,
    /// A signature that does not verify under the sender's session key -- signed by
    /// someone else, for another group, or altered.
    BadSignature,
    /// A unicast that does not decrypt for this member.
    Undecryptable,
    /// Already received: one message per round, sender and recipient.
    Replayed,
    /// Too soon: an identity (round 1) before every member's commitment is in, or a
    /// protocol round before the session code was confirmed. Not held: offer it again
    /// once [`crate::Session::awaiting`] asks for it.
    Early,
    /// A payload that names a message type, instance or direction this round has none of.
    UnexpectedContent,
    /// An identity that does not open the commitment its sender made in round 0: a key
    /// substituted after the commitments were seen. Its sender's commitment stays, so
    /// only the key it committed to can still be taken.
    CommitmentMismatch,
}

/// The parsed fixed part of an envelope.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct Header {
    pub protocol: Protocol,
    pub session: [u8; SESSION_ID_LEN],
    pub round: u8,
    pub from: u8,
    pub to: u8,
}

/// A parsed envelope, borrowing its bytes.
pub struct Envelope<'a> {
    pub header: Header,
    pub payload: &'a [u8],
    /// `None` when the envelope ends after its payload.
    pub signature: Option<&'a [u8; SIG_LEN]>,
    /// Header and payload: what the signature covers, with the roster digest.
    pub signed: &'a [u8],
}

impl<'a> Envelope<'a> {
    /// Parse the framing. Says nothing yet about who sent it.
    pub fn parse(bytes: &'a [u8]) -> Result<Self, Refused> {
        if bytes.len() < HEADER_LEN || bytes[..4] != MAGIC {
            return Err(Refused::Malformed);
        }
        if bytes[4] != VERSION {
            return Err(Refused::Version);
        }
        let protocol = Protocol::from_byte(bytes[5]).ok_or(Refused::Malformed)?;
        let mut session = [0u8; SESSION_ID_LEN];
        session.copy_from_slice(&bytes[6..14]);
        let len = u32::from_le_bytes([bytes[17], bytes[18], bytes[19], bytes[20]]) as usize;
        if len > MAX_PAYLOAD {
            return Err(Refused::Malformed);
        }
        let end = HEADER_LEN + len;
        let signature = match bytes.len().checked_sub(end) {
            Some(0) => None,
            Some(SIG_LEN) => Some(bytes[end..].try_into().map_err(|_| Refused::Malformed)?),
            _ => return Err(Refused::Malformed),
        };
        Ok(Envelope {
            header: Header {
                protocol,
                session,
                round: bytes[14],
                from: bytes[15],
                to: bytes[16],
            },
            payload: &bytes[HEADER_LEN..end],
            signature,
            signed: &bytes[..end],
        })
    }
}

/// Header and payload, unsigned: the caller appends the signature.
pub(crate) fn frame(h: &Header, payload: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(HEADER_LEN + payload.len() + SIG_LEN);
    out.extend_from_slice(&MAGIC);
    out.push(VERSION);
    out.push(h.protocol as u8);
    out.extend_from_slice(&h.session);
    out.push(h.round);
    out.push(h.from);
    out.push(h.to);
    out.extend_from_slice(&(payload.len() as u32).to_le_bytes());
    out.extend_from_slice(payload);
    out
}

/// The digest a signature covers.
pub(crate) fn signed_digest(roster: &[u8; 32], signed: &[u8]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(SIGN_DOMAIN);
    h.update(roster);
    h.update(signed);
    h.finalize()
}

/// The file a message travels in: `r<round>-<from>-<to>.msg`, `to` 0 for a broadcast.
/// Source: docs/TSS.md "Members, sessions, messages".
pub fn file_name(round: u8, from: u8, to: u8) -> String {
    format!("r{round}-{from}-{to}.msg")
}

/// `(round, from, to)` from a name [`file_name`] wrote; `None` for anything else.
pub fn parse_file_name(name: &str) -> Option<(u8, u8, u8)> {
    let rest = name.strip_prefix('r')?.strip_suffix(".msg")?;
    let mut parts = rest.split('-');
    let mut num = || -> Option<u8> {
        let p = parts.next()?;
        // Only the form file_name writes: no sign, no leading zero.
        if p.is_empty()
            || (p.len() > 1 && p.starts_with('0'))
            || !p.bytes().all(|c| c.is_ascii_digit())
        {
            return None;
        }
        p.parse().ok()
    };
    let r = (num()?, num()?, num()?);
    parts.next().is_none().then_some(r)
}

/// The session's directory on a card: `TSS/<session id in hex>`.
pub fn session_dir(session: &[u8; SESSION_ID_LEN]) -> String {
    let mut s = String::from("TSS/");
    for b in session {
        s.push_str(&format!("{b:02x}"));
    }
    s
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn file_names_round_trip_and_nothing_else_parses() {
        assert_eq!(file_name(2, 1, 0), "r2-1-0.msg");
        assert_eq!(parse_file_name("r2-1-0.msg"), Some((2, 1, 0)));
        assert_eq!(parse_file_name("r12-9-3.msg"), Some((12, 9, 3)));
        for bad in [
            "r2-1.msg",
            "r2-1-0-4.msg",
            "r2-01-0.msg",
            "r-1-0.msg",
            "r2-1-0.txt",
            "x2-1-0.msg",
            "r2-+1-0.msg",
            "r256-1-0.msg",
        ] {
            assert_eq!(parse_file_name(bad), None, "{bad}");
        }
    }

    #[test]
    fn session_dir_is_hex() {
        assert_eq!(
            session_dir(&[0, 1, 0xab, 3, 4, 5, 6, 0xff]),
            "TSS/0001ab03040506ff"
        );
    }

    #[test]
    fn framing_is_checked_before_anything_else() {
        let h = Header {
            protocol: Protocol::Sign,
            session: [7; 8],
            round: 3,
            from: 2,
            to: 1,
        };
        let mut bytes = frame(&h, b"payload");
        let e = Envelope::parse(&bytes).unwrap();
        assert_eq!(e.header, h);
        assert!(e.signature.is_none());
        bytes.extend_from_slice(&[0; SIG_LEN]);
        assert!(Envelope::parse(&bytes).unwrap().signature.is_some());
        bytes.push(0);
        assert_eq!(Envelope::parse(&bytes).err(), Some(Refused::Malformed));
        for other in [1, 2, 4] {
            let mut v = frame(&h, b"");
            v[4] = other;
            assert_eq!(Envelope::parse(&v).err(), Some(Refused::Version));
        }
    }
}
