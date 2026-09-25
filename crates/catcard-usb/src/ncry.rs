//! `ncry` — an encrypted channel negotiated over the plaintext transport.
//!
//! The framing in the crate root moves messages in the clear. Anything a passive
//! observer on the wire should not see — an `xpub`, an address, a PSBT, the log —
//! travels instead inside an [`Opcode::NcryMsg`](crate::Opcode::NcryMsg) once a session
//! has been set up.
//!
//! # Handshake
//!
//! One round trip, ephemeral on both sides — the Noise `NN` shape:
//!
//! ```text
//! host   → device   NcryStart, payload = host ephemeral X25519 public key (32 B)
//! device → host     Ok,        payload = device ephemeral X25519 public key (32 B)
//! ```
//!
//! Each side computes the same X25519 shared secret and runs it through HKDF-SHA256 to
//! two directional keys. The device's ephemeral scalar comes from the HMAC-DRBG, never
//! from the raw entropy pool and never from anything key-derived, so a session key can
//! be neither predicted nor traced to a seed.
//!
//! # What this does and does not defend
//!
//! Both keys are ephemeral and neither party is authenticated, so this stops a **passive**
//! eavesdropper — a USB analyser, a logging hub — from reading the protocol. It does
//! **not** stop an **active** man-in-the-middle that relays the handshake and mounts its
//! own to each side: with no static identity to bind, the two sides cannot tell a relay
//! from the wire. Adding device authentication (a static device key and an on-screen
//! session fingerprint) is a later, version-bumped step; the `info` string carries the
//! version so an authenticated `v2` cannot be confused for this one.
//!
//! # Records
//!
//! After the handshake, each direction is a ChaCha20-Poly1305 stream keyed separately,
//! with a per-direction message counter as the nonce. A counter is used once and never
//! reused; the receiver derives the nonce from the count it expects next, so a replayed
//! or reordered record authenticates against the wrong nonce and is rejected. The
//! transport is reliable request/response, so there is no window to track — the next
//! record is the only acceptable one.
//!
//! The bulk firmware-upgrade path is deliberately left in the clear: the image is a
//! public, signed blob whose integrity the signature already guarantees, and it is the
//! one message that streams to staging without being buffered whole, which a per-message
//! seal would break.

use purecrypto::cipher::ChaCha20Poly1305;
use purecrypto::ec::X25519PrivateKey;
use purecrypto::hash::Sha256;
use purecrypto::kdf::hkdf;
use zeroize::Zeroize;

/// Length of an X25519 public key, and of an ephemeral scalar.
pub const KEY_LEN: usize = 32;
/// Length of the Poly1305 authentication tag a sealed record carries.
pub const TAG_LEN: usize = 16;

/// Bytes added to a plaintext when it is sealed: the authentication tag.
pub const OVERHEAD: usize = TAG_LEN;

/// Domain separation for the key schedule. Bump the version suffix for any change that a
/// peer speaking the old scheme would get wrong — a different curve, KDF, cipher, or an
/// authenticated handshake — so the two cannot derive a matching key by accident.
const INFO: &[u8] = b"catcard-ncry-v1";

/// Why a channel operation could not be completed.
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub enum Error {
    /// The peer's public key is a small-order point (its shared secret is the canonical
    /// zero). Rejected as RFC 7748 §6.1 permits and RFC 8446 §7.4.2 requires, rather than
    /// keying a channel off a value the peer could have forced.
    SmallOrderPeer,
    /// A record failed authentication: a wrong key, a corrupted or tampered record, or a
    /// replay or reorder (whose nonce is not the one expected next).
    BadTag,
    /// The direction's message counter is exhausted. Unreachable in practice — it is a
    /// 64-bit count — but a wrapped counter would reuse a nonce, so it is refused instead.
    Exhausted,
}

/// The nonce for message `counter` on one direction: the count little-endian in the low
/// eight bytes, the top four zero. Each direction has its own key, so both may start at
/// zero without ever sharing a (key, nonce) pair.
fn nonce(counter: u64) -> [u8; 12] {
    let mut n = [0u8; 12];
    n[..8].copy_from_slice(&counter.to_le_bytes());
    n
}

/// Derive the two directional keys from the shared secret, bound to both public keys so
/// the schedule commits to the exact handshake that produced it.
///
/// Returns `(initiator→responder, responder→initiator)`. The transcript is always the
/// initiator's key first, whichever side is deriving.
fn derive(
    dh: &[u8; KEY_LEN],
    initiator_pub: &[u8; KEY_LEN],
    responder_pub: &[u8; KEY_LEN],
) -> ([u8; 32], [u8; 32]) {
    let mut transcript = [0u8; 2 * KEY_LEN];
    transcript[..KEY_LEN].copy_from_slice(initiator_pub);
    transcript[KEY_LEN..].copy_from_slice(responder_pub);

    let mut okm = [0u8; 64];
    hkdf::<Sha256>(&transcript, dh, INFO, &mut okm);

    let mut i2r = [0u8; 32];
    let mut r2i = [0u8; 32];
    i2r.copy_from_slice(&okm[..32]);
    r2i.copy_from_slice(&okm[32..]);
    okm.zeroize();
    (i2r, r2i)
}

/// An established channel: one key and message counter per direction.
///
/// The keys are wiped on drop. There is no `Clone`: a copied counter would seal two
/// records under one nonce.
pub struct Session {
    send_key: [u8; 32],
    recv_key: [u8; 32],
    send_ctr: u64,
    recv_ctr: u64,
}

impl Drop for Session {
    fn drop(&mut self) {
        self.send_key.zeroize();
        self.recv_key.zeroize();
    }
}

impl Session {
    /// The device side of the handshake.
    ///
    /// `eph_priv` is a fresh ephemeral scalar from the HMAC-DRBG; `initiator_pub` is the
    /// host's ephemeral public key from the `NcryStart` payload. Returns the device's
    /// ephemeral public key to send back, and the session to keep.
    pub fn responder(
        eph_priv: &[u8; KEY_LEN],
        initiator_pub: &[u8; KEY_LEN],
    ) -> Result<([u8; KEY_LEN], Self), Error> {
        let sk = X25519PrivateKey::from_bytes(*eph_priv);
        let responder_pub = sk.public_key();
        let mut dh = sk
            .diffie_hellman(initiator_pub)
            .map_err(|_| Error::SmallOrderPeer)?;
        let (i2r, r2i) = derive(&dh, initiator_pub, &responder_pub);
        dh.zeroize();
        // The device receives on initiator→responder and sends on responder→initiator.
        Ok((
            responder_pub,
            Session {
                send_key: r2i,
                recv_key: i2r,
                send_ctr: 0,
                recv_ctr: 0,
            },
        ))
    }

    /// The host side of the handshake.
    ///
    /// `eph_priv` is the host's ephemeral scalar (whose public key it already sent);
    /// `responder_pub` is the device's ephemeral public key from the reply.
    pub fn initiator(
        eph_priv: &[u8; KEY_LEN],
        responder_pub: &[u8; KEY_LEN],
    ) -> Result<Self, Error> {
        let sk = X25519PrivateKey::from_bytes(*eph_priv);
        let initiator_pub = sk.public_key();
        let mut dh = sk
            .diffie_hellman(responder_pub)
            .map_err(|_| Error::SmallOrderPeer)?;
        let (i2r, r2i) = derive(&dh, &initiator_pub, responder_pub);
        dh.zeroize();
        // The host sends on initiator→responder and receives on responder→initiator.
        Ok(Session {
            send_key: i2r,
            recv_key: r2i,
            send_ctr: 0,
            recv_ctr: 0,
        })
    }

    /// Seal `buf` in place under the next send nonce and return the tag to append.
    ///
    /// The wire record is `buf` (now ciphertext) followed by the returned [`TAG_LEN`]
    /// bytes. Advances the send counter only on success.
    pub fn seal(&mut self, buf: &mut [u8]) -> Result<[u8; TAG_LEN], Error> {
        if self.send_ctr == u64::MAX {
            return Err(Error::Exhausted);
        }
        let aead = ChaCha20Poly1305::new(&self.send_key);
        let tag = aead.encrypt(&nonce(self.send_ctr), &[], buf);
        self.send_ctr += 1;
        Ok(tag)
    }

    /// Open a record in place: verify `tag` against the next receive nonce and, only if
    /// it matches, decrypt `buf`. On any failure `buf` is left as ciphertext and the
    /// receive counter does not advance, so a caller that drops the session on error
    /// never confuses a forged record for a gap.
    pub fn open(&mut self, buf: &mut [u8], tag: &[u8; TAG_LEN]) -> Result<(), Error> {
        if self.recv_ctr == u64::MAX {
            return Err(Error::Exhausted);
        }
        let aead = ChaCha20Poly1305::new(&self.recv_key);
        aead.decrypt(&nonce(self.recv_ctr), &[], buf, tag)
            .map_err(|_| Error::BadTag)?;
        self.recv_ctr += 1;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Two fixed ephemeral scalars, so the handshake is reproducible and a host
    // implementation can be checked against the same vector.
    const HOST_PRIV: [u8; 32] = [
        0x77, 0x07, 0x6d, 0x0a, 0x73, 0x18, 0xa5, 0x7d, 0x3c, 0x16, 0xc1, 0x72, 0x51, 0xb2, 0x66,
        0x45, 0xdf, 0x4c, 0x2f, 0x87, 0xeb, 0xc0, 0x99, 0x2a, 0xb1, 0x77, 0xfb, 0xa5, 0x1d, 0xb9,
        0x2c, 0x2a,
    ];
    const DEV_PRIV: [u8; 32] = [
        0x5d, 0xab, 0x08, 0x7e, 0x62, 0x4a, 0x8a, 0x4b, 0x79, 0xe1, 0x7f, 0x8b, 0x83, 0x80, 0x0e,
        0xe6, 0x6f, 0x3b, 0xb1, 0x29, 0x26, 0x18, 0xb6, 0xfd, 0x1c, 0x2f, 0x8b, 0x27, 0xff, 0x88,
        0xe0, 0xeb,
    ];

    /// Run the handshake both sides and return (host, device) sessions.
    fn pair() -> (Session, Session) {
        let host_pub = X25519PrivateKey::from_bytes(HOST_PRIV).public_key();
        let (dev_pub, device) = Session::responder(&DEV_PRIV, &host_pub).unwrap();
        let host = Session::initiator(&HOST_PRIV, &dev_pub).unwrap();
        (host, device)
    }

    #[test]
    fn directions_agree_and_round_trip() {
        let (mut host, mut device) = pair();

        // host → device
        let mut buf = *b"xpub-secret-payload";
        let plain = buf;
        let tag = host.seal(&mut buf).unwrap();
        assert_ne!(buf, plain, "ciphertext must differ from plaintext");
        device.open(&mut buf, &tag).unwrap();
        assert_eq!(buf, plain);

        // device → host
        let mut reply = *b"here-is-your-address";
        let reply_plain = reply;
        let tag = device.seal(&mut reply).unwrap();
        host.open(&mut reply, &tag).unwrap();
        assert_eq!(reply, reply_plain);
    }

    #[test]
    fn the_two_directions_use_different_keys() {
        let (host, _device) = pair();
        assert_ne!(host.send_key, host.recv_key);
    }

    #[test]
    fn a_flipped_ciphertext_byte_is_rejected() {
        let (mut host, mut device) = pair();
        let mut buf = *b"sensitive";
        let tag = host.seal(&mut buf).unwrap();
        buf[0] ^= 1;
        assert_eq!(device.open(&mut buf, &tag), Err(Error::BadTag));
    }

    #[test]
    fn a_flipped_tag_bit_is_rejected() {
        let (mut host, mut device) = pair();
        let mut buf = *b"sensitive";
        let mut tag = host.seal(&mut buf).unwrap();
        tag[0] ^= 1;
        assert_eq!(device.open(&mut buf, &tag), Err(Error::BadTag));
    }

    #[test]
    fn a_replayed_record_is_rejected() {
        let (mut host, mut device) = pair();

        let mut first = *b"record-zero";
        let saved = first;
        let first_tag = host.seal(&mut first).unwrap();
        device.open(&mut first, &first_tag).unwrap();

        // A second, distinct record advances the device's expected counter.
        let mut second = *b"record-one!";
        let second_tag = host.seal(&mut second).unwrap();
        device.open(&mut second, &second_tag).unwrap();

        // Replaying record zero now authenticates against counter 2's nonce: rejected.
        let mut replay = saved;
        let _ = host; // counters on the host are irrelevant to the replay
        assert_eq!(device.open(&mut replay, &first_tag), Err(Error::BadTag));
    }

    #[test]
    fn a_reordered_record_is_rejected() {
        let (mut host, mut device) = pair();
        let mut a = *b"first-first";
        let ta = host.seal(&mut a).unwrap();
        let mut b = *b"then-secnd!";
        let tb = host.seal(&mut b).unwrap();
        // Deliver the second record first: its nonce (1) is not the one expected (0).
        assert_eq!(device.open(&mut b, &tb), Err(Error::BadTag));
        // The in-order first record still opens.
        device.open(&mut a, &ta).unwrap();
    }

    #[test]
    fn a_small_order_peer_key_is_rejected() {
        // The all-zero u-coordinate is small-order; its shared secret is canonical zero.
        let zero = [0u8; 32];
        assert_eq!(
            Session::responder(&DEV_PRIV, &zero).err(),
            Some(Error::SmallOrderPeer)
        );
        assert_eq!(
            Session::initiator(&HOST_PRIV, &zero).err(),
            Some(Error::SmallOrderPeer)
        );
    }

    #[test]
    fn an_empty_payload_still_authenticates() {
        let (mut host, mut device) = pair();
        let mut empty: [u8; 0] = [];
        let tag = host.seal(&mut empty).unwrap();
        device.open(&mut empty, &tag).unwrap();
        // A wrong tag on an empty record is still caught.
        let mut bad = tag;
        bad[0] ^= 1;
        assert_eq!(device.open(&mut [], &bad), Err(Error::BadTag));
    }

    // A cross-implementation known-answer test. The host tool derives the same key
    // schedule from the same two scalars; sealing counter-0 record `b"catcard"` with an
    // empty AAD must produce exactly these bytes on both sides. If this vector ever
    // changes, the host and firmware have diverged.
    #[test]
    fn known_answer_pins_the_wire_format() {
        let (mut host, _device) = pair();
        let mut buf = *b"catcard";
        let tag = host.seal(&mut buf).unwrap();
        // Pinned from this implementation; the Python host is checked against the same.
        assert_eq!(
            buf.len() + tag.len(),
            7 + TAG_LEN,
            "record is plaintext length plus one tag"
        );
        // Record the produced bytes so a divergence is a visible diff, not a silent
        // interop break. (Value asserted below is filled in from a first run.)
        let mut record = [0u8; 7 + TAG_LEN];
        record[..7].copy_from_slice(&buf);
        record[7..].copy_from_slice(&tag);
        assert_eq!(record, KAT_RECORD);
    }

    // Counter-0 seal of b"catcard" host→device under the fixed scalars above: the seven
    // ciphertext bytes followed by the sixteen-byte tag. The Python host derives the same
    // schedule and must reproduce these exact bytes.
    const KAT_RECORD: [u8; 7 + TAG_LEN] = [
        247, 67, 233, 137, 162, 231, 77, 87, 146, 173, 195, 250, 120, 56, 89, 36, 225, 153, 102,
        171, 8, 87, 85,
    ];
}
