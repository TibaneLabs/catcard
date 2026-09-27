//! The two DER structures a security key hands out: an ECDSA signature, and the
//! self-signed X.509 certificate a U2F registration carries.
//!
//! Both are fixed shapes built into a caller's buffer, so there is no general DER
//! encoder here -- only the few tags these need, with every length computed from what is
//! actually written. Sources: ITU-T X.690 §8.1-8.3, §10 (DER) [C]; RFC 5280 §4.1
//! (certificate) [C]; RFC 5758 §3.2 (ecdsa-with-SHA256, parameters absent) [C]; RFC 5480
//! §2.1 (id-ecPublicKey, prime256v1) [C]; SEC 1 v2 §C.5 (`ECDSA-Sig-Value`) [C].

/// The longest [`signature`]: two 33-byte INTEGERs and their headers.
pub const SIG_MAX: usize = 2 + 2 * (2 + 33);

/// `SEQUENCE { INTEGER r, INTEGER s }`, the signature form WebAuthn's `packed` statement
/// and U2F both carry. Returns the length written.
pub fn signature(r: &[u8; 32], s: &[u8; 32], out: &mut [u8; SIG_MAX]) -> usize {
    let mut at = 2;
    for v in [r, s] {
        at += integer(v, &mut out[at..]);
    }
    out[0] = 0x30;
    out[1] = (at - 2) as u8;
    at
}

/// An unsigned big-endian value as a DER INTEGER: leading zero bytes dropped, one put
/// back if the top bit would otherwise read as a sign. At most 35 bytes for 32 in.
fn integer(v: &[u8; 32], out: &mut [u8]) -> usize {
    let first = v.iter().position(|&b| b != 0).unwrap_or(31);
    let body = &v[first..];
    let pad = (body[0] & 0x80 != 0) as usize;
    out[0] = 0x02;
    out[1] = (body.len() + pad) as u8;
    out[2] = 0;
    out[2 + pad..2 + pad + body.len()].copy_from_slice(body);
    2 + pad + body.len()
}

/// A DER length.
fn length(n: usize, out: &mut [u8]) -> usize {
    if n < 0x80 {
        out[0] = n as u8;
        1
    } else if n <= 0xFF {
        out[0] = 0x81;
        out[1] = n as u8;
        2
    } else {
        out[0] = 0x82;
        out[1] = (n >> 8) as u8;
        out[2] = n as u8;
        3
    }
}

/// `ecdsa-with-SHA256`, parameters absent. Source: RFC 5758 §3.2 [C]
const ALG_ES256: [u8; 12] = [
    0x30, 0x0A, 0x06, 0x08, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x04, 0x03, 0x02,
];

/// `CN=CatCard FIDO`, as issuer and subject alike.
const NAME: [u8; 25] = [
    0x30, 0x17, 0x31, 0x15, 0x30, 0x13, 0x06, 0x03, 0x55, 0x04, 0x03, 0x0C, 0x0C, b'C', b'a', b't',
    b'C', b'a', b'r', b'd', b' ', b'F', b'I', b'D', b'O',
];

/// 2000-01-01 00:00:00 UTC to "no well-defined expiration".
/// Source: RFC 5280 §4.1.2.5 -- `99991231235959Z` as GeneralizedTime [C]
const VALIDITY: [u8; 34] = [
    0x30, 0x20, // SEQUENCE
    0x17, 0x0D, b'0', b'0', b'0', b'1', b'0', b'1', b'0', b'0', b'0', b'0', b'0', b'0', b'Z', 0x18,
    0x0F, b'9', b'9', b'9', b'9', b'1', b'2', b'3', b'1', b'2', b'3', b'5', b'9', b'5', b'9', b'Z',
];

/// `SubjectPublicKeyInfo` up to the point bytes: id-ecPublicKey, prime256v1, and the
/// BIT STRING header for a 65-byte uncompressed point. Source: RFC 5480 §2.1.1, §2.2 [C]
const SPKI_HEAD: [u8; 26] = [
    0x30, 0x59, 0x30, 0x13, 0x06, 0x07, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x02, 0x01, 0x06, 0x08, 0x2A,
    0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07, 0x03, 0x42, 0x00,
];

/// The to-be-signed part's size: serial, algorithm, issuer, validity, subject, key.
const TBS_BODY: usize =
    10 + ALG_ES256.len() + NAME.len() + VALIDITY.len() + NAME.len() + SPKI_HEAD.len() + 65;
/// With its SEQUENCE header (`30 81 xx`).
pub const TBS_LEN: usize = 3 + TBS_BODY;
const _: () = assert!(TBS_BODY > 0x7F && TBS_BODY <= 0xFF);

/// The longest [`certificate`].
pub const CERT_MAX: usize = 4 + TBS_LEN + ALG_ES256.len() + 3 + SIG_MAX;

/// The to-be-signed certificate for `public` (an uncompressed SEC 1 point) and an
/// 8-byte `serial`, which the caller makes unpredictable. Returns the bytes to sign.
///
/// A version-1 certificate -- no extensions, nothing to identify the device -- whose
/// issuer and subject are both `CN=CatCard FIDO`. It exists because U2F registration
/// requires *a* certificate, not because it attests to anything: each registration's is
/// self-signed by that registration's own key, so two sites, or two registrations at
/// one site, cannot be linked through it.
pub fn tbs(public: &[u8; 65], serial: &[u8; 8]) -> [u8; TBS_LEN] {
    let mut t = [0u8; TBS_LEN];
    t[0] = 0x30;
    t[1] = 0x81;
    t[2] = TBS_BODY as u8;
    let mut at = 3;
    // serialNumber: eight bytes, positive and minimal -- the top bit clear and the next
    // set, so no DER rule about leading bytes can bite. [C] X.690 §8.3.2
    t[at] = 0x02;
    t[at + 1] = 8;
    t[at + 2..at + 10].copy_from_slice(serial);
    t[at + 2] = (t[at + 2] & 0x3F) | 0x40;
    at += 10;
    for part in [&ALG_ES256[..], &NAME, &VALIDITY, &NAME, &SPKI_HEAD, public] {
        t[at..at + part.len()].copy_from_slice(part);
        at += part.len();
    }
    debug_assert_eq!(at, TBS_LEN);
    t
}

/// The whole certificate: `tbs`, the algorithm, and `sig` (a DER signature over `tbs`)
/// as a BIT STRING. Returns the length written, or `None` if `out` is too small.
pub fn certificate(tbs: &[u8; TBS_LEN], sig: &[u8], out: &mut [u8]) -> Option<usize> {
    let bits = 1 + sig.len();
    let body = TBS_LEN + ALG_ES256.len() + 2 + bits;
    let mut head = [0u8; 4];
    head[0] = 0x30;
    let hn = 1 + length(body, &mut head[1..]);
    let total = hn + body;
    let out = out.get_mut(..total)?;
    let mut at = 0;
    for part in [&head[..hn], tbs, &ALG_ES256] {
        out[at..at + part.len()].copy_from_slice(part);
        at += part.len();
    }
    out[at] = 0x03;
    at += 1;
    at += length(bits, &mut out[at..]);
    out[at] = 0; // no unused bits
    at += 1;
    out[at..at + sig.len()].copy_from_slice(sig);
    at += sig.len();
    debug_assert_eq!(at, total);
    Some(total)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn integers_are_minimal_and_positive() {
        let mut out = [0u8; SIG_MAX];
        // Top bit set: a zero byte goes in front.
        let r = [0x80; 32];
        // Leading zeros go, down to one byte.
        let mut s = [0u8; 32];
        s[31] = 0x05;
        let n = signature(&r, &s, &mut out);
        assert_eq!(&out[..4], &[0x30, 2 + 33 + 3, 0x02, 33]);
        assert_eq!(out[4], 0);
        assert_eq!(&out[4 + 33..n], &[0x02, 0x01, 0x05]);
        // A value whose first non-zero byte has its top bit set keeps the zero.
        let mut s = [0u8; 32];
        s[30] = 0x80;
        let n = signature(&[0x01; 32], &s, &mut out);
        assert_eq!(&out[2 + 34..n], &[0x02, 0x03, 0x00, 0x80, 0x00]);
        // Zero is one zero byte.
        let n = signature(&[0; 32], &[0; 32], &mut out);
        assert_eq!(&out[..n], &[0x30, 6, 2, 1, 0, 2, 1, 0]);
    }

    /// Walk a DER value: `(tag, header length, content length)`.
    fn tlv(b: &[u8]) -> (u8, usize, usize) {
        let tag = b[0];
        match b[1] {
            n if n < 0x80 => (tag, 2, n as usize),
            0x81 => (tag, 3, b[2] as usize),
            0x82 => (tag, 4, u16::from_be_bytes([b[2], b[3]]) as usize),
            _ => panic!("length form"),
        }
    }

    #[test]
    fn the_certificate_parses_as_a_sequence_of_three_whose_lengths_agree() {
        let mut public = [0u8; 65];
        public[0] = 4;
        let t = tbs(&public, &[0xFF; 8]);
        let sig = [0x30, 6, 2, 1, 1, 2, 1, 1];
        let mut out = [0u8; CERT_MAX];
        let n = certificate(&t, &sig, &mut out).unwrap();
        let c = &out[..n];
        let (tag, h, len) = tlv(c);
        assert_eq!((tag, h + len), (0x30, n));
        let inner = &c[h..];
        let (tag, th, tlen) = tlv(inner);
        assert_eq!(tag, 0x30);
        assert_eq!(&inner[..th + tlen], &t[..]);
        let rest = &inner[th + tlen..];
        assert_eq!(&rest[..12], &ALG_ES256);
        let (tag, bh, blen) = tlv(&rest[12..]);
        assert_eq!((tag, blen), (0x03, sig.len() + 1));
        assert_eq!(&rest[12 + bh + 1..], &sig);
        // The serial is positive and minimal whatever it was given.
        assert_eq!(&t[3..5], &[0x02, 8]);
        assert_eq!(t[5], 0x7F);
        // The key is at the end of the TBS.
        assert_eq!(&t[TBS_LEN - 65..], &public);
        assert!(certificate(&t, &sig, &mut [0u8; 100]).is_none());
    }
}
