//! Base58 and Base58Check.
//!
//! Used for extended keys (`xprv`/`xpub`), WIF, and legacy P2PKH/P2SH addresses.
//!
//! No allocation: callers supply the output buffer. Sizes are bounded because
//! everything CatCard encodes is small and fixed — an extended key is 78 bytes, an
//! address payload 21.

use sha2::{Digest, Sha256};

/// Bitcoin's Base58 alphabet. Deliberately omits `0`, `O`, `I` and `l`.
pub const ALPHABET: &[u8; 58] = b"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

/// Bytes appended by Base58Check: the first 4 of a double-SHA256.
pub const CHECKSUM_LEN: usize = 4;

/// Largest payload this module handles: an extended key (78) plus checksum.
pub const MAX_DECODED: usize = 128;

/// Worst-case encoded length for [`MAX_DECODED`] bytes.
///
/// log(256)/log(58) ≈ 1.365, so 128 bytes never exceeds 175 characters; rounded up.
pub const MAX_ENCODED: usize = 192;

#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub enum Error {
    /// A character outside the Base58 alphabet. Carries its position so a UI can point
    /// at it — `0`/`O`/`I`/`l` confusions are the common case.
    BadCharacter { position: usize },
    /// Input or output longer than this module's fixed bounds.
    TooLong { len: usize },
    /// Fewer bytes than a checksum.
    TooShort { len: usize },
    /// The trailing checksum does not match the payload: a typo, or corruption.
    BadChecksum,
    /// The caller's output buffer is too small.
    BufferTooSmall { need: usize, have: usize },
}

/// The 4-byte Base58Check checksum of `payload`.
pub fn checksum(payload: &[u8]) -> [u8; CHECKSUM_LEN] {
    let first = Sha256::digest(payload);
    let second = Sha256::digest(first);
    let mut out = [0u8; CHECKSUM_LEN];
    out.copy_from_slice(&second[..CHECKSUM_LEN]);
    out
}

/// Encode `data` as plain Base58 (no checksum) into `out`. Returns the length written.
pub fn encode(data: &[u8], out: &mut [u8]) -> Result<usize, Error> {
    if data.len() > MAX_DECODED {
        return Err(Error::TooLong { len: data.len() });
    }

    // Leading zero bytes become leading '1's rather than vanishing into the number.
    let zeros = data.iter().take_while(|&&b| b == 0).count();

    // Repeated division of a big-endian bignum by 58.
    let mut buf = [0u8; MAX_ENCODED];
    let mut written = 0usize;
    for &byte in &data[zeros..] {
        let mut carry = byte as u32;
        for slot in buf.iter_mut().take(written) {
            carry += (*slot as u32) << 8;
            *slot = (carry % 58) as u8;
            carry /= 58;
        }
        while carry > 0 {
            if written == MAX_ENCODED {
                return Err(Error::TooLong { len: data.len() });
            }
            buf[written] = (carry % 58) as u8;
            written += 1;
            carry /= 58;
        }
    }

    let total = zeros + written;
    if out.len() < total {
        return Err(Error::BufferTooSmall {
            need: total,
            have: out.len(),
        });
    }
    out[..zeros].fill(ALPHABET[0]);
    // `buf` holds least-significant digit first; emit reversed.
    for i in 0..written {
        out[zeros + i] = ALPHABET[buf[written - 1 - i] as usize];
    }
    Ok(total)
}

/// Decode plain Base58 into `out`. Returns the length written.
pub fn decode(text: &str, out: &mut [u8]) -> Result<usize, Error> {
    let bytes = text.as_bytes();
    if bytes.len() > MAX_ENCODED {
        return Err(Error::TooLong { len: bytes.len() });
    }

    let zeros = bytes.iter().take_while(|&&c| c == ALPHABET[0]).count();

    let mut buf = [0u8; MAX_DECODED];
    let mut written = 0usize;
    for (position, &c) in bytes.iter().enumerate().skip(zeros) {
        let digit = digit_of(c).ok_or(Error::BadCharacter { position })? as u32;
        let mut carry = digit;
        for slot in buf.iter_mut().take(written) {
            carry += (*slot as u32) * 58;
            *slot = (carry & 0xff) as u8;
            carry >>= 8;
        }
        while carry > 0 {
            if written == MAX_DECODED {
                return Err(Error::TooLong { len: bytes.len() });
            }
            buf[written] = (carry & 0xff) as u8;
            written += 1;
            carry >>= 8;
        }
    }

    let total = zeros + written;
    if out.len() < total {
        return Err(Error::BufferTooSmall {
            need: total,
            have: out.len(),
        });
    }
    out[..zeros].fill(0);
    for i in 0..written {
        out[zeros + i] = buf[written - 1 - i];
    }
    Ok(total)
}

fn digit_of(c: u8) -> Option<u8> {
    // Linear scan over 58 entries: small, and constant with respect to which character
    // was supplied rather than short-circuiting on a match.
    let mut found = None;
    for (i, &a) in ALPHABET.iter().enumerate() {
        if a == c {
            found = Some(i as u8);
        }
    }
    found
}

/// Encode `payload` with a trailing checksum.
pub fn encode_check(payload: &[u8], out: &mut [u8]) -> Result<usize, Error> {
    if payload.len() + CHECKSUM_LEN > MAX_DECODED {
        return Err(Error::TooLong { len: payload.len() });
    }
    let mut buf = [0u8; MAX_DECODED];
    buf[..payload.len()].copy_from_slice(payload);
    buf[payload.len()..payload.len() + CHECKSUM_LEN].copy_from_slice(&checksum(payload));
    encode(&buf[..payload.len() + CHECKSUM_LEN], out)
}

/// Decode and verify a Base58Check string. Returns the payload length written to `out`.
pub fn decode_check(text: &str, out: &mut [u8]) -> Result<usize, Error> {
    let mut buf = [0u8; MAX_DECODED];
    let n = decode(text, &mut buf)?;
    if n < CHECKSUM_LEN {
        return Err(Error::TooShort { len: n });
    }
    let split = n - CHECKSUM_LEN;
    let (payload, tail) = buf.split_at(split);

    use subtle::ConstantTimeEq;
    let ok: bool = checksum(payload).ct_eq(&tail[..CHECKSUM_LEN]).into();
    if !ok {
        return Err(Error::BadChecksum);
    }
    if out.len() < split {
        return Err(Error::BufferTooSmall {
            need: split,
            have: out.len(),
        });
    }
    out[..split].copy_from_slice(payload);
    Ok(split)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn enc(data: &[u8]) -> String {
        let mut out = [0u8; MAX_ENCODED];
        let n = encode(data, &mut out).unwrap();
        core::str::from_utf8(&out[..n]).unwrap().to_string()
    }
    fn dec(text: &str) -> Vec<u8> {
        let mut out = [0u8; MAX_DECODED];
        let n = decode(text, &mut out).unwrap();
        out[..n].to_vec()
    }
    fn unhex(s: &str) -> Vec<u8> {
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }

    /// Vectors from the Bitcoin Core `base58_encode_decode.json` fixture.
    const VECTORS: &[(&str, &str)] = &[
        ("", ""),
        ("61", "2g"),
        ("626262", "a3gV"),
        ("636363", "aPEr"),
        (
            "73696d706c792061206c6f6e6720737472696e67",
            "2cFupjhnEsSn59qHXstmK2ffpLv2",
        ),
        (
            "00eb15231dfceb60925886b67d065299925915aeb172c06647",
            "1NS17iag9jJgTHD1VXjvLCEnZuQ3rJDE9L",
        ),
        ("516b6fcd0f", "ABnLTmg"),
        ("bf4f89001e670274dd", "3SEo3LWLoPntC"),
        ("572e4794", "3EFU7m"),
        ("ecac89cad93923c02321", "EJDM8drfXA6uyA"),
        ("10c8511e", "Rt5zm"),
        ("00000000000000000000", "1111111111"),
    ];

    #[test]
    fn known_vectors_encode() {
        for (hex, want) in VECTORS {
            assert_eq!(enc(&unhex(hex)), *want, "encoding {hex}");
        }
    }

    #[test]
    fn known_vectors_decode() {
        for (hex, text) in VECTORS {
            assert_eq!(dec(text), unhex(hex), "decoding {text}");
        }
    }

    #[test]
    fn leading_zeros_survive_the_round_trip() {
        // A zero byte carries no magnitude, so a naive bignum conversion drops it —
        // and an address with a dropped leading zero is a different address.
        for zeros in 0..8 {
            let mut data = vec![0u8; zeros];
            data.extend_from_slice(&[0x01, 0x02, 0x03]);
            let text = enc(&data);
            assert_eq!(text.chars().take_while(|&c| c == '1').count(), zeros);
            assert_eq!(dec(&text), data);
        }
    }

    #[test]
    fn all_zero_input() {
        assert_eq!(enc(&[0u8; 5]), "11111");
        assert_eq!(dec("11111"), vec![0u8; 5]);
    }

    #[test]
    fn round_trip_arbitrary_lengths() {
        for len in 1..=82usize {
            let data: Vec<u8> = (0..len)
                .map(|i| (i as u8).wrapping_mul(89).wrapping_add(7))
                .collect();
            assert_eq!(dec(&enc(&data)), data, "length {len}");
        }
    }

    #[test]
    fn ambiguous_characters_are_not_in_the_alphabet() {
        for c in *b"0OIl" {
            assert!(!ALPHABET.contains(&c), "{} should be excluded", c as char);
        }
        assert_eq!(ALPHABET.len(), 58);
        // And the alphabet has no duplicates.
        let mut a = ALPHABET.to_vec();
        a.sort_unstable();
        let before = a.len();
        a.dedup();
        assert_eq!(a.len(), before);
    }

    #[test]
    fn invalid_characters_report_their_position() {
        let mut out = [0u8; MAX_DECODED];
        assert_eq!(
            decode("2cFup0hn", &mut out),
            Err(Error::BadCharacter { position: 5 })
        );
        assert_eq!(
            decode("abcO", &mut out),
            Err(Error::BadCharacter { position: 3 })
        );
        // Position is counted past the leading '1's too.
        assert_eq!(
            decode("11I", &mut out),
            Err(Error::BadCharacter { position: 2 })
        );
    }

    #[test]
    fn check_round_trip() {
        let payload = unhex("00f54a5851e9372b87810a8e60cdd2e7cfd80b6e31");
        let mut buf = [0u8; MAX_ENCODED];
        let n = encode_check(&payload, &mut buf).unwrap();
        let text = core::str::from_utf8(&buf[..n]).unwrap();
        assert_eq!(text, "1PMycacnJaSqwwJqjawXBErnLsZ7RkXUAs");

        let mut back = [0u8; MAX_DECODED];
        let m = decode_check(text, &mut back).unwrap();
        assert_eq!(&back[..m], &payload[..]);
    }

    #[test]
    fn a_single_altered_character_fails_the_checksum() {
        // The entire point of Base58Check: a mistyped address must not be spendable-to.
        let mut buf = [0u8; MAX_ENCODED];
        let n = encode_check(
            &unhex("00f54a5851e9372b87810a8e60cdd2e7cfd80b6e31"),
            &mut buf,
        )
        .unwrap();
        let good = core::str::from_utf8(&buf[..n]).unwrap().to_string();

        let mut out = [0u8; MAX_DECODED];
        for i in 0..good.len() {
            let mut chars: Vec<u8> = good.bytes().collect();
            // Swap for a different valid alphabet character.
            let cur = chars[i];
            chars[i] = if cur == ALPHABET[0] {
                ALPHABET[1]
            } else {
                ALPHABET[0]
            };
            let bad = String::from_utf8(chars).unwrap();
            assert_eq!(
                decode_check(&bad, &mut out),
                Err(Error::BadChecksum),
                "altering position {i} was accepted"
            );
        }
    }

    #[test]
    fn truncated_input_is_rejected() {
        let mut out = [0u8; MAX_DECODED];
        assert!(matches!(
            decode_check("", &mut out),
            Err(Error::TooShort { .. })
        ));
        assert!(matches!(
            decode_check("2g", &mut out),
            Err(Error::TooShort { .. })
        ));
    }

    #[test]
    fn small_output_buffers_error_rather_than_truncate() {
        let mut tiny = [0u8; 2];
        assert!(matches!(
            encode(&[1, 2, 3, 4, 5], &mut tiny),
            Err(Error::BufferTooSmall { .. })
        ));
        assert!(matches!(
            decode("2cFupjhnEsSn59qHXstmK2ffpLv2", &mut tiny),
            Err(Error::BufferTooSmall { .. })
        ));
    }

    #[test]
    fn oversized_input_is_rejected_not_wrapped() {
        let mut out = [0u8; MAX_ENCODED];
        assert!(matches!(
            encode(&[0xffu8; MAX_DECODED + 1], &mut out),
            Err(Error::TooLong { .. })
        ));
    }

    #[test]
    fn max_encoded_bound_is_sufficient() {
        // MAX_ENCODED sizes internal buffers; if it were too small, encoding the
        // largest payload would error instead of succeeding.
        let mut out = [0u8; MAX_ENCODED];
        let n = encode(&[0xffu8; MAX_DECODED], &mut out).unwrap();
        assert!(n <= MAX_ENCODED, "{n} exceeds MAX_ENCODED");
    }

    #[test]
    fn checksum_matches_double_sha256() {
        let payload = b"catcard";
        let expect = Sha256::digest(Sha256::digest(payload));
        assert_eq!(checksum(payload), expect[..4]);
    }
}
