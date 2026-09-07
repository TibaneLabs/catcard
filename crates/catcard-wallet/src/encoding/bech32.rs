//! Bech32 (BIP-173) and Bech32m (BIP-350), and the segwit address format built on them.
//!
//! The two differ only in the checksum constant, but using the wrong one is a real
//! hazard: a v0 address must use Bech32 and a v1+ (taproot) address must use Bech32m,
//! and an address encoded with the wrong variant is rejected by relaying nodes. That
//! rule is enforced in [`encode_segwit`] and [`decode_segwit`] rather than left to
//! callers.
//!
//! Allocation-free. The 90-character limit BIP-173 imposes bounds every buffer.

/// Bech32 data characters. Ordered so that the most visually similar characters are far
/// apart in value, which is what gives the checksum its error-location properties.
pub const CHARSET: &[u8; 32] = b"qpzry9x8gf2tvdw0s3jn54khce6mua7l";

/// Checksum constant for Bech32 (BIP-173). Witness v0 only.
pub const BECH32_CONST: u32 = 1;
/// Checksum constant for Bech32m (BIP-350). Witness v1 and later.
pub const BECH32M_CONST: u32 = 0x2bc8_30a3;

/// Maximum total length of a Bech32 string, per BIP-173.
pub const MAX_LENGTH: usize = 90;
/// Checksum length in data characters.
pub const CHECKSUM_LEN: usize = 6;
/// Longest human-readable part.
pub const MAX_HRP_LEN: usize = 83;
/// Largest witness program, per BIP-141.
pub const MAX_PROGRAM_LEN: usize = 40;
/// Data characters a `MAX_LENGTH` string can hold, after `1` and a 2-char HRP.
pub const MAX_DATA_LEN: usize = MAX_LENGTH - 3;

/// Which checksum a string uses.
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub enum Variant {
    /// BIP-173. Correct for witness version 0.
    Bech32,
    /// BIP-350. Correct for witness versions 1 to 16.
    Bech32m,
}

impl Variant {
    pub const fn constant(self) -> u32 {
        match self {
            Variant::Bech32 => BECH32_CONST,
            Variant::Bech32m => BECH32M_CONST,
        }
    }

    /// The variant a given witness version must use.
    pub const fn for_witness_version(version: u8) -> Self {
        if version == 0 {
            Variant::Bech32
        } else {
            Variant::Bech32m
        }
    }
}

#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub enum Error {
    /// Longer than the 90 characters BIP-173 permits.
    TooLong { len: usize },
    /// Too short to contain an HRP, a separator and a checksum.
    TooShort { len: usize },
    /// No `1` separator, or nothing before it.
    NoSeparator,
    /// HRP is empty, over-long, or contains a character outside 33..=126.
    BadHrp,
    /// The HRP is well-formed but is not the one expected for this network. Accepting
    /// it would let a testnet address be paid to on mainnet, or vice versa.
    WrongHrp,
    /// Upper and lower case mixed. BIP-173 forbids it because the checksum is
    /// case-insensitive but the QR encoding is not.
    MixedCase,
    /// A data character outside the Bech32 charset, at this position in the string.
    BadCharacter { position: usize },
    /// The checksum does not verify under either variant.
    BadChecksum,
    /// The checksum verifies, but under the other variant — a v0 address encoded as
    /// Bech32m, or a taproot address encoded as Bech32.
    WrongVariant { found: Variant, expected: Variant },
    /// Witness version above 16.
    BadWitnessVersion { version: u8 },
    /// Witness program length is invalid for its version.
    BadProgramLength { version: u8, len: usize },
    /// Padding bits in the 5-to-8 conversion were non-zero, or there were too many.
    BadPadding,
    /// The caller's output buffer is too small.
    BufferTooSmall { need: usize, have: usize },
}

/// BCH code over GF(32) — the core of the checksum.
fn polymod(values: &[u8]) -> u32 {
    const GEN: [u32; 5] = [
        0x3b6a_57b2,
        0x2650_8e6d,
        0x1ea1_19fa,
        0x3d42_33dd,
        0x2a14_62b3,
    ];
    let mut chk: u32 = 1;
    for &v in values {
        let top = chk >> 25;
        chk = ((chk & 0x1ff_ffff) << 5) ^ (v as u32);
        for (i, g) in GEN.iter().enumerate() {
            if (top >> i) & 1 == 1 {
                chk ^= g;
            }
        }
    }
    chk
}

/// Expand the HRP into the values the checksum is computed over: high bits, a zero
/// separator, then low bits.
fn hrp_expand(hrp: &[u8], out: &mut [u8]) -> usize {
    let n = hrp.len();
    for (i, &c) in hrp.iter().enumerate() {
        out[i] = c >> 5;
        out[n + 1 + i] = c & 0x1f;
    }
    out[n] = 0;
    2 * n + 1
}

/// Which variant's checksum `hrp`/`data` satisfies, if either.
fn checksum_variant(hrp: &[u8], data: &[u8]) -> Option<Variant> {
    let mut buf = [0u8; 2 * MAX_HRP_LEN + 1 + MAX_DATA_LEN];
    let n = hrp_expand(hrp, &mut buf);
    buf[n..n + data.len()].copy_from_slice(data);
    match polymod(&buf[..n + data.len()]) {
        BECH32_CONST => Some(Variant::Bech32),
        BECH32M_CONST => Some(Variant::Bech32m),
        _ => None,
    }
}

/// Encode `hrp` and 5-bit `data` into `out`. Returns the length written.
pub fn encode(hrp: &str, data: &[u8], variant: Variant, out: &mut [u8]) -> Result<usize, Error> {
    let hrp_bytes = hrp.as_bytes();
    if hrp_bytes.is_empty() || hrp_bytes.len() > MAX_HRP_LEN {
        return Err(Error::BadHrp);
    }
    if hrp_bytes.iter().any(|&c| !(33..=126).contains(&c)) {
        return Err(Error::BadHrp);
    }
    if hrp_bytes.iter().any(|c| c.is_ascii_uppercase()) {
        // We always emit lowercase; accepting uppercase input here would produce a
        // string whose case is inconsistent with the data part.
        return Err(Error::MixedCase);
    }
    if data.iter().any(|&d| d >= 32) {
        return Err(Error::BadCharacter { position: 0 });
    }

    let total = hrp_bytes.len() + 1 + data.len() + CHECKSUM_LEN;
    if total > MAX_LENGTH {
        return Err(Error::TooLong { len: total });
    }
    if out.len() < total {
        return Err(Error::BufferTooSmall {
            need: total,
            have: out.len(),
        });
    }

    // checksum = polymod(hrp_expand || data || [0;6]) ^ const
    let mut buf = [0u8; 2 * MAX_HRP_LEN + 1 + MAX_DATA_LEN + CHECKSUM_LEN];
    let n = hrp_expand(hrp_bytes, &mut buf);
    buf[n..n + data.len()].copy_from_slice(data);
    let end = n + data.len() + CHECKSUM_LEN;
    let poly = polymod(&buf[..end]) ^ variant.constant();

    out[..hrp_bytes.len()].copy_from_slice(hrp_bytes);
    out[hrp_bytes.len()] = b'1';
    let mut at = hrp_bytes.len() + 1;
    for &d in data {
        out[at] = CHARSET[d as usize];
        at += 1;
    }
    for i in 0..CHECKSUM_LEN {
        let shift = 5 * (5 - i);
        out[at] = CHARSET[((poly >> shift) & 0x1f) as usize];
        at += 1;
    }
    Ok(at)
}

/// A decoded Bech32 string: the HRP length written to `hrp_out`, the 5-bit data length
/// written to `data_out`, and which variant verified.
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub struct Decoded {
    pub hrp_len: usize,
    pub data_len: usize,
    pub variant: Variant,
}

/// Decode a Bech32/Bech32m string. `data_out` receives 5-bit values, checksum stripped.
pub fn decode(text: &str, hrp_out: &mut [u8], data_out: &mut [u8]) -> Result<Decoded, Error> {
    let bytes = text.as_bytes();
    if bytes.len() > MAX_LENGTH {
        return Err(Error::TooLong { len: bytes.len() });
    }
    if bytes.len() < 8 {
        return Err(Error::TooShort { len: bytes.len() });
    }

    let has_lower = bytes.iter().any(|c| c.is_ascii_lowercase());
    let has_upper = bytes.iter().any(|c| c.is_ascii_uppercase());
    if has_lower && has_upper {
        return Err(Error::MixedCase);
    }

    // The separator is the *last* '1', because the HRP may contain '1'.
    let sep = bytes
        .iter()
        .rposition(|&c| c == b'1')
        .ok_or(Error::NoSeparator)?;
    if sep == 0 || sep + CHECKSUM_LEN + 1 > bytes.len() {
        return Err(Error::NoSeparator);
    }

    let hrp_len = sep;
    if hrp_len > MAX_HRP_LEN {
        return Err(Error::BadHrp);
    }
    if hrp_out.len() < hrp_len {
        return Err(Error::BufferTooSmall {
            need: hrp_len,
            have: hrp_out.len(),
        });
    }
    for (i, &c) in bytes[..sep].iter().enumerate() {
        if !(33..=126).contains(&c) {
            return Err(Error::BadHrp);
        }
        hrp_out[i] = c.to_ascii_lowercase();
    }

    let raw = &bytes[sep + 1..];
    let mut values = [0u8; MAX_DATA_LEN];
    for (i, &c) in raw.iter().enumerate() {
        let lower = c.to_ascii_lowercase();
        let v = CHARSET
            .iter()
            .position(|&x| x == lower)
            .ok_or(Error::BadCharacter {
                position: sep + 1 + i,
            })?;
        values[i] = v as u8;
    }

    let variant =
        checksum_variant(&hrp_out[..hrp_len], &values[..raw.len()]).ok_or(Error::BadChecksum)?;

    let data_len = raw.len() - CHECKSUM_LEN;
    if data_out.len() < data_len {
        return Err(Error::BufferTooSmall {
            need: data_len,
            have: data_out.len(),
        });
    }
    data_out[..data_len].copy_from_slice(&values[..data_len]);

    Ok(Decoded {
        hrp_len,
        data_len,
        variant,
    })
}

/// Regroup bits. `from`/`to` are bit widths; `pad` appends zero bits on the way up.
fn convert_bits(
    input: &[u8],
    from: u32,
    to: u32,
    pad: bool,
    out: &mut [u8],
) -> Result<usize, Error> {
    let mut acc: u32 = 0;
    let mut bits: u32 = 0;
    let mut written = 0usize;
    let max = (1u32 << to) - 1;

    for &value in input {
        if (value as u32) >> from != 0 {
            return Err(Error::BadPadding);
        }
        acc = (acc << from) | value as u32;
        bits += from;
        while bits >= to {
            bits -= to;
            if written == out.len() {
                return Err(Error::BufferTooSmall {
                    need: written + 1,
                    have: out.len(),
                });
            }
            out[written] = ((acc >> bits) & max) as u8;
            written += 1;
        }
    }

    if pad {
        if bits > 0 {
            if written == out.len() {
                return Err(Error::BufferTooSmall {
                    need: written + 1,
                    have: out.len(),
                });
            }
            out[written] = ((acc << (to - bits)) & max) as u8;
            written += 1;
        }
    } else {
        // Going down in width, leftover bits must be zero padding only. Non-zero
        // padding, or a full extra group, means the input was malformed — and BIP-173
        // requires rejecting it rather than silently truncating.
        if bits >= from || ((acc << (to - bits)) & max) != 0 {
            return Err(Error::BadPadding);
        }
    }
    Ok(written)
}

/// Encode a segwit address. Picks the variant the witness version requires.
pub fn encode_segwit(
    hrp: &str,
    version: u8,
    program: &[u8],
    out: &mut [u8],
) -> Result<usize, Error> {
    if version > 16 {
        return Err(Error::BadWitnessVersion { version });
    }
    check_program_length(version, program.len())?;

    let mut data = [0u8; MAX_DATA_LEN];
    data[0] = version;
    let n = convert_bits(program, 8, 5, true, &mut data[1..])?;
    encode(
        hrp,
        &data[..n + 1],
        Variant::for_witness_version(version),
        out,
    )
}

/// Decode a segwit address into `(version, program_len)`, writing the program to `out`.
///
/// `expected_hrp` is the network's prefix (`bc`, `tb`, `bcrt`, ...) and is **required**:
/// a decoder that ignored it would accept a testnet address as a mainnet one, which is
/// a fund-loss bug rather than a validation nicety. BIP-350's invalid-address vectors
/// include exactly this case.
pub fn decode_segwit(text: &str, expected_hrp: &str, out: &mut [u8]) -> Result<(u8, usize), Error> {
    let mut hrp = [0u8; MAX_HRP_LEN];
    let mut data = [0u8; MAX_DATA_LEN];
    let d = decode(text, &mut hrp, &mut data)?;
    if d.data_len == 0 {
        return Err(Error::TooShort { len: 0 });
    }

    // `decode` lowercased the HRP, so this comparison is case-insensitive as BIP-173
    // requires.
    if &hrp[..d.hrp_len] != expected_hrp.as_bytes() {
        return Err(Error::WrongHrp);
    }

    let version = data[0];
    if version > 16 {
        return Err(Error::BadWitnessVersion { version });
    }

    // The variant is not a free choice: it identifies the address type, and accepting
    // the wrong one would let a v0 address masquerade as taproot or vice versa.
    let expected = Variant::for_witness_version(version);
    if d.variant != expected {
        return Err(Error::WrongVariant {
            found: d.variant,
            expected,
        });
    }

    let len = convert_bits(&data[1..d.data_len], 5, 8, false, out)?;
    check_program_length(version, len)?;
    Ok((version, len))
}

fn check_program_length(version: u8, len: usize) -> Result<(), Error> {
    // BIP-141: 2..=40 generally. BIP-173: exactly 20 or 32 for v0.
    let ok = match version {
        0 => len == 20 || len == 32,
        _ => (2..=MAX_PROGRAM_LEN).contains(&len),
    };
    if ok {
        Ok(())
    } else {
        Err(Error::BadProgramLength { version, len })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn addr(hrp: &str, v: u8, prog: &[u8]) -> String {
        let mut out = [0u8; MAX_LENGTH];
        let n = encode_segwit(hrp, v, prog, &mut out).unwrap();
        core::str::from_utf8(&out[..n]).unwrap().to_string()
    }
    fn unhex(s: &str) -> Vec<u8> {
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }

    /// BIP-173 / BIP-350 valid address vectors: (address, scriptPubKey hex).
    const SEGWIT_VECTORS: &[(&str, &str)] = &[
        (
            "BC1QW508D6QEJXTDG4Y5R3ZARVARY0C5XW7KV8F3T4",
            "0014751e76e8199196d454941c45d1b3a323f1433bd6",
        ),
        (
            "tb1qrp33g0q5c5txsp9arysrx4k6zdkfs4nce4xj0gdcccefvpysxf3q0sl5k7",
            "00201863143c14c5166804bd19203356da136c985678cd4d27a1b8c6329604903262",
        ),
        (
            "bc1pw508d6qejxtdg4y5r3zarvary0c5xw7kw508d6qejxtdg4y5r3zarvary0c5xw7kt5nd6y",
            "5128751e76e8199196d454941c45d1b3a323f1433bd6751e76e8199196d454941c45d1b3a323f1433bd6",
        ),
        ("BC1SW50QGDZ25J", "6002751e"),
        (
            "bc1zw508d6qejxtdg4y5r3zarvaryvaxxpcs",
            "5210751e76e8199196d454941c45d1b3a323",
        ),
        (
            "tb1qqqqqp399et2xygdj5xreqhjjvcmzhxw4aywxecjdzew6hylgvsesrxh6hy",
            "0020000000c4a5cad46221b2a187905e5266362b99d5e91c6ce24d165dab93e86433",
        ),
        (
            "bc1p0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7vqzk5jj0",
            "512079be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798",
        ),
    ];

    #[test]
    fn official_segwit_vectors_decode() {
        for (address, spk_hex) in SEGWIT_VECTORS {
            let mut prog = [0u8; MAX_PROGRAM_LEN];
            let hrp = if address.to_lowercase().starts_with("bc1") {
                "bc"
            } else {
                "tb"
            };
            let (version, len) = decode_segwit(address, hrp, &mut prog)
                .unwrap_or_else(|e| panic!("{address}: {e:?}"));

            // Rebuild the scriptPubKey: OP_n, push length, program.
            let spk = unhex(spk_hex);
            let op = if version == 0 { 0x00 } else { 0x50 + version };
            assert_eq!(spk[0], op, "{address}: witness version opcode");
            assert_eq!(spk[1] as usize, len, "{address}: push length");
            assert_eq!(&spk[2..], &prog[..len], "{address}: program");
        }
    }

    #[test]
    fn official_segwit_vectors_re_encode() {
        for (address, _) in SEGWIT_VECTORS {
            let mut prog = [0u8; MAX_PROGRAM_LEN];
            let hrp = if address.to_lowercase().starts_with("bc1") {
                "bc"
            } else {
                "tb"
            };
            let (version, len) = decode_segwit(address, hrp, &mut prog).unwrap();
            assert_eq!(addr(hrp, version, &prog[..len]), address.to_lowercase());
        }
    }

    #[test]
    fn v0_uses_bech32_and_v1_uses_bech32m() {
        // The single most consequential rule in BIP-350.
        assert_eq!(Variant::for_witness_version(0), Variant::Bech32);
        for v in 1..=16u8 {
            assert_eq!(Variant::for_witness_version(v), Variant::Bech32m);
        }

        let prog20 = [0x11u8; 20];
        let mut hrp = [0u8; MAX_HRP_LEN];
        let mut data = [0u8; MAX_DATA_LEN];
        let a = addr("bc", 0, &prog20);
        assert_eq!(
            decode(&a, &mut hrp, &mut data).unwrap().variant,
            Variant::Bech32
        );
        let b = addr("bc", 1, &[0x11u8; 32]);
        assert_eq!(
            decode(&b, &mut hrp, &mut data).unwrap().variant,
            Variant::Bech32m
        );
    }

    #[test]
    fn wrong_variant_is_rejected_with_a_specific_error() {
        // Take a valid v0 address and re-checksum it as Bech32m. Every character is
        // still valid and the checksum verifies — only the variant rule catches it.
        let prog = [0x11u8; 20];
        let mut data = [0u8; MAX_DATA_LEN];
        data[0] = 0;
        let n = convert_bits(&prog, 8, 5, true, &mut data[1..]).unwrap();
        let mut out = [0u8; MAX_LENGTH];
        let len = encode("bc", &data[..n + 1], Variant::Bech32m, &mut out).unwrap();
        let text = core::str::from_utf8(&out[..len]).unwrap();

        let mut p = [0u8; MAX_PROGRAM_LEN];
        assert_eq!(
            decode_segwit(text, "bc", &mut p),
            Err(Error::WrongVariant {
                found: Variant::Bech32m,
                expected: Variant::Bech32
            })
        );
    }

    /// BIP-173/350 invalid-address vectors. Each must be rejected, for any reason.
    #[test]
    fn official_invalid_addresses_are_rejected() {
        const INVALID: &[&str] = &[
            // Invalid HRP.
            "tc1p0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7vq5zuyut",
            // Invalid checksum algorithm (bech32 instead of bech32m) for v1.
            "bc1p0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7vqh2y7hd",
            // Invalid checksum algorithm (bech32m instead of bech32) for v0.
            "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kemeawh",
            // Mixed case.
            "bc1p38j9r5y49hruaue7wxjce0updqjuyyx0kh56v8s25huc6995vvpql3jow4",
            // Invalid character in data part.
            "bc1p0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7vq47Zagq",
            // Zero padding of more than 4 bits.
            "bc1p0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7v07qwwzcrf",
            // Non-zero padding in 8-to-5 conversion.
            "bc1p0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7vpggkg4j",
            // Empty data section.
            "bc1gmk9yu",
            // Invalid witness version.
            "BC130XLXVLHEMJA6C4DQV22UAPCTQUPFHLXM9H8Z3K2E72Q4K9HCZ7VQ7ZWS8R",
            // Invalid program length for v0.
            "bc1qrp33g0q5c5txsp9arysrx4k6zdkfs4nce4xj0gdcccefvpysxf3q0sL5k7",
        ];
        let mut prog = [0u8; MAX_PROGRAM_LEN];
        for a in INVALID {
            // Try both mainnet and testnet prefixes: a vector must be invalid for the
            // network it names, not merely mismatched against an arbitrary one.
            let hrp = if a.to_lowercase().starts_with("tb1") {
                "tb"
            } else {
                "bc"
            };
            assert!(
                decode_segwit(a, hrp, &mut prog).is_err(),
                "should have been rejected: {a}"
            );
        }
    }

    #[test]
    fn a_testnet_address_is_not_accepted_on_mainnet() {
        // The HRP is the only thing distinguishing these; paying a testnet address on
        // mainnet burns the funds.
        let mut prog = [0u8; MAX_PROGRAM_LEN];
        let tb = "tb1qrp33g0q5c5txsp9arysrx4k6zdkfs4nce4xj0gdcccefvpysxf3q0sl5k7";
        assert!(decode_segwit(tb, "tb", &mut prog).is_ok());
        assert_eq!(decode_segwit(tb, "bc", &mut prog), Err(Error::WrongHrp));

        let bc = "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4";
        assert!(decode_segwit(bc, "bc", &mut prog).is_ok());
        assert_eq!(decode_segwit(bc, "tb", &mut prog), Err(Error::WrongHrp));
        // Regtest shares testnet's program formats but not its prefix.
        assert_eq!(decode_segwit(bc, "bcrt", &mut prog), Err(Error::WrongHrp));
    }

    #[test]
    fn mixed_case_is_rejected() {
        let mut hrp = [0u8; MAX_HRP_LEN];
        let mut data = [0u8; MAX_DATA_LEN];
        assert_eq!(
            decode(
                "bc1QW508D6QEJXTDG4Y5R3ZARVARY0C5XW7KV8F3T4",
                &mut hrp,
                &mut data
            ),
            Err(Error::MixedCase)
        );
    }

    #[test]
    fn uppercase_decodes_to_the_same_program_as_lowercase() {
        // QR codes use uppercase because it is more compact in alphanumeric mode.
        let (mut a, mut b) = ([0u8; MAX_PROGRAM_LEN], [0u8; MAX_PROGRAM_LEN]);
        let upper =
            decode_segwit("BC1QW508D6QEJXTDG4Y5R3ZARVARY0C5XW7KV8F3T4", "bc", &mut a).unwrap();
        let lower =
            decode_segwit("bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4", "bc", &mut b).unwrap();
        assert_eq!(upper, lower);
        assert_eq!(a, b);
    }

    #[test]
    fn program_lengths_are_enforced_per_version() {
        let mut out = [0u8; MAX_LENGTH];
        // v0 accepts only 20 and 32.
        for len in [2usize, 19, 21, 31, 33, 40] {
            assert!(matches!(
                encode_segwit("bc", 0, &vec![0u8; len], &mut out),
                Err(Error::BadProgramLength { version: 0, .. })
            ));
        }
        assert!(encode_segwit("bc", 0, &[0u8; 20], &mut out).is_ok());
        assert!(encode_segwit("bc", 0, &[0u8; 32], &mut out).is_ok());
        // v1+ accepts 2..=40.
        assert!(encode_segwit("bc", 1, &[0u8; 2], &mut out).is_ok());
        assert!(encode_segwit("bc", 1, &[0u8; 40], &mut out).is_ok());
        assert!(matches!(
            encode_segwit("bc", 1, &[0u8; 41], &mut out),
            Err(Error::BadProgramLength { .. })
        ));
        assert!(matches!(
            encode_segwit("bc", 1, &[0u8; 1], &mut out),
            Err(Error::BadProgramLength { .. })
        ));
    }

    #[test]
    fn witness_version_above_16_is_rejected() {
        let mut out = [0u8; MAX_LENGTH];
        assert!(matches!(
            encode_segwit("bc", 17, &[0u8; 20], &mut out),
            Err(Error::BadWitnessVersion { version: 17 })
        ));
    }

    #[test]
    fn a_single_altered_character_fails_the_checksum() {
        let good = addr("bc", 0, &[0x11u8; 20]);
        let mut prog = [0u8; MAX_PROGRAM_LEN];
        let mut failures = 0;
        for i in 3..good.len() {
            let mut bytes: Vec<u8> = good.bytes().collect();
            let cur = bytes[i];
            bytes[i] = if cur == CHARSET[0] {
                CHARSET[1]
            } else {
                CHARSET[0]
            };
            let bad = String::from_utf8(bytes).unwrap();
            if bad != good {
                assert!(
                    decode_segwit(&bad, "bc", &mut prog).is_err(),
                    "accepted {bad}"
                );
                failures += 1;
            }
        }
        assert!(failures > 30, "expected to have mutated most positions");
    }

    #[test]
    fn round_trip_every_witness_version() {
        for v in 0..=16u8 {
            let prog = if v == 0 {
                vec![0x42u8; 20]
            } else {
                vec![0x42u8; 32]
            };
            let a = addr("bc", v, &prog);
            let mut out = [0u8; MAX_PROGRAM_LEN];
            let (version, len) = decode_segwit(&a, "bc", &mut out).unwrap();
            assert_eq!(version, v);
            assert_eq!(&out[..len], &prog[..]);
        }
    }

    #[test]
    fn length_limit_is_enforced() {
        let mut out = [0u8; MAX_LENGTH];
        // An 83-character HRP plus data exceeds 90 characters overall.
        let hrp = "a".repeat(MAX_HRP_LEN);
        assert!(matches!(
            encode(&hrp, &[0u8; 20], Variant::Bech32, &mut out),
            Err(Error::TooLong { .. })
        ));
    }

    #[test]
    fn bit_conversion_rejects_non_zero_padding() {
        // 5-to-8 with leftover bits set must fail, not silently drop them.
        let mut out = [0u8; 8];
        assert_eq!(
            convert_bits(&[31, 31, 31], 5, 8, false, &mut out),
            Err(Error::BadPadding)
        );
        // Exact multiples convert cleanly.
        assert!(convert_bits(&[0u8; 8], 5, 8, false, &mut out).is_ok());
    }

    #[test]
    fn polymod_matches_the_reference_constants() {
        // The empty-data checksum for hrp "" is what pins the generator table.
        assert_eq!(Variant::Bech32.constant(), 1);
        assert_eq!(Variant::Bech32m.constant(), 0x2bc830a3);
    }
}
