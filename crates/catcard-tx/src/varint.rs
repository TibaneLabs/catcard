//! Bitcoin's compact size integer.
//!
//! # Canonical encoding is a consensus matter, not a nicety
//!
//! `0x01` and `0xfd0100` both decode to 1, but they are different bytes, so a
//! transaction accepting either would have two valid serialisations and therefore two
//! txids. Decoding here rejects any encoding that could have been shorter.

use crate::{Error, Reader};

pub struct VarInt;

impl VarInt {
    /// Bytes a value encodes to.
    pub const fn encoded_len(value: u64) -> usize {
        match value {
            0..=0xfc => 1,
            0xfd..=0xffff => 3,
            0x1_0000..=0xffff_ffff => 5,
            _ => 9,
        }
    }

    /// Write `value` into `out`; returns the length written.
    pub fn write(value: u64, out: &mut [u8]) -> Result<usize, Error> {
        let n = Self::encoded_len(value);
        if out.len() < n {
            return Err(Error::Truncated { at: 0 });
        }
        match n {
            1 => out[0] = value as u8,
            3 => {
                out[0] = 0xfd;
                out[1..3].copy_from_slice(&(value as u16).to_le_bytes());
            }
            5 => {
                out[0] = 0xfe;
                out[1..5].copy_from_slice(&(value as u32).to_le_bytes());
            }
            _ => {
                out[0] = 0xff;
                out[1..9].copy_from_slice(&value.to_le_bytes());
            }
        }
        Ok(n)
    }

    /// Read a canonical varint.
    pub fn read(r: &mut Reader<'_>) -> Result<u64, Error> {
        let at = r.position();
        let first = r.u8()?;
        let value = match first {
            0..=0xfc => return Ok(first as u64),
            0xfd => u16::from_le_bytes(r.take(2)?.try_into().expect("2 bytes")) as u64,
            0xfe => u32::from_le_bytes(r.take(4)?.try_into().expect("4 bytes")) as u64,
            _ => u64::from_le_bytes(r.take(8)?.try_into().expect("8 bytes")),
        };
        // Reject anything that fits in a shorter encoding.
        if Self::encoded_len(value) != r.position() - at {
            return Err(Error::NonCanonicalVarInt { at });
        }
        Ok(value)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn enc(v: u64) -> Vec<u8> {
        let mut out = [0u8; 9];
        let n = VarInt::write(v, &mut out).unwrap();
        out[..n].to_vec()
    }
    fn dec(bytes: &[u8]) -> Result<u64, Error> {
        VarInt::read(&mut Reader::new(bytes))
    }

    #[test]
    fn boundary_values_use_the_expected_width() {
        assert_eq!(enc(0), vec![0x00]);
        assert_eq!(enc(0xfc), vec![0xfc]);
        assert_eq!(enc(0xfd), vec![0xfd, 0xfd, 0x00]);
        assert_eq!(enc(0xffff), vec![0xfd, 0xff, 0xff]);
        assert_eq!(enc(0x1_0000), vec![0xfe, 0x00, 0x00, 0x01, 0x00]);
        assert_eq!(enc(0xffff_ffff), vec![0xfe, 0xff, 0xff, 0xff, 0xff]);
        assert_eq!(enc(0x1_0000_0000)[0], 0xff);
        assert_eq!(enc(u64::MAX).len(), 9);
    }

    #[test]
    fn round_trips_across_the_boundaries() {
        for v in [
            0u64,
            1,
            0xfb,
            0xfc,
            0xfd,
            0xfe,
            0xff,
            0x100,
            0xffff,
            0x1_0000,
            0xffff_ffff,
            0x1_0000_0000,
            u64::MAX,
        ] {
            assert_eq!(dec(&enc(v)).unwrap(), v, "value {v}");
        }
    }

    #[test]
    fn non_canonical_encodings_are_rejected() {
        // Each of these decodes to a value that fits in fewer bytes. Accepting them
        // would give one transaction two serialisations and two txids.
        assert!(matches!(
            dec(&[0xfd, 0x01, 0x00]),
            Err(Error::NonCanonicalVarInt { .. })
        ));
        assert!(matches!(
            dec(&[0xfe, 0x01, 0x00, 0x00, 0x00]),
            Err(Error::NonCanonicalVarInt { .. })
        ));
        assert!(matches!(
            dec(&[0xff, 0xfd, 0, 0, 0, 0, 0, 0, 0]),
            Err(Error::NonCanonicalVarInt { .. })
        ));
        // The largest value that still fits the shorter form.
        assert!(matches!(
            dec(&[0xfe, 0xff, 0xff, 0x00, 0x00]),
            Err(Error::NonCanonicalVarInt { .. })
        ));
    }

    #[test]
    fn minimal_encodings_at_each_boundary_are_accepted() {
        assert_eq!(dec(&[0xfd, 0xfd, 0x00]).unwrap(), 0xfd);
        assert_eq!(dec(&[0xfe, 0x00, 0x00, 0x01, 0x00]).unwrap(), 0x1_0000);
        assert_eq!(
            dec(&[0xff, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00]).unwrap(),
            0x1_0000_0000
        );
    }

    #[test]
    fn truncated_input_is_an_error() {
        assert!(dec(&[]).is_err());
        assert!(dec(&[0xfd]).is_err());
        assert!(dec(&[0xfd, 0x01]).is_err());
        assert!(dec(&[0xff, 0, 0, 0]).is_err());
    }

    #[test]
    fn a_small_output_buffer_errors() {
        let mut tiny = [0u8; 2];
        assert!(VarInt::write(0xffff, &mut tiny).is_err());
        assert!(VarInt::write(1, &mut tiny).is_ok());
    }
}
