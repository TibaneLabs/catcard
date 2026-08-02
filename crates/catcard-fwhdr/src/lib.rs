//! The signed firmware image header, and the digest the bootloader verifies.
//!
//! This is an **imposed format**: the bootloader lives in protected flash and cannot
//! be replaced, so an image must match this layout byte-for-byte or it will not boot.
//! Implemented from `hw-reference/firmware-signing.md §1–2` [C].
//!
//! Used by the host `catcard-image` tool to build and sign images, and by the firmware
//! itself to read its own header (version reporting, self-check, upgrade validation).

#![cfg_attr(not(feature = "std"), no_std)]
#![deny(unsafe_code)]

use sha2::{Digest, Sha256};

pub use catcard_board::{FW_HEADER_OFFSET, FW_HEADER_SIZE};

/// `magic_value` at offset 0. Source: firmware-signing.md §1 [C]
pub const MAGIC: u32 = 0xCC00_1234;

/// The header is 128 bytes.
pub const HEADER_LEN: usize = 128;

/// Offset of the header within the image: `0x4000 - 128`.
pub const HEADER_OFFSET: usize = FW_HEADER_OFFSET as usize;

/// Byte range of the 64-byte signature field within the image. This is the only
/// region excluded from the digest. Source: firmware-signing.md §2 [C]
pub const SIG_START: usize = HEADER_OFFSET + 64; // 0x3FC0
pub const SIG_END: usize = HEADER_OFFSET + HEADER_LEN; // 0x4000

/// `firmware_length` must be a multiple of this. Source: firmware-signing.md §1 [C]
pub const LENGTH_ALIGN: u32 = 512;

/// Field offsets within the header. Source: firmware-signing.md §1 [C]
mod off {
    pub const MAGIC: usize = 0;
    pub const TIMESTAMP: usize = 4;
    pub const VERSION: usize = 12;
    pub const PUBKEY_NUM: usize = 20;
    pub const FIRMWARE_LENGTH: usize = 24;
    pub const INSTALL_FLAGS: usize = 28;
    pub const HW_COMPAT: usize = 32;
    pub const FUTURE: usize = 36;
    pub const SIGNATURE: usize = 64;
}

/// `hw_compat` permit-list bits. Zero means "any hardware".
/// Source: firmware-signing.md §1 [C]
pub mod hw_compat {
    pub const MK_1: u32 = 0x01;
    pub const MK_2: u32 = 0x02;
    pub const MK_3: u32 = 0x04;
    pub const MK_4: u32 = 0x08;
    pub const MK_5: u32 = 0x10;
    /// Accepted on anything.
    pub const ANY: u32 = 0x00;
}

/// `install_flags` bits.
///
/// Only one bit is documented in the reference; the rest are unknown and must be left
/// clear. Source: firmware-signing.md §1, install-and-usb-transport.md §2 [C] for
/// HIGH_WATER; remaining bits `[?]`.
pub mod install_flags {
    /// Boot records this image's timestamp as the new anti-downgrade high-water mark.
    /// Setting this makes the install **irreversible**: older images stop being
    /// accepted by the bootloader from then on.
    pub const HIGH_WATER: u32 = 0x01;
}

/// The number of signing keys compiled into the bootloader. Slot 0 is the published
/// developer key; 1..=5 are Coinkite production keys.
/// Source: firmware-signing.md §4 [C]
pub const NUM_PUBKEYS: u32 = 6;
/// The one key slot available to third parties. Images signed with it boot with a
/// 25-second warning and a red "not genuine" light.
pub const DEV_PUBKEY_NUM: u32 = 0;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Error {
    /// Image is shorter than the header offset + header.
    ImageTooShort {
        len: usize,
        need: usize,
    },
    BadMagic {
        found: u32,
    },
    /// `pubkey_num` must be < 6 or the bootloader rejects the image outright.
    BadPubkeyNum {
        found: u32,
    },
    /// `firmware_length` must be 512-aligned.
    UnalignedLength {
        found: u32,
    },
    /// `firmware_length` disagrees with the actual image size, or overruns flash.
    BadLength {
        found: u32,
        image_len: usize,
    },
    /// Timestamp is not valid packed BCD.
    BadTimestamp,
}

#[cfg(feature = "std")]
impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Error::ImageTooShort { len, need } => {
                write!(f, "image is {len} bytes, need at least {need}")
            }
            Error::BadMagic { found } => {
                write!(f, "bad header magic {found:#010x}, expected {MAGIC:#010x}")
            }
            Error::BadPubkeyNum { found } => {
                write!(
                    f,
                    "pubkey_num {found} is out of range (must be < {NUM_PUBKEYS})"
                )
            }
            Error::UnalignedLength { found } => {
                write!(
                    f,
                    "firmware_length {found} is not a multiple of {LENGTH_ALIGN}"
                )
            }
            Error::BadLength { found, image_len } => {
                write!(
                    f,
                    "firmware_length {found} does not match image size {image_len}"
                )
            }
            Error::BadTimestamp => write!(f, "timestamp is not valid BCD"),
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for Error {}

/// A parsed firmware header.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FirmwareHeader {
    pub magic: u32,
    /// Packed BCD `YYMMDDHHMMSS0000`, big-endian digit order. Must strictly increase
    /// across releases or the bootloader treats the image as a downgrade.
    pub timestamp: [u8; 8],
    /// NUL-padded ASCII, humans only.
    pub version: [u8; 8],
    pub pubkey_num: u32,
    /// Total signed image length; 512-aligned; marks the end of the image in flash.
    pub firmware_length: u32,
    pub install_flags: u32,
    pub hw_compat: u32,
    pub future: [u8; 28],
    /// secp256k1 ECDSA over the double-SHA256 digest, raw `r || s`.
    pub signature: [u8; 64],
}

impl Default for FirmwareHeader {
    fn default() -> Self {
        Self {
            magic: MAGIC,
            timestamp: [0; 8],
            version: [0; 8],
            pubkey_num: DEV_PUBKEY_NUM,
            firmware_length: 0,
            install_flags: 0,
            hw_compat: hw_compat::ANY,
            future: [0; 28],
            signature: [0; 64],
        }
    }
}

fn rd_u32(b: &[u8], at: usize) -> u32 {
    u32::from_le_bytes([b[at], b[at + 1], b[at + 2], b[at + 3]])
}

impl FirmwareHeader {
    /// Decode a 128-byte header. Does not validate; use [`Self::validate`].
    pub fn from_bytes(b: &[u8; HEADER_LEN]) -> Self {
        let mut timestamp = [0u8; 8];
        timestamp.copy_from_slice(&b[off::TIMESTAMP..off::TIMESTAMP + 8]);
        let mut version = [0u8; 8];
        version.copy_from_slice(&b[off::VERSION..off::VERSION + 8]);
        let mut future = [0u8; 28];
        future.copy_from_slice(&b[off::FUTURE..off::FUTURE + 28]);
        let mut signature = [0u8; 64];
        signature.copy_from_slice(&b[off::SIGNATURE..off::SIGNATURE + 64]);

        Self {
            magic: rd_u32(b, off::MAGIC),
            timestamp,
            version,
            pubkey_num: rd_u32(b, off::PUBKEY_NUM),
            firmware_length: rd_u32(b, off::FIRMWARE_LENGTH),
            install_flags: rd_u32(b, off::INSTALL_FLAGS),
            hw_compat: rd_u32(b, off::HW_COMPAT),
            future,
            signature,
        }
    }

    pub fn to_bytes(&self) -> [u8; HEADER_LEN] {
        let mut b = [0u8; HEADER_LEN];
        b[off::MAGIC..off::MAGIC + 4].copy_from_slice(&self.magic.to_le_bytes());
        b[off::TIMESTAMP..off::TIMESTAMP + 8].copy_from_slice(&self.timestamp);
        b[off::VERSION..off::VERSION + 8].copy_from_slice(&self.version);
        b[off::PUBKEY_NUM..off::PUBKEY_NUM + 4].copy_from_slice(&self.pubkey_num.to_le_bytes());
        b[off::FIRMWARE_LENGTH..off::FIRMWARE_LENGTH + 4]
            .copy_from_slice(&self.firmware_length.to_le_bytes());
        b[off::INSTALL_FLAGS..off::INSTALL_FLAGS + 4]
            .copy_from_slice(&self.install_flags.to_le_bytes());
        b[off::HW_COMPAT..off::HW_COMPAT + 4].copy_from_slice(&self.hw_compat.to_le_bytes());
        b[off::FUTURE..off::FUTURE + 28].copy_from_slice(&self.future);
        b[off::SIGNATURE..off::SIGNATURE + 64].copy_from_slice(&self.signature);
        b
    }

    /// Read the header out of a whole image.
    pub fn from_image(image: &[u8]) -> Result<Self, Error> {
        let need = HEADER_OFFSET + HEADER_LEN;
        if image.len() < need {
            return Err(Error::ImageTooShort {
                len: image.len(),
                need,
            });
        }
        let mut raw = [0u8; HEADER_LEN];
        raw.copy_from_slice(&image[HEADER_OFFSET..need]);
        Ok(Self::from_bytes(&raw))
    }

    /// The checks the bootloader makes before it will even consider the signature.
    pub fn validate(&self, image_len: usize) -> Result<(), Error> {
        if self.magic != MAGIC {
            return Err(Error::BadMagic { found: self.magic });
        }
        if self.pubkey_num >= NUM_PUBKEYS {
            return Err(Error::BadPubkeyNum {
                found: self.pubkey_num,
            });
        }
        if self.firmware_length % LENGTH_ALIGN != 0 {
            return Err(Error::UnalignedLength {
                found: self.firmware_length,
            });
        }
        if self.firmware_length as usize != image_len {
            return Err(Error::BadLength {
                found: self.firmware_length,
                image_len,
            });
        }
        if !is_bcd(&self.timestamp) {
            return Err(Error::BadTimestamp);
        }
        Ok(())
    }

    /// True if this image can only be signed by a key we do not have.
    pub fn is_factory_signed(&self) -> bool {
        self.pubkey_num != DEV_PUBKEY_NUM
    }

    /// The version string, trimmed at the first NUL. `None` if not valid ASCII.
    pub fn version_str(&self) -> Option<&str> {
        let end = self.version.iter().position(|&c| c == 0).unwrap_or(8);
        core::str::from_utf8(&self.version[..end]).ok()
    }
}

fn is_bcd(b: &[u8]) -> bool {
    b.iter().all(|&x| (x >> 4) <= 9 && (x & 0xf) <= 9)
}

/// Pack a UTC timestamp into the header's BCD field: `YYMMDDHHMMSS0000`.
///
/// `year` is the full year; only the last two digits are stored, which is what the
/// bootloader compares. Source: firmware-signing.md §1 [C]
pub fn pack_timestamp(year: u32, month: u32, day: u32, hour: u32, min: u32, sec: u32) -> [u8; 8] {
    fn bcd(v: u32) -> u8 {
        (((v / 10) % 10) as u8) << 4 | ((v % 10) as u8)
    }
    [
        bcd(year % 100),
        bcd(month),
        bcd(day),
        bcd(hour),
        bcd(min),
        bcd(sec),
        0,
        0,
    ]
}

/// The 32-byte digest the bootloader signs and verifies.
///
/// Double SHA-256 over the whole image with **only** the 64-byte signature field
/// excised. Every other header field is therefore covered and cannot be altered
/// without invalidating the signature.
///
/// ```text
/// inner  = SHA256( image[0 .. 0x3FC0] || image[0x4000 .. firmware_length] )
/// digest = SHA256( inner )
/// ```
///
/// Source: firmware-signing.md §2 [C]
pub fn signed_digest(image: &[u8]) -> Result<[u8; 32], Error> {
    if image.len() < SIG_END {
        return Err(Error::ImageTooShort {
            len: image.len(),
            need: SIG_END,
        });
    }
    let mut inner = Sha256::new();
    inner.update(&image[..SIG_START]);
    inner.update(&image[SIG_END..]);
    let digest = Sha256::digest(inner.finalize());
    Ok(digest.into())
}

/// Write `header` into `image` at the fixed offset.
pub fn place_header(image: &mut [u8], header: &FirmwareHeader) -> Result<(), Error> {
    let need = HEADER_OFFSET + HEADER_LEN;
    if image.len() < need {
        return Err(Error::ImageTooShort {
            len: image.len(),
            need,
        });
    }
    image[HEADER_OFFSET..need].copy_from_slice(&header.to_bytes());
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn blank_image(len: usize) -> Vec<u8> {
        vec![0u8; len]
    }

    #[test]
    fn offsets_match_the_spec() {
        assert_eq!(HEADER_OFFSET, 0x3F80);
        assert_eq!(SIG_START, 0x3FC0);
        assert_eq!(SIG_END, 0x4000);
        assert_eq!(HEADER_LEN, FW_HEADER_SIZE as usize);
    }

    #[test]
    fn header_roundtrips() {
        let h = FirmwareHeader {
            magic: MAGIC,
            timestamp: pack_timestamp(2026, 8, 2, 14, 30, 5),
            version: *b"0.0.1\0\0\0",
            pubkey_num: 0,
            firmware_length: 0x8000,
            install_flags: 0,
            hw_compat: hw_compat::MK_3,
            future: [0; 28],
            signature: [0xab; 64],
        };
        assert_eq!(FirmwareHeader::from_bytes(&h.to_bytes()), h);
    }

    #[test]
    fn header_is_little_endian_at_the_documented_offsets() {
        let h = FirmwareHeader {
            pubkey_num: 0x0000_0003,
            firmware_length: 0x0001_0000,
            hw_compat: 0x0000_0008,
            ..Default::default()
        };
        let b = h.to_bytes();
        assert_eq!(&b[0..4], &[0x34, 0x12, 0x00, 0xCC]); // magic LE
        assert_eq!(&b[20..24], &[3, 0, 0, 0]);
        assert_eq!(&b[24..28], &[0, 0, 1, 0]);
        assert_eq!(&b[32..36], &[8, 0, 0, 0]);
    }

    #[test]
    fn timestamp_packs_as_bcd() {
        // 2026-08-02 14:30:05 -> 26 08 02 14 30 05 00 00
        assert_eq!(
            pack_timestamp(2026, 8, 2, 14, 30, 5),
            [0x26, 0x08, 0x02, 0x14, 0x30, 0x05, 0x00, 0x00]
        );
        assert!(is_bcd(&pack_timestamp(2026, 12, 31, 23, 59, 59)));
    }

    #[test]
    fn timestamps_compare_as_big_endian_bytes() {
        // The bootloader's downgrade check is an ordering on this field, so packed
        // BCD in YYMMDDHHMMSS order must sort chronologically as a byte string.
        let a = pack_timestamp(2026, 8, 2, 14, 0, 0);
        let b = pack_timestamp(2026, 8, 2, 14, 0, 1);
        let c = pack_timestamp(2026, 9, 1, 0, 0, 0);
        assert!(a < b);
        assert!(b < c);
    }

    #[test]
    fn digest_ignores_only_the_signature_field() {
        let mut img = blank_image(0x8000);
        let base = signed_digest(&img).unwrap();

        // Touching the signature slot must not change the digest.
        img[SIG_START] = 0xff;
        img[SIG_END - 1] = 0xff;
        assert_eq!(signed_digest(&img).unwrap(), base);

        // Touching the byte just before it must.
        img[SIG_START - 1] = 0xff;
        assert_ne!(signed_digest(&img).unwrap(), base);
    }

    #[test]
    fn digest_covers_every_other_header_field() {
        let mut img = blank_image(0x8000);
        let h = FirmwareHeader {
            firmware_length: 0x8000,
            ..Default::default()
        };
        place_header(&mut img, &h).unwrap();
        let base = signed_digest(&img).unwrap();

        for mutate in [
            (|h: &mut FirmwareHeader| h.hw_compat = 0x10) as fn(&mut FirmwareHeader),
            |h: &mut FirmwareHeader| h.install_flags = 1,
            |h: &mut FirmwareHeader| h.pubkey_num = 2,
            |h: &mut FirmwareHeader| h.timestamp = pack_timestamp(2030, 1, 1, 0, 0, 0),
            |h: &mut FirmwareHeader| h.version = *b"9.9.9\0\0\0",
        ] {
            let mut h2 = h.clone();
            mutate(&mut h2);
            let mut img2 = img.clone();
            place_header(&mut img2, &h2).unwrap();
            assert_ne!(
                signed_digest(&img2).unwrap(),
                base,
                "a mutated header field left the digest unchanged"
            );
        }
    }

    #[test]
    fn digest_is_a_double_sha256() {
        let img = blank_image(0x4200);
        let mut inner = Sha256::new();
        inner.update(&img[..SIG_START]);
        inner.update(&img[SIG_END..]);
        let expect: [u8; 32] = Sha256::digest(inner.finalize()).into();
        assert_eq!(signed_digest(&img).unwrap(), expect);
    }

    #[test]
    fn validate_rejects_the_bootloaders_reasons() {
        let len = 0x8000usize;
        let ok = FirmwareHeader {
            firmware_length: len as u32,
            timestamp: pack_timestamp(2026, 8, 2, 0, 0, 0),
            ..Default::default()
        };
        assert!(ok.validate(len).is_ok());

        let mut h = ok.clone();
        h.magic = 0;
        assert!(matches!(h.validate(len), Err(Error::BadMagic { .. })));

        let mut h = ok.clone();
        h.pubkey_num = NUM_PUBKEYS;
        assert!(matches!(h.validate(len), Err(Error::BadPubkeyNum { .. })));

        let mut h = ok.clone();
        h.firmware_length = 0x8001;
        assert!(matches!(
            h.validate(0x8001),
            Err(Error::UnalignedLength { .. })
        ));

        let mut h = ok.clone();
        h.timestamp = [0xff; 8];
        assert!(matches!(h.validate(len), Err(Error::BadTimestamp)));

        assert!(matches!(
            ok.validate(len + 512),
            Err(Error::BadLength { .. })
        ));
    }

    #[test]
    fn short_image_is_an_error_not_a_panic() {
        assert!(matches!(
            signed_digest(&blank_image(0x100)),
            Err(Error::ImageTooShort { .. })
        ));
        assert!(matches!(
            FirmwareHeader::from_image(&blank_image(0x100)),
            Err(Error::ImageTooShort { .. })
        ));
    }

    #[test]
    fn version_string_trims_at_nul() {
        let h = FirmwareHeader {
            version: *b"0.1.0\0\0\0",
            ..Default::default()
        };
        assert_eq!(h.version_str(), Some("0.1.0"));
    }
}
