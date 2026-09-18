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

use purecrypto::hash::{Digest, Sha256};

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

/// Smallest `firmware_length` the bootloader accepts, on every generation.
///
/// Out-of-range images are rejected *before* any signature work, so a too-small image
/// fails with no diagnosis about its contents. A minimal firmware has to be padded up to
/// this whether or not it uses the space. Source: firmware-signing.md §1 [C]
pub const MIN_FIRMWARE_LENGTH: u32 = 256 * 1024;

/// Field offsets within the header, relative to [`HEADER_OFFSET`].
///
/// Public because anything that has to reason about a header *in an image* — rather
/// than about a parsed one — needs them, and reproducing the numbers at each call site
/// is how two copies drift apart. Source: firmware-signing.md §1 [C]
pub mod off {
    pub const MAGIC: usize = 0;
    pub const TIMESTAMP: usize = 4;
    pub const VERSION: usize = 12;
    pub const PUBKEY_NUM: usize = 20;
    pub const FIRMWARE_LENGTH: usize = 24;
    pub const INSTALL_FLAGS: usize = 28;
    pub const HW_COMPAT: usize = 32;
    pub const BEST_TS: usize = 36;
    pub const FUTURE: usize = 44;
    pub const SIGNATURE: usize = 64;
}

/// `hw_compat` permit-list bits. Zero means "any hardware".
/// Source: firmware-signing.md §1 [C]
pub mod hw_compat {
    pub const MK_1: u32 = 0x01;
    pub const MK_2: u32 = 0x02;
    pub const MK_3: u32 = 0x04;
    pub const MK_4: u32 = 0x08;
    /// **Q1**, not mk5. An earlier revision of the reference gave `0x10` as `MK_5_OK`;
    /// it is `MK_Q1_OK`. A build that set `0x10` meaning "mk5" was claiming Q1
    /// compatibility.
    pub const MK_Q1: u32 = 0x10;
    pub const MK_5: u32 = 0x20;
    /// Accepted on anything.
    pub const ANY: u32 = 0x00;

    /// Every bit the reference defines.
    pub const DEFINED: u32 = MK_1 | MK_2 | MK_3 | MK_4 | MK_Q1 | MK_5;
}

/// `install_flags` bits. No others are defined.
/// Source: firmware-signing.md §1 [C]
pub mod install_flags {
    /// Boot records this image's timestamp as the new anti-downgrade high-water mark.
    /// Setting this makes the install **irreversible**: older images stop being
    /// accepted by the bootloader from then on.
    pub const HIGH_WATER: u32 = 0x01;
    /// The header's `best_ts` carries a recommended minimum timestamp.
    pub const BEST_TS: u32 = 0x02;

    /// Every bit the reference defines. Anything else must be left clear.
    pub const DEFINED: u32 = HIGH_WATER | BEST_TS;
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
    /// `firmware_length` is outside the bounds the bootloader enforces. Rejected before
    /// any signature work, so a too-small image fails with no clue about its contents.
    LengthOutOfBounds {
        found: u32,
        min: u32,
        max: Option<u32>,
    },
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
            Error::LengthOutOfBounds { found, min, max } => match max {
                Some(max) => write!(
                    f,
                    "firmware_length {found} is outside the bootloader's bounds [{min}, {max}]"
                ),
                None => write!(f, "firmware_length {found} is below the minimum {min}"),
            },
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
    /// Recommended minimum timestamp for downgrade protection. Meaningful only when
    /// `install_flags & BEST_TS` is set. Source: firmware-signing.md §1 [C]
    pub best_ts: [u8; 8],
    pub future: [u8; 20],
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
            best_ts: [0; 8],
            future: [0; 20],
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
        let mut best_ts = [0u8; 8];
        best_ts.copy_from_slice(&b[off::BEST_TS..off::BEST_TS + 8]);
        let mut future = [0u8; 20];
        future.copy_from_slice(&b[off::FUTURE..off::FUTURE + 20]);
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
            best_ts,
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
        b[off::BEST_TS..off::BEST_TS + 8].copy_from_slice(&self.best_ts);
        b[off::FUTURE..off::FUTURE + 20].copy_from_slice(&self.future);
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
        if !self.firmware_length.is_multiple_of(LENGTH_ALIGN) {
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
        if self.firmware_length < MIN_FIRMWARE_LENGTH {
            return Err(Error::LengthOutOfBounds {
                found: self.firmware_length,
                min: MIN_FIRMWARE_LENGTH,
                max: None,
            });
        }
        if !is_bcd(&self.timestamp) {
            return Err(Error::BadTimestamp);
        }
        Ok(())
    }

    /// The upper length bound, which is per-board and so cannot be checked by
    /// [`Self::validate`] alone.
    ///
    /// `max_length` is the board's firmware region: `0x0F8000` on mk3, `0x1E0000` on
    /// mk4-class. Source: firmware-signing.md §1 [C]
    pub fn check_max_length(&self, max_length: u32) -> Result<(), Error> {
        if self.firmware_length > max_length {
            return Err(Error::LengthOutOfBounds {
                found: self.firmware_length,
                min: MIN_FIRMWARE_LENGTH,
                max: Some(max_length),
            });
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

/// The build time as `YYYY-MM-DD HH:MM`, from the header's BCD timestamp.
///
/// What a person actually compares when deciding whether an image is the one they meant
/// to install: two builds of the same firmware carry the same version string and differ
/// only here. The century is assumed, because the header stores two digits of year --
/// that is what the bootloader compares, so it is all there is.
///
/// Invalid BCD renders as `?`, rather than as arithmetic on nibbles that are not digits.
pub fn format_timestamp(ts: &[u8; 8]) -> [u8; 16] {
    let mut out = *b"20??-??-?? ??:??";
    let digits = |v: u8| -> Option<(u8, u8)> {
        let (hi, lo) = (v >> 4, v & 0xF);
        (hi <= 9 && lo <= 9).then_some((b'0' + hi, b'0' + lo))
    };
    // Where each BCD byte's two digits land in `YYYY-MM-DD HH:MM`.
    for (byte, at) in [(0usize, 2usize), (1, 5), (2, 8), (3, 11), (4, 14)] {
        if let Some((hi, lo)) = digits(ts[byte]) {
            out[at] = hi;
            out[at + 1] = lo;
        }
    }
    out
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
    Ok(Sha256::digest(&inner.finalize()))
}

/// [`signed_digest`], computed over an image fed in pieces.
///
/// The whole image does not have to be in RAM at once, which on a 256 KB minimum it
/// cannot be. Feed the bytes in order from offset 0; the signature window is skipped
/// for you.
///
/// Use it over the image **as stored**, not as received. Those differ exactly when the
/// staging memory is faulty, which is the case worth catching: a digest taken on the way
/// in would agree with the host and disagree with what the bootloader installs.
#[derive(Clone)]
pub struct DigestStream {
    inner: Sha256,
    at: usize,
}

impl Default for DigestStream {
    fn default() -> Self {
        Self::new()
    }
}

impl DigestStream {
    pub fn new() -> Self {
        Self {
            inner: Sha256::new(),
            at: 0,
        }
    }

    /// Feed the next bytes of the image, in order.
    pub fn update(&mut self, bytes: &[u8]) {
        let mut off = self.at;
        for chunk in bytes.chunks(1) {
            if !(SIG_START..SIG_END).contains(&off) {
                self.inner.update(chunk);
            }
            off += 1;
        }
        self.at = off;
    }

    /// How many bytes have been fed.
    pub fn position(&self) -> usize {
        self.at
    }

    /// The double-SHA256 digest.
    pub fn finish(self) -> [u8; 32] {
        Sha256::digest(&self.inner.finalize())
    }
}

/// `approved_pubkeys[0]` — the published developer key, raw `X || Y`.
///
/// Public by design: Coinkite publishes the matching private key so anyone can build
/// firmware a Coldcard bootloader will load. It grants **no authenticity** — it is here
/// so a device can tell "this is the image the host meant to send" from "this is
/// corrupt", which is a different question from "this is trustworthy".
///
/// The five factory keys are not published, so an image signed with one of those cannot
/// be checked before installing it. See `catcard-upgrade`.
/// Source: firmware-signing.md §4 [C].
pub const DEV_PUBKEY: [u8; 64] = APPROVED_PUBKEYS[DEV_PUBKEY_NUM as usize];

/// The bootloader's `approved_pubkeys[]`: the six secp256k1 public keys (uncompressed
/// `X‖Y`, 64 bytes, no `0x04` prefix) a firmware image's `pubkey_num` selects between. A
/// signature is checked against exactly one of these. Slot 0 is the published developer
/// key (its private half is public, so a slot-0 signature attests nothing); slots 1..=5
/// are Coinkite production keys whose private halves are secret.
///
/// Having all six lets this firmware *report* an image's real signing key -- including a
/// production-signed image it did not build -- rather than only its own dev key. It cannot
/// forge any of them; verification only reads them.
///
/// Per generation: slots 0..=4 exist on every board; **slot 5 is enabled only on
/// mk4/mk5/Q1** and `#if 0`-disabled on mk3, so an mk3 bootloader will refuse a slot-5
/// image even with a valid signature.
///
/// Source: hw-reference/firmware-keys/approved-pubkeys.txt and README.md [C], from
/// `stm32/{,mk4-}bootloader/firmware-keys.h` at tag `2026-09-03T1541-v5.6.2`.
pub const APPROVED_PUBKEYS: [[u8; 64]; NUM_PUBKEYS as usize] = [
    // [0] dev-shared (private key published)
    [
        0xb4, 0xcb, 0x41, 0x26, 0xf7, 0xe1, 0x6c, 0xf3, 0x8f, 0xf2, 0xb4, 0x71, 0x1d, 0xfb, 0x23,
        0x01, 0x0d, 0x76, 0xd6, 0x66, 0xa7, 0x8a, 0xa3, 0x6c, 0x9b, 0x53, 0xf9, 0xf6, 0x7b, 0x58,
        0x18, 0x05, 0x58, 0x0b, 0x3b, 0xe9, 0x31, 0xc4, 0x9f, 0xb8, 0x44, 0x04, 0x3c, 0x11, 0x96,
        0x08, 0x0f, 0x47, 0x81, 0x25, 0xed, 0x37, 0x7a, 0x23, 0x9e, 0x4a, 0xaf, 0xb7, 0x18, 0x38,
        0xba, 0x38, 0x04, 0xda,
    ],
    // [1] Coinkite production (the key every shipped release is signed with)
    [
        0xd6, 0xa2, 0xc8, 0x1d, 0x1c, 0x81, 0x5e, 0xdf, 0xa6, 0x0c, 0x29, 0x6d, 0xb8, 0x57, 0x8f,
        0x8d, 0x5e, 0x29, 0x69, 0x92, 0xce, 0xd1, 0x78, 0xc1, 0x7b, 0x20, 0xd7, 0x31, 0x7b, 0xa1,
        0x96, 0xb5, 0x3d, 0xef, 0x1b, 0x0c, 0xaa, 0x79, 0x1a, 0xc3, 0x45, 0x58, 0xc4, 0xc8, 0x8a,
        0x2d, 0xeb, 0xff, 0xfe, 0x9b, 0x82, 0x01, 0x87, 0x5f, 0x5e, 0xbc, 0x96, 0xa5, 0xe5, 0x4f,
        0xc7, 0x68, 0xfe, 0x9f,
    ],
    // [2] Coinkite production (reserved for future use)
    [
        0x42, 0xef, 0x66, 0x01, 0x56, 0xc4, 0xcf, 0x95, 0xf4, 0xb5, 0xf0, 0x38, 0x64, 0x11, 0x26,
        0xc5, 0x99, 0x39, 0xc1, 0x66, 0x32, 0x06, 0x12, 0x14, 0x4c, 0x25, 0x9c, 0x68, 0x35, 0x8c,
        0xd3, 0xba, 0x24, 0x78, 0xde, 0x8c, 0x52, 0xab, 0xdf, 0x6c, 0xb8, 0xbf, 0x09, 0x78, 0x03,
        0xbb, 0x63, 0x3a, 0x11, 0x01, 0xd9, 0x0e, 0xa4, 0x7a, 0x73, 0x8f, 0xbf, 0x18, 0x3b, 0x7f,
        0xf0, 0x0a, 0x7b, 0xc8,
    ],
    // [3] Coinkite production (reserved for future use)
    [
        0x67, 0x60, 0x54, 0x56, 0x82, 0x0c, 0xec, 0xc5, 0x1d, 0xbc, 0x82, 0x08, 0x16, 0xc1, 0x39,
        0xef, 0xf5, 0xbf, 0xba, 0x32, 0x7c, 0xce, 0x5f, 0xe3, 0x74, 0x1e, 0x62, 0xd7, 0xe9, 0xfc,
        0xc5, 0x4c, 0x8a, 0xe8, 0x11, 0x8d, 0xc3, 0xad, 0xc2, 0x13, 0x92, 0x29, 0x4f, 0x2a, 0xea,
        0xd2, 0xf8, 0xa4, 0xc4, 0xd5, 0x7c, 0xfe, 0x12, 0x05, 0x45, 0x3b, 0x54, 0x89, 0x59, 0x07,
        0xda, 0xd6, 0xd7, 0x88,
    ],
    // [4] Coinkite production (reserved for future use)
    [
        0x43, 0xb1, 0xcf, 0x37, 0xd2, 0x7c, 0x89, 0x1f, 0x5b, 0xfe, 0xac, 0xf3, 0xba, 0x33, 0xfc,
        0x95, 0x81, 0xd9, 0xe7, 0xdd, 0x25, 0x95, 0xef, 0x14, 0xdd, 0xef, 0x97, 0xbb, 0x33, 0xf3,
        0xd8, 0xa7, 0x34, 0x2b, 0x7a, 0x97, 0xba, 0xb3, 0xaa, 0x73, 0xe7, 0x9d, 0x41, 0x32, 0xd8,
        0xfc, 0xa1, 0x17, 0x66, 0xb5, 0x0b, 0xfe, 0x63, 0x40, 0x21, 0x89, 0xc9, 0x92, 0x7b, 0x8e,
        0x72, 0xdf, 0x0b, 0x59,
    ],
    // [5] Coinkite production (reserved) -- enabled on mk4/mk5/Q1, disabled on mk3
    [
        0xd0, 0x5c, 0xdc, 0x76, 0x16, 0x30, 0xdd, 0x30, 0xc2, 0x80, 0xf1, 0x56, 0x26, 0x5c, 0xa8,
        0x61, 0xd7, 0x4f, 0x69, 0x69, 0xe5, 0xb8, 0x57, 0x3d, 0x35, 0xe2, 0x2a, 0x58, 0xdd, 0xce,
        0x9a, 0xc6, 0x45, 0xa9, 0x1c, 0x2b, 0x0c, 0x01, 0xfc, 0x8e, 0xbf, 0x3f, 0x51, 0x13, 0x80,
        0x7e, 0x7c, 0x13, 0xd5, 0x4f, 0x4b, 0x5e, 0x9b, 0x4c, 0x9b, 0xd5, 0x9e, 0x1d, 0xd8, 0xe0,
        0xad, 0xc0, 0x46, 0x22,
    ],
];

/// Whether a signing slot is a Coinkite production key (1..=5) rather than the published
/// developer key (0). `hw-reference/firmware-keys/README.md`: `IS_FACTORY_KEY(n) = n != 0`.
pub const fn is_factory_key(slot: u32) -> bool {
    slot != DEV_PUBKEY_NUM
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

    /// The smallest image the bootloader would actually accept. Tests that call
    /// `validate` have to use a realistic size, or they assert about images no device
    /// would take.
    fn min_len() -> usize {
        MIN_FIRMWARE_LENGTH as usize
    }

    #[test]
    fn offsets_match_the_spec() {
        assert_eq!(HEADER_OFFSET, 0x3F80);
        assert_eq!(SIG_START, 0x3FC0);
        assert_eq!(SIG_END, 0x4000);
        assert_eq!(HEADER_LEN, FW_HEADER_SIZE as usize);
    }

    #[test]
    fn approved_pubkeys_table_is_well_formed() {
        assert_eq!(APPROVED_PUBKEYS.len(), NUM_PUBKEYS as usize);
        // Slot 0 is the dev key, and DEV_PUBKEY is defined from it.
        assert_eq!(DEV_PUBKEY, APPROVED_PUBKEYS[DEV_PUBKEY_NUM as usize]);
        // The published dev key begins b4cb4126... (hw-reference/firmware-keys).
        assert_eq!(&APPROVED_PUBKEYS[0][..4], &[0xb4, 0xcb, 0x41, 0x26]);
        // Production key 1 -- what every shipped release is signed with -- begins d6a2c81d.
        assert_eq!(&APPROVED_PUBKEYS[1][..4], &[0xd6, 0xa2, 0xc8, 0x1d]);
        // Every key is distinct; a copy-paste slip would alias two slots.
        for (i, a) in APPROVED_PUBKEYS.iter().enumerate() {
            for (j, b) in APPROVED_PUBKEYS.iter().enumerate().skip(i + 1) {
                assert_ne!(a, b, "slots {i} and {j}");
            }
        }
        assert!(!is_factory_key(0));
        assert!((1..=5).all(is_factory_key));
    }

    #[test]
    fn header_roundtrips() {
        let h = FirmwareHeader {
            magic: MAGIC,
            timestamp: pack_timestamp(2026, 8, 2, 14, 30, 5),
            version: *b"0.0.1\0\0\0",
            pubkey_num: 0,
            firmware_length: MIN_FIRMWARE_LENGTH,
            install_flags: 0,
            hw_compat: hw_compat::MK_3,
            best_ts: [0; 8],
            future: [0; 20],
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
            firmware_length: MIN_FIRMWARE_LENGTH,
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
        let expect: [u8; 32] = Sha256::digest(&inner.finalize());
        assert_eq!(signed_digest(&img).unwrap(), expect);
    }

    #[test]
    fn validate_rejects_the_bootloaders_reasons() {
        let len = min_len();
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
        h.firmware_length = MIN_FIRMWARE_LENGTH + 1;
        assert!(matches!(
            h.validate(min_len() + 1),
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
    fn a_too_small_image_is_rejected() {
        // Found by booting a real CatCard image against a real bootloader: a 62 KB
        // image was refused before any signature work, with no diagnosis about its
        // contents. The bootloader enforces a 256 KB floor on every generation.
        let h = FirmwareHeader {
            firmware_length: 0x_f600,
            timestamp: pack_timestamp(2026, 8, 2, 0, 0, 0),
            ..Default::default()
        };
        assert_eq!(
            h.validate(0xf600),
            Err(Error::LengthOutOfBounds {
                found: 0xf600,
                min: MIN_FIRMWARE_LENGTH,
                max: None
            })
        );
        assert_eq!(MIN_FIRMWARE_LENGTH, 256 * 1024);
    }

    #[test]
    fn the_upper_bound_is_per_board() {
        // 0x0F8000 on mk3, 0x1E0000 on mk4-class — which is each board's whole firmware
        // region, so the board table already carries the right numbers.
        let h = FirmwareHeader {
            firmware_length: 0x10_0000,
            ..Default::default()
        };
        assert!(h.check_max_length(0x1E_0000).is_ok(), "fits an mk4");
        assert!(
            matches!(
                h.check_max_length(0x0F_8000),
                Err(Error::LengthOutOfBounds { max: Some(_), .. })
            ),
            "should not fit an mk3"
        );
        for b in catcard_board::spec::ALL {
            let expect = match b.mcu {
                catcard_board::Mcu::Stm32L496 => 0x0F_8000,
                catcard_board::Mcu::Stm32L4S5 => 0x1E_0000,
            };
            assert_eq!(b.memory.firmware_flash_len, expect, "{}", b.name);
        }
    }

    #[test]
    fn hw_compat_bit_0x10_is_q1_not_mk5() {
        // An earlier revision of the reference gave 0x10 as MK_5_OK. It is MK_Q1_OK, so
        // anything that set 0x10 meaning "mk5" was claiming Q1 compatibility.
        assert_eq!(hw_compat::MK_Q1, 0x10);
        assert_eq!(hw_compat::MK_5, 0x20);
        assert_eq!(hw_compat::DEFINED, 0x3f);

        let q1 = catcard_board::spec::Q1;
        assert_eq!(q1.hw_compat_bit, hw_compat::MK_Q1);
        assert_eq!(
            q1.hw_compat_bit & hw_compat::MK_4,
            0,
            "Q1 must not claim mk4 compatibility"
        );
    }

    #[test]
    fn best_ts_occupies_its_own_field() {
        // The reference previously showed one 28-byte `future`; the real struct splits
        // it into best_ts[8] + future[20]. The signed bytes are the same, so a wrong
        // reading is invisible until something writes best_ts.
        let h = FirmwareHeader {
            best_ts: pack_timestamp(2026, 1, 2, 3, 4, 5),
            install_flags: install_flags::BEST_TS,
            ..Default::default()
        };
        let b = h.to_bytes();
        assert_eq!(&b[36..44], &h.best_ts, "best_ts is at offset 36");
        assert_eq!(&b[44..64], &[0u8; 20], "future starts at 44");
        assert_eq!(FirmwareHeader::from_bytes(&b), h);
        assert_eq!(install_flags::DEFINED, 0x03);
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

#[cfg(test)]
mod stream_tests {
    use super::*;

    /// The streamed digest must equal the one-shot digest whatever the chunk size.
    ///
    /// The signature window starts at `0x3FC0`, which is **not** a multiple of 256: the USB
    /// path feeds 64-byte frames and lands on the boundary, the SD path feeds 256-byte
    /// blocks and straddles it. A stream that only works when the window falls on a chunk
    /// edge passes over USB and fails on a card, which is exactly the shape of bug worth a
    /// test that tries several sizes.
    #[test]
    fn streaming_matches_the_one_shot_digest_at_every_chunk_size() {
        let mut image = alloc_image(0x1_2000);
        let want = signed_digest(&image).unwrap();
        for chunk in [1usize, 3, 7, 64, 100, 256, 512, 1000, 4096] {
            let mut stream = DigestStream::new();
            for part in image.chunks(chunk) {
                stream.update(part);
            }
            assert_eq!(stream.finish(), want, "chunk size {chunk}");
        }
        // And the window really is being skipped: changing a byte inside it must not
        // change the digest, while changing one either side must.
        image[SIG_START + 5] ^= 0xFF;
        assert_eq!(signed_digest(&image).unwrap(), want, "inside the window");
        image[SIG_START - 1] ^= 0xFF;
        assert_ne!(signed_digest(&image).unwrap(), want, "before the window");
    }

    fn alloc_image(len: usize) -> Vec<u8> {
        // Every byte distinct enough that a misplaced one changes the hash.
        (0..len).map(|i| (i.wrapping_mul(31) >> 3) as u8).collect()
    }
}

#[cfg(test)]
mod timestamp_tests {
    use super::*;

    /// The date a person reads off the install screen is the one in the header.
    ///
    /// Two builds of the same firmware carry the same version string; the timestamp is
    /// the only thing that tells them apart, so it has to be right rather than roughly
    /// right.
    #[test]
    fn a_timestamp_renders_as_the_date_it_encodes() {
        let ts = pack_timestamp(2026, 9, 18, 19, 4, 54);
        assert_eq!(&format_timestamp(&ts), b"2026-09-18 19:04");

        // Midnight on the first, where every field is a leading zero.
        let ts = pack_timestamp(2030, 1, 1, 0, 0, 0);
        assert_eq!(&format_timestamp(&ts), b"2030-01-01 00:00");

        // And the end of a year, where nothing is.
        let ts = pack_timestamp(2026, 12, 31, 23, 59, 59);
        assert_eq!(&format_timestamp(&ts), b"2026-12-31 23:59");
    }

    /// A field that is not BCD shows as unknown rather than as a nonsense date.
    ///
    /// The header comes off a card or a USB cable, so its bytes are someone else's until
    /// proven otherwise, and `0xAB` is not a month.
    #[test]
    fn a_field_that_is_not_bcd_reads_as_unknown() {
        let mut ts = pack_timestamp(2026, 9, 18, 19, 4, 0);
        ts[1] = 0xAB;
        assert_eq!(&format_timestamp(&ts), b"2026-??-18 19:04");
    }
}
