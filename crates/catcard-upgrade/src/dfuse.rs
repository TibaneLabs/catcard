//! Finding the firmware inside a DfuSe container.
//!
//! A `.dfu` is what `catcard-image` writes and what goes on a microSD card, so a device
//! reading a card meets the wrapper rather than the image. Over USB this is the host's
//! job — the wrapper is unpacked by `tools/usbclient.py` and the device never sees one —
//! and that split is deliberate: the USB parser is reachable by anything that can open
//! the port, so it stays as small as it can be.
//!
//! A card is different only in degree, not in kind: the bytes are still someone else's.
//! So this reads **fixed offsets and nothing else**. It walks no chains, trusts no
//! length it has not bounded, and hands back a range for the caller to stream — the
//! image inside is signature-checked afterwards regardless, by the same code that checks
//! one arriving over USB.
//!
//! Layout, from `tools/catcard-image/src/dfuse.rs` which writes it:
//!
//! ```text
//! 0   prefix  11  "DfuSe" | version=1 | image size u32 | targets u8
//! 11  target 274  "Target" | alt u8 | named u32 | name[255] | size u32 | elements u32
//! 285 element   8  address u32 | size u32
//! 293 the image itself
//! ```

/// Where the firmware sits inside the container.
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub struct Element {
    /// Byte offset of the image within the file.
    pub offset: u32,
    /// Length of the image.
    pub len: u32,
    /// Where the container says it should be flashed. Not acted on — the bootloader
    /// decides that — but wrong values are a sign the file is not what it claims.
    pub address: u32,
}

/// Why a container was refused.
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub enum NotDfuSe {
    /// Shorter than the headers it must contain.
    TooShort,
    /// No `DfuSe` signature: this is a raw image, or not ours at all.
    NoSignature,
    /// A DfuSe version this does not read.
    Version(u8),
    /// More than one target or element. `catcard-image` writes exactly one of each, and
    /// picking the "right" one out of several is a judgement this should not make.
    NotSingle { targets: u8, elements: u32 },
    /// The element runs past the end of the file.
    Truncated { need: u64, have: u64 },
}

/// Bytes of header before the image starts.
pub const HEADER_LEN: u32 = 11 + 274 + 8;

/// Locate the image, given the first [`HEADER_LEN`] bytes and the file's total size.
///
/// `head` may be longer; only the first [`HEADER_LEN`] bytes are read. A file with no
/// DfuSe signature is not an error the caller must treat as fatal — a raw `.bin` is a
/// perfectly good thing to find on a card — so that case is distinguishable.
pub fn locate(head: &[u8], file_len: u64) -> Result<Element, NotDfuSe> {
    if head.len() < HEADER_LEN as usize {
        return Err(NotDfuSe::TooShort);
    }
    if &head[..5] != b"DfuSe" {
        return Err(NotDfuSe::NoSignature);
    }
    if head[5] != 1 {
        return Err(NotDfuSe::Version(head[5]));
    }
    let targets = head[10];
    if targets != 1 {
        return Err(NotDfuSe::NotSingle {
            targets,
            elements: 0,
        });
    }
    if &head[11..17] != b"Target" {
        return Err(NotDfuSe::NoSignature);
    }
    let elements = u32::from_le_bytes([head[281], head[282], head[283], head[284]]);
    if elements != 1 {
        return Err(NotDfuSe::NotSingle { targets, elements });
    }
    let address = u32::from_le_bytes([head[285], head[286], head[287], head[288]]);
    let len = u32::from_le_bytes([head[289], head[290], head[291], head[292]]);

    // The element must fit in the file, with the 16-byte DFU suffix still to come after
    // it. Checked in u64 so a length near u32::MAX cannot wrap into looking reasonable.
    let need = HEADER_LEN as u64 + len as u64;
    if need > file_len {
        return Err(NotDfuSe::Truncated {
            need,
            have: file_len,
        });
    }
    Ok(Element {
        offset: HEADER_LEN,
        len,
        address,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A container with one target and one element, as `catcard-image` writes.
    fn container(len: u32, address: u32, targets: u8, elements: u32) -> [u8; 293] {
        let mut h = [0u8; 293];
        h[..5].copy_from_slice(b"DfuSe");
        h[5] = 1;
        h[10] = targets;
        h[11..17].copy_from_slice(b"Target");
        h[281..285].copy_from_slice(&elements.to_le_bytes());
        h[285..289].copy_from_slice(&address.to_le_bytes());
        h[289..293].copy_from_slice(&len.to_le_bytes());
        h
    }

    #[test]
    fn the_image_starts_after_the_headers() {
        let h = container(262_144, 0x0802_0000, 1, 1);
        assert_eq!(
            locate(&h, 293 + 262_144 + 16),
            Ok(Element {
                offset: 293,
                len: 262_144,
                address: 0x0802_0000,
            })
        );
    }

    /// A raw `.bin` is a legitimate thing to find, and must be distinguishable from a
    /// broken container rather than lumped in with one.
    #[test]
    fn a_raw_image_is_reported_as_having_no_signature() {
        let mut raw = [0u8; 293];
        raw[0] = 0xFF;
        assert_eq!(locate(&raw, 262_144), Err(NotDfuSe::NoSignature));
    }

    #[test]
    fn a_truncated_file_is_refused_rather_than_read_past() {
        let h = container(262_144, 0, 1, 1);
        assert_eq!(
            locate(&h, 1000),
            Err(NotDfuSe::Truncated {
                need: 293 + 262_144,
                have: 1000
            })
        );
    }

    /// The length is attacker-supplied. Near `u32::MAX` it must not wrap into a range
    /// that looks like it fits.
    #[test]
    fn an_absurd_length_cannot_wrap_into_looking_valid() {
        let h = container(u32::MAX, 0, 1, 1);
        assert!(matches!(locate(&h, 300), Err(NotDfuSe::Truncated { .. })));
    }

    #[test]
    fn several_targets_or_elements_are_refused_not_guessed_between() {
        assert!(matches!(
            locate(&container(10, 0, 2, 1), 10_000),
            Err(NotDfuSe::NotSingle { targets: 2, .. })
        ));
        assert!(matches!(
            locate(&container(10, 0, 1, 3), 10_000),
            Err(NotDfuSe::NotSingle { elements: 3, .. })
        ));
    }

    #[test]
    fn a_short_file_and_a_wrong_version_are_each_their_own_error() {
        assert_eq!(locate(&[0u8; 8], 8), Err(NotDfuSe::TooShort));
        let mut h = container(10, 0, 1, 1);
        h[5] = 2;
        assert_eq!(locate(&h, 10_000), Err(NotDfuSe::Version(2)));
    }
}
