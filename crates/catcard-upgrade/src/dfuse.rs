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
//!
//! A stock release `.dfu` has the same shape with a **second element after the first**:
//! the application at the firmware base, then the bootloader at `0x0800_0000`, which a
//! locked unit cannot take anyway. Only element 0 is read, and only if it is addressed at
//! this board's firmware base -- so the second element is never walked to, and a container
//! that puts anything else first is refused rather than searched.
//! Source: hw-reference/firmware-signing.md §"Delivery: the `.dfu` carries the bootloader
//! too" [C]

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
    /// Not exactly one target, or no elements at all.
    NotSingle { targets: u8, elements: u32 },
    /// Element 0 is not addressed at this board's firmware base -- a container that puts
    /// something else first. Choosing among elements is not a judgement this makes.
    WrongAddress { address: u32 },
    /// The element runs past the end of the file.
    Truncated { need: u64, have: u64 },
}

/// Bytes of header before the image starts.
pub const HEADER_LEN: u32 = 11 + 274 + 8;

/// Locate the image, given the first [`HEADER_LEN`] bytes, the file's total size, and the
/// firmware base of the board it is for.
///
/// `head` may be longer; only the first [`HEADER_LEN`] bytes are read. A file with no
/// DfuSe signature is not an error the caller must treat as fatal — a raw `.bin` is a
/// perfectly good thing to find on a card — so that case is distinguishable.
pub fn locate(head: &[u8], file_len: u64, firmware_base: u32) -> Result<Element, NotDfuSe> {
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
    // One element from `catcard-image`, two from a stock release (application, then
    // bootloader). Element 0 is the only one read either way.
    if elements == 0 {
        return Err(NotDfuSe::NotSingle { targets, elements });
    }
    let address = u32::from_le_bytes([head[285], head[286], head[287], head[288]]);
    if address != firmware_base {
        return Err(NotDfuSe::WrongAddress { address });
    }
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

    const BASE: u32 = 0x0802_0000;

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
            locate(&h, 293 + 262_144 + 16, BASE),
            Ok(Element {
                offset: 293,
                len: 262_144,
                address: 0x0802_0000,
            })
        );
    }

    #[test]
    fn a_stock_release_takes_its_application_and_never_reads_the_bootloader() {
        // Stock ships application then bootloader in one container. The application is
        // element 0 at the firmware base, and that is all that is taken: the bootloader
        // element after it stays unread.
        let h = container(262_144, BASE, 1, 2);
        let whole_file = 293 + 262_144 + 8 + 0x1C000 + 16;
        assert_eq!(
            locate(&h, whole_file, BASE),
            Ok(Element {
                offset: 293,
                len: 262_144,
                address: BASE,
            })
        );
    }

    #[test]
    fn a_container_that_leads_with_something_else_is_refused() {
        // A bootloader-first ordering, or a file for another board's base: picking a
        // different element out of it is not a call this makes.
        let h = container(0x7800, 0x0800_0000, 1, 2);
        assert_eq!(
            locate(&h, 293 + 0x7800 + 16, BASE),
            Err(NotDfuSe::WrongAddress {
                address: 0x0800_0000
            })
        );
        let mk3 = container(262_144, 0x0800_8000, 1, 1);
        assert!(matches!(
            locate(&mk3, 293 + 262_144 + 16, BASE),
            Err(NotDfuSe::WrongAddress { .. })
        ));
        assert!(matches!(
            locate(&container(262_144, BASE, 1, 0), 1 << 20, BASE),
            Err(NotDfuSe::NotSingle { .. })
        ));
    }

    /// A raw `.bin` is a legitimate thing to find, and must be distinguishable from a
    /// broken container rather than lumped in with one.
    #[test]
    fn a_raw_image_is_reported_as_having_no_signature() {
        let mut raw = [0u8; 293];
        raw[0] = 0xFF;
        assert_eq!(locate(&raw, 262_144, BASE), Err(NotDfuSe::NoSignature));
    }

    #[test]
    fn a_truncated_file_is_refused_rather_than_read_past() {
        let h = container(262_144, BASE, 1, 1);
        assert_eq!(
            locate(&h, 1000, BASE),
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
        let h = container(u32::MAX, BASE, 1, 1);
        assert!(matches!(
            locate(&h, 300, BASE),
            Err(NotDfuSe::Truncated { .. })
        ));
    }

    #[test]
    fn several_targets_are_refused_not_guessed_between() {
        assert!(matches!(
            locate(&container(10, BASE, 2, 1), 10_000, BASE),
            Err(NotDfuSe::NotSingle { targets: 2, .. })
        ));
    }

    #[test]
    fn elements_after_a_correctly_addressed_first_one_are_left_unread() {
        // Element 0 at the base is the image; whatever follows it -- stock's bootloader, or
        // anything else -- is never walked to, so how many there are does not matter.
        assert!(matches!(
            locate(&container(10, BASE, 1, 3), 10_000, BASE),
            Ok(Element { len: 10, .. })
        ));
    }

    #[test]
    fn a_short_file_and_a_wrong_version_are_each_their_own_error() {
        assert_eq!(locate(&[0u8; 8], 8, BASE), Err(NotDfuSe::TooShort));
        let mut h = container(10, 0, 1, 1);
        h[5] = 2;
        assert_eq!(locate(&h, 10_000, BASE), Err(NotDfuSe::Version(2)));
    }
}
