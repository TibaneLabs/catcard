//! ST DfuSe (`.dfu`) container.
//!
//! The delivery wrapper the device ingests over USB or from a microSD card. The
//! signed `.bin` is the single image element; the bootloader re-verifies the
//! signature on install regardless of the wrapper, so this layer is packaging only.
//!
//! Layout per ST UM0391:
//!
//! ```text
//! prefix  11 B   "DfuSe" | bVersion=1 | DFUImageSize | bTargets
//! target 274 B   "Target" | bAltSetting | bTargetNamed | szTargetName[255]
//!                | dwTargetSize | dwNbElements
//! element        dwElementAddress | dwElementSize | data
//! suffix  16 B   bcdDevice | idProduct | idVendor | bcdDFU=0x011A | "UFD" | 16 | CRC
//! ```
//!
//! `DFUImageSize` counts the prefix and every target, and excludes the 16-byte
//! suffix. `dwCRC` is CRC-32 over everything preceding it, left *not* finally
//! inverted (i.e. `!crc32(data)` in the usual zlib convention).

use anyhow::{ensure, Result};

/// DFU-spec wildcard: the file is accepted by any device. Preferred over asserting a
/// VID/PID we do not own — see `docs/USB.md`.
pub const VID_ANY: u16 = 0xFFFF;
pub const PID_ANY: u16 = 0xFFFF;

const PREFIX_LEN: usize = 11;
const TARGET_PREFIX_LEN: usize = 274;
const SUFFIX_LEN: usize = 16;
const BCD_DFU: u16 = 0x011A;

/// CRC-32 (IEEE 802.3 polynomial), returned without the final inversion, which is
/// what the DFU suffix stores.
fn dfu_crc(data: &[u8]) -> u32 {
    let mut crc: u32 = 0xFFFF_FFFF;
    for &b in data {
        crc ^= b as u32;
        for _ in 0..8 {
            let mask = (crc & 1).wrapping_neg();
            crc = (crc >> 1) ^ (0xEDB8_8320 & mask);
        }
    }
    crc
}

pub struct Element<'a> {
    pub address: u32,
    pub data: &'a [u8],
}

/// Wrap one or more elements into a DfuSe file.
pub fn pack(
    target_name: &str,
    elements: &[Element<'_>],
    vid: u16,
    pid: u16,
    bcd_device: u16,
) -> Result<Vec<u8>> {
    ensure!(
        !elements.is_empty(),
        "a DfuSe file needs at least one element"
    );
    ensure!(
        target_name.len() < 255,
        "target name must be shorter than 255 bytes"
    );

    let mut body = Vec::new();
    for e in elements {
        body.extend_from_slice(&e.address.to_le_bytes());
        body.extend_from_slice(&(e.data.len() as u32).to_le_bytes());
        body.extend_from_slice(e.data);
    }

    let mut target = Vec::with_capacity(TARGET_PREFIX_LEN + body.len());
    target.extend_from_slice(b"Target");
    target.push(0); // bAlternateSetting
    target.extend_from_slice(&1u32.to_le_bytes()); // bTargetNamed
    let mut name = [0u8; 255];
    name[..target_name.len()].copy_from_slice(target_name.as_bytes());
    target.extend_from_slice(&name);
    target.extend_from_slice(&(body.len() as u32).to_le_bytes()); // dwTargetSize
    target.extend_from_slice(&(elements.len() as u32).to_le_bytes()); // dwNbElements
    debug_assert_eq!(target.len(), TARGET_PREFIX_LEN);
    target.extend_from_slice(&body);

    let mut out = Vec::with_capacity(PREFIX_LEN + target.len() + SUFFIX_LEN);
    out.extend_from_slice(b"DfuSe");
    out.push(0x01); // bVersion
    out.extend_from_slice(&((PREFIX_LEN + target.len()) as u32).to_le_bytes());
    out.push(1); // bTargets
    debug_assert_eq!(out.len(), PREFIX_LEN);
    out.extend_from_slice(&target);

    out.extend_from_slice(&bcd_device.to_le_bytes());
    out.extend_from_slice(&pid.to_le_bytes());
    out.extend_from_slice(&vid.to_le_bytes());
    out.extend_from_slice(&BCD_DFU.to_le_bytes());
    out.extend_from_slice(b"UFD");
    out.push(SUFFIX_LEN as u8);
    let crc = dfu_crc(&out);
    out.extend_from_slice(&crc.to_le_bytes());

    Ok(out)
}

/// A parsed DfuSe file, for `catcard-image info`/round-trip checking.
#[derive(Debug)]
pub struct Parsed {
    pub target_name: String,
    pub elements: Vec<(u32, Vec<u8>)>,
    pub vid: u16,
    pub pid: u16,
}

pub fn unpack(file: &[u8]) -> Result<Parsed> {
    ensure!(
        file.len() >= PREFIX_LEN + TARGET_PREFIX_LEN + SUFFIX_LEN,
        "file is too short to be a DfuSe container"
    );
    ensure!(&file[0..5] == b"DfuSe", "missing DfuSe signature");
    ensure!(file[5] == 0x01, "unsupported DfuSe version {}", file[5]);

    let suffix = &file[file.len() - SUFFIX_LEN..];
    ensure!(&suffix[8..11] == b"UFD", "missing UFD suffix signature");
    ensure!(
        suffix[11] as usize == SUFFIX_LEN,
        "unexpected suffix length"
    );

    let want = u32::from_le_bytes(suffix[12..16].try_into().unwrap());
    let got = dfu_crc(&file[..file.len() - 4]);
    ensure!(
        got == want,
        "DFU suffix CRC mismatch: {got:#010x} != {want:#010x}"
    );

    let image_size = u32::from_le_bytes(file[6..10].try_into().unwrap()) as usize;
    ensure!(
        image_size == file.len() - SUFFIX_LEN,
        "DFUImageSize {image_size} disagrees with file length {}",
        file.len() - SUFFIX_LEN
    );
    ensure!(
        file[10] == 1,
        "expected exactly one target, got {}",
        file[10]
    );

    let t = &file[PREFIX_LEN..];
    ensure!(&t[0..6] == b"Target", "missing Target signature");
    let name_raw = &t[11..11 + 255];
    let name_end = name_raw.iter().position(|&c| c == 0).unwrap_or(255);
    let target_name = String::from_utf8_lossy(&name_raw[..name_end]).into_owned();
    let nb_elements = u32::from_le_bytes(t[270..274].try_into().unwrap()) as usize;

    let mut at = TARGET_PREFIX_LEN;
    let mut elements = Vec::new();
    for i in 0..nb_elements {
        ensure!(
            at + 8 <= t.len(),
            "element {i} header runs past end of file"
        );
        let addr = u32::from_le_bytes(t[at..at + 4].try_into().unwrap());
        let size = u32::from_le_bytes(t[at + 4..at + 8].try_into().unwrap()) as usize;
        at += 8;
        ensure!(
            at + size <= t.len(),
            "element {i} data runs past end of file"
        );
        elements.push((addr, t[at..at + size].to_vec()));
        at += size;
    }

    Ok(Parsed {
        target_name,
        elements,
        pid: u16::from_le_bytes(suffix[2..4].try_into().unwrap()),
        vid: u16::from_le_bytes(suffix[4..6].try_into().unwrap()),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The CRC-32 of "123456789" is 0xCBF43926 in the usual (finally inverted)
    /// convention, so the DFU suffix form is its complement.
    #[test]
    fn crc_matches_the_known_check_value() {
        assert_eq!(dfu_crc(b"123456789"), !0xCBF4_3926u32);
    }

    #[test]
    fn crc_of_empty_input() {
        assert_eq!(dfu_crc(b""), 0xFFFF_FFFF);
    }

    #[test]
    fn roundtrip() {
        let payload: Vec<u8> = (0..1024u32).map(|i| (i % 256) as u8).collect();
        let file = pack(
            "CatCard mk3",
            &[Element {
                address: 0x0800_8000,
                data: &payload,
            }],
            VID_ANY,
            PID_ANY,
            0,
        )
        .unwrap();

        let p = unpack(&file).unwrap();
        assert_eq!(p.target_name, "CatCard mk3");
        assert_eq!(p.vid, VID_ANY);
        assert_eq!(p.pid, PID_ANY);
        assert_eq!(p.elements.len(), 1);
        assert_eq!(p.elements[0].0, 0x0800_8000);
        assert_eq!(p.elements[0].1, payload);
    }

    #[test]
    fn layout_offsets_are_as_specified() {
        let file = pack(
            "t",
            &[Element {
                address: 0x1000,
                data: &[1, 2, 3, 4],
            }],
            1,
            2,
            3,
        )
        .unwrap();
        assert_eq!(&file[0..5], b"DfuSe");
        assert_eq!(file[5], 1);
        assert_eq!(file[10], 1); // bTargets
        assert_eq!(&file[11..17], b"Target");
        // DFUImageSize excludes the 16-byte suffix.
        let size = u32::from_le_bytes(file[6..10].try_into().unwrap()) as usize;
        assert_eq!(size, file.len() - 16);
        // prefix + target prefix + element header + payload + suffix
        assert_eq!(file.len(), 11 + 274 + 8 + 4 + 16);
        // Suffix field order is bcdDevice, idProduct, idVendor.
        let s = &file[file.len() - 16..];
        assert_eq!(u16::from_le_bytes(s[0..2].try_into().unwrap()), 3);
        assert_eq!(u16::from_le_bytes(s[2..4].try_into().unwrap()), 2);
        assert_eq!(u16::from_le_bytes(s[4..6].try_into().unwrap()), 1);
        assert_eq!(u16::from_le_bytes(s[6..8].try_into().unwrap()), BCD_DFU);
    }

    #[test]
    fn a_corrupted_byte_fails_the_crc() {
        let mut file = pack(
            "t",
            &[Element {
                address: 0,
                data: &[7; 64],
            }],
            1,
            2,
            0,
        )
        .unwrap();
        let n = file.len();
        file[n - 32] ^= 0x01;
        let err = unpack(&file).unwrap_err().to_string();
        assert!(err.contains("CRC mismatch"), "{err}");
    }

    #[test]
    fn rejects_a_truncated_file() {
        let file = pack(
            "t",
            &[Element {
                address: 0,
                data: &[7; 64],
            }],
            1,
            2,
            0,
        )
        .unwrap();
        assert!(unpack(&file[..file.len() - 4]).is_err());
        assert!(unpack(&file[..10]).is_err());
    }

    #[test]
    fn rejects_a_non_dfuse_file() {
        assert!(unpack(&vec![0u8; 400]).is_err());
    }
}
