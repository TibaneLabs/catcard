//! Apps carried in a firmware image (docs/APPS.md, phase 2).
//!
//! Each app ELF is flattened from the start of the app area to the end of what it loads,
//! zlib-compressed, and put in a bundle appended after the firmware's own content -- inside
//! the image length the header declares, so the image signature covers it. The firmware
//! finds the bundle through `CATCARD_APPS_BUNDLE`, a two-word static this patches to
//! `["CAPB", bundle address]`.
//!
//! Bundle layout, little-endian:
//! - header, 16 bytes: `"CAPB"`, version 1, entry count, total length;
//! - one 32-byte entry per app: 16-byte NUL-padded name, offset of its stream from the
//!   bundle start, packed length, unpacked length, reserved 0;
//! - the zlib streams, each starting on a 4-byte boundary.

use anyhow::{Context, Result, bail, ensure};

use crate::elf;

/// Where apps run: `catcard-fw`'s `apps::ARENA` and `catcard-app`'s `link.x` on mk4/mk5/Q1.
pub const APP_AREA: u32 = 0x2004_0000;
const APP_AREA_LEN: usize = 256 * 1024;
/// `catcard_app::ABI` and `catcard-fw`'s `apps::ABI`.
const APP_ABI: u32 = 1;
const APP_MAGIC: &[u8; 4] = b"CAPP";
const BUNDLE_MAGIC: &[u8; 4] = b"CAPB";
const BUNDLE_VERSION: u32 = 1;
const HEADER: usize = 16;
const ENTRY: usize = 32;
const NAME_MAX: usize = 16;
/// The firmware's marker, by symbol name (`catcard-fw` `apps::CATCARD_APPS_BUNDLE`).
pub const MARKER_SYMBOL: &str = "CATCARD_APPS_BUNDLE";

/// One app, flattened and checked: what the device will unpack into the app area.
pub struct App {
    pub name: String,
    pub image: Vec<u8>,
}

/// Flatten the app ELF at `path` and check its header against what the loader expects.
pub fn load(name: &str, elf_bytes: &[u8]) -> Result<App> {
    ensure!(
        !name.is_empty() && name.len() <= NAME_MAX && name.is_ascii(),
        "app name {name:?} must be 1 to {NAME_MAX} ASCII characters"
    );
    let segments = elf::load_segments(elf_bytes).with_context(|| format!("app {name}"))?;
    let image = elf::flatten(&segments, APP_AREA, 0)?;
    ensure!(
        image.len() <= APP_AREA_LEN,
        "app {name} is {} bytes; the app area holds {APP_AREA_LEN}",
        image.len()
    );
    ensure!(
        image.len() >= 32 && &image[..4] == APP_MAGIC,
        "app {name} does not start with a CAPP header: was it linked with catcard-app's link.x?"
    );
    let abi = u32::from_le_bytes(image[28..32].try_into().expect("four bytes"));
    ensure!(
        abi == APP_ABI,
        "app {name} speaks services ABI {abi}; this firmware serves {APP_ABI}"
    );
    Ok(App {
        name: name.to_string(),
        image,
    })
}

/// zlib-compress `data` with the same library the device inflates with.
pub fn compress(data: &[u8]) -> Result<Vec<u8>> {
    let mut table = vec![0u16; 1 << 15];
    // Stored blocks bound the worst case: five bytes per 64 KiB block, plus the wrapper.
    let mut out = vec![0u8; data.len() + data.len() / 16 + 64];
    let n = minizlib::zlib(data, &mut table, minizlib::Buffer::new(&mut out))
        .map_err(|e| anyhow::anyhow!("compressing: {e:?}"))?;
    out.truncate(n as usize);
    Ok(out)
}

/// The bundle for `apps`, ready to append.
pub fn bundle(apps: &[App]) -> Result<Vec<u8>> {
    ensure!(!apps.is_empty(), "no apps");
    let mut names = std::collections::HashSet::new();
    for a in apps {
        ensure!(names.insert(&a.name), "app {} listed twice", a.name);
    }
    let mut out = vec![0u8; HEADER + ENTRY * apps.len()];
    out[..4].copy_from_slice(BUNDLE_MAGIC);
    out[4..8].copy_from_slice(&BUNDLE_VERSION.to_le_bytes());
    out[8..12].copy_from_slice(&(apps.len() as u32).to_le_bytes());
    for (i, a) in apps.iter().enumerate() {
        let packed = compress(&a.image)?;
        while !out.len().is_multiple_of(4) {
            out.push(0);
        }
        let offset = out.len() as u32;
        out.extend_from_slice(&packed);
        let e = HEADER + i * ENTRY;
        out[e..e + a.name.len()].copy_from_slice(a.name.as_bytes());
        out[e + 16..e + 20].copy_from_slice(&offset.to_le_bytes());
        out[e + 20..e + 24].copy_from_slice(&(packed.len() as u32).to_le_bytes());
        out[e + 24..e + 28].copy_from_slice(&(a.image.len() as u32).to_le_bytes());
    }
    let total = out.len() as u32;
    out[12..16].copy_from_slice(&total.to_le_bytes());
    Ok(out)
}

/// Append `bundle` to the flattened firmware `flat` (which starts at `base`) and point the
/// firmware's marker at it. `marker` is the marker's address, from the firmware ELF.
/// Returns the bundle's flash address.
pub fn attach(flat: &mut Vec<u8>, base: u32, marker: u32, bundle: &[u8]) -> Result<u32> {
    let at = marker
        .checked_sub(base)
        .context("the apps marker is below the firmware base")? as usize;
    ensure!(
        at + 8 <= flat.len(),
        "the apps marker at {marker:#010x} is outside the flattened firmware"
    );
    // As linked: `[0xFFFF_FFFF, 0]` (`catcard-fw` `apps::BUNDLE_UNSET`).
    let unset = [0xFF, 0xFF, 0xFF, 0xFF, 0, 0, 0, 0];
    if flat[at..at + 8] != unset[..] {
        bail!("the apps marker is not in its linked state: was this image already packaged?");
    }
    // A page boundary, so the bundle never shares a flash page with code that changes.
    let start = flat.len().next_multiple_of(256);
    flat.resize(start, 0xFF);
    let addr = base + start as u32;
    flat.extend_from_slice(bundle);
    flat[at..at + 4].copy_from_slice(BUNDLE_MAGIC);
    flat[at + 4..at + 8].copy_from_slice(&addr.to_le_bytes());
    Ok(addr)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn app(name: &str, len: usize) -> App {
        let mut image = vec![0u8; len];
        image[..4].copy_from_slice(APP_MAGIC);
        image[28..32].copy_from_slice(&APP_ABI.to_le_bytes());
        for (i, b) in image.iter_mut().enumerate().skip(32) {
            *b = (i % 7) as u8;
        }
        App {
            name: name.into(),
            image,
        }
    }

    #[test]
    fn a_bundle_lists_each_app_and_inflates_back_to_its_image() {
        let apps = [app("flappy", 5000), app("hello", 300)];
        let b = bundle(&apps).unwrap();
        assert_eq!(&b[..4], b"CAPB");
        assert_eq!(u32::from_le_bytes(b[8..12].try_into().unwrap()), 2);
        assert_eq!(
            u32::from_le_bytes(b[12..16].try_into().unwrap()) as usize,
            b.len()
        );
        for (i, a) in apps.iter().enumerate() {
            let e = HEADER + i * ENTRY;
            let name = &b[e..e + 16];
            assert_eq!(&name[..a.name.len()], a.name.as_bytes());
            assert!(name[a.name.len()..].iter().all(|&c| c == 0));
            let w = |k: usize| {
                u32::from_le_bytes(b[e + 16 + 4 * k..e + 20 + 4 * k].try_into().unwrap()) as usize
            };
            let (off, packed, unpacked) = (w(0), w(1), w(2));
            assert_eq!(off % 4, 0);
            assert_eq!(unpacked, a.image.len());
            let mut out = vec![0u8; unpacked];
            let n =
                minizlib::unzlib(&b[off..off + packed], minizlib::Buffer::new(&mut out)).unwrap();
            assert_eq!(n as usize, unpacked);
            assert_eq!(out, a.image);
        }
    }

    #[test]
    fn attaching_points_the_marker_at_a_page_aligned_bundle() {
        let base = 0x0802_0000;
        let mut flat = vec![0x11u8; 1000];
        flat[600..608].copy_from_slice(&[0xFF, 0xFF, 0xFF, 0xFF, 0, 0, 0, 0]);
        let b = bundle(&[app("x", 100)]).unwrap();
        let addr = attach(&mut flat, base, base + 600, &b).unwrap();
        assert_eq!(addr, base + 1024);
        assert_eq!(&flat[600..604], b"CAPB");
        assert_eq!(u32::from_le_bytes(flat[604..608].try_into().unwrap()), addr);
        assert_eq!(&flat[1024..1024 + b.len()], &b[..]);
        // Packaging twice is refused rather than nesting a second bundle.
        assert!(attach(&mut flat, base, base + 600, &b).is_err());
    }

    #[test]
    fn two_apps_with_one_name_are_refused() {
        assert!(bundle(&[app("dup", 64), app("dup", 64)]).is_err());
    }
}
