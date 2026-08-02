//! Assembling, signing and inspecting a firmware image.

use anyhow::{bail, ensure, Context, Result};
use catcard_board::BoardSpec;
use catcard_fwhdr::{
    hw_compat, install_flags, pack_timestamp, place_header, signed_digest, FirmwareHeader,
    HEADER_LEN, HEADER_OFFSET, LENGTH_ALIGN,
};

use crate::sign;

/// Value written into flash where the image has no content.
///
/// `0xFF` is erased-flash state, so a gap costs no programming and the image matches
/// what an erased page reads as. The digest covers these bytes, so the choice must be
/// stable — changing it changes every signature.
pub const FILL: u8 = 0xFF;

pub struct BuildOptions<'a> {
    pub board: &'a BoardSpec,
    pub version: &'a str,
    pub timestamp: [u8; 8],
    /// Set the anti-downgrade high-water mark on install. Irreversible on the device.
    pub high_water: bool,
    /// `None` restricts the image to this board; `Some(mask)` overrides `hw_compat`.
    pub hw_compat_override: Option<u32>,
}

/// Turn flattened flash contents into a complete, unsigned image.
pub fn assemble(mut image: Vec<u8>, opts: &BuildOptions<'_>) -> Result<Vec<u8>> {
    let board = opts.board;

    ensure!(
        opts.version.len() < 8,
        "version string {:?} is {} bytes; the header field holds 7 plus a NUL",
        opts.version,
        opts.version.len()
    );
    ensure!(
        opts.version.is_ascii(),
        "version string must be ASCII: {:?}",
        opts.version
    );

    // The header lives at a fixed offset, so the image must reach at least that far.
    if image.len() < HEADER_OFFSET + HEADER_LEN {
        image.resize(HEADER_OFFSET + HEADER_LEN, FILL);
    }

    // `firmware_length` must be 512-aligned.
    let aligned = image.len().next_multiple_of(LENGTH_ALIGN as usize);
    image.resize(aligned, FILL);

    ensure!(
        image.len() as u32 <= board.memory.firmware_flash_len,
        "image is {} bytes but {} has only {} bytes of firmware flash",
        image.len(),
        board.name,
        board.memory.firmware_flash_len
    );

    let mut version = [0u8; 8];
    version[..opts.version.len()].copy_from_slice(opts.version.as_bytes());

    let header = FirmwareHeader {
        timestamp: opts.timestamp,
        version,
        pubkey_num: catcard_fwhdr::DEV_PUBKEY_NUM,
        firmware_length: image.len() as u32,
        install_flags: if opts.high_water {
            install_flags::HIGH_WATER
        } else {
            0
        },
        hw_compat: opts.hw_compat_override.unwrap_or(board.hw_compat_bit),
        ..Default::default()
    };
    header
        .validate(image.len())
        .map_err(|e| anyhow::anyhow!(e))?;
    place_header(&mut image, &header).map_err(|e| anyhow::anyhow!(e))?;

    // Sanity: the vector table must actually be at the start of the image, or the
    // bootloader will branch into fill bytes.
    ensure!(
        image[..8] != [FILL; 8],
        "the image begins with fill bytes — the vector table is missing, which \
         usually means the linker script placed it somewhere other than {:#010x}",
        board.memory.firmware_base
    );

    Ok(image)
}

/// Sign an assembled image in place, returning the digest that was signed.
pub fn sign_image(image: &mut [u8], pem: &str, pubkey_num: u32) -> Result<[u8; 32]> {
    ensure!(
        pubkey_num < catcard_fwhdr::NUM_PUBKEYS,
        "pubkey_num {pubkey_num} is out of range"
    );

    // Write pubkey_num and clear the signature slot *before* digesting: the digest
    // covers pubkey_num, and the signature slot must be excluded consistently.
    let mut header = FirmwareHeader::from_image(image).map_err(|e| anyhow::anyhow!(e))?;
    header.pubkey_num = pubkey_num;
    header.signature = [0; 64];
    place_header(image, &header).map_err(|e| anyhow::anyhow!(e))?;

    let digest = signed_digest(image).map_err(|e| anyhow::anyhow!(e))?;
    let key = sign::load_key(pem)?;

    if pubkey_num == catcard_fwhdr::DEV_PUBKEY_NUM {
        let pk = sign::public_key_bytes(&key);
        ensure!(
            pk == sign::DEV_PUBKEY,
            "pubkey_num is 0 (the dev slot) but the supplied key is not the dev key; \
             the bootloader would reject this image"
        );
    }

    header.signature = sign::sign_digest(&key, &digest)?;
    place_header(image, &header).map_err(|e| anyhow::anyhow!(e))?;
    Ok(digest)
}

pub struct Report {
    pub header: FirmwareHeader,
    pub digest: [u8; 32],
    pub signature_ok: Option<bool>,
    pub signature_note: Option<String>,
}

/// Re-run every check the bootloader makes that we are able to reproduce.
pub fn verify(image: &[u8]) -> Result<Report> {
    let header = FirmwareHeader::from_image(image).map_err(|e| anyhow::anyhow!(e))?;
    header
        .validate(image.len())
        .map_err(|e| anyhow::anyhow!(e))
        .context("header failed the checks the bootloader makes before verifying")?;
    let digest = signed_digest(image).map_err(|e| anyhow::anyhow!(e))?;

    let (signature_ok, signature_note) = match sign::pubkey_for_slot(header.pubkey_num) {
        Ok(pk) => (
            Some(sign::verify_digest(&pk, &digest, &header.signature)?),
            None,
        ),
        Err(e) => (None, Some(e.to_string())),
    };

    Ok(Report {
        header,
        digest,
        signature_ok,
        signature_note,
    })
}

/// Describe `hw_compat` for humans.
pub fn describe_hw_compat(mask: u32) -> String {
    if mask == hw_compat::ANY {
        return "any hardware".to_string();
    }
    let mut parts = Vec::new();
    for (bit, name) in [
        (hw_compat::MK_1, "mk1"),
        (hw_compat::MK_2, "mk2"),
        (hw_compat::MK_3, "mk3"),
        (hw_compat::MK_4, "mk4"),
        (hw_compat::MK_5, "mk5"),
    ] {
        if mask & bit != 0 {
            parts.push(name);
        }
    }
    let unknown = mask & !0x1f;
    if unknown != 0 {
        return format!("{} (+ unknown bits {unknown:#x})", parts.join(", "));
    }
    if parts.is_empty() {
        return format!("no hardware ({mask:#x} matches nothing — this will not install)");
    }
    parts.join(", ")
}

/// Format a header timestamp as `YYYY-MM-DD HH:MM:SS`.
pub fn describe_timestamp(ts: &[u8; 8]) -> String {
    let d = |b: u8| (b >> 4) * 10 + (b & 0xf);
    format!(
        "20{:02}-{:02}-{:02} {:02}:{:02}:{:02}",
        d(ts[0]),
        d(ts[1]),
        d(ts[2]),
        d(ts[3]),
        d(ts[4]),
        d(ts[5])
    )
}

/// Split a UNIX timestamp into UTC calendar fields and pack it for the header.
///
/// Uses Howard Hinnant's `civil_from_days`, which is exact for the whole proleptic
/// Gregorian range — no dependency and no drift.
pub fn timestamp_from_unix(secs: i64) -> Result<[u8; 8]> {
    let days = secs.div_euclid(86_400);
    let rem = secs.rem_euclid(86_400);

    let z = days + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if m <= 2 { y + 1 } else { y };

    ensure!(
        (2000..2100).contains(&y),
        "timestamp year {y} is outside 2000-2099; the header stores only two digits, \
         so the bootloader's downgrade comparison would be meaningless"
    );

    Ok(pack_timestamp(
        y as u32,
        m as u32,
        d as u32,
        (rem / 3600) as u32,
        ((rem % 3600) / 60) as u32,
        (rem % 60) as u32,
    ))
}

/// Parse `YYYY-MM-DDTHH:MM:SS` (or with a space) into a header timestamp.
pub fn parse_timestamp(s: &str) -> Result<[u8; 8]> {
    let (date, time) = s
        .split_once(['T', ' '])
        .with_context(|| format!("expected YYYY-MM-DDTHH:MM:SS, got {s:?}"))?;
    let dp: Vec<&str> = date.split('-').collect();
    let tp: Vec<&str> = time.split(':').collect();
    ensure!(
        dp.len() == 3 && tp.len() == 3,
        "expected YYYY-MM-DDTHH:MM:SS, got {s:?}"
    );
    let n = |x: &str| -> Result<u32> { x.parse().with_context(|| format!("bad number {x:?}")) };
    let (y, mo, d) = (n(dp[0])?, n(dp[1])?, n(dp[2])?);
    let (h, mi, sec) = (n(tp[0])?, n(tp[1])?, n(tp[2])?);
    ensure!((2000..2100).contains(&y), "year {y} is outside 2000-2099");
    ensure!((1..=12).contains(&mo), "month {mo} is out of range");
    ensure!((1..=31).contains(&d), "day {d} is out of range");
    ensure!(
        h < 24 && mi < 60 && sec < 60,
        "time {time:?} is out of range"
    );
    Ok(pack_timestamp(y, mo, d, h, mi, sec))
}

/// Build timestamp, honouring `SOURCE_DATE_EPOCH` for reproducible builds.
pub fn default_timestamp() -> Result<[u8; 8]> {
    if let Ok(v) = std::env::var("SOURCE_DATE_EPOCH") {
        let secs: i64 = v
            .trim()
            .parse()
            .with_context(|| format!("SOURCE_DATE_EPOCH is not an integer: {v:?}"))?;
        return timestamp_from_unix(secs);
    }
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .context("system clock is before the UNIX epoch")?;
    timestamp_from_unix(now.as_secs() as i64)
}

/// Where the SPI-NOR staging write must start when uploading an image to a running
/// device. Not used by this tool -- it is the firmware's upload path that needs it --
/// but it belongs with the rest of the image format. Source:
/// `install-and-usb-transport.md §2` [C].
#[allow(dead_code)]
pub const SFLASH_STAGING_OFFSET: u32 = 0;

pub fn ensure_installable(board: &BoardSpec, image: &[u8]) -> Result<()> {
    let header = FirmwareHeader::from_image(image).map_err(|e| anyhow::anyhow!(e))?;
    if header.hw_compat != hw_compat::ANY && header.hw_compat & board.hw_compat_bit == 0 {
        bail!(
            "image hw_compat is {} but board {} needs bit {:#x}",
            describe_hw_compat(header.hw_compat),
            board.name,
            board.hw_compat_bit
        );
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use catcard_board::spec::{MK3, MK4};

    fn opts(board: &'static BoardSpec) -> BuildOptions<'static> {
        BuildOptions {
            board,
            version: "0.0.1",
            timestamp: pack_timestamp(2026, 8, 2, 12, 0, 0),
            high_water: false,
            hw_compat_override: None,
        }
    }

    /// Stand-in for a linked firmware: a plausible vector table then some code.
    fn fake_flash(len: usize) -> Vec<u8> {
        let mut v = vec![0u8; len];
        v[0..4].copy_from_slice(&0x2004_0000u32.to_le_bytes()); // initial SP
        v[4..8].copy_from_slice(&0x0800_4001u32.to_le_bytes()); // reset vector, thumb
        for (i, b) in v[8..].iter_mut().enumerate() {
            *b = (i % 251) as u8;
        }
        v
    }

    #[test]
    fn assemble_pads_to_512_and_sets_the_length() {
        let img = assemble(fake_flash(0x4100), &opts(&MK3)).unwrap();
        assert_eq!(img.len() % LENGTH_ALIGN as usize, 0);
        let h = FirmwareHeader::from_image(&img).unwrap();
        assert_eq!(h.firmware_length as usize, img.len());
        assert!(h.validate(img.len()).is_ok());
    }

    #[test]
    fn assemble_grows_a_short_image_to_reach_the_header() {
        // A trivially small firmware still has to carry a header at 0x3F80.
        let img = assemble(fake_flash(0x200), &opts(&MK3)).unwrap();
        assert!(img.len() >= HEADER_OFFSET + HEADER_LEN);
        let h = FirmwareHeader::from_image(&img).unwrap();
        assert_eq!(h.magic, catcard_fwhdr::MAGIC);
    }

    #[test]
    fn assemble_sets_the_boards_hw_compat_bit() {
        let img = assemble(fake_flash(0x4100), &opts(&MK3)).unwrap();
        assert_eq!(
            FirmwareHeader::from_image(&img).unwrap().hw_compat,
            hw_compat::MK_3
        );
        let img = assemble(fake_flash(0x4100), &opts(&MK4)).unwrap();
        assert_eq!(
            FirmwareHeader::from_image(&img).unwrap().hw_compat,
            hw_compat::MK_4
        );
    }

    #[test]
    fn assemble_rejects_an_image_larger_than_flash() {
        let too_big = MK3.memory.firmware_flash_len as usize + 512;
        let err = assemble(fake_flash(too_big), &opts(&MK3))
            .unwrap_err()
            .to_string();
        assert!(err.contains("firmware flash"), "{err}");
    }

    #[test]
    fn assemble_rejects_an_overlong_version_string() {
        let mut o = opts(&MK3);
        o.version = "10.20.30";
        assert!(assemble(fake_flash(0x4100), &o).is_err());
    }

    #[test]
    fn assemble_rejects_an_image_with_no_vector_table() {
        let blank = vec![FILL; 0x4100];
        let err = assemble(blank, &opts(&MK3)).unwrap_err().to_string();
        assert!(err.contains("vector table"), "{err}");
    }

    #[test]
    fn sign_then_verify_round_trip() {
        let mut img = assemble(fake_flash(0x5000), &opts(&MK3)).unwrap();
        let digest = sign_image(&mut img, sign::DEV_PRIVKEY_PEM, 0).unwrap();

        let r = verify(&img).unwrap();
        assert_eq!(r.digest, digest);
        assert_eq!(r.signature_ok, Some(true));
        assert_eq!(r.header.pubkey_num, 0);
    }

    #[test]
    fn a_modified_image_fails_verification() {
        let mut img = assemble(fake_flash(0x5000), &opts(&MK3)).unwrap();
        sign_image(&mut img, sign::DEV_PRIVKEY_PEM, 0).unwrap();
        img[0x5000 - 1] ^= 0x01;
        assert_eq!(verify(&img).unwrap().signature_ok, Some(false));
    }

    #[test]
    fn a_modified_header_field_fails_verification() {
        let mut img = assemble(fake_flash(0x5000), &opts(&MK3)).unwrap();
        sign_image(&mut img, sign::DEV_PRIVKEY_PEM, 0).unwrap();

        // Flip hw_compat to claim mk4 compatibility; the digest covers it.
        let mut h = FirmwareHeader::from_image(&img).unwrap();
        h.hw_compat = hw_compat::MK_4;
        place_header(&mut img, &h).unwrap();
        assert_eq!(verify(&img).unwrap().signature_ok, Some(false));
    }

    #[test]
    fn signing_is_idempotent_in_effect() {
        // Re-signing must produce an image that still verifies, even though ECDSA is
        // randomised, because the signature slot is cleared before digesting.
        let mut a = assemble(fake_flash(0x5000), &opts(&MK3)).unwrap();
        let d1 = sign_image(&mut a, sign::DEV_PRIVKEY_PEM, 0).unwrap();
        let d2 = sign_image(&mut a, sign::DEV_PRIVKEY_PEM, 0).unwrap();
        assert_eq!(d1, d2, "digest changed on re-sign");
        assert_eq!(verify(&a).unwrap().signature_ok, Some(true));
    }

    #[test]
    fn claiming_a_production_slot_with_the_dev_key_is_reported_not_silently_wrong() {
        let mut img = assemble(fake_flash(0x5000), &opts(&MK3)).unwrap();
        // Signing as slot 3 with the dev key produces an image the device rejects.
        // We cannot verify it here, and `verify` must say so rather than claim OK.
        sign_image(&mut img, sign::DEV_PRIVKEY_PEM, 3).unwrap();
        let r = verify(&img).unwrap();
        assert_eq!(r.signature_ok, None);
        assert!(r.signature_note.unwrap().contains("not published"));
    }

    #[test]
    fn signing_slot_0_with_a_foreign_key_is_refused() {
        // Slot 0 must carry the dev key or the device rejects the image, so catch a
        // mismatch at build time rather than after a slow SD-card round trip.
        use k256::pkcs8::LineEnding;
        use k256::SecretKey;
        let other = SecretKey::from_slice(&[7u8; 32])
            .unwrap()
            .to_sec1_pem(LineEnding::LF)
            .unwrap();

        let mut img = assemble(fake_flash(0x5000), &opts(&MK3)).unwrap();
        let err = sign_image(&mut img, &other, 0)
            .expect_err("signed slot 0 with a foreign key")
            .to_string();
        assert!(err.contains("not the dev key"), "{err}");

        // The same key is fine for a slot we make no claim about.
        assert!(sign_image(&mut img, &other, 2).is_ok());
    }

    #[test]
    fn hw_compat_gate() {
        let img = assemble(fake_flash(0x4100), &opts(&MK3)).unwrap();
        assert!(ensure_installable(&MK3, &img).is_ok());
        assert!(ensure_installable(&MK4, &img).is_err());

        let mut o = opts(&MK3);
        o.hw_compat_override = Some(hw_compat::ANY);
        let any = assemble(fake_flash(0x4100), &o).unwrap();
        assert!(ensure_installable(&MK4, &any).is_ok());
    }

    #[test]
    fn hw_compat_descriptions() {
        assert_eq!(describe_hw_compat(0), "any hardware");
        assert_eq!(describe_hw_compat(hw_compat::MK_3), "mk3");
        assert_eq!(describe_hw_compat(0x18), "mk4, mk5");
        assert!(describe_hw_compat(0x20).contains("unknown bits"));
    }

    #[test]
    fn unix_timestamps_convert_correctly() {
        // 2026-08-02T00:00:00Z
        assert_eq!(
            timestamp_from_unix(1_785_628_800).unwrap(),
            pack_timestamp(2026, 8, 2, 0, 0, 0)
        );
        // 2000-01-01T00:00:00Z — the low end of the two-digit-year range.
        assert_eq!(
            timestamp_from_unix(946_684_800).unwrap(),
            pack_timestamp(2000, 1, 1, 0, 0, 0)
        );
        // 2024-02-29T12:34:56Z — a leap day, and a non-midnight time.
        assert_eq!(
            timestamp_from_unix(1_709_210_096).unwrap(),
            pack_timestamp(2024, 2, 29, 12, 34, 56)
        );
        // 2099-12-31T23:59:59Z — the last second the header can represent.
        assert_eq!(
            timestamp_from_unix(4_102_444_799).unwrap(),
            pack_timestamp(2099, 12, 31, 23, 59, 59)
        );
    }

    #[test]
    fn timestamps_outside_the_two_digit_year_range_are_refused() {
        assert!(timestamp_from_unix(0).is_err()); // 1970
        assert!(timestamp_from_unix(4_102_444_800).is_err()); // 2100
    }

    #[test]
    fn timestamp_parsing() {
        assert_eq!(
            parse_timestamp("2026-08-02T14:30:05").unwrap(),
            pack_timestamp(2026, 8, 2, 14, 30, 5)
        );
        assert_eq!(
            parse_timestamp("2026-08-02 14:30:05").unwrap(),
            pack_timestamp(2026, 8, 2, 14, 30, 5)
        );
        assert!(parse_timestamp("2026-08-02").is_err());
        assert!(parse_timestamp("1999-01-01T00:00:00").is_err());
        assert!(parse_timestamp("2026-13-01T00:00:00").is_err());
        assert!(parse_timestamp("2026-01-01T25:00:00").is_err());
    }

    #[test]
    fn timestamp_rendering_round_trips() {
        let ts = parse_timestamp("2026-08-02T14:30:05").unwrap();
        assert_eq!(describe_timestamp(&ts), "2026-08-02 14:30:05");
    }

    #[test]
    fn source_date_epoch_makes_builds_reproducible() {
        // Two assembles with the same SOURCE_DATE_EPOCH must be byte-identical.
        std::env::set_var("SOURCE_DATE_EPOCH", "1785628800");
        let ts = default_timestamp().unwrap();
        assert_eq!(ts, pack_timestamp(2026, 8, 2, 0, 0, 0));
        std::env::remove_var("SOURCE_DATE_EPOCH");
    }
}
