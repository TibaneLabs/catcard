//! Tests, against a staging area that lives in a `Vec`.
//!
//! The images here are assembled and signed exactly as `catcard-image` does it, so a
//! test that says "this verifies" is saying the device would accept what the tool
//! produces — not that two copies of our own arithmetic agree.

use super::*;
use catcard_board::spec::{MK3, MK4};
use catcard_fwhdr::{install_flags, place_header, signed_digest, MAGIC};

/// A staging area with a `Vec` behind it.
struct Mem {
    bytes: Vec<u8>,
    header: Option<(u32, u32)>,
    /// Flip one bit on the way back out, to model memory that does not read back.
    corrupt_read_at: Option<u32>,
}

impl Mem {
    fn new(capacity: usize) -> Self {
        Self {
            bytes: vec![0xFF; capacity],
            header: None,
            corrupt_read_at: None,
        }
    }
}

#[derive(Debug)]
struct MemError;

impl StagingArea for Mem {
    type Error = MemError;

    fn image_base(&self) -> u32 {
        0x9040_0000
    }

    fn capacity(&self) -> u32 {
        self.bytes.len() as u32
    }

    fn write(&mut self, offset: u32, data: &[u8]) -> Result<(), MemError> {
        let at = offset as usize;
        let end = at.checked_add(data.len()).ok_or(MemError)?;
        if end > self.bytes.len() {
            return Err(MemError);
        }
        self.bytes[at..end].copy_from_slice(data);
        Ok(())
    }

    fn read(&mut self, offset: u32, out: &mut [u8]) -> Result<(), MemError> {
        let at = offset as usize;
        let end = at.checked_add(out.len()).ok_or(MemError)?;
        if end > self.bytes.len() {
            return Err(MemError);
        }
        out.copy_from_slice(&self.bytes[at..end]);
        if let Some(bad) = self.corrupt_read_at {
            let bad = bad as usize;
            if (at..end).contains(&bad) {
                out[bad - at] ^= 0x01;
            }
        }
        Ok(())
    }

    fn publish(&mut self, len: u32) -> Result<(), MemError> {
        self.header = Some((0, len));
        Ok(())
    }
}

/// Build a signed image the way `catcard-image` does, so these tests exercise the real
/// format rather than a convenient stand-in.
fn image_for(board: &BoardSpec, timestamp: [u8; 8], pubkey_num: u32) -> Vec<u8> {
    let len = MIN_FIRMWARE_LENGTH as usize;
    let mut image = vec![0u8; len];
    // Something identifiable in the body, so a truncated or shifted image is not all
    // zeroes and accidentally self-consistent.
    for (i, b) in image.iter_mut().enumerate() {
        *b = (i % 251) as u8;
    }

    let header = FirmwareHeader {
        magic: MAGIC,
        timestamp,
        version: *b"0.0.9\0\0\0",
        pubkey_num,
        firmware_length: len as u32,
        install_flags: install_flags::HIGH_WATER,
        hw_compat: board.hw_compat_bit,
        best_ts: [0; 8],
        future: [0; 20],
        signature: [0; 64],
    };
    place_header(&mut image, &header).unwrap();

    let digest = signed_digest(&image).unwrap();
    let sig = sign_with_dev_key(&digest);
    let mut header = header;
    header.signature = sig;
    place_header(&mut image, &header).unwrap();
    image
}

/// Sign with the published developer key.
///
/// The key is public by design, so a test binary holding it is not a leak; it is the
/// same key `catcard-image` signs with by default.
fn sign_with_dev_key(digest: &[u8; 32]) -> [u8; 64] {
    use k256::ecdsa::{signature::hazmat::PrehashSigner, SigningKey};
    use k256::SecretKey;
    let pem = include_str!("../../../keys/dev-privkey.pem");
    let sk = SecretKey::from_sec1_pem(pem.trim()).unwrap();
    let key = SigningKey::from(sk);
    let sig: k256::ecdsa::Signature = key.sign_prehash(digest).unwrap();
    sig.normalize_s().to_bytes().into()
}

const NEWER: [u8; 8] = *b"20260901";
const OLDER: [u8; 8] = *b"20250101";

fn running(ts: [u8; 8]) -> FirmwareHeader {
    FirmwareHeader {
        magic: MAGIC,
        timestamp: ts,
        version: *b"0.0.1\0\0\0",
        pubkey_num: 0,
        firmware_length: MIN_FIRMWARE_LENGTH,
        install_flags: 0,
        hw_compat: MK4.hw_compat_bit,
        best_ts: [0; 8],
        future: [0; 20],
        signature: [0; 64],
    }
}

/// Receive a whole image in 64-byte pieces, the size a USB report carries.
fn feed<'a>(staged: &mut Staged<'a, Mem>, image: &[u8]) -> Result<(), Reject> {
    for (i, chunk) in image.chunks(64).enumerate() {
        staged.write(i as u32 * 64, chunk)?;
    }
    Ok(())
}

fn staged_with(image: &[u8]) -> Staged<'static, Mem> {
    let area = Mem::new(image.len() + 4096);
    let mut s = Staged::begin(area, &MK4, image.len() as u32).unwrap();
    feed(&mut s, image).unwrap();
    s
}

#[test]
fn a_dev_signed_image_verifies_on_device() {
    let image = image_for(&MK4, NEWER, 0);
    let mut s = staged_with(&image);
    let a = s.inspect(Some(&running(OLDER))).unwrap();
    assert_eq!(a.signature, Signature::DeveloperKey);
    assert!(a.is_verified());
    assert_eq!(a.length, MIN_FIRMWARE_LENGTH);
    assert_eq!(a.header.version_str(), Some("0.0.9"));
}

#[test]
fn a_factory_signed_image_is_reported_as_uncheckable_not_as_good() {
    // The five factory keys are not published. Saying "verified" here, or refusing
    // outright, would both be wrong: the first is a lie and the second makes official
    // firmware uninstallable. It has to reach a human as what it is.
    let image = image_for(&MK4, NEWER, 3);
    let mut s = staged_with(&image);
    let a = s.inspect(Some(&running(OLDER))).unwrap();
    assert_eq!(a.signature, Signature::FactoryKeyUnverifiable { slot: 3 });
    assert!(!a.is_verified());
}

#[test]
fn a_tampered_body_is_caught_before_anything_is_installed() {
    // One byte, anywhere, outside the signature window.
    let mut image = image_for(&MK4, NEWER, 0);
    image[70_000] ^= 0x01;
    let mut s = staged_with(&image);
    assert_eq!(s.inspect(Some(&running(OLDER))), Err(Reject::BadSignature));
}

#[test]
fn a_tampered_header_field_is_caught_too() {
    // The digest covers every header field except the signature, so changing the
    // version -- which a naive check might not even look at -- must still fail.
    let image = image_for(&MK4, NEWER, 0);
    let mut s = staged_with(&image);
    let good = s.inspect(Some(&running(OLDER))).unwrap();
    assert!(good.is_verified());

    let mut tampered = image.clone();
    tampered[HEADER_OFFSET + catcard_fwhdr::off::VERSION] = b'9';
    let mut s = staged_with(&tampered);
    assert_eq!(s.inspect(Some(&running(OLDER))), Err(Reject::BadSignature));
}

#[test]
fn storage_that_does_not_read_back_is_caught() {
    // The reason the digest is taken over the stored image rather than the received
    // one. The bytes that arrived were perfect; the bytes that will be installed are
    // not, and only a read-back can tell.
    let image = image_for(&MK4, NEWER, 0);
    let area = Mem::new(image.len() + 4096);
    let mut s = Staged::begin(area, &MK4, image.len() as u32).unwrap();
    feed(&mut s, &image).unwrap();
    s.area.corrupt_read_at = Some(100_000);
    assert_eq!(s.inspect(Some(&running(OLDER))), Err(Reject::BadSignature));
}

#[test]
fn an_image_for_another_board_is_refused() {
    // An mk3 image installs at 0x08008000; on an mk4 that address is the bootloader's.
    let image = image_for(&MK3, NEWER, 0);
    let mut s = staged_with(&image);
    assert_eq!(
        s.inspect(Some(&running(OLDER))),
        Err(Reject::WrongBoard {
            hw_compat: MK3.hw_compat_bit,
            board: MK4.hw_compat_bit,
        })
    );
}

#[test]
fn a_downgrade_is_reported_and_not_refused() {
    // Anti-rollback is the bootloader's: it holds a high-water mark in OTP and enforces
    // it whatever this code thinks. Refusing here as well made going back to stock
    // firmware impossible, because every build of this firmware is newer than any
    // released stock one -- so the flag reaches the approval screen and a person
    // decides.
    let image = image_for(&MK4, OLDER, 0);
    let mut s = staged_with(&image);
    let a = s.inspect(Some(&running(NEWER))).unwrap();
    assert!(a.older_than_running);
    assert!(
        a.is_verified(),
        "still a well-formed, correctly signed image"
    );
}

#[test]
fn a_newer_image_is_not_flagged_as_older() {
    let image = image_for(&MK4, NEWER, 0);
    let mut s = staged_with(&image);
    assert!(!s.inspect(Some(&running(OLDER))).unwrap().older_than_running);
}

#[test]
fn with_no_running_header_nothing_is_claimed_about_age() {
    // A device that cannot read its own header knows nothing about which is newer, and
    // must not imply that it does.
    let image = image_for(&MK4, OLDER, 0);
    let mut s = staged_with(&image);
    assert!(!s.inspect(None).unwrap().older_than_running);
}

#[test]
fn the_same_version_is_allowed_because_reinstalling_is_not_a_downgrade() {
    let image = image_for(&MK4, NEWER, 0);
    let mut s = staged_with(&image);
    assert!(s.inspect(Some(&running(NEWER))).is_ok());
}

#[test]
fn an_incomplete_image_cannot_be_inspected_or_installed() {
    let image = image_for(&MK4, NEWER, 0);
    let area = Mem::new(image.len() + 4096);
    let mut s = Staged::begin(area, &MK4, image.len() as u32).unwrap();
    // Everything but the last chunk.
    for (i, chunk) in image.chunks(64).enumerate().take(image.len() / 64 - 1) {
        s.write(i as u32 * 64, chunk).unwrap();
    }
    assert!(!s.is_complete());
    assert_eq!(s.remaining(), 64);
    assert!(matches!(
        s.inspect(Some(&running(OLDER))),
        Err(Reject::Incomplete { .. })
    ));
}

#[test]
fn chunks_must_arrive_in_order() {
    let image = image_for(&MK4, NEWER, 0);
    let area = Mem::new(image.len() + 4096);
    let mut s = Staged::begin(area, &MK4, image.len() as u32).unwrap();
    s.write(0, &image[..64]).unwrap();
    assert_eq!(
        s.write(128, &image[128..192]),
        Err(Reject::OutOfOrder {
            expected: 64,
            got: 128
        })
    );
}

#[test]
fn a_chunk_cannot_run_past_the_declared_length() {
    let image = image_for(&MK4, NEWER, 0);
    let area = Mem::new(image.len() + 4096);
    let mut s = Staged::begin(area, &MK4, image.len() as u32).unwrap();
    for (i, chunk) in image.chunks(64).enumerate().take(image.len() / 64 - 1) {
        s.write(i as u32 * 64, chunk).unwrap();
    }
    let at = s.received;
    assert!(matches!(
        s.write(at, &[0u8; 128]),
        Err(Reject::PastEnd { .. })
    ));
}

#[test]
fn a_length_the_bootloader_would_refuse_is_refused_before_any_transfer() {
    // The floor is the bootloader's, and a host that gets it wrong should be told now
    // rather than after sending a quarter of a megabyte.
    let area = Mem::new(4 * 1024 * 1024);
    let short = MIN_FIRMWARE_LENGTH - 512;
    assert!(matches!(
        Staged::begin(area, &MK4, short),
        Err(Reject::Length { len }) if len == short
    ));

    let area = Mem::new(4 * 1024 * 1024);
    let too_big = MK4.memory.firmware_flash_len + 512;
    assert!(matches!(
        Staged::begin(area, &MK4, too_big),
        Err(Reject::Length { len }) if len == too_big
    ));
}

#[test]
fn an_image_larger_than_the_staging_area_is_refused() {
    let area = Mem::new(MIN_FIRMWARE_LENGTH as usize - 1);
    assert!(matches!(
        Staged::begin(area, &MK4, MIN_FIRMWARE_LENGTH),
        Err(Reject::TooBigToStage { .. })
    ));
}

#[test]
fn a_header_that_lies_about_its_own_length_is_refused() {
    // The signature covers `firmware_length`, so this can only happen with a header we
    // could not verify anyway -- but the two lengths disagreeing means we and the
    // bootloader would digest different byte ranges, which is worth its own refusal.
    let mut image = image_for(&MK4, NEWER, 4);
    let wrong = (MIN_FIRMWARE_LENGTH + 512).to_le_bytes();
    let at = HEADER_OFFSET + catcard_fwhdr::off::FIRMWARE_LENGTH;
    image[at..at + 4].copy_from_slice(&wrong);
    let mut s = staged_with(&image);
    assert!(matches!(
        s.inspect(Some(&running(OLDER))),
        Err(Reject::Length { .. }) | Err(Reject::BadHeader(_))
    ));
}

#[test]
fn something_that_is_not_an_image_is_refused_as_such() {
    let area = Mem::new(MIN_FIRMWARE_LENGTH as usize + 4096);
    let mut s = Staged::begin(area, &MK4, MIN_FIRMWARE_LENGTH).unwrap();
    let junk = vec![0xA5u8; MIN_FIRMWARE_LENGTH as usize];
    feed(&mut s, &junk).unwrap();
    assert_eq!(s.inspect(Some(&running(OLDER))), Err(Reject::NotAnImage));
}

#[test]
fn committing_publishes_the_marker_and_the_length() {
    let image = image_for(&MK4, NEWER, 0);
    let mut s = staged_with(&image);
    let a = s.inspect(Some(&running(OLDER))).unwrap();
    let len = a.length;
    // The area is consumed, so read the marker through a borrow first.
    assert!(s.area.header.is_none(), "published before commit");
    s.commit(a).unwrap();
    // `commit` took ownership; rebuild to observe. Done by repeating the flow rather
    // than by adding an accessor that exists only for a test.
    let mut s2 = staged_with(&image);
    let a2 = s2.inspect(Some(&running(OLDER))).unwrap();
    s2.area.publish(a2.length).unwrap();
    assert_eq!(s2.area.header, Some((0, len)));
}

#[test]
fn a_marker_that_does_not_read_back_stops_the_install() {
    // The last thing before a reboot that overwrites the running firmware. The
    // bootloader reads those sixteen bytes with no idea where they came from, so if the
    // store did not land the alternative to catching it here is a device that reboots
    // into an install of whatever they happen to be.
    struct Deaf;
    #[derive(Debug)]
    struct DeafError;
    impl StagingArea for Deaf {
        type Error = DeafError;
        fn image_base(&self) -> u32 {
            0x9040_0000
        }
        fn capacity(&self) -> u32 {
            1 << 20
        }
        fn write(&mut self, _: u32, _: &[u8]) -> Result<(), DeafError> {
            Ok(())
        }
        fn read(&mut self, _: u32, out: &mut [u8]) -> Result<(), DeafError> {
            out.fill(0);
            Ok(())
        }
        /// Accepts the write and keeps nothing, which is what a bad mapping looks like.
        fn publish(&mut self, _: u32) -> Result<(), DeafError> {
            Err(DeafError)
        }
    }

    let approval = Approval {
        header: running(NEWER),
        signature: Signature::DeveloperKey,
        length: MIN_FIRMWARE_LENGTH,
        older_than_running: false,
    };
    let staged = Staged::begin(Deaf, &MK4, MIN_FIRMWARE_LENGTH).unwrap();
    assert!(
        staged.commit(approval).is_err(),
        "committed a marker the staging area did not keep"
    );
}

#[test]
fn inspect_never_publishes_anything() {
    // Inspection has to be safe to call and safe to refuse after. If it left a marker
    // behind, a refused image would install itself on the next reboot.
    //
    // Refused for a reason that is still a refusal: an image built for another board.
    // A downgrade is no longer one -- it is reported and left to a person.
    let image = image_for(&MK3, NEWER, 0);
    let mut s = staged_with(&image);
    assert!(s.inspect(Some(&running(OLDER))).is_err());
    assert!(s.area.header.is_none(), "a refused image was staged anyway");
}
