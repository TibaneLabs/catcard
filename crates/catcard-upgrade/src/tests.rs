//! Tests, against a staging area that lives in a `Vec`.
//!
//! The images here are assembled and signed exactly as `catcard-image` does it, so a
//! test that says "this verifies" is saying the device would accept what the tool
//! produces — not that two copies of our own arithmetic agree.

use super::*;
use catcard_board::spec::{MK3, MK4, MK5, Q1};
use catcard_fwhdr::{MAGIC, install_flags, place_header, signed_digest};

/// A staging area with a `Vec` behind it.
struct Mem {
    bytes: Vec<u8>,
    header: Option<(u32, u32)>,
    /// Flip one bit on the way back out, to model memory that does not read back.
    corrupt_read_at: Option<u32>,
    /// Offsets and lengths the area was asked to write, and how many times it was read.
    /// A staging area that is memory-mapped PSRAM cares about both.
    writes: Vec<(u32, usize)>,
    reads: usize,
}

impl Mem {
    fn new(capacity: usize) -> Self {
        Self {
            bytes: vec![0xFF; capacity],
            header: None,
            corrupt_read_at: None,
            writes: Vec::new(),
            reads: 0,
        }
    }
}

#[derive(Debug)]
struct MemError;

impl StagingArea for Mem {
    type Error = MemError;

    fn image_offset(&self) -> u32 {
        0x0040_0000
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
        self.writes.push((offset, data.len()));
        self.bytes[at..end].copy_from_slice(data);
        Ok(())
    }

    fn read(&mut self, offset: u32, out: &mut [u8]) -> Result<(), MemError> {
        self.reads += 1;
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
    // The scalar of `keys/dev-privkey.pem`, inlined so the test needs no PEM parser.
    // It is public by design (see `keys/README.md`), and its matching public key is
    // `catcard_fwhdr::DEV_PUBKEY`, which `inspect` verifies the fixture against.
    const DEV_SECRET: [u8; 32] = [
        0xa4, 0xc2, 0x38, 0x13, 0x84, 0x61, 0x65, 0x8f, 0xe0, 0xe1, 0x7a, 0xb1, 0x5d, 0x90, 0xf5,
        0x19, 0x4f, 0x49, 0x3d, 0x34, 0x7a, 0x77, 0xd4, 0x64, 0xee, 0xff, 0xa3, 0x1f, 0x45, 0x4e,
        0xa8, 0xdf,
    ];
    catcard_sign::ecdsa_sign(&DEV_SECRET, digest).unwrap()
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
fn a_dev_signature_wearing_a_factory_slot_label_is_rejected() {
    // Now that the firmware holds all six approved keys, every signature is actually
    // checked. This image is dev-signed but its header claims pubkey_num=3, so the
    // signature is verified against production key 3 -- which it does not match. That is a
    // forgery attempt (or corruption), and is refused before anything is staged, rather
    // than waved through as "uncheckable".
    let image = image_for(&MK4, NEWER, 3);
    let mut s = staged_with(&image);
    assert!(matches!(
        s.inspect(Some(&running(OLDER))),
        Err(Reject::BadSignature { .. })
    ));
}

#[test]
fn a_verified_signature_is_classified_by_its_key_and_the_board() {
    // The classification of an already-verified signature. Split out because no test can
    // forge a production signature (the private keys are secret), so the happy factory
    // paths are exercised here rather than through a full `inspect`.
    assert_eq!(classify(&MK4, 0), Signature::DeveloperKey);
    // Production slots the board enables -> a named, attributable Coinkite signature.
    assert_eq!(classify(&MK4, 1), Signature::FactoryKey { slot: 1 });
    assert_eq!(classify(&MK4, 5), Signature::FactoryKey { slot: 5 });
    assert_eq!(classify(&MK5, 5), Signature::FactoryKey { slot: 5 });
    assert_eq!(classify(&Q1, 5), Signature::FactoryKey { slot: 5 });
    // Slot 5 is #if 0-disabled on mk3: a real signature the local bootloader will refuse.
    assert_eq!(classify(&MK3, 5), Signature::UntrustedSlot { slot: 5 });
    // mk3 still trusts slots 0..=4.
    assert_eq!(classify(&MK3, 1), Signature::FactoryKey { slot: 1 });
}

#[test]
fn is_verified_tracks_whether_this_board_accepts_the_key() {
    let approval = |sig| Approval {
        header: running(NEWER),
        signature: sig,
        length: MIN_FIRMWARE_LENGTH,
        older_than_running: false,
    };
    // Verifies and the board accepts the key.
    assert!(approval(Signature::DeveloperKey).is_verified());
    assert!(approval(Signature::FactoryKey { slot: 1 }).is_verified());
    // Verifies cryptographically, but this board's bootloader will not boot it, so
    // "checked" would mislead.
    assert!(!approval(Signature::UntrustedSlot { slot: 5 }).is_verified());
    // Only a production key is attributable.
    assert!(!approval(Signature::DeveloperKey).is_factory_signed());
    assert!(approval(Signature::FactoryKey { slot: 1 }).is_factory_signed());
    assert!(approval(Signature::UntrustedSlot { slot: 5 }).is_factory_signed());
}

#[test]
fn a_tampered_body_is_caught_before_anything_is_installed() {
    // One byte, anywhere, outside the signature window.
    let mut image = image_for(&MK4, NEWER, 0);
    image[70_000] ^= 0x01;
    let mut s = staged_with(&image);
    assert!(matches!(
        s.inspect(Some(&running(OLDER))),
        Err(Reject::BadSignature { .. })
    ));
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
    assert!(matches!(
        s.inspect(Some(&running(OLDER))),
        Err(Reject::BadSignature { .. })
    ));
}

#[test]
fn storage_that_does_not_read_back_is_caught() {
    // The reason the digest is taken over the stored image rather than the received
    // one. The bytes that arrived were perfect; the bytes that will be installed are
    // not, and only a read-back can tell.
    //
    // And it is reported as what it is: this device failed to store the image, rather
    // than `BadSignature`, which blames the sender for a fault of ours.
    //
    // **`inspect` no longer asks this question**, deliberately: it verifies against the
    // digest taken as the bytes arrived, so it never reads the image back and an
    // upgrade costs one pass instead of two. PSRAM is slow and that pass was the whole
    // of the second progress bar. The safety net did not disappear -- the bootloader
    // re-verifies the staged image in RAM before installing, and refuses with
    // `AUTH_FAIL` -- so what changed is who names the fault, not whether a corrupt
    // image can be installed.
    let image = image_for(&MK4, NEWER, 0);
    let area = Mem::new(image.len() + 4096);
    let mut s = Staged::begin(area, &MK4, image.len() as u32).unwrap();
    feed(&mut s, &image).unwrap();
    s.area.corrupt_read_at = Some(100_000);
    assert!(matches!(
        s.verify_stored(),
        Err(Reject::RamStoreFailed { .. })
    ));
    // The fast path accepts it, because what arrived was genuinely signed.
    assert!(s.inspect(Some(&running(OLDER))).is_ok());
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
        fn image_offset(&self) -> u32 {
            0x0040_0000
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

/// A released stock image's signature, against the key its header names.
///
/// The values come from `2026-09-03T1540-v1.5.2Q-q1-coldcard.dfu`: the digest computed over
/// the signed ranges the format defines, the 64-byte signature out of its header, and the
/// published key 1. An independent implementation verifies this signature, so if this test
/// fails, the fault is on our side of the fence -- which is exactly what it is here to say.
#[test]
fn a_released_stock_signature_verifies_under_the_key_its_header_names() {
    let digest: [u8; 32] = [
        0xfd, 0x06, 0x7c, 0xec, 0xae, 0x80, 0xcd, 0x59, 0x5a, 0xc4, 0x92, 0x36, 0x05, 0x6e, 0x7d,
        0x00, 0xc2, 0x94, 0x03, 0xec, 0x21, 0xd2, 0xc9, 0xf8, 0x07, 0x54, 0xc0, 0xa4, 0x8e, 0xa7,
        0x6b, 0xd9,
    ];
    let signature: [u8; 64] = [
        0xf3, 0x6a, 0xae, 0xa7, 0x00, 0x72, 0x04, 0x24, 0xfe, 0xcf, 0x72, 0xd8, 0x56, 0x1c, 0xa5,
        0x9f, 0xa9, 0x68, 0xa7, 0xd0, 0xa6, 0x5d, 0xad, 0xf6, 0x56, 0x4c, 0xb6, 0x9b, 0x87, 0x73,
        0x87, 0xe0, 0x3f, 0x7f, 0x07, 0xaa, 0xcb, 0x4f, 0x74, 0xe0, 0xe5, 0x2f, 0x88, 0x48, 0x3d,
        0xc8, 0xd4, 0x69, 0x92, 0xbf, 0x62, 0x19, 0x69, 0x7c, 0x4d, 0x8f, 0x00, 0xd0, 0x51, 0x79,
        0x91, 0xff, 0xcd, 0x0e,
    ];
    let key = super::compressed(&catcard_fwhdr::APPROVED_PUBKEYS[1]);
    assert_eq!(
        catcard_sign::ecdsa_verify(&key, &digest, &signature),
        Ok(true),
        "our verifier refuses a signature the format's own rules accept"
    );
}

/// Staging writes whole words at word-aligned offsets, and reads nothing while it does.
///
/// Both halves matter on the boards that stage into memory-mapped PSRAM: only a full 32-bit
/// store at a 4-aligned address is issued correctly there, and a read placed between writes
/// corrupts them. Frames over USB are 56 then 62 bytes, so most of them start unaligned --
/// which is how a firmware image staged over USB came back failing its own signature check.
#[test]
fn staging_writes_aligned_words_and_reads_nothing_on_the_way() {
    let image = image_for(&Q1, *b"20260918", 0);
    let mut staged = Staged::begin(Mem::new(image.len()), &Q1, image.len() as u32).unwrap();

    // Fed exactly as the USB path feeds it: a 56-byte first frame, then 62 bytes a frame.
    let mut at = 0usize;
    let mut first = true;
    while at < image.len() {
        let n = if first { 56 } else { 62 }.min(image.len() - at);
        first = false;
        staged.write(at as u32, &image[at..at + n]).unwrap();
        at += n;
    }
    // Nothing was read while it was being written. Reading afterwards is fine and is what
    // the digest does; a read *between* writes is what corrupts PSRAM.
    assert_eq!(
        staged.area().reads,
        0,
        "the area was read while it was being written"
    );

    // The digest reads the area, so the carried tail has to be put away first -- which
    // `settle` does, and the image verifying at all is the proof.
    let digest = staged.digest().unwrap();
    assert_eq!(
        digest,
        signed_digest(&image).unwrap(),
        "the staged image is the image"
    );

    let area = staged.area();
    for (offset, len) in &area.writes {
        assert_eq!(offset % 4, 0, "write at {offset:#x} is not word-aligned");
        assert_eq!(
            len % 4,
            0,
            "write at {offset:#x} is {len} bytes, not whole words"
        );
    }
    // Every byte of the image is there, and the pad past its end is at most three bytes.
    assert!(area.bytes[..image.len()] == image[..], "the bytes differ");
}

/// The ordinary path still installs: an approval commits the bytes it was granted over.
#[test]
fn an_untouched_image_still_commits() {
    let image = image_for(&Q1, *b"20260918", 0);
    let mut staged = Staged::begin(Mem::new(image.len()), &Q1, image.len() as u32).unwrap();
    staged.write(0, &image).unwrap();
    let approval = staged.inspect(None).expect("a signed image");
    let region = staged.commit(approval).expect("unchanged bytes commit");
    assert_eq!(region.len, image.len() as u32);
}

/// The two digests agree on an image that is fine.
///
/// They are computed by different code over the same bytes -- one from the arriving
/// stream, one by reading the area back -- and both skip the signature window. If they
/// ever disagreed about *which* bytes to skip, every honest upgrade would be called a
/// storage fault.
#[test]
fn the_two_digests_agree_on_an_image_that_is_fine() {
    let image = image_for(&MK4, NEWER, 0);
    let mut s = staged_with(&image);
    assert_eq!(s.verify_stored(), Ok(()));
    let approval = s.inspect(Some(&running(OLDER))).expect("a good image");
    assert_eq!(approval.length, image.len() as u32);
}

/// Verifying costs no read of the staging area at all.
///
/// The point of the change: an upgrade used to read the whole image back to get a
/// digest it could have taken on the way in. This counts the reads, because "it feels
/// faster" is not a property anything can hold on to.
#[test]
fn a_good_image_is_verified_without_reading_the_area_back() {
    let image = image_for(&MK4, NEWER, 0);
    let mut s = staged_with(&image);
    s.area.reads = 0;
    s.inspect(Some(&running(OLDER))).expect("a good image");
    // The header still comes from the area -- 128 bytes, once. What must not happen is
    // a pass over the whole image.
    assert!(
        s.area.reads <= 2,
        "inspect read the staging area {} times; it should need the header and no more",
        s.area.reads
    );
}

/// A signature that is genuinely wrong is still a signature fault, not a storage one.
///
/// The two must not collapse into each other: the new check sits in front of the
/// signature check, so an image whose bytes stored perfectly and whose signature is
/// simply invalid has to come out the far side still called unsigned.
#[test]
fn a_truly_bad_signature_is_not_blamed_on_the_medium() {
    let mut image = image_for(&MK4, NEWER, 0);
    // Flip a signature byte: the digest skips this window, so both digests still agree
    // and only the signature check can object.
    image[catcard_fwhdr::SIG_START] ^= 0x01;
    let mut s = staged_with(&image);
    assert!(matches!(
        s.inspect(Some(&running(OLDER))),
        Err(Reject::BadSignature { .. })
    ));
}

// --- scattered placement, for a transport that delivers out of order ----------------

/// The same image placed in a shuffled order verifies, exactly as the ordered one does.
///
/// This is the property the QR path rests on. The digest cannot be taken as the bytes
/// arrive -- there is no order to take it in -- so `inspect` reads the image back
/// instead, and the test is that the answer is the same either way.
#[test]
fn an_image_placed_out_of_order_still_verifies() {
    let image = image_for(&MK4, NEWER, 0);
    let area = Mem::new(image.len() + 4096);
    let mut s = Staged::begin(area, &MK4, image.len() as u32).unwrap();

    // Parts of 2,684 bytes -- a multiple of four, which the alignment rule requires --
    // placed back to front, which is the worst order and a legal one.
    let per = 2684usize;
    let n = image.len().div_ceil(per);
    for i in (0..n).rev() {
        let at = i * per;
        let end = (at + per).min(image.len());
        s.place(at as u32, &image[at..end]).expect("a part");
    }
    s.placed_all();

    let a = s.inspect(Some(&running(OLDER))).expect("it verifies");
    assert_eq!(a.signature, Signature::DeveloperKey);
    assert_eq!(a.length, image.len() as u32);
}

/// A part that is not word-aligned is refused, rather than merged.
///
/// Merging means the area reads the word it is about to change, and a read placed in
/// among writes is what corrupts this part -- so a sender whose parts are not a
/// multiple of four is told, rather than quietly given a staging area that will not
/// read back.
#[test]
fn an_unaligned_part_is_refused() {
    let image = image_for(&MK4, NEWER, 0);
    let area = Mem::new(image.len() + 4096);
    let mut s = Staged::begin(area, &MK4, image.len() as u32).unwrap();

    // An offset that is not a multiple of four.
    assert!(matches!(
        s.place(2685, &image[..64]),
        Err(Reject::Unaligned { .. })
    ));
    // A length that is not, in the middle of the image.
    assert!(matches!(
        s.place(0, &image[..2685]),
        Err(Reject::Unaligned { .. })
    ));
    // But the end of the image may be a partial word: nothing follows it.
    let tail = image.len() - 3;
    s.place(tail as u32 & !3, &image[tail & !3..])
        .expect("the tail");
}

/// A part past the declared end is refused, wherever it claims to go.
#[test]
fn a_placed_part_cannot_run_past_the_image() {
    let image = image_for(&MK4, NEWER, 0);
    let area = Mem::new(image.len() + 4096);
    let mut s = Staged::begin(area, &MK4, image.len() as u32).unwrap();
    let at = image.len() as u32 - 64;
    assert!(matches!(
        s.place(at, &image[..128]),
        Err(Reject::PastEnd { .. })
    ));
}

/// Completeness is the transport's to declare, not something inferred from offsets.
///
/// Writing the last part makes the highest offset touched equal the image length,
/// which says nothing about the holes before it. `inspect` must still refuse until the
/// thing counting the parts says they are all in.
#[test]
fn the_last_part_alone_does_not_make_an_image_complete() {
    let image = image_for(&MK4, NEWER, 0);
    let area = Mem::new(image.len() + 4096);
    let mut s = Staged::begin(area, &MK4, image.len() as u32).unwrap();

    let at = (image.len() - 64) as u32;
    s.place(at, &image[at as usize..]).expect("the last part");
    assert!(
        matches!(s.inspect(None), Err(Reject::Incomplete { .. })),
        "a single part at the end is not an image"
    );
}

// --- expanding a compressed stream in place ----------------------------------------

mod expanding {
    use super::*;
    use crate::expand::{self, Error};

    /// Where a compressed stream sits: past anything it can expand into.
    const FROM: u32 = 6 * 1024 * 1024;
    const CAPACITY: usize = 8 * 1024 * 1024;
    /// What BBQr's compressor keeps its back-references inside.
    const SENDER_WINDOW: usize = 1024;

    fn firmwareish(len: usize) -> Vec<u8> {
        // Code-like: repetitive enough to compress, not uniform enough to be trivial.
        (0..len)
            .map(|i| match i % 11 {
                0 => 0x00,
                1 => 0xF0,
                2 => 0x4B,
                n => ((i / 11).wrapping_mul(7) + n) as u8,
            })
            .collect()
    }

    /// Deflate the way the sender does: raw, matching only within its window.
    fn deflate(data: &[u8], window: usize) -> Vec<u8> {
        let mut out = vec![0u8; data.len() * 2 + 1024];
        let mut table = vec![0u16; window];
        let mut c = minizlib::Compressor::<_, minizlib::Raw>::new(
            minizlib::Buffer::new(&mut out),
            &mut table,
        );
        for block in data.chunks(window) {
            c.write(block).expect("compresses");
        }
        let n = c.finish().expect("finishes") as usize;
        out.truncate(n);
        out
    }

    fn staged(stream: &[u8]) -> Mem {
        let mut mem = Mem::new(CAPACITY);
        mem.write(FROM, stream).expect("stages");
        mem
    }

    /// The whole point: what went in compressed comes out identical, with the window in
    /// ordinary memory and both ends crossing the medium in chunks.
    #[test]
    fn a_stream_expands_to_what_was_compressed() {
        let image = firmwareish(300 * 1024);
        let stream = deflate(&image, SENDER_WINDOW);
        assert!(stream.len() < image.len(), "the fixture should compress");

        let mut mem = staged(&stream);
        let mut window = vec![0u8; 8 * 1024];
        let mut chunk = vec![0u8; 1024];
        let n = expand::inflate(
            &mut mem,
            FROM,
            stream.len() as u32,
            image.len() as u32,
            &mut window,
            &mut chunk,
        )
        .expect("expands");

        assert_eq!(n as usize, image.len());
        assert_eq!(&mem.bytes[..image.len()], &image[..]);
    }

    /// The expansion runs forwards over the front of the area while the stream is being
    /// read from the back of it. They must not meet -- and with the real offsets they
    /// cannot, which is what this pins.
    #[test]
    fn the_expansion_never_reaches_the_stream() {
        let image = firmwareish(300 * 1024);
        let stream = deflate(&image, SENDER_WINDOW);
        let mut mem = staged(&stream);
        let mut window = vec![0u8; 8 * 1024];
        let mut chunk = vec![0u8; 1024];
        expand::inflate(
            &mut mem,
            FROM,
            stream.len() as u32,
            image.len() as u32,
            &mut window,
            &mut chunk,
        )
        .expect("expands");

        // Every write landed below where the stream starts.
        for &(offset, len) in &mem.writes {
            if offset == FROM {
                continue; // the staging write this test did itself
            }
            assert!(
                offset + len as u32 <= FROM,
                "wrote {len} at {offset}, into the stream"
            );
        }
        // And the stream is still there, untouched.
        let mut back = vec![0u8; stream.len()];
        mem.read(FROM, &mut back).expect("reads");
        assert_eq!(back, stream);
    }

    /// A few kilobytes of deflate can become gigabytes. The caller says how much it is
    /// prepared to receive, and that is where it stops -- not at the end of the area.
    #[test]
    fn it_stops_at_the_length_the_caller_allowed() {
        let image = firmwareish(200 * 1024);
        let stream = deflate(&image, SENDER_WINDOW);
        let mut mem = staged(&stream);
        let mut window = vec![0u8; 8 * 1024];
        let mut chunk = vec![0u8; 1024];
        assert_eq!(
            expand::inflate(
                &mut mem,
                FROM,
                stream.len() as u32,
                (image.len() - 1) as u32,
                &mut window,
                &mut chunk,
            ),
            Err(Error::TooLong)
        );
    }

    /// A stream compressed with a wider window than the reader has says so, rather than
    /// producing bytes that are wrong in the middle.
    #[test]
    fn too_wide_a_window_is_named_not_guessed() {
        let image = firmwareish(200 * 1024);
        let stream = deflate(&image, 16 * 1024);
        let mut mem = staged(&stream);
        let mut window = vec![0u8; 1024];
        let mut chunk = vec![0u8; 1024];
        assert_eq!(
            expand::inflate(
                &mut mem,
                FROM,
                stream.len() as u32,
                image.len() as u32,
                &mut window,
                &mut chunk,
            ),
            Err(Error::WindowTooSmall)
        );
    }

    /// A stream that does not sit where it can be expanded past is refused, rather than
    /// half-written and then found out. Both halves: one that starts inside what the
    /// expansion will write, and one that runs off the end of the area.
    #[test]
    fn a_stream_with_nowhere_to_go_is_refused() {
        let image = firmwareish(64 * 1024);
        let stream = deflate(&image, SENDER_WINDOW);
        let mut window = vec![0u8; 8 * 1024];
        let mut chunk = vec![0u8; 1024];

        // Starting below what the expansion writes: it would eat its own input.
        let mut mem = staged(&stream);
        assert_eq!(
            expand::inflate(
                &mut mem,
                image.len() as u32 / 2,
                stream.len() as u32,
                image.len() as u32,
                &mut window,
                &mut chunk,
            ),
            Err(Error::NoRoom)
        );

        // Past the end of the area, which is how a compressed scan failed with nothing
        // but "staging write failed" to say for itself.
        let mut mem = Mem::new(CAPACITY);
        assert_eq!(
            expand::inflate(
                &mut mem,
                CAPACITY as u32 - 16,
                stream.len() as u32,
                image.len() as u32,
                &mut window,
                &mut chunk,
            ),
            Err(Error::NoRoom)
        );
    }

    /// **The medium never sees a partial word.** A short write would make the area read
    /// the word back to merge with, and the expansion is the one place in a QR transfer
    /// where reads and writes are interleaved at full speed rather than a part at a
    /// time. Every write but the last is a whole number of aligned words; the last may
    /// be padded, because nothing follows the image's end.
    #[test]
    fn every_write_is_whole_aligned_words() {
        let image = firmwareish(200 * 1024 + 3);
        let stream = deflate(&image, SENDER_WINDOW);
        let mut mem = staged(&stream);
        let mut window = vec![0u8; 8 * 1024];
        let mut chunk = vec![0u8; 1024];
        let n = expand::inflate(
            &mut mem,
            FROM,
            stream.len() as u32,
            image.len() as u32 + 4,
            &mut window,
            &mut chunk,
        )
        .expect("expands");
        assert_eq!(n as usize, image.len());

        for &(offset, len) in &mem.writes {
            if offset == FROM {
                continue; // the staging write this test did itself
            }
            assert_eq!(offset % 4, 0, "wrote {len} at unaligned {offset}");
            assert_eq!(len % 4, 0, "wrote a partial word of {len} at {offset}");
        }
        assert_eq!(&mem.bytes[..image.len()], &image[..]);
    }

    /// **Raw deflate carries no checksum**, so a damaged stream can expand to exactly
    /// the right length and simply be the wrong bytes -- there is nothing in the format
    /// to notice. That is not a gap to be closed here: the image's signature is checked
    /// over what comes out, and it is the thing that catches this. What matters is that
    /// the damage is not silently repaired into the original, which would mean the
    /// expansion was ignoring the stream.
    #[test]
    fn damage_survives_to_where_the_signature_can_see_it() {
        let image = firmwareish(64 * 1024);
        let mut stream = deflate(&image, SENDER_WINDOW);
        let middle = stream.len() / 2;
        stream[middle] ^= 0xFF;
        let mut mem = staged(&stream);
        let mut window = vec![0u8; 8 * 1024];
        let mut chunk = vec![0u8; 1024];
        match expand::inflate(
            &mut mem,
            FROM,
            stream.len() as u32,
            image.len() as u32,
            &mut window,
            &mut chunk,
        ) {
            // Caught by the format, which it sometimes is.
            Err(_) => {}
            // Or not, in which case the bytes must differ from the image -- the
            // signature check is what refuses them.
            Ok(n) => assert_ne!(
                &mem.bytes[..n as usize],
                &image[..n as usize],
                "damage was expanded away"
            ),
        }
    }

    /// The chunk size only changes how often the bus turns round, never the result.
    #[test]
    fn the_chunk_size_does_not_change_the_answer() {
        let image = firmwareish(128 * 1024);
        let stream = deflate(&image, SENDER_WINDOW);
        for chunk_len in [1usize, 7, 64, 1024, 4096] {
            let mut mem = staged(&stream);
            let mut window = vec![0u8; 8 * 1024];
            let mut chunk = vec![0u8; chunk_len];
            let n = expand::inflate(
                &mut mem,
                FROM,
                stream.len() as u32,
                image.len() as u32,
                &mut window,
                &mut chunk,
            )
            .unwrap_or_else(|e| panic!("chunk {chunk_len}: {e:?}"));
            assert_eq!(n as usize, image.len(), "chunk {chunk_len}");
            assert_eq!(&mem.bytes[..image.len()], &image[..], "chunk {chunk_len}");
        }
    }
}
