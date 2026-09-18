//! Staging a firmware image for the bootloader to install.
//!
//! # Why this is written defensively
//!
//! The bootloader **installs first and verifies afterwards**. A staged image is copied
//! over the running firmware on the next boot, and only then is its signature checked.
//! A bad image therefore does not fail safely: it destroys the working firmware and
//! lands on the bootloader's corrupt-firmware screen, which offers DFU — and DFU is
//! refused on an RDP=2 unit. On a locked production device that is the end of the story.
//!
//! So everything checkable is checked *before* the reboot, and the digest is taken over
//! the image **as stored** rather than as received, because those two differ exactly
//! when the staging memory is faulty — the case a check on the incoming bytes would
//! agree with the host about and be wrong.
//!
//! # What cannot be checked
//!
//! Only the developer key is published. An image signed by one of the five factory keys
//! cannot be verified here at all, and [`Approval::signature`] says so rather than
//! implying an absence of evidence is evidence of absence. Deciding what to do about
//! that is the caller's — it is a question for a human at a screen.
//!
//! # The mechanism
//!
//! There is no callgate that requests an upgrade. The bootloader looks for a staged
//! image while it boots, so "install this" is spelled: write the image, write the
//! marker, reboot. Source: `hw-reference/install-and-usb-transport.md §2` [C].

#![cfg_attr(not(feature = "std"), no_std)]
#![deny(unsafe_op_in_unsafe_fn)]

use catcard_board::BoardSpec;
use catcard_fwhdr::{
    APPROVED_PUBKEYS, DigestStream, FirmwareHeader, HEADER_LEN, HEADER_OFFSET, MIN_FIRMWARE_LENGTH,
    hw_compat, is_factory_key,
};

pub mod claim;
pub mod dfuse;
pub mod nor;
pub mod psram;

/// Why an image was refused.
///
/// Every variant is a reason not to reboot. None of them leave the device worse off,
/// which is the entire point of checking here rather than finding out afterwards.
/// Times the signature is re-read before an image is called unsigned.
///
/// See the comment at the use site: the staging medium has transient read faults, and
/// the signature is the one window the digest cannot check.
const REREADS: usize = 3;

#[derive(Clone, PartialEq, Eq, Debug)]
pub enum Reject {
    /// Shorter than the bootloader's floor, or longer than the flash it installs into.
    Length { len: u32 },
    /// Longer than the staging area.
    TooBigToStage { len: u32, capacity: u32 },
    /// Chunks must arrive in order from zero; this one did not follow the last.
    OutOfOrder { expected: u32, got: u32 },
    /// A chunk ran past the length declared at the start.
    PastEnd { end: u32, len: u32 },
    /// Asked to install before every byte arrived.
    Incomplete { have: u32, want: u32 },
    /// The header at `0x3F80` is not a firmware header.
    NotAnImage,
    /// The header is structurally wrong. Carries the underlying reason.
    BadHeader(catcard_fwhdr::Error),
    /// Built for a different board. Installing it would brick this one.
    WrongBoard { hw_compat: u32, board: u32 },
    /// The signature is present, we hold the key, and it does not verify.
    /// Carries the first bytes of the two things it judged. "Bad signature" alone
    /// cannot tell a tampered image from a misread one, and the digest here is the
    /// device's own -- computed inside the verification, on the same pass. Comparing it
    /// against the digest the staging area reports separately is what distinguishes a
    /// read that went wrong *during* verification from an image that is not signed.
    BadSignature { digest: [u8; 4], sig: [u8; 4] },
    /// The staging area did not read back what was written.
    StorageFault { offset: u32 },
    /// The image that arrived and the image the staging area reads back are not the
    /// same. The transfer was fine; the medium lost or altered something.
    ///
    /// Its own variant because the cure is the opposite of the one for a bad signature:
    /// this image is worth sending again, and a device that called it "not signed"
    /// would be blaming the sender for a fault of its own.
    ReadBack { sent: [u8; 4], read: [u8; 4] },
    /// This board has nowhere to put an image. Not a fault in the offer: the device
    /// cannot accept any upgrade over USB at all, and the host should stop rather than
    /// send a quarter of a megabyte to find out.
    NoStagingArea,
    /// The staging medium is already held: another path is partway through an image, and
    /// there is only one staging area. Handing out a second view of the same bytes is how
    /// an approved image gets replaced by a different one before it installs.
    StagingBusy,
}

impl From<catcard_fwhdr::Error> for Reject {
    fn from(e: catcard_fwhdr::Error) -> Self {
        Reject::BadHeader(e)
    }
}

/// What is known about an image's signature.
///
/// Every variant here means the signature *verified* against the approved public key its
/// `pubkey_num` selects -- the firmware holds all six now, so a bad signature does not
/// reach here at all: it is [`Reject::BadSignature`]. What the variants distinguish is
/// *whose* key signed it and whether this board's bootloader will accept that key.
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub enum Signature {
    /// Signed with the published developer key (slot 0), and it verifies.
    ///
    /// This says the image is intact and is what the host meant to send. It says
    /// **nothing** about who made it: the matching private key is published, so anyone
    /// can produce this signature. On hardware such an image boots with a warning and no
    /// green light.
    DeveloperKey,
    /// Signed with one of the five Coinkite production keys (slots 1..=5), and it verifies
    /// against that key -- so this is a genuine Coinkite image (e.g. stock firmware). The
    /// private key is secret, so the signature *is* attributable, unlike the dev key. This
    /// board's bootloader enables `slot`, so it will boot clean with the green light.
    FactoryKey { slot: u32 },
    /// The signature verifies against a production key the *bootloader on this board* does
    /// not enable -- slot 5 on mk3. The signature is real, but the local bootloader will
    /// refuse the image. Reported, not refused: the person decides, and the bootloader has
    /// the final say regardless.
    UntrustedSlot { slot: u32 },
}

/// What a user is being asked to approve.
///
/// Assembled before anything irreversible happens, so a screen can state what will be
/// installed and on what evidence.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Approval {
    pub header: FirmwareHeader,
    pub signature: Signature,
    /// Bytes that will be written over the running firmware.
    pub length: u32,
    /// The image is older than what is running.
    ///
    /// **Reported, not refused.** Anti-rollback belongs to the bootloader, which holds a
    /// high-water mark in OTP and enforces it whatever we think. Refusing here as well
    /// looked prudent and was not: every build of this firmware is newer than any
    /// released stock firmware, so it made going back to stock impossible — a decision
    /// no wallet should take away from its owner, and one the bootloader had not made.
    ///
    /// So it reaches the screen as a warning and a person decides.
    pub older_than_running: bool,
}

impl Approval {
    /// Whether the signature verified against a key this board's bootloader will accept.
    ///
    /// True for the dev key and for a production key this board enables. False only for a
    /// production key the local bootloader does not enable (slot 5 on mk3) -- the
    /// signature is valid, but calling it "checked" here would imply the device will boot
    /// it, which it will not.
    pub fn is_verified(&self) -> bool {
        matches!(
            self.signature,
            Signature::DeveloperKey | Signature::FactoryKey { .. }
        )
    }

    /// Whether a Coinkite production key signed this image (as opposed to the published
    /// developer key). A production signature is attributable; a dev one is not.
    pub fn is_factory_signed(&self) -> bool {
        matches!(
            self.signature,
            Signature::FactoryKey { .. } | Signature::UntrustedSlot { .. }
        )
    }
}

/// Somewhere to put an image while it is being received.
///
/// `read` is not an optimisation to skip: validation reads back through it, so an area
/// that writes and reads different bytes is caught here rather than by the bootloader
/// after it has installed them.
pub trait StagingArea {
    type Error;

    /// Bytes available for an image.
    fn capacity(&self) -> u32;

    /// Where the image is staged, as an **offset from the staging medium's base**.
    ///
    /// `gate 18/7` names the region rather than looking for a marker, and the bootloader
    /// reads `PSRAM_base + start` -- so this is an offset, not an absolute address.
    /// Passing the absolute address made the bootloader read past the end of PSRAM and
    /// reject the image with -112, which is the whole reason an install never took.
    fn image_offset(&self) -> u32;

    fn write(&mut self, offset: u32, data: &[u8]) -> Result<(), Self::Error>;
    fn read(&mut self, offset: u32, out: &mut [u8]) -> Result<(), Self::Error>;

    /// Publish the marker that makes the bootloader install `len` bytes on next boot.
    ///
    /// **Irreversible in effect**: the next boot overwrites the running firmware. Called
    /// only from [`Staged::commit`], which will not reach it without a full validation.
    fn publish(&mut self, len: u32) -> Result<(), Self::Error>;
}

/// An image being received into a staging area.
pub struct Staged<'a, A: StagingArea> {
    area: A,
    board: &'a BoardSpec,
    length: u32,
    received: u32,
    /// Bytes accepted but not yet pushed to the area: fewer than four, always the tail of
    /// what has been received. See [`Self::write`].
    carry: [u8; 4],
    carry_len: u8,
    /// The digest of what **arrived**, taken as it arrives.
    ///
    /// The other digest is of what the staging area *reads back*. Two digests of the
    /// same image, one never touching the medium, is what tells a transfer that went
    /// wrong apart from a medium that did -- and those two faults want opposite fixes,
    /// so reporting either as the other costs a day.
    ///
    /// Valid because [`write`](Self::write) refuses anything out of order, so the bytes
    /// reach this in image order, once each.
    stream: DigestStream,
}

impl<'a, A: StagingArea> Staged<'a, A> {
    /// Begin receiving an image of exactly `length` bytes.
    ///
    /// The length is checked against the bootloader's floor, the board's flash and the
    /// staging area before a single byte is accepted, so a host that is obviously wrong
    /// is told immediately rather than after transferring a quarter of a megabyte.
    pub fn begin(area: A, board: &'a BoardSpec, length: u32) -> Result<Self, Reject> {
        if length < MIN_FIRMWARE_LENGTH || length > board.memory.firmware_flash_len {
            return Err(Reject::Length { len: length });
        }
        let capacity = area.capacity();
        if length > capacity {
            return Err(Reject::TooBigToStage {
                len: length,
                capacity,
            });
        }
        Ok(Self {
            area,
            board,
            length,
            received: 0,
            carry: [0; 4],
            carry_len: 0,
            stream: DigestStream::new(),
        })
    }

    /// Bytes stored so far, which is also the offset the next chunk must carry.
    pub fn received(&self) -> u32 {
        self.received
    }

    /// Bytes still to come.
    pub fn remaining(&self) -> u32 {
        self.length - self.received
    }

    /// Bytes the image will have when it is whole.
    pub fn length(&self) -> u32 {
        self.length
    }

    pub fn is_complete(&self) -> bool {
        self.received == self.length
    }

    /// Store the next chunk.
    ///
    /// Chunks must be sequential from zero. Out-of-order writes would need a map of
    /// which bytes had arrived, and "the image is complete" would become a claim to
    /// check rather than a counter to compare — for a transfer we control both ends of,
    /// that is complexity bought with the one property that must not be got wrong.
    pub fn write(&mut self, offset: u32, data: &[u8]) -> Result<(), Reject>
    where
        A::Error: Into<StorageError>,
    {
        if offset != self.received {
            return Err(Reject::OutOfOrder {
                expected: self.received,
                got: offset,
            });
        }
        let end = offset
            .checked_add(data.len() as u32)
            .ok_or(Reject::PastEnd {
                end: u32::MAX,
                len: self.length,
            })?;
        if end > self.length {
            return Err(Reject::PastEnd {
                end,
                len: self.length,
            });
        }
        // Hashed here, before the medium sees any of it: this is the "what was sent"
        // half of the comparison, and it must not depend on anything the area does.
        self.stream.update(data);

        // Push whole four-byte words at word-aligned offsets, and nothing else.
        //
        // A staging area can be memory-mapped PSRAM, where only a full 32-bit store at a
        // 4-aligned address is issued correctly, and where a read placed between writes
        // corrupts them. Frames arriving over USB are 56 and 62 bytes, so most of them
        // start unaligned -- and asking the area to write a partial word would make it
        // read the word, merge and write it back, which is that read. So the odd bytes at
        // the end of a write are carried and go out with the front of the next one.
        //
        // Writes are in order (checked above), so the carry is always the tail of what has
        // been received, and `settle` puts the last of it away.
        let mut at = offset - u32::from(self.carry_len);
        let mut rest = data;
        if self.carry_len > 0 {
            let need = 4 - usize::from(self.carry_len);
            if rest.len() < need {
                // Still short of a word: keep them together and wait for more.
                self.carry[usize::from(self.carry_len)..][..rest.len()].copy_from_slice(rest);
                self.carry_len += rest.len() as u8;
                self.received = end;
                return Ok(());
            }
            let mut word = self.carry;
            word[usize::from(self.carry_len)..].copy_from_slice(&rest[..need]);
            self.area
                .write(at, &word)
                .map_err(|_| Reject::StorageFault { offset: at })?;
            at += 4;
            rest = &rest[need..];
            self.carry_len = 0;
        }
        let whole = rest.len() & !3;
        if whole > 0 {
            self.area
                .write(at, &rest[..whole])
                .map_err(|_| Reject::StorageFault { offset: at })?;
        }
        let tail = &rest[whole..];
        self.carry[..tail.len()].copy_from_slice(tail);
        self.carry_len = tail.len() as u8;

        self.received = end;
        Ok(())
    }

    /// The staging area itself, for a test that checks how it was written.
    #[cfg(test)]
    pub(crate) fn area(&self) -> &A {
        &self.area
    }

    /// Put the carried tail away, zero-padded to a whole word.
    ///
    /// The padding sits past the image's last byte, which nothing reads: the header says how
    /// long the image is, and the signature covers exactly that much. Called before anything
    /// reads the area back, so a reader never sees a hole where the last few bytes go.
    fn settle(&mut self) -> Result<(), Reject> {
        if self.carry_len == 0 {
            return Ok(());
        }
        let at = self.received - u32::from(self.carry_len);
        let mut word = [0u8; 4];
        word[..usize::from(self.carry_len)]
            .copy_from_slice(&self.carry[..usize::from(self.carry_len)]);
        self.area
            .write(at, &word)
            .map_err(|_| Reject::StorageFault { offset: at })?;
        self.carry_len = 0;
        Ok(())
    }

    /// Read the image back and decide whether it may be installed.
    ///
    /// `running` is the header of the firmware currently executing, used for the
    /// downgrade check; pass `None` only where it genuinely cannot be read.
    ///
    /// Nothing here writes anything. It is safe to call, and safe to refuse after.
    /// The header the staged image carries, whatever it says.
    ///
    /// For reporting a refusal: what the image claims about itself -- which key signed it,
    /// how long it is, which boards it is for -- is what makes a rejection chaseable
    /// afterwards, and [`inspect`](Self::inspect) only says which check said no.
    pub fn header(&mut self) -> Option<FirmwareHeader> {
        self.settle().ok()?;
        let mut raw = [0u8; catcard_fwhdr::FW_HEADER_SIZE as usize];
        self.area.read(HEADER_OFFSET as u32, &mut raw).ok()?;
        let header = FirmwareHeader::from_bytes(&raw);
        (header.magic == catcard_fwhdr::MAGIC).then_some(header)
    }

    pub fn inspect(&mut self, running: Option<&FirmwareHeader>) -> Result<Approval, Reject> {
        self.inspect_with(running, |_, _| {})
    }

    /// As [`inspect`](Self::inspect), reporting `(done, total)` as the image is digested.
    ///
    /// Reading a megabyte out of a staging area is not instant -- on PSRAM the bus has to be
    /// released to the part often enough for it to refresh itself, which is most of the time
    /// it takes -- and a screen that says nothing for that long reads as a hung device.
    pub fn inspect_with(
        &mut self,
        running: Option<&FirmwareHeader>,
        progress: impl FnMut(u32, u32),
    ) -> Result<Approval, Reject> {
        self.settle()?;
        if !self.is_complete() {
            return Err(Reject::Incomplete {
                have: self.received,
                want: self.length,
            });
        }

        // The header, read back from where the bootloader will read it.
        let mut raw = [0u8; HEADER_LEN];
        self.area
            .read(HEADER_OFFSET as u32, &mut raw)
            .map_err(|_| Reject::StorageFault {
                offset: HEADER_OFFSET as u32,
            })?;
        let header = FirmwareHeader::from_bytes(&raw);
        if header.magic != catcard_fwhdr::MAGIC {
            return Err(Reject::NotAnImage);
        }
        header.validate(self.length as usize)?;

        // The image says how long it is; that must be what we were told to expect, or
        // the bootloader and we disagree about which bytes are covered by the signature.
        if header.firmware_length != self.length {
            return Err(Reject::Length {
                len: header.firmware_length,
            });
        }

        // Built for this board? A mk3 image installed on an mk4 runs at the wrong base.
        if header.hw_compat != hw_compat::ANY && header.hw_compat & self.board.hw_compat_bit == 0 {
            return Err(Reject::WrongBoard {
                hw_compat: header.hw_compat,
                board: self.board.hw_compat_bit,
            });
        }

        let older_than_running = running.is_some_and(|cur| header.timestamp < cur.timestamp);

        // `validate` already rejected `pubkey_num >= NUM_PUBKEYS`, so the slot indexes the
        // table. We hold all six approved keys now, so every signature is actually checked
        // -- dev or production alike -- against the exact key the bootloader would use, over
        // the exact double-SHA256 digest it signs (hw-reference/firmware-signing.md §2 [C]).
        let slot = header.pubkey_num;
        let digest = self.stored_digest_with(progress)?;

        // Two digests of one image: what arrived, and what the area reads back. They
        // must agree, and when they do not the fault is the staging area -- not the
        // signature, which is what a device says when it cannot tell the difference.
        //
        // This is worth doing on every upgrade and not only when something fails. The
        // digest deliberately skips the 64-byte signature window, so a medium that
        // misreads *that* window alone still produces two matching digests and a
        // signature that will not verify; knowing the rest of the image read back
        // correctly is what makes that conclusion available at all.
        let arrived = self.stream.clone().finish();
        if arrived != digest {
            return Err(Reject::ReadBack {
                sent: [arrived[0], arrived[1], arrived[2], arrived[3]],
                read: [digest[0], digest[1], digest[2], digest[3]],
            });
        }
        let key = compressed(&APPROVED_PUBKEYS[slot as usize]);
        let mut verified = matches!(
            catcard_sign::ecdsa_verify(&key, &digest, &header.signature),
            Ok(true)
        );

        // Read the signature again and try once more.
        //
        // Not leniency: a signature that is genuinely wrong fails every attempt, and
        // nothing here accepts a digest it did not compute. It is that the signature
        // comes out of a staging medium with **transient read faults** -- a Q1 has
        // refused a correct, correctly-staged image this way -- and the 64 bytes of
        // signature are the one part of the image the digest cannot vouch for, because
        // the digest is computed with that window skipped. Everything else agreeing
        // while only this disagrees is the shape of a bad read, not of a bad image.
        //
        // So it is re-read from the medium rather than reused, which is the whole point:
        // a second look at the same bytes.
        for _ in 0..REREADS {
            if verified {
                break;
            }
            let mut again = [0u8; HEADER_LEN];
            if self.area.read(HEADER_OFFSET as u32, &mut again).is_err() {
                break;
            }
            let reread = FirmwareHeader::from_bytes(&again);
            verified = matches!(
                catcard_sign::ecdsa_verify(&key, &digest, &reread.signature),
                Ok(true)
            );
        }
        if !verified {
            // We hold the key and it does not verify: corrupt or tampered. Refuse before
            // staging rather than let the bootloader find out after overwriting firmware.
            return Err(Reject::BadSignature {
                digest: [digest[0], digest[1], digest[2], digest[3]],
                sig: [
                    header.signature[0],
                    header.signature[1],
                    header.signature[2],
                    header.signature[3],
                ],
            });
        }
        let signature = classify(self.board, slot);

        Ok(Approval {
            header,
            signature,
            length: self.length,
            older_than_running,
        })
    }

    /// The digest of the image as it sits in the staging area, for reporting a refusal.
    ///
    /// The same computation `inspect` judges on, exposed so a caller can say what it got:
    /// a signature that will not verify is either the wrong bytes or the wrong key, and the
    /// digest is what tells those apart.
    pub fn digest(&mut self) -> Result<[u8; 32], Reject> {
        self.settle()?;
        self.stored_digest()
    }

    /// Read `buf.len()` bytes of the staged image at `offset`, for the same reason.
    pub fn sample(&mut self, offset: u32, buf: &mut [u8]) -> Result<(), Reject> {
        self.settle()?;
        self.area
            .read(offset, buf)
            .map_err(|_| Reject::StorageFault { offset })
    }

    /// Digest the image as it now sits in the staging area.
    fn stored_digest(&mut self) -> Result<[u8; 32], Reject> {
        self.stored_digest_with(|_, _| {})
    }

    /// The digest, calling `progress` with `(done, total)` as it goes.
    fn stored_digest_with(
        &mut self,
        mut progress: impl FnMut(u32, u32),
    ) -> Result<[u8; 32], Reject> {
        let mut stream = DigestStream::new();
        let mut buf = [0u8; 256];
        let mut off = 0u32;
        while off < self.length {
            let n = buf.len().min((self.length - off) as usize);
            self.area
                .read(off, &mut buf[..n])
                .map_err(|_| Reject::StorageFault { offset: off })?;
            stream.update(&buf[..n]);
            off += n as u32;
            progress(off, self.length);
        }
        Ok(stream.finish())
    }

    /// **Tell the bootloader to install this image on the next boot.**
    ///
    /// Irreversible: the running firmware is overwritten before it is verified. Takes an
    /// [`Approval`] by value rather than re-deriving one, so this cannot be reached
    /// without [`inspect`](Self::inspect) having passed, and a caller cannot skip the
    /// screen that showed it.
    ///
    /// Does not reboot. That is the caller's, so the last irreversible step is not
    /// buried in a function that also does bookkeeping.
    /// Publish the recovery header, and report the region it names.
    ///
    /// On mk3 that is the whole story: the bootrom installs what it finds staged. On
    /// mk4 and later nothing happens until a logged-in `gate 18/7` authorises *this*
    /// region, which is why the caller is handed it rather than left to recompute it.
    pub fn commit(mut self, approval: Approval) -> Result<Region, Reject> {
        self.settle()?;
        let start = self.area.image_offset();
        self.area
            .publish(approval.length)
            .map_err(|_| Reject::StorageFault { offset: 0 })?;
        Ok(Region {
            start,
            len: approval.length,
        })
    }
}

/// Where a staged image sits, as `gate 18/7` wants it: `start` is an **offset** from the
/// staging medium's base, not an absolute address -- the bootloader adds it to the base.
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub struct Region {
    pub start: u32,
    pub len: u32,
}

/// Placeholder for a staging area's own error, which callers do not act on
/// individually — every one of them means the same thing here.
pub struct StorageError;

impl<E> From<E> for StorageError
where
    E: core::fmt::Debug,
{
    fn from(_: E) -> Self {
        StorageError
    }
}

/// Whether this board's bootloader has the given signing slot enabled. Only slot 5 varies:
/// it is `#if 0`-disabled on mk3 and compiled in on every mk4-class board (mk4/mk5/Q1).
/// Source: hw-reference/firmware-keys/README.md [C].
fn slot_enabled(board: &BoardSpec, slot: u32) -> bool {
    !(slot == 5 && board.hw_compat_bit == hw_compat::MK_3)
}

/// Classify a signature that has already *verified* against `APPROVED_PUBKEYS[slot]`, by
/// which key signed it and whether this board enables that slot. Pulled out of `inspect`
/// so the slot logic is testable without a factory private key (which is secret, so no
/// test can produce a real production signature).
fn classify(board: &BoardSpec, slot: u32) -> Signature {
    if !is_factory_key(slot) {
        Signature::DeveloperKey
    } else if slot_enabled(board, slot) {
        Signature::FactoryKey { slot }
    } else {
        // A valid production signature on a slot this board's bootloader has disabled
        // (slot 5 on mk3): real, but this device will not boot it.
        Signature::UntrustedSlot { slot }
    }
}

/// Raw `X || Y` to the compressed SEC1 form verification takes.
///
/// The prefix records the parity of `Y`, which is all that is needed to recover it from
/// `X` on the curve — so the last byte of `Y` decides it.
fn compressed(raw: &[u8; 64]) -> [u8; 33] {
    let mut out = [0u8; 33];
    out[0] = if raw[63] & 1 == 0 { 0x02 } else { 0x03 };
    out[1..].copy_from_slice(&raw[..32]);
    out
}

#[cfg(test)]
mod tests;
