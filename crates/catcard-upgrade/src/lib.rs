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
    DEV_PUBKEY, DEV_PUBKEY_NUM, DigestStream, FirmwareHeader, HEADER_LEN, HEADER_OFFSET,
    MIN_FIRMWARE_LENGTH, hw_compat,
};

pub mod dfuse;
pub mod psram;

/// Why an image was refused.
///
/// Every variant is a reason not to reboot. None of them leave the device worse off,
/// which is the entire point of checking here rather than finding out afterwards.
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
    BadSignature,
    /// The staging area did not read back what was written.
    StorageFault { offset: u32 },
    /// This board has nowhere to put an image. Not a fault in the offer: the device
    /// cannot accept any upgrade over USB at all, and the host should stop rather than
    /// send a quarter of a megabyte to find out.
    NoStagingArea,
}

impl From<catcard_fwhdr::Error> for Reject {
    fn from(e: catcard_fwhdr::Error) -> Self {
        Reject::BadHeader(e)
    }
}

/// What is known about an image's signature.
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub enum Signature {
    /// Signed with the published developer key, and it verifies.
    ///
    /// This says the image is intact and is what the host meant to send. It says
    /// **nothing** about who made it: the matching private key is published, so anyone
    /// can produce this signature. On hardware such an image boots with a warning and no
    /// green light.
    DeveloperKey,
    /// Signed with one of the five factory keys, which are not published.
    ///
    /// Cannot be checked here. The bootloader will check it after installing — and if it
    /// is wrong, after having already overwritten the running firmware.
    FactoryKeyUnverifiable { slot: u32 },
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
    /// Whether the image was actually verified, as opposed to merely well-formed.
    pub fn is_verified(&self) -> bool {
        matches!(self.signature, Signature::DeveloperKey)
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
        self.area
            .write(offset, data)
            .map_err(|_| Reject::StorageFault { offset })?;
        self.received = end;
        Ok(())
    }

    /// Read the image back and decide whether it may be installed.
    ///
    /// `running` is the header of the firmware currently executing, used for the
    /// downgrade check; pass `None` only where it genuinely cannot be read.
    ///
    /// Nothing here writes anything. It is safe to call, and safe to refuse after.
    pub fn inspect(&mut self, running: Option<&FirmwareHeader>) -> Result<Approval, Reject> {
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

        let digest = self.stored_digest()?;
        let signature = match header.pubkey_num {
            DEV_PUBKEY_NUM => {
                match catcard_sign::ecdsa_verify(
                    &compressed(&DEV_PUBKEY),
                    &digest,
                    &header.signature,
                ) {
                    Ok(true) => Signature::DeveloperKey,
                    _ => return Err(Reject::BadSignature),
                }
            }
            slot => Signature::FactoryKeyUnverifiable { slot },
        };

        Ok(Approval {
            header,
            signature,
            length: self.length,
            older_than_running,
        })
    }

    /// Digest the image as it now sits in the staging area.
    fn stored_digest(&mut self) -> Result<[u8; 32], Reject> {
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
