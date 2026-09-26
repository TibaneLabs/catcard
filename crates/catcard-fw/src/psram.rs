//! The board's PSRAM, and who is using it.
//!
//! PSRAM is the only large working memory this device has, and several things want it:
//! a firmware image on its way in over USB or off a card, a PSBT too big for SRAM, the
//! frames of an animated QR being reassembled. None of them needs a private region --
//! it is scratch, and whoever has it may use all of it however it likes. What they need
//! is to be the only one.
//!
//! So the region is **taken**, not addressed. [`take`] hands out one [`Lease`] at a time
//! and records what took it, so a second asker is not merely refused but told what has
//! it; the lease releases on drop, wherever the using ends. Nothing has to remember to
//! hand it back, which matters because a screen can leave by being cancelled, by
//! failing, or by a key nobody expected.
//!
//! # Why exclusion rather than partitioning
//!
//! Handing each user its own slice was tried and is worse in both directions. It caps
//! every user at a fraction of the memory for a conflict that mostly cannot happen, and
//! it fails quietly: the mistake it invites is arithmetic, and arithmetic that overlaps
//! gets caught -- if at all -- as data that changed underneath somebody. Exclusion fails
//! loudly, at the door, before a byte moves.
//!
//! It also has to be exclusion for a reason that has nothing to do with layout. Reads
//! and writes to this part are not free of each other: the bus has timing rules the
//! driver keeps (`catcard_upgrade::psram`), and two users interleaving traffic through
//! it is how the region misbehaves even when their addresses never meet.
//!
//! # What a refusal means
//!
//! A USB upgrade offered while something else holds the PSRAM is refused **on its first
//! frame**, before half a megabyte crosses the wire to be thrown away. That is the whole
//! reason the claim is taken before the medium is brought up rather than at the point of
//! the first write.

use catcard_board::BOARD;
use catcard_upgrade::claim::{Claim, Ticket};

/// What has the PSRAM.
///
/// The tag is what a refusal names, so these are the words a person sees.
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
#[repr(u8)]
pub enum Use {
    /// A firmware image is staged in it, from USB or from a card.
    Upgrade = 1,
    /// A transaction is being signed out of it.
    Signing = 2,
    /// The frames of an animated QR are being reassembled in it.
    AnimatedQr = 3,
    /// The Debug soak test is exercising it.
    Soak = 4,
    /// A settings image staged by the host is being checked and written back.
    Restore = 5,
    /// A computer's sign request: uploaded into it, signed out of it, and the result
    /// held in it until the computer fetches it.
    Host = 6,
}

impl Use {
    /// The few words a screen has for it.
    pub fn what(self) -> &'static str {
        match self {
            Use::Upgrade => "a firmware update",
            Use::Signing => "signing a transaction",
            Use::AnimatedQr => "reading a QR",
            Use::Soak => "the memory test",
            Use::Restore => "restoring settings",
            Use::Host => "a computer's request",
        }
    }

    fn from_tag(tag: u8) -> Option<Self> {
        Some(match tag {
            1 => Use::Upgrade,
            2 => Use::Signing,
            3 => Use::AnimatedQr,
            4 => Use::Soak,
            5 => Use::Restore,
            6 => Use::Host,
            _ => return None,
        })
    }
}

/// Why the PSRAM could not be had.
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub enum Unavailable {
    /// This board has no PSRAM. Not a conflict: no waiting will help.
    NoMedium,
    /// Something else has it, and this is what.
    Busy(Use),
}

impl Unavailable {
    /// The few words a screen has for it.
    ///
    /// Here rather than at each screen so that every refusal says the same thing, and
    /// so that adding a user of the PSRAM is one place to change rather than as many
    /// places as there are screens that can be told no.
    pub fn message(self) -> &'static str {
        match self {
            Unavailable::NoMedium => "no memory for this",
            Unavailable::Busy(Use::Upgrade) => "busy: a firmware update",
            Unavailable::Busy(Use::Signing) => "busy: signing a transaction",
            Unavailable::Busy(Use::AnimatedQr) => "busy: reading a QR",
            Unavailable::Busy(Use::Soak) => "busy: the memory test",
            Unavailable::Busy(Use::Restore) => "busy: restoring settings",
            Unavailable::Busy(Use::Host) => "busy: a computer's request",
        }
    }
}

/// One holder at a time.
static HELD: Claim = Claim::new();

/// The PSRAM, held exclusively for as long as this lives.
///
/// Dropping it releases the region, which happens wherever the use ends -- finished,
/// cancelled, refused partway, or abandoned when a screen returns.
pub struct Lease {
    base: u32,
    len: u32,
    _ticket: Ticket,
}

impl Lease {
    /// The region as bytes.
    ///
    /// Takes `&mut self` so the borrow checker keeps one view of it at a time, and the
    /// slice cannot outlive the lease that makes it exclusive.
    ///
    /// **Byte stores into this are not reliable** -- see `catcard_upgrade::psram`, which
    /// writes it in aligned words for that reason. A caller writing through this slice
    /// directly is taking that on: it is right for a buffer that is filled from the card
    /// and read back, and wrong for anything the bootloader will act on.
    pub fn bytes(&mut self) -> &mut [u8] {
        // SAFETY: the region is the memory-mapped PSRAM the board table describes, and
        // this lease is the only one in existence -- `take` hands out no second one
        // until this is dropped.
        unsafe { core::slice::from_raw_parts_mut(self.base as *mut u8, self.len as usize) }
    }
}

/// Take the PSRAM for `what`, exclusively.
///
/// [`Unavailable::NoMedium`] is a property of the board and [`Unavailable::Busy`] a
/// property of the moment: one is "this device cannot", the other is "not while that is
/// happening", and they are different things to tell a person.
pub fn take(what: Use) -> Result<Lease, Unavailable> {
    let psram = BOARD.psram.ok_or(Unavailable::NoMedium)?;
    let ticket = HELD.take(what as u8).ok_or_else(|| {
        // Racing with a release here would report `Busy(Upgrade)` for a claim that has
        // just come free. That is a refusal a moment too early, not a wrong answer: the
        // decision was made by `take`, which cannot race, and this only names it.
        Unavailable::Busy(holder().unwrap_or(what))
    })?;
    Ok(Lease {
        base: psram.base,
        // Everything below the recovery header. Those last two kilobytes are the
        // bootloader's: they say where a staged image is, and they are read by code that
        // runs before any of this does.
        len: psram.usable(),
        _ticket: ticket,
    })
}

/// What has the PSRAM, if anything. For reporting, never for deciding -- deciding is
/// [`take`], which cannot race.
pub fn holder() -> Option<Use> {
    HELD.holder().and_then(Use::from_tag)
}
