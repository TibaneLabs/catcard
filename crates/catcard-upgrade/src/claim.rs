//! One holder at a time for a medium that has only one of itself.
//!
//! A board has exactly one firmware-staging area, at a fixed address, and more than one
//! path stages into it: the card browser, a USB offer, headless recovery. Handing each of
//! them a fresh handle to the same bytes is what let a host overwrite an image between the
//! screen that asked about it and the keypress that approved it.
//!
//! So the medium is taken rather than constructed. A [`Ticket`] is the proof of holding it
//! and releases it when dropped, which happens wherever the staging ends -- installed,
//! declined, refused, or abandoned when the screen returns -- without anything having to
//! remember to say so.
//!
//! The holder says **who**, not just whether. A refusal that can name what is using the
//! medium is the difference between "busy, try later" and a screen that says a USB
//! upgrade cannot start because a transaction is being signed. The tag is an opaque
//! number here: this crate has no business knowing what the firmware does with the
//! medium, only that one thing does it at a time.
//!
//! The alternative considered was re-reading the staged bytes at the moment of installing
//! and comparing them against what was approved. That is sound but costs a second pass over
//! the whole image, on a bus that has to be handed back to the part every few microseconds,
//! at the moment after someone has pressed yes. A lock costs nothing and refuses the second
//! writer at the door instead.

use core::sync::atomic::{AtomicU8, Ordering};

/// Nobody holds it. Not a valid holder tag, which is why [`take`](Claim::take) refuses it.
const FREE: u8 = 0;

/// A medium that only one holder may have at a time, and which knows which one.
pub struct Claim {
    /// The holder's tag, or [`FREE`]. One atomic rather than a flag beside a name: the
    /// taking and the recording have to be the same indivisible act, or a refusal can
    /// name the wrong holder -- or none, which reads as a bug in the claim itself.
    holder: AtomicU8,
}

impl Claim {
    /// A claim nobody holds.
    pub const fn new() -> Self {
        Self {
            holder: AtomicU8::new(FREE),
        }
    }

    /// Take it for `holder`, or `None` if someone already has it.
    ///
    /// The claim is `'static` because the ticket outlives the call: it lives as long as the
    /// staging does, which on this device is until a screen returns.
    ///
    /// `holder` is the caller's own tag for itself and must not be zero, which is the
    /// value that means free. A zero tag is refused rather than taken, because a holder
    /// that cannot be named is one a refusal cannot explain.
    pub fn take(&'static self, holder: u8) -> Option<Ticket> {
        if holder == FREE {
            return None;
        }
        // `Acquire` on the way in and `Release` on the way out: whoever takes it next sees
        // everything the previous holder wrote through it.
        self.holder
            .compare_exchange(FREE, holder, Ordering::Acquire, Ordering::Relaxed)
            .ok()
            .map(|_| Ticket { claim: self })
    }

    /// Who holds it, or `None` if nobody does. For reporting, not for deciding --
    /// deciding is [`take`](Self::take), which cannot race.
    pub fn holder(&self) -> Option<u8> {
        match self.holder.load(Ordering::Relaxed) {
            FREE => None,
            tag => Some(tag),
        }
    }

    /// Whether someone holds it. For reporting, not for deciding -- deciding is
    /// [`take`](Self::take), which cannot race.
    pub fn is_taken(&self) -> bool {
        self.holder.load(Ordering::Relaxed) != FREE
    }
}

impl Default for Claim {
    fn default() -> Self {
        Self::new()
    }
}

/// Proof of holding a [`Claim`]; releases it when dropped.
#[derive(Debug)]
pub struct Ticket {
    claim: &'static Claim,
}

impl Drop for Ticket {
    fn drop(&mut self) {
        self.claim.holder.store(FREE, Ordering::Release);
    }
}

impl core::fmt::Debug for Claim {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Claim")
            .field("holder", &self.holder())
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    static ONE: Claim = Claim::new();
    static TWO: Claim = Claim::new();
    static THREE: Claim = Claim::new();
    static FOUR: Claim = Claim::new();
    static FIVE: Claim = Claim::new();

    // Stand-in tags, as the firmware's users of the medium have.
    const STAGING: u8 = 1;
    const SIGNING: u8 = 2;

    /// A second taker is refused while the first still holds it.
    ///
    /// This is the whole point: the USB path asking for the medium while the card path is
    /// showing an approval must be told no, rather than handed the same bytes to overwrite.
    #[test]
    fn only_one_holder_at_a_time() {
        let first = ONE.take(STAGING).expect("nobody holds it");
        assert!(ONE.is_taken());
        assert!(ONE.take(SIGNING).is_none(), "two holders of one medium");
        drop(first);
        assert!(!ONE.is_taken());
        assert!(ONE.take(SIGNING).is_some(), "released and takeable again");
    }

    /// A refusal can say who has it.
    ///
    /// The point of the tag. "Busy" alone tells a person to try again later without
    /// saying what to wait for; on a device where the same memory holds a firmware
    /// image, a transaction being signed and a QR being read, that is the difference
    /// between a useful message and a power cycle.
    #[test]
    fn the_refusal_names_the_holder() {
        assert_eq!(FOUR.holder(), None, "nobody has it yet");
        let held = FOUR.take(SIGNING).expect("free");
        assert_eq!(FOUR.holder(), Some(SIGNING));
        // The would-be second holder is refused, and what it learns is who has it --
        // not its own tag back, which would name the wrong thing.
        assert!(FOUR.take(STAGING).is_none());
        assert_eq!(
            FOUR.holder(),
            Some(SIGNING),
            "a refused take changes nothing"
        );
        drop(held);
        assert_eq!(FOUR.holder(), None);
    }

    /// Taking it anonymously is refused, rather than recorded as free.
    ///
    /// Zero is the value that means nobody, so a holder using it would take the medium
    /// and leave the claim reading as available -- the exact failure the claim exists to
    /// prevent, reached by asking for it politely.
    #[test]
    fn a_holder_that_cannot_be_named_is_refused() {
        assert!(FIVE.take(0).is_none(), "zero is not a holder");
        assert!(!FIVE.is_taken(), "a refused take must not have taken it");
        assert_eq!(FIVE.holder(), None);
        // And the claim is still usable afterwards.
        let real = FIVE.take(STAGING).expect("still free");
        assert_eq!(FIVE.holder(), Some(STAGING));
        drop(real);
    }

    /// Dropping the ticket is what releases it, wherever that happens.
    ///
    /// Staging ends in several ways -- installed, declined, refused partway, or abandoned
    /// when a screen returns -- and none of them should have to remember to say so.
    #[test]
    fn the_medium_comes_back_however_the_staging_ended() {
        for _ in 0..3 {
            let ticket = TWO.take(STAGING).expect("free at the top of each round");
            // However this round ends, the ticket goes out of scope here.
            drop(ticket);
        }
        assert!(!TWO.is_taken());

        // Including a path that returns early with the ticket still in hand.
        fn refused_partway() -> Option<u32> {
            let _ticket = THREE.take(STAGING)?;
            None
        }
        assert_eq!(refused_partway(), None);
        assert!(!THREE.is_taken(), "an early return still releases it");
    }
}
