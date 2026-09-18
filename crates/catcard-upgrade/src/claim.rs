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
//! The alternative considered was re-reading the staged bytes at the moment of installing
//! and comparing them against what was approved. That is sound but costs a second pass over
//! the whole image, on a bus that has to be handed back to the part every few microseconds,
//! at the moment after someone has pressed yes. A lock costs nothing and refuses the second
//! writer at the door instead.

use core::sync::atomic::{AtomicBool, Ordering};

/// A medium that only one holder may have at a time.
pub struct Claim {
    taken: AtomicBool,
}

impl Claim {
    /// A claim nobody holds.
    pub const fn new() -> Self {
        Self {
            taken: AtomicBool::new(false),
        }
    }

    /// Take it, or `None` if someone already has it.
    ///
    /// The claim is `'static` because the ticket outlives the call: it lives as long as the
    /// staging does, which on this device is until a screen returns.
    pub fn take(&'static self) -> Option<Ticket> {
        // `Acquire` on the way in and `Release` on the way out: whoever takes it next sees
        // everything the previous holder wrote through it.
        if self.taken.swap(true, Ordering::Acquire) {
            None
        } else {
            Some(Ticket { claim: self })
        }
    }

    /// Whether someone holds it. For reporting, not for deciding -- deciding is
    /// [`take`](Self::take), which cannot race.
    pub fn is_taken(&self) -> bool {
        self.taken.load(Ordering::Relaxed)
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
        self.claim.taken.store(false, Ordering::Release);
    }
}

impl core::fmt::Debug for Claim {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Claim")
            .field("taken", &self.is_taken())
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    static ONE: Claim = Claim::new();
    static TWO: Claim = Claim::new();
    static THREE: Claim = Claim::new();

    /// A second taker is refused while the first still holds it.
    ///
    /// This is the whole point: the USB path asking for the medium while the card path is
    /// showing an approval must be told no, rather than handed the same bytes to overwrite.
    #[test]
    fn only_one_holder_at_a_time() {
        let first = ONE.take().expect("nobody holds it");
        assert!(ONE.is_taken());
        assert!(ONE.take().is_none(), "two holders of one medium");
        drop(first);
        assert!(!ONE.is_taken());
        assert!(ONE.take().is_some(), "released and takeable again");
    }

    /// Dropping the ticket is what releases it, wherever that happens.
    ///
    /// Staging ends in several ways -- installed, declined, refused partway, or abandoned
    /// when a screen returns -- and none of them should have to remember to say so.
    #[test]
    fn the_medium_comes_back_however_the_staging_ended() {
        for _ in 0..3 {
            let ticket = TWO.take().expect("free at the top of each round");
            // However this round ends, the ticket goes out of scope here.
            drop(ticket);
        }
        assert!(!TWO.is_taken());

        // Including a path that returns early with the ticket still in hand.
        fn refused_partway() -> Option<u32> {
            let _ticket = THREE.take()?;
            None
        }
        assert_eq!(refused_partway(), None);
        assert!(!THREE.is_taken(), "an early return still releases it");
    }
}
