//! A ring of bytes that outlives whatever wrote it.
//!
//! Exists because of a device with a dark screen. It enumerated, took a PIN typed blind,
//! and refused an upgrade for a reason that was drawn on a panel nobody could read — and
//! every diagnostic this firmware had ended the same way. A log that can be fetched over
//! USB, or read out of a RAM dump, is the one channel that does not depend on the part
//! that is broken.
//!
//! A ring rather than a growing buffer: boot is the interesting part, but so is whatever
//! happened most recently, and a fixed allocation that never fails is worth more here
//! than a complete history that might. When it wraps, the oldest bytes go.
//!
//! **Nothing secret goes in here.** It is readable by anything that can open the USB
//! port, including a host that has not proved it knows the PIN, and it survives in RAM
//! after a logout. No PIN digits, no seed, no secret material — the rule is that a line
//! must be safe to read aloud to a stranger holding the device.
#![no_std]
#![deny(unsafe_op_in_unsafe_fn)]

/// A byte ring with a linear view over it.
///
/// `N` must be a power of two only for speed, not for correctness — the arithmetic here
/// uses `%`, so any size works.
pub struct Ring<const N: usize> {
    buf: [u8; N],
    /// Where the next byte goes.
    head: usize,
    /// Whether the ring has been round at least once, which is what decides where the
    /// oldest byte is.
    wrapped: bool,
}

impl<const N: usize> Default for Ring<N> {
    fn default() -> Self {
        Self::new()
    }
}

impl<const N: usize> Ring<N> {
    pub const fn new() -> Self {
        Self {
            buf: [0; N],
            head: 0,
            wrapped: false,
        }
    }

    /// Bytes currently held: everything once wrapped, otherwise what was written.
    pub fn len(&self) -> usize {
        if self.wrapped {
            N
        } else {
            self.head
        }
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Whether anything has been dropped off the back.
    pub fn wrapped(&self) -> bool {
        self.wrapped
    }

    /// Append, dropping the oldest bytes when full.
    ///
    /// A write longer than the whole ring keeps its **tail**, not its head: the end of a
    /// long line is where the interesting part usually is, and keeping the front would
    /// leave a truncation with no clue that the rest existed.
    pub fn write(&mut self, data: &[u8]) {
        if N == 0 {
            return;
        }
        let data = if data.len() > N {
            &data[data.len() - N..]
        } else {
            data
        };
        for &b in data {
            self.buf[self.head] = b;
            self.head = (self.head + 1) % N;
            if self.head == 0 {
                self.wrapped = true;
            }
        }
    }

    /// Copy out from `offset`, counting from the **oldest** byte, and return how many
    /// were copied.
    ///
    /// Linear from the reader's point of view: a host paging through with increasing
    /// offsets never has to know where the ring's seam is, which is the arithmetic worth
    /// keeping in one place.
    pub fn read(&self, offset: usize, out: &mut [u8]) -> usize {
        let len = self.len();
        if offset >= len {
            return 0;
        }
        let start = if self.wrapped { self.head } else { 0 };
        let n = out.len().min(len - offset);
        for (i, slot) in out[..n].iter_mut().enumerate() {
            *slot = self.buf[(start + offset + i) % N];
        }
        n
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_empty_ring_reads_nothing() {
        let r: Ring<8> = Ring::new();
        assert_eq!(r.len(), 0);
        assert!(r.is_empty());
        assert_eq!(r.read(0, &mut [0u8; 4]), 0);
    }

    #[test]
    fn what_goes_in_comes_out_in_order() {
        let mut r: Ring<16> = Ring::new();
        r.write(b"hello ");
        r.write(b"world");
        let mut out = [0u8; 16];
        let n = r.read(0, &mut out);
        assert_eq!(&out[..n], b"hello world");
        assert!(!r.wrapped());
    }

    /// The oldest bytes go, and what is left still reads in order — this is the part a
    /// reader cannot check for itself, because a wrapped ring looks like any other.
    #[test]
    fn wrapping_drops_the_oldest_and_keeps_the_order() {
        let mut r: Ring<8> = Ring::new();
        r.write(b"abcdefghij");
        assert!(r.wrapped());
        assert_eq!(r.len(), 8);
        let mut out = [0u8; 8];
        let n = r.read(0, &mut out);
        assert_eq!(&out[..n], b"cdefghij");
    }

    /// Paging must be seamless across the wrap: a host reads with rising offsets and
    /// must not be able to tell where the seam is.
    #[test]
    fn reading_in_pages_matches_reading_all_at_once() {
        let mut r: Ring<16> = Ring::new();
        for i in 0..40u8 {
            r.write(&[b'a' + i % 26]);
        }
        let mut whole = [0u8; 16];
        let n = r.read(0, &mut whole);

        let mut paged = [0u8; 16];
        let mut at = 0;
        while at < n {
            let mut page = [0u8; 5];
            let got = r.read(at, &mut page);
            assert!(got > 0, "paging stalled at {at}");
            paged[at..at + got].copy_from_slice(&page[..got]);
            at += got;
        }
        assert_eq!(&paged[..n], &whole[..n]);
    }

    /// A line longer than the ring keeps its end, not its beginning.
    #[test]
    fn an_oversized_write_keeps_its_tail() {
        let mut r: Ring<4> = Ring::new();
        r.write(b"0123456789");
        let mut out = [0u8; 4];
        let n = r.read(0, &mut out);
        assert_eq!(&out[..n], b"6789");
    }

    #[test]
    fn reading_past_the_end_returns_nothing_rather_than_stale_bytes() {
        let mut r: Ring<8> = Ring::new();
        r.write(b"abc");
        assert_eq!(r.read(3, &mut [0u8; 4]), 0);
        assert_eq!(r.read(99, &mut [0u8; 4]), 0);
    }

    /// A zero-length ring is a degenerate configuration, not a panic.
    #[test]
    fn a_zero_length_ring_is_inert() {
        let mut r: Ring<0> = Ring::new();
        r.write(b"anything");
        assert_eq!(r.len(), 0);
        assert_eq!(r.read(0, &mut [0u8; 4]), 0);
    }
}
