//! The editable digit buffer behind a PIN prompt.
//!
//! Deliberately knows nothing about callgate 18, secure elements or what a PIN means —
//! it is a bounded string of digits with an editing model. That keeps the part with the
//! off-by-one bugs testable on the host, and keeps this crate unable to reach the PIN
//! gate, which is a boundary worth having in a wallet.
//!
//! Digits are held as ASCII, because that is what the bootloader hashes: the gate takes
//! the PIN as bytes, and `b'0'` is not `0`.

use zeroize::{Zeroize, ZeroizeOnDrop};

/// What a rendered digit looks like once entered.
///
/// A count of these is all a shoulder-surfer should get. The buffer never offers the
/// digits back for display; [`PinBuffer::as_bytes`] exists for the gate, not the screen.
pub const MASK: u8 = b'*';

/// A bounded run of decimal digits, with the editing a keypad needs.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct PinBuffer<const N: usize> {
    digits: [u8; N],
    len: usize,
}

impl<const N: usize> Default for PinBuffer<N> {
    fn default() -> Self {
        Self::new()
    }
}

impl<const N: usize> PinBuffer<N> {
    pub const fn new() -> Self {
        Self {
            digits: [0; N],
            len: 0,
        }
    }

    /// Append a digit. Returns false if full or `d > 9`, having changed nothing.
    ///
    /// A full buffer refuses rather than dropping the oldest digit or wrapping: silently
    /// discarding a keypress produces a PIN the user did not type, and they would spend
    /// an attempt discovering it.
    pub fn push(&mut self, d: u8) -> bool {
        if self.len >= N || d > 9 {
            return false;
        }
        self.digits[self.len] = b'0' + d;
        self.len += 1;
        true
    }

    /// Remove the last digit. Returns false if already empty.
    pub fn pop(&mut self) -> bool {
        if self.len == 0 {
            return false;
        }
        self.len -= 1;
        // Overwrite rather than just shortening: a popped digit that stays in the array
        // is still a digit of the user's PIN sitting in RAM.
        self.digits[self.len] = 0;
        true
    }

    /// Forget everything typed so far.
    pub fn clear(&mut self) {
        self.digits.zeroize();
        self.len = 0;
    }

    pub fn len(&self) -> usize {
        self.len
    }

    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    pub fn is_full(&self) -> bool {
        self.len == N
    }

    /// The digits, as the ASCII the gate hashes.
    pub fn as_bytes(&self) -> &[u8] {
        &self.digits[..self.len]
    }

    /// The digits themselves, as text, for a bring-up build.
    ///
    /// **This puts a PIN on the screen.** It exists because during bring-up the question
    /// is whether the keypad decodes to the digit printed on the cap, and a row of
    /// asterisks cannot answer it — a mirrored map produces a PIN that is wrong in a way
    /// that looks exactly like a PIN that is right. Callers must keep it behind a
    /// feature; nothing shipped should ever call it.
    ///
    /// `out` must be at least `N` bytes.
    pub fn visible<'a>(&self, out: &'a mut [u8]) -> &'a str {
        // The buffer already holds ASCII -- `push` stores `b'0' + d`, because that is
        // what the gate hashes. Adding the offset again here turned `1` into `9`.
        let n = self.len.min(out.len());
        out[..n].copy_from_slice(&self.digits[..n]);
        // SAFETY-free: every byte written came from `push`, which only stores digits.
        core::str::from_utf8(&out[..n]).unwrap_or("")
    }

    /// Fill `out` with one [`MASK`] per entered digit and return it as a `str`.
    ///
    /// `out` must be at least `N` bytes. The mask is what goes on screen; the digits
    /// never do.
    pub fn masked<'a>(&self, out: &'a mut [u8]) -> &'a str {
        let n = self.len.min(out.len());
        out[..n].fill(MASK);
        // SAFETY-free: MASK is ASCII, so the filled prefix is valid UTF-8 by
        // construction. `from_utf8` would need an unwrap; this cannot fail.
        core::str::from_utf8(&out[..n]).unwrap_or("")
    }
}

#[cfg(test)]
mod tests {
    /// The bring-up renderer must show the digits that were entered, in order — that is
    /// the entire point of it, and a mask that leaked through here would answer the
    /// keypad question with a row of stars.
    #[test]
    fn visible_shows_the_digits_in_order() {
        let mut b = super::PinBuffer::<8>::new();
        for d in [1u8, 2, 9, 0] {
            b.push(d);
        }
        let mut out = [0u8; 8];
        assert_eq!(b.visible(&mut out), "1290");
        let mut m = [0u8; 8];
        assert_ne!(
            b.masked(&mut m),
            b.visible(&mut out),
            "masking must still mask"
        );
    }

    use super::*;

    #[test]
    fn digits_are_stored_as_the_ascii_the_gate_hashes() {
        // b'0' is 0x30, not 0. Storing the numeric value would produce a PIN of control
        // characters that is wrong in a way nothing on screen would reveal.
        let mut p = PinBuffer::<8>::new();
        for d in [1, 2, 3, 4] {
            assert!(p.push(d));
        }
        assert_eq!(p.as_bytes(), b"1234");
    }

    #[test]
    fn a_full_buffer_refuses_rather_than_dropping_a_digit() {
        // Wrapping or shifting here would hand the gate a PIN the user did not type.
        let mut p = PinBuffer::<4>::new();
        for d in [1, 2, 3, 4] {
            assert!(p.push(d));
        }
        assert!(p.is_full());
        assert!(!p.push(5));
        assert_eq!(p.as_bytes(), b"1234");
    }

    #[test]
    fn popping_overwrites_rather_than_just_shortening() {
        // A digit left behind the length is still a digit of the PIN in RAM.
        let mut p = PinBuffer::<8>::new();
        p.push(7);
        p.push(9);
        assert!(p.pop());
        assert_eq!(p.as_bytes(), b"7");
        assert_eq!(p.digits[1], 0, "the popped digit is still there");
    }

    #[test]
    fn popping_an_empty_buffer_is_a_no_op_not_an_underflow() {
        let mut p = PinBuffer::<4>::new();
        assert!(!p.pop());
        assert!(p.is_empty());
        assert_eq!(p.as_bytes(), b"");
    }

    #[test]
    fn clear_wipes_the_whole_array() {
        let mut p = PinBuffer::<4>::new();
        for d in [1, 2, 3, 4] {
            p.push(d);
        }
        p.clear();
        assert!(p.is_empty());
        assert_eq!(p.digits, [0; 4]);
    }

    #[test]
    fn only_decimal_digits_are_accepted() {
        let mut p = PinBuffer::<4>::new();
        assert!(!p.push(10));
        assert!(!p.push(255));
        assert!(p.is_empty());
    }

    #[test]
    fn the_mask_shows_a_count_and_never_a_digit() {
        let mut p = PinBuffer::<8>::new();
        for d in [9, 8, 7] {
            p.push(d);
        }
        let mut buf = [0u8; 8];
        let shown = p.masked(&mut buf);
        assert_eq!(shown, "***");
        assert!(
            !shown.bytes().any(|b| b.is_ascii_digit()),
            "a digit reached the screen"
        );
    }

    #[test]
    fn masking_into_a_short_buffer_truncates_rather_than_panicking() {
        // The screen is 128 pixels wide and a PIN part can be 15 digits; a caller that
        // sizes its scratch buffer for what fits must not take the device down.
        let mut p = PinBuffer::<16>::new();
        for _ in 0..16 {
            p.push(1);
        }
        let mut small = [0u8; 4];
        assert_eq!(p.masked(&mut small), "****");
    }

    #[test]
    fn an_empty_buffer_masks_to_nothing() {
        let p = PinBuffer::<8>::new();
        let mut buf = [0u8; 8];
        assert_eq!(p.masked(&mut buf), "");
    }
}
