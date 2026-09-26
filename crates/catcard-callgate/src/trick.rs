//! The trick-PIN slot passed to callgate 22, and the flag word a trick carries.
//!
//! A trick PIN is a second PIN the second secure element (SE2) recognises: entering it at
//! the login prompt fires an effect -- wipe the seed, brick the device, open a decoy
//! wallet -- *inside* the bootloader, before gate 18 returns, and the login then reports
//! success as though the PIN were the real one. Fourteen slots, SE2 pages 0 to 13; a
//! duress wallet's secret takes the one or two pages after its own.
//!
//! This module is the bytes: the 128-byte `trick_slot_t` that follows the signed
//! `pinAttempt_t` in method 22's buffer, the `tc_flags` bits, and the page arithmetic the
//! bootloader checks. It decides nothing about what a trick should be -- that is
//! `catcard_pin::trick`.
//!
//! Source: hw-reference/trick-pin-slot-format.md [C] (every offset, flag and page rule
//! here); secure-elements.md §Trick PINs [C]. **mk4 and later only**: the mk3 has no SE2
//! and its bootloader has no method 22.

use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::pin::{PIN_ATTEMPT_SIZE, SECRET_LEN};

/// Trick slots in SE2: pages 0 to 13.
/// Source: trick-pin-slot-format.md §3.1 (`NUM_TRICKS = 14`) [C]
pub const NUM_TRICKS: usize = 14;

/// `sizeof(trick_slot_t)`, asserted by the bootloader and by stock's firmware alike.
/// Source: trick-pin-slot-format.md §1.1, §1.3 [C]
pub const TRICK_SLOT_SIZE: usize = 128;

/// Method 22's whole buffer: the signed `pinAttempt_t`, then the slot.
/// Source: trick-pin-slot-format.md §1.1 (`REQUIRE_OUT(280 + 128)`) [C]
pub const TRICK_BUF_LEN: usize = PIN_ATTEMPT_SIZE + TRICK_SLOT_SIZE;

/// Longest PIN a slot holds. The bootloader refuses a longer `pin_len` with `ERANGE`.
/// Source: trick-pin-slot-format.md §1.3 [C]
pub const TRICK_PIN_MAX: usize = 16;

/// Largest duress secret a slot carries: 64 bytes, for an xprv wallet.
pub const XDATA_LEN: usize = 64;

const _: () = assert!(TRICK_BUF_LEN == 408);
const _: () = assert!(TRICK_BUF_LEN <= crate::abi::MAX_BUF_LEN);

/// `tc_flags` bits.
///
/// The top five ([`HIDDEN_MASK`]) are acted on by the bootloader and **censored** before
/// the login reports a trick: firmware never learns that a wipe, a brick, a fake-out or a
/// duress wallet fired. The rest reach the firmware in the attempt's `delay_required`.
///
/// Source: trick-pin-slot-format.md §1.4 [C]; secure-elements.md §Trick PINs [C]
pub mod tc {
    /// Erase the seed (the MCU key) as the PIN is checked.
    pub const WIPE: u16 = 0x8000;
    /// Destroy the pairing secret: the device never works again.
    pub const BRICK: u16 = 0x4000;
    /// Answer as a wrong PIN would. Usually with [`WIPE`].
    pub const FAKE_OUT: u16 = 0x2000;
    /// A BIP-39 duress wallet: 16 or 32 bytes of entropy in the next page.
    pub const WORD_WALLET: u16 = 0x1000;
    /// An xprv duress wallet: chain code and key in the next two pages.
    pub const XPRV_WALLET: u16 = 0x0800;
    /// Delta mode: log into the *real* wallet with a PIN that differs from the true one
    /// in its last digits. Deliberately not hidden -- the firmware must know.
    pub const DELTA_MODE: u16 = 0x0400;
    /// Reboot, inside the bootloader.
    pub const REBOOT: u16 = 0x0200;
    /// No bootloader action (`TC_RFU`); the firmware's to define (`TC_FW_DEFINED`).
    /// Stock uses it, with `tc_arg` [`super::TCA_SP_UNLOCK`], for the spending policy's
    /// unlock PIN.
    pub const FW_DEFINED: u16 = 0x0100;
    /// Firmware only: look like a device with no wallet.
    pub const BLANK_WALLET: u16 = 0x0080;
    /// Firmware only: show a login countdown of `tc_arg` minutes.
    pub const COUNTDOWN: u16 = 0x0040;

    /// Flags the login never reports (`TC_HIDDEN_MASK`).
    pub const HIDDEN_MASK: u16 = 0xf800;
}

/// `tc_arg` of a [`tc::FW_DEFINED`] trick that unlocks the spending policy.
/// Source: trick-pin-slot-format.md §1.4 (`TCA_SP_UNLOCK = 0x0001`) [C]
pub const TCA_SP_UNLOCK: u16 = 0x0001;

/// The flags a login reports for a trick with `flags`: the hidden ones removed.
/// Source: trick-pin-slot-format.md §2.2 (`delay_required = tc_flags & ~TC_HIDDEN_MASK`) [C]
pub const fn censor(flags: u16) -> u16 {
    flags & !tc::HIDDEN_MASK
}

/// How many data pages after its own a trick with `flags` occupies: two for an xprv
/// wallet, one for a word wallet, none otherwise.
/// Source: trick-pin-slot-format.md §3.1 [C]
pub const fn data_pages(flags: u16) -> usize {
    if flags & tc::XPRV_WALLET != 0 {
        2
    } else if flags & tc::WORD_WALLET != 0 {
        1
    } else {
        0
    }
}

/// Pages in all: the slot's own and its data pages.
pub const fn pages(flags: u16) -> usize {
    1 + data_pages(flags)
}

/// Whether a trick with `flags` may start at `slot_num`: its data pages must fit below
/// page 14. The bootloader answers anything else with `EPIN_RANGE_ERR`.
/// Source: trick-pin-slot-format.md §3.1 (range checks in `se2_save_trick`) [C]
pub const fn fits(slot_num: usize, flags: u16) -> bool {
    slot_num + pages(flags) <= NUM_TRICKS
}

/// The `blank_slots` bits that erase a trick at `slot_num` with `flags`: its own page and
/// every data page. `None` when it would run past the last page.
pub const fn blank_mask(slot_num: usize, flags: u16) -> Option<u32> {
    if !fits(slot_num, flags) {
        return None;
    }
    let n = pages(flags) as u32;
    Some(((1u32 << n) - 1) << slot_num)
}

/// The lowest slot a trick with `flags` can take, given `blank` -- the bootloader's
/// `blank_slots`, where a set bit is an empty page. `None` when there is no run of empty
/// pages long enough.
pub fn first_free(blank: u32, flags: u16) -> Option<usize> {
    (0..NUM_TRICKS).find(|&s| blank_mask(s, flags).is_some_and(|m| blank & m == m))
}

/// The four bytes stored after the PIN hash: `tc_flags` then `tc_arg`, little-endian,
/// before they are XOR-ed with the hash's tail.
/// Source: trick-pin-slot-format.md §3.4 [C]
pub const fn meta(flags: u16, arg: u16) -> [u8; 4] {
    let f = flags.to_le_bytes();
    let a = arg.to_le_bytes();
    [f[0], f[1], a[0], a[1]]
}

/// `tail ^ meta`: what the page's last four bytes hold, and -- applied again with the
/// same tail -- how the bootloader recovers the meta on a match. This firmware never
/// sees a PIN hash; the function exists so the worked example in the reference is a test.
/// Source: trick-pin-slot-format.md §3.4 (`xor_mixin`) [C]
pub const fn mix(tail: [u8; 4], meta: [u8; 4]) -> [u8; 4] {
    [
        tail[0] ^ meta[0],
        tail[1] ^ meta[1],
        tail[2] ^ meta[2],
        tail[3] ^ meta[3],
    ]
}

/// The 72-byte secret gate 18/4 returns after a login with a duress trick of `flags`
/// whose data is `xdata`, as the bootloader builds it.
///
/// A model, not something the firmware computes at login -- there the bootloader hands
/// this back and the firmware cannot tell it from the real one. It is what "Activate
/// Wallet" must land in, and what the tests hold the slot encoding to.
///
/// Source: trick-pin-slot-format.md §2.4 [C]
pub fn duress_secret(flags: u16, xdata: &[u8; XDATA_LEN]) -> [u8; SECRET_LEN] {
    let mut out = [0u8; SECRET_LEN];
    if flags & tc::WORD_WALLET != 0 {
        if xdata[16..32].iter().all(|&b| b == 0) {
            out[0] = 0x80;
            out[1..17].copy_from_slice(&xdata[..16]);
        } else {
            out[0] = 0x82;
            out[1..33].copy_from_slice(&xdata[..32]);
        }
    } else if flags & tc::XPRV_WALLET != 0 {
        out[0] = crate::pin::XPRV_MARKER;
        out[1..65].copy_from_slice(xdata);
    }
    out
}

/// `trick_slot_t`: method 22's request and answer, after the `pinAttempt_t`.
///
/// Little-endian, packed, 128 bytes. The field order and widths put every field on its
/// natural alignment, so `repr(C)` has no padding; the layout is still marshalled
/// explicitly by [`Self::to_bytes`] and [`Self::from_bytes`], because the same bytes are
/// read by a host test and by the device.
///
/// Holds a PIN and possibly a duress wallet's secret: zeroed on drop.
///
/// Source: trick-pin-slot-format.md §1.3 [C] (offsets asserted by the bootloader:
/// `slot_num@0, tc_flags@4, tc_arg@6, xdata@8, pin@72, pin_len@88, blank_slots@92,
/// spare@96`)
#[repr(C)]
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct TrickSlot {
    /// Slot index 0 to 13, or -1 when a lookup found nothing.
    pub slot_num: i32,
    /// [`tc`] bits.
    pub tc_flags: u16,
    /// The trick's argument: a BIP-85 index, countdown minutes, [`TCA_SP_UNLOCK`].
    pub tc_arg: u16,
    /// A duress wallet's secret: 16 or 32 bytes of BIP-39 entropy, or a 64-byte xprv.
    pub xdata: [u8; XDATA_LEN],
    /// The PIN, ASCII, `prefix-suffix`.
    pub pin: [u8; TRICK_PIN_MAX],
    pub pin_len: i32,
    /// Bit `i` set: page `i` is empty. An output of a lookup; an input to a save, where
    /// non-zero means "blank these pages and write nothing else".
    pub blank_slots: u32,
    pub spare: [u32; 8],
}

const _: () = assert!(core::mem::size_of::<TrickSlot>() == TRICK_SLOT_SIZE);

/// A PIN that does not fit a slot's 16 bytes.
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub struct TrickPinTooLong;

impl Default for TrickSlot {
    fn default() -> Self {
        Self::new()
    }
}

impl TrickSlot {
    pub const fn new() -> Self {
        Self {
            slot_num: 0,
            tc_flags: 0,
            tc_arg: 0,
            xdata: [0; XDATA_LEN],
            pin: [0; TRICK_PIN_MAX],
            pin_len: 0,
            blank_slots: 0,
            spare: [0; 8],
        }
    }

    /// A lookup request for `pin`.
    pub fn lookup(pin: &[u8]) -> Result<Self, TrickPinTooLong> {
        let mut s = Self::new();
        s.set_pin(pin)?;
        Ok(s)
    }

    /// A save request that blanks every page in `mask` and writes nothing else.
    /// Source: trick-pin-slot-format.md §3.4 (`blank_slots` as input) [C]
    pub fn blanking(mask: u32) -> Self {
        let mut s = Self::new();
        s.blank_slots = mask;
        s
    }

    pub fn set_pin(&mut self, pin: &[u8]) -> Result<(), TrickPinTooLong> {
        if pin.len() > TRICK_PIN_MAX {
            return Err(TrickPinTooLong);
        }
        self.pin.zeroize();
        self.pin[..pin.len()].copy_from_slice(pin);
        self.pin_len = pin.len() as i32;
        Ok(())
    }

    /// The 128 bytes the bootloader reads.
    pub fn to_bytes(&self) -> [u8; TRICK_SLOT_SIZE] {
        let mut b = [0u8; TRICK_SLOT_SIZE];
        b[0..4].copy_from_slice(&self.slot_num.to_le_bytes());
        b[4..6].copy_from_slice(&self.tc_flags.to_le_bytes());
        b[6..8].copy_from_slice(&self.tc_arg.to_le_bytes());
        b[8..72].copy_from_slice(&self.xdata);
        b[72..88].copy_from_slice(&self.pin);
        b[88..92].copy_from_slice(&self.pin_len.to_le_bytes());
        b[92..96].copy_from_slice(&self.blank_slots.to_le_bytes());
        for (i, w) in self.spare.iter().enumerate() {
            b[96 + 4 * i..100 + 4 * i].copy_from_slice(&w.to_le_bytes());
        }
        b
    }

    /// The slot as the bootloader wrote it back.
    pub fn from_bytes(b: &[u8; TRICK_SLOT_SIZE]) -> Self {
        let w = |at: usize| u32::from_le_bytes([b[at], b[at + 1], b[at + 2], b[at + 3]]);
        let mut s = Self::new();
        s.slot_num = w(0) as i32;
        s.tc_flags = u16::from_le_bytes([b[4], b[5]]);
        s.tc_arg = u16::from_le_bytes([b[6], b[7]]);
        s.xdata.copy_from_slice(&b[8..72]);
        s.pin.copy_from_slice(&b[72..88]);
        s.pin_len = w(88) as i32;
        s.blank_slots = w(92);
        for (i, sp) in s.spare.iter_mut().enumerate() {
            *sp = w(96 + 4 * i);
        }
        s
    }

    /// The slot index, if the bootloader named one (a lookup that missed says -1).
    pub fn slot(&self) -> Option<usize> {
        usize::try_from(self.slot_num)
            .ok()
            .filter(|&s| s < NUM_TRICKS)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use core::mem::offset_of;

    #[test]
    fn the_slot_is_the_documented_128_bytes_at_the_documented_offsets() {
        assert_eq!(core::mem::size_of::<TrickSlot>(), 128);
        assert_eq!(offset_of!(TrickSlot, slot_num), 0);
        assert_eq!(offset_of!(TrickSlot, tc_flags), 4);
        assert_eq!(offset_of!(TrickSlot, tc_arg), 6);
        assert_eq!(offset_of!(TrickSlot, xdata), 8);
        assert_eq!(offset_of!(TrickSlot, pin), 72);
        assert_eq!(offset_of!(TrickSlot, pin_len), 88);
        assert_eq!(offset_of!(TrickSlot, blank_slots), 92);
        assert_eq!(offset_of!(TrickSlot, spare), 96);
        assert_eq!(TRICK_BUF_LEN, 280 + 128);
    }

    /// trick-pin-slot-format.md §5.1: PIN "11-22", a 12-word duress wallet, slot 5,
    /// `tc_arg` 2025, entropy `AA` x16. Every byte of the marshalled request.
    #[test]
    fn the_worked_example_marshals_byte_for_byte() {
        let mut s = TrickSlot::new();
        s.slot_num = 5;
        s.tc_flags = tc::WORD_WALLET;
        s.tc_arg = 2025;
        s.xdata[..16].fill(0xAA);
        s.set_pin(b"11-22").unwrap();
        let b = s.to_bytes();

        let mut want = [0u8; 128];
        want[0..4].copy_from_slice(&[0x05, 0x00, 0x00, 0x00]);
        want[4..6].copy_from_slice(&[0x00, 0x10]);
        want[6..8].copy_from_slice(&[0xE9, 0x07]);
        want[8..24].fill(0xAA);
        want[72..77].copy_from_slice(&[0x31, 0x31, 0x2D, 0x32, 0x32]);
        want[88..92].copy_from_slice(&[0x05, 0x00, 0x00, 0x00]);
        assert_eq!(b, want);

        // And back.
        let r = TrickSlot::from_bytes(&b);
        assert_eq!(r.slot(), Some(5));
        assert_eq!(r.tc_flags, 0x1000);
        assert_eq!(r.tc_arg, 2025);
        assert_eq!(&r.xdata[..16], &[0xAA; 16]);
        assert!(r.xdata[16..].iter().all(|&x| x == 0));
        assert_eq!(&r.pin[..5], b"11-22");
        assert_eq!(r.pin_len, 5);
        assert_eq!(r.blank_slots, 0);
    }

    /// §5.1 again: meta `[00 10 E9 07]` mixed into the illustrative tail `[E0 E1 E2 E3]`
    /// is `[E0 F1 0B E4]`, and mixing again recovers the meta.
    #[test]
    fn the_worked_example_meta_mixes_as_documented() {
        let m = meta(tc::WORD_WALLET, 2025);
        assert_eq!(m, [0x00, 0x10, 0xE9, 0x07]);
        let tail = [0xE0, 0xE1, 0xE2, 0xE3];
        let stored = mix(tail, m);
        assert_eq!(stored, [0xE0, 0xF1, 0x0B, 0xE4]);
        assert_eq!(mix(tail, stored), m);
    }

    /// §5.3: that slot's fetch is `0x80` then the sixteen entropy bytes, zeros after.
    #[test]
    fn the_worked_example_fetches_a_12_word_secret() {
        let mut x = [0u8; XDATA_LEN];
        x[..16].fill(0xAA);
        let s = duress_secret(tc::WORD_WALLET, &x);
        assert_eq!(s[0], 0x80);
        assert_eq!(&s[1..17], &[0xAA; 16]);
        assert!(s[17..].iter().all(|&b| b == 0));
    }

    #[test]
    fn the_other_duress_shapes_fetch_as_the_stash_says() {
        let mut x = [0u8; XDATA_LEN];
        x[..32].fill(0x11);
        let s = duress_secret(tc::WORD_WALLET, &x);
        assert_eq!(s[0], 0x82);
        assert_eq!(&s[1..33], &[0x11; 32]);

        x[32..].fill(0x22);
        let s = duress_secret(tc::XPRV_WALLET, &x);
        assert_eq!(s[0], 0x01);
        assert_eq!(&s[1..65], &x[..]);
        assert!(s[65..].iter().all(|&b| b == 0));

        // No wallet flag: a blank duress, all zero.
        assert_eq!(duress_secret(tc::WIPE, &x), [0u8; SECRET_LEN]);
    }

    #[test]
    fn flag_values_match_the_reference_table() {
        assert_eq!(tc::WIPE, 0x8000);
        assert_eq!(tc::BRICK, 0x4000);
        assert_eq!(tc::FAKE_OUT, 0x2000);
        assert_eq!(tc::WORD_WALLET, 0x1000);
        assert_eq!(tc::XPRV_WALLET, 0x0800);
        assert_eq!(tc::DELTA_MODE, 0x0400);
        assert_eq!(tc::REBOOT, 0x0200);
        assert_eq!(tc::FW_DEFINED, 0x0100);
        assert_eq!(tc::BLANK_WALLET, 0x0080);
        assert_eq!(tc::COUNTDOWN, 0x0040);
        assert_eq!(tc::HIDDEN_MASK, 0xf800);
        assert_eq!(TCA_SP_UNLOCK, 1);
    }

    #[test]
    fn the_login_never_reports_a_hidden_flag_and_always_reports_delta() {
        let every = tc::WIPE
            | tc::BRICK
            | tc::FAKE_OUT
            | tc::WORD_WALLET
            | tc::XPRV_WALLET
            | tc::DELTA_MODE
            | tc::REBOOT
            | tc::FW_DEFINED
            | tc::BLANK_WALLET
            | tc::COUNTDOWN;
        let seen = censor(every);
        assert_eq!(seen & tc::HIDDEN_MASK, 0);
        assert_ne!(seen & tc::DELTA_MODE, 0);
        // A pure duress wallet reports nothing at all: that is the point of it.
        assert_eq!(censor(tc::WORD_WALLET), 0);
        assert_eq!(censor(tc::WIPE | tc::XPRV_WALLET), 0);
    }

    #[test]
    fn data_pages_and_the_range_checks() {
        assert_eq!(pages(tc::WIPE), 1);
        assert_eq!(pages(tc::WORD_WALLET), 2);
        assert_eq!(pages(tc::XPRV_WALLET), 3);
        // A word wallet cannot start at 13; an xprv wallet not at 12 or 13.
        assert!(fits(13, tc::WIPE));
        assert!(fits(12, tc::WORD_WALLET));
        assert!(!fits(13, tc::WORD_WALLET));
        assert!(fits(11, tc::XPRV_WALLET));
        assert!(!fits(12, tc::XPRV_WALLET));
        assert!(!fits(13, tc::XPRV_WALLET));
        assert!(!fits(14, tc::BRICK));
    }

    #[test]
    fn blank_masks_cover_the_slot_and_its_data_pages() {
        assert_eq!(blank_mask(5, tc::WORD_WALLET), Some(0b11 << 5));
        assert_eq!(blank_mask(0, tc::XPRV_WALLET), Some(0b111));
        assert_eq!(blank_mask(13, tc::REBOOT), Some(1 << 13));
        assert_eq!(blank_mask(13, tc::WORD_WALLET), None);
    }

    #[test]
    fn a_free_slot_needs_a_long_enough_run_of_empty_pages() {
        let all = (1u32 << NUM_TRICKS) - 1;
        assert_eq!(first_free(all, tc::XPRV_WALLET), Some(0));
        // Page 0 used, 1 empty, 2 used: a word wallet has to go to 3.
        let blank = all & !0b101;
        assert_eq!(first_free(blank, tc::WIPE), Some(1));
        assert_eq!(first_free(blank, tc::WORD_WALLET), Some(3));
        // Only page 13 left: room for a one-page trick, not a wallet.
        assert_eq!(first_free(1 << 13, tc::REBOOT), Some(13));
        assert_eq!(first_free(1 << 13, tc::WORD_WALLET), None);
        assert_eq!(first_free(0, tc::REBOOT), None);
    }

    #[test]
    fn a_pin_longer_than_the_slot_is_refused_and_a_short_one_clears_the_rest() {
        let mut s = TrickSlot::lookup(b"123456-123456").unwrap();
        assert!(s.set_pin(&[b'1'; 17]).is_err());
        s.set_pin(b"12-34").unwrap();
        assert!(s.pin[5..].iter().all(|&b| b == 0));
        assert_eq!(s.pin_len, 5);
    }

    #[test]
    fn a_missed_lookup_names_no_slot() {
        let mut s = TrickSlot::new();
        s.slot_num = -1;
        assert_eq!(s.slot(), None);
        s.slot_num = 14;
        assert_eq!(s.slot(), None);
    }

    #[test]
    fn a_blanking_request_carries_only_the_mask() {
        let b = TrickSlot::blanking(0b110).to_bytes();
        assert_eq!(&b[92..96], &[0b110, 0, 0, 0]);
        assert!(b[..92].iter().all(|&x| x == 0));
    }
}
