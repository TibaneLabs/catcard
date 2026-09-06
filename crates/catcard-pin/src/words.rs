//! Rendering the bootloader's 32 anti-phishing bits as two words.
//!
//! The bootloader computes the bits (callgate 16, HMAC over the PIN prefix under a key
//! only it holds). How they become words is **ours to define**, because it is a display
//! convention rather than part of the ABI.
//!
//! That freedom has a catch: users memorise their words, so the mapping is effectively
//! permanent from the first device that ships. It is fixed here, with vectors, so a
//! later refactor cannot quietly shift everybody's words by one.
//!
//! CatCard's words will **not** match stock Coldcard's for the same device and prefix,
//! even though both are derived from the same 32 bits. Nothing is wrong when that is
//! observed — the two firmwares simply chose different mappings.

use catcard_bip39::wordlist::{ENGLISH, WORD_COUNT};

/// Bits consumed per word — an index into the 2048-entry list.
pub const BITS_PER_WORD: u32 = 11;

/// The two words shown between the PIN prefix and the suffix.
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub struct Words {
    /// Indices into [`ENGLISH`], in display order.
    pub index: [u16; 2],
}

impl Words {
    /// The words themselves, in display order.
    pub fn as_str(&self) -> [&'static str; 2] {
        [
            ENGLISH[self.index[0] as usize],
            ENGLISH[self.index[1] as usize],
        ]
    }
}

/// Split the gate's 32 bits into two 11-bit wordlist indices.
///
/// The **low** 22 bits are used, most-significant of the pair first, and the top 10 bits
/// are discarded. Discarding is not a weakness: the words exist so a user can recognise
/// their own device, and 22 bits is far more than a person can distinguish by memory.
/// Their strength comes from the attacker not holding the pairing secret, not from the
/// width of this field.
pub const fn from_bits(bits: u32) -> Words {
    let hi = ((bits >> BITS_PER_WORD) & (WORD_COUNT as u32 - 1)) as u16;
    let lo = (bits & (WORD_COUNT as u32 - 1)) as u16;
    Words { index: [hi, lo] }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_mapping_is_pinned_to_these_vectors() {
        // These are the reason this module exists as its own file. Users memorise their
        // words; if this mapping ever shifts, every device in the field starts showing
        // different ones and the anti-phishing check becomes noise. A failure here is
        // never "update the expected value".
        for (bits, expect) in [
            (0x0000_0000u32, ["abandon", "abandon"]),
            (0x0000_0001, ["abandon", "ability"]),
            (0x0000_0800, ["ability", "abandon"]),
            (0x003f_ffff, ["zoo", "zoo"]),
            (0xffc0_0000, ["abandon", "abandon"]),
            (0xdead_beef, ["report", "target"]),
            (0x5555_aaaa, ["find", "fetch"]),
        ] {
            assert_eq!(from_bits(bits).as_str(), expect, "bits {bits:#010x}");
        }
    }

    #[test]
    fn the_top_ten_bits_are_ignored() {
        // Stated as a test because it is the part a reader is most likely to doubt.
        for extra in 0..1024u32 {
            assert_eq!(
                from_bits(0x0012_3456 | (extra << 22)),
                from_bits(0x0012_3456)
            );
        }
    }

    #[test]
    fn every_index_is_inside_the_wordlist() {
        // 11 bits addresses exactly 2048, so this cannot fail by arithmetic — it fails
        // if the wordlist is ever not 2048 long, which would make `as_str` panic on a
        // device rather than here.
        assert_eq!(WORD_COUNT, 1 << BITS_PER_WORD);
        for bits in [0u32, 0x003f_ffff, 0xffff_ffff, 0x5555_5555, 0xaaaa_aaaa] {
            let w = from_bits(bits);
            assert!(w.index.iter().all(|&i| (i as usize) < WORD_COUNT));
            let _ = w.as_str();
        }
    }
}
