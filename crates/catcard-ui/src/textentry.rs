//! Typing exact text on a keypad that has ten keys.
//!
//! The seed-word entry can match a prefix against a wordlist, so it never has to know which
//! letter was meant. A passphrase has no wordlist: every character has to be chosen exactly,
//! on a keypad with no letters printed on it. So this is the old phone method -- press a key
//! repeatedly to walk its characters, pause or move on to commit -- as a state machine, so
//! the cycling, the commit rules and the capacity are testable without a device.
//!
//! The Q1 has a real keyboard and needs none of this: it pushes characters straight in with
//! [`Entry::put`].
//!
//! Nothing here holds a secret longer than the caller does: the buffer is the caller's to
//! zeroize, and [`Entry::clear`] wipes it.

use zeroize::Zeroize;

/// Characters each keypad digit walks, in order.
///
/// Lower case first because that is what most passphrases are, then the digit itself, then
/// upper case. `1` carries punctuation and `0` the space.
pub const KEYS: [&str; 10] = [
    " 0",          // 0
    ".,!?@#$%&*-_+=/:;'\"()", // 1
    "abc2ABC",     // 2
    "def3DEF",     // 3
    "ghi4GHI",     // 4
    "jkl5JKL",     // 5
    "mno6MNO",     // 6
    "pqrs7PQRS",   // 7
    "tuv8TUV",     // 8
    "wxyz9WXYZ",   // 9
];

/// Longest text this holds. Stock's passphrase limit is 100 characters; this matches it.
/// Source: BIP-39 puts no limit on the passphrase; 100 is stock's, kept for interop of
/// habit rather than of format.
pub const MAX_LEN: usize = 100;

/// Text being typed on a keypad.
#[derive(Default)]
pub struct Entry {
    text: heapless::String<MAX_LEN>,
    /// The key being cycled and how far along its characters, if one is.
    pending: Option<(usize, usize)>,
}

impl Entry {
    pub const fn new() -> Self {
        Self {
            text: heapless::String::new(),
            pending: None,
        }
    }

    pub fn as_str(&self) -> &str {
        &self.text
    }

    pub fn len(&self) -> usize {
        self.text.len()
    }

    pub fn is_empty(&self) -> bool {
        self.text.is_empty()
    }

    /// Whether a key is mid-cycle, i.e. the last character can still change.
    pub fn cycling(&self) -> bool {
        self.pending.is_some()
    }

    /// Press keypad digit `digit`.
    ///
    /// Pressing the same digit again walks its characters, replacing the last one; pressing
    /// a different digit commits what is there and starts the new key. Full, it does
    /// nothing rather than dropping the press silently into a wrapped buffer.
    pub fn press(&mut self, digit: u8) {
        let Some(chars) = KEYS.get(digit as usize) else {
            return;
        };
        let count = chars.chars().count();
        if count == 0 {
            return;
        }
        match self.pending {
            Some((key, at)) if key == digit as usize => {
                let next = (at + 1) % count;
                self.replace_last(chars.chars().nth(next).unwrap_or(' '));
                self.pending = Some((key, next));
            }
            _ => {
                if self.text.len() == MAX_LEN {
                    return;
                }
                let _ = self.text.push(chars.chars().next().unwrap_or(' '));
                self.pending = Some((digit as usize, 0));
            }
        }
    }

    /// Put `c` in directly, for a board with a keyboard. Commits any cycling key first.
    pub fn put(&mut self, c: char) {
        self.pending = None;
        let _ = self.text.push(c);
    }

    /// Commit the character being cycled, so the next press of the same key adds another.
    ///
    /// The caller decides when: after a pause, or when the owner moves on deliberately.
    pub fn commit(&mut self) {
        self.pending = None;
    }

    /// Remove the last character, cycling or not. True if there was one.
    pub fn backspace(&mut self) -> bool {
        self.pending = None;
        self.text.pop().is_some()
    }

    pub fn clear(&mut self) {
        self.pending = None;
        // Wipe the whole buffer, not just the part in use: the tail still holds what was
        // typed before a backspace.
        let mut bytes = core::mem::take(&mut self.text).into_bytes();
        bytes.zeroize();
    }

    fn replace_last(&mut self, c: char) {
        self.text.pop();
        let _ = self.text.push(c);
    }
}

impl Drop for Entry {
    fn drop(&mut self) {
        self.clear();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Type a string of keypad digits, committing between different keys the way the screen
    /// does, and pressing the same key repeatedly to cycle.
    fn typed(presses: &[(u8, usize)]) -> String {
        let mut e = Entry::new();
        for &(digit, times) in presses {
            for _ in 0..times {
                e.press(digit);
            }
            e.commit();
        }
        e.as_str().to_string()
    }

    #[test]
    fn a_key_walks_its_characters_and_wraps() {
        // 2 -> a, aa -> b, aaa -> c, then the digit, then upper case, then back to a.
        assert_eq!(typed(&[(2, 1)]), "a");
        assert_eq!(typed(&[(2, 2)]), "b");
        assert_eq!(typed(&[(2, 3)]), "c");
        assert_eq!(typed(&[(2, 4)]), "2");
        assert_eq!(typed(&[(2, 5)]), "A");
        assert_eq!(typed(&[(2, 8)]), "a", "seven characters, so the eighth wraps");
    }

    #[test]
    fn a_different_key_commits_the_last_character() {
        // "cat": 2 three times, then 2 once (committed), then 8 once.
        assert_eq!(typed(&[(2, 3), (2, 1), (8, 1)]), "cat");
        // Without the commit between them, the second press would have cycled instead.
        let mut e = Entry::new();
        for _ in 0..3 {
            e.press(2);
        }
        e.press(2);
        assert_eq!(e.as_str(), "2", "same key, still cycling");
    }

    #[test]
    fn the_space_and_the_punctuation_keys_are_reachable() {
        assert_eq!(typed(&[(0, 1)]), " ");
        assert_eq!(typed(&[(0, 2)]), "0");
        assert_eq!(typed(&[(1, 1)]), ".");
        assert_eq!(typed(&[(1, 3)]), "!");
    }

    #[test]
    fn backspace_removes_what_was_typed_cycling_or_not() {
        let mut e = Entry::new();
        e.press(2);
        e.press(2); // cycling: "b"
        assert!(e.backspace());
        assert_eq!(e.as_str(), "");
        assert!(!e.cycling());
        assert!(!e.backspace(), "nothing left to remove");
    }

    #[test]
    fn a_keyboard_puts_characters_in_directly() {
        let mut e = Entry::new();
        for c in "Corréct hörse".chars() {
            e.put(c);
        }
        assert_eq!(e.as_str(), "Corréct hörse");
    }

    #[test]
    fn it_fills_up_rather_than_wrapping_or_truncating_silently() {
        let mut e = Entry::new();
        for _ in 0..MAX_LEN {
            e.press(0);
            e.commit();
        }
        assert_eq!(e.len(), MAX_LEN);
        e.press(2);
        assert_eq!(e.len(), MAX_LEN, "a press past the end changes nothing");
        // Cycling the last character still works when full.
        e.commit();
        assert!(e.backspace());
        e.press(2);
        e.press(2);
        assert_eq!(e.as_str().chars().last(), Some('b'));
    }

    #[test]
    fn clearing_empties_it() {
        let mut e = Entry::new();
        for c in "secret".chars() {
            e.put(c);
        }
        e.clear();
        assert!(e.is_empty());
        assert_eq!(e.as_str(), "");
    }

    #[test]
    fn every_key_has_characters_and_none_are_shared() {
        let mut seen = std::collections::BTreeSet::new();
        for (i, k) in KEYS.iter().enumerate() {
            assert!(!k.is_empty(), "key {i} has no characters");
            for c in k.chars() {
                assert!(seen.insert(c), "{c:?} appears on two keys");
            }
        }
        // Every lower-case letter is typable.
        for c in 'a'..='z' {
            assert!(seen.contains(&c), "{c} is not on any key");
        }
    }
}
