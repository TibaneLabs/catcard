//! The Precursor's keyboard: which key sits at which (row, column) of its 9x10 matrix,
//! and what each means to the screens.
//!
//! The matrix is scanned and debounced by the Precursor's gateware, which publishes one
//! column mask per row; the board turns those into [`Event`]s with [`events`]. Unlike the
//! Q1 ([`crate::qwerty`]) there is no scan for firmware to shuffle: the gateware drives
//! the columns in its own fixed order, so that mitigation is not available here.
//!
//! The positions were established twice, independently: on a pvt2 unit, every key pressed
//! once in reading order with the matrix position logged (2026-11-06), and Xous's own
//! QWERTY map, which agrees with all 54. Source: catcard-precursor key test [C];
//! xous-core services/keyboard/src/mappings/qwerty.rs [C].
//!
//! # Meaning
//!
//! The screens are written against the numpad's [`Key`] set, so this maps onto it the way
//! [`crate::qwerty`] does for the Q1: the number row types digits, letters and symbols type
//! [`Key::Char`], ENTER and the navigation pad's centre confirm, backspace cancels (it is
//! delete in a PIN field), and the pad's arrows take the numpad's arrow digits -- `5` up,
//! `8` down, `7` left, `9` right -- so menus move the way the arrows point. F1-F4, the two
//! shifts and SYM produce nothing yet.

use crate::keypad::{Event, Key};

/// Matrix rows. Source: betrusted_soc.py `kbd` pads [C]
pub const ROWS: usize = 9;
/// Matrix columns.
pub const COLS: usize = 10;

/// What the key at `(row, col)` means, if anything.
pub const fn decode(row: usize, col: usize) -> Option<Key> {
    use Key::*;
    Some(match (row, col) {
        // Number row: 1-5 on row 0, 6-0 on row 4.
        (0, c @ 0..=4) => Digit(c as u8 + 1),
        (4, 5) => Digit(6),
        (4, 6) => Digit(7),
        (4, 7) => Digit(8),
        (4, 8) => Digit(9),
        (4, 9) => Digit(0),
        // Letters and the symbols that share their rows.
        (1, c @ 0..=4) => Char(b"qwert"[c]),
        (5, c @ 5..=9) => Char(b"yuiop"[c - 5]),
        (2, c @ 0..=4) => Char(b"asdfg"[c]),
        (6, c @ 5..=8) => Char(b"hjkl"[c - 5]),
        (3, c @ 0..=4) => Char(b"!zxcv"[c]),
        (7, c @ 5..=8) => Char(b"bnm?"[c - 5]),
        (8, 7) => Char(b' '),
        // Confirm and cancel.
        (7, 9) => Confirm, // ENTER
        (5, 2) => Confirm, // navigation pad centre
        (6, 9) => Cancel,  // backspace
        // The navigation pad, as the numpad's arrow digits.
        (6, 4) => Digit(5), // up
        (8, 2) => Digit(8), // down
        (8, 3) => Digit(7), // left
        (3, 6) => Digit(9), // right
        // F1 (8,0), F2 (8,1), F3 (3,8), F4 (3,9), shifts (8,5) (8,9), SYM (8,6),
        // the emoji key (8,8): scanned, no meaning yet.
        _ => return None,
    })
}

/// The events between two scans, `prev` and `now` (one column mask per row), in matrix
/// order. A key with no meaning produces nothing. At most `out.len()` are reported.
pub fn events(prev: &[u16; ROWS], now: &[u16; ROWS], out: &mut [Event]) -> usize {
    let mut n = 0;
    for r in 0..ROWS {
        let diff = prev[r] ^ now[r];
        for c in 0..COLS {
            if diff & (1 << c) == 0 {
                continue;
            }
            if let Some(key) = decode(r, c) {
                if n == out.len() {
                    return n;
                }
                out[n] = if now[r] & (1 << c) != 0 {
                    Event::Pressed(key)
                } else {
                    Event::Released(key)
                };
                n += 1;
            }
        }
    }
    n
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_rows_of_keys_read_as_printed() {
        // Each printed row of the keyboard, left to right, as (row, col) -- the order the
        // key test was done in.
        let digits = [
            (0, 0),
            (0, 1),
            (0, 2),
            (0, 3),
            (0, 4),
            (4, 5),
            (4, 6),
            (4, 7),
            (4, 8),
            (4, 9),
        ];
        let got: Vec<_> = digits.iter().map(|&(r, c)| decode(r, c)).collect();
        let want: Vec<_> = [1, 2, 3, 4, 5, 6, 7, 8, 9, 0]
            .iter()
            .map(|&d| Some(Key::Digit(d)))
            .collect();
        assert_eq!(got, want);

        let text = |pos: &[(usize, usize)]| -> Vec<u8> {
            pos.iter()
                .map(|&(r, c)| match decode(r, c) {
                    Some(Key::Char(ch)) => ch,
                    other => panic!("({r},{c}) is {other:?}"),
                })
                .collect()
        };
        assert_eq!(
            text(&[
                (1, 0),
                (1, 1),
                (1, 2),
                (1, 3),
                (1, 4),
                (5, 5),
                (5, 6),
                (5, 7),
                (5, 8),
                (5, 9)
            ]),
            b"qwertyuiop"
        );
        assert_eq!(
            text(&[
                (2, 0),
                (2, 1),
                (2, 2),
                (2, 3),
                (2, 4),
                (6, 5),
                (6, 6),
                (6, 7),
                (6, 8)
            ]),
            b"asdfghjkl"
        );
        assert_eq!(
            text(&[
                (3, 0),
                (3, 1),
                (3, 2),
                (3, 3),
                (3, 4),
                (7, 5),
                (7, 6),
                (7, 7),
                (7, 8)
            ]),
            b"!zxcvbnm?"
        );
    }

    #[test]
    fn the_pad_moves_like_the_numpad_arrows() {
        assert_eq!(decode(6, 4), Some(Key::Digit(5)));
        assert_eq!(decode(8, 2), Some(Key::Digit(8)));
        assert_eq!(decode(8, 3), Some(Key::Digit(7)));
        assert_eq!(decode(3, 6), Some(Key::Digit(9)));
        assert_eq!(decode(5, 2), Some(Key::Confirm));
        assert_eq!(decode(7, 9), Some(Key::Confirm));
        assert_eq!(decode(6, 9), Some(Key::Cancel));
    }

    #[test]
    fn edges_become_events_and_unmapped_keys_are_silent() {
        let prev = [0u16; ROWS];
        let mut now = [0u16; ROWS];
        now[6] |= 1 << 4; // up
        now[8] |= 1 << 0; // F1: no meaning
        let mut out = [Event::Released(Key::Cancel); 4];
        assert_eq!(events(&prev, &now, &mut out), 1);
        assert_eq!(out[0], Event::Pressed(Key::Digit(5)));
        assert_eq!(events(&now, &prev, &mut out), 1);
        assert_eq!(out[0], Event::Released(Key::Digit(5)));
        assert_eq!(events(&now, &now, &mut out), 0);
    }
}
