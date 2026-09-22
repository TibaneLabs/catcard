//! A shuffled number row for PIN entry: stock's "Scramble Keys".
//!
//! With it on, the key printed `1` does not type a 1. The screen shows, under each key's
//! label, the digit that key types this time, and the order is drawn again for each half of
//! the PIN. Someone who watched the fingers -- or reads the smudges afterwards -- learns
//! positions, and positions no longer mean digits.
//!
//! **What must never go wrong is the mapping.** A layout that typed something other than
//! what it showed would spend a PIN attempt on every login, and thirteen of those brick the
//! device. So it is a permutation by construction, shown from the same table it types from,
//! and tested as one below.

/// Which digit each key types. Indexed by the digit printed on the key.
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub struct Layout([u8; 10]);

/// The labels, in the order the keys sit on the Q1's number row -- and the order the
/// legend is drawn in on every board.
pub const LABELS: [u8; 10] = [1, 2, 3, 4, 5, 6, 7, 8, 9, 0];

impl Layout {
    /// Every key types its own label.
    pub const PLAIN: Layout = Layout([0, 1, 2, 3, 4, 5, 6, 7, 8, 9]);

    /// A uniformly random order: Fisher-Yates, drawing each swap from `below(n)`, which must
    /// return a value in `0..n` with every one equally likely (the UI DRBG's `below`).
    ///
    /// `None` if `below` fails or answers out of range. The caller decides what that means;
    /// nothing here quietly hands back a layout that is not a shuffle.
    pub fn shuffled<E>(mut below: impl FnMut(u32) -> Result<u32, E>) -> Option<Layout> {
        let mut d = Self::PLAIN.0;
        for i in (1..d.len()).rev() {
            let j = below(i as u32 + 1).ok()? as usize;
            if j > i {
                return None;
            }
            d.swap(i, j);
        }
        Some(Layout(d))
    }

    /// The digit the key labelled `key` types. A key that is not a digit types itself.
    pub fn digit(&self, key: u8) -> u8 {
        self.0.get(key as usize).copied().unwrap_or(key)
    }

    /// Whether any key types something other than its label.
    pub fn is_plain(&self) -> bool {
        *self == Self::PLAIN
    }

    /// The two legend rows, as ASCII: the labels in [`LABELS`] order, and under each the
    /// digit it types. `spaced` puts a space between columns where there is room for one.
    pub fn legend(&self, spaced: bool, keys: &mut [u8; 19], types: &mut [u8; 19]) -> usize {
        let mut n = 0;
        for (i, label) in LABELS.iter().enumerate() {
            if spaced && i > 0 {
                keys[n] = b' ';
                types[n] = b' ';
                n += 1;
            }
            keys[n] = b'0' + label;
            types[n] = b'0' + self.digit(*label);
            n += 1;
        }
        n
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A counter standing in for the DRBG: deterministic, and in range.
    fn lcg(seed: u64) -> impl FnMut(u32) -> Result<u32, ()> {
        let mut s = seed;
        move |n| {
            s = s
                .wrapping_mul(6364136223846793005)
                .wrapping_add(1442695040888963407);
            Ok(((s >> 33) as u32) % n)
        }
    }

    /// Every layout is a permutation: ten keys, ten different digits, each 0 to 9. This is
    /// the property the device's attempts counter depends on.
    #[test]
    fn every_layout_types_each_digit_exactly_once() {
        for seed in 0..2000 {
            let l = Layout::shuffled(lcg(seed)).unwrap();
            let mut seen = [false; 10];
            for key in 0..10 {
                let d = l.digit(key);
                assert!(d < 10);
                assert!(!seen[d as usize], "seed {seed}: {d} typed twice");
                seen[d as usize] = true;
            }
        }
    }

    /// What is drawn is what is typed: the legend is read back through `digit`.
    #[test]
    fn the_legend_shows_what_each_key_types() {
        let l = Layout::shuffled(lcg(7)).unwrap();
        for spaced in [false, true] {
            let (mut k, mut t) = ([0u8; 19], [0u8; 19]);
            let n = l.legend(spaced, &mut k, &mut t);
            assert_eq!(n, if spaced { 19 } else { 10 });
            for i in 0..n {
                if k[i] == b' ' {
                    assert_eq!(t[i], b' ');
                    continue;
                }
                assert_eq!(t[i] - b'0', l.digit(k[i] - b'0'));
            }
        }
    }

    /// Every position can hold every digit -- no digit is pinned to its own key, which is
    /// what a shuffle with an off-by-one would do.
    #[test]
    fn every_digit_reaches_every_key() {
        let mut reach = [[false; 10]; 10];
        for seed in 0..5000 {
            let l = Layout::shuffled(lcg(seed)).unwrap();
            for key in 0..10u8 {
                reach[key as usize][l.digit(key) as usize] = true;
            }
        }
        assert!(reach.iter().all(|r| r.iter().all(|&b| b)));
    }

    /// A generator that fails, or answers out of range, gives no layout rather than a
    /// broken one.
    #[test]
    fn a_bad_generator_gives_no_layout() {
        assert_eq!(Layout::shuffled(|_| Err::<u32, ()>(())), None);
        assert_eq!(Layout::shuffled(Ok::<u32, ()>), None);
        assert!(Layout::PLAIN.is_plain());
        assert_eq!(Layout::PLAIN.digit(4), 4);
    }
}
