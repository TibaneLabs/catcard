//! Entropy the owner supplies by hand: dice rolls, coin flips, a keypad mash.
//!
//! # Why a type and not a number
//!
//! The one thing this crate must never grow is an API that takes a narrow integer of
//! "entropy" (see [`crate::pool`]). A run of dice rolls is exactly the shape of input
//! that invites one -- "the user rolled 50 times, add 129 bits" -- so the run itself is
//! the value here. [`UserSymbols`] carries the symbols, counts them, knows its own
//! alphabet and decides for itself whether it is worth anything; the pool asks it,
//! rather than being told.
//!
//! # The digest convention
//!
//! A run is folded into the pool as **SHA-256 over the ASCII digits**, which is the
//! public Coldcard dice convention: 50 rolls of `4 3 1 6 ...` hash the eleven-byte
//! string `"4316..."`, exactly what `printf '%s' 4316... | sha256sum` produces off the
//! device. Matching it means an owner can recompute the digest their rolls should have
//! produced on any machine and compare it with what the device shows.
//! Source: <https://coldcard.com/docs/verifying-dice-roll-math/> [C]
//!
//! **What is deliberately not matched is the replacement.** In the stock firmware that
//! digest *is* the seed -- `BIP39(sha256(rolls))` -- so a wallet made from 10 rolls has
//! 26 bits behind it and nothing else. Here the digest is one more contribution to
//! [`EntropyPool`](crate::EntropyPool), on top of the hardware TRNGs, so user input can
//! only ever add. A short or lopsided run is still mixed and simply credited nothing.
//!
//! # Crediting
//!
//! By keyspace, at the exact `log2` of the alphabet rounded down to a thousandth of a
//! bit: a d6 face is 2.584 bits, a coin flip 1, a keypad digit 3.321. Two limits keep
//! that honest:
//!
//! - **A gate.** Nothing is credited until the run is long enough (50 rolls, 128 flips,
//!   65 taps) and no one symbol takes more than its share. A die stuck on one face is a
//!   pattern, not entropy.
//! - **A cap.** A run is absorbed as one 32-byte digest, so it can carry at most 256
//!   bits no matter how long it runs.
//!
//! And none of these is a hardware source, so no amount of typing satisfies a policy's
//! two-TRNG requirement. User input tops the pool up; it never stands in for it.

use purecrypto::hash::{Digest, Sha256};
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::pool::Source;

/// Longest run kept. Past this the values stop being recorded (the caller may still mix
/// press timing). 512 symbols is ten times the dice minimum and four times the coin's,
/// and 512 d6 rolls are worth 1323 bits -- five times what a single run can ever be
/// credited -- so the cap costs nothing real.
pub const MAX_SYMBOLS: usize = 512;

/// Which fixed alphabet a run was typed from.
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub enum Alphabet {
    /// A physical d6: ASCII `1`..`6`.
    Dice,
    /// A coin: ASCII `0` (tails) and `1` (heads).
    Coin,
    /// A free mash of the number keys: ASCII `0`..`9`.
    Keypad,
}

impl Alphabet {
    /// The ASCII symbols this alphabet accepts.
    pub const fn symbols(self) -> &'static [u8] {
        match self {
            Alphabet::Dice => b"123456",
            Alphabet::Coin => b"01",
            Alphabet::Keypad => b"0123456789",
        }
    }

    /// Where a run of these lands in the pool's accounting.
    pub const fn source(self) -> Source {
        match self {
            Alphabet::Dice => Source::UserDice,
            Alphabet::Coin => Source::UserCoin,
            Alphabet::Keypad => Source::UserKeypad,
        }
    }

    /// Symbols required before a run is credited anything.
    ///
    /// 50 rolls is the published dice minimum (50 x 2.584 = 129 bits, past a 128-bit
    /// seed). Source: <https://coldcard.com/docs/verifying-dice-roll-math/> [C]
    /// 128 flips is the same bar in the coin's alphabet: 128 bits. [I]
    /// 65 taps is stock's own key-mash minimum, kept as it is rather than the 39 that the
    /// keyspace arithmetic alone would ask for: a mash is the least even of the three --
    /// a thumb favours the keys under it -- so the bar is the published one, and a run
    /// that clears it is worth 215 bits by keyspace, well past the seed.
    /// Source: hw-reference/firmware-features.md §2 "Key-mash -- >= 65 keypresses" [C]
    pub const fn min_symbols(self) -> u32 {
        match self {
            Alphabet::Dice => 50,
            Alphabet::Coin => 128,
            Alphabet::Keypad => 65,
        }
    }

    /// The largest share of a run any one symbol may take before it reads as a pattern.
    ///
    /// A fair d6 gives each face 16.7%, a coin 50%, a mashed numpad 10%. These ceilings
    /// sit well above those, so an ordinary run passes and a die stuck on one face does
    /// not. [I]
    pub const fn max_share_pct(self) -> u32 {
        match self {
            Alphabet::Dice => 30,
            Alphabet::Coin => 65,
            Alphabet::Keypad => 40,
        }
    }

    /// Thousandths of a bit each symbol is worth: `log2(alphabet)`, truncated.
    ///
    /// log2(6) = 2.5849625, log2(2) = 1, log2(10) = 3.3219280. Truncating rather than
    /// rounding keeps the credit at or below the real keyspace. [C]
    pub const fn millibits(self) -> u32 {
        match self {
            Alphabet::Dice => 2584,
            Alphabet::Coin => 1000,
            Alphabet::Keypad => 3321,
        }
    }

    /// A short word for the screen: "rolls", "flips", "taps".
    pub const fn noun(self) -> &'static str {
        match self {
            Alphabet::Dice => "rolls",
            Alphabet::Coin => "flips",
            Alphabet::Keypad => "taps",
        }
    }
}

/// Why a symbol was not recorded.
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub enum Rejected {
    /// Not one of this alphabet's symbols (a `7` while rolling a d6).
    NotInAlphabet,
    /// The run already holds [`MAX_SYMBOLS`].
    Full,
}

/// Why a run is credited nothing.
///
/// A weak run is still mixed into the pool -- mixing cannot subtract -- it simply counts
/// for zero. This says which way it fell short, so a screen can ask for more rather than
/// failing silently.
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub enum Weak {
    /// Fewer symbols than the alphabet's minimum.
    TooFew { have: u32, need: u32 },
    /// One symbol takes more of the run than the alphabet allows.
    Lopsided { share_pct: u32, max_pct: u32 },
}

impl core::fmt::Display for Weak {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Weak::TooFew { have, need } => write!(f, "{have} of {need} needed"),
            Weak::Lopsided { share_pct, max_pct } => {
                write!(f, "one symbol is {share_pct}%, max {max_pct}%")
            }
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for Weak {}

/// A run of symbols the owner typed.
///
/// Holds the symbols themselves, because the digest convention is over the symbols and
/// because the frequency gate needs to see the whole run. They are seed material, so the
/// buffer zeroizes on drop.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct UserSymbols {
    #[zeroize(skip)]
    alphabet: Alphabet,
    /// ASCII, exactly as it will be hashed.
    typed: [u8; MAX_SYMBOLS],
    len: usize,
    /// How often each ASCII symbol appeared, indexed by `symbol - b'0'`. A distribution
    /// is a partial view of the run, so it is cleared with it.
    counts: [u32; 10],
}

impl UserSymbols {
    pub fn new(alphabet: Alphabet) -> Self {
        Self {
            alphabet,
            typed: [0; MAX_SYMBOLS],
            len: 0,
            counts: [0; 10],
        }
    }

    pub fn alphabet(&self) -> Alphabet {
        self.alphabet
    }

    /// Record one ASCII symbol -- `b'4'` for a four, not `4`.
    ///
    /// ASCII is the unit the convention is defined in, so it is the unit the caller
    /// speaks in too; a run that was pushed as raw values would hash to something no
    /// `sha256sum` reproduces.
    pub fn push(&mut self, symbol: u8) -> Result<(), Rejected> {
        if !self.alphabet.symbols().contains(&symbol) {
            return Err(Rejected::NotInAlphabet);
        }
        if self.len >= MAX_SYMBOLS {
            return Err(Rejected::Full);
        }
        self.typed[self.len] = symbol;
        self.len += 1;
        self.counts[(symbol - b'0') as usize] += 1;
        Ok(())
    }

    /// How many symbols have been entered.
    pub fn count(&self) -> u32 {
        self.len as u32
    }

    pub fn is_full(&self) -> bool {
        self.len >= MAX_SYMBOLS
    }

    /// What the run is worth by keyspace, in whole bits, capped at what a 32-byte digest
    /// can carry.
    ///
    /// This is the honest arithmetic -- 50 d6 rolls is 129 bits -- and it is what a
    /// screen should show. It says nothing about whether the pool will *count* it; see
    /// [`credited_bits`](Self::credited_bits).
    pub fn worth_bits(&self) -> u32 {
        let bits = (self.len as u64 * self.alphabet.millibits() as u64) / 1000;
        bits.min(256) as u32
    }

    /// What the pool will credit: [`worth_bits`](Self::worth_bits), or zero if the run
    /// has not cleared its gate.
    pub fn credited_bits(&self) -> u32 {
        match self.weakness() {
            Some(_) => 0,
            None => self.worth_bits(),
        }
    }

    /// The share of the run taken by its most frequent symbol, in percent.
    pub fn dominant_share_pct(&self) -> u32 {
        if self.len == 0 {
            return 100;
        }
        let top = self.counts.iter().copied().max().unwrap_or(0) as u64;
        ((top * 100) / self.len as u64) as u32
    }

    /// `None` once the run is long enough and even enough to be credited.
    pub fn weakness(&self) -> Option<Weak> {
        let need = self.alphabet.min_symbols();
        if self.count() < need {
            return Some(Weak::TooFew {
                have: self.count(),
                need,
            });
        }
        // Integer share, compared strictly: 15 sixes in 50 rolls is 30% and passes, 16
        // is 32% and does not.
        let max = self.alphabet.max_share_pct();
        let share = self.dominant_share_pct();
        if share > max {
            return Some(Weak::Lopsided {
                share_pct: share,
                max_pct: max,
            });
        }
        None
    }

    /// SHA-256 over the ASCII symbols, the value the pool absorbs.
    ///
    /// The owner can reproduce this off the device from their written-down rolls, which
    /// is the whole reason for matching the convention.
    /// Source: <https://coldcard.com/docs/verifying-dice-roll-math/> [C]
    pub fn digest(&self) -> [u8; 32] {
        let mut out = [0u8; 32];
        out.copy_from_slice(Sha256::digest(&self.typed[..self.len]).as_ref());
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn run(alphabet: Alphabet, symbols: &str) -> UserSymbols {
        let mut u = UserSymbols::new(alphabet);
        for b in symbols.bytes() {
            u.push(b).unwrap();
        }
        u
    }

    /// Fifty rolls, every face used, nothing dominant.
    fn fifty_rolls() -> UserSymbols {
        let mut u = UserSymbols::new(Alphabet::Dice);
        for i in 0..50u8 {
            u.push(b'1' + (i % 6)).unwrap();
        }
        u
    }

    #[test]
    fn the_digest_is_sha256_over_the_ascii_digits() {
        // The published convention, pinned to a hash anyone can check:
        //   printf '%s' 123456 | sha256sum
        //   -> 8d969eef6ecad3c29a3a629280e686cf0c3f5d5a86aff3ca12020c923adc6c92
        // If this ever changes, an owner's off-device check of their own rolls stops
        // matching what the device did with them.
        let d = run(Alphabet::Dice, "123456").digest();
        let expect = [
            0x8d, 0x96, 0x9e, 0xef, 0x6e, 0xca, 0xd3, 0xc2, 0x9a, 0x3a, 0x62, 0x92, 0x80, 0xe6,
            0x86, 0xcf, 0x0c, 0x3f, 0x5d, 0x5a, 0x86, 0xaf, 0xf3, 0xca, 0x12, 0x02, 0x0c, 0x92,
            0x3a, 0xdc, 0x6c, 0x92,
        ];
        assert_eq!(d, expect);
    }

    #[test]
    fn an_empty_run_is_the_empty_string_digest() {
        let d = UserSymbols::new(Alphabet::Dice).digest();
        // sha256("") -- proof that nothing else is prepended to the rolls.
        assert_eq!(
            d[..4],
            [0xe3, 0xb0, 0xc4, 0x42],
            "something other than the rolls is being hashed"
        );
    }

    #[test]
    fn fifty_d6_rolls_are_worth_129_bits() {
        // log2(6) * 50 = 129.2. The number the screen shows the owner.
        assert_eq!(fifty_rolls().worth_bits(), 129);
        assert_eq!(fifty_rolls().count(), 50);
    }

    #[test]
    fn a_run_cannot_be_worth_more_than_its_digest() {
        let mut u = UserSymbols::new(Alphabet::Dice);
        for i in 0..MAX_SYMBOLS {
            u.push(b'1' + (i % 6) as u8).unwrap();
        }
        // 512 rolls is 1323 bits of keyspace, but it is absorbed as 32 bytes.
        assert_eq!(u.worth_bits(), 256);
        assert_eq!(u.push(b'1'), Err(Rejected::Full));
    }

    #[test]
    fn a_symbol_outside_the_alphabet_is_refused() {
        let mut u = UserSymbols::new(Alphabet::Dice);
        assert_eq!(u.push(b'7'), Err(Rejected::NotInAlphabet));
        assert_eq!(u.push(b'0'), Err(Rejected::NotInAlphabet));
        assert_eq!(u.count(), 0);

        let mut c = UserSymbols::new(Alphabet::Coin);
        assert_eq!(c.push(b'2'), Err(Rejected::NotInAlphabet));
        assert!(c.push(b'0').is_ok());
    }

    #[test]
    fn a_short_run_is_worth_nothing_however_it_is_measured() {
        // Ten rolls: 25 bits of keyspace, credited zero, because ten rolls is not a
        // seed and must never look like one.
        let u = run(Alphabet::Dice, "1234561234");
        assert_eq!(u.worth_bits(), 25);
        assert_eq!(u.credited_bits(), 0);
        assert_eq!(u.weakness(), Some(Weak::TooFew { have: 10, need: 50 }));
    }

    #[test]
    fn a_die_stuck_on_one_face_is_not_credited() {
        let mut u = UserSymbols::new(Alphabet::Dice);
        for i in 0..100u8 {
            // Half the run is sixes: a pattern, not a die.
            u.push(if i % 2 == 0 { b'6' } else { b'1' + (i % 5) })
                .unwrap();
        }
        assert!(matches!(u.weakness(), Some(Weak::Lopsided { .. })));
        assert_eq!(u.credited_bits(), 0);
    }

    #[test]
    fn a_fair_run_clears_its_gate() {
        assert_eq!(fifty_rolls().weakness(), None);
        assert_eq!(fifty_rolls().credited_bits(), 129);

        let mut c = UserSymbols::new(Alphabet::Coin);
        for i in 0..128u8 {
            c.push(b'0' + (i % 2)).unwrap();
        }
        assert_eq!(c.credited_bits(), 128);
    }

    /// Sixty-four taps are worth 212 bits by keyspace and credited nothing; the
    /// sixty-fifth clears stock's bar and the run is credited what it is worth.
    #[test]
    fn a_keypad_mash_needs_sixty_five_presses() {
        let mut u = UserSymbols::new(Alphabet::Keypad);
        for i in 0..64u8 {
            u.push(b'0' + (i % 10)).unwrap();
        }
        assert_eq!(u.worth_bits(), 212);
        assert_eq!(u.credited_bits(), 0);
        assert_eq!(u.weakness(), Some(Weak::TooFew { have: 64, need: 65 }));
        u.push(b'4').unwrap();
        assert_eq!(u.weakness(), None);
        // 65 x 3.321 = 215.8, truncated: never more than the keyspace.
        assert_eq!(u.credited_bits(), 215);
    }

    #[test]
    fn the_order_of_the_rolls_matters() {
        assert_ne!(
            run(Alphabet::Dice, "123456").digest(),
            run(Alphabet::Dice, "654321").digest()
        );
    }
}
