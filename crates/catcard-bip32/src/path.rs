//! Child numbers and derivation paths.

use crate::Error;

/// Indices at or above this are hardened.
pub const HARDENED_OFFSET: u32 = 0x8000_0000;

/// Longest path this crate stores. BIP-32 permits 255 levels; real paths are five
/// (`m/purpose'/coin'/account'/change/index`), so a fixed buffer avoids allocation
/// without constraining anything anyone uses.
pub const MAX_PATH_DEPTH: usize = 12;

/// A single derivation step.
#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Debug)]
pub struct ChildNumber(pub u32);

impl ChildNumber {
    pub const ZERO: ChildNumber = ChildNumber(0);

    /// A normal (non-hardened) child. `index` must be below 2^31.
    pub const fn normal(index: u32) -> Result<Self, Error> {
        if index >= HARDENED_OFFSET {
            return Err(Error::UnusableChild { index });
        }
        Ok(ChildNumber(index))
    }

    /// A hardened child. `index` is the number before the apostrophe, below 2^31.
    pub const fn hardened(index: u32) -> Result<Self, Error> {
        if index >= HARDENED_OFFSET {
            return Err(Error::UnusableChild { index });
        }
        Ok(ChildNumber(index + HARDENED_OFFSET))
    }

    pub const fn is_hardened(self) -> bool {
        self.0 >= HARDENED_OFFSET
    }

    /// The index as written in a path, without the hardened bit.
    pub const fn index(self) -> u32 {
        self.0 & !HARDENED_OFFSET
    }

    /// Big-endian, as fed to the derivation HMAC.
    pub const fn to_bytes(self) -> [u8; 4] {
        self.0.to_be_bytes()
    }
}

/// A parsed derivation path.
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub struct DerivationPath {
    steps: [ChildNumber; MAX_PATH_DEPTH],
    len: usize,
}

impl DerivationPath {
    /// The empty path, `m`.
    pub const MASTER: DerivationPath = DerivationPath {
        steps: [ChildNumber::ZERO; MAX_PATH_DEPTH],
        len: 0,
    };

    pub fn from_slice(steps: &[ChildNumber]) -> Result<Self, Error> {
        if steps.len() > MAX_PATH_DEPTH {
            return Err(Error::TooDeep);
        }
        let mut this = Self::MASTER;
        this.steps[..steps.len()].copy_from_slice(steps);
        this.len = steps.len();
        Ok(this)
    }

    pub fn push(&mut self, child: ChildNumber) -> Result<(), Error> {
        if self.len == MAX_PATH_DEPTH {
            return Err(Error::TooDeep);
        }
        self.steps[self.len] = child;
        self.len += 1;
        Ok(())
    }

    pub fn len(&self) -> usize {
        self.len
    }

    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    pub fn iter(&self) -> impl Iterator<Item = ChildNumber> + '_ {
        self.steps[..self.len].iter().copied()
    }

    /// True if every step is hardened — the property that makes an account key safe to
    /// export as an xpub.
    pub fn is_fully_hardened(&self) -> bool {
        self.iter().all(|c| c.is_hardened())
    }
}

/// Parses `m/44'/0'/0'/0/0`. Accepts `'`, `h` or `H` for hardened, and tolerates a
/// missing leading `m/`.
impl core::str::FromStr for DerivationPath {
    type Err = ParseError;

    fn from_str(s: &str) -> Result<Self, ParseError> {
        let mut path = DerivationPath::MASTER;
        let trimmed = s.trim();
        if trimmed.is_empty() {
            return Err(ParseError::Empty);
        }

        let mut parts = trimmed.split('/');
        let first = parts.next().expect("split yields at least one part");
        // A leading "m" or "M" is the master marker, not a step.
        if !(first == "m" || first == "M") {
            // Allow a bare path like "44'/0'"; re-handle `first` as a step.
            let rest = core::iter::once(first).chain(parts);
            return parse_steps(rest, &mut path).map(|()| path);
        }
        parse_steps(parts, &mut path).map(|()| path)
    }
}

fn parse_steps<'a>(
    parts: impl Iterator<Item = &'a str>,
    path: &mut DerivationPath,
) -> Result<(), ParseError> {
    for (position, part) in parts.enumerate() {
        if part.is_empty() {
            return Err(ParseError::EmptyStep { position });
        }
        let (digits, hardened) = match part.as_bytes()[part.len() - 1] {
            b'\'' | b'h' | b'H' => (&part[..part.len() - 1], true),
            _ => (part, false),
        };
        if digits.is_empty() || !digits.bytes().all(|c| c.is_ascii_digit()) {
            return Err(ParseError::BadStep { position });
        }
        let index: u32 = digits
            .parse()
            .map_err(|_| ParseError::IndexTooLarge { position })?;
        if index >= HARDENED_OFFSET {
            return Err(ParseError::IndexTooLarge { position });
        }
        let child = if hardened {
            ChildNumber::hardened(index)
        } else {
            ChildNumber::normal(index)
        }
        .map_err(|_| ParseError::IndexTooLarge { position })?;
        path.push(child).map_err(|_| ParseError::TooDeep)?;
    }
    Ok(())
}

#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub enum ParseError {
    Empty,
    /// Two consecutive separators, or a trailing one.
    EmptyStep {
        position: usize,
    },
    /// Not a number, with or without a hardened marker.
    BadStep {
        position: usize,
    },
    /// Index is 2^31 or greater, which cannot be represented.
    IndexTooLarge {
        position: usize,
    },
    TooDeep,
}

#[cfg(test)]
mod tests {
    use super::*;
    use core::str::FromStr;

    fn p(s: &str) -> DerivationPath {
        DerivationPath::from_str(s).unwrap()
    }

    #[test]
    fn parses_the_canonical_bip44_path() {
        let path = p("m/44'/0'/0'/0/0");
        assert_eq!(path.len(), 5);
        let steps: Vec<ChildNumber> = path.iter().collect();
        assert_eq!(steps[0], ChildNumber::hardened(44).unwrap());
        assert_eq!(steps[3], ChildNumber::normal(0).unwrap());
        assert!(steps[0].is_hardened());
        assert!(!steps[3].is_hardened());
    }

    #[test]
    fn hardened_markers_are_interchangeable() {
        assert_eq!(p("m/44'/0'/0'"), p("m/44h/0h/0h"));
        assert_eq!(p("m/44'/0'/0'"), p("m/44H/0H/0H"));
    }

    #[test]
    fn master_path_is_empty() {
        assert!(p("m").is_empty());
        assert!(p("M").is_empty());
        assert_eq!(p("m").len(), 0);
    }

    #[test]
    fn leading_marker_is_optional() {
        assert_eq!(p("44'/0'"), p("m/44'/0'"));
    }

    #[test]
    fn hardened_offset_arithmetic() {
        assert_eq!(ChildNumber::hardened(0).unwrap().0, HARDENED_OFFSET);
        assert_eq!(ChildNumber::hardened(44).unwrap().0, HARDENED_OFFSET + 44);
        assert_eq!(ChildNumber::hardened(44).unwrap().index(), 44);
        assert_eq!(ChildNumber::normal(44).unwrap().index(), 44);
        // The wire encoding is big-endian.
        assert_eq!(
            ChildNumber::hardened(0).unwrap().to_bytes(),
            [0x80, 0, 0, 0]
        );
        assert_eq!(ChildNumber::normal(1).unwrap().to_bytes(), [0, 0, 0, 1]);
    }

    #[test]
    fn indices_at_or_above_2_31_are_rejected() {
        assert!(ChildNumber::normal(HARDENED_OFFSET).is_err());
        assert!(ChildNumber::hardened(HARDENED_OFFSET).is_err());
        assert_eq!(
            DerivationPath::from_str("m/2147483648"),
            Err(ParseError::IndexTooLarge { position: 0 })
        );
        // 2147483647 is the largest legal index.
        assert!(DerivationPath::from_str("m/2147483647'").is_ok());
    }

    #[test]
    fn malformed_paths_are_rejected() {
        for (s, want) in [
            ("", ParseError::Empty),
            ("m/", ParseError::EmptyStep { position: 0 }),
            ("m//0", ParseError::EmptyStep { position: 0 }),
            ("m/0/", ParseError::EmptyStep { position: 1 }),
            ("m/abc", ParseError::BadStep { position: 0 }),
            ("m/0/x'", ParseError::BadStep { position: 1 }),
            ("m/'", ParseError::BadStep { position: 0 }),
            ("m/-1", ParseError::BadStep { position: 0 }),
            ("m/0x10", ParseError::BadStep { position: 0 }),
        ] {
            assert_eq!(DerivationPath::from_str(s), Err(want), "input {s:?}");
        }
    }

    #[test]
    fn overlong_paths_are_rejected() {
        let long = core::iter::repeat_n("0", MAX_PATH_DEPTH + 1)
            .collect::<Vec<_>>()
            .join("/");
        assert_eq!(
            DerivationPath::from_str(&format!("m/{long}")),
            Err(ParseError::TooDeep)
        );
        let ok = core::iter::repeat_n("0", MAX_PATH_DEPTH)
            .collect::<Vec<_>>()
            .join("/");
        assert!(DerivationPath::from_str(&format!("m/{ok}")).is_ok());
    }

    #[test]
    fn fully_hardened_detection() {
        // An account xpub is only safe to export when every step above it is hardened.
        assert!(p("m/44'/0'/0'").is_fully_hardened());
        assert!(!p("m/44'/0'/0'/0").is_fully_hardened());
        assert!(
            p("m").is_fully_hardened(),
            "the master path is vacuously hardened"
        );
    }

    #[test]
    fn whitespace_around_a_path_is_tolerated() {
        assert_eq!(p("  m/0'/1  "), p("m/0'/1"));
    }
}
