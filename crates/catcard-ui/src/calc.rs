//! The calculator behind the Q1's Calculator Login: an integer evaluator, and the rule
//! that tells a PIN typed into it from a sum.
//!
//! With Calculator Login on, the screen before the PIN looks like a plain calculator and
//! *is* one: what is typed is evaluated on ENTER and the answer shown. The PIN goes in by
//! stock's convention, classified in this order:
//!
//! 1. **The whole PIN**: `prefix`, a separator (`-`, `_` or a space), `suffix`, on one
//!    line -- `12-3456`, `1234_5678`, `12 34`. That is a login attempt. A wrong one shows
//!    as the line's arithmetic value (`12-34` is `-22`), with the tries left, so it reads
//!    as an ordinary sum.
//! 2. **The prefix alone**: its digits and a dangling `-` or `_` -- `12-`. The two
//!    anti-phishing words appear where an answer would.
//! 3. Anything else is a sum.
//!
//! So the anti-phishing check is the owner's to ask for: `12-` first, look at the words,
//! then the whole PIN.
//!
//! **This does make a subtraction of two small numbers a PIN attempt**, which is stock's
//! design and the price of the disguise: `12-34` on this screen is a guess at the PIN.
//! Each part is held to the PIN's own 2 to 6 digits, so a part no PIN has is only ever a
//! sum.
//!
//! Source: hw-reference/input.md §"Q1 Calculator Login" [C] (the order, the separators,
//! the lengths, and the wrong-PIN display).
//!
//! Integer arithmetic on `i64` with `+ - * /` and parentheses; division truncates and
//! by zero is an error; `_` between digits is a digit separator, as Python -- which stock's
//! calculator is -- reads it. Nothing here touches the PIN's *meaning* -- `catcard_pin` does
//! that -- so this is testable on the host as text in, text out.

use zeroize::{Zeroize, ZeroizeOnDrop};

/// The characters the calculator takes, besides digits.
pub const OPERATORS: &[u8] = b"+-*/() _";

/// What the typed line holds, `N` bytes at most, wiped on drop: it carries PIN digits
/// between key and gate exactly as a PIN field does.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct Line<const N: usize> {
    buf: [u8; N],
    len: usize,
}

impl<const N: usize> Default for Line<N> {
    fn default() -> Self {
        Self::new()
    }
}

impl<const N: usize> Line<N> {
    pub const fn new() -> Self {
        Self {
            buf: [0; N],
            len: 0,
        }
    }

    /// Append `c` if it is something the calculator takes and there is room.
    pub fn push(&mut self, c: u8) -> bool {
        if !(c.is_ascii_digit() || OPERATORS.contains(&c)) || self.len >= N {
            return false;
        }
        self.buf[self.len] = c;
        self.len += 1;
        true
    }

    /// Remove the last character; false if there was none.
    pub fn pop(&mut self) -> bool {
        if self.len == 0 {
            return false;
        }
        self.len -= 1;
        self.buf[self.len] = 0;
        true
    }

    pub fn clear(&mut self) {
        self.buf.zeroize();
        self.len = 0;
    }

    pub fn as_str(&self) -> &str {
        core::str::from_utf8(&self.buf[..self.len]).unwrap_or("")
    }

    pub fn len(&self) -> usize {
        self.len
    }

    pub fn is_empty(&self) -> bool {
        self.len == 0
    }
}

/// How a typed line is to be taken.
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub enum Typed<'a> {
    /// The whole PIN, prefix and suffix on one line: a login attempt.
    Pin { prefix: &'a str, suffix: &'a str },
    /// The PIN prefix and a dangling `-` or `_`: show its words.
    Prefix(&'a str),
    /// Anything else: a sum to evaluate.
    Expression,
}

/// The separators the whole PIN may use: stock's `[-_ ]`. Source: input.md [C]
pub const PIN_SEPARATORS: &[u8] = b"-_ ";

/// The separators a prefix alone may end in: stock's `[-_]` -- not a space, which
/// nobody would see. Source: input.md [C]
pub const PREFIX_SEPARATORS: &[u8] = b"-_";

/// Decide what `line` is. `min..=max` is the length a PIN part may have.
///
/// Stock checks the whole line's length (13 at most for a PIN, 7 for a prefix) and each
/// part's at least two digits; with parts held to `min..=max` -- 2 to 6 -- both of
/// stock's limits follow. A line that fits stock's pattern with a part longer than `max`
/// is a sum here: no PIN has such a part, so trying it could only spend an attempt.
/// Source: hw-reference/input.md §"Q1 Calculator Login" [C]; gate18-pin-state-machine.md
/// §6.1 [C] (2 to 6)
pub fn classify(line: &str, min: usize, max: usize) -> Typed<'_> {
    let part = |s: &str| (min..=max).contains(&s.len()) && s.bytes().all(|b| b.is_ascii_digit());
    let b = line.as_bytes();
    // The whole PIN: exactly one separator, digits either side.
    if let Some(at) = b.iter().position(|c| PIN_SEPARATORS.contains(c)) {
        let (prefix, suffix) = (&line[..at], &line[at + 1..]);
        if part(prefix) && part(suffix) {
            return Typed::Pin { prefix, suffix };
        }
    }
    // The prefix alone.
    if let Some((&last, head)) = b.split_last()
        && PREFIX_SEPARATORS.contains(&last)
    {
        let p = &line[..head.len()];
        if part(p) {
            return Typed::Prefix(p);
        }
    }
    Typed::Expression
}

/// Why a sum did not evaluate.
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub enum Error {
    Empty,
    Syntax,
    DivideByZero,
    Overflow,
}

/// Parentheses nested deeper than this are refused: each level is a stack frame.
const MAX_DEPTH: u8 = 16;

struct Parser<'a> {
    s: &'a [u8],
    at: usize,
}

impl Parser<'_> {
    fn skip_spaces(&mut self) {
        while self.at < self.s.len() && self.s[self.at] == b' ' {
            self.at += 1;
        }
    }

    fn peek(&mut self) -> Option<u8> {
        self.skip_spaces();
        self.s.get(self.at).copied()
    }

    fn expr(&mut self, depth: u8) -> Result<i64, Error> {
        let mut v = self.term(depth)?;
        loop {
            match self.peek() {
                Some(b'+') => {
                    self.at += 1;
                    v = v.checked_add(self.term(depth)?).ok_or(Error::Overflow)?;
                }
                Some(b'-') => {
                    self.at += 1;
                    v = v.checked_sub(self.term(depth)?).ok_or(Error::Overflow)?;
                }
                _ => return Ok(v),
            }
        }
    }

    fn term(&mut self, depth: u8) -> Result<i64, Error> {
        let mut v = self.unary(depth)?;
        loop {
            match self.peek() {
                Some(b'*') => {
                    self.at += 1;
                    v = v.checked_mul(self.unary(depth)?).ok_or(Error::Overflow)?;
                }
                Some(b'/') => {
                    self.at += 1;
                    let d = self.unary(depth)?;
                    if d == 0 {
                        return Err(Error::DivideByZero);
                    }
                    v = v.checked_div(d).ok_or(Error::Overflow)?;
                }
                _ => return Ok(v),
            }
        }
    }

    fn unary(&mut self, depth: u8) -> Result<i64, Error> {
        if self.peek() == Some(b'-') {
            self.at += 1;
            return self.unary(depth)?.checked_neg().ok_or(Error::Overflow);
        }
        self.primary(depth)
    }

    fn primary(&mut self, depth: u8) -> Result<i64, Error> {
        match self.peek() {
            Some(b'(') => {
                if depth >= MAX_DEPTH {
                    return Err(Error::Syntax);
                }
                self.at += 1;
                let v = self.expr(depth + 1)?;
                if self.peek() != Some(b')') {
                    return Err(Error::Syntax);
                }
                self.at += 1;
                Ok(v)
            }
            Some(c) if c.is_ascii_digit() => {
                let mut v: i64 = 0;
                loop {
                    match self.s.get(self.at).copied() {
                        Some(c) if c.is_ascii_digit() => {
                            v = v
                                .checked_mul(10)
                                .and_then(|v| v.checked_add(i64::from(c - b'0')))
                                .ok_or(Error::Overflow)?;
                            self.at += 1;
                        }
                        // A digit separator, as Python reads one: a single `_` with a
                        // digit on each side. `12_34` is 1234; `12_`, `1__2` are errors.
                        Some(b'_') => match self.s.get(self.at + 1) {
                            Some(d) if d.is_ascii_digit() => self.at += 1,
                            _ => return Err(Error::Syntax),
                        },
                        _ => break,
                    }
                }
                Ok(v)
            }
            _ => Err(Error::Syntax),
        }
    }
}

/// Evaluate `expr`.
pub fn eval(expr: &str) -> Result<i64, Error> {
    let mut p = Parser {
        s: expr.as_bytes(),
        at: 0,
    };
    if p.peek().is_none() {
        return Err(Error::Empty);
    }
    let v = p.expr(0)?;
    if p.peek().is_some() {
        return Err(Error::Syntax);
    }
    Ok(v)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sums_evaluate_with_precedence_and_parentheses() {
        for (s, v) in [
            ("1+2*3", 7),
            ("(1+2)*3", 9),
            ("10/3", 3),
            ("-5+2", -3),
            ("2--3", 5),
            ("1234-5678", -4444),
            ("((1))", 1),
            (" 2 * 3 ", 6),
            ("0", 0),
            ("100-58", 42),
            ("2*(3+4)*5", 70),
            ("-(2+3)", -5),
        ] {
            assert_eq!(eval(s), Ok(v), "{s}");
        }
    }

    #[test]
    fn what_is_not_a_sum_is_refused_by_kind() {
        assert_eq!(eval(""), Err(Error::Empty));
        assert_eq!(eval("   "), Err(Error::Empty));
        assert_eq!(eval("1+"), Err(Error::Syntax));
        assert_eq!(eval("1234-"), Err(Error::Syntax));
        assert_eq!(eval("(1"), Err(Error::Syntax));
        assert_eq!(eval("1)"), Err(Error::Syntax));
        assert_eq!(eval("*1"), Err(Error::Syntax));
        assert_eq!(eval("7/0"), Err(Error::DivideByZero));
        assert_eq!(eval("9223372036854775807+1"), Err(Error::Overflow));
        assert_eq!(eval("99999999999999999999"), Err(Error::Overflow));
        assert_eq!(eval("-9223372036854775808/-1"), Err(Error::Overflow));
        assert_eq!(eval("1.5"), Err(Error::Syntax));
    }

    #[test]
    fn nesting_is_bounded() {
        let mut deep = std::string::String::new();
        for _ in 0..40 {
            deep.push('(');
        }
        deep.push('1');
        for _ in 0..40 {
            deep.push(')');
        }
        assert_eq!(eval(&deep), Err(Error::Syntax));
    }

    /// input.md §"Q1 Calculator Login": the whole PIN on one line, with `-`, `_` or a
    /// space between the parts.
    #[test]
    fn the_whole_pin_is_one_line_with_any_of_three_separators() {
        for (s, p, x) in [
            ("12-3456", "12", "3456"),
            ("1234_5678", "1234", "5678"),
            ("12 34", "12", "34"),
            ("123456-654321", "123456", "654321"),
        ] {
            assert_eq!(
                classify(s, 2, 6),
                Typed::Pin {
                    prefix: p,
                    suffix: x
                },
                "{s}"
            );
        }
    }

    /// The prefix alone, ending in `-` or `_`, asks for the words.
    #[test]
    fn a_prefix_and_a_dangling_separator_asks_for_the_words() {
        assert_eq!(classify("12-", 2, 6), Typed::Prefix("12"));
        assert_eq!(classify("1234_", 2, 6), Typed::Prefix("1234"));
        assert_eq!(classify("123456-", 2, 6), Typed::Prefix("123456"));
        // A trailing space is not a prefix: nobody would see it.
        assert_eq!(classify("12 ", 2, 6), Typed::Expression);
    }

    /// Everything else is a sum -- including stock's pattern with a part no PIN has.
    #[test]
    fn anything_else_is_a_sum() {
        for s in [
            "1-",
            "1234567-",
            "1234",
            "1-2345",
            "12-3",
            "1234567-12",
            "12-1234567",
            "12+34",
            "-1234",
            "12-34-56",
            "12--34",
            "(12)-34",
            "",
            "-",
            "_",
            "12_34_56",
        ] {
            assert_eq!(classify(s, 2, 6), Typed::Expression, "{s}");
        }
    }

    /// A wrong PIN shows the line's value, as stock's `eval` would: `12-34` is `-22`,
    /// `12_34` is `1234` (Python's digit separator), `12 34` is not a sum.
    #[test]
    fn a_wrong_pin_evaluates_as_the_sum_it_looks_like() {
        assert_eq!(eval("12-34"), Ok(-22));
        assert_eq!(eval("12_34"), Ok(1234));
        assert_eq!(eval("1_000+1"), Ok(1001));
        assert_eq!(eval("12 34"), Err(Error::Syntax));
        assert_eq!(eval("12_"), Err(Error::Syntax));
        assert_eq!(eval("1__2"), Err(Error::Syntax));
        assert_eq!(eval("_12"), Err(Error::Syntax));
    }

    #[test]
    fn the_line_takes_only_calculator_characters_and_wipes() {
        let mut l: Line<8> = Line::new();
        assert!(l.push(b'1'));
        assert!(l.push(b'-'));
        assert!(l.push(b'('));
        assert!(!l.push(b'a'));
        assert!(!l.push(b'.'));
        assert!(l.push(b'_'));
        assert!(l.pop());
        assert_eq!(l.as_str(), "1-(");
        assert!(l.pop());
        assert_eq!(l.as_str(), "1-");
        for c in b"23456" {
            l.push(*c);
        }
        assert_eq!(l.len(), 7);
        assert!(l.push(b'7'));
        assert!(!l.push(b'8'), "full");
        l.clear();
        assert!(l.is_empty());
        assert!(!l.pop());
    }
}
