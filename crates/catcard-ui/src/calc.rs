//! The calculator behind the Q1's Calculator Login: an integer evaluator, and the rule
//! that tells a PIN typed into it from a sum.
//!
//! With Calculator Login on, the screen before the PIN looks like a plain calculator and
//! *is* one: what is typed is evaluated on ENTER and the answer shown. The PIN goes in
//! through a convention no arithmetic produces:
//!
//! 1. the prefix's digits followed by `-`, then ENTER -- a dangling minus, which no sum
//!    ends in. The two anti-phishing words appear where an answer would;
//! 2. the suffix's digits alone, then ENTER.
//!
//! **Why not `prefix-suffix` on one line.** That is a subtraction, and a calculator that
//! spent a PIN attempt on every subtraction of two numbers would brick itself in thirteen
//! sums. The dangling minus is a syntax error to a calculator, so it can never be reached
//! by someone using the screen for what it claims to be; and the suffix counts only
//! while the words are showing, which only that step produces.
//!
//! Integer arithmetic on `i64` with `+ - * /` and parentheses; division truncates and
//! by zero is an error. Nothing here touches the PIN's *meaning* -- `catcard_pin` does
//! that -- so this is testable on the host as text in, text out.

use zeroize::{Zeroize, ZeroizeOnDrop};

/// The characters the calculator takes, besides digits.
pub const OPERATORS: &[u8] = b"+-*/() ";

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
    /// The PIN prefix: digits and a dangling minus.
    Prefix(&'a str),
    /// The PIN suffix: digits alone, while the words are showing.
    Suffix(&'a str),
    /// Anything else: a sum to evaluate.
    Expression,
}

/// Decide what `line` is. `awaiting_suffix` is whether the words are up; `min..=max` is
/// the length a PIN part may have.
pub fn classify(line: &str, awaiting_suffix: bool, min: usize, max: usize) -> Typed<'_> {
    let digits = |s: &str| (min..=max).contains(&s.len()) && s.bytes().all(|b| b.is_ascii_digit());
    if awaiting_suffix {
        if digits(line) {
            return Typed::Suffix(line);
        }
    } else if let Some(p) = line.strip_suffix('-')
        && digits(p)
    {
        return Typed::Prefix(p);
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
                while let Some(c) = self.s.get(self.at).copied()
                    && c.is_ascii_digit()
                {
                    v = v
                        .checked_mul(10)
                        .and_then(|v| v.checked_add(i64::from(c - b'0')))
                        .ok_or(Error::Overflow)?;
                    self.at += 1;
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

    /// The whole point: a PIN is only ever taken through a line no sum produces.
    #[test]
    fn a_pin_prefix_is_digits_and_a_dangling_minus() {
        assert_eq!(classify("1234-", false, 2, 6), Typed::Prefix("1234"));
        assert_eq!(classify("12-", false, 2, 6), Typed::Prefix("12"));
        assert_eq!(classify("123456-", false, 2, 6), Typed::Prefix("123456"));
        // Too short, too long, or a sum: never a prefix.
        for s in [
            "1-",
            "1234567-",
            "1234",
            "1234-5678",
            "12+3",
            "-1234",
            "",
            "-",
        ] {
            assert_eq!(classify(s, false, 2, 6), Typed::Expression, "{s}");
        }
    }

    #[test]
    fn a_suffix_counts_only_while_the_words_are_up() {
        assert_eq!(classify("5678", true, 2, 6), Typed::Suffix("5678"));
        assert_eq!(classify("5678", false, 2, 6), Typed::Expression);
        // With the words up, anything but a bare part is a sum -- including a second
        // prefix, which is how the pending one is dropped.
        for s in ["5678-", "1", "1234567", "5+6", "", "1234-"] {
            assert_eq!(classify(s, true, 2, 6), Typed::Expression, "{s}");
        }
    }

    #[test]
    fn the_line_takes_only_calculator_characters_and_wipes() {
        let mut l: Line<8> = Line::new();
        assert!(l.push(b'1'));
        assert!(l.push(b'-'));
        assert!(l.push(b'('));
        assert!(!l.push(b'a'));
        assert!(!l.push(b'.'));
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
