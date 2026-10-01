//! Codex32 (BIP-93): a wallet secret as a checksummed string, and Shamir sharing of it.
//!
//! A codex32 string is a bech32-style encoding with a long BCH checksum, and its symbols
//! are elements of GF(32). Because the checksum is linear, *k* strings of a share set can
//! be combined by Lagrange interpolation, symbol by symbol, into any other member of the
//! set -- the secret itself sits at index `s`. That is the whole of the sharing: there is
//! no other key schedule, and a set made here can be recovered by hand with the BIP's
//! paper volvelles.
//!
//! # Three prefixes
//!
//! BIP-93 defines `ms` (a raw BIP-32 master seed). Coldcard adds two of its own, which
//! other codex32 tools do not know: `cw` (BIP-39 entropy, English words) and `cx` (an
//! extended private key, chain code then key). The prefix is mixed into the checksum, so
//! the same symbols under another prefix do not verify -- a prefix is not a conversion.
//! Source: hw-reference/codex32-format.md §Three prefixes [C]
//!
//! Only the lengths Coldcard accepts parse: `ms` 16/32/64 bytes, `cw` 16/24/32, `cx` 64.
//! BIP-93 itself also allows 20/24/28-byte `ms` seeds; those are refused here by length
//! rather than mistaken for a bad checksum. Source: as above, `Share.parse` [C]
//!
//! # What is secret
//!
//! Everything but the header. A share's payload is a point on the polynomial whose
//! constant term is the seed, so the arithmetic below never branches or indexes on a
//! symbol's value: GF(32) multiplication is shift-and-mask, the alphabet is searched with
//! masks rather than indexed, and the checksum's generator selection is masked too. Share
//! *indices* are public -- they are written on the shares -- so the Lagrange weights,
//! which depend only on them, are free to branch.
//!
//! # Padding survives interpolation
//!
//! The payload's last symbol carries 2-4 bits beyond the bytes. They are part of the
//! polynomial, so a share is never decoded to bytes and re-encoded before it is combined;
//! the bits are dropped only when a secret becomes wallet bytes.
//! Source: hw-reference/codex32-format.md §Wire format [C]
//!
//! # Matching headers do not authenticate a set
//!
//! Any *k* shares with matching headers and valid checksums interpolate to *some* valid
//! secret. A substituted share recovers a different wallet, not an error. Callers have
//! to say so, and to show what was recovered before it is used.

use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::KeyWork;

/// The bech32 alphabet, values 0-31 in order. `b`, `i`, `o` and `1` are not in it.
/// Source: BIP-173; hw-reference/codex32-format.md §Wire format [C]
pub const ALPHABET: &[u8; 32] = b"qpzry9x8gf2tvdw0s3jn54khce6mua7l";

/// The value of index `s`: the secret itself.
pub const SECRET_INDEX: u8 = 16;

/// The share indices a split hands out, in order: `a c d e f g h j k`.
/// Source: hw-reference/codex32-format.md §Device operations "Shamir Split" [C]
pub const SHARE_ORDER: [u8; 9] = [29, 24, 13, 25, 9, 8, 23, 18, 22];

/// Most shares in a set, and the highest threshold: the threshold is one digit.
pub const MAX_SHARES: usize = 9;

/// Longest string: a 64-byte payload with the long checksum.
pub const MAX_STRING: usize = 127;

/// Header symbols: threshold, four of identifier, index.
const HEADER: usize = 6;

/// Most payload symbols: 64 bytes is 512 bits, 103 symbols.
const MAX_PAYLOAD: usize = 103;

/// Header plus payload: what is interpolated.
const MAX_DATA: usize = HEADER + MAX_PAYLOAD;

/// The two checksum residues BIP-93 targets. Source: BIP-93 §Checksum, §Long codex32 [C]
const SHORT_CONST: u128 = 0x10ce0795c2fd1e62a;
const LONG_CONST: u128 = 0x43381e570bf4798ab26;

const SHORT_GEN: [u128; 5] = [
    0x19dc500ce73fde210,
    0x1bfae00def77fe529,
    0x1fbd920fffe7bee52,
    0x1739640bdeee3fdad,
    0x07729a039cfc75f5a,
];
const LONG_GEN: [u128; 5] = [
    0x3d59d273535ea62d897,
    0x7a9becb6361c6c51507,
    0x543f9b7e6c38d8a2a0e,
    0x0c577eaeccf1990d13c,
    0x1887f74f8dc71b10651,
];

/// What a string says it holds. Source: hw-reference/codex32-format.md §Three prefixes [C]
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub enum Hrp {
    /// BIP-93: a raw BIP-32 master seed, fed to HMAC-SHA512 "Bitcoin seed".
    Ms,
    /// Coldcard: English BIP-39 entropy -- words, no passphrase.
    Cw,
    /// Coldcard: an extended private key, `chain_code(32) || k(32)`.
    Cx,
}

impl Hrp {
    /// The two letters, lowercase.
    pub const fn text(self) -> &'static str {
        match self {
            Hrp::Ms => "ms",
            Hrp::Cw => "cw",
            Hrp::Cx => "cx",
        }
    }

    /// Payload lengths in bytes this prefix may carry.
    const fn lengths(self) -> &'static [usize] {
        match self {
            Hrp::Ms => &[16, 32, 64],
            Hrp::Cw => &[16, 24, 32],
            Hrp::Cx => &[64],
        }
    }

    fn from_text(two: &[u8]) -> Option<Self> {
        match two {
            b"ms" => Some(Hrp::Ms),
            b"cw" => Some(Hrp::Cw),
            b"cx" => Some(Hrp::Cx),
            _ => None,
        }
    }

    /// Whether `bytes` is a payload length this prefix carries.
    pub fn carries(self, bytes: usize) -> bool {
        self.lengths().contains(&bytes)
    }
}

/// Why a string, a set or a secret was refused.
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub enum Error {
    /// Not `ms1`, `cw1` or `cx1` at the front.
    Prefix,
    /// Upper and lower case mixed.
    MixedCase,
    /// Not one of the lengths this prefix carries.
    Length,
    /// A character outside the bech32 alphabet.
    Character,
    /// The threshold is not `0` or `2`-`9`, or it is `0` on a share that is not `s`.
    Threshold,
    /// The checksum does not verify.
    Checksum,
    /// A share of a different set: prefix, identifier, threshold or length differ.
    Mismatch,
    /// That index is already in the set.
    Duplicate,
    /// The secret (`s`) where a share was wanted.
    SecretNotShare,
    /// A share where the secret (`s`) was wanted.
    NotSecret,
    /// The set already holds as many shares as its threshold.
    Full,
    /// Fewer shares than the threshold.
    Incomplete,
    /// A `cx` key outside `1 <= k < n`, or not enough noise for a split.
    Invalid,
}

// ---------------------------------------------------------------------------------------
// GF(32), polynomial x^5 + x^3 + 1
// ---------------------------------------------------------------------------------------

/// Multiply in GF(32), reducing by `x^5 + x^3 + 1` (41). Shift-and-mask: no branch or
/// table index depends on either operand. Source: BIP-93 `bech32_mul`;
/// hw-reference/codex32-format.md §Sharing [C]
fn mul(a: u8, b: u8) -> u8 {
    let mut a = a & 31;
    let mut r = 0u8;
    for i in 0..5 {
        r ^= a & ((b >> i) & 1).wrapping_neg();
        a <<= 1;
        a ^= 41 & ((a >> 5) & 1).wrapping_neg();
    }
    r & 31
}

/// `a^-1` as `a^30` (the group has order 31). Zero maps to zero; callers never ask.
fn inv(a: u8) -> u8 {
    let a2 = mul(a, a);
    let a4 = mul(a2, a2);
    let a8 = mul(a4, a4);
    let a16 = mul(a8, a8);
    mul(mul(a16, a8), mul(a4, a2))
}

// ---------------------------------------------------------------------------------------
// Alphabet, constant-time both ways
// ---------------------------------------------------------------------------------------

/// The symbol for a lowercase character, or 0xFF. Every alphabet entry is compared, so
/// how long this takes says nothing about which character it was.
fn symbol_of(c: u8) -> u8 {
    let mut out = 0xFFu8;
    for (v, &a) in ALPHABET.iter().enumerate() {
        let eq = ((a ^ c) as u32).wrapping_sub(1) >> 31; // 1 when equal
        let m = (eq as u8).wrapping_neg();
        out = (out & !m) | (v as u8 & m);
    }
    out
}

/// The character for a symbol, the same way round.
fn char_of(v: u8) -> u8 {
    let mut out = 0u8;
    for (i, &a) in ALPHABET.iter().enumerate() {
        let eq = (((i as u8) ^ v) as u32).wrapping_sub(1) >> 31;
        out |= a & (eq as u8).wrapping_neg();
    }
    out
}

// ---------------------------------------------------------------------------------------
// Checksum
// ---------------------------------------------------------------------------------------

/// Which checksum a data part of `symbols` (checksum included) takes: the long one once
/// the expanded prefix and data exceed 93 values. Source: BIP-93 §Long codex32 [C]
fn is_long(data_with_checksum: usize) -> bool {
    5 + data_with_checksum > 93
}

/// BIP-93's polymod, generalised to any prefix: the residue starts at 1 and the prefix
/// goes in with BIP-173 expansion first. For `ms` that start is exactly BIP-93's
/// `0x23181b3`. Source: hw-reference/codex32-format.md §Wire format "Checksum" [C]
struct Polymod {
    residue: u128,
    long: bool,
}

impl Polymod {
    fn new(hrp: Hrp, long: bool) -> Self {
        let mut p = Polymod { residue: 1, long };
        let h = hrp.text().as_bytes();
        for &c in h {
            p.feed(c >> 5);
        }
        p.feed(0);
        for &c in h {
            p.feed(c & 31);
        }
        p
    }

    fn feed(&mut self, v: u8) {
        let (shift, gens) = if self.long {
            (70, &LONG_GEN)
        } else {
            (60, &SHORT_GEN)
        };
        let b = (self.residue >> shift) as u8;
        self.residue = ((self.residue & ((1u128 << shift) - 1)) << 5) ^ u128::from(v & 31);
        for (i, g) in gens.iter().enumerate() {
            let bit = u128::from((b >> i) & 1);
            self.residue ^= g & bit.wrapping_neg();
        }
    }

    fn target(&self) -> u128 {
        if self.long { LONG_CONST } else { SHORT_CONST }
    }
}

/// Checksum symbols for `data` (header and payload), written to `out` (13 or 15 long).
fn checksum(hrp: Hrp, data: &[u8], out: &mut [u8]) -> usize {
    let n = if is_long(data.len() + 13) { 15 } else { 13 };
    let mut p = Polymod::new(hrp, n == 15);
    for &v in data {
        p.feed(v);
    }
    for _ in 0..n {
        p.feed(0);
    }
    let r = p.residue ^ p.target();
    for (i, o) in out.iter_mut().take(n).enumerate() {
        *o = ((r >> (5 * (n - 1 - i))) & 31) as u8;
    }
    n
}

/// Whether `symbols` (data part with its checksum) verifies under `hrp`.
fn verifies(hrp: Hrp, symbols: &[u8]) -> bool {
    let mut p = Polymod::new(hrp, is_long(symbols.len()));
    for &v in symbols {
        p.feed(v);
    }
    p.residue == p.target()
}

/// Payload symbols for `bytes` of secret: `ceil(8n / 5)`.
const fn payload_symbols(bytes: usize) -> usize {
    (bytes * 8).div_ceil(5)
}

/// The byte length a payload of `symbols` carries, if it is one with at most 4 bits of
/// padding (BIP-93 refuses a longer incomplete group).
const fn payload_bytes(symbols: usize) -> Option<usize> {
    let bits = symbols * 5;
    if bits % 8 > 4 {
        return None;
    }
    Some(bits / 8)
}

// ---------------------------------------------------------------------------------------
// One string
// ---------------------------------------------------------------------------------------

/// One codex32 string: a share, or the secret at index `s`.
///
/// Held as symbols -- header and payload, padding bits and all; the checksum is
/// recomputed whenever it is written out. Wiped on drop.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct Share {
    #[zeroize(skip)]
    hrp: Hrp,
    data: [u8; MAX_DATA],
    len: u8,
}

impl Share {
    const fn empty() -> Self {
        Share {
            hrp: Hrp::Ms,
            data: [0; MAX_DATA],
            len: 0,
        }
    }

    /// Parse a string. Spaces are ignored (they are only presentation); case must be all
    /// lower or all upper. Source: hw-reference/codex32-format.md §Wire format [C]
    pub fn parse(text: &str, _kw: &KeyWork) -> Result<Self, Error> {
        let mut buf = [0u8; MAX_STRING];
        let mut n = 0usize;
        let (mut lower, mut upper) = (false, false);
        for &c in text.as_bytes() {
            if c == b' ' {
                continue;
            }
            if n == MAX_STRING {
                buf.zeroize();
                return Err(Error::Length);
            }
            lower |= c.is_ascii_lowercase();
            upper |= c.is_ascii_uppercase();
            buf[n] = c.to_ascii_lowercase();
            n += 1;
        }
        let out = Self::parse_lower(&buf[..n], lower && upper);
        buf.zeroize();
        out
    }

    fn parse_lower(s: &[u8], mixed: bool) -> Result<Self, Error> {
        if mixed {
            return Err(Error::MixedCase);
        }
        if s.len() < 3 || s[2] != b'1' {
            return Err(Error::Prefix);
        }
        let hrp = Hrp::from_text(&s[..2]).ok_or(Error::Prefix)?;
        let body = &s[3..];
        // The data part is header + payload + checksum; which checksum follows from the
        // length, and the payload must then be a length this prefix carries.
        let check = if is_long(body.len()) { 15 } else { 13 };
        let payload = body
            .len()
            .checked_sub(HEADER + check)
            .ok_or(Error::Length)?;
        let bytes = payload_bytes(payload).ok_or(Error::Length)?;
        if !hrp.carries(bytes) || payload_symbols(bytes) != payload {
            return Err(Error::Length);
        }
        let mut sym = [0u8; MAX_DATA + 15];
        let mut bad = 0u8;
        for (o, &c) in sym.iter_mut().zip(body) {
            let v = symbol_of(c);
            bad |= v >> 7;
            *o = v & 31;
        }
        if bad != 0 {
            sym.zeroize();
            return Err(Error::Character);
        }
        let threshold = threshold_of(sym[0]);
        let ok_threshold = match threshold {
            Some(0) => sym[5] == SECRET_INDEX,
            Some(_) => true,
            None => false,
        };
        if !ok_threshold {
            sym.zeroize();
            return Err(Error::Threshold);
        }
        if !verifies(hrp, &sym[..body.len()]) {
            sym.zeroize();
            return Err(Error::Checksum);
        }
        let mut share = Share::empty();
        share.hrp = hrp;
        let len = HEADER + payload;
        share.data[..len].copy_from_slice(&sym[..len]);
        share.len = len as u8;
        sym.zeroize();
        Ok(share)
    }

    /// A string for `bytes` of secret, with zero padding.
    ///
    /// `threshold` is `0` (a standalone secret, index `s` only) or 2-9; `id` and `index`
    /// are symbols. Refuses a length the prefix does not carry.
    pub fn from_bytes(
        hrp: Hrp,
        threshold: u8,
        id: [u8; 4],
        index: u8,
        bytes: &[u8],
        _kw: &KeyWork,
    ) -> Result<Self, Error> {
        if !hrp.carries(bytes.len()) {
            return Err(Error::Length);
        }
        let t = threshold_symbol(threshold).ok_or(Error::Threshold)?;
        if threshold == 0 && index != SECRET_INDEX {
            return Err(Error::Threshold);
        }
        let mut share = Share::empty();
        share.hrp = hrp;
        share.data[0] = t;
        for (o, v) in share.data[1..5].iter_mut().zip(id) {
            *o = v & 31;
        }
        share.data[5] = index & 31;
        let syms = payload_symbols(bytes.len());
        bits_to_symbols(bytes, &mut share.data[HEADER..HEADER + syms]);
        share.len = (HEADER + syms) as u8;
        Ok(share)
    }

    /// What the string holds.
    pub fn hrp(&self) -> Hrp {
        self.hrp
    }

    /// The threshold: `0` for a standalone secret, else 2-9.
    pub fn threshold(&self) -> u8 {
        threshold_of(self.data[0]).unwrap_or(0)
    }

    /// The four identifier characters, lowercase.
    pub fn id(&self) -> [u8; 4] {
        let mut out = [0u8; 4];
        for (o, &v) in out.iter_mut().zip(&self.data[1..5]) {
            *o = ALPHABET[v as usize];
        }
        out
    }

    /// The index, as a symbol. [`SECRET_INDEX`] for the secret.
    pub fn index(&self) -> u8 {
        self.data[5]
    }

    /// The index as its character, lowercase.
    pub fn index_char(&self) -> u8 {
        ALPHABET[self.data[5] as usize]
    }

    /// Whether this is the secret rather than a share.
    pub fn is_secret(&self) -> bool {
        self.data[5] == SECRET_INDEX
    }

    /// Bytes of secret the payload carries.
    pub fn byte_len(&self) -> usize {
        payload_bytes(self.len as usize - HEADER).unwrap_or(0)
    }

    /// Payload symbols, padding included.
    fn payload(&self) -> &[u8] {
        &self.data[HEADER..self.len as usize]
    }

    /// Length of the written string.
    pub fn text_len(&self) -> usize {
        let n = self.len as usize;
        3 + n + if is_long(n + 13) { 15 } else { 13 }
    }

    /// Write the string, checksum and all, into `out`: uppercase when `upper`, which is
    /// how Coldcard shows it. Returns the text.
    pub fn write<'o>(&self, upper: bool, out: &'o mut [u8; MAX_STRING], _kw: &KeyWork) -> &'o str {
        let n = self.len as usize;
        let mut check = [0u8; 15];
        let c = checksum(self.hrp, &self.data[..n], &mut check);
        let case = if upper { 0x20u8 } else { 0 };
        let h = self.hrp.text().as_bytes();
        out[0] = h[0] ^ case;
        out[1] = h[1] ^ case;
        out[2] = b'1';
        let mut at = 3;
        for &v in self.data[..n].iter().chain(&check[..c]) {
            let ch = char_of(v);
            // Letters change case; digits do not (bit 6 is set only on letters).
            out[at] = ch ^ (case & ((ch >> 1) & 0x20));
            at += 1;
        }
        // Every byte written is ASCII from the alphabet or the prefix.
        core::str::from_utf8(&out[..at]).unwrap_or("")
    }

    /// The wallet this secret is: the payload as bytes, padding dropped.
    ///
    /// Only an index-`s` string is a wallet. A `cx` key must be a valid secp256k1 scalar
    /// before it is used; a share's payload is not a key and is not checked.
    /// Source: hw-reference/codex32-format.md §How each secret maps [C]
    pub fn secret(&self, _kw: &KeyWork) -> Result<Secret, Error> {
        if !self.is_secret() {
            return Err(Error::NotSecret);
        }
        let mut s = Secret {
            hrp: self.hrp,
            bytes: [0; 64],
            len: self.byte_len(),
        };
        symbols_to_bits(self.payload(), &mut s.bytes[..s.len]);
        if self.hrp == Hrp::Cx {
            let mut k = [0u8; 32];
            k.copy_from_slice(&s.bytes[32..64]);
            let ok = crate::bip32::is_valid_secret(&k);
            k.zeroize();
            if !ok {
                return Err(Error::Invalid);
            }
        }
        Ok(s)
    }
}

/// The threshold digit a symbol spells, if it is `0` or `2`-`9`.
fn threshold_of(v: u8) -> Option<u8> {
    match ALPHABET[v as usize & 31] {
        b'0' => Some(0),
        d @ b'2'..=b'9' => Some(d - b'0'),
        _ => None,
    }
}

/// The symbol for threshold `t`, if it is a threshold.
fn threshold_symbol(t: u8) -> Option<u8> {
    if t == 1 || t > 9 {
        return None;
    }
    let ch = b'0' + t;
    ALPHABET.iter().position(|&c| c == ch).map(|p| p as u8)
}

/// Pack `bytes` MSB-first into 5-bit symbols; the last symbol's spare bits are zero.
fn bits_to_symbols(bytes: &[u8], out: &mut [u8]) {
    let mut acc: u32 = 0;
    let mut bits = 0u32;
    let mut at = 0;
    for &b in bytes {
        acc = (acc << 8) | u32::from(b);
        bits += 8;
        while bits >= 5 {
            bits -= 5;
            out[at] = ((acc >> bits) & 31) as u8;
            at += 1;
        }
    }
    if bits > 0 {
        out[at] = ((acc << (5 - bits)) & 31) as u8;
    }
    acc.zeroize();
}

/// Unpack 5-bit symbols MSB-first into `out`, dropping whatever bits are left over.
fn symbols_to_bits(symbols: &[u8], out: &mut [u8]) {
    let mut acc: u32 = 0;
    let mut bits = 0u32;
    let mut at = 0;
    for &v in symbols {
        acc = (acc << 5) | u32::from(v & 31);
        bits += 5;
        if bits >= 8 {
            bits -= 8;
            if at < out.len() {
                out[at] = (acc >> bits) as u8;
                at += 1;
            }
        }
    }
    acc.zeroize();
}

/// A recovered or imported secret, as wallet bytes. Wiped on drop.
///
/// How it is stored is the prefix's business: words for `cw`, a raw master for `ms`, an
/// xprv for `cx`. Source: hw-reference/secret-stash-format.md §Codex32 [C]
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct Secret {
    #[zeroize(skip)]
    hrp: Hrp,
    bytes: [u8; 64],
    len: usize,
}

impl Secret {
    /// Which kind of wallet.
    pub fn hrp(&self) -> Hrp {
        self.hrp
    }

    /// The bytes: entropy, seed, or chain code then key.
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes[..self.len]
    }
}

// ---------------------------------------------------------------------------------------
// A set of shares
// ---------------------------------------------------------------------------------------

/// Up to nine strings of one set, enough to interpolate any other member once there are
/// as many as the threshold. Wiped on drop (each share wipes itself).
pub struct Set {
    shares: [Share; MAX_SHARES],
    count: usize,
}

impl Default for Set {
    fn default() -> Self {
        Self::new()
    }
}

impl Set {
    pub const fn new() -> Self {
        Set {
            shares: [const { Share::empty() }; MAX_SHARES],
            count: 0,
        }
    }

    /// How many are in.
    pub fn len(&self) -> usize {
        self.count
    }

    pub fn is_empty(&self) -> bool {
        self.count == 0
    }

    /// The threshold the set's first share named, once there is one.
    pub fn threshold(&self) -> Option<u8> {
        (self.count > 0).then(|| self.shares[0].threshold())
    }

    /// Whether there are as many shares as the threshold.
    pub fn is_complete(&self) -> bool {
        self.threshold()
            .is_some_and(|t| self.count == usize::from(t))
    }

    /// The shares in, in the order they arrived.
    pub fn shares(&self) -> &[Share] {
        &self.shares[..self.count]
    }

    /// Whether `index` (a symbol) is already in the set.
    pub fn holds(&self, index: u8) -> bool {
        self.shares().iter().any(|s| s.index() == index)
    }

    /// Add a share. Refuses the secret, a share of another set (prefix, identifier,
    /// threshold, length), a repeated index, and one past the threshold.
    /// Source: hw-reference/codex32-format.md §Device operations "Shamir Recover" [C]
    pub fn add(&mut self, share: Share) -> Result<usize, Error> {
        if share.is_secret() {
            return Err(Error::SecretNotShare);
        }
        self.push(share)
    }

    fn push(&mut self, share: Share) -> Result<usize, Error> {
        if let Some(first) = self.shares().first() {
            if first.hrp != share.hrp
                || first.data[..5] != share.data[..5]
                || first.len != share.len
            {
                return Err(Error::Mismatch);
            }
            if self.is_complete() {
                return Err(Error::Full);
            }
        }
        if self.holds(share.index()) {
            return Err(Error::Duplicate);
        }
        // A threshold-0 string is the secret alone, so it never gets here as a share;
        // the parser already refused threshold 0 on any other index.
        self.shares[self.count] = share;
        self.count += 1;
        Ok(self.count)
    }

    /// The member of this set at `index` (a symbol): the secret at [`SECRET_INDEX`], any
    /// other index a further share that joins the same set.
    ///
    /// Lagrange interpolation over every header and payload symbol. The weights depend
    /// only on the indices, which are public; the products with share symbols are the
    /// constant-time multiply. Source: BIP-93 `ms32_interpolate`;
    /// hw-reference/codex32-format.md §Sharing [C]
    pub fn interpolate(&self, index: u8, _kw: &KeyWork) -> Result<Share, Error> {
        if !self.is_complete() {
            return Err(Error::Incomplete);
        }
        let index = index & 31;
        let pts = self.shares();
        let mut w = [0u8; MAX_SHARES];
        for (i, si) in pts.iter().enumerate() {
            let xi = si.index();
            let (mut num, mut den) = (1u8, 1u8);
            for (j, sj) in pts.iter().enumerate() {
                if i != j {
                    num = mul(num, index ^ sj.index());
                    den = mul(den, xi ^ sj.index());
                }
            }
            w[i] = mul(num, inv(den));
        }
        let first = &pts[0];
        let mut out = Share::empty();
        out.hrp = first.hrp;
        out.len = first.len;
        for k in 0..first.len as usize {
            let mut acc = 0u8;
            for (wi, s) in w.iter().zip(pts) {
                acc ^= mul(*wi, s.data[k]);
            }
            out.data[k] = acc;
        }
        Ok(out)
    }

    /// Interpolate the secret.
    pub fn recover(&self, kw: &KeyWork) -> Result<Share, Error> {
        self.interpolate(SECRET_INDEX, kw)
    }

    /// The first index of [`SHARE_ORDER`] nobody in the set has, for Derive Shares.
    pub fn unused_index(&self) -> Option<u8> {
        SHARE_ORDER.iter().copied().find(|&i| !self.holds(i))
    }
}

/// Noise bytes a split of `secret` at threshold `k` needs: four identifier symbols, then
/// every payload symbol -- padding included -- of `k - 1` free shares, five bits each.
pub fn noise_len(secret: &Share, k: u8) -> usize {
    let syms = 4 + usize::from(k.saturating_sub(1)) * secret.payload().len();
    (syms * 5).div_ceil(8)
}

/// Split `secret` into a set with threshold `k` (2-9) and a fresh identifier.
///
/// `noise` is seed-grade randomness, at least [`noise_len`] bytes: the identifier and
/// the `k - 1` free shares (indices `a`, `c`, ... in [`SHARE_ORDER`]) are read from it,
/// five bits a symbol. The returned set holds the secret and those shares, so every share
/// of the split is [`Set::interpolate`] at `SHARE_ORDER[i]` -- the first `k - 1` are the
/// free shares themselves, the rest are determined by them.
///
/// This is the one place a weak generator leaks the secret outright: with predictable
/// free shares, a single share gives the polynomial away. Hence bytes in, never a seed.
/// Source: hw-reference/codex32-format.md §Shamir Split randomness [C]
pub fn split(secret: &Share, k: u8, noise: &[u8], _kw: &KeyWork) -> Result<Set, Error> {
    if !secret.is_secret() {
        return Err(Error::NotSecret);
    }
    let t = match k {
        2..=9 => threshold_symbol(k).ok_or(Error::Threshold)?,
        _ => return Err(Error::Threshold),
    };
    if noise.len() < noise_len(secret, k) {
        return Err(Error::Invalid);
    }
    let mut bits = BitReader::new(noise);
    let mut head = [0u8; 5];
    head[0] = t;
    for h in head[1..5].iter_mut() {
        *h = bits.next();
    }
    let mut set = Set::new();
    let mut s = secret.clone();
    s.data[..5].copy_from_slice(&head);
    set.push(s)?;
    for &index in SHARE_ORDER.iter().take(usize::from(k) - 1) {
        let mut share = Share::empty();
        share.hrp = secret.hrp;
        share.len = secret.len;
        share.data[..5].copy_from_slice(&head);
        share.data[5] = index;
        for v in share.data[HEADER..secret.len as usize].iter_mut() {
            *v = bits.next();
        }
        set.push(share)?;
    }
    Ok(set)
}

/// Five bits at a time out of a byte slice, MSB first.
struct BitReader<'a> {
    bytes: &'a [u8],
    at: usize,
}

impl<'a> BitReader<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        BitReader { bytes, at: 0 }
    }

    fn next(&mut self) -> u8 {
        let mut v = 0u8;
        for _ in 0..5 {
            let byte = self.bytes.get(self.at / 8).copied().unwrap_or(0);
            v = (v << 1) | ((byte >> (7 - self.at % 8)) & 1);
            self.at += 1;
        }
        v
    }
}

/// The fixed identifier a generated or regenerated standalone secret uses: `seed`.
/// Source: hw-reference/codex32-format.md §Device operations "Generate" [C]
pub fn seed_id() -> [u8; 4] {
    let mut id = [0u8; 4];
    for (o, c) in id.iter_mut().zip(b"seed") {
        *o = symbol_of(*c);
    }
    id
}

#[cfg(test)]
mod tests;
