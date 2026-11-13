//! Signing typed data with an Ethereum key: EIP-712.
//!
//! What a site asks for when the thing to be agreed has fields -- a token permit, an
//! order, a vote. The digest is
//!
//! ```text
//! keccak256( 0x19 0x01 || hashStruct(domain) || hashStruct(message) )
//! hashStruct(s) = keccak256( typeHash(s) || enc(field 1) || enc(field 2) || ... )
//! typeHash(s)   = keccak256( encodeType(s) )
//! ```
//!
//! with `encodeType` the struct written as `Name(type name,type name)` followed by every
//! struct it refers to, sorted by name, and `enc` a value's 32 bytes: an atomic value
//! padded, `keccak256` of a `string` or `bytes`, `hashStruct` of a struct, and for an
//! array `keccak256` of its elements' encodings one after another.
//!
//! Source: EIP-712 "Typed structured data hashing and signing" [C], as `eth_signTypedData_v4`
//! implements it (arrays and nested structs). Public standard.
//!
//! # What arrives
//!
//! Not JSON. The host turns the JSON a site hands it into the layout below -- the same
//! types, the same values, in the order the types give them -- and this reads that. A
//! JSON reader on the device would be the largest thing in this crate and the one most
//! likely to read a document differently from the site that wrote it.
//!
//! ```text
//! [u8 version = 1]
//! [u8 types] x ( [short name] [u8 fields] x ( [short type] [short name] ) )
//! [u8 primary]                      index of the message's type
//! [domain's value] [message's value]
//! ```
//!
//! A `short` is a length byte and that many bytes. One of the types is `EIP712Domain`.
//! A value is written by its type:
//!
//! | type | bytes |
//! |---|---|
//! | `uintN` | `[u8 n]`, then `n` bytes big-endian, `n` at most `N/8` |
//! | `intN` | `N/8` bytes, two's complement, big-endian |
//! | `bool` | one byte, 0 or 1 |
//! | `address` | twenty bytes |
//! | `bytesN` | `N` bytes |
//! | `string`, `bytes` | `[u16 length]` little-endian, then the bytes |
//! | `T[]` | `[u16 count]` little-endian, then each element |
//! | `T[n]` | the `n` elements |
//! | a struct | its fields in order |
//!
//! # One walk
//!
//! [`Typed::walk`] hashes the values and hands each one to the caller in the same pass,
//! so the digest is of exactly what was put on the screen: there is no second reading
//! that could differ from the first.
//!
//! # What this refuses
//!
//! A `string` that is not printable ASCII (it could not be shown), a type string EIP-712
//! does not define (`uint` alone, `bytes33`), a domain with a field the standard does not
//! give it, a message whose type *is* the domain, values nested more than [`MAX_DEPTH`]
//! deep, and anything left over after the last value.

use purecrypto::hash::{Digest, Keccak256};

/// The layout's version byte.
pub const VERSION: u8 = 1;

/// Most struct types one request may define.
pub const MAX_TYPES: usize = 12;

/// Most fields one struct may have.
pub const MAX_FIELDS: usize = 24;

/// How deep a value may sit: each struct field and each array index is one level.
pub const MAX_DEPTH: usize = 6;

/// Longest type or field name.
pub const MAX_NAME: usize = 64;

/// The domain's type name. Source: EIP-712 §Definition of domainSeparator [C]
pub const DOMAIN: &str = "EIP712Domain";

/// The fields a domain may have, in the order the standard lists them.
/// Source: EIP-712 §Definition of domainSeparator [C]
const DOMAIN_FIELDS: [(&str, &str); 5] = [
    ("string", "name"),
    ("string", "version"),
    ("uint256", "chainId"),
    ("address", "verifyingContract"),
    ("bytes32", "salt"),
];

/// Why typed data could not be read.
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub enum Error {
    /// A version byte this does not know.
    Version,
    /// The bytes ended inside something.
    Truncated,
    /// Bytes left after the last value.
    Trailing,
    /// No types, or more than [`MAX_TYPES`].
    TooManyTypes,
    /// A struct with more than [`MAX_FIELDS`] fields.
    TooManyFields,
    /// A type or field name that is not an identifier.
    BadName,
    /// Two types, or two fields of one type, with the same name.
    Duplicate,
    /// A field of a type nothing defines.
    UnknownType,
    /// A type string EIP-712 does not have.
    BadType,
    /// No `EIP712Domain` among the types.
    NoDomain,
    /// A domain with no fields, a field the standard does not give it, or out of order.
    BadDomain,
    /// The primary type is not one of the types, or is the domain itself.
    BadPrimary,
    /// Nested more than [`MAX_DEPTH`] deep.
    TooDeep,
    /// A value that does not fit its type.
    BadValue,
    /// A `string` that is not printable ASCII.
    NotText,
}

impl Error {
    /// The same, in the words a screen or a refusal has.
    pub const fn why(self) -> &'static str {
        match self {
            Error::Version => "typed data of an unknown version",
            Error::Truncated => "typed data ends early",
            Error::Trailing => "typed data has bytes left over",
            Error::TooManyTypes => "typed data has too many types",
            Error::TooManyFields => "a type has too many fields",
            Error::BadName => "a name is not an identifier",
            Error::Duplicate => "a name is used twice",
            Error::UnknownType => "a field's type is not defined",
            Error::BadType => "not an EIP-712 type",
            Error::NoDomain => "typed data has no domain",
            Error::BadDomain => "not an EIP-712 domain",
            Error::BadPrimary => "no such message type",
            Error::TooDeep => "typed data is nested too deep",
            Error::BadValue => "a value does not fit its type",
            Error::NotText => "a text field is not plain ASCII",
        }
    }
}

/// A reader over the request's bytes.
#[derive(Copy, Clone)]
struct Cur<'a> {
    b: &'a [u8],
}

impl<'a> Cur<'a> {
    fn take(&mut self, n: usize) -> Result<&'a [u8], Error> {
        if self.b.len() < n {
            return Err(Error::Truncated);
        }
        let (head, tail) = self.b.split_at(n);
        self.b = tail;
        Ok(head)
    }

    fn u8(&mut self) -> Result<u8, Error> {
        Ok(self.take(1)?[0])
    }

    fn u16(&mut self) -> Result<u16, Error> {
        let s = self.take(2)?;
        Ok(u16::from_le_bytes([s[0], s[1]]))
    }

    /// A length byte and that many bytes of ASCII.
    fn short(&mut self) -> Result<&'a str, Error> {
        let n = usize::from(self.u8()?);
        let s = self.take(n)?;
        if !s.is_ascii() {
            return Err(Error::BadName);
        }
        core::str::from_utf8(s).map_err(|_| Error::BadName)
    }
}

/// Whether `s` is a name: a letter or `_`, then letters, digits and `_`.
fn ident(s: &str) -> bool {
    let b = s.as_bytes();
    !b.is_empty()
        && b.len() <= MAX_NAME
        && (b[0].is_ascii_alphabetic() || b[0] == b'_')
        && b.iter().all(|c| c.is_ascii_alphanumeric() || *c == b'_')
}

/// A decimal number as a type string writes one: digits, no leading zero.
fn number(s: &str) -> Option<u16> {
    let b = s.as_bytes();
    if b.is_empty() || b.len() > 4 || b[0] == b'0' || !b.iter().all(u8::is_ascii_digit) {
        return None;
    }
    s.parse().ok()
}

/// What a type string says.
#[derive(Copy, Clone)]
enum Ty<'a> {
    Uint(u16),
    Int(u16),
    Bool,
    Address,
    Fixed(u8),
    Bytes,
    Str,
    Struct(usize),
    /// Elements of the type named, and how many when the type fixes it.
    Array(&'a str, Option<u16>),
}

/// An atomic or dynamic type's string, or `None` for anything else.
fn atomic(s: &str) -> Option<Ty<'static>> {
    let width = |n: &str| number(n).filter(|n| n % 8 == 0 && (8..=256).contains(n));
    match s {
        "bool" => Some(Ty::Bool),
        "address" => Some(Ty::Address),
        "string" => Some(Ty::Str),
        "bytes" => Some(Ty::Bytes),
        _ => {
            if let Some(n) = s.strip_prefix("bytes") {
                number(n)
                    .filter(|n| (1..=32).contains(n))
                    .map(|n| Ty::Fixed(n as u8))
            } else if let Some(n) = s.strip_prefix("uint") {
                width(n).map(Ty::Uint)
            } else if let Some(n) = s.strip_prefix("int") {
                width(n).map(Ty::Int)
            } else {
                None
            }
        }
    }
}

/// Keccak-256 of `b`, in a frame of its own: see [`Typed::type_hash`].
#[inline(never)]
fn hash(b: &[u8]) -> [u8; 32] {
    Keccak256::digest(b)
}

/// One struct type: its name and its fields as they arrived.
#[derive(Copy, Clone)]
struct TypeDef<'a> {
    name: &'a str,
    /// `count` fields, each `[short type][short name]`, already read through once.
    fields: &'a [u8],
    count: u8,
}

/// The fields of a type: `(type, name)`.
struct Fields<'a> {
    c: Cur<'a>,
    left: u8,
}

impl<'a> Iterator for Fields<'a> {
    type Item = (&'a str, &'a str);

    fn next(&mut self) -> Option<Self::Item> {
        if self.left == 0 {
            return None;
        }
        self.left -= 1;
        let ty = self.c.short().ok()?;
        let name = self.c.short().ok()?;
        Some((ty, name))
    }
}

/// Which of the two structs a value belongs to.
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub enum Part {
    /// The domain: who is asking, and on which chain.
    Domain,
    /// The message itself.
    Message,
}

/// One step of where a value sits.
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub enum Seg<'a> {
    /// A struct's field.
    Field(&'a str),
    /// An array's element.
    Index(u16),
}

/// Where a value sits, written as `details.token` or `to[1].wallet`.
pub struct Label<'p, 'a>(pub &'p [Seg<'a>]);

impl core::fmt::Display for Label<'_, '_> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        for (i, seg) in self.0.iter().enumerate() {
            match seg {
                Seg::Field(name) if i == 0 => f.write_str(name)?,
                Seg::Field(name) => write!(f, ".{name}")?,
                Seg::Index(k) => write!(f, "[{k}]")?,
            }
        }
        Ok(())
    }
}

/// One value, as it was read.
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub enum Leaf<'a> {
    /// A `uintN`, as 32 bytes big-endian, and its `N`.
    Uint {
        raw: [u8; 32],
        bits: u16,
    },
    /// An `intN`, sign-extended to 32 bytes.
    Int {
        raw: [u8; 32],
    },
    Bool(bool),
    Address([u8; 20]),
    /// A `bytesN`.
    Fixed(&'a [u8]),
    /// A `bytes`.
    Bytes(&'a [u8]),
    /// A `string`: printable ASCII and line breaks.
    Str(&'a str),
    /// An array with nothing in it.
    Empty,
}

/// What a walk came to.
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub struct Hashes {
    /// `hashStruct(domain)`: the domain separator.
    pub domain: [u8; 32],
    /// `hashStruct(message)`.
    pub message: [u8; 32],
    /// What is signed.
    pub digest: [u8; 32],
}

/// What a walk hands each value to.
pub type See<'s, 'a> = dyn FnMut(Part, &[Seg<'a>], Leaf<'a>) + 's;

/// Typed data, its types checked and its values not yet read.
pub struct Typed<'a> {
    types: [TypeDef<'a>; MAX_TYPES],
    count: usize,
    domain: usize,
    primary: usize,
    values: &'a [u8],
}

impl<'a> Typed<'a> {
    /// Read the types of `blob` and check them. The values are read by [`Typed::walk`].
    pub fn parse(blob: &'a [u8]) -> Result<Self, Error> {
        let mut c = Cur { b: blob };
        if c.u8()? != VERSION {
            return Err(Error::Version);
        }
        let count = usize::from(c.u8()?);
        if count == 0 || count > MAX_TYPES {
            return Err(Error::TooManyTypes);
        }
        let mut types = [TypeDef {
            name: "",
            fields: &[],
            count: 0,
        }; MAX_TYPES];
        for i in 0..count {
            let name = c.short()?;
            // A struct named as an atomic type would never be reached: the atomic
            // reading wins. Refused, so the types mean what they appear to.
            if !ident(name) || atomic(name).is_some() {
                return Err(Error::BadName);
            }
            if types[..i].iter().any(|t| t.name == name) {
                return Err(Error::Duplicate);
            }
            let fields = c.u8()?;
            if usize::from(fields) > MAX_FIELDS {
                return Err(Error::TooManyFields);
            }
            let start = c.b;
            for _ in 0..fields {
                let ty = c.short()?;
                if ty.is_empty() {
                    return Err(Error::BadType);
                }
                if !ident(c.short()?) {
                    return Err(Error::BadName);
                }
            }
            types[i] = TypeDef {
                name,
                fields: &start[..start.len() - c.b.len()],
                count: fields,
            };
        }
        let primary = usize::from(c.u8()?);
        let domain = types[..count]
            .iter()
            .position(|t| t.name == DOMAIN)
            .ok_or(Error::NoDomain)?;
        if primary >= count || primary == domain {
            return Err(Error::BadPrimary);
        }
        let typed = Typed {
            types,
            count,
            domain,
            primary,
            values: c.b,
        };
        for i in 0..count {
            for (k, (ty, name)) in typed.fields(i).enumerate() {
                typed.base(ty)?;
                if typed.fields(i).take(k).any(|(_, n)| n == name) {
                    return Err(Error::Duplicate);
                }
            }
        }
        // The domain: only the standard's fields, each of the standard's type, in the
        // standard's order.
        let mut next = 0;
        for field in typed.fields(domain) {
            let at = DOMAIN_FIELDS[next..]
                .iter()
                .position(|f| *f == field)
                .ok_or(Error::BadDomain)?;
            next += at + 1;
        }
        if next == 0 {
            return Err(Error::BadDomain);
        }
        Ok(typed)
    }

    /// The name of the message's type.
    pub fn primary(&self) -> &'a str {
        self.types[self.primary].name
    }

    fn fields(&self, i: usize) -> Fields<'a> {
        Fields {
            c: Cur {
                b: self.types[i].fields,
            },
            left: self.types[i].count,
        }
    }

    /// What the type string `s` says, one array level at a time.
    fn ty(&self, s: &'a str) -> Result<Ty<'a>, Error> {
        if let Some(inner) = s.strip_suffix(']') {
            let at = inner.rfind('[').ok_or(Error::BadType)?;
            let (elem, n) = (&inner[..at], &inner[at + 1..]);
            if elem.is_empty() {
                return Err(Error::BadType);
            }
            let fixed = if n.is_empty() {
                None
            } else {
                Some(number(n).ok_or(Error::BadType)?)
            };
            return Ok(Ty::Array(elem, fixed));
        }
        if let Some(t) = atomic(s) {
            return Ok(t);
        }
        if !ident(s) {
            return Err(Error::BadType);
        }
        self.types[..self.count]
            .iter()
            .position(|t| t.name == s)
            .map(Ty::Struct)
            .ok_or(Error::UnknownType)
    }

    /// What `s` is an array of, however many arrays deep; `s` itself when it is not one.
    fn base(&self, mut s: &'a str) -> Result<Ty<'a>, Error> {
        for _ in 0..=MAX_DEPTH {
            match self.ty(s)? {
                Ty::Array(elem, _) => s = elem,
                t => return Ok(t),
            }
        }
        Err(Error::TooDeep)
    }

    /// `Name(type name,type name)` for type `i`, into `h`.
    fn encode_type(&self, i: usize, h: &mut Keccak256) {
        h.update(self.types[i].name.as_bytes());
        h.update(b"(");
        for (k, (ty, name)) in self.fields(i).enumerate() {
            if k > 0 {
                h.update(b",");
            }
            h.update(ty.as_bytes());
            h.update(b" ");
            h.update(name.as_bytes());
        }
        h.update(b")");
    }

    /// `typeHash` of type `i`: the type itself, then every struct it reaches, by name.
    // Its own frame, and gone before the fields are read: `structure` calls itself
    // through `value`, and a hasher held at every level is what the stack is spent on.
    #[inline(never)]
    fn type_hash(&self, i: usize) -> [u8; 32] {
        const _: () = assert!(MAX_TYPES <= 16);
        let mut reached: u16 = 1 << i;
        loop {
            let before = reached;
            for j in 0..self.count {
                if reached & (1 << j) == 0 {
                    continue;
                }
                for (ty, _) in self.fields(j) {
                    if let Ok(Ty::Struct(k)) = self.base(ty) {
                        reached |= 1 << k;
                    }
                }
            }
            if reached == before {
                break;
            }
        }
        let mut h = Keccak256::new();
        self.encode_type(i, &mut h);
        let mut rest = reached & !(1 << i);
        while rest != 0 {
            let mut first: Option<usize> = None;
            for j in 0..self.count {
                if rest & (1 << j) != 0
                    && first.is_none_or(|f| self.types[j].name < self.types[f].name)
                {
                    first = Some(j);
                }
            }
            let Some(j) = first else { break };
            self.encode_type(j, &mut h);
            rest &= !(1 << j);
        }
        h.finalize()
    }

    /// Read the values, hand each to `see` in the order they are hashed, and give the
    /// digest of exactly those.
    pub fn walk(&self, see: &mut See<'_, 'a>) -> Result<Hashes, Error> {
        let mut c = Cur { b: self.values };
        let mut path = [Seg::Index(0); MAX_DEPTH];
        let domain = self.structure(&mut c, self.domain, Part::Domain, &mut path, 0, see)?;
        let message = self.structure(&mut c, self.primary, Part::Message, &mut path, 0, see)?;
        if !c.b.is_empty() {
            return Err(Error::Trailing);
        }
        let mut h = Keccak256::new();
        h.update(&[0x19, 0x01]);
        h.update(&domain);
        h.update(&message);
        Ok(Hashes {
            domain,
            message,
            digest: h.finalize(),
        })
    }

    /// `hashStruct` of a value of type `i`, read from `c`.
    fn structure(
        &self,
        c: &mut Cur<'a>,
        i: usize,
        part: Part,
        path: &mut [Seg<'a>; MAX_DEPTH],
        depth: usize,
        see: &mut See<'_, 'a>,
    ) -> Result<[u8; 32], Error> {
        let mut h = Keccak256::new();
        h.update(&self.type_hash(i));
        for (ty, name) in self.fields(i) {
            if depth >= MAX_DEPTH {
                return Err(Error::TooDeep);
            }
            path[depth] = Seg::Field(name);
            h.update(&self.value(c, ty, part, path, depth + 1, see)?);
        }
        Ok(h.finalize())
    }

    /// The 32 bytes an array of `elem` is hashed as, read from `c`: the hash of its
    /// elements' encodings, one after another.
    #[allow(clippy::too_many_arguments)]
    #[inline(never)]
    fn array(
        &self,
        c: &mut Cur<'a>,
        elem: &'a str,
        fixed: Option<u16>,
        part: Part,
        path: &mut [Seg<'a>; MAX_DEPTH],
        depth: usize,
        see: &mut See<'_, 'a>,
    ) -> Result<[u8; 32], Error> {
        let n = match fixed {
            Some(n) => n,
            None => c.u16()?,
        };
        if n == 0 {
            see(part, &path[..depth], Leaf::Empty);
        }
        let mut h = Keccak256::new();
        for k in 0..n {
            if depth >= MAX_DEPTH {
                return Err(Error::TooDeep);
            }
            path[depth] = Seg::Index(k);
            h.update(&self.value(c, elem, part, path, depth + 1, see)?);
        }
        Ok(h.finalize())
    }

    /// The 32 bytes a value of type `ty` is hashed as, read from `c`.
    fn value(
        &self,
        c: &mut Cur<'a>,
        ty: &'a str,
        part: Part,
        path: &mut [Seg<'a>; MAX_DEPTH],
        depth: usize,
        see: &mut See<'_, 'a>,
    ) -> Result<[u8; 32], Error> {
        let mut out = [0u8; 32];
        let leaf = match self.ty(ty)? {
            Ty::Struct(i) => return self.structure(c, i, part, path, depth, see),
            Ty::Array(elem, fixed) => {
                return self.array(c, elem, fixed, part, path, depth, see);
            }
            Ty::Uint(bits) => {
                let n = usize::from(c.u8()?);
                if n > usize::from(bits) / 8 {
                    return Err(Error::BadValue);
                }
                out[32 - n..].copy_from_slice(c.take(n)?);
                Leaf::Uint { raw: out, bits }
            }
            Ty::Int(bits) => {
                let n = usize::from(bits) / 8;
                let b = c.take(n)?;
                if b[0] & 0x80 != 0 {
                    out = [0xff; 32];
                }
                out[32 - n..].copy_from_slice(b);
                Leaf::Int { raw: out }
            }
            Ty::Bool => match c.u8()? {
                0 => Leaf::Bool(false),
                1 => {
                    out[31] = 1;
                    Leaf::Bool(true)
                }
                _ => return Err(Error::BadValue),
            },
            Ty::Address => {
                let mut a = [0u8; 20];
                a.copy_from_slice(c.take(20)?);
                out[12..].copy_from_slice(&a);
                Leaf::Address(a)
            }
            Ty::Fixed(n) => {
                let b = c.take(usize::from(n))?;
                out[..b.len()].copy_from_slice(b);
                Leaf::Fixed(b)
            }
            Ty::Bytes => {
                let n = usize::from(c.u16()?);
                let b = c.take(n)?;
                out = hash(b);
                Leaf::Bytes(b)
            }
            Ty::Str => {
                let n = usize::from(c.u16()?);
                let b = c.take(n)?;
                if !b.iter().all(|&x| (0x20..0x7f).contains(&x) || x == b'\n') {
                    return Err(Error::NotText);
                }
                out = hash(b);
                Leaf::Str(core::str::from_utf8(b).map_err(|_| Error::NotText)?)
            }
        };
        see(part, &path[..depth], leaf);
        Ok(out)
    }
}

#[cfg(test)]
mod tests;
