//! BC-UR: a payload split across animated QR codes, for the chains that are not Bitcoin.
//!
//! BBQr is the denser format and the better one for a firmware image, but its file
//! types are Bitcoin artefacts -- a PSBT, a transaction. Anything else needs this, which
//! is why it is not an alternative but a second requirement.
//!
//! A part looks like:
//!
//! ```text
//! ur:<type>/<seqNum>-<seqLen>/<bytewords>
//! ```
//!
//! and the bytewords decode to CBOR:
//!
//! ```text
//! [ seqNum, seqLen, messageLen, checksum, data ]
//! ```
//!
//! Source: Blockchain Commons BCR-2020-005 and BCR-2024-001.
//!
//! # What is read, and what is not
//!
//! **Pure parts only.** BC-UR is a fountain code: parts numbered past `seqLen` are XOR
//! mixtures of several fragments, chosen by a PRNG seeded from the checksum. Parts up
//! to `seqLen` are single fragments, and every conforming encoder emits those first, so
//! a decoder that takes only them interoperates with all of them -- it simply waits for
//! the animation to come round. Accepting mixtures would buy a shorter wait at the cost
//! of a PRNG and a solver that both have to agree with the sender exactly, in the path
//! that decides what gets signed.
//!
//! **Fragments are padded.** Every fragment is the same length and `messageLen` says
//! where the real data stops, so unlike BBQr there is no short last part whose length
//! has to be learned before anything can be placed.
//!
//! # Where the bytes go is the caller's
//!
//! As in [`catcard_bbqr`](https://docs.rs/catcard-bbqr): [`Collector::accept`] says
//! where a part belongs and hands back its decoded bytes; the caller writes them
//! wherever it is assembling, and calls [`Collector::confirm`] once it has. A part is
//! not counted until it has actually been stored, because a collector that says
//! "complete" about a payload with a hole in it is worse than one that never finishes.

#![no_std]

pub mod bytewords;

mod cbor;

pub use cbor::Error as CborError;

/// What a part is not.
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub enum Error {
    /// Not a UR at all: no `ur:` prefix, or no type, or no payload.
    NotUr,
    /// The sequence field is not `<seqNum>-<seqLen>`, or the numbers are impossible.
    Numbering,
    /// The bytewords would not decode, or their checksum did not match.
    Bytewords(bytewords::Error),
    /// The CBOR inside is not the five-element part this expects.
    Cbor(CborError),
    /// A fountain mixture rather than a single fragment. Not an error in the payload --
    /// just a part this decoder skips, waiting for the pure ones.
    Mixture { seq_num: u32, seq_len: u32 },
    /// This part disagrees with the ones already seen about which message it is.
    Mismatch,
    /// The part would not fit in the space the caller has.
    TooLong,
}

impl From<bytewords::Error> for Error {
    fn from(e: bytewords::Error) -> Self {
        Error::Bytewords(e)
    }
}

impl From<CborError> for Error {
    fn from(e: CborError) -> Self {
        Error::Cbor(e)
    }
}

/// The most fragments a message may be split into.
///
/// Not from the format, which allows far more: this is what the `seen` set costs to
/// track, and 1024 fragments at even a kilobyte each is a megabyte of payload -- past
/// anything that can sensibly be waved at a camera.
pub const MAX_PARTS: usize = 1024;

/// What a part said about itself.
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub struct Part {
    pub seq_num: u32,
    pub seq_len: u32,
    pub message_len: u32,
    pub checksum: u32,
}

/// Where a part's bytes belong, once it is known to be a pure fragment.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Placed {
    /// Zero-based fragment index.
    pub index: u32,
    /// Where the fragment's bytes sit in the scratch buffer that was passed in.
    pub at: core::ops::Range<usize>,
    /// Where its bytes go in the message.
    pub offset: usize,
    /// How many of them belong to the message -- the last fragment's padding is not
    /// included, so this can be shorter than the fragment.
    pub len: usize,
    pub fresh: bool,
    pub have: u32,
    pub total: u32,
}

/// A UR line taken apart: its type, its sequence field if it has one, and its payload.
struct Fields<'a> {
    #[allow(dead_code)]
    ty: &'a [u8],
    seq: Option<&'a [u8]>,
    payload: &'a [u8],
}

/// Split `ur:type/seq/payload`.
///
/// A single-part UR has no sequence field; it reads as one fragment of one.
fn split(line: &[u8]) -> Result<Fields<'_>, Error> {
    let rest = line.strip_prefix(b"ur:").ok_or(Error::NotUr)?;
    let mut it = rest.split(|&c| c == b'/');
    let ty = it.next().ok_or(Error::NotUr)?;
    let a = it.next().ok_or(Error::NotUr)?;
    match it.next() {
        Some(b) if it.next().is_none() => Ok(Fields {
            ty,
            seq: Some(a),
            payload: b,
        }),
        None => Ok(Fields {
            ty,
            seq: None,
            payload: a,
        }),
        _ => Err(Error::NotUr),
    }
}

fn decimal(text: &[u8]) -> Option<u32> {
    if text.is_empty() {
        return None;
    }
    let mut n: u32 = 0;
    for &c in text {
        n = n
            .checked_mul(10)?
            .checked_add(c.checked_sub(b'0')? as u32)?;
        if c > b'9' {
            return None;
        }
    }
    Some(n)
}

/// Collects the fragments of one message.
///
/// Holds no payload: a fragment is decoded into whatever the caller is filling.
pub struct Collector {
    /// What the first part said. Every later part must agree.
    of: Option<Part>,
    seen: [u64; MAX_PARTS / 64],
    count: u32,
}

impl Collector {
    pub const fn new() -> Self {
        Collector {
            of: None,
            seen: [0; MAX_PARTS / 64],
            count: 0,
        }
    }

    /// Forget everything, so a different message can be read.
    pub fn reset(&mut self) {
        *self = Self::new();
    }

    /// What is being collected, once a part has been seen.
    pub fn about(&self) -> Option<Part> {
        self.of
    }

    /// Fragments seen so far.
    pub fn have(&self) -> u32 {
        self.count
    }

    /// Whether every fragment has been seen.
    pub fn complete(&self) -> bool {
        self.of.is_some_and(|p| self.count == p.seq_len)
    }

    /// Read one line, decoding it into `scratch`.
    ///
    /// The fragment's bytes end up at `scratch[placed.at]`; the returned [`Placed`]
    /// says where in the message they belong and how many of them count -- the last
    /// fragment carries padding, which is not part of the message.
    ///
    /// Does **not** count the part. [`confirm`](Self::confirm) does, once the caller has
    /// stored it.
    pub fn accept(&mut self, line: &[u8], scratch: &mut [u8]) -> Result<Placed, Error> {
        let Fields { seq, payload, .. } = split(line)?;

        // The sequence field is a claim the CBOR inside repeats; it is parsed to reject
        // a malformed line early, and the CBOR is what is believed.
        if let Some(seq) = seq {
            let mut halves = seq.split(|&c| c == b'-');
            let (a, b) = (halves.next(), halves.next());
            if halves.next().is_some() || a.and_then(decimal).is_none() {
                return Err(Error::Numbering);
            }
            if b.and_then(decimal).is_none() {
                return Err(Error::Numbering);
            }
        }

        let n = bytewords::decode(payload, scratch)?;
        let (part, data) = cbor::part(&scratch[..n])?;

        if part.seq_len == 0 || part.seq_len as usize > MAX_PARTS {
            return Err(Error::Numbering);
        }
        if part.seq_num == 0 {
            return Err(Error::Numbering);
        }
        // Past `seq_len` is a fountain mixture: several fragments combined. Skipped,
        // not failed -- the pure ones come round again.
        if part.seq_num > part.seq_len {
            return Err(Error::Mixture {
                seq_num: part.seq_num,
                seq_len: part.seq_len,
            });
        }

        match self.of {
            None => self.of = Some(part),
            Some(seen) => {
                if (seen.seq_len, seen.message_len, seen.checksum)
                    != (part.seq_len, part.message_len, part.checksum)
                {
                    return Err(Error::Mismatch);
                }
            }
        }

        // Every fragment is the same length, the last one padded, so an index is an
        // offset with no learning required.
        let fragment = (part.message_len as usize).div_ceil(part.seq_len as usize);
        if data.len() != fragment {
            return Err(Error::Mismatch);
        }
        let index = part.seq_num - 1;
        let offset = fragment * index as usize;
        // The last fragment's tail is padding, and stops at the message's end.
        let len = fragment.min((part.message_len as usize).saturating_sub(offset));

        let bit = 1u64 << (index % 64);
        let fresh = self.seen[index as usize / 64] & bit == 0;
        Ok(Placed {
            index,
            offset,
            len,
            at: data,
            fresh,
            have: self.count,
            total: part.seq_len,
        })
    }

    /// Record that a fragment has been stored.
    pub fn confirm(&mut self, placed: Placed) -> Placed {
        let bit = 1u64 << (placed.index % 64);
        let word = placed.index as usize / 64;
        let fresh = self.seen[word] & bit == 0;
        if fresh {
            self.seen[word] |= bit;
            self.count += 1;
        }
        Placed {
            fresh,
            have: self.count,
            ..placed
        }
    }

    /// Check the assembled message against the checksum every part carried.
    ///
    /// The fragments each proved their own bytewords checksum on the way in; this is
    /// the separate claim that they are the fragments of *this* message and that all of
    /// it is here.
    pub fn verify(&self, message: &[u8]) -> bool {
        self.of
            .is_some_and(|p| self.complete() && bytewords::crc32(message) == p.checksum)
    }
}

impl Default for Collector {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests;
