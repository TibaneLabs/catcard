//! BC-UR: a payload split across animated QR codes, for the chains that are not Bitcoin.
//!
//! BBQr is the denser format and the better one for a firmware image, but its file
//! types are Bitcoin artefacts -- a PSBT, a transaction. Anything else needs this, which
//! is why it is not an alternative but a second requirement.
//!
//! A UR comes in two shapes. A whole message in one code:
//!
//! ```text
//! ur:<type>/<bytewords>
//! ```
//!
//! where the bytewords decode to the message itself; or one part of several:
//!
//! ```text
//! ur:<type>/<seqNum>-<seqLen>/<bytewords>
//! ```
//!
//! where they decode to CBOR:
//!
//! ```text
//! [ seqNum, seqLen, messageLen, checksum, data ]
//! ```
//!
//! [`Collector`] takes either, and a single-part UR is simply a message of one
//! fragment -- same `Placed`, same `verify`, so a caller has one path. Most
//! `crypto-hdkey` and `crypto-account` URs, and a small PSBT, arrive in the first
//! shape, and refusing them would mean refusing most of what a wallet shows.
//!
//! Source: Blockchain Commons BCR-2020-005 and BCR-2024-001.
//!
//! # The type is carried
//!
//! The UR type says what the message *is* -- a PSBT, an account, opaque bytes -- and
//! [`registry`] is what unwraps it. So the collector keeps the type it saw and refuses
//! a part that disagrees: a different type is a different message, exactly as a
//! different checksum is, and mixing two animations that happen to have the same shape
//! would assemble a document neither sender sent.
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

pub mod encode;
pub mod registry;

mod cbor;

pub use cbor::Error as CborError;
/// The format itself -- bytewords, the checksum and the `ur:` line -- is outscript's.
/// What is here is the part that needs no allocator: where a fragment belongs.
pub use outscript::bcur::{Ur, bytewords, crc32};

/// What a part is not.
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub enum Error {
    /// Not a UR at all: no `ur:` prefix, or no type, or no payload.
    NotUr,
    /// The sequence field is not `<seqNum>-<seqLen>`, or the numbers are impossible.
    Numbering,
    /// The bytewords would not decode, or their checksum did not match.
    Bytewords(outscript::bcur::Error),
    /// The CBOR inside is not the five-element part this expects.
    Cbor(CborError),
    /// A fountain mixture rather than a single fragment. Not an error in the payload --
    /// just a part this decoder skips, waiting for the pure ones.
    Mixture { seq_num: u32, seq_len: u32 },
    /// This part disagrees with the ones already seen about which message it is.
    Mismatch,
    /// This part's UR type is not the type the parts before it had.
    TypeMismatch,
    /// The UR type is longer than [`MAX_TYPE`]. Every registered type is far shorter;
    /// this is refused rather than truncated, because a truncated type would compare
    /// equal to a different one.
    TypeTooLong,
    /// The part would not fit in the space the caller has.
    TooLong,
}

impl From<outscript::bcur::Error> for Error {
    fn from(e: outscript::bcur::Error) -> Self {
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

/// The longest UR type this will hold on to.
///
/// The longest name in BCR-2020-006's registry is `account-descriptor`, at eighteen
/// characters. Thirty-two is room for a type nobody has registered yet, and it is what
/// a [`Collector`] costs in bytes for remembering what it is collecting.
pub const MAX_TYPE: usize = 32;

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

/// Collects the fragments of one message.
///
/// Holds no payload: a fragment is decoded into whatever the caller is filling.
pub struct Collector {
    /// What the first part said. Every later part must agree.
    of: Option<Part>,
    /// The UR type the first part carried, lower-cased. Every later part must agree.
    ty: heapless::String<MAX_TYPE>,
    seen: [u64; MAX_PARTS / 64],
    count: u32,
}

impl Collector {
    pub const fn new() -> Self {
        Collector {
            of: None,
            ty: heapless::String::new(),
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

    /// The UR type being collected, lower-cased, once a part has been seen.
    ///
    /// Lower case because that is how the specification writes a type and how a
    /// registry lookup expects it; a QR carries the whole line upper-cased so the
    /// symbol can stay in alphanumeric mode.
    pub fn ur_type(&self) -> Option<&str> {
        self.of.is_some().then_some(self.ty.as_str())
    }

    /// The registry item being collected, if it is one this device knows.
    ///
    /// `None` for a type outside [`registry::Kind`] -- the transport does not care what
    /// it is carrying, so an unknown type still assembles; it simply arrives as bytes
    /// nobody can name.
    pub fn kind(&self) -> Option<registry::Kind> {
        registry::Kind::from_ur_type(self.ur_type()?)
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
    pub fn accept(&mut self, line: &str, scratch: &mut [u8]) -> Result<Placed, Error> {
        // Either case: a UR meant for a QR is upper-cased whole, prefix and type
        // included, so that the symbol can use its alphanumeric mode. The sequence
        // field it carries is a claim the CBOR inside repeats -- parsing it here
        // rejects a malformed line early, and the CBOR is what is believed.
        let ur = Ur::parse(line).map_err(|_| Error::NotUr)?;
        if ur.ur_type.len() > MAX_TYPE {
            return Err(Error::TypeTooLong);
        }
        let n = ur.decode_to_slice(scratch)?;

        // A UR with no sequence field carries the whole message, and its bytewords are
        // the message's own bytes -- there is no five-element part to read, and nothing
        // is padded. It is the one-fragment case of everything below.
        let (part, data) = if ur.sequence.is_none() {
            let message = Part {
                seq_num: 1,
                seq_len: 1,
                message_len: n as u32,
                // Bytewords already proved this checksum over exactly these bytes, so
                // it is not a second opinion -- it is what makes `verify` mean the same
                // thing whichever shape the UR arrived in.
                checksum: crc32(&scratch[..n]),
            };
            (message, 0..n)
        } else {
            cbor::part(&scratch[..n])?
        };

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

        // The type is checked before the numbers are believed, so that two animations
        // that happen to share a shape cannot be assembled into one message.
        match self.of {
            None => {}
            Some(seen) => {
                if !self.ty.eq_ignore_ascii_case(ur.ur_type) {
                    return Err(Error::TypeMismatch);
                }
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

        // Recorded only now that the part is known good, so a refused line leaves an
        // empty collector empty rather than committed to a type it never accepted.
        if self.of.is_none() {
            self.ty.clear();
            for c in ur.ur_type.chars() {
                self.ty
                    .push(c.to_ascii_lowercase())
                    .map_err(|_| Error::TypeTooLong)?;
            }
            self.of = Some(part);
        }

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
            .is_some_and(|p| self.complete() && crc32(message) == p.checksum)
    }
}

impl Default for Collector {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests;
