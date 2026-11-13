//! Signing a message with a Solana key: the off-chain message envelope.
//!
//! A Solana signature is over bytes, and a transaction is bytes. So a message is never
//! signed bare: it is wrapped in an envelope whose first byte, `0xff`, no transaction can
//! begin with -- a legacy transaction's first byte is a count of signatures it needs, a
//! versioned one's is `0x80` and a version -- and the signature is over the envelope.
//!
//! Two layouts, and this writes both for one signer:
//!
//! ```text
//! version 1:  [16 signing domain][u8 1][u8 signers = 1][32 signer][text]
//! version 0:  [16 signing domain][u8 0][32 application domain][u8 format]
//!             [u8 signers = 1][32 signer][u16 length, little-endian][text]
//! ```
//!
//! Version 1 is the current one. Version 0 is what the Solana CLI and older hardware
//! wallet apps make, and a verifier written for one does not accept the other, so the
//! host says which it wants.
//!
//! Source: Anza "Off-chain message signing" proposal, `docs.anza.xyz/proposals/
//! off-chain-message-signing`, read 2026-11-12 [C]. Public specification.
//!
//! # What this refuses
//!
//! Version 0's format 2 (long UTF-8), which the specification keeps from hardware
//! wallets, and a format-0 message with anything outside `0x20..=0x7e`, which is what
//! format 0 means. What text may be *shown* is the screen's rule, and the firmware's.

/// What every envelope begins with: `0xff` and `solana offchain`.
/// Source: Anza off-chain message signing §Signing domain [C]
pub const SIGNING_DOMAIN: [u8; 16] = *b"\xffsolana offchain";

/// A version-0 request's head: the application domain and the format byte.
pub const V0_HEAD: usize = 32 + 1;

/// The longest version-0 envelope formats 0 and 1 allow, preamble and body together.
/// Source: Anza off-chain message signing §Message format (version 0) [C]
pub const V0_MAX: usize = 1232;

/// Why a message cannot be wrapped.
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub enum Error {
    /// A version-0 request shorter than its head, or with no text after it.
    Short,
    /// A version-0 format this does not sign.
    Format,
    /// A format-0 message with a byte outside `0x20..=0x7e`.
    NotAscii,
    /// Longer than the format allows.
    TooLong,
}

impl Error {
    /// The same, in the words a screen or a refusal has.
    pub const fn why(self) -> &'static str {
        match self {
            Error::Short => "not a Solana off-chain message",
            Error::Format => "that message format is not signed here",
            Error::NotAscii => "format 0 is one line of plain ASCII",
            Error::TooLong => "message too long",
        }
    }
}

/// Which envelope, and what goes in it besides the signer and the text.
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub enum Envelope<'a> {
    V1,
    V0 {
        /// Whatever the application chose to be known by. Shown base58.
        application: &'a [u8; 32],
        /// 0, restricted ASCII; 1, UTF-8.
        format: u8,
    },
}

/// A request's bytes as an envelope and the text to go in it.
///
/// A version-1 request is the text. A version-0 request is `[32 application domain]
/// [u8 format][text]`.
pub fn request(v0: bool, payload: &[u8]) -> Result<(Envelope<'_>, &[u8]), Error> {
    if !v0 {
        if payload.is_empty() {
            return Err(Error::Short);
        }
        return Ok((Envelope::V1, payload));
    }
    let Some((head, text)) = payload.split_at_checked(V0_HEAD) else {
        return Err(Error::Short);
    };
    if text.is_empty() {
        return Err(Error::Short);
    }
    let (application, format) = head.split_at(32);
    let application: &[u8; 32] = application.try_into().map_err(|_| Error::Short)?;
    match format[0] {
        0 if !text.iter().all(|b| (0x20..=0x7e).contains(b)) => return Err(Error::NotAscii),
        0 | 1 => {}
        _ => return Err(Error::Format),
    }
    let envelope = Envelope::V0 {
        application,
        format: format[0],
    };
    if len(&envelope, text.len()) > V0_MAX {
        return Err(Error::TooLong);
    }
    Ok((envelope, text))
}

/// How long the envelope around `text` bytes is.
pub const fn len(envelope: &Envelope<'_>, text: usize) -> usize {
    match envelope {
        Envelope::V1 => 16 + 1 + 1 + 32 + text,
        Envelope::V0 { .. } => 16 + 1 + 32 + 1 + 1 + 32 + 2 + text,
    }
}

/// Write the envelope for `signer` around `text` into `out`: the bytes to be signed.
/// `None` when `out` is shorter than [`len`] says, or the text is longer than a
/// version-0 length can say.
pub fn write(
    envelope: &Envelope<'_>,
    signer: &[u8; 32],
    text: &[u8],
    out: &mut [u8],
) -> Option<usize> {
    let total = len(envelope, text.len());
    let out = out.get_mut(..total)?;
    let mut at = 0;
    let mut put = |b: &[u8]| {
        out[at..at + b.len()].copy_from_slice(b);
        at += b.len();
    };
    put(&SIGNING_DOMAIN);
    match envelope {
        Envelope::V1 => {
            put(&[1, 1]);
            put(signer);
        }
        Envelope::V0 {
            application,
            format,
        } => {
            put(&[0]);
            put(*application);
            put(&[*format, 1]);
            put(signer);
            put(&u16::try_from(text.len()).ok()?.to_le_bytes());
        }
    }
    put(text);
    Some(total)
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use std::vec;
    use std::vec::Vec;

    const SIGNER: [u8; 32] = [0x11; 32];
    const APP: [u8; 32] = [0x22; 32];

    fn wrap(v0: bool, payload: &[u8]) -> Result<Vec<u8>, Error> {
        let (envelope, text) = request(v0, payload)?;
        let mut out = vec![0u8; len(&envelope, text.len())];
        assert_eq!(write(&envelope, &SIGNER, text, &mut out), Some(out.len()));
        Ok(out)
    }

    // Byte for byte against the specification's tables.
    #[test]
    fn version_1_is_the_domain_the_signer_and_the_text() {
        let got = wrap(false, b"hi").unwrap();
        let mut want = b"\xffsolana offchain".to_vec();
        want.extend_from_slice(&[1, 1]);
        want.extend_from_slice(&SIGNER);
        want.extend_from_slice(b"hi");
        assert_eq!(got, want);
        assert_eq!(got.len(), 0x12 + 32 + 2);
    }

    #[test]
    fn version_0_carries_the_application_the_format_and_a_length() {
        let mut payload = APP.to_vec();
        payload.push(0);
        payload.extend_from_slice(b"hello");
        let got = wrap(true, &payload).unwrap();
        let mut want = b"\xffsolana offchain".to_vec();
        want.push(0);
        want.extend_from_slice(&APP);
        want.extend_from_slice(&[0, 1]);
        want.extend_from_slice(&SIGNER);
        want.extend_from_slice(&[5, 0]);
        want.extend_from_slice(b"hello");
        assert_eq!(got, want);
        // The offsets the specification gives.
        assert_eq!(got[0x10], 0);
        assert_eq!(&got[0x11..0x31], &APP);
        assert_eq!(got[0x31], 0);
        assert_eq!(got[0x32], 1);
        assert_eq!(&got[0x33..0x53], &SIGNER);
    }

    #[test]
    fn no_envelope_is_a_transaction() {
        // 0xff: not a signature count a transaction could have, not a version prefix.
        assert_eq!(SIGNING_DOMAIN[0], 0xff);
        let got = wrap(false, b"hi").unwrap();
        assert!(crate::parse(&got).is_err());
        assert!(crate::parse_message(&got).is_err());
    }

    #[test]
    fn what_a_format_does_not_allow_is_refused() {
        let v0 = |format: u8, text: &[u8]| {
            let mut p = APP.to_vec();
            p.push(format);
            p.extend_from_slice(text);
            wrap(true, &p).err()
        };
        assert_eq!(v0(0, b"plain"), None);
        assert_eq!(v0(0, b"two\nlines"), Some(Error::NotAscii));
        assert_eq!(v0(0, "caf\u{e9}".as_bytes()), Some(Error::NotAscii));
        assert_eq!(v0(1, b"two\nlines"), None);
        assert_eq!(v0(2, b"plain"), Some(Error::Format));
        assert_eq!(v0(0, b""), Some(Error::Short));
        assert_eq!(wrap(true, &APP).err(), Some(Error::Short));
        assert_eq!(wrap(false, b"").err(), Some(Error::Short));
        // 1232 bytes, preamble and all.
        let most = V0_MAX
            - len(
                &Envelope::V0 {
                    application: &APP,
                    format: 0,
                },
                0,
            );
        assert_eq!(v0(0, &vec![b'x'; most]), None);
        assert_eq!(v0(0, &vec![b'x'; most + 1]), Some(Error::TooLong));
    }

    #[test]
    fn the_envelope_needs_its_room() {
        let (envelope, text) = request(false, b"hi").unwrap();
        let mut out = [0u8; 51];
        assert_eq!(write(&envelope, &SIGNER, text, &mut out), None);
    }

    #[test]
    fn a_signature_over_the_envelope_verifies() {
        use outscript::crypto::ed25519;
        let seed = [7u8; 32];
        let public = ed25519::public_from_seed(&seed);
        let (envelope, text) = request(false, b"Sign in to example.com").unwrap();
        let mut out = vec![0u8; len(&envelope, text.len())];
        write(&envelope, &public, text, &mut out).unwrap();
        let sig = ed25519::sign(&seed, &out);
        assert!(ed25519::verify(&public, &out, &sig));
        // And not over the bare text: the envelope is what was signed.
        assert!(!ed25519::verify(&public, text, &sig));
    }
}
