//! The armoured file a signed message travels in, and checking one.
//!
//! ```text
//! -----BEGIN BITCOIN SIGNED MESSAGE-----
//! the message
//! -----BEGIN SIGNATURE-----
//! bc1q...the address that signed
//! base64 of the signature
//! -----END BITCOIN SIGNED MESSAGE-----
//! ```
//!
//! The format is a convention rather than a standard -- it is what Electrum, Sparrow, and
//! the wallets that read a signed-message file write -- so this reads it generously and
//! writes it in one fixed shape. Generously means: either line ending, whitespace around
//! the fields, and a signature broken across lines, because a file that made a round trip
//! through a mail client is still the file someone was sent.
//!
//! # What "verified" means here
//!
//! Nothing in the file is taken as a claim about itself. The address is decoded to the
//! script it stands for, and the signature has to be one that satisfies *that* script over
//! *that* message. A legacy signature is put through key recovery and the recovered key is
//! re-encoded as an address, which then has to be the address written in the file; a
//! BIP-322 one is checked against the script the address decodes to. In neither case does
//! this trust a byte in the file to say which key signed.
//!
//! Two schemes are read, because both exist in the wild:
//!
//! - [`Scheme::Legacy`] -- the 65-byte recoverable signature of [`crate::message`], which
//!   is what every wallet has written since 2011.
//! - [`Scheme::Bip322Simple`] -- a BIP-322 *simple* signature ([`crate::bip322`]), with or
//!   without its `smp` prefix.
//!
//! They tell themselves apart by length: a legacy signature is exactly 65 bytes, and no
//! witness stack this reads can be.

use crate::address::{self, AddressKind};
use crate::bip32::Network;
use crate::{bip322, message};

/// The opening line.
pub const BEGIN: &str = "-----BEGIN BITCOIN SIGNED MESSAGE-----";
/// The line between the message and the signature block.
pub const SEPARATOR: &str = "-----BEGIN SIGNATURE-----";
/// The closing line.
pub const END: &str = "-----END BITCOIN SIGNED MESSAGE-----";

/// Most signature text read out of a file, before its whitespace is dropped: base64 of a
/// P2WPKH witness stack is 148 characters, and a file may have wrapped it.
pub const MAX_SIG_TEXT: usize = 256;

/// Longest address this reads.
pub const MAX_ADDRESS: usize = address::MAX_ADDRESS_LEN;

/// Which scheme a file's signature turned out to be.
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub enum Scheme {
    /// The 65-byte recoverable signature over the "Bitcoin Signed Message" digest.
    Legacy,
    /// BIP-322, *simple* variant.
    Bip322Simple,
}

impl Scheme {
    /// What to call it on a screen.
    pub const fn name(self) -> &'static str {
        match self {
            Scheme::Legacy => "legacy",
            Scheme::Bip322Simple => "BIP-322",
        }
    }
}

#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub enum Error {
    /// The file is not an armoured signed message: a marker line is missing or out of
    /// order.
    NotArmoured,
    /// A field is missing, empty, or longer than this can hold.
    Malformed,
    /// The signature is a variant or an address type this does not check. Said as itself
    /// rather than as "invalid": "I cannot check this" and "this is forged" are different
    /// answers and a screen must not merge them.
    Unsupported,
    /// The address is not one this can decode.
    BadAddress,
    /// Well formed, and not a signature this address made over this message.
    Invalid,
}

/// The three fields of an armoured file, borrowed out of it.
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub struct Armoured<'a> {
    /// The message, exactly as it sits between the markers.
    pub message: &'a str,
    /// The address the file says signed.
    pub address: &'a str,
    /// The signature text, which may still carry line breaks.
    pub signature: &'a str,
}

/// Write the armoured form.
///
/// Both the message screen and the card flow write through this, so the file this device
/// produces is the file its own verifier was written against.
pub fn write(
    out: &mut impl core::fmt::Write,
    message: &str,
    address: &str,
    signature: &str,
) -> core::fmt::Result {
    write!(
        out,
        "{BEGIN}\n{message}\n{SEPARATOR}\n{address}\n{signature}\n{END}\n"
    )
}

/// Strip one line ending from the front of `s`, if there is one.
fn skip_newline(s: &str) -> Option<&str> {
    let s = s.strip_prefix('\r').unwrap_or(s);
    s.strip_prefix('\n')
}

/// Pull the three fields out of an armoured file.
///
/// Anything before the opening marker is ignored -- a file may carry a note above it --
/// and so is anything after the closing one.
pub fn parse(text: &str) -> Result<Armoured<'_>, Error> {
    let start = text.find(BEGIN).ok_or(Error::NotArmoured)?;
    let after = &text[start + BEGIN.len()..];
    let after = skip_newline(after).ok_or(Error::NotArmoured)?;

    let sep = after.find(SEPARATOR).ok_or(Error::NotArmoured)?;
    // The newline before the separator belongs to the format, not to the message.
    let message = after[..sep]
        .strip_suffix('\n')
        .map(|m| m.strip_suffix('\r').unwrap_or(m))
        .ok_or(Error::NotArmoured)?;

    let rest = &after[sep + SEPARATOR.len()..];
    let rest = skip_newline(rest).ok_or(Error::NotArmoured)?;
    let end = rest.find(END).ok_or(Error::NotArmoured)?;
    let block = &rest[..end];

    // First line of the block is the address; everything else up to the closing marker is
    // the signature, however it was wrapped.
    let (address, signature) = block.split_once('\n').ok_or(Error::Malformed)?;
    let address = address.trim();
    let signature = signature.trim();
    if address.is_empty() || signature.is_empty() || address.len() > MAX_ADDRESS {
        return Err(Error::Malformed);
    }
    Ok(Armoured {
        message,
        address,
        signature,
    })
}

/// The signature text with every space and line break taken out.
fn compact(signature: &str, out: &mut [u8; MAX_SIG_TEXT]) -> Result<usize, Error> {
    let mut n = 0;
    for b in signature.bytes() {
        if b.is_ascii_whitespace() {
            continue;
        }
        *out.get_mut(n).ok_or(Error::Malformed)? = b;
        n += 1;
    }
    if n == 0 {
        return Err(Error::Malformed);
    }
    Ok(n)
}

/// Is this file's signature really this file's address, over this file's message?
///
/// The only `Ok` is a signature that checked out, and it says which scheme it was.
///
/// The address is read first, before a byte of the signature is decoded. What an address
/// stands for decides what could possibly satisfy it, so a file for a script this has no
/// interpreter for -- a P2WSH multisig -- is answered as "cannot check" whatever its
/// signature looks like, rather than as a signature that failed to parse.
pub fn verify(file: &Armoured<'_>) -> Result<Scheme, Error> {
    let kind = address_kind(file.address)?;

    // A prefix names the variant outright; `smp` is the one implemented, and the other two
    // are refused as themselves.
    let head = file.signature.trim_start();
    if matches!(head.get(..3), Some("ful") | Some("pof")) {
        return Err(Error::Unsupported);
    }
    let bip322_prefixed = head.get(..bip322::PREFIX.len()) == Some(bip322::PREFIX);
    if bip322_prefixed && !matches!(kind, AddressKind::P2wpkh | AddressKind::P2tr) {
        return Err(Error::Unsupported);
    }

    let mut text = [0u8; MAX_SIG_TEXT];
    let n = compact(file.signature, &mut text)?;
    let text = core::str::from_utf8(&text[..n]).map_err(|_| Error::Malformed)?;
    if bip322_prefixed {
        return bip322_verify(file, kind, text).map(|()| Scheme::Bip322Simple);
    }

    // No prefix: 65 bytes is a legacy signature, and a witness stack never is.
    let mut raw = [0u8; 192];
    let len = outscript::base64::decode_to_slice(text, &mut raw).map_err(|_| Error::Malformed)?;
    if len == message::SIG_LEN {
        let mut sig = [0u8; message::SIG_LEN];
        sig.copy_from_slice(&raw[..len]);
        legacy_verify(file, &sig).map(|()| Scheme::Legacy)
    } else {
        bip322_verify(file, kind, text).map(|()| Scheme::Bip322Simple)
    }
}

/// Check a legacy signature by recovering the key and re-deriving the address.
///
/// The header byte says which address type the signer used; that is a claim, and the way
/// it is checked is by building that address from the recovered key and comparing it with
/// the one in the file. A header that lies produces an address that does not match.
fn legacy_verify(file: &Armoured<'_>, sig: &[u8; message::SIG_LEN]) -> Result<(), Error> {
    let (pubkey, kind) = message::recover(file.message, sig).map_err(|e| match e {
        message::Error::UnsupportedKind => Error::Unsupported,
        message::Error::NotPrintable | message::Error::TooLong { .. } => Error::Malformed,
        _ => Error::Invalid,
    })?;
    // Both networks: the same key signs the same message either way, and which network an
    // address was written for is the address's business, not the signature's.
    for network in [Network::Mainnet, Network::Testnet] {
        let mut buf = [0u8; address::MAX_ADDRESS_LEN];
        let Ok(n) = address::encode(kind, network, &pubkey, &mut buf) else {
            continue;
        };
        let Ok(built) = core::str::from_utf8(&buf[..n]) else {
            continue;
        };
        if same_address(built, file.address, kind) {
            return Ok(());
        }
    }
    Err(Error::Invalid)
}

/// Are these the same address?
///
/// Bech32 is defined case-insensitively and is written either way; Base58Check is not, and
/// comparing it loosely would accept a string that is not a valid address at all.
fn same_address(built: &str, given: &str, kind: AddressKind) -> bool {
    if kind.is_bech32() {
        built.eq_ignore_ascii_case(given)
    } else {
        built == given
    }
}

/// Check a BIP-322 simple signature against the script the address stands for.
fn bip322_verify(file: &Armoured<'_>, kind: AddressKind, text: &str) -> Result<(), Error> {
    if !matches!(kind, AddressKind::P2wpkh | AddressKind::P2tr) {
        return Err(Error::Unsupported);
    }
    let script = challenge_of(file.address)?;
    bip322::verify_armoured(file.message.as_bytes(), script.as_slice(), text).map_err(|e| match e {
        bip322::Error::UnsupportedKind | bip322::Error::UnsupportedScript => Error::Unsupported,
        bip322::Error::Invalid => Error::Invalid,
        _ => Error::Malformed,
    })
}

/// A scriptPubKey, inline.
pub struct Script {
    buf: [u8; bip322::MAX_SCRIPT],
    len: usize,
}

impl Script {
    pub fn as_slice(&self) -> &[u8] {
        &self.buf[..self.len]
    }
}

/// Which of the four address types this is, from the address itself.
///
/// Bitcoin only, mainnet or testnet. The decoder this calls reads several chains' address
/// formats, and accepting one of those here would mean checking a signature against a
/// script whose address this device would never show. A P2WSH address is decoded and then
/// refused: there is no script interpreter here, so there is nothing honest to say about
/// one beyond "not this".
pub fn address_kind(address: &str) -> Result<AddressKind, Error> {
    let decoded = decode(address)?;
    match decoded.format {
        "p2pkh" => Ok(AddressKind::P2pkh),
        "p2sh" => Ok(AddressKind::P2shP2wpkh),
        "p2wpkh" => Ok(AddressKind::P2wpkh),
        "p2tr" => Ok(AddressKind::P2tr),
        _ => Err(Error::Unsupported),
    }
}

/// The scriptPubKey an address stands for: BIP-322's `message_challenge`.
pub fn challenge_of(address: &str) -> Result<Script, Error> {
    let decoded = decode(address)?;
    let script = decoded.script.as_ref();
    let len = script.len();
    let mut buf = [0u8; bip322::MAX_SCRIPT];
    if len > buf.len() {
        return Err(Error::Unsupported);
    }
    buf[..len].copy_from_slice(script);
    Ok(Script { buf, len })
}

fn decode(address: &str) -> Result<outscript::address::DecodedAddress, Error> {
    for network in ["bitcoin", "bitcoin-testnet"] {
        if let Ok(decoded) = outscript::address::decode_bitcoin_based_address(network, address) {
            return Ok(decoded);
        }
    }
    Err(Error::BadAddress)
}

#[cfg(test)]
mod tests;
