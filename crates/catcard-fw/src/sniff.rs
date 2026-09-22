//! What arrived, when the device did not ask for anything in particular.
//!
//! Two paths take bytes without being told first what they are: the Q1's scanner, which
//! reads whatever code is pointed at it, and the NFC tag, which holds whatever a phone
//! wrote to it. Both then have to say what they are holding and offer the one thing worth
//! doing with it, and both had better answer the same way -- a PSBT that signs when it
//! arrives by camera and reads as "data this cannot use" when it arrives by tap is a bug
//! nobody would find until they needed it.
//!
//! So the guess lives here, once, and the two screens share it.

/// What the bytes look like.
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub(crate) enum Content {
    /// A signed CatCard image: the header magic is where a header would be.
    Firmware,
    /// A PSBT, binary or base64.
    Psbt,
    /// A SeedQR: a whole wallet, in one of its two shapes.
    Seed(catcard_wallet::seedqr::Kind),
    /// Something a person can read.
    Text,
    /// Bytes that are none of the above.
    Unknown,
}

impl Content {
    /// The few words a screen has for it, and what it offers to do.
    ///
    /// An empty action list is "nothing can be done with this", which the caller shows as
    /// a message rather than as a question.
    pub(crate) fn offer(self) -> (&'static str, &'static [&'static str]) {
        match self {
            Content::Firmware => ("a firmware image", &["Install it"]),
            Content::Psbt => ("a transaction", &["Sign it"]),
            // No action here on purpose. A seed is loaded only where the payload can be
            // copied out and the memory it arrived through wiped before any screen goes
            // up, which the scanner does for itself; a tag that holds one is named and
            // left alone.
            Content::Seed(_) => ("a seed backup", &[]),
            Content::Text => ("text", &["Show it"]),
            Content::Unknown => ("data this cannot use", &[]),
        }
    }
}

/// Decide what arrived.
///
/// Cheap checks in the order that a false positive matters least. The firmware magic is
/// four bytes at a fixed offset inside a quarter-megabyte image, so nothing short can
/// claim to be one; the PSBT magic is its first five bytes. Only what neither claims is
/// offered as text.
pub(crate) fn sniff(bytes: &[u8]) -> Content {
    const PSBT_MAGIC: &[u8] = b"psbt\xff";
    if bytes.starts_with(PSBT_MAGIC) {
        return Content::Psbt;
    }
    let at = catcard_fwhdr::HEADER_OFFSET;
    if bytes.len() > at + 4
        && u32::from_le_bytes([bytes[at], bytes[at + 1], bytes[at + 2], bytes[at + 3]])
            == catcard_fwhdr::MAGIC
    {
        return Content::Firmware;
    }
    // Base64 of a PSBT, as a `.psbt` written as text is. Checked before the general text
    // case so it is offered for signing rather than shown as gibberish.
    if bytes.starts_with(b"cHNidP") {
        return Content::Psbt;
    }
    // A SeedQR, in either shape. Before the text case, because a Standard one *is* text
    // -- 48 to 96 digits -- and showing a seed on the glass as "here is what you
    // scanned" is not what someone holding their backup up to the camera asked for.
    //
    // The two shapes are sniffed differently on purpose. Standard is claimed on its own
    // terms: nothing else this device reads is exactly that many characters of nothing
    // but digits. Compact is 16 to 32 arbitrary bytes and has no shape at all, so it is
    // claimed only where the alternative reading was `Unknown` -- a payload of that
    // length that is valid text stays text, and a Compact code whose entropy happens to
    // be printable is a case this loses to a rule that keeps every text scan working.
    let text = core::str::from_utf8(bytes).ok();
    match catcard_wallet::seedqr::kind_of(bytes) {
        Some(kind @ catcard_wallet::seedqr::Kind::Standard) => return Content::Seed(kind),
        Some(kind @ catcard_wallet::seedqr::Kind::Compact) if text.is_none() => {
            return Content::Seed(kind);
        }
        _ => {}
    }
    match text {
        Some(_) => Content::Text,
        None => Content::Unknown,
    }
}
