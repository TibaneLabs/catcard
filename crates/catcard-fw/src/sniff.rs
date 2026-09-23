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
    /// An EVM transaction, with the chain it names.
    #[cfg(feature = "multichain")]
    EvmTx { chain_id: Option<u64> },
    /// A Solana transaction: the bytes themselves, or written down as base64.
    ///
    /// `base64` is the character range of that base64 within the payload, for the one
    /// that arrived written down -- a broadcast link, or what a wallet's "copy
    /// transaction" gives. `None` means the payload is the transaction.
    #[cfg(feature = "multichain")]
    SolanaTx { base64: Option<(usize, usize)> },
    /// Something a person can read.
    Text,
    /// Bytes that are none of the above.
    Unknown,
}

/// One thing that can be done with what arrived.
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub(crate) enum Act {
    /// What this firmware understands it to be: install it, sign it, read it.
    Use,
    /// Keep the bytes, whatever they are: a folder and a name, on the card.
    Save,
}

/// What a screen offers for some content: the rows, and what each one means.
pub(crate) type Choices = heapless::Vec<(&'static str, Act), 2>;

impl Content {
    /// The few words a screen has for it.
    pub(crate) fn note(self) -> &'static str {
        match self {
            #[cfg(feature = "multichain")]
            Content::EvmTx { .. } => "an EVM transaction",
            #[cfg(feature = "multichain")]
            Content::SolanaTx { .. } => "a Solana transaction",
            Content::Firmware => "a firmware image",
            Content::Psbt => "a transaction",
            Content::Seed(_) => "a seed backup",
            Content::Text => "text",
            Content::Unknown => "data this device cannot read",
        }
    }

    /// Everything worth doing with it, in the order a screen should offer them.
    ///
    /// **Whatever arrived can be kept.** A code or a tag often carries something its
    /// owner wants on the card whether or not this firmware understands it, so `Save`
    /// is offered for every kind but one -- and where nothing else can be done with the
    /// bytes, it is the only row rather than a dead end.
    ///
    /// The exception is a seed. It is never written to removable media, and it is not
    /// chosen from a list either: the payload is copied out and the memory it arrived
    /// through is wiped before any screen goes up, so the caller answers that one before
    /// asking anything (see `Content::is_seed`).
    pub(crate) fn choices(self) -> Choices {
        let mut out = Choices::new();
        let primary = match self {
            #[cfg(feature = "multichain")]
            Content::EvmTx { .. } => Some("Sign it"),
            #[cfg(feature = "multichain")]
            Content::SolanaTx { .. } => Some("Sign it"),
            Content::Firmware => Some("Install it"),
            Content::Psbt => Some("Sign it"),
            Content::Text => Some("Show it"),
            Content::Seed(_) | Content::Unknown => None,
        };
        if let Some(p) = primary {
            let _ = out.push((p, Act::Use));
        }
        if !self.is_seed() {
            let _ = out.push(("Save to card", Act::Save));
        }
        out
    }

    /// Whether this is a whole wallet, which every path handles before it asks anything.
    pub(crate) fn is_seed(self) -> bool {
        matches!(self, Content::Seed(_))
    }

    /// The extension a saved copy takes, from what the bytes turned out to be -- so the
    /// file opens as what it is on the computer that reads the card next.
    pub(crate) fn extension(self) -> &'static str {
        match self {
            #[cfg(feature = "multichain")]
            Content::EvmTx { .. } => "tx",
            #[cfg(feature = "multichain")]
            Content::SolanaTx { .. } => "tx",
            Content::Firmware => "bin",
            Content::Psbt => "psbt",
            Content::Text => "txt",
            Content::Seed(_) | Content::Unknown => "dat",
        }
    }
}

/// Whether `bytes` are a Solana transaction, whole and entire.
///
/// There is no magic number, so what makes these bytes one is that all of them read as
/// one: every length fits, every account index names a key the message carries, and
/// nothing is left over at the end. The two extra conditions are against the empty
/// shapes that technically parse -- a message with no instructions does nothing, and one
/// requiring no signature is not something to offer to sign.
#[cfg(feature = "multichain")]
fn is_solana(bytes: &[u8]) -> bool {
    // A transaction, or the message inside one. **Both arrive in the wild**: a wallet
    // asking for a signature often sends the message alone, because the signature slots
    // are its own to fill in afterwards -- that is what `sol-sign-request` carries, and
    // some senders wrap the same bytes in `ur:bytes` instead.
    //
    // The transaction reading is tried first and is the stricter one: it requires the
    // signature slots to match the header, which is what stops a message being read as a
    // transaction whose header is somewhere in the middle of its account list.
    let read = catcard_solana::parse(bytes).or_else(|_| catcard_solana::parse_message(bytes));
    read.map(|tx| tx.instruction_count() > 0 && tx.signing().required > 0)
        .unwrap_or(false)
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
    // A Solana transaction. As with the EVM case there is no magic number, so what
    // makes these bytes one is that the whole of them read as one: every length fits,
    // every account index names a key the message carries, and nothing is left over at
    // the end. That last part is what keeps this from claiming anything that merely
    // starts like a transaction.
    //
    // Tried before the EVM case because it is the stricter test: an EVM transaction is
    // RLP, and RLP is a shape a great many things fall into.
    #[cfg(feature = "multichain")]
    if is_solana(bytes) {
        return Content::SolanaTx { base64: None };
    }
    // An EVM transaction: RLP, or an EIP-2718 envelope. Tried before the text case
    // because a transaction is bytes and a failed parse costs one pass over them.
    //
    // The check is the parse itself -- nothing about RLP is a magic number, so what
    // makes these bytes a transaction is that every field reads as one and nothing is
    // left over. A chain id is required as well: a transaction naming no chain is
    // valid, but it is also what random bytes look like when they happen to parse.
    #[cfg(feature = "multichain")]
    if let Ok(tx) = catcard_evm::parse(bytes)
        && tx.chain_id.is_some()
    {
        return Content::EvmTx {
            chain_id: tx.chain_id,
        };
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
    // A Solana transaction written down: a broadcast link, or the base64 on its own.
    //
    // This one has to be *decoded* before it can be claimed, because base64 of a
    // transaction has no prefix the way base64 of a PSBT does -- `cHNidP` is the PSBT
    // magic showing through, and Solana has no magic. So the text is decoded into a
    // borrowed block and parsed, and a claim is made only if the whole of it reads as a
    // transaction. The work is bounded by the network's own packet size: anything longer
    // than 1232 bytes is not a transaction anybody could send, and is not decoded.
    //
    // Before the SeedQR and text cases, because base64 is text and a transaction shown
    // as gibberish is a transaction nobody can sign.
    #[cfg(feature = "multichain")]
    if let Some(text) = text
        && let Some(body) = catcard_solana::link::body_of(text)
        && let Some(mut block) = crate::heap::take(catcard_solana::link::PACKET_MAX)
        && let Ok(n) = outscript::base64::decode_to_slice(body, block.bytes())
        && is_solana(&block.bytes()[..n])
    {
        let at = body.as_ptr() as usize - bytes.as_ptr() as usize;
        return Content::SolanaTx {
            base64: Some((at, body.len())),
        };
    }
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

/// What a UR turned out to hold, and where inside the message it starts.
///
/// Q1 only, with [`from_ur`]: the scanner is the one path that learns a UR type, and
/// the NFC tag on an mk4 or mk5 holds NDEF records, which say what they are their own
/// way. A guess is all [`sniff`] has there, and all it needs.
///
/// A registry item is CBOR: a `crypto-psbt` message is the transaction wrapped in a
/// byte string, so the bytes that arrive begin `58 a7 70 73 62 74 ff ...` and not
/// `psbt\xff`. [C] BCR-2020-006 §"Partially Signed Bitcoin Transaction (PSBT)". The
/// header is a few bytes at the front, so nothing has to be moved: `skip` says where
/// the payload begins and `len` how much of it there is.
#[cfg(feature = "board-q1")]
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub(crate) struct Arrival {
    pub what: Content,
    /// Bytes of CBOR header in front of the payload.
    pub skip: usize,
    /// The payload's length, after the header.
    pub len: usize,
}

/// What arrived, when the code said what it was.
///
/// A UR carries its type, and a type beats a guess: a transaction labelled
/// `crypto-psbt` is a transaction even if it will not parse, and saying so gets the
/// owner "not a PSBT" from the signer rather than "data this device cannot read" from
/// a screen that never tried.
///
/// `None` when there is nothing better to say than [`sniff`] would say -- no type, a
/// type this does not unwrap, a message that is not the item its type claims, or a
/// payload that could only be used from the front of the staging area.
#[cfg(feature = "board-q1")]
pub(crate) fn from_ur(
    message: &[u8],
    kind: Option<catcard_bcur::registry::Kind>,
) -> Option<Arrival> {
    use catcard_bcur::registry::{Kind, bytestring};

    let kind = kind?;
    let body = match kind {
        // The two items that are one CBOR byte string. Everything else in the registry
        // is a map this has no screen for; it is saved as it arrived.
        Kind::Psbt | Kind::Bytes => bytestring::decode(message).ok()?,
        _ => return None,
    };
    let what = match kind {
        Kind::Psbt => Content::Psbt,
        // `bytes` says nothing about what is inside, so the guess still runs -- but
        // over the payload, with the CBOR header off the front, which is the whole
        // difference between a PSBT and unrecognised data.
        _ => sniff(body),
    };
    // **Refused by what cannot be done, not by what can.**
    //
    // The one restriction is real: a payload inside a UR does not begin at the staging
    // area's base, and an image is installed from the base -- so an image wrapped in a
    // UR is saved and installed from the card instead. Which costs nothing anyone will
    // notice: an image is 700 kB, and nobody sends that as three thousand QR codes.
    //
    // This used to be written the other way round, as a list of what was allowed:
    // `Psbt | Text`. That list was correct when those were the only two things this
    // device could read, and it silently stopped being correct every time another was
    // added -- an EVM transaction, then a Solana one -- because a payload that failed it
    // fell back to sniffing the CBOR wrapper, which is not a transaction. The device
    // then said "data this device cannot read" about a transaction it could read
    // perfectly well, three lines further down. Written this way, a new kind of content
    // works by default and only a genuine restriction has to be stated.
    if matches!(what, Content::Firmware) {
        return None;
    }
    Some(Arrival {
        what,
        skip: message.len() - body.len(),
        len: body.len(),
    })
}

/// Write scanned bytes to the card: a folder the owner picks, under a name they type.
///
/// The name is theirs because the device has nothing better to call it -- a code carries
/// no filename -- and the folder is theirs because a card that already holds someone's
/// files should not gain ours at its root without being asked. What the device supplies
/// is the extension, from what the bytes turned out to be, so the file opens as what it
/// is on the computer that reads the card next.
pub(crate) fn save_to_card(ui: &mut crate::ui::Ui<'_>, bytes: &[u8], what: Content) {
    const HEAD: &str = "Save to card";
    let ext = what.extension();

    let Some(folder) =
        crate::menu::browse_sd(ui, "Where to save", None, crate::menu::Browse::Folder)
    else {
        return;
    };
    let Some(typed) = crate::passphrase::read(ui, "File name") else {
        return;
    };
    let Some(name) = catcard_sd::name::from_typed(typed.as_str(), ext) else {
        crate::menu::message(
            ui.panel,
            HEAD,
            "that name has no",
            "characters a card takes",
        );
        crate::menu::wait_for_any_key(ui);
        return;
    };
    let mut path: heapless::String<{ crate::menu::BROWSE_PATH_MAX }> = heapless::String::new();
    let _ = path.push_str(folder.as_str());
    if !path.ends_with('/') {
        let _ = path.push('/');
    }
    if path.push_str(&name).is_err() {
        crate::menu::message(ui.panel, HEAD, "that path is too long", "");
        crate::menu::wait_for_any_key(ui);
        return;
    }

    crate::menu::card_wait(ui.panel, HEAD, "writing to the card");
    match crate::menu::write_card_file(&path, bytes) {
        Ok(()) => {
            crate::catlog!("qr: {} bytes saved as {}", bytes.len(), path.as_str());
            crate::menu::message(ui.panel, "Saved", &name, "on the card");
        }
        Err(why) => {
            crate::catlog!("qr: save failed: {}", why);
            crate::menu::message(ui.panel, HEAD, why, "nothing was written");
        }
    }
    crate::menu::wait_for_any_key(ui);
}
