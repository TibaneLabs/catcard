//! A transaction written down as a link, which is how one travels without a cable.
//!
//! A Solana transaction is bytes, and the two ways this device exchanges bytes with a
//! phone -- a QR on the glass, a tag under it -- both carry text well and raw bytes
//! badly. The convention on both sides is a URL with the transaction base64'd in its
//! fragment:
//!
//! ```text
//! https://www.tibane.net/tools/studio#tx:AQAAAAAA...
//! ```
//!
//! The fragment matters: what follows `#` is never sent to the server. A phone that taps
//! this device opens a page, and the transaction stays in the phone -- the page reads it
//! out of the address bar and offers to broadcast it. A transaction in the *query*
//! would be handed to whoever hosts the page before anybody had decided to send it.
//!
//! This module is only the writing-down. [`crate::parse`] is what decides whether the
//! bytes underneath are a transaction, and nothing here shortcuts that.

/// Where a tapped phone goes, after `https://www.`.
///
/// Split at that point because an NDEF URI record abbreviates the common prefixes to one
/// byte, and this is the half that goes in the record.
pub const HOST_AND_PATH: &str = "tibane.net/tools/studio";

/// What separates the page from the transaction.
///
/// `#` rather than `?` on purpose -- see the note above -- and `tx:` so the fragment says
/// what it holds rather than being an unlabelled blob.
pub const MARKER: &str = "#tx:";

/// The most a Solana transaction can be, in bytes.
///
/// A transaction is submitted in one UDP packet and the network's packet is 1232 bytes,
/// so anything larger is not a transaction anybody could send. Used here as the bound on
/// how much base64 is worth decoding: without it, "is this text a transaction?" would be
/// a question with no upper limit on the work of answering it.
pub const PACKET_MAX: usize = 1232;

/// The characters of base64 the largest transaction becomes.
pub const BODY_MAX: usize = PACKET_MAX.div_ceil(3) * 4;

/// The base64 inside `text`, if `text` is a transaction written down.
///
/// Two shapes, because two kinds of sender:
///
/// - a **link**, which is what this device writes and what the page above understands.
///   Everything after [`MARKER`] is the body, so the host and path can change without
///   this having to know.
/// - **bare base64**, which is what a wallet's "copy transaction" gives. Accepted
///   because it is what people have in hand, and safe to accept because the answer is
///   still decided by whether the bytes parse.
///
/// What comes back is only *shaped* like a transaction: base64, in whole groups, short
/// enough to be one. Standard base64, not the URL-safe alphabet -- `+` and `/` are legal
/// in a fragment, so there is nothing to escape and a sender that escaped anyway would
/// be writing a different encoding than the page reads.
pub fn body_of(text: &str) -> Option<&str> {
    let body = match text.find(MARKER) {
        Some(at) => &text[at + MARKER.len()..],
        // A link this device does not recognise the front of is not a transaction: a URL
        // with base64 after some *other* marker is somebody else's format, and reading
        // the tail of it would be a guess.
        None if text.contains("://") => return None,
        None => text,
    };
    let body = body.trim();
    if body.is_empty() || !body.len().is_multiple_of(4) || body.len() > BODY_MAX {
        return None;
    }
    let bytes = body.as_bytes();
    let pad = bytes.iter().rev().take_while(|&&c| c == b'=').count();
    if pad > 2 {
        return None;
    }
    for &c in &bytes[..bytes.len() - pad] {
        if !matches!(c, b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'+' | b'/') {
            return None;
        }
    }
    Some(body)
}

/// How long the link for a transaction of `raw_len` bytes is, after `https://www.`.
///
/// For a caller sizing a tag image before it builds one.
pub const fn link_len(raw_len: usize) -> usize {
    HOST_AND_PATH.len() + MARKER.len() + raw_len.div_ceil(3) * 4
}

/// Write the link for `raw` into `out`, from the host onwards, and say how long it is.
///
/// From the host rather than from `https://`, because that is where an NDEF URI record
/// starts: the scheme is one byte of the record, and this is the rest of it. A caller
/// showing the link to a person puts `https://www.` back in front.
///
/// `out` must be at least [`link_len`] bytes; anything shorter gives `None` rather than
/// a truncated link, since half a transaction in a URL is one that fails on the phone.
/// So does a `raw` longer than [`PACKET_MAX`], which is not a transaction anybody could
/// send.
pub fn write_link(raw: &[u8], out: &mut [u8]) -> Option<usize> {
    let need = link_len(raw.len());
    if out.len() < need || raw.len() > PACKET_MAX {
        return None;
    }
    let mut at = 0;
    for part in [HOST_AND_PATH.as_bytes(), MARKER.as_bytes()] {
        out[at..at + part.len()].copy_from_slice(part);
        at += part.len();
    }
    outscript::base64::encode_to_slice(raw, &mut out[at..need]).ok()?;
    Some(need)
}

#[cfg(test)]
mod tests {
    extern crate alloc;

    use super::*;

    /// One transaction, written all three ways it can arrive.
    ///
    /// The bytes are a legacy transfer with its signature slot still empty; what matters
    /// here is only that the same body comes back out of each shape.
    const BODY: &str = "AQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABAAECKMWB+7ajqiaSkc8RgBoARL9iARrcqWkUpPC8Sws2Cd4AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAMFgaJ7stVvyq0AHbRVJLqWsaETSp7LP6draEz+ENr/7AQECAAAMAgAAAADKmjsAAAAA";

    #[test]
    fn a_link_and_the_base64_inside_it_are_the_same_transaction() {
        let mut link = alloc::string::String::from("https://www.");
        link.push_str(HOST_AND_PATH);
        link.push_str(MARKER);
        link.push_str(BODY);
        assert_eq!(body_of(&link), Some(BODY));
        // The NDEF form, with `https://www.` abbreviated away by the record.
        assert_eq!(body_of(&link["https://www.".len()..]), Some(BODY));
        assert_eq!(body_of(BODY), Some(BODY));
        // Trailing whitespace is what a file or a text record brings with it.
        let mut spaced = alloc::string::String::from(BODY);
        spaced.push_str("\r\n");
        assert_eq!(body_of(&spaced), Some(BODY));
    }

    #[test]
    fn what_is_not_a_transaction_written_down() {
        // Ordinary text, and text that is base64 of the wrong shape.
        assert_eq!(body_of("hello"), None);
        assert_eq!(body_of("AQAB!"), None);
        assert_eq!(body_of(""), None);
        // Somebody else's link. The tail is base64 and it is still not ours: only the
        // marker says the fragment is a transaction.
        assert_eq!(body_of("https://example.com/x#other:AQAB"), None);
        // Longer than a transaction can be, so not worth decoding to find out.
        let huge = alloc::string::String::from_iter(core::iter::repeat_n('A', BODY_MAX + 4));
        assert_eq!(body_of(&huge), None);
    }

    /// The body of a link is a transaction, not merely base64.
    ///
    /// What `body_of` returns has only been checked for shape, so this is the other half:
    /// the bytes underneath go through the parser like any others, and what comes out is
    /// the transfer they describe -- one lamport-carrying instruction, no signature on it
    /// yet.
    #[test]
    fn the_body_of_a_link_parses_as_a_transaction() {
        let mut raw = [0u8; PACKET_MAX];
        let n = outscript::base64::decode_to_slice(BODY, &mut raw).expect("base64");
        let tx = crate::parse(&raw[..n]).expect("a transaction");
        assert_eq!(tx.signing().required, 1);
        assert_eq!(tx.signing().present, 0);
        assert_eq!(tx.instruction_count(), 1);
        assert!(matches!(
            tx.action(0),
            Some(crate::Action::TransferSol {
                lamports: 1_000_000_000,
                ..
            })
        ));
    }

    /// The link this device writes is the link the page reads.
    ///
    /// Written out in full and compared against the exact URL the tool hands people, so
    /// that a change to the host, the marker or the encoding has to be a change to this
    /// test as well.
    #[test]
    fn the_link_written_is_the_link_expected() {
        const URL: &str = "https://www.tibane.net/tools/studio#tx:AQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABAAECKMWB+7ajqiaSkc8RgBoARL9iARrcqWkUpPC8Sws2Cd4AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAMFgaJ7stVvyq0AHbRVJLqWsaETSp7LP6draEz+ENr/7AQECAAAMAgAAAADKmjsAAAAA";

        let mut raw = [0u8; PACKET_MAX];
        let n = outscript::base64::decode_to_slice(BODY, &mut raw).expect("base64");
        let mut out = [0u8; 2048];
        let written = write_link(&raw[..n], &mut out).expect("room");
        let link = core::str::from_utf8(&out[..written]).expect("ascii");
        assert_eq!(link, &URL["https://www.".len()..]);
        // And what was written reads back as what went in.
        assert_eq!(body_of(link), Some(BODY));
    }

    /// A buffer a byte short is refused, not filled with as much as fits.
    #[test]
    fn a_link_that_would_not_fit_is_not_written() {
        let raw = [7u8; 60];
        let mut out = [0u8; 2048];
        let need = link_len(raw.len());
        assert!(write_link(&raw, &mut out[..need - 1]).is_none());
        assert!(write_link(&raw, &mut out[..need]).is_some());
    }

    #[test]
    fn a_link_is_as_long_as_it_says_it_will_be() {
        let raw = 183;
        assert_eq!(
            link_len(raw),
            HOST_AND_PATH.len() + MARKER.len() + BODY.len()
        );
        assert_eq!(BODY.len(), raw.div_ceil(3) * 4);
    }
}
