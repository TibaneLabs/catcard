//! The file-name conventions for signing PSBTs off a card.
//!
//! Batch signing walks a card, signs every transaction it finds, and writes a result for
//! each. So it needs two things that are pure string logic and nothing to do with the SD
//! driver: which of the files on a card is a transaction *to sign* (as opposed to one this
//! signing already produced), and what each one's signed and finalised results are called.
//!
//! Kept here, out of the firmware, so both can be checked against their edge cases -- a name
//! that is all extension, a name with no extension, a result file offered back as a source,
//! a name too long for the buffer -- without a card in the loop.

/// The suffix a signed PSBT is written with, before the `.psbt` extension: `NAME-signed.psbt`.
const SIGNED_SUFFIX: &str = "-signed";
/// The suffix a finalised (broadcast-ready) transaction is written with: `NAME-final.txn`.
const FINAL_SUFFIX: &str = "-final";

/// The stem of a `.psbt` file name -- the part before the extension -- if it is one and the
/// stem is not empty.
///
/// The extension match is case-insensitive (`TX.PSBT` counts); a name that is only an
/// extension (`.psbt`) has no stem and is not a transaction to act on.
fn psbt_stem(name: &str) -> Option<&str> {
    let (stem, ext) = name.trim().rsplit_once('.')?;
    if stem.is_empty() || !ext.eq_ignore_ascii_case("psbt") {
        return None;
    }
    Some(stem)
}

/// Whether a card file is a transaction a batch should sign.
///
/// A `.psbt` with a non-empty stem, except the ones a signing writes itself -- a stem ending
/// `-signed`, or the single-file `SIGNED.PSB` result -- so running a batch twice does not
/// feed it its own output and sign it again.
pub fn is_batch_source(name: &str) -> bool {
    let Some(stem) = psbt_stem(name) else {
        // `SIGNED.PSB` is not `.psbt`, so `psbt_stem` already rejects it; named here so the
        // intent is on the page rather than a coincidence of extensions.
        return false;
    };
    if stem
        .len()
        .checked_sub(SIGNED_SUFFIX.len())
        .is_some_and(|at| {
            stem.is_char_boundary(at) && stem[at..].eq_ignore_ascii_case(SIGNED_SUFFIX)
        })
    {
        return false;
    }
    !name.trim().eq_ignore_ascii_case("SIGNED.PSB")
}

/// Write a source file's result name -- `/NAME-signed.psbt` or `/NAME-final.txn` -- into
/// `out`, returning its length. The leading `/` is the card's root, where these are written.
///
/// `None` when `name` is not a `.psbt`, or when the result does not fit `out`: a truncated
/// name would write the signed transaction to the wrong file, so it is refused rather than
/// shortened.
fn result_name(name: &str, suffix: &str, ext: &str, out: &mut [u8]) -> Option<usize> {
    let stem = psbt_stem(name)?;
    let mut at = 0usize;
    let mut put = |bytes: &[u8]| -> Option<()> {
        out.get_mut(at..at + bytes.len())?.copy_from_slice(bytes);
        at += bytes.len();
        Some(())
    };
    put(b"/")?;
    put(stem.as_bytes())?;
    put(suffix.as_bytes())?;
    put(b".")?;
    put(ext.as_bytes())?;
    Some(at)
}

/// The name a source file's signed PSBT is written under: `/NAME-signed.psbt`.
pub fn signed_name(name: &str, out: &mut [u8]) -> Option<usize> {
    result_name(name, SIGNED_SUFFIX, "psbt", out)
}

/// The name a source file's finalised transaction is written under: `/NAME-final.txn`.
pub fn final_name(name: &str, out: &mut [u8]) -> Option<usize> {
    result_name(name, FINAL_SUFFIX, "txn", out)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn name(f: impl FnOnce(&str, &mut [u8]) -> Option<usize>, src: &str) -> Option<String> {
        let mut out = [0u8; 256];
        let n = f(src, &mut out)?;
        Some(core::str::from_utf8(&out[..n]).unwrap().to_string())
    }

    #[test]
    fn a_transaction_to_sign_is_recognised() {
        assert!(is_batch_source("tx.psbt"));
        assert!(is_batch_source("a long name with spaces.psbt"));
        // Case does not matter for the extension.
        assert!(is_batch_source("TX.PSBT"));
    }

    #[test]
    fn a_result_file_is_not_a_source() {
        // What this signing writes must not be picked up as input on a second pass.
        assert!(!is_batch_source("tx-signed.psbt"));
        assert!(!is_batch_source("TX-SIGNED.PSBT"));
        assert!(!is_batch_source("SIGNED.PSB"));
        // And nothing that is not a psbt at all.
        assert!(!is_batch_source("tx.txn"));
        assert!(!is_batch_source("readme.txt"));
        assert!(!is_batch_source(".psbt"));
        assert!(!is_batch_source("nodot"));
    }

    #[test]
    fn result_names_follow_the_source() {
        assert_eq!(
            name(signed_name, "tx.psbt").as_deref(),
            Some("/tx-signed.psbt")
        );
        assert_eq!(
            name(final_name, "tx.psbt").as_deref(),
            Some("/tx-final.txn")
        );
        // The stem is kept verbatim, extension case included in the stem's own bytes.
        assert_eq!(
            name(signed_name, "Spend-2024.PSBT").as_deref(),
            Some("/Spend-2024-signed.psbt")
        );
        // Not a psbt: no result name.
        assert_eq!(name(signed_name, "tx.bin"), None);
    }

    #[test]
    fn a_name_too_long_for_the_buffer_is_refused_not_truncated() {
        let src = "aaaaaaaaaaaaaaaaaaaa.psbt";
        let mut out = [0u8; 8]; // far too small
        assert_eq!(signed_name(src, &mut out), None);
    }

    /// The signed output of one source is never itself a source, so a batch cannot loop.
    #[test]
    fn a_signed_output_is_never_a_source() {
        let out = name(signed_name, "tx.psbt").unwrap();
        // Drop the leading '/', as an enumeration of the card would list it.
        let listed = out.trim_start_matches('/');
        assert!(!is_batch_source(listed), "{listed} would be re-signed");
    }
}
