//! BIP-21 payment URIs: `bitcoin:<address>[?amount=..&label=..&message=..]`.
//!
//! The one format a phone's camera and a wallet's "send" screen both understand. An
//! address alone says where; the URI says where, how much and what for, so the payer's
//! wallet fills its form in and the person paying checks it rather than typing it.
//!
//! Both directions live here. **Writing** puts an amount and a label on an address this
//! device is showing; **parsing** reads a URI that arrived by camera or by tag, so the
//! address in it can be checked against this wallet's own.
//!
//! Source for everything below: BIP-21 (bitcoin/bips, `bip-0021.mediawiki`) [C].
//!
//! - `bitcoin:` is case-insensitive; everything after it -- the address and the parameter
//!   *keys* -- is case-sensitive. (A bech32 address is case-insensitive by its own rule,
//!   BIP-173, which is the address's business and not the URI's.)
//! - `amount` is decimal BTC, a period as the separator, no thousands separators.
//! - `label` and `message` are UTF-8, percent-encoded as RFC 3986 says.
//! - A parameter whose key begins `req-` is **required**: a reader that does not implement
//!   it "MUST consider the entire URI invalid". Unknown parameters without the prefix are
//!   ignored.
//!
//! Stock adds a `wallet=` parameter of its own (hw-reference/firmware-features.md §1
//! [C] names it, and says nothing about what it carries). It is kept and shown as the
//! opaque text it is; see `docs/HARDWARE-OPEN-ITEMS.md`.

use core::fmt::{self, Write as _};

/// The scheme, as the standard writes it. Matched without regard to case.
pub const SCHEME: &str = "bitcoin:";

/// Satoshis in one bitcoin.
pub const SATS_PER_BTC: u64 = 100_000_000;

/// The most an `amount` can ask for: twenty-one million bitcoin, to the satoshi. Anything
/// above it is not a payment anybody can make, so it is refused rather than displayed.
pub const MAX_SATS: u64 = 21_000_000 * SATS_PER_BTC;

/// Longest amount this writes: `21000000.12345678`.
pub const AMOUNT_MAX: usize = 17;

/// Characters a label typed on the device may have. Short on purpose: the label rides
/// in a QR beside the address, and every character of it costs up to three bytes once
/// it is percent-encoded.
pub const LABEL_MAX: usize = 24;

/// Longest URI this writes: the scheme, the longest address, the longest amount and a
/// label of [`LABEL_MAX`] characters each encoded as three bytes.
pub const MAX_URI: usize = SCHEME.len()
    + super::MAX_ADDRESS_LEN
    + "?amount=".len()
    + AMOUNT_MAX
    + "&label=".len()
    + 3 * LABEL_MAX;

/// A parsed URI. Text fields are borrowed from the input and are **still percent-encoded**:
/// decode them with [`decode`] into a buffer whose size the caller chose.
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub struct Uri<'a> {
    /// The address, exactly as written (not validated here beyond its character set).
    pub address: &'a str,
    /// The amount in satoshis, if one was given.
    pub amount: Option<u64>,
    /// `label=`, percent-encoded.
    pub label: Option<&'a str>,
    /// `message=`, percent-encoded.
    pub message: Option<&'a str>,
    /// Stock's `wallet=` extension, percent-encoded and otherwise opaque `[?]`.
    pub wallet: Option<&'a str>,
}

/// Why a URI was refused. The variant is the screen's whole explanation, so each one
/// names what a person can act on.
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub enum Error<'a> {
    /// Not `bitcoin:` anything.
    NotAUri,
    /// The scheme with nothing, or something that is not an address, after it.
    BadAddress,
    /// `amount=` is not decimal BTC, or has more than eight decimals.
    BadAmount,
    /// `amount=` is more bitcoin than exist.
    AmountTooLarge,
    /// A `req-` parameter this does not implement, by name. BIP-21 says the whole URI is
    /// invalid then, and the name is what tells the person which wallet feature was
    /// asked for.
    UnknownRequired(&'a str),
    /// Percent-encoding that does not decode, or does not decode to UTF-8.
    BadEncoding,
    /// The decoded text does not fit the buffer offered for it.
    TooLong,
}

impl Error<'_> {
    /// A few words for a screen. The required parameter's name is not in here -- it is
    /// in the variant, for the caller to print beside these.
    pub fn describe(self) -> &'static str {
        match self {
            Error::NotAUri => "not a bitcoin: URI",
            Error::BadAddress => "no address in it",
            Error::BadAmount => "amount is not decimal BTC",
            Error::AmountTooLarge => "amount exceeds 21M BTC",
            Error::UnknownRequired(_) => "needs a parameter this cannot honour",
            Error::BadEncoding => "text is not encoded properly",
            Error::TooLong => "text too long",
        }
    }
}

/// Whether `text` begins with the scheme, in any case.
pub fn is_uri(text: &str) -> bool {
    text.get(..SCHEME.len())
        .is_some_and(|head| head.eq_ignore_ascii_case(SCHEME))
}

/// The address alone: the scheme off the front, in any case, and the parameters off the
/// back. `None` when it is not a URI, or when what is left is not the shape of an address.
///
/// For the paths that only ever wanted the address -- the verify screen's scanner -- and
/// must keep working on a URI whose parameters it does not otherwise read.
pub fn address_of(text: &str) -> Option<&str> {
    if !is_uri(text) {
        return None;
    }
    let rest = &text[SCHEME.len()..];
    let address = rest.split('?').next().unwrap_or("");
    plausible_address(address).then_some(address)
}

/// The character set of an address: base58 and bech32 are both alphanumeric ASCII, and
/// nothing that is not can be one. A length check too, since a hundred characters of
/// letters is not an address either.
fn plausible_address(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= super::MAX_ADDRESS_LEN
        && s.bytes().all(|b| b.is_ascii_alphanumeric())
}

/// Read a URI. The scheme in any case; the rest as the standard says.
///
/// Parameters are read in order and the first of a repeated key wins. A `req-` key this
/// does not know refuses the whole URI, by name; any other unknown key is skipped, as
/// the standard allows. Empty segments (`?&amount=1`, a trailing `&`) are skipped too.
pub fn parse(text: &str) -> Result<Uri<'_>, Error<'_>> {
    if !is_uri(text) {
        return Err(Error::NotAUri);
    }
    let rest = &text[SCHEME.len()..];
    let (address, query) = match rest.split_once('?') {
        Some((a, q)) => (a, q),
        None => (rest, ""),
    };
    if !plausible_address(address) {
        return Err(Error::BadAddress);
    }
    let mut uri = Uri {
        address,
        amount: None,
        label: None,
        message: None,
        wallet: None,
    };
    for param in query.split('&') {
        if param.is_empty() {
            continue;
        }
        let (key, value) = match param.split_once('=') {
            Some((k, v)) => (k, v),
            None => (param, ""),
        };
        match key {
            "amount" => {
                if uri.amount.is_none() {
                    uri.amount = Some(parse_amount(value)?);
                }
            }
            "label" => uri.label = uri.label.or(Some(value)),
            "message" => uri.message = uri.message.or(Some(value)),
            "wallet" => uri.wallet = uri.wallet.or(Some(value)),
            // Required, and not one of the above: the standard is explicit that the URI
            // is then invalid as a whole. The name goes back so the person can see what
            // was wanted -- `req-payjoin`, say -- rather than a bare refusal.
            k if k.starts_with("req-") => return Err(Error::UnknownRequired(k)),
            _ => {}
        }
    }
    Ok(uri)
}

/// Decimal BTC to satoshis. `50`, `20.3`, `0.00000001`, `.5`, `5.`; not `1,000`, not
/// nine decimals, not more than [`MAX_SATS`], not the empty string.
///
/// No floating point anywhere: the value is read digit by digit into a u64, and a
/// fraction is padded to eight places, so `20.3` is exactly 2 030 000 000 and nothing
/// is rounded on the way.
pub fn parse_amount(text: &str) -> Result<u64, Error<'static>> {
    let (whole, frac) = match text.split_once('.') {
        Some((w, f)) => (w, f),
        None => (text, ""),
    };
    if whole.is_empty() && frac.is_empty() {
        return Err(Error::BadAmount);
    }
    if frac.len() > 8
        || !whole.bytes().all(|b| b.is_ascii_digit())
        || !frac.bytes().all(|b| b.is_ascii_digit())
    {
        return Err(Error::BadAmount);
    }
    let mut btc: u64 = 0;
    for b in whole.bytes() {
        btc = btc
            .checked_mul(10)
            .and_then(|v| v.checked_add(u64::from(b - b'0')))
            .ok_or(Error::AmountTooLarge)?;
    }
    let mut sats_frac: u64 = 0;
    for b in frac.bytes() {
        sats_frac = sats_frac * 10 + u64::from(b - b'0');
    }
    for _ in frac.len()..8 {
        sats_frac *= 10;
    }
    let sats = btc
        .checked_mul(SATS_PER_BTC)
        .and_then(|v| v.checked_add(sats_frac))
        .ok_or(Error::AmountTooLarge)?;
    if sats > MAX_SATS {
        return Err(Error::AmountTooLarge);
    }
    Ok(sats)
}

/// Satoshis as decimal BTC, the way `amount=` wants it: no trailing zeros, no point
/// where there is nothing after it. `0` for nothing, `1` for a whole coin, `0.00000001`
/// for one satoshi.
pub fn write_amount(sats: u64, out: &mut impl fmt::Write) -> fmt::Result {
    let whole = sats / SATS_PER_BTC;
    let mut frac = sats % SATS_PER_BTC;
    if frac == 0 {
        return write!(out, "{whole}");
    }
    let mut places = 8;
    while frac % 10 == 0 {
        frac /= 10;
        places -= 1;
    }
    write!(out, "{whole}.{frac:0places$}")
}

/// `text` percent-encoded for a query value, as a `Display`.
///
/// RFC 3986 unreserved characters pass; every other byte of the UTF-8 goes as `%XX`. That
/// is stricter than a query strictly needs -- `!` and `*` could pass -- and that is the
/// point: a reader that decodes fewer characters than it should still gets this right.
pub struct Encoded<'a>(pub &'a str);

impl fmt::Display for Encoded<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for b in self.0.bytes() {
            match b {
                b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'.' | b'_' | b'~' => {
                    f.write_char(b as char)?;
                }
                _ => write!(f, "%{b:02X}")?,
            }
        }
        Ok(())
    }
}

/// Write a URI: the address, then whichever of the three parameters were given.
///
/// The address goes in as it is written. A bech32 address may be upper-cased by the
/// caller first (BIP-173 allows either case) -- but with parameters after it, the URI
/// has lower-case keys in it and is in QR byte mode whatever the address's case, so
/// there is nothing to gain and the caller usually leaves it alone.
pub fn write(
    out: &mut impl fmt::Write,
    address: &str,
    amount: Option<u64>,
    label: Option<&str>,
    message: Option<&str>,
) -> fmt::Result {
    out.write_str(SCHEME)?;
    out.write_str(address)?;
    // `?` before the first parameter, `&` before the rest.
    let mut sep = '?';
    if let Some(sats) = amount {
        out.write_char(sep)?;
        sep = '&';
        out.write_str("amount=")?;
        write_amount(sats, out)?;
    }
    if let Some(label) = label.filter(|l| !l.is_empty()) {
        out.write_char(sep)?;
        sep = '&';
        write!(out, "label={}", Encoded(label))?;
    }
    if let Some(message) = message.filter(|m| !m.is_empty()) {
        out.write_char(sep)?;
        write!(out, "message={}", Encoded(message))?;
    }
    Ok(())
}

/// Percent-decode `encoded` into `out`, as text.
///
/// `%XX` becomes the byte; anything else is copied. The result must be UTF-8. Control
/// characters (below space, and DEL) come out as spaces: a label is shown on a screen
/// beside an amount, and a newline in it would let the label write a second line that
/// looks like the device's own.
pub fn decode<'a>(encoded: &str, out: &'a mut [u8]) -> Result<&'a str, Error<'static>> {
    let mut n = 0usize;
    let mut bytes = encoded.bytes();
    while let Some(b) = bytes.next() {
        let byte = if b == b'%' {
            let hi = bytes.next().and_then(hex).ok_or(Error::BadEncoding)?;
            let lo = bytes.next().and_then(hex).ok_or(Error::BadEncoding)?;
            (hi << 4) | lo
        } else {
            b
        };
        let byte = if byte < 0x20 || byte == 0x7f {
            b' '
        } else {
            byte
        };
        *out.get_mut(n).ok_or(Error::TooLong)? = byte;
        n += 1;
    }
    core::str::from_utf8(&out[..n]).map_err(|_| Error::BadEncoding)
}

fn hex(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::string::String;

    const ADDR: &str = "175tWpb8K1S7NmH4Zx6rewF9WQrcZv245W";

    fn uri(amount: Option<u64>, label: Option<&str>, message: Option<&str>) -> String {
        let mut s = String::new();
        write(&mut s, ADDR, amount, label, message).unwrap();
        s
    }

    fn amount(sats: u64) -> String {
        let mut s = String::new();
        write_amount(sats, &mut s).unwrap();
        s
    }

    fn decoded(s: &str) -> String {
        let mut buf = [0u8; 256];
        decode(s, &mut buf).unwrap().into()
    }

    // --- the BIP's own examples, written and read ----------------------------------

    #[test]
    fn the_bips_examples_are_written_byte_for_byte() {
        assert_eq!(
            uri(None, None, None),
            "bitcoin:175tWpb8K1S7NmH4Zx6rewF9WQrcZv245W"
        );
        assert_eq!(
            uri(None, Some("Luke-Jr"), None),
            "bitcoin:175tWpb8K1S7NmH4Zx6rewF9WQrcZv245W?label=Luke-Jr"
        );
        assert_eq!(
            uri(Some(2_030_000_000), Some("Luke-Jr"), None),
            "bitcoin:175tWpb8K1S7NmH4Zx6rewF9WQrcZv245W?amount=20.3&label=Luke-Jr"
        );
        assert_eq!(
            uri(
                Some(50 * SATS_PER_BTC),
                Some("Luke-Jr"),
                Some("Donation for project xyz")
            ),
            "bitcoin:175tWpb8K1S7NmH4Zx6rewF9WQrcZv245W?amount=50&label=Luke-Jr&message=Donation%20for%20project%20xyz"
        );
    }

    #[test]
    fn the_bips_examples_are_read_back() {
        let u = parse("bitcoin:175tWpb8K1S7NmH4Zx6rewF9WQrcZv245W").unwrap();
        assert_eq!(u.address, ADDR);
        assert_eq!((u.amount, u.label, u.message), (None, None, None));

        let u = parse("bitcoin:175tWpb8K1S7NmH4Zx6rewF9WQrcZv245W?label=Luke-Jr").unwrap();
        assert_eq!(u.label, Some("Luke-Jr"));

        let u =
            parse("bitcoin:175tWpb8K1S7NmH4Zx6rewF9WQrcZv245W?amount=20.3&label=Luke-Jr").unwrap();
        assert_eq!(u.amount, Some(2_030_000_000));
        assert_eq!(u.label, Some("Luke-Jr"));

        let u = parse("bitcoin:175tWpb8K1S7NmH4Zx6rewF9WQrcZv245W?amount=50&label=Luke-Jr&message=Donation%20for%20project%20xyz").unwrap();
        assert_eq!(u.amount, Some(5_000_000_000));
        assert_eq!(decoded(u.message.unwrap()), "Donation for project xyz");
    }

    #[test]
    fn a_required_parameter_this_does_not_know_refuses_the_whole_uri_by_name() {
        // The BIP's own example of a URI a client must reject.
        let got = parse(
            "bitcoin:175tWpb8K1S7NmH4Zx6rewF9WQrcZv245W?req-somethingyoudontunderstand=50&req-somethingelseyoudontget=999",
        );
        assert_eq!(
            got,
            Err(Error::UnknownRequired("req-somethingyoudontunderstand"))
        );
        // The same thing after the fields this does read still refuses it: the
        // standard says the entire URI is invalid, not the parameter.
        let got = parse("bitcoin:175tWpb8K1S7NmH4Zx6rewF9WQrcZv245W?amount=1&req-payjoin=x");
        assert_eq!(got, Err(Error::UnknownRequired("req-payjoin")));
    }

    #[test]
    fn unknown_optional_parameters_are_ignored() {
        // The BIP's other example: the same keys without the prefix are fine.
        let u = parse("bitcoin:175tWpb8K1S7NmH4Zx6rewF9WQrcZv245W?somethingyoudontunderstand=50&somethingelseyoudontget=999").unwrap();
        assert_eq!(u.address, ADDR);
        assert_eq!(u.amount, None);
    }

    // --- scheme and address ---------------------------------------------------------

    #[test]
    fn the_scheme_is_case_insensitive_and_nothing_else_is() {
        for s in ["BITCOIN:", "Bitcoin:", "bitcoin:"] {
            let mut text = String::from(s);
            text.push_str(ADDR);
            text.push_str("?amount=1");
            assert_eq!(parse(&text).unwrap().amount, Some(SATS_PER_BTC));
            assert_eq!(address_of(&text), Some(ADDR));
        }
        // An upper-cased key is some other parameter, and not a required one.
        let mut text = String::from("bitcoin:");
        text.push_str(ADDR);
        text.push_str("?AMOUNT=1");
        assert_eq!(parse(&text).unwrap().amount, None);
    }

    #[test]
    fn an_upper_cased_bech32_address_survives_as_written() {
        // The QR alphanumeric form: the address is case-insensitive by BIP-173, and this
        // hands it on untouched for the address code to fold.
        let u = parse("BITCOIN:BC1QW508D6QEJXTDG4Y5R3ZARVARY0C5XW7KV8F3T4").unwrap();
        assert_eq!(u.address, "BC1QW508D6QEJXTDG4Y5R3ZARVARY0C5XW7KV8F3T4");
    }

    #[test]
    fn what_is_not_a_uri_says_so() {
        assert_eq!(parse(ADDR), Err(Error::NotAUri));
        assert_eq!(parse("lightning:lnbc1..."), Err(Error::NotAUri));
        assert_eq!(parse(""), Err(Error::NotAUri));
        assert_eq!(address_of(ADDR), None);
        assert!(!is_uri("bitcoin"));
    }

    #[test]
    fn a_uri_with_no_address_or_a_broken_one_is_refused() {
        assert_eq!(parse("bitcoin:"), Err(Error::BadAddress));
        assert_eq!(parse("bitcoin:?amount=1"), Err(Error::BadAddress));
        assert_eq!(parse("bitcoin:1abc def"), Err(Error::BadAddress));
        assert_eq!(parse("bitcoin:bc1q-not-an-address"), Err(Error::BadAddress));
        let mut long = String::from("bitcoin:");
        for _ in 0..(super::super::MAX_ADDRESS_LEN + 1) {
            long.push('q');
        }
        assert_eq!(parse(&long), Err(Error::BadAddress));
        assert_eq!(address_of("bitcoin:?amount=1"), None);
    }

    #[test]
    fn address_of_cuts_the_parameters_off() {
        assert_eq!(
            address_of("bitcoin:175tWpb8K1S7NmH4Zx6rewF9WQrcZv245W?amount=50&label=x"),
            Some(ADDR)
        );
    }

    // --- amounts --------------------------------------------------------------------

    #[test]
    fn amounts_are_written_without_trailing_zeros() {
        assert_eq!(amount(0), "0");
        assert_eq!(amount(1), "0.00000001");
        assert_eq!(amount(10), "0.0000001");
        assert_eq!(amount(SATS_PER_BTC), "1");
        assert_eq!(amount(150_000_000), "1.5");
        assert_eq!(amount(2_030_000_000), "20.3");
        assert_eq!(amount(12_345_678), "0.12345678");
        assert_eq!(amount(MAX_SATS), "21000000");
        assert_eq!(amount(MAX_SATS - 1), "20999999.99999999");
        assert!(amount(MAX_SATS - 1).len() <= AMOUNT_MAX);
    }

    #[test]
    fn every_amount_round_trips() {
        for sats in [
            0,
            1,
            9,
            10,
            99_999_999,
            SATS_PER_BTC,
            SATS_PER_BTC + 1,
            123_456_789_012,
            MAX_SATS - 1,
            MAX_SATS,
        ] {
            assert_eq!(parse_amount(&amount(sats)), Ok(sats), "{sats}");
        }
    }

    #[test]
    fn amounts_are_read_exactly_with_no_floating_point() {
        assert_eq!(parse_amount("50"), Ok(5_000_000_000));
        assert_eq!(parse_amount("50.00"), Ok(5_000_000_000));
        assert_eq!(parse_amount("20.3"), Ok(2_030_000_000));
        assert_eq!(parse_amount("0.1"), Ok(10_000_000));
        assert_eq!(parse_amount("0.00000001"), Ok(1));
        assert_eq!(parse_amount(".5"), Ok(50_000_000));
        assert_eq!(parse_amount("5."), Ok(500_000_000));
        assert_eq!(parse_amount("0"), Ok(0));
        assert_eq!(parse_amount("21000000"), Ok(MAX_SATS));
        assert_eq!(parse_amount("21000000.00000000"), Ok(MAX_SATS));
    }

    #[test]
    fn more_than_eight_decimals_is_refused_even_when_they_are_zeros() {
        assert_eq!(parse_amount("0.000000001"), Err(Error::BadAmount));
        assert_eq!(parse_amount("1.000000000"), Err(Error::BadAmount));
    }

    #[test]
    fn malformed_amounts_are_refused() {
        for bad in [
            "", ".", "1,000", "1e5", "-1", "+1", " 1", "1 ", "0x10", "1.2.3", "abc",
        ] {
            assert_eq!(parse_amount(bad), Err(Error::BadAmount), "{bad:?}");
        }
    }

    #[test]
    fn more_bitcoin_than_exists_is_refused() {
        assert_eq!(
            parse_amount("21000000.00000001"),
            Err(Error::AmountTooLarge)
        );
        assert_eq!(parse_amount("21000001"), Err(Error::AmountTooLarge));
        assert_eq!(
            parse_amount("99999999999999999999999"),
            Err(Error::AmountTooLarge)
        );
        assert_eq!(
            parse_amount("184467440737.09551616"),
            Err(Error::AmountTooLarge)
        );
        let mut text = String::from("bitcoin:");
        text.push_str(ADDR);
        text.push_str("?amount=21000001");
        assert_eq!(parse(&text), Err(Error::AmountTooLarge));
    }

    #[test]
    fn a_bad_amount_refuses_the_uri() {
        let mut text = String::from("bitcoin:");
        text.push_str(ADDR);
        text.push_str("?amount=1,5");
        assert_eq!(parse(&text), Err(Error::BadAmount));
    }

    // --- labels and messages ---------------------------------------------------------

    #[test]
    fn labels_with_spaces_and_unicode_are_percent_encoded_and_decoded() {
        let label = "Café ☕ tip jar";
        let text = uri(Some(100_000), Some(label), None);
        assert_eq!(
            text,
            "bitcoin:175tWpb8K1S7NmH4Zx6rewF9WQrcZv245W?amount=0.001&label=Caf%C3%A9%20%E2%98%95%20tip%20jar"
        );
        let u = parse(&text).unwrap();
        assert_eq!(decoded(u.label.unwrap()), label);
    }

    #[test]
    fn reserved_characters_in_a_label_cannot_break_the_query() {
        // `&`, `=`, `?`, `#` and `%` each have a meaning in a URI; a label holding them
        // must come back as itself and must not spawn parameters.
        let label = "a&b=c?d#e%f+g";
        let text = uri(None, Some(label), Some("x"));
        let u = parse(&text).unwrap();
        assert_eq!(decoded(u.label.unwrap()), label);
        assert_eq!(u.message, Some("x"));
        assert!(!text.contains("&b="));
    }

    #[test]
    fn empty_label_and_message_are_left_out() {
        assert_eq!(
            uri(None, Some(""), Some("")),
            "bitcoin:175tWpb8K1S7NmH4Zx6rewF9WQrcZv245W"
        );
        assert_eq!(
            uri(Some(0), Some(""), None),
            "bitcoin:175tWpb8K1S7NmH4Zx6rewF9WQrcZv245W?amount=0"
        );
    }

    #[test]
    fn the_first_of_a_repeated_key_wins() {
        let u = parse(
            "bitcoin:175tWpb8K1S7NmH4Zx6rewF9WQrcZv245W?label=one&label=two&amount=1&amount=2",
        )
        .unwrap();
        assert_eq!(u.label, Some("one"));
        assert_eq!(u.amount, Some(SATS_PER_BTC));
    }

    #[test]
    fn empty_segments_and_valueless_keys_are_tolerated() {
        let u = parse("bitcoin:175tWpb8K1S7NmH4Zx6rewF9WQrcZv245W?&amount=1&&label&").unwrap();
        assert_eq!(u.amount, Some(SATS_PER_BTC));
        assert_eq!(u.label, Some(""));
    }

    #[test]
    fn the_wallet_extension_is_kept_opaque() {
        let u = parse("bitcoin:175tWpb8K1S7NmH4Zx6rewF9WQrcZv245W?wallet=whatever%20this%20is")
            .unwrap();
        assert_eq!(u.wallet, Some("whatever%20this%20is"));
        assert_eq!(decoded(u.wallet.unwrap()), "whatever this is");
    }

    #[test]
    fn decoding_refuses_what_is_not_encoded_properly() {
        let mut buf = [0u8; 16];
        assert_eq!(decode("%2", &mut buf), Err(Error::BadEncoding));
        assert_eq!(decode("%zz", &mut buf), Err(Error::BadEncoding));
        assert_eq!(decode("%FF", &mut buf), Err(Error::BadEncoding));
        assert_eq!(decode("%C3", &mut buf), Err(Error::BadEncoding));
        assert_eq!(decode("seventeen chars!!", &mut buf), Err(Error::TooLong));
        assert_eq!(decode("sixteen chars!!!", &mut buf), Ok("sixteen chars!!!"));
    }

    #[test]
    fn control_characters_cannot_write_a_second_line() {
        assert_eq!(decoded("one%0Atwo%09three%7F"), "one two three ");
    }

    #[test]
    fn a_plus_is_a_plus() {
        // RFC 3986 has no `+`-for-space rule; that is HTML forms. A label written that
        // way by some wallet shows its plus signs, which is the honest reading.
        assert_eq!(decoded("a+b"), "a+b");
    }

    #[test]
    fn the_longest_uri_this_writes_fits_its_bound() {
        let mut addr = String::new();
        for _ in 0..super::super::MAX_ADDRESS_LEN {
            addr.push('q');
        }
        let mut label = String::new();
        for _ in 0..LABEL_MAX {
            label.push(' ');
        }
        let mut s = String::new();
        write(&mut s, &addr, Some(MAX_SATS - 1), Some(&label), None).unwrap();
        assert_eq!(s.len(), MAX_URI);
    }
}
