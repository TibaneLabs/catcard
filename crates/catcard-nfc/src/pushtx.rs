//! The PushTx link: a signed transaction as a URL a phone can open to broadcast it.
//!
//! The device has no network. What it can do is put a link on the NFC tag whose
//! **fragment** carries the transaction; a phone that taps the device opens the link, the
//! page reads the transaction out of its own address bar, and the phone's owner sends it.
//! A fragment is never sent to the server by the browser, so the service only sees the
//! transaction once the page there chooses to post it.
//!
//! The format is the public PushTx specification (pushtx.org, "NFC Push TX"), which fixes
//! three query-style parameters after the service URL:
//!
//! ```text
//! <service>t=<base64url tx>&c=<checksum>&n=<network>
//! ```
//!
//! - `t`: the raw transaction, base64url (RFC 4648 §5) **without padding**;
//! - `c`: the **rightmost 8 bytes** of SHA-256 over the raw transaction, base64url;
//! - `n`: `XTN` for testnet, `XRT` for regtest, and **absent** on mainnet.
//!
//! The service URL must end in `?`, `#` or `&`; the two public services end in `#`.
//! The whole URL "might be as large as 8,000 bytes", which is what bounds a transaction
//! here well before the tag does. Source: pushtx.org and the specification it links to
//! [C]; the checksum rule is checked below against the specification's own worked
//! example.

use purecrypto::hash::{Digest as _, Sha256};

/// The service Coldcard runs. Source: PushTx specification, "Default providers" [C]
pub const COLDCARD: &str = "https://coldcard.com/pushtx#";
/// mempool.space's endpoint. Source: same [C]
pub const MEMPOOL: &str = "https://mempool.space/pushtx#";

/// The longest service URL this accepts. The two public ones are under thirty bytes; a
/// self-hosted page with a path is under a hundred. Anything longer is a typo.
pub const SERVICE_MAX: usize = 128;

/// The longest complete URL the specification expects a phone to take.
pub const URL_MAX: usize = 8000;

/// Bytes the checksum keeps: the last eight of the SHA-256.
pub const CHECKSUM_LEN: usize = 8;

/// Which chain the transaction is for, as the `n` parameter spells it.
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub enum Network {
    /// No `n` parameter at all.
    Mainnet,
    /// `n=XTN`.
    Testnet,
    /// `n=XRT`.
    Regtest,
}

impl Network {
    /// The parameter value, or `None` where the specification omits it.
    pub const fn code(self) -> Option<&'static str> {
        match self {
            Network::Mainnet => None,
            Network::Testnet => Some("XTN"),
            Network::Regtest => Some("XRT"),
        }
    }

    /// Bytes `&n=...` adds to the URL.
    const fn tail_len(self) -> usize {
        match self.code() {
            Some(c) => "&n=".len() + c.len(),
            None => 0,
        }
    }
}

/// Why a URL could not be built.
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub enum Error {
    /// The output buffer is too small for it.
    TooLong { needed: usize, room: usize },
    /// The service URL is not one the specification allows (see [`check_service`]).
    BadService(ServiceError),
}

/// What is wrong with a service URL.
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub enum ServiceError {
    /// Not `https://`. A transaction handed to a plain-http page is a transaction handed
    /// to everyone on the path.
    NotHttps,
    /// Does not end in `?`, `#` or `&`, so the parameters cannot be appended.
    BadEnding,
    /// Longer than [`SERVICE_MAX`], or nothing after the scheme.
    BadLength,
    /// A byte outside printable ASCII, or a space, or a `%`/`"`/`<`/`>` that would need
    /// escaping: a URL is typed on a keypad, and one of these is a slip.
    BadChar,
}

/// Whether `url` is a service URL the specification allows: `https://`, something after
/// it, printable ASCII throughout, ending in `?`, `#` or `&`.
pub fn check_service(url: &str) -> Result<(), ServiceError> {
    let Some(rest) = url.strip_prefix("https://") else {
        return Err(ServiceError::NotHttps);
    };
    if url.len() > SERVICE_MAX || rest.len() < 2 {
        return Err(ServiceError::BadLength);
    }
    if !url
        .bytes()
        .all(|b| (0x21..0x7f).contains(&b) && !matches!(b, b'"' | b'<' | b'>' | b'%' | b'\\'))
    {
        return Err(ServiceError::BadChar);
    }
    if !url.ends_with(['?', '#', '&']) {
        return Err(ServiceError::BadEnding);
    }
    Ok(())
}

/// Characters base64url spends on `n` bytes, without padding.
pub const fn base64url_len(n: usize) -> usize {
    n.div_ceil(3) * 4 - (3 - n % 3) % 3
}

/// Write `data` as unpadded base64url into `out`. Returns how many characters, or
/// `None` where `out` is too short.
pub fn base64url(data: &[u8], out: &mut [u8]) -> Option<usize> {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    let need = base64url_len(data.len());
    if out.len() < need {
        return None;
    }
    let mut at = 0;
    for chunk in data.chunks(3) {
        let b0 = chunk[0] as u32;
        let b1 = chunk.get(1).copied().unwrap_or(0) as u32;
        let b2 = chunk.get(2).copied().unwrap_or(0) as u32;
        let n = (b0 << 16) | (b1 << 8) | b2;
        let chars = [
            ALPHABET[(n >> 18) as usize & 63],
            ALPHABET[(n >> 12) as usize & 63],
            ALPHABET[(n >> 6) as usize & 63],
            ALPHABET[n as usize & 63],
        ];
        let keep = chunk.len() + 1;
        out[at..at + keep].copy_from_slice(&chars[..keep]);
        at += keep;
    }
    Some(at)
}

/// The `c` parameter's bytes: the last eight of the transaction's SHA-256.
pub fn checksum(tx: &[u8]) -> [u8; CHECKSUM_LEN] {
    let mut h = Sha256::new();
    h.update(tx);
    let digest = h.finalize();
    let mut out = [0u8; CHECKSUM_LEN];
    out.copy_from_slice(&digest[32 - CHECKSUM_LEN..]);
    out
}

/// Bytes the parameters take for a transaction of `tx_len` bytes on `net`: everything
/// after the service URL.
pub const fn params_len(tx_len: usize, net: Network) -> usize {
    "t=".len() + base64url_len(tx_len) + "&c=".len() + base64url_len(CHECKSUM_LEN) + net.tail_len()
}

/// Bytes the whole URL takes.
pub const fn url_len(service_len: usize, tx_len: usize, net: Network) -> usize {
    service_len + params_len(tx_len, net)
}

/// The most transaction a URL of `room` bytes can carry after a service URL of
/// `service_len` bytes, on `net`.
pub const fn max_tx_len(room: usize, service_len: usize, net: Network) -> usize {
    let fixed = url_len(service_len, 0, net);
    if room < fixed {
        return 0;
    }
    // Three bytes per four characters; the remainder is what a partial group would need.
    let chars = room - fixed;
    (chars / 4) * 3
        + match chars % 4 {
            0 | 1 => 0,
            2 => 1,
            _ => 2,
        }
}

/// Write the parameters alone -- `t=...&c=...[&n=...]` -- into `out`.
///
/// Split from [`write_url`] because the NDEF record abbreviates `https://` to one byte,
/// so the caller writes the service's remainder itself and this writes what follows.
pub fn write_params(tx: &[u8], net: Network, out: &mut [u8]) -> Result<usize, Error> {
    let needed = params_len(tx.len(), net);
    if out.len() < needed {
        return Err(Error::TooLong {
            needed,
            room: out.len(),
        });
    }
    let short = Error::TooLong {
        needed,
        room: out.len(),
    };
    let mut at = put(out, 0, b"t=");
    at += base64url(tx, &mut out[at..]).ok_or(short)?;
    at = put(out, at, b"&c=");
    at += base64url(&checksum(tx), &mut out[at..]).ok_or(short)?;
    if let Some(code) = net.code() {
        at = put(out, at, b"&n=");
        at = put(out, at, code.as_bytes());
    }
    Ok(at)
}

/// Copy `s` into `out` at `at`; the position after it. The caller has sized `out`.
fn put(out: &mut [u8], at: usize, s: &[u8]) -> usize {
    out[at..at + s.len()].copy_from_slice(s);
    at + s.len()
}

/// Write the whole URL -- the service, then the parameters -- into `out`.
pub fn write_url(service: &str, tx: &[u8], net: Network, out: &mut [u8]) -> Result<usize, Error> {
    check_service(service).map_err(Error::BadService)?;
    let needed = url_len(service.len(), tx.len(), net);
    if out.len() < needed {
        return Err(Error::TooLong {
            needed,
            room: out.len(),
        });
    }
    out[..service.len()].copy_from_slice(service.as_bytes());
    let n = write_params(tx, net, &mut out[service.len()..])?;
    Ok(service.len() + n)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The specification's worked example: a 519-byte testnet transaction, as the page
    /// shows it. The base64 and checksum below are quoted from it verbatim.
    const EXAMPLE_HEX: &[&str] = &[
        "020000000387a8adf0de10ba3d20b46eeb619c903947d63cf1602512f9bd7227cd5543e123000000006a47304402207e",
        "33d629acd628a21a877501e0e3063fa9c10cc039b22101fca6bca493cfb42b0220011c5ca232abb62c62728ba2531864",
        "e2342afcc025d75a6d2201c39518e09390012103386e03005436c34abffd0af2e36e0e67c6b5a70c623e9159a47cbf35",
        "19766d09ffffffff0e687d11c56ec38d929d205eabbdb1efbf21460814343d3829c76d2703fc1b2e000000006a473044",
        "0220705058a03912433caf29b6760f027b6357e4549f58c0bb3a6189c42cb7056ff9022011b302f0559743926f7b90da",
        "02a289b2aa23de978af378ae6ffa0e9266e2620e012103b91219f6b74a141b78672b87019f00b031cdf70dc749f1a48c",
        "5b3450ff08d92fffffffff941ba33e781780ba7f84669e846d5ca9bd5277997090acdfdf5039fe930a049d000000006a",
        "473044022020140b554e94184caa6573d36e57b5aced915878d3bc0424b8a33816ae0776a202201934dcc3df3141d706",
        "59e5908557d59bfbd9a2b048398a2f40f41e2b42e0f6df012102cf58f8a8556be3d73e0d30704291e8ab60e51a9426bc",
        "df06d21f4091127199beffffffff028ccff008000000001976a91420903cff2ab36a3d0dce1bd85442019e8e60113188",
        "ac8ccff008000000001976a9144695ef14f295eb845fd39e8dd95496ccfb453af488ac00000000",
    ];
    const EXAMPLE_T: &str = "AgAAAAOHqK3w3hC6PSC0buthnJA5R9Y88WAlEvm9cifNVUPhIwAAAABqRzBEAiB-M9YprNYoohqHdQHg4wY_qcEMwDmyIQH8prykk8-0KwIgARxcojKrtixicouiUxhk4jQq_MAl11ptIgHDlRjgk5ABIQM4bgMAVDbDSr_9CvLjbg5nxrWnDGI-kVmkfL81GXZtCf____8OaH0RxW7DjZKdIF6rvbHvvyFGCBQ0PTgpx20nA_wbLgAAAABqRzBEAiBwUFigORJDPK8ptnYPAntjV-RUn1jAuzphicQstwVv-QIgEbMC8FWXQ5Jve5DaAqKJsqoj3peK83iub_oOkmbiYg4BIQO5Ehn2t0oUG3hnK4cBnwCwMc33DcdJ8aSMWzRQ_wjZL_____-UG6M-eBeAun-EZp6EbVypvVJ3mXCQrN_fUDn-kwoEnQAAAABqRzBEAiAgFAtVTpQYTKplc9NuV7Ws7ZFYeNO8BCS4ozgWrgd2ogIgGTTcw98xQdcGWeWQhVfVm_vZorBIOYovQPQeK0Lg9t8BIQLPWPioVWvj1z4NMHBCkeirYOUalCa83wbSH0CREnGZvv____8CjM_wCAAAAAAZdqkUIJA8_yqzaj0NzhvYVEIBno5gETGIrIzP8AgAAAAAGXapFEaV7xTyleuEX9OejdlUlsz7RTr0iKwAAAAA";
    const EXAMPLE_C: &str = "hre47vyMC78";

    fn example_tx() -> Vec<u8> {
        let hex: String = EXAMPLE_HEX.concat();
        (0..hex.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).unwrap())
            .collect()
    }

    #[test]
    fn the_specifications_example_url_is_reproduced_exactly() {
        let tx = example_tx();
        assert_eq!(tx.len(), 519);
        let mut out = [0u8; 1024];
        let n = write_url(MEMPOOL, &tx, Network::Testnet, &mut out).unwrap();
        let url = core::str::from_utf8(&out[..n]).unwrap();
        let expected = format!("{MEMPOOL}t={EXAMPLE_T}&c={EXAMPLE_C}&n=XTN");
        assert_eq!(url, expected);
        assert_eq!(n, url_len(MEMPOOL.len(), tx.len(), Network::Testnet));
    }

    /// The checksum is the *last* eight bytes, not the first: the first eight of this
    /// digest would read `G2N5oy5BR7c`, and the specification's page says `hre47vyMC78`.
    #[test]
    fn checksum_is_the_rightmost_eight_bytes_of_sha256() {
        let c = checksum(&example_tx());
        let mut out = [0u8; 16];
        let n = base64url(&c, &mut out).unwrap();
        assert_eq!(&out[..n], EXAMPLE_C.as_bytes());
        assert_eq!(n, 11);
    }

    #[test]
    fn mainnet_has_no_network_parameter_and_the_others_do() {
        let tx = [0x02, 0x00, 0x00, 0x00];
        let mut out = [0u8; 128];
        let n = write_url(COLDCARD, &tx, Network::Mainnet, &mut out).unwrap();
        let url = core::str::from_utf8(&out[..n]).unwrap();
        assert!(url.starts_with("https://coldcard.com/pushtx#t=AgAAAA&c="));
        assert!(!url.contains("&n="));
        let n = write_url(COLDCARD, &tx, Network::Regtest, &mut out).unwrap();
        assert!(core::str::from_utf8(&out[..n]).unwrap().ends_with("&n=XRT"));
        let n = write_url(COLDCARD, &tx, Network::Testnet, &mut out).unwrap();
        assert!(core::str::from_utf8(&out[..n]).unwrap().ends_with("&n=XTN"));
    }

    /// RFC 4648 §10 test vectors, with the `=` padding dropped as §5 use here requires,
    /// and one input whose output needs the `-` and `_` characters.
    #[test]
    fn base64url_matches_rfc_4648() {
        let cases: &[(&[u8], &str)] = &[
            (b"", ""),
            (b"f", "Zg"),
            (b"fo", "Zm8"),
            (b"foo", "Zm9v"),
            (b"foob", "Zm9vYg"),
            (b"fooba", "Zm9vYmE"),
            (b"foobar", "Zm9vYmFy"),
            (&[0xfb, 0xff, 0xbf], "-_-_"),
        ];
        for &(input, want) in cases {
            let mut out = [0u8; 16];
            let n = base64url(input, &mut out).unwrap();
            assert_eq!(core::str::from_utf8(&out[..n]).unwrap(), want);
            assert_eq!(n, base64url_len(input.len()), "{want}");
        }
    }

    #[test]
    fn base64url_refuses_a_short_buffer_rather_than_truncating() {
        let mut out = [0u8; 3];
        assert_eq!(base64url(b"foo", &mut out), None);
    }

    #[test]
    fn a_short_buffer_is_refused_with_the_size_needed() {
        let tx = [0u8; 30];
        let mut out = [0u8; 40];
        let want = url_len(COLDCARD.len(), 30, Network::Mainnet);
        assert_eq!(
            write_url(COLDCARD, &tx, Network::Mainnet, &mut out),
            Err(Error::TooLong {
                needed: want,
                room: 40
            })
        );
    }

    #[test]
    fn service_urls_are_checked_as_the_specification_says() {
        assert_eq!(check_service(COLDCARD), Ok(()));
        assert_eq!(check_service(MEMPOOL), Ok(()));
        assert_eq!(check_service("https://x.example/p?"), Ok(()));
        assert_eq!(check_service("https://x.example/p?a=1&"), Ok(()));
        assert_eq!(
            check_service("http://x.example/p#"),
            Err(ServiceError::NotHttps)
        );
        assert_eq!(
            check_service("https://x.example/p"),
            Err(ServiceError::BadEnding)
        );
        assert_eq!(
            check_service("https://x.example/ p#"),
            Err(ServiceError::BadChar)
        );
        assert_eq!(
            check_service("https://x.example/%#"),
            Err(ServiceError::BadChar)
        );
        assert_eq!(check_service("https://#"), Err(ServiceError::BadLength));
        let long = format!("https://{}#", "a".repeat(SERVICE_MAX));
        assert_eq!(check_service(&long), Err(ServiceError::BadLength));
        assert_eq!(
            write_url("http://x#", &[1], Network::Mainnet, &mut [0u8; 64]),
            Err(Error::BadService(ServiceError::NotHttps))
        );
    }

    /// `max_tx_len` is the inverse of `url_len`: the largest transaction it names fits,
    /// and one byte more does not.
    #[test]
    fn max_tx_len_is_tight() {
        for room in [100usize, 500, 1000, 7999, URL_MAX] {
            for net in [Network::Mainnet, Network::Testnet] {
                let most = max_tx_len(room, COLDCARD.len(), net);
                assert!(url_len(COLDCARD.len(), most, net) <= room, "{room} {net:?}");
                assert!(
                    url_len(COLDCARD.len(), most + 1, net) > room,
                    "{room} {net:?}"
                );
            }
        }
        assert_eq!(max_tx_len(10, COLDCARD.len(), Network::Mainnet), 0);
    }
}
