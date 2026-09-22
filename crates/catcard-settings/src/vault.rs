//! The Seed Vault: keys the owner has kept, in the settings object.
//!
//! A device can work in more wallets than the one whose words are in the secure element --
//! a BIP-85 child, a seed joined from XOR parts -- and reaching one of those means typing
//! an index or three phrases again every session. The vault is where they are kept so they
//! can be picked from a list instead.
//!
//! # Where they live, and what that means
//!
//! In a wallet's own settings file, under `"seeds"`, beside its multisig registrations.
//! Every wallet the device works in has one, encrypted under that wallet's stash, so a
//! BIP-85 child's vault is the child's and not the root's. All of them are readable only
//! on an unlocked device, and all of them go when it is wiped. It is not a backup: an
//! entry here is a convenience for reaching a wallet whose words are written down
//! somewhere else.
//!
//! # The format is stock's
//!
//! ```json
//! "seeds": [["C2AAB8AA", "8010...", "my label", "TRNG Words"]]
//! ```
//!
//! Four strings in a fixed order: the master fingerprint of the wallet, the secret as the
//! secure element would hold it (marker byte then entropy, hex), a label the owner can
//! change, and how the key was made -- the *kind* only, never its parameters. A BIP-85
//! index or the parts of an XOR would be a second copy of the thing the entry is for.
//!
//! An entry we cannot read -- a secret that is not a marker plus entropy, or a row with
//! the wrong number of strings -- is skipped rather than dropped: it stays in the document
//! it came from unless the owner changes the list, because another firmware's entry is not
//! ours to delete.

use crate::json::{Doc, Error, elements};

/// Where the list lives in the settings object.
pub const KEY: &str = "seeds";

/// Most entries kept. Stock does not publish a limit; this is what a 4 KB settings slot
/// holds beside everything else, with room to spare.
pub const MAX_SEEDS: usize = 16;

/// Longest label, in bytes. Long enough to say which wallet this is and no longer: the
/// list has to fit a screen.
pub const MAX_LABEL: usize = 24;

/// One stored key, borrowed from the settings document.
#[derive(Copy, Clone, PartialEq, Eq, Debug, Default)]
pub struct Seed<'a> {
    /// Master fingerprint, uppercase hex, as stock writes it: `"C2AAB8AA"`.
    pub xfp: &'a str,
    /// The secret as the secure element would hold it: marker byte, then entropy, hex.
    pub secret: &'a str,
    /// What the owner calls it. Defaults to `[XFP]` when it was stored.
    pub label: &'a str,
    /// How the key was made -- `BIP85`, `XOR`, `TRNG Words` -- and nothing about which.
    pub method: &'a str,
}

/// The entries in `doc`, as many as `out` holds. Returns how many were read.
pub fn list<'a>(doc: &Doc<'a>, out: &mut [Seed<'a>]) -> usize {
    let Some(raw) = doc.get(KEY) else {
        return 0;
    };
    let Ok(rows) = elements(raw) else {
        return 0;
    };
    let mut n = 0;
    for row in rows {
        if n == out.len() {
            break;
        }
        let Ok(row) = row else { break };
        let Some(seed) = parse_row(row) else {
            // Somebody else's row, or a damaged one. Skipped here and kept in the
            // document: this list is only rewritten when the owner changes it.
            continue;
        };
        out[n] = seed;
        n += 1;
    }
    n
}

/// One `["xfp", "secret", "label", "method"]` row.
fn parse_row(row: &str) -> Option<Seed<'_>> {
    let mut it = elements(row).ok()?;
    let mut field = || -> Option<&str> {
        let raw = it.next()?.ok()?;
        raw.strip_prefix('"')?.strip_suffix('"')
    };
    let xfp = field()?;
    let secret = field()?;
    // Stock writes four; a row with only the first three is still usable, and one with
    // more has fields we do not know about -- neither is a reason to lose the key.
    let label = field().unwrap_or("");
    let method = field().unwrap_or("");
    (!xfp.is_empty() && is_hex(secret) && !secret.is_empty()).then_some(Seed {
        xfp,
        secret,
        label,
        method,
    })
}

fn is_hex(s: &str) -> bool {
    s.len().is_multiple_of(2) && s.bytes().all(|b| b.is_ascii_hexdigit())
}

/// Whether a string can go into the JSON as it stands.
///
/// Nothing here escapes. A label is typed on this device's keypad, which cannot produce a
/// control character, and refusing a quote is better than writing a document that another
/// firmware then fails to parse.
pub fn storable(text: &str) -> bool {
    !text
        .bytes()
        .any(|b| b == b'"' || b == b'\\' || !(0x20..0x7F).contains(&b))
}

/// The list with `seed` added, or replacing the entry with the same fingerprint.
///
/// Replacing rather than appending, so storing a key that is already there is harmless --
/// and so renaming one is the same operation as adding it.
pub fn with_added<'a>(
    existing: &[Seed<'a>],
    seed: Seed<'a>,
    out: &mut [Seed<'a>],
) -> Result<usize, Error> {
    if !storable(seed.label) || !storable(seed.xfp) || !is_hex(seed.secret) {
        return Err(Error::Malformed { at: 0 });
    }
    let mut n = 0;
    let mut replaced = false;
    for s in existing {
        if n == out.len() {
            return Err(Error::Malformed { at: 0 });
        }
        if s.xfp == seed.xfp {
            out[n] = seed;
            replaced = true;
        } else {
            out[n] = *s;
        }
        n += 1;
    }
    if !replaced {
        if n == out.len() || n == MAX_SEEDS {
            return Err(Error::Malformed { at: 0 });
        }
        out[n] = seed;
        n += 1;
    }
    Ok(n)
}

/// The list without the entry whose fingerprint is `xfp`. Returns how many remain.
pub fn without<'a>(existing: &[Seed<'a>], xfp: &str, out: &mut [Seed<'a>]) -> usize {
    let mut n = 0;
    for s in existing {
        if s.xfp == xfp || n == out.len() {
            continue;
        }
        out[n] = *s;
        n += 1;
    }
    n
}

/// Whether `xfp` is already in the list.
pub fn holds(existing: &[Seed<'_>], xfp: &str) -> bool {
    existing.iter().any(|s| s.xfp == xfp)
}

/// Write the list as the JSON array that goes under [`KEY`].
pub fn render(seeds: &[Seed<'_>], out: &mut [u8]) -> Result<usize, Error> {
    let mut at = 0usize;
    let mut put = |s: &str, at: &mut usize| -> Result<(), Error> {
        let end = *at + s.len();
        out.get_mut(*at..end)
            .ok_or(Error::Malformed { at: *at })?
            .copy_from_slice(s.as_bytes());
        *at = end;
        Ok(())
    };
    put("[", &mut at)?;
    for (i, s) in seeds.iter().enumerate() {
        if !storable(s.xfp) || !storable(s.label) || !storable(s.method) || !is_hex(s.secret) {
            return Err(Error::Malformed { at });
        }
        if i > 0 {
            put(",", &mut at)?;
        }
        for (n, part) in [s.xfp, s.secret, s.label, s.method].iter().enumerate() {
            put(if n == 0 { "[\"" } else { ",\"" }, &mut at)?;
            put(part, &mut at)?;
            put("\"", &mut at)?;
        }
        put("]", &mut at)?;
    }
    put("]", &mut at)?;
    Ok(at)
}

/// Decode a stored secret's hex into `out`, returning the bytes written.
///
/// The first is the stash's marker byte and the rest is what it introduces, which for a
/// BIP-39 wallet is the entropy. `None` if it is not hex, is empty, or is longer than
/// `out`.
pub fn decode_secret(hex: &str, out: &mut [u8]) -> Option<usize> {
    if !is_hex(hex) || hex.is_empty() || hex.len() / 2 > out.len() {
        return None;
    }
    let b = hex.as_bytes();
    for (i, pair) in b.as_chunks::<2>().0.iter().enumerate() {
        let hi = (pair[0] as char).to_digit(16)?;
        let lo = (pair[1] as char).to_digit(16)?;
        out[i] = (hi * 16 + lo) as u8;
    }
    Some(hex.len() / 2)
}

/// Hex-encode `bytes` into `out`, returning the text. Uppercase, as stock writes it.
pub fn encode_secret<'o>(bytes: &[u8], out: &'o mut [u8]) -> Option<&'o str> {
    const HEX: &[u8; 16] = b"0123456789ABCDEF";
    let need = bytes.len() * 2;
    if need > out.len() {
        return None;
    }
    for (i, b) in bytes.iter().enumerate() {
        out[2 * i] = HEX[(b >> 4) as usize];
        out[2 * i + 1] = HEX[(b & 0x0F) as usize];
    }
    core::str::from_utf8(&out[..need]).ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    const DOC: &str = r#"{"_age":23,"axi":"y6g3","chain":"BTC","seeds":[["C2AAB8AA","801033445566778899AABBCCDDEEFF0011","w16_100_1_50","TRNG Words"],["11223344","8200112233445566778899AABBCCDDEEFF00112233445566778899AABBCCDDEEFF","[11223344]","BIP85"]]}"#;

    fn parse(s: &str) -> Doc<'_> {
        Doc::parse(s.as_bytes()).unwrap()
    }

    /// The shape stock writes, read back field for field.
    #[test]
    fn a_stock_document_reads() {
        let doc = parse(DOC);
        let mut out = [Seed::default(); MAX_SEEDS];
        let n = list(&doc, &mut out);
        assert_eq!(n, 2);
        assert_eq!(out[0].xfp, "C2AAB8AA");
        assert_eq!(out[0].label, "w16_100_1_50");
        assert_eq!(out[0].method, "TRNG Words");
        assert_eq!(out[1].xfp, "11223344");
        assert_eq!(out[1].method, "BIP85");
        // The first is a 12-word wallet: marker 0x80 and sixteen bytes.
        let mut raw = [0u8; 33];
        let got = decode_secret(out[0].secret, &mut raw).unwrap();
        assert_eq!(got, 17);
        assert_eq!(raw[0], 0x80);
    }

    /// Settings with no vault, and settings whose vault is something else entirely, are
    /// an empty list rather than an error: this key is one of many in a shared document.
    #[test]
    fn a_document_without_a_vault_has_no_seeds() {
        let mut out = [Seed::default(); MAX_SEEDS];
        assert_eq!(list(&parse(r#"{"_age":1}"#), &mut out), 0);
        assert_eq!(list(&parse(r#"{"seeds":"nonsense"}"#), &mut out), 0);
        assert_eq!(list(&parse(r#"{"seeds":[]}"#), &mut out), 0);
    }

    /// A row this firmware cannot read is skipped, and the ones around it still load.
    /// Another firmware's entry is not ours to lose.
    #[test]
    fn an_unreadable_row_does_not_take_the_others_with_it() {
        let doc = parse(
            r#"{"seeds":[["AAAA0001","80AA","one","XOR"],["BBBB0002","not hex","two","XOR"],[],["CCCC0003","80BB","three","XOR"]]}"#,
        );
        let mut out = [Seed::default(); MAX_SEEDS];
        let n = list(&doc, &mut out);
        assert_eq!(n, 2);
        assert_eq!(out[0].xfp, "AAAA0001");
        assert_eq!(out[1].xfp, "CCCC0003");
    }

    /// What is rendered reads back as what went in.
    #[test]
    fn a_rendered_list_parses_to_itself() {
        let doc = parse(DOC);
        let mut out = [Seed::default(); MAX_SEEDS];
        let n = list(&doc, &mut out);
        let mut buf = [0u8; 512];
        let len = render(&out[..n], &mut buf).unwrap();
        let text = core::str::from_utf8(&buf[..len]).unwrap();
        let mut around = heapless::String::<640>::new();
        core::fmt::Write::write_fmt(&mut around, format_args!(r#"{{"seeds":{text}}}"#)).unwrap();
        let again = parse(&around);
        let mut back = [Seed::default(); MAX_SEEDS];
        let m = list(&again, &mut back);
        assert_eq!(m, n);
        assert_eq!(back[..m], out[..n]);
    }

    /// Storing a key that is already there renames it rather than making a second one:
    /// a vault with the same wallet in it twice is a vault nobody can read.
    #[test]
    fn adding_a_fingerprint_that_is_there_replaces_it() {
        let existing = [
            Seed {
                xfp: "AAAA0001",
                secret: "80AA",
                label: "first",
                method: "XOR",
            },
            Seed {
                xfp: "BBBB0002",
                secret: "80BB",
                label: "second",
                method: "BIP85",
            },
        ];
        let mut out = [Seed::default(); MAX_SEEDS];
        let n = with_added(
            &existing,
            Seed {
                xfp: "AAAA0001",
                secret: "80AA",
                label: "renamed",
                method: "XOR",
            },
            &mut out,
        )
        .unwrap();
        assert_eq!(n, 2);
        assert_eq!(out[0].label, "renamed");
        assert_eq!(out[1].label, "second");
        assert!(holds(&out[..n], "BBBB0002"));
    }

    #[test]
    fn a_forgotten_key_is_gone_and_the_rest_stay() {
        let existing = [
            Seed {
                xfp: "AAAA0001",
                secret: "80AA",
                label: "first",
                method: "XOR",
            },
            Seed {
                xfp: "BBBB0002",
                secret: "80BB",
                label: "second",
                method: "BIP85",
            },
        ];
        let mut out = [Seed::default(); MAX_SEEDS];
        let n = without(&existing, "AAAA0001", &mut out);
        assert_eq!(n, 1);
        assert_eq!(out[0].xfp, "BBBB0002");
        assert!(!holds(&out[..n], "AAAA0001"));
    }

    /// A label that would break the document is refused, not escaped: the store is
    /// shared with a firmware whose parser is not ours.
    #[test]
    fn a_label_with_a_quote_in_it_is_refused() {
        let seed = Seed {
            xfp: "AAAA0001",
            secret: "80AA",
            label: "say \"hi\"",
            method: "XOR",
        };
        let mut out = [Seed::default(); MAX_SEEDS];
        assert!(with_added(&[], seed, &mut out).is_err());
        let mut buf = [0u8; 128];
        assert!(render(&[seed], &mut buf).is_err());
    }

    #[test]
    fn the_vault_is_bounded() {
        let full: heapless::Vec<Seed<'_>, MAX_SEEDS> = (0..MAX_SEEDS)
            .map(|_| Seed {
                xfp: "AAAA0001",
                secret: "80AA",
                label: "x",
                method: "XOR",
            })
            .collect();
        let mut out = [Seed::default(); MAX_SEEDS];
        // Every one has the same fingerprint, so this replaces rather than grows.
        assert_eq!(with_added(&full, full[0], &mut out).unwrap(), MAX_SEEDS);
        // A different one has nowhere to go.
        let one_more = Seed {
            xfp: "FFFF0009",
            secret: "80FF",
            label: "x",
            method: "XOR",
        };
        assert!(with_added(&full, one_more, &mut out).is_err());
    }

    /// Hex in and hex out, both ways, including the odd lengths that are not secrets.
    #[test]
    fn hex_round_trips_and_refuses_what_is_not_hex() {
        let mut buf = [0u8; 8];
        assert_eq!(encode_secret(&[0x80, 0x0f], &mut buf), Some("800F"));
        let mut raw = [0u8; 4];
        assert_eq!(decode_secret("800F", &mut raw), Some(2));
        assert_eq!(&raw[..2], &[0x80, 0x0f]);
        assert_eq!(decode_secret("80F", &mut raw), None);
        assert_eq!(decode_secret("80GG", &mut raw), None);
        assert_eq!(decode_secret("", &mut raw), None);
        // Longer than the buffer is refused rather than truncated.
        assert_eq!(decode_secret("80AABBCCDDEE", &mut raw), None);
    }
}
