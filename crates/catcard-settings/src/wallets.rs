//! Registered multisig wallets, as they sit in the settings.
//!
//! What is stored is **the descriptor the owner imported**, verbatim, rather than this
//! firmware's reading of it. A descriptor is self-describing and carries its own checksum,
//! so keeping the text means a wallet survives a change in how we parse one, and what a
//! person compared on screen when they registered it is what is still there afterwards.
//!
//! # Not under stock's key
//!
//! Stock keeps its own wallets under `multisig`, and the format document describes that as
//! "(complex)" -- we do not know its shape, and inventing one would overwrite the wallets
//! of anyone whose device has been stock. So these live under [`KEY`] and stock's are left
//! exactly as they were. A device can hold both and neither firmware loses anything.
//!
//! # Identity is the descriptor
//!
//! Re-importing a wallet replaces it rather than making a second, and a near-duplicate --
//! the same cosigners in another order, or `multi` where `sortedmulti` was meant -- is a
//! different entry, visibly, instead of silently shadowing the first.
//!
//! What decides that is the descriptor text, not its checksum. The BIP-380 checksum is a
//! BCH code over a linear function, so a descriptor carrying any chosen checksum can be
//! constructed; keying on it would let an imported wallet replace an unrelated registered
//! one.

use crate::json::Doc;

/// Where these live in the settings dictionary. **Not** stock's `multisig`; see the module
/// documentation.
pub const KEY: &str = "ccms";

/// Wallets one device may register.
///
/// The settings slot holds about four kilobytes for *everything*, and a three-cosigner
/// descriptor is around four hundred bytes, so this is a bound on the arithmetic rather
/// than a policy. A wallet that does not fit is refused at the door with a reason, not
/// stored half way.
pub const MAX_WALLETS: usize = 8;

/// A registered wallet: a name for the owner, and the descriptor itself.
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub struct Wallet<'a> {
    pub name: &'a str,
    pub descriptor: &'a str,
}

impl<'a> Wallet<'a> {
    /// The descriptor's checksum, which is this wallet's identity.
    pub fn checksum(&self) -> Option<&'a str> {
        let (_, sum) = self.descriptor.rsplit_once('#')?;
        (sum.len() == 8).then_some(sum)
    }
}

/// Why a wallet could not be stored.
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub enum Error {
    /// More than [`MAX_WALLETS`].
    TooMany,
    /// The descriptor or name holds a character this cannot store: a quote, a backslash,
    /// or a control character. Escaping them would be easy and wrong -- a descriptor
    /// containing one is not a descriptor, and a name containing one came from somewhere
    /// that should be looked at rather than quietly accommodated.
    NotStorable,
    /// The descriptor carries no checksum, so it has no identity here.
    NoChecksum,
    /// The buffer given to [`render`] was too small.
    Overflow,
}

/// Read the registered wallets out of a settings document.
///
/// Entries that are not objects, or lack a descriptor, are skipped rather than failing the
/// list: one unreadable entry must not hide the others, and the settings may have been
/// written by a version that stores more than this one reads.
pub fn list<'a>(doc: &Doc<'a>, out: &mut [Wallet<'a>]) -> usize {
    let Some(raw) = doc.get(KEY) else {
        return 0;
    };
    let Ok(elements) = crate::json::elements(raw) else {
        return 0;
    };
    let mut n = 0;
    for element in elements {
        if n == out.len() {
            break;
        }
        let Ok(text) = element else { break };
        let Ok(entry) = Doc::parse(text.as_bytes()) else {
            continue;
        };
        let Some(descriptor) = entry.get_str("d") else {
            continue;
        };
        out[n] = Wallet {
            name: entry.get_str("n").unwrap_or(""),
            descriptor,
        };
        n += 1;
    }
    n
}

/// The list with `wallet` added, or replacing the one with the same checksum.
///
/// Returns how many entries `out` now holds. Replacing rather than appending is what makes
/// importing the same wallet twice harmless -- a person who is not sure whether a
/// registration took can simply do it again.
pub fn with_added<'a>(
    existing: &[Wallet<'a>],
    wallet: Wallet<'a>,
    out: &mut [Wallet<'a>],
) -> Result<usize, Error> {
    if wallet.checksum().is_none() {
        return Err(Error::NoChecksum);
    }
    if !storable(wallet.descriptor) || !storable(wallet.name) {
        return Err(Error::NotStorable);
    }
    let mut n = 0;
    let mut replaced = false;
    for w in existing {
        if n == out.len() {
            return Err(Error::TooMany);
        }
        if w.descriptor == wallet.descriptor {
            out[n] = wallet;
            replaced = true;
        } else {
            out[n] = *w;
        }
        n += 1;
    }
    if !replaced {
        if n == out.len() || n == MAX_WALLETS {
            return Err(Error::TooMany);
        }
        out[n] = wallet;
        n += 1;
    }
    Ok(n)
}

/// The list with the wallet whose checksum is `sum` renamed to `name`. Returns how many
/// entries `out` holds, which is as many as `existing` had.
///
/// The descriptor -- the identity -- is untouched: a rename is the one edit that changes
/// nothing about which spends this device will sign. `Err(NotStorable)` for a name the
/// JSON cannot carry; `Ok` with the list unchanged if no wallet has that checksum, so a
/// caller can see nothing happened by comparing names rather than by a second lookup.
pub fn renamed<'a>(
    existing: &[Wallet<'a>],
    sum: &str,
    name: &'a str,
    out: &mut [Wallet<'a>],
) -> Result<usize, Error> {
    if !storable(name) {
        return Err(Error::NotStorable);
    }
    let mut n = 0;
    for w in existing {
        if n == out.len() {
            return Err(Error::TooMany);
        }
        out[n] = if w.checksum() == Some(sum) {
            Wallet {
                name,
                descriptor: w.descriptor,
            }
        } else {
            *w
        };
        n += 1;
    }
    Ok(n)
}

/// The list without the wallet whose checksum is `sum`. Returns how many remain.
pub fn without<'a>(existing: &[Wallet<'a>], sum: &str, out: &mut [Wallet<'a>]) -> usize {
    let mut n = 0;
    for w in existing {
        if w.checksum() == Some(sum) || n == out.len() {
            continue;
        }
        out[n] = *w;
        n += 1;
    }
    n
}

/// Write the list as the JSON array that goes into the settings.
pub fn render(wallets: &[Wallet<'_>], out: &mut [u8]) -> Result<usize, Error> {
    let mut at = 0usize;
    let mut put = |s: &str, at: &mut usize| -> Result<(), Error> {
        let end = *at + s.len();
        out.get_mut(*at..end)
            .ok_or(Error::Overflow)?
            .copy_from_slice(s.as_bytes());
        *at = end;
        Ok(())
    };
    put("[", &mut at)?;
    for (i, w) in wallets.iter().enumerate() {
        if !storable(w.descriptor) || !storable(w.name) {
            return Err(Error::NotStorable);
        }
        if i > 0 {
            put(",", &mut at)?;
        }
        put("{\"n\":\"", &mut at)?;
        put(w.name, &mut at)?;
        put("\",\"d\":\"", &mut at)?;
        put(w.descriptor, &mut at)?;
        put("\"}", &mut at)?;
    }
    put("]", &mut at)?;
    Ok(at)
}

/// Whether a string can go into the JSON as it stands.
///
/// Nothing here escapes: a descriptor with a quote in it is not a descriptor, and a name
/// with a control character in it came from somewhere worth looking at. Refusing is the
/// honest answer and keeps the writer trivial enough to be obviously correct.
fn storable(text: &str) -> bool {
    !text
        .bytes()
        .any(|b| b == b'"' || b == b'\\' || b < 0x20 || b == 0x7F)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Two descriptors, disjoint cosigner keys, the same BIP-380 checksum. The checksum is
    /// a BCH code over a linear function, so one carrying any chosen value can be solved
    /// for. Keying replacement on it would let the second delete the first.
    #[test]
    fn a_colliding_checksum_does_not_replace_another_wallet() {
        let genuine = Wallet {
            name: "genuine",
            descriptor: "wsh(sortedmulti(2,[aabbccdd/48h/0h/0h/2h]xpub6ERApfZwUNrhLCkDtcHTcxd75RbzS1ed54G1LkBUHQVHQKqhMkhgbmJbZRkrgZw4koxb5JaHWkY4ALHY2grBGRjaDMzQLcgJvLJuZZvRcEL/0/*,[11223344/48h/0h/0h/2h]xpub6BosfCnifzxcFwrSzQiqu2DBVTshkCXacvNsWGYJVVhhawA7d4R5WSWGFNbi8Aw6ZRc1brxMyWMzG3DSSSSoekkudhUd9yLb6qx39T9nMdj/0/*))#rk2ttxtk",
        };
        let collider = Wallet {
            name: "collider",
            descriptor: "wsh(sortedmulti(2,[aabbccdd/48h/0h/0h/2h]xpub661MyMwAqRbcFtXgS5sYJABqqG9YLmC4Q1Rdap9gSE8NqtwybGhePY2gZ29ESFjqJoCu1Rupje8YtGqsefD265TMg7usUDFdp6W1EGMcet8/0/(69h324c]:2%*,[11223344/48h/0h/0h/2h]xpub68NZiKmJWnxxS6aaHmn81bvJeTESw724CRDs6HbuccFQN9Ku14VQrADWgqbhhTHBaohPX4CjNLf9fq9MYo6oDaPPLPxSb7gwQN3ih19Zm4Y/0/*))#rk2ttxtk",
        };
        assert_eq!(genuine.checksum(), collider.checksum());

        let mut out = [Wallet {
            name: "",
            descriptor: "",
        }; MAX_WALLETS];
        let n = with_added(&[genuine], collider, &mut out).unwrap();
        assert_eq!(n, 2, "the collider must not take the genuine wallet's slot");
        assert!(out[..n].contains(&genuine));
        assert!(out[..n].contains(&collider));
    }

    /// Re-importing the very same descriptor still replaces rather than duplicating.
    #[test]
    fn the_same_descriptor_replaces_itself() {
        let first = Wallet {
            name: "old",
            descriptor: "raw(deadbeef)#89f8spxm",
        };
        let again = Wallet {
            name: "new",
            descriptor: "raw(deadbeef)#89f8spxm",
        };
        let mut out = [Wallet {
            name: "",
            descriptor: "",
        }; MAX_WALLETS];
        let n = with_added(&[first], again, &mut out).unwrap();
        assert_eq!(n, 1);
        assert_eq!(out[0].name, "new");
    }

    const A: &str = "wsh(sortedmulti(2,[aabbccdd/48h/0h/0h/2h]xpubA/0/*,[11223344/48h/0h/0h/2h]xpubB/0/*))#abcdefgh";
    const B: &str = "sh(wsh(sortedmulti(2,[aabbccdd/48h/0h/0h/1h]xpubC/0/*,[11223344/48h/0h/0h/1h]xpubD/0/*)))#hgfedcba";

    #[test]
    fn a_wallet_round_trips_through_the_settings() {
        let mut wallets = [Wallet {
            name: "",
            descriptor: "",
        }; MAX_WALLETS];
        let n = with_added(
            &[],
            Wallet {
                name: "Home",
                descriptor: A,
            },
            &mut wallets,
        )
        .unwrap();
        assert_eq!(n, 1);

        let mut json = [0u8; 1024];
        let len = render(&wallets[..n], &mut json).unwrap();
        let settings = format!(
            "{{\"_age\":1,\"ccms\":{}}}",
            core::str::from_utf8(&json[..len]).unwrap()
        );

        let doc = Doc::parse(settings.as_bytes()).unwrap();
        let mut back = [Wallet {
            name: "",
            descriptor: "",
        }; MAX_WALLETS];
        let got = list(&doc, &mut back);
        assert_eq!(got, 1);
        assert_eq!(back[0].name, "Home");
        assert_eq!(back[0].descriptor, A);
        assert_eq!(back[0].checksum(), Some("abcdefgh"));
    }

    /// Registering the same wallet twice leaves one, because the checksum is the identity.
    #[test]
    fn re_importing_a_wallet_replaces_it_rather_than_doubling_it() {
        let first = Wallet {
            name: "Home",
            descriptor: A,
        };
        let mut one = [first; MAX_WALLETS];
        let n = with_added(&[], first, &mut one).unwrap();

        // The same descriptor, a different name: still the same wallet.
        let again = Wallet {
            name: "Home vault",
            descriptor: A,
        };
        let mut two = [first; MAX_WALLETS];
        let n = with_added(&one[..n], again, &mut two).unwrap();
        assert_eq!(n, 1, "the same checksum made a second entry");
        assert_eq!(two[0].name, "Home vault", "the newer name did not win");
    }

    /// A different wallet is a different entry, even from the same cosigners.
    #[test]
    fn a_different_checksum_is_a_different_wallet() {
        let home = Wallet {
            name: "Home",
            descriptor: A,
        };
        let other = Wallet {
            name: "Wrapped",
            descriptor: B,
        };
        let mut list_a = [home; MAX_WALLETS];
        let n = with_added(&[], home, &mut list_a).unwrap();
        let mut list_b = [home; MAX_WALLETS];
        let n = with_added(&list_a[..n], other, &mut list_b).unwrap();
        assert_eq!(n, 2);
        assert_eq!(list_b[1].descriptor, B);

        let mut left = [home; MAX_WALLETS];
        let n = without(&list_b[..n], "abcdefgh", &mut left);
        assert_eq!(n, 1);
        assert_eq!(left[0].descriptor, B, "removed the wrong wallet");
    }

    /// A rename changes the name of exactly the wallet named, and nothing about its
    /// descriptor; a name the JSON cannot carry is refused before anything moves.
    #[test]
    fn a_rename_touches_one_name_and_no_descriptor() {
        let home = Wallet {
            name: "Home",
            descriptor: A,
        };
        let other = Wallet {
            name: "Wrapped",
            descriptor: B,
        };
        let mut out = [home; MAX_WALLETS];
        let n = renamed(&[home, other], "abcdefgh", "Home vault", &mut out).unwrap();
        assert_eq!(n, 2);
        assert_eq!(out[0].name, "Home vault");
        assert_eq!(out[0].descriptor, A);
        assert_eq!(out[1], other);

        // An unknown checksum renames nothing.
        let n = renamed(&[home, other], "zzzzzzzz", "x", &mut out).unwrap();
        assert_eq!(&out[..n], &[home, other]);
        // A quote in the name is refused rather than escaped.
        assert_eq!(
            renamed(&[home], "abcdefgh", "he said \"hi\"", &mut out),
            Err(Error::NotStorable)
        );
    }

    #[test]
    fn a_descriptor_without_a_checksum_has_no_identity_and_is_refused() {
        let no_sum = Wallet {
            name: "x",
            descriptor: "wsh(sortedmulti(2,a,b))",
        };
        let mut out = [no_sum; MAX_WALLETS];
        assert_eq!(with_added(&[], no_sum, &mut out), Err(Error::NoChecksum));
    }

    #[test]
    fn a_quote_or_a_control_character_is_refused_rather_than_escaped() {
        for bad in ["a\"b#abcdefgh", "a\\b#abcdefgh", "a\nb#abcdefgh"] {
            let w = Wallet {
                name: "x",
                descriptor: bad,
            };
            let mut out = [w; MAX_WALLETS];
            assert_eq!(
                with_added(&[], w, &mut out),
                Err(Error::NotStorable),
                "{bad}"
            );
        }
        // And in the name, which is typed by a person and can hold anything.
        let w = Wallet {
            name: "he said \"hi\"",
            descriptor: A,
        };
        let mut out = [w; MAX_WALLETS];
        assert_eq!(with_added(&[], w, &mut out), Err(Error::NotStorable));
    }

    #[test]
    fn the_list_survives_an_entry_it_cannot_read() {
        // A settings blob written by a version that stores more, or one entry corrupted:
        // the rest must still list, or one bad wallet hides the others.
        let settings = format!(
            "{{\"_age\":2,\"ccms\":[{{\"n\":\"one\",\"d\":\"{A}\"}},{{\"x\":1}},{{\"n\":\"two\",\"d\":\"{B}\"}}]}}"
        );
        let doc = Doc::parse(settings.as_bytes()).unwrap();
        let mut out = [Wallet {
            name: "",
            descriptor: "",
        }; MAX_WALLETS];
        let n = list(&doc, &mut out);
        assert_eq!(n, 2);
        assert_eq!(out[0].name, "one");
        assert_eq!(out[1].name, "two");
    }

    #[test]
    fn nothing_registered_lists_as_nothing() {
        let doc = Doc::parse(b"{\"_age\":1}").unwrap();
        let mut out = [Wallet {
            name: "",
            descriptor: "",
        }; MAX_WALLETS];
        assert_eq!(list(&doc, &mut out), 0);
    }
}
