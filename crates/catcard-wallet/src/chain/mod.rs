//! The chain registry.
//!
//! CatCard ships **one firmware that supports every enabled chain** — there is no
//! per-coin app to install, and no app loader. What varies is the build: chains are
//! cargo features, so a Bitcoin-only firmware is a real artefact with the other chains'
//! code absent from the image rather than merely hidden.
//!
//! ```text
//! cargo fw-mk4                                             # every chain
//! cargo build ... --no-default-features \
//!     --features board-mk4,chain-bitcoin                   # Bitcoin only
//! ```
//!
//! # Why the code must be absent, not disabled
//!
//! A runtime toggle would leave every chain's transaction parser linked into a
//! Bitcoin-only device, reachable by anything that can reach the transport. Compiling
//! it out is the difference between a smaller product and a smaller attack surface, and
//! it is the whole reason a single-coin build is worth offering.
//!
//! # Chain confusion is the risk this module exists to bound
//!
//! One firmware serving several chains means a host can name one chain while supplying
//! another's payload, or ask for a signature over a key derived under different rules.
//! Two things guard that, and both live here rather than in each chain's code:
//!
//! - A chain's [`Curve`] and [`Scheme`] come from **this table**, never from the
//!   request. The host chooses *which* chain, never *how* its keys are derived.
//! - [`Chain::accepts_path`] rejects a path whose SLIP-44 coin type belongs to a
//!   different chain, so an Ethereum signature cannot be taken over `m/44'/0'/…`.

use crate::bip32::{ChildNumber, DerivationPath};

/// Signature curve.
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub enum Curve {
    Secp256k1,
    Ed25519,
}

/// How child keys are derived.
///
/// Two curves but three schemes: ed25519 has two incompatible derivations in the wild,
/// and picking the wrong one produces a valid wallet at addresses the user cannot see.
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub enum Scheme {
    /// BIP-32 over secp256k1. Hardened and normal derivation.
    Bip32,
    /// SLIP-0010 over ed25519. **Hardened only** — there is no public derivation, so no
    /// watch-only xpub. Solana and most ed25519 chains use this.
    Slip10Ed25519,
    /// BIP32-Ed25519 (Khovratovich & Law), as Cardano uses. Supports normal derivation
    /// by carrying the expanded scalar pair rather than the seed, so watch-only works.
    /// Not interchangeable with [`Scheme::Slip10Ed25519`] — same curve, different keys.
    Bip32Ed25519,
}

impl Scheme {
    pub const fn curve(self) -> Curve {
        match self {
            Scheme::Bip32 => Curve::Secp256k1,
            Scheme::Slip10Ed25519 | Scheme::Bip32Ed25519 => Curve::Ed25519,
        }
    }

    /// Whether an extended *public* key can derive children.
    ///
    /// False for SLIP-0010: an account model that assumes it can hand a host an xpub and
    /// let it derive addresses is secp256k1-specific, and silently wrong here.
    pub const fn supports_public_derivation(self) -> bool {
        matches!(self, Scheme::Bip32 | Scheme::Bip32Ed25519)
    }
}

/// Stable identifier for a chain, used on the wire.
///
/// Explicit discriminants: these travel in the protocol, so they are part of the
/// compatibility surface and must not shift when the enum is reordered.
#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Debug)]
#[repr(u16)]
pub enum ChainId {
    Bitcoin = 1,
    Ethereum = 2,
    Solana = 3,
}

impl ChainId {
    pub const fn as_u16(self) -> u16 {
        self as u16
    }

    /// Parse an identifier off the wire. Unknown values are `None` — never a default.
    pub const fn from_u16(v: u16) -> Option<Self> {
        match v {
            1 => Some(ChainId::Bitcoin),
            2 => Some(ChainId::Ethereum),
            3 => Some(ChainId::Solana),
            _ => None,
        }
    }
}

/// Everything the firmware needs to know about a chain, independent of its crypto.
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub struct Chain {
    pub id: ChainId,
    /// Shown on screen. Short enough for a 16-column panel.
    pub name: &'static str,
    pub scheme: Scheme,
    /// SLIP-44 coin type, the `m/44'/<coin>'` level.
    pub coin_type: u32,
}

impl Chain {
    pub const fn curve(&self) -> Curve {
        self.scheme.curve()
    }

    /// Whether `path` is one this chain should sign under.
    ///
    /// Checks the SLIP-44 coin type at level 2 against this chain's. A host that names
    /// Ethereum while supplying `m/44'/0'/…` is either confused or trying to obtain an
    /// Ethereum signature over a Bitcoin key, and neither should proceed silently.
    ///
    /// A path shorter than two levels has no coin type to check and is refused here —
    /// deliberately. `m` and `m/44'` are not addresses to sign under, and accepting them
    /// would open the very hole this check closes.
    pub fn accepts_path(&self, path: &DerivationPath) -> Result<(), PathRejected> {
        let mut it = path.iter();
        let purpose = it
            .next()
            .ok_or(PathRejected::TooShort { len: path.len() })?;
        let coin = it
            .next()
            .ok_or(PathRejected::TooShort { len: path.len() })?;

        // BIP-44 and its successors all harden the first two levels. An unhardened coin
        // type means the path is not a BIP-44-family path at all.
        if !purpose.is_hardened() || !coin.is_hardened() {
            return Err(PathRejected::NotHardened);
        }
        if coin.index() != self.coin_type {
            return Err(PathRejected::WrongCoinType {
                found: coin.index(),
                expected: self.coin_type,
            });
        }
        Ok(())
    }

    /// The account-level prefix for this chain: `m/<purpose>'/<coin>'`.
    pub fn account_prefix(&self, purpose: u32) -> Result<DerivationPath, crate::bip32::Error> {
        DerivationPath::from_slice(&[
            ChildNumber::hardened(purpose)?,
            ChildNumber::hardened(self.coin_type)?,
        ])
    }
}

#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub enum PathRejected {
    /// Fewer than the two levels a coin type needs.
    TooShort { len: usize },
    /// Purpose or coin type not hardened.
    NotHardened,
    /// The coin type belongs to a different chain.
    WrongCoinType { found: u32, expected: u32 },
}

/// Why a chain request could not be served.
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub enum Unsupported {
    /// The identifier is not one this protocol version knows.
    UnknownChain { id: u16 },
    /// A known chain, compiled out of this firmware.
    ///
    /// Distinct from [`Self::UnknownChain`] on purpose: a host talking to a Bitcoin-only
    /// device should be able to say "this device does not do Ethereum" rather than
    /// "something went wrong", and a user should be able to tell a single-coin build
    /// from a broken one.
    NotInThisBuild { id: ChainId },
}

// ---------------------------------------------------------------------------
// The registry. One entry per feature.
// ---------------------------------------------------------------------------

/// Bitcoin. BIP-44/49/84/86 purposes over secp256k1.
#[cfg(feature = "chain-bitcoin")]
pub const BITCOIN: Chain = Chain {
    id: ChainId::Bitcoin,
    name: "Bitcoin",
    scheme: Scheme::Bip32,
    coin_type: 0,
};

/// Ethereum and EVM chains. `m/44'/60'`, secp256k1, recoverable signatures.
#[cfg(feature = "chain-ethereum")]
pub const ETHEREUM: Chain = Chain {
    id: ChainId::Ethereum,
    name: "Ethereum",
    scheme: Scheme::Bip32,
    coin_type: 60,
};

/// Solana. `m/44'/501'`, ed25519 under SLIP-0010, so hardened-only.
#[cfg(feature = "chain-solana")]
pub const SOLANA: Chain = Chain {
    id: ChainId::Solana,
    name: "Solana",
    scheme: Scheme::Slip10Ed25519,
    coin_type: 501,
};

/// Chains compiled into this firmware.
pub const SUPPORTED: &[Chain] = &[
    #[cfg(feature = "chain-bitcoin")]
    BITCOIN,
    #[cfg(feature = "chain-ethereum")]
    ETHEREUM,
    #[cfg(feature = "chain-solana")]
    SOLANA,
];

/// Every chain this protocol version defines, enabled or not.
///
/// Used to tell "compiled out" from "never heard of it" — see [`Unsupported`].
pub const KNOWN: &[ChainId] = &[ChainId::Bitcoin, ChainId::Ethereum, ChainId::Solana];

/// Look up a chain by wire identifier.
pub fn resolve(id: u16) -> Result<&'static Chain, Unsupported> {
    let known = ChainId::from_u16(id).ok_or(Unsupported::UnknownChain { id })?;
    SUPPORTED
        .iter()
        .find(|c| c.id == known)
        .ok_or(Unsupported::NotInThisBuild { id: known })
}

/// Whether this build carries exactly one chain.
///
/// A single-coin device is a distinct product, and the UI says so rather than leaving
/// the user to infer it from an empty menu.
pub fn is_single_chain() -> bool {
    SUPPORTED.len() == 1
}

/// A short build identifier for the boot screen and the image tool: `btc`, `btc+eth`.
///
/// Two builds that differ only in their chain set must not be indistinguishable at a
/// glance, since they are different products with different attack surfaces.
pub fn build_tag(out: &mut [u8]) -> usize {
    let mut at = 0;
    for (i, c) in SUPPORTED.iter().enumerate() {
        let tag: &[u8] = match c.id {
            ChainId::Bitcoin => b"btc",
            ChainId::Ethereum => b"eth",
            ChainId::Solana => b"sol",
        };
        if i > 0 {
            if at == out.len() {
                return at;
            }
            out[at] = b'+';
            at += 1;
        }
        for &b in tag {
            if at == out.len() {
                return at;
            }
            out[at] = b;
            at += 1;
        }
    }
    at
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bip32::HARDENED_OFFSET;
    use core::str::FromStr;

    fn path(s: &str) -> DerivationPath {
        DerivationPath::from_str(s).unwrap()
    }

    #[test]
    fn wire_identifiers_are_stable() {
        // These travel in the protocol; renumbering them breaks every host.
        assert_eq!(ChainId::Bitcoin.as_u16(), 1);
        assert_eq!(ChainId::Ethereum.as_u16(), 2);
        assert_eq!(ChainId::Solana.as_u16(), 3);
        for id in KNOWN {
            assert_eq!(ChainId::from_u16(id.as_u16()), Some(*id));
        }
    }

    #[test]
    fn an_unknown_identifier_is_never_defaulted() {
        // Falling back to "probably Bitcoin" would let a host get a signature from a
        // chain it did not name.
        assert_eq!(ChainId::from_u16(0), None);
        assert_eq!(ChainId::from_u16(9999), None);
        assert!(matches!(
            resolve(0),
            Err(Unsupported::UnknownChain { id: 0 })
        ));
        assert!(matches!(
            resolve(4242),
            Err(Unsupported::UnknownChain { id: 4242 })
        ));
    }

    #[test]
    fn slip44_coin_types_are_the_registered_ones() {
        for c in SUPPORTED {
            let expect = match c.id {
                ChainId::Bitcoin => 0,
                ChainId::Ethereum => 60,
                ChainId::Solana => 501,
            };
            assert_eq!(c.coin_type, expect, "{}", c.name);
        }
    }

    #[test]
    fn each_chains_scheme_implies_its_curve() {
        assert_eq!(Scheme::Bip32.curve(), Curve::Secp256k1);
        assert_eq!(Scheme::Slip10Ed25519.curve(), Curve::Ed25519);
        assert_eq!(Scheme::Bip32Ed25519.curve(), Curve::Ed25519);
        for c in SUPPORTED {
            assert_eq!(c.curve(), c.scheme.curve());
        }
    }

    #[test]
    fn only_slip10_lacks_public_derivation() {
        // The property watch-only wallets need. Assuming it holds everywhere is how an
        // account model ends up secp256k1-specific without anyone noticing.
        assert!(Scheme::Bip32.supports_public_derivation());
        assert!(Scheme::Bip32Ed25519.supports_public_derivation());
        assert!(!Scheme::Slip10Ed25519.supports_public_derivation());
    }

    #[test]
    fn the_two_ed25519_schemes_are_not_interchangeable() {
        // Same curve, different keys from the same seed. Treating them as one produces
        // a valid wallet at addresses the user cannot find.
        assert_eq!(Scheme::Slip10Ed25519.curve(), Scheme::Bip32Ed25519.curve());
        assert_ne!(Scheme::Slip10Ed25519, Scheme::Bip32Ed25519);
        assert_ne!(
            Scheme::Slip10Ed25519.supports_public_derivation(),
            Scheme::Bip32Ed25519.supports_public_derivation()
        );
    }

    #[test]
    fn registry_has_no_duplicate_ids_or_coin_types() {
        for (i, a) in SUPPORTED.iter().enumerate() {
            for b in &SUPPORTED[i + 1..] {
                assert_ne!(a.id, b.id);
                assert_ne!(a.coin_type, b.coin_type, "{} vs {}", a.name, b.name);
            }
        }
    }

    // -- chain confusion -----------------------------------------------------

    #[cfg(all(feature = "chain-bitcoin", feature = "chain-ethereum"))]
    #[test]
    fn a_path_from_another_chain_is_refused() {
        // The core defence: a host naming Ethereum while supplying a Bitcoin path is
        // either confused or after an Ethereum signature over a Bitcoin key.
        assert_eq!(
            ETHEREUM.accepts_path(&path("m/44'/0'/0'/0/0")),
            Err(PathRejected::WrongCoinType {
                found: 0,
                expected: 60
            })
        );
        assert_eq!(
            BITCOIN.accepts_path(&path("m/44'/60'/0'/0/0")),
            Err(PathRejected::WrongCoinType {
                found: 60,
                expected: 0
            })
        );
        assert!(ETHEREUM.accepts_path(&path("m/44'/60'/0'/0/0")).is_ok());
        assert!(BITCOIN.accepts_path(&path("m/44'/0'/0'/0/0")).is_ok());
    }

    #[cfg(feature = "chain-bitcoin")]
    #[test]
    fn every_bitcoin_purpose_is_accepted() {
        // 44/49/84/86 are all Bitcoin; the check is on the coin type, not the purpose.
        for purpose in [44u32, 49, 84, 86] {
            assert!(
                BITCOIN
                    .accepts_path(&path(&format!("m/{purpose}'/0'/0'/0/0")))
                    .is_ok(),
                "purpose {purpose}"
            );
        }
    }

    #[cfg(feature = "chain-bitcoin")]
    #[test]
    fn short_and_unhardened_paths_are_refused() {
        // `m` and `m/44'` have no coin type to check. Accepting them would open the
        // hole the coin-type check closes.
        assert!(matches!(
            BITCOIN.accepts_path(&DerivationPath::MASTER),
            Err(PathRejected::TooShort { len: 0 })
        ));
        assert!(matches!(
            BITCOIN.accepts_path(&path("m/44'")),
            Err(PathRejected::TooShort { len: 1 })
        ));
        // An unhardened coin type is not a BIP-44-family path.
        assert_eq!(
            BITCOIN.accepts_path(&path("m/44'/0/0'/0/0")),
            Err(PathRejected::NotHardened)
        );
        assert_eq!(
            BITCOIN.accepts_path(&path("m/44/0'/0'/0/0")),
            Err(PathRejected::NotHardened)
        );
    }

    #[cfg(feature = "chain-solana")]
    #[test]
    fn solana_paths_are_checked_the_same_way() {
        assert!(SOLANA.accepts_path(&path("m/44'/501'/0'/0'")).is_ok());
        assert_eq!(
            SOLANA.accepts_path(&path("m/44'/60'/0'/0'")),
            Err(PathRejected::WrongCoinType {
                found: 60,
                expected: 501
            })
        );
    }

    /// Works in every feature configuration, which is the point: the per-chain tests
    /// below are feature-gated, so without this an Ethereum-only build would exercise
    /// no path checking at all — and would not even compile under `-D warnings`,
    /// because nothing would use the `path` helper.
    #[test]
    fn every_enabled_chain_accepts_its_own_path_and_rejects_a_foreign_one() {
        for c in SUPPORTED {
            let mine = path(&format!("m/44'/{}'/0'/0/0", c.coin_type));
            assert!(
                c.accepts_path(&mine).is_ok(),
                "{} rejected its own path",
                c.name
            );

            // A coin type no chain in this build owns.
            let foreign_coin = 9999u32;
            assert!(SUPPORTED.iter().all(|o| o.coin_type != foreign_coin));
            let theirs = path(&format!("m/44'/{foreign_coin}'/0'/0/0"));
            assert_eq!(
                c.accepts_path(&theirs),
                Err(PathRejected::WrongCoinType {
                    found: foreign_coin,
                    expected: c.coin_type
                }),
                "{} accepted a foreign coin type",
                c.name
            );
        }
    }

    #[test]
    fn account_prefixes_are_hardened() {
        for c in SUPPORTED {
            let p = c.account_prefix(44).unwrap();
            assert_eq!(p.len(), 2);
            assert!(p.is_fully_hardened());
            assert!(c.accepts_path(&p).is_ok());
            let steps: Vec<ChildNumber> = p.iter().collect();
            assert_eq!(steps[1].index(), c.coin_type);
            assert!(steps[1].0 >= HARDENED_OFFSET);
        }
    }

    // -- build shape ---------------------------------------------------------

    #[test]
    fn the_default_build_carries_every_known_chain() {
        // Guards against a chain being defined and then forgotten in SUPPORTED.
        #[cfg(all(
            feature = "chain-bitcoin",
            feature = "chain-ethereum",
            feature = "chain-solana"
        ))]
        {
            assert_eq!(SUPPORTED.len(), KNOWN.len());
            for id in KNOWN {
                assert!(SUPPORTED.iter().any(|c| c.id == *id), "{id:?} missing");
            }
            assert!(!is_single_chain());
        }
    }

    #[test]
    fn a_disabled_chain_is_absent_and_says_so() {
        // The point of the feature: not present, and distinguishable from unknown.
        #[cfg(not(feature = "chain-ethereum"))]
        {
            assert!(!SUPPORTED.iter().any(|c| c.id == ChainId::Ethereum));
            assert_eq!(
                resolve(ChainId::Ethereum.as_u16()),
                Err(Unsupported::NotInThisBuild {
                    id: ChainId::Ethereum
                })
            );
        }
        // ...and enabled chains resolve.
        for c in SUPPORTED {
            assert_eq!(resolve(c.id.as_u16()).unwrap().id, c.id);
        }
    }

    #[test]
    fn build_tag_names_the_chain_set() {
        let mut buf = [0u8; 32];
        let n = build_tag(&mut buf);
        let tag = core::str::from_utf8(&buf[..n]).unwrap();

        for c in SUPPORTED {
            let expect = match c.id {
                ChainId::Bitcoin => "btc",
                ChainId::Ethereum => "eth",
                ChainId::Solana => "sol",
            };
            assert!(tag.contains(expect), "{tag} missing {expect}");
        }
        assert_eq!(tag.matches('+').count(), SUPPORTED.len().saturating_sub(1));
    }

    #[test]
    fn build_tag_truncates_rather_than_overflowing() {
        let mut tiny = [0u8; 2];
        let n = build_tag(&mut tiny);
        assert!(n <= 2);
    }
}
