//! Which keys a computer may ask this device to sign with.
//!
//! A host that wants signatures over USB first asks for addresses, and the person at the
//! device chooses an account and which chains to show. What was shown is the whole of
//! what a later sign request may reach: each key the request lists has to sit **below**
//! an account-level path (`m/purpose'/coin'/account'`) that was shown, on the chain the
//! request names. A key anywhere else -- another account, another purpose, another
//! chain's coin type, the account node itself -- is refused before anything reaches the
//! screen.
//!
//! This is the pure half of that rule: which account paths a chain exposes, where its
//! first address sits, and whether a path is under an exposed account. The firmware keeps
//! the list for the life of one encrypted session and forgets it when the session ends.

use crate::bip32::{HARDENED_OFFSET, Network};
use crate::chain::{Chain, ChainId, Encoding, Format};

/// Deepest key path a host may list. Matches the USB layer's bound.
pub const MAX_DEPTH: usize = 8;

/// Levels in an account path: purpose, coin type, account.
pub const ACCOUNT_DEPTH: usize = 3;

/// A key path a host listed.
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub struct KeyPath {
    steps: [u32; MAX_DEPTH],
    depth: u8,
}

impl KeyPath {
    /// A placeholder, for filling an array.
    pub const EMPTY: Self = Self {
        steps: [0; MAX_DEPTH],
        depth: 0,
    };

    /// A path of these steps, or `None` for depth zero or past [`MAX_DEPTH`].
    pub fn new(steps: &[u32]) -> Option<Self> {
        if steps.is_empty() || steps.len() > MAX_DEPTH {
            return None;
        }
        let mut p = Self::EMPTY;
        p.steps[..steps.len()].copy_from_slice(steps);
        p.depth = steps.len() as u8;
        Some(p)
    }

    pub fn steps(&self) -> &[u32] {
        &self.steps[..self.depth as usize]
    }

    /// Whether every step is hardened -- what SLIP-0010 (Solana) can derive.
    pub fn fully_hardened(&self) -> bool {
        self.steps().iter().all(|s| s & HARDENED_OFFSET != 0)
    }
}

/// One account the person agreed to show: the chain, and `m/purpose'/coin'/account'`.
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub struct Exposed {
    pub chain: ChainId,
    pub account: [u32; ACCOUNT_DEPTH],
}

/// Whether `path` is strictly below `account`: it starts with every step of `account` and
/// goes at least one level further.
///
/// Strictly, because the account node is not a key anything pays to, and a signature
/// under it would be one the review never described.
pub fn is_under(path: &[u32], account: &[u32]) -> bool {
    path.len() > account.len() && path.starts_with(account)
}

/// Why a sign request's keys were refused.
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub enum Refused {
    /// No key listed.
    NoKeys,
    /// Key `index` is not under any account this session showed on `chain`.
    NotExposed { index: usize },
}

/// Check every key a sign request lists against what was exposed, for `chain`.
///
/// An exposure on another chain does not count, even at the same path: a Tron account and
/// an Ethereum one can share a derivation shape, and a request naming one must not reach
/// the other's approval.
pub fn check(exposed: &[Exposed], chain: ChainId, keys: &[KeyPath]) -> Result<(), Refused> {
    if keys.is_empty() {
        return Err(Refused::NoKeys);
    }
    for (index, key) in keys.iter().enumerate() {
        let ok = exposed
            .iter()
            .any(|e| e.chain == chain && is_under(key.steps(), &e.account));
        if !ok {
            return Err(Refused::NotExposed { index });
        }
    }
    Ok(())
}

/// Whether `format` is a UTXO script (an xpub to hand out) rather than an account chain's
/// single address.
pub fn is_utxo(format: &Format) -> bool {
    matches!(format.encoding, Encoding::Utxo(_))
}

/// What one of a chain's formats shows for one account.
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub struct AccountView {
    pub format: Format,
    /// `m/purpose'/coin'/account'`, the coin type following `network` where the chain
    /// has a testnet (Bitcoin), and the chain's own otherwise.
    pub account: [u32; ACCOUNT_DEPTH],
    /// The first address: `.../0/0` for a BIP-32 chain, `.../0'` for Solana (SLIP-0010
    /// is hardened all the way down, and `m/44'/501'/n'/0'` is the path Phantom and
    /// Solflare use).
    pub address: KeyPath,
}

/// The view of `format` on `chain` for account number `account`, or `None` when the
/// account number does not fit a hardened step.
pub fn view(chain: &Chain, format: Format, network: Network, account: u32) -> Option<AccountView> {
    if account >= HARDENED_OFFSET {
        return None;
    }
    let acct = [
        format.purpose | HARDENED_OFFSET,
        chain.coin_type_on(network) | HARDENED_OFFSET,
        account | HARDENED_OFFSET,
    ];
    let mut addr = [0u32; ACCOUNT_DEPTH + 2];
    addr[..ACCOUNT_DEPTH].copy_from_slice(&acct);
    let address = match format.encoding {
        Encoding::Solana => KeyPath::new(&[acct[0], acct[1], acct[2], HARDENED_OFFSET])?,
        _ => KeyPath::new(&addr)?,
    };
    Some(AccountView {
        format,
        account: acct,
        address,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::chain::BITCOIN;

    const H: u32 = HARDENED_OFFSET;

    fn key(steps: &[u32]) -> KeyPath {
        KeyPath::new(steps).unwrap()
    }

    fn btc(purpose: u32, account: u32) -> Exposed {
        Exposed {
            chain: ChainId::Bitcoin,
            account: [purpose | H, H, account | H],
        }
    }

    #[test]
    fn under_means_strictly_below() {
        let acct = [84 | H, H, H];
        assert!(is_under(&[84 | H, H, H, 0, 3], &acct));
        assert!(is_under(&[84 | H, H, H, 1], &acct));
        // The account node itself is not below it.
        assert!(!is_under(&acct, &acct));
        // Neither is a sibling account, another purpose, nor a hardened/unhardened twin.
        assert!(!is_under(&[84 | H, H, 1 | H, 0, 0], &acct));
        assert!(!is_under(&[49 | H, H, H, 0, 0], &acct));
        assert!(!is_under(&[84 | H, H, 0, 0, 0], &acct));
        assert!(!is_under(&[84 | H, H], &acct));
        assert!(!is_under(&[], &acct));
    }

    #[test]
    fn a_key_under_a_shown_account_passes() {
        let shown = [btc(84, 0), btc(86, 0)];
        let keys = [key(&[84 | H, H, H, 0, 3]), key(&[86 | H, H, H, 1, 0])];
        assert_eq!(check(&shown, ChainId::Bitcoin, &keys), Ok(()));
    }

    #[test]
    fn a_key_outside_every_shown_account_is_refused_by_position() {
        let shown = [btc(84, 0)];
        let keys = [key(&[84 | H, H, H, 0, 3]), key(&[84 | H, H, 1 | H, 0, 0])];
        assert_eq!(
            check(&shown, ChainId::Bitcoin, &keys),
            Err(Refused::NotExposed { index: 1 })
        );
    }

    #[test]
    fn nothing_shown_means_nothing_signs() {
        assert_eq!(
            check(&[], ChainId::Bitcoin, &[key(&[84 | H, H, H, 0, 0])]),
            Err(Refused::NotExposed { index: 0 })
        );
        assert_eq!(
            check(&[btc(84, 0)], ChainId::Bitcoin, &[]),
            Err(Refused::NoKeys)
        );
    }

    #[test]
    fn an_exposure_on_another_chain_does_not_count() {
        // Same path shape, different chain: refused.
        let shown = [Exposed {
            chain: ChainId::Tron,
            account: [44 | H, 60 | H, H],
        }];
        assert_eq!(
            check(
                &shown,
                ChainId::Ethereum,
                &[key(&[44 | H, 60 | H, H, 0, 0])]
            ),
            Err(Refused::NotExposed { index: 0 })
        );
    }

    #[test]
    fn bitcoin_views_follow_the_network() {
        let fmt = BITCOIN.formats[0];
        let main = view(&BITCOIN, fmt, Network::Mainnet, 5).unwrap();
        assert_eq!(main.account, [84 | H, H, 5 | H]);
        assert_eq!(main.address.steps(), &[84 | H, H, 5 | H, 0, 0]);
        let test = view(&BITCOIN, fmt, Network::Testnet, 5).unwrap();
        assert_eq!(test.account, [84 | H, 1 | H, 5 | H]);
        assert!(is_utxo(&fmt));
        // An account number that does not fit a hardened step.
        assert!(view(&BITCOIN, fmt, Network::Mainnet, H).is_none());
    }

    #[test]
    fn every_bitcoin_format_has_its_own_purpose() {
        let purposes: Vec<u32> = BITCOIN
            .formats
            .iter()
            .map(|f| view(&BITCOIN, *f, Network::Mainnet, 0).unwrap().account[0] & !H)
            .collect();
        let mut sorted = purposes.clone();
        sorted.sort_unstable();
        assert_eq!(sorted, vec![44, 49, 84, 86]);
    }

    #[cfg(feature = "multichain")]
    #[test]
    fn account_chains_have_one_address_at_the_path_their_wallets_use() {
        use crate::chain::{DOGECOIN, ETHEREUM, SOLANA, TRON};
        let sol = view(&SOLANA, SOLANA.formats[0], Network::Testnet, 2).unwrap();
        assert_eq!(sol.account, [44 | H, 501 | H, 2 | H]);
        assert_eq!(sol.address.steps(), &[44 | H, 501 | H, 2 | H, H]);
        assert!(sol.address.fully_hardened());
        assert!(!is_utxo(&SOLANA.formats[0]));

        // Testnet moves Bitcoin only.
        let eth = view(&ETHEREUM, ETHEREUM.formats[0], Network::Testnet, 0).unwrap();
        assert_eq!(eth.address.steps(), &[44 | H, 60 | H, H, 0, 0]);
        let trx = view(&TRON, TRON.formats[0], Network::Mainnet, 1).unwrap();
        assert_eq!(trx.account, [44 | H, 195 | H, 1 | H]);

        // A UTXO altcoin gets exactly its registry's formats: Dogecoin is legacy only.
        assert_eq!(DOGECOIN.formats.len(), 1);
        let doge = view(&DOGECOIN, DOGECOIN.formats[0], Network::Mainnet, 0).unwrap();
        assert_eq!(doge.account, [44 | H, 3 | H, H]);
        assert!(is_utxo(&DOGECOIN.formats[0]));
    }
}
