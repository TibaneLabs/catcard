//! Addresses on every chain in the registry, from the key they pay to.
//!
//! One function per curve, and the chain's [`Encoding`] decides the rest. Bitcoin goes
//! through [`crate::address::encode`], which it always has; the other Bitcoin-family
//! chains build the same script and let `outscript` write it in their own version bytes
//! and prefix; Ethereum and Tron hash the uncompressed key; Solana is the ed25519 key.
//!
//! What a chain *can* be asked for is its [`Chain::formats`] list, not this module: an
//! encoding a chain has no entry for is refused here too ([`Error::NotThisChain`]), so a
//! caller that skipped the list still cannot get a Bitcoin Cash segwit address.

use super::{Chain, ChainId, Encoding};
use crate::address::{AddressKind, PUBKEY_LEN};

/// The longest address any encoding here writes: a CashAddr with its `bitcoincash:`
/// prefix, 54 bytes, comfortably under this.
pub const MAX_LEN: usize = 96;

/// Why no address came out.
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub enum Error {
    /// `out` is too short. [`MAX_LEN`] always suffices.
    BufferTooSmall,
    /// Not a point on the curve.
    InvalidKey,
    /// The chain has no such format, or it needs the other curve's key.
    NotThisChain,
    /// The encoder refused, which for valid input is a bug to report.
    Encoding,
}

/// The name `outscript` gives a Bitcoin-family script kind.
fn script_format(kind: AddressKind) -> &'static str {
    match kind {
        AddressKind::P2pkh => "p2pkh",
        AddressKind::P2shP2wpkh => "p2sh",
        AddressKind::P2wpkh => "p2wpkh",
        AddressKind::P2tr => "p2tr",
    }
}

/// The address `pubkey`, a compressed secp256k1 key, has on `chain` as `encoding`.
///
/// `network` selects Bitcoin's mainnet/testnet/regtest parameters; it is ignored for every
/// other chain, whose network is fixed by the chain itself. A caller that only ever means
/// mainnet passes [`crate::bip32::Network::Mainnet`].
pub fn from_secp256k1(
    chain: &Chain,
    encoding: Encoding,
    network: crate::bip32::Network,
    pubkey: &[u8; PUBKEY_LEN],
    out: &mut [u8],
) -> Result<usize, Error> {
    if !chain.formats.iter().any(|f| f.encoding == encoding) {
        return Err(Error::NotThisChain);
    }
    match encoding {
        Encoding::Utxo(kind) if chain.id == ChainId::Bitcoin => {
            crate::address::encode(kind, network, pubkey, out).map_err(|e| match e {
                crate::address::Error::InvalidKey => Error::InvalidKey,
                crate::address::Error::BufferTooSmall { .. } => Error::BufferTooSmall,
                _ => Error::Encoding,
            })
        }
        Encoding::Utxo(kind) => {
            // The same script Bitcoin would pay to, which `script_pubkey` also checks
            // the key for; only the way it is written differs between chains.
            let mut script = [0u8; 40];
            let n = crate::address::script_pubkey(kind, pubkey, &mut script)
                .map_err(|_| Error::InvalidKey)?;
            outscript::address::encode_address_to_slice(
                script_format(kind),
                &script[..n],
                chain.network,
                out,
            )
            .map_err(|e| match e {
                outscript::Error::BufferTooSmall => Error::BufferTooSmall,
                _ => Error::Encoding,
            })
        }
        #[cfg(feature = "multichain")]
        Encoding::Evm => {
            let hash = evm_hash(pubkey)?;
            outscript::address::eip55_to_slice(&hash, out).ok_or(Error::BufferTooSmall)
        }
        #[cfg(feature = "multichain")]
        Encoding::Tron => {
            let hash = evm_hash(pubkey)?;
            outscript::address::encode_base58_addr_to_slice(0x41, &hash, out)
                .map_err(|_| Error::BufferTooSmall)
        }
        _ => Err(Error::NotThisChain),
    }
}

/// The address `pubkey`, an ed25519 key, has on Solana: the key itself, base58.
#[cfg(feature = "multichain")]
pub fn from_ed25519(chain: &Chain, pubkey: &[u8; 32], out: &mut [u8]) -> Result<usize, Error> {
    if !chain.formats.iter().any(|f| f.encoding == Encoding::Solana) {
        return Err(Error::NotThisChain);
    }
    if !outscript::crypto::ed25519::is_on_curve(pubkey) {
        return Err(Error::InvalidKey);
    }
    outscript::base58::encode_to_slice(pubkey, out).map_err(|_| Error::BufferTooSmall)
}

/// Ethereum's address hash: Keccak-256 of the uncompressed key without its `04` prefix,
/// last twenty bytes. Tron uses the same twenty.
#[cfg(feature = "multichain")]
fn evm_hash(pubkey: &[u8; PUBKEY_LEN]) -> Result<[u8; 20], Error> {
    let point = outscript::crypto::secp256k1::SecpPublicKey::from_sec1(pubkey)
        .map_err(|_| Error::InvalidKey)?;
    let full = point.serialize_uncompressed();
    let digest = outscript::hash::keccak256_once(&full[1..]);
    let mut out = [0u8; 20];
    out.copy_from_slice(&digest[12..]);
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::KeyWork;
    use crate::bip32::{DerivationPath, ExtendedPrivKey, Network};
    use crate::bip39::Mnemonic;
    use core::str::FromStr;

    fn kw() -> KeyWork {
        // SAFETY: a host test; there is nothing to mask and nothing to time.
        unsafe { KeyWork::assume_masked() }
    }

    /// The mnemonic every wallet's published vectors use.
    const ABANDON: &str = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";

    fn seed() -> [u8; 64] {
        let m = Mnemonic::parse(ABANDON, &kw()).unwrap();
        let mut s = [0u8; 64];
        m.to_seed("", &mut s, &kw()).unwrap();
        s
    }

    fn secp_at(path: &str) -> [u8; PUBKEY_LEN] {
        let master = ExtendedPrivKey::from_seed(&seed(), Network::Mainnet, &kw()).unwrap();
        let key = master
            .derive_path(&DerivationPath::from_str(path).unwrap(), &kw())
            .unwrap();
        key.public_key(&kw())
    }

    fn addr(chain: &Chain, encoding: Encoding, path: &str) -> String {
        let mut out = [0u8; MAX_LEN];
        let n = from_secp256k1(chain, encoding, crate::bip32::Network::Mainnet, &secp_at(path), &mut out).unwrap();
        core::str::from_utf8(&out[..n]).unwrap().to_owned()
    }

    /// BIP-84's own test vector, through the chain path: Bitcoin is unchanged by it.
    #[test]
    fn bitcoin_matches_bip84() {
        assert_eq!(
            addr(
                &super::super::BITCOIN,
                Encoding::Utxo(AddressKind::P2wpkh),
                "m/84'/0'/0'/0/0"
            ),
            "bc1qcr8te4kr609gcawutmrza0j4xv80jy8z306fyu"
        );
    }

    /// The network reaches Bitcoin's address encoding: the same key on testnet and
    /// regtest wears `tb` and `bcrt`, while other chains ignore it.
    #[test]
    fn bitcoin_addresses_follow_the_network() {
        let key = secp_at("m/84'/1'/0'/0/0");
        let enc = |net| {
            let mut out = [0u8; MAX_LEN];
            let n = from_secp256k1(
                &super::super::BITCOIN,
                Encoding::Utxo(AddressKind::P2wpkh),
                net,
                &key,
                &mut out,
            )
            .unwrap();
            core::str::from_utf8(&out[..n]).unwrap().to_owned()
        };
        assert!(enc(crate::bip32::Network::Testnet).starts_with("tb1"));
        assert!(enc(crate::bip32::Network::Regtest).starts_with("bcrt1"));
    }

    /// A format the chain does not list is refused, even if the encoder could write it.
    #[test]
    fn a_format_a_chain_does_not_have_is_refused() {
        let key = secp_at("m/44'/0'/0'/0/0");
        let mut out = [0u8; MAX_LEN];
        assert_eq!(
            from_secp256k1(&super::super::BITCOIN, Encoding::Evm, crate::bip32::Network::Mainnet, &key, &mut out),
            Err(Error::NotThisChain)
        );
    }

    #[cfg(feature = "multichain")]
    mod multichain {
        use super::super::super::*;
        use super::*;

        #[test]
        fn ethereum_matches_the_published_vector() {
            assert_eq!(
                addr(&ETHEREUM, Encoding::Evm, "m/44'/60'/0'/0/0"),
                "0x9858EfFD232B4033E47d90003D41EC34EcaEda94"
            );
        }

        #[test]
        fn tron_matches_the_published_vector() {
            assert_eq!(
                addr(&TRON, Encoding::Tron, "m/44'/195'/0'/0/0"),
                "TUEZSdKsoDHQMeZwihtdoBiN46zxhGWYdH"
            );
        }

        #[test]
        fn litecoin_matches_the_published_vector() {
            assert_eq!(
                addr(
                    &LITECOIN,
                    Encoding::Utxo(AddressKind::P2wpkh),
                    "m/84'/2'/0'/0/0"
                ),
                "ltc1qjmxnz78nmc8nq77wuxh25n2es7rzm5c2rkk4wh"
            );
        }

        #[test]
        fn dogecoin_matches_the_published_vector() {
            assert_eq!(
                addr(
                    &DOGECOIN,
                    Encoding::Utxo(AddressKind::P2pkh),
                    "m/44'/3'/0'/0/0"
                ),
                "DBus3bamQjgJULBJtYXpEzDWQRwF5iwxgC"
            );
        }

        #[test]
        fn bitcoin_cash_matches_the_published_vector() {
            assert_eq!(
                addr(
                    &BITCOIN_CASH,
                    Encoding::Utxo(AddressKind::P2pkh),
                    "m/44'/145'/0'/0/0"
                ),
                "bitcoincash:qqyx49mu0kkn9ftfj6hje6g2wfer34yfnq5tahq3q6"
            );
        }

        /// Namecoin in its own version bytes and prefix. No published vector for this
        /// mnemonic that I could check, so this pins what distinguishes it from Bitcoin:
        /// `N`/`M` legacy (version `0x34`), `nc1q` native segwit.
        #[test]
        fn namecoin_writes_its_own_prefixes() {
            let legacy = addr(
                &NAMECOIN,
                Encoding::Utxo(AddressKind::P2pkh),
                "m/44'/7'/0'/0/0",
            );
            assert!(
                legacy.starts_with('N') || legacy.starts_with('M'),
                "{legacy}"
            );
            let native = addr(
                &NAMECOIN,
                Encoding::Utxo(AddressKind::P2wpkh),
                "m/84'/7'/0'/0/0",
            );
            assert!(native.starts_with("nc1q"), "{native}");
        }

        /// No segwit on Bitcoin Cash, whatever a caller asks for.
        #[test]
        fn bitcoin_cash_refuses_segwit() {
            let key = secp_at("m/84'/145'/0'/0/0");
            let mut out = [0u8; MAX_LEN];
            assert_eq!(
                from_secp256k1(
                    &BITCOIN_CASH,
                    Encoding::Utxo(AddressKind::P2wpkh),
                    crate::bip32::Network::Mainnet,
                    &key,
                    &mut out
                ),
                Err(Error::NotThisChain)
            );
        }

        /// Solana's well-known first address for this mnemonic, through SLIP-10 at
        /// `m/44'/501'/0'/0'`.
        #[test]
        fn solana_matches_the_published_vector() {
            let key = crate::slip10::derive(&seed(), &[44, 501, 0, 0], &kw()).unwrap();
            let public = outscript::crypto::ed25519::public_from_seed(key.secret());
            let mut out = [0u8; MAX_LEN];
            let n = from_ed25519(&SOLANA, &public, &mut out).unwrap();
            assert_eq!(
                core::str::from_utf8(&out[..n]).unwrap(),
                "HAgk14JpMQLgt6rVgv7cBQFJWFto5Dqxi472uT3DKpqk"
            );
        }

        /// Every format of every chain writes something that fits, from one key.
        #[test]
        fn every_format_writes_within_max_len() {
            let key = secp_at("m/44'/0'/0'/0/0");
            for c in SUPPORTED {
                for f in c.formats {
                    if f.encoding == Encoding::Solana {
                        continue;
                    }
                    let mut out = [0u8; MAX_LEN];
                    let n = from_secp256k1(c, f.encoding, crate::bip32::Network::Mainnet, &key, &mut out)
                        .unwrap_or_else(|e| panic!("{} {}: {e:?}", c.name, f.label));
                    assert!(n > 0 && n <= MAX_LEN, "{} {}", c.name, f.label);
                }
            }
        }
    }
}
