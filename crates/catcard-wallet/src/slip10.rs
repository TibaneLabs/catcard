//! SLIP-0010 key derivation over ed25519: Solana's, and most ed25519 chains'.
//!
//! BIP-32's shape with a different key and none of its public derivation: the master is
//! `HMAC-SHA512("ed25519 seed", seed)`, and a child is
//! `HMAC-SHA512(chain_code, 0x00 || key || ser32(index | 2^31))`, left half the key, right
//! half the next chain code. **Every step is hardened** -- ed25519 has no way to derive a
//! child public key from a parent public key -- so an index given here is always hardened,
//! and there is no watch-only account key to cache: each address needs the seed.
//!
//! Source: SLIP-0010, satoshilabs/slips `slip-0010.md`, "Master key generation" and
//! "Private parent key -> private child key" for ed25519 [C]; checked against its test
//! vector 1 below.

use purecrypto::hash::HmacSha512;
use zeroize::{Zeroize, ZeroizeOnDrop};

/// The HMAC key the master is made under, for ed25519.
const CURVE_KEY: &[u8] = b"ed25519 seed";

/// A SLIP-0010 ed25519 node: the 32-byte private key (which ed25519 calls the *seed* of
/// its keypair) and the chain code. Wiped on drop.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct Node {
    key: [u8; 32],
    chain_code: [u8; 32],
}

impl Node {
    /// The private key: what `ed25519::public_from_seed` takes.
    pub fn secret(&self) -> &[u8; 32] {
        &self.key
    }

    pub fn chain_code(&self) -> &[u8; 32] {
        &self.chain_code
    }

    /// The ed25519 public key for this node's key.
    pub fn public_key(&self, _kw: &crate::KeyWork) -> [u8; 32] {
        outscript::crypto::ed25519::public_from_seed(&self.key)
    }

    fn from_mac(mac: HmacSha512) -> Self {
        let mut out = mac.finalize();
        let bytes = out.as_slice();
        let mut node = Node {
            key: [0; 32],
            chain_code: [0; 32],
        };
        node.key.copy_from_slice(&bytes[..32]);
        node.chain_code.copy_from_slice(&bytes[32..64]);
        out.zeroize();
        node
    }

    /// The master node for a BIP-39 seed.
    pub fn master(seed: &[u8], _kw: &crate::KeyWork) -> Self {
        let mut mac = HmacSha512::new(CURVE_KEY);
        mac.update(seed);
        Self::from_mac(mac)
    }

    /// The hardened child `index` -- `index` below 2^31; the hardening bit is added here.
    pub fn child(&self, index: u32, _kw: &crate::KeyWork) -> Option<Self> {
        if index >= crate::bip32::HARDENED_OFFSET {
            return None;
        }
        let mut mac = HmacSha512::new(&self.chain_code);
        mac.update(&[0]);
        mac.update(&self.key);
        mac.update(&(index | crate::bip32::HARDENED_OFFSET).to_be_bytes());
        Some(Self::from_mac(mac))
    }
}

/// The node at `path` below `seed`'s master, every step hardened: `[44, 501, 0, 0]` is
/// `m/44'/501'/0'/0'`.
pub fn derive(seed: &[u8], path: &[u32], kw: &crate::KeyWork) -> Option<Node> {
    let mut node = Node::master(seed, kw);
    for &index in path {
        node = node.child(index, kw)?;
    }
    Some(node)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::KeyWork;

    fn kw() -> KeyWork {
        // SAFETY: a host test; there is nothing to mask and nothing to time.
        unsafe { KeyWork::assume_masked() }
    }

    fn hex(s: &str) -> Vec<u8> {
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }

    /// SLIP-0010 test vector 1 for ed25519, seed `000102030405060708090a0b0c0d0e0f`:
    /// the master and `m/0'`.
    #[test]
    fn slip10_test_vector_1() {
        let seed = hex("000102030405060708090a0b0c0d0e0f");
        let m = Node::master(&seed, &kw());
        assert_eq!(
            m.secret().to_vec(),
            hex("2b4be7f19ee27bbf30c667b642d5f4aa69fd169872f8fc3059c08ebae2eb19e7")
        );
        assert_eq!(
            m.chain_code().to_vec(),
            hex("90046a93de5380a72b5e45010748567d5ea02bbf6522f979e05c0d8d8ca9fffb")
        );
        let c = m.child(0, &kw()).unwrap();
        assert_eq!(
            c.secret().to_vec(),
            hex("68e0fe46dfb67e368c75379acec591dad19df3cde26e63b93a8e704f1dade7a3")
        );
        assert_eq!(
            c.chain_code().to_vec(),
            hex("8b59aa11380b624e81507a27fedda59fea6d0b779a778918a2fd3590e16e9c69")
        );
    }

    /// There is no unhardened child: an index with the bit already set is refused
    /// rather than silently hardened twice.
    #[test]
    fn indices_are_below_the_hardening_bit() {
        let m = Node::master(&[0u8; 16], &kw());
        assert!(m.child(crate::bip32::HARDENED_OFFSET, &kw()).is_none());
        assert!(derive(&[0u8; 16], &[44, 0x8000_0000], &kw()).is_none());
    }
}
