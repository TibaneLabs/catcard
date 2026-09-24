//! BIP-85: children of the seed, for other things.
//!
//! One seed, backed up once, and everything else derived from it: the words for another
//! wallet, a key for Bitcoin Core, a password for a website. Each child is a fully hardened
//! path under `m/83696968'`, so no child reveals anything about the seed or about its
//! siblings, and any of them can be recreated from the same words years later.
//!
//! The construction is one line: take the private key `k` at the application's path, and
//!
//! ```text
//! entropy = HMAC-SHA512(key = "bip-entropy-from-k", msg = k)
//! ```
//!
//! then each application slices that 64-byte entropy its own way.
//!
//! What this does **not** do is write anything down. A child is derived, shown or exported,
//! and forgotten; the seed is the only thing that needs keeping.
//!
//! Source: BIP-85, including its test vectors -- a public standard [C].

use purecrypto::hash::HmacSha512;
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

use crate::KeyWork;
use crate::bip32::{ChildNumber, ExtendedPrivKey};

/// The HMAC key that separates BIP-85 entropy from everything else. Source: BIP-85 [C]
pub const HMAC_KEY: &[u8] = b"bip-entropy-from-k";

/// The purpose every BIP-85 path starts with: `83696968'`.
pub const PURPOSE: u32 = 83_696_968;

/// Application numbers. Source: BIP-85 [C]
pub mod app {
    /// BIP-39 words.
    pub const BIP39: u32 = 39;
    /// A private key as WIF, for a Bitcoin Core `hdseed`.
    pub const WIF: u32 = 2;
    /// An extended private key.
    pub const XPRV: u32 = 32;
    /// Raw bytes as hex.
    pub const HEX: u32 = 128_169;
    /// A base64 password.
    pub const PWD_BASE64: u32 = 707_764;
}

/// English, the only BIP-39 language here. Source: BIP-85 language codes [C]
pub const LANG_ENGLISH: u32 = 0;

/// The 64 bytes an application slices. Zeroized when dropped.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct Entropy([u8; 64]);

impl Entropy {
    pub fn as_bytes(&self) -> &[u8; 64] {
        &self.0
    }
}

/// Why a child could not be derived.
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub enum Error {
    /// A path element outside what BIP-32 can harden, or an application parameter outside
    /// what the application allows.
    BadParameter,
    /// Derivation failed, or the derived key was not a usable scalar.
    Derivation,
    /// The output buffer was too small.
    BufferTooSmall,
}

/// The entropy for a path under `m/83696968'`.
///
/// `steps` are the elements after the purpose, each of which is hardened here: for words
/// that is `[language, word_count, index]`, for a password `[length, index]`.
pub fn entropy(master: &ExtendedPrivKey, steps: &[u32], kw: &KeyWork) -> Result<Entropy, Error> {
    let mut here = master
        .derive_child(
            ChildNumber::hardened(PURPOSE).map_err(|_| Error::BadParameter)?,
            kw,
        )
        .map_err(|_| Error::Derivation)?;
    for &step in steps {
        let child = ChildNumber::hardened(step).map_err(|_| Error::BadParameter)?;
        here = here
            .derive_child(child, kw)
            .map_err(|_| Error::Derivation)?;
    }
    let mut mac = HmacSha512::new(HMAC_KEY);
    mac.update(here.secret_bytes());
    // The HMAC output *is* the child secret; the copy left here is wiped on drop.
    let full = Zeroizing::new(mac.finalize());
    let mut out = [0u8; 64];
    out.copy_from_slice(&full[..]);
    Ok(Entropy(out))
}

/// The BIP-39 entropy for `words` words at `index`: `m/83696968'/39'/0'/{words}'/{index}'`.
///
/// 12, 18 and 24 words take the first 16, 24 and 32 bytes. Other counts are refused: the
/// stash format cannot hold them and BIP-85's own table does not define them here.
pub fn words_entropy(
    master: &ExtendedPrivKey,
    words: u32,
    index: u32,
    kw: &KeyWork,
) -> Result<(Entropy, usize), Error> {
    // Every length BIP-39 defines, not only the three the application's text names.
    //
    // BIP-85 spells out 12, 18 and 24, but the derivation is mechanical: the word count
    // goes in the path and the entropy is the first `ENT/8` bytes of the HMAC, so 15 and
    // 21 follow without inventing anything and any implementation that accepts them
    // reproduces the same words.
    //
    // **They are less portable all the same.** Most wallets offer the three the spec
    // names, so a 15- or 21-word child may be awkward to reproduce elsewhere -- which
    // matters for a key whose only backup is the path to it.
    //
    // **The secret stash cannot hold all five.** Its marker byte spells 16, 24 and 32
    // bytes only (`catcard_callgate::pin::BIP39_ENTROPY_LENS`), so a 15- or 21-word
    // child can be *worked in* -- derived afresh each time from the root and the path --
    // but not written to the secure element as a seed of its own.
    //
    // Source: BIP-85 §"BIP39" [C]; the lengths from BIP-39 §"Generating the mnemonic" [C]
    let len = match words {
        12 => 16,
        15 => 20,
        18 => 24,
        21 => 28,
        24 => 32,
        _ => return Err(Error::BadParameter),
    };
    let e = entropy(master, &[app::BIP39, LANG_ENGLISH, words, index], kw)?;
    Ok((e, len))
}

/// The extended private key at `m/83696968'/32'/{index}'`.
///
/// **The halves are the other way round from BIP-32**: the first 32 bytes of the entropy
/// are the chain code and the second 32 the key. Depth, child number and parent fingerprint
/// are all zero, so the result is a root key in its own right.
pub fn xprv(master: &ExtendedPrivKey, index: u32, kw: &KeyWork) -> Result<ExtendedPrivKey, Error> {
    let e = entropy(master, &[app::XPRV, index], kw)?;
    let mut chain_code = [0u8; 32];
    let mut secret = [0u8; 32];
    chain_code.copy_from_slice(&e.as_bytes()[..32]);
    secret.copy_from_slice(&e.as_bytes()[32..]);
    // A key outside 1..n-1 is not usable; BIP-85 says to hard fail rather than fix it up,
    // so the caller moves to the next index.
    if !crate::bip32::is_valid_secret(&secret) {
        secret.zeroize();
        return Err(Error::Derivation);
    }
    let child = ExtendedPrivKey::root_from_parts(master.network, chain_code, secret, kw);
    secret.zeroize();
    child.map_err(|_| Error::Derivation)
}

/// The private key at `m/83696968'/2'/{index}'`, as bytes: the most significant 32 of the
/// entropy. The caller wipes it.
///
/// A key outside `1..n-1` is refused, as for [`xprv`], so the caller moves to the next
/// index rather than holding something no wallet can use.
pub fn wif_secret(master: &ExtendedPrivKey, index: u32, kw: &KeyWork) -> Result<[u8; 32], Error> {
    let e = entropy(master, &[app::WIF, index], kw)?;
    let mut secret = [0u8; 32];
    secret.copy_from_slice(&e.as_bytes()[..32]);
    if !crate::bip32::is_valid_secret(&secret) {
        secret.zeroize();
        return Err(Error::Derivation);
    }
    Ok(secret)
}

/// The same key written as WIF, for a Bitcoin Core `hdseed`. Returns the length written.
pub fn wif(
    master: &ExtendedPrivKey,
    index: u32,
    out: &mut [u8],
    kw: &KeyWork,
) -> Result<usize, Error> {
    let mut secret = wif_secret(master, index, kw)?;
    let n = encode_wif(&secret, out, kw);
    secret.zeroize();
    n
}

/// A mainnet private key, used compressed, as WIF. Returns the length written.
///
/// Base58 over the key itself, so it is private-key work like the `xprv` encoding: the
/// digits it divides through are the scalar's, and it runs inside the masked region.
pub fn encode_wif(secret: &[u8; 32], out: &mut [u8], _kw: &KeyWork) -> Result<usize, Error> {
    let mut payload = [0u8; 34];
    payload[0] = 0x80; // mainnet private key
    payload[1..33].copy_from_slice(secret);
    payload[33] = 0x01; // the key is used compressed
    let n = crate::encoding::base58::encode_check(&payload, out).map_err(|_| Error::BufferTooSmall);
    payload.zeroize();
    n
}

/// `num_bytes` of entropy at `m/83696968'/128169'/{num_bytes}'/{index}'`, as hex.
///
/// 16 to 64 bytes, as the application defines; the entropy is truncated, keeping the most
/// significant bytes.
pub fn hex(
    master: &ExtendedPrivKey,
    num_bytes: u32,
    index: u32,
    out: &mut [u8],
    kw: &KeyWork,
) -> Result<usize, Error> {
    if !(16..=64).contains(&num_bytes) {
        return Err(Error::BadParameter);
    }
    let need = num_bytes as usize * 2;
    if out.len() < need {
        return Err(Error::BufferTooSmall);
    }
    let e = entropy(master, &[app::HEX, num_bytes, index], kw)?;
    const HEX: &[u8; 16] = b"0123456789abcdef";
    for (i, b) in e.as_bytes()[..num_bytes as usize].iter().enumerate() {
        out[i * 2] = HEX[(b >> 4) as usize];
        out[i * 2 + 1] = HEX[(b & 0xF) as usize];
    }
    Ok(need)
}

/// A password of `length` characters at `m/83696968'/707764'/{length}'/{index}'`.
///
/// Base64 of all 64 entropy bytes, cut to `length`. 20 to 86 characters, which is where the
/// base64 of 64 bytes ends before its padding.
pub fn password(
    master: &ExtendedPrivKey,
    length: u32,
    index: u32,
    out: &mut [u8],
    kw: &KeyWork,
) -> Result<usize, Error> {
    if !(20..=86).contains(&length) {
        return Err(Error::BadParameter);
    }
    let length = length as usize;
    if out.len() < length {
        return Err(Error::BufferTooSmall);
    }
    let e = entropy(master, &[app::PWD_BASE64, length as u32, index], kw)?;
    let mut full = [0u8; 88];
    let n = outscript::base64::encode_to_slice(e.as_bytes(), &mut full)
        .map_err(|_| Error::BufferTooSmall)?;
    if n < length {
        full.zeroize();
        return Err(Error::BadParameter);
    }
    out[..length].copy_from_slice(&full[..length]);
    full.zeroize();
    Ok(length)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bip32::Network;
    use crate::bip39::Mnemonic;

    /// BIP-85's test vectors all start from this root key.
    const ROOT: &str = "xprv9s21ZrQH143K2LBWUUQRFXhucrQqBpKdRRxNVq2zBqsx8HVqFk2uYo8kmbaLLHRdqtQpUm98uKfu3vca1LqdGhUtyoFnCNkfmXRyPXLjbKb";

    fn root() -> ExtendedPrivKey {
        ExtendedPrivKey::from_base58(ROOT, &KeyWork::host()).unwrap()
    }

    fn hex_of(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{b:02x}")).collect()
    }

    #[test]
    fn the_two_basic_vectors_match() {
        let kw = KeyWork::host();
        // m/83696968'/0'/0'
        let e = entropy(&root(), &[0, 0], &kw).unwrap();
        assert_eq!(
            hex_of(e.as_bytes()),
            "efecfbccffea313214232d29e71563d941229afb4338c21f9517c41aaa0d16f0\
             0b83d2a09ef747e7a64e8e2bd5a14869e693da66ce94ac2da570ab7ee48618f7"
        );
        // m/83696968'/0'/1'
        let e = entropy(&root(), &[0, 1], &kw).unwrap();
        assert_eq!(
            hex_of(e.as_bytes()),
            "70c6e3e8ebee8dc4c0dbba66076819bb8c09672527c4277ca8729532ad711872\
             218f826919f6b67218adde99018a6df9095ab2b58d803b5b93ec9802085a690e"
        );
    }

    #[test]
    fn the_bip39_vectors_give_the_published_words() {
        let kw = KeyWork::host();
        for (words, ent, phrase) in [
            (
                12,
                "6250b68daf746d12a24d58b4787a714b",
                "girl mad pet galaxy egg matter matrix prison refuse sense ordinary nose",
            ),
            (
                18,
                "938033ed8b12698449d4bbca3c853c66b293ea1b1ce9d9dc",
                "near account window bike charge season chef number sketch tomorrow excuse sniff circle vital hockey outdoor supply token",
            ),
            (
                24,
                "ae131e2312cdc61331542efe0d1077bac5ea803adf24b313a4f0e48e9c51f37f",
                "puppy ocean match cereal symbol another shed magic wrap hammer bulb intact gadget divorce twin tonight reason outdoor destroy simple truth cigar social volcano",
            ),
        ] {
            let (e, len) = words_entropy(&root(), words, 0, &kw).unwrap();
            assert_eq!(hex_of(&e.as_bytes()[..len]), ent, "{words} words");
            // And that entropy is the mnemonic BIP-85 publishes.
            let m = Mnemonic::from_entropy(&e.as_bytes()[..len], &kw).unwrap();
            let mut out = [0u8; 256];
            let n = m.render(&mut out);
            assert_eq!(core::str::from_utf8(&out[..n]).unwrap(), phrase);
        }
        // 15 and 21 derive too -- see `words_entropy`. What is refused is a count
        // BIP-39 does not define, rather than one this crate merely did not offer.
        assert!(words_entropy(&root(), 15, 0, &kw).is_ok());
        assert_eq!(
            words_entropy(&root(), 13, 0, &kw).err(),
            Some(Error::BadParameter)
        );
    }

    #[test]
    fn the_wif_vector_matches() {
        let kw = KeyWork::host();
        let mut out = [0u8; 64];
        let n = wif(&root(), 0, &mut out, &kw).unwrap();
        assert_eq!(
            core::str::from_utf8(&out[..n]).unwrap(),
            "Kzyv4uF39d4Jrw2W7UryTHwZr1zQVNk4dAFyqE6BuMrMh1Za7uhp"
        );
    }

    /// The bytes a WIF child is loaded from are the key the vector's WIF encodes, and
    /// their public key is the one an xprv holding the same scalar would give.
    #[test]
    fn the_wif_secret_is_the_key_the_vector_names() {
        let kw = KeyWork::host();
        let secret = wif_secret(&root(), 0, &kw).unwrap();
        let mut out = [0u8; 64];
        let n = encode_wif(&secret, &mut out, &kw).unwrap();
        assert_eq!(
            core::str::from_utf8(&out[..n]).unwrap(),
            "Kzyv4uF39d4Jrw2W7UryTHwZr1zQVNk4dAFyqE6BuMrMh1Za7uhp"
        );
        let as_xprv =
            ExtendedPrivKey::root_from_parts(Network::Mainnet, [7; 32], secret, &kw).unwrap();
        assert_eq!(
            crate::bip32::public_key_of(&secret, &kw),
            Some(as_xprv.public_key(&kw))
        );
        assert_eq!(crate::bip32::public_key_of(&[0; 32], &kw), None);
    }

    #[test]
    fn the_xprv_vector_matches_including_the_swapped_halves() {
        let kw = KeyWork::host();
        let child = xprv(&root(), 0, &kw).unwrap();
        assert_eq!(
            child.to_base58(&kw).as_str(),
            "xprv9s21ZrQH143K2srSbCSg4m4kLvPMzcWydgmKEnMmoZUurYuBuYG46c6P71UGXMzmriLzCCBvKQWBUv3vPB3m1SATMhp3uEjXHJ42jFg7myX"
        );
        // The entropy's halves are the other way round from BIP-32: the *second* 32 bytes
        // are the key, so using the first would give a different xprv entirely.
        let e = entropy(&root(), &[app::XPRV, 0], &kw).unwrap();
        assert_eq!(child.secret_bytes()[..], e.as_bytes()[32..]);
    }

    #[test]
    fn the_hex_and_password_vectors_match() {
        let kw = KeyWork::host();
        let mut out = [0u8; 128];
        let n = hex(&root(), 64, 0, &mut out, &kw).unwrap();
        assert_eq!(
            core::str::from_utf8(&out[..n]).unwrap(),
            "492db4698cf3b73a5a24998aa3e9d7fa96275d85724a91e71aa2d645442f8785\
             55d078fd1f1f67e368976f04137b1f7a0d19232136ca50c44614af72b5582a5c"
        );
        let mut pwd = [0u8; 86];
        let n = password(&root(), 21, 0, &mut pwd, &kw).unwrap();
        assert_eq!(
            core::str::from_utf8(&pwd[..n]).unwrap(),
            "dKLoepugzdVJvdL56ogNV"
        );
    }

    #[test]
    fn parameters_outside_the_applications_ranges_are_refused() {
        let kw = KeyWork::host();
        let mut out = [0u8; 128];
        assert_eq!(
            hex(&root(), 15, 0, &mut out, &kw).err(),
            Some(Error::BadParameter)
        );
        assert_eq!(
            hex(&root(), 65, 0, &mut out, &kw).err(),
            Some(Error::BadParameter)
        );
        assert_eq!(
            password(&root(), 19, 0, &mut out, &kw).err(),
            Some(Error::BadParameter)
        );
        assert_eq!(
            password(&root(), 87, 0, &mut out, &kw).err(),
            Some(Error::BadParameter)
        );
        // A buffer that cannot hold the answer is an error, not a truncation.
        assert_eq!(
            hex(&root(), 32, 0, &mut [0u8; 8], &kw).err(),
            Some(Error::BufferTooSmall)
        );
    }

    #[test]
    fn every_child_is_different_and_the_index_matters() {
        let kw = KeyWork::host();
        let a = entropy(&root(), &[app::HEX, 32, 0], &kw).unwrap();
        let b = entropy(&root(), &[app::HEX, 32, 1], &kw).unwrap();
        let c = entropy(&root(), &[app::WIF, 0], &kw).unwrap();
        assert_ne!(a.as_bytes(), b.as_bytes());
        assert_ne!(a.as_bytes(), c.as_bytes());
        // And a different seed gives different children.
        let other = ExtendedPrivKey::from_seed(&[7u8; 32], Network::Mainnet, &kw).unwrap();
        let d = entropy(&other, &[app::HEX, 32, 0], &kw).unwrap();
        assert_ne!(a.as_bytes(), d.as_bytes());
    }
}

#[cfg(test)]
mod words_len_tests {
    use super::*;
    use crate::bip39::{Mnemonic, words_for_entropy};

    /// Every word count BIP-39 defines derives, and gives that many words.
    ///
    /// The spec's own text names 12, 18 and 24; the other two fall out of the same
    /// arithmetic and are worth having rather than refusing.
    #[test]
    fn the_five_bip39_lengths_all_derive() {
        let kw = crate::KeyWork::host();
        let master = crate::bip32::ExtendedPrivKey::from_seed(
            &[7u8; 32],
            crate::bip32::Network::Mainnet,
            &kw,
        )
        .unwrap();
        for (words, ent) in [(12, 16), (15, 20), (18, 24), (21, 28), (24, 32)] {
            let (e, len) = words_entropy(&master, words, 0, &kw).expect("derives");
            assert_eq!(len, ent, "{words} words");
            assert_eq!(words_for_entropy(len), Some(words as usize));
            // And it is a mnemonic, not just bytes of the right length.
            let m = Mnemonic::from_entropy(&e.as_bytes()[..len], &kw).expect("a mnemonic");
            assert_eq!(m.entropy().len(), ent);
        }
        // Anything else is refused rather than rounded to a neighbour.
        for bad in [0u32, 11, 13, 16, 23, 25, 48] {
            assert!(words_entropy(&master, bad, 0, &kw).is_err(), "{bad}");
        }
    }
}
