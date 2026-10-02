//! The session code: what the user compares across devices before anything secret moves.
//!
//! `SHA-256("CatCard TSS session v1\0" || protocol || session id || n || t || k ||
//! member_1..member_k || parameters digest || pubkey_1..pubkey_k)`, members in ascending
//! order with their identity keys in the same order. The parameters digest is the
//! protocol's own: for signing it names the joint key, the signing mode and every
//! (path, sighash) to be signed, so devices that loaded different transactions show
//! different codes.
//!
//! Shown as the first [`WORDS`] BIP-39 words of the digest, 11 bits each.
//!
//! # How strong the comparison is
//!
//! An attacker who sits between members during round 0 can give each device a
//! different set of identity keys, and needs the codes on the two sides to match. The
//! keys it substitutes are its own, so it can grind both sides: a birthday search over
//! 88 bits, about 2^44 hash-and-point operations, done between the moment it sees the
//! honest keys and the moment the user looks at the screens. A commit-then-reveal round
//! 0 (hashes first, keys second) would remove the grinding and let fewer words do; it
//! costs one more pass of the cards. Noted in docs/TSS.md as open.
//!
//! The full digest is also the *roster digest* every later message is signed over.

use catcard_wallet::bip39::wordlist;
use purecrypto::hash::{Digest, Sha256};

use crate::PUBKEY_LEN;
use crate::envelope::{Protocol, SESSION_ID_LEN};

/// Words shown.
pub const WORDS: usize = 8;

const DOMAIN: &[u8] = b"CatCard TSS session v1\0";

/// The digest of a complete roster.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct SessionCode([u8; 32]);

impl SessionCode {
    pub(crate) fn compute(
        protocol: Protocol,
        session: &[u8; SESSION_ID_LEN],
        n: u8,
        t: u8,
        members: &[u8],
        params: &[u8; 32],
        keys: &[[u8; PUBKEY_LEN]],
    ) -> Self {
        let mut h = Sha256::new();
        h.update(DOMAIN);
        h.update(&[protocol as u8]);
        h.update(session);
        h.update(&[n, t, members.len() as u8]);
        h.update(members);
        h.update(params);
        for k in keys {
            h.update(k);
        }
        SessionCode(h.finalize())
    }

    /// The whole digest.
    pub fn digest(&self) -> &[u8; 32] {
        &self.0
    }

    /// The words the user compares.
    pub fn words(&self) -> [&'static str; WORDS] {
        let mut out = [""; WORDS];
        for (i, w) in out.iter_mut().enumerate() {
            let bit = i * wordlist::BITS_PER_WORD;
            // 11 bits starting at `bit`, MSB first; three bytes always cover them.
            let b = |k: usize| u32::from(self.0[bit / 8 + k]);
            let window = (b(0) << 16) | (b(1) << 8) | b(2);
            let idx = (window >> (24 - wordlist::BITS_PER_WORD - bit % 8)) & 0x7ff;
            *w = wordlist::word(idx as usize);
        }
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn words_are_the_digest_eleven_bits_at_a_time() {
        // 0x00 0x20 ...: the first word is index 0 ("abandon"), the second index 1
        // ("ability"), from bits 11..22.
        let mut d = [0u8; 32];
        d[1] = 0x00;
        d[2] = 0x04;
        let w = SessionCode(d).words();
        assert_eq!(w[0], "abandon");
        assert_eq!(w[1], "ability");
        let w = SessionCode([0xff; 32]).words();
        assert!(w.iter().all(|&x| x == "zoo"));
    }

    #[test]
    fn every_input_changes_the_code() {
        let k = [[2u8; 33], [3u8; 33]];
        let base = SessionCode::compute(Protocol::Keygen, &[1; 8], 2, 2, &[1, 2], &[0; 32], &k);
        let variants = [
            SessionCode::compute(Protocol::Sign, &[1; 8], 2, 2, &[1, 2], &[0; 32], &k),
            SessionCode::compute(Protocol::Keygen, &[2; 8], 2, 2, &[1, 2], &[0; 32], &k),
            SessionCode::compute(Protocol::Keygen, &[1; 8], 3, 2, &[1, 2], &[0; 32], &k),
            SessionCode::compute(Protocol::Keygen, &[1; 8], 2, 2, &[1, 3], &[0; 32], &k),
            SessionCode::compute(Protocol::Keygen, &[1; 8], 2, 2, &[1, 2], &[1; 32], &k),
            SessionCode::compute(
                Protocol::Keygen,
                &[1; 8],
                2,
                2,
                &[1, 2],
                &[0; 32],
                &[k[1], k[0]],
            ),
        ];
        for v in variants {
            assert_ne!(v, base);
        }
    }
}
