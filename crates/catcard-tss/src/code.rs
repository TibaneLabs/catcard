//! The session code: what the user compares across devices before anything secret moves.
//!
//! `SHA-256("CatCard TSS session v2\0" || protocol || session id || n || t || k ||
//! member_1..member_k || parameters digest || commitment_1..commitment_k ||
//! pubkey_1..pubkey_k)`, members in ascending order with their commitments and identity
//! keys in the same order. The parameters digest is the protocol's own: for signing it
//! names the joint key, the signing mode and every (path, sighash) to be signed, so
//! devices that loaded different transactions show different codes.
//!
//! Shown as the first [`WORDS`] BIP-39 words of the digest, 11 bits each.
//!
//! # Commit, then reveal
//!
//! Round 0 is in two passes. First every member broadcasts a [`commitment`]: a hash of
//! its identity key, its member number, the session and its parameters, and 32 fresh
//! random bytes. Only once it holds every other member's commitment does it broadcast
//! the key and the random bytes (round 1), and a key that does not open its sender's
//! commitment is refused.
//!
//! # How strong the comparison is
//!
//! An attacker who sits between members during round 0 can give each device a
//! different set of identity keys, and needs the codes on the two sides to match.
//! Without the commitments it could grind the keys it substitutes until the two codes
//! agree -- a birthday search over 88 bits, about 2^44 work. With them, every view a
//! device ends up with contains that device's own key, which it reveals only after the
//! attacker has committed to everything else in that view: when the key becomes known
//! the view's code is already fixed, and it is uniformly random to the attacker. Two
//! views then agree with probability 2^-88 per session run, whatever the attacker
//! computes, and each try costs the users a fresh session. Eight words stay.
//!
//! The full digest is also the *roster digest* every later message is signed over.

use catcard_wallet::bip39::wordlist;
use purecrypto::hash::{Digest, Sha256};

use crate::PUBKEY_LEN;
use crate::envelope::{Protocol, SESSION_ID_LEN};

/// Words shown.
pub const WORDS: usize = 8;

const DOMAIN: &[u8] = b"CatCard TSS session v2\0";
const COMMIT_DOMAIN: &[u8] = b"CatCard TSS commitment v1\0";

/// The random bytes a commitment hides its key behind.
pub(crate) const NONCE_LEN: usize = 32;
/// A commitment.
pub(crate) const COMMITMENT_LEN: usize = 32;

/// What the session code is computed over, besides the identities.
pub(crate) struct Context<'a> {
    pub protocol: Protocol,
    pub session: &'a [u8; SESSION_ID_LEN],
    pub n: u8,
    pub t: u8,
    /// Who takes part, ascending.
    pub members: &'a [u8],
    /// The protocol's parameters digest.
    pub params: &'a [u8; 32],
}

impl Context<'_> {
    fn hash_into(&self, h: &mut Sha256) {
        h.update(&[self.protocol as u8]);
        h.update(self.session);
        h.update(&[self.n, self.t, self.members.len() as u8]);
        h.update(self.members);
        h.update(self.params);
    }
}

/// Member `member`'s commitment to `key`: `SHA-256("CatCard TSS commitment v1\0" ||
/// protocol || session id || n || t || k || members || parameters digest || member ||
/// pubkey || nonce)`.
///
/// Binding the member number and the whole context means a commitment cannot be
/// replayed under another member's name or into another session; the nonce means the
/// commitment says nothing about the key until it is opened.
pub(crate) fn commitment(
    ctx: &Context<'_>,
    member: u8,
    key: &[u8; PUBKEY_LEN],
    nonce: &[u8; NONCE_LEN],
) -> [u8; COMMITMENT_LEN] {
    let mut h = Sha256::new();
    h.update(COMMIT_DOMAIN);
    ctx.hash_into(&mut h);
    h.update(&[member]);
    h.update(key);
    h.update(nonce);
    h.finalize()
}

/// The digest of a complete roster.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct SessionCode([u8; 32]);

impl SessionCode {
    pub(crate) fn compute(
        ctx: &Context<'_>,
        commitments: &[[u8; COMMITMENT_LEN]],
        keys: &[[u8; PUBKEY_LEN]],
    ) -> Self {
        let mut h = Sha256::new();
        h.update(DOMAIN);
        ctx.hash_into(&mut h);
        for c in commitments {
            h.update(c);
        }
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

    fn ctx<'a>(
        protocol: Protocol,
        session: &'a [u8; 8],
        n: u8,
        members: &'a [u8],
        params: &'a [u8; 32],
    ) -> Context<'a> {
        Context {
            protocol,
            session,
            n,
            t: 2,
            members,
            params,
        }
    }

    #[test]
    fn every_input_changes_the_code() {
        let k = [[2u8; 33], [3u8; 33]];
        let c = [[4u8; 32], [5u8; 32]];
        let base_ctx = ctx(Protocol::Keygen, &[1; 8], 2, &[1, 2], &[0; 32]);
        let base = SessionCode::compute(&base_ctx, &c, &k);
        let variants = [
            SessionCode::compute(&ctx(Protocol::Sign, &[1; 8], 2, &[1, 2], &[0; 32]), &c, &k),
            SessionCode::compute(
                &ctx(Protocol::Keygen, &[2; 8], 2, &[1, 2], &[0; 32]),
                &c,
                &k,
            ),
            SessionCode::compute(
                &ctx(Protocol::Keygen, &[1; 8], 3, &[1, 2], &[0; 32]),
                &c,
                &k,
            ),
            SessionCode::compute(
                &ctx(Protocol::Keygen, &[1; 8], 2, &[1, 3], &[0; 32]),
                &c,
                &k,
            ),
            SessionCode::compute(
                &ctx(Protocol::Keygen, &[1; 8], 2, &[1, 2], &[1; 32]),
                &c,
                &k,
            ),
            SessionCode::compute(&base_ctx, &c, &[k[1], k[0]]),
            SessionCode::compute(&base_ctx, &[c[1], c[0]], &k),
            SessionCode::compute(&base_ctx, &[c[0], [6; 32]], &k),
        ];
        for v in variants {
            assert_ne!(v, base);
        }
    }

    #[test]
    fn a_commitment_binds_member_key_nonce_and_context() {
        let x = ctx(Protocol::Keygen, &[1; 8], 3, &[1, 2, 3], &[0; 32]);
        let base = commitment(&x, 2, &[2; 33], &[9; 32]);
        assert_ne!(commitment(&x, 3, &[2; 33], &[9; 32]), base);
        assert_ne!(commitment(&x, 2, &[3; 33], &[9; 32]), base);
        assert_ne!(commitment(&x, 2, &[2; 33], &[8; 32]), base);
        let other = ctx(Protocol::Keygen, &[2; 8], 3, &[1, 2, 3], &[0; 32]);
        assert_ne!(commitment(&other, 2, &[2; 33], &[9; 32]), base);
        let params = ctx(Protocol::Keygen, &[1; 8], 3, &[1, 2, 3], &[1; 32]);
        assert_ne!(commitment(&params, 2, &[2; 33], &[9; 32]), base);
    }
}
