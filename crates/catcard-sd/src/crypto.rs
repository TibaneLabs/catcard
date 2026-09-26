//! Transparent whole-card AES-128-XTS: the cipher that sits under [`read_block`] and
//! [`write_block`](crate::write_block) when a [`Card`](crate::Card) is unlocked.
//!
//! # What this is, and is not
//!
//! This is *data-at-rest* encryption of the card's bytes. Every 512-byte sector is
//! enciphered length-preserving with AES-128-XTS, the tweak being the sector's LBA, so
//! two identical plaintext sectors at different LBAs come out as different ciphertext and
//! a sector moved to a different LBA no longer decrypts. It is **not** the card
//! controller's own CMD42 password lock ([`crate::lock_unlock`]) -- that refuses transfers
//! at the card; this leaves the transfers alone and garbles the bytes they carry.
//!
//! The key is never derived here. Firmware turns a password or passphrase into the
//! 32 bytes below (K1 ‖ K2) with a slow KDF and hands them in; this crate only keys the
//! cipher and enciphers sectors.
//!
//! Source: IEEE 1619-2007 "XTS-AES" (tweak = data-unit / sector index), NIST SP 800-38E.
//! [C] -- the standard fixes the construction; `purecrypto::cipher::Aes128Xts` implements
//! it and is exercised against the IEEE 1619 vectors in that crate.

use crate::BLOCK_LEN;
use purecrypto::cipher::Aes128Xts;
use zeroize::ZeroizeOnDrop;

/// Bytes of key material AES-128-XTS needs: K1 (data, 16) ‖ K2 (tweak, 16).
pub const XTS_KEY_LEN: usize = 32;
/// Each half of [`XTS_KEY_LEN`].
pub const XTS_HALF_LEN: usize = 16;

/// Why keying failed.
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub enum CryptoError {
    /// K1 == K2. IEEE 1619 / FIPS 140 guidance requires this be rejected: with equal
    /// halves the XEX construction degenerates and the mode loses its security argument.
    /// `Aes128Xts::from_keys` refuses it, and so, therefore, does this.
    RepeatedKey,
}

/// A keyed AES-128-XTS instance held for the length of a session on one card.
///
/// # Zeroization
///
/// The two `Aes128` inside the [`Aes128Xts`] are each `ZeroizeOnDrop` in `purecrypto`
/// (they wipe their expanded round keys on drop, with volatile stores), so dropping a
/// `SectorCrypto` wipes all key material it holds -- which is why the marker
/// [`ZeroizeOnDrop`] below is truthful without a hand-written `Drop`: the field drop glue
/// does the wiping. Nothing here stores the raw K1/K2 bytes; only the expanded schedules
/// live, and they go with the cipher.
pub struct SectorCrypto {
    xts: Aes128Xts,
}

// The expanded key schedules inside `xts` are wiped by the inner `Aes128`'s own
// `ZeroizeOnDrop` when this struct drops. This marker asserts that drop-wipe property.
impl ZeroizeOnDrop for SectorCrypto {}

impl SectorCrypto {
    /// Key from K1 (data) and K2 (tweak). Rejects `k1 == k2` -- see [`CryptoError`].
    pub fn from_halves(
        k1: &[u8; XTS_HALF_LEN],
        k2: &[u8; XTS_HALF_LEN],
    ) -> Result<Self, CryptoError> {
        let xts = Aes128Xts::from_keys(k1, k2).map_err(|_| CryptoError::RepeatedKey)?;
        Ok(Self { xts })
    }

    /// Key from the 32-byte K1 ‖ K2 layout. Rejects equal halves, as [`from_halves`] does.
    ///
    /// [`from_halves`]: Self::from_halves
    pub fn from_key(key: &[u8; XTS_KEY_LEN]) -> Result<Self, CryptoError> {
        let mut k1 = [0u8; XTS_HALF_LEN];
        let mut k2 = [0u8; XTS_HALF_LEN];
        k1.copy_from_slice(&key[..XTS_HALF_LEN]);
        k2.copy_from_slice(&key[XTS_HALF_LEN..]);
        let out = Self::from_halves(&k1, &k2);
        // The borrowed `key` is the caller's to wipe; these two locals are ours.
        use zeroize::Zeroize as _;
        k1.zeroize();
        k2.zeroize();
        out
    }

    /// Decrypt one sector in place, its LBA as the XTS tweak.
    ///
    /// `BLOCK_LEN` (512) is a whole number of 16-byte AES blocks and well within the XTS
    /// data-unit bounds, so the underlying call cannot fail on a real sector; the length
    /// check is a static invariant of this crate, not a wait or a device condition, so a
    /// mismatch is a firmware bug and panics rather than corrupting silently.
    pub fn decrypt_sector(&self, lba: u32, buf: &mut [u8; BLOCK_LEN]) {
        self.xts
            .decrypt_sector(u128::from(lba), buf)
            .expect("BLOCK_LEN is a valid XTS data unit");
    }

    /// Encrypt one sector in place, its LBA as the XTS tweak. See [`decrypt_sector`] on why
    /// the length cannot fail here.
    ///
    /// [`decrypt_sector`]: Self::decrypt_sector
    pub fn encrypt_sector(&self, lba: u32, buf: &mut [u8; BLOCK_LEN]) {
        self.xts
            .encrypt_sector(u128::from(lba), buf)
            .expect("BLOCK_LEN is a valid XTS data unit");
    }
}
