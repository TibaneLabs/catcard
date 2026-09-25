//! Clone Coldcard: device-to-device migration with no memorized password.
//!
//! The other way a wallet leaves this device. An [encrypted backup](crate) is protected
//! by twelve words the owner has to write down and type back; a clone is protected by a
//! key **two devices agree on directly**, so nothing has to be memorized and nothing goes
//! on screen. It is the migration for someone standing in front of both devices with one
//! microSD card, moving a wallet from an old device to a new one.
//!
//! # The handshake, and why it is two trips of the card
//!
//! The key is an ephemeral X25519 Diffie-Hellman between the two devices. Neither can send
//! the other a live message, so the shared secret is bootstrapped across the card:
//!
//! ```text
//!  target (blank)        card                     source (has wallet)
//!  ─────────────────────────────────────────────────────────────────
//!  generate (t)          ── start file ──▶
//!  keep t in RAM         (target public key)      read target public key
//!                                                 generate (s)
//!                                                 dh = X25519(s, target_pub)
//!                                                 seal wallet under HKDF(dh)
//!                        ◀── clone file ──        write source_pub ‖ archive
//!  read source_pub
//!  dh = X25519(t, source_pub)
//!  open wallet under HKDF(dh)
//! ```
//!
//! Both sides run the shared secret through HKDF-SHA256 with a transcript that names both
//! public keys, so the key commits to the exact pair of ephemerals that produced it and a
//! mixed-up or substituted public key derives a different key rather than a working one.
//! The archive itself is the same [`sevenz`](crate::sevenz) AES-256 container a backup
//! uses -- only the key comes from the handshake instead of the word list, so the reader
//! is the same code with a key it already holds rather than one it derives from a password.
//!
//! This is **CatCard's own format**, not stock's clone wire format, which is not in
//! `hw-reference`. It is tagged `[I]` in `docs/HARDWARE-OPEN-ITEMS.md`: two CatCards clone
//! to each other, but a CatCard and a stock Coldcard do not.
//!
//! # The ephemeral private key is the whole secret while the card travels
//!
//! The target holds its ephemeral private key in RAM the entire time the card is at the
//! other device. [`Ephemeral`] zeroizes it on drop, and the shared secret and the derived
//! bytes are wiped the moment the archive key is in hand.

use crate::{Error, kdf};
use purecrypto::ec::X25519PrivateKey;
use purecrypto::hash::Sha256;
use purecrypto::kdf::hkdf;
use zeroize::{Zeroize, ZeroizeOnDrop};

/// An X25519 public key, and an ephemeral scalar.
pub const PUBKEY_LEN: usize = 32;

/// The clone archive's magic, then the source device's ephemeral public key.
pub const MAGIC: [u8; 8] = *b"CCLONE01";

/// The start file's magic, then the target device's ephemeral public key.
pub const START_MAGIC: [u8; 8] = *b"CCLNSTRT";

/// The bytes the clone archive carries before the 7-Zip archive itself.
pub const HEADER_LEN: usize = MAGIC.len() + PUBKEY_LEN;

/// The whole of the start file: magic and the target's public key.
pub const START_LEN: usize = START_MAGIC.len() + PUBKEY_LEN;

/// Domain separation for the key schedule. The version suffix is bumped for any change a
/// peer speaking the old scheme would get wrong, so two versions cannot derive a matching
/// key by accident.
const INFO: &[u8] = b"catcard-clone-v1";

/// One side's ephemeral X25519 key pair for a single clone.
///
/// The scalar never leaves this type except through [`agree`](Ephemeral::agree); the
/// public key is what goes on the card. Dropped -- and so wiped -- as soon as the clone is
/// done, which for the target is only after the archive has been opened.
#[derive(ZeroizeOnDrop)]
pub struct Ephemeral {
    scalar: [u8; PUBKEY_LEN],
    #[zeroize(skip)]
    public: [u8; PUBKEY_LEN],
}

impl Ephemeral {
    /// Build a key pair from a fresh ephemeral scalar -- 32 bytes the caller drew from the
    /// protocol DRBG. X25519 clamps the scalar internally, so any 32 bytes are usable.
    pub fn new(scalar: &[u8; PUBKEY_LEN]) -> Self {
        let public = X25519PrivateKey::from_bytes(*scalar).public_key();
        Ephemeral {
            scalar: *scalar,
            public,
        }
    }

    /// The public key to put on the card.
    pub fn public(&self) -> &[u8; PUBKEY_LEN] {
        &self.public
    }

    /// Derive the archive key and IV shared with the peer.
    ///
    /// `peer_pub` is the other device's ephemeral public key. `source_pub` and
    /// `target_pub` are the transcript -- always in that order, whichever side is deriving
    /// -- so both sides hash the same thing and get the same key. A small-order peer key,
    /// whose shared secret an attacker could force to a known value, is
    /// [`Error::CloneKeyAgreement`] rather than a channel keyed off it.
    pub fn agree(
        &self,
        peer_pub: &[u8; PUBKEY_LEN],
        source_pub: &[u8; PUBKEY_LEN],
        target_pub: &[u8; PUBKEY_LEN],
    ) -> Result<(kdf::Key, [u8; 16]), Error> {
        let mut dh = X25519PrivateKey::from_bytes(self.scalar)
            .diffie_hellman(peer_pub)
            .map_err(|_| Error::CloneKeyAgreement)?;

        let mut transcript = [0u8; 2 * PUBKEY_LEN];
        transcript[..PUBKEY_LEN].copy_from_slice(source_pub);
        transcript[PUBKEY_LEN..].copy_from_slice(target_pub);

        // 32 bytes of AES-256 key, then 16 bytes of IV, from one expansion.
        let mut okm = [0u8; 48];
        hkdf::<Sha256>(&transcript, &dh, INFO, &mut okm);
        dh.zeroize();

        let mut key = [0u8; 32];
        key.copy_from_slice(&okm[..32]);
        let mut iv = [0u8; 16];
        iv.copy_from_slice(&okm[32..48]);
        okm.zeroize();

        let out = kdf::Key::from_bytes(key);
        key.zeroize();
        Ok((out, iv))
    }
}

/// Write the start file the target device leaves for the source: magic and its public key.
pub fn write_start(buf: &mut [u8], target_pub: &[u8; PUBKEY_LEN]) -> Result<usize, Error> {
    if buf.len() < START_LEN {
        return Err(Error::BufferTooSmall);
    }
    buf[..START_MAGIC.len()].copy_from_slice(&START_MAGIC);
    buf[START_MAGIC.len()..START_LEN].copy_from_slice(target_pub);
    Ok(START_LEN)
}

/// Read the target's public key out of a start file the source device found on the card.
pub fn read_start(buf: &[u8]) -> Result<[u8; PUBKEY_LEN], Error> {
    if buf.len() < START_LEN {
        return Err(Error::Truncated);
    }
    if buf[..START_MAGIC.len()] != START_MAGIC {
        return Err(Error::CloneBadMagic);
    }
    let mut pub_ = [0u8; PUBKEY_LEN];
    pub_.copy_from_slice(&buf[START_MAGIC.len()..START_LEN]);
    Ok(pub_)
}

/// Write the clone archive's header -- magic and the source's public key -- into the front
/// of `buf`. The 7-Zip archive is sealed at `buf[HEADER_LEN..]`.
pub fn write_header(buf: &mut [u8], source_pub: &[u8; PUBKEY_LEN]) -> Result<usize, Error> {
    if buf.len() < HEADER_LEN {
        return Err(Error::BufferTooSmall);
    }
    buf[..MAGIC.len()].copy_from_slice(&MAGIC);
    buf[MAGIC.len()..HEADER_LEN].copy_from_slice(source_pub);
    Ok(HEADER_LEN)
}

/// Read the source's public key out of a clone archive's header.
pub fn read_header(buf: &[u8]) -> Result<[u8; PUBKEY_LEN], Error> {
    if buf.len() < HEADER_LEN {
        return Err(Error::Truncated);
    }
    if buf[..MAGIC.len()] != MAGIC {
        return Err(Error::CloneBadMagic);
    }
    let mut pub_ = [0u8; PUBKEY_LEN];
    pub_.copy_from_slice(&buf[MAGIC.len()..HEADER_LEN]);
    Ok(pub_)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{body, sevenz};

    /// Both sides derive the same key from the same handshake, and a wallet sealed on one
    /// opens on the other. The whole clone contract in one test, with no hardware: two
    /// ephemerals, the transcript both agree on, and a real archive through the container.
    #[test]
    fn a_clone_survives_the_whole_round_trip() {
        // The two devices' ephemerals. In firmware these come from the DRBG.
        let target = Ephemeral::new(&[3u8; 32]);
        let source = Ephemeral::new(&[7u8; 32]);

        let (src_key, src_iv) = source
            .agree(target.public(), source.public(), target.public())
            .unwrap();
        let (dst_key, dst_iv) = target
            .agree(source.public(), source.public(), target.public())
            .unwrap();

        // The heart of it: neither side sent the other a key, yet they match.
        assert_eq!(src_key.as_bytes(), dst_key.as_bytes());
        assert_eq!(src_iv, dst_iv);

        // Seal a wallet body into a clone container: header, then the archive after it.
        let mut buf = [0u8; 1024];
        write_header(&mut buf, source.public()).unwrap();
        let body_len = {
            let mut w = body::BodyWriter::new(&mut buf[HEADER_LEN + sevenz::BODY_OFFSET..]);
            w.preamble();
            w.hex("raw_secret", &[0x82; 72]);
            w.eof();
            w.finish().unwrap().len()
        };
        let archive_len = sevenz::seal_at(
            &mut buf[HEADER_LEN..],
            body_len,
            "clone.txt",
            &src_key,
            &src_iv,
            &[],
            kdf::DEFAULT_CYCLES_POWER,
        )
        .unwrap()
        .len();
        let total = HEADER_LEN + archive_len;

        // The reader: recover the source key from the header, agree, and open.
        let recovered = read_header(&buf[..total]).unwrap();
        assert_eq!(&recovered, source.public());
        let (key, _iv) = target
            .agree(&recovered, &recovered, target.public())
            .unwrap();

        let file = match sevenz::open(&buf[HEADER_LEN..total]).unwrap() {
            sevenz::Found::File(s) => s,
            sevenz::Found::Header(_) => panic!("clone never writes an encrypted header"),
        };
        let plain = sevenz::decrypt_in_place(&mut buf[HEADER_LEN..total], &file, &key).unwrap();
        let text = core::str::from_utf8(plain).unwrap();
        let got = body::scan(text).unwrap();
        assert_eq!(got.details.raw_secret.map(str::len), Some(144));
    }

    /// The wrong peer key derives a different archive key, so the wrong device -- or a
    /// tampered header -- cannot open the wallet.
    #[test]
    fn a_different_peer_derives_a_different_key() {
        let target = Ephemeral::new(&[3u8; 32]);
        let source = Ephemeral::new(&[7u8; 32]);
        let impostor = Ephemeral::new(&[9u8; 32]);

        let (good, _) = source
            .agree(target.public(), source.public(), target.public())
            .unwrap();
        let (bad, _) = impostor
            .agree(target.public(), source.public(), target.public())
            .unwrap();
        assert_ne!(good.as_bytes(), bad.as_bytes());
    }

    #[test]
    fn the_frames_reject_the_wrong_magic() {
        let mut start = [0u8; START_LEN];
        write_start(&mut start, &[5u8; 32]).unwrap();
        assert_eq!(read_start(&start).unwrap(), [5u8; 32]);

        let mut hdr = [0u8; HEADER_LEN];
        write_header(&mut hdr, &[6u8; 32]).unwrap();
        assert_eq!(read_header(&hdr).unwrap(), [6u8; 32]);

        // A start file is not a clone archive, and vice versa.
        assert_eq!(read_header(&start).unwrap_err(), Error::CloneBadMagic);
        assert_eq!(read_start(&hdr).unwrap_err(), Error::CloneBadMagic);
        assert_eq!(read_header(&[0u8; 4]).unwrap_err(), Error::Truncated);
    }
}
