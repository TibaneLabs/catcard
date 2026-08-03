//! Authenticated, power-fail-safe settings storage.
//!
//! # The two failure modes this exists to survive
//!
//! **Power loss mid-write.** A wallet is unplugged constantly, often mid-operation.
//! Erasing a sector and rewriting it in place has a window — sometimes hundreds of
//! milliseconds — where the settings are neither the old value nor the new one. So this
//! keeps **two slots** and always writes to the one that is not currently authoritative.
//! Until the new slot's MAC verifies, the old one still wins; there is no instant at
//! which both are invalid.
//!
//! **Tampering.** The SPI-NOR part is outside the secure element and outside the MCU.
//! Anyone who can desolder it can rewrite it. Settings decide things that matter — which
//! derivation paths are shown, whether a duress wallet exists — so every slot carries an
//! HMAC over its contents *and its sequence number*, keyed by a secret the attacker does
//! not have. Unauthenticated settings are attacker-controlled settings.
//!
//! Rollback to an older *authentic* slot is still possible for someone with physical
//! access; defeating that needs a monotonic counter in the secure element, which is
//! future work (see `docs/ROADMAP.md`).

#![cfg_attr(not(feature = "std"), no_std)]
#![deny(unsafe_code)]

use hmac::digest::KeyInit;
use hmac::{Hmac, Mac};
use sha2::Sha256;
use subtle::ConstantTimeEq;
use zeroize::{Zeroize, ZeroizeOnDrop};

type HmacSha256 = Hmac<Sha256>;

/// Identifies a slot as ours and the format as this version.
pub const MAGIC: u32 = 0xCA7C_5E77;

/// Bytes of settings payload a slot holds.
pub const PAYLOAD_LEN: usize = 1024;

/// `magic(4) || seq(8) || len(2) || reserved(2) || mac(32)`.
pub const HEADER_LEN: usize = 48;

/// Total bytes a slot occupies.
pub const SLOT_LEN: usize = HEADER_LEN + PAYLOAD_LEN;

/// Slots kept. Two is the minimum for the alternation to be safe.
pub const SLOTS: usize = 2;

/// Key length for the authentication secret.
pub const KEY_LEN: usize = 32;

const OFF_MAGIC: usize = 0;
const OFF_SEQ: usize = 4;
const OFF_LEN: usize = 12;
const OFF_MAC: usize = 16;

#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub enum Error<E> {
    Storage(E),
    /// No slot held authentic, well-formed settings. Either the device is new, or both
    /// slots were damaged.
    NoValidSlot,
    /// The payload does not fit.
    TooLarge {
        len: usize,
    },
    /// The caller's buffer is smaller than the stored payload.
    BufferTooSmall {
        need: usize,
        have: usize,
    },
}

/// Erase-and-write storage, one slot at a time.
///
/// Deliberately slot-granular rather than byte-granular: the alternation argument only
/// holds if a slot write cannot partially overwrite the *other* slot, and making that
/// structural is better than documenting it.
pub trait SlotStorage {
    type Error;

    /// Read a whole slot.
    fn read_slot(&mut self, slot: usize, out: &mut [u8; SLOT_LEN]) -> Result<(), Self::Error>;

    /// Erase then write a whole slot.
    fn write_slot(&mut self, slot: usize, data: &[u8; SLOT_LEN]) -> Result<(), Self::Error>;
}

/// Compute a slot's MAC.
///
/// Covers the sequence number as well as the payload. Without that, an attacker could
/// take an authentic old payload and re-stamp it with a higher sequence number to force
/// a rollback — the MAC would still verify.
fn mac_of(key: &[u8; KEY_LEN], seq: u64, payload: &[u8]) -> [u8; 32] {
    let mut m = HmacSha256::new_from_slice(key).expect("HMAC takes any key");
    m.update(&MAGIC.to_le_bytes());
    m.update(&seq.to_le_bytes());
    m.update(&(payload.len() as u16).to_le_bytes());
    m.update(payload);
    m.finalize().into_bytes().into()
}

/// A parsed, authenticated slot.
struct Slot {
    seq: u64,
    len: usize,
}

fn parse(raw: &[u8; SLOT_LEN], key: &[u8; KEY_LEN]) -> Option<Slot> {
    let magic = u32::from_le_bytes(raw[OFF_MAGIC..OFF_MAGIC + 4].try_into().ok()?);
    if magic != MAGIC {
        return None;
    }
    let seq = u64::from_le_bytes(raw[OFF_SEQ..OFF_SEQ + 8].try_into().ok()?);
    let len = u16::from_le_bytes(raw[OFF_LEN..OFF_LEN + 2].try_into().ok()?) as usize;
    if len > PAYLOAD_LEN {
        return None;
    }
    let payload = &raw[HEADER_LEN..HEADER_LEN + len];
    let expect = mac_of(key, seq, payload);

    // Constant time: a timing signal here would let an attacker with the flash in hand
    // search for a MAC byte at a time.
    let ok: bool = expect.ct_eq(&raw[OFF_MAC..OFF_MAC + 32]).into();
    if ok {
        Some(Slot { seq, len })
    } else {
        None
    }
}

/// The settings store.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct Store<S: SlotStorage> {
    #[zeroize(skip)]
    storage: S,
    key: [u8; KEY_LEN],
    /// Sequence number of the authoritative slot, or 0 if there is none.
    #[zeroize(skip)]
    seq: u64,
    /// Which slot is authoritative.
    #[zeroize(skip)]
    current: usize,
    #[zeroize(skip)]
    loaded: bool,
}

impl<S: SlotStorage> Store<S> {
    /// Bind a store to its storage and authentication key.
    ///
    /// The key must be device-specific and unavailable to an attacker who has only the
    /// flash chip — derive it from the secure element, not from anything in the image.
    pub fn new(storage: S, key: [u8; KEY_LEN]) -> Self {
        Self {
            storage,
            key,
            seq: 0,
            current: 0,
            loaded: false,
        }
    }

    /// Read the authoritative payload into `out`; returns its length.
    ///
    /// Picks the authentic slot with the highest sequence number. A slot that fails its
    /// MAC is ignored entirely rather than partially trusted.
    pub fn load(&mut self, out: &mut [u8]) -> Result<usize, Error<S::Error>> {
        let mut best: Option<(usize, Slot)> = None;
        let mut raw = [0u8; SLOT_LEN];

        for slot in 0..SLOTS {
            self.storage
                .read_slot(slot, &mut raw)
                .map_err(Error::Storage)?;
            if let Some(parsed) = parse(&raw, &self.key) {
                let better = best.as_ref().is_none_or(|(_, b)| parsed.seq > b.seq);
                if better {
                    best = Some((slot, parsed));
                }
            }
        }

        let (slot, parsed) = best.ok_or(Error::NoValidSlot)?;
        if out.len() < parsed.len {
            return Err(Error::BufferTooSmall {
                need: parsed.len,
                have: out.len(),
            });
        }

        // Re-read: `raw` currently holds whichever slot was examined last.
        self.storage
            .read_slot(slot, &mut raw)
            .map_err(Error::Storage)?;
        out[..parsed.len].copy_from_slice(&raw[HEADER_LEN..HEADER_LEN + parsed.len]);

        self.seq = parsed.seq;
        self.current = slot;
        self.loaded = true;
        Ok(parsed.len)
    }

    /// Write a new payload, superseding the current one.
    ///
    /// Writes to the slot that is *not* authoritative, so a power failure at any point
    /// leaves the previous settings intact and still authoritative.
    pub fn save(&mut self, payload: &[u8]) -> Result<(), Error<S::Error>> {
        if payload.len() > PAYLOAD_LEN {
            return Err(Error::TooLarge { len: payload.len() });
        }

        // If nothing has been loaded, find out what is already there so the sequence
        // number moves forward rather than colliding with an existing slot.
        if !self.loaded {
            let mut scratch = [0u8; PAYLOAD_LEN];
            match self.load(&mut scratch) {
                Ok(_) => {}
                Err(Error::NoValidSlot) => {
                    self.seq = 0;
                    self.current = 1; // so the first write lands in slot 0
                }
                Err(e) => return Err(e),
            }
            scratch.zeroize();
        }

        let seq = self.seq + 1;
        let target = (self.current + 1) % SLOTS;

        let mut raw = [0u8; SLOT_LEN];
        raw[OFF_MAGIC..OFF_MAGIC + 4].copy_from_slice(&MAGIC.to_le_bytes());
        raw[OFF_SEQ..OFF_SEQ + 8].copy_from_slice(&seq.to_le_bytes());
        raw[OFF_LEN..OFF_LEN + 2].copy_from_slice(&(payload.len() as u16).to_le_bytes());
        raw[OFF_MAC..OFF_MAC + 32].copy_from_slice(&mac_of(&self.key, seq, payload));
        raw[HEADER_LEN..HEADER_LEN + payload.len()].copy_from_slice(payload);

        self.storage
            .write_slot(target, &raw)
            .map_err(Error::Storage)?;

        self.seq = seq;
        self.current = target;
        self.loaded = true;
        Ok(())
    }

    /// Sequence number of the authoritative slot.
    pub fn sequence(&self) -> u64 {
        self.seq
    }

    /// Which slot is authoritative.
    pub fn current_slot(&self) -> usize {
        self.current
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Storage that can be told to fail partway through a write, modelling a power cut.
    struct MockStorage {
        slots: [[u8; SLOT_LEN]; SLOTS],
        /// Write this many bytes, then fail. `None` writes fully.
        fail_after: Option<usize>,
        writes: usize,
    }

    impl MockStorage {
        fn new() -> Self {
            // Erased flash reads as 0xFF.
            Self {
                slots: [[0xFF; SLOT_LEN]; SLOTS],
                fail_after: None,
                writes: 0,
            }
        }
    }

    impl SlotStorage for MockStorage {
        type Error = ();

        fn read_slot(&mut self, slot: usize, out: &mut [u8; SLOT_LEN]) -> Result<(), ()> {
            out.copy_from_slice(&self.slots[slot]);
            Ok(())
        }

        fn write_slot(&mut self, slot: usize, data: &[u8; SLOT_LEN]) -> Result<(), ()> {
            self.writes += 1;
            match self.fail_after {
                None => {
                    self.slots[slot].copy_from_slice(data);
                    Ok(())
                }
                Some(n) => {
                    // Erase happens first, so the slot is blanked and then partially
                    // rewritten — exactly what an interrupted flash write leaves.
                    self.slots[slot] = [0xFF; SLOT_LEN];
                    self.slots[slot][..n].copy_from_slice(&data[..n]);
                    Err(())
                }
            }
        }
    }

    const KEY: [u8; KEY_LEN] = [0x42; KEY_LEN];

    fn store() -> Store<MockStorage> {
        Store::new(MockStorage::new(), KEY)
    }

    #[test]
    fn a_blank_device_has_no_settings() {
        let mut s = store();
        let mut buf = [0u8; PAYLOAD_LEN];
        assert!(matches!(s.load(&mut buf), Err(Error::NoValidSlot)));
    }

    #[test]
    fn save_then_load_round_trips() {
        let mut s = store();
        s.save(b"hello settings").unwrap();
        let mut buf = [0u8; PAYLOAD_LEN];
        let n = s.load(&mut buf).unwrap();
        assert_eq!(&buf[..n], b"hello settings");
    }

    #[test]
    fn writes_alternate_between_slots() {
        // If two consecutive saves hit the same slot, a power cut during the second
        // destroys the only copy.
        let mut s = store();
        s.save(b"a").unwrap();
        let first = s.current_slot();
        s.save(b"b").unwrap();
        assert_ne!(s.current_slot(), first);
        s.save(b"c").unwrap();
        assert_eq!(s.current_slot(), first);
    }

    #[test]
    fn the_newest_authentic_slot_wins() {
        let mut s = store();
        for i in 0..5u8 {
            s.save(&[i; 4]).unwrap();
        }
        let mut buf = [0u8; PAYLOAD_LEN];
        let n = s.load(&mut buf).unwrap();
        assert_eq!(&buf[..n], &[4u8; 4]);
        assert_eq!(s.sequence(), 5);
    }

    #[test]
    fn power_loss_mid_write_is_atomic() {
        // The property the two-slot design exists for: after a power cut the device
        // comes back holding *either* the old settings or the new ones, never a blend
        // and never nothing. Which of the two depends on how far the write got, and
        // both outcomes are correct — a completed write that was interrupted during
        // trailing padding really has landed.
        for cut_at in 0..=SLOT_LEN {
            let mut s = Store::new(MockStorage::new(), KEY);
            s.save(b"good value").unwrap();
            s.storage.fail_after = Some(cut_at);
            let _ = s.save(b"interrupted");

            // A fresh store, as if the device had rebooted.
            let mut fresh = Store::new(
                MockStorage {
                    slots: s.storage.slots,
                    fail_after: None,
                    writes: 0,
                },
                KEY,
            );
            let mut buf = [0u8; PAYLOAD_LEN];
            let n = fresh
                .load(&mut buf)
                .unwrap_or_else(|e| panic!("no settings at all after a cut at {cut_at}: {e:?}"));
            let got = &buf[..n];
            assert!(
                got == b"good value" || got == b"interrupted",
                "torn settings after a cut at {cut_at}: {got:?}"
            );
        }
    }

    #[test]
    fn an_interrupted_header_always_falls_back_to_the_old_slot() {
        // Cutting before the MAC is written means the new slot cannot possibly
        // authenticate, so the old one must still be authoritative.
        for cut_at in 0..HEADER_LEN {
            let mut s = Store::new(MockStorage::new(), KEY);
            s.save(b"good value").unwrap();
            s.storage.fail_after = Some(cut_at);
            let _ = s.save(b"interrupted");

            let mut fresh = Store::new(
                MockStorage {
                    slots: s.storage.slots,
                    fail_after: None,
                    writes: 0,
                },
                KEY,
            );
            let mut buf = [0u8; PAYLOAD_LEN];
            let n = fresh.load(&mut buf).unwrap();
            assert_eq!(
                &buf[..n],
                b"good value",
                "old settings lost when the cut was at byte {cut_at}"
            );
        }
    }

    #[test]
    fn a_tampered_payload_is_rejected() {
        // The flash chip is outside every trust boundary the device has.
        let mut s = store();
        s.save(b"authentic").unwrap();
        let slot = s.current_slot();
        s.storage.slots[slot][HEADER_LEN] ^= 0x01;

        let mut fresh = Store::new(
            MockStorage {
                slots: s.storage.slots,
                fail_after: None,
                writes: 0,
            },
            KEY,
        );
        let mut buf = [0u8; PAYLOAD_LEN];
        assert!(matches!(fresh.load(&mut buf), Err(Error::NoValidSlot)));
    }

    #[test]
    fn a_reused_mac_cannot_be_restamped_with_a_higher_sequence() {
        // Without the sequence number under the MAC, an attacker could take an old
        // authentic payload and renumber it to force a rollback.
        let mut s = store();
        s.save(b"old").unwrap();
        let old_slot = s.current_slot();
        s.save(b"new").unwrap();

        // Bump the old slot's sequence past the new one, leaving its MAC alone.
        let bumped = (s.sequence() + 10).to_le_bytes();
        s.storage.slots[old_slot][OFF_SEQ..OFF_SEQ + 8].copy_from_slice(&bumped);

        let mut fresh = Store::new(
            MockStorage {
                slots: s.storage.slots,
                fail_after: None,
                writes: 0,
            },
            KEY,
        );
        let mut buf = [0u8; PAYLOAD_LEN];
        let n = fresh.load(&mut buf).unwrap();
        assert_eq!(&buf[..n], b"new", "a re-stamped old slot was accepted");
    }

    #[test]
    fn settings_written_under_one_key_do_not_load_under_another() {
        let mut s = store();
        s.save(b"secret settings").unwrap();

        let mut other = Store::new(
            MockStorage {
                slots: s.storage.slots,
                fail_after: None,
                writes: 0,
            },
            [0x99; KEY_LEN],
        );
        let mut buf = [0u8; PAYLOAD_LEN];
        assert!(matches!(other.load(&mut buf), Err(Error::NoValidSlot)));
    }

    #[test]
    fn a_bad_magic_is_ignored() {
        let mut s = store();
        s.save(b"x").unwrap();
        let slot = s.current_slot();
        s.storage.slots[slot][0] ^= 0xFF;
        let mut fresh = Store::new(
            MockStorage {
                slots: s.storage.slots,
                fail_after: None,
                writes: 0,
            },
            KEY,
        );
        let mut buf = [0u8; PAYLOAD_LEN];
        assert!(matches!(fresh.load(&mut buf), Err(Error::NoValidSlot)));
    }

    #[test]
    fn an_absurd_length_field_is_rejected_not_trusted() {
        // A length past the slot would otherwise index out of bounds.
        let mut s = store();
        s.save(b"x").unwrap();
        let slot = s.current_slot();
        s.storage.slots[slot][OFF_LEN..OFF_LEN + 2].copy_from_slice(&u16::MAX.to_le_bytes());
        let mut fresh = Store::new(
            MockStorage {
                slots: s.storage.slots,
                fail_after: None,
                writes: 0,
            },
            KEY,
        );
        let mut buf = [0u8; PAYLOAD_LEN];
        assert!(matches!(fresh.load(&mut buf), Err(Error::NoValidSlot)));
    }

    #[test]
    fn an_oversized_payload_is_refused() {
        let mut s = store();
        assert!(matches!(
            s.save(&[0u8; PAYLOAD_LEN + 1]),
            Err(Error::TooLarge { .. })
        ));
    }

    #[test]
    fn a_full_payload_fits_exactly() {
        let mut s = store();
        let data = [0xABu8; PAYLOAD_LEN];
        s.save(&data).unwrap();
        let mut buf = [0u8; PAYLOAD_LEN];
        assert_eq!(s.load(&mut buf).unwrap(), PAYLOAD_LEN);
        assert_eq!(buf, data);
    }

    #[test]
    fn an_empty_payload_is_valid_and_distinct_from_absent() {
        let mut s = store();
        s.save(b"").unwrap();
        let mut buf = [0u8; PAYLOAD_LEN];
        assert_eq!(s.load(&mut buf).unwrap(), 0);
    }

    #[test]
    fn a_small_read_buffer_errors_rather_than_truncating() {
        let mut s = store();
        s.save(b"0123456789").unwrap();
        let mut small = [0u8; 4];
        assert!(matches!(
            s.load(&mut small),
            Err(Error::BufferTooSmall { need: 10, have: 4 })
        ));
    }

    #[test]
    fn saving_without_loading_first_does_not_collide_with_existing_slots() {
        // A reboot between saves must not restart the sequence at 1 and lose ordering.
        let mut s = store();
        s.save(b"first").unwrap();
        s.save(b"second").unwrap();
        let slots = s.storage.slots;
        let seq_before = s.sequence();

        let mut fresh = Store::new(
            MockStorage {
                slots,
                fail_after: None,
                writes: 0,
            },
            KEY,
        );
        fresh.save(b"third").unwrap();
        assert_eq!(fresh.sequence(), seq_before + 1);

        let mut buf = [0u8; PAYLOAD_LEN];
        let n = fresh.load(&mut buf).unwrap();
        assert_eq!(&buf[..n], b"third");
    }

    #[test]
    fn header_layout_is_stable() {
        assert_eq!(HEADER_LEN, 48);
        assert_eq!(OFF_MAC + 32, HEADER_LEN);
        assert_eq!(SLOT_LEN, HEADER_LEN + PAYLOAD_LEN);
    }
}
