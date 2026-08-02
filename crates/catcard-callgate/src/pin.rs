//! The `pinAttempt_t` structure passed to callgate 18.
//!
//! This is an imposed ABI: the bootloader reads and writes this struct in place and
//! authenticates it with an HMAC only it can compute, so the layout must match exactly.
//!
//! Source: `hw-reference/bootloader-callgate-abi.md §gate 18` [C].

use zeroize::{Zeroize, ZeroizeOnDrop};

/// `PIN_ATTEMPT_SIZE_V2` — the ATECC608 layout, used by mk3 and later.
/// Source: bootloader-callgate-abi.md [C]
pub const PIN_ATTEMPT_SIZE: usize = 280;

/// `PIN_ATTEMPT_SIZE_V1` — the mk2/ATECC508 layout, which has no `cached_main_pin`.
/// Not implemented; recorded so a V1 device is diagnosed rather than silently corrupted.
/// Source: generations-mk2-q-mk5.md §Mk2 [C]
pub const PIN_ATTEMPT_SIZE_V1: usize = 248;

/// `magic_value` for the V2 (ATECC608) struct. The caller sets this before
/// [`PinOp::Setup`](crate::abi::PinOp::Setup); a mismatch returns
/// [`err::BAD_MAGIC`](crate::abi::err::BAD_MAGIC).
/// Source: gate18-pin-state-machine.md §1 [C]
pub const PA_MAGIC_V2: u32 = 0x2eaf_6312;

/// `magic_value` for the V1 (ATECC508 / mk2) struct.
/// Source: generations-mk2-q-mk5.md §Mk2 [C]
pub const PA_MAGIC_V1: u32 = 0x2eaf_6311;

/// Maximum PIN length in the prefix/suffix fields.
pub const MAX_PIN_LEN: usize = 32;

/// The wallet secret returned by [`PinOp::FetchSecret`](crate::abi::PinOp::FetchSecret).
pub const SECRET_LEN: usize = 72;

/// The "long secret" is 416 bytes, read and written 32 bytes at a time.
pub const LONG_SECRET_LEN: usize = 416;
pub const LONG_SECRET_CHUNK: usize = 32;

/// In-place I/O buffer for callgate 18.
///
/// Field order and signedness follow the documented `struct` format
/// `"<Ii32si6I32si32si32si72s32s"` (gate18-pin-state-machine.md §1 [C]). The `6I` run
/// is what fixes `delay_achieved`/`delay_required` at one word each, and the whole
/// layout sums to exactly 280.
///
/// Every privileged field is zeroed on drop; this struct holds a plaintext PIN and,
/// after a fetch, the wallet secret.
#[repr(C)]
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct PinAttempt {
    /// [`PA_MAGIC_V2`]. Set by the caller before
    /// [`PinOp::Setup`](crate::abi::PinOp::Setup); checked on every call.
    pub magic: u32,
    /// Obsolete (secondary wallets were an ATECC508-era feature). Must be 0.
    pub is_secondary: i32,
    /// The PIN being tested, as ASCII digits with a `-` separating prefix and suffix.
    pub pin: [u8; MAX_PIN_LEN],
    /// Valid bytes in `pin`. **Must be bounded to `0..=32`** — the audit of the stock
    /// firmware found this unchecked on the caller side. [`Self::set_pin`] is the only
    /// way this crate writes it.
    pub pin_len: i32,
    /// Rate-limit delay already served. Obsolete on ATECC608.
    pub delay_achieved: u32,
    /// Rate-limit delay demanded. Obsolete on ATECC608.
    pub delay_required: u32,
    /// Failed attempts so far.
    pub num_fails: u32,
    /// Attempts remaining before the device bricks itself.
    pub attempts_left: u32,
    /// See [`state`](crate::abi::state).
    pub state_flags: u32,
    /// Bootloader-private; opaque to us, but covered by the HMAC.
    pub private_state: u32,
    /// The bootloader's authenticator over this struct: double-SHA256 over
    /// `pairing_secret || reboot_seed || struct[..hmac] || cached_main_pin`. It is
    /// validated on every non-setup call and re-signed on return, so the struct must
    /// round-trip unmodified from a prior call. `reboot_seed` is per-boot, so a struct
    /// cannot be replayed across a reset. Never write to this.
    pub hmac: [u8; 32],
    /// Which slots [`PinOp::Change`](crate::abi::PinOp::Change) should act on, and the
    /// long-secret block index. See [`change`](crate::abi::change).
    pub change_flags: i32,
    pub old_pin: [u8; MAX_PIN_LEN],
    pub old_pin_len: i32,
    pub new_pin: [u8; MAX_PIN_LEN],
    pub new_pin_len: i32,
    /// The wallet secret, in `SecretStash` encoding. See [`SecretKind`].
    pub secret: [u8; SECRET_LEN],
    /// Main PIN cached by the bootloader across a duress-wallet login.
    pub cached_main_pin: [u8; MAX_PIN_LEN],
}

impl Default for PinAttempt {
    fn default() -> Self {
        Self::new()
    }
}

impl PinAttempt {
    /// A fresh V2 attempt struct, ready for [`PinOp::Setup`](crate::abi::PinOp::Setup).
    pub const fn new() -> Self {
        Self {
            magic: PA_MAGIC_V2,
            is_secondary: 0,
            pin: [0; MAX_PIN_LEN],
            pin_len: 0,
            delay_achieved: 0,
            delay_required: 0,
            num_fails: 0,
            attempts_left: 0,
            state_flags: 0,
            private_state: 0,
            hmac: [0; 32],
            change_flags: 0,
            old_pin: [0; MAX_PIN_LEN],
            old_pin_len: 0,
            new_pin: [0; MAX_PIN_LEN],
            new_pin_len: 0,
            secret: [0; SECRET_LEN],
            cached_main_pin: [0; MAX_PIN_LEN],
        }
    }

    /// Set the PIN to test. Fails if it does not fit.
    pub fn set_pin(&mut self, pin: &[u8]) -> Result<(), PinTooLong> {
        if pin.len() > MAX_PIN_LEN {
            return Err(PinTooLong { len: pin.len() });
        }
        self.pin.zeroize();
        self.pin[..pin.len()].copy_from_slice(pin);
        self.pin_len = pin.len() as i32;
        Ok(())
    }

    pub fn is_blank(&self) -> bool {
        self.state_flags & crate::abi::state::IS_BLANK != 0
    }

    pub fn logged_in(&self) -> bool {
        self.state_flags & crate::abi::state::SUCCESSFUL != 0
    }

    /// Logged in, but no seed has been stored yet.
    pub fn has_zero_secret(&self) -> bool {
        self.state_flags & crate::abi::state::ZERO_SECRET != 0
    }
}

/// A PIN longer than the bootloader's field can hold.
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub struct PinTooLong {
    pub len: usize,
}

/// Compile-time proof that our field layout is the documented 280 bytes. If this ever
/// fails, the reading of `delay_*` in the reference is wrong and the driver would
/// silently corrupt the bootloader's HMAC.
const _: () = assert!(core::mem::size_of::<PinAttempt>() == PIN_ATTEMPT_SIZE);
const _: () = assert!(core::mem::align_of::<PinAttempt>() == 4);

/// How to interpret [`PinAttempt::secret`].
///
/// The bootloader hands back an encoded blob rather than raw key material; the marker
/// byte says which encoding. Source: bootloader-callgate-abi.md §"What this means" [C]
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub enum SecretKind {
    /// Nothing stored — the wallet is uninitialised.
    Empty,
    /// BIP-32 extended private key.
    Xprv,
    /// BIP-39 mnemonic entropy. The marker's low bits encode the length.
    Bip39 { marker: u8 },
    /// A marker we do not recognise; do not guess at it.
    Unknown { marker: u8 },
}

/// Classify a secret blob by its marker byte.
///
/// Source: bootloader-callgate-abi.md [C] — `0x01` = xprv, `0x80`+ = BIP-39 words.
/// The exact word-count encoding within the `0x80+` range is `[?]`; see
/// `docs/HARDWARE-OPEN-ITEMS.md`.
pub fn classify_secret(secret: &[u8; SECRET_LEN]) -> SecretKind {
    match secret[0] {
        0x00 if secret.iter().all(|&b| b == 0) => SecretKind::Empty,
        0x01 => SecretKind::Xprv,
        m if m >= 0x80 => SecretKind::Bip39 { marker: m },
        m => SecretKind::Unknown { marker: m },
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use core::mem::offset_of;

    #[test]
    fn layout_matches_documented_size() {
        assert_eq!(core::mem::size_of::<PinAttempt>(), 280);
        assert_eq!(PIN_ATTEMPT_SIZE, 280);
        // V1 differs by exactly the trailing cached_main_pin[32].
        assert_eq!(PIN_ATTEMPT_SIZE - PIN_ATTEMPT_SIZE_V1, MAX_PIN_LEN);
    }

    #[test]
    fn a_fresh_struct_carries_the_v2_magic() {
        // Without this the bootloader returns BAD_MAGIC before doing anything.
        assert_eq!(PinAttempt::new().magic, PA_MAGIC_V2);
        assert_eq!(PA_MAGIC_V2, 0x2eaf_6312);
        assert_eq!(PA_MAGIC_V1, 0x2eaf_6311);
        assert_ne!(PA_MAGIC_V1, PA_MAGIC_V2);
    }

    #[test]
    fn is_secondary_defaults_to_zero() {
        // Obsolete field; a non-zero value selects mk2 secondary-wallet behaviour.
        assert_eq!(PinAttempt::new().is_secondary, 0);
    }

    /// The field order is what the bootloader indexes by; these offsets are the
    /// arithmetic that makes the documented field list add up to 280.
    #[test]
    fn field_offsets() {
        assert_eq!(offset_of!(PinAttempt, magic), 0);
        assert_eq!(offset_of!(PinAttempt, is_secondary), 4);
        assert_eq!(offset_of!(PinAttempt, pin), 8);
        assert_eq!(offset_of!(PinAttempt, pin_len), 40);
        assert_eq!(offset_of!(PinAttempt, delay_achieved), 44);
        assert_eq!(offset_of!(PinAttempt, delay_required), 48);
        assert_eq!(offset_of!(PinAttempt, num_fails), 52);
        assert_eq!(offset_of!(PinAttempt, attempts_left), 56);
        assert_eq!(offset_of!(PinAttempt, state_flags), 60);
        assert_eq!(offset_of!(PinAttempt, private_state), 64);
        assert_eq!(offset_of!(PinAttempt, hmac), 68);
        assert_eq!(offset_of!(PinAttempt, change_flags), 100);
        assert_eq!(offset_of!(PinAttempt, old_pin), 104);
        assert_eq!(offset_of!(PinAttempt, old_pin_len), 136);
        assert_eq!(offset_of!(PinAttempt, new_pin), 140);
        assert_eq!(offset_of!(PinAttempt, new_pin_len), 172);
        assert_eq!(offset_of!(PinAttempt, secret), 176);
        assert_eq!(offset_of!(PinAttempt, cached_main_pin), 248);
    }

    #[test]
    fn it_fits_the_callgate_buffer_limit() {
        const { assert!(PIN_ATTEMPT_SIZE <= crate::abi::MAX_BUF_LEN) };
    }

    #[test]
    fn set_pin_bounds() {
        let mut pa = PinAttempt::new();
        assert!(pa.set_pin(b"12-34").is_ok());
        assert_eq!(pa.pin_len, 5);
        assert_eq!(&pa.pin[..5], b"12-34");
        assert!(pa.set_pin(&[b'1'; 33]).is_err());
    }

    #[test]
    fn set_pin_clears_the_previous_value() {
        let mut pa = PinAttempt::new();
        pa.set_pin(b"123456789012").unwrap();
        pa.set_pin(b"12-34").unwrap();
        assert!(
            pa.pin[5..].iter().all(|&b| b == 0),
            "stale PIN digits left in the buffer"
        );
    }

    #[test]
    fn secret_classification() {
        assert_eq!(classify_secret(&[0; SECRET_LEN]), SecretKind::Empty);

        let mut s = [0u8; SECRET_LEN];
        s[0] = 0x01;
        assert_eq!(classify_secret(&s), SecretKind::Xprv);

        s[0] = 0x82;
        assert_eq!(classify_secret(&s), SecretKind::Bip39 { marker: 0x82 });

        s[0] = 0x42;
        assert_eq!(classify_secret(&s), SecretKind::Unknown { marker: 0x42 });
    }

    #[test]
    fn a_zero_marker_with_nonzero_tail_is_not_empty() {
        let mut s = [0u8; SECRET_LEN];
        s[10] = 1;
        assert_eq!(classify_secret(&s), SecretKind::Unknown { marker: 0 });
    }

    #[test]
    fn state_flag_helpers() {
        let mut pa = PinAttempt::new();
        pa.state_flags = crate::abi::state::SUCCESSFUL | crate::abi::state::ZERO_SECRET;
        assert!(pa.logged_in());
        assert!(pa.has_zero_secret());
        assert!(!pa.is_blank());
    }
}
