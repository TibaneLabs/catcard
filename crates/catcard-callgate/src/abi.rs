//! Method numbers, argument encodings and error codes.
//!
//! Source: `hw-reference/bootloader-callgate-abi.md` [C].

/// Callgate method selector (the first argument).
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
#[repr(i32)]
pub enum Method {
    /// Bootloader version string into `buf_io` (>=64 bytes); returns strlen.
    GetBootloaderVersion = 0,
    /// SHA-256 over (32-bit salt || bootloader flash) — anti-replay self-attestation.
    GetBootloaderChecksum = 1,
    /// Wipe SRAM, show a screen, reboot to DFU. See [`DfuMode`].
    EnterDfu = 2,
    /// Wipe all SRAM and lock up or reboot. See [`LogoutMode`].
    ShowLogout = 3,
    /// Read/clear/verify the ATECC-driven "genuine" light. See [`GenuineOp`].
    GenuineLight = 4,
    /// Non-zero return if the pairing secret no longer works (device is bricked).
    IsBricked = 5,
    /// Returns 0 when an ATECC608 is present.
    Has608 = 6,
    /// Read the DFU/select button state into `buf_io[0]` (selftest).
    GetDfuButton = 12,
    /// Read a non-encrypted SE data slot (`arg2` = slot 0..=15) into `buf_io`.
    ReadDataSlot = 15,
    /// Anti-phishing words: HMAC over a PIN prefix, in place in `buf_io`.
    AntiPhishingWords = 16,
    /// 32 bytes from the bootloader's own STM32 TRNG.
    GetBootloaderRng = 17,
    /// The PIN/secret API. `arg2` selects a [`PinOp`]; `buf_io` is a
    /// [`PinAttempt`](crate::pin::PinAttempt).
    PinAttempt = 18,
    /// Factory bag number, and the irreversible RDP lockdown. See [`BagOp`].
    BagNumber = 19,
    /// Read the full 128-byte ATECC config zone.
    ReadSeConfig = 20,
    /// Anti-downgrade high-water mark and the SE monotonic counter. See [`OtpOp`].
    Downgrade = 21,
    /// Read TRNG bytes from a secure element. `arg2` selects [`RngSource`].
    /// mk4 and later only.
    ReadSeRng = 26,
}

/// `arg2` for [`Method::EnterDfu`].
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
#[repr(u32)]
pub enum DfuMode {
    /// Normal DFU entry. Refused on RDP=2 units, which lock up instead.
    Normal = 0,
    Downgrade = 1,
    Blank = 2,
    /// Irreversible: destroys the pairing secret.
    Brick = 3,
}

/// `arg2` for [`Method::ShowLogout`].
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
#[repr(u32)]
pub enum LogoutMode {
    /// Show the logout screen, wipe SRAM, lock up.
    Logout = 0,
    /// Keep the current screen contents.
    KeepScreen = 1,
    /// Logout screen, then reboot.
    LogoutAndReboot = 2,
}

/// `arg2` for [`Method::GenuineLight`].
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
#[repr(u32)]
pub enum GenuineOp {
    Read = 0,
    Clear = 1,
    /// Documented as always failing — the light cannot be set without a checksum match.
    Set = 2,
    /// Checksum flash, then set the light only if it matches what the SE has committed.
    VerifyAndSet = 3,
}

/// `arg2` for [`Method::BagNumber`].
///
/// The lockdown values are **irreversible**. RDP=2 permanently disables SWD and DFU;
/// there is no recovery. Nothing in this crate calls them.
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
#[repr(u32)]
pub enum BagOp {
    Read = 0,
    Set = 1,
    SetRdpLevel0 = 100,
    SetRdpLevel1 = 101,
    SetRdpLevel2 = 102,
}

/// `arg2` for [`Method::Downgrade`].
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
#[repr(u32)]
pub enum OtpOp {
    /// Read the minimum acceptable firmware timestamp (the high-water mark).
    ReadMinVersion = 0,
    /// Check a candidate timestamp against it.
    Check = 1,
    /// Record a new high-water mark. Irreversible.
    Record = 2,
    /// Read the SE monotonic counter.
    Counter = 3,
}

/// `arg2` for [`Method::ReadSeRng`].
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
#[repr(u32)]
pub enum RngSource {
    /// ATECC608 `Random`.
    Se1 = 1,
    /// The second secure element (mk4+).
    Se2 = 2,
}

/// `arg2` for [`Method::PinAttempt`].
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
#[repr(u32)]
pub enum PinOp {
    /// Initialise the attempt struct; returns state flags and attempts-left.
    Setup = 0,
    /// Obsolete on ATECC608 — rate limiting is enforced by the SE's KDF.
    Delay = 1,
    /// Test a PIN. On success, unlocks secret access.
    Login = 2,
    /// Change a PIN and/or a secret slot.
    Change = 3,
    /// Return the wallet secret after a successful login.
    FetchSecret = 4,
    /// Commit the firmware checksum to the SE and turn the genuine light green.
    GreenLight = 5,
    /// Read or write the 416-byte long secret, 32 bytes at a time.
    LongSecret = 6,
}

/// The largest `buf_io` the bootloader will accept.
/// Source: bootloader-callgate-abi.md [C]
pub const MAX_BUF_LEN: usize = 1024;

/// Error codes returned by [`Method::PinAttempt`].
///
/// Source: bootloader-callgate-abi.md, gate18-pin-state-machine.md §5 [C]
pub mod err {
    /// The attempt struct's HMAC did not verify: tampered with, or from a previous boot.
    pub const HMAC_FAIL: i32 = -100;
    /// This method requires a signed struct; run [`PinOp::Setup`](super::PinOp::Setup).
    pub const HMAC_REQUIRED: i32 = -101;
    /// Wrong `magic_value` — usually a V1/V2 struct mismatch.
    pub const BAD_MAGIC: i32 = -102;
    /// A length or offset field was out of range.
    pub const RANGE_ERR: i32 = -103;
    pub const BAD_REQUEST: i32 = -104;
    /// The device is bricked: the pairing secret no longer works. Stop and enter DFU.
    pub const I_AM_BRICK: i32 = -105;
    /// The secure element did not respond as expected.
    pub const AE_FAIL: i32 = -106;
    pub const MUST_WAIT: i32 = -107;
    pub const PIN_REQUIRED: i32 = -108;
    pub const WRONG_SUCCESS: i32 = -109;
    /// The struct is from an earlier boot; `reboot_seed` changed.
    pub const OLD_ATTEMPT: i32 = -110;
    pub const AUTH_MISMATCH: i32 = -111;
    /// Wrong PIN. The secure element's failure counter has been incremented.
    pub const AUTH_FAIL: i32 = -112;
    pub const OLD_AUTH_FAIL: i32 = -113;
    /// Operation is only valid for the primary wallet.
    pub const PRIMARY_ONLY: i32 = -114;

    /// Any return value in this range is a PIN-subsystem error.
    pub const FIRST: i32 = PRIMARY_ONLY;
    pub const LAST: i32 = HMAC_FAIL;

    pub fn is_pin_error(rv: i32) -> bool {
        (FIRST..=LAST).contains(&rv)
    }

    /// True if the device has destroyed its pairing secret and can never be recovered.
    pub fn is_bricked(rv: i32) -> bool {
        rv == I_AM_BRICK
    }
}

/// `change_flags` values for [`PinOp::Change`].
///
/// Source: gate18-pin-state-machine.md §4 [C]
pub mod change {
    pub const WALLET_PIN: i32 = 0x001;
    pub const DURESS_PIN: i32 = 0x002;
    /// Setting this PIN arms a code that **destroys the pairing secret** when entered.
    pub const BRICKME_PIN: i32 = 0x004;
    pub const SECRET: i32 = 0x008;
    pub const DURESS_SECRET: i32 = 0x010;
    /// Obsolete: secondary wallets existed only on the mk2's ATECC508.
    pub const SECONDARY_WALLET_PIN: i32 = 0x020;
    /// Long-secret block index, shifted left by 8.
    pub const LS_OFFSET_MASK: i32 = 0xf00;
    pub const LS_OFFSET_SHIFT: u32 = 8;
    /// Every bit the bootloader accepts.
    pub const VALID_MASK: i32 = 0xf3f;

    /// Encode a long-secret block index into `change_flags`.
    pub const fn ls_offset(block: u32) -> i32 {
        ((block << LS_OFFSET_SHIFT) as i32) & LS_OFFSET_MASK
    }
}

/// `state_flags` bits in [`PinAttempt`](crate::pin::PinAttempt).
/// Source: bootloader-callgate-abi.md [C]
pub mod state {
    /// The last login attempt succeeded.
    pub const SUCCESSFUL: u32 = 0x01;
    /// No PIN is set — the device is blank.
    pub const IS_BLANK: u32 = 0x02;
    pub const HAS_DURESS: u32 = 0x04;
    pub const HAS_BRICKME: u32 = 0x08;
    /// The secret slot is all zeroes: logged in, but no wallet seed stored yet.
    pub const ZERO_SECRET: u32 = 0x10;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn method_numbers_match_the_reference_table() {
        assert_eq!(Method::GetBootloaderVersion as i32, 0);
        assert_eq!(Method::EnterDfu as i32, 2);
        assert_eq!(Method::Has608 as i32, 6);
        assert_eq!(Method::ReadDataSlot as i32, 15);
        assert_eq!(Method::GetBootloaderRng as i32, 17);
        assert_eq!(Method::PinAttempt as i32, 18);
        assert_eq!(Method::ReadSeConfig as i32, 20);
        assert_eq!(Method::Downgrade as i32, 21);
        assert_eq!(Method::ReadSeRng as i32, 26);
    }

    #[test]
    fn pin_error_range_covers_every_documented_code() {
        for rv in [
            err::HMAC_FAIL,
            err::HMAC_REQUIRED,
            err::BAD_MAGIC,
            err::RANGE_ERR,
            err::BAD_REQUEST,
            err::I_AM_BRICK,
            err::AE_FAIL,
            err::MUST_WAIT,
            err::PIN_REQUIRED,
            err::WRONG_SUCCESS,
            err::OLD_ATTEMPT,
            err::AUTH_MISMATCH,
            err::AUTH_FAIL,
            err::OLD_AUTH_FAIL,
            err::PRIMARY_ONLY,
        ] {
            assert!(err::is_pin_error(rv), "{rv} not classified as a PIN error");
        }
        assert_eq!(err::FIRST, -114);
        assert_eq!(err::LAST, -100);
        assert!(!err::is_pin_error(0));
        assert!(!err::is_pin_error(-1));
        // -115 is past the documented range; do not claim to recognise it.
        assert!(!err::is_pin_error(-115));
    }

    #[test]
    fn brick_is_singled_out() {
        assert!(err::is_bricked(err::I_AM_BRICK));
        assert!(!err::is_bricked(err::AUTH_FAIL));
    }

    #[test]
    fn change_flags_fit_the_valid_mask() {
        for f in [
            change::WALLET_PIN,
            change::DURESS_PIN,
            change::BRICKME_PIN,
            change::SECRET,
            change::DURESS_SECRET,
            change::SECONDARY_WALLET_PIN,
        ] {
            assert_eq!(
                f & change::VALID_MASK,
                f,
                "{f:#x} outside the accepted mask"
            );
        }
        assert_eq!(
            change::LS_OFFSET_MASK & change::VALID_MASK,
            change::LS_OFFSET_MASK
        );
    }

    #[test]
    fn long_secret_offsets_encode_into_the_right_field() {
        assert_eq!(change::ls_offset(0), 0x000);
        assert_eq!(change::ls_offset(1), 0x100);
        assert_eq!(change::ls_offset(12), 0xc00);
        // The 416-byte long secret is 13 blocks of 32; all of them must fit.
        for block in 0..13u32 {
            let f = change::ls_offset(block);
            assert_eq!(f & change::LS_OFFSET_MASK, f);
            assert_eq!((f >> change::LS_OFFSET_SHIFT) as u32, block);
        }
    }
}
