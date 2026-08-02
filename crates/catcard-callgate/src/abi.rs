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
/// The reference documents the endpoints (`-100`, `-105`, `-112`) and that the range
/// is contiguous; the intermediate names are **not** documented and are deliberately
/// left unnamed rather than guessed. Source: bootloader-callgate-abi.md [C]
pub mod err {
    /// The attempt struct's HMAC did not verify — it was tampered with or is stale.
    pub const HMAC_FAIL: i32 = -100;
    /// The device is bricked: the pairing secret no longer works.
    pub const I_AM_BRICK: i32 = -105;
    /// Authentication against the secure element failed.
    pub const AUTH_FAIL: i32 = -112;

    /// Any return value in this range is a PIN-subsystem error.
    pub const FIRST: i32 = -112;
    pub const LAST: i32 = -100;

    pub fn is_pin_error(rv: i32) -> bool {
        (FIRST..=LAST).contains(&rv)
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
    fn pin_error_range() {
        assert!(err::is_pin_error(err::HMAC_FAIL));
        assert!(err::is_pin_error(err::AUTH_FAIL));
        assert!(err::is_pin_error(err::I_AM_BRICK));
        assert!(!err::is_pin_error(0));
        assert!(!err::is_pin_error(-1));
        assert!(!err::is_pin_error(-113));
    }
}
