//! The bootloader callgate — CatCard's only route to PIN, secrets and SE entropy.
//!
//! The Coldcard bootloader sits in protected flash below our firmware and cannot be
//! replaced (at RDP=2 it cannot even be read). It owns the pairing secret, PIN
//! rate-limiting, secure-element authentication, the genuine light, and DFU. App
//! firmware reaches all of it through one entry point, whose address the bootloader
//! publishes in a table at `0x0800_0040` — see [`entry`].
//!
//! ```ignore
//! let gate = unsafe { Callgate::discover(&BOARD) }?;
//! let mut buf = [0u8; 32];
//! unsafe { gate.bootloader_rng(&mut buf) }?;
//! ```
//!
//! Two things about this interface are easy to get wrong and fatal in different ways:
//!
//! - **It is not an AAPCS call.** The buffer *length* goes in `r2`, where a normal
//!   three-argument C function would put the scalar argument. Calling it through an
//!   `extern "C"` function pointer compiles fine and passes garbage.
//! - **Interrupts must be masked.** An interrupt taken inside firewall-protected code
//!   closes the firewall, which the hardware treats as a violation and resets the CPU.
//!
//! [`Callgate::call`] handles both.
//!
//! Source: `hw-reference/bootloader-callgate-abi.md` [C].

#![cfg_attr(not(test), no_std)]
#![deny(unsafe_op_in_unsafe_fn)]

pub mod abi;
pub mod entry;
pub mod pin;

use abi::{err, Method, PinOp, RngSource, MAX_BUF_LEN};
use catcard_board::BoardSpec;
use entry::{BootloaderInfo, EntryError};
use pin::{PinAttempt, PIN_ATTEMPT_SIZE};

#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub enum Error {
    /// The bootloader info table did not yield a usable entry address.
    Entry(EntryError),
    /// `buf_io` is not in SRAM1. The bootloader would reject it.
    BufferNotInSram1 { addr: u32, len: usize },
    /// `buf_io` is larger than the bootloader accepts.
    BufferTooLong { len: usize },
    /// The buffer is too small for the method's documented output.
    BufferTooShort { len: usize, need: usize },
    /// A PIN-subsystem error (`-114 ..= -100`). See [`abi::err`].
    Pin(i32),
    /// Any other non-zero return.
    Failed(i32),
}

impl From<EntryError> for Error {
    fn from(e: EntryError) -> Self {
        Error::Entry(e)
    }
}

/// Verify a `buf_io` against the bootloader's own range check, before we make the call
/// rather than after it rejects us.
///
/// Source: bootloader-callgate-abi.md [C] — "must be in SRAM1, `len <= 1024`".
pub fn check_buffer(sram1_base: u32, sram1_len: u32, addr: u32, len: usize) -> Result<(), Error> {
    if len > MAX_BUF_LEN {
        return Err(Error::BufferTooLong { len });
    }
    let end = addr as u64 + len as u64;
    let sram_end = sram1_base as u64 + sram1_len as u64;
    if (addr as u64) < sram1_base as u64 || end > sram_end {
        return Err(Error::BufferNotInSram1 { addr, len });
    }
    Ok(())
}

/// A bound callgate: a validated entry address, the bootloader's protocol version, and
/// the SRAM1 window to validate buffers against.
#[derive(Copy, Clone, Debug)]
pub struct Callgate {
    info: BootloaderInfo,
    sram1_base: u32,
    sram1_len: u32,
}

impl Callgate {
    /// Read the entry address the running bootloader published, validate it, and bind.
    ///
    /// # Safety
    ///
    /// `board` must describe the hardware this is running on — its firmware base bounds
    /// the range the entry address is accepted in, and its SRAM1 window is what buffers
    /// are checked against.
    pub unsafe fn discover(board: &BoardSpec) -> Result<Self, Error> {
        // SAFETY: reads two words of mapped main flash.
        let info = unsafe { entry::read_info_table(board)? };
        // SAFETY: `info.callgate_entry` was validated by `read_info_table`.
        Ok(unsafe { Self::bind(info, board) })
    }

    /// Bind to an already-validated info table.
    ///
    /// # Safety
    ///
    /// `info.callgate_entry` must be the real callgate entry point for the running
    /// bootloader — normally because it came from [`entry::read_info_table`]. Branching
    /// anywhere else inside the protected segment resets the CPU.
    pub const unsafe fn bind(info: BootloaderInfo, board: &BoardSpec) -> Self {
        Self {
            info,
            sram1_base: board.memory.sram1_base,
            sram1_len: board.memory.sram1_len,
        }
    }

    /// The bootloader's callgate protocol version. Check it before relying on a method
    /// that a later bootloader added.
    pub const fn info(&self) -> BootloaderInfo {
        self.info
    }

    /// Invoke the callgate with a buffer.
    ///
    /// Range-checks `buf` the way the bootloader does, masks interrupts for the
    /// duration, and passes the pointer and length in `r1`/`r2` with `arg2` in `r3`.
    ///
    /// # Safety
    ///
    /// `buf` must satisfy the selected method's documented contract — the bootloader
    /// writes into it using the length the *method* implies.
    pub unsafe fn call(&self, method: Method, buf: &mut [u8], arg2: u32) -> Result<i32, Error> {
        check_buffer(
            self.sram1_base,
            self.sram1_len,
            buf.as_ptr() as u32,
            buf.len(),
        )?;
        // SAFETY: buffer range-checked above; entry validated at construction.
        let rv = unsafe { self.raw(method as i32, buf.as_mut_ptr(), buf.len() as u32, arg2) };
        Self::decode(rv)
    }

    /// Invoke a method that takes no buffer, passing NULL/0.
    ///
    /// Not the same as passing an empty slice: an empty slice's pointer is a dangling
    /// non-null value that would fail the SRAM1 range check.
    ///
    /// # Safety
    ///
    /// `method` must be one that takes no `buf_io`.
    pub unsafe fn call_no_buf(&self, method: Method, arg2: u32) -> Result<i32, Error> {
        // SAFETY: NULL/0 is the documented encoding for "no buffer".
        let rv = unsafe { self.raw(method as i32, core::ptr::null_mut(), 0, arg2) };
        Self::decode(rv)
    }

    /// # Safety
    /// See [`entry::invoke`]. Callers must have range-checked any buffer.
    unsafe fn raw(&self, method: i32, buf: *mut u8, len: u32, arg2: u32) -> i32 {
        let dest = self.info.callgate_entry;
        // SAFETY: an interrupt taken inside firewall code resets the CPU, so the call
        // must happen with interrupts masked; `dest` was validated at construction.
        unsafe { entry::with_interrupts_masked(|| entry::invoke(dest, method, buf, len, arg2)) }
    }

    fn decode(rv: i32) -> Result<i32, Error> {
        match rv {
            rv if rv >= 0 => Ok(rv),
            rv if err::is_pin_error(rv) => Err(Error::Pin(rv)),
            rv => Err(Error::Failed(rv)),
        }
    }

    // -- convenience wrappers -------------------------------------------------

    /// Callgate 0: bootloader version string. Returns the length written.
    ///
    /// # Safety
    /// See [`Self::call`].
    pub unsafe fn bootloader_version(&self, buf: &mut [u8]) -> Result<usize, Error> {
        if buf.len() < 64 {
            return Err(Error::BufferTooShort {
                len: buf.len(),
                need: 64,
            });
        }
        // SAFETY: buffer meets the documented >=64-byte output contract.
        let n = unsafe { self.call(Method::GetBootloaderVersion, buf, 0)? };
        Ok(n as usize)
    }

    /// Callgate 5: has the pairing secret stopped working?
    ///
    /// # Safety
    /// See [`Self::call_no_buf`].
    pub unsafe fn is_bricked(&self) -> Result<bool, Error> {
        // SAFETY: this method takes no buffer.
        Ok(unsafe { self.call_no_buf(Method::IsBricked, 0)? } != 0)
    }

    /// Callgate 6: is an ATECC608 present (as opposed to the mk2's 508)?
    ///
    /// # Safety
    /// See [`Self::call_no_buf`].
    pub unsafe fn has_608(&self) -> bool {
        // SAFETY: this method takes no buffer. Returns 0 when present, ENOENT if not.
        matches!(unsafe { self.call_no_buf(Method::Has608, 0) }, Ok(0))
    }

    /// Callgate 17: 32 bytes from the bootloader's STM32 TRNG.
    ///
    /// # Safety
    /// See [`Self::call`].
    pub unsafe fn bootloader_rng(&self, out: &mut [u8; 32]) -> Result<(), Error> {
        // SAFETY: exactly the documented 32-byte output buffer.
        unsafe { self.call(Method::GetBootloaderRng, out.as_mut_slice(), 0)? };
        Ok(())
    }

    /// Callgate 26: TRNG bytes from a secure element (mk4+).
    ///
    /// The buffer comes back as `[len][bytes...]`; returns how many bytes are valid.
    ///
    /// # Safety
    /// See [`Self::call`].
    pub unsafe fn se_rng(&self, source: RngSource, out: &mut [u8; 33]) -> Result<usize, Error> {
        // SAFETY: exactly the documented 33-byte output buffer.
        unsafe { self.call(Method::ReadSeRng, out.as_mut_slice(), source as u32)? };
        let n = out[0] as usize;
        if n > 32 {
            // A length byte larger than the buffer means we did not get what the ABI
            // describes; treating it as valid would read uninitialised bytes.
            return Err(Error::Failed(-1));
        }
        Ok(n)
    }

    /// Callgate 18 with a [`PinAttempt`] buffer.
    ///
    /// # Safety
    ///
    /// `attempt` must live in SRAM1 (checked) and, except for
    /// [`PinOp::Setup`](abi::PinOp::Setup), must be a struct the bootloader previously
    /// signed — it validates the embedded HMAC on every other call.
    pub unsafe fn pin_attempt(&self, op: PinOp, attempt: &mut PinAttempt) -> Result<i32, Error> {
        // SAFETY: `PinAttempt` is `#[repr(C)]` and exactly `PIN_ATTEMPT_SIZE` bytes
        // (statically asserted), so viewing it as a byte buffer is well defined.
        let buf = unsafe {
            core::slice::from_raw_parts_mut(attempt as *mut PinAttempt as *mut u8, PIN_ATTEMPT_SIZE)
        };
        // SAFETY: buffer matches the documented `pinAttempt_t` contract.
        unsafe { self.call(Method::PinAttempt, buf, op as u32) }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const BASE: u32 = 0x2000_0000;
    const LEN: u32 = 192 * 1024;

    #[test]
    fn buffer_must_be_inside_sram1() {
        assert!(check_buffer(BASE, LEN, BASE, 280).is_ok());
        assert!(check_buffer(BASE, LEN, BASE + LEN - 280, 280).is_ok());

        // Just below SRAM1.
        assert!(matches!(
            check_buffer(BASE, LEN, BASE - 4, 8),
            Err(Error::BufferNotInSram1 { .. })
        ));
        // Runs off the end.
        assert!(matches!(
            check_buffer(BASE, LEN, BASE + LEN - 4, 8),
            Err(Error::BufferNotInSram1 { .. })
        ));
        // The SRAM2 alias window the bootloader reserves is not SRAM1.
        assert!(matches!(
            check_buffer(BASE, LEN, 0x1000_6000, 32),
            Err(Error::BufferNotInSram1 { .. })
        ));
    }

    #[test]
    fn buffer_length_is_capped_at_1024() {
        assert!(check_buffer(BASE, LEN, BASE, MAX_BUF_LEN).is_ok());
        assert!(matches!(
            check_buffer(BASE, LEN, BASE, MAX_BUF_LEN + 1),
            Err(Error::BufferTooLong { .. })
        ));
    }

    #[test]
    fn address_arithmetic_does_not_overflow() {
        // A bogus pointer near the top of the address space must be rejected, not wrap.
        assert!(matches!(
            check_buffer(BASE, LEN, u32::MAX - 4, 64),
            Err(Error::BufferNotInSram1 { .. })
        ));
    }

    #[test]
    fn a_pin_attempt_fits_the_buffer_limit_on_every_board() {
        for b in catcard_board::spec::ALL {
            assert!(
                check_buffer(
                    b.memory.sram1_base,
                    b.memory.sram1_len,
                    b.memory.sram1_base,
                    PIN_ATTEMPT_SIZE
                )
                .is_ok(),
                "{}",
                b.name
            );
        }
    }

    #[test]
    fn return_codes_are_classified() {
        assert_eq!(Callgate::decode(0), Ok(0));
        assert_eq!(Callgate::decode(64), Ok(64));
        assert_eq!(
            Callgate::decode(err::AUTH_FAIL),
            Err(Error::Pin(err::AUTH_FAIL))
        );
        assert_eq!(
            Callgate::decode(err::PRIMARY_ONLY),
            Err(Error::Pin(err::PRIMARY_ONLY))
        );
        // Outside the PIN range: a generic failure, not a PIN error.
        assert_eq!(Callgate::decode(-2), Err(Error::Failed(-2)));
        assert_eq!(Callgate::decode(-115), Err(Error::Failed(-115)));
    }
}
