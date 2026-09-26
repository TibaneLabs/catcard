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

use abi::{BagOp, GenuineOp, MAX_BUF_LEN, Method, OtpOp, PinOp, RngSource, err};
use catcard_board::BoardSpec;
use entry::{BootloaderInfo, EntryError};
use pin::{PIN_ATTEMPT_SIZE, PinAttempt};
use zeroize::Zeroize;

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
/// `window` is how much of SRAM1, from its base, *this board's bootloader* accepts — which
/// is not always all of it. The mk3's takes only the first 96 KB and answers a buffer above
/// that with `1`: a generic error, indistinguishable from success to a caller that only
/// looks for a negative return, and with nothing written into the buffer. See
/// [`BoardSpec::gate_buf_len`](catcard_board::spec::BoardSpec::gate_buf_len).
///
/// Source: bootloader-callgate-abi.md [C] — "must be in SRAM1, `len <= 1024`"; the window
/// itself measured on hardware.
pub fn check_buffer(sram1_base: u32, window: u32, addr: u32, len: usize) -> Result<(), Error> {
    if len > MAX_BUF_LEN {
        return Err(Error::BufferTooLong { len });
    }
    let end = addr as u64 + len as u64;
    let window_end = sram1_base as u64 + window as u64;
    if (addr as u64) < sram1_base as u64 || end > window_end {
        return Err(Error::BufferNotInSram1 { addr, len });
    }
    Ok(())
}

/// The buffer every call actually hands the bootloader.
///
/// A caller's `pinAttempt_t` or output buffer is wherever the caller put it, and on a stack
/// that is the *top* of SRAM1 — which the mk3's bootloader refuses. A static lands in
/// `.bss`, at the bottom of RAM, inside every window we know of; the caller's bytes are
/// copied in and the answer copied back. One memcpy of at most a kilobyte per call, against
/// a failure mode whose symptom was a device that could not be logged into at all.
///
/// Only ever touched between masking and unmasking interrupts, inside [`Callgate::call`],
/// so there is no second reference to alias. Wiped before that call returns, so a secret
/// the caller's own type zeroizes does not outlive it here.
///
/// **Pinned to the base of SRAM1** through a dedicated `.gate_buf` linker section (placed
/// first in RAM by `catcard-fw/build.rs`), so it stays inside the mk3 bootloader's 96 KB
/// callgate window (`0x2000_0000`–`0x2001_8000`) no matter how much `.bss` grows above it.
/// It used to be an ordinary `.bss` static, and once `.bss` drifted past 96 KB the mk3 gate
/// began refusing every call — the device could not be logged in at all.
/// Source: hw-reference/bootloader-callgate-abi.md §0.1 [C].
///
/// `MaybeUninit` because that section is `(NOLOAD)`: the bootloader hands off by a plain
/// jump and cortex-m-rt only clears `.bss`, so nothing zero-initialises this. That is sound
/// — the caller's `len` bytes are always copied in before anything is read back (never past
/// that `len`), and the buffer is zeroized after every call.
///
/// The `link_section` is applied only for the bare-metal target: a Mach-O/ELF host build
/// (the crate's own tests) would reject the section name, and there the placement does not
/// matter.
#[cfg_attr(target_os = "none", unsafe(link_section = ".gate_buf"))]
static mut GATE_BUF: core::mem::MaybeUninit<[u8; MAX_BUF_LEN]> = core::mem::MaybeUninit::uninit();

/// A bound callgate: a validated entry address, the bootloader's protocol version, and
/// the SRAM1 window to validate buffers against.
#[derive(Copy, Clone, Debug)]
pub struct Callgate {
    info: BootloaderInfo,
    sram1_base: u32,
    /// How much of SRAM1 this bootloader accepts a buffer in; see [`check_buffer`].
    gate_buf_len: u32,
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
            gate_buf_len: board.gate_buf_len,
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
        if buf.len() > MAX_BUF_LEN {
            return Err(Error::BufferTooLong { len: buf.len() });
        }
        // The caller's buffer is wherever the caller put it -- on the stack, at the top of
        // SRAM1 -- so hand the bootloader the static instead and copy both ways around the
        // call. `GATE_BUF` is checked against this board's window rather than assumed to be
        // inside it: a future `.bss` that grew past 96 KB would otherwise reintroduce
        // exactly the silent failure this exists to prevent.
        let len = buf.len();
        let staging = core::ptr::addr_of_mut!(GATE_BUF) as *mut u8;
        check_buffer(self.sram1_base, self.gate_buf_len, staging as u32, len)?;

        // SAFETY: interrupts are masked for the whole of this, so nothing else can reach
        // `GATE_BUF`; `staging` is a static of `MAX_BUF_LEN` bytes and `len` is bounded by
        // it; the entry was validated at construction.
        let rv = unsafe {
            entry::with_interrupts_masked(|| {
                core::ptr::copy_nonoverlapping(buf.as_ptr(), staging, len);
                let rv = entry::invoke(
                    self.info.callgate_entry,
                    method as i32,
                    staging,
                    len as u32,
                    arg2,
                );
                core::ptr::copy_nonoverlapping(staging, buf.as_mut_ptr(), len);
                // What passes through here is the caller's whole struct: `PinAttempt`
                // carries the plaintext PIN, and after `FetchSecret` the wallet secret.
                // Those types zeroize themselves; this static would keep a copy of them
                // in `.bss` for the rest of the run.
                core::slice::from_raw_parts_mut(staging, len).zeroize();
                rv
            })
        };
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

    /// Callgate 16: the two anti-phishing words for a PIN prefix.
    ///
    /// The bootloader HMACs the prefix under a key only it holds and returns 32 bits,
    /// which the caller renders as two words from a fixed list. Showing them between
    /// the prefix and the suffix is what lets the user detect a substituted device:
    /// an impostor cannot compute them, because it does not have the pairing secret.
    ///
    /// `buf` carries the prefix in and the four bytes out, so it must be at least
    /// [`MAX_PIN_LEN`](pin::MAX_PIN_LEN) long. Returns the 32 bits.
    ///
    /// # Safety
    /// See [`Self::call`].
    pub unsafe fn anti_phishing_words(&self, prefix: &[u8]) -> Result<u32, Error> {
        if prefix.len() > pin::MAX_PIN_LEN {
            return Err(Error::Failed(err::RANGE_ERR));
        }
        // The gate reads the prefix from the buffer and writes its answer back into it,
        // so the buffer is sized for the larger of the two rather than for the prefix.
        let mut buf = [0u8; pin::MAX_PIN_LEN];
        buf[..prefix.len()].copy_from_slice(prefix);
        // SAFETY: `arg2` is the prefix length, as documented; the buffer is MAX_PIN_LEN.
        let outcome =
            unsafe { self.call(Method::AntiPhishingWords, &mut buf, prefix.len() as u32) };
        let words = u32::from_le_bytes([buf[0], buf[1], buf[2], buf[3]]);
        // The gate writes its four bytes over the front of the buffer and leaves the rest
        // as it found it -- which is the PIN prefix. Wiped before this returns, whichever
        // way the call went, so the prefix does not outlive the call in a dead frame.
        buf.zeroize();
        outcome?;
        Ok(words)
    }

    /// Callgate 3: wipe every byte of SRAM, then lock up or reboot.
    ///
    /// **This does not return, in any mode** — the bootloader clears the SRAM we are
    /// running out of, so there is nothing to return to. That is the point: it can wipe
    /// memory that code executing from SRAM could not.
    ///
    /// [`LogoutMode::LogoutAndReboot`] is how firmware asks for a clean restart, and is
    /// the last step of staging an upgrade: the bootloader looks for a staged image
    /// while it boots.
    ///
    /// # Safety
    /// Everything in SRAM is gone afterwards. See [`Self::call_no_buf`].
    pub unsafe fn logout(&self, mode: abi::LogoutMode) -> ! {
        // SAFETY: this method takes no buffer.
        let _ = unsafe { self.call_no_buf(Method::ShowLogout, mode as u32) };
        // Only reached if the gate is not what we think it is. Nothing here is safe to
        // carry on with — SRAM may be half-wiped — so stop rather than return.
        loop {
            core::hint::spin_loop();
        }
    }

    /// Callgate 2: wipe SRAM, show a screen, and reboot into DFU.
    ///
    /// **Does not return.** On an RDP=2 unit the bootloader refuses DFU and locks up
    /// instead, which is the documented behaviour and not a fault.
    ///
    /// # Safety
    /// Irreversible from the running firmware's point of view. See [`Self::call_no_buf`].
    pub unsafe fn enter_dfu(&self, mode: abi::DfuMode) -> ! {
        // SAFETY: this method takes no buffer.
        let _ = unsafe { self.call_no_buf(Method::EnterDfu, mode as u32) };
        loop {
            core::hint::spin_loop();
        }
    }

    /// Callgate 23: wipe the seed and reset. **Irreversible, and does not return.**
    ///
    /// mk4 and later only. Needs no login, which is the point: it is how a device erases
    /// itself from the PIN prompt.
    ///
    /// Stock reaches this through `ckcc.oneway`, a second entry beside the gate
    /// (hw-reference/bootloader-callgate-abi.md §"A second entry point" [C]). Methods 2 and
    /// 3 are on the same list and answer through this gate on real hardware, so 23 is
    /// called the same way -- **inferred, not seen [I]**; docs/HARDWARE-OPEN-ITEMS.md. If
    /// the gate were to return instead, this stops rather than carrying on as though the
    /// seed were gone.
    ///
    /// # Safety
    /// Destroys the stored wallet. See [`Self::call_no_buf`].
    pub unsafe fn fast_wipe(&self, mode: abi::FastWipe) -> ! {
        // SAFETY: this method takes no buffer.
        let _ = unsafe { self.call_no_buf(Method::FastWipe, mode as u32) };
        loop {
            core::hint::spin_loop();
        }
    }

    /// Callgate 4: the ATECC-driven "genuine" light.
    ///
    /// Takes no buffer; `arg2` is the [`GenuineOp`]. [`GenuineOp::Read`] answers through
    /// the gate's return value, **whose encoding the reference does not state** -- it is
    /// handed up raw for a screen to show as the number it is, never decoded into
    /// "green" or "red" here. [`GenuineOp::VerifyAndSet`] checksums flash and lights the
    /// green only if that matches what the SE already holds; it cannot commit a new
    /// checksum -- that is gate 18/5, [`PinOp::GreenLight`], which needs a login.
    /// [`GenuineOp::Clear`] turns the light off and [`GenuineOp::Set`] is documented as
    /// always failing; nothing in this firmware calls either.
    ///
    /// Source: hw-reference/bootloader-callgate-abi.md method 4 [C]; the meaning of the
    /// `Read` return value [?] -- docs/HARDWARE-OPEN-ITEMS.md.
    ///
    /// # Safety
    /// See [`Self::call_no_buf`]. `VerifyAndSet` changes what the front LED shows.
    pub unsafe fn genuine_light(&self, op: GenuineOp) -> Result<i32, Error> {
        // SAFETY: this method takes no buffer.
        unsafe { self.call_no_buf(Method::GenuineLight, op as u32) }
    }

    /// Callgate 19/0: the factory bag number, **read only**.
    ///
    /// The 32 bytes of `rom_secrets.bag_number` as the bootloader hands them out; all
    /// `0xFF` on a unit that was never bagged. Only [`BagOp::Read`] is ever sent from
    /// here: `Set` is a factory step, and the `100+` values are the irreversible RDP
    /// lockdown, which no code in this crate issues.
    ///
    /// Source: hw-reference/bootloader-callgate-abi.md method 19 [C];
    /// platform.md §`rom_secrets_t` (32-byte field) [C]; that the bytes are text [I].
    ///
    /// # Safety
    /// See [`Self::call`].
    pub unsafe fn bag_number(&self, out: &mut [u8; 32]) -> Result<(), Error> {
        out.fill(0);
        // SAFETY: exactly the documented 32-byte in/out buffer, and a read-only op.
        unsafe { self.call(Method::BagNumber, out.as_mut_slice(), BagOp::Read as u32)? };
        Ok(())
    }

    /// Callgate 19/2 (mk4 and later): the RDP-2 / factory-mode flag, **raw**.
    ///
    /// The reference confirms the sub-method exists on mk4+ and reads a flag, and says
    /// nothing about how the answer is encoded -- in the return value, in the buffer, or
    /// which value means locked. So this returns both untouched, and **no caller may
    /// treat any answer as "the device is open"**: it is a diagnostic to log, not a
    /// state to act on. Absent from the mk3 bootloader, whose method 19 knows only
    /// `0`/`1`/`100+`; not sent there.
    ///
    /// Source: hw-reference/bootloader-callgate-abi.md "gate 19 gained sub-method 2 on
    /// Mk4" [C]; the encoding [?] -- docs/HARDWARE-OPEN-ITEMS.md.
    ///
    /// # Safety
    /// See [`Self::call`].
    pub unsafe fn lock_flag_raw(&self, out: &mut [u8; 32]) -> Result<i32, Error> {
        out.fill(0);
        // SAFETY: method 19's documented 32-byte in/out buffer; a read sub-method.
        unsafe {
            self.call(
                Method::BagNumber,
                out.as_mut_slice(),
                BagOp::ReadLockFlag as u32,
            )
        }
    }

    /// Callgate 21/0: the anti-downgrade high-water mark the bootloader enforces.
    ///
    /// Eight bytes, in the header's own BCD `YYMMDDHHMMSS0000` shape: an image whose
    /// `timestamp` is below this is refused at install. All zero on a unit that has
    /// never recorded one.
    ///
    /// Source: hw-reference/bootloader-callgate-abi.md method 21 (`in/out 8`) [C];
    /// firmware-signing.md §header `timestamp` [C]; that the eight bytes are that field
    /// verbatim [I] -- docs/HARDWARE-OPEN-ITEMS.md.
    ///
    /// # Safety
    /// See [`Self::call`].
    pub unsafe fn high_water_read(&self, out: &mut [u8; 8]) -> Result<(), Error> {
        out.fill(0);
        // SAFETY: the documented 8-byte buffer for sub-methods 0..=2; read only.
        unsafe {
            self.call(
                Method::Downgrade,
                out.as_mut_slice(),
                OtpOp::ReadMinVersion as u32,
            )?
        };
        Ok(())
    }

    /// Callgate 21/1: ask the bootloader whether `timestamp` clears the high-water mark.
    ///
    /// The return value is passed up raw: the reference says the sub-method checks a
    /// candidate and not how it answers, so a caller logs it and decides nothing on it.
    ///
    /// Source: hw-reference/bootloader-callgate-abi.md method 21 [C].
    ///
    /// # Safety
    /// See [`Self::call`].
    pub unsafe fn high_water_check(&self, timestamp: &[u8; 8]) -> Result<i32, Error> {
        let mut buf = *timestamp;
        // SAFETY: the documented 8-byte buffer; a check, which writes nothing to OTP.
        unsafe { self.call(Method::Downgrade, buf.as_mut_slice(), OtpOp::Check as u32) }
    }

    /// Callgate 21/2: **record `timestamp` as the new high-water mark. IRREVERSIBLE.**
    ///
    /// The mark lives in the MCU's OTP: it can be raised and never lowered. Every image
    /// older than `timestamp` -- stock firmware included, and every earlier CatCard --
    /// is refused by this bootloader for the life of the device. The bootloader does
    /// this itself when it installs an image flagged `HIGH_WATER`; this is the explicit
    /// version, for an owner who wants the floor raised now.
    ///
    /// Only ever called from a menu row that asked twice. `timestamp` is normally the
    /// running image's own, which this bootloader has already accepted.
    ///
    /// Source: hw-reference/bootloader-callgate-abi.md method 21 [C];
    /// install-and-usb-transport.md §"Downgrade protection" [C].
    ///
    /// # Safety
    /// Irreversible on the device; see [`Self::call`].
    pub unsafe fn high_water_record(&self, timestamp: &[u8; 8]) -> Result<(), Error> {
        let mut buf = *timestamp;
        // SAFETY: the documented 8-byte buffer. The caller has taken the decision.
        unsafe { self.call(Method::Downgrade, buf.as_mut_slice(), OtpOp::Record as u32)? };
        Ok(())
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
        let rv = unsafe { self.call(Method::PinAttempt, buf, op as u32) }?;
        // Gate 18 answers 0 on success; everything else is a refusal, including the small
        // positives that `decode` lets through for the methods that return a length. A
        // bootloader that declines to touch the struct and returns `1` must not read as a
        // successful login -- that is exactly how an unusable PIN prompt was reached.
        if rv != 0 {
            return Err(Error::Failed(rv));
        }
        Ok(rv)
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
    fn a_buffer_past_this_bootloaders_window_is_refused_here_rather_than_by_the_gate() {
        // The mk3 takes a buffer only in the first 96 KB of SRAM1 and answers anything
        // above it with `1` -- a generic error that writes nothing and, to a caller
        // watching for a negative return, looks like success. The check has to use the
        // board's window, not the size of SRAM1, or that failure comes back.
        const WINDOW: u32 = 96 * 1024;
        assert!(check_buffer(BASE, WINDOW, BASE + WINDOW - 280, 280).is_ok());
        assert!(matches!(
            check_buffer(BASE, WINDOW, BASE + WINDOW, 280),
            Err(Error::BufferNotInSram1 { .. })
        ));
        // One byte over the end is over the end.
        assert!(matches!(
            check_buffer(BASE, WINDOW, BASE + WINDOW - 279, 280),
            Err(Error::BufferNotInSram1 { .. })
        ));
        // And the rest of SRAM1 is still refused even though it is real memory.
        assert!(matches!(
            check_buffer(BASE, WINDOW, BASE + 200 * 1024, 280),
            Err(Error::BufferNotInSram1 { .. })
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
