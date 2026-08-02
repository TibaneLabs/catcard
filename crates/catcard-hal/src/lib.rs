//! Register-level drivers for the STM32L4 / L4+ peripherals CatCard uses.
//!
//! Scope on purpose: this crate owns *chip* peripherals. Board wiring lives in
//! `catcard-board`; device drivers that sit on top of a bus (SSD1306, SPI-NOR, the
//! secure elements) live in their own crates. Nothing here knows which board it is on
//! except through a [`BoardSpec`](catcard_board::BoardSpec) passed in.
//!
//! Every address is cited to the ST reference manual (RM0351 for STM32L4, RM0432 for
//! STM32L4+) or to `hw-reference`, per `CLEANROOM.md`.
//!
//! # Bring-up order
//!
//! ```ignore
//! unsafe { dwt::enable() };
//! unsafe { clock::enable_hsi48() }?;   // the RNG needs this or DRDY never asserts
//! let rng = unsafe { rng::Rng::init() }?;
//! ```

#![cfg_attr(not(test), no_std)]
#![deny(unsafe_op_in_unsafe_fn)]

pub mod clock;
pub mod dwt;
pub mod gpio;
pub mod reg;
pub mod rng;
pub mod uid;

/// Everything that can go wrong during early bring-up.
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub enum InitError {
    Clock(clock::Error),
    Rng(rng::Error),
}

impl From<clock::Error> for InitError {
    fn from(e: clock::Error) -> Self {
        InitError::Clock(e)
    }
}
impl From<rng::Error> for InitError {
    fn from(e: rng::Error) -> Self {
        InitError::Rng(e)
    }
}

/// Bring up the chip peripherals every board needs, in the required order.
///
/// # Safety
/// Call exactly once, from the reset path, before anything else touches these
/// peripherals.
pub unsafe fn init_core() -> Result<rng::Rng, InitError> {
    unsafe {
        dwt::enable();
        clock::enable_hsi48()?;
        Ok(rng::Rng::init()?)
    }
}
