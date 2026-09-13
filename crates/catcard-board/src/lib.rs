//! Board definitions for CatCard.
//!
//! This crate is pure `const` data with no MCU dependencies, so it can be used from
//! three places: the firmware itself, `catcard-fw/build.rs` (which turns
//! [`MemoryMap`](memory::MemoryMap) into a linker script), and the host-side
//! `catcard-image` tool (which needs each board's flash layout and `hw_compat` bit).
//!
//! Selecting a board:
//!
//! - Firmware enables exactly one of `board-mk3` / `board-mk4` / `board-mk5` /
//!   `board-q1` and reads
//!   [`BOARD`].
//! - Host tools enable none and use [`spec::ALL`] or [`spec::BoardSpec::by_name`].
//!
//! Provenance for every hardware fact is cited inline; see `CLEANROOM.md`.

#![cfg_attr(not(test), no_std)]
#![deny(unsafe_code)]

pub mod memory;
pub mod pin;
pub mod spec;
pub mod usb;

pub use memory::{FW_HEADER_OFFSET, FW_HEADER_SIZE, MemoryMap};
pub use pin::{Pin, Port};
pub use spec::{BoardSpec, Display, Input, Mcu, NfcPins, Psram, Se2Pins};
pub use usb::{PRODUCT_ID, VENDOR_ID};

/// How many board features are enabled. At most one may be.
///
/// Counted rather than enumerated in pairs: the pairwise form needed a new clause for
/// every board added, and adding mk5 to it would have meant three more.
///
/// **Zero is allowed and is not an oversight.** The host tools depend on this crate to
/// read `spec::ALL` -- every board at once, none of them selected -- and only firmware
/// needs a `BOARD`. A firmware build that selects none fails on `BOARD` being undefined,
/// which names the problem as precisely as this would.
const BOARDS_SELECTED: usize = cfg!(feature = "board-mk3") as usize
    + cfg!(feature = "board-mk4") as usize
    + cfg!(feature = "board-mk5") as usize
    + cfg!(feature = "board-q1") as usize;

// Written as a match rather than `<= 1`: with no board selected the constant folds to
// zero, and clippy reads a comparison against a type's minimum as always-true noise.
const _: () = assert!(
    matches!(BOARDS_SELECTED, 0 | 1),
    "enable at most one of the `board-mk3`, `board-mk4`, `board-mk5`, `board-q1` features"
);

/// The board this firmware is being built for.
#[cfg(feature = "board-mk3")]
pub const BOARD: BoardSpec = spec::MK3;
/// The board this firmware is being built for.
#[cfg(feature = "board-mk4")]
pub const BOARD: BoardSpec = spec::MK4;
/// The board this firmware is being built for.
#[cfg(feature = "board-mk5")]
pub const BOARD: BoardSpec = spec::MK5;
/// The board this firmware is being built for.
#[cfg(feature = "board-q1")]
pub const BOARD: BoardSpec = spec::Q1;
