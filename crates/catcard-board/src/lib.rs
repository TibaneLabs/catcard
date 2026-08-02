//! Board definitions for CatCard.
//!
//! This crate is pure `const` data with no MCU dependencies, so it can be used from
//! three places: the firmware itself, `catcard-fw/build.rs` (which turns
//! [`MemoryMap`](memory::MemoryMap) into a linker script), and the host-side
//! `catcard-image` tool (which needs each board's flash layout and `hw_compat` bit).
//!
//! Selecting a board:
//!
//! - Firmware enables exactly one of `board-mk3` / `board-mk4` / `board-q1` and reads
//!   [`BOARD`].
//! - Host tools enable none and use [`spec::ALL`] or [`spec::BoardSpec::by_name`].
//!
//! Provenance for every hardware fact is cited inline; see `CLEANROOM.md`.

#![cfg_attr(not(test), no_std)]
#![deny(unsafe_code)]

pub mod memory;
pub mod pin;
pub mod spec;

pub use memory::{MemoryMap, FW_HEADER_OFFSET, FW_HEADER_SIZE};
pub use pin::{Pin, Port};
pub use spec::{BoardSpec, Display, Input, Mcu};

#[cfg(any(
    all(
        feature = "board-mk3",
        any(feature = "board-mk4", feature = "board-q1")
    ),
    all(feature = "board-mk4", feature = "board-q1"),
))]
compile_error!(
    "enable exactly one of the `board-mk3`, `board-mk4`, `board-q1` features on catcard-board"
);

/// The board this firmware is being built for.
#[cfg(feature = "board-mk3")]
pub const BOARD: BoardSpec = spec::MK3;
/// The board this firmware is being built for.
#[cfg(feature = "board-mk4")]
pub const BOARD: BoardSpec = spec::MK4;
/// The board this firmware is being built for.
#[cfg(feature = "board-q1")]
pub const BOARD: BoardSpec = spec::Q1;
