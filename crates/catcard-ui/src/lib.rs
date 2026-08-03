//! Display primitives for CatCard.
//!
//! Panel-independent drawing lives in [`framebuffer`]; per-controller command sets in
//! [`ssd1306`] (and, once the Q1 panel is identified, an `st77xx` module beside it).
//! Neither knows about SPI or GPIO — the board layer supplies those, so everything
//! here is testable on the host.

#![cfg_attr(not(test), no_std)]
#![deny(unsafe_code)]

pub mod display;
pub mod font;
pub mod framebuffer;
pub mod ssd1306;
pub mod text;

pub use display::{DisplayBus, Ssd1306};
pub use framebuffer::{Framebuffer, Mono128x64};
