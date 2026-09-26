//! Display primitives for CatCard.
//!
//! Panel-independent drawing lives in [`framebuffer`]; per-controller drivers in
//! [`ssd1306`] (the mk3/mk4/mk5 OLED) and [`st7789`] (the Q1 LCD). Input scanners are
//! [`keypad`] (the 4x3 numpad) and [`qwerty`] (the Q1 keyboard).
//! Neither knows about SPI or GPIO — the board layer supplies those, so everything
//! here is testable on the host.

#![cfg_attr(not(test), no_std)]
#![deny(unsafe_code)]

pub mod art;
pub mod calc;
pub mod canvas;
pub mod display;
pub mod face;
pub mod field;
pub mod flappy;
pub mod font;
pub mod framebuffer;
pub mod grid;
pub mod icons;
pub mod keypad;
pub mod menu;
pub mod pager;
pub mod pinentry;
pub mod qwerty;
pub mod scramble;
pub mod scroll;
pub mod splash;
pub mod ssd1306;
pub mod st7789;
pub mod statusbar;
pub mod sweep;
pub mod text;
pub mod textentry;
pub mod widgets;

pub use art::Bitmap;
pub use display::{DisplayBus, Ssd1306};
pub use font::Font;
pub use framebuffer::{Framebuffer, Mono128x64};
pub use keypad::{Event as KeyEvent, Key, Keypad, Matrix};
