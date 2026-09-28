//! The bench front end to the raw TRNG reader: `DebugTrng`, plaintext. Bench builds only.
//!
//! `usb-trng-capture`, a default feature that `SHIP=1` strips. Nothing here reads: the
//! request goes to [`crate::rngread`], the reader the paired `RngSample` shares, and is
//! read from the main menu loop like every other. What this front end is *not* is asked
//! or limited -- no question on the device, no secure-element allowance -- which is why a
//! release leaves it out, and why CI checks a published image for this module's name and
//! the `trngcap:` marker it logs.

use catcard_usb::Status;
use catcard_usb::rng;

use crate::rngread::{self, Origin};

/// Answer a `DebugTrng` request (USB task): the list, or one chunk. Writes the reply body
/// into `out` (at least [`rngread::REPLY_LEN`] bytes).
pub fn request(p: &[u8], out: &mut [u8]) -> (Status, usize) {
    use core::sync::atomic::{AtomicBool, Ordering};
    // The marker CI looks for in a published image, once per power-up.
    static SAID: AtomicBool = AtomicBool::new(false);
    if !SAID.swap(true, Ordering::Relaxed) {
        crate::catlog!("trngcap: bench capture over plaintext USB");
    }
    match rng::parse_request(p) {
        Ok(rng::Request::List) => (Status::Ok, rngread::list(out)),
        Ok(rng::Request::Chunk { source, len }) => {
            rngread::request(Origin::Bench, source, len, out)
        }
        Err(st) => (st, 0),
    }
}
