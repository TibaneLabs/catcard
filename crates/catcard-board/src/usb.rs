//! USB device identity.
//!
//! Product-level rather than board-level — every generation presents the same identity,
//! because it identifies *CatCard*, not the silicon underneath. It lives in this crate
//! because this is the one dependency-free crate both the firmware and the host tooling
//! already share, so the descriptor and the packaging tool cannot drift apart.

/// USB vendor ID, allocated to Karpeles Lab Inc. by the USB-IF.
///
/// This is a real allocation, not a squatted number. The stock Coldcard firmware
/// advertises `0xd13e`, which its own source describes as "unofficial, unpermissioned"
/// and which does not appear in the USB-IF table; CatCard does not reuse it.
pub const VENDOR_ID: u16 = 0x39F2;

/// Product ID for the CatCard firmware.
///
/// The vendor ID is shared across Karpeles Lab products, so product IDs are allocated
/// outside this repository. Do not invent a second one here — if CatCard ever needs a
/// distinct identity for a different mode (a DFU or recovery interface, say), it has to
/// be allocated, not chosen.
pub const PRODUCT_ID: u16 = 0x0401;

/// DFU specification wildcard: "this file is not specific to one device".
///
/// Used in the DfuSe suffix rather than [`VENDOR_ID`]/[`PRODUCT_ID`] — see
/// `docs/USB.md` for why the packaging default differs from the device identity.
pub const ANY_ID: u16 = 0xFFFF;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_allocated_identity() {
        assert_eq!(VENDOR_ID, 0x39F2);
        assert_eq!(VENDOR_ID, 14834, "the decimal form on the allocation");
        assert_eq!(PRODUCT_ID, 0x0401);
    }

    #[test]
    fn we_do_not_advertise_the_stock_identity() {
        // 0xd13e:0xcc10 is unregistered and belongs to nobody; reusing it would make
        // CatCard indistinguishable from a Coldcard to every host on the bus.
        assert_ne!(VENDOR_ID, 0xd13e);
        assert_ne!(PRODUCT_ID, 0xcc10);
    }

    #[test]
    fn the_wildcard_is_not_a_real_id() {
        // 0xFFFF is reserved by the DFU spec to mean "any device", so it must never be
        // mistaken for an allocation.
        assert_ne!(VENDOR_ID, ANY_ID);
        assert_ne!(PRODUCT_ID, ANY_ID);
    }
}
