//! Decoding a card's CID register.
//!
//! The CID is 128 bits the card reports once, during bring-up, in answer to CMD2
//! (`ALL_SEND_CID`) or CMD10 (`SEND_CID`). It never changes over the life of the card, so
//! the serial number in it is a stable per-card identifier — a later feature keys device
//! settings by it, which is why [`Card::serial`](crate::Card::serial) exists and must be
//! reliable.
//!
//! The four words are the response as the peripheral presents a long (R2) response: most
//! significant first, header (start/transmission/reserved) and CRC stripped, so
//! `raw[0]` holds register bits `[127:96]` down to `raw[3]` holding `[31:0]`. This is the
//! same word alignment the CSD decode in [`crate::capacity_blocks`] relies on, which is
//! confirmed correct against real cards.
//!
//! Field layout, all bit positions in the 128-bit CID register:
//!
//! | field | bits    | meaning                                              |
//! |-------|---------|------------------------------------------------------|
//! | MID   | 127:120 | manufacturer ID (assigned by SD-3C)                  |
//! | OID   | 119:104 | OEM/application ID, two ASCII characters             |
//! | PNM   | 103:64  | product name, five ASCII characters                  |
//! | PRV   | 63:56   | product revision, two BCD nibbles (major.minor)      |
//! | PSN   | 55:24   | product serial number                                |
//! | MDT   | 19:8    | manufacture date: year offset from 2000, then month  |
//!
//! Source: SD Physical Layer Simplified Specification, "The CID register" [C]

/// A card's decoded CID. Holds the raw words; every field is derived on demand, so the
/// struct stays `Copy` and cheap to pass to a screen.
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub struct Cid {
    /// The register as four words, most significant first: `raw[0]` is bits `[127:96]`.
    pub raw: [u32; 4],
}

impl Cid {
    /// Wrap the raw CID words from a long response.
    pub fn new(raw: [u32; 4]) -> Self {
        Self { raw }
    }

    /// Manufacturer ID, bits `[127:120]`. Source: SD Phys. Layer, CID §MID [C]
    pub fn mid(&self) -> u8 {
        (self.raw[0] >> 24) as u8
    }

    /// A name for the manufacturer ID, or `None` if it is not one this table knows (the
    /// caller then shows the hex byte).
    ///
    /// The numeric MID field is spec; the *names* behind the numbers are assigned by
    /// SD-3C, LLC and are not published in the spec, so this small table is community
    /// knowledge, not a normative source. Tagged [I]: correct enough to label a screen,
    /// never relied on for anything.
    pub fn mid_name(&self) -> Option<&'static str> {
        // Source: widely reproduced SD MID assignments (community lists) [I]
        Some(match self.mid() {
            0x01 => "Panasonic",
            0x02 => "Toshiba/Kioxia",
            0x03 => "SanDisk",
            0x1b => "Samsung",
            0x1d => "AData",
            0x27 => "Phison",
            0x28 => "Lexar",
            0x31 => "Silicon Power",
            0x41 => "Kingston",
            0x74 => "Transcend",
            0x76 => "Patriot",
            0x82 => "Sony",
            0x9c => "Angelbird/Hoodman",
            _ => return None,
        })
    }

    /// OEM/application ID, bits `[119:104]`, as two bytes meant to be ASCII.
    /// Source: SD Phys. Layer, CID §OID [C]
    pub fn oid(&self) -> [u8; 2] {
        [(self.raw[0] >> 16) as u8, (self.raw[0] >> 8) as u8]
    }

    /// Product name, bits `[103:64]`, as five bytes meant to be ASCII. The field spans
    /// the low byte of `raw[0]` and all of `raw[1]`.
    /// Source: SD Phys. Layer, CID §PNM [C]
    pub fn pnm(&self) -> [u8; 5] {
        [
            self.raw[0] as u8,
            (self.raw[1] >> 24) as u8,
            (self.raw[1] >> 16) as u8,
            (self.raw[1] >> 8) as u8,
            self.raw[1] as u8,
        ]
    }

    /// Product revision, bits `[63:56]`, as (major, minor). Each is a BCD nibble.
    /// Source: SD Phys. Layer, CID §PRV [C]
    pub fn prv(&self) -> (u8, u8) {
        let prv = (self.raw[2] >> 24) as u8;
        (prv >> 4, prv & 0x0F)
    }

    /// Product serial number, bits `[55:24]`. Spans the low 24 bits of `raw[2]` and the
    /// top byte of `raw[3]`. This is the stable per-card identifier.
    /// Source: SD Phys. Layer, CID §PSN [C]
    pub fn psn(&self) -> u32 {
        ((self.raw[2] & 0x00FF_FFFF) << 8) | (self.raw[3] >> 24)
    }

    /// Manufacture month, 1–12, from the low nibble of the MDT field, bits `[11:8]`.
    /// Source: SD Phys. Layer, CID §MDT [C]
    pub fn mdt_month(&self) -> u8 {
        (self.raw[3] >> 8) as u8 & 0x0F
    }

    /// Manufacture year, as a full year (offset from 2000), bits `[19:12]`.
    /// Source: SD Phys. Layer, CID §MDT [C]
    pub fn mdt_year(&self) -> u16 {
        let offset = ((self.raw[3] >> 12) & 0xFF) as u16;
        2000 + offset
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A real-shaped CID, decoded field by field — the known answer that pins the bit
    /// layout so a later edit that shifts a field by a nibble is caught here.
    ///
    /// Bytes (MSB first), a SanDisk "SC32G": MID 03, OID "SD", PNM "SC32G", PRV 3.0,
    /// PSN 0x12345678, MDT 2018-09, CRC byte 01.
    /// `03 53 44 53 43 33 32 47 30 12 34 56 78 01 29 01`
    const SANDISK: [u32; 4] = [0x0353_4453, 0x4333_3247, 0x3012_3456, 0x7801_2901];

    #[test]
    fn decodes_a_known_cid() {
        let cid = Cid::new(SANDISK);
        assert_eq!(cid.mid(), 0x03);
        assert_eq!(cid.mid_name(), Some("SanDisk"));
        assert_eq!(&cid.oid(), b"SD");
        assert_eq!(&cid.pnm(), b"SC32G");
        assert_eq!(cid.prv(), (3, 0));
        assert_eq!(cid.psn(), 0x1234_5678);
        assert_eq!(cid.mdt_month(), 9);
        assert_eq!(cid.mdt_year(), 2018);
    }

    #[test]
    fn an_unknown_mid_has_no_name() {
        let cid = Cid::new([0xEE00_0000, 0, 0, 0]);
        assert_eq!(cid.mid(), 0xEE);
        assert_eq!(cid.mid_name(), None);
    }
}
