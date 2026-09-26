//! Settings slots in raw SPI-NOR, as the mk3 keeps them.
//!
//! The mk3 has no LittleFS volume: stock writes each settings blob straight into one
//! 4 KB sector of the SPI-NOR part, thirty-two of them in the last 128 KB --
//! `range(0xE0000, 0x100000, 0x1000)` -- and the `pos` in the AES counter is the sector's
//! **byte offset**, not its index. Source: hw-reference/settings-nvstore-format.md §1 [C].
//!
//! Everything below the region is the firmware-staging area, which the bootloader copies
//! into main flash on the next boot when a valid trailing header is there. Nothing here
//! addresses a byte under [`Layout::base`]: every address is `base + index * SECTOR`
//! with `index < count`, checked before the medium is asked, so the settings cannot
//! erase a staged image and a bug in a slot number cannot become a bricked device.
//! Source: hw-reference/storage.md §"mk3 firmware staging & recovery" [C].
//!
//! # A slot is exactly one sector
//!
//! A file on LittleFS can grow past 4096 bytes when the JSON outruns its padding; a NOR
//! sector cannot. A write of any other length is refused rather than spilling into the
//! next slot, and the store reports it as a medium failure -- which it is.
//!
//! # Erase, program, read back
//!
//! NOR only clears bits, so a slot is erased before it is programmed. The old copy of the
//! settings lives in *another* slot throughout ([`crate::store::write`] writes the new
//! one first), so a power cut between the erase and the last programmed byte leaves the
//! old copy live and this slot as garbage that never decrypts. Every write is read back
//! and compared before it is called done: a part that accepted the program command and
//! kept a stuck bit would otherwise report a saved setting that is not there.
//!
//! Waits belong to the medium. This asks for an erase or a program and expects the
//! answer bounded; the firmware's driver polls the status register a fixed number of
//! times and gives up ([`catcard_flash`]'s `ERASE_POLL_LIMIT` / `PROGRAM_POLL_LIMIT`).

use crate::store::{MediumError, Slots};

/// Bytes in one NOR sector, the erase unit and the slot. Source: storage.md §SPI-NOR [C].
pub const SECTOR: u32 = 4096;

/// A sealed slot is one sector, no more and no less.
const _: () = assert!(SECTOR as usize == crate::nvstore::SLOT_LEN);

/// Bytes read back at a time when checking a sector: small enough for a stack frame on
/// the boot path, large enough that a sector is sixty-four transfers.
const WINDOW: usize = 64;

/// Where the slots are: the first one's byte offset and how many follow it, each one
/// sector further on.
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub struct Layout {
    /// Byte offset of slot 0 in the part.
    pub base: u32,
    /// Slots, each [`SECTOR`] bytes, back to back from `base`.
    pub count: u32,
}

impl Layout {
    /// The `pos` of slot `index`, which is also its byte offset in the part.
    ///
    /// `None` past the end: an index the layout does not have is never turned into an
    /// address, so it can never reach the staging area below the region.
    pub const fn offset(&self, index: u32) -> Option<u32> {
        if index >= self.count {
            return None;
        }
        Some(self.base + index * SECTOR)
    }

    /// One past the last byte of the region.
    pub const fn end(&self) -> u32 {
        self.base + self.count * SECTOR
    }
}

/// The mk3's layout: 32 slots in the last 128 KB of the 1 MB MX25L8006E.
/// Source: hw-reference/settings-nvstore-format.md §1 [C]
pub const MK3: Layout = Layout {
    base: 0x000E_0000,
    count: 32,
};

/// The region ends exactly at the top of the 1 MB part, and starts where the staging
/// area's ceiling is (`catcard_upgrade::nor::NVSTORE_BASE`).
const _: () = assert!(MK3.end() == 0x0010_0000);
const _: () = assert!(MK3.base == 0x000E_0000);

/// A NOR part, as the slots need it: read anywhere, erase a sector, program erased cells.
///
/// The three commands the settings use and nothing else. Whatever bus and chip-select
/// sit underneath are the firmware's; on the host this is an array of bytes that clears
/// bits the way silicon does ([`tests::MemNor`]).
pub trait BlockMedium {
    /// Fill `out` from `addr`.
    fn read(&mut self, addr: u32, out: &mut [u8]) -> Result<(), MediumError>;

    /// Erase the [`SECTOR`] at `addr`, which is sector-aligned. Bounded: a part that
    /// never reports idle is an error, not a hang.
    fn erase_sector(&mut self, addr: u32) -> Result<(), MediumError>;

    /// Program `data` at `addr`, into cells that were erased. Bounded, as the erase is.
    fn program(&mut self, addr: u32, data: &[u8]) -> Result<(), MediumError>;
}

/// Settings slots over a [`BlockMedium`].
pub struct NorSlots<M> {
    medium: M,
    layout: Layout,
    /// Whether writes and clears are allowed. A read-only view is what the boot path
    /// and every screen that only looks open: nothing they do can change a slot.
    writable: bool,
    last_cleared: Option<u32>,
}

impl<M: BlockMedium> NorSlots<M> {
    /// Slots that may be written.
    pub fn new(medium: M, layout: Layout) -> Self {
        Self {
            medium,
            layout,
            writable: true,
            last_cleared: None,
        }
    }

    /// Slots that refuse every write and clear.
    pub fn read_only(medium: M, layout: Layout) -> Self {
        Self {
            writable: false,
            ..Self::new(medium, layout)
        }
    }

    /// Where these slots are.
    pub fn layout(&self) -> Layout {
        self.layout
    }

    /// Give the medium back.
    pub fn into_medium(self) -> M {
        self.medium
    }

    /// Whether every byte of the sector at `addr` reads as erased, a window at a time.
    fn sector_is_erased(&mut self, addr: u32) -> Result<bool, MediumError> {
        let mut window = [0u8; WINDOW];
        let mut at = addr;
        let end = addr + SECTOR;
        while at < end {
            self.medium.read(at, &mut window)?;
            if window.iter().any(|&b| b != 0xFF) {
                return Ok(false);
            }
            at += WINDOW as u32;
        }
        Ok(true)
    }

    /// Whether the sector at `addr` holds exactly `bytes`, a window at a time.
    fn sector_matches(&mut self, addr: u32, bytes: &[u8]) -> Result<bool, MediumError> {
        let mut window = [0u8; WINDOW];
        for (i, chunk) in bytes.chunks(WINDOW).enumerate() {
            let at = addr + (i * WINDOW) as u32;
            self.medium.read(at, &mut window[..chunk.len()])?;
            if window[..chunk.len()] != *chunk {
                return Ok(false);
            }
        }
        Ok(true)
    }

    /// How many slots hold something, and the bytes they occupy.
    ///
    /// For the Settings Space screen. A slot that is not erased counts, whether or not
    /// it decrypts under any key this device has: it is space that is taken.
    pub fn usage(&mut self) -> Result<(u32, u64), MediumError> {
        let mut used = 0u32;
        for index in 0..self.layout.count {
            let addr = self.layout.offset(index).ok_or(MediumError)?;
            if !self.sector_is_erased(addr)? {
                used += 1;
            }
        }
        Ok((used, u64::from(used) * u64::from(SECTOR)))
    }
}

impl<M: BlockMedium> Slots for NorSlots<M> {
    fn count(&self) -> u32 {
        self.layout.count
    }

    /// The sector's byte offset in the part: what stock puts in the counter on this
    /// medium. A blob sealed under the mk4 convention -- the bare index -- does not
    /// decrypt here, and that is the format, not a bug.
    /// Source: hw-reference/settings-nvstore-format.md §1 [C]
    fn pos(&self, index: u32) -> u32 {
        // An index past the layout has no offset; `read`/`write` refuse it before any
        // counter is built, so the value here is never used for a real slot.
        self.layout.offset(index).unwrap_or(u32::MAX)
    }

    fn read(&mut self, index: u32, buf: &mut [u8]) -> Result<Option<usize>, MediumError> {
        let addr = self.layout.offset(index).ok_or(MediumError)?;
        // The caller's buffer must hold a whole slot: a partial read would hand the
        // store a truncated stream whose digest can never check, and it would then
        // treat the slot as somebody else's rather than as unread.
        let slot = buf.get_mut(..SECTOR as usize).ok_or(MediumError)?;
        self.medium.read(addr, slot)?;
        if slot.iter().all(|&b| b == 0xFF) {
            return Ok(None);
        }
        Ok(Some(SECTOR as usize))
    }

    fn write(&mut self, index: u32, bytes: &[u8]) -> Result<(), MediumError> {
        if !self.writable {
            return Err(MediumError);
        }
        let addr = self.layout.offset(index).ok_or(MediumError)?;
        // One sector, exactly. Shorter would read back with 0xFF appended and fail its
        // digest; longer has nowhere to go but the next slot.
        if bytes.len() != SECTOR as usize {
            return Err(MediumError);
        }
        self.medium.erase_sector(addr)?;
        self.medium.program(addr, bytes)?;
        if !self.sector_matches(addr, bytes)? {
            return Err(MediumError);
        }
        Ok(())
    }

    fn clear(&mut self, index: u32) -> Result<(), MediumError> {
        if !self.writable {
            return Err(MediumError);
        }
        let addr = self.layout.offset(index).ok_or(MediumError)?;
        self.medium.erase_sector(addr)?;
        // An erase the part did not carry out leaves the old copy readable beside the
        // new one, which is harmless for the reader (newest wins) but not for the
        // keystream rule `last_cleared` exists for: say so rather than remember a
        // clear that did not happen.
        if !self.sector_is_erased(addr)? {
            return Err(MediumError);
        }
        self.last_cleared = Some(index);
        Ok(())
    }

    fn last_cleared(&self) -> Option<u32> {
        self.last_cleared
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::json::Doc;
    use crate::nvstore::{self, Key, SLOT_LEN};
    use crate::store::{self, Error, SCRATCH};

    /// The 1 MB MX25L8006E as bytes: erased cells read 0xFF, an erase blanks one 4 KB
    /// sector, a program only clears bits. It also keeps the evidence the tests are
    /// about -- every address an erase or program touched -- and can be told to stop
    /// programming partway, which is what a power cut leaves.
    pub(crate) struct MemNor {
        pub mem: Vec<u8>,
        /// Every sector address an erase was issued for.
        pub erased: Vec<u32>,
        /// Every `(addr, len)` a program was issued for.
        pub programmed: Vec<(u32, usize)>,
        /// Program this many bytes of the next program, then fail. `None` programs fully.
        pub cut_program_after: Option<usize>,
        /// A cell that will not clear: `(addr, mask)` of bits that stay set however
        /// they are programmed. Models a worn or stuck bit.
        pub stuck: Option<(u32, u8)>,
    }

    pub(crate) const PART: usize = 0x0010_0000;

    impl MemNor {
        pub(crate) fn new() -> Self {
            Self {
                mem: vec![0xFF; PART],
                erased: Vec::new(),
                programmed: Vec::new(),
                cut_program_after: None,
                stuck: None,
            }
        }

        /// Fresh, with a recognisable pattern staged below the settings region -- a
        /// firmware image waiting for the bootloader -- so the tests can tell whether
        /// the settings ever touched it.
        pub(crate) fn with_staged_image() -> Self {
            let mut m = Self::new();
            for (i, b) in m.mem[..MK3.base as usize].iter_mut().enumerate() {
                *b = (i % 251) as u8;
            }
            m
        }

        pub(crate) fn staged_image_intact(&self) -> bool {
            self.mem[..MK3.base as usize]
                .iter()
                .enumerate()
                .all(|(i, &b)| b == (i % 251) as u8)
        }

        /// The lowest address any erase or program touched.
        pub(crate) fn lowest_touched(&self) -> Option<u32> {
            self.erased
                .iter()
                .copied()
                .chain(self.programmed.iter().map(|(a, _)| *a))
                .min()
        }
    }

    impl BlockMedium for MemNor {
        fn read(&mut self, addr: u32, out: &mut [u8]) -> Result<(), MediumError> {
            let a = addr as usize;
            let src = self.mem.get(a..a + out.len()).ok_or(MediumError)?;
            out.copy_from_slice(src);
            Ok(())
        }

        fn erase_sector(&mut self, addr: u32) -> Result<(), MediumError> {
            assert_eq!(addr % SECTOR, 0, "misaligned erase at {addr:#x}");
            let a = addr as usize;
            let sector = self
                .mem
                .get_mut(a..a + SECTOR as usize)
                .ok_or(MediumError)?;
            sector.fill(0xFF);
            if let Some((stuck_at, mask)) = self.stuck
                && (addr..addr + SECTOR).contains(&stuck_at)
            {
                self.mem[stuck_at as usize] |= mask;
            }
            self.erased.push(addr);
            Ok(())
        }

        fn program(&mut self, addr: u32, data: &[u8]) -> Result<(), MediumError> {
            let a = addr as usize;
            if a + data.len() > self.mem.len() {
                return Err(MediumError);
            }
            let (n, cut) = match self.cut_program_after.take() {
                Some(n) => (n.min(data.len()), true),
                None => (data.len(), false),
            };
            for (i, b) in data[..n].iter().enumerate() {
                self.mem[a + i] &= b;
            }
            if let Some((stuck_at, mask)) = self.stuck
                && (a..a + n).contains(&(stuck_at as usize))
            {
                self.mem[stuck_at as usize] |= mask;
            }
            self.programmed.push((addr, n));
            if cut { Err(MediumError) } else { Ok(()) }
        }
    }

    fn key() -> Key {
        nvstore::hash_key(&[0x82; 72])
    }

    fn mk3() -> NorSlots<MemNor> {
        NorSlots::new(MemNor::with_staged_image(), MK3)
    }

    fn scratch() -> Vec<u8> {
        vec![0u8; SCRATCH]
    }

    /// The layout is stock's: thirty-two sectors from `0xE0000`, the last ending at the
    /// top of the part, and `pos` is the byte offset.
    #[test]
    fn the_mk3_layout_is_thirty_two_sectors_from_0xe0000() {
        assert_eq!(MK3.count, 32);
        assert_eq!(MK3.offset(0), Some(0xE0000));
        assert_eq!(MK3.offset(1), Some(0xE1000));
        assert_eq!(MK3.offset(31), Some(0xFF000));
        assert_eq!(MK3.offset(32), None);
        assert_eq!(MK3.end(), 0x100000);
        let slots = mk3();
        assert_eq!(slots.count(), 32);
        for i in 0..32 {
            assert_eq!(slots.pos(i), 0xE0000 + i * 0x1000);
        }
    }

    /// A blob sealed at a known offset -- as stock would have left it -- is read back
    /// through the store; the same bytes sealed under the mk4 convention (the bare
    /// index as `pos`) at the same place are not.
    #[test]
    fn a_blob_written_at_a_known_offset_reads_back() {
        let k = key();
        let mut nor = MemNor::with_staged_image();
        let json = br#"{"_age": 5, "chain": "BTC", "nick": "mk3"}"#;
        let mut sealed = [0u8; SLOT_LEN];
        // Slot 3 is at 0xE3000, and that offset is what goes in the counter.
        let n = nvstore::seal(json, &k, 0xE3000, &mut sealed).unwrap();
        assert_eq!(n, SLOT_LEN);
        nor.mem[0xE3000..0xE3000 + SLOT_LEN].copy_from_slice(&sealed);

        let mut slots = NorSlots::read_only(nor, MK3);
        let mut buf = scratch();
        let n = store::read(&mut slots, &k, &mut buf).unwrap();
        assert_eq!(&buf[..n], json);
        assert_eq!(Doc::parse(&buf[..n]).unwrap().get_str("nick"), Some("mk3"));

        // Sealed with `pos = 3` -- a file index, the other generation's convention --
        // and placed in slot 3: not ours, because the counter is not this medium's.
        let mut nor = MemNor::with_staged_image();
        let n = nvstore::seal(json, &k, 3, &mut sealed).unwrap();
        nor.mem[0xE3000..0xE3000 + n].copy_from_slice(&sealed[..n]);
        let mut slots = NorSlots::read_only(nor, MK3);
        assert_eq!(store::read(&mut slots, &k, &mut buf), Err(Error::Absent));
    }

    /// Saves steered at every slot in turn land in every slot, and nothing below the
    /// region is ever erased or programmed: the staged image is byte for byte what it
    /// was.
    #[test]
    fn rotation_visits_all_thirty_two_slots_and_never_touches_the_staging_area() {
        let k = key();
        let mut slots = mk3();
        let mut doc = scratch();
        let mut seal = scratch();
        // More saves than slots, each steered at a different one, so the live slot and
        // the just-cleared one (both skipped) still let every index come up.
        for n in 0..96u32 {
            let choose = n % 32;
            store::set(&mut slots, &k, "n", &n, choose, &mut doc, &mut seal)
                .unwrap_or_else(|e| panic!("save {n} failed: {e:?}"));
        }
        let mut visited = [false; 32];
        for (addr, len) in &slots.medium.programmed {
            assert!(
                *addr >= MK3.base,
                "programmed below the region at {addr:#x}"
            );
            assert!(*addr + *len as u32 <= MK3.end(), "programmed past the part");
            visited[((*addr - MK3.base) / SECTOR) as usize] = true;
        }
        for addr in &slots.medium.erased {
            assert!(*addr >= MK3.base, "erased below the region at {addr:#x}");
            assert!(*addr < MK3.end());
        }
        assert!(
            visited.iter().all(|v| *v),
            "slots never written: {:?}",
            visited
                .iter()
                .enumerate()
                .filter(|(_, v)| !**v)
                .map(|(i, _)| i)
                .collect::<Vec<_>>()
        );
        assert_eq!(slots.medium.lowest_touched(), Some(MK3.base));
        assert!(slots.medium.staged_image_intact());

        // And the latest save is what reads back.
        let n = store::read(&mut slots, &k, &mut doc).unwrap();
        assert_eq!(Doc::parse(&doc[..n]).unwrap().get_u64("n"), Some(95));
    }

    /// The new slot is written whole before the old one is erased, so a power cut at
    /// any point in the program leaves the old settings live -- and the half-written
    /// slot is never mistaken for them.
    #[test]
    fn a_power_cut_mid_program_leaves_the_old_settings_live() {
        let k = key();
        for cut_at in [0usize, 1, 100, 2048, 4063, 4064, 4095] {
            let mut slots = mk3();
            let mut doc = scratch();
            let mut seal = scratch();
            store::set(&mut slots, &k, "v", &"old", 4, &mut doc, &mut seal).unwrap();
            slots.medium.cut_program_after = Some(cut_at);
            let r = store::set(&mut slots, &k, "v", &"new", 9, &mut doc, &mut seal);
            assert_eq!(r, Err(Error::Medium), "cut at {cut_at}");

            // The device comes back: a fresh view over the same bytes.
            let mut fresh = NorSlots::new(
                MemNor {
                    mem: slots.medium.mem.clone(),
                    erased: Vec::new(),
                    programmed: Vec::new(),
                    cut_program_after: None,
                    stuck: None,
                },
                MK3,
            );
            let n = store::read(&mut fresh, &k, &mut doc).unwrap();
            let d = Doc::parse(&doc[..n]).unwrap();
            assert_eq!(d.get_str("v"), Some("old"), "cut at {cut_at}");
            assert_eq!(d.get_u64("_age"), Some(1), "cut at {cut_at}");
        }
    }

    /// A program the part did not carry out is a failed write, not a saved setting.
    #[test]
    fn a_slot_that_does_not_read_back_is_a_failed_write() {
        let k = key();
        let mut slots = mk3();
        let mut seal = scratch();
        // Slot 7, byte 100: bit 0 will not clear. Steer the save there.
        slots.medium.stuck = Some((0xE7000 + 100, 0x01));
        let json = br#"{"_age":1,"v":"x"}"#;
        let r = store::write(&mut slots, &k, json, 7, &mut seal);
        // Either the sealed byte happened to have that bit set (then it verifies) or the
        // write is refused; what never happens is a report of success over wrong bytes.
        match r {
            Ok(7) => {
                let mut buf = scratch();
                let n = store::read(&mut slots, &k, &mut buf).unwrap();
                assert_eq!(&buf[..n], json);
            }
            Ok(other) => panic!("landed in {other}, was steered at 7"),
            Err(e) => assert_eq!(e, Error::Medium),
        }
        // A byte the seal wants clear that the part keeps set: refused for certain.
        let mut slots = mk3();
        let mut sealed = [0u8; SLOT_LEN];
        nvstore::seal(json, &k, 0xE7000, &mut sealed).unwrap();
        let clear_bit = (0..8).find(|b| sealed[100] & (1 << b) == 0).unwrap();
        slots.medium.stuck = Some((0xE7000 + 100, 1 << clear_bit));
        assert_eq!(
            store::write(&mut slots, &k, json, 7, &mut seal),
            Err(Error::Medium)
        );
    }

    /// A NOR slot is one sector: longer JSON has nowhere to grow into.
    #[test]
    fn a_slot_is_exactly_one_sector() {
        let k = key();
        let mut slots = mk3();
        assert_eq!(slots.write(0, &[0u8; 4095]), Err(MediumError));
        assert_eq!(slots.write(0, &[0u8; 4097]), Err(MediumError));
        assert!(
            slots.medium.programmed.is_empty(),
            "nothing should be programmed"
        );
        // JSON past the padding seals to more than a sector, and the store reports the
        // medium refusing it rather than truncating.
        let mut json = Vec::from(br#"{"_age":1,"big":""#.as_slice());
        json.resize(nvstore::BODY_LEN + 50, b'x');
        json.extend_from_slice(br#""}"#);
        let mut seal = vec![0u8; json.len() + nvstore::DIGEST_LEN];
        assert_eq!(
            store::write(&mut slots, &k, &json, 0, &mut seal),
            Err(Error::Medium)
        );
        assert!(slots.medium.staged_image_intact());
    }

    /// Slot indexes past the layout are refused before any address is formed.
    #[test]
    fn an_index_past_the_layout_never_becomes_an_address() {
        let mut slots = mk3();
        let mut buf = scratch();
        assert_eq!(slots.read(32, &mut buf), Err(MediumError));
        assert_eq!(slots.write(32, &[0u8; 4096]), Err(MediumError));
        assert_eq!(slots.clear(32), Err(MediumError));
        assert_eq!(slots.read(u32::MAX, &mut buf), Err(MediumError));
        assert!(slots.medium.erased.is_empty());
        assert!(slots.medium.programmed.is_empty());
    }

    /// A buffer smaller than a slot is refused rather than filled partway.
    #[test]
    fn a_short_buffer_is_refused_not_truncated() {
        let mut slots = mk3();
        let mut small = [0u8; 100];
        assert_eq!(slots.read(0, &mut small), Err(MediumError));
    }

    /// The read-only view reads and does nothing else.
    #[test]
    fn a_read_only_view_refuses_to_write_or_clear() {
        let k = key();
        let mut writable = mk3();
        let mut seal = scratch();
        store::write(&mut writable, &k, br#"{"_age":1}"#, 2, &mut seal).unwrap();
        let mut ro = NorSlots::read_only(writable.into_medium(), MK3);
        let mut buf = scratch();
        assert!(store::read(&mut ro, &k, &mut buf).is_ok());
        assert_eq!(ro.write(5, &[0u8; 4096]), Err(MediumError));
        assert_eq!(ro.clear(2), Err(MediumError));
        assert_eq!(ro.last_cleared(), None);
        // And the store's save is refused through it.
        let mut doc = scratch();
        assert_eq!(
            store::set(&mut ro, &k, "nick", &"x", 5, &mut doc, &mut seal),
            Err(Error::Medium)
        );
        // Nothing was erased or programmed through the read-only view.
        assert_eq!(ro.medium.erased.len(), 1, "only the writable view's erase");
    }

    /// Erased reads as empty; anything else reads as a full sector, whoever wrote it.
    #[test]
    fn erased_is_empty_and_anything_else_is_a_full_sector() {
        let mut slots = mk3();
        let mut buf = scratch();
        assert_eq!(slots.read(0, &mut buf), Ok(None));
        // One byte cleared anywhere in the sector: not empty, not ours to reuse.
        slots.medium.mem[0xE0000 + 4000] = 0x7F;
        assert_eq!(slots.read(0, &mut buf), Ok(Some(4096)));
        assert_eq!(buf[4000], 0x7F);
        assert_eq!(slots.usage(), Ok((1, 4096)));
    }

    /// A clear erases the sector and is remembered, so the next save avoids it.
    #[test]
    fn a_clear_erases_and_is_remembered() {
        let k = key();
        let mut slots = mk3();
        let mut seal = scratch();
        assert_eq!(
            store::write(&mut slots, &k, br#"{"_age":1}"#, 6, &mut seal),
            Ok(6)
        );
        assert_eq!(
            store::write(&mut slots, &k, br#"{"_age":2}"#, 11, &mut seal),
            Ok(11)
        );
        assert_eq!(slots.last_cleared(), Some(6));
        let mut buf = scratch();
        assert_eq!(slots.read(6, &mut buf), Ok(None));
        assert!(slots.medium.erased.contains(&0xE6000));
        // Steered straight back at 6: goes elsewhere.
        let third = store::write(&mut slots, &k, br#"{"_age":3}"#, 6, &mut seal).unwrap();
        assert_ne!(third, 6);
        assert_ne!(third, 11);
        assert_eq!(slots.usage(), Ok((1, 4096)));
    }

    /// Settings under the pre-login key and under a wallet's key share the region
    /// without either overwriting the other -- the same rule as on LittleFS, on this
    /// medium.
    #[test]
    fn two_keys_share_the_region() {
        let mine = key();
        let theirs = nvstore::prelogin_key();
        let mut slots = mk3();
        let mut doc = scratch();
        let mut seal = scratch();
        store::set(&mut slots, &theirs, "nick", &"cat", 0, &mut doc, &mut seal).unwrap();
        for i in 0..5 {
            store::set(&mut slots, &mine, "i", &i, 0, &mut doc, &mut seal).unwrap();
        }
        let n = store::read(&mut slots, &theirs, &mut doc).unwrap();
        assert_eq!(Doc::parse(&doc[..n]).unwrap().get_str("nick"), Some("cat"));
        let n = store::read(&mut slots, &mine, &mut doc).unwrap();
        assert_eq!(Doc::parse(&doc[..n]).unwrap().get_u64("i"), Some(4));
        assert_eq!(slots.usage(), Ok((2, 8192)));
        assert!(slots.medium.staged_image_intact());
    }
}
