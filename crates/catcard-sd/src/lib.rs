//! Bringing up an SD card, and reading blocks off it.
//!
//! Split the way [`catcard_pin`](../catcard_pin/index.html) is split: **the sequence
//! lives here and the registers do not.** Card bring-up is a conversation — send CMD0,
//! ask CMD8 whether the card understands 2.7-3.6 V, poll ACMD41 until it stops saying
//! busy, read the CSD to find out how big it is — and every interesting mistake is in
//! that conversation rather than in any single register write. Kept behind a
//! [`Transport`], it runs on the host against a fake card, which is the only way the
//! off-by-ones get found without a scope.
//!
//! Sources are public: the SD Physical Layer Simplified Specification for the command
//! set and the CSD layout, and ST's reference manuals for the peripheral behind
//! `Transport`.
#![no_std]
#![deny(unsafe_op_in_unsafe_fn)]

/// Bytes in a block. Every SD card addresses 512-byte blocks regardless of its
/// internal page size, and SDHC/SDXC address *in* blocks rather than bytes.
pub const BLOCK_LEN: usize = 512;

/// What went wrong. No variant means "probably fine".
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub enum Error {
    /// No card in the slot, as reported by the card-detect pin.
    NoCard,
    /// The card never answered a command that requires an answer.
    Timeout { cmd: u8 },
    /// The card answered, but the response did not check out.
    BadResponse { cmd: u8 },
    /// CMD8 came back with the wrong voltage or check pattern, so this is either not an
    /// SD card or not one that can run at our supply.
    Unusable,
    /// The card stayed busy through initialisation for longer than the spec allows.
    InitTimeout,
    /// The CSD described a capacity this code will not credit.
    BadCsd,
    /// A data transfer failed its CRC, or the peripheral reported an underrun.
    DataError { block: u32 },
    /// The peripheral itself did not start, which is not the card's fault.
    Peripheral,
    /// The card was still busy with a written block when the wait for it ran out.
    Busy,
    /// A write was asked of a card this code only reads. Upgrading from a card needs
    /// nothing written to it, and a firmware that cannot write the card cannot corrupt
    /// someone's files either.
    ReadOnly,
    /// Something this transport does not do at all -- a short transfer on a transport
    /// that only models blocks, for instance.
    Unsupported,
}

/// Which response shape a command expects, since that decides how long to wait and how
/// many bits to collect.
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub enum Response {
    /// No response at all: CMD0.
    None,
    /// 48 bits, the usual case.
    Short,
    /// 136 bits: CID and CSD.
    Long,
}

/// The peripheral, reduced to what bring-up needs.
///
/// Deliberately small. Everything above this trait is testable on a host; everything
/// below it needs silicon, so the less that is below it the better.
pub trait Transport {
    /// Send a command and collect its response.
    fn command(&mut self, cmd: u8, arg: u32, resp: Response) -> Result<[u32; 4], Error>;

    /// Read one 512-byte block, having already issued the command that starts it.
    fn read_data(&mut self, out: &mut [u8; BLOCK_LEN]) -> Result<(), Error>;

    /// Write one 512-byte block, having already issued the command that starts it.
    ///
    /// Defaults to refusing: a transport that models only reads -- the tests' fake cards,
    /// a future read-only medium -- is read-only by saying nothing, and the card layer
    /// turns that into [`Error::ReadOnly`] rather than a silent success.
    fn write_data(&mut self, data: &[u8; BLOCK_LEN]) -> Result<(), Error> {
        let _ = data;
        Err(Error::ReadOnly)
    }

    /// Switch the bus to four data lines. A card that refuses stays on one.
    fn set_bus_width_4(&mut self) -> Result<(), Error>;

    /// Raise the clock once the card is out of identification mode.
    fn set_fast_clock(&mut self);

    /// Whether a card is physically present, if the board can tell.
    fn card_present(&self) -> bool;

    /// Arm the data path for one incoming block, before the read command is sent.
    ///
    /// The order is the point: a controller told to expect data only after the card has
    /// been asked for it drops the first words on the floor. Split out so the sequence
    /// lives here, where it is tested, rather than in the driver.
    fn arm_block_read(&mut self) {}

    /// Arm the data path for a transfer of `len` bytes, before the command is sent.
    ///
    /// The general form of the two calls above, for the commands whose payload is not a
    /// block: a lock/unlock structure, a card's SCR, a status register. `len` must be a
    /// power of two -- the controller's block size is an exponent, not a length -- which
    /// is a real constraint on what a caller may ask for and not a detail of this
    /// driver.
    ///
    /// Defaults to doing nothing, like the block arms: a transport that models a fake
    /// card has nothing to arm.
    fn arm_data(&mut self, len: usize, to_host: bool) {
        let _ = (len, to_host);
    }

    /// Read a short payload, having already armed and issued its command.
    fn read_short(&mut self, out: &mut [u8]) -> Result<(), Error> {
        let _ = out;
        Err(Error::Unsupported)
    }

    /// Write a short payload, having already armed and issued its command.
    fn write_short(&mut self, data: &[u8]) -> Result<(), Error> {
        let _ = data;
        Err(Error::ReadOnly)
    }

    /// Arm the data path for one outgoing block, before the write command is sent.
    ///
    /// The same ordering point as [`Transport::arm_block_read`], the other direction: a
    /// controller told to expect an outgoing transfer only after the command has gone out
    /// misses the window the card opens for it.
    fn arm_block_write(&mut self) {}
}

/// How a card is addressed, which is the one thing that changes how blocks are read.
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub enum Addressing {
    /// Standard capacity: the argument to a read is a **byte** offset.
    ByteAddressed,
    /// High capacity (SDHC/SDXC): the argument is a **block** number.
    BlockAddressed,
}

/// A card that finished initialisation.
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub struct Card {
    /// Relative card address, as assigned by CMD3; the upper half of every addressed
    /// command's argument.
    pub rca: u16,
    pub addressing: Addressing,
    /// Capacity in 512-byte blocks.
    pub blocks: u32,
    /// Whether the bus is running four bits wide.
    pub wide: bool,
}

impl Card {
    /// Capacity in whole mebibytes, for a screen.
    pub fn mib(&self) -> u32 {
        self.blocks / 2048
    }
}

// Command numbers used here. Named rather than inlined, because `55` twice on a line is
// how an ACMD becomes an ordinary command by accident.
const CMD_GO_IDLE: u8 = 0;
const CMD_ALL_SEND_CID: u8 = 2;
const CMD_SEND_RCA: u8 = 3;
const CMD_SELECT: u8 = 7;
const CMD_SEND_STATUS: u8 = 13;
const CMD_SEND_IF_COND: u8 = 8;
const CMD_SEND_CSD: u8 = 9;
const CMD_READ_SINGLE: u8 = 17;
const CMD_WRITE_SINGLE: u8 = 24;
const CMD_APP: u8 = 55;
const ACMD_OP_COND: u8 = 41;

/// Card status (the R1 response to CMD13): `CURRENT_STATE` in bits 12:9, and
/// `READY_FOR_DATA` in bit 8. Source: SD Physical Layer Specification, "Card Status" [C]
const STATUS_READY_FOR_DATA: u32 = 1 << 8;
const STATUS_STATE_SHIFT: u32 = 9;
const STATE_TRANSFER: u32 = 4;

/// CMD13 polls before a card still programming a block is given up on. Each poll is a
/// command exchange of well under a millisecond; the specification's write timeout is
/// 250 ms on standard cards, 500 ms on SDXC, so this is many times what any card takes.
const BUSY_POLLS: u32 = 20_000;

/// CMD8 check pattern, echoed back by a card that understood the question.
const IF_COND_PATTERN: u32 = 0x1AA;
/// Host capacity support: we can talk to a high-capacity card.
const OCR_HCS: u32 = 1 << 30;
/// Card power-up finished.
const OCR_BUSY_DONE: u32 = 1 << 31;
/// Card is high capacity, so blocks are addressed by number.
const OCR_CCS: u32 = 1 << 30;
/// 3.2-3.4 V, which is the rail these boards run the slot at.
const OCR_VOLTAGE: u32 = 1 << 20;

/// How many times ACMD41 may say "still busy".
///
/// The spec gives a card one second to finish powering up. This is a count rather than a
/// duration because the loop has no clock of its own; the transport paces it.
const INIT_TRIES: u32 = 2000;

/// Bring a card up and report what it is.
pub fn init<T: Transport>(t: &mut T) -> Result<Card, Error> {
    if !t.card_present() {
        return Err(Error::NoCard);
    }

    t.command(CMD_GO_IDLE, 0, Response::None)?;

    // CMD8 is also the version check: a card that ignores it is pre-2.0, and one that
    // echoes the pattern back can be asked for high capacity below.
    let r = t.command(CMD_SEND_IF_COND, IF_COND_PATTERN, Response::Short)?;
    if r[0] & 0xFFF != IF_COND_PATTERN {
        return Err(Error::Unusable);
    }

    // ACMD41 until the card stops claiming to be busy. Each ACMD is CMD55 then the
    // command itself, addressed to RCA 0 because we have not assigned one yet.
    let ocr;
    let mut tries = 0;
    loop {
        t.command(CMD_APP, 0, Response::Short)?;
        let r = t.command(ACMD_OP_COND, OCR_HCS | OCR_VOLTAGE, Response::Short)?;
        if r[0] & OCR_BUSY_DONE != 0 {
            ocr = r[0];
            break;
        }
        tries += 1;
        if tries >= INIT_TRIES {
            return Err(Error::InitTimeout);
        }
    }

    let addressing = if ocr & OCR_CCS != 0 {
        Addressing::BlockAddressed
    } else {
        Addressing::ByteAddressed
    };

    t.command(CMD_ALL_SEND_CID, 0, Response::Long)?;

    // The card picks its own address and tells us; it lives in the top 16 bits.
    let r = t.command(CMD_SEND_RCA, 0, Response::Short)?;
    let rca = (r[0] >> 16) as u16;
    if rca == 0 {
        return Err(Error::BadResponse { cmd: CMD_SEND_RCA });
    }

    let csd = t.command(CMD_SEND_CSD, (rca as u32) << 16, Response::Long)?;
    let blocks = capacity_blocks(&csd)?;

    // Selecting the card moves it from stand-by to transfer state; nothing can be read
    // until this happens, and a missed CMD7 shows up as every later read timing out.
    t.command(CMD_SELECT, (rca as u32) << 16, Response::Short)?;

    let wide = t.set_bus_width_4().is_ok();
    t.set_fast_clock();

    Ok(Card {
        rca,
        addressing,
        blocks,
        wide,
    })
}

/// Read one block.
pub fn read_block<T: Transport>(
    t: &mut T,
    card: &Card,
    lba: u32,
    out: &mut [u8; BLOCK_LEN],
) -> Result<(), Error> {
    if lba >= card.blocks {
        return Err(Error::DataError { block: lba });
    }
    // The argument's units depend on the card, which is the whole reason `Addressing`
    // is carried around: sending a block number to a byte-addressed card reads a
    // location 512 times too low, and succeeds while returning the wrong data.
    let arg = match card.addressing {
        Addressing::BlockAddressed => lba,
        Addressing::ByteAddressed => lba.saturating_mul(BLOCK_LEN as u32),
    };
    t.arm_block_read();
    t.command(CMD_READ_SINGLE, arg, Response::Short)?;
    t.read_data(out)
}

/// Write one block.
///
/// The mirror of [`read_block`], and it shares the addressing trap: the argument is a
/// block number on an SDHC card and a byte offset on an SDSC one, and getting it wrong
/// writes the right bytes to the wrong place -- which on a write is not recoverable by
/// reading again.
pub fn write_block<T: Transport>(
    t: &mut T,
    card: &Card,
    lba: u32,
    data: &[u8; BLOCK_LEN],
) -> Result<(), Error> {
    if lba >= card.blocks {
        return Err(Error::DataError { block: lba });
    }
    let arg = match card.addressing {
        Addressing::BlockAddressed => lba,
        Addressing::ByteAddressed => lba.saturating_mul(BLOCK_LEN as u32),
    };
    t.arm_block_write();
    t.command(CMD_WRITE_SINGLE, arg, Response::Short)?;
    t.write_data(data)?;
    wait_until_ready(t, card)
}

/// Wait for a card to finish programming the block it was just sent.
///
/// A card acknowledges a written block before it has stored it, and holds the data line
/// busy while it does. It answers CMD13 during that time but no data command, so the next
/// read or write sent straight away goes unanswered: on the mk3's controller that was a
/// CMD17 timing out right after a write, and a file write failing half way. The spec's
/// answer is to ask the card's state until it is back in *transfer* and ready for data.
fn wait_until_ready<T: Transport>(t: &mut T, card: &Card) -> Result<(), Error> {
    let rca = u32::from(card.rca) << 16;
    for _ in 0..BUSY_POLLS {
        let [status, ..] = t.command(CMD_SEND_STATUS, rca, Response::Short)?;
        if status & STATUS_READY_FOR_DATA != 0
            && (status >> STATUS_STATE_SHIFT) & 0xF == STATE_TRANSFER
        {
            return Ok(());
        }
    }
    Err(Error::Busy)
}

/// Capacity in 512-byte blocks, from a 136-bit CSD.
///
/// The two CSD versions compute this completely differently, and version 1's formula is
/// the one with the factor-of-four trap: `C_SIZE_MULT` is an exponent, and the `+2` in
/// it is easy to drop.
///
/// `csd` is the response as four words, most significant first, with the 8-bit CRC and
/// start/stop bits already stripped by the peripheral — which is how ST's SDMMC presents
/// a long response.
fn capacity_blocks(csd: &[u32; 4]) -> Result<u32, Error> {
    match csd[0] >> 30 {
        // CSD v2: capacity is a single field, in 512 KB units.
        1 => {
            let c_size = ((csd[1] & 0x3F) << 16) | (csd[2] >> 16);
            // (C_SIZE + 1) * 512 KB, expressed in 512-byte blocks.
            c_size
                .checked_add(1)
                .and_then(|n| n.checked_mul(1024))
                .ok_or(Error::BadCsd)
        }
        // CSD v1: capacity is assembled from three fields.
        0 => {
            let c_size = ((csd[1] & 0x3FF) << 2) | (csd[2] >> 30);
            let c_size_mult = (csd[2] >> 15) & 0x7;
            let read_bl_len = (csd[1] >> 16) & 0xF;
            if !(9..=11).contains(&read_bl_len) {
                return Err(Error::BadCsd);
            }
            // blocks = (C_SIZE + 1) * 2^(C_SIZE_MULT + 2) * 2^READ_BL_LEN / 512
            let mult = 1u32.checked_shl(c_size_mult + 2).ok_or(Error::BadCsd)?;
            let bytes_per = 1u32.checked_shl(read_bl_len).ok_or(Error::BadCsd)?;
            c_size
                .checked_add(1)
                .and_then(|n| n.checked_mul(mult))
                .and_then(|n| n.checked_mul(bytes_per / BLOCK_LEN as u32))
                .ok_or(Error::BadCsd)
        }
        _ => Err(Error::BadCsd),
    }
}

/// The heapless FAT driver, re-exported so callers name one crate.
///
/// `fstool::fs::fat` with `alloc` off is the driver that needs no heap: one sector of
/// scratch RAM whatever the size of the card, rather than holding the whole allocation
/// table resident.
pub use fstool::fs::fat;

/// The heapless exFAT driver, re-exported alongside [`fat`]. Modern high-capacity SDXC
/// cards ship exFAT out of the box, so a browser that only read FAT would turn many cards
/// away. It shares FAT's [`fat::SectorDriver`] (both are `fstool`'s one device trait), so
/// [`Sectors`] drives it unchanged.
pub use fstool::fs::exfat;

pub mod format;

/// An initialised card, presented as the sectors a FAT volume is built from.
///
/// Owns its transport because a mounted [`fat::Volume`] owns its device for as long as
/// it is mounted; handing it a borrow would tie the volume's lifetime to a peripheral
/// the firmware needs back afterwards. [`Sectors::into_inner`] returns it.
pub struct Sectors<T: Transport> {
    t: T,
    card: Card,
}

impl<T: Transport> Sectors<T> {
    pub fn new(t: T, card: Card) -> Self {
        Self { t, card }
    }

    /// The card, as initialised.
    pub fn card(&self) -> &Card {
        &self.card
    }

    /// Give the transport back.
    pub fn into_inner(self) -> T {
        self.t
    }
}

impl<T: Transport> fat::SectorDriver for Sectors<T> {
    type Error = Error;

    fn sector_size(&self) -> u32 {
        BLOCK_LEN as u32
    }

    fn sector_count(&self) -> u64 {
        self.card.blocks as u64
    }

    fn read_sectors(&mut self, lba: u64, buf: &mut [u8]) -> Result<(), Error> {
        // The driver asks for whole multiples of a sector and checks the range first, but
        // this is the boundary to a card, so check again rather than trust a caller.
        // `as_chunks_mut` both splits into sector-sized arrays and surfaces any leftover
        // as `rest`, which stands in for the old modulo check.
        let (chunks, rest) = buf.as_chunks_mut::<BLOCK_LEN>();
        if !rest.is_empty() {
            return Err(Error::DataError { block: u32::MAX });
        }
        for (i, chunk) in chunks.iter_mut().enumerate() {
            let block = lba
                .checked_add(i as u64)
                .and_then(|b| u32::try_from(b).ok())
                .ok_or(Error::DataError { block: u32::MAX })?;
            read_block(&mut self.t, &self.card, block, chunk)?;
        }
        Ok(())
    }

    fn write_sectors(&mut self, lba: u64, buf: &[u8]) -> Result<(), Error> {
        // As in `read_sectors`: the driver hands whole sectors, but this is the boundary
        // to a card, so a leftover past the last whole sector is refused here.
        let (chunks, rest) = buf.as_chunks::<BLOCK_LEN>();
        if !rest.is_empty() {
            return Err(Error::DataError { block: u32::MAX });
        }
        for (i, chunk) in chunks.iter().enumerate() {
            let block = lba
                .checked_add(i as u64)
                .and_then(|b| u32::try_from(b).ok())
                .ok_or(Error::DataError { block: u32::MAX })?;
            write_block(&mut self.t, &self.card, block, chunk)?;
        }
        Ok(())
    }
}

/// Why [`AnyVolume::mount_with`] gave up.
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub enum MountError {
    /// The card itself could not be brought up (the `make` closure failed).
    Device,
    /// The card came up but held neither a FAT nor an exFAT filesystem.
    NoFilesystem,
}

/// A mounted volume, FAT or exFAT, behind one small API.
///
/// The two `fstool` backends have parallel but distinct types and no shared no-alloc trait
/// spans them, so this enum forwards the handful of operations the firmware needs to
/// whichever mounted. exFAT counts bytes in `u64`; FAT's `u32` sizes are widened to match.
///
/// The two variants differ in size (each holds its driver's resident state); on a device
/// with no allocator there is nowhere to box the larger one, and one lives on the stack for
/// a browse, which is fine. The forwarding methods return `Result<_, ()>`: the underlying
/// error is rich, but the caller only ever turns it into a short on-screen string.
#[allow(clippy::large_enum_variant, clippy::result_unit_err)]
pub enum AnyVolume<D: fat::SectorDriver, const S: usize = 512> {
    Fat(fat::Volume<D, S>),
    Exfat(exfat::Volume<D, S>),
}

#[allow(clippy::result_unit_err)]
impl<D: fat::SectorDriver, const S: usize> AnyVolume<D, S> {
    /// Mount the card, trying FAT then exFAT.
    ///
    /// `make` produces a fresh device for each attempt because a failed `mount_auto`
    /// consumes the device it was given and does not hand it back; the exFAT attempt
    /// therefore re-initialises the card. FAT is tried first as the common case, so a FAT
    /// card mounts on the first device with no second bring-up.
    pub fn mount_with<F>(mut make: F) -> Result<Self, MountError>
    where
        F: FnMut() -> Result<D, ()>,
    {
        let dev = make().map_err(|()| MountError::Device)?;
        if let Ok(v) = fat::Volume::<D, S>::mount_auto(dev) {
            return Ok(AnyVolume::Fat(v));
        }
        let dev = make().map_err(|()| MountError::Device)?;
        match exfat::Volume::<D, S>::mount_auto(dev) {
            Ok(v) => Ok(AnyVolume::Exfat(v)),
            Err(_) => Err(MountError::NoFilesystem),
        }
    }

    /// Call `f(name, is_dir, len)` for each entry of `path` ("" is the root). FAT's `.`
    /// and `..` are skipped; exFAT has none.
    pub fn enumerate<F>(&mut self, path: &str, mut f: F) -> Result<(), ()>
    where
        F: FnMut(&str, bool, u64),
    {
        match self {
            AnyVolume::Fat(v) => {
                let dir = if path.is_empty() {
                    v.root()
                } else {
                    v.open_dir(path).map_err(|_| ())?
                };
                let mut it = v.iter_dir(dir);
                while let Some(e) = it.next().map_err(|_| ())? {
                    if e.is_dot() {
                        continue;
                    }
                    f(e.name(), e.is_dir(), e.len() as u64);
                }
                Ok(())
            }
            AnyVolume::Exfat(v) => {
                let dir = if path.is_empty() {
                    v.root()
                } else {
                    v.open_dir(path).map_err(|_| ())?
                };
                let mut it = v.iter_dir(dir);
                while let Some(e) = it.next().map_err(|_| ())? {
                    f(e.name(), e.is_dir(), e.len());
                }
                Ok(())
            }
        }
    }

    /// Open an existing file for reading.
    pub fn open_file(&mut self, path: &str) -> Result<AnyFile, ()> {
        match self {
            AnyVolume::Fat(v) => v.open_file(path).map(AnyFile::Fat).map_err(|_| ()),
            AnyVolume::Exfat(v) => v.open_file(path).map(AnyFile::Exfat).map_err(|_| ()),
        }
    }

    /// Open a file, creating it if it does not exist.
    pub fn open_or_create_file(&mut self, path: &str) -> Result<AnyFile, ()> {
        match self {
            AnyVolume::Fat(v) => v
                .open_or_create_file(path)
                .map(AnyFile::Fat)
                .map_err(|_| ()),
            AnyVolume::Exfat(v) => v
                .open_or_create_file(path)
                .map(AnyFile::Exfat)
                .map_err(|_| ()),
        }
    }

    /// Delete a file, freeing the clusters it held.
    ///
    /// Files only. Both backends refuse a directory rather than walking into it, which is
    /// what the browser wants: the one thing a person can delete from a listing is the file
    /// under the cursor, and a recursive delete behind one keypress is not a feature a
    /// wallet should have. The error is the usual `()` -- there is nothing the caller can do
    /// with "not found" that it would not also do with "the card refused the write".
    pub fn remove_file(&mut self, path: &str) -> Result<(), ()> {
        match self {
            AnyVolume::Fat(v) => v.remove_file(path).map_err(|_| ()),
            AnyVolume::Exfat(v) => v.remove_file(path).map_err(|_| ()),
        }
    }

    /// Flush the volume's own metadata.
    pub fn flush(&mut self) -> Result<(), ()> {
        match self {
            AnyVolume::Fat(v) => v.flush().map_err(|_| ()),
            AnyVolume::Exfat(v) => v.flush().map_err(|_| ()),
        }
    }
}

/// An open file on either kind of volume. Its operations take the matching [`AnyVolume`];
/// a file and volume of different kinds is a caller bug and returns `Err`.
#[allow(clippy::large_enum_variant)]
pub enum AnyFile {
    Fat(fat::File),
    Exfat(exfat::File),
}

#[allow(clippy::len_without_is_empty, clippy::result_unit_err)]
impl AnyFile {
    /// The file's length in bytes.
    pub fn len(&self) -> u64 {
        match self {
            AnyFile::Fat(f) => f.len() as u64,
            AnyFile::Exfat(f) => f.len(),
        }
    }

    /// Read into `buf`, returning how many bytes were read (0 at end of file).
    pub fn read<D: fat::SectorDriver, const S: usize>(
        &mut self,
        vol: &mut AnyVolume<D, S>,
        buf: &mut [u8],
    ) -> Result<usize, ()> {
        match (self, vol) {
            (AnyFile::Fat(f), AnyVolume::Fat(v)) => f.read(v, buf).map_err(|_| ()),
            (AnyFile::Exfat(f), AnyVolume::Exfat(v)) => f.read(v, buf).map_err(|_| ()),
            _ => Err(()),
        }
    }

    /// Move the read/write cursor to `pos`.
    pub fn seek<D: fat::SectorDriver, const S: usize>(
        &mut self,
        vol: &mut AnyVolume<D, S>,
        pos: u64,
    ) -> Result<(), ()> {
        match (self, vol) {
            (AnyFile::Fat(f), AnyVolume::Fat(v)) => f.seek(v, pos as u32).map_err(|_| ()),
            // exFAT's seek is infallible and needs no volume.
            (AnyFile::Exfat(f), AnyVolume::Exfat(_)) => {
                f.seek(pos);
                Ok(())
            }
            _ => Err(()),
        }
    }

    /// Write all of `buf`.
    pub fn write_all<D: fat::SectorDriver, const S: usize>(
        &mut self,
        vol: &mut AnyVolume<D, S>,
        buf: &[u8],
    ) -> Result<(), ()> {
        match (self, vol) {
            (AnyFile::Fat(f), AnyVolume::Fat(v)) => f.write_all(v, buf).map_err(|_| ()),
            (AnyFile::Exfat(f), AnyVolume::Exfat(v)) => f.write_all(v, buf).map_err(|_| ()),
            _ => Err(()),
        }
    }

    /// Truncate or extend the file to `len` bytes.
    pub fn set_len<D: fat::SectorDriver, const S: usize>(
        &mut self,
        vol: &mut AnyVolume<D, S>,
        len: u64,
    ) -> Result<(), ()> {
        match (self, vol) {
            (AnyFile::Fat(f), AnyVolume::Fat(v)) => f.set_len(v, len as u32).map_err(|_| ()),
            (AnyFile::Exfat(f), AnyVolume::Exfat(v)) => f.set_len(v, len).map_err(|_| ()),
            _ => Err(()),
        }
    }

    /// Flush the file's own metadata and data.
    pub fn flush<D: fat::SectorDriver, const S: usize>(
        &mut self,
        vol: &mut AnyVolume<D, S>,
    ) -> Result<(), ()> {
        match (self, vol) {
            (AnyFile::Fat(f), AnyVolume::Fat(v)) => f.flush(v).map_err(|_| ()),
            (AnyFile::Exfat(f), AnyVolume::Exfat(v)) => f.flush(v).map_err(|_| ()),
            _ => Err(()),
        }
    }
}

#[cfg(test)]
mod tests;

/// Turning what somebody typed into a name a card will take.
pub mod name {
    /// The longest name this builds, extension included.
    pub const MAX: usize = 40;

    /// `typed` as a file name: the characters a FAT volume takes, an extension added
    /// where none was given, and nothing that could climb out of the folder it goes in.
    ///
    /// A path separator is **dropped, not rejected**: the caller has already chosen the
    /// folder, and someone typing `../secrets` means a file, not a place. What comes back
    /// is a bare name -- never a path -- so a caller that joins it to a folder cannot be
    /// talked into writing somewhere else.
    ///
    /// `None` when nothing usable is left: a name of slashes and dots is not a name.
    pub fn from_typed(typed: &str, ext: &str) -> Option<heapless::String<MAX>> {
        let mut out: heapless::String<MAX> = heapless::String::new();
        for c in typed.chars() {
            if c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | '_' | ' ') {
                let _ = out.push(c);
            }
        }
        // A leading dot hides the file on the computer that reads the card next, and a
        // trailing dot or space is a name Windows will not open.
        while out.starts_with([' ', '.']) {
            out.remove(0);
        }
        while out.ends_with([' ', '.']) {
            out.pop();
        }
        if out.is_empty() {
            return None;
        }
        if !out.contains('.') {
            if out.len() + 1 + ext.len() > MAX {
                while out.len() + 1 + ext.len() > MAX {
                    out.pop();
                }
            }
            let _ = out.push('.');
            let _ = out.push_str(ext);
        }
        Some(out)
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn a_plain_name_gains_the_extension_it_lacks() {
            assert_eq!(from_typed("notes", "txt").unwrap(), "notes.txt");
            assert_eq!(from_typed("notes.md", "txt").unwrap(), "notes.md");
        }

        /// The one that matters: nothing typed can name a place, only a thing.
        #[test]
        fn a_name_cannot_climb_out_of_its_folder() {
            for typed in ["../../secrets", "/etc/passwd", "..\\..\\x"] {
                let name = from_typed(typed, "bin").unwrap();
                assert!(!name.contains('/'), "{typed} -> {name}");
                assert!(!name.contains('\\'), "{typed} -> {name}");
                assert!(!name.starts_with('.'), "{typed} -> {name}");
            }
        }

        #[test]
        fn a_name_with_nothing_usable_in_it_is_refused() {
            for typed in ["", "///", "...", "   ", "/../"] {
                assert_eq!(from_typed(typed, "txt"), None, "{typed:?}");
            }
        }

        /// Long input is cut to fit with its extension, rather than losing the extension
        /// or overflowing the name.
        #[test]
        fn a_long_name_still_ends_in_its_extension() {
            let name = from_typed(&"a".repeat(80), "psbt").unwrap();
            assert!(name.len() <= MAX);
            assert!(name.ends_with(".psbt"), "{name}");
        }
    }
}
