//! USB mass storage over Bulk-Only Transport, backed by the SD card.
//!
//! Runs only while `Utils → USB Drive` is open. [`usbtask`](crate::usbtask) has already
//! switched the device's identity to mass storage; this loop moves the CBW / data / CSW
//! of Bulk-Only Transport and turns the SCSI commands [`catcard_usb::msc`] decodes into
//! reads and writes of the card. It returns when the caller's `should_exit` reports the
//! screen was left, at which point the caller switches the identity back.

use catcard_hal::sdmmc::Sdmmc;
use catcard_sd::{BLOCK_LEN, Card, read_block, write_block};
use catcard_usb::msc::{self, Cbw, Command, Sense, csw_status};

use crate::usbtask;

/// Polls with no host progress before a data phase is abandoned. The host has stopped
/// reading or writing -- unplugged, or moved on -- so the transfer is dropped and the
/// loop goes back to waiting for a command rather than spinning forever.
const IDLE_LIMIT: u32 = 2_000_000;

/// Serve the card as a USB drive until `should_exit` returns true.
pub fn run(dev: &mut Sdmmc, card: &Card, mut should_exit: impl FnMut() -> bool) {
    let mut sense = Sense::OK;
    let mut pkt = [0u8; 64];
    let mut block = [0u8; BLOCK_LEN];

    loop {
        if should_exit() {
            return;
        }
        // A Command Block Wrapper arrives on bulk-OUT as a single 31-byte packet.
        let Some(n) = usbtask::msc_poll(&mut pkt) else {
            continue;
        };
        let Some(cbw) = Cbw::parse(&pkt[..n]) else {
            // Out of phase; drop it and wait for a clean CBW rather than acting on it.
            continue;
        };
        // Clear any reset that landed before this CBW: recovery is done, this is a fresh
        // command, and only a reset arriving *during* it should drop its CSW.
        usbtask::msc_take_reset();
        let cmd = msc::decode(&cbw.cb[..cbw.cb_len as usize]);
        // Ejecting the drive from the host is another way to say "done" -- answer the
        // command, then leave the screen exactly as the `x` key does.
        if matches!(cmd, Command::Eject) {
            let mut cswb = [0u8; msc::CSW_LEN];
            msc::csw(&mut cswb, cbw.tag, 0, csw_status::PASSED);
            send_bytes(&cswb);
            return;
        }
        let (status, moved) = dispatch(dev, card, &cbw, cmd, &mut block, &mut sense);
        // If a Bulk-Only Mass Storage Reset arrived while this command was in flight, the
        // host has abandoned it and is not waiting for a CSW. Drop it and go back to
        // waiting for the next CBW -- sending a stale CSW now would be read as the front
        // of the next command's data and desync the transport for good.
        if usbtask::msc_take_reset() {
            continue;
        }
        let mut cswb = [0u8; msc::CSW_LEN];
        msc::csw(
            &mut cswb,
            cbw.tag,
            cbw.data_len.saturating_sub(moved),
            status,
        );
        send_bytes(&cswb);
    }
}

/// Carry out one command's data phase; return the CSW status and how many data bytes
/// moved (for the CSW residue).
fn dispatch(
    dev: &mut Sdmmc,
    card: &Card,
    cbw: &Cbw,
    cmd: Command,
    block: &mut [u8; BLOCK_LEN],
    sense: &mut Sense,
) -> (u8, u32) {
    let mut reply = [0u8; 64];
    match cmd {
        // `Eject` is intercepted in `run` before it reaches here; acked, for exhaustiveness.
        Command::TestUnitReady | Command::NoData | Command::Eject => (csw_status::PASSED, 0),
        Command::Inquiry { .. } => {
            let n = msc::inquiry(&mut reply);
            reply_in(&reply[..n], cbw)
        }
        Command::ReadCapacity => {
            let n = msc::read_capacity(card.blocks, &mut reply);
            reply_in(&reply[..n], cbw)
        }
        Command::ModeSense { .. } => {
            let n = msc::mode_sense(false, &mut reply);
            reply_in(&reply[..n], cbw)
        }
        Command::ReadFormatCapacities { .. } => {
            let n = msc::read_format_capacities(card.blocks, &mut reply);
            reply_in(&reply[..n], cbw)
        }
        Command::RequestSense { .. } => {
            let n = msc::request_sense(*sense, &mut reply);
            *sense = Sense::OK; // sense is consumed by being read
            reply_in(&reply[..n], cbw)
        }
        Command::Read { lba, blocks } => transfer_read(dev, card, lba, blocks, sense),
        Command::Write { lba, blocks } => transfer_write(dev, card, lba, blocks, block, sense),
        Command::Unsupported => {
            *sense = Sense::INVALID_COMMAND;
            (csw_status::FAILED, 0)
        }
    }
}

/// Send a fixed reply, trimmed to what the host asked for.
fn reply_in(data: &[u8], cbw: &Cbw) -> (u8, u32) {
    let want = (cbw.data_len as usize).min(data.len());
    (csw_status::PASSED, send_bytes(&data[..want]) as u32)
}

fn out_of_range(card: &Card, lba: u32, blocks: u16) -> bool {
    lba as u64 + blocks as u64 > card.blocks as u64
}

/// Blocks read from the card and streamed to the host as one gapless bulk-IN transfer.
///
/// A single 512-byte block's eight packets go out fine, but reading the next block from
/// the card between two sends leaves a gap the host's back-to-back IN tokens outrun --
/// the data phase then comes up a packet short and the transport desyncs. Reading a run
/// of blocks into one buffer and sending them together removes those gaps; only the
/// boundary between buffers still carries one, and at this size they are rare.
const CHUNK_BLOCKS: usize = 32;
const CHUNK_LEN: usize = CHUNK_BLOCKS * BLOCK_LEN;

/// The read buffer. Used only by the single-threaded USB Drive loop, one reader at a
/// time; big enough that a typical readahead is one gapless transfer.
static mut READ_CHUNK: [u8; CHUNK_LEN] = [0; CHUNK_LEN];

fn transfer_read(
    dev: &mut Sdmmc,
    card: &Card,
    lba: u32,
    blocks: u16,
    sense: &mut Sense,
) -> (u8, u32) {
    if out_of_range(card, lba, blocks) {
        *sense = Sense::LBA_OUT_OF_RANGE;
        return (csw_status::FAILED, 0);
    }
    // SAFETY: the USB Drive screen is single-threaded and `transfer_read` is its only
    // user of this buffer; no other reference is live while `run` is on the stack.
    let buf = unsafe { &mut *core::ptr::addr_of_mut!(READ_CHUNK) };
    let total = blocks as u32;
    let mut sent = 0u32;
    let mut done = 0u32;
    while done < total {
        let n = (total - done).min(CHUNK_BLOCKS as u32);
        for i in 0..n as usize {
            let slot = &mut buf[i * BLOCK_LEN..(i + 1) * BLOCK_LEN];
            let Ok(slot) = <&mut [u8; BLOCK_LEN]>::try_from(slot) else {
                unreachable!("slice is exactly one block")
            };
            if read_block(dev, card, lba + done + i as u32, slot).is_err() {
                *sense = Sense::MEDIUM_ERROR;
                // Ship the whole blocks read before the failure, then fail the command.
                let got = send_bytes(&buf[..i * BLOCK_LEN]);
                return (csw_status::FAILED, sent + got as u32);
            }
        }
        let bytes = n as usize * BLOCK_LEN;
        let got = send_bytes(&buf[..bytes]);
        sent += got as u32;
        if got < bytes {
            // The host stopped reading (or reset); the CSW residue reports the shortfall.
            break;
        }
        done += n;
    }
    (csw_status::PASSED, sent)
}

fn transfer_write(
    dev: &mut Sdmmc,
    card: &Card,
    lba: u32,
    blocks: u16,
    block: &mut [u8; BLOCK_LEN],
    sense: &mut Sense,
) -> (u8, u32) {
    if out_of_range(card, lba, blocks) {
        *sense = Sense::LBA_OUT_OF_RANGE;
        return (csw_status::FAILED, 0);
    }
    let mut got = 0u32;
    for i in 0..blocks as u32 {
        if !recv_block(block) {
            return (csw_status::FAILED, got);
        }
        got += BLOCK_LEN as u32;
        if write_block(dev, card, lba + i, block).is_err() {
            *sense = Sense::MEDIUM_ERROR;
            return (csw_status::FAILED, got);
        }
    }
    (csw_status::PASSED, got)
}

/// Send `data` on bulk-IN in 64-byte packets. Returns how many bytes went out -- short of
/// `data.len()` only if the host stopped reading.
///
/// The wait for the endpoint to free is spun on the cheap [`msc_send`](usbtask::msc_send),
/// which checks the IN FIFO and `EPENA` directly, so the next packet goes in the instant
/// the last one drains. The full core service ([`msc_poll`](usbtask::msc_poll)) -- which is
/// what notices a mass-storage reset -- runs only once every [`POLL_EVERY`] spins: doing it
/// after every packet was pure overhead on the fast path and kept the pipe from filling.
fn send_bytes(data: &[u8]) -> usize {
    /// Cheap endpoint-free spins between one full core service.
    const POLL_EVERY: u32 = 64;

    let mut off = 0;
    let mut idle = 0u32;
    let mut spins = 0u32;
    let mut scratch = [0u8; 64];
    while off < data.len() {
        let end = (off + 64).min(data.len());
        if usbtask::msc_send(&data[off..end]) {
            off = end;
            idle = 0;
            spins = 0;
            continue;
        }
        spins += 1;
        if spins.is_multiple_of(POLL_EVERY) {
            usbtask::msc_poll(&mut scratch);
            // A mass-storage reset during the wait means the host has torn this transfer
            // down; stop pushing data it will never read. `run` sees the same flag and
            // skips the CSW.
            if usbtask::msc_reset_pending() {
                break;
            }
            // `idle` counts services without progress, so the timeout is unchanged.
            idle += 1;
            if idle > IDLE_LIMIT {
                break;
            }
        }
    }
    off
}

/// Receive one 512-byte block from bulk-OUT. False if the host stopped sending.
fn recv_block(block: &mut [u8; BLOCK_LEN]) -> bool {
    let mut off = 0;
    let mut idle = 0u32;
    let mut pkt = [0u8; 64];
    while off < BLOCK_LEN {
        match usbtask::msc_poll(&mut pkt) {
            Some(n) => {
                let end = (off + n).min(BLOCK_LEN);
                block[off..end].copy_from_slice(&pkt[..end - off]);
                off = end;
                idle = 0;
            }
            None => {
                // The host reset the transport mid-write: abandon the block.
                if usbtask::msc_reset_pending() {
                    return false;
                }
                idle += 1;
                if idle > IDLE_LIMIT {
                    return false;
                }
            }
        }
    }
    true
}
