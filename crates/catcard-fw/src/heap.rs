//! The firmware's heap: one region, lent out a block at a time.
//!
//! What this replaces is ninety kilobytes of `static` buffers, one per screen, each
//! sized for its own worst case and resident for the device's whole life — in a
//! firmware whose boot stack is only what `.bss` leaves over, and which overflowed into
//! the kernel's task table because of it. The screens that own those buffers are modal:
//! at most one is open, so at most one set is in use, and reserving them all at once was
//! paying for a concurrency that cannot happen.
//!
//! # Ask for a [`Block`], not for a `Vec`
//!
//! [`take`] returns `None` when the heap cannot find room, and a [`Block`] that frees
//! itself when dropped — so a screen that cannot get its buffer says so and returns,
//! and a host offering a compressed image can be told to send it uncompressed instead.
//!
//! The global allocator is registered too, so `alloc` works where it genuinely helps.
//! But it is the lesser path: `Vec::push` **aborts** when it cannot grow, which here
//! means the panic handler, which means a wiped device. Anything large, anything
//! optional, and anything on a path that can report a failure should call [`take`].
//!
//! # What a block leaves behind
//!
//! Nothing. A [`Block`] is wiped before its extent goes back on the free list, so the
//! next [`take`] never hands out what the last holder left in it -- and what the last
//! holder left in it is usually a decrypted settings file: the Seed Vault, the notes and
//! their passwords, the 2FA card list. Thirty-two kilobytes of volatile stores on the
//! rare occasion a block is dropped is nothing against handing a wallet's secrets to
//! whichever screen asks for a buffer next.
//!
//! That guarantee is for blocks. A `Vec` freed through the global allocator is not
//! wiped, which is one more reason large or sensitive buffers come from [`take`].
//!
//! # What must not come from here
//!
//! Key material and signing. Those sizes are known in advance and they belong on the
//! stack, where `keywork::run` masks interrupts around them. The wipe above is a
//! backstop for a block that held a secret by way of a settings file, not a licence to
//! put one there on purpose.

use core::alloc::{GlobalAlloc, Layout};
use core::ptr::NonNull;

use catcard_alloc::Heap;
use zeroize::Zeroize as _;

/// The heap, in bytes.
///
/// From the worst case the allocator's own tests measure: the largest screen (16 KiB of
/// card blocks) with a compressed upload's 8 KiB inflate slab alongside it, which is
/// 24,608 bytes once each block carries a header. 32 KiB leaves a quarter spare, and
/// the heartbeat reports the high-water mark so this can be revisited with evidence
/// rather than re-guessed.
pub const SIZE: usize = 32 * 1024;

/// The region itself. Aligned, because blocks handed out of it are written as words.
///
/// The field is never named: the bytes are reached through `addr_of_mut!` and handed to
/// the heap, which is the only thing that reads them. It exists to reserve the space and
/// to carry the alignment.
#[repr(align(8))]
struct Region(#[allow(dead_code)] [u8; SIZE]);
static mut REGION: Region = Region([0; SIZE]);

static mut HEAP: Heap = Heap::empty();

/// Run `f` with exclusive use of the heap.
///
/// Interrupts masked: the UI task and the USB task both allocate, and the kernel can
/// switch between them. An allocation walks a handful of pointers, so this is a few
/// microseconds — far shorter than the callgate calls the firmware already makes with
/// interrupts off.
fn with<R>(f: impl FnOnce(&mut Heap) -> R) -> R {
    cortex_m::interrupt::free(|_| {
        // SAFETY: interrupts are masked and this is a single-core device, so nothing
        // else can be inside `with` at the same time. The borrow ends with the closure.
        f(unsafe { &mut *core::ptr::addr_of_mut!(HEAP) })
    })
}

/// Give the heap its region.
///
/// # Safety
/// Call once, from the boot path, before anything allocates.
pub unsafe fn init() {
    with(|heap| {
        // SAFETY: the region is a `static` that outlives everything, and the caller's
        // contract is that this runs once before any allocation.
        unsafe { heap.init(core::ptr::addr_of_mut!(REGION).cast::<u8>(), SIZE) };
    });
    crate::catlog!("heap: {} bytes", SIZE);
}

/// Bytes in use, the most ever in use, and the region's size.
pub fn stats() -> (usize, usize, usize) {
    with(|heap| (heap.used(), heap.high_water(), heap.size()))
}

/// A block of heap memory, returned when it is dropped.
///
/// Dropping is the only way it goes back, which is what makes a screen that exits by
/// being cancelled — or by a key nobody expected — as safe as one that finishes.
pub struct Block {
    ptr: NonNull<u8>,
    len: usize,
}

// SAFETY: a block owns its bytes exclusively; moving it between tasks moves the
// ownership with it, and the heap it came from is locked on every access.
unsafe impl Send for Block {}

impl Block {
    /// The bytes, for as long as this block lives.
    pub fn bytes(&mut self) -> &mut [u8] {
        // SAFETY: `ptr` came from the heap, is `len` bytes long, and this block is the
        // only owner of it — the borrow checker ties the slice to `&mut self`.
        unsafe { core::slice::from_raw_parts_mut(self.ptr.as_ptr(), self.len) }
    }

    /// The block as words, for a buffer that is counted in `u32`s.
    ///
    /// Only the picture viewer asks for these today, and that is a Q1 screen, so on the
    /// other boards they are compiled with nothing calling them.
    ///
    /// Blocks come out of the heap aligned to a word -- [`take`] asks for it -- so this
    /// is a view, not a copy. A tail of fewer than four bytes is left out rather than
    /// rounded up.
    #[cfg_attr(not(feature = "board-q1"), allow(dead_code))]
    pub fn words(&mut self) -> &mut [u32] {
        // SAFETY: `ptr` is 4-aligned and `len` bytes long, this block owns them, and the
        // borrow checker ties the slice to `&mut self` as it does for `bytes`.
        unsafe { core::slice::from_raw_parts_mut(self.ptr.as_ptr().cast::<u32>(), self.len / 4) }
    }

    /// The block as 16-bit pixels, for a picture on the way to the panel.
    #[cfg_attr(not(feature = "board-q1"), allow(dead_code))]
    pub fn pixels(&mut self) -> &mut [u16] {
        // SAFETY: as `words` -- a word-aligned block is also halfword-aligned.
        unsafe { core::slice::from_raw_parts_mut(self.ptr.as_ptr().cast::<u16>(), self.len / 2) }
    }

    /// The bytes, with the borrow detached from this block.
    ///
    /// For the one shape [`bytes`](Self::bytes) cannot serve: a decoder that holds its
    /// output buffer across calls has to be stored beside the block that owns it, and a
    /// slice borrowed from a sibling field is a self-reference the compiler will not
    /// allow. The heap region never moves, so a pointer into it stays valid; what the
    /// compiler can no longer check is who else is looking.
    ///
    /// # Safety
    /// The returned slice must not outlive this block, and nothing else may reference
    /// those bytes while it exists — including a second call to this method.
    pub unsafe fn leak_mut(&mut self) -> &'static mut [u8] {
        // SAFETY: the caller's contract.
        unsafe { core::slice::from_raw_parts_mut(self.ptr.as_ptr(), self.len) }
    }
}

impl Drop for Block {
    fn drop(&mut self) {
        // Wiped before it is free, not after: once it is on the free list another task
        // can be handed it. Volatile stores, so the compiler cannot decide a buffer
        // that is about to be freed is dead and skip the writes.
        self.bytes().zeroize();
        with(|heap| {
            // SAFETY: `ptr` came from this heap and is freed exactly once — `Block` is
            // not `Copy` and this is its only drop.
            unsafe { heap.dealloc(self.ptr) };
        });
    }
}

/// Take `len` bytes, or `None` if the heap has no room.
///
/// Word-aligned, because most of what the firmware puts in these ends up copied into
/// memory-mapped PSRAM, where only aligned word stores are issued correctly.
pub fn take(len: usize) -> Option<Block> {
    let layout = Layout::from_size_align(len, 4).ok()?;
    let ptr = alloc_from_anywhere(layout)?;
    Some(Block { ptr, len })
}

/// Allocate out of the linked heap, and out of the spare bank if the linked heap cannot.
///
/// The one place that decides to reach for the spare RAM, so `take` and the global
/// allocator behave the same and neither has to know the bank exists.
fn alloc_from_anywhere(layout: Layout) -> Option<NonNull<u8>> {
    if let Some(p) = with(|heap| heap.try_alloc(layout)) {
        return Some(p);
    }
    if !claim_spare() {
        return None;
    }
    with(|heap| heap.try_alloc(layout))
}

/// Whether the spare bank has been looked at, and what came of it.
///
/// Foreground only, like the rest of this module; the claim itself runs with interrupts
/// masked inside [`with`].
static mut SPARE: Spare = Spare::Untried;

#[derive(Copy, Clone, PartialEq, Eq)]
enum Spare {
    /// Not looked at yet. Nothing has needed more than the linked heap.
    Untried,
    /// In the heap, and counted in its size.
    Added,
    /// The board has none, or what is there did not behave like memory.
    None,
}

/// Whether the spare bank is in the heap -- and so may hold anything the heap ever held.
///
/// For the wipe paths: the bank is zeroed on a panic or a fault only if it was claimed,
/// because claiming is also what proved it is memory. Touching an unclaimed bank from a
/// fault handler could fault again, and a fault inside the hard fault handler is a
/// lockup with nothing wiped at all. Reads one static; safe from handler mode.
pub fn spare_claimed() -> bool {
    // SAFETY: a single aligned read of a plain enum; the only writer runs in the
    // foreground under `with`, and this is called with interrupts masked.
    unsafe { *core::ptr::addr_of!(SPARE) == Spare::Added }
}

/// Give the heap the RAM the image does not link, the first time something needs it.
///
/// Returns whether the heap grew.
///
/// # Why this is not done at boot
///
/// Because the bank is memory this firmware has never used. The linked region is proven
/// by the device starting at all; SRAM2/SRAM3 are proven only by a table in the hardware
/// reference, and the way an address that is not memory announces itself on a Cortex-M4
/// is a bus fault -- which on the boot path means a device that stops before USB exists,
/// on units at RDP=2 where there is no other way in. Waiting until something asks for a
/// big block puts that risk inside one screen: the worst case is a screen that dies and
/// a power cycle, not a wallet nobody can reach.
///
/// Source: hw-reference/platform.md §"Mk4/Mk5/Q flash & SRAM map" [C] -- SRAM1/2/3 are
/// one contiguous 640 KB from 0x2000_0000 on the L4+ boards, of which the image links
/// the first 192 KB and the bootloader reserves the top 8 KB.
fn claim_spare() -> bool {
    // SAFETY: foreground, single core; `with` masks interrupts around the mutation.
    match unsafe { *core::ptr::addr_of!(SPARE) } {
        Spare::Added => return true,
        Spare::None => return false,
        Spare::Untried => {}
    }
    let outcome = match catcard_board::BOARD.memory.spare_ram {
        Some(spare) if looks_like_memory(spare) => {
            with(|heap| {
                // SAFETY: the bank is real (just checked), word-aligned, outside every
                // linked section, below what the bootloader reserves, and added once --
                // `SPARE` makes sure of the last part.
                unsafe { heap.add_region(spare.base as *mut u8, spare.len as usize) };
            });
            crate::catlog!(
                "heap: +{} bytes of spare RAM at {:#010x}",
                spare.len,
                spare.base
            );
            Spare::Added
        }
        Some(spare) => {
            crate::catlog!("heap: spare RAM at {:#010x} did not answer", spare.base);
            Spare::None
        }
        None => Spare::None,
    };
    // SAFETY: as above.
    unsafe { *core::ptr::addr_of_mut!(SPARE) = outcome };
    outcome == Spare::Added
}

/// Whether a bank really holds what is written to it, before any of it is handed out.
///
/// A bus fault is not what this catches -- nothing in software can. What it catches is
/// the quieter failure: a bank smaller than the table says, or one that aliases another,
/// where stores land somewhere and reads return something. So the check writes a value
/// derived from each address it visits and only then reads them all back: an alias makes
/// two probes collide, and the second pass sees a word it did not write. The last word
/// of the bank is always one of them, because a short bank is the case that would
/// otherwise corrupt whatever it wraps onto.
fn looks_like_memory(spare: catcard_board::memory::SpareRam) -> bool {
    /// Far enough apart to land in different banks and different 64 KiB pages, and few
    /// enough that the whole check is a few dozen instructions.
    const STEP: u32 = 32 * 1024;
    let last = spare.end() - 4;
    let probe = |at: u32| -> u32 { at ^ 0xA5A5_5A5A };

    let mut at = spare.base;
    loop {
        // SAFETY: inside the bank the board table describes, word-aligned, and nothing
        // else can be using it -- it is in no section this image links.
        unsafe { core::ptr::write_volatile(at as *mut u32, probe(at)) };
        if at == last {
            break;
        }
        at = (at + STEP).min(last);
    }
    let mut at = spare.base;
    loop {
        // SAFETY: as above.
        let got = unsafe { core::ptr::read_volatile(at as *const u32) };
        if got != probe(at) {
            return false;
        }
        if at == last {
            return true;
        }
        at = (at + STEP).min(last);
    }
}

/// The global allocator, so `alloc` collections work.
///
/// Registered for the sake of code that genuinely reads better with a `Vec`, and with
/// the caveat in the module documentation: the `alloc` APIs abort when they cannot
/// grow, and on this device aborting means the panic handler wipes it. Large or
/// optional buffers go through [`take`], which can be told no.
struct Global;

// SAFETY: every entry point locks the heap, and the pointers handed out come from it.
unsafe impl GlobalAlloc for Global {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        alloc_from_anywhere(layout).map_or(core::ptr::null_mut(), |p| p.as_ptr())
    }

    unsafe fn dealloc(&self, ptr: *mut u8, _layout: Layout) {
        let Some(ptr) = NonNull::new(ptr) else { return };
        with(|heap| {
            // SAFETY: the caller's contract is that this came from this allocator.
            unsafe { heap.dealloc(ptr) };
        });
    }
}

#[global_allocator]
static GLOBAL: Global = Global;
