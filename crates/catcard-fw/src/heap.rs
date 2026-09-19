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
//! # What must not come from here
//!
//! Key material and signing. Those sizes are known in advance, they belong on the
//! stack, and a seed that lives in a freed block is a seed sitting in memory nobody is
//! tracking. `keywork::run` is where that work goes.

use core::alloc::{GlobalAlloc, Layout};
use core::ptr::NonNull;

use catcard_alloc::Heap;

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
    let ptr = with(|heap| heap.try_alloc(layout))?;
    Some(Block { ptr, len })
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
        with(|heap| heap.try_alloc(layout)).map_or(core::ptr::null_mut(), |p| p.as_ptr())
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
