//! The global allocator: `catcard-alloc` over the 4 MiB the linker script reserves after
//! `.bss`. Wallet code reads better with the odd `String` (an `xpub` is one), and there is
//! room to spare in 16 MiB of SRAM.
//!
//! One hart, interrupts never enabled (see `start.rs`): nothing can re-enter the
//! allocator, so a cell without a lock is enough.

use core::alloc::{GlobalAlloc, Layout};
use core::cell::UnsafeCell;
use core::ptr::NonNull;

use catcard_alloc::Heap;

struct Global(UnsafeCell<Heap>);

// SAFETY: single hart, no interrupt handlers -- see the module comment.
unsafe impl Sync for Global {}

#[global_allocator]
static GLOBAL: Global = Global(UnsafeCell::new(Heap::empty()));

unsafe extern "C" {
    static mut _heap_start: u8;
    static mut _heap_end: u8;
}

/// Hands the heap its region. Call once, before anything allocates.
pub fn init() {
    let start = &raw mut _heap_start;
    let end = &raw mut _heap_end;
    let len = end as usize - start as usize;
    // SAFETY: the region is reserved by the linker script for the heap alone and is
    // writable SRAM; `init` is called once from `rust_main`, before any allocation.
    unsafe { (*GLOBAL.0.get()).init(start, len) };
}

/// Bytes currently allocated.
pub fn used() -> usize {
    // SAFETY: no re-entrancy (module comment); a shared read of a counter.
    unsafe { (*GLOBAL.0.get()).used() }
}

// SAFETY: allocations come from the heap and go back to it; no re-entrancy.
unsafe impl GlobalAlloc for Global {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        // SAFETY: exclusive access, see the module comment.
        let heap = unsafe { &mut *self.0.get() };
        heap.try_alloc(layout)
            .map_or(core::ptr::null_mut(), |p| p.as_ptr())
    }

    unsafe fn dealloc(&self, ptr: *mut u8, _layout: Layout) {
        let Some(ptr) = NonNull::new(ptr) else { return };
        // SAFETY: exclusive access, and the caller's contract is that `ptr` came from here.
        unsafe { (*self.0.get()).dealloc(ptr) };
    }
}
