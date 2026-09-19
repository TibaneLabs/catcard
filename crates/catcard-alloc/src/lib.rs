//! A small heap whose allocation **reports failure instead of panicking**.
//!
//! # Why a heap at all, in a wallet
//!
//! Because there was already one, badly. A firmware with no allocator still has to
//! decide where its buffers live, and the way that was decided here was a `static` per
//! user, each sized for its own worst case and resident for the device's whole life.
//! That is an allocator: one that always allocates the maximum, never frees, cannot
//! report failure, and whose accounting nobody checks. On the Q1 it had reserved about
//! ninety kilobytes for buffers that are used one screen at a time, and the space it
//! took came out of the only stack the boot path has -- which overflowed into the
//! kernel's task table and took the device down.
//!
//! A heap is not obviously safer than static buffers. It is safer than *that*.
//!
//! # Fallible, not panicking
//!
//! [`Heap::try_alloc`] returns `None` when it cannot find room. It never panics, never
//! aborts, and has no "handle this out of line" path. That is the whole point: on this
//! device, running out of memory is something a caller can often do something sensible
//! about -- a host can be told to resend an image uncompressed, a screen can say it has
//! no room and return -- and none of those are available to code that has already died.
//!
//! The standard [`alloc`](https://doc.rust-lang.org/alloc/) collections do not work this
//! way; `Vec::push` aborts on failure. Firmware here should ask this type directly, or
//! use the fallible APIs (`try_reserve`), and keep key material and signing off the heap
//! entirely -- those paths have bounded, known sizes and belong on the stack.
//!
//! # The design
//!
//! First fit over an address-ordered free list, with immediate coalescing in both
//! directions. Free blocks carry their bookkeeping inside themselves, so an unallocated
//! heap costs nothing but its own bytes; allocated blocks carry a two-word header.
//!
//! Address ordering is what makes coalescing cheap and total: neighbours in the list are
//! neighbours in memory, so a freed block merges with whichever of them touch it. The
//! alternative -- a size-ordered or unordered list -- is faster to search and leaves a
//! heap that slowly stops being able to hand out large blocks, which on a device that
//! asks for 16 KB at a time is the only failure that matters.
//!
//! First fit rather than best fit for the same reason: with a handful of large, mostly
//! LIFO allocations, best fit spends its time finding a tighter block and leaves smaller
//! offcuts behind. Neither is clever, and cleverness here would need evidence this
//! device cannot provide.

#![no_std]
#![deny(unsafe_op_in_unsafe_fn)]

use core::alloc::Layout;
use core::mem::{align_of, size_of};
use core::ptr::NonNull;

/// The alignment every block starts on, and the header's own alignment.
const ALIGN: usize = align_of::<usize>();

/// What an allocated block carries, immediately before the payload.
///
/// `total` is the whole extent, including this header and any padding placed in front of
/// it to meet an alignment; `pad` says how much of that is in front, so freeing can find
/// where the extent began. Two words rather than one, because an allocator that cannot
/// find the start of what it handed out cannot coalesce it.
#[repr(C)]
#[derive(Copy, Clone)]
struct Header {
    total: usize,
    pad: usize,
}

/// A free block, with the list threaded through the free space itself.
#[repr(C)]
struct Free {
    size: usize,
    next: Option<NonNull<Free>>,
}

/// The smallest extent worth leaving behind: a free block has to be able to hold its own
/// bookkeeping, or it cannot be on the list at all.
const MIN_BLOCK: usize = size_of::<Free>();

/// Round `n` up to a multiple of `to`, which must be a power of two.
const fn align_up(n: usize, to: usize) -> usize {
    (n + to - 1) & !(to - 1)
}

/// A heap over a caller-supplied region.
pub struct Heap {
    head: Option<NonNull<Free>>,
    /// Bytes handed out, counted as whole extents so it matches what was taken from the
    /// region rather than what was asked for.
    used: usize,
    /// The most that has been out at once, which is the number worth reporting: a heap
    /// that has never been more than a third full is one that can be made smaller.
    high_water: usize,
    /// The region's total size, for reporting how much is left.
    size: usize,
}

// SAFETY: the heap owns its region exclusively and has no interior mutability of its
// own; sharing one between threads is the caller's problem to solve with a lock, exactly
// as for any other `&mut`-driven structure. Firmware here uses it from the foreground.
unsafe impl Send for Heap {}

impl Heap {
    /// A heap with no memory. [`init`](Self::init) gives it some.
    ///
    /// Separate from `init` so the heap can be a `static`, which is where a global
    /// allocator has to live, and be given its region once the boot path knows where
    /// that is.
    pub const fn empty() -> Self {
        Heap {
            head: None,
            used: 0,
            high_water: 0,
            size: 0,
        }
    }

    /// Give the heap a region to hand out.
    ///
    /// # Safety
    /// `start` must point to `len` bytes that are writable, and that nothing else uses
    /// for as long as this heap does. Call once.
    pub unsafe fn init(&mut self, start: *mut u8, len: usize) {
        let base = align_up(start as usize, ALIGN);
        let end = (start as usize).saturating_add(len);
        if end <= base || end - base < MIN_BLOCK {
            // Too small to hold even one free block. Left empty rather than rounded up
            // into something that would be handed out.
            return;
        }
        let size = (end - base) & !(ALIGN - 1);
        // SAFETY: `base` is inside the caller's region, aligned, and the region is at
        // least `MIN_BLOCK` long, so a `Free` fits.
        unsafe {
            let node = base as *mut Free;
            node.write(Free { size, next: None });
            self.head = Some(NonNull::new_unchecked(node));
        }
        self.size = size;
    }

    /// Bytes currently handed out, including headers and padding.
    pub fn used(&self) -> usize {
        self.used
    }

    /// Bytes the region holds in total.
    pub fn size(&self) -> usize {
        self.size
    }

    /// The most that has been handed out at once.
    pub fn high_water(&self) -> usize {
        self.high_water
    }

    /// The largest single allocation this heap could satisfy right now.
    ///
    /// For reporting, and for a caller deciding whether to ask at all. It is a property
    /// of the current fragmentation, not of the free total: a heap with plenty free and
    /// none of it contiguous is the case this number exists to make visible.
    pub fn largest_free(&self) -> usize {
        let mut best = 0;
        let mut cur = self.head;
        while let Some(node) = cur {
            // SAFETY: every node on the list is a live `Free` this heap wrote.
            let node = unsafe { node.as_ref() };
            best = best.max(node.size.saturating_sub(size_of::<Header>()));
            cur = node.next;
        }
        best
    }

    /// Allocate, or `None` if there is no room. **Never panics.**
    pub fn try_alloc(&mut self, layout: Layout) -> Option<NonNull<u8>> {
        let want = align_up(layout.size().max(1), ALIGN);
        let align = layout.align().max(ALIGN);

        let mut prev: Option<NonNull<Free>> = None;
        let mut cur = self.head;
        while let Some(mut node) = cur {
            // SAFETY: every node on the list is a live `Free` this heap wrote.
            let (base, size, next) = unsafe {
                let n = node.as_ref();
                (node.as_ptr() as usize, n.size, n.next)
            };

            // Where the payload would land in this block, and what the whole extent
            // would then cost including the padding in front of the header.
            let payload = align_up(base + size_of::<Header>(), align);
            let pad = payload - size_of::<Header>() - base;
            let total = pad + size_of::<Header>() + want;

            if size >= total {
                // What is left over is a free block if it can hold one, and part of this
                // allocation otherwise -- a remainder too small to track is not free
                // space, it is a leak waiting to be counted as one.
                let remainder = size - total;
                let (total, rest) = if remainder >= MIN_BLOCK {
                    (total, Some((base + total, remainder)))
                } else {
                    (size, None)
                };

                // Unlink this block, then put any remainder back in its place so the
                // list stays ordered by address.
                let replacement = match rest {
                    Some((at, len)) => {
                        // SAFETY: `at` is inside the block being taken, aligned, and has
                        // room for a `Free` -- `remainder >= MIN_BLOCK` above.
                        unsafe {
                            let n = at as *mut Free;
                            n.write(Free { size: len, next });
                            Some(NonNull::new_unchecked(n))
                        }
                    }
                    None => next,
                };
                match prev {
                    // SAFETY: `prev` is a live node on this list.
                    Some(mut p) => unsafe { p.as_mut().next = replacement },
                    None => self.head = replacement,
                }

                // SAFETY: the header sits inside the extent just taken, immediately
                // before the payload, and is aligned because `payload` is.
                unsafe {
                    let header = (payload - size_of::<Header>()) as *mut Header;
                    header.write(Header { total, pad });
                }
                self.used += total;
                self.high_water = self.high_water.max(self.used);
                // SAFETY: `payload` is inside the region and non-null.
                return Some(unsafe { NonNull::new_unchecked(payload as *mut u8) });
            }

            prev = Some(node);
            // Keep the borrow of `node` from outliving the loop body.
            let _ = &mut node;
            cur = next;
        }
        None
    }

    /// Give a block back.
    ///
    /// # Safety
    /// `ptr` must have come from [`try_alloc`](Self::try_alloc) on this heap and not yet
    /// been freed.
    pub unsafe fn dealloc(&mut self, ptr: NonNull<u8>) {
        // SAFETY: the caller's contract: the header is where `try_alloc` wrote it.
        let (base, total) = unsafe {
            let header = (ptr.as_ptr() as usize - size_of::<Header>()) as *const Header;
            let h = header.read();
            (ptr.as_ptr() as usize - size_of::<Header>() - h.pad, h.total)
        };
        self.used = self.used.saturating_sub(total);
        // SAFETY: `base` begins an extent this heap handed out, so it is aligned and has
        // room for a `Free`.
        unsafe { self.insert(base, total) };
    }

    /// Put an extent back on the address-ordered list, merging with either neighbour it
    /// touches.
    ///
    /// # Safety
    /// `base` must begin `size` bytes that belong to this heap and are not on the list.
    unsafe fn insert(&mut self, base: usize, size: usize) {
        // Find the last block before this one, which is where it belongs.
        let mut prev: Option<NonNull<Free>> = None;
        let mut cur = self.head;
        while let Some(node) = cur {
            if node.as_ptr() as usize > base {
                break;
            }
            prev = Some(node);
            // SAFETY: a live node on the list.
            cur = unsafe { node.as_ref().next };
        }

        // SAFETY: `base` is a writable extent of at least `MIN_BLOCK` -- every extent
        // handed out was at least that large.
        let mut node = unsafe {
            let n = base as *mut Free;
            n.write(Free { size, next: cur });
            NonNull::new_unchecked(n)
        };

        // Merge forward: the block after this one, if it starts where this one ends.
        if let Some(after) = cur {
            // SAFETY: a live node on the list.
            unsafe {
                if base + size == after.as_ptr() as usize {
                    let a = after.as_ref();
                    node.as_mut().size += a.size;
                    node.as_mut().next = a.next;
                }
            }
        }

        // Merge backward, which also links the new block in either way.
        match prev {
            // SAFETY: a live node on the list.
            Some(mut p) => unsafe {
                let p_end = p.as_ptr() as usize + p.as_ref().size;
                if p_end == base {
                    p.as_mut().size += node.as_ref().size;
                    p.as_mut().next = node.as_ref().next;
                } else {
                    p.as_mut().next = Some(node);
                }
            },
            None => self.head = Some(node),
        }
    }
}

#[cfg(test)]
mod tests;
