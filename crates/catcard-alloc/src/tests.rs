//! What the heap has to get right, stated as the ways it could be wrong.
//!
//! The one that matters most is that two live allocations never overlap, so most of
//! these write a distinct pattern into every block and read them all back afterwards
//! rather than trusting the addresses to look plausible.

use super::*;

extern crate alloc;
extern crate std;
use alloc::vec;
use alloc::vec::Vec;

/// A heap over an owned, aligned region.
///
/// `u64` backing so the region is aligned whatever the host, and kept alive beside the
/// heap so nothing dangles.
struct Owned {
    heap: Heap,
    _backing: Vec<u64>,
}

impl Owned {
    fn new(bytes: usize) -> Self {
        let mut backing = vec![0u64; bytes.div_ceil(8)];
        let mut heap = Heap::empty();
        // SAFETY: the backing outlives the heap and nothing else touches it.
        unsafe { heap.init(backing.as_mut_ptr().cast(), bytes) };
        Owned {
            heap,
            _backing: backing,
        }
    }
}

fn layout(size: usize, align: usize) -> Layout {
    Layout::from_size_align(size, align).expect("a valid layout")
}

/// Fill a block with a byte, so overlap shows up as the wrong byte later.
fn paint(p: NonNull<u8>, len: usize, with: u8) {
    // SAFETY: `len` bytes were just allocated at `p`.
    unsafe { core::ptr::write_bytes(p.as_ptr(), with, len) };
}

fn check(p: NonNull<u8>, len: usize, expect: u8) -> bool {
    // SAFETY: as `paint`.
    unsafe { core::slice::from_raw_parts(p.as_ptr(), len) }
        .iter()
        .all(|&b| b == expect)
}

#[test]
fn a_block_round_trips() {
    let mut o = Owned::new(4096);
    let p = o
        .heap
        .try_alloc(layout(100, 1))
        .expect("room for 100 bytes");
    paint(p, 100, 0xA5);
    assert!(check(p, 100, 0xA5));
    assert!(o.heap.used() >= 100);
    // SAFETY: `p` came from this heap and is live.
    unsafe { o.heap.dealloc(p) };
    assert_eq!(o.heap.used(), 0, "freeing everything leaves nothing out");
}

/// Live blocks never overlap. This is the property; everything else is bookkeeping.
#[test]
fn live_blocks_never_overlap() {
    let mut o = Owned::new(16 * 1024);
    let sizes = [1usize, 7, 64, 300, 1000, 33, 512, 17];
    let mut live: Vec<(NonNull<u8>, usize)> = Vec::new();
    for (i, &n) in sizes.iter().enumerate() {
        let p = o.heap.try_alloc(layout(n, 1)).expect("room");
        paint(p, n, i as u8 + 1);
        live.push((p, n));
    }
    // Every block still reads back as its own byte, so none was written through by
    // another allocation.
    for (i, &(p, n)) in live.iter().enumerate() {
        assert!(check(p, n, i as u8 + 1), "block {i} was overwritten");
    }
    for (p, _) in live {
        // SAFETY: each came from this heap and is live exactly once.
        unsafe { o.heap.dealloc(p) };
    }
    assert_eq!(o.heap.used(), 0);
}

/// Alignment is honoured, including alignments larger than a word.
#[test]
fn every_alignment_is_honoured() {
    let mut o = Owned::new(32 * 1024);
    let mut live = Vec::new();
    for align in [1usize, 2, 4, 8, 16, 32, 64, 128, 256] {
        let p = o
            .heap
            .try_alloc(layout(64, align))
            .unwrap_or_else(|| panic!("room for an align-{align} block"));
        assert_eq!(
            p.as_ptr() as usize % align,
            0,
            "align {align} was not honoured"
        );
        paint(p, 64, align as u8);
        live.push((p, align));
    }
    for (p, align) in live {
        assert!(
            check(p, 64, align as u8),
            "align-{align} block was clobbered"
        );
        // SAFETY: from this heap, live.
        unsafe { o.heap.dealloc(p) };
    }
    assert_eq!(o.heap.used(), 0, "aligned blocks free their padding too");
}

/// Running out returns `None`. It does not panic, and it does not hand out a short block.
///
/// The reason this type exists. A caller that is told no can send an image uncompressed
/// or tell someone the screen has no room; a caller that has been aborted cannot.
#[test]
fn exhaustion_is_reported_not_fatal() {
    let mut o = Owned::new(2048);
    let mut live = Vec::new();
    // Take 256 bytes at a time until it says no, which it must do before running past
    // the end of a 2 KiB region.
    for _ in 0..100 {
        match o.heap.try_alloc(layout(256, 1)) {
            Some(p) => live.push(p),
            None => break,
        }
    }
    assert!(!live.is_empty(), "a 2 KiB heap must fit something");
    assert!(
        live.len() < 100,
        "it must refuse before it runs out of heap"
    );
    assert!(
        o.heap.try_alloc(layout(256, 1)).is_none(),
        "still refusing once full"
    );
    // And it recovers: free one and the next request fits again.
    // SAFETY: from this heap, live.
    unsafe { o.heap.dealloc(live.pop().expect("at least one")) };
    assert!(o.heap.try_alloc(layout(256, 1)).is_some());
}

/// A request larger than the heap is refused rather than wrapping or truncating.
#[test]
fn an_impossible_request_is_refused() {
    let mut o = Owned::new(1024);
    assert!(o.heap.try_alloc(layout(4096, 1)).is_none());
    assert!(o.heap.try_alloc(layout(usize::MAX / 2, 1)).is_none());
    // The heap is untouched and still works.
    assert!(o.heap.try_alloc(layout(64, 1)).is_some());
}

/// Freed neighbours merge, so the heap can hand out a large block again afterwards.
///
/// Without coalescing this is the failure that matters on this device: the free total
/// stays healthy while the largest single block shrinks, until a 16 KB screen buffer
/// cannot be had on a heap that is mostly empty.
#[test]
fn freed_neighbours_merge_back_into_one_block() {
    let mut o = Owned::new(8192);
    let big = 1024;
    let mut live = Vec::new();
    while let Some(p) = o.heap.try_alloc(layout(big, 1)) {
        live.push(p);
    }
    let count = live.len();
    assert!(count >= 4, "expected several 1 KiB blocks, got {count}");

    for p in live.drain(..) {
        // SAFETY: from this heap, live.
        unsafe { o.heap.dealloc(p) };
    }
    assert_eq!(o.heap.used(), 0);

    // All of it is one block again: a request for what they held together fits.
    let whole = big * count;
    assert!(
        o.heap.try_alloc(layout(whole, 1)).is_some(),
        "{count} freed 1 KiB blocks did not merge back into {whole} contiguous bytes"
    );
}

/// Merging works in both directions, and from the middle.
///
/// Freeing the middle of three adjacent blocks has to join the one before it and the one
/// after it in a single step, or the heap ends up with two free blocks that touch --
/// which is the state coalescing exists to prevent.
///
/// The heap is filled first, deliberately. With spare room at the end, the largest free
/// block is that leftover tail and a merge among three small blocks is invisible: the
/// first version of this test measured exactly that and passed a heap that had not
/// merged at all.
#[test]
fn a_block_freed_between_two_free_ones_joins_both() {
    let mut o = Owned::new(8192);
    let n = 512;
    let mut live = Vec::new();
    while let Some(p) = o.heap.try_alloc(layout(n, 1)) {
        live.push(p);
    }
    assert!(live.len() >= 4, "expected several blocks");

    // The first three are adjacent, in address order, with no free space anywhere.
    // SAFETY: from this heap, each freed once.
    unsafe {
        o.heap.dealloc(live[0]);
        o.heap.dealloc(live[2]);
    }
    assert!(
        o.heap.try_alloc(layout(n * 3, 1)).is_none(),
        "two separated free blocks must not satisfy a request for three"
    );

    // SAFETY: as above.
    unsafe { o.heap.dealloc(live[1]) };
    let joined = o
        .heap
        .try_alloc(layout(n * 3, 1))
        .expect("freeing the middle block must join all three into one");

    // SAFETY: from this heap, live.
    unsafe { o.heap.dealloc(joined) };
    for &p in &live[3..] {
        // SAFETY: as above; 0..3 were freed already.
        unsafe { o.heap.dealloc(p) };
    }
    assert_eq!(o.heap.used(), 0);
}

/// A heap churned in a hostile order still hands out large blocks.
///
/// Allocate many, free every other one -- the classic way to shred a free list -- then
/// free the rest and check the heap came back whole rather than as a hundred fragments
/// that happen to add up.
#[test]
fn churn_does_not_permanently_fragment_the_heap() {
    let mut o = Owned::new(16 * 1024);
    let whole = o.heap.largest_free();

    for round in 0..8 {
        let mut live = Vec::new();
        let size = 64 + round * 16; // a different size each round, to shift the seams
        while let Some(p) = o.heap.try_alloc(layout(size, 1)) {
            live.push(p);
        }
        // Free the odd ones first, then the even ones: every free block is created with
        // a live neighbour on each side, so nothing merges until the second pass.
        for (i, &p) in live.iter().enumerate() {
            if i % 2 == 1 {
                // SAFETY: from this heap, freed once.
                unsafe { o.heap.dealloc(p) };
            }
        }
        for (i, &p) in live.iter().enumerate() {
            if i % 2 == 0 {
                // SAFETY: as above.
                unsafe { o.heap.dealloc(p) };
            }
        }
        assert_eq!(o.heap.used(), 0, "round {round} leaked");
        assert_eq!(
            o.heap.largest_free(),
            whole,
            "round {round} left the heap fragmented"
        );
    }
}

/// An offcut too small to be a free block is given to the allocation, not dropped.
///
/// The alternative is a few bytes that belong to nobody: not free, not accounted, and
/// gone until reboot. Over enough allocations that is a leak, and a leak in a heap this
/// size is a device that stops being able to open a screen.
#[test]
fn a_remainder_too_small_to_track_is_not_lost() {
    let mut o = Owned::new(4096);
    let whole = o.heap.largest_free();
    // Ask for all but a sliver, so what is left cannot hold a free block's bookkeeping.
    let ask = whole - MIN_BLOCK / 2;
    let p = o
        .heap
        .try_alloc(layout(ask, 1))
        .expect("nearly the whole heap");
    // SAFETY: from this heap, live.
    unsafe { o.heap.dealloc(p) };
    assert_eq!(o.heap.used(), 0);
    assert_eq!(
        o.heap.largest_free(),
        whole,
        "the sliver was not returned with the block"
    );
}

/// The high-water mark is the peak, not the current usage.
///
/// It is what says whether the heap is the right size, so it has to survive the frees
/// that brought usage back down.
#[test]
fn the_high_water_mark_remembers_the_peak() {
    let mut o = Owned::new(8192);
    let a = o.heap.try_alloc(layout(1000, 1)).unwrap();
    let b = o.heap.try_alloc(layout(1000, 1)).unwrap();
    let peak = o.heap.used();
    assert!(peak >= 2000);
    // SAFETY: from this heap, each freed once.
    unsafe {
        o.heap.dealloc(a);
        o.heap.dealloc(b);
    }
    assert_eq!(o.heap.used(), 0);
    assert_eq!(o.heap.high_water(), peak, "the peak was forgotten");
}

/// A heap given nothing usable stays empty rather than handing out memory it lacks.
#[test]
fn a_region_too_small_to_use_yields_nothing() {
    let mut heap = Heap::empty();
    let mut tiny = [0u64; 1];
    // SAFETY: the region is real, just too small to hold a free block.
    unsafe { heap.init(tiny.as_mut_ptr().cast(), MIN_BLOCK - 1) };
    assert_eq!(heap.size(), 0);
    assert!(heap.try_alloc(layout(1, 1)).is_none());
}

/// Zero-sized requests get a real, distinct, freeable block.
///
/// `Layout` allows a size of zero and the global allocator will pass one through, so it
/// has to mean something rather than alias another block or fail.
#[test]
fn a_zero_sized_request_still_gets_its_own_block() {
    let mut o = Owned::new(4096);
    let a = o.heap.try_alloc(layout(0, 1)).expect("zero is allocatable");
    let b = o.heap.try_alloc(layout(0, 1)).expect("and twice");
    assert_ne!(a, b, "two zero-sized blocks must not be the same address");
    // SAFETY: from this heap, each freed once.
    unsafe {
        o.heap.dealloc(a);
        o.heap.dealloc(b);
    }
    assert_eq!(o.heap.used(), 0);
}
