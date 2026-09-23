//! Decoded icons, kept so they are decoded once rather than once a frame.
//!
//! A colour mark is stored deflated -- a 20x20 icon is about 500 bytes that way and 1600
//! raw -- and [`catcard_ui::art::rgba::decode`] inflates it to get at the pixels. That
//! was happening inside the draw: every visible mark, on every frame, while a list is
//! being scrolled. The pixels are identical every time, so all but the first of those
//! inflates is work done twice.
//!
//! So the raw pixels are kept here after the first decode, keyed by the art they came
//! from. Scrolling then costs a copy per mark instead of a Huffman decode per mark.
//!
//! # Where the memory comes from, and why that is alright
//!
//! Sixteen slots of 24x24 RGBA is 36 kB, which would be most of the main heap -- but
//! [`crate::heap::take`] reaches into the spare bank when the linked heap cannot hold
//! something, and 440 kB of that sits unused. The block is taken once, on the first
//! draw that wants a mark, and kept: a cache that gave its memory back between frames
//! would be a cache that never hit.
//!
//! If the allocation fails, every lookup misses and the caller decodes as it always did.
//! Slower, and correct, which is the right way round for a cache.

use catcard_ui::art::rgba::Rgba;

/// How many icons are kept. A document shows at most [`MARKS`](Self) of them at once and
/// a menu cycles through a few dozen, so this is sized to hold a screenful and its
/// neighbours -- past that the oldest goes, which on a list being scrolled is the row
/// that left the screen first.
const SLOTS: usize = 16;

/// The largest mark this will hold, which is the largest the display composites.
const SIDE: usize = 24;

/// Bytes one slot takes: RGBA, at the largest size.
const SLOT: usize = SIDE * SIDE * 4;

/// What a slot is holding.
#[derive(Copy, Clone, PartialEq, Eq)]
struct Key {
    /// The deflated bytes' address. These live in `static` arrays in the art modules, so
    /// the address is stable for the life of the firmware and identifies the icon
    /// exactly -- two icons cannot share one, and one icon cannot have two.
    at: usize,
    len: usize,
}

/// The cache: one block of pixels, and what is in each slot.
struct Cache {
    block: Option<crate::heap::Block>,
    keys: [Option<Key>; SLOTS],
    /// How many pixels each slot actually holds, since an icon may be smaller than the
    /// largest.
    sizes: [(usize, usize); SLOTS],
    /// Where the next eviction takes from: round-robin, which on a scrolling list evicts
    /// what left the screen first without keeping a use count for every slot.
    next: usize,
    /// Set once the block could not be taken, so the attempt is made once rather than on
    /// every frame that wants a mark.
    refused: bool,
}

static mut CACHE: Cache = Cache {
    block: None,
    keys: [None; SLOTS],
    sizes: [(0, 0); SLOTS],
    next: 0,
    refused: false,
};

/// Run `each` over `art`'s pixels, from the cache where possible.
///
/// The callback is the same shape [`catcard_ui::art::rgba::decode`] takes, so a caller
/// swaps one for the other and nothing else changes.
pub(crate) fn pixels(art: &Rgba, mut each: impl FnMut(usize, usize, [u8; 4])) {
    // SAFETY: foreground only, single core, and never from an interrupt: marks are
    // decoded inside a draw, and `display` refuses a nested one.
    let cache = unsafe { &mut *core::ptr::addr_of_mut!(CACHE) };
    let (w, h) = (art.width as usize, art.height as usize);
    let key = Key {
        at: art.deflated.as_ptr() as usize,
        len: art.deflated.len(),
    };

    if cache.block.is_none() && !cache.refused {
        match crate::heap::take(SLOT * SLOTS) {
            Some(block) => {
                cache.block = Some(block);
                crate::catlog!("art: {} bytes of icon cache", SLOT * SLOTS);
            }
            None => cache.refused = true,
        }
    }
    let Some(block) = cache.block.as_mut() else {
        // No cache: decode straight through, which is what this replaced.
        let _ = catcard_ui::art::rgba::decode(art, each);
        return;
    };
    // An icon larger than a slot is not cached, and is not refused either.
    if w > SIDE || h > SIDE {
        let _ = catcard_ui::art::rgba::decode(art, each);
        return;
    }

    let found = cache.keys.iter().position(|k| *k == Some(key));
    let slot = match found {
        Some(slot) => slot,
        None => {
            let slot = cache.next;
            cache.next = (cache.next + 1) % SLOTS;
            let base = slot * SLOT;
            let store = block.bytes();
            // Decoded once, into the slot. The key is written only after the decode
            // succeeds, so a truncated or corrupt blob leaves an empty slot rather than
            // a slot claiming to hold an icon it does not.
            let mut wrote = 0usize;
            let ok = catcard_ui::art::rgba::decode(art, |x, y, p| {
                let at = base + (y * w + x) * 4;
                if let Some(px) = store.get_mut(at..at + 4) {
                    px.copy_from_slice(&p);
                    wrote += 1;
                }
            })
            .is_ok();
            if !ok || wrote != w * h {
                cache.keys[slot] = None;
                // Whatever did arrive is handed on, so a half-decoded icon still draws
                // as much of itself as it did before there was a cache.
                let _ = catcard_ui::art::rgba::decode(art, each);
                return;
            }
            cache.keys[slot] = Some(key);
            cache.sizes[slot] = (w, h);
            slot
        }
    };

    let base = slot * SLOT;
    let (w, h) = cache.sizes[slot];
    let store = block.bytes();
    for y in 0..h {
        for x in 0..w {
            let at = base + (y * w + x) * 4;
            let Some(px) = store.get(at..at + 4) else {
                return;
            };
            each(x, y, [px[0], px[1], px[2], px[3]]);
        }
    }
}
