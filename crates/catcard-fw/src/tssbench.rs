//! Bench: a DKLs keygen and one signature, every party on this device, timed
//! (docs/TSS.md, "Open before implementation": time and heap per round on the device).
//!
//! `DebugTssBench` over USB queues a run with `n` parties and threshold `t`; the menu loop
//! runs it on the UI task -- tsslib is far too deep for the USB task's stack -- and the same
//! opcode, sent empty, reads the result. The randomness is the UI DRBG's: these keys are
//! thrown away when the run ends and nothing is stored.

use alloc::format;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicU8, Ordering};

use catcard_entropy::HmacDrbg;
use tsslib::dklstss;
use tsslib::tss::PartyId;

use crate::ui::Ui;

/// tsslib's randomness, from a DRBG: `RngCore` over [`HmacDrbg::generate`].
struct Drbg<'a>(&'a mut HmacDrbg);

impl purecrypto::rng::RngCore for Drbg<'_> {
    fn fill_bytes(&mut self, dest: &mut [u8]) {
        // A DRBG that refuses has to be noticed, not papered over with zeros.
        if self.0.generate(dest).is_err() {
            panic!("tss bench: DRBG refused");
        }
    }
}
impl purecrypto::rng::CryptoRng for Drbg<'_> {}

/// 0 idle, 1 pending, 2 running, 3 done.
static STATE: AtomicU8 = AtomicU8::new(0);
static mut ARGS: (u8, u8) = (0, 0);
/// ok, keygen ms, sign ms, heap used before, heap peak after, share bytes (party 1, in
/// tsslib's binary key encoding), n, t.
static mut RESULT: [u32; 8] = [0; 8];

/// Queue a run; false if one is already queued or running.
pub fn request(n: u8, t: u8) -> bool {
    if matches!(STATE.load(Ordering::Acquire), 1 | 2) || n < 2 || t == 0 || t >= n || n > 8 {
        return false;
    }
    // SAFETY: nothing is queued or running, so the menu loop is not reading it.
    unsafe { *core::ptr::addr_of_mut!(ARGS) = (n, t) };
    STATE.store(1, Ordering::Release);
    true
}

/// The state byte and, once done, the result words.
pub fn status() -> (u8, [u32; 8]) {
    let s = STATE.load(Ordering::Acquire);
    // SAFETY: written before `Done` is published; read only after.
    let r = if s == 3 {
        unsafe { *core::ptr::addr_of!(RESULT) }
    } else {
        [0; 8]
    };
    (s, r)
}

/// From the menu loop.
pub fn serve(ui: &mut Ui<'_>) {
    if STATE.load(Ordering::Acquire) != 1 {
        return;
    }
    STATE.store(2, Ordering::Release);
    // SAFETY: written by `request` before it published `Pending`.
    let (n, t) = unsafe { *core::ptr::addr_of!(ARGS) };
    let r = run(ui, n as usize, t as usize);
    // SAFETY: `Running`: nobody else reads or writes it.
    unsafe { *core::ptr::addr_of_mut!(RESULT) = r };
    STATE.store(3, Ordering::Release);
}

fn run(ui: &mut Ui<'_>, n: usize, t: usize) -> [u32; 8] {
    // SAFETY: reads RCC.
    let per_ms = (unsafe { catcard_hal::clock::hclk_hz() } / 1000).max(1);
    let mut rng = Drbg(ui.drbg);
    let ids: Vec<PartyId> = (1..=n)
        .map(|i| PartyId::new(format!("{i}"), "", alloc::vec![i as u8]))
        .collect();
    let (used0, _, _) = crate::heap::stats();
    crate::catlog!("tssbench: {}-party keygen, signing threshold {} (+1)", n, t);

    let t0 = catcard_hal::dwt::cycles();
    let keys = match dklstss::keygen(n, t, &ids, &mut rng) {
        Ok(k) => k,
        Err(e) => {
            crate::catlog!("tssbench: keygen failed: {}", e);
            return [
                0,
                0,
                0,
                used0 as u32,
                crate::heap::stats().1 as u32,
                0,
                n as u32,
                t as u32,
            ];
        }
    };
    let t1 = catcard_hal::dwt::cycles();
    let signers: Vec<usize> = (0..=t).collect();
    let ok = dklstss::sign(&keys, &signers, &[0x5A; 32], &mut rng).is_ok();
    let t2 = catcard_hal::dwt::cycles();
    let share = keys
        .first()
        .and_then(|k| k.to_bytes().ok())
        .map_or(0, |j| j.len());
    let (_, peak, _) = crate::heap::stats();
    drop(keys);

    let keygen_ms = t1.wrapping_sub(t0) / per_ms;
    let sign_ms = t2.wrapping_sub(t1) / per_ms;
    crate::catlog!(
        "tssbench: keygen {} ms, sign {} ms ({}), share {} B, heap {} -> peak {}",
        keygen_ms,
        sign_ms,
        if ok { "ok" } else { "FAILED" },
        share,
        used0,
        peak
    );
    [
        ok as u32,
        keygen_ms,
        sign_ms,
        used0 as u32,
        peak as u32,
        share as u32,
        n as u32,
        t as u32,
    ]
}
