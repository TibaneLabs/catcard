//! A security key on a pipe: CTAPHID packets in on stdin, out on stdout, answered by the
//! same code the firmware runs.
//!
//! For `tools/fido_check.py --sim`, which drives it through python-fido2's own HID
//! transport, CTAP2 client and attestation verifiers -- an independent implementation
//! checking framing, canonical CBOR and every signature, at a desk.
//!
//! The person always says yes (set `FIDO_SIM_ANSWER=deny` for no); the wallet is a fixed
//! test node; U2F's "press the key" is given on the second ask, as a person would after
//! seeing the first refusal. Nothing here is on the device.
//!
//! ```text
//! cargo run -p catcard-fido --example fido_sim
//! ```

use std::io::{Read, Write};

use catcard_fido::ctap2::{self, Ask, Env, Presence};
use catcard_fido::hid::{self, Ctaphid, Event};
use catcard_fido::keys::Master;
use catcard_fido::u2f;
use catcard_wallet::KeyWork;

struct Sim {
    generation: u32,
    answer: Presence,
    counter: u64,
    u2f_asked: Vec<(bool, [u8; 32])>,
}

impl Env for Sim {
    fn presence(&mut self, ask: Ask<'_>) -> Presence {
        eprintln!("fido_sim: asked {ask:?} -> {:?}", self.answer);
        self.answer
    }
    fn with_master<R>(&mut self, f: impl FnOnce(&Master, &KeyWork) -> R) -> Option<R> {
        let kw = KeyWork::host();
        let m = Master::from_parts(&[0x5A; 32], &[0xA5; 32], self.generation, &kw);
        Some(f(&m, &kw))
    }
    fn random(&mut self, out: &mut [u8]) -> bool {
        for b in out.iter_mut() {
            self.counter = self
                .counter
                .wrapping_mul(6364136223846793005)
                .wrapping_add(1442695040888963407);
            *b = (self.counter >> 56) as u8;
        }
        true
    }
    fn reset(&mut self) -> u8 {
        eprintln!(
            "fido_sim: reset, generation {} -> {}",
            self.generation,
            self.generation + 1
        );
        self.generation += 1;
        ctap2::status::OK
    }
    fn u2f_presence(&mut self, register: bool, app: &[u8; 32]) -> bool {
        let key = (register, *app);
        if let Some(i) = self.u2f_asked.iter().position(|k| *k == key) {
            self.u2f_asked.remove(i);
            return self.answer == Presence::Allowed;
        }
        self.u2f_asked.push(key);
        false
    }
}

fn main() {
    let answer = match std::env::var("FIDO_SIM_ANSWER").as_deref() {
        Ok("deny") => Presence::Denied,
        _ => Presence::Allowed,
    };
    let mut sim = Sim {
        generation: 0,
        answer,
        counter: 0x1234_5678,
        u2f_asked: Vec::new(),
    };
    let mut h = Ctaphid::new([7, 0, 0]);
    let mut buf = vec![0u8; hid::MAX_MSG];
    let mut out = vec![0u8; hid::MAX_MSG];
    let mut stdin = std::io::stdin().lock();
    let mut stdout = std::io::stdout().lock();
    let mut pkt = [0u8; hid::PACKET];
    let mut now = 0u32;
    while stdin.read_exact(&mut pkt).is_ok() {
        now = now.wrapping_add(1);
        if let Event::Request { cmd, len, .. } = h.feed(&pkt, &mut buf, now) {
            let n = if cmd == hid::cmd::CBOR {
                ctap2::handle(&buf[..len], &mut out, &mut sim)
            } else {
                u2f::handle(&buf[..len], &mut out, &mut sim)
            };
            buf[..n].copy_from_slice(&out[..n]);
            h.respond(n);
        }
        let mut o = [0u8; hid::PACKET];
        while h.next_packet(&buf, &mut o) {
            if stdout.write_all(&o).is_err() {
                return;
            }
        }
        let _ = stdout.flush();
    }
}
