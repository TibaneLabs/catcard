//! Shared by the integration tests: a deterministic randomness source, a simulated SD
//! card, and drivers that run every member of a session over it.
#![allow(dead_code)]

use catcard_tss::{
    EcdsaSignature, Entropy, NoEntropy, Session, ShareRecord, SignMode, SignRequest, Status,
    file_name,
};
use catcard_wallet::KeyWork;
use purecrypto::hash::Sha256;
use purecrypto::rng::{HmacDrbg, RngCore};

/// Deterministic: HMAC-DRBG seeded with a label. Every member gets its own label, so
/// two members never draw the same bytes.
pub struct TestRng(HmacDrbg<Sha256>);

impl TestRng {
    pub fn new(label: &str) -> Self {
        TestRng(HmacDrbg::new(
            label.as_bytes(),
            b"catcard-tss test nonce",
            b"tests",
        ))
    }
}

impl Entropy for TestRng {
    fn fill(&mut self, out: &mut [u8]) -> Result<(), NoEntropy> {
        self.0.fill_bytes(out);
        Ok(())
    }
}

/// A source that has run dry.
pub struct Empty;

impl Entropy for Empty {
    fn fill(&mut self, _: &mut [u8]) -> Result<(), NoEntropy> {
        Err(NoEntropy)
    }
}

pub const KW: KeyWork = KeyWork::host();

/// An SD card: files by name, nothing else.
#[derive(Default)]
pub struct Card {
    pub files: Vec<(String, Vec<u8>)>,
}

impl Card {
    /// Write what `s` has to say. True if it said anything.
    pub fn put(&mut self, s: &mut Session) -> bool {
        let out = s.take_outbox();
        let any = !out.is_empty();
        for o in out {
            let name = o.file_name();
            assert!(self.get(&name).is_none(), "{name} written twice");
            self.files.push((name, o.bytes));
        }
        any
    }

    pub fn get(&self, name: &str) -> Option<&[u8]> {
        self.files
            .iter()
            .find(|(n, _)| n == name)
            .map(|(_, b)| b.as_slice())
    }
}

/// Run `sessions` -- the members present -- over `card` until none can move. Codes are
/// compared, as the user would, before anyone confirms. Bounded: a stalled session
/// stops the loop rather than spinning.
pub fn run(sessions: &mut [Session], card: &mut Card) {
    for _ in 0..64 {
        let mut moved = false;
        for s in sessions.iter_mut() {
            moved |= card.put(s);
        }
        if sessions.iter().all(|s| s.status() == Status::Comparing) {
            let words = sessions[0].code().unwrap().words();
            for s in sessions.iter() {
                assert_eq!(s.code().unwrap().words(), words, "session codes differ");
            }
            for s in sessions.iter_mut() {
                s.confirm(&KW).unwrap();
            }
            moved = true;
        }
        for s in sessions.iter_mut() {
            for (r, f, t) in s.awaiting() {
                if let Some(bytes) = card.get(&file_name(r, f, t)) {
                    let bytes = bytes.to_vec();
                    s.receive(&bytes, &KW).unwrap();
                    moved = true;
                }
            }
        }
        if !moved {
            return;
        }
    }
    panic!("sessions did not settle");
}

/// Every member of an `n`, `t` DKG; their share records, in member order.
pub fn create(n: u8, t: u8, label: &str) -> Vec<ShareRecord> {
    let id = [n, t, 0xc0, 0xde, 0, 0, 0, 1];
    let mut sessions: Vec<Session> = (1..=n)
        .map(|m| {
            Session::keygen(id, n, t, m, &mut TestRng::new(&format!("{label}/{m}")), &KW).unwrap()
        })
        .collect();
    let mut card = Card::default();
    run(&mut sessions, &mut card);
    sessions
        .iter()
        .map(|s| {
            assert_eq!(s.status(), Status::Finished, "{:?}", s.failure());
            s.share().unwrap().clone()
        })
        .collect()
}

/// Signing sessions for `signers` (member numbers) over `records` (indexed by member - 1).
pub fn signing_sessions(
    records: &[ShareRecord],
    signers: &[u8],
    requests: &[SignRequest],
    mode: SignMode,
    label: &str,
) -> Vec<Session> {
    let id = [0x51, 0x67, signers.len() as u8, 0, 0, 0, 0, 2];
    signers
        .iter()
        .map(|&m| {
            Session::sign(
                id,
                &records[usize::from(m) - 1],
                signers,
                requests,
                mode,
                &mut TestRng::new(&format!("{label}/sign/{m}")),
                &KW,
            )
            .unwrap()
        })
        .collect()
}

/// Sign with `signers`; every signer's signatures, which must agree.
pub fn sign(
    records: &[ShareRecord],
    signers: &[u8],
    requests: &[SignRequest],
    mode: SignMode,
) -> Vec<EcdsaSignature> {
    let mut sessions = signing_sessions(records, signers, requests, mode, "sign");
    let mut card = Card::default();
    run(&mut sessions, &mut card);
    let first = sessions[0].signatures().expect("finished");
    for s in &sessions {
        assert_eq!(s.status(), Status::Finished, "{:?}", s.failure());
        assert_eq!(s.signatures().unwrap(), first);
    }
    first
}

pub fn sighash(label: &str) -> [u8; 32] {
    use purecrypto::hash::Digest;
    let mut h = Sha256::new();
    h.update(label.as_bytes());
    h.finalize()
}

/// `sig` is a low-S ECDSA signature of `hash` under `public`, by purecrypto.
pub fn verifies(public: &[u8; 33], hash: &[u8; 32], sig: &EcdsaSignature) -> bool {
    use purecrypto::ec::secp256k1::ecdsa::{Secp256k1EcdsaPublicKey, Secp256k1EcdsaSignature};
    let key = Secp256k1EcdsaPublicKey::from_sec1(public).unwrap();
    let s = Secp256k1EcdsaSignature::from_bytes(&sig.compact);
    let der = Secp256k1EcdsaSignature::from_der(&sig.der);
    s.is_low_s() && key.verify_prehash(hash, &s).is_ok() && der.map(|d| d == s).unwrap_or(false)
}
