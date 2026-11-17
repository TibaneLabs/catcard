use catcard_sealed::{
    Contents, Cost, Error, HEADER_LEN, Header, MAX_M_KIB, RECORD_LEN, open, seal,
};
use purecrypto::cipher::ChaCha20Poly1305;
use purecrypto::kdf::argon2::{Argon2Params, Argon2Type, argon2};

const CHEAP: Cost = Cost {
    t: 1,
    m_kib: 256,
    p: 1,
};
const DS: [u8; 32] = [0xd5; 32];
const SALT: [u8; 16] = [0x5a; 16];
const NONCE: [u8; 12] = [0x0e; 12];

fn sample() -> Contents {
    Contents::bip39(&[0x42; 16]).unwrap()
}

/// The KDF underneath, against RFC 9106 section 5.3 (Argon2id with a secret and
/// associated data), so the construction below rests on a checked primitive.
#[test]
fn argon2id_matches_rfc9106() {
    let p = Argon2Params {
        t_cost: 3,
        m_cost_kib: 32,
        parallelism: 4,
        variant: Argon2Type::Argon2id,
        version: 0x13,
    };
    let mut out = [0u8; 32];
    argon2(&p, &[1; 32], &[2; 16], &[3; 8], &[4; 12], &mut out).unwrap();
    let want = "0d640df58d78766c08c037a34a8b53c9d01ef0452d75b65eb52520e96b01e659";
    let got: String = out.iter().map(|b| format!("{b:02x}")).collect();
    assert_eq!(got, want);
}

/// The record is exactly the documented construction, rebuilt here by hand.
#[test]
fn the_record_is_the_documented_construction() {
    let rec = seal(&sample(), b"hunter2", &DS, CHEAP, SALT, NONCE).unwrap();

    let mut head = [0u8; HEADER_LEN];
    head[..8].copy_from_slice(&[b'C', b'C', b'S', b'L', 1, 2, 0, 0]);
    head[8..12].copy_from_slice(&1u32.to_le_bytes());
    head[12..16].copy_from_slice(&256u32.to_le_bytes());
    head[16..20].copy_from_slice(&1u32.to_le_bytes());
    head[20..36].copy_from_slice(&SALT);
    head[36..48].copy_from_slice(&NONCE);
    assert_eq!(rec[..HEADER_LEN], head);

    let p = Argon2Params {
        t_cost: 1,
        m_cost_kib: 256,
        parallelism: 1,
        variant: Argon2Type::Argon2id,
        version: 0x13,
    };
    let mut key = [0u8; 32];
    argon2(
        &p,
        b"hunter2",
        &SALT,
        &DS,
        b"CatCard Precursor sealed seed v1",
        &mut key,
    )
    .unwrap();
    let mut body = [0u8; 96];
    body[0] = 1;
    body[2] = 16;
    body[4..20].copy_from_slice(&[0x42; 16]);
    let tag = ChaCha20Poly1305::new(&key).encrypt(&NONCE, &head, &mut body);
    assert_eq!(rec[48..144], body);
    assert_eq!(rec[144..], tag);
}

#[test]
fn round_trips() {
    for len in [16, 20, 24, 28, 32] {
        let c = Contents::bip39(&vec![len as u8; len]).unwrap();
        let rec = seal(&c, b"pass", &DS, CHEAP, SALT, NONCE).unwrap();
        let back = open(&rec, b"pass", &DS).unwrap();
        assert!(back == c);
        assert_eq!(back.entropy(), &vec![len as u8; len][..]);
        assert_eq!(back.signing_key(), None);
    }
    let c = sample().with_signing_key([0x77; 32]);
    let rec = seal(&c, b"", &DS, CHEAP, SALT, NONCE).unwrap();
    assert_eq!(
        open(&rec, b"", &DS).unwrap().signing_key(),
        Some(&[0x77; 32])
    );
}

#[test]
fn needs_both_the_passphrase_and_the_device_secret() {
    let rec = seal(&sample(), b"right", &DS, CHEAP, SALT, NONCE).unwrap();
    assert_eq!(
        open(&rec, b"wrong", &DS).err(),
        Some(Error::WrongPassphrase)
    );
    assert_eq!(open(&rec, b"righ", &DS).err(), Some(Error::WrongPassphrase));
    let mut other = DS;
    other[31] ^= 1;
    assert_eq!(
        open(&rec, b"right", &other).err(),
        Some(Error::WrongPassphrase)
    );
    assert_eq!(
        open(&rec, b"right", &[0; 32]).err(),
        Some(Error::WrongPassphrase)
    );
}

#[test]
fn every_byte_is_authenticated() {
    let rec = seal(&sample(), b"p", &DS, CHEAP, SALT, NONCE).unwrap();
    for at in 0..RECORD_LEN {
        let mut bad = rec;
        bad[at] ^= 0x01;
        // Header bytes may fail parsing first; the cost words may also still parse
        // (t=1 -> 0 fails, m=256 -> 257 parses). Either way: never Ok.
        assert!(open(&bad, b"p", &DS).is_err(), "flip at {at} accepted");
    }
}

#[test]
fn erased_flash_and_strangers_are_not_records() {
    assert_eq!(
        Header::parse(&[0xff; RECORD_LEN]).err(),
        Some(Error::NotARecord)
    );
    assert_eq!(
        Header::parse(&[0; RECORD_LEN]).err(),
        Some(Error::NotARecord)
    );
    let rec = seal(&sample(), b"p", &DS, CHEAP, SALT, NONCE).unwrap();
    assert_eq!(
        Header::parse(&rec[..RECORD_LEN - 1]).err(),
        Some(Error::NotARecord)
    );
    let mut v2 = rec;
    v2[4] = 2;
    assert_eq!(open(&v2, b"p", &DS).err(), Some(Error::NotARecord));
}

/// A record in flash is attacker-writable; a huge cost must be refused before Argon2
/// allocates anything.
#[test]
fn hostile_costs_are_refused_unread() {
    let rec = seal(&sample(), b"p", &DS, CHEAP, SALT, NONCE).unwrap();
    for (at, v) in [
        (8, 0u32),
        (8, 1000),
        (12, u32::MAX),
        (12, MAX_M_KIB + 1),
        (16, 4),
        (16, 0),
    ] {
        let mut bad = rec;
        bad[at..at + 4].copy_from_slice(&v.to_le_bytes());
        assert_eq!(
            open(&bad, b"p", &DS).err(),
            Some(Error::BadCost),
            "word {at} = {v}"
        );
    }
}

#[test]
fn weak_costs_and_odd_contents_are_not_written() {
    let weak = Cost { m_kib: 64, ..CHEAP };
    assert_eq!(
        seal(&sample(), b"p", &DS, weak, SALT, NONCE).err(),
        Some(Error::BadCost)
    );
    for len in [0, 15, 17, 33] {
        assert_eq!(
            Contents::bip39(&vec![1; len]).err(),
            Some(Error::BadContents)
        );
    }
}

#[test]
fn contents_never_print() {
    let c = sample().with_signing_key([9; 32]);
    assert_eq!(format!("{c:?}"), "Contents(..)");
}
