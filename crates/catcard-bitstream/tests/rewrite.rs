//! Rewriting checked two ways: synthetic bitstreams built here by a separate encoder,
//! and -- when `CATCARD_PRECURSOR_GATEWARE` names a file holding a Precursor gateware
//! image (flash offset 0, e.g. the first 0x28_0000 bytes of a flash dump, or a release
//! `soc_csr.bin`) -- the real thing.

use catcard_bitstream::{Error, KeyRom, KeySource, Layout, Target, read_keyrom, rewrite};
use purecrypto::cipher::{Aes256, BlockCipher};
use purecrypto::hash::{Digest, Sha256};

const MAP: &[u8; 16384] = include_bytes!("../src/keyrom-map.bin");
const FRAMES: [usize; 8] = [0x35e, 0x35f, 0x360, 0x361, 0x364, 0x365, 0x366, 0x367];

fn flip(b: &mut [u8]) {
    for w in b.as_chunks_mut::<4>().0 {
        w.reverse();
        for x in w.iter_mut() {
            *x = x.reverse_bits();
        }
    }
}

fn hmac(key: &[u8; 32], msg: &[u8]) -> [u8; 32] {
    let mut ipad = [0x36u8; 64];
    let mut opad = [0x5cu8; 64];
    for i in 0..32 {
        ipad[i] ^= key[i];
        opad[i] ^= key[i];
    }
    let mut h = Sha256::new();
    h.update(&ipad);
    h.update(msg);
    let inner = h.finalize();
    let mut h = Sha256::new();
    h.update(&opad);
    h.update(&inner);
    h.finalize()
}

fn rom(seed: u32) -> KeyRom {
    let mut r = KeyRom::zeroed();
    let mut x = seed;
    for w in r.0.iter_mut() {
        x ^= x << 13;
        x ^= x >> 17;
        x ^= x << 5;
        *w = x;
    }
    r
}

/// A small but structurally faithful bitstream: the layout described in lib.rs, with
/// the key ROM planted through the bit map and everything else filler.
fn build(key: &[u8; 32], hkey: &[u8; 32], iv: &[u8; 16], keyrom: &KeyRom, efuse: bool) -> Vec<u8> {
    let ctl0 = if efuse { 0x8000_0541u32 } else { 0x0000_0541 };
    let mut n: Vec<u32> = Vec::new(); // decrypted stream, as words
    // HMAC key block: K ^ ipad, then ipad.
    let mut kb = [0x36u8; 64];
    for i in 0..32 {
        kb[i] ^= hkey[i];
    }
    for c in kb.chunks(4) {
        n.push(u32::from_be_bytes(c.try_into().unwrap()));
    }
    n.extend([
        0x2000_0000,
        0x3000_C001,
        0xFFFF_FFFF,
        0x3000_A001,
        ctl0,
        0x2000_0000,
        0x3000_4000,
    ]);
    let count = (FRAMES[7] + 3) * 101;
    n.push(0x4000_0000 | count as u32);
    let fstart = n.len();
    for i in 0..count {
        n.push((i as u32).wrapping_mul(0x9E37_79B9));
    }
    for (fi, &frame) in FRAMES.iter().enumerate() {
        for w in 0..32 {
            let mut v = 0u32;
            for bit in 0..32 {
                let e = ((fi * 32 + w) * 32 + bit) * 2;
                let (adr, rb) = (MAP[e] as usize, MAP[e + 1] as u32);
                v |= (keyrom.0[adr] >> rb & 1) << bit;
            }
            n[fstart + frame * 101 + w] = v;
        }
    }
    n.extend([
        0x3000_8001,
        0x0000_0005,
        0x3000_A001,
        ctl0,
        0x3000_8001,
        0x0000_0007,
    ]);
    while !n.len().is_multiple_of(4) {
        n.push(0x2000_0000);
    }
    let msg_end = n.len() * 4;
    let mut pt: Vec<u8> = n.iter().flat_map(|w| w.to_be_bytes()).collect();
    // Tail: 320 bytes of inner padding, K ^ opad, the digest slot, outer padding, tag.
    pt.push(0x80);
    pt.resize(msg_end + 56, 0);
    pt.extend((msg_end as u64 * 8).to_be_bytes());
    pt.resize(msg_end + 320, 0);
    pt.extend(hkey.iter().map(|k| k ^ 0x5c));
    pt.extend([0x5c; 32]);
    pt.extend([0; 32]);
    pt.push(0x80);
    pt.resize(msg_end + 320 + 128 - 8, 0);
    pt.extend(768u64.to_be_bytes());
    let tag = hmac(hkey, &pt[64..msg_end]);
    pt.extend(tag);
    assert_eq!(pt.len(), msg_end + 480);

    // Encrypt: flash order -> AES order, CBC, back to flash order.
    let aes = Aes256::new(key);
    let mut chain = *iv;
    let mut ct = pt.clone();
    for b in ct.as_chunks_mut::<16>().0 {
        flip(b);
        for i in 0..16 {
            b[i] ^= chain[i];
        }
        aes.encrypt_block(b);
        chain = *b;
        flip(b);
    }

    let mut head: Vec<u32> = vec![0xFFFF_FFFF, 0xFFFF_FFFF, 0xAA99_5566, 0x2000_0000];
    head.extend([
        0x3000_C001,
        ctl0 & 0x8000_0000 | 0x40,
        0x3000_A001,
        ctl0 & 0x8000_0000 | 0x40,
    ]);
    // Pad so the ciphertext starts on a block: IV packet (5 words) + length (2 words).
    while !(head.len() + 7).is_multiple_of(4) {
        head.push(0x2000_0000);
    }
    head.push(0x3001_6004);
    let mut ivf = *iv;
    flip(&mut ivf);
    for c in ivf.chunks(4) {
        head.push(u32::from_be_bytes(c.try_into().unwrap()));
    }
    head.extend([0x3003_4001, (ct.len() / 4) as u32]);
    let mut out: Vec<u8> = head.iter().flat_map(|w| w.to_be_bytes()).collect();
    assert_eq!(out.len() % 16, 0);
    out.extend(ct);
    out
}

const K0: [u8; 32] = [0; 32];

#[test]
fn the_map_covers_every_key_rom_bit_once() {
    let mut seen = [0u32; 256];
    for e in MAP.chunks(2) {
        let (adr, bit) = (e[0] as usize, e[1]);
        assert!(bit < 32);
        assert_eq!(seen[adr] >> bit & 1, 0, "bit mapped twice");
        seen[adr] |= 1 << bit;
    }
    assert!(seen.iter().all(|&w| w == u32::MAX));
}

#[test]
fn reads_the_key_rom_of_a_synthetic_image() {
    let r = rom(1);
    let img = build(&K0, &[7; 32], &[3; 16], &r, true);
    let out = read_keyrom(&img, &K0).unwrap();
    assert_eq!(out.keyrom_in, r);
    assert_eq!(out.source_key_source, KeySource::Efuse);
}

#[test]
fn an_identity_rewrite_is_byte_identical() {
    let img = build(&K0, &[7; 32], &[3; 16], &rom(2), true);
    let mut out = vec![0; img.len()];
    let t = Target {
        key: K0,
        source: KeySource::Efuse,
        iv: None,
        hmac_key: None,
        keyrom: None,
    };
    rewrite(&img, &K0, t, &mut out).unwrap();
    assert!(out == img);
}

#[test]
fn rekeys_retargets_and_patches_in_one_pass() {
    let img = build(&K0, &[7; 32], &[3; 16], &rom(3), true);
    let newkey = [0x5a; 32];
    let newrom = rom(4);
    let t = Target {
        key: newkey,
        source: KeySource::Bbram,
        iv: Some([0xc3; 16]),
        hmac_key: Some([0x11; 32]),
        keyrom: Some(newrom.clone()),
    };
    let mut out = vec![0; img.len()];
    let o = rewrite(&img, &K0, t, &mut out).unwrap();
    assert_eq!(o.keyrom_in, rom(3));

    let l = Layout::parse(&out).unwrap();
    assert_eq!(l.key_source, KeySource::Bbram);
    let back = read_keyrom(&out, &newkey).unwrap();
    assert_eq!(back.keyrom_in, newrom);
    assert_eq!(back.source_key_source, KeySource::Bbram);
    assert_eq!(read_keyrom(&out, &K0).err(), Some(Error::WrongKey));

    // And it is what the reference encoder would have produced from scratch.
    let reference = build(&newkey, &[0x11; 32], &[0xc3; 16], &newrom, false);
    assert!(out == reference);
}

#[test]
fn a_tampered_source_is_refused() {
    let img = build(&K0, &[7; 32], &[3; 16], &rom(5), true);
    let l = Layout::parse(&img).unwrap();
    for at in [
        l.ct_start + 4096,
        l.ct_start + l.ct_len / 2,
        l.image_len() - 200,
        l.image_len() - 1,
    ] {
        let mut bad = img.clone();
        bad[at] ^= 0x04;
        assert_eq!(
            read_keyrom(&bad, &K0).err(),
            Some(Error::SourceHmac),
            "flip at {at}"
        );
    }
}

#[test]
fn a_wrong_source_key_is_refused_at_the_first_block() {
    let img = build(&[9; 32], &[7; 32], &[3; 16], &rom(6), true);
    assert_eq!(read_keyrom(&img, &K0).err(), Some(Error::WrongKey));
}

/// The developer public key every unprovisioned Precursor carries at key ROM 0x18
/// (betrusted-soc devkey/dev-x509.crt, gen_keyrom.py) [C].
const DEV_PUBKEY: [u32; 8] = [
    0x1c9beae3, 0x2aeac875, 0x07c18094, 0x387eff1c, 0x74614282, 0xaffd8152, 0xd871352e, 0xdf3f58bb,
];

#[test]
fn real_gateware() {
    let Ok(path) = std::env::var("CATCARD_PRECURSOR_GATEWARE") else {
        eprintln!("CATCARD_PRECURSOR_GATEWARE not set; skipping the real-image checks");
        return;
    };
    let img = std::fs::read(path).unwrap();
    let l = Layout::parse(&img).unwrap();
    let o = read_keyrom(&img, &K0).unwrap();
    assert_eq!(&o.keyrom_in.0[0x18..0x20], &DEV_PUBKEY);

    let mut same = vec![0; l.image_len()];
    let t = Target {
        key: K0,
        source: l.key_source,
        iv: None,
        hmac_key: None,
        keyrom: None,
    };
    rewrite(&img, &K0, t, &mut same).unwrap();
    assert!(
        same[..] == img[..l.image_len()],
        "identity rewrite must reproduce the image"
    );

    let mut newrom = o.keyrom_in.clone();
    newrom.0[0x10..0x18].copy_from_slice(&[1, 2, 3, 4, 5, 6, 7, 8]);
    let key = [0xa5; 32];
    let t = Target {
        key,
        source: KeySource::Bbram,
        iv: Some([0x42; 16]),
        hmac_key: Some([0x24; 32]),
        keyrom: Some(newrom.clone()),
    };
    let mut out = vec![0; l.image_len()];
    rewrite(&img, &K0, t, &mut out).unwrap();
    assert_eq!(read_keyrom(&out, &key).unwrap().keyrom_in, newrom);
}
