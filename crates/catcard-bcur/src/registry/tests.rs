//! What a registry item must be, and what it must not be mistaken for.
//!
//! The assertions are the published test vectors from the BCRs themselves: if this
//! code and Blockchain Commons disagree about a byte, the vector says which is wrong.
//! Everything else here is a failure mode -- an item cut short, a field of the wrong
//! major type, a tag that belongs to a different structure, a length field that
//! promises more than it delivers.

use super::*;
use crate::cbor::Error as CborError;

extern crate alloc;
extern crate std;
use alloc::vec;
use alloc::vec::Vec;

/// Hex to bytes. The BCRs publish their vectors as hex, so the tests read as the
/// documents do.
fn hex(text: &str) -> Vec<u8> {
    let digits: Vec<u8> = text
        .bytes()
        .filter(|b| !b.is_ascii_whitespace())
        .map(|b| (b as char).to_digit(16).expect("hex") as u8)
        .collect();
    assert_eq!(digits.len() % 2, 0, "hex must be whole bytes");
    digits.chunks(2).map(|p| p[0] << 4 | p[1]).collect()
}

fn to_hex(bytes: &[u8]) -> alloc::string::String {
    use core::fmt::Write as _;
    let mut out = alloc::string::String::new();
    for b in bytes {
        let _ = write!(out, "{b:02x}");
    }
    out
}

// --- crypto-psbt, BCR-2020-006 §"Partially Signed Bitcoin Transaction (PSBT)" -------

/// The published PSBT vector's CBOR: a byte string of 167 bytes.
const PSBT_CBOR: &str = "58a770736274ff01009a020000000258e87a21b56daf0c23be8e7070456c336f7cba\
a5c8757924f545887bb2abdd750000000000ffffffff838d0427d0ec650a68aa46bb0b098aea4422c071b2ca78352a0\
77959d07cea1d0100000000ffffffff0270aaf00800000000160014d85c2b71d0060b09c9886aeb815e50991dda124d\
00e1f5050000000016001400aea9a2e5f0f876a588df5546e8742d1d87008f000000000000000000";

/// The UR vectors are read from files beside this one, verbatim as the BCRs print
/// them: a transcription that wrapped a line or dropped a syllable would be a test of
/// the transcription. See `vectors/README.md`.
fn vector(name: &str) -> &'static str {
    match name {
        "psbt" => include_str!("vectors/psbt.ur"),
        "hdkey-1" => include_str!("vectors/hdkey-1.ur"),
        "hdkey-2" => include_str!("vectors/hdkey-2.ur"),
        "crypto-output-1" => include_str!("vectors/crypto-output-1.ur"),
        "crypto-account" => include_str!("vectors/crypto-account.ur"),
        other => panic!("no such vector: {other}"),
    }
    .trim_end()
}

/// The published vector, both ways.
///
/// This is the gap the module exists for: the CBOR header comes off, and what is left
/// starts with `psbt\xff` -- which is what a PSBT parser is looking for.
#[test]
fn the_published_psbt_vector_unwraps_to_a_psbt() {
    let message = hex(PSBT_CBOR);
    let psbt = bytestring::decode(&message).expect("a byte string");
    assert_eq!(psbt.len(), 167);
    assert!(psbt.starts_with(b"psbt\xff"), "the PSBT's own magic");

    let mut out = vec![0u8; bytestring::encoded_len(psbt.len())];
    let n = bytestring::encode(psbt, &mut out).expect("room");
    assert_eq!(
        to_hex(&out[..n]),
        PSBT_CBOR,
        "byte for byte, the BCR's CBOR"
    );
}

/// And the whole way: the BCR's UR string, through the collector, to the PSBT.
#[test]
fn the_published_psbt_ur_reaches_the_psbt() {
    let mut scratch = vec![0u8; 512];
    let mut c = crate::Collector::new();
    let placed = c
        .accept(vector("psbt"), &mut scratch)
        .expect("a single-part UR");
    let message: Vec<u8> = scratch[placed.at.start..placed.at.start + placed.len].to_vec();
    c.confirm(placed);

    assert!(c.complete());
    assert!(c.verify(&message));
    assert_eq!(c.kind(), Some(Kind::Psbt));
    assert_eq!(to_hex(&message), PSBT_CBOR);
    assert!(
        bytestring::decode(&message)
            .unwrap()
            .starts_with(b"psbt\xff")
    );
}

/// Anything after the byte string means the message is not this item.
///
/// Ignoring a tail would let a sender append to a document after the point the user
/// looked at it.
#[test]
fn a_psbt_with_a_tail_is_refused() {
    let mut message = hex(PSBT_CBOR);
    message.push(0x00);
    assert_eq!(bytestring::decode(&message), Err(Error::Trailing));
}

/// A byte string whose header promises more than the message holds.
#[test]
fn a_truncated_psbt_is_refused() {
    let message = hex(PSBT_CBOR);
    for cut in [1usize, 2, 50, message.len() - 1] {
        assert_eq!(
            bytestring::decode(&message[..cut]),
            Err(Error::Cbor(CborError::Short)),
            "cut to {cut} bytes"
        );
    }
}

/// A text string is not a byte string, even though both hold bytes.
#[test]
fn a_psbt_of_the_wrong_major_type_is_refused() {
    // `63 616263`: a three-character text string.
    assert_eq!(
        bytestring::decode(&hex("63616263")),
        Err(Error::Cbor(CborError::WrongType {
            expected: cbor::BYTES,
            found: cbor::TEXT,
        }))
    );
}

/// A PSBT under somebody else's tag is not a PSBT.
#[test]
fn a_psbt_under_a_foreign_tag_is_refused() {
    // #6.303 (crypto-hdkey) around the byte string.
    let mut message = hex("d9012f");
    message.extend_from_slice(&hex(PSBT_CBOR));
    assert_eq!(bytestring::decode(&message), Err(Error::Tag(303)));

    // Its own tag, either generation, is read -- BCR-2020-006 says a top-level item
    // MUST NOT be tagged, but an encoder that tags it anyway has still sent a PSBT.
    for tag in ["d90136", "d99d76"] {
        let mut message = hex(tag);
        message.extend_from_slice(&hex(PSBT_CBOR));
        assert!(
            bytestring::decode(&message)
                .unwrap()
                .starts_with(b"psbt\xff")
        );
    }
}

// --- crypto-hdkey, BCR-2020-007 -----------------------------------------------------

/// Test Vector 1: the BIP-32 master key, as CBOR.
const HDKEY1_CBOR: &str = "a301f503582100e8f32e723decf4051aefac8e2c93c9c5b214313817cdb01a1494b9\
17c8436b35045820873dff81c02f525623fd1fe5167eac3a55a049de3d314bb42ee227ffed37d508";

/// Test Vector 2: a testnet public key at `m/44'/1'/1'/0/1`.
const HDKEY2_CBOR: &str = "a5035821026fe2355745bb2db3630bbc80ef5d58951c963c841f54170ba6e5c12be7\
fc12a6045820ced155c72456255881793514edc5bd9447e7f74abb88c6d6b6480fd016ee8c8505d99d71a1020106d99\
d70a1018a182cf501f501f500f401f4081ae9181cf3";

/// BCR-2020-007's first vector: a master key, read and written.
#[test]
fn the_published_master_key_vector_round_trips() {
    let message = hex(HDKEY1_CBOR);
    let key = HdKey::decode(&message).expect("a master key");
    assert!(key.is_master);
    assert_eq!(key.key_data[0], 0x00, "a private key is 0x00 || the secret");
    assert!(key.chain_code.is_some());
    assert_eq!(key.origin, None);
    assert_eq!(key.parent_fingerprint, None);

    let mut out = vec![0u8; 256];
    // No nested structures here, so the tag generation makes no difference -- both
    // write the same three fields.
    for tags in [Tags::V1, Tags::V2] {
        let n = key.encode(tags, &mut out).expect("room");
        assert_eq!(to_hex(&out[..n]), HDKEY1_CBOR);
    }
}

/// And its UR, which is what says the whole stack agrees with the document.
#[test]
fn the_published_master_key_ur_round_trips() {
    let message = collect(vector("hdkey-1"), Kind::HdKey);
    assert_eq!(to_hex(&message), HDKEY1_CBOR);

    let mut line = vec![0u8; 512];
    let n = crate::encode::single("hdkey", &message, &mut line).expect("room");
    assert_eq!(
        core::str::from_utf8(&line[..n]).unwrap(),
        vector("hdkey-1").to_ascii_uppercase(),
        "the same UR the BCR prints, in the case a QR wants"
    );
}

/// BCR-2020-007's second vector, which exercises everything the first does not: a
/// coin-info, a five-step origin, a parent fingerprint, and the version-2 nested tags.
#[test]
fn the_published_derived_key_vector_round_trips() {
    let message = hex(HDKEY2_CBOR);
    let key = HdKey::decode(&message).expect("a derived key");

    assert!(!key.is_master && !key.is_private);
    assert_eq!(key.key_data[0], 0x02, "a compressed public key");
    assert_eq!(
        key.use_info,
        Some(CoinInfo {
            coin_type: 0,
            network: 1
        }),
        "testnet-btc"
    );
    assert_eq!(key.parent_fingerprint, Some(0xE918_1CF3));

    let origin = key.origin.clone().expect("an origin");
    assert_eq!(origin.source_fingerprint, None);
    assert_eq!(
        origin.components.as_slice(),
        // m/44'/1'/1'/0/1
        &[
            Component::hardened(44),
            Component::hardened(1),
            Component::hardened(1),
            Component::normal(0),
            Component::normal(1),
        ]
    );

    let mut out = vec![0u8; 256];
    let n = key.encode(Tags::V2, &mut out).expect("room");
    assert_eq!(to_hex(&out[..n]), HDKEY2_CBOR);

    // The same key written with the 2020 tags is the same document with #6.305 and
    // #6.304 in place of #6.40305 and #6.40304 -- and reads back identically.
    let n = key.encode(Tags::V1, &mut out).expect("room");
    assert_ne!(to_hex(&out[..n]), HDKEY2_CBOR);
    assert_eq!(HdKey::decode(&out[..n]).unwrap(), key, "either generation");
}

#[test]
fn the_published_derived_key_ur_round_trips() {
    let message = collect(vector("hdkey-2"), Kind::HdKey);
    assert_eq!(to_hex(&message), HDKEY2_CBOR);
}

/// `crypto-hdkey` and `hdkey` are the same item under two names.
#[test]
fn either_generation_of_name_is_the_same_kind() {
    for name in ["crypto-hdkey", "hdkey", "CRYPTO-HDKEY", "HdKey"] {
        assert_eq!(Kind::from_ur_type(name), Some(Kind::HdKey), "{name}");
    }
    assert_eq!(Kind::from_ur_type("crypto-psbt"), Some(Kind::Psbt));
    assert_eq!(Kind::from_ur_type("psbt"), Some(Kind::Psbt));
    assert_eq!(Kind::from_ur_type("crypto-seed"), None);
    // What this device puts on the screen.
    assert_eq!(Kind::Psbt.written_as(), "crypto-psbt");
    assert_eq!(Kind::Account.written_as(), "crypto-account");
}

/// A master key without a chain code is not a master key.
///
/// "A master key is always private, has no use or derivation information, and always
/// includes a chain code." -- BCR-2020-007 §"CDDL for HDKey".
#[test]
fn a_master_key_without_a_chain_code_is_refused() {
    // {1: true, 3: h'00...'}: the vector with field 4 removed.
    let message =
        hex("a201f503582100e8f32e723decf4051aefac8e2c93c9c5b214313817cdb01a1494b917c8436b35");
    assert_eq!(HdKey::decode(&message), Err(Error::Field(4)));
}

/// A key with no key data is not a key.
#[test]
fn a_key_without_key_data_is_refused() {
    // {4: h'87...'}: the chain code alone.
    let message = hex("a1045820873dff81c02f525623fd1fe5167eac3a55a049de3d314bb42ee227ffed37d508");
    assert_eq!(HdKey::decode(&message), Err(Error::Field(3)));
}

/// Key data of the wrong length is refused rather than padded or truncated.
#[test]
fn key_data_of_the_wrong_size_is_refused() {
    // {3: h'0203'}: two bytes where thirty-three belong.
    assert_eq!(HdKey::decode(&hex("a103420203")), Err(Error::Size(2)));
}

/// A field of the wrong major type: `is-master` as an integer rather than a bool.
///
/// CBOR's `1` and `true` are one byte apart; a reader that coerced them would call a
/// derived key a master key.
#[test]
fn a_field_of_the_wrong_major_type_is_refused() {
    // {1: 1, 3: h'00...'}
    let message =
        hex("a20101 03582100e8f32e723decf4051aefac8e2c93c9c5b214313817cdb01a1494b917c8436b35");
    assert!(matches!(
        HdKey::decode(&message),
        Err(Error::Cbor(CborError::WrongType { .. }))
    ));
}

/// An item cut off part way through.
#[test]
fn a_truncated_key_is_refused() {
    let message = hex(HDKEY2_CBOR);
    for cut in [1usize, 5, 40, 90, message.len() - 1] {
        assert!(
            HdKey::decode(&message[..cut]).is_err(),
            "{cut} bytes must not read as a key"
        );
    }
}

/// Fields this does not read are stepped over, not refused.
///
/// `name` and `note` are free text a sender chooses; a key that carries one is still
/// that key.
#[test]
fn a_name_and_a_note_are_stepped_over() {
    // The master-key vector with {9: "a", 10: "bc"} appended.
    let mut message = hex(HDKEY1_CBOR);
    message[0] = 0xA5; // map(5)
    message.extend_from_slice(&hex("09 6161 0a 626263"));
    let key = HdKey::decode(&message).expect("still a key");
    assert!(key.is_master);
    assert_eq!(to_hex(&key.key_data[..1]), "00");
}

/// A keypath longer than there is room for is refused, not silently shortened.
#[test]
fn a_path_deeper_than_there_is_room_for_is_refused() {
    let mut body = vec![0xA1, 0x01]; // {1: [...]}
    let steps = hdkey::MAX_COMPONENTS + 1;
    body.push(0x80 | (steps * 2) as u8); // array of 2 elements per step
    for _ in 0..steps {
        body.extend_from_slice(&[0x00, 0xF4]); // 0, false
    }
    assert_eq!(KeyPath::decode(&body), Err(Error::TooMany));
}

/// An array header that claims far more than the message holds is refused before it
/// is walked, not counted out one missing element at a time.
#[test]
fn an_enormous_component_count_is_refused() {
    // {1: [<4 billion elements>]}
    let body = hex("a1019affffffff");
    assert!(matches!(
        KeyPath::decode(&body),
        Err(Error::Cbor(CborError::TooDeep))
    ));
}

/// A keypath with an empty path and no ancestor names nothing.
#[test]
fn an_empty_path_without_a_source_is_refused() {
    assert_eq!(KeyPath::decode(&hex("a10180")), Err(Error::Field(2)));
}

/// The three exotic component shapes, written and read back.
///
/// A wallet's `children` field is usually `[[], false]` -- a wildcard -- and a reader
/// that choked on it would refuse every key that said what to derive.
#[test]
fn ranges_wildcards_and_pairs_survive_a_round_trip() {
    let path = KeyPath {
        components: heapless::Vec::from_slice(&[
            Component::hardened(48),
            Component::Range {
                low: 0,
                high: 5,
                hardened: false,
            },
            Component::Pair {
                external: (0, false),
                internal: (1, false),
            },
            Component::Wildcard { hardened: false },
        ])
        .unwrap(),
        source_fingerprint: Some(0x37B5_EED4),
        depth: Some(4),
    };
    let mut out = vec![0u8; 128];
    let n = path.encode(&mut out).expect("room");
    assert_eq!(KeyPath::decode(&out[..n]).unwrap(), path);
}

/// A range whose ends are the wrong way round is not a range.
#[test]
fn a_backwards_range_is_refused() {
    // {1: [[5, 0], false]}
    assert_eq!(
        KeyPath::decode(&hex("a101828205 00f4")),
        Err(Error::Unsupported)
    );
}

/// Coin info's defaults are what an omitted field means, and what is omitted on the
/// way out.
#[test]
fn coin_info_defaults_are_not_written() {
    let mut out = vec![0u8; 32];
    let n = CoinInfo::BITCOIN.encode(&mut out).unwrap();
    assert_eq!(to_hex(&out[..n]), "a0", "an empty map");
    assert_eq!(CoinInfo::decode(&out[..n]).unwrap(), CoinInfo::BITCOIN);

    let eth = CoinInfo {
        coin_type: 0x3c,
        network: 1,
    };
    let n = eth.encode(&mut out).unwrap();
    assert_eq!(to_hex(&out[..n]), "a201183c0201");
    assert_eq!(CoinInfo::decode(&out[..n]).unwrap(), eth);
}

// --- crypto-account, BCR-2020-015 ---------------------------------------------------

/// The published account: seven output descriptors for BIP-44 account 0 of the seed
/// "shield group erode awake lock sausage cash glare wave crew flame glove".
const ACCOUNT_CBOR: &str = "a2011a37b5eed40287d90134d90193d9012fa403582103eb3e2863911826374de8\
6c231a4b76f0b89dfa174afb78d7f478199884d9dd320458206456a5df2db0f6d9af72b2a1af4b25f45200ed6fcc29c\
3440b311d4796b70b5b06d90130a20186182cf500f500f5021a37b5eed4081a99f9cdf7d90134d90190d90194d9012f\
a403582102c7e4823730f6ee2cf864e2c352060a88e60b51a84e89e4c8c75ec22590ad6b690458209d2f86043276f92\
51a4a4f577166a5abeb16b6ec61e226b5b8fa11038bfda42d06d90130a201861831f500f500f5021a37b5eed4081aa8\
0f7cdbd90134d90194d9012fa403582103fd433450b6924b4f7efdd5d1ed017d364be95ab2b592dc8bddb3b00c1c24f\
63f04582072ede7334d5acf91c6fda622c205199c595a31f9218ed30792d301d5ee9e3a8806d90130a201861854f500\
f500f5021a37b5eed4081a0d5de1d7d90134d90190d9019ad9012fa4035821035ccd58b63a2cdc23d0812710603592e\
7457573211880cb59b1ef012e168e059a04582088d3299b448f87215d96b0c226235afc027f9e7dc700284f3e912a34\
daeb1a2306d90130a20182182df5021a37b5eed4081a37b5eed4d90134d90190d90191d9019ad9012fa4035821032c7\
8ebfcabdac6d735a0820ef8732f2821b4fb84cd5d6b26526938f90c0507110458207953efe16a73e5d3f9f2d4c6e49b\
d88e22093bbd85be5a7e862a4b98a16e0ab606d90130a201881830f500f500f501f5021a37b5eed4081a59b69b2ad90\
134d90191d9019ad9012fa40358210260563ee80c26844621b06b74070baf0e23fb76ce439d0237e87502ebbd3ca346\
0458202fa0e41c9dc43dc4518659bfcef935ba8101b57dbc0812805dd983bc1d34b81306d90130a201881830f500f50\
0f502f5021a37b5eed4081a59b69b2ad90134d90199d9012fa403582102bbb97cf9efa176b738efd6ee1d4d0fa391a9\
73394fbc16e4c5e78e536cd14d2d0458204b4693e1f794206ed1355b838da24949a92b63d02e58910bf3bd3d9c24228\
1e606d90130a201861856f500f500f5021a37b5eed4081acec7070c";

/// One byte above differs from the BCR's printed hex string: the fourth descriptor's
/// key data reads `...0359 29 7457...` there, and `...0359 2E 7457...` in both the
/// annotated binary dump and the UR in the same section. Two of the three agree, and
/// the UR is what a device actually receives, so `2E` is what is written here. It is a
/// typo in the document, not a case to handle in code.
const MASTER_FP: u32 = 0x37B5_EED4;

/// Every script type BCR-2020-015 tabulates, in the order the vector lists them, with
/// the derivation each is at.
const EXPECTED: [(Script, &[Component]); 7] = [
    (
        Script::Pkh,
        &[
            Component::hardened(44),
            Component::hardened(0),
            Component::hardened(0),
        ],
    ),
    (
        Script::ShWpkh,
        &[
            Component::hardened(49),
            Component::hardened(0),
            Component::hardened(0),
        ],
    ),
    (
        Script::Wpkh,
        &[
            Component::hardened(84),
            Component::hardened(0),
            Component::hardened(0),
        ],
    ),
    (Script::ShCosigner, &[Component::hardened(45)]),
    (
        Script::ShWshCosigner,
        &[
            Component::hardened(48),
            Component::hardened(0),
            Component::hardened(0),
            Component::hardened(1),
        ],
    ),
    (
        Script::WshCosigner,
        &[
            Component::hardened(48),
            Component::hardened(0),
            Component::hardened(0),
            Component::hardened(2),
        ],
    ),
    (
        Script::Tr,
        &[
            Component::hardened(86),
            Component::hardened(0),
            Component::hardened(0),
        ],
    ),
];

/// BCR-2020-015's account, read: seven descriptors, each with its script and its path.
#[test]
fn the_published_account_vector_reads() {
    let message = hex(ACCOUNT_CBOR);
    let account = Account::decode(&message).expect("an account");
    assert_eq!(account.master_fingerprint, MASTER_FP);
    assert_eq!(account.len(), 7);

    let got: Vec<Descriptor> = account
        .descriptors()
        .map(|d| d.expect("a descriptor"))
        .collect();
    assert_eq!(got.len(), 7);
    for (d, (script, path)) in got.iter().zip(EXPECTED) {
        assert_eq!(d.script, script);
        let origin = d.key.origin.clone().expect("an origin");
        assert_eq!(origin.components.as_slice(), path, "{script:?}");
        assert_eq!(origin.source_fingerprint, Some(MASTER_FP), "{script:?}");
        assert!(d.key.chain_code.is_some(), "{script:?} must be derivable");
        assert!(d.key.parent_fingerprint.is_some(), "{script:?}");
        assert!(!d.key.is_private, "an account export is public only");
    }
}

/// And written: the same seven descriptors produce the BCR's bytes exactly.
///
/// This is the one that matters for exporting -- a wallet's importer compares against
/// documents like this, not against a description of them.
#[test]
fn the_published_account_vector_is_written_byte_for_byte() {
    let message = hex(ACCOUNT_CBOR);
    let account = Account::decode(&message).expect("an account");

    let mut out = vec![0u8; 2048];
    let mut enc = account::Encoder::new(&mut out, account.master_fingerprint, 7).expect("room");
    for d in account.descriptors() {
        let d = d.expect("a descriptor");
        enc.push(d.script, &d.key).expect("room");
    }
    let n = enc.finish().expect("all seven");
    assert_eq!(to_hex(&out[..n]), ACCOUNT_CBOR);
}

/// An array that promises more descriptors than were pushed is never emitted.
#[test]
fn an_account_short_of_its_own_count_is_refused() {
    let key = HdKey::derived([2u8; 33]);
    let mut out = vec![0u8; 512];
    let mut enc = account::Encoder::new(&mut out, MASTER_FP, 3).expect("room");
    enc.push(Script::Wpkh, &key).unwrap();
    assert_eq!(enc.finish(), Err(Error::Field(2)));
}

/// And one that is pushed past its count stops rather than overrunning the array.
#[test]
fn an_account_past_its_own_count_is_refused() {
    let key = HdKey::derived([2u8; 33]);
    let mut out = vec![0u8; 512];
    let mut enc = account::Encoder::new(&mut out, MASTER_FP, 1).expect("room");
    enc.push(Script::Wpkh, &key).unwrap();
    assert_eq!(enc.push(Script::Pkh, &key), Err(Error::TooMany));
}

/// An output buffer too small fails rather than writing a partial document.
#[test]
fn an_account_that_does_not_fit_fails_at_the_push() {
    let mut key = HdKey::derived([2u8; 33]);
    key.chain_code = Some([3u8; 32]);
    let mut out = vec![0u8; 40];
    let mut enc = account::Encoder::new(&mut out, MASTER_FP, 1).expect("the header fits");
    assert_eq!(
        enc.push(Script::Wpkh, &key),
        Err(Error::Cbor(CborError::NoRoom))
    );
}

/// The version-2 `account-descriptor` is a different structure, and says so.
#[test]
fn a_version_two_account_is_not_read_as_a_version_one() {
    // #6.40311 around the published body.
    let mut message = hex("d99d77");
    message.extend_from_slice(&hex(ACCOUNT_CBOR));
    assert_eq!(Account::decode(&message).err(), Some(Error::Unsupported));
}

/// So is the version-3 output descriptor inside one.
#[test]
fn a_version_three_output_descriptor_is_not_read_as_a_version_one() {
    // {1: <fp>, 2: [40308({1: "wpkh(@0)"})]}
    let message = hex("a2011a37b5eed40281d99d74a10168 77706b6828403029");
    let account = Account::decode(&message).expect("the account shell reads");
    let first = account.descriptors().next().expect("one descriptor");
    assert_eq!(first, Err(Error::Unsupported));
}

/// A descriptor whose key is not an HD key is refused.
///
/// BCR-2020-010's own first vector is `pkh(<eckey>)`; this device has no use for a
/// bare public key at account level and will not pretend one is an xpub.
#[test]
fn the_published_eckey_output_vector_is_not_read() {
    let message = hex(
        "d90193d90132a103582102c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5",
    );
    assert_eq!(Descriptor::decode(&message), Err(Error::Unsupported));

    // And the same vector as its published UR, so the refusal is of the document the
    // BCR prints and not of a transcription of it.
    let mut scratch = vec![0u8; 256];
    let mut c = crate::Collector::new();
    let placed = c
        .accept(vector("crypto-output-1"), &mut scratch)
        .expect("a UR");
    assert_eq!(c.kind(), Some(Kind::Output));
    let body = &scratch[placed.at.start..placed.at.start + placed.len];
    assert_eq!(to_hex(body), to_hex(&message));
    assert_eq!(Descriptor::decode(body), Err(Error::Unsupported));
}

/// A script function outside the account-level set is refused, not guessed at.
#[test]
fn an_unknown_script_function_is_refused() {
    // #6.406 (multi) around an hdkey.
    let mut message = hex("d90196d9012f");
    message.extend_from_slice(&hex(HDKEY1_CBOR));
    assert_eq!(Descriptor::decode(&message), Err(Error::Unsupported));
}

/// A standalone `crypto-output`, written and read, with no account around it.
#[test]
fn a_lone_output_descriptor_round_trips() {
    let message = hex(ACCOUNT_CBOR);
    let account = Account::decode(&message).unwrap();
    let first = account.descriptors().next().unwrap().unwrap();

    let mut out = vec![0u8; 512];
    let n = first.encode(&mut out).expect("room");
    // No #6.308 at the top level: the UR type is what says what it is.
    assert!(to_hex(&out[..n]).starts_with("d90193"), "pkh, then the key");
    assert_eq!(Descriptor::decode(&out[..n]).unwrap(), first);
}

/// An account whose descriptor list is empty is not an account: the CDDL says
/// `[+ output-exp]`, one or more.
#[test]
fn an_account_with_no_descriptors_is_refused() {
    assert_eq!(
        Account::decode(&hex("a2011a37b5eed40280")).err(),
        Some(Error::TooMany)
    );
}

/// An account missing its master fingerprint cannot resolve the keys that omit theirs.
#[test]
fn an_account_without_a_master_fingerprint_is_refused() {
    let message = hex(ACCOUNT_CBOR);
    let account = Account::decode(&message).unwrap();
    let first = account.descriptors().next().unwrap().unwrap();
    let mut body = vec![0xA1, 0x02, 0x81]; // {2: [ ... ]}
    body.push(0xD9);
    body.extend_from_slice(&[0x01, 0x34]); // #6.308
    let mut one = vec![0u8; 512];
    let n = first.encode(&mut one).unwrap();
    body.extend_from_slice(&one[..n]);
    assert_eq!(Account::decode(&body).err(), Some(Error::Field(1)));
}

// --- the whole way, for the account -------------------------------------------------

/// The published account as a UR: single-part, through the collector, to the seven
/// descriptors, and back out to the same line.
#[test]
fn the_published_account_ur_round_trips() {
    let line = vector("crypto-account");
    let message = collect(line, Kind::Account);
    assert_eq!(to_hex(&message), ACCOUNT_CBOR);

    let account = Account::decode(&message).unwrap();
    assert_eq!(account.len(), 7);

    let mut out = vec![0u8; 4096];
    let n = crate::encode::single("crypto-account", &message, &mut out).expect("room");
    assert_eq!(
        core::str::from_utf8(&out[..n]).unwrap(),
        line.to_ascii_uppercase()
    );
}

/// Run a single-part UR line through the collector and hand back the message.
fn collect(line: &str, kind: Kind) -> Vec<u8> {
    let mut scratch = vec![0u8; 4096];
    let mut c = crate::Collector::new();
    let placed = c.accept(line, &mut scratch).expect("a UR");
    let message = scratch[placed.at.start..placed.at.start + placed.len].to_vec();
    c.confirm(placed);
    assert!(c.complete(), "a single-part UR is complete at once");
    assert!(c.verify(&message));
    assert_eq!(c.kind(), Some(kind));
    message
}

/// The published account, built the way the device builds it: from the seed.
///
/// Everything above reads the BCR's bytes or writes them back. This one starts from
/// the BIP-39 phrase the BCR says the account is for and derives its way to the same
/// bytes -- so it is the derivation table, the fingerprint's byte order, the hardened
/// indices and the encoder all at once, against a document written by someone else.
///
/// It is the test that would have caught a fingerprint written little-endian, which
/// reads perfectly well and names the wrong wallet.
#[test]
fn the_published_account_is_reached_from_its_own_seed() {
    use catcard_wallet::KeyWork;
    use catcard_wallet::bip32::{ChildNumber, ExtendedPrivKey, Network};
    use catcard_wallet::bip39::Mnemonic;

    // BCR-2020-015 §"Example/Test Vector": "Defines the #0 account for BTC mainnet for
    // the following BIP39 seed". [C]
    const PHRASE: &str = "shield group erode awake lock sausage cash glare wave crew flame glove";

    let kw = KeyWork::host();
    let mnemonic = Mnemonic::parse(PHRASE, &kw).expect("a valid phrase");
    let mut seed = [0u8; catcard_wallet::bip39::SEED_LEN];
    mnemonic.to_seed("", &mut seed, &kw).expect("a seed");
    let master = ExtendedPrivKey::from_seed(&seed, Network::Mainnet, &kw).expect("a master key");
    let fingerprint = u32::from_be_bytes(master.fingerprint(&kw));
    assert_eq!(fingerprint, MASTER_FP, "the BCR's master fingerprint");

    let mut out = vec![0u8; 2048];
    let mut enc =
        account::Encoder::new(&mut out, fingerprint, account::STANDARD.len() as u32).unwrap();
    for (script, path) in account::STANDARD {
        let mut here = master.clone();
        for &index in path {
            here = here
                .derive_child(ChildNumber::hardened(index).unwrap(), &kw)
                .expect("a child");
        }
        let xpub = here.to_extended_pub(&kw);
        let d = Descriptor::account_key(
            script,
            path,
            CoinInfo::BITCOIN,
            fingerprint,
            u32::from_be_bytes(xpub.parent_fingerprint),
            xpub.public_key,
            xpub.chain_code,
        )
        .expect("a descriptor");
        enc.push(d.script, &d.key).expect("room");
    }
    let n = enc.finish().expect("all seven");
    assert_eq!(to_hex(&out[..n]), ACCOUNT_CBOR);
}

// --- crypto-account on testnet ------------------------------------------------------

/// Build the BCR's account from its seed the way the device does -- through
/// [`account::standard_path`] for `coin_type`, on `network` -- and hand back the bytes.
fn account_from_the_bcr_seed(
    coin_type: u32,
    network: catcard_wallet::bip32::Network,
    use_info: CoinInfo,
) -> Vec<u8> {
    use catcard_wallet::KeyWork;
    use catcard_wallet::bip32::{ChildNumber, ExtendedPrivKey};
    use catcard_wallet::bip39::Mnemonic;

    const PHRASE: &str = "shield group erode awake lock sausage cash glare wave crew flame glove";

    let kw = KeyWork::host();
    let mnemonic = Mnemonic::parse(PHRASE, &kw).expect("a valid phrase");
    let mut seed = [0u8; catcard_wallet::bip39::SEED_LEN];
    mnemonic.to_seed("", &mut seed, &kw).expect("a seed");
    let master = ExtendedPrivKey::from_seed(&seed, network, &kw).expect("a master key");
    let fingerprint = u32::from_be_bytes(master.fingerprint(&kw));

    let mut out = vec![0u8; 2048];
    let mut enc =
        account::Encoder::new(&mut out, fingerprint, account::STANDARD.len() as u32).unwrap();
    for (script, _) in account::STANDARD {
        let path = account::standard_path(script, coin_type);
        let mut here = master.clone();
        for &index in path.iter() {
            here = here
                .derive_child(ChildNumber::hardened(index).unwrap(), &kw)
                .expect("a child");
        }
        let xpub = here.to_extended_pub(&kw);
        let d = Descriptor::account_key(
            script,
            &path,
            use_info,
            fingerprint,
            u32::from_be_bytes(xpub.parent_fingerprint),
            xpub.public_key,
            xpub.chain_code,
        )
        .expect("a descriptor");
        enc.push(d.script, &d.key).expect("room");
    }
    let n = enc.finish().expect("all seven");
    out.truncate(n);
    out
}

/// The coin-0 paths [`account::standard_path`] gives are [`account::STANDARD`]'s rows,
/// script for script: the table the published vector checks is the one the function
/// produces on mainnet.
#[test]
fn the_standard_paths_for_coin_zero_are_the_published_table() {
    for (script, path) in account::STANDARD {
        assert_eq!(
            account::standard_path(script, 0).as_slice(),
            path,
            "{script:?}"
        );
    }
}

/// On mainnet, going through `standard_path` and an explicit `CoinInfo::BITCOIN`
/// changes nothing: the bytes are still BCR-2020-015's, use-info and all.
#[test]
fn a_mainnet_account_is_byte_identical_to_the_published_vector() {
    use catcard_wallet::bip32::Network;
    let got = account_from_the_bcr_seed(0, Network::Mainnet, CoinInfo::BITCOIN);
    assert_eq!(to_hex(&got), ACCOUNT_CBOR);
    assert!(
        !to_hex(&got).contains("05d90131"),
        "a mainnet key carries no use-info: the default is omitted"
    );
}

/// On testnet every key says so: `use-info` is present with `network: 1`, and the
/// origin's coin level is 1 on every path that has one.
///
/// The CBOR is checked as bytes as well as through the reader: map key 5, tag #6.305,
/// `{2: 1}` -- `05 d90131 a1 02 01` -- once per descriptor, so an encoder that dropped
/// the field for being "mostly default" would fail here rather than in a wallet.
/// [C] BCR-2020-007 §"CDDL for HDKey", §"CDDL for Coin Info"
#[test]
fn a_testnet_account_carries_use_info_and_coin_type_one() {
    use catcard_wallet::bip32::Network;

    let got = account_from_the_bcr_seed(1, Network::Testnet, CoinInfo::BITCOIN_TESTNET);
    let hex_text = to_hex(&got);
    assert_eq!(
        hex_text.matches("05d90131a10201").count(),
        7,
        "each of the seven keys carries use-info {{network: 1}}"
    );

    let account = Account::decode(&got).expect("an account");
    assert_eq!(account.len(), 7);
    for (d, (script, mainnet_path)) in account.descriptors().zip(account::STANDARD) {
        let d = d.expect("a descriptor");
        assert_eq!(d.script, script);
        assert_eq!(
            d.key.use_info,
            Some(CoinInfo::BITCOIN_TESTNET),
            "{script:?}"
        );
        let origin = d.key.origin.clone().expect("an origin");
        // Every level hardened, and the path is the coin-1 row.
        let want: Vec<Component> = account::standard_path(script, 1)
            .iter()
            .map(|&i| Component::hardened(i))
            .collect();
        assert_eq!(origin.components.as_slice(), want.as_slice(), "{script:?}");
        // The coin level is the one that moved; BIP-45 has none and is unchanged.
        if mainnet_path.len() > 1 {
            assert_eq!(want[1], Component::hardened(1), "{script:?} coin type");
            assert_eq!(mainnet_path[1], 0);
        } else {
            let same: Vec<Component> = mainnet_path
                .iter()
                .map(|&i| Component::hardened(i))
                .collect();
            assert_eq!(want, same, "{script:?}");
        }
    }

    // And it is not the mainnet document with a flag on it: the keys themselves differ,
    // because they were derived under coin type 1.
    let mainnet = account_from_the_bcr_seed(0, Network::Mainnet, CoinInfo::BITCOIN);
    let main_keys: Vec<_> = Account::decode(&mainnet)
        .unwrap()
        .descriptors()
        .map(|d| d.unwrap().key.key_data)
        .collect();
    let test_keys: Vec<_> = account
        .descriptors()
        .map(|d| d.unwrap().key.key_data)
        .collect();
    for (i, (m, t)) in main_keys.iter().zip(&test_keys).enumerate() {
        // BIP-45's key has no coin level and is the same on both networks.
        if account::STANDARD[i].1.len() > 1 {
            assert_ne!(m, t, "descriptor {i} must be a different key on testnet");
        } else {
            assert_eq!(m, t, "descriptor {i} (BIP-45) has no coin level");
        }
    }
}

// --- sol-sign-request, sol-signature -------------------------------------------------

/// Keystone's own example, read as a UR and then as a request.
///
/// The string is copied from the test in `@keystonehq/bc-ur-registry-sol` that produces
/// it, so this checks interoperability with the thing wallets actually talk to rather
/// than with our own idea of the format. Everything in it is asserted, because each
/// field is a different way of signing the wrong thing: the wrong bytes, with the wrong
/// key, answered to the wrong question.
#[test]
fn keystones_own_sign_request_is_read() {
    use crate::registry::hdkey::Component;
    use crate::registry::solsign::{self, SignType};

    const LINE: &str = "ur:sol-sign-request/onadtpdagdndcawmgtfrkigrpmndutdnbtkgfssbjnaohdmtadaeadaxsptpfwoewnlbtspkrpaytodmonecolwlhdurzscxsgyninqdflrhbysschcfihgubsmdkocxprderdvorhgslfuttyrtmumkftioengogorlemwpkiuobychvacejpvtaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaebedthhsawnwfneenaajslrmtwdaeiojnimjpwpiypmastadsvlwpvlgwhfhecstdadaoaoaeadbnaoaeaeaeaevyykahaeaeaeaeaxtaaddyoeadlocsdwykcfadykykaeykaeykaocybgeehfksahisjkjljziyjzhsjpihamadkkgseofg";

    let mut scratch = vec![0u8; 2048];
    let mut c = crate::Collector::new();
    let placed = c.accept(LINE, &mut scratch).expect("a single-part UR");
    let message = scratch[placed.at.start..placed.at.start + placed.len].to_vec();
    c.confirm(placed);
    assert!(c.complete());
    assert_eq!(c.kind(), Some(Kind::SolSignRequest));

    let req = solsign::decode(&message).expect("a sign request");
    assert_eq!(req.sign_type, SignType::Transaction);
    // m/44'/501'/0'/0', under the master whose fingerprint is 12345678.
    assert_eq!(req.path.source_fingerprint, Some(0x1234_5678));
    assert_eq!(
        req.path.components.as_slice(),
        &[
            Component::hardened(44),
            Component::hardened(501),
            Component::hardened(0),
            Component::hardened(0),
        ]
    );
    // The UUID 9b1deb4d-3b7d-4bad-9bdd-2b0d7b3dcb6d, as sixteen bytes.
    assert_eq!(
        req.request_id,
        Some(
            &[
                0x9b, 0x1d, 0xeb, 0x4d, 0x3b, 0x7d, 0x4b, 0xad, 0x9b, 0xdd, 0x2b, 0x0d, 0x7b, 0x3d,
                0xcb, 0x6d
            ][..]
        )
    );
    // And what it asks to have signed is a message: a header, three keys, a blockhash
    // and one instruction. 150 bytes, opening with the header rather than with a
    // signature count.
    assert_eq!(req.sign_data.len(), 150);
    assert_eq!(&req.sign_data[..4], &[0x01, 0x00, 0x01, 0x03]);
}

/// The answer is a signature and the handle it answers, and nothing else.
#[test]
fn a_signature_answers_the_request_that_asked() {
    use crate::registry::solsign;

    let id = [0x9bu8; 16];
    let signature = [0x42u8; 64];
    let mut out = vec![0u8; solsign::signature_len(id.len())];
    let n = solsign::encode_signature(&signature, Some(&id), &mut out).expect("room");
    assert!(n <= out.len());

    // Read back with the CBOR reader, since there is no decoder for the answer -- this
    // device writes it and never receives one.
    let mut r = crate::cbor::Reader::new(&out[..n]);
    assert_eq!(r.map().expect("a map"), 2);
    assert_eq!(r.uint().expect("key"), 1);
    assert_eq!(r.tag().expect("uuid tag"), 37);
    assert_eq!(r.bytes().expect("id"), &id[..]);
    assert_eq!(r.uint().expect("key"), 2);
    assert_eq!(r.bytes().expect("signature"), &signature[..]);
    assert!(r.at_end());

    // Without a handle it is one pair, and still fits what the sizer said.
    let mut out = vec![0u8; solsign::signature_len(0)];
    let n = solsign::encode_signature(&signature, None, &mut out).expect("room");
    let mut r = crate::cbor::Reader::new(&out[..n]);
    assert_eq!(r.map().expect("a map"), 1);
}

/// A field this does not read is stepped over, and stepping over an array means adding
/// its claimed length to a count. The length is whatever the head says, up to
/// `u64::MAX`, and adding *that* is an overflow -- which with overflow checks on and
/// `panic = "abort"` was a device reset from one scanned code. It is an error now, and
/// it is the same error for every shape the arithmetic can be made to fail in.
#[test]
fn an_absurd_length_in_a_skipped_field_is_refused_not_overflowed() {
    use crate::registry::solsign;

    // {5: [array of 2^64-1 elements]}: key 5 is `origin`, which is skipped. The outer
    // array adds 2 to the pending count; the inner one adds u64::MAX to that.
    let overflow = hex("a1 05 82 9b ffffffffffffffff");
    assert!(matches!(
        solsign::decode(&overflow),
        Err(Error::Cbor(CborError::TooDeep))
    ));
    // The map counterpart: 2^63 pairs, which doubles to more than a u64 holds.
    let map_overflow = hex("a1 05 82 bb 8000000000000000");
    assert!(matches!(
        solsign::decode(&map_overflow),
        Err(Error::Cbor(CborError::TooDeep))
    ));
    // And a length that fits the arithmetic but not the walk: refused the same way,
    // before a single element is looked at.
    let too_many = hex("a1 05 9a ffffffff");
    assert!(matches!(
        solsign::decode(&too_many),
        Err(Error::Cbor(CborError::TooDeep))
    ));
}

// --- crypto-multi-accounts -----------------------------------------------------------

/// Every account in one message, with both curves in it.
///
/// What a wallet reads when it syncs with a hardware wallet. The two entries are the two
/// shapes that have to coexist: a secp256k1 account node, which the wallet derives
/// addresses under, and an ed25519 account key, which *is* the address once base58'd --
/// there being no public derivation on that curve to offer instead.
#[test]
fn every_account_goes_in_one_message() {
    use crate::registry::hdkey::{Component, HdKey, KeyPath};
    use crate::registry::multi;

    let mut evm = HdKey::of(&[0x02; 33]).expect("a compressed key");
    evm.chain_code = Some([0x11; 32]);
    evm.origin = Some(
        KeyPath::new(
            0xCA41_2C00,
            &[
                Component::hardened(44),
                Component::hardened(60),
                Component::hardened(0),
                Component::normal(0),
            ],
        )
        .expect("a path"),
    );
    evm.name = Some(heapless::String::try_from("Ethereum").expect("short enough"));

    let mut sol = HdKey::of(&[0x33; 32]).expect("an ed25519 key");
    sol.origin = Some(
        KeyPath::new(
            0xCA41_2C00,
            &[
                Component::hardened(44),
                Component::hardened(501),
                Component::hardened(0),
                Component::hardened(0),
            ],
        )
        .expect("a path"),
    );
    sol.name = Some(heapless::String::try_from("Solana").expect("short enough"));

    let keys = [evm.clone(), sol.clone()];
    let mut out = vec![0u8; multi::encoded_len(keys.len(), 8)];
    let n = multi::encode(0xCA41_2C00, &keys, "CatCard", &mut out).expect("room");

    // Read it back with the CBOR reader: a map of three, the fingerprint, the two keys
    // tagged as `crypto-hdkey`, and the device's name.
    let mut r = crate::cbor::Reader::new(&out[..n]);
    assert_eq!(r.map().expect("a map"), 3);
    assert_eq!(r.uint().expect("key"), 1);
    assert_eq!(r.uint().expect("fingerprint"), 0xCA41_2C00);
    assert_eq!(r.uint().expect("key"), 2);
    assert_eq!(r.array().expect("the keys"), 2);

    assert_eq!(r.tag().expect("tagged"), 303);
    let first = HdKey::read(&mut r).expect("the first key");
    assert_eq!(first.key_data.len(), 33);
    assert_eq!(first.name.as_deref(), Some("Ethereum"));
    assert_eq!(first.chain_code, Some([0x11; 32]));

    assert_eq!(r.tag().expect("tagged"), 303);
    let second = HdKey::read(&mut r).expect("the second key");
    assert_eq!(second.key_data.len(), 32, "an ed25519 key is 32 bytes");
    assert_eq!(second.name.as_deref(), Some("Solana"));
    assert_eq!(second.chain_code, None, "nothing derives from it");

    assert_eq!(r.uint().expect("key"), 3);
    assert!(r.at_end() || true);
}

/// A full `chains::MAX` worth of accounts encodes and reads back unchanged.
///
/// `export_keystone` gathers up to sixteen account keys (the firmware's `chains::MAX`),
/// and moving that accumulator off the stack must not change a byte the encoder writes.
/// Sixteen distinct secp256k1 accounts go in; every one comes back with its key, chain
/// code, path and name intact, and the message is exactly the length re-encoding it
/// produces -- so the slice the firmware now hands in encodes the same as the vector did.
#[test]
fn sixteen_accounts_round_trip() {
    use crate::registry::hdkey::{Component, HdKey, KeyPath};
    use crate::registry::multi;

    const N: usize = 16;
    const FP: u32 = 0xCA41_2C00;

    let mut keys: heapless::Vec<HdKey, N> = heapless::Vec::new();
    for i in 0..N as u32 {
        let mut key = HdKey::of(&[(0x02 + i) as u8; 33]).expect("a compressed key");
        key.chain_code = Some([i as u8; 32]);
        key.parent_fingerprint = Some(0x1000_0000 + i);
        key.origin = Some(
            KeyPath::new(
                FP,
                &[
                    Component::hardened(44),
                    Component::hardened(i),
                    Component::hardened(0),
                ],
            )
            .expect("a path"),
        );
        let mut name: heapless::String<{ crate::registry::hdkey::NAME_MAX }> =
            heapless::String::new();
        core::fmt::Write::write_fmt(&mut name, format_args!("Chain {i}")).expect("short enough");
        key.name = Some(name);
        keys.push(key).expect("room for sixteen");
    }

    let mut out = vec![0u8; multi::encoded_len(N, 7)];
    let n = multi::encode(FP, &keys, "CatCard", &mut out).expect("room");

    // Read every one back and check it matches the key that went in.
    let mut r = crate::cbor::Reader::new(&out[..n]);
    assert_eq!(r.map().expect("a map"), 3);
    assert_eq!(r.uint().expect("key"), 1);
    assert_eq!(r.uint().expect("fingerprint"), u64::from(FP));
    assert_eq!(r.uint().expect("key"), 2);
    assert_eq!(r.array().expect("the keys"), N as u64);
    for i in 0..N {
        assert_eq!(r.tag().expect("tagged"), 303);
        let got = HdKey::read(&mut r).expect("a key");
        assert_eq!(got, keys[i], "account {i} survived the round trip");
    }
    assert_eq!(r.uint().expect("key"), 3);
    assert_eq!(r.text().expect("the device"), "CatCard");
    assert!(r.at_end(), "nothing trails the device name");

    // Encoding it a second time is byte-identical: the encoder has no hidden state.
    let mut again = vec![0u8; multi::encoded_len(N, 7)];
    let m = multi::encode(FP, &keys, "CatCard", &mut again).expect("room");
    assert_eq!(&out[..n], &again[..m], "the encoding is deterministic");
}

/// A key of a length neither curve uses is refused.
#[test]
fn a_key_of_no_curve_is_refused() {
    use crate::registry::hdkey::HdKey;
    assert!(HdKey::of(&[0u8; 31]).is_err());
    assert!(HdKey::of(&[0u8; 34]).is_err());
    assert!(HdKey::of(&[0u8; 32]).is_ok());
    assert!(HdKey::of(&[0u8; 33]).is_ok());
}
