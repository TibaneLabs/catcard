extern crate std;
use super::*;
use std::format;
use std::string::String;
use std::vec::Vec;

fn unhex(s: &str) -> Vec<u8> {
    (0..s.len() / 2)
        .map(|i| u8::from_str_radix(&s[2 * i..2 * i + 2], 16).unwrap())
        .collect()
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

// The example in EIP-712 itself ("Mail"), in the device's layout. The same bytes are
// pinned in `tools/hostwallet.py`'s selftest, which makes them from the JSON.
const MAIL: &str = "01030c454950373132446f6d61696e0406737472696e67046e616d6506737472696e670776657273696f6e0775696e7432353607636861696e4964076164647265737311766572696679696e67436f6e747261637406506572736f6e0206737472696e67046e616d6507616464726573730677616c6c6574044d61696c0306506572736f6e0466726f6d06506572736f6e02746f06737472696e6708636f6e74656e7473020a004574686572204d61696c0100310101cccccccccccccccccccccccccccccccccccccccc0300436f77cd2a3d9f938e13cd947ec05abc7fe734df8dd8260300426f62bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb0b0048656c6c6f2c20426f6221";

// Everything the Mail example lacks: arrays of structs, a fixed array, nested and empty
// arrays, a negative `int64`, `bytes4`, `bytes`, `bytes32`, a two-line string, a struct
// reached only through another, the types out of name order, and the domain not first.
const RICH: &str = "0104054f726465720a0761646472657373056d616b6572064974656d5b5d056974656d7307626f6f6c5b325d05666c61677305696e7436340564656c7461066279746573340374616705627974657304626c6f620975696e74385b5d5b5d046772696406737472696e67046d656d6f064974656d5b5d046e6f6e650775696e74323536056c696d69740c454950373132446f6d61696e0306737472696e67046e616d650775696e7432353607636861696e496407627974657333320473616c74044974656d0205417373657405746f6b656e0775696e7431323806616d6f756e7405417373657402076164647265737308636f6e74726163740775696e7432353602696400040053686f700189abababababababababababababababababababababababababababababababab00000000219ab540356cbb839cbe05303d7705fa0200dac17f958d2ee523a2206206994597c13d831ec700030f4240a0b86991c6218b36c1d19d4a2e9eb0ce3606eb48010710ffffffffffffffffffffffffffffffff0100fffffffffffffffbdeadbeef0500010203040503000200010101020000010001ff090074776f0a6c696e6573000020ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff";

fn walk(blob: &[u8]) -> Result<(Hashes, Vec<String>), Error> {
    let typed = Typed::parse(blob)?;
    let mut rows = Vec::new();
    let hashes = typed.walk(&mut |part, path, leaf| {
        let what = match leaf {
            Leaf::Uint { raw, bits } => {
                let lead = raw.iter().take_while(|b| **b == 0).count().min(31);
                format!("u{bits}:{}", hex(&raw[lead..]))
            }
            Leaf::Int { raw } => format!("i:{}", hex(&raw[24..])),
            Leaf::Bool(b) => format!("{b}"),
            Leaf::Address(a) => format!("@{}", hex(&a[..2])),
            Leaf::Fixed(b) => format!("fixed:{}", hex(b)),
            Leaf::Bytes(b) => format!("bytes:{}", hex(b)),
            Leaf::Str(s) => format!("{s:?}"),
            Leaf::Empty => String::from("(empty)"),
        };
        let part = if part == Part::Domain { "D" } else { "M" };
        rows.push(format!("{part} {} = {what}", Label(path)));
    })?;
    Ok((hashes, rows))
}

// The four values are the ones EIP-712 gives for its own example (its `Example.js`), and
// the ones an independent reading of the standard computes from the JSON.
#[test]
fn the_standards_own_example_hashes_as_the_standard_says() {
    let blob = unhex(MAIL);
    let typed = Typed::parse(&blob).unwrap();
    assert_eq!(typed.primary(), "Mail");
    assert_eq!(
        hex(&typed.type_hash(typed.primary)),
        "a0cedeb2dc280ba39b857546d74f5549c3a1d7bdc2dd96bf881f76108e23dac2"
    );
    let (h, rows) = walk(&blob).unwrap();
    assert_eq!(
        hex(&h.domain),
        "f2cee375fa42b42143804025fc449deafd50cc031ca257e0b194a650a912090f"
    );
    assert_eq!(
        hex(&h.message),
        "c52c0ee5d84264471806290a3f2c4cecfc5490626bf912d01f240d7a274b371e"
    );
    assert_eq!(
        hex(&h.digest),
        "be609aee343fb3c4b28e1df9e632fca64fcfaede20f02e86244efddf30957bd2"
    );
    assert_eq!(
        rows,
        [
            "D name = \"Ether Mail\"",
            "D version = \"1\"",
            "D chainId = u256:01",
            "D verifyingContract = @cccc",
            "M from.name = \"Cow\"",
            "M from.wallet = @cd2a",
            "M to.name = \"Bob\"",
            "M to.wallet = @bbbb",
            "M contents = \"Hello, Bob!\"",
        ]
    );
}

// Expected values from a reference written apart from this code: Keccak-f[1600] from
// FIPS 202 and `eth_signTypedData_v4`'s rules applied to the JSON directly.
#[test]
fn arrays_nesting_and_every_atomic_type_hash_as_v4_does() {
    let blob = unhex(RICH);
    let typed = Typed::parse(&blob).unwrap();
    assert_eq!(
        hex(&typed.type_hash(typed.primary)),
        "28f869624027ff1f0dcda23cb0b18ca4031bbb56ca275253cc5d80cafae1db08"
    );
    let (h, rows) = walk(&blob).unwrap();
    assert_eq!(
        hex(&h.domain),
        "af529b5b9fa404e83755970772ee4a55c9b891fa3c4088dadab11c7d74876e25"
    );
    assert_eq!(
        hex(&h.message),
        "a1765ba9157cf98972a0b514ea3c91ba9e91fc15260d8d72516506ac03cb3769"
    );
    assert_eq!(
        hex(&h.digest),
        "98443ee2e79b8539710ef4c148cec28fb1ad4054d312241dad1366fed24f7127"
    );
    assert_eq!(
        rows,
        [
            "D name = \"Shop\"",
            "D chainId = u256:89",
            "D salt = fixed:abababababababababababababababababababababababababababababababab",
            "M maker = @0000",
            "M items[0].token.contract = @dac1",
            "M items[0].token.id = u256:00",
            "M items[0].amount = u128:0f4240",
            "M items[1].token.contract = @a0b8",
            "M items[1].token.id = u256:07",
            "M items[1].amount = u128:ffffffffffffffffffffffffffffffff",
            "M flags[0] = true",
            "M flags[1] = false",
            "M delta = i:fffffffffffffffb",
            "M tag = fixed:deadbeef",
            "M blob = bytes:0102030405",
            "M grid[0][0] = u8:01",
            "M grid[0][1] = u8:02",
            "M grid[1] = (empty)",
            "M grid[2][0] = u8:ff",
            "M memo = \"two\\nlines\"",
            "M none = (empty)",
            "M limit = u256:ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
        ]
    );
}

#[test]
fn every_value_shown_is_hashed_and_nothing_else() {
    // Change any one byte -- of the types or of the values -- and the digest changes or
    // the read fails: there is no byte the walk skips.
    let blob = unhex(MAIL);
    let (good, _) = walk(&blob).unwrap();
    for at in 0..blob.len() {
        let mut b = blob.clone();
        b[at] ^= 0x01;
        if let Ok((h, _)) = walk(&b) {
            assert_ne!(h.digest, good.digest, "byte {at} is not hashed");
        }
    }
    // Cut anywhere, or with a byte to spare, it is refused.
    for n in 0..blob.len() {
        assert!(walk(&blob[..n]).is_err(), "cut at {n}");
    }
    let mut long = blob.clone();
    long.push(0);
    assert_eq!(walk(&long).err(), Some(Error::Trailing));
}

/// A request from parts: `types` as `(name, [(type, name)])`, then raw value bytes.
fn build(types: &[(&str, &[(&str, &str)])], primary: u8, values: &[u8]) -> Vec<u8> {
    let short = |s: &str, out: &mut Vec<u8>| {
        out.push(s.len() as u8);
        out.extend_from_slice(s.as_bytes());
    };
    let mut out = std::vec![VERSION, types.len() as u8];
    for (name, fields) in types {
        short(name, &mut out);
        out.push(fields.len() as u8);
        for (ty, fname) in *fields {
            short(ty, &mut out);
            short(fname, &mut out);
        }
    }
    out.push(primary);
    out.extend_from_slice(values);
    out
}

const DOM: (&str, &[(&str, &str)]) = (DOMAIN, &[("string", "name")]);
/// A domain named "D".
const DOM_VALUE: [u8; 3] = [1, 0, b'D'];

fn with(field_type: &str, value: &[u8]) -> Result<(Hashes, Vec<String>), Error> {
    let mut values = DOM_VALUE.to_vec();
    values.extend_from_slice(value);
    walk(&build(&[DOM, ("T", &[(field_type, "x")])], 1, &values))
}

#[test]
fn only_eip_712s_types_are_types() {
    for ok in ["uint8", "uint256", "int8", "int256", "bytes1", "bytes32"] {
        assert!(atomic(ok).is_some(), "{ok}");
    }
    for bad in [
        "uint", "int", "uint0", "uint7", "uint264", "uint08", "bytes0", "bytes33", "bytes01",
        "Uint8", "uint8 ", "fixed", "byte",
    ] {
        assert!(atomic(bad).is_none(), "{bad}");
        assert!(with(bad, &[0]).is_err(), "{bad}");
    }
    assert_eq!(with("Nobody", &[]).err(), Some(Error::UnknownType));
    assert_eq!(with("uint8[", &[]).err(), Some(Error::BadType));
    assert_eq!(with("[]", &[]).err(), Some(Error::BadType));
    assert_eq!(with("uint8[0x2]", &[]).err(), Some(Error::BadType));
    assert_eq!(with("uint8[02]", &[]).err(), Some(Error::BadType));
}

#[test]
fn a_value_has_to_fit_its_type() {
    assert!(with("uint8", &[1, 0xff]).is_ok());
    assert!(with("uint8", &[0]).is_ok());
    assert_eq!(with("uint8", &[2, 1, 0]).err(), Some(Error::BadValue));
    assert_eq!(with("uint256", &[33]).err(), Some(Error::BadValue));
    assert_eq!(with("bool", &[2]).err(), Some(Error::BadValue));
    assert_eq!(with("int16", &[0xff]).err(), Some(Error::Truncated));
    assert_eq!(with("address", &[0; 19]).err(), Some(Error::Truncated));
    assert_eq!(with("uint8[2]", &[1, 1]).err(), Some(Error::Truncated));
    // A negative number fills the word with ones; a positive one with zeros.
    let (_, rows) = with("int16", &[0xff, 0xfe]).unwrap();
    assert_eq!(rows[1], "M x = i:fffffffffffffffe");
    let (_, rows) = with("int16", &[0x7f, 0xfe]).unwrap();
    assert_eq!(rows[1], "M x = i:0000000000007ffe");
}

#[test]
fn text_a_screen_cannot_show_is_not_signed() {
    assert!(with("string", &[2, 0, b'o', b'k']).is_ok());
    assert!(with("string", &[0, 0]).is_ok());
    assert_eq!(with("string", &[1, 0, 0x07]).err(), Some(Error::NotText));
    assert_eq!(
        with("string", &[2, 0, 0xc3, 0xa9]).err(),
        Some(Error::NotText)
    );
    assert_eq!(with("string", &[1, 0, 0x7f]).err(), Some(Error::NotText));
}

#[test]
fn the_domain_is_the_standards_and_the_message_is_not_the_domain() {
    let t: (&str, &[(&str, &str)]) = ("T", &[]);
    let ok = |d: &[(&str, &str)]| Typed::parse(&build(&[(DOMAIN, d), t], 1, &[])).err();
    assert_eq!(ok(&[("string", "name"), ("bytes32", "salt")]), None);
    assert_eq!(ok(&[("uint256", "chainId")]), None);
    assert_eq!(ok(&[]), Some(Error::BadDomain));
    assert_eq!(ok(&[("string", "title")]), Some(Error::BadDomain));
    assert_eq!(ok(&[("uint64", "chainId")]), Some(Error::BadDomain));
    assert_eq!(
        ok(&[("string", "version"), ("string", "name")]),
        Some(Error::BadDomain)
    );
    assert_eq!(
        Typed::parse(&build(&[t], 0, &[])).err(),
        Some(Error::NoDomain)
    );
    assert_eq!(
        Typed::parse(&build(&[DOM, t], 0, &[])).err(),
        Some(Error::BadPrimary)
    );
    assert_eq!(
        Typed::parse(&build(&[DOM, t], 2, &[])).err(),
        Some(Error::BadPrimary)
    );
}

#[test]
fn names_are_identifiers_and_used_once() {
    let parse = |types: &[(&str, &[(&str, &str)])]| Typed::parse(&build(types, 1, &[])).err();
    assert_eq!(parse(&[DOM, ("T", &[])]), None);
    assert_eq!(
        parse(&[DOM, ("T", &[]), ("T", &[])]),
        Some(Error::Duplicate)
    );
    assert_eq!(
        parse(&[DOM, ("T", &[("bool", "a"), ("bool", "a")])]),
        Some(Error::Duplicate)
    );
    assert_eq!(parse(&[DOM, ("", &[])]), Some(Error::BadName));
    assert_eq!(parse(&[DOM, ("1T", &[])]), Some(Error::BadName));
    assert_eq!(parse(&[DOM, ("T(", &[])]), Some(Error::BadName));
    assert_eq!(parse(&[DOM, ("uint8", &[])]), Some(Error::BadName));
    assert_eq!(
        parse(&[DOM, ("T", &[("bool", "a b")])]),
        Some(Error::BadName)
    );
    assert_eq!(
        parse(&[DOM, ("T", &[("bool", "a,bool b")])]),
        Some(Error::BadName)
    );
    let mut b = build(&[DOM, ("T", &[])], 1, &[]);
    b[0] = 2;
    assert_eq!(Typed::parse(&b).err(), Some(Error::Version));
}

#[test]
fn depth_is_bounded_and_a_type_that_holds_itself_ends() {
    // A list of itself: the types are fine, and the values decide how deep it goes.
    let node: (&str, &[(&str, &str)]) = ("Node", &[("Node[]", "kids")]);
    let mut values = DOM_VALUE.to_vec();
    values.extend_from_slice(&[1, 0, 1, 0, 0, 0]);
    let (_, rows) = walk(&build(&[DOM, node], 1, &values)).unwrap();
    assert_eq!(rows[1], "M kids[0].kids[0].kids = (empty)");
    let mut values = DOM_VALUE.to_vec();
    for _ in 0..MAX_DEPTH {
        values.extend_from_slice(&[1, 0]);
    }
    values.extend_from_slice(&[0, 0]);
    assert_eq!(
        walk(&build(&[DOM, node], 1, &values)).err(),
        Some(Error::TooDeep)
    );
    // An array type nested past the bound is refused with the types.
    assert_eq!(
        with("uint8[][][][][][][][]", &[]).err(),
        Some(Error::TooDeep)
    );
}

#[test]
fn the_digest_is_never_a_transactions_or_a_personal_messages() {
    // What is hashed begins 0x19 0x01: not RLP, not a typed envelope, and not the 0x19
    // 0x45 ("E") a personal_sign digest begins with.
    assert_ne!(crate::personal::PREFIX[1], 0x01);
    assert!(crate::parse(&[0x19, 0x01]).is_err());
}
