//! Per-card parameters for whole-card SD encryption, kept in the settings, keyed by the
//! card's serial number.
//!
//! # What is stored, and why it is device-bound
//!
//! When a card is encrypted, the device records under [`KEY`] a small object *per card
//! serial*: the KDF salt, the iteration count, and a verifier. It does **not** store the
//! key. The store lives in this device's own settings on internal flash, so the record
//! exists only here -- which is what makes an encrypted card readable only on the device
//! that encrypted it, on top of the ciphertext being unreadable anywhere without the
//! password. The verifier lets [`verify`] tell a right password from a wrong one before
//! the derived key is trusted to decrypt anything.
//!
//! # The key derivation
//!
//! The password (a separately-entered one, or the wallet's BIP-39 passphrase) is stretched
//! with PBKDF2-HMAC-SHA256 (RFC 8018 §5.2) over the per-card salt and iteration count into
//! 48 bytes: the first 32 are the AES-128-XTS key K1 ‖ K2, the last 16 are the verifier.
//! The three come from independent PBKDF2 output blocks, so the stored verifier reveals
//! nothing about the key beyond what an offline password guess already would -- and the
//! iteration count is the cost of each such guess. A memory-hard KDF (scrypt/Argon2) would
//! be stronger but does not fit the device's ~32 KB heap, so the defence is the iteration
//! count, stored per card so a later firmware can raise it without stranding old cards.
//!
//! # Not a stock key
//!
//! [`KEY`] (`ccenc`) is this firmware's own; stock has no such feature and no such key, so
//! a device that has been stock keeps whatever it had. `[?]` -- as with the other stores,
//! stock's own layout, if it ever grows one, is not something this can know.
//!
//! Source: RFC 8018 (PBKDF2), IEEE 1619 (XTS key is K1 ‖ K2). [C]

use crate::json::Doc;
use purecrypto::ct::ConstantTimeEq;
use purecrypto::hash::Sha256;
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

/// Where the map of per-card parameters lives in a settings object. **Not** a stock key.
pub const KEY: &str = "ccenc";

/// Salt length, in bytes. 128 bits of per-card salt, drawn fresh at encryption time.
pub const SALT_LEN: usize = 16;

/// Verifier length, in bytes. 128 bits is ample to make a wrong password's collision
/// chance negligible; it is a check value, not a key.
pub const VERIFIER_LEN: usize = 16;

/// The AES-128-XTS key length this derives: K1 (16) ‖ K2 (16).
pub const XTS_KEY_LEN: usize = 32;

/// Bytes PBKDF2 produces: the XTS key then the verifier.
const DERIVE_LEN: usize = XTS_KEY_LEN + VERIFIER_LEN;

/// Default PBKDF2 iteration count for a newly-encrypted card.
///
/// A deliberate balance for a hardware wallet: the KDF runs in software (no SHA-256
/// accelerator on these parts) over a ~32 KB heap that rules out a memory-hard KDF, and
/// unlocking is a rare, deliberate action where a few seconds is acceptable -- while
/// encrypting rewrites the whole card, next to which the stretch is nothing. The count is
/// stored per card ([`Params::iterations`]), so raising this default never invalidates a
/// card written under the old one, and a future firmware on faster silicon can raise it.
pub const DEFAULT_ITERATIONS: u32 = 200_000;

/// Most cards one device keeps parameters for at once. Bounds the JSON so the `ccenc`
/// value cannot crowd out the rest of a settings slot.
pub const MAX_CARDS: usize = 8;

/// Why a parameter operation failed.
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub enum Error {
    /// The stored (or supplied) parameters were not the shape this expects.
    Malformed,
    /// `iterations` was zero -- PBKDF2 requires at least one round.
    ZeroIterations,
    /// More than [`MAX_CARDS`] would be stored.
    TooMany,
    /// The render buffer was too small.
    Overflow,
}

/// One card's stored parameters. Public values -- salt, count and a verifier -- so this is
/// plain data, not a secret; the secret is the key it never holds.
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub struct Params {
    pub salt: [u8; SALT_LEN],
    pub iterations: u32,
    pub verifier: [u8; VERIFIER_LEN],
}

/// A derived AES-128-XTS key: K1 (data) and K2 (tweak). Wiped on drop.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct DerivedKey {
    pub k1: [u8; 16],
    pub k2: [u8; 16],
}

/// Stretch `password` with the given `salt` and `iterations`, returning the XTS key and
/// the verifier. The 48-byte PBKDF2 output is wiped before return; only the split parts
/// leave, the key inside a `ZeroizeOnDrop` holder.
fn stretch(
    password: &[u8],
    salt: &[u8; SALT_LEN],
    iterations: u32,
) -> Result<(DerivedKey, [u8; VERIFIER_LEN]), Error> {
    if iterations == 0 {
        return Err(Error::ZeroIterations);
    }
    let mut out = Zeroizing::new([0u8; DERIVE_LEN]);
    // Fixed 48-byte output and non-zero iterations, so this cannot hit either fallible
    // path; treat any error defensively rather than unwrapping.
    purecrypto::kdf::try_pbkdf2::<Sha256>(password, salt, iterations, out.as_mut_slice())
        .map_err(|_| Error::ZeroIterations)?;

    let mut key = DerivedKey {
        k1: [0u8; 16],
        k2: [0u8; 16],
    };
    key.k1.copy_from_slice(&out[..16]);
    key.k2.copy_from_slice(&out[16..32]);
    let mut verifier = [0u8; VERIFIER_LEN];
    verifier.copy_from_slice(&out[32..DERIVE_LEN]);
    // `out` wipes on drop; the verifier is not a secret.
    Ok((key, verifier))
}

/// Fresh parameters for encrypting a card under `password`: derive, and keep the verifier
/// (never the key) alongside the salt and count. Returns the key too, for the caller to
/// use immediately and then drop.
pub fn new_params(
    password: &[u8],
    salt: [u8; SALT_LEN],
    iterations: u32,
) -> Result<(Params, DerivedKey), Error> {
    let (key, verifier) = stretch(password, &salt, iterations)?;
    Ok((
        Params {
            salt,
            iterations,
            verifier,
        },
        key,
    ))
}

/// Check `password` against stored `params`; on a match, hand back the derived key.
///
/// The verifier comparison is constant time, so a wrong password reveals nothing beyond
/// the verdict. `None` is a wrong password (or a card whose parameters do not verify).
pub fn verify(params: &Params, password: &[u8]) -> Option<DerivedKey> {
    let (key, verifier) = stretch(password, &params.salt, params.iterations).ok()?;
    if bool::from(verifier.ct_eq(&params.verifier)) {
        Some(key)
    } else {
        // Drop the derived key without returning it; the password was wrong.
        None
    }
}

/// Read one card's parameters out of a settings document.
///
/// `None` when this card has none (the common case), or when the map is absent. A
/// malformed entry for the asked-for serial is [`Error::Malformed`] rather than silently
/// `None`, so a corrupt record is not mistaken for "never encrypted".
pub fn get(doc: &Doc<'_>, serial: u32) -> Result<Option<Params>, Error> {
    let Some(map_raw) = doc.get(KEY) else {
        return Ok(None);
    };
    let map = Doc::parse(map_raw.as_bytes()).map_err(|_| Error::Malformed)?;
    let key = SerialKey::new(serial);
    let Some(entry_raw) = map.get(key.as_str()) else {
        return Ok(None);
    };
    parse_params(entry_raw).map(Some)
}

/// Whether the map already holds parameters for `serial`.
pub fn contains(doc: &Doc<'_>, serial: u32) -> bool {
    matches!(get(doc, serial), Ok(Some(_)))
}

/// The map with `serial`'s parameters added or replaced, rendered as the JSON object that
/// goes under [`KEY`]. Every other card's entry is carried through verbatim.
///
/// `existing` is the current map's raw text (an [`crate::json::Doc`] value under [`KEY`]),
/// or `None`/empty for a device with no map yet.
pub fn with_set(
    existing: Option<&str>,
    serial: u32,
    params: &Params,
    out: &mut [u8],
) -> Result<usize, Error> {
    render(existing, Some((serial, params)), None, out)
}

/// The map with `serial`'s parameters removed, rendered as JSON. Other cards are kept.
pub fn without(existing: Option<&str>, serial: u32, out: &mut [u8]) -> Result<usize, Error> {
    render(existing, None, Some(serial), out)
}

/// Render the map: every existing entry except `remove` and except any `add` (which is
/// re-emitted at the end), then `add` if given. `{}` when nothing is left.
fn render(
    existing: Option<&str>,
    add: Option<(u32, &Params)>,
    remove: Option<u32>,
    out: &mut [u8],
) -> Result<usize, Error> {
    let doc = match existing {
        Some(raw) if !raw.is_empty() && raw != "{}" => {
            Doc::parse(raw.as_bytes()).map_err(|_| Error::Malformed)?
        }
        _ => Doc::new(),
    };

    // Which serials are dropped from the carried-through set: the one being removed, and
    // the one being (re-)added (so a replace does not duplicate it).
    let mut add_key = add.map(|(s, _)| SerialKey::new(s));
    let mut remove_key = remove.map(SerialKey::new);
    let skip = |k: &str, add_key: &mut Option<SerialKey>, remove_key: &mut Option<SerialKey>| {
        add_key.as_ref().is_some_and(|s| s.as_str() == k)
            || remove_key.as_ref().is_some_and(|s| s.as_str() == k)
    };

    let mut w = Writer::new(out);
    w.put("{")?;

    let mut count = 0usize;
    let mut first = true;
    for e in doc.entries() {
        if skip(e.key, &mut add_key, &mut remove_key) {
            continue;
        }
        if count >= MAX_CARDS {
            return Err(Error::TooMany);
        }
        if !first {
            w.put(",")?;
        }
        first = false;
        w.put("\"")?;
        w.put(e.key)?;
        w.put("\":")?;
        w.put(e.raw)?;
        count += 1;
    }

    if let Some((serial, params)) = add {
        if count >= MAX_CARDS {
            return Err(Error::TooMany);
        }
        if !first {
            w.put(",")?;
        }
        let key = SerialKey::new(serial);
        w.put("\"")?;
        w.put(key.as_str())?;
        w.put("\":")?;
        write_params(&mut w, params)?;
    }

    w.put("}")?;
    Ok(w.len())
}

/// Parse one `{"s":..,"i":..,"v":..}` entry.
fn parse_params(raw: &str) -> Result<Params, Error> {
    let d = Doc::parse(raw.as_bytes()).map_err(|_| Error::Malformed)?;
    let salt_hex = d.get_str("s").ok_or(Error::Malformed)?;
    let ver_hex = d.get_str("v").ok_or(Error::Malformed)?;
    let iterations =
        u32::try_from(d.get_u64("i").ok_or(Error::Malformed)?).map_err(|_| Error::Malformed)?;
    if iterations == 0 {
        return Err(Error::ZeroIterations);
    }
    let mut salt = [0u8; SALT_LEN];
    let mut verifier = [0u8; VERIFIER_LEN];
    hex_decode(salt_hex, &mut salt)?;
    hex_decode(ver_hex, &mut verifier)?;
    Ok(Params {
        salt,
        iterations,
        verifier,
    })
}

/// Write one entry's object: `{"s":"<hex salt>","i":<iter>,"v":"<hex verifier>"}`.
fn write_params(w: &mut Writer<'_>, p: &Params) -> Result<(), Error> {
    let mut salt_hex = [0u8; SALT_LEN * 2];
    let mut ver_hex = [0u8; VERIFIER_LEN * 2];
    hex_encode(&p.salt, &mut salt_hex);
    hex_encode(&p.verifier, &mut ver_hex);
    let mut iter_text: heapless::String<10> = heapless::String::new();
    {
        use core::fmt::Write as _;
        let _ = write!(iter_text, "{}", p.iterations);
    }
    w.put("{\"s\":\"")?;
    w.put(core::str::from_utf8(&salt_hex).map_err(|_| Error::Malformed)?)?;
    w.put("\",\"i\":")?;
    w.put(&iter_text)?;
    w.put(",\"v\":\"")?;
    w.put(core::str::from_utf8(&ver_hex).map_err(|_| Error::Malformed)?)?;
    w.put("\"}")?;
    Ok(())
}

/// A card serial rendered as a decimal string, for use as a JSON key.
struct SerialKey {
    buf: heapless::String<10>,
}

impl SerialKey {
    fn new(serial: u32) -> Self {
        use core::fmt::Write as _;
        let mut buf = heapless::String::new();
        let _ = write!(buf, "{serial}");
        Self { buf }
    }
    fn as_str(&self) -> &str {
        self.buf.as_str()
    }
}

/// A bounds-checked byte writer into a caller buffer.
struct Writer<'a> {
    out: &'a mut [u8],
    at: usize,
}

impl<'a> Writer<'a> {
    fn new(out: &'a mut [u8]) -> Self {
        Self { out, at: 0 }
    }
    fn put(&mut self, s: &str) -> Result<(), Error> {
        let end = self.at + s.len();
        self.out
            .get_mut(self.at..end)
            .ok_or(Error::Overflow)?
            .copy_from_slice(s.as_bytes());
        self.at = end;
        Ok(())
    }
    fn len(&self) -> usize {
        self.at
    }
}

/// Lowercase-hex encode `bytes` into `out`, which must be exactly `2 * bytes.len()`.
fn hex_encode(bytes: &[u8], out: &mut [u8]) {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    for (i, b) in bytes.iter().enumerate() {
        out[i * 2] = HEX[(b >> 4) as usize];
        out[i * 2 + 1] = HEX[(b & 0xF) as usize];
    }
}

/// Decode lowercase- or uppercase-hex `text` into `out`, which fixes the byte count.
/// [`Error::Malformed`] on the wrong length or a non-hex character.
fn hex_decode(text: &str, out: &mut [u8]) -> Result<(), Error> {
    let bytes = text.as_bytes();
    if bytes.len() != out.len() * 2 {
        return Err(Error::Malformed);
    }
    for (i, slot) in out.iter_mut().enumerate() {
        let hi = nibble(bytes[i * 2])?;
        let lo = nibble(bytes[i * 2 + 1])?;
        *slot = (hi << 4) | lo;
    }
    Ok(())
}

fn nibble(c: u8) -> Result<u8, Error> {
    match c {
        b'0'..=b'9' => Ok(c - b'0'),
        b'a'..=b'f' => Ok(c - b'a' + 10),
        b'A'..=b'F' => Ok(c - b'A' + 10),
        _ => Err(Error::Malformed),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const SALT: [u8; SALT_LEN] = [0x5A; SALT_LEN];

    #[test]
    fn the_same_password_and_params_derive_the_same_key() {
        let a = stretch(b"open sesame", &SALT, 4096).unwrap();
        let b = stretch(b"open sesame", &SALT, 4096).unwrap();
        assert_eq!(a.0.k1, b.0.k1);
        assert_eq!(a.0.k2, b.0.k2);
        assert_eq!(a.1, b.1, "verifier is deterministic");
        // K1 and K2 are independent PBKDF2 blocks, so they must not coincide -- an XTS key
        // with equal halves would be refused by the cipher.
        assert_ne!(a.0.k1, a.0.k2);
    }

    #[test]
    fn a_different_password_or_salt_derives_a_different_key() {
        let base = stretch(b"pw", &SALT, 4096).unwrap();
        let other_pw = stretch(b"PW", &SALT, 4096).unwrap();
        assert_ne!(base.0.k1, other_pw.0.k1);
        let other_salt = stretch(b"pw", &[0x01; SALT_LEN], 4096).unwrap();
        assert_ne!(base.0.k1, other_salt.0.k1);
    }

    #[test]
    fn verify_accepts_the_right_password_and_rejects_a_wrong_one() {
        let (params, key) = new_params(b"correct horse", SALT, 4096).unwrap();
        let good = verify(&params, b"correct horse").expect("right password verifies");
        assert_eq!(good.k1, key.k1);
        assert_eq!(good.k2, key.k2);
        assert!(
            verify(&params, b"wrong horse").is_none(),
            "a wrong password must not verify"
        );
    }

    #[test]
    fn zero_iterations_is_refused() {
        // `DerivedKey` has no `Debug`/`PartialEq` (it is a secret), so match on the error.
        assert!(matches!(
            stretch(b"pw", &SALT, 0),
            Err(Error::ZeroIterations)
        ));
        assert!(matches!(
            new_params(b"pw", SALT, 0),
            Err(Error::ZeroIterations)
        ));
    }

    #[test]
    fn params_round_trip_through_the_json_map() {
        let (params, _key) = new_params(b"pw", SALT, 12345).unwrap();
        let serial = 0x1234_5678u32;

        let mut buf = [0u8; 256];
        let n = with_set(None, serial, &params, &mut buf).unwrap();
        let map_text = core::str::from_utf8(&buf[..n]).unwrap();

        // Wrap it as it would sit in a settings blob, then read it back.
        let blob = std::format!("{{\"{KEY}\":{map_text}}}");
        let doc = Doc::parse(blob.as_bytes()).unwrap();
        let got = get(&doc, serial).unwrap().expect("the entry is there");
        assert_eq!(got, params);
        assert!(contains(&doc, serial));
        assert!(
            get(&doc, 999).unwrap().is_none(),
            "a stranger serial is absent"
        );
    }

    #[test]
    fn two_cards_coexist_and_one_can_be_removed() {
        let (p1, _) = new_params(b"one", [1; SALT_LEN], 4096).unwrap();
        let (p2, _) = new_params(b"two", [2; SALT_LEN], 4096).unwrap();

        let mut buf = [0u8; 512];
        let n = with_set(None, 111, &p1, &mut buf).unwrap();
        let step1 = std::string::String::from(core::str::from_utf8(&buf[..n]).unwrap());
        let n = with_set(Some(&step1), 222, &p2, &mut buf).unwrap();
        let both = std::string::String::from(core::str::from_utf8(&buf[..n]).unwrap());

        let blob = std::format!("{{\"{KEY}\":{both}}}");
        let doc = Doc::parse(blob.as_bytes()).unwrap();
        assert_eq!(get(&doc, 111).unwrap().unwrap(), p1);
        assert_eq!(get(&doc, 222).unwrap().unwrap(), p2);

        // Remove the first; the second survives.
        let n = without(Some(&both), 111, &mut buf).unwrap();
        let left = std::string::String::from(core::str::from_utf8(&buf[..n]).unwrap());
        let blob = std::format!("{{\"{KEY}\":{left}}}");
        let doc = Doc::parse(blob.as_bytes()).unwrap();
        assert!(get(&doc, 111).unwrap().is_none());
        assert_eq!(get(&doc, 222).unwrap().unwrap(), p2);
    }

    #[test]
    fn replacing_a_serial_does_not_duplicate_it() {
        let (p1, _) = new_params(b"one", [1; SALT_LEN], 4096).unwrap();
        let (p2, _) = new_params(b"one-again", [9; SALT_LEN], 8192).unwrap();
        let mut buf = [0u8; 512];
        let n = with_set(None, 42, &p1, &mut buf).unwrap();
        let first = std::string::String::from(core::str::from_utf8(&buf[..n]).unwrap());
        let n = with_set(Some(&first), 42, &p2, &mut buf).unwrap();
        let second = core::str::from_utf8(&buf[..n]).unwrap();
        // Exactly one entry for serial 42, holding the new params.
        assert_eq!(second.matches("\"42\":").count(), 1);
        let blob = std::format!("{{\"{KEY}\":{second}}}");
        let doc = Doc::parse(blob.as_bytes()).unwrap();
        assert_eq!(get(&doc, 42).unwrap().unwrap(), p2);
    }

    #[test]
    fn an_empty_map_renders_and_parses_as_empty() {
        let mut buf = [0u8; 8];
        let n = without(None, 1, &mut buf).unwrap();
        assert_eq!(&buf[..n], b"{}");
    }

    #[test]
    fn a_malformed_entry_is_reported_not_silently_absent() {
        let blob = std::format!("{{\"{KEY}\":{{\"7\":{{\"s\":\"zz\",\"i\":1,\"v\":\"00\"}}}}}}");
        let doc = Doc::parse(blob.as_bytes()).unwrap();
        assert_eq!(get(&doc, 7), Err(Error::Malformed));
    }
}
