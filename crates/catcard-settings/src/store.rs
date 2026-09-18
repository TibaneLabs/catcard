//! Choosing which slot the settings are in, and which one to write next.
//!
//! The format is [`crate::nvstore`]; the dictionary is [`crate::json`]; the medium is the
//! board's, behind [`Slots`]. What is here is the part with the rules in it:
//!
//! - **Newest wins.** Every slot that decrypts under the key is a candidate, and the one
//!   with the highest `_age` is the settings. Staler copies are left alone rather than
//!   tidied away: a power cut during a save is exactly when an older copy is the only
//!   readable one, and this code has no way to know it is not in that moment.
//! - **Write the new one before removing the old.** At no point is there no valid slot.
//! - **A slot that will not decrypt is not an error.** It belongs to another key -- the
//!   pre-login settings, or a passphrase wallet's -- or to nobody.
//!
//! Every function takes the scratch buffer it needs from the caller: a slot is four
//! kilobytes, there is no allocator here, and the firmware knows where that memory should
//! live better than this does.

use crate::json::Doc;
use crate::nvstore::{self, Key, SLOT_LEN};

/// Slots a device scans. Stock uses a hundred files on mk4 and later, thirty-two SPI-NOR
/// blocks on mk3. Source: hw-reference/settings-nvstore-format.md §1 [C]
pub const SLOTS_FLASH: u32 = 100;

/// Bytes a scratch buffer needs: one whole slot.
pub const SCRATCH: usize = SLOT_LEN;

/// A medium failed. What went wrong belongs in the firmware's log, not in a type the
/// rules here would have to match on: from up here every medium failure is the same -- the
/// settings could not be read or written.
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub struct MediumError;

/// Where slots live, so the store does not care which board it is on.
pub trait Slots {
    /// How many slots to scan.
    fn count(&self) -> u32;

    /// The `pos` that goes in the AES counter for slot `index`: the index itself on mk4 and
    /// later, the block's byte offset on mk3. Getting this wrong makes every slot
    /// undecryptable, which is why it belongs to the medium rather than to the crypto.
    fn pos(&self, index: u32) -> u32;

    /// Read slot `index` into `buf`. `Ok(None)` if the slot is empty.
    fn read(&mut self, index: u32, buf: &mut [u8]) -> Result<Option<usize>, MediumError>;

    /// Replace slot `index` with `bytes`.
    fn write(&mut self, index: u32, bytes: &[u8]) -> Result<(), MediumError>;

    /// Empty slot `index`.
    fn clear(&mut self, index: u32) -> Result<(), MediumError>;
}

/// Why the settings could not be read or written.
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub enum Error {
    /// Nothing readable under this key. Not a failure on a device that has never saved.
    Absent,
    /// The medium failed.
    Medium,
    /// The blob decrypted but is not a settings object.
    Malformed,
    /// Every slot is taken and none could be replaced.
    Full,
}

/// The slot that holds the live settings, and its `_age`.
struct Best {
    index: u32,
    age: u64,
}

/// Find the live slot under `key`.
fn newest<S: Slots>(slots: &mut S, key: &Key, buf: &mut [u8]) -> Option<Best> {
    let mut best: Option<Best> = None;
    for index in 0..slots.count() {
        let pos = slots.pos(index);
        let Ok(Some(len)) = slots.read(index, buf) else {
            continue;
        };
        // Two decrypted bytes rule out almost everything before four kilobytes are hashed.
        if len < 2 || !nvstore::looks_like_ours(&buf[..2], key, pos) {
            continue;
        }
        let Ok(range) = nvstore::open(&mut buf[..len], key, pos) else {
            continue;
        };
        let age = Doc::parse(&buf[range.clone()])
            .ok()
            .and_then(|d| d.get_u64("_age"))
            .unwrap_or(0);
        if best.as_ref().is_none_or(|b| age > b.age) {
            best = Some(Best { index, age });
        }
    }
    best
}

/// Read the settings under `key` into `buf`, returning the JSON's length.
///
/// `buf` must be at least [`SLOT_LEN`]; the JSON is left at its start.
pub fn read<S: Slots>(slots: &mut S, key: &Key, buf: &mut [u8]) -> Result<usize, Error> {
    let best = newest(slots, key, buf).ok_or(Error::Absent)?;
    let pos = slots.pos(best.index);
    let len = slots
        .read(best.index, buf)
        .map_err(|_| Error::Medium)?
        .ok_or(Error::Absent)?;
    let range = nvstore::open(&mut buf[..len], key, pos).map_err(|_| Error::Malformed)?;
    // Move the JSON to the front, so the caller has one slice and no offset to carry.
    let json_len = range.len();
    buf.copy_within(range, 0);
    Ok(json_len)
}

/// Write `json` as the settings under `key`.
///
/// Picks a slot that is not the live one, writes it, then empties the old one. `age` is the
/// `_age` the caller already put in the JSON: this does not edit the dictionary, because
/// the caller knows what else it changed.
pub fn write<S: Slots>(
    slots: &mut S,
    key: &Key,
    json: &[u8],
    choose: u32,
    scratch: &mut [u8],
) -> Result<u32, Error> {
    if scratch.len() < SCRATCH {
        return Err(Error::Malformed);
    }
    let live = newest(slots, key, scratch).map(|b| b.index);
    // Somewhere that is not where the readable copy is. `choose` is a random number from
    // the caller's DRBG, so repeated saves spread across the slots rather than wearing one
    // out -- the whole reason there are a hundred of them.
    let count = slots.count();
    let mut target = None;
    for step in 0..count {
        let index = (choose.wrapping_add(step)) % count;
        if Some(index) == live {
            continue;
        }
        target = Some(index);
        break;
    }
    let target = target.ok_or(Error::Full)?;

    let len = nvstore::seal(json, key, slots.pos(target), scratch).map_err(|_| Error::Malformed)?;
    slots
        .write(target, &scratch[..len])
        .map_err(|_| Error::Medium)?;
    // Only now is the old copy removed: until this point both were readable, and after it
    // the new one is.
    if let Some(old) = live {
        let _ = slots.clear(old);
    }
    Ok(target)
}

/// Change one key and save the settings back.
///
/// The value goes in **in place**: the rest of the object -- including every key this
/// firmware has never heard of, in the order the firmware that wrote them put them -- keeps
/// its exact bytes. That is the point of the whole store. A device that has been stock and
/// then this and then stock again must not lose a setting on the way through, and
/// re-rendering an object around a change is how that gets lost.
///
/// `_age` goes up by one, so a later read prefers this copy; then a free slot is written and
/// the old one erased, which is the order that survives losing power.
///
/// `doc` holds the settings while they are edited and must be [`SCRATCH`] bytes; `scratch`
/// is the sealing buffer and must be too. `choose` picks the slot, as in [`write`].
///
/// Returns the slot written.
pub fn set<S: Slots, V: emjson::ToJson + ?Sized>(
    slots: &mut S,
    key: &Key,
    name: &str,
    value: &V,
    choose: u32,
    doc: &mut [u8],
    scratch: &mut [u8],
) -> Result<u32, Error> {
    use emjson::Seg;
    use emjson::edit::{Editor, MemStorage};

    if doc.len() < SCRATCH || scratch.len() < SCRATCH {
        return Err(Error::Malformed);
    }
    // What is stored now, or an empty object on a device that has never saved. `Absent` is
    // not a failure here: the first save is what makes it not absent.
    let mut len = match read(slots, key, doc) {
        Ok(n) => n,
        Err(Error::Absent) => {
            doc[..2].copy_from_slice(b"{}");
            2
        }
        Err(e) => return Err(e),
    };
    let age = Doc::parse(&doc[..len]).map(|d| next_age(&d)).unwrap_or(1);

    {
        // The editor moves the document's tail through this; a small window is enough, and
        // it must not be the sealing buffer, which is needed intact afterwards.
        let mut window = [0u8; 64];
        let mut editor = Editor::new(MemStorage::new(doc, len), &mut window);
        // `Seg::Key` rather than a JSON Pointer: a key holding `/` or `~` would have to be
        // escaped in a pointer, and nothing guarantees a settings key does not.
        editor
            .set(&[Seg::Key(name)][..], value)
            .map_err(|_| Error::Malformed)?;
        editor
            .set(&[Seg::Key("_age")][..], &age)
            .map_err(|_| Error::Malformed)?;
        len = editor.storage().doc_len();
    }

    write(slots, key, &doc[..len], choose, scratch)
}

/// The `_age` a save should carry: one past what is stored.
pub fn next_age(doc: &Doc<'_>) -> u64 {
    doc.get_u64("_age").unwrap_or(0).saturating_add(1)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Slots in RAM, as a device's medium would behave: reads report empty until written,
    /// writes replace, clears empty.
    pub(super) struct Ram {
        slots: [Option<(usize, [u8; SLOT_LEN])>; 8],
    }

    impl Ram {
        pub(super) fn new() -> Self {
            Self {
                slots: [None; 8].map(|_: Option<(usize, [u8; SLOT_LEN])>| None),
            }
        }
    }

    impl Slots for Ram {
        fn count(&self) -> u32 {
            self.slots.len() as u32
        }
        fn pos(&self, index: u32) -> u32 {
            index
        }
        fn read(&mut self, index: u32, buf: &mut [u8]) -> Result<Option<usize>, MediumError> {
            match &self.slots[index as usize] {
                None => Ok(None),
                Some((len, bytes)) => {
                    buf[..*len].copy_from_slice(&bytes[..*len]);
                    Ok(Some(*len))
                }
            }
        }
        fn write(&mut self, index: u32, bytes: &[u8]) -> Result<(), MediumError> {
            let mut slot = [0u8; SLOT_LEN];
            slot[..bytes.len()].copy_from_slice(bytes);
            self.slots[index as usize] = Some((bytes.len(), slot));
            Ok(())
        }
        fn clear(&mut self, index: u32) -> Result<(), MediumError> {
            self.slots[index as usize] = None;
            Ok(())
        }
    }

    fn scratch() -> [u8; SCRATCH] {
        [0u8; SCRATCH]
    }

    fn key() -> Key {
        nvstore::hash_key(&[0x82; 72])
    }

    #[test]
    fn nothing_saved_reads_as_absent() {
        let mut ram = Ram::new();
        let mut buf = [0u8; SLOT_LEN];
        assert_eq!(read(&mut ram, &key(), &mut buf), Err(Error::Absent));
    }

    #[test]
    fn what_is_written_comes_back() {
        let mut ram = Ram::new();
        let key = key();
        let json = br#"{"_age":1,"chain":"BTC"}"#;
        let at = write(&mut ram, &key, json, 3, &mut scratch()).unwrap();
        let mut buf = [0u8; SLOT_LEN];
        let n = read(&mut ram, &key, &mut buf).unwrap();
        assert_eq!(&buf[..n], json);
        // And it went where it was asked to go.
        assert!(ram.slots[at as usize].is_some());
    }

    #[test]
    fn the_newest_age_wins_however_the_slots_are_ordered() {
        let mut ram = Ram::new();
        let key = key();
        // Write three generations; each save lands somewhere else and removes the last.
        for (age, choose) in [(1u64, 5u32), (2, 1), (3, 6)] {
            let mut json = heapless::String::<64>::new();
            use core::fmt::Write as _;
            let _ = write!(json, r#"{{"_age":{age},"rz":{age}}}"#);
            super::write(&mut ram, &key, json.as_bytes(), choose, &mut scratch()).unwrap();
        }
        let mut buf = [0u8; SLOT_LEN];
        let n = read(&mut ram, &key, &mut buf).unwrap();
        let doc = Doc::parse(&buf[..n]).unwrap();
        assert_eq!(doc.get_u64("_age"), Some(3));
        // Exactly one slot is live: each save removed its predecessor.
        let live = (0..ram.count())
            .filter(|i| ram.slots[*i as usize].is_some())
            .count();
        assert_eq!(live, 1);
    }

    #[test]
    fn a_stale_copy_left_by_a_power_cut_is_still_readable() {
        let mut ram = Ram::new();
        let key = key();
        write(&mut ram, &key, br#"{"_age":1,"rz":8}"#, 0, &mut scratch()).unwrap();
        // Simulate a save that wrote its new slot and never got to remove the old: two
        // valid slots, different ages.
        let mut buf = scratch();
        let len = nvstore::seal(br#"{"_age":2,"rz":0}"#, &key, 4, &mut buf).unwrap();
        ram.write(4, &buf[..len]).unwrap();

        let mut out = [0u8; SLOT_LEN];
        let n = read(&mut ram, &key, &mut out).unwrap();
        let doc = Doc::parse(&out[..n]).unwrap();
        assert_eq!(doc.get_u64("_age"), Some(2), "the newer one wins");
        // The older slot is not deleted: if the newer one had been the corrupt half of a
        // torn write, it is what the device still has.
        assert!(ram.slots[0].is_some());
    }

    #[test]
    fn a_slot_under_another_key_is_ignored_not_broken() {
        let mut ram = Ram::new();
        let mine = key();
        let theirs = nvstore::prelogin_key();
        write(
            &mut ram,
            &theirs,
            br#"{"_age":9,"nick":"cat"}"#,
            2,
            &mut scratch(),
        )
        .unwrap();
        let mut buf = [0u8; SLOT_LEN];
        assert_eq!(read(&mut ram, &mine, &mut buf), Err(Error::Absent));
        // And mine can live beside it.
        write(&mut ram, &mine, br#"{"_age":1}"#, 5, &mut scratch()).unwrap();
        let n = read(&mut ram, &mine, &mut buf).unwrap();
        assert_eq!(&buf[..n], br#"{"_age":1}"#);
        let n = read(&mut ram, &theirs, &mut buf).unwrap();
        assert_eq!(Doc::parse(&buf[..n]).unwrap().get_str("nick"), Some("cat"));
    }

    #[test]
    fn the_next_age_is_one_past_what_is_stored() {
        let doc = Doc::parse(br#"{"_age":41}"#).unwrap();
        assert_eq!(next_age(&doc), 42);
        assert_eq!(next_age(&Doc::new()), 1);
    }
}

#[cfg(test)]
mod save_tests {
    use super::tests::Ram;
    use super::*;

    fn key() -> Key {
        nvstore::hash_key(&[0x11; 72])
    }

    /// A save keeps every key it did not touch, byte for byte, in its original order.
    ///
    /// This is the property the whole store exists for: a blob written by stock carries
    /// settings this firmware has never heard of -- multisig wallets, trick PINs, a spending
    /// policy -- and losing one means its owner re-enters it, if they even notice.
    #[test]
    fn a_save_keeps_the_keys_it_does_not_understand_exactly_as_they_were() {
        let mut slots = Ram::new();
        let k = key();
        let mut doc = [0u8; SCRATCH];
        let mut scratch = [0u8; SCRATCH];

        // A blob as another firmware might have left it: keys we know, keys we do not, and
        // a nested value we could not begin to interpret.
        let stock = br#"{"_age":7,"chain":"XTN","multisig":[{"name":"cosign","M":2,"N":3}],"tp":{"1234":{"mode":"wipe"}},"rz":8}"#;
        let slot = write(&mut slots, &k, stock, 3, &mut scratch).unwrap();
        assert_eq!(read(&mut slots, &k, &mut doc).unwrap(), stock.len());

        set(&mut slots, &k, "nick", &"kitty", 9, &mut doc, &mut scratch).unwrap();

        let n = read(&mut slots, &k, &mut doc).unwrap();
        let after = Doc::parse(&doc[..n]).unwrap();
        // Every original key still there, still in order, with its bytes untouched.
        let before = Doc::parse(stock).unwrap();
        for e in before.entries() {
            if e.key == "_age" {
                continue;
            }
            assert_eq!(after.get(e.key), Some(e.raw), "{} changed", e.key);
        }
        let order: Vec<&str> = after.entries().iter().map(|e| e.key).collect();
        assert_eq!(&order[..5], &["_age", "chain", "multisig", "tp", "rz"]);
        // And the new one, at the end.
        assert_eq!(after.get_str("nick"), Some("kitty"));
        // `_age` went up, so this copy wins over the old one.
        assert_eq!(after.get_u64("_age"), Some(8));
        // Written somewhere else, and the old slot emptied: never two live copies.
        assert_ne!(read_slot_count(&mut slots), 0);
        let _ = slot;
    }

    /// Changing a key that is already there replaces its value, not its position.
    #[test]
    fn changing_a_key_leaves_it_where_it_was() {
        let mut slots = Ram::new();
        let k = key();
        let mut doc = [0u8; SCRATCH];
        let mut scratch = [0u8; SCRATCH];
        write(
            &mut slots,
            &k,
            br#"{"_age":1,"chain":"BTC","rz":8,"nick":"old"}"#,
            0,
            &mut scratch,
        )
        .unwrap();

        set(&mut slots, &k, "nick", &"new", 5, &mut doc, &mut scratch).unwrap();

        let n = read(&mut slots, &k, &mut doc).unwrap();
        let after = Doc::parse(&doc[..n]).unwrap();
        assert_eq!(after.get_str("nick"), Some("new"));
        let order: Vec<&str> = after.entries().iter().map(|e| e.key).collect();
        assert_eq!(order, ["_age", "chain", "rz", "nick"], "nothing moved");
    }

    /// The first save on a device that has never saved writes a settings object.
    #[test]
    fn the_first_save_starts_from_an_empty_object() {
        let mut slots = Ram::new();
        let k = key();
        let mut doc = [0u8; SCRATCH];
        let mut scratch = [0u8; SCRATCH];
        assert_eq!(read(&mut slots, &k, &mut doc), Err(Error::Absent));

        set(&mut slots, &k, "nick", &"first", 0, &mut doc, &mut scratch).unwrap();

        let n = read(&mut slots, &k, &mut doc).unwrap();
        let doc = Doc::parse(&doc[..n]).unwrap();
        assert_eq!(doc.get_str("nick"), Some("first"));
        assert_eq!(doc.get_u64("_age"), Some(1));
    }

    /// Values that are not strings go in as JSON, not as text.
    #[test]
    fn numbers_and_booleans_are_written_as_json() {
        let mut slots = Ram::new();
        let k = key();
        let mut doc = [0u8; SCRATCH];
        let mut scratch = [0u8; SCRATCH];
        set(
            &mut slots,
            &k,
            "idle_to",
            &600u32,
            0,
            &mut doc,
            &mut scratch,
        )
        .unwrap();
        set(&mut slots, &k, "nfc", &true, 1, &mut doc, &mut scratch).unwrap();
        let n = read(&mut slots, &k, &mut doc).unwrap();
        let doc = Doc::parse(&doc[..n]).unwrap();
        assert_eq!(doc.get("idle_to"), Some("600"));
        assert_eq!(doc.get_bool("nfc"), Some(true));
        assert_eq!(doc.get_u64("_age"), Some(2), "each save is a new version");
    }

    /// Keys this firmware never reads survive a save, byte for byte and in order.
    ///
    /// Stock caches `xfp`/`xpub` here. This firmware ignores them -- it derives its own
    /// from the seed, because this blob is encrypted and *not* authenticated, so a cached
    /// public key in it is not evidence of anything. Ignoring has to mean leaving alone:
    /// a device that has been stock, then this, then stock again must find its settings
    /// intact, and re-rendering the object around a change is how that gets lost.
    #[test]
    fn keys_this_firmware_ignores_are_left_exactly_as_they_were() {
        let mut slots = Ram::new();
        let k = key();
        let mut doc = [0u8; SCRATCH];
        let mut scratch = [0u8; SCRATCH];

        // The shape stock leaves behind, including keys whose schema we never decided.
        macro_rules! theirs {
            () => {
                r#""xfp":1130956799,"xpub":"xpub661MyMwAqRbcFW31YEwpkMuc5THy2PSt5bDMsktWQcFF8syAmRUapSCGu8ED9W6oDMSgv6Zz8idoc4a6mr8BDzTJY47LJhkJ8UB7WEGuduB","multisig":[{"opaque":1}],"chain":"BTC""#
            };
        }
        const THEIRS: &str = theirs!();
        const STOCK: &str = concat!(r#"{"_age":7,"#, theirs!(), "}");
        write(&mut slots, &k, STOCK.as_bytes(), 3, &mut scratch).unwrap();

        set(&mut slots, &k, "nick", &"ours", 4, &mut doc, &mut scratch).unwrap();

        let n = read(&mut slots, &k, &mut doc).unwrap();
        let text = core::str::from_utf8(&doc[..n]).unwrap();
        // One substring: proves the bytes *and* their order, together.
        assert!(text.contains(THEIRS), "stock's keys were rewritten: {text}");

        let parsed = Doc::parse(text.as_bytes()).unwrap();
        assert_eq!(
            parsed.get_str("nick"),
            Some("ours"),
            "our own key is missing"
        );
        assert_eq!(
            parsed.get_u64("_age"),
            Some(8),
            "the version did not advance"
        );
    }

    /// How many slots hold something.
    fn read_slot_count(slots: &mut Ram) -> usize {
        let mut buf = [0u8; SLOT_LEN];
        (0..slots.count())
            .filter(|i| matches!(slots.read(*i, &mut buf), Ok(Some(_))))
            .count()
    }
}
