//! The generic JSON wallet export, and the shapes built on it.
//!
//! One file serves seven menu entries -- Generic JSON, Sparrow, Cove, Nunchuk, Fully
//! Noded, Theya and Bitcoin Safe -- with identical bytes and only the filename
//! differing. It is the export most software asks for, because it carries every account
//! key a watch-only wallet might want along with a ready-made descriptor for each.
//!
//! Source: hw-reference/wallet-export-formats.md §"Format A" [C]. Field order matters:
//! the file is compared byte for byte against what other tooling expects, so the keys go
//! out in the order the reference lists them and nothing is pretty-printed.

use core::fmt::Write as _;

use catcard_wallet::bip32::serialize::Slip132;
use catcard_wallet::bip32::{ChildNumber, ExtendedPrivKey, ExtendedPubKey, Network};
use catcard_wallet::descriptor::{self, SingleSig};

use crate::display;
use crate::menu::{Working, public_at};

/// How the export names a script type, and everything that follows from it.
struct Entry {
    /// The JSON key: `bip44`, `bip49`, ...
    key: &'static str,
    /// The `name` field, which is the address type spelled the way the format spells it.
    name: &'static str,
    /// The purpose level, and for BIP-48 the script level below the account.
    purpose: u32,
    script: Option<u32>,
    /// Which SLIP-132 form this type is announced in, when it differs from classic.
    form: Slip132,
    /// Single-signature entries carry a first address and a finished descriptor;
    /// multisig entries carry a template with placeholders in it and no checksum.
    single: Option<catcard_wallet::address::AddressKind>,
    /// The descriptor wrapper for a multisig template.
    multi: Option<&'static str>,
}

/// The rows of the file, in the order the format lists them.
const ENTRIES: [Entry; 5] = [
    Entry {
        key: "bip44",
        name: "p2pkh",
        purpose: 44,
        script: None,
        form: Slip132::Classic,
        single: Some(catcard_wallet::address::AddressKind::P2pkh),
        multi: None,
    },
    Entry {
        key: "bip49",
        name: "p2sh-p2wpkh",
        purpose: 49,
        script: None,
        form: Slip132::P2wpkhP2sh,
        single: Some(catcard_wallet::address::AddressKind::P2shP2wpkh),
        multi: None,
    },
    Entry {
        key: "bip84",
        name: "p2wpkh",
        purpose: 84,
        script: None,
        form: Slip132::P2wpkh,
        single: Some(catcard_wallet::address::AddressKind::P2wpkh),
        multi: None,
    },
    Entry {
        key: "bip48_1",
        name: "p2sh-p2wsh",
        purpose: 48,
        script: Some(1),
        form: Slip132::P2wshP2sh,
        single: None,
        multi: Some("sh(wsh(sortedmulti(M,"),
    },
    Entry {
        key: "bip48_2",
        name: "p2wsh",
        purpose: 48,
        script: Some(2),
        form: Slip132::P2wsh,
        single: None,
        multi: Some("wsh(sortedmulti(M,"),
    },
];

/// The most the file can be. Six entries, each with two extended keys and a descriptor.
pub const MAX_LEN: usize = 4096;

/// Build the generic JSON export for `account`.
///
/// Returns `None` only if a derivation fails, which means the seed is not usable rather
/// than that the format went wrong.
pub fn generic_json(
    master: &ExtendedPrivKey,
    account: u32,
    busy: &mut Working<'_>,
    panel: &mut display::Panel,
    out: &mut heapless::String<MAX_LEN>,
) -> Option<()> {
    let master_fp = crate::keywork::run(|kw| master.fingerprint(kw));
    let [a, b, c, d] = master_fp;
    // Mainnet only for now: the coin type is the one thing here that testnet changes,
    // and this firmware has no testnet mode to select.
    let network = Network::Mainnet;
    let coin = 0u32;

    let master_pub = crate::keywork::run(|kw| master.to_extended_pub(kw));
    let mut xpub = [0u8; catcard_wallet::bip32::serialize::MAX_BASE58_LEN];
    let n = master_pub.write_base58(&mut xpub).ok()?;

    // No whitespace, and the keys in the order the format lists them: this file is read
    // by other people's parsers and compared against other people's fixtures.
    let _ = write!(
        out,
        "{{\"chain\":\"BTC\",\"xfp\":\"{a:02X}{b:02X}{c:02X}{d:02X}\",\"account\":{account},\"xpub\":\"{}\"",
        core::str::from_utf8(&xpub[..n]).unwrap_or("")
    );

    for entry in &ENTRIES {
        busy.tick(panel);
        let steps = [
            ChildNumber::hardened(entry.purpose).ok()?,
            ChildNumber::hardened(coin).ok()?,
            ChildNumber::hardened(account).ok()?,
        ];
        let key = match entry.script {
            None => public_at(master, &steps, busy, panel)?,
            Some(s) => {
                let all = [steps[0], steps[1], steps[2], ChildNumber::hardened(s).ok()?];
                public_at(master, &all, busy, panel)?
            }
        };
        write_entry(entry, &key, master_fp, coin, account, network, out);
    }
    let _ = out.push('}');
    Some(())
}

/// One `"bip84":{...}` row.
fn write_entry(
    entry: &Entry,
    key: &ExtendedPubKey,
    master_fp: [u8; 4],
    coin: u32,
    account: u32,
    network: Network,
    out: &mut heapless::String<MAX_LEN>,
) {
    let [a, b, c, d] = master_fp;
    // The derived node's **own** fingerprint, not the master's: the first four bytes of
    // the hash160 of its public key. A reader uses it to tell one account from another.
    let [e, f, g, h] = key.fingerprint();

    let mut xpub = [0u8; catcard_wallet::bip32::serialize::MAX_BASE58_LEN];
    let Ok(n) = key.write_base58(&mut xpub) else {
        return;
    };
    let xpub = core::str::from_utf8(&xpub[..n]).unwrap_or("");

    // The path, written the way the format writes it: `h` for hardened, no apostrophes.
    let mut deriv: heapless::String<32> = heapless::String::new();
    let _ = match entry.script {
        None => write!(deriv, "m/{}h/{coin}h/{account}h", entry.purpose),
        Some(s) => write!(deriv, "m/{}h/{coin}h/{account}h/{s}h", entry.purpose),
    };

    let _ = write!(
        out,
        ",\"{}\":{{\"name\":\"{}\",\"xfp\":\"{e:02X}{f:02X}{g:02X}{h:02X}\",\"deriv\":\"{}\",\"xpub\":\"{xpub}\",\"desc\":\"",
        entry.key, entry.name, deriv
    );

    match (entry.single, entry.multi) {
        // A finished descriptor, checksum and all.
        (Some(kind), _) => {
            let single = SingleSig {
                kind,
                fingerprint: master_fp,
                coin,
                account,
            };
            let mut line = [0u8; descriptor::MAX_LEN];
            if let Ok(len) = single.write(xpub, &mut line) {
                let _ = out.push_str(core::str::from_utf8(&line[..len]).unwrap_or(""));
            }
        }
        // A template: `M` and the trailing `...` are literal, waiting for a coordinator
        // to substitute the other cosigners. It carries **no checksum**, because the
        // text is not yet a descriptor -- one over the placeholders would be a checksum
        // of something nobody will ever import.
        (None, Some(wrapper)) => {
            let closers = wrapper.matches('(').count();
            let _ = write!(out, "{wrapper}[{a:02x}{b:02x}{c:02x}{d:02x}");
            let _ = match entry.script {
                None => write!(out, "/{}h/{coin}h/{account}h", entry.purpose),
                Some(s) => write!(out, "/{}h/{coin}h/{account}h/{s}h", entry.purpose),
            };
            let _ = write!(out, "]{xpub}/0/*,...");
            for _ in 0..closers {
                let _ = out.push(')');
            }
        }
        (None, None) => {}
    }
    let _ = out.push('"');

    // `_pub` only when the SLIP-132 form is a different string. For `bip44` it is the
    // same key in the same encoding, and a field repeating its neighbour tells a reader
    // nothing while making them wonder what it is for.
    if entry.form != Slip132::Classic {
        let mut alt = [0u8; catcard_wallet::bip32::serialize::MAX_BASE58_LEN];
        if let Ok(m) = key.write_base58_as(entry.form, &mut alt) {
            let alt = core::str::from_utf8(&alt[..m]).unwrap_or("");
            if alt != xpub {
                let _ = write!(out, ",\"_pub\":\"{alt}\"");
            }
        }
    }

    // The first receive address, for single-signature entries only: a multisig address
    // needs every cosigner's key and this file holds one.
    if let Some(kind) = entry.single
        && let Some(first) = first_address(key, kind, network)
    {
        let _ = write!(out, ",\"first\":\"{first}\"");
    }
    let _ = out.push('}');
}

/// The `0/0` address under an account key.
fn first_address(
    account: &ExtendedPubKey,
    kind: catcard_wallet::address::AddressKind,
    network: Network,
) -> Option<heapless::String<{ catcard_wallet::address::MAX_ADDRESS_LEN }>> {
    // Unhardened the whole way, so this is public-key arithmetic and the seed is not
    // involved -- no `keywork::run` around it.
    let chain = ChildNumber::normal(0).ok()?;
    let index = ChildNumber::normal(0).ok()?;
    let leaf = account.derive_child(chain).ok()?.derive_child(index).ok()?;
    let mut buf = [0u8; catcard_wallet::address::MAX_ADDRESS_LEN];
    let n = catcard_wallet::address::encode(kind, network, &leaf.public_key, &mut buf).ok()?;
    let mut s = heapless::String::new();
    s.push_str(core::str::from_utf8(&buf[..n]).ok()?).ok()?;
    Some(s)
}
