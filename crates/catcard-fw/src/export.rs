//! The wallet export formats: the bytes each piece of software expects to be handed.
//!
//! Six formats over sixteen menu entries. The generic JSON ([`generic_json`]) is seven of
//! them on its own -- Generic JSON, Sparrow, Cove, Nunchuk, Fully Noded, Theya and
//! Bitcoin Safe -- with identical bytes and only the filename differing; it is the export
//! most software asks for, because it carries every account key a watch-only wallet might
//! want along with a ready-made descriptor for each. The rest are [`bitcoin_core`],
//! [`electrum`] (which Blue Wallet also reads), [`wasabi`], [`unchained`] and
//! [`ss_descriptor`], which is the four descriptor vendors.
//!
//! Source: hw-reference/wallet-export-formats.md §§A-F [C]. Field order, key spelling and
//! the absence of whitespace are all load-bearing: these files are read by other people's
//! parsers and compared against other people's fixtures, so the keys go out in the order
//! the reference lists them and nothing is pretty-printed.

use core::fmt::Write as _;

use catcard_wallet::bip32::serialize::Slip132;
use catcard_wallet::bip32::{ChildNumber, ExtendedPrivKey, ExtendedPubKey, Network};
use catcard_wallet::descriptor::{self, SingleSig};

use zeroize::Zeroize as _;

use crate::display;
use crate::menu::{Working, public_at};

/// How the export names a script type, and everything that follows from it.
struct Entry {
    /// The JSON key: `bip44`, `bip49`, ...
    key: &'static str,
    /// The `name` field, which is the address type spelled the way the format spells it.
    name: &'static str,
    /// Where the key sits under the master.
    path: Path,
    /// Which SLIP-132 form this type is announced in, when it differs from classic.
    form: Slip132,
    /// Single-signature entries carry a first address and a finished descriptor;
    /// multisig entries carry a template with placeholders in it and no checksum.
    single: Option<catcard_wallet::address::AddressKind>,
    /// The descriptor wrapper for a multisig template.
    multi: Option<&'static str>,
}

/// The shape of an entry's derivation.
///
/// Three shapes rather than an optional level, because BIP-45's path has no coin type and
/// no account in it at all -- it is one hardened step and then the keys. Writing that as
/// "purpose 45 with the account part suppressed" would leave two fields that must not be
/// read, and something would eventually read them.
#[derive(Copy, Clone)]
enum Path {
    /// `m/{purpose}h/{coin}h/{account}h`.
    Account(u32),
    /// `m/48h/{coin}h/{account}h/{script}h`.
    Cosigner(u32),
    /// `m/45h`, and nothing below it.
    Bip45,
}

/// The rows of the file, in the order the format lists them.
const ENTRIES: [Entry; 6] = [
    Entry {
        key: "bip44",
        name: "p2pkh",
        path: Path::Account(44),
        form: Slip132::Classic,
        single: Some(catcard_wallet::address::AddressKind::P2pkh),
        multi: None,
    },
    Entry {
        key: "bip49",
        name: "p2sh-p2wpkh",
        path: Path::Account(49),
        form: Slip132::P2wpkhP2sh,
        single: Some(catcard_wallet::address::AddressKind::P2shP2wpkh),
        multi: None,
    },
    Entry {
        key: "bip84",
        name: "p2wpkh",
        path: Path::Account(84),
        form: Slip132::P2wpkh,
        single: Some(catcard_wallet::address::AddressKind::P2wpkh),
        multi: None,
    },
    Entry {
        key: "bip48_1",
        name: "p2sh-p2wsh",
        path: Path::Cosigner(1),
        form: Slip132::P2wshP2sh,
        single: None,
        multi: Some("sh(wsh(sortedmulti(M,"),
    },
    Entry {
        key: "bip48_2",
        name: "p2wsh",
        path: Path::Cosigner(2),
        form: Slip132::P2wsh,
        single: None,
        multi: Some("wsh(sortedmulti(M,"),
    },
    // BIP-45 last, and only for account zero: the path has no account level, so the same
    // key would be written into every account's file and mean something different in each.
    Entry {
        key: "bip45",
        name: "p2sh",
        path: Path::Bip45,
        form: Slip132::Classic,
        single: None,
        multi: Some("sh(sortedmulti(M,"),
    },
];

/// The most any export here can be.
///
/// Set by the largest, which is Bitcoin Core's: two JSON blobs carrying four descriptors
/// between them, each with a 111-character xpub, wrapped in about fourteen hundred
/// characters of instructions. The generic JSON's six entries come in under it.
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
    let (network, coin) = (NETWORK, COIN);

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
        // BIP-45's key does not vary with the account, so writing it into a non-zero
        // account's file would put the same key under two different headings.
        if matches!(entry.path, Path::Bip45) && account != 0 {
            continue;
        }
        busy.tick(panel);
        let key = derive(master, entry.path, coin, account, busy, panel)?;
        write_entry(entry, &key, master_fp, coin, account, network, out);
    }
    let _ = out.push('}');
    Some(())
}

/// The key at an entry's path.
fn derive(
    master: &ExtendedPrivKey,
    path: Path,
    coin: u32,
    account: u32,
    busy: &mut Working<'_>,
    panel: &mut display::Panel,
) -> Option<ExtendedPubKey> {
    match path {
        Path::Bip45 => public_at(master, &[ChildNumber::hardened(45).ok()?], busy, panel),
        Path::Account(purpose) => {
            let steps = [
                ChildNumber::hardened(purpose).ok()?,
                ChildNumber::hardened(coin).ok()?,
                ChildNumber::hardened(account).ok()?,
            ];
            public_at(master, &steps, busy, panel)
        }
        Path::Cosigner(script) => {
            let steps = [
                ChildNumber::hardened(48).ok()?,
                ChildNumber::hardened(coin).ok()?,
                ChildNumber::hardened(account).ok()?,
                ChildNumber::hardened(script).ok()?,
            ];
            public_at(master, &steps, busy, panel)
        }
    }
}

/// An entry's path, written the way the format writes it: `h` for hardened, no
/// apostrophes, and no leading `m/` when it is going inside a descriptor's origin.
fn write_path(
    out: &mut impl core::fmt::Write,
    path: Path,
    coin: u32,
    account: u32,
) -> core::fmt::Result {
    match path {
        Path::Bip45 => write!(out, "/45h"),
        Path::Account(purpose) => write!(out, "/{purpose}h/{coin}h/{account}h"),
        Path::Cosigner(script) => write!(out, "/48h/{coin}h/{account}h/{script}h"),
    }
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

    let mut deriv: heapless::String<32> = heapless::String::new();
    let _ = deriv.push('m');
    let _ = write_path(&mut deriv, entry.path, coin, account);

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
            let _ = write_path(out, entry.path, coin, account);
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

// ---------------------------------------------------------------------------
// The other formats.
//
// Each is one menu entry's file, and each exists because some particular piece of
// software asks for exactly it. They share almost nothing: the whole point of a format
// is that a parser somewhere expects these bytes and not equivalent ones, so the
// temptation to unify them into one templated writer is a temptation to break them all
// at once. What is shared is the derivation, which is [`account_key`].
//
// Source: hw-reference/wallet-export-formats.md §§B-F [C]. Field order, spelling and
// the absence of whitespace are all load-bearing.
// ---------------------------------------------------------------------------

/// Mainnet, and the coin type that follows from it.
///
/// Both formats-wide constants rather than parameters: this firmware has no testnet
/// mode to select, and threading a network through every writer to always pass the same
/// value would suggest the other one had been tested.
const NETWORK: Network = Network::Mainnet;
const COIN: u32 = 0;

/// Derive `m/{purpose}h/{COIN}h/{account}h`, and a fourth hardened step if given.
///
/// The one thing every format below needs. `script` is BIP-48's level: `Some(1)` for
/// P2SH-P2WSH, `Some(2)` for P2WSH.
fn account_key(
    master: &ExtendedPrivKey,
    purpose: u32,
    account: u32,
    script: Option<u32>,
    busy: &mut Working<'_>,
    panel: &mut display::Panel,
) -> Option<ExtendedPubKey> {
    busy.tick(panel);
    let steps = [
        ChildNumber::hardened(purpose).ok()?,
        ChildNumber::hardened(COIN).ok()?,
        ChildNumber::hardened(account).ok()?,
    ];
    match script {
        None => public_at(master, &steps, busy, panel),
        Some(s) => {
            let all = [steps[0], steps[1], steps[2], ChildNumber::hardened(s).ok()?];
            public_at(master, &all, busy, panel)
        }
    }
}

/// A key in `form`, as Base58Check, into a caller-held buffer.
///
/// Returns a `&str` borrowed from `buf` so the caller can `write!` it without a second
/// copy; every format here writes an extended key into the middle of a line.
fn base58<'b>(
    key: &ExtendedPubKey,
    form: Slip132,
    buf: &'b mut [u8; catcard_wallet::bip32::serialize::MAX_BASE58_LEN],
) -> Option<&'b str> {
    let n = key.write_base58_as(form, buf).ok()?;
    core::str::from_utf8(&buf[..n]).ok()
}

/// Format B: Bitcoin Core.
///
/// A text file a person pastes from rather than a file Core reads -- which is why it is
/// mostly prose, and why the prose is copied exactly. It wraps two RPC commands:
/// `importdescriptors` for anything current, and `importmulti` for the versions that
/// predate it. Native segwit only, which is what stock offers here.
///
/// Source: hw-reference/wallet-export-formats.md §"Format B" [C]. Every `#` heading, the
/// note, and the trailing space after the v0.21.0 heading are verbatim.
pub fn bitcoin_core(
    master: &ExtendedPrivKey,
    account: u32,
    busy: &mut Working<'_>,
    panel: &mut display::Panel,
    out: &mut heapless::String<MAX_LEN>,
) -> Option<()> {
    const PURPOSE: u32 = 84;
    let kind = catcard_wallet::address::AddressKind::P2wpkh;

    let master_fp = crate::keywork::run(|kw| master.fingerprint(kw));
    let [a, b, c, d] = master_fp;
    let key = account_key(master, PURPOSE, account, None, busy, panel)?;
    let mut raw = [0u8; catcard_wallet::bip32::serialize::MAX_BASE58_LEN];
    let xpub = base58(&key, Slip132::Classic, &mut raw)?;

    let single = SingleSig {
        kind,
        fingerprint: master_fp,
        coin: COIN,
        account,
    };
    // The receive and change descriptors, written once and used by both blobs.
    let mut ext = [0u8; descriptor::MAX_LEN];
    let mut int = [0u8; descriptor::MAX_LEN];
    let e = single.write_chain(xpub, "0", &mut ext).ok()?;
    let i = single.write_chain(xpub, "1", &mut int).ok()?;
    let ext = core::str::from_utf8(&ext[..e]).ok()?;
    let int = core::str::from_utf8(&int[..i]).ok()?;

    let _ = write!(
        out,
        "# Bitcoin Core Wallet Import File\n\n\
         https://github.com/Coldcard/firmware/blob/master/docs/bitcoin-core-usage.md\n\n\
         ## For wallet with master key fingerprint: {a:02X}{b:02X}{c:02X}{d:02X}\n\n\
         Wallet operates on blockchain: Bitcoin Mainnet\n\n\
         ## Bitcoin Core RPC\n\n\
         The following command can be entered after opening Window -> Console\n\
         in Bitcoin Core, or using bitcoin-cli:\n\n\
         importdescriptors '"
    );
    // `active` and a hundred-address range: what Core is told to watch immediately.
    let _ = write!(
        out,
        "[{{\"desc\":\"{ext}\",\"active\":true,\"timestamp\":\"now\",\"internal\":false,\"range\":[0,100]}},\
         {{\"desc\":\"{int}\",\"active\":true,\"timestamp\":\"now\",\"internal\":true,\"range\":[0,100]}}]"
    );
    let _ = write!(
        out,
        "'\n\n\
         > **NOTE** If your UTXO was created before generating `importdescriptors` command, you should adjust the value of `timestamp` before executing command in bitcoin core. \n  \
         By default it is set to `now` meaning do not rescan the blockchain. If approximate time of UTXO creation is known - adjust `timestamp` from `now` to UNIX epoch time.\n  \
         0 can be specified to scan the entire blockchain. Alternatively `rescanblockchain` command can be used after executing importdescriptors command.\n\n\
         ### Bitcoin Core before v0.21.0 \n\n\
         This command can be used on older versions, but it is not as robust\n\
         and \"importdescriptors\" should be prefered if possible:\n\n\
         importmulti '"
    );
    // The older call takes a wider range and says watch-only in so many words. The key
    // order here is the order stock emits, which is not the order above.
    let _ = write!(
        out,
        "[{{\"desc\":\"{ext}\",\"range\":[0,1000],\"timestamp\":\"now\",\"internal\":false,\"keypool\":true,\"watchonly\":true}},\
         {{\"desc\":\"{int}\",\"range\":[0,1000],\"timestamp\":\"now\",\"internal\":true,\"keypool\":true,\"watchonly\":true}}]"
    );
    let _ = write!(out, "'\n\n## Resulting Addresses (first 3)\n\n");
    for index in 0..3u32 {
        busy.tick(panel);
        let addr = address_at(&key, kind, index)?;
        let _ = writeln!(out, "m/{PURPOSE}h/{COIN}h/{account}h/0/{index} => {addr}");
    }
    Some(())
}

/// Format C: Electrum, and Blue Wallet, which reads the same file.
///
/// The only format here that wants the master key *and* an account key, and the only one
/// that wants the fingerprint as an integer rather than as hex.
///
/// Source: hw-reference/wallet-export-formats.md §"Format C" [C].
pub fn electrum(
    master: &ExtendedPrivKey,
    kind: catcard_wallet::address::AddressKind,
    account: u32,
    busy: &mut Working<'_>,
    panel: &mut display::Panel,
    out: &mut heapless::String<MAX_LEN>,
) -> Option<()> {
    let purpose = kind.bip44_purpose();
    let master_fp = crate::keywork::run(|kw| master.fingerprint(kw));
    let [a, b, c, d] = master_fp;
    // `ckcc_xfp` is the fingerprint as a little-endian `u32` -- the same four bytes the
    // hex string spells, read as a number. Stock stores it that way and writes it out
    // raw, so a reader comparing the two fields sees one value in two notations.
    let xfp_int = u32::from_le_bytes(master_fp);

    let master_pub = crate::keywork::run(|kw| master.to_extended_pub(kw));
    let mut mraw = [0u8; catcard_wallet::bip32::serialize::MAX_BASE58_LEN];
    let master_xpub = base58(&master_pub, Slip132::Classic, &mut mraw)?;

    let key = account_key(master, purpose, account, None, busy, panel)?;
    let mut araw = [0u8; catcard_wallet::bip32::serialize::MAX_BASE58_LEN];
    // SLIP-132 here, unlike everywhere else: Electrum reads the script type off the
    // version bytes rather than off the derivation path.
    let account_xpub = base58(&key, slip132_for(kind), &mut araw)?;

    let _ = write!(
        out,
        "{{\"seed_version\":17,\"use_encryption\":false,\"wallet_type\":\"standard\",\
         \"keystore\":{{\"type\":\"hardware\",\"hw_type\":\"coldcard\",\
         \"label\":\"Coldcard Import {a:02X}{b:02X}{c:02X}{d:02X}"
    );
    if account != 0 {
        let _ = write!(out, " Acct#{account}");
    }
    let _ = write!(
        out,
        "\",\"ckcc_xfp\":{xfp_int},\"ckcc_xpub\":\"{master_xpub}\",\
         \"derivation\":\"m/{purpose}h/{COIN}h/{account}h\",\"xpub\":\"{account_xpub}\"}}}}"
    );
    Some(())
}

/// Format D: Wasabi.
///
/// Three fields, no choices: native segwit, account zero. The version string is this
/// firmware's, which is what the field asks for -- a reader uses it to know what wrote
/// the file, so reporting stock's version would be a lie about provenance.
///
/// Source: hw-reference/wallet-export-formats.md §"Format D" [C]. The mixed-case
/// `ColdCardFirmwareVersion` is the literal key.
pub fn wasabi(
    master: &ExtendedPrivKey,
    busy: &mut Working<'_>,
    panel: &mut display::Panel,
    out: &mut heapless::String<MAX_LEN>,
) -> Option<()> {
    let master_fp = crate::keywork::run(|kw| master.fingerprint(kw));
    let [a, b, c, d] = master_fp;
    let key = account_key(master, 84, 0, None, busy, panel)?;
    let mut raw = [0u8; catcard_wallet::bip32::serialize::MAX_BASE58_LEN];
    let xpub = base58(&key, Slip132::Classic, &mut raw)?;
    let _ = write!(
        out,
        "{{\"ColdCardFirmwareVersion\":\"{}\",\"MasterFingerprint\":\"{a:02X}{b:02X}{c:02X}{d:02X}\",\"ExtPubKey\":\"{xpub}\"}}",
        crate::VERSION
    );
    Some(())
}

/// Format E: Unchained.
///
/// Multisig-oriented: three cosigner keys at the paths a coordinator asks for, each in
/// the SLIP-132 form that says what it is for. The BIP-45 leg is a single hardened step
/// and has no account level at all, which is why it is dropped when an account other
/// than zero is being exported -- there would be nothing to vary.
///
/// Source: hw-reference/wallet-export-formats.md §"Format E" [C]. Stock's key order comes
/// out of a Python set and is therefore not fixed; the reference says to key by name. The
/// order written here is the one its example shows.
pub fn unchained(
    master: &ExtendedPrivKey,
    account: u32,
    busy: &mut Working<'_>,
    panel: &mut display::Panel,
    out: &mut heapless::String<MAX_LEN>,
) -> Option<()> {
    let master_fp = crate::keywork::run(|kw| master.fingerprint(kw));
    let [a, b, c, d] = master_fp;
    let _ = write!(
        out,
        "{{\"xfp\":\"{a:02X}{b:02X}{c:02X}{d:02X}\",\"account\":{account}"
    );

    if account == 0 {
        busy.tick(panel);
        let step = ChildNumber::hardened(45).ok()?;
        let key = public_at(master, &[step], busy, panel)?;
        let mut raw = [0u8; catcard_wallet::bip32::serialize::MAX_BASE58_LEN];
        let xpub = base58(&key, Slip132::Classic, &mut raw)?;
        let _ = write!(out, ",\"p2sh_deriv\":\"m/45h\",\"p2sh\":\"{xpub}\"");
    }

    for (name, script, form) in [
        ("p2sh_p2wsh", 1u32, Slip132::P2wshP2sh),
        ("p2wsh", 2, Slip132::P2wsh),
    ] {
        let key = account_key(master, 48, account, Some(script), busy, panel)?;
        let mut raw = [0u8; catcard_wallet::bip32::serialize::MAX_BASE58_LEN];
        let xpub = base58(&key, form, &mut raw)?;
        let _ = write!(
            out,
            ",\"{name}_deriv\":\"m/48h/{COIN}h/{account}h/{script}h\",\"{name}\":\"{xpub}\""
        );
    }
    let _ = out.push('}');
    Some(())
}

/// Format F: one single-signature descriptor -- Descriptor, Bull Bitcoin, Zeus, Samourai.
///
/// Five menu entries and one file. What differs between them is the filename, the address
/// types offered and, for Samourai, a fixed account number; the bytes are built the same
/// way. `int_ext` chooses one multipath line over a receive line and a change line.
///
/// Source: hw-reference/wallet-export-formats.md §"Format F" [C].
pub fn ss_descriptor(
    master: &ExtendedPrivKey,
    kind: catcard_wallet::address::AddressKind,
    account: u32,
    int_ext: bool,
    busy: &mut Working<'_>,
    panel: &mut display::Panel,
    out: &mut heapless::String<MAX_LEN>,
) -> Option<()> {
    let master_fp = crate::keywork::run(|kw| master.fingerprint(kw));
    let key = account_key(master, kind.bip44_purpose(), account, None, busy, panel)?;
    let mut raw = [0u8; catcard_wallet::bip32::serialize::MAX_BASE58_LEN];
    // Classic, not SLIP-132: the origin path in the descriptor already says what the
    // script type is, and a reader that saw both could be told two different things.
    let xpub = base58(&key, Slip132::Classic, &mut raw)?;

    let single = SingleSig {
        kind,
        fingerprint: master_fp,
        coin: COIN,
        account,
    };
    let chains: &[&str] = if int_ext {
        &[SingleSig::MULTIPATH]
    } else {
        &["0", "1"]
    };
    for chain in chains {
        let mut line = [0u8; descriptor::MAX_LEN];
        let n = single.write_chain(xpub, chain, &mut line).ok()?;
        let _ = out.push_str(core::str::from_utf8(&line[..n]).ok()?);
        let _ = out.push('\n');
    }
    Some(())
}

// ---------------------------------------------------------------------------
// The detached signature.
// ---------------------------------------------------------------------------

/// Where a format's detached signature is signed from.
///
/// Every format names its own: a path down to one leaf, and the address form that leaf
/// is written in. They differ -- Bitcoin Core signs from its native-segwit account, the
/// generic JSON from BIP-44's -- and the file says which address signed, so a verifier
/// needs to be told nothing else.
///
/// Source: hw-reference/wallet-export-formats.md, the "Signing derivation" line of each
/// format [C].
#[derive(Clone)]
pub struct Signing {
    /// The whole path from the master, hardened steps included.
    pub steps: heapless::Vec<ChildNumber, 6>,
    /// Which address form the signing key is written as.
    pub kind: catcard_wallet::address::AddressKind,
}

impl Signing {
    /// `m/{purpose}h/{COIN}h/{account}h/0/0`, which is what most formats sign from.
    pub fn account(
        purpose: u32,
        account: u32,
        kind: catcard_wallet::address::AddressKind,
    ) -> Option<Self> {
        let mut steps = heapless::Vec::new();
        for step in [
            ChildNumber::hardened(purpose).ok()?,
            ChildNumber::hardened(COIN).ok()?,
            ChildNumber::hardened(account).ok()?,
            ChildNumber::normal(0).ok()?,
            ChildNumber::normal(0).ok()?,
        ] {
            steps.push(step).ok()?;
        }
        Some(Signing { steps, kind })
    }

    /// `m/48h/{COIN}h/{account}h/2h/0/0`, which is Unchained's.
    pub fn cosigner(account: u32) -> Option<Self> {
        let mut steps = heapless::Vec::new();
        for step in [
            ChildNumber::hardened(48).ok()?,
            ChildNumber::hardened(COIN).ok()?,
            ChildNumber::hardened(account).ok()?,
            ChildNumber::hardened(2).ok()?,
            ChildNumber::normal(0).ok()?,
            ChildNumber::normal(0).ok()?,
        ] {
            steps.push(step).ok()?;
        }
        Some(Signing {
            steps,
            kind: catcard_wallet::address::AddressKind::P2pkh,
        })
    }
}

/// The longest a `.sig` file gets: the two banner lines, a 64-character digest and a
/// filename, an address and 88 characters of base64.
pub const MAX_SIG_LEN: usize = 320;

/// Write the detached signature for `contents` under `basename`.
///
/// An RFC-2440-style armoured block over one line: the lower-case hex of the file's
/// SHA-256, two spaces, and the file's name without its directory. Signing the name
/// along with the digest is what stops a signature being lifted off one export and
/// presented with another.
///
/// The name has to be the one actually written, which is why this runs after the
/// collision numbering has picked it and not before.
///
/// Source: hw-reference/wallet-export-formats.md §"Detached signature file" [C].
pub fn signature_file(
    master: &ExtendedPrivKey,
    signing: &Signing,
    contents: &[u8],
    basename: &str,
    out: &mut heapless::String<MAX_SIG_LEN>,
) -> Result<(), &'static str> {
    use catcard_wallet::message;

    let digest = {
        use purecrypto::hash::{Digest as _, Sha256};
        let mut h = Sha256::new();
        h.update(contents);
        h.finalize()
    };
    // The signed body. Two spaces between the digest and the name, which is the format.
    let mut body: heapless::String<{ message::MAX_MESSAGE }> = heapless::String::new();
    for byte in digest {
        write!(body, "{byte:02x}").map_err(|_| "name too long")?;
    }
    body.push_str("  ").map_err(|_| "name too long")?;
    body.push_str(basename).map_err(|_| "name too long")?;

    let signed = crate::keywork::run(|kw| {
        let mut here = master.clone();
        for &step in &signing.steps {
            here = here
                .derive_child(step, kw)
                .map_err(|_| "derivation failed")?;
        }
        let mut secret = *here.secret_bytes();
        let sig = message::sign(&body, &secret, signing.kind, kw);
        secret.zeroize();
        let sig = sig.map_err(|_| "could not sign")?;
        // Check our own work before it leaves: recover the key from the signature and
        // compare it with the one that signed. A sidecar that does not verify is worse
        // than no sidecar, because it looks like tampering.
        let pubkey = here.public_key(kw);
        match message::recover(&body, &sig) {
            Ok((recovered, _)) if recovered == pubkey => {}
            _ => return Err("signature did not verify"),
        }
        let mut buf = [0u8; catcard_wallet::address::MAX_ADDRESS_LEN];
        let n = catcard_wallet::address::encode(signing.kind, NETWORK, &pubkey, &mut buf)
            .map_err(|_| "address failed")?;
        let mut addr: heapless::String<{ catcard_wallet::address::MAX_ADDRESS_LEN }> =
            heapless::String::new();
        addr.push_str(core::str::from_utf8(&buf[..n]).unwrap_or(""))
            .map_err(|_| "address failed")?;
        Ok((sig, addr))
    })?;

    let (sig, addr) = signed;
    let mut armoured = [0u8; message::MAX_ARMOURED];
    let n = message::armour(&sig, &mut armoured).map_err(|_| "could not encode it")?;
    let armoured = core::str::from_utf8(&armoured[..n]).map_err(|_| "could not encode it")?;

    // Every line ends with a newline, the last one included.
    write!(
        out,
        "-----BEGIN BITCOIN SIGNED MESSAGE-----\n\
         {body}\n\
         -----BEGIN BITCOIN SIGNATURE-----\n\
         {addr}\n\
         {armoured}\n\
         -----END BITCOIN SIGNATURE-----\n"
    )
    .map_err(|_| "signature too long")
}

/// The SLIP-132 form that announces `kind`.
fn slip132_for(kind: catcard_wallet::address::AddressKind) -> Slip132 {
    use catcard_wallet::address::AddressKind as K;
    match kind {
        K::P2shP2wpkh => Slip132::P2wpkhP2sh,
        K::P2wpkh => Slip132::P2wpkh,
        // Taproot has no SLIP-132 form of its own, and classic is what it is written as.
        K::P2pkh | K::P2tr => Slip132::Classic,
    }
}

/// The `0/index` address under an account key.
fn address_at(
    account: &ExtendedPubKey,
    kind: catcard_wallet::address::AddressKind,
    index: u32,
) -> Option<heapless::String<{ catcard_wallet::address::MAX_ADDRESS_LEN }>> {
    // Unhardened the whole way, so this is public-key arithmetic and the seed is not
    // involved -- no `keywork::run` around it.
    let chain = ChildNumber::normal(0).ok()?;
    let leaf = account
        .derive_child(chain)
        .ok()?
        .derive_child(ChildNumber::normal(index).ok()?)
        .ok()?;
    let mut buf = [0u8; catcard_wallet::address::MAX_ADDRESS_LEN];
    let n = catcard_wallet::address::encode(kind, NETWORK, &leaf.public_key, &mut buf).ok()?;
    let mut s = heapless::String::new();
    s.push_str(core::str::from_utf8(&buf[..n]).ok()?).ok()?;
    Some(s)
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
