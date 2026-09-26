//! Multisig wallets: what one is, the scripts it produces, and the descriptor that
//! describes it.
//!
//! A multisig wallet is not a key this device owns; it is an **agreement** between keys,
//! most of which belong to other devices. So the record here is the agreement -- how many
//! signatures, whose keys, in which script form, sorted or not -- and everything else is
//! derived from it. Nothing about an address may come from whoever hands us a transaction:
//! a host that can choose the script can choose where the money goes.
//!
//! # What is fixed here rather than taken from a request
//!
//! - **The cosigners.** A wallet is registered once, from a descriptor a person imported,
//!   and every later address is rebuilt from that record. A PSBT naming other keys is
//!   describing a different wallet.
//! - **The order.** [BIP-67] sorts the public keys at each address, so all cosigners build
//!   the same script without agreeing on an order. Stock defaults to sorted and allows
//!   unsorted only deliberately; this records which the descriptor asked for, since
//!   `multi` and `sortedmulti` are different wallets with the same keys.
//! - **The script form.** `sh`, `wsh` or `sh(wsh)` come from the descriptor, not from the
//!   shape of a script a host supplies.
//!
//! Taproot multisig (`tr`, `multi_a`) is not here, as it is not in stock either.
//!
//! [BIP-67]: https://github.com/bitcoin/bips/blob/master/bip-0067.mediawiki

use crate::bip32::serialize::Slip132;
use crate::bip32::{ChildNumber, ExtendedPrivKey, ExtendedPubKey, HARDENED_OFFSET, hash160};
use crate::descriptor;

/// The Coldcard multisig setup file (stock's text format, J1): reading and writing it.
pub mod coldcard;
/// The other exports of a wallet (Bitcoin Core, Electrum) and the `ccxp` key bundle.
pub mod export;

/// Cosigners one wallet may have. Stock's limit, and the point past which the witness
/// script stops fitting the standardness rules anyway.
pub const MAX_COSIGNERS: usize = 15;

/// Levels a cosigner's key-origin path may have: `48h/coin/account/script`, and room.
pub const MAX_ORIGIN: usize = 8;

/// The largest redeem or witness script this can build.
///
/// `OP_M`, fifteen 33-byte pushes with their length bytes, `OP_N`, `OP_CHECKMULTISIG`.
pub const MAX_SCRIPT: usize = 1 + MAX_COSIGNERS * 34 + 1 + 1;

/// Which script a wallet's addresses take.
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub enum Kind {
    /// `sh(multi(...))` — the original, a redeem script hashed into a P2SH address.
    P2sh,
    /// `wsh(multi(...))` — native segwit, the witness script hashed into a v0 program.
    P2wsh,
    /// `sh(wsh(multi(...)))` — the segwit script wrapped in P2SH for old senders.
    P2shP2wsh,
}

/// One cosigner: whose key, and where it sits under their master.
///
/// The origin is not decoration. It is what lets a device recognise *its own* key in a
/// wallet -- by fingerprint -- and what a person compares when checking that the wallet
/// they are registering is the one they meant.
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub struct Cosigner {
    /// The master fingerprint the descriptor claims for this key.
    pub fingerprint: [u8; 4],
    /// The path from that master to `xpub`, as the descriptor wrote it.
    pub origin: [u32; MAX_ORIGIN],
    pub origin_len: usize,
    /// The account-level extended public key everything below is derived from.
    pub xpub: ExtendedPubKey,
}

/// Which cosigner, if any, is provably this device's.
///
/// A descriptor's `[fingerprint/path]` origin is a claim by whoever wrote the file, and
/// master fingerprints are public: they appear in every exported descriptor. So a match on
/// the fingerprint alone proves nothing. This derives `master` along the claimed path and
/// requires the key it reaches to be the one the descriptor names.
///
/// [`Error::ForgedOrigin`] means a cosigner claimed this device's fingerprint and did not
/// derive to its own key, which is the case worth refusing rather than displaying. The
/// first claim decides: a file where one cosigner's claim on this device is false is
/// refused whole, rather than sifted for the claims that happen to hold.
pub fn our_cosigner(
    wallet: &Multisig,
    master: &ExtendedPrivKey,
    kw: &crate::KeyWork,
) -> Result<Option<usize>, Error> {
    let fp = master.fingerprint(kw);
    for (i, c) in wallet.cosigners().iter().enumerate() {
        if c.fingerprint != fp {
            continue;
        }
        let mut key = master.clone();
        let mut reached = true;
        for &step in c.origin() {
            let child = if step & HARDENED_OFFSET != 0 {
                ChildNumber::hardened(step & !HARDENED_OFFSET)
            } else {
                ChildNumber::normal(step)
            };
            match child.and_then(|ch| key.derive_child(ch, kw)) {
                Ok(next) => key = next,
                Err(_) => {
                    reached = false;
                    break;
                }
            }
        }
        // The key material only: the public key and the chain code are what prove the
        // cosigner is this device's. An extended key also carries depth, parent
        // fingerprint and child number, which are description rather than proof -- some
        // wallets normalise them when they export -- and an attacker can write whatever
        // it likes there regardless. Comparing them would refuse honest imports without
        // refusing a single forgery.
        let ours = key.to_extended_pub(kw);
        if reached && (ours.public_key, ours.chain_code) == (c.xpub.public_key, c.xpub.chain_code) {
            return Ok(Some(i));
        }
        return Err(Error::ForgedOrigin { at: i });
    }
    Ok(None)
}

impl Cosigner {
    /// The origin path as written.
    pub fn origin(&self) -> &[u32] {
        &self.origin[..self.origin_len]
    }
}

/// A registered multisig wallet.
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub struct Multisig {
    /// Signatures required.
    pub m: u8,
    /// Cosigners, in the order the descriptor listed them.
    cosigners: [Cosigner; MAX_COSIGNERS],
    n: usize,
    pub kind: Kind,
    /// Whether the keys are sorted at each address ([BIP-67], `sortedmulti`).
    ///
    /// Not a preference: `multi` and `sortedmulti` over the same keys are different
    /// wallets with different addresses, so this belongs to the record.
    pub sorted: bool,
}

/// Why a descriptor could not be read as a multisig wallet.
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub enum Error {
    /// The checksum is absent or does not match. A descriptor is not accepted without
    /// one: a single wrong character is a different wallet, and the checksum is the only
    /// thing standing between a typo and an address nobody can spend from.
    BadChecksum,
    /// Not a script function this understands, or nested in a way it does not allow.
    NotMultisig,
    /// The threshold is missing, not a number, zero, or larger than the cosigner count.
    BadThreshold,
    /// A key is malformed: no origin, a bad xpub, or a derivation suffix this cannot use.
    BadKey { at: usize },
    /// More cosigners than [`MAX_COSIGNERS`], or none.
    CosignerCount { n: usize },
    /// Two cosigners share an extended key, so fewer parties hold the wallet than the
    /// threshold implies. Stock refuses this and so does this.
    DuplicateKey,
    /// A cosigner claims this device's master fingerprint but its key does not derive from
    /// this device's master along the origin the descriptor gives.
    ForgedOrigin { at: usize },
    /// A cosigner's key is written in a SLIP-132 form that names a different script type
    /// from the one the descriptor wraps it in: a `zpub` (single-signature P2WPKH) inside
    /// `wsh(...)`, or a `Zpub` (P2WSH) inside `sh(...)`. The bytes of the key are fine;
    /// the file disagrees with itself about what wallet it describes.
    FormMismatch { at: usize },
    /// The output buffer was too small.
    Overflow,
}

impl Multisig {
    /// Build a wallet from its parts, validating the threshold and cosigners the way
    /// [`parse`] does.
    ///
    /// For reconstructing a wallet whose definition arrived somewhere other than a
    /// descriptor -- from the keys inside a PSBT ([`crate::psbtview::reconstruct_for_input`]).
    /// The same rules apply: at least one cosigner and no more than [`MAX_COSIGNERS`], a
    /// threshold in `1..=n`, and no two cosigners sharing an extended key.
    pub fn new(m: u8, cosigners: &[Cosigner], kind: Kind, sorted: bool) -> Result<Multisig, Error> {
        let n = cosigners.len();
        if n == 0 || n > MAX_COSIGNERS {
            return Err(Error::CosignerCount { n });
        }
        if m == 0 || m as usize > n {
            return Err(Error::BadThreshold);
        }
        for i in 0..n {
            for j in (i + 1)..n {
                if cosigners[i].xpub == cosigners[j].xpub {
                    return Err(Error::DuplicateKey);
                }
            }
        }
        let mut slots = [cosigners[0]; MAX_COSIGNERS];
        slots[..n].copy_from_slice(cosigners);
        Ok(Multisig {
            m,
            cosigners: slots,
            n,
            kind,
            sorted,
        })
    }

    /// The cosigners, in descriptor order.
    pub fn cosigners(&self) -> &[Cosigner] {
        &self.cosigners[..self.n]
    }

    /// How many cosigners there are: the `N` of `M-of-N`.
    pub fn n(&self) -> usize {
        self.n
    }

    /// Whether any cosigner claims this master fingerprint.
    ///
    /// A claim, not a proof: the key still has to derive to what the script needs, which
    /// is what signing checks. This is for deciding whether a wallet is worth showing.
    pub fn involves(&self, fingerprint: [u8; 4]) -> bool {
        self.cosigners()
            .iter()
            .any(|c| c.fingerprint == fingerprint)
    }

    /// Build the redeem or witness script for one address: `M <pubkey…> N CHECKMULTISIG`.
    ///
    /// `branch` and `index` are the two unhardened levels below each cosigner's account
    /// key -- the same pair for every cosigner, which is what makes them one address.
    pub fn script(&self, branch: u32, index: u32, out: &mut [u8]) -> Result<usize, Error> {
        let mut keys = [[0u8; 33]; MAX_COSIGNERS];
        for (slot, cosigner) in keys.iter_mut().zip(self.cosigners()) {
            let bad = |_| Error::BadKey { at: 0 };
            let child = cosigner
                .xpub
                .derive_child(ChildNumber::normal(branch).map_err(bad)?)
                .map_err(bad)?
                .derive_child(ChildNumber::normal(index).map_err(bad)?)
                .map_err(bad)?;
            *slot = child.public_key;
        }
        assemble(self.m, &mut keys[..self.n], self.sorted, out)
    }

    /// The scriptPubKey of one address, in this wallet's script form.
    pub fn script_pubkey(&self, branch: u32, index: u32, out: &mut [u8]) -> Result<usize, Error> {
        use purecrypto::hash::{Digest as _, Sha256};

        let mut script = [0u8; MAX_SCRIPT];
        let n = self.script(branch, index, &mut script)?;
        let script = &script[..n];

        match self.kind {
            Kind::P2sh => {
                let hash = hash160(script);
                write_p2sh(&hash, out)
            }
            Kind::P2wsh => {
                let sha = Sha256::digest(script);
                write_p2wsh(sha.as_slice(), out)
            }
            Kind::P2shP2wsh => {
                // The P2SH redeem script *is* the P2WSH program, and the address commits
                // to a hash of that rather than of the witness script.
                let sha = Sha256::digest(script);
                let mut program = [0u8; 34];
                let len = write_p2wsh(sha.as_slice(), &mut program)?;
                let hash = hash160(&program[..len]);
                write_p2sh(&hash, out)
            }
        }
    }

    /// Write this wallet as an output descriptor, checksum included, into `out`.
    ///
    /// The inverse of [`parse`]: `sh(...)`, `wsh(...)` or `sh(wsh(...))` around
    /// `multi(m,...)` or `sortedmulti(m,...)`, each key written with its origin and the
    /// `/0/*` receive suffix -- `[fingerprint/path]xpub/0/*`. Round-trips through [`parse`],
    /// which is what lets a wallet reconstructed from a PSBT be stored and read back as the
    /// same agreement. Hardened origin steps are written `h`.
    ///
    /// A fifteen-cosigner descriptor is close to two kilobytes; `out` has to hold it, and
    /// [`Error::Overflow`] says when it does not.
    pub fn write_descriptor(&self, out: &mut [u8]) -> Result<usize, Error> {
        self.write_descriptor_chain(0, out)
    }

    /// As [`write_descriptor`](Self::write_descriptor), with `/{chain}/*` as the suffix:
    /// `0` is the receive descriptor stored as the wallet's identity, `1` the change one
    /// Bitcoin Core's import wants alongside it.
    pub fn write_descriptor_chain(&self, chain: u32, out: &mut [u8]) -> Result<usize, Error> {
        use crate::bip32::serialize::MAX_BASE58_LEN;
        use core::fmt::Write as _;

        let (open, close) = match self.kind {
            Kind::P2sh => ("sh(", ")"),
            Kind::P2wsh => ("wsh(", ")"),
            Kind::P2shP2wsh => ("sh(wsh(", "))"),
        };
        let func = if self.sorted { "sortedmulti" } else { "multi" };

        let mut buf = Buf { out, len: 0 };
        buf.write_str(open).map_err(|_| Error::Overflow)?;
        write!(buf, "{}({}", func, self.m).map_err(|_| Error::Overflow)?;
        for c in self.cosigners() {
            let [a, b, cc, d] = c.fingerprint;
            write!(buf, ",[{a:02x}{b:02x}{cc:02x}{d:02x}").map_err(|_| Error::Overflow)?;
            for &step in c.origin() {
                if step & HARDENED_OFFSET != 0 {
                    write!(buf, "/{}h", step & !HARDENED_OFFSET).map_err(|_| Error::Overflow)?;
                } else {
                    write!(buf, "/{step}").map_err(|_| Error::Overflow)?;
                }
            }
            let mut key = [0u8; MAX_BASE58_LEN];
            let n = c.xpub.write_base58(&mut key).map_err(|_| Error::Overflow)?;
            let key = core::str::from_utf8(&key[..n]).map_err(|_| Error::Overflow)?;
            write!(buf, "]{key}/{chain}/*").map_err(|_| Error::Overflow)?;
        }
        // Close the `multi(...)`/`sortedmulti(...)` itself, then the script wrapper(s).
        buf.write_str(")").map_err(|_| Error::Overflow)?;
        buf.write_str(close).map_err(|_| Error::Overflow)?;

        let len = buf.len;
        let body = core::str::from_utf8(&buf.out[..len]).map_err(|_| Error::Overflow)?;
        let sum = crate::descriptor::checksum(body).ok_or(Error::Overflow)?;
        buf.write_char('#').map_err(|_| Error::Overflow)?;
        let sum = core::str::from_utf8(&sum).map_err(|_| Error::Overflow)?;
        buf.write_str(sum).map_err(|_| Error::Overflow)?;
        Ok(buf.len)
    }
}

/// Any error, read as "the output buffer was too small": the one failure a writer over a
/// caller's buffer has. Generic so one name serves `fmt`, Base58 and UTF-8 errors alike.
pub(crate) fn overflow<E>(_: E) -> Error {
    Error::Overflow
}

/// A `core::fmt::Write` over a fixed byte buffer, for [`Multisig::write_descriptor`] and
/// the export writers beside it.
pub(crate) struct Buf<'a> {
    pub(crate) out: &'a mut [u8],
    pub(crate) len: usize,
}

/// How one wallet stands to another: the question an import asks of every registered
/// wallet before it adds a new one.
///
/// Stock calls the middle case "similar" and warns about it, because two registrations
/// over the same keys are the way a person comes to sign against the wrong one: a
/// `multi` where the other cosigners have `sortedmulti`, or the same keys in a different
/// order, produces addresses none of them recognise.
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub enum Likeness {
    /// The same agreement in every respect.
    Same,
    /// The same set of extended keys, but not the same wallet: another order, another
    /// threshold, another script form, or sorted where the other is not.
    Similar,
    Different,
}

/// Compare two wallets. See [`Likeness`].
pub fn compare(a: &Multisig, b: &Multisig) -> Likeness {
    if a == b {
        return Likeness::Same;
    }
    if a.n() != b.n() {
        return Likeness::Different;
    }
    // The same keys, as a set: every key of `a` is in `b`, and the counts agree, and
    // `new`/`parse` refuse a duplicate key, so that is set equality.
    let same_keys = a
        .cosigners()
        .iter()
        .all(|x| b.cosigners().iter().any(|y| y.xpub == x.xpub));
    if same_keys {
        Likeness::Similar
    } else {
        Likeness::Different
    }
}

impl core::fmt::Write for Buf<'_> {
    fn write_str(&mut self, s: &str) -> core::fmt::Result {
        let end = self.len + s.len();
        self.out
            .get_mut(self.len..end)
            .ok_or(core::fmt::Error)?
            .copy_from_slice(s.as_bytes());
        self.len = end;
        Ok(())
    }
}

/// Which registered wallet a script belongs to, at which address.
///
/// The script is rebuilt from each wallet's own record and compared with the one the coin
/// is actually locked to. That is the whole check: a host cannot nominate a wallet, and a
/// script that no registered wallet produces belongs to none of them.
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub struct Match {
    /// Index into the slice of wallets that was searched.
    pub wallet: usize,
    pub branch: u32,
    pub index: u32,
}

/// Find the registered wallet whose address at `branch`/`index` is `script_pubkey`.
///
/// `None` means no registered wallet owns it, which for an input is a refusal to sign and
/// for an output is "not our change". Both are the safe answer: a multisig script this
/// device cannot account for is one whose cosigners it has never been shown.
pub fn match_script(
    wallets: &[Multisig],
    script_pubkey: &[u8],
    branch: u32,
    index: u32,
) -> Option<Match> {
    for (at, wallet) in wallets.iter().enumerate() {
        let mut built = [0u8; 34];
        let Ok(n) = wallet.script_pubkey(branch, index, &mut built) else {
            continue;
        };
        if built[..n] == *script_pubkey {
            return Some(Match {
                wallet: at,
                branch,
                index,
            });
        }
    }
    None
}

/// Whether a scriptPubKey is one of the script-hash forms a multisig wallet produces.
///
/// Used to decide whether an input *needs* a registered wallet before it may be signed:
/// a P2SH or P2WSH input is either a wallet this device knows or one it must refuse, and
/// the two must not be confused with the single-signature forms.
pub fn is_script_hash(script_pubkey: &[u8]) -> bool {
    matches!(script_pubkey, [0xA9, 0x14, .., 0x87] if script_pubkey.len() == 23)
        || matches!(script_pubkey, [0x00, 32, ..] if script_pubkey.len() == 34)
}

/// Write `M <key…> N CHECKMULTISIG` from keys already derived.
///
/// Separate from [`Multisig::script`] so it can be checked against BIP-383's test vectors,
/// which derive their keys along per-key paths this wallet model does not use. The bytes
/// this produces are what every cosigner must agree on, so they are worth checking against
/// someone else's implementation rather than only against ours.
pub fn assemble(
    m: u8,
    keys: &mut [[u8; 33]],
    sorted: bool,
    out: &mut [u8],
) -> Result<usize, Error> {
    if keys.is_empty() || keys.len() > MAX_COSIGNERS {
        return Err(Error::CosignerCount { n: keys.len() });
    }
    if m == 0 || m as usize > keys.len() {
        return Err(Error::BadThreshold);
    }
    if sorted {
        // BIP-67: lexicographic over the compressed encoding, so every cosigner builds
        // the same script without having agreed an order.
        keys.sort_unstable();
    }

    // `OP_1`..`OP_16` are 0x51..0x60, and `MAX_COSIGNERS` keeps both numbers inside that.
    let mut at = 0usize;
    let mut put = |bytes: &[u8], at: &mut usize| -> Result<(), Error> {
        out.get_mut(*at..*at + bytes.len())
            .ok_or(Error::Overflow)?
            .copy_from_slice(bytes);
        *at += bytes.len();
        Ok(())
    };
    put(&[0x50 + m], &mut at)?;
    for key in keys.iter() {
        put(&[33], &mut at)?;
        put(key, &mut at)?;
    }
    put(&[0x50 + keys.len() as u8], &mut at)?;
    put(&[0xAE], &mut at)?; // OP_CHECKMULTISIG
    Ok(at)
}

/// `OP_HASH160 <20> OP_EQUAL`.
fn write_p2sh(hash: &[u8; 20], out: &mut [u8]) -> Result<usize, Error> {
    let buf = out.get_mut(..23).ok_or(Error::Overflow)?;
    buf[0] = 0xA9;
    buf[1] = 20;
    buf[2..22].copy_from_slice(hash);
    buf[22] = 0x87;
    Ok(23)
}

/// `OP_0 <32>`.
fn write_p2wsh(sha: &[u8], out: &mut [u8]) -> Result<usize, Error> {
    let buf = out.get_mut(..34).ok_or(Error::Overflow)?;
    buf[0] = 0x00;
    buf[1] = 32;
    buf[2..34].copy_from_slice(sha);
    Ok(34)
}

/// Read a multisig wallet out of an output descriptor.
///
/// Accepts `sh(...)`, `wsh(...)` and `sh(wsh(...))` around `multi(...)` or
/// `sortedmulti(...)`, each key written with its origin: `[fingerprint/path]xpub/0/*`.
/// The checksum is required.
pub fn parse(text: &str) -> Result<Multisig, Error> {
    let text = text.trim();
    if !descriptor::verify(text) {
        return Err(Error::BadChecksum);
    }
    // `verify` established the shape and that the body holds no `#`; split the
    // same way it did, so both cover the same bytes.
    let body = text.rsplit_once('#').map_or(text, |(body, _)| body);

    let (kind, inner) = if let Some(rest) = strip(body, "sh(wsh(") {
        (Kind::P2shP2wsh, strip_close(rest, 2)?)
    } else if let Some(rest) = strip(body, "wsh(") {
        (Kind::P2wsh, strip_close(rest, 1)?)
    } else if let Some(rest) = strip(body, "sh(") {
        (Kind::P2sh, strip_close(rest, 1)?)
    } else {
        return Err(Error::NotMultisig);
    };

    let (sorted, args) = if let Some(rest) = strip(inner, "sortedmulti(") {
        (true, strip_close(rest, 1)?)
    } else if let Some(rest) = strip(inner, "multi(") {
        (false, strip_close(rest, 1)?)
    } else {
        return Err(Error::NotMultisig);
    };

    let mut parts = args.split(',');
    let m: u8 = parts
        .next()
        .and_then(|t| t.trim().parse().ok())
        .ok_or(Error::BadThreshold)?;

    // Parsed into an `Option` array rather than over a placeholder key: there is no
    // meaningful empty `ExtendedPubKey`, and inventing one would put a key in a record
    // that nobody chose.
    let mut parsed: [Option<Cosigner>; MAX_COSIGNERS] = [None; MAX_COSIGNERS];
    let mut n = 0usize;
    for (at, key) in parts.enumerate() {
        if n == MAX_COSIGNERS {
            return Err(Error::CosignerCount { n: n + 1 });
        }
        let (cosigner, form) = parse_key(key.trim(), at)?;
        // The SLIP-132 prefix is a hint about the script type, read but never trusted
        // over the descriptor: `wsh(...)` says what the wallet is. A hint that agrees, or
        // a classic `xpub` that says nothing, is fine; one that names another script
        // type is a file at odds with itself.
        if !kind.accepts_form(form) {
            return Err(Error::FormMismatch { at });
        }
        parsed[n] = Some(cosigner);
        n += 1;
    }
    let Some(first) = parsed[0] else {
        return Err(Error::CosignerCount { n });
    };
    let mut cosigners = [first; MAX_COSIGNERS];
    for (slot, got) in cosigners.iter_mut().zip(parsed.iter()).skip(1) {
        if let Some(c) = got {
            *slot = *c;
        }
    }
    if m == 0 || m as usize > n {
        return Err(Error::BadThreshold);
    }
    // Two cosigners with one key is a wallet whose threshold lies about how many parties
    // hold it: 2-of-3 where two of the three are the same device is a 2-of-2.
    for i in 0..n {
        for j in (i + 1)..n {
            if cosigners[i].xpub == cosigners[j].xpub {
                return Err(Error::DuplicateKey);
            }
        }
    }

    Ok(Multisig {
        m,
        cosigners,
        n,
        kind,
        sorted,
    })
}

impl Kind {
    /// Whether a cosigner key written in `form` may sit inside this script wrapper.
    ///
    /// SLIP-132 gives the two multisig forms their own prefixes -- `Ypub` for P2WSH in
    /// P2SH, `Zpub` for native P2WSH -- and none for bare `sh(multi(...))`, which stays
    /// classic. Classic always passes: it names no script type at all.
    /// Source: SLIP-0132 registry, "Address Encoding" column [C].
    pub const fn accepts_form(self, form: Slip132) -> bool {
        matches!(
            (self, form),
            (_, Slip132::Classic)
                | (Kind::P2wsh, Slip132::P2wsh)
                | (Kind::P2shP2wsh, Slip132::P2wshP2sh)
        )
    }
}

/// `[fingerprint/a/b/c]xpub.../0/*` or `.../<0;1>/*`, and the SLIP-132 form the key was
/// written in.
fn parse_key(text: &str, at: usize) -> Result<(Cosigner, Slip132), Error> {
    let bad = || Error::BadKey { at };
    let rest = text.strip_prefix('[').ok_or_else(bad)?;
    let (origin_text, rest) = rest.split_once(']').ok_or_else(bad)?;

    let mut origin_parts = origin_text.split('/');
    let fp_text = origin_parts.next().ok_or_else(bad)?;
    if fp_text.len() != 8 {
        return Err(bad());
    }
    let mut fingerprint = [0u8; 4];
    for (slot, pair) in fingerprint.iter_mut().zip(fp_text.as_bytes().chunks(2)) {
        let hex = core::str::from_utf8(pair).map_err(|_| bad())?;
        *slot = u8::from_str_radix(hex, 16).map_err(|_| bad())?;
    }

    let mut origin = [0u32; MAX_ORIGIN];
    let mut origin_len = 0usize;
    for step in origin_parts {
        if origin_len == MAX_ORIGIN {
            return Err(bad());
        }
        let (digits, hardened) = match step.strip_suffix(['h', 'H', '\'']) {
            Some(d) => (d, true),
            None => (step, false),
        };
        let index: u32 = digits.parse().map_err(|_| bad())?;
        if index >= 0x8000_0000 {
            return Err(bad());
        }
        origin[origin_len] = if hardened { index | 0x8000_0000 } else { index };
        origin_len += 1;
    }

    // The key itself, then the derivation suffix. What the suffix *is* does not change the
    // wallet -- every reader walks the same two unhardened levels below the account key --
    // so it is checked for shape and not stored.
    let (key_text, suffix) = match rest.split_once('/') {
        Some((k, s)) => (k, s),
        None => (rest, ""),
    };
    if !suffix.is_empty() && !suffix.ends_with('*') {
        return Err(bad());
    }
    let (xpub, form) = ExtendedPubKey::from_base58_with_form(key_text).map_err(|_| bad())?;

    Ok((
        Cosigner {
            fingerprint,
            origin,
            origin_len,
            xpub,
        },
        form,
    ))
}

/// `text` without `prefix`, if it starts with it.
fn strip<'a>(text: &'a str, prefix: &str) -> Option<&'a str> {
    text.strip_prefix(prefix)
}

/// `text` without `count` closing parentheses at its end.
fn strip_close(text: &str, count: usize) -> Result<&str, Error> {
    let mut rest = text;
    for _ in 0..count {
        rest = rest.strip_suffix(')').ok_or(Error::NotMultisig)?;
    }
    Ok(rest)
}

#[cfg(test)]
mod tests;
