//! Signing a PSBT with this wallet's keys.
//!
//! The PSBT itself -- parsing, the signer role, the sighashes, finalisation -- is
//! [`outscript`]. This module is the part that is ours: deciding **which** of a PSBT's keys
//! this seed controls, deriving those keys, and keeping the derivation and the signature
//! inside a masked region.
//!
//! # What "ours" means
//!
//! An input names the keys that can spend it, each with a master fingerprint and a
//! derivation path. A key is ours when the fingerprint matches this seed's master and the
//! key derived down that path is the key the record names. The fingerprint alone is a
//! four-byte claim from the host and proves nothing: [`match_key`] derives and compares.
//!
//! # Interrupts
//!
//! Every function here that touches a private key takes a [`KeyWork`], so it can only be
//! called from inside `keywork::run`. The boundary between inputs is a fine place to let
//! the screen move: which input is being signed is public -- it is in the PSBT -- so
//! pausing there leaks nothing.

use outscript::crypto::secp256k1::{DerSignature, SecpPrivateKey, SecpPublicKey};
use outscript::psbt::SignerError;
use outscript::psbt::{Psbt, PsbtSigner, input as in_key};

use zeroize::Zeroize;

use crate::KeyWork;
use crate::bip32::{ChildNumber, ExtendedPrivKey, FINGERPRINT_LEN};
use crate::tx::sighash::SIGHASH_ALL;

/// Whether `kind` is a sighash type this device will produce.
///
/// `SIGHASH_ALL` alone: every other type leaves part of the transaction unsigned --
/// NONE and SINGLE the outputs, ANYONECANPAY the other inputs -- which is a thing to offer
/// deliberately with its own warning, not to produce because a PSBT asked. A multichain
/// build also takes the one unified opt-in byte that means exactly ALL
/// (`SIGHASH_ALL | SIGHASH_UNIFIED`), which covers the same outputs under the fork's hash.
///
/// One answer for the review and the signature: [`crate::psbtview::summarise`] refuses
/// the transaction on it, and [`sign_input`] refuses the input on it, so a PSBT that
/// reaches the signer by some other path meets the same policy. `outscript` itself signs
/// whatever type the input carries.
///
/// Source: BIP-174 "If a sighash type is not provided, the signer should sign using
/// SIGHASH_ALL" [C]
pub fn sighash_allowed(kind: u32) -> bool {
    if kind == SIGHASH_ALL {
        return true;
    }
    #[cfg(feature = "multichain")]
    if kind == SIGHASH_ALL | u32::from(crate::tx::unified::SIGHASH_UNIFIED) {
        return true;
    }
    false
}

/// What to do with an input asking for a sighash type [`sighash_allowed`] refuses.
///
/// The owner's choice, from the settings (`catcard_settings::prefs::SighashChecks`): the
/// default blocks, and the Danger Zone can turn that into a warning. This is the wallet
/// crate's copy of that choice so the review and the signature read one value.
/// Source: hw-reference/firmware-features.md §5 "Sighash policy" [C]
#[derive(Copy, Clone, PartialEq, Eq, Debug, Default)]
pub enum SighashPolicy {
    /// Refuse the transaction. The default.
    #[default]
    Block,
    /// Sign it once the owner has been warned. The review lists the inputs and their
    /// types; a consolidation is refused regardless.
    Warn,
}

/// Whether `kind` is a type this device will produce under `policy`.
///
/// Under [`SighashPolicy::Block`] this is [`sighash_allowed`]. Under
/// [`SighashPolicy::Warn`] the five other standard ECDSA types are allowed as well --
/// `ALL|ANYONECANPAY`, `NONE`, `SINGLE`, and those two with `ANYONECANPAY` -- and
/// nothing beyond them: an unknown flag byte is not "unusual", it is undefined.
/// Source: BIP-143 "hash type" values; Bitcoin Core `SIGHASH_*` [C]
pub fn sighash_allowed_under(kind: u32, policy: SighashPolicy) -> bool {
    use crate::tx::sighash::{SIGHASH_ANYONECANPAY, SIGHASH_NONE, SIGHASH_SINGLE};
    if sighash_allowed(kind) {
        return true;
    }
    match policy {
        SighashPolicy::Block => false,
        SighashPolicy::Warn => {
            let base = kind & !SIGHASH_ANYONECANPAY;
            kind & !(SIGHASH_ANYONECANPAY | 0x1f) == 0
                && (base == SIGHASH_ALL || base == SIGHASH_NONE || base == SIGHASH_SINGLE)
        }
    }
}

/// Longest derivation path this will follow.
///
/// Deeper than any standard single-signature or multisig path (`m/84h/0h/0h/0/i` is five),
/// and bounded so a hostile PSBT cannot ask for an unbounded walk.
pub const MAX_STEPS: usize = 12;

/// Longest public key a derivation record names: 65 bytes, uncompressed.
///
/// BIP-174 allows either SEC1 form in a `BIP32_DERIVATION` key, and a bare P2PK output
/// from before compressed keys were the norm pushes the uncompressed one. Source: BIP-174
/// "`<33 or 65 byte pubkey>`" [C]
pub const MAX_PUBKEY_LEN: usize = 65;

/// One of our keys, as an input asks for it.
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub struct KeyRequest {
    /// The public key the record names: 33 bytes compressed, 65 uncompressed, or 32
    /// x-only for taproot.
    pub pubkey: [u8; MAX_PUBKEY_LEN],
    pub pubkey_len: usize,
    steps: [u32; MAX_STEPS],
    depth: usize,
    /// Whether this came from a taproot record, and so wants a Schnorr signature.
    pub taproot: bool,
}

impl KeyRequest {
    /// A placeholder, for filling an array before [`key_requests`] writes into it.
    pub const EMPTY: Self = Self {
        pubkey: [0; MAX_PUBKEY_LEN],
        pubkey_len: 0,
        steps: [0; MAX_STEPS],
        depth: 0,
        taproot: false,
    };

    /// The path below the master key.
    pub fn steps(&self) -> &[u32] {
        &self.steps[..self.depth]
    }

    pub fn pubkey(&self) -> &[u8] {
        &self.pubkey[..self.pubkey_len]
    }

    /// Whether the record names the key in its uncompressed (65-byte) form.
    pub fn uncompressed(&self) -> bool {
        self.pubkey_len == MAX_PUBKEY_LEN
    }
}

/// Why an input could not be signed with our keys.
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub enum Error {
    /// No key in this input belongs to this seed.
    NotOurs,
    /// A derivation path this will not follow: too deep, or a step that is not a child.
    BadPath,
    /// The key derived down the stated path is not the key the record names. The host is
    /// wrong about what it is asking for, which is never something to sign through.
    KeyMismatch,
    /// Deriving the key failed.
    Derivation,
    /// The input asks for a sighash type this will not produce; see [`sighash_allowed`]
    /// and [`sighash_allowed_under`]. Also a type the policy allows on an input this has
    /// no digest for: a non-`ALL` type on a legacy (pre-segwit) input, whose sighash does
    /// not commit to the amount and which this crate does not compute.
    Sighash { kind: u32 },
    /// `outscript` refused the input: a script it does not sign, a UTXO that does not
    /// match, a hash that does not check out.
    Psbt(outscript::Error),
}

impl From<outscript::Error> for Error {
    fn from(e: outscript::Error) -> Self {
        Error::Psbt(e)
    }
}

/// Read the `<4 byte fingerprint> <32-bit little endian path element>*` value of a
/// derivation record.
fn origin(value: &[u8]) -> Option<([u8; FINGERPRINT_LEN], &[u8])> {
    if value.len() < FINGERPRINT_LEN || !(value.len() - FINGERPRINT_LEN).is_multiple_of(4) {
        return None;
    }
    let mut fp = [0u8; FINGERPRINT_LEN];
    fp.copy_from_slice(&value[..FINGERPRINT_LEN]);
    Some((fp, &value[FINGERPRINT_LEN..]))
}

fn steps_of(path: &[u8]) -> Option<([u32; MAX_STEPS], usize)> {
    let depth = path.len() / 4;
    if depth > MAX_STEPS {
        return None;
    }
    let mut steps = [0u32; MAX_STEPS];
    for (slot, raw) in steps.iter_mut().zip(path.as_chunks::<4>().0) {
        *slot = u32::from_le_bytes(*raw);
    }
    Some((steps, depth))
}

/// Most keys one input can name: BIP-67 multisig allows fifteen cosigners, and every one
/// of them could be ours in a wallet that holds several of the keys.
pub const MAX_KEYS_PER_INPUT: usize = 15;

/// One derivation record as a [`KeyRequest`], if it claims `fingerprint` and is the shape
/// its type requires.
///
/// Shared by the input scan here and the change check in [`crate::psbtview`], so both read
/// a record the same way.
pub fn request_from_record(
    rec: outscript::psbt::Record<'_>,
    fingerprint: [u8; FINGERPRINT_LEN],
    taproot: bool,
) -> Option<KeyRequest> {
    let key = rec.key_data();
    // 33 bytes compressed (or 65 uncompressed) for BIP-32 records, 32 x-only for taproot
    // ones. Another length is a record this does not understand, not one to guess at.
    let shape_ok = if taproot {
        key.len() == 32
    } else {
        key.len() == 33 || key.len() == MAX_PUBKEY_LEN
    };
    if !shape_ok {
        return None;
    }
    // A taproot derivation value carries leaf hashes before the origin.
    let value = if taproot {
        let (count, rest) = varint_usize(rec.value)?;
        count.checked_mul(32).and_then(|s| rest.get(s..))?
    } else {
        rec.value
    };
    let (fp, path) = origin(value)?;
    if fp != fingerprint {
        return None;
    }
    let (steps, depth) = steps_of(path)?;
    let mut pubkey = [0u8; MAX_PUBKEY_LEN];
    pubkey[..key.len()].copy_from_slice(key);
    Some(KeyRequest {
        pubkey,
        pubkey_len: key.len(),
        steps,
        depth,
        taproot,
    })
}

/// Collect the keys in input `index` that claim to come from `fingerprint`, into `out`.
///
/// A claim, not a fact: [`match_key`] is what settles it. Returns how many were written;
/// records beyond `out`'s length are ignored, and the ECDSA ones come before the taproot
/// ones so a caller that signs only ECDSA meets those first.
pub fn key_requests(
    psbt: &Psbt<'_>,
    index: usize,
    fingerprint: [u8; FINGERPRINT_LEN],
    out: &mut [KeyRequest],
) -> Result<usize, Error> {
    let Some(map) = psbt.input(index).map(|i| i.map()) else {
        return Ok(0);
    };
    let mut n = 0;
    for taproot in [false, true] {
        let keytype = if taproot {
            in_key::TAP_BIP32_DERIVATION
        } else {
            in_key::BIP32_DERIVATION
        };
        for rec in map.records_of(keytype) {
            if n == out.len() {
                return Ok(n);
            }
            // A path too deep to follow is refused for the whole input rather than skipped:
            // a signer that quietly ignores one key in a multisig input produces a PSBT
            // nobody can finalise, with no reason given.
            if claims(rec, fingerprint, taproot)
                && request_from_record(rec, fingerprint, taproot).is_none()
            {
                return Err(Error::BadPath);
            }
            if let Some(request) = request_from_record(rec, fingerprint, taproot) {
                out[n] = request;
                n += 1;
            }
        }
    }
    Ok(n)
}

/// Whether a record names `fingerprint` at all, ignoring whether the rest of it is
/// something this can follow.
fn claims(
    rec: outscript::psbt::Record<'_>,
    fingerprint: [u8; FINGERPRINT_LEN],
    taproot: bool,
) -> bool {
    let value = if taproot {
        match varint_usize(rec.value)
            .and_then(|(c, rest)| c.checked_mul(32).and_then(|s| rest.get(s..)))
        {
            Some(v) => v,
            None => return false,
        }
    } else {
        rec.value
    };
    origin(value).is_some_and(|(fp, _)| fp == fingerprint)
}

/// A minimal compact-size read, for the leaf-hash count of a taproot record.
fn varint_usize(value: &[u8]) -> Option<(usize, &[u8])> {
    let (&first, rest) = value.split_first()?;
    match first {
        0..=0xfc => Some((first as usize, rest)),
        0xfd => {
            let (n, rest) = rest.split_at_checked(2)?;
            Some((u16::from_le_bytes(n.try_into().ok()?) as usize, rest))
        }
        0xfe => {
            let (n, rest) = rest.split_at_checked(4)?;
            Some((u32::from_le_bytes(n.try_into().ok()?) as usize, rest))
        }
        // A count that needs eight bytes is not a leaf count; refuse rather than truncate.
        _ => None,
    }
}

/// The private key for `request`, if it really is ours.
///
/// Derives down the path and compares the result with the key the record names -- x-only
/// for a taproot record, uncompressed for a 65-byte one, compressed otherwise. A mismatch
/// is [`Error::KeyMismatch`]: the host asked for a signature from a key that is not at
/// the path it gave.
///
/// The returned key zeroizes its own copy of the secret on drop.
pub fn match_key(
    master: &ExtendedPrivKey,
    request: &KeyRequest,
    kw: &KeyWork,
) -> Result<Signer, Error> {
    let mut here = master.clone();
    for &step in request.steps() {
        let child = ChildNumber(step);
        here = here
            .derive_child(child, kw)
            .map_err(|_| Error::Derivation)?;
    }
    let mut secret = *here.secret_bytes();
    let signer = Signer::new(&secret, request.taproot);
    secret.zeroize();
    let signer = signer.ok_or(Error::Derivation)?;

    let ours = signer.key.public_key().serialize_compressed();
    let matches = if request.taproot {
        ours[1..] == *request.pubkey()
    } else if request.uncompressed() {
        signer.key.public_key().serialize_uncompressed()[..] == *request.pubkey()
    } else {
        ours[..] == *request.pubkey()
    };
    if !matches {
        return Err(Error::KeyMismatch);
    }
    Ok(signer)
}

/// One of our keys, ready to sign one input.
///
/// Holds the key material for as long as the signature takes and no longer: the bytes this
/// module owns are zeroized, and `outscript`'s key wipes its own copy of the scalar when
/// dropped (`ZeroizeOnDrop`, since 0.2.1).
pub struct Signer {
    key: SecpPrivateKey,
    taproot: bool,
}

impl Signer {
    fn new(secret: &[u8; 32], taproot: bool) -> Option<Self> {
        Some(Self {
            key: SecpPrivateKey::from_bytes(secret).ok()?,
            taproot,
        })
    }

    /// A signer for a bare private key -- a WIF-store key with no derivation path.
    ///
    /// `outscript` decides which script an input pays and whether this key is involved, so
    /// this does not carry a taproot flag: it can produce either signature, and the input's
    /// script settles which. `None` for bytes that are not a usable scalar.
    pub fn from_secret(secret: &[u8; 32], _kw: &KeyWork) -> Option<Self> {
        Self::new(secret, false)
    }

    /// Whether this key signs the taproot key path.
    pub fn is_taproot(&self) -> bool {
        self.taproot
    }

    /// The compressed public key, for rebuilding the script an output of ours would pay to.
    pub fn public_key_bytes(&self) -> [u8; 33] {
        self.key.public_key().serialize_compressed()
    }

    /// The uncompressed (65-byte) public key, for a bare P2PK script that pushes that form.
    pub fn public_key_uncompressed(&self) -> [u8; MAX_PUBKEY_LEN] {
        self.key.public_key().serialize_uncompressed()
    }
}

/// The bare pay-to-public-key script for `pubkey` (33 or 65 bytes), written into `out`;
/// returns its length, or `None` for a key of another length.
///
/// `<push> <key> OP_CHECKSIG`: the oldest output form there is, with no hash between the
/// key and the coin. It has no address -- nothing encodes it -- so it is recognised by
/// the script alone, and shown as "P2PK" and the key. The legacy sighash signs it, which
/// `outscript` already does for any legacy script that pushes our key.
/// Source: Bitcoin script `OP_CHECKSIG` (0xac); stock signs P2PK
/// (hw-reference/firmware-features.md §3, §5) [C]
pub fn p2pk_script(pubkey: &[u8], out: &mut [u8; P2PK_SCRIPT_MAX]) -> Option<usize> {
    if !matches!(pubkey.len(), 33 | MAX_PUBKEY_LEN) {
        return None;
    }
    out[0] = pubkey.len() as u8;
    out[1..1 + pubkey.len()].copy_from_slice(pubkey);
    out[1 + pubkey.len()] = 0xac;
    Some(pubkey.len() + 2)
}

/// Longest P2PK script: a 65-byte key with its push byte and `OP_CHECKSIG`.
pub const P2PK_SCRIPT_MAX: usize = 1 + MAX_PUBKEY_LEN + 1;

/// Whether `script` is a bare P2PK output, and the key it pays, if so.
pub fn p2pk_key(script: &[u8]) -> Option<&[u8]> {
    match script {
        [0x21, key @ .., 0xac] if key.len() == 33 => Some(key),
        [0x41, key @ .., 0xac] if key.len() == MAX_PUBKEY_LEN => Some(key),
        _ => None,
    }
}

/// Whether `script` pays `pubkey` (compressed) through bare P2PK, in either SEC1 form.
///
/// Public work: the uncompressed form is the same point written out in full, and a script
/// pushing that form is paid by the same key.
pub fn p2pk_pays(script: &[u8], pubkey: &[u8; 33]) -> bool {
    let Some(key) = p2pk_key(script) else {
        return false;
    };
    if key.len() == 33 {
        return key == pubkey;
    }
    SecpPublicKey::from_sec1(pubkey).is_ok_and(|pk| pk.serialize_uncompressed()[..] == *key)
}

impl PsbtSigner for Signer {
    fn public_key(&self) -> SecpPublicKey {
        self.key.public_key()
    }

    fn sign_ecdsa(&self, digest: &[u8; 32]) -> Result<DerSignature, SignerError> {
        Ok(self.key.sign_der(digest))
    }

    fn sign_taproot(&self, sighash: &[u8; 32]) -> Result<[u8; 64], SignerError> {
        SecpPrivateKey::sign_taproot(&self.key, sighash).map_err(|_| SignerError)
    }
}

/// Sign input `index` of `psbt` with our key, writing the updated PSBT into `out`.
///
/// One input at a time, because each write produces a whole new PSBT: the caller
/// alternates between two buffers, and can move the screen between inputs.
///
/// The sighash policy is checked here as well as at review ([`sighash_allowed`]): the
/// review refuses the whole transaction, this refuses the input, and neither trusts the
/// other to have run. Absent a type the signature is `SIGHASH_ALL`, which is allowed.
pub fn sign_input(
    psbt: &Psbt<'_>,
    index: usize,
    master: &ExtendedPrivKey,
    fingerprint: [u8; FINGERPRINT_LEN],
    out: &mut [u8],
    kw: &KeyWork,
) -> Result<usize, Error> {
    sign_input_under(
        psbt,
        index,
        master,
        fingerprint,
        SighashPolicy::Block,
        out,
        kw,
    )
}

/// [`sign_input`] under the owner's sighash policy.
///
/// A type [`sighash_allowed`] takes goes through `outscript`'s signer as before. One that
/// only [`SighashPolicy::Warn`] admits is signed here instead, because `outscript` signs
/// ECDSA inputs under `SIGHASH_ALL` alone: the BIP-143 digest is computed by this crate
/// ([`crate::tx::sighash::bip143`]), which does drop the outputs and inputs the type says
/// to, and the signature is written as the input's partial-signature record. That path
/// covers segwit v0 inputs (P2WPKH, nested P2WPKH, P2WSH); a taproot input's type is
/// honoured by `outscript` itself; a legacy input under a non-`ALL` type is refused with
/// [`Error::Sighash`], since its digest is not computed here.
pub fn sign_input_under(
    psbt: &Psbt<'_>,
    index: usize,
    master: &ExtendedPrivKey,
    fingerprint: [u8; FINGERPRINT_LEN],
    policy: SighashPolicy,
    out: &mut [u8],
    kw: &KeyWork,
) -> Result<usize, Error> {
    sign_input_filtered(psbt, index, master, fingerprint, policy, None, out, kw)
}

/// [`sign_input_under`], with only the keys at `listed` paths.
///
/// For a request that named the keys it wants -- a computer asking over USB, which may
/// only reach keys under an account the person showed it. A record for a key of ours at
/// a path not in `listed` is passed over as though it were somebody else's, so an input
/// that only such a key can sign fails [`Error::NotOurs`] and is left unsigned. The
/// restriction is here, where the key is chosen, rather than in a pass that removes
/// signatures afterwards: a signature that was never made cannot be left behind by
/// mistake.
#[allow(clippy::too_many_arguments)]
pub fn sign_input_listed(
    psbt: &Psbt<'_>,
    index: usize,
    master: &ExtendedPrivKey,
    fingerprint: [u8; FINGERPRINT_LEN],
    policy: SighashPolicy,
    listed: &[crate::hostkeys::KeyPath],
    out: &mut [u8],
    kw: &KeyWork,
) -> Result<usize, Error> {
    sign_input_filtered(
        psbt,
        index,
        master,
        fingerprint,
        policy,
        Some(listed),
        out,
        kw,
    )
}

/// Whether `request`'s path is one of `listed`, or any path at all when there is no list.
pub fn is_listed(request: &KeyRequest, listed: Option<&[crate::hostkeys::KeyPath]>) -> bool {
    listed.is_none_or(|l| l.iter().any(|k| k.steps() == request.steps()))
}

#[allow(clippy::too_many_arguments)]
fn sign_input_filtered(
    psbt: &Psbt<'_>,
    index: usize,
    master: &ExtendedPrivKey,
    fingerprint: [u8; FINGERPRINT_LEN],
    policy: SighashPolicy,
    listed: Option<&[crate::hostkeys::KeyPath]>,
    out: &mut [u8],
    kw: &KeyWork,
) -> Result<usize, Error> {
    let kind = psbt.input(index).and_then(|i| i.sighash_type());
    if let Some(kind) = kind
        && !sighash_allowed_under(kind, policy)
    {
        return Err(Error::Sighash { kind });
    }
    let mut keys = [KeyRequest::EMPTY; MAX_KEYS_PER_INPUT];
    let found = key_requests(psbt, index, fingerprint, &mut keys)?;
    let mut last = Error::NotOurs;
    for request in keys[..found].iter().filter(|r| is_listed(r, listed)) {
        match match_key(master, request, kw) {
            Ok(signer) => return sign_with(psbt, index, &signer, kind, out),
            Err(e) => last = e,
        }
    }
    Err(last)
}

/// Sign input `index` with `signer`, by whichever path its sighash type needs.
fn sign_with(
    psbt: &Psbt<'_>,
    index: usize,
    signer: &Signer,
    kind: Option<u32>,
    out: &mut [u8],
) -> Result<usize, Error> {
    match kind {
        // The ordinary type, or a taproot input, whose type `outscript` honours itself.
        Some(kind) if !sighash_allowed(kind) && !signer.taproot => {
            sign_odd_sighash(psbt, index, signer, kind, out)
        }
        _ => Ok(psbt.sign_input_to_slice(index, signer, out)?),
    }
}

/// Sign a segwit v0 input under a non-`ALL` type, writing the updated PSBT into `out`.
///
/// The one place this crate builds a signature by hand. The script code is settled the
/// way BIP-143 says -- the implied P2PKH script for a P2WPKH program, the witness script
/// for P2WSH -- and only after the spent output (which [`Psbt::utxo`] has checked against
/// the previous transaction's txid) is shown to pay a script our key is in. A legacy
/// input, or a P2SH input whose redeem script is not a P2WPKH program, is refused: its
/// digest is not the BIP-143 one and is not computed here.
fn sign_odd_sighash(
    psbt: &Psbt<'_>,
    index: usize,
    signer: &Signer,
    kind: u32,
    out: &mut [u8],
) -> Result<usize, Error> {
    use crate::tx::Transaction;
    use crate::tx::sighash::{Midstates, bip143};
    use purecrypto::hash::{Digest, Sha256};

    let inp = psbt.input(index).ok_or(Error::NotOurs)?;
    let spent = psbt.utxo(index)?;
    let pubkey = signer.public_key_bytes();
    let key_hash = crate::bip32::hash160(&pubkey);

    // `76 a9 14 <h160> 88 ac`: the script code BIP-143 gives a P2WPKH spend.
    let mut p2pkh = [0u8; 25];
    p2pkh[..3].copy_from_slice(&[0x76, 0xa9, 0x14]);
    p2pkh[3..23].copy_from_slice(&key_hash);
    p2pkh[23..].copy_from_slice(&[0x88, 0xac]);

    // The program the coin is locked to: native, or inside P2SH via the redeem script.
    let program: &[u8] = if spent.script.len() == 23
        && spent.script[0] == 0xa9
        && spent.script[1] == 0x14
        && spent.script[22] == 0x87
    {
        let redeem = inp.redeem_script().ok_or(Error::Sighash { kind })?;
        if crate::bip32::hash160(redeem) != spent.script[2..22] {
            return Err(Error::Psbt(outscript::Error::InvalidRecordValue));
        }
        redeem
    } else {
        spent.script
    };
    let script_code: &[u8] = match program {
        [0x00, 0x14, hash @ ..] if hash.len() == 20 => {
            if *hash != key_hash {
                return Err(Error::NotOurs);
            }
            &p2pkh
        }
        [0x00, 0x20, hash @ ..] if hash.len() == 32 => {
            let ws = inp.witness_script().ok_or(Error::Sighash { kind })?;
            if Sha256::digest(ws)[..] != *hash {
                return Err(Error::Psbt(outscript::Error::InvalidRecordValue));
            }
            // Our key has to be pushed in the script, as `<33> <key>`.
            let pushed = ws.windows(34).any(|w| w[0] == 33 && w[1..] == pubkey[..]);
            if !pushed {
                return Err(Error::NotOurs);
            }
            ws
        }
        // A legacy script (P2PKH, bare P2SH): no BIP-143 digest, and none computed here.
        _ => return Err(Error::Sighash { kind }),
    };

    let tx_bytes = psbt.unsigned_tx().bytes();
    let tx = Transaction::parse(tx_bytes).map_err(|_| Error::Sighash { kind })?;
    let mid = Midstates::compute(&tx).map_err(|_| Error::Sighash { kind })?;
    let digest = bip143(&tx, &mid, index, script_code, spent.amount, kind)
        .map_err(|_| Error::Sighash { kind })?;
    let der = signer.key.sign_der(&digest);

    // `<der> <type byte>` under `PARTIAL_SIG || <compressed key>`, as BIP-174 lays it out.
    let mut value = [0u8; 73];
    let n = der.len();
    value[..n].copy_from_slice(&der);
    value[n] = kind as u8;
    let mut record_key = [0u8; 34];
    record_key[0] = in_key::PARTIAL_SIG as u8;
    record_key[1..].copy_from_slice(&pubkey);
    Ok(psbt.set_input_record(index, &record_key, &value[..n + 1], out)?)
}

/// Sign input `index` with a bare private key -- a WIF-store key -- writing the updated
/// PSBT into `out`.
///
/// Unlike [`sign_input`], which asks the input which of our derived keys it names, this key
/// has no derivation and no fingerprint: `outscript` matches its public key against the
/// script the input actually pays and signs only if it is involved, returning
/// [`Error::Psbt`] wrapping `KeyNotInvolved` otherwise. The same sighash `policy` applies
/// as for a seed key ([`sign_input_under`]): a WIF spend is refused on a type this device
/// will not produce, so the signature and the review cannot disagree.
///
/// The scalar is elliptic-curve work, so this takes a [`KeyWork`] and runs masked.
pub fn sign_input_with_secret(
    psbt: &Psbt<'_>,
    index: usize,
    secret: &[u8; 32],
    policy: SighashPolicy,
    out: &mut [u8],
    kw: &KeyWork,
) -> Result<usize, Error> {
    let kind = psbt.input(index).and_then(|i| i.sighash_type());
    if let Some(kind) = kind
        && !sighash_allowed_under(kind, policy)
    {
        return Err(Error::Sighash { kind });
    }
    let signer = Signer::from_secret(secret, kw).ok_or(Error::Derivation)?;
    sign_with(psbt, index, &signer, kind, out)
}

/// Whether input `index` pays a single-signature address of `pubkey` (compressed), or a
/// bare P2PK script pushing it in either form.
///
/// The chain pins which script the input spends -- [`Psbt::utxo`] checks the previous
/// transaction's txid against this outpoint -- so this rebuilds the four single-sig
/// scripts our key could produce and compares. Public work: it is only the public key and
/// hashes, no scalar, so it needs no [`KeyWork`]. Used to recognise a WIF-store input in
/// the review and to list which inputs a WIF key can sign, ahead of the signature itself.
pub fn input_pays_key(psbt: &Psbt<'_>, index: usize, pubkey: &[u8; 33]) -> bool {
    use crate::address::{self, AddressKind};
    let Ok(spent) = psbt.utxo(index) else {
        return false;
    };
    if p2pk_pays(spent.script, pubkey) {
        return true;
    }
    [
        AddressKind::P2wpkh,
        AddressKind::P2shP2wpkh,
        AddressKind::P2pkh,
        AddressKind::P2tr,
    ]
    .into_iter()
    .any(|kind| {
        let mut built = [0u8; 34];
        matches!(address::script_pubkey(kind, pubkey, &mut built), Ok(n) if built[..n] == *spent.script)
    })
}

#[cfg(test)]
mod tests;
