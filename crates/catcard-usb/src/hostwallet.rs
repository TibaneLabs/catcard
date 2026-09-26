//! Host-wallet commands: a computer asks for addresses, or for a signature, and a person
//! at the device decides.
//!
//! Everything here is **encrypted-channel only**: the opcodes are answered only inside
//! [`Opcode::NcryMsg`](crate::Opcode::NcryMsg), and in the clear they are
//! `UnknownOpcode`, as the debug ones are inside. What travels -- addresses, extended
//! public keys, transactions -- is exactly what a passive observer on the wire should not
//! be able to collect.
//!
//! This module is the byte layouts and nothing else: encode and decode, bounds, and
//! refusal of anything truncated or trailing. The device's state machine and screens live
//! in the firmware; the host's in `tools/usbclient.py`. `docs/USB.md` §"Host-wallet
//! commands" is the prose version of the same layouts, and the tests below pin them.
//!
//! # Conventions
//!
//! - Integers are little-endian.
//! - A derivation path is `[u8 depth][depth × u32]`, each step with the hardened bit
//!   (`0x8000_0000`) set where it is hardened. Depth is 1 to [`MAX_DEPTH`].
//! - A chain is the one-byte form of `catcard_wallet::chain::ChainId` (Bitcoin 1,
//!   Ethereum 2, Solana 3, ...), the same numbers every other chain field uses.

use crate::ncry;

/// Version byte of every structure here that carries one. Bumped for any change a host
/// that understood the previous layout would read wrongly.
pub const VERSION: u8 = 1;

/// Deepest path a request or a reply carries. An account is three levels and an address
/// five; eight leaves room without letting a request name a path nobody uses.
pub const MAX_DEPTH: usize = 8;

/// Most keys one sign request may list: one per input a PSBT could reasonably have us
/// sign in one pass, with room to spare.
pub const MAX_KEYS: usize = 32;

/// Most result bytes one `HostResult` reply carries. The reply is sealed into a
/// single-message reply buffer of 512 bytes -- two of status, sixteen of tag, four of
/// total -- so 490 is the ceiling; 448 is a round number under it.
pub const PAGE_MAX: usize = 448;

/// Most transaction bytes one `HostSignData` carries: the sealed plaintext bound, less
/// the two-byte opcode and the four-byte offset.
pub const DATA_MAX: usize = ncry::PLAIN_MAX - 2 - 4;

/// Longest refusal reason the device sends. Short English, for a log line or a dialog.
pub const REASON_MAX: usize = 64;

/// The hardened bit of a path step.
pub const HARDENED: u32 = 0x8000_0000;

/// The one-byte stage `NotNow` carries in reply to `HostResult` and `HostAbort`.
pub mod stage {
    /// Nothing has been asked in this session, or the last result was fetched in full.
    pub const NOTHING: u8 = 0;
    /// An upload is open and not yet committed.
    pub const UPLOADING: u8 = 1;
    /// The request is waiting for the device's screen.
    pub const QUEUED: u8 = 2;
    /// The person at the device is deciding.
    pub const ON_SCREEN: u8 = 3;
    /// The device is busy with a request another session made.
    pub const OTHER_SESSION: u8 = 4;
}

/// The one-byte reason `NotNow` carries in reply to `HostAddresses` and `HostSignBegin`.
pub mod busy {
    /// The PIN has not been entered.
    pub const LOCKED: u8 = 1;
    /// A host request or an upgrade offer is already pending, or a result waits to be
    /// fetched.
    pub const BUSY: u8 = 2;
}

/// The first byte of every result, saying which layout follows.
pub mod kind {
    pub const ADDRESSES: u8 = 1;
    pub const BITCOIN: u8 = 2;
    pub const EVM: u8 = 3;
    pub const SOLANA: u8 = 4;
}

/// Which shape an address entry is.
pub mod shape {
    /// A UTXO chain: an account extended public key the host derives from, and the
    /// first receive address as a check.
    pub const UTXO: u8 = 1;
    /// An account chain: one address, its key, and the path it is at.
    pub const ACCOUNT: u8 = 2;
}

/// How an entry's address is written.
pub mod format {
    /// BIP-44 pay-to-public-key-hash.
    pub const P2PKH: u8 = 1;
    /// BIP-49 P2WPKH nested in P2SH.
    pub const P2SH_P2WPKH: u8 = 2;
    /// BIP-84 native segwit.
    pub const P2WPKH: u8 = 3;
    /// BIP-86 taproot, single key.
    pub const P2TR: u8 = 4;
    /// EIP-55 hex, Ethereum and every EVM chain.
    pub const EVM: u8 = 5;
    /// Tron's base58check `T...`.
    pub const TRON: u8 = 6;
    /// Solana: the ed25519 key itself, base58.
    pub const SOLANA: u8 = 7;
}

/// Why bytes could not be read or written.
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub enum Error {
    /// Ran out of bytes before the structure did.
    Truncated,
    /// Bytes left over after the structure ended. Refused rather than ignored: a
    /// trailing byte is a host and a device disagreeing about the layout.
    Trailing,
    /// A version byte this build does not read.
    Version,
    /// A path deeper than [`MAX_DEPTH`], or of depth zero.
    BadPath,
    /// A sign request listing no key, or more than [`MAX_KEYS`].
    KeyCount,
    /// A field longer than its bound.
    TooLong,
    /// The output buffer is too small.
    NoRoom,
    /// A value outside what the field allows.
    BadValue,
}

// ---------------------------------------------------------------------------
// Paths
// ---------------------------------------------------------------------------

/// A derivation path as the wire carries it.
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub struct Path {
    steps: [u32; MAX_DEPTH],
    depth: u8,
}

impl Path {
    /// A placeholder, for filling an array.
    pub const EMPTY: Self = Self {
        steps: [0; MAX_DEPTH],
        depth: 0,
    };

    /// A path of these steps, or `None` for depth zero or past [`MAX_DEPTH`].
    pub fn new(steps: &[u32]) -> Option<Self> {
        if steps.is_empty() || steps.len() > MAX_DEPTH {
            return None;
        }
        let mut p = Self::EMPTY;
        p.steps[..steps.len()].copy_from_slice(steps);
        p.depth = steps.len() as u8;
        Some(p)
    }

    pub fn steps(&self) -> &[u32] {
        &self.steps[..self.depth as usize]
    }

    /// Bytes this path takes on the wire.
    pub fn encoded_len(&self) -> usize {
        1 + 4 * self.depth as usize
    }
}

// ---------------------------------------------------------------------------
// A reader and a writer, so every layout below is read the same strict way
// ---------------------------------------------------------------------------

struct Cursor<'a> {
    b: &'a [u8],
    at: usize,
}

impl<'a> Cursor<'a> {
    fn new(b: &'a [u8]) -> Self {
        Self { b, at: 0 }
    }

    fn take(&mut self, n: usize) -> Result<&'a [u8], Error> {
        let end = self.at.checked_add(n).ok_or(Error::Truncated)?;
        let s = self.b.get(self.at..end).ok_or(Error::Truncated)?;
        self.at = end;
        Ok(s)
    }

    fn u8(&mut self) -> Result<u8, Error> {
        Ok(self.take(1)?[0])
    }

    fn u32(&mut self) -> Result<u32, Error> {
        let s = self.take(4)?;
        Ok(u32::from_le_bytes([s[0], s[1], s[2], s[3]]))
    }

    fn path(&mut self) -> Result<Path, Error> {
        let depth = self.u8()? as usize;
        if depth == 0 || depth > MAX_DEPTH {
            return Err(Error::BadPath);
        }
        let mut p = Path::EMPTY;
        for slot in p.steps.iter_mut().take(depth) {
            *slot = self.u32()?;
        }
        p.depth = depth as u8;
        Ok(p)
    }

    /// `[u8 len][bytes]`.
    fn short(&mut self) -> Result<&'a [u8], Error> {
        let n = self.u8()? as usize;
        self.take(n)
    }

    fn rest(&self) -> &'a [u8] {
        &self.b[self.at..]
    }

    fn done(&self) -> Result<(), Error> {
        if self.at == self.b.len() {
            Ok(())
        } else {
            Err(Error::Trailing)
        }
    }
}

struct Out<'a> {
    b: &'a mut [u8],
    at: usize,
}

impl<'a> Out<'a> {
    fn new(b: &'a mut [u8]) -> Self {
        Self { b, at: 0 }
    }

    fn put(&mut self, bytes: &[u8]) -> Result<(), Error> {
        let end = self.at.checked_add(bytes.len()).ok_or(Error::NoRoom)?;
        self.b
            .get_mut(self.at..end)
            .ok_or(Error::NoRoom)?
            .copy_from_slice(bytes);
        self.at = end;
        Ok(())
    }

    fn u8(&mut self, v: u8) -> Result<(), Error> {
        self.put(&[v])
    }

    fn u32(&mut self, v: u32) -> Result<(), Error> {
        self.put(&v.to_le_bytes())
    }

    fn path(&mut self, p: &Path) -> Result<(), Error> {
        self.u8(p.depth)?;
        for s in p.steps() {
            self.u32(*s)?;
        }
        Ok(())
    }

    fn short(&mut self, bytes: &[u8]) -> Result<(), Error> {
        let n = u8::try_from(bytes.len()).map_err(|_| Error::TooLong)?;
        self.u8(n)?;
        self.put(bytes)
    }
}

/// A length as the `u32` the wire carries, or [`Error::TooLong`].
fn len32(n: usize) -> Result<u32, Error> {
    u32::try_from(n).map_err(|_| Error::TooLong)
}

// ---------------------------------------------------------------------------
// Requests
// ---------------------------------------------------------------------------

/// `HostSignBegin`: `[u8 chain][u32 blob length]`, exactly five bytes.
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub struct SignBegin {
    pub chain: u8,
    pub length: u32,
}

impl SignBegin {
    pub fn decode(p: &[u8]) -> Result<Self, Error> {
        let mut c = Cursor::new(p);
        let chain = c.u8()?;
        let length = c.u32()?;
        c.done()?;
        if length == 0 {
            return Err(Error::BadValue);
        }
        Ok(Self { chain, length })
    }

    pub fn encode(&self) -> [u8; 5] {
        let mut out = [0u8; 5];
        out[0] = self.chain;
        out[1..].copy_from_slice(&self.length.to_le_bytes());
        out
    }
}

/// `HostSignData`: `[u32 offset][1..=DATA_MAX bytes]`.
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub struct SignData<'a> {
    pub offset: u32,
    pub bytes: &'a [u8],
}

impl<'a> SignData<'a> {
    pub fn decode(p: &'a [u8]) -> Result<Self, Error> {
        let mut c = Cursor::new(p);
        let offset = c.u32()?;
        let bytes = c.rest();
        if bytes.is_empty() {
            return Err(Error::Truncated);
        }
        if bytes.len() > DATA_MAX {
            return Err(Error::TooLong);
        }
        Ok(Self { offset, bytes })
    }

    /// `[u32 offset][bytes]` into `out`; returns the length.
    pub fn encode(&self, out: &mut [u8]) -> Result<usize, Error> {
        if self.bytes.is_empty() || self.bytes.len() > DATA_MAX {
            return Err(Error::BadValue);
        }
        let mut o = Out::new(out);
        o.u32(self.offset)?;
        o.put(self.bytes)?;
        Ok(o.at)
    }
}

/// `HostResult`: `[u32 offset]`, exactly four bytes.
pub fn decode_offset(p: &[u8]) -> Result<u32, Error> {
    let mut c = Cursor::new(p);
    let v = c.u32()?;
    c.done()?;
    Ok(v)
}

/// A request with no payload (`HostAddresses`, `HostSignCommit`, `HostAbort`): anything
/// in it is refused rather than ignored.
pub fn decode_empty(p: &[u8]) -> Result<(), Error> {
    if p.is_empty() {
        Ok(())
    } else {
        Err(Error::Trailing)
    }
}

/// The uploaded sign request, once whole:
///
/// ```text
/// [u8 version = 1][u8 chain][u8 key count]
/// key count × [u8 depth][depth × u32]
/// [u32 tx length][tx bytes]
/// ```
///
/// Nothing may follow the transaction.
#[derive(Clone, Debug)]
pub struct SignBlob<'a> {
    pub chain: u8,
    keys: [Path; MAX_KEYS],
    count: usize,
    /// The transaction, as the chain's own signer reads it: a PSBT (v0 or v2, binary),
    /// an EVM transaction (RLP, typed or legacy, unsigned), or a Solana transaction or
    /// message.
    pub tx: &'a [u8],
    /// Where `tx` starts within the blob, so a caller holding the blob in a buffer of its
    /// own can move the transaction to the front without re-reading it.
    pub tx_at: usize,
}

impl<'a> SignBlob<'a> {
    pub fn decode(b: &'a [u8]) -> Result<Self, Error> {
        let mut c = Cursor::new(b);
        if c.u8()? != VERSION {
            return Err(Error::Version);
        }
        let chain = c.u8()?;
        let count = c.u8()? as usize;
        if count == 0 || count > MAX_KEYS {
            return Err(Error::KeyCount);
        }
        let mut keys = [Path::EMPTY; MAX_KEYS];
        for k in keys.iter_mut().take(count) {
            *k = c.path()?;
        }
        let n = c.u32()? as usize;
        if n == 0 {
            return Err(Error::BadValue);
        }
        let tx_at = c.at;
        let tx = c.take(n)?;
        c.done()?;
        Ok(Self {
            chain,
            keys,
            count,
            tx,
            tx_at,
        })
    }

    pub fn keys(&self) -> &[Path] {
        &self.keys[..self.count]
    }

    /// The blob for `chain`, `keys` and `tx`, into `out`; returns the length.
    pub fn encode(chain: u8, keys: &[Path], tx: &[u8], out: &mut [u8]) -> Result<usize, Error> {
        if keys.is_empty() || keys.len() > MAX_KEYS {
            return Err(Error::KeyCount);
        }
        if tx.is_empty() {
            return Err(Error::BadValue);
        }
        let mut o = Out::new(out);
        o.u8(VERSION)?;
        o.u8(chain)?;
        o.u8(keys.len() as u8)?;
        for k in keys {
            o.path(k)?;
        }
        o.u32(len32(tx.len())?)?;
        o.put(tx)?;
        Ok(o.at)
    }
}

// ---------------------------------------------------------------------------
// Paging a result out
// ---------------------------------------------------------------------------

/// One `HostResult` page: `[u32 total][result[offset..offset + n]]` into `out`, with `n`
/// at most [`PAGE_MAX`] and at most what `out` holds past the four-byte total.
///
/// Returns the bytes written and whether this page reaches the end. An offset past the
/// end is [`Error::BadValue`]; an offset exactly at the end is an empty last page, so a
/// host that asks once too often is told it is finished rather than refused.
pub fn page(result: &[u8], offset: u32, out: &mut [u8]) -> Result<(usize, bool), Error> {
    let total = len32(result.len())?;
    if offset > total {
        return Err(Error::BadValue);
    }
    let from = offset as usize;
    let room = out.len().checked_sub(4).ok_or(Error::NoRoom)?;
    let n = (result.len() - from).min(PAGE_MAX).min(room);
    let mut o = Out::new(out);
    o.u32(total)?;
    o.put(&result[from..from + n])?;
    Ok((o.at, from + n == result.len()))
}

/// Read a page back: `(total, bytes)`.
pub fn read_page(reply: &[u8]) -> Result<(u32, &[u8]), Error> {
    let mut c = Cursor::new(reply);
    let total = c.u32()?;
    let rest = c.rest();
    if rest.len() > PAGE_MAX || rest.len() as u64 > total as u64 {
        return Err(Error::TooLong);
    }
    Ok((total, rest))
}

// ---------------------------------------------------------------------------
// The address reply
// ---------------------------------------------------------------------------

/// One address entry.
///
/// ```text
/// [u8 shape][u8 chain][u8 format]
/// [account path][address path]
/// shape UTXO only:  [u8 len][extended public key, base58 ASCII]
/// [u8 len][address, ASCII]
/// [u8 len][public key at the address path]
/// ```
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub struct Entry<'a> {
    pub shape: u8,
    pub chain: u8,
    pub format: u8,
    /// `m/purpose'/coin'/account'`: what the person exposed, and what a later sign
    /// request's keys have to sit under.
    pub account_path: Path,
    /// Where `address` and `pubkey` are.
    pub address_path: Path,
    /// The account's extended public key. Empty for an account chain.
    pub xpub: &'a [u8],
    pub address: &'a [u8],
    /// Compressed secp256k1 (33) or ed25519 (32).
    pub pubkey: &'a [u8],
}

/// Writes the address reply:
///
/// ```text
/// [u8 kind = ADDRESSES][u8 version = 1][4 master fingerprint][u32 account][u8 count]
/// count × entry
/// ```
pub struct AddressWriter<'a> {
    out: Out<'a>,
    count: u8,
}

/// The fixed head of an address reply, before its entries.
pub const ADDRESS_HEAD: usize = 1 + 1 + 4 + 4 + 1;

impl<'a> AddressWriter<'a> {
    pub fn new(out: &'a mut [u8], fingerprint: [u8; 4], account: u32) -> Result<Self, Error> {
        let mut o = Out::new(out);
        o.u8(kind::ADDRESSES)?;
        o.u8(VERSION)?;
        o.put(&fingerprint)?;
        o.u32(account)?;
        o.u8(0)?;
        Ok(Self { out: o, count: 0 })
    }

    /// Append an entry. A failure leaves what was written before it intact.
    pub fn push(&mut self, e: &Entry<'_>) -> Result<(), Error> {
        if self.count == u8::MAX {
            return Err(Error::TooLong);
        }
        if e.shape == shape::UTXO && e.xpub.is_empty() {
            return Err(Error::BadValue);
        }
        let mark = self.out.at;
        let r = (|| {
            self.out.u8(e.shape)?;
            self.out.u8(e.chain)?;
            self.out.u8(e.format)?;
            self.out.path(&e.account_path)?;
            self.out.path(&e.address_path)?;
            if e.shape == shape::UTXO {
                self.out.short(e.xpub)?;
            }
            self.out.short(e.address)?;
            self.out.short(e.pubkey)
        })();
        match r {
            Ok(()) => {
                self.count += 1;
                Ok(())
            }
            Err(err) => {
                self.out.at = mark;
                Err(err)
            }
        }
    }

    pub fn count(&self) -> u8 {
        self.count
    }

    /// Seal the count into the head and return the reply's length.
    pub fn finish(self) -> usize {
        let at = self.out.at;
        self.out.b[ADDRESS_HEAD - 1] = self.count;
        at
    }
}

/// An address reply being read.
#[derive(Clone, Debug)]
pub struct Addresses<'a> {
    pub fingerprint: [u8; 4],
    pub account: u32,
    pub count: u8,
    body: &'a [u8],
}

impl<'a> Addresses<'a> {
    /// Read the head, and every entry once, so a malformed reply is refused here rather
    /// than halfway through a host's loop.
    pub fn decode(r: &'a [u8]) -> Result<Self, Error> {
        let mut c = Cursor::new(r);
        if c.u8()? != kind::ADDRESSES {
            return Err(Error::BadValue);
        }
        if c.u8()? != VERSION {
            return Err(Error::Version);
        }
        let mut fingerprint = [0u8; 4];
        fingerprint.copy_from_slice(c.take(4)?);
        let account = c.u32()?;
        let count = c.u8()?;
        let me = Self {
            fingerprint,
            account,
            count,
            body: c.rest(),
        };
        let mut c = Cursor::new(me.body);
        for _ in 0..count {
            entry(&mut c)?;
        }
        c.done()?;
        Ok(me)
    }

    pub fn entries(&self) -> impl Iterator<Item = Entry<'a>> + '_ {
        let mut c = Cursor::new(self.body);
        (0..self.count).map_while(move |_| entry(&mut c).ok())
    }
}

fn entry<'a>(c: &mut Cursor<'a>) -> Result<Entry<'a>, Error> {
    let shape = c.u8()?;
    if shape != shape::UTXO && shape != shape::ACCOUNT {
        return Err(Error::BadValue);
    }
    let chain = c.u8()?;
    let format = c.u8()?;
    let account_path = c.path()?;
    let address_path = c.path()?;
    let xpub = if shape == shape::UTXO { c.short()? } else { &[] };
    let address = c.short()?;
    let pubkey = c.short()?;
    Ok(Entry {
        shape,
        chain,
        format,
        account_path,
        address_path,
        xpub,
        address,
        pubkey,
    })
}

// ---------------------------------------------------------------------------
// Sign results
// ---------------------------------------------------------------------------

/// Bytes a Bitcoin result takes for a PSBT of `psbt` bytes and a transaction of `tx`.
pub const fn bitcoin_len(psbt: usize, tx: usize) -> usize {
    1 + 1 + 4 + psbt + 4 + tx
}

/// `[u8 kind = BITCOIN][u8 psbt version, 0 or 2][u32 len][psbt][u32 len][tx]`.
///
/// The PSBT goes back in the version it arrived in. `tx` is the finalised network
/// transaction, or empty while any input still wants a signature.
pub fn write_bitcoin(
    out: &mut [u8],
    psbt_version: u8,
    psbt: &[u8],
    tx: &[u8],
) -> Result<usize, Error> {
    if psbt_version != 0 && psbt_version != 2 {
        return Err(Error::BadValue);
    }
    let mut o = Out::new(out);
    o.u8(kind::BITCOIN)?;
    o.u8(psbt_version)?;
    o.u32(len32(psbt.len())?)?;
    o.put(psbt)?;
    o.u32(len32(tx.len())?)?;
    o.put(tx)?;
    Ok(o.at)
}

/// Read a Bitcoin result: `(psbt version, psbt, tx)`.
pub fn read_bitcoin(r: &[u8]) -> Result<(u8, &[u8], &[u8]), Error> {
    let mut c = Cursor::new(r);
    if c.u8()? != kind::BITCOIN {
        return Err(Error::BadValue);
    }
    let v = c.u8()?;
    if v != 0 && v != 2 {
        return Err(Error::BadValue);
    }
    let n = c.u32()? as usize;
    let psbt = c.take(n)?;
    let n = c.u32()? as usize;
    let tx = c.take(n)?;
    c.done()?;
    Ok((v, psbt, tx))
}

/// `[u8 kind = EVM][u32 len][signed raw transaction]`.
pub fn write_evm(out: &mut [u8], signed: &[u8]) -> Result<usize, Error> {
    let mut o = Out::new(out);
    o.u8(kind::EVM)?;
    o.u32(len32(signed.len())?)?;
    o.put(signed)?;
    Ok(o.at)
}

pub fn read_evm(r: &[u8]) -> Result<&[u8], Error> {
    let mut c = Cursor::new(r);
    if c.u8()? != kind::EVM {
        return Err(Error::BadValue);
    }
    let n = c.u32()? as usize;
    let tx = c.take(n)?;
    c.done()?;
    Ok(tx)
}

/// One Solana signature: the signer slot it fills and the 64 bytes.
pub type SolanaSignature = (u8, [u8; 64]);

/// `[u8 kind = SOLANA][u8 count][count × ([u8 slot][64 signature])][u32 len][transaction]`.
///
/// The transaction carries the signatures in their slots already; they are also listed
/// on their own because some hosts want only the signature.
pub fn write_solana(
    out: &mut [u8],
    signatures: &[SolanaSignature],
    tx: &[u8],
) -> Result<usize, Error> {
    let count = u8::try_from(signatures.len()).map_err(|_| Error::TooLong)?;
    let mut o = Out::new(out);
    o.u8(kind::SOLANA)?;
    o.u8(count)?;
    for (slot, sig) in signatures {
        o.u8(*slot)?;
        o.put(sig)?;
    }
    o.u32(len32(tx.len())?)?;
    o.put(tx)?;
    Ok(o.at)
}

/// Read a Solana result: the signatures' bytes (`count × 65`) and the transaction.
pub fn read_solana(r: &[u8]) -> Result<(&[u8], &[u8]), Error> {
    let mut c = Cursor::new(r);
    if c.u8()? != kind::SOLANA {
        return Err(Error::BadValue);
    }
    let count = c.u8()? as usize;
    let sigs = c.take(count * 65)?;
    let n = c.u32()? as usize;
    let tx = c.take(n)?;
    c.done()?;
    Ok((sigs, tx))
}

#[cfg(test)]
mod tests;
