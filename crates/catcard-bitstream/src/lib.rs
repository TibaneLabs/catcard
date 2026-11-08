//! Rewriting the Precursor's encrypted gateware: a new AES key, a new key source
//! (eFuse or BBRAM), a new HMAC key and IV, and new contents for the key ROM.
//!
//! The Precursor's FPGA (Spartan-7 XC7S50) loads an AES-256-CBC encrypted bitstream,
//! authenticated by HMAC-SHA256 over the decrypted stream. Inside the gateware is a
//! 256 x 32-bit **key ROM** (`keyrom` CSR) made of LUTs whose INIT values sit in eight
//! known configuration frames. Its contents are therefore part of the encrypted
//! bitstream, readable at run time by code on the SoC and by nobody holding only the
//! flash -- *once the bitstream is encrypted to a key only this FPGA has*. Stock
//! release gateware is encrypted to the all-zero key; this crate is how a device makes
//! its gateware its own.
//!
//! One pass, [`Rewriter`], streams the ciphertext in flash order: it decrypts with the
//! source key, checks the source HMAC, reads the key ROM out, optionally replaces it,
//! patches the key-source selection, and re-encrypts with the target key and IV under
//! a recomputed HMAC. Nothing is committed by this crate; the caller writes the output
//! somewhere and only trusts it after [`Rewriter::finish`] returns `Ok` (which is the
//! first point the *source* is known to be authentic) and, ideally, after reading the
//! output back through a second `Rewriter`.
//!
//! # Format facts
//!
//! All checked against the bench unit's own gateware (v0.9.5, flash dump 2026-11-05)
//! and two public release images, by decrypting them with the zero key and
//! recomputing their HMAC [C]:
//!
//! - Flash holds the bitstream with every 32-bit word bit-reversed relative to the AES
//!   byte stream ("bitflip" below: reverse the 4 bytes, reverse the bits of each).
//!   Configuration words read big-endian from the flash bytes; AES runs on the flipped
//!   form. Source: Xous root-keys `oracle.rs` `decrypt`/`encrypt_sector` [C].
//! - Plaintext header: sync word, then type-1 writes including MASK (`0x3000c001`) and
//!   CTL0 (`0x3000a001`) whose bit 31 selects the key: 1 = eFuse, 0 = BBRAM; then
//!   the IV write (`0x30016004` + 4 words) and the ciphertext length (`0x30034001` +
//!   word count). Ciphertext starts 16-byte aligned. Xilinx UG470 ch. 5 [C] for the
//!   packet format; the bit-31 meaning from Xous `oracle.rs` [C].
//! - Decrypted stream: 64 bytes `K ^ ipad` (the HMAC key block), configuration
//!   packets (one more CTL0 write), a type-2 FDRI header and the frame data (101 words
//!   per frame), trailing packets (CTL0 again), then the HMAC tail: the inner SHA-256
//!   padding, 64 bytes `K ^ opad`, the outer padding, and the 32-byte tag. The inner
//!   message is everything before the padding, `ct_len - 480` bytes; the tag is
//!   `SHA256((K ^ opad) || SHA256((K ^ ipad) || message))` -- standard HMAC-SHA256,
//!   key `K`, message from byte 64 [C].
//! - Key ROM bits: frames 0x35e..0x361 and 0x364..0x367, words 0..31 of each, mapped
//!   bit by bit by `keyrom-map.bin` (Xous key2bits tables, see
//!   `tools/precursor/keyrom-map.py`) [C].

#![no_std]
#![deny(unsafe_code)]

use purecrypto::cipher::{Aes256, BlockCipher};
use purecrypto::hash::{Digest, Sha256};
use zeroize::{Zeroize, ZeroizeOnDrop};

/// Words in the key ROM.
pub const KEYROM_WORDS: usize = 256;
/// AES block size.
const BLOCK: usize = 16;
/// Words per 7-series configuration frame. UG470 ch. 5 (101-word frames); Xous
/// `oracle.rs` `ciphertext_offset_to_frame` (101 * 4) [C].
const FRAME_WORDS: usize = 101;
/// The frames holding key ROM bits, in the order `keyrom-map.bin` lists them.
const KEYROM_FRAMES: [usize; 8] = [0x35e, 0x35f, 0x360, 0x361, 0x364, 0x365, 0x366, 0x367];
/// Words at the start of each of those frames that hold key ROM bits.
const KEYROM_FRAME_WORDS: usize = 32;
/// (address, bit) of the key ROM bit at each (frame, word, bit). See module docs.
static KEYROM_MAP: &[u8; 16384] = include_bytes!("keyrom-map.bin");

/// Bytes from the end of the ciphertext back to the end of the HMAC message [C]. The
/// tail they hold is fully determined by the message length and the HMAC key, in this
/// order (offsets from the end):
///
/// - 480..160: the inner SHA-256 padding -- `0x80`, zeros, the inner input length in
///   bits as a big-endian u64 at 424..416 (the input being the 64-byte `K ^ ipad`
///   block plus the message, i.e. `ct_len - 480` bytes) -- then zeros;
/// - 160..96: `K ^ opad` (32 bytes) and 32 bytes of `opad` -- the outer key block;
/// - 96..64: zeros, where the FPGA's engine places the inner digest;
/// - 64..32: the outer padding, `0x80`, zeros, and 768 (bits: 64 + 32 bytes) as a
///   big-endian u64;
/// - 32..0: the tag.
///
/// Checked against the bench unit's gateware and a release image, 2026-11-08 [C].
const HMAC_TAIL: usize = 480;
const OPAD_FROM_END: usize = 160;
const DIGEST_SLOT_FROM_END: usize = 96;
const OUTER_PAD_FROM_END: usize = 64;
const TAG_FROM_END: usize = 32;

const SYNC: u32 = 0xAA99_5566;
const CMD_MASK: u32 = 0x3000_C001;
const CMD_CTL0: u32 = 0x3000_A001;
const CMD_IV: u32 = 0x3001_6004;
const CMD_CIPHERTEXT: u32 = 0x3003_4001;
/// CTL0 / MASK bit 31: decryption key from eFuse when set, BBRAM when clear.
const KEY_SOURCE_BIT: u32 = 1 << 31;

/// Where the FPGA takes the bitstream key from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeySource {
    Efuse,
    Bbram,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error {
    /// No sync word in the header.
    NoSync,
    /// No IV or ciphertext-length packet before the header ran out.
    NoCipherHeader,
    /// The ciphertext does not start on an AES block, or its length is not whole blocks.
    Misaligned,
    /// The first block did not decrypt to an HMAC key block: wrong source key, or not
    /// an encrypted bitstream.
    WrongKey,
    /// No type-2 frame-data header near the start of the decrypted stream.
    NoFrames,
    /// The frame data does not reach the key ROM frames, or overlaps the HMAC tail.
    BadLayout,
    /// Input fed out of whole blocks, or past the end of the ciphertext.
    BadChunk,
    /// `finish` before the whole ciphertext was fed.
    Incomplete,
    /// The source's HMAC tag did not verify: the source is corrupt or was tampered with.
    /// The output must be discarded.
    SourceHmac,
    /// The CTL0 key-source selection was not found the expected number of times.
    KeySourceNotFound,
}

/// The key ROM's contents, word `i` being what the `keyrom` CSR returns for address `i`.
#[derive(Clone, PartialEq, Eq, Zeroize, ZeroizeOnDrop)]
pub struct KeyRom(pub [u32; KEYROM_WORDS]);

impl KeyRom {
    pub const fn zeroed() -> Self {
        KeyRom([0; KEYROM_WORDS])
    }
}

impl core::fmt::Debug for KeyRom {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("KeyRom(..)")
    }
}

/// The plaintext header's facts: where the ciphertext is and which key it claims.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Layout {
    /// Offset of the first ciphertext byte.
    pub ct_start: usize,
    /// Ciphertext length in bytes.
    pub ct_len: usize,
    /// Offset of the IV's first byte.
    iv_at: usize,
    /// The key source the plaintext CTL0 selects.
    pub key_source: KeySource,
}

impl Layout {
    /// Parses the plaintext header at the start of `image` (the first few hundred
    /// bytes suffice; pass at least up to the ciphertext).
    pub fn parse(image: &[u8]) -> Result<Self, Error> {
        let word = |i: usize| -> Option<u32> {
            image
                .get(i..i + 4)
                .map(|b| u32::from_be_bytes([b[0], b[1], b[2], b[3]]))
        };
        let mut i = 0;
        while word(i).ok_or(Error::NoSync)? != SYNC {
            i += 4;
        }
        let (mut iv_at, mut ctl0) = (None, None);
        loop {
            i += 4;
            match word(i).ok_or(Error::NoCipherHeader)? {
                CMD_CTL0 => ctl0 = word(i + 4),
                CMD_IV => iv_at = Some(i + 4),
                CMD_CIPHERTEXT => {
                    let words = word(i + 4).ok_or(Error::NoCipherHeader)? as usize;
                    let ct_start = i + 8;
                    let ct_len = words * 4;
                    if ct_start % BLOCK != 0 || !ct_len.is_multiple_of(BLOCK) {
                        return Err(Error::Misaligned);
                    }
                    let (Some(iv_at), Some(ctl0)) = (iv_at, ctl0) else {
                        return Err(Error::NoCipherHeader);
                    };
                    return Ok(Layout {
                        ct_start,
                        ct_len,
                        iv_at,
                        key_source: source_of(ctl0),
                    });
                }
                _ => {}
            }
        }
    }

    /// Total image length the header describes: header plus ciphertext. Flash may
    /// carry more after it (Precursor puts the CSR description at 0x27_7000).
    pub fn image_len(&self) -> usize {
        self.ct_start + self.ct_len
    }
}

fn source_of(ctl0: u32) -> KeySource {
    if ctl0 & KEY_SOURCE_BIT != 0 {
        KeySource::Efuse
    } else {
        KeySource::Bbram
    }
}

fn with_source(word: u32, source: KeySource) -> u32 {
    match source {
        KeySource::Efuse => word | KEY_SOURCE_BIT,
        KeySource::Bbram => word & !KEY_SOURCE_BIT,
    }
}

/// Flash byte order <-> AES byte order, one 16-byte block: per 32-bit word, reverse
/// the bytes and the bits within each byte. Its own inverse.
fn flip(block: &mut [u8; BLOCK]) {
    for w in block.as_chunks_mut::<4>().0 {
        w.reverse();
        for b in w.iter_mut() {
            *b = b.reverse_bits();
        }
    }
}

/// What the rewritten bitstream should be.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct Target {
    /// AES-256 key to encrypt to.
    pub key: [u8; 32],
    #[zeroize(skip)]
    pub source: KeySource,
    /// A fresh IV, or `None` to keep the source's.
    pub iv: Option<[u8; 16]>,
    /// A fresh HMAC key, or `None` to keep the source's.
    pub hmac_key: Option<[u8; 32]>,
    /// New key ROM contents, or `None` to keep the source's.
    pub keyrom: Option<KeyRom>,
}

/// One streaming pass over a bitstream's ciphertext. See the module docs.
pub struct Rewriter {
    layout: Layout,
    dec: Aes256,
    enc: Aes256,
    /// Previous source ciphertext block, AES order (the CBC chain for decryption).
    dec_chain: [u8; BLOCK],
    /// Previous output ciphertext block, AES order.
    enc_chain: [u8; BLOCK],
    target: Target,
    /// Ciphertext bytes consumed so far.
    pos: usize,
    src_hmac_key: [u8; 32],
    src_inner: Sha256,
    out_inner: Sha256,
    out_inner_digest: [u8; 32],
    /// The source's tag and opad block as they arrive, for the check in `finish`.
    src_tag: [u8; 32],
    /// Frame data start (byte offset in the decrypted stream) and word count, once found.
    frames: Option<(usize, usize)>,
    /// The previous decrypted word was a CTL0 write command.
    after_ctl0: bool,
    ctl0_patched: u32,
    keyrom_in: KeyRom,
    /// The key source the source's first encrypted CTL0 selected.
    enc_source: Option<KeySource>,
    /// Every source tail byte so far was the canonical one.
    tail_ok: bool,
    /// `header` has run and primed the CBC chains.
    started: bool,
}

impl Drop for Rewriter {
    fn drop(&mut self) {
        self.src_hmac_key.zeroize();
        self.out_inner_digest.zeroize();
        self.dec_chain.zeroize();
        self.enc_chain.zeroize();
    }
}

/// What a completed pass learned.
pub struct Outcome {
    /// The key ROM as the source carried it.
    pub keyrom_in: KeyRom,
    /// The key source the source bitstream selected inside its ciphertext (the plaintext
    /// header's copy is [`Layout::key_source`]).
    pub source_key_source: KeySource,
}

impl Rewriter {
    /// Starts a pass. `src_key` decrypts the source; `target` says what to produce.
    pub fn new(src_key: &[u8; 32], layout: Layout, target: Target) -> Result<Self, Error> {
        if layout.ct_len < 1024 + HMAC_TAIL {
            return Err(Error::BadLayout);
        }
        Ok(Rewriter {
            layout,
            dec: Aes256::new(src_key),
            enc: Aes256::new(&target.key),
            dec_chain: [0; BLOCK],
            enc_chain: [0; BLOCK],
            target,
            pos: 0,
            src_hmac_key: [0; 32],
            src_inner: Sha256::new(),
            out_inner: Sha256::new(),
            out_inner_digest: [0; 32],
            src_tag: [0; 32],
            frames: None,
            after_ctl0: false,
            ctl0_patched: 0,
            keyrom_in: KeyRom::zeroed(),
            enc_source: None,
            tail_ok: true,
            started: false,
        })
    }

    /// Writes the output's plaintext header: `head_out[..ct_start]` from
    /// `head_in[..ct_start]`, with the key source and the IV replaced as the target says.
    /// Also primes both CBC chains, so it must come before the first [`feed`](Self::feed).
    pub fn header(&mut self, head_in: &[u8], head_out: &mut [u8]) -> Result<(), Error> {
        let n = self.layout.ct_start;
        if head_in.len() < n || head_out.len() < n {
            return Err(Error::BadChunk);
        }
        head_out[..n].copy_from_slice(&head_in[..n]);
        let mut i = 0;
        let mut patched = 0;
        while i + 8 <= self.layout.iv_at {
            let w = u32::from_be_bytes([
                head_out[i],
                head_out[i + 1],
                head_out[i + 2],
                head_out[i + 3],
            ]);
            if w == CMD_CTL0 || w == CMD_MASK {
                let v = &mut head_out[i + 4..i + 8];
                let val = with_source(
                    u32::from_be_bytes([v[0], v[1], v[2], v[3]]),
                    self.target.source,
                );
                v.copy_from_slice(&val.to_be_bytes());
                patched += 1;
                i += 4;
            }
            i += 4;
        }
        if patched != 2 {
            return Err(Error::KeySourceNotFound);
        }
        let iv_at = self.layout.iv_at;
        let mut iv_in = [0u8; BLOCK];
        iv_in.copy_from_slice(&head_in[iv_at..iv_at + BLOCK]);
        flip(&mut iv_in);
        self.dec_chain = iv_in;
        self.enc_chain = match self.target.iv {
            Some(iv) => {
                let mut f = iv;
                flip(&mut f);
                head_out[iv_at..iv_at + BLOCK].copy_from_slice(&f);
                iv
            }
            None => iv_in,
        };
        self.started = true;
        Ok(())
    }

    /// Processes the next `ct_in.len()` ciphertext bytes (whole AES blocks, in order)
    /// into `ct_out` (same length).
    pub fn feed(&mut self, ct_in: &[u8], ct_out: &mut [u8]) -> Result<(), Error> {
        if !self.started
            || !ct_in.len().is_multiple_of(BLOCK)
            || ct_out.len() != ct_in.len()
            || self.pos + ct_in.len() > self.layout.ct_len
        {
            return Err(Error::BadChunk);
        }
        for (cin, cout) in ct_in
            .as_chunks::<BLOCK>()
            .0
            .iter()
            .zip(ct_out.as_chunks_mut::<BLOCK>().0.iter_mut())
        {
            let mut c = *cin;
            flip(&mut c);
            let mut p = c;
            self.dec.decrypt_block(&mut p);
            for (b, k) in p.iter_mut().zip(self.dec_chain.iter()) {
                *b ^= k;
            }
            self.dec_chain = c;
            // `p` is now plaintext in AES order; `flip` makes it flash order, in which
            // configuration words read big-endian and the HMAC is computed.
            flip(&mut p);
            self.block(&mut p)?;
            flip(&mut p);
            for (b, k) in p.iter_mut().zip(self.enc_chain.iter()) {
                *b ^= k;
            }
            self.enc.encrypt_block(&mut p);
            self.enc_chain = p;
            flip(&mut p);
            cout.copy_from_slice(&p);
            p.zeroize();
            self.pos += BLOCK;
        }
        Ok(())
    }

    /// One plaintext block, flash order, at `self.pos`: read what the source says,
    /// rewrite it in place to what the output says.
    fn block(&mut self, p: &mut [u8; BLOCK]) -> Result<(), Error> {
        let at = self.pos;
        let len = self.layout.ct_len;
        let msg_end = len - HMAC_TAIL;

        // The source's inner hash covers the source plaintext as it arrived.
        if at < msg_end {
            self.src_inner.update(p);
        }
        if at >= len - TAG_FROM_END {
            let o = at - (len - TAG_FROM_END);
            self.src_tag[o..o + BLOCK].copy_from_slice(p);
        }

        if at < 64 {
            self.hmac_header(at, p)?;
        }

        // Configuration words.
        for w in 0..BLOCK / 4 {
            let off = at + w * 4;
            if off < 64 || off >= msg_end {
                continue;
            }
            let word = u32::from_be_bytes([p[w * 4], p[w * 4 + 1], p[w * 4 + 2], p[w * 4 + 3]]);
            let new = self.word(off, word)?;
            p[w * 4..w * 4 + 4].copy_from_slice(&new.to_be_bytes());
        }

        if at < msg_end {
            self.out_inner.update(p);
            if at + BLOCK == msg_end {
                let inner = core::mem::replace(&mut self.out_inner, Sha256::new());
                self.out_inner_digest = inner.finalize();
            }
        }

        // The HMAC tail: the source's must be exactly the canonical one for its key
        // (nothing in it is covered by the tag), and the output gets the canonical one
        // for the output key.
        if at >= len - TAG_FROM_END {
            let tag = self.out_tag();
            let o = at - (len - TAG_FROM_END);
            p.copy_from_slice(&tag[o..o + BLOCK]);
        } else if at >= msg_end {
            let out_key = self.out_hmac_key();
            for (i, b) in p.iter_mut().enumerate() {
                if *b != self.tail_byte(at + i, &self.src_hmac_key) {
                    self.tail_ok = false;
                }
                *b = self.tail_byte(at + i, &out_key);
            }
        }
        Ok(())
    }

    /// The canonical HMAC tail byte at stream offset `o` (in `msg_end..len - 32`).
    fn tail_byte(&self, o: usize, key: &[u8; 32]) -> u8 {
        let len = self.layout.ct_len;
        let msg_end = len - HMAC_TAIL;
        if o < len - OPAD_FROM_END {
            let r = o - msg_end;
            let bits = (msg_end as u64 * 8).to_be_bytes();
            match r {
                0 => 0x80,
                56..=63 => bits[r - 56],
                _ => 0,
            }
        } else if o < len - DIGEST_SLOT_FROM_END {
            let r = o - (len - OPAD_FROM_END);
            if r < 32 { key[r] ^ 0x5c } else { 0x5c }
        } else if o < len - OUTER_PAD_FROM_END {
            0
        } else {
            let r = o - (len - OUTER_PAD_FROM_END);
            let bits = 768u64.to_be_bytes();
            match r {
                0 => 0x80,
                24..=31 => bits[r - 24],
                _ => 0,
            }
        }
    }

    /// The first 64 decrypted bytes: `K ^ ipad` for a 32-byte key, then 32 bytes of
    /// `ipad` alone -- which is also the check that the source key is right.
    fn hmac_header(&mut self, at: usize, p: &mut [u8; BLOCK]) -> Result<(), Error> {
        if at >= 32 {
            if p.iter().any(|&b| b != 0x36) {
                return Err(Error::WrongKey);
            }
            return Ok(());
        }
        for (i, b) in p.iter_mut().enumerate() {
            self.src_hmac_key[at + i] = *b ^ 0x36;
            if let Some(k) = self.target.hmac_key {
                *b = k[at + i] ^ 0x36;
            }
        }
        Ok(())
    }

    fn out_hmac_key(&self) -> [u8; 32] {
        self.target.hmac_key.unwrap_or(self.src_hmac_key)
    }

    fn out_tag(&self) -> [u8; 32] {
        let mut opad = [0x5cu8; 64];
        for (o, k) in opad.iter_mut().zip(self.out_hmac_key().iter()) {
            *o ^= k;
        }
        let mut h = Sha256::new();
        h.update(&opad);
        h.update(&self.out_inner_digest);
        opad.zeroize();
        h.finalize()
    }

    /// One decrypted configuration word at stream offset `off`; returns the output word.
    fn word(&mut self, off: usize, word: u32) -> Result<u32, Error> {
        let Some((start, count)) = self.frames else {
            // Before the frame data: look for the type-2 header (bits 31..29 = 010),
            // and keep the CTL0 key source in step with the target.
            if off > 1024 {
                return Err(Error::NoFrames);
            }
            let out = self.ctl0(word);
            if word & 0xE000_0000 == 0x4000_0000 {
                let count = (word & 0x03FF_FFFF) as usize;
                let start = off + 4;
                let last = KEYROM_FRAMES[KEYROM_FRAMES.len() - 1];
                if count < (last + 1) * FRAME_WORDS
                    || start + count * 4 > self.layout.ct_len - HMAC_TAIL
                {
                    return Err(Error::BadLayout);
                }
                self.frames = Some((start, count));
            }
            return Ok(out);
        };
        if off < start + count * 4 {
            return Ok(self.frame_word((off - start) / 4, word));
        }
        Ok(self.ctl0(word))
    }

    fn ctl0(&mut self, word: u32) -> u32 {
        if self.after_ctl0 {
            self.after_ctl0 = false;
            self.ctl0_patched += 1;
            self.enc_source.get_or_insert(source_of(word));
            return with_source(word, self.target.source);
        }
        self.after_ctl0 = word == CMD_CTL0;
        word
    }

    /// Frame data word `n` (counted from the first frame word).
    fn frame_word(&mut self, n: usize, word: u32) -> u32 {
        let frame = n / FRAME_WORDS;
        let fword = n % FRAME_WORDS;
        if fword >= KEYROM_FRAME_WORDS {
            return word;
        }
        let Some(fi) = KEYROM_FRAMES.iter().position(|&f| f == frame) else {
            return word;
        };
        let base = (fi * KEYROM_FRAME_WORDS + fword) * 32 * 2;
        let mut out = 0u32;
        for bit in 0..32 {
            let adr = KEYROM_MAP[base + bit * 2] as usize;
            let rbit = KEYROM_MAP[base + bit * 2 + 1] as u32;
            if word >> bit & 1 != 0 {
                self.keyrom_in.0[adr] |= 1 << rbit;
            }
            let v = match &self.target.keyrom {
                Some(rom) => rom.0[adr] >> rbit & 1,
                None => word >> bit & 1,
            };
            out |= v << bit;
        }
        out
    }

    /// Ends the pass. `Ok` means the source was complete and authentic and the output
    /// fed out so far is the whole, consistently re-authenticated ciphertext.
    pub fn finish(mut self) -> Result<Outcome, Error> {
        if self.pos != self.layout.ct_len {
            return Err(Error::Incomplete);
        }
        let mut opad = [0x5cu8; 64];
        for (o, k) in opad.iter_mut().zip(self.src_hmac_key.iter()) {
            *o ^= k;
        }
        let inner = core::mem::replace(&mut self.src_inner, Sha256::new()).finalize();
        let mut h = Sha256::new();
        h.update(&opad);
        h.update(&inner);
        let expect = h.finalize();
        opad.zeroize();
        // Not secret (the tag is in the clear once decrypted), so a plain compare.
        if expect != self.src_tag || !self.tail_ok {
            return Err(Error::SourceHmac);
        }
        // The CTL0 write before the frames and the one after them [C].
        if self.ctl0_patched != 2 {
            return Err(Error::KeySourceNotFound);
        }
        Ok(Outcome {
            keyrom_in: core::mem::replace(&mut self.keyrom_in, KeyRom::zeroed()),
            source_key_source: self.enc_source.unwrap_or(self.layout.key_source),
        })
    }
}

/// Whole-image convenience: rewrites `src` (header plus ciphertext) into `out` (at
/// least `layout.image_len()` bytes). For host tools and tests; firmware streams by
/// flash sector with [`Rewriter`] directly.
pub fn rewrite(
    src: &[u8],
    src_key: &[u8; 32],
    target: Target,
    out: &mut [u8],
) -> Result<Outcome, Error> {
    let layout = Layout::parse(src)?;
    let (s, n) = (layout.ct_start, layout.image_len());
    if src.len() < n || out.len() < n {
        return Err(Error::BadChunk);
    }
    let mut rw = Rewriter::new(src_key, layout, target)?;
    rw.header(&src[..s], &mut out[..s])?;
    rw.feed(&src[s..n], &mut out[s..n])?;
    rw.finish()
}

/// Reads and authenticates the key ROM of `image` without producing output.
pub fn read_keyrom(image: &[u8], key: &[u8; 32]) -> Result<Outcome, Error> {
    let layout = Layout::parse(image)?;
    let target = Target {
        key: *key,
        source: layout.key_source,
        iv: None,
        hmac_key: None,
        keyrom: None,
    };
    let mut rw = Rewriter::new(key, layout, target)?;
    let mut head = [0u8; 512];
    let s = layout.ct_start;
    if s > head.len() || image.len() < layout.image_len() {
        return Err(Error::BadChunk);
    }
    rw.header(&image[..s], &mut head[..s])?;
    let mut scratch = [0u8; 1024];
    for chunk in image[s..layout.image_len()].chunks(1024) {
        rw.feed(chunk, &mut scratch[..chunk.len()])?;
    }
    scratch.zeroize();
    rw.finish()
}
