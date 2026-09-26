//! The 7-Zip container: one stored file, AES-256-CBC encrypted.
//!
//! This is not a 7-Zip implementation. It reads and writes exactly the shape a backup
//! is -- a single **stored** (uncompressed) file behind the `06 F1 07 01` AES coder --
//! and refuses everything else by name rather than pretending to cope. A wallet that
//! silently restored half a seed because it guessed at an LZMA stream would be worse
//! than one that said "this backup uses compression I cannot read".
//!
//! # The layout
//!
//! ```text
//! 0       signature header, 32 bytes
//! 32      the packed streams -- here, one, the ciphertext
//! ...     the "next header": the archive's whole structure, usually plain
//! ```
//!
//! The signature header is `'7z' BC AF 27 1C`, a two-byte version, a CRC over the
//! twenty bytes that follow, then the next header's offset (relative to byte 32), its
//! length and its own CRC -- all little-endian. Source: 7-Zip's published format notes,
//! confirmed byte-for-byte against archives written by `7z` 17.05. [C]
//!
//! The next header is a tagged byte stream. Integers in it are 7-Zip's variable-length
//! form: the top bits of the first byte say how many more bytes follow, and those bytes
//! are little-endian. [`read_number`]/[`write_number`] are the two halves and their
//! round-trip is pinned by a test.
//!
//! # Where the padding goes
//!
//! CBC needs whole blocks, and 7-Zip does not use PKCS#7: it zero-pads the plaintext to
//! the next 16-byte boundary and stores the **true** length in the folder's
//! `kCodersUnPackSize`, while `kSize` in the pack info carries the padded length. So a
//! 28-byte file packs to 32 bytes and the header says both numbers. That is why
//! [`Stream`] carries `packed_len` and `unpacked_len` separately, and why a gap of a
//! whole block or more between them is [`Error::BadCiphertext`] -- no writer produces it.
//!
//! # A wrong password reads as a bad checksum
//!
//! There is no MAC here. Decrypting with the wrong key yields noise, and the only thing
//! that notices is the CRC-32 the header carries over the plaintext. So
//! [`Error::BadChecksum`] means "wrong words, or a damaged file", and the two cannot be
//! told apart. The caller should say so.

use purecrypto::cipher::{Aes256, Cbc};

use crate::Error;
use crate::kdf::{Key, MAX_SALT};

/// `'7z' BC AF 27 1C`, then format version 0.4. Source: 7-Zip format notes. [C]
const SIGNATURE: [u8; 8] = [b'7', b'z', 0xBC, 0xAF, 0x27, 0x1C, 0x00, 0x04];

/// Where the packed streams start: immediately after the signature header.
const BASE: usize = 32;

/// AES-256 + SHA-256 key derivation. Source: 7-Zip method id table. [C]
const AES_CODER_ID: [u8; 4] = [0x06, 0xF1, 0x07, 0x01];
/// The "store it as it is" coder.
const COPY_CODER_ID: [u8; 1] = [0x00];

// Next-header property ids. Source: 7-Zip format notes. [C]
const K_END: u8 = 0x00;
const K_HEADER: u8 = 0x01;
const K_MAIN_STREAMS: u8 = 0x04;
const K_FILES_INFO: u8 = 0x05;
const K_PACK_INFO: u8 = 0x06;
const K_UNPACK_INFO: u8 = 0x07;
const K_SUBSTREAMS_INFO: u8 = 0x08;
const K_SIZE: u8 = 0x09;
const K_CRC: u8 = 0x0A;
const K_FOLDER: u8 = 0x0B;
const K_CODERS_UNPACK_SIZE: u8 = 0x0C;
const K_NUM_UNPACK_STREAM: u8 = 0x0D;
const K_EMPTY_STREAM: u8 = 0x0E;
const K_EMPTY_FILE: u8 = 0x0F;
const K_ANTI: u8 = 0x10;
const K_NAME: u8 = 0x11;
const K_ENCODED_HEADER: u8 = 0x17;

/// Coders accepted in one folder. Our shape needs two (AES then Copy); the extra room
/// only exists so a third is *refused* by coder id rather than by a length check.
const MAX_CODERS: usize = 4;

/// Space [`write`] needs beyond the ciphertext and the encoded name.
///
/// Every variable-length integer in the header is at most nine bytes and there are
/// fewer than a dozen of them, plus eighteen bytes of coder properties and a handful of
/// tags. Rounded well up: getting this wrong costs a byte of stack, not correctness,
/// because [`write`] still checks before every store.
pub const OVERHEAD: usize = 160;

/// An upper bound on the archive [`write`] will produce.
pub fn len_bound(name: &str, data_len: usize) -> usize {
    // UTF-16 is at most one code unit -- two bytes -- per UTF-8 byte, plus a terminator.
    BASE + data_len.next_multiple_of(16) + OVERHEAD + 2 * name.len()
}

/// One AES-encrypted stream inside an archive, and everything needed to open it.
///
/// Offsets are from the start of the archive, not from anything internal, so a `Stream`
/// found in a decrypted header is still usable against the original bytes.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Stream {
    /// Where the ciphertext starts, from byte zero of the archive.
    pub offset: usize,
    /// Ciphertext length: a whole number of AES blocks.
    pub packed_len: usize,
    /// Plaintext length, which is `packed_len` less the zero padding.
    pub unpacked_len: usize,
    /// `1 << cycles_power` key-derivation rounds.
    pub cycles_power: u8,
    /// CRC-32 over the plaintext, when the archive declares one.
    pub crc: Option<u32>,
    salt: [u8; MAX_SALT],
    salt_len: u8,
    iv: [u8; 16],
}

impl Stream {
    /// The key-derivation salt, usually empty -- 7-Zip leaves it out and relies on the
    /// per-archive IV for uniqueness.
    pub fn salt(&self) -> &[u8] {
        &self.salt[..self.salt_len as usize]
    }

    /// The CBC initialisation vector, zero-extended to sixteen bytes if the archive
    /// stored fewer (which the format allows and which 7-Zip's own reader does).
    pub fn iv(&self) -> &[u8; 16] {
        &self.iv
    }
}

/// One **unencrypted** stored file inside an archive: a cleartext backup.
///
/// No key, no IV, no padding -- the bytes at `offset` are the file. The CRC is the only
/// integrity check the format gives it, exactly as for the encrypted case.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Plain {
    /// Where the file starts, from byte zero of the archive.
    pub offset: usize,
    /// The file's length: stored, so packed and unpacked are the same number.
    pub len: usize,
    /// CRC-32 over the file, when the archive declares one.
    pub crc: Option<u32>,
}

/// What [`open`] found at the end of the archive.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Found {
    /// The header was plain: this is the one file in the archive.
    File(Stream),
    /// The header is itself encrypted. Decrypt this stream, then pass the plaintext to
    /// [`file_in`]. Its salt and cycle count are normally the same as the file's, so the
    /// key can be derived once and used twice -- only the IV differs.
    Header(Stream),
    /// The one file is stored **in the clear**: no AES coder at all. Nothing to derive
    /// and no password to ask for -- [`extract_in_place`] reads it straight out. A
    /// caller that wants to *refuse* an unencrypted backup does it here, by name.
    Clear(Plain),
}

/// What one folder describes: the AES stream, or the file as it is.
enum Entry {
    Aes(Stream),
    Clear(Plain),
}

// ---------------------------------------------------------------------------
// Reading
// ---------------------------------------------------------------------------

/// Reads the signature header and the next header, and says what is in the archive.
pub fn open(archive: &[u8]) -> Result<Found, Error> {
    if archive.len() < BASE {
        return Err(Error::Truncated);
    }
    if archive[..6] != SIGNATURE[..6] {
        return Err(Error::NotSevenZip);
    }
    // The start header's CRC covers the twenty bytes after it. Checked first: every
    // length below comes out of those bytes, and trusting a length from a corrupt
    // header is how a reader ends up indexing off the end of the world.
    if u32::from_le_bytes(archive[8..12].try_into().unwrap()) != crc32(&archive[12..32]) {
        return Err(Error::BadChecksum);
    }
    let next_off = u64::from_le_bytes(archive[12..20].try_into().unwrap());
    let next_len = u64::from_le_bytes(archive[20..28].try_into().unwrap());
    let next_crc = u32::from_le_bytes(archive[28..32].try_into().unwrap());

    let start = BASE
        .checked_add(usize::try_from(next_off).map_err(|_| Error::Truncated)?)
        .ok_or(Error::Truncated)?;
    let len = usize::try_from(next_len).map_err(|_| Error::Truncated)?;
    let end = start.checked_add(len).ok_or(Error::Truncated)?;
    if end > archive.len() {
        return Err(Error::Truncated);
    }
    if len == 0 {
        return Err(Error::NotOneFile);
    }
    let header = &archive[start..end];
    if crc32(header) != next_crc {
        return Err(Error::BadChecksum);
    }

    let mut r = Reader::new(header);
    match r.byte()? {
        K_HEADER => Ok(match parse_header_body(&mut r)? {
            Entry::Aes(s) => Found::File(s),
            Entry::Clear(p) => Found::Clear(p),
        }),
        K_ENCODED_HEADER => match parse_streams_info(&mut r)? {
            Entry::Aes(s) => Ok(Found::Header(s)),
            // An "encoded" header that is merely stored is nothing any writer produces:
            // the point of encoding a header is to compress or encrypt it.
            Entry::Clear(_) => Err(Error::BadArchive),
        },
        _ => Err(Error::BadArchive),
    }
}

/// The one file described by a header that had to be decrypted first.
///
/// An encrypted header over an unencrypted file is a mix no writer produces, and is
/// refused as [`Error::NotEncrypted`] rather than read as either.
pub fn file_in(decoded_header: &[u8]) -> Result<Stream, Error> {
    let mut r = Reader::new(decoded_header);
    if r.byte()? != K_HEADER {
        return Err(Error::BadArchive);
    }
    match parse_header_body(&mut r)? {
        Entry::Aes(s) => Ok(s),
        Entry::Clear(_) => Err(Error::NotEncrypted),
    }
}

/// Copies the cleartext file `p` out of `archive` into `out`, checking its CRC.
pub fn extract<'o>(archive: &[u8], p: &Plain, out: &'o mut [u8]) -> Result<&'o [u8], Error> {
    let end = plain_end(archive.len(), p)?;
    if out.len() < p.len {
        return Err(Error::BufferTooSmall);
    }
    out[..p.len].copy_from_slice(&archive[p.offset..end]);
    check_plain(&out[..p.len], p)
}

/// Moves the cleartext file `p` to the **front of the buffer the archive is in**.
///
/// The one-buffer counterpart of [`decrypt_in_place`]: the archive is overwritten and
/// the file comes back at offset zero, so a caller reads a cleartext backup exactly the
/// way it reads a decrypted one.
pub fn extract_in_place<'a>(archive: &'a mut [u8], p: &Plain) -> Result<&'a [u8], Error> {
    let end = plain_end(archive.len(), p)?;
    archive.copy_within(p.offset..end, 0);
    check_plain(&archive[..p.len], p)
}

fn plain_end(archive_len: usize, p: &Plain) -> Result<usize, Error> {
    let end = p.offset.checked_add(p.len).ok_or(Error::Truncated)?;
    if end > archive_len {
        return Err(Error::Truncated);
    }
    Ok(end)
}

fn check_plain<'o>(file: &'o [u8], p: &Plain) -> Result<&'o [u8], Error> {
    if let Some(want) = p.crc
        && crc32(file) != want
    {
        return Err(Error::BadChecksum);
    }
    Ok(file)
}

/// Decrypts `s` out of `archive` into `out`, and returns the plaintext.
///
/// `out` must hold the **padded** length: decryption happens in place over whole
/// blocks, and the returned slice is the shorter, true one. When the archive carries a
/// CRC it is checked, and a mismatch is [`Error::BadChecksum`] -- which for a backup
/// almost always means the words were wrong.
pub fn decrypt<'o>(
    archive: &[u8],
    s: &Stream,
    key: &Key,
    out: &'o mut [u8],
) -> Result<&'o [u8], Error> {
    let end = ciphertext_end(archive.len(), s)?;
    if out.len() < s.packed_len {
        return Err(Error::BufferTooSmall);
    }
    out[..s.packed_len].copy_from_slice(&archive[s.offset..end]);
    unwrap_at_front(out, s, key)
}

/// Decrypts `s` to the **front of the buffer the archive is already in**.
///
/// The archive is destroyed in the process, which is the point: a device reading a
/// backup off a card has one buffer, and copying the ciphertext somewhere else to
/// decrypt it would mean holding two copies of the seed at once. The plaintext comes
/// back at offset zero.
pub fn decrypt_in_place<'a>(
    archive: &'a mut [u8],
    s: &Stream,
    key: &Key,
) -> Result<&'a [u8], Error> {
    let end = ciphertext_end(archive.len(), s)?;
    archive.copy_within(s.offset..end, 0);
    unwrap_at_front(archive, s, key)
}

/// Where the ciphertext ends, once its lengths have been agreed with.
fn ciphertext_end(archive_len: usize, s: &Stream) -> Result<usize, Error> {
    if !s.packed_len.is_multiple_of(16) {
        return Err(Error::BadCiphertext);
    }
    if s.unpacked_len > s.packed_len || s.packed_len - s.unpacked_len >= 16 {
        return Err(Error::BadCiphertext);
    }
    let end = s.offset.checked_add(s.packed_len).ok_or(Error::Truncated)?;
    if end > archive_len {
        return Err(Error::Truncated);
    }
    Ok(end)
}

/// Decrypts `buf[..packed_len]` in place and checks what comes out.
fn unwrap_at_front<'o>(buf: &'o mut [u8], s: &Stream, key: &Key) -> Result<&'o [u8], Error> {
    Cbc::new(Aes256::new(key.as_bytes()), &s.iv)
        .decrypt(&mut buf[..s.packed_len])
        .map_err(|_| Error::BadCiphertext)?;
    let plain = &buf[..s.unpacked_len];
    if let Some(want) = s.crc
        && crc32(plain) != want
    {
        return Err(Error::BadChecksum);
    }
    Ok(plain)
}

/// `kHeader`, after its tag: the main streams, then the file list.
fn parse_header_body(r: &mut Reader<'_>) -> Result<Entry, Error> {
    let mut id = r.byte()?;
    // Archive properties and additional streams are legal and we do not use them; an
    // archive that has them is not one we wrote and not one we will guess at.
    if id != K_MAIN_STREAMS {
        return Err(Error::BadArchive);
    }
    let stream = parse_streams_info(r)?;
    id = r.byte()?;
    if id == K_FILES_INFO {
        check_files_info(r)?;
        id = r.byte()?;
    }
    if id != K_END {
        return Err(Error::BadArchive);
    }
    Ok(stream)
}

/// A `StreamsInfo`: pack info, unpack info, sub-stream info, `kEnd`.
///
/// Restricted throughout to one pack stream, one folder and one sub-stream, because
/// that is what a backup is. Anything wider is [`Error::NotOneFile`].
fn parse_streams_info(r: &mut Reader<'_>) -> Result<Entry, Error> {
    let mut pack_pos = 0u64;
    let mut packed_len: Option<u64> = None;
    let mut folder: Option<FolderInfo> = None;
    let mut sub_crc: Option<u32> = None;
    let mut have_substreams = false;

    loop {
        match r.byte()? {
            K_PACK_INFO => {
                pack_pos = r.number()?;
                if r.number()? != 1 {
                    return Err(Error::NotOneFile);
                }
                loop {
                    match r.byte()? {
                        K_SIZE => packed_len = Some(r.number()?),
                        K_CRC => {
                            skip_digests(r, 1)?;
                        }
                        K_END => break,
                        _ => return Err(Error::BadArchive),
                    }
                }
            }
            K_UNPACK_INFO => folder = Some(parse_unpack_info(r)?),
            K_SUBSTREAMS_INFO => {
                have_substreams = true;
                sub_crc = parse_substreams_info(r, folder.as_ref())?;
            }
            K_END => break,
            _ => return Err(Error::BadArchive),
        }
    }

    let f = folder.ok_or(Error::BadArchive)?;
    let packed_len = packed_len.ok_or(Error::BadArchive)?;
    let offset = BASE
        .checked_add(usize::try_from(pack_pos).map_err(|_| Error::Truncated)?)
        .ok_or(Error::Truncated)?;
    let packed_len = usize::try_from(packed_len).map_err(|_| Error::Truncated)?;
    let unpacked_len = usize::try_from(f.unpacked_len).map_err(|_| Error::Truncated)?;
    // A CRC listed against the sub-stream wins; with no sub-stream section the
    // folder's own CRC covers the single file.
    let crc = if have_substreams { sub_crc } else { f.crc };
    Ok(match f.aes {
        Some(aes) => Entry::Aes(Stream {
            offset,
            packed_len,
            unpacked_len,
            cycles_power: aes.cycles_power,
            crc,
            salt: aes.salt,
            salt_len: aes.salt_len,
            iv: aes.iv,
        }),
        None => {
            // Stored as it is: the pack stream *is* the file, so the two lengths have to
            // agree. A writer that pads a Copy stream does not exist.
            if packed_len != unpacked_len {
                return Err(Error::BadArchive);
            }
            Entry::Clear(Plain {
                offset,
                len: unpacked_len,
                crc,
            })
        }
    })
}

/// The AES coder's properties, when the folder has one.
struct AesProps {
    cycles_power: u8,
    salt: [u8; MAX_SALT],
    salt_len: u8,
    iv: [u8; 16],
}

struct FolderInfo {
    unpacked_len: u64,
    /// `None` is a folder of one Copy coder: the file in the clear.
    aes: Option<AesProps>,
    crc: Option<u32>,
}

fn parse_unpack_info(r: &mut Reader<'_>) -> Result<FolderInfo, Error> {
    if r.byte()? != K_FOLDER {
        return Err(Error::BadArchive);
    }
    if r.number()? != 1 {
        return Err(Error::NotOneFile);
    }
    if r.byte()? != 0 {
        // "external": the folder list lives in another stream. Never written for an
        // archive this small.
        return Err(Error::BadArchive);
    }

    let num_coders = r.number()?;
    if num_coders == 0 || num_coders > MAX_CODERS as u64 {
        return Err(Error::Compressed);
    }
    let mut total_in = 0u64;
    let mut total_out = 0u64;
    let mut aes: Option<AesProps> = None;
    for _ in 0..num_coders {
        let flags = r.byte()?;
        if flags & 0x80 != 0 {
            // "alternative methods", obsolete and never written.
            return Err(Error::BadArchive);
        }
        let id_size = usize::from(flags & 0x0F);
        let id = r.take(id_size)?;
        let (n_in, n_out) = if flags & 0x10 != 0 {
            (r.number()?, r.number()?)
        } else {
            (1, 1)
        };
        // Stream counts are bounded before they are summed. They come straight out of
        // the file, and two coders each declaring 2^63 streams would otherwise add up to
        // an overflow -- which on the device is a panic, and a panic is a wiped device,
        // from nothing more than a crafted `.7z` on a card. No coder has more streams
        // than there are coders in the archives this reads.
        if n_in > MAX_CODERS as u64 || n_out > MAX_CODERS as u64 {
            return Err(Error::BadArchive);
        }
        total_in += n_in;
        total_out += n_out;
        let props = if flags & 0x20 != 0 {
            let n = usize::try_from(r.number()?).map_err(|_| Error::Truncated)?;
            r.take(n)?
        } else {
            &[]
        };
        if id == AES_CODER_ID {
            if aes.is_some() {
                return Err(Error::NotEncrypted);
            }
            aes = Some(parse_aes_props(props)?);
        } else if id != COPY_CODER_ID {
            // LZMA, LZMA2, BCJ, delta, anything else: named as compression because
            // that is what it is in practice, and because "unsupported coder" tells
            // the owner nothing they can act on.
            return Err(Error::Compressed);
        }
    }
    // No AES coder is a cleartext archive, and it has exactly one shape: a single Copy
    // coder. Two Copy coders chained together is nothing any writer produces, and is
    // not something to guess at.
    if aes.is_none() && num_coders != 1 {
        return Err(Error::BadArchive);
    }

    // Bind pairs wire one coder's output to another's input. The folder's own output is
    // the one out-stream nothing consumes.
    if total_out == 0 || total_out > MAX_CODERS as u64 {
        return Err(Error::BadArchive);
    }
    let mut bound = [false; MAX_CODERS];
    let num_pairs = total_out - 1;
    for _ in 0..num_pairs {
        let _in_index = r.number()?;
        let out_index = usize::try_from(r.number()?).map_err(|_| Error::BadArchive)?;
        if out_index >= MAX_CODERS || bound[out_index] {
            return Err(Error::BadArchive);
        }
        bound[out_index] = true;
    }
    if total_in < num_pairs {
        return Err(Error::BadArchive);
    }
    let num_packed = total_in - num_pairs;
    if num_packed != 1 {
        return Err(Error::NotOneFile);
    }

    // No kEnd here: the folder list runs straight into the unpacked sizes. Source: the
    // reference archive in this module's tests, where `01 00` (the bind pair) is
    // followed immediately by `0c` (kCodersUnPackSize). [C]
    if r.byte()? != K_CODERS_UNPACK_SIZE {
        return Err(Error::BadArchive);
    }
    let mut sizes = [0u64; MAX_CODERS];
    for slot in sizes.iter_mut().take(total_out as usize) {
        *slot = r.number()?;
    }
    let final_out = (0..total_out as usize)
        .find(|&i| !bound[i])
        .ok_or(Error::BadArchive)?;

    let mut crc = None;
    loop {
        match r.byte()? {
            K_CRC => crc = read_one_digest(r)?,
            K_END => break,
            _ => return Err(Error::BadArchive),
        }
    }

    Ok(FolderInfo {
        unpacked_len: sizes[final_out],
        aes,
        crc,
    })
}

/// The AES coder's properties: rounds, salt and IV.
///
/// `props[0]`: low six bits are the log2 round count; bit 7 says the salt is at least
/// one byte, bit 6 says the same of the IV. `props[1]`, present when either is, adds its
/// high nibble to the salt length and its low nibble to the IV length. Source: read off
/// an archive written by `7z` 17.05 -- `53 0F` decoded as 19 rounds, no salt, a 16-byte
/// IV, which is exactly the eighteen bytes that followed. [C]
fn parse_aes_props(props: &[u8]) -> Result<AesProps, Error> {
    let b0 = *props.first().ok_or(Error::BadArchive)?;
    let cycles_power = b0 & 0x3F;
    let (salt_len, iv_len, rest) = if b0 & 0xC0 == 0 {
        (0usize, 0usize, &props[1..])
    } else {
        let b1 = *props.get(1).ok_or(Error::BadArchive)?;
        let salt_len = usize::from((b0 >> 7) & 1) + usize::from(b1 >> 4);
        let iv_len = usize::from((b0 >> 6) & 1) + usize::from(b1 & 0x0F);
        (salt_len, iv_len, &props[2..])
    };
    if rest.len() != salt_len + iv_len || salt_len > MAX_SALT || iv_len > 16 {
        return Err(Error::BadArchive);
    }
    let mut salt = [0u8; MAX_SALT];
    salt[..salt_len].copy_from_slice(&rest[..salt_len]);
    // A short IV is zero-extended, which is what 7-Zip's own reader does.
    let mut iv = [0u8; 16];
    iv[..iv_len].copy_from_slice(&rest[salt_len..]);
    Ok(AesProps {
        cycles_power,
        salt,
        salt_len: salt_len as u8,
        iv,
    })
}

/// Sub-stream info for the single-file case. Returns the file's CRC if it is here.
fn parse_substreams_info(
    r: &mut Reader<'_>,
    folder: Option<&FolderInfo>,
) -> Result<Option<u32>, Error> {
    let mut crc = None;
    loop {
        match r.byte()? {
            K_NUM_UNPACK_STREAM => {
                if r.number()? != 1 {
                    return Err(Error::NotOneFile);
                }
            }
            K_SIZE => {
                // With one sub-stream per folder the size is implied by the folder, so
                // nothing is written. A size list here means more than one sub-stream.
                return Err(Error::NotOneFile);
            }
            K_CRC => {
                // Digests are listed only for streams whose CRC is not already known
                // from the folder.
                if folder.is_some_and(|f| f.crc.is_some()) {
                    crc = folder.and_then(|f| f.crc);
                } else {
                    crc = read_one_digest(r)?;
                }
            }
            K_END => break,
            _ => return Err(Error::BadArchive),
        }
    }
    Ok(crc)
}

/// `kFilesInfo`: one file, with a stream, and nothing exotic.
fn check_files_info(r: &mut Reader<'_>) -> Result<(), Error> {
    if r.number()? != 1 {
        return Err(Error::NotOneFile);
    }
    loop {
        let id = r.byte()?;
        if id == K_END {
            return Ok(());
        }
        let size = usize::try_from(r.number()?).map_err(|_| Error::Truncated)?;
        let body = r.take(size)?;
        match id {
            // An empty-stream, empty-file or anti item means the one entry is a
            // directory, a zero-length file or a deletion marker -- none of which is a
            // backup, and all of which would otherwise leave us decrypting nothing.
            K_EMPTY_STREAM | K_EMPTY_FILE | K_ANTI => return Err(Error::NotOneFile),
            // Names are not load-bearing here -- the archive holds one file and we want
            // it whatever it is called -- but an external name list points somewhere we
            // do not follow.
            K_NAME if body.first() != Some(&0) => return Err(Error::BadArchive),
            _ => {}
        }
    }
}

fn read_one_digest(r: &mut Reader<'_>) -> Result<Option<u32>, Error> {
    if r.byte()? == 0 {
        // A bit vector saying which of the (one) digests is present.
        if r.byte()? & 0x80 == 0 {
            return Ok(None);
        }
    }
    Ok(Some(r.u32le()?))
}

fn skip_digests(r: &mut Reader<'_>, count: usize) -> Result<(), Error> {
    let defined = if r.byte()? == 0 {
        let bits = r.take(count.div_ceil(8))?;
        (0..count)
            .filter(|i| bits[i / 8] & (0x80 >> (i % 8)) != 0)
            .count()
    } else {
        count
    };
    r.take(defined * 4)?;
    Ok(())
}

// ---------------------------------------------------------------------------
// Writing
// ---------------------------------------------------------------------------

/// Packs `data` as one stored, encrypted file called `name`.
///
/// `key` must be the one [`crate::kdf`] derives from the password with *these* `salt`
/// and `cycles_power`; nothing here can check that, and a mismatch produces an archive
/// the password does not open. `iv` must never repeat for a given key -- draw it from
/// the UI DRBG.
///
/// The folder is written as the reference tool writes it: an AES coder feeding a Copy
/// coder. A lone AES coder would probably be read back correctly, but "probably" is not
/// a property a backup gets to have, and the two-coder form is the one proven against
/// the real extractor.
pub fn write<'o>(
    out: &'o mut [u8],
    name: &str,
    data: &[u8],
    key: &Key,
    iv: &[u8; 16],
    salt: &[u8],
    cycles_power: u8,
) -> Result<&'o [u8], Error> {
    let end = BODY_OFFSET
        .checked_add(data.len())
        .ok_or(Error::BufferTooSmall)?;
    if out.len() < end {
        return Err(Error::BufferTooSmall);
    }
    out[BODY_OFFSET..end].copy_from_slice(data);
    seal_at(out, data.len(), name, key, iv, salt, cycles_power)
}

/// Where a body must sit for [`seal_at`] to wrap it: exactly where the ciphertext goes.
pub const BODY_OFFSET: usize = BASE;

/// Wraps a body **already written** at `out[BODY_OFFSET..][..body_len]`.
///
/// The device has one buffer of any size, and the body in it is the seed in plaintext.
/// Building it somewhere else and copying it in would mean two copies of the seed alive
/// at once, so the caller builds it where it will be encrypted and this seals it in
/// place. [`write`] is the same thing with the copy, for a caller that does not care.
#[allow(clippy::too_many_arguments)]
pub fn seal_at<'o>(
    out: &'o mut [u8],
    body_len: usize,
    name: &str,
    key: &Key,
    iv: &[u8; 16],
    salt: &[u8],
    cycles_power: u8,
) -> Result<&'o [u8], Error> {
    if salt.len() > MAX_SALT || cycles_power > 0x3F {
        return Err(Error::BadArchive);
    }
    let padded = body_len.next_multiple_of(16);
    let ct_end = BASE.checked_add(padded).ok_or(Error::BufferTooSmall)?;
    if out.len() < ct_end {
        return Err(Error::BufferTooSmall);
    }
    let crc = crc32(&out[BASE..BASE + body_len]);

    out[BASE + body_len..ct_end].fill(0);
    Cbc::new(Aes256::new(key.as_bytes()), iv)
        .encrypt(&mut out[BASE..ct_end])
        .map_err(|_| Error::BadCiphertext)?;

    let coder = Coder::Aes {
        iv,
        salt,
        cycles_power,
    };
    finish_archive(out, ct_end, name, body_len, padded, crc, coder)
}

/// Packs `data` as one stored file called `name`, **unencrypted**.
///
/// A cleartext backup: anyone holding the file holds what is in it. Nothing here
/// decides whether that is acceptable -- the firmware asks the owner, twice, by name --
/// but the archive is a real 7-Zip one, so a laptop opens it with no password at all.
pub fn write_clear<'o>(out: &'o mut [u8], name: &str, data: &[u8]) -> Result<&'o [u8], Error> {
    let end = BODY_OFFSET
        .checked_add(data.len())
        .ok_or(Error::BufferTooSmall)?;
    if out.len() < end {
        return Err(Error::BufferTooSmall);
    }
    out[BODY_OFFSET..end].copy_from_slice(data);
    seal_clear_at(out, data.len(), name)
}

/// Wraps a body already at `out[BODY_OFFSET..][..body_len]` as a cleartext archive.
///
/// The one-buffer form of [`write_clear`], as [`seal_at`] is of [`write`]. The body is
/// left exactly where it is and only the header is written after it.
pub fn seal_clear_at<'o>(
    out: &'o mut [u8],
    body_len: usize,
    name: &str,
) -> Result<&'o [u8], Error> {
    let end = BASE.checked_add(body_len).ok_or(Error::BufferTooSmall)?;
    if out.len() < end {
        return Err(Error::BufferTooSmall);
    }
    let crc = crc32(&out[BASE..end]);
    finish_archive(out, end, name, body_len, body_len, crc, Coder::Copy)
}

/// Write the next header after the packed stream and the signature header in front of
/// it, and return the whole archive.
fn finish_archive<'o>(
    out: &'o mut [u8],
    packed_end: usize,
    name: &str,
    unpacked_len: usize,
    packed_len: usize,
    crc: u32,
    coder: Coder<'_>,
) -> Result<&'o [u8], Error> {
    let header_len = {
        let mut w = Writer::new(&mut out[packed_end..]);
        write_header(&mut w, name, unpacked_len, packed_len, crc, coder);
        w.finish()?
    };

    // The signature header last: it carries lengths only now known, and CRCs over
    // bytes only now written.
    out[..8].copy_from_slice(&SIGNATURE);
    out[12..20].copy_from_slice(&(packed_len as u64).to_le_bytes());
    out[20..28].copy_from_slice(&(header_len as u64).to_le_bytes());
    let header_crc = crc32(&out[packed_end..packed_end + header_len]);
    out[28..32].copy_from_slice(&header_crc.to_le_bytes());
    let start_crc = crc32(&out[12..32]);
    out[8..12].copy_from_slice(&start_crc.to_le_bytes());

    Ok(&out[..packed_end + header_len])
}

/// How the one folder is coded: AES then Copy, or Copy alone.
enum Coder<'a> {
    Aes {
        iv: &'a [u8; 16],
        salt: &'a [u8],
        cycles_power: u8,
    },
    Copy,
}

fn write_header(
    w: &mut Writer<'_>,
    name: &str,
    unpacked_len: usize,
    packed_len: usize,
    crc: u32,
    coder: Coder<'_>,
) {
    w.byte(K_HEADER);
    w.byte(K_MAIN_STREAMS);

    w.byte(K_PACK_INFO);
    w.number(0); // packPos: the packed stream starts at BASE
    w.number(1); // one pack stream
    w.byte(K_SIZE);
    w.number(packed_len as u64);
    w.byte(K_END);

    w.byte(K_UNPACK_INFO);
    w.byte(K_FOLDER);
    w.number(1); // one folder
    w.byte(0); // not external
    match coder {
        Coder::Aes {
            iv,
            salt,
            cycles_power,
        } => {
            w.number(2); // two coders: AES, then Copy
            w.byte(0x20 | AES_CODER_ID.len() as u8); // has properties, four-byte id
            w.bytes(&AES_CODER_ID);
            w.number(2 + salt.len() as u64 + iv.len() as u64);
            w.byte(cycles_power | if salt.is_empty() { 0 } else { 0x80 } | 0x40);
            w.byte(((salt.len().saturating_sub(1) as u8) << 4) | (iv.len() as u8 - 1));
            w.bytes(salt);
            w.bytes(iv);
            w.byte(COPY_CODER_ID.len() as u8); // no properties, one-byte id
            w.bytes(&COPY_CODER_ID);
            w.number(1); // bind pair: Copy's input ...
            w.number(0); // ... takes AES's output
            w.byte(K_CODERS_UNPACK_SIZE);
            w.number(unpacked_len as u64); // out of the AES coder
            w.number(unpacked_len as u64); // out of the Copy coder -- the folder's output
        }
        Coder::Copy => {
            // One coder and no bind pairs: the reference tool's `-mx0 -m0=Copy` with no
            // password writes exactly this. Source: the cleartext archive in this
            // module's `reference_tool` tests. [C]
            w.number(1);
            w.byte(COPY_CODER_ID.len() as u8); // no properties, one-byte id
            w.bytes(&COPY_CODER_ID);
            w.byte(K_CODERS_UNPACK_SIZE);
            w.number(unpacked_len as u64);
        }
    }
    w.byte(K_END);

    // One sub-stream per folder is the default, so only the CRC needs saying.
    w.byte(K_SUBSTREAMS_INFO);
    w.byte(K_CRC);
    w.byte(1); // all defined
    w.bytes(&crc.to_le_bytes());
    w.byte(K_END);

    w.byte(K_END); // main streams

    w.byte(K_FILES_INFO);
    w.number(1);
    w.byte(K_NAME);
    // A UTF-16 code unit each, plus the terminator, plus the "not external" byte.
    w.number(1 + 2 * (name.encode_utf16().count() as u64 + 1));
    w.byte(0); // not external
    let mut units = [0u16; 2];
    for c in name.chars() {
        for unit in c.encode_utf16(&mut units) {
            w.bytes(&unit.to_le_bytes());
        }
    }
    w.bytes(&[0, 0]);
    w.byte(K_END);

    w.byte(K_END); // header
}

// ---------------------------------------------------------------------------
// Primitives
// ---------------------------------------------------------------------------

struct Reader<'a> {
    data: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    fn new(data: &'a [u8]) -> Self {
        Reader { data, pos: 0 }
    }

    fn byte(&mut self) -> Result<u8, Error> {
        let b = *self.data.get(self.pos).ok_or(Error::Truncated)?;
        self.pos += 1;
        Ok(b)
    }

    fn take(&mut self, n: usize) -> Result<&'a [u8], Error> {
        let end = self.pos.checked_add(n).ok_or(Error::Truncated)?;
        let s = self.data.get(self.pos..end).ok_or(Error::Truncated)?;
        self.pos = end;
        Ok(s)
    }

    fn u32le(&mut self) -> Result<u32, Error> {
        Ok(u32::from_le_bytes(self.take(4)?.try_into().unwrap()))
    }

    fn number(&mut self) -> Result<u64, Error> {
        read_number(|| self.byte())
    }
}

/// 7-Zip's variable-length integer.
///
/// The first byte's leading one-bits count the extra bytes; the first zero bit ends the
/// count and the bits below it are the value's top bits. Extra bytes are little-endian
/// and come first in significance order. Source: 7-Zip format notes, and the archives
/// in this module's tests. [C]
pub fn read_number<E>(mut next: impl FnMut() -> Result<u8, E>) -> Result<u64, E> {
    let first = next()?;
    let mut value = 0u64;
    let mut mask = 0x80u8;
    for i in 0..8 {
        if first & mask == 0 {
            value |= u64::from(first & (mask.wrapping_sub(1))) << (8 * i);
            return Ok(value);
        }
        value |= u64::from(next()?) << (8 * i);
        mask >>= 1;
    }
    Ok(value)
}

/// The inverse of [`read_number`], in the shortest form.
pub fn write_number(mut value: u64, mut put: impl FnMut(u8)) {
    let mut first = 0u8;
    let mut mask = 0x80u8;
    let mut extra = 0usize;
    while extra < 8 {
        if value < 1u64 << (7 * (extra + 1)) {
            first |= (value >> (8 * extra)) as u8;
            break;
        }
        first |= mask;
        mask >>= 1;
        extra += 1;
    }
    put(first);
    for _ in 0..extra {
        put(value as u8);
        value >>= 8;
    }
}

/// A cursor that records overflow instead of panicking, so the header can be laid out
/// as a straight sequence of writes and checked once at the end.
struct Writer<'a> {
    buf: &'a mut [u8],
    pos: usize,
    overflow: bool,
}

impl<'a> Writer<'a> {
    fn new(buf: &'a mut [u8]) -> Self {
        Writer {
            buf,
            pos: 0,
            overflow: false,
        }
    }

    fn byte(&mut self, b: u8) {
        match self.buf.get_mut(self.pos) {
            Some(slot) => {
                *slot = b;
                self.pos += 1;
            }
            None => self.overflow = true,
        }
    }

    fn bytes(&mut self, bs: &[u8]) {
        for b in bs {
            self.byte(*b);
        }
    }

    fn number(&mut self, v: u64) {
        let mut tmp = [0u8; 9];
        let mut n = 0usize;
        write_number(v, |b| {
            tmp[n] = b;
            n += 1;
        });
        self.bytes(&tmp[..n]);
    }

    fn finish(self) -> Result<usize, Error> {
        if self.overflow {
            Err(Error::BufferTooSmall)
        } else {
            Ok(self.pos)
        }
    }
}

/// CRC-32 (IEEE, reflected, `0xEDB88320`), computed a bit at a time.
///
/// A 1 KiB table would be eight times faster and is not worth the flash: the only
/// things checksummed here are a few kilobytes of backup and a hundred bytes of header.
pub fn crc32(data: &[u8]) -> u32 {
    let mut crc = 0xFFFF_FFFFu32;
    for &b in data {
        crc ^= u32::from(b);
        for _ in 0..8 {
            let lsb = crc & 1;
            crc >>= 1;
            if lsb != 0 {
                crc ^= 0xEDB8_8320;
            }
        }
    }
    !crc
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::kdf;

    /// The archive `7z a -mx0 -m0=Copy -p"abc def"` wrote over a 28-byte file, verbatim.
    ///
    /// This is the whole point of the module: not that our writer round-trips with our
    /// reader, but that the reference tool's bytes parse and decrypt. Generated on the
    /// host with p7zip 17.05 and a throwaway password; it holds no key material.
    const REFERENCE: &[u8] = &[
        0x37, 0x7a, 0xbc, 0xaf, 0x27, 0x1c, 0x00, 0x04, 0x49, 0xcd, 0xa0, 0x0b, 0x20, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x6a, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x1f, 0x94,
        0xa2, 0xb9, 0x0a, 0xd2, 0x76, 0x73, 0xaa, 0x46, 0x1b, 0xca, 0x86, 0x5b, 0x26, 0x97, 0xae,
        0x60, 0x33, 0x1b, 0xd4, 0xa5, 0x54, 0x17, 0x24, 0x4d, 0x8b, 0xcc, 0xb7, 0xd2, 0x25, 0x96,
        0x8b, 0x12, 0x8a, 0x35, 0x01, 0x04, 0x06, 0x00, 0x01, 0x09, 0x20, 0x00, 0x07, 0x0b, 0x01,
        0x00, 0x02, 0x24, 0x06, 0xf1, 0x07, 0x01, 0x12, 0x53, 0x0f, 0xad, 0x3d, 0xe3, 0x3c, 0xe7,
        0xfb, 0x35, 0x2d, 0x5b, 0xc2, 0x16, 0x65, 0x14, 0x74, 0xf7, 0x0f, 0x01, 0x00, 0x01, 0x00,
        0x0c, 0x1c, 0x1c, 0x00, 0x08, 0x0a, 0x01, 0x49, 0x11, 0xc2, 0x5e, 0x00, 0x00, 0x05, 0x01,
        0x19, 0x03, 0x00, 0x00, 0x00, 0x11, 0x15, 0x00, 0x69, 0x00, 0x6e, 0x00, 0x6e, 0x00, 0x65,
        0x00, 0x72, 0x00, 0x2e, 0x00, 0x74, 0x00, 0x78, 0x00, 0x74, 0x00, 0x00, 0x00, 0x14, 0x0a,
        0x01, 0x00, 0x80, 0x3f, 0x0f, 0xf7, 0xc4, 0x4a, 0xdd, 0x01, 0x15, 0x06, 0x01, 0x00, 0x20,
        0x80, 0xa4, 0x81, 0x00, 0x00,
    ];
    const REFERENCE_PASSWORD: &str = "abc def";
    const REFERENCE_PLAIN: &[u8] = b"hello backup world\nline two\n";

    fn only_file(archive: &[u8]) -> Stream {
        match open(archive).unwrap() {
            Found::File(s) => s,
            other => panic!("expected a plain header, got {other:?}"),
        }
    }

    #[test]
    fn an_archive_the_reference_tool_wrote_decrypts() {
        let s = only_file(REFERENCE);
        assert_eq!(s.cycles_power, 19);
        assert!(s.salt().is_empty());
        assert_eq!(s.unpacked_len, REFERENCE_PLAIN.len());
        assert_eq!(s.packed_len, 32);

        let key = kdf::derive(REFERENCE_PASSWORD, s.salt(), s.cycles_power).unwrap();
        let mut out = [0u8; 64];
        let plain = decrypt(REFERENCE, &s, &key, &mut out).unwrap();
        assert_eq!(plain, REFERENCE_PLAIN);
    }

    /// The failure a wrong word list produces, and the only one available: there is no
    /// MAC, so the CRC is what stands between a bad password and a restored nonsense
    /// seed.
    #[test]
    fn the_wrong_password_is_caught_by_the_checksum() {
        let s = only_file(REFERENCE);
        let key = kdf::derive("abc dfe", s.salt(), s.cycles_power).unwrap();
        let mut out = [0u8; 64];
        assert_eq!(
            decrypt(REFERENCE, &s, &key, &mut out).unwrap_err(),
            Error::BadChecksum
        );
    }

    #[test]
    fn what_we_write_is_what_we_read() {
        let key = Key::from_bytes([7u8; 32]);
        let iv = [0x5Au8; 16];
        let data = b"# Coldcard backup file! DO NOT CHANGE.\n\n# EOF\n";
        let mut buf = vec![0u8; len_bound("backup.txt", data.len())];
        let archive = write(&mut buf, "backup.txt", data, &key, &iv, &[], 19)
            .unwrap()
            .to_vec();

        let s = only_file(&archive);
        assert_eq!(s.cycles_power, 19);
        assert_eq!(s.unpacked_len, data.len());
        let mut out = vec![0u8; s.packed_len];
        assert_eq!(decrypt(&archive, &s, &key, &mut out).unwrap(), data);
    }

    /// A salt is legal and changes the key; the reference tool does not write one, so
    /// this is the only place the two-nibble length encoding gets exercised.
    #[test]
    fn a_salted_archive_round_trips() {
        let key = Key::from_bytes([3u8; 32]);
        let salt = [0xA5u8; 9];
        let mut buf = vec![0u8; len_bound("x", 100)];
        let archive = write(&mut buf, "x", &[1u8; 100], &key, &[0u8; 16], &salt, 17)
            .unwrap()
            .to_vec();
        let s = only_file(&archive);
        assert_eq!(s.salt(), &salt[..]);
        assert_eq!(s.cycles_power, 17);
    }

    /// An empty file still has to produce a valid archive, because a body that failed to
    /// render would otherwise be written out as a perfectly well-formed empty backup.
    #[test]
    fn an_empty_file_round_trips() {
        let key = Key::from_bytes([1u8; 32]);
        let mut buf = vec![0u8; len_bound("e", 0)];
        let archive = write(&mut buf, "e", &[], &key, &[0u8; 16], &[], 10)
            .unwrap()
            .to_vec();
        let s = only_file(&archive);
        assert_eq!((s.packed_len, s.unpacked_len), (0, 0));
        let mut out = [0u8; 16];
        assert_eq!(decrypt(&archive, &s, &key, &mut out).unwrap(), b"");
    }

    /// The path the device actually takes: one buffer, the body built where it will be
    /// encrypted, and the restore decrypting back into the same bytes it read. If this
    /// ever disagreed with the copying pair, a backup written on hardware would not be
    /// the backup the host tests check.
    #[test]
    fn the_one_buffer_path_agrees_with_the_copying_one() {
        let key = Key::from_bytes([9u8; 32]);
        let iv = [0x2Cu8; 16];
        let body = b"# Coldcard backup file! DO NOT CHANGE.\n\nchain = \"BTC\"\n\n# EOF\n";

        let mut a = vec![0u8; len_bound("b.txt", body.len())];
        a[BODY_OFFSET..BODY_OFFSET + body.len()].copy_from_slice(body);
        let sealed = seal_at(&mut a, body.len(), "b.txt", &key, &iv, &[], 12)
            .unwrap()
            .to_vec();

        let mut b = vec![0u8; len_bound("b.txt", body.len())];
        let written = write(&mut b, "b.txt", body, &key, &iv, &[], 12).unwrap();
        assert_eq!(sealed, written, "the two writers must agree byte for byte");

        let mut held = sealed.clone();
        let s = only_file(&held);
        assert_eq!(decrypt_in_place(&mut held, &s, &key).unwrap(), body);
    }

    /// Two coders each declaring 2^63 streams once added up to an overflow -- on the
    /// device a panic, and so a wipe, from nothing but a crafted file on a card. The
    /// counts are bounded before they are summed.
    #[test]
    fn absurd_stream_counts_are_refused_before_they_are_summed() {
        fn num(out: &mut Vec<u8>, v: u64) {
            write_number(v, |b| out.push(b));
        }
        let mut folder = Vec::new();
        folder.push(K_FOLDER);
        num(&mut folder, 1); // one folder
        folder.push(0); // not external
        num(&mut folder, 2); // two coders, within MAX_CODERS
        for _ in 0..2 {
            // "complex" coder: a one-byte id (Copy), then its stream counts.
            folder.push(0x10 | 1);
            folder.push(COPY_CODER_ID[0]);
            num(&mut folder, 1 << 63);
            num(&mut folder, 1 << 63);
        }
        let mut r = Reader::new(&folder);
        assert!(matches!(parse_unpack_info(&mut r), Err(Error::BadArchive)));
    }

    #[test]
    fn a_short_buffer_is_refused_rather_than_half_written() {
        let key = Key::from_bytes([1u8; 32]);
        let mut buf = [0u8; 40];
        assert_eq!(
            write(&mut buf, "x", &[0u8; 64], &key, &[0u8; 16], &[], 10).unwrap_err(),
            Error::BufferTooSmall
        );
        // Long enough for the ciphertext, far too short for the header.
        let mut buf = [0u8; 96];
        assert_eq!(
            write(&mut buf, "x", &[0u8; 64], &key, &[0u8; 16], &[], 10).unwrap_err(),
            Error::BufferTooSmall
        );
    }

    #[test]
    fn something_that_is_not_an_archive_is_refused() {
        assert_eq!(open(&[0u8; 64]).unwrap_err(), Error::NotSevenZip);
        assert_eq!(open(b"7z").unwrap_err(), Error::Truncated);
    }

    /// A flipped bit in the start header would otherwise be read as a length, and a
    /// length is how a reader gets pointed at memory it should not touch.
    #[test]
    fn a_corrupt_start_header_is_refused_before_its_lengths_are_used() {
        let mut bad = REFERENCE.to_vec();
        bad[20] ^= 0x40; // the next header's length
        assert_eq!(open(&bad).unwrap_err(), Error::BadChecksum);
    }

    #[test]
    fn a_corrupt_next_header_is_refused() {
        let mut bad = REFERENCE.to_vec();
        let last = bad.len() - 1;
        bad[last] ^= 0xFF;
        assert_eq!(open(&bad).unwrap_err(), Error::BadChecksum);
    }

    /// The one thing a backup reader must never do is guess at a compressed stream.
    #[test]
    fn a_compressed_archive_is_named_as_such_and_refused() {
        let key = Key::from_bytes([1u8; 32]);
        let mut buf = vec![0u8; len_bound("x", 64)];
        let mut archive = write(&mut buf, "x", &[0u8; 64], &key, &[0u8; 16], &[], 10)
            .unwrap()
            .to_vec();
        // The same four-byte-id-with-properties coder, but LZMA rather than AES.
        let at = archive
            .windows(4)
            .position(|w| w == AES_CODER_ID)
            .expect("coder id is in there");
        archive[at..at + 4].copy_from_slice(&[0x03, 0x01, 0x01, 0x00]);
        fix_crcs(&mut archive);
        assert_eq!(open(&archive).unwrap_err(), Error::Compressed);
    }

    #[test]
    fn ciphertext_that_is_not_whole_blocks_is_refused() {
        let s = Stream {
            offset: BASE,
            packed_len: 30,
            unpacked_len: 28,
            cycles_power: 19,
            crc: None,
            salt: [0; MAX_SALT],
            salt_len: 0,
            iv: [0; 16],
        };
        let mut out = [0u8; 64];
        assert_eq!(
            decrypt(REFERENCE, &s, &Key::from_bytes([0; 32]), &mut out).unwrap_err(),
            Error::BadCiphertext
        );
    }

    /// A whole block of padding means the header's two lengths disagree about what is
    /// in the file -- a writer would never produce it, so something is lying.
    #[test]
    fn a_whole_block_of_padding_is_refused() {
        let s = Stream {
            offset: BASE,
            packed_len: 32,
            unpacked_len: 16,
            cycles_power: 19,
            crc: None,
            salt: [0; MAX_SALT],
            salt_len: 0,
            iv: [0; 16],
        };
        let mut out = [0u8; 64];
        assert_eq!(
            decrypt(REFERENCE, &s, &Key::from_bytes([0; 32]), &mut out).unwrap_err(),
            Error::BadCiphertext
        );
    }

    #[test]
    fn the_number_encoding_round_trips_at_every_width() {
        for v in [
            0u64,
            1,
            0x7F,
            0x80,
            0x3FFF,
            0x4000,
            0x1F_FFFF,
            0x20_0000,
            u32::MAX as u64,
            u64::MAX,
        ] {
            let mut buf = [0u8; 9];
            let mut n = 0;
            write_number(v, |b| {
                buf[n] = b;
                n += 1;
            });
            let mut i = 0;
            let back = read_number(|| {
                let b = buf[i];
                i += 1;
                Ok::<u8, ()>(b)
            })
            .unwrap();
            assert_eq!(back, v, "{v:#x} round-tripped as {back:#x}");
            assert_eq!(i, n, "{v:#x}: read {i} bytes, wrote {n}");
        }
    }

    /// The numbers in the reference archive, decoded by hand from its hex dump: the
    /// pack size (32), the unpacked size (28) and the name property's length (21).
    #[test]
    fn the_number_encoding_matches_the_reference_archive() {
        let one = |bytes: &[u8]| {
            let mut k = 0usize;
            read_number(|| {
                let b = bytes[k];
                k += 1;
                Ok::<u8, ()>(b)
            })
            .unwrap()
        };
        assert_eq!(one(&[0x20]), 32);
        assert_eq!(one(&[0x1c]), 28);
        assert_eq!(one(&[0x15]), 21);
    }

    #[test]
    fn crc32_matches_the_value_in_the_reference_archive() {
        assert_eq!(crc32(REFERENCE_PLAIN), 0x5EC2_1149);
        assert_eq!(crc32(b""), 0);
        assert_eq!(crc32(b"123456789"), 0xCBF4_3926);
    }

    /// Recompute the two CRCs in the signature header after a test has edited the body.
    fn fix_crcs(archive: &mut [u8]) {
        let off = u64::from_le_bytes(archive[12..20].try_into().unwrap()) as usize;
        let len = u64::from_le_bytes(archive[20..28].try_into().unwrap()) as usize;
        let start = BASE + off;
        let crc = crc32(&archive[start..start + len]);
        archive[28..32].copy_from_slice(&crc.to_le_bytes());
        let start_crc = crc32(&archive[12..32]);
        archive[8..12].copy_from_slice(&start_crc.to_le_bytes());
    }

    // -- cleartext ------------------------------------------------------------------

    /// A cleartext archive is one Copy coder and no key: the file goes in as it is and
    /// comes back out through both extractors, byte for byte.
    #[test]
    fn a_cleartext_archive_round_trips() {
        let body = b"# Coldcard backup file! DO NOT CHANGE.\n\nchain = \"BTC\"\n\n# EOF\n";
        let mut buf = vec![0u8; len_bound("backup.txt", body.len())];
        let archive = write_clear(&mut buf, "backup.txt", body).unwrap().to_vec();

        let p = match open(&archive).unwrap() {
            Found::Clear(p) => p,
            other => panic!("expected a cleartext file, got {other:?}"),
        };
        assert_eq!((p.offset, p.len), (BASE, body.len()));
        assert_eq!(p.crc, Some(crc32(body)));

        let mut out = vec![0u8; p.len];
        assert_eq!(extract(&archive, &p, &mut out).unwrap(), body);
        let mut held = archive.clone();
        assert_eq!(extract_in_place(&mut held, &p).unwrap(), body);
    }

    /// The one-buffer sealer and the copying writer produce the same bytes, as their
    /// encrypted counterparts do.
    #[test]
    fn the_cleartext_sealer_agrees_with_the_cleartext_writer() {
        let body = b"chain = \"XTN\"\n";
        let mut a = vec![0u8; len_bound("b.txt", body.len())];
        a[BODY_OFFSET..BODY_OFFSET + body.len()].copy_from_slice(body);
        let sealed = seal_clear_at(&mut a, body.len(), "b.txt").unwrap().to_vec();
        let mut b = vec![0u8; len_bound("b.txt", body.len())];
        let written = write_clear(&mut b, "b.txt", body).unwrap();
        assert_eq!(sealed, written);
    }

    /// Detection, not a question: the same reader tells an encrypted archive from a
    /// cleartext one by its coders, so the firmware never asks for words a file does
    /// not need -- and never hands an unencrypted file to the decryptor.
    #[test]
    fn cleartext_and_encrypted_archives_are_told_apart_by_the_reader() {
        let body = b"# Coldcard backup file! DO NOT CHANGE.\n# EOF\n";
        let key = Key::from_bytes([7u8; 32]);
        let mut buf = vec![0u8; len_bound("b", body.len())];
        let sealed = write(&mut buf, "b", body, &key, &[3u8; 16], &[], 10)
            .unwrap()
            .to_vec();
        assert!(matches!(open(&sealed).unwrap(), Found::File(_)));

        let mut buf = vec![0u8; len_bound("b", body.len())];
        let clear = write_clear(&mut buf, "b", body).unwrap().to_vec();
        assert!(matches!(open(&clear).unwrap(), Found::Clear(_)));

        // A cleartext file behind an encrypted header is a mix nobody writes; the
        // header reader refuses it by name rather than reading it as either.
        let off = u64::from_le_bytes(clear[12..20].try_into().unwrap()) as usize;
        let len = u64::from_le_bytes(clear[20..28].try_into().unwrap()) as usize;
        let header = &clear[BASE + off..BASE + off + len];
        assert_eq!(file_in(header).unwrap_err(), Error::NotEncrypted);
    }

    /// With no key there is no wrong-password failure; the CRC is the only thing
    /// standing between a damaged file and a restore of the damage.
    #[test]
    fn a_damaged_cleartext_file_fails_its_checksum() {
        let body = b"# Coldcard backup file! DO NOT CHANGE.\nchain = \"BTC\"\n";
        let mut buf = vec![0u8; len_bound("b", body.len())];
        let mut archive = write_clear(&mut buf, "b", body).unwrap().to_vec();
        archive[BASE + 3] ^= 0x01;
        let p = match open(&archive).unwrap() {
            Found::Clear(p) => p,
            other => panic!("expected a cleartext file, got {other:?}"),
        };
        assert_eq!(
            extract_in_place(&mut archive, &p).unwrap_err(),
            Error::BadChecksum
        );
    }

    /// A Copy stream is never padded, so a cleartext folder whose pack and unpack sizes
    /// disagree is a malformed archive, not a file with some padding to strip.
    #[test]
    fn a_padded_cleartext_stream_is_refused() {
        let body = b"# Coldcard backup file! DO NOT CHANGE.\n";
        let mut buf = vec![0u8; len_bound("b", body.len())];
        let mut archive = write_clear(&mut buf, "b", body).unwrap().to_vec();
        // Grow the pack size by one in the next header. Its `kSize` number is the byte
        // after `kPackInfo(06) packPos(00) numPackStreams(01) kSize(09)`.
        let off = u64::from_le_bytes(archive[12..20].try_into().unwrap()) as usize;
        let start = BASE + off;
        assert_eq!(
            &archive[start..start + 6],
            &[K_HEADER, K_MAIN_STREAMS, K_PACK_INFO, 0, 1, K_SIZE]
        );
        archive[start + 6] += 1;
        fix_crcs(&mut archive);
        assert_eq!(open(&archive).unwrap_err(), Error::BadArchive);
    }
}

/// Against the reference implementation, both ways.
///
/// [`tests::REFERENCE`] pins one archive forever, which proves the reader but says
/// nothing about the writer: `7z` has to actually *open* what we produce. These tests
/// shell out to the `7z` on the host to check that, and build fresh archives rather
/// than relying only on the frozen one.
///
/// They **skip** where `7z` is not installed rather than failing: a machine without
/// p7zip is one that cannot run them, not a bug in this crate. The frozen vector holds
/// the line in that case.
///
/// Passwords and contents here are throwaway. No seed, and nothing derived from one,
/// ever goes into a fixture.
#[cfg(test)]
mod reference_tool {
    use super::*;
    use crate::kdf;
    use std::path::{Path, PathBuf};
    use std::process::Command;

    const PASSWORD: &str = "canary lantern rubble";
    const CYCLES: u8 = 19;

    fn seven_zip() -> Option<&'static str> {
        ["7z", "7za", "7zz"].into_iter().find(|exe| {
            Command::new(exe)
                .arg("--help")
                .output()
                .is_ok_and(|o| o.status.success() || !o.stdout.is_empty())
        })
    }

    /// A fresh directory under the system temp dir, named for the test using it.
    fn workdir(tag: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("catcard-backup-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn run(exe: &str, dir: &Path, args: &[&str]) -> std::process::Output {
        Command::new(exe)
            .current_dir(dir)
            .args(args)
            .output()
            .expect("7z ran")
    }

    /// The direction that matters for a backup the owner will one day open on a laptop:
    /// what this firmware writes has to be readable by the tool everybody already has.
    #[test]
    fn the_reference_tool_opens_what_we_write() {
        let Some(exe) = seven_zip() else {
            eprintln!("skipped: no 7z on PATH");
            return;
        };
        let dir = workdir("we-write");

        let body = b"# Coldcard backup file! DO NOT CHANGE.\n\nchain = \"BTC\"\n\n# EOF\n";
        let key = kdf::derive(PASSWORD, &[], CYCLES).unwrap();
        let iv = [0x11u8; 16];
        let mut buf = vec![0u8; len_bound("backup.txt", body.len())];
        let archive = write(&mut buf, "backup.txt", body, &key, &iv, &[], CYCLES).unwrap();
        std::fs::write(dir.join("ours.7z"), archive).unwrap();

        let pw = format!("-p{PASSWORD}");
        let out = run(exe, &dir, &["t", &pw, "ours.7z"]);
        assert!(
            out.status.success(),
            "7z refused our archive:\n{}\n{}",
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr),
        );

        let out = run(exe, &dir, &["x", "-y", &pw, "ours.7z"]);
        assert!(out.status.success(), "7z x failed: {out:?}");
        assert_eq!(std::fs::read(dir.join("backup.txt")).unwrap(), body);

        let _ = std::fs::remove_dir_all(&dir);
    }

    /// And the direction that matters for a restore: an archive nobody here built.
    #[test]
    fn we_open_what_the_reference_tool_writes() {
        let Some(exe) = seven_zip() else {
            eprintln!("skipped: no 7z on PATH");
            return;
        };
        let dir = workdir("they-write");

        let body: Vec<u8> = (0..1000u32).map(|i| (i % 251) as u8).collect();
        std::fs::write(dir.join("inner.txt"), &body).unwrap();
        let pw = format!("-p{PASSWORD}");
        let out = run(
            exe,
            &dir,
            &[
                "a",
                "-t7z",
                "-mx0",
                "-m0=Copy",
                "-mhe=off",
                &pw,
                "theirs.7z",
                "inner.txt",
            ],
        );
        assert!(out.status.success(), "7z a failed: {out:?}");

        let archive = std::fs::read(dir.join("theirs.7z")).unwrap();
        let s = match open(&archive).unwrap() {
            Found::File(s) => s,
            other => panic!("-mhe=off should leave the header plain, got {other:?}"),
        };
        assert_eq!(s.unpacked_len, body.len());
        let key = kdf::derive(PASSWORD, s.salt(), s.cycles_power).unwrap();
        let mut out_buf = vec![0u8; s.packed_len];
        assert_eq!(
            decrypt(&archive, &s, &key, &mut out_buf).unwrap(),
            &body[..]
        );

        let _ = std::fs::remove_dir_all(&dir);
    }

    /// `-mhe=on` encrypts the header too, so the file list is unreadable without the
    /// password. Nothing here writes one, but a backup made elsewhere might be one, and
    /// answering "not a backup" to a perfectly good file is the worst failure available.
    #[test]
    fn we_open_an_archive_whose_header_is_encrypted_too() {
        let Some(exe) = seven_zip() else {
            eprintln!("skipped: no 7z on PATH");
            return;
        };
        let dir = workdir("hidden-header");

        let body = b"# Coldcard backup file! DO NOT CHANGE.\n\n# EOF\n";
        std::fs::write(dir.join("inner.txt"), body).unwrap();
        let pw = format!("-p{PASSWORD}");
        let out = run(
            exe,
            &dir,
            &[
                "a",
                "-t7z",
                "-mx0",
                "-m0=Copy",
                "-mhe=on",
                &pw,
                "hidden.7z",
                "inner.txt",
            ],
        );
        assert!(out.status.success(), "7z a failed: {out:?}");

        let archive = std::fs::read(dir.join("hidden.7z")).unwrap();
        let hdr = match open(&archive).unwrap() {
            Found::Header(s) => s,
            other => panic!("-mhe=on should encrypt the header, got {other:?}"),
        };
        // One derivation serves both streams: same salt, same round count, different
        // IV. That is what makes the encrypted-header case affordable on the device.
        let key = kdf::derive(PASSWORD, hdr.salt(), hdr.cycles_power).unwrap();
        let mut hdr_buf = vec![0u8; hdr.packed_len];
        let decoded = decrypt(&archive, &hdr, &key, &mut hdr_buf)
            .unwrap()
            .to_vec();

        let s = file_in(&decoded).unwrap();
        assert_eq!(s.salt(), hdr.salt());
        assert_eq!(s.cycles_power, hdr.cycles_power);
        let mut out_buf = vec![0u8; s.packed_len];
        assert_eq!(decrypt(&archive, &s, &key, &mut out_buf).unwrap(), body);

        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Compression is what we refuse, and it is `7z`'s default -- so the refusal is
    /// checked against a file the tool really produces, not one a test edited into
    /// that shape.
    #[test]
    fn a_real_compressed_archive_is_refused_by_name() {
        let Some(exe) = seven_zip() else {
            eprintln!("skipped: no 7z on PATH");
            return;
        };
        let dir = workdir("compressed");

        std::fs::write(dir.join("inner.txt"), vec![b'a'; 4096]).unwrap();
        let pw = format!("-p{PASSWORD}");
        let out = run(
            exe,
            &dir,
            &["a", "-t7z", "-mhe=off", &pw, "lzma.7z", "inner.txt"],
        );
        assert!(out.status.success(), "7z a failed: {out:?}");

        let archive = std::fs::read(dir.join("lzma.7z")).unwrap();
        assert_eq!(open(&archive).unwrap_err(), Error::Compressed);

        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A cleartext backup has to open on a laptop with no password at all, or the
    /// "cleartext" option is a lie. `7z t` with no `-p` is that laptop.
    #[test]
    fn the_reference_tool_opens_a_cleartext_archive_we_write() {
        let Some(exe) = seven_zip() else {
            eprintln!("skipped: no 7z on PATH");
            return;
        };
        let dir = workdir("we-write-clear");

        let body = b"# Coldcard backup file! DO NOT CHANGE.\n\nchain = \"BTC\"\n\n# EOF\n";
        let mut buf = vec![0u8; len_bound("backup.txt", body.len())];
        let archive = write_clear(&mut buf, "backup.txt", body).unwrap();
        std::fs::write(dir.join("clear.7z"), archive).unwrap();

        let out = run(exe, &dir, &["t", "clear.7z"]);
        assert!(
            out.status.success(),
            "7z refused our cleartext archive:\n{}\n{}",
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr),
        );
        let out = run(exe, &dir, &["x", "-y", "clear.7z"]);
        assert!(out.status.success(), "7z x failed: {out:?}");
        assert_eq!(std::fs::read(dir.join("backup.txt")).unwrap(), body);

        let _ = std::fs::remove_dir_all(&dir);
    }

    /// And a stored, unencrypted archive the tool wrote is read as cleartext -- the
    /// detection the firmware relies on to skip the password screen.
    #[test]
    fn we_open_a_cleartext_archive_the_reference_tool_writes() {
        let Some(exe) = seven_zip() else {
            eprintln!("skipped: no 7z on PATH");
            return;
        };
        let dir = workdir("they-write-clear");

        let body: Vec<u8> = (0..700u32).map(|i| (i % 253) as u8).collect();
        std::fs::write(dir.join("inner.txt"), &body).unwrap();
        let out = run(
            exe,
            &dir,
            &["a", "-t7z", "-mx0", "-m0=Copy", "clear.7z", "inner.txt"],
        );
        assert!(out.status.success(), "7z a failed: {out:?}");

        let archive = std::fs::read(dir.join("clear.7z")).unwrap();
        let p = match open(&archive).unwrap() {
            Found::Clear(p) => p,
            other => panic!("a stored archive with no password is cleartext, got {other:?}"),
        };
        assert_eq!(p.len, body.len());
        let mut out_buf = vec![0u8; p.len];
        assert_eq!(extract(&archive, &p, &mut out_buf).unwrap(), &body[..]);

        let _ = std::fs::remove_dir_all(&dir);
    }
}
