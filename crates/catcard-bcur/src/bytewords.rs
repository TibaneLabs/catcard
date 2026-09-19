//! Bytewords: bytes as four-letter words, and the "minimal" form that fits a QR code.
//!
//! Each byte is one of 256 words. The **minimal** encoding writes only a word's first
//! and last letter, so two characters a byte -- which is what an animated QR carries,
//! because those letters are all lower case and a QR's alphanumeric mode is upper case
//! only. Minimal bytewords therefore travel in byte mode, and this is the density BC-UR
//! pays for being readable aloud.
//!
//! A sequence ends with a **CRC-32 of everything before it**, big-endian, encoded the
//! same way -- so the last four words are the checksum and are not part of the payload.
//!
//! Source: Blockchain Commons BCR-2020-012. The table below was taken from that
//! document and checked against its own test vector: the payload
//! `c7098580125e2ab0981253468b2dbc52` has CRC-32 `feac0dea` and encodes minimally as
//! `staslplabghydrpfmkbggufgludprfgmzepsbtwd`, which `the_spec_test_vector` asserts.

/// The first and last letter of each of the 256 words, in order.
///
/// Only these two letters are ever needed: the full words exist to be read aloud, and
/// nothing here reads anything aloud. Two bytes a word rather than four.
///
/// Written as eight rows of thirty-two words so it can be read against the
/// specification, and joined at compile time so there is one copy of it.
const PAIRS: [u8; 512] = {
    const ROWS: [&[u8]; 8] = [
        b"aeadaoaxaaahamatayasbkbdbnbtbabsbebybgbwbbbzcmchcscfcycwcecackct",
        b"cxclcpcndkdadsdidedtdrdndwdpdmdldyeheyeoeeecenemetesftfrfnfsfmfh",
        b"fzfpfwfxfyfefgflfdgagegrgsgtglgwgdgygmgughgohfhghdhkhthphhhlhyhe",
        b"hnhsidiaieihiyioisinimjejzjnjtjljojsjpjkjykpkoktkskkknkgkekikblb",
        b"lalylflslrlplnltloldlelulklgmnmymhmemomumwmdmtmsmknlnyndnsntnnne",
        b"nboyoeotoxonolospdptpkpypspmplpepfpaprqdqzrerprlrorhrdrkrfryrnrs",
        b"rtsesasrssskswstspsosgsbsfsntotktitttdtetytltbtstptatnuyuoutueur",
        b"vtvyvovlvevwvavdvswlwdwmwpwewywswtwnwzwfwkykynylyaytzszoztzczezm",
    ];
    let mut out = [0u8; 512];
    let (mut row, mut at) = (0, 0);
    while row < ROWS.len() {
        let mut i = 0;
        while i < ROWS[row].len() {
            out[at] = ROWS[row][i];
            at += 1;
            i += 1;
        }
        row += 1;
    }
    out
};

/// Every two-letter pair that is a word, as a direct lookup.
///
/// Indexed `(first - b'a') * 26 + (last - b'a')`, holding the byte that pair means, or
/// [`NONE`] where no word has that shape. Built at compile time from [`PAIRS`] so there
/// is one copy of the list and no chance of the two disagreeing.
///
/// `u16`, not `u8`, and that is the whole reason this comment exists: there are 256
/// words and a "no such word" marker, which is 257 things, and 257 things do not fit in
/// a byte. The first version used `0xFF` as the marker, which is also the index of
/// `zoom` -- so every byte `0xFF` in a payload decoded as "not a word". The spec's own
/// test vector contains no `0xFF` and passed happily.
const NONE: u16 = 0x100;
const LOOKUP: [u16; 26 * 26] = {
    let mut table = [NONE; 26 * 26];
    let mut i = 0;
    while i < 256 {
        let first = (PAIRS[i * 2] - b'a') as usize;
        let last = (PAIRS[i * 2 + 1] - b'a') as usize;
        table[first * 26 + last] = i as u16;
        i += 1;
    }
    table
};

/// What a sequence is not.
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub enum Error {
    /// An odd length, or too short to hold the checksum.
    Length,
    /// Two letters that are not the ends of any word.
    NotAWord,
    /// The decode is fine and the checksum does not match what it covers.
    Checksum { want: u32, got: u32 },
    /// More bytes than the caller left room for.
    TooLong,
}

/// Bytes the checksum occupies at the end of every sequence.
pub const CHECKSUM_LEN: usize = 4;

/// How many bytes `text` decodes to, not counting the checksum.
pub fn decoded_len(text: &[u8]) -> Result<usize, Error> {
    if !text.len().is_multiple_of(2) {
        return Err(Error::Length);
    }
    (text.len() / 2)
        .checked_sub(CHECKSUM_LEN)
        .ok_or(Error::Length)
}

/// Decode minimal bytewords into `out`, checking the trailing CRC-32.
///
/// Returns how many bytes were written, which excludes the checksum: it is there to be
/// verified, not to be delivered.
pub fn decode(text: &[u8], out: &mut [u8]) -> Result<usize, Error> {
    let need = decoded_len(text)?;
    if need > out.len() {
        return Err(Error::TooLong);
    }
    // The payload, then the four checksum bytes, which are decoded the same way.
    for (slot, pair) in out[..need].iter_mut().zip(text.chunks(2)) {
        *slot = byte_of(pair)?;
    }
    let mut want = 0u32;
    for pair in text[need * 2..].chunks(2) {
        want = want << 8 | byte_of(pair)? as u32;
    }
    let got = crc32(&out[..need]);
    if got != want {
        return Err(Error::Checksum { want, got });
    }
    Ok(need)
}

fn byte_of(pair: &[u8]) -> Result<u8, Error> {
    // Either case. Bytewords are written lower case, but a UR may legitimately be
    // upper-cased whole so that a QR can use its alphanumeric mode -- so a reader that
    // insisted on lower case would refuse the denser half of what is out there.
    let (a, b) = (pair[0].to_ascii_lowercase(), pair[1].to_ascii_lowercase());
    if !a.is_ascii_lowercase() || !b.is_ascii_lowercase() {
        return Err(Error::NotAWord);
    }
    match LOOKUP[(a - b'a') as usize * 26 + (b - b'a') as usize] {
        NONE => Err(Error::NotAWord),
        byte => Ok(byte as u8),
    }
}

/// Write `data` and its CRC-32 as minimal bytewords, **upper case**.
///
/// Upper case because that is the half of ASCII a QR's alphanumeric mode covers, and a
/// UR written in it fits a third more in the same symbol. The specification allows it
/// and readers lower-case what they receive, which is why [`decode`] takes either.
///
/// Returns how many characters were written: two per byte, including the checksum.
pub fn encode_upper(data: &[u8], out: &mut [u8]) -> usize {
    let mut at = 0;
    let mut put = |byte: u8, out: &mut [u8]| {
        let pair = &PAIRS[byte as usize * 2..][..2];
        if at + 2 <= out.len() {
            out[at] = pair[0].to_ascii_uppercase();
            out[at + 1] = pair[1].to_ascii_uppercase();
            at += 2;
        }
    };
    for &b in data {
        put(b, out);
    }
    for b in crc32(data).to_be_bytes() {
        put(b, out);
    }
    at
}

/// CRC-32, the ordinary one: reflected, polynomial `0xEDB88320`, inverted either end.
///
/// Computed a bit at a time rather than from a table. A table is 1 KiB of flash to save
/// microseconds on a payload that took a person a minute to wave at a camera.
pub fn crc32(data: &[u8]) -> u32 {
    let mut crc = 0xFFFF_FFFFu32;
    for &b in data {
        crc ^= b as u32;
        for _ in 0..8 {
            let bit = crc & 1;
            crc >>= 1;
            if bit != 0 {
                crc ^= 0xEDB8_8320;
            }
        }
    }
    !crc
}
