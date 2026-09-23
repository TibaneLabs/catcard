//! Writing a mint the way everybody writes it, and storing it the way flash wants it.
//!
//! A Solana address is thirty-two bytes that people exchange as forty-four characters of
//! base58. Both matter, in different places: the text is what somebody compares against
//! an explorer, and the bytes are what a transaction carries and what a table should
//! hold -- a third smaller, and with no decoding at lookup time.
//!
//! [`mint`] is the bridge, and it runs at **compile time**. So the baked table reads as
//! the addresses it came from, and is still an array of bytes in the image.
//!
//! That is worth more than the bytes it saves. A generated table of hex arrays can only
//! be checked by running something over it; a table of base58 literals can be read down
//! the side of the source list it came from. And an address that is not an address is a
//! build error rather than a row nobody looked at.

/// The base58 alphabet, in the order that gives each character its value.
const ALPHABET: &[u8; 58] = b"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

/// The thirty-two bytes of a base58-written Solana address, at compile time.
///
/// # Panics
/// At compile time, for anything that is not exactly a 32-byte address: an unknown
/// character, or a value too long or too short. A panic in a `const` is a build that
/// stops, which is where a wrong address should stop.
pub const fn mint(text: &str) -> [u8; 32] {
    let bytes = text.as_bytes();
    // Leading '1's are leading zero bytes; the rest is a base-58 number.
    let mut zeros = 0;
    while zeros < bytes.len() && bytes[zeros] == b'1' {
        zeros += 1;
    }

    // Big-endian accumulator, built by repeated multiply-and-add.
    let mut acc = [0u8; 32];
    let mut i = zeros;
    while i < bytes.len() {
        // The character's value.
        let mut v = 58;
        let mut k = 0;
        while k < 58 {
            if ALPHABET[k] == bytes[i] {
                v = k;
                break;
            }
            k += 1;
        }
        assert!(v < 58, "not base58");

        let mut carry = v as u32;
        let mut j = 32;
        while j > 0 {
            j -= 1;
            let x = acc[j] as u32 * 58 + carry;
            acc[j] = (x & 0xff) as u8;
            carry = x >> 8;
        }
        // Anything carried out of the top is an address wider than an address.
        assert!(carry == 0, "too long for 32 bytes");
        i += 1;
    }

    // The leading zeros have to be real, not an accident of a short value: a 32-byte
    // address written with fewer leading '1's than it has zero bytes would come out the
    // same, and that is a different address with the same name.
    let mut lead = 0;
    while lead < 32 && acc[lead] == 0 {
        lead += 1;
    }
    assert!(lead == zeros, "not 32 bytes");
    acc
}

#[cfg(test)]
mod tests {
    extern crate alloc;

    use super::*;

    /// The compile-time decoder agrees with one written the other way round.
    ///
    /// The check that matters is not that `mint` returns *something*, it is that what it
    /// returns spells the address it was given. So this encodes the bytes back and
    /// compares the text, with an encoder that shares no code with the decoder.
    fn base58(raw: &[u8; 32]) -> alloc::string::String {
        use alloc::string::String;
        let mut digits = [0u8; 64];
        let mut len = 0;
        for &b in raw {
            let mut carry = b as u32;
            for d in digits.iter_mut().take(len) {
                carry += (*d as u32) << 8;
                *d = (carry % 58) as u8;
                carry /= 58;
            }
            while carry > 0 {
                digits[len] = (carry % 58) as u8;
                len += 1;
                carry /= 58;
            }
        }
        let mut out = String::new();
        for &b in raw {
            if b != 0 {
                break;
            }
            out.push('1');
        }
        for i in (0..len).rev() {
            out.push(ALPHABET[digits[i] as usize] as char);
        }
        out
    }

    #[test]
    fn a_mint_literal_is_the_address_it_is_written_as() {
        // Wrapped SOL, which is the awkward one: its base58 is nearly all '1's.
        const WSOL: [u8; 32] = mint("So11111111111111111111111111111111111111112");
        assert_eq!(base58(&WSOL), "So11111111111111111111111111111111111111112");

        const USDC: [u8; 32] = mint("EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v");
        assert_eq!(
            base58(&USDC),
            "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v"
        );

        // The System program: thirty-two zero bytes, written as thirty-two '1's.
        const SYSTEM: [u8; 32] = mint("11111111111111111111111111111111");
        assert_eq!(SYSTEM, [0u8; 32]);
    }

    #[test]
    fn every_baked_mint_spells_itself() {
        for i in 0..crate::mints::known() {
            let (raw, mint) = crate::mints::at(i).expect("in range");
            let symbol = mint.symbol;
            let text = base58(&raw);
            assert_eq!(
                crate::mints::lookup(&raw).map(|m| m.symbol),
                Some(symbol),
                "{text} does not find itself"
            );
        }
    }
}
