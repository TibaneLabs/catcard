//! Writing an address the way everybody writes it, and storing it the way flash wants it.
//!
//! An EVM address is twenty bytes that people exchange as `0x` and forty hex digits.
//! [`address`] converts at **compile time**, so the baked token table reads as the
//! addresses it came from while the image holds bytes.
//!
//! That is worth more than it costs, which is nothing. A generated table of byte arrays
//! can only be checked by running something over it; a table of `0x…` literals can be
//! read down the side of the source list it came from. And an address that is not an
//! address stops the build rather than becoming a row nobody looked at.

/// The twenty bytes of a hex-written EVM address, at compile time.
///
/// Case is ignored -- EIP-55 checksumming is about the *text*, and this is about the
/// bytes underneath it.
///
/// # Panics
/// At compile time, for anything that is not exactly twenty bytes of hex with an
/// optional `0x`.
pub const fn address(text: &str) -> [u8; 20] {
    let b = text.as_bytes();
    // An optional `0x`, because both spellings are in circulation.
    let start = if b.len() >= 2 && b[0] == b'0' && (b[1] == b'x' || b[1] == b'X') {
        2
    } else {
        0
    };
    assert!(b.len() - start == 40, "an address is forty hex digits");

    let mut out = [0u8; 20];
    let mut i = 0;
    while i < 20 {
        out[i] = nibble(b[start + i * 2]) << 4 | nibble(b[start + i * 2 + 1]);
        i += 1;
    }
    out
}

const fn nibble(c: u8) -> u8 {
    match c {
        b'0'..=b'9' => c - b'0',
        b'a'..=b'f' => c - b'a' + 10,
        b'A'..=b'F' => c - b'A' + 10,
        _ => panic!("not a hex digit"),
    }
}

#[cfg(test)]
mod tests {
    extern crate alloc;

    use super::*;

    /// The compile-time decoder agrees with hex written back out the other way.
    #[test]
    fn an_address_literal_is_the_address_it_is_written_as() {
        const USDC: [u8; 20] = address("0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48");
        let mut text = alloc::string::String::from("0x");
        for b in USDC {
            text.push(char::from_digit((b >> 4) as u32, 16).expect("hex"));
            text.push(char::from_digit((b & 0xf) as u32, 16).expect("hex"));
        }
        assert_eq!(text, "0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48");

        // Case does not change the bytes, and neither does the prefix.
        assert_eq!(
            address("a0b86991c6218b36c1d19d4a2e9eb0ce3606eb48"),
            address("0xA0B86991C6218B36C1D19D4A2E9EB0CE3606EB48"),
        );
    }

    /// Every baked address finds itself, on its own chain.
    #[test]
    fn every_baked_token_finds_itself() {
        for i in 0..crate::tokens::known() {
            let (chain, addr, symbol) = crate::tokens::at(i).expect("in range");
            assert_eq!(
                crate::tokens::lookup(chain, &addr).map(|t| t.symbol),
                Some(symbol),
            );
        }
    }
}
