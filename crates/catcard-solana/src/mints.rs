//! Solana mints this firmware can name.
//!
//! Generated. Edit the source list and re-run:
//!
//! ```text
//! tools/tokengen/mints.py tools/tokengen/solana-tokens.js crates/catcard-solana/src/mints.rs
//! ```
//!
//! **A row here is a claim about a mint**, and the screens treat it as one: the
//! address is shown whether or not it is named, and a name is a label on it rather
//! than a replacement for it. How each row earned its place -- two independent
//! sources agreeing on the address *and* the decimals -- is written at the top of
//! the source list.
//!
//! Written as base58 and **stored as the thirty-two bytes a mint is**:
//! [`crate::literal::mint`] converts at compile time, so this file can be read
//! against the source list by eye while the image holds bytes and decodes
//! nothing. 28 mints, 896 bytes of addresses.

/// What a mint turns out to be.
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub struct Mint {
    /// The ticker, as the chain's own explorers write it.
    pub symbol: &'static str,
    /// Decimal places, for turning the raw amount into the number people use.
    pub decimals: u8,
}

use crate::literal::mint;

/// `(mint, symbol, decimals)`, sorted by address so it can be searched.
#[rustfmt::skip]
static MINTS: [([u8; 32], &str, u8); 28] = [
    (mint("JUPyiwrYJFskUPiHa7hkeR8VUtAeFoSYbKedZNsDvCN"), "JUP", 6),
    (mint("METvsvVRapdj9cFLzq4Tr43xK4tAjQfwX76z3n6mWQL"), "MET", 6),
    (mint("So11111111111111111111111111111111111111112"), "SOL", 9),
    (mint("USDSwr9ApdHk5bvJKMjzff41FfuX8bSxdKcR81vTwcA"), "USDS", 6),
    (mint("bSo13r4TkiE4KumL71LsHTPpL2euBYLFx6h9HP3piy1"), "bSOL", 9),
    (mint("jtojtomepa8beP8AuQc6eXt5FriJwfFMwQx2v2f9mCL"), "JTO", 9),
    (mint("mSoLzYCxHdYgdzU16g5QSh3i5K3z3KZK7ytfqcJm7So"), "mSOL", 9),
    (mint("pumpCmXqMfrsAkQ5r49WcJnRayYRqmXz6ae8H7H9Dfn"), "PUMP", 6),
    (mint("27G8MtK7VtTcCHkpASjSDdkWWYfoqT6ggEuKidVJidD4"), "JLP", 6),
    (mint("2b1kV6DkPAnxd5ixfnxCpjxmKwqjjaYmCZfHsFu24GXo"), "PYUSD", 6),
    (mint("2u1tszSeqZ3qBWF3uNGPFc8TzMk2tdiwknnRMWGWjGWH"), "USDG", 6),
    (mint("2zMMhcVQEXDtdE6vsFS7S7D5oUodfJHE8vd1gnBouauv"), "PENGU", 6),
    (mint("3NZ9JMVBmGAqocybic2c7LQCJScmgsAZ6vQqTDzcqmJh"), "WBTC", 8),
    (mint("4k3Dyjzvzp8eMZWUXbBCjEvwSkkk59S5iCNLY3QrkX6R"), "RAY", 6),
    (mint("4y3oUrsJfSp431R3wJrWiaLxRPsnYtpkVJmoV2bYpBiy"), "WIFE", 6),
    (mint("7vfCXTUXx5WJV5JADk17DUJ4ksgau7utNKj4b963voxs"), "ETH", 8),
    (mint("98sMhvDwXj1RQi5c5Mndm3vPe9cBqPrbLaufMXFNMh5g"), "HYPE", 9),
    (mint("9BB6NFEcjBCtnNLFko2FqVQBq8HHM13kCyYcdQbgpump"), "Fartcoin", 6),
    (mint("A7bdiYdS5GjqGFtxf17ppRHtDKPkkRqbKtR27dxvQXaS"), "ZEC", 8),
    (mint("DezXAZ8z7PnrnRJjz3wXBoRgixCa6xjnB7YaB1pPB263"), "Bonk", 5),
    (mint("DtR4D9FtVoTX2569gaL837ZgrB6wNjj6tkmnX9Rdk9B2"), "aura", 6),
    (mint("Dz9mQ9NzkBcCsuGPFJ3r1bS4wgqKMHBPiVuniW8Mbonk"), "USELESS", 6),
    (mint("EKpQGSJtjMFqKZ9KQanSqYXRcF8fBopzLHYxdM65zcjm"), "$WIF", 6),
    (mint("EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v"), "USDC", 6),
    (mint("Es9vMFrzaCERmJfrF4H2FYD4KCoNkY11McCe8BenwNYB"), "USDT", 6),
    (mint("HZ1JovNiVvGrGNiiYvEozEVgZ58xaU3RKwX8eACQBCt3"), "PYTH", 6),
    (mint("HzwqbKZw8HxMN6bF2yFZNrht3c2iXXzpKcFu7uBEDKtr"), "EURC", 6),
    (mint("J1toso1uCk3RLmjorhTtrVwY9HJ7X8V9yYac6Y7kGCPn"), "JitoSOL", 9),
];

/// The mint at `address`, if this build knows it.
///
/// A miss is the ordinary case rather than an error: this is a few dozen mints out
/// of millions, and everything else is shown by address with its amount in raw
/// units -- which is what an unchecked transfer gives anyway.
pub fn lookup(address: &[u8; 32]) -> Option<Mint> {
    let i = MINTS.binary_search_by(|(m, _, _)| m.cmp(address)).ok()?;
    let (_, symbol, decimals) = MINTS[i];
    Some(Mint { symbol, decimals })
}

/// How many mints this build carries, for a screen that wants to say so.
pub fn known() -> usize {
    MINTS.len()
}

/// Row `i`: the mint's address and what it is.
///
/// For a walk over every mint this build knows -- which is how an amount in a
/// token account gets a name when the instruction moving it did not carry one.
pub fn at(i: usize) -> Option<([u8; 32], Mint)> {
    let (address, symbol, decimals) = *MINTS.get(i)?;
    Some((address, Mint { symbol, decimals }))
}
