//! Address and key encodings.
//!
//! Everything here is allocation-free: callers supply output buffers, and the bounds
//! are fixed because everything CatCard encodes is small — an extended key is 78 bytes,
//! an address payload 21 or 33.

pub mod base58;
pub mod bech32;
