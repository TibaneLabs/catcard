//! A FIDO2 security key: CTAP2 and U2F (CTAP1) over CTAPHID, with every credential key
//! derived from the wallet in force.
//!
//! | module | what |
//! |---|---|
//! | [`hid`] | CTAPHID: 64-byte reports, channels, reassembly, keepalives, timeouts |
//! | [`cbor`] | the strict, canonical CBOR subset CTAP2 speaks |
//! | [`ctap2`] | `authenticatorMakeCredential`, `GetAssertion`, `GetNextAssertion`, `GetInfo`, `Reset`, `Selection` |
//! | [`pin`] | `authenticatorClientPIN`: PIN/UV auth protocols 2 and 1, the pinUvAuthToken |
//! | [`passkeys`] | discoverable credentials: the per-wallet file and its records |
//! | [`credmgmt`] | `authenticatorCredentialManagement`: list, rename, delete passkeys |
//! | [`u2f`] | the U2F raw messages: `REGISTER`, `AUTHENTICATE`, `VERSION` |
//! | [`keys`] | the credential key derivation, and why nothing is stored |
//! | [`der`] | ECDSA signatures and the U2F self-signed certificate |
//!
//! Everything here is `no_std`, allocation-free and host-tested; the firmware supplies
//! the transport, the screen, the wallet and the storage through [`ctap2::Env`]. What
//! is **not** here: built-in user verification (the client PIN is the only UV), NFC, BLE,
//! enterprise attestation, large blobs, and every extension. See `docs/FIDO.md`.
//!
//! Sources, cited per item as `[C]`: FIDO CTAP 2.1 Proposed Standard (2021-06-15) incl.
//! §11.2 CTAPHID; FIDO U2F Raw Message Formats v1.2; W3C WebAuthn Level 2; RFC 8949
//! (CBOR); RFC 9052/9053 (COSE); SEC 1 v2 and FIPS 186-5 (P-256 ECDSA); RFC 6979
//! (deterministic nonces); RFC 5280 and ITU-T X.690 (X.509, DER).

#![cfg_attr(not(feature = "std"), no_std)]
#![deny(unsafe_code)]

pub mod cbor;
pub mod credmgmt;
pub mod ctap2;
pub mod der;
pub mod hid;
pub mod keys;
pub mod passkeys;
pub mod pin;
pub mod u2f;

#[cfg(test)]
mod flows;
