//! Output script descriptors: what a watch-only wallet needs to follow this device.
//!
//! A descriptor names the script, the key's origin (master fingerprint and path) and the
//! extended public key to derive from, with a checksum that catches a mistyped or damaged
//! string. Exporting one is how a computer learns every address this device will sign
//! for, without ever seeing a private key -- and so how the PSBTs it later asks this device
//! to sign get made.
//!
//! Only the single-signature forms are written here: `pkh` (BIP-381), `wpkh` and
//! `sh(wpkh)` (BIP-382) and the key-path-only `tr` (BIP-386), with the receive and change
//! chains in one key expression as `/<0;1>/*` (BIP-389).
//!
//! Sources: BIP-380 (syntax, checksum algorithm and its test vectors), BIP-381, BIP-382,
//! BIP-386, BIP-389 -- all public standards [C].

use core::fmt::{self, Write};

use crate::address::AddressKind;
use crate::bip32::FINGERPRINT_LEN;

/// The checksum's length in characters.
pub const CHECKSUM_LEN: usize = 8;

/// Every character a descriptor may contain, in the order that gives each its symbol.
/// Source: BIP-380 "Checksum" [C]
const INPUT_CHARSET: &[u8] =
    b"0123456789()[],'/*abcdefgh@:$%{}IJKLMNOPQRSTUVWXYZ&+-.;<=>?!^_|~ijklmnopqrstuvwxyzABCDEFGH`#\"\\ ";

/// The alphabet the checksum is written in. Source: BIP-380 [C]
const CHECKSUM_CHARSET: &[u8] = b"qpzry9x8gf2tvdw0s3jn54khce6mua7l";

/// The BCH code's generator. Source: BIP-380 [C]
const GENERATOR: [u64; 5] = [
    0xf5dee51989,
    0xa9fdca3312,
    0x1bab10e32d,
    0x3706b1677a,
    0x644d626ffd,
];

fn polymod(chk: u64, value: u64) -> u64 {
    let top = chk >> 35;
    let mut chk = ((chk & 0x7_ffff_ffff) << 5) ^ value;
    for (i, g) in GENERATOR.iter().enumerate() {
        if (top >> i) & 1 == 1 {
            chk ^= g;
        }
    }
    chk
}

/// The polymod over a descriptor's characters, before any checksum symbols. `None` if a
/// character is outside the descriptor character set.
fn expand(s: &str) -> Option<u64> {
    let mut chk = 1u64;
    let mut groups = [0u64; 3];
    let mut count = 0;
    for c in s.bytes() {
        let v = INPUT_CHARSET.iter().position(|&x| x == c)? as u64;
        chk = polymod(chk, v & 31);
        groups[count] = v >> 5;
        count += 1;
        if count == 3 {
            chk = polymod(chk, groups[0] * 9 + groups[1] * 3 + groups[2]);
            count = 0;
        }
    }
    match count {
        1 => chk = polymod(chk, groups[0]),
        2 => chk = polymod(chk, groups[0] * 3 + groups[1]),
        _ => {}
    }
    Some(chk)
}

/// The checksum for `descriptor` (without its `#`), or `None` if it holds a character a
/// descriptor may not.
pub fn checksum(descriptor: &str) -> Option<[u8; CHECKSUM_LEN]> {
    let mut chk = expand(descriptor)?;
    for _ in 0..CHECKSUM_LEN {
        chk = polymod(chk, 0);
    }
    chk ^= 1;
    let mut out = [0u8; CHECKSUM_LEN];
    for (i, o) in out.iter_mut().enumerate() {
        *o = CHECKSUM_CHARSET[((chk >> (5 * (7 - i))) & 31) as usize];
    }
    Some(out)
}

/// Whether `text` is a descriptor followed by `#` and its correct checksum.
pub fn verify(text: &str) -> bool {
    let Some((body, sum)) = text.rsplit_once('#') else {
        return false;
    };
    sum.len() == CHECKSUM_LEN && checksum(body).is_some_and(|c| c == sum.as_bytes())
}

/// A single-signature account: which script, and where its key sits under the master.
#[derive(Copy, Clone, Debug)]
pub struct SingleSig {
    pub kind: AddressKind,
    /// The master key's fingerprint.
    pub fingerprint: [u8; FINGERPRINT_LEN],
    /// SLIP-44 coin type: 0 for Bitcoin, 1 for its test networks.
    pub coin: u32,
    pub account: u32,
}

/// Why a descriptor could not be written.
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub enum Error {
    /// The output buffer is too small.
    Overflow,
}

/// A `fmt::Write` over a fixed byte buffer.
struct Buf<'a> {
    out: &'a mut [u8],
    len: usize,
}

impl Write for Buf<'_> {
    fn write_str(&mut self, s: &str) -> fmt::Result {
        let end = self.len + s.len();
        self.out
            .get_mut(self.len..end)
            .ok_or(fmt::Error)?
            .copy_from_slice(s.as_bytes());
        self.len = end;
        Ok(())
    }
}

/// Room for any descriptor [`SingleSig::write`] produces: the longest wrapper, an origin
/// with three hardened steps, a 111-character xpub, the multipath suffix and the checksum.
pub const MAX_LEN: usize = 256;

impl SingleSig {
    /// Write the account's descriptor, checksum included, for the account-level extended
    /// public key `xpub` (Base58Check, `xpub...`), into `out`. Returns the length.
    ///
    /// For example `wpkh([d34db33f/84h/0h/0h]xpub.../<0;1>/*)#checksum`. Hardened steps are
    /// written `h`, which every descriptor reader accepts and needs no shell quoting.
    pub fn write(&self, xpub: &str, out: &mut [u8]) -> Result<usize, Error> {
        // `tr` here is key-path only -- no script tree -- which is what BIP-86 single-sig
        // taproot is. Source: BIP-386 [C]
        let (open, close) = match self.kind {
            AddressKind::P2pkh => ("pkh(", ")"),
            AddressKind::P2wpkh => ("wpkh(", ")"),
            AddressKind::P2shP2wpkh => ("sh(wpkh(", "))"),
            AddressKind::P2tr => ("tr(", ")"),
        };
        let mut buf = Buf { out, len: 0 };
        let [a, b, c, d] = self.fingerprint;
        write!(
            buf,
            "{open}[{a:02x}{b:02x}{c:02x}{d:02x}/{}h/{}h/{}h]{xpub}/<0;1>/*{close}",
            self.kind.bip44_purpose(),
            self.coin,
            self.account,
        )
        .map_err(|_| Error::Overflow)?;
        let len = buf.len;
        let body = core::str::from_utf8(&buf.out[..len]).map_err(|_| Error::Overflow)?;
        let sum = checksum(body).ok_or(Error::Overflow)?;
        buf.write_char('#').map_err(|_| Error::Overflow)?;
        let sum = core::str::from_utf8(&sum).map_err(|_| Error::Overflow)?;
        buf.write_str(sum).map_err(|_| Error::Overflow)?;
        Ok(buf.len)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_bip380_checksum_vectors() {
        assert_eq!(&checksum("raw(deadbeef)").unwrap(), b"89f8spxm");
        assert!(verify("raw(deadbeef)#89f8spxm"));
        assert!(!verify("raw(deadbeef)"));
        assert!(!verify("raw(deadbeef)#"));
        assert!(!verify("raw(deadbeef)#89f8spxmx"));
        assert!(!verify("raw(deadbeef)#89f8spx"));
        assert!(!verify("raw(deedbeef)#89f8spxm"));
        assert!(!verify("raw(deedbeef)##9f8spxm"));
        assert!(!verify("raw(Ü)#00000000"));
        assert_eq!(checksum("raw(Ü)"), None);
    }

    #[test]
    fn checksums_match_the_bip380_reference_implementation() {
        // `descsum_create` from BIP-380's own Python, run on these two strings.
        assert!(write(AddressKind::P2wpkh).ends_with("#fz79emew"));
        assert!(write(AddressKind::P2shP2wpkh).ends_with("#sn8q85u0"));
    }

    #[test]
    fn the_bip84_vector_account_comes_out_as_its_published_key_and_fingerprint() {
        use crate::bip32::{ChildNumber, ExtendedPrivKey, Network};
        use crate::bip39::{Mnemonic, SEED_LEN};
        use crate::encoding::base58;

        // BIP-84 "Test vectors": this mnemonic's account 0 is published as a zpub; the same
        // key with the xpub version bytes (0488b21e) is what the descriptor carries.
        let kw = crate::KeyWork::host();
        let m = Mnemonic::parse(
            "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about",
            &kw,
        )
        .unwrap();
        let mut seed = [0u8; SEED_LEN];
        m.to_seed("", &mut seed, &kw).unwrap();
        let master = ExtendedPrivKey::from_seed(&seed, Network::Mainnet, &kw).unwrap();
        let fingerprint = master.fingerprint(&kw);
        let mut account = master;
        for step in [84, 0, 0] {
            account = account
                .derive_child(ChildNumber::hardened(step).unwrap(), &kw)
                .unwrap();
        }
        let xpub = account.to_extended_pub(&kw).to_base58();

        let mut raw = [0u8; 82];
        let n = base58::decode_check(
            "zpub6rFR7y4Q2AijBEqTUquhVz398htDFrtymD9xYYfG1m4wAcvPhXNfE3EfH1r1ADqtfSdVCToUG868RvUUkgDKf31mGDtKsAYz2oz2AGutZYs",
            &mut raw,
        )
        .unwrap();
        raw[..4].copy_from_slice(&[0x04, 0x88, 0xb2, 0x1e]);
        let mut expected = [0u8; 128];
        let e = base58::encode_check(&raw[..n], &mut expected).unwrap();
        assert_eq!(xpub.as_str(), core::str::from_utf8(&expected[..e]).unwrap());

        let a = SingleSig {
            kind: AddressKind::P2wpkh,
            fingerprint,
            coin: 0,
            account: 0,
        };
        let mut out = [0u8; MAX_LEN];
        let len = a.write(&xpub, &mut out).unwrap();
        let d = core::str::from_utf8(&out[..len]).unwrap();
        // The fingerprint every wallet shows for this mnemonic.
        assert!(d.starts_with("wpkh([73c5da0a/84h/0h/0h]xpub"), "{d}");
        assert!(verify(d));
    }

    #[test]
    fn a_checksum_catches_a_changed_character_anywhere() {
        let base = "wpkh([ffffffff/84h/0h/0h]xpub6ERApfZwUNrhLCkDtcHTcxd75RbzS1ed54G1LkBUHQVHQKqhMkhgbmJbZRkrgZw4koxb5JaHWkY4ALHY2grBGRjaDMzQLcgJvLJuZZvRcEL/<0;1>/*)";
        let sum = checksum(base).unwrap();
        let mut s = base.as_bytes().to_vec();
        for i in 0..s.len() {
            let was = s[i];
            s[i] = if was == b'a' { b'b' } else { b'a' };
            let changed = core::str::from_utf8(&s).unwrap();
            assert_ne!(checksum(changed).unwrap(), sum, "position {i}");
            s[i] = was;
        }
    }

    const XPUB: &str = "xpub6ERApfZwUNrhLCkDtcHTcxd75RbzS1ed54G1LkBUHQVHQKqhMkhgbmJbZRkrgZw4koxb5JaHWkY4ALHY2grBGRjaDMzQLcgJvLJuZZvRcEL";

    fn write(kind: AddressKind) -> String {
        let a = SingleSig {
            kind,
            fingerprint: [0xd3, 0x4d, 0xb3, 0x3f],
            coin: 0,
            account: 0,
        };
        let mut out = [0u8; MAX_LEN];
        let n = a.write(XPUB, &mut out).unwrap();
        String::from_utf8(out[..n].to_vec()).unwrap()
    }

    #[test]
    fn each_single_sig_form_is_written_with_its_origin_multipath_and_checksum() {
        let w = write(AddressKind::P2wpkh);
        assert!(w.starts_with(&format!("wpkh([d34db33f/84h/0h/0h]{XPUB}/<0;1>/*)#")));
        assert!(verify(&w));
        let sh = write(AddressKind::P2shP2wpkh);
        assert!(sh.starts_with(&format!("sh(wpkh([d34db33f/49h/0h/0h]{XPUB}/<0;1>/*))#")));
        assert!(verify(&sh));
        let p = write(AddressKind::P2pkh);
        assert!(p.starts_with(&format!("pkh([d34db33f/44h/0h/0h]{XPUB}/<0;1>/*)#")));
        assert!(verify(&p));
        let t = write(AddressKind::P2tr);
        assert!(t.starts_with(&format!("tr([d34db33f/86h/0h/0h]{XPUB}/<0;1>/*)#")));
        assert!(verify(&t));
    }

    #[test]
    fn a_short_buffer_is_refused_not_truncated() {
        let a = SingleSig {
            kind: AddressKind::P2wpkh,
            fingerprint: [0; 4],
            coin: 0,
            account: 0,
        };
        assert_eq!(a.write(XPUB, &mut [0u8; 40]), Err(Error::Overflow));
    }
}
