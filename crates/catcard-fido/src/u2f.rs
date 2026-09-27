//! U2F (CTAP1): the raw APDUs a `CTAPHID_MSG` carries.
//!
//! | INS | command | here |
//! |---|---|---|
//! | 0x01 | `U2F_REGISTER` | a new key handle, the same shape as a CTAP2 credential id |
//! | 0x02 | `U2F_AUTHENTICATE` | control 0x07 check-only, 0x03 enforce presence, 0x08 don't |
//! | 0x03 | `U2F_VERSION` | `"U2F_V2"` |
//!
//! Source: FIDO U2F Raw Message Formats v1.2 (2017-04-11) §3-§6 [C]; CTAP 2.1 §11.2.9.1.1
//! (MSG) and §8.1 "U2F Interoperability" for control byte 0x08 [C]; ISO/IEC 7816-4 §5.1
//! for the short and extended APDU encodings [C].
//!
//! # One key space for both protocols
//!
//! A U2F key handle **is** a CTAP2 credential id ([`crate::keys`]), bound to the
//! application parameter the same way a credential id is bound to `rpIdHash`. A site
//! whose U2F application id equals its WebAuthn RP id (or which uses the WebAuthn `appid`
//! extension) therefore finds a U2F registration from CTAP2 and a CTAP2 one from U2F.
//!
//! # User presence, the U2F way
//!
//! U2F has no keepalive: a command that needs a press and has not got one answers
//! `SW_CONDITIONS_NOT_SATISFIED` at once, and the host sends it again until it does not
//! (§4.2 of the raw message spec, "test-of-user-presence required"). So
//! [`Env::u2f_presence`](crate::ctap2::Env::u2f_presence) does not wait: it says whether
//! a press has been given for this site, and the device asks on its screen *after* the
//! refusal has gone back. The next retry finds the press.
//!
//! # The attestation certificate
//!
//! U2F registration must carry an X.509 certificate and a signature by its key. This
//! device makes one per registration, self-signed by that registration's own key
//! ([`crate::der::tbs`]), rather than holding one attestation key for all of them: a
//! shared key would either be the same on every CatCard (and prove nothing) or unique to
//! one (and link every site it registers with). A relying party that checks U2F
//! attestation against a list of vendors will not find this one, which is the truth.

use catcard_wallet::KeyWork;

use crate::ctap2::Env;
use crate::der;
use crate::keys::{CRED_ID_LEN, NONCE_LEN};

/// Status words. Source: U2F Raw Message Formats §3.3 [C]
pub mod sw {
    pub const NO_ERROR: u16 = 0x9000;
    pub const CONDITIONS_NOT_SATISFIED: u16 = 0x6985;
    pub const WRONG_DATA: u16 = 0x6A80;
    pub const WRONG_LENGTH: u16 = 0x6700;
    pub const CLA_NOT_SUPPORTED: u16 = 0x6E00;
    pub const INS_NOT_SUPPORTED: u16 = 0x6D00;
}

/// Instruction bytes. Source: U2F Raw Message Formats §4.1, §5.1, §6.1 [C]
pub mod ins {
    pub const REGISTER: u8 = 0x01;
    pub const AUTHENTICATE: u8 = 0x02;
    pub const VERSION: u8 = 0x03;
}

/// `U2F_AUTHENTICATE` control bytes. Source: U2F Raw Message Formats §5.1; CTAP 2.1
/// §8.1.2 (0x08) [C]
pub mod control {
    pub const ENFORCE_UP: u8 = 0x03;
    pub const CHECK_ONLY: u8 = 0x07;
    pub const DONT_ENFORCE_UP: u8 = 0x08;
}

/// The longest response: a registration, with its certificate.
pub const RESPONSE_MAX: usize = 1 + 65 + 1 + CRED_ID_LEN + der::CERT_MAX + der::SIG_MAX + 2;

/// A parsed command APDU.
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub struct Apdu<'a> {
    pub cla: u8,
    pub ins: u8,
    pub p1: u8,
    pub p2: u8,
    pub data: &'a [u8],
}

/// Parse a command APDU in any of the ISO 7816-4 cases, short or extended. The
/// expected-length field is accepted and not otherwise used: every response here fits.
pub fn parse(b: &[u8]) -> Result<Apdu<'_>, u16> {
    if b.len() < 4 {
        return Err(sw::WRONG_LENGTH);
    }
    let (cla, ins, p1, p2) = (b[0], b[1], b[2], b[3]);
    let rest = &b[4..];
    let data: &[u8] = match rest.len() {
        // Case 1: header only. Case 2S: header and Le.
        0 | 1 => &[],
        _ if rest[0] != 0 => {
            // Short: Lc, data, and maybe one byte of Le.
            let lc = rest[0] as usize;
            match rest.len() - 1 {
                n if n == lc || n == lc + 1 => &rest[1..1 + lc],
                _ => return Err(sw::WRONG_LENGTH),
            }
        }
        // Extended: 00, then Le alone (case 2E) or Lc, data and maybe two of Le.
        3 => &[],
        n if n >= 3 => {
            let lc = u16::from_be_bytes([rest[1], rest[2]]) as usize;
            // A zero Lc followed by a two-byte Le: no data. Not ISO's own spelling of case
            // 2E, but the one U2F hosts send for VERSION (python-fido2 among them), and a
            // U2F token answers it.
            if lc == 0 {
                return match n {
                    5 => Ok(Apdu {
                        cla,
                        ins,
                        p1,
                        p2,
                        data: &[],
                    }),
                    _ => Err(sw::WRONG_LENGTH),
                };
            }
            match n - 3 {
                m if m == lc || m == lc + 2 => &rest[3..3 + lc],
                _ => return Err(sw::WRONG_LENGTH),
            }
        }
        _ => return Err(sw::WRONG_LENGTH),
    };
    Ok(Apdu {
        cla,
        ins,
        p1,
        p2,
        data,
    })
}

fn status_only(code: u16, out: &mut [u8]) -> usize {
    out[..2].copy_from_slice(&code.to_be_bytes());
    2
}

/// Answer what needs no keys and no person: `VERSION`, and every malformed or unknown
/// command. `None` means the APDU is a well-formed `REGISTER` or `AUTHENTICATE` and must
/// go to [`handle`].
pub fn immediate(apdu: &[u8], out: &mut [u8]) -> Option<usize> {
    let a = match parse(apdu) {
        Ok(a) => a,
        Err(code) => return Some(status_only(code, out)),
    };
    if a.cla != 0 {
        return Some(status_only(sw::CLA_NOT_SUPPORTED, out));
    }
    match a.ins {
        ins::VERSION => {
            if !a.data.is_empty() {
                return Some(status_only(sw::WRONG_LENGTH, out));
            }
            out[..6].copy_from_slice(b"U2F_V2");
            out[6..8].copy_from_slice(&sw::NO_ERROR.to_be_bytes());
            Some(8)
        }
        ins::REGISTER if a.data.len() != 64 => Some(status_only(sw::WRONG_LENGTH, out)),
        ins::REGISTER => None,
        ins::AUTHENTICATE => {
            if a.data.len() < 65 || a.data.len() != 65 + a.data[64] as usize {
                return Some(status_only(sw::WRONG_LENGTH, out));
            }
            match a.p1 {
                control::ENFORCE_UP | control::CHECK_ONLY | control::DONT_ENFORCE_UP => None,
                _ => Some(status_only(sw::WRONG_DATA, out)),
            }
        }
        _ => Some(status_only(sw::INS_NOT_SUPPORTED, out)),
    }
}

/// Answer one U2F command APDU into `out` (at least [`RESPONSE_MAX`] bytes): response
/// data, then the two-byte status word. Returns the length.
pub fn handle<E: Env>(apdu: &[u8], out: &mut [u8], env: &mut E) -> usize {
    if let Some(n) = immediate(apdu, out) {
        return n;
    }
    let Ok(a) = parse(apdu) else {
        return status_only(sw::WRONG_LENGTH, out);
    };
    let r = match a.ins {
        ins::REGISTER => register(a.data, out, env),
        _ => authenticate(a.p1, a.data, out, env),
    };
    match r {
        Ok(n) => {
            out[n..n + 2].copy_from_slice(&sw::NO_ERROR.to_be_bytes());
            n + 2
        }
        Err(code) => status_only(code, out),
    }
}

fn arr32(b: &[u8]) -> &[u8; 32] {
    b.try_into().expect("length checked by `immediate`")
}

/// §4.3: `05 ‖ public key ‖ L ‖ key handle ‖ certificate ‖ signature` where the signature
/// is over `00 ‖ application ‖ challenge ‖ key handle ‖ public key`.
fn register<E: Env>(data: &[u8], out: &mut [u8], env: &mut E) -> Result<usize, u16> {
    let challenge = arr32(&data[..32]);
    let app = arr32(&data[32..64]);
    if !env.u2f_presence(true, app) {
        return Err(sw::CONDITIONS_NOT_SATISFIED);
    }
    let mut nonce = [0u8; NONCE_LEN];
    let mut serial = [0u8; 8];
    if !env.random(&mut nonce) || !env.random(&mut serial) {
        return Err(sw::CONDITIONS_NOT_SATISFIED);
    }
    env.with_master(|m, kw: &KeyWork| {
        let kh = m.credential_id(app, &nonce, kw);
        let key = m
            .signing_key(app, &nonce, kw)
            .ok_or(sw::CONDITIONS_NOT_SATISFIED)?;
        let public = key.public_sec1(kw);
        let tbs = der::tbs(&public, &serial);
        let (r, s) = key.sign(&[&tbs], kw).ok_or(sw::CONDITIONS_NOT_SATISFIED)?;
        let mut cert_sig = [0u8; der::SIG_MAX];
        let cn = der::signature(&r, &s, &mut cert_sig);
        let (r, s) = key
            .sign(&[&[0u8], app, challenge, &kh, &public], kw)
            .ok_or(sw::CONDITIONS_NOT_SATISFIED)?;
        let mut sig = [0u8; der::SIG_MAX];
        let sn = der::signature(&r, &s, &mut sig);

        let mut at = 0;
        out[at] = 0x05;
        at += 1;
        out[at..at + 65].copy_from_slice(&public);
        at += 65;
        out[at] = CRED_ID_LEN as u8;
        at += 1;
        out[at..at + CRED_ID_LEN].copy_from_slice(&kh);
        at += CRED_ID_LEN;
        at += der::certificate(&tbs, &cert_sig[..cn], &mut out[at..])
            .ok_or(sw::CONDITIONS_NOT_SATISFIED)?;
        out[at..at + sn].copy_from_slice(&sig[..sn]);
        Ok(at + sn)
    })
    .ok_or(sw::CONDITIONS_NOT_SATISFIED)?
}

/// §5.4: `flags ‖ counter ‖ signature` where the signature is over
/// `application ‖ flags ‖ counter ‖ challenge`. The counter is zero, as for CTAP2 (see
/// `ctap2::attested_auth_data`).
fn authenticate<E: Env>(p1: u8, data: &[u8], out: &mut [u8], env: &mut E) -> Result<usize, u16> {
    let challenge = arr32(&data[..32]);
    let app = arr32(&data[32..64]);
    let kh = &data[65..];
    let nonce = env
        .with_master(|m, kw| m.owns(app, kh, kw))
        .ok_or(sw::CONDITIONS_NOT_SATISFIED)?
        .ok_or(sw::WRONG_DATA)?;
    let up = match p1 {
        // "If the key handle was created by this U2F token, the token MUST respond with
        // SW_CONDITIONS_NOT_SATISFIED" -- the answer is the question's yes. §5.1 [C]
        control::CHECK_ONLY => return Err(sw::CONDITIONS_NOT_SATISFIED),
        control::ENFORCE_UP => {
            if !env.u2f_presence(false, app) {
                return Err(sw::CONDITIONS_NOT_SATISFIED);
            }
            true
        }
        _ => false,
    };
    let flags = [up as u8];
    let counter = 0u32.to_be_bytes();
    env.with_master(|m, kw| {
        let key = m
            .signing_key(app, &nonce, kw)
            .ok_or(sw::CONDITIONS_NOT_SATISFIED)?;
        let (r, s) = key
            .sign(&[app, &flags, &counter, challenge], kw)
            .ok_or(sw::CONDITIONS_NOT_SATISFIED)?;
        let mut sig = [0u8; der::SIG_MAX];
        let sn = der::signature(&r, &s, &mut sig);
        out[0] = flags[0];
        out[1..5].copy_from_slice(&counter);
        out[5..5 + sn].copy_from_slice(&sig[..sn]);
        Ok(5 + sn)
    })
    .ok_or(sw::CONDITIONS_NOT_SATISFIED)?
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ctap2::tests::{Fake, get_assertion_req, registered};
    use crate::ctap2::{self, status};
    use purecrypto::ec::ecdsa::{EcdsaPublicKey, Signature};
    use purecrypto::hash::{Digest, Sha256};

    fn ext(ins: u8, p1: u8, data: &[u8]) -> Vec<u8> {
        // Extended length, as the raw message spec writes it, with Le 00 00.
        let mut v = vec![0x00, ins, p1, 0x00, 0x00];
        v.extend_from_slice(&(data.len() as u16).to_be_bytes());
        v.extend_from_slice(data);
        v.extend_from_slice(&[0x00, 0x00]);
        v
    }

    fn short(ins: u8, p1: u8, data: &[u8]) -> Vec<u8> {
        let mut v = vec![0x00, ins, p1, 0x00, data.len() as u8];
        v.extend_from_slice(data);
        v
    }

    fn call(env: &mut Fake, apdu: &[u8]) -> Vec<u8> {
        let mut out = vec![0u8; RESPONSE_MAX];
        let n = handle(apdu, &mut out, env);
        out.truncate(n);
        out
    }

    fn sw_of(r: &[u8]) -> u16 {
        u16::from_be_bytes([r[r.len() - 2], r[r.len() - 1]])
    }

    fn der_sig(d: &[u8]) -> (Signature, usize) {
        assert_eq!(d[0], 0x30);
        let total = 2 + d[1] as usize;
        let lr = d[3] as usize;
        let r = &d[4..4 + lr];
        let ls = d[5 + lr] as usize;
        let s = &d[6 + lr..6 + lr + ls];
        let pad = |v: &[u8]| {
            let v = if v.len() == 33 { &v[1..] } else { v };
            let mut o = [0u8; 32];
            o[32 - v.len()..].copy_from_slice(v);
            o
        };
        (Signature::from_components(&pad(r), &pad(s)), total)
    }

    #[test]
    fn apdu_encodings_short_and_extended() {
        let d = [7u8; 64];
        for enc in [
            ext(1, 3, &d),
            short(1, 3, &d),
            {
                let mut s = short(1, 3, &d);
                s.push(0);
                s
            },
            {
                let mut e = ext(1, 3, &d);
                e.truncate(e.len() - 2);
                e
            },
        ] {
            let a = parse(&enc).unwrap();
            assert_eq!((a.cla, a.ins, a.p1, a.data), (0, 1, 3, &d[..]));
        }
        // Header only, header + Le, extended Le alone.
        assert_eq!(parse(&[0, 3, 0, 0]).unwrap().data, &[] as &[u8]);
        assert_eq!(parse(&[0, 3, 0, 0, 0]).unwrap().data, &[] as &[u8]);
        assert_eq!(parse(&[0, 3, 0, 0, 0, 0, 0]).unwrap().data, &[] as &[u8]);
        // Lengths that do not add up.
        for bad in [
            &[0, 1, 0][..],
            &[0, 1, 0, 0, 5, 1, 2],
            &[0, 1, 0, 0, 0, 0],
            &[0, 1, 0, 0, 0, 0, 5, 1],
            &[0, 1, 0, 0, 0, 0, 0, 1],
            &[0, 1, 0, 0, 0, 0, 0, 0],
        ] {
            assert_eq!(parse(bad), Err(sw::WRONG_LENGTH), "{bad:02x?}");
        }
    }

    #[test]
    fn version_and_the_immediate_refusals() {
        let mut out = [0u8; 16];
        let n = immediate(&[0, 3, 0, 0], &mut out).unwrap();
        assert_eq!(&out[..n], b"U2F_V2\x90\x00");
        // Extended, Lc zero and a two-byte Le: how U2F hosts ask for the version.
        let n = immediate(&ext(3, 0, &[]), &mut out).unwrap();
        assert_eq!(&out[..n], b"U2F_V2\x90\x00");
        for (apdu, want) in [
            (vec![0x80, 3, 0, 0], sw::CLA_NOT_SUPPORTED),
            (vec![0, 0x40, 0, 0], sw::INS_NOT_SUPPORTED),
            (short(1, 0, &[0; 63]), sw::WRONG_LENGTH),
            (short(2, 3, &[0; 64]), sw::WRONG_LENGTH),
            (
                short(2, 3, &{
                    let mut d = vec![0; 65];
                    d[64] = 5;
                    d
                }),
                sw::WRONG_LENGTH,
            ),
            (short(2, 0x09, &[0; 65]), sw::WRONG_DATA),
            (short(3, 0, &[1]), sw::WRONG_LENGTH),
        ] {
            let n = immediate(&apdu, &mut out).unwrap();
            assert_eq!(
                u16::from_be_bytes([out[n - 2], out[n - 1]]),
                want,
                "{apdu:02x?}"
            );
        }
        assert!(immediate(&short(1, 3, &[0; 64]), &mut out).is_none());
    }

    #[test]
    fn register_then_authenticate_with_verified_signatures_and_a_parseable_certificate() {
        let mut env = Fake::new(0);
        let challenge = [0x11u8; 32];
        let app = Sha256::digest(b"https://example.com");
        let mut d = challenge.to_vec();
        d.extend_from_slice(&app);
        let r = call(&mut env, &ext(ins::REGISTER, 3, &d));
        assert_eq!(sw_of(&r), sw::NO_ERROR);
        assert_eq!(r[0], 0x05);
        let public: [u8; 65] = r[1..66].try_into().unwrap();
        let khl = r[66] as usize;
        assert_eq!(khl, CRED_ID_LEN);
        let kh = r[67..67 + khl].to_vec();
        let cert_at = 67 + khl;
        assert_eq!(r[cert_at], 0x30);
        let cert_len = match r[cert_at + 1] {
            0x82 => 4 + u16::from_be_bytes([r[cert_at + 2], r[cert_at + 3]]) as usize,
            0x81 => 3 + r[cert_at + 2] as usize,
            n => 2 + n as usize,
        };
        let cert = &r[cert_at..cert_at + cert_len];
        let (sig, sl) = der_sig(&r[cert_at + cert_len..]);
        assert_eq!(cert_at + cert_len + sl + 2, r.len());
        let pk = EcdsaPublicKey::from_sec1(&public).unwrap();
        let mut signed = vec![0u8];
        signed.extend_from_slice(&app);
        signed.extend_from_slice(&challenge);
        signed.extend_from_slice(&kh);
        signed.extend_from_slice(&public);
        pk.verify::<Sha256>(&signed, &sig).unwrap();
        // The certificate is self-signed by the same key, and carries it.
        let tbs = &cert[4..4 + der::TBS_LEN];
        assert_eq!(&tbs[der::TBS_LEN - 65..], &public);
        let (csig, _) = der_sig(&cert[4 + der::TBS_LEN + 12 + 3..]);
        pk.verify::<Sha256>(tbs, &csig).unwrap();

        // Check-only: ours is "conditions not satisfied", anything else "wrong data".
        let mut a = challenge.to_vec();
        a.extend_from_slice(&app);
        a.push(khl as u8);
        a.extend_from_slice(&kh);
        assert_eq!(
            call(&mut env, &ext(ins::AUTHENTICATE, 0x07, &a)),
            [0x69, 0x85]
        );
        let mut bad = a.clone();
        let last = bad.len() - 1;
        bad[last] ^= 1;
        assert_eq!(
            call(&mut env, &ext(ins::AUTHENTICATE, 0x07, &bad)),
            [0x6A, 0x80]
        );

        // Enforced presence: signed, UP set, counter zero.
        let r = call(&mut env, &ext(ins::AUTHENTICATE, 0x03, &a));
        assert_eq!(sw_of(&r), sw::NO_ERROR);
        assert_eq!(&r[..5], &[1, 0, 0, 0, 0]);
        let (sig, _) = der_sig(&r[5..]);
        let mut signed = app.to_vec();
        signed.extend_from_slice(&r[..5]);
        signed.extend_from_slice(&challenge);
        pk.verify::<Sha256>(&signed, &sig).unwrap();

        // Without presence: refused until the person has pressed.
        env.u2f_ok = false;
        assert_eq!(
            call(&mut env, &ext(ins::AUTHENTICATE, 0x03, &a)),
            [0x69, 0x85]
        );
        assert_eq!(call(&mut env, &ext(ins::REGISTER, 0x03, &d)), [0x69, 0x85]);
        // Don't-enforce: signed, UP clear.
        let r = call(&mut env, &ext(ins::AUTHENTICATE, 0x08, &a));
        assert_eq!(r[0], 0);
        assert_eq!(sw_of(&r), sw::NO_ERROR);

        // No wallet: conditions not satisfied, and nobody asked.
        env.master = None;
        env.asked.clear();
        assert_eq!(
            call(&mut env, &ext(ins::AUTHENTICATE, 0x03, &a)),
            [0x69, 0x85]
        );
        assert!(env.asked.is_empty());
    }

    #[test]
    fn a_u2f_key_handle_is_a_ctap2_credential_and_back() {
        let mut env = Fake::new(0);
        let rp = "example.com";
        let app = Sha256::digest(rp.as_bytes());
        let mut d = [0x22u8; 32].to_vec();
        d.extend_from_slice(&app);
        let r = call(&mut env, &ext(ins::REGISTER, 3, &d));
        let kh = r[67..67 + CRED_ID_LEN].to_vec();
        // CTAP2 finds it.
        let mut out = vec![0u8; 1024];
        let n = ctap2::handle(
            &get_assertion_req(rp, &[&kh], Some(false)),
            &mut out,
            &mut env,
        );
        assert_eq!(out[0], status::OK, "{:02x?}", &out[..n]);
        // And a CTAP2 credential passes the U2F check.
        let mc = ctap2::tests::make_credential_req(rp, &[-7], &[], None);
        let n = ctap2::handle(&mc, &mut out, &mut env);
        let (id, ..) = registered(&out[..n]);
        let mut a = [0u8; 32].to_vec();
        a.extend_from_slice(&app);
        a.push(id.len() as u8);
        a.extend_from_slice(&id);
        assert_eq!(
            call(&mut env, &ext(ins::AUTHENTICATE, 0x07, &a)),
            [0x69, 0x85]
        );
        // Under another wallet it is not ours.
        env.master = Some(crate::keys::Master::from_parts(
            &[5; 32],
            &[5; 32],
            0,
            &KeyWork::host(),
        ));
        assert_eq!(
            call(&mut env, &ext(ins::AUTHENTICATE, 0x07, &a)),
            [0x6A, 0x80]
        );
    }
}
