//! `authenticatorCredentialManagement`: what a browser's "manage security key" screen
//! uses to list, rename and delete passkeys.
//!
//! Every request carries a pinUvAuthToken with the `cm` permission, so the person has
//! typed the PIN and pressed the device to get it ([`crate::pin`]); nothing here asks
//! again. The enumerations are stateful: `...GetNext...` follows its `...Begin` with no
//! other command between, within [`crate::pin::NEXT_MS`].
//!
//! Source: FIDO CTAP 2.1 (Proposed Standard, 2021-06-15, errata 2022-06-21) §6.8 [C].

use crate::cbor::{self, Key, Reader, Writer};
use crate::ctap2::{
    Env, Note, R, c, descriptor, id_nonce, status, user_entity, write_cose_es256, write_user,
};
use crate::passkeys::Record;
use crate::pin::{Cursor, NEXT_MS, Session, check_protocol, perm};

/// Subcommands. Source: §6.8 [C]
pub mod sub {
    pub const GET_CREDS_METADATA: u64 = 0x01;
    pub const ENUMERATE_RPS_BEGIN: u64 = 0x02;
    pub const ENUMERATE_RPS_NEXT: u64 = 0x03;
    pub const ENUMERATE_CREDENTIALS_BEGIN: u64 = 0x04;
    pub const ENUMERATE_CREDENTIALS_NEXT: u64 = 0x05;
    pub const DELETE_CREDENTIAL: u64 = 0x06;
    pub const UPDATE_USER_INFORMATION: u64 = 0x07;
}

/// The credProtect level reported for every passkey: `userVerificationOptional`, the
/// default, since the extension is not supported. Source: CTAP 2.1 §12.1 [C]
const CRED_PROTECT_DEFAULT: u64 = 1;

struct Request<'a> {
    sub: u64,
    /// The subCommandParams map as it was sent: the MAC covers these bytes.
    params_raw: &'a [u8],
    rp_id_hash: Option<&'a [u8]>,
    credential: Option<&'a [u8]>,
    user: Option<crate::ctap2::User<'a>>,
    protocol: Option<u64>,
    auth: Option<&'a [u8]>,
}

fn parse(body: &[u8]) -> R<Request<'_>> {
    let mut r = Reader::new(body);
    let mut m = c(r.map())?;
    let mut q = Request {
        sub: 0,
        params_raw: &[],
        rp_id_hash: None,
        credential: None,
        user: None,
        protocol: None,
        auth: None,
    };
    let mut sub = None;
    while let Some(k) = c(r.key(&mut m))? {
        match k {
            Key::Int(0x01) => sub = Some(c(r.uint())?),
            Key::Int(0x02) => {
                let start = r.position();
                let mut p = c(r.map())?;
                while let Some(k) = c(r.key(&mut p))? {
                    match k {
                        Key::Int(0x01) => q.rp_id_hash = Some(c(r.bytes())?),
                        Key::Int(0x02) => {
                            let (id, _) =
                                c(descriptor(&mut r))?.ok_or(status::MISSING_PARAMETER)?;
                            q.credential = Some(id);
                        }
                        Key::Int(0x03) => q.user = Some(user_entity(&mut r, cbor::MAX_DEPTH - 3)?),
                        _ => c(r.skip(cbor::MAX_DEPTH - 2))?,
                    }
                }
                q.params_raw = &body[start..r.position()];
            }
            Key::Int(0x03) => q.protocol = Some(c(r.uint())?),
            Key::Int(0x04) => q.auth = Some(c(r.bytes())?),
            _ => c(r.skip(cbor::MAX_DEPTH - 1))?,
        }
    }
    c(r.finish())?;
    q.sub = sub.ok_or(status::MISSING_PARAMETER)?;
    Ok(q)
}

/// Answer one request into `out` (the response map); its length.
#[inline(never)]
pub fn handle<'a, E: Env>(
    body: &'a [u8],
    out: &mut [u8],
    s: &mut Session,
    env: &mut E,
    note: &mut Note<'a>,
) -> R<usize> {
    let q = parse(body)?;
    note.sub = Some(q.sub);
    let now = env.now_ms();
    match q.sub {
        sub::ENUMERATE_RPS_NEXT => return next_rp(out, s, env, now),
        sub::ENUMERATE_CREDENTIALS_NEXT => return next_credential(out, s, env, now),
        _ => s.cursor = Cursor::None,
    }
    if !matches!(q.sub, 0x01..=0x07) {
        return Err(status::INVALID_SUBCOMMAND);
    }
    // Every other subcommand: the token, with `cm`. Source: §6.8.2-§6.8.6 [C]
    let auth = q.auth.ok_or(status::PUAT_REQUIRED)?;
    let needs = match q.sub {
        sub::ENUMERATE_CREDENTIALS_BEGIN => q.rp_id_hash.is_some(),
        sub::DELETE_CREDENTIAL => q.credential.is_some(),
        sub::UPDATE_USER_INFORMATION => q.credential.is_some() && q.user.is_some(),
        _ => true,
    };
    if !needs {
        return Err(status::MISSING_PARAMETER);
    }
    let protocol = check_protocol(q.protocol)?;
    let sub_byte = [q.sub as u8];
    if !s.verify_token(protocol, &[&sub_byte, q.params_raw], auth, now) {
        return Err(status::PIN_AUTH_INVALID);
    }
    if !s.has_permission(perm::CM) {
        return Err(status::PIN_AUTH_INVALID);
    }
    match q.sub {
        sub::GET_CREDS_METADATA => {
            no_rp_bound(s)?;
            let (n, left) = env.passkeys(|p| ((p.len(), p.remaining()), false))?;
            let mut w = Writer::new(out);
            w.map(2)
                .uint(0x01)
                .uint(n as u64)
                .uint(0x02)
                .uint(left as u64);
            w.finish().map_err(|_| status::OTHER)
        }
        sub::ENUMERATE_RPS_BEGIN => {
            no_rp_bound(s)?;
            let (rec, total) = env.passkeys(|p| {
                let total = p.sites();
                ((p.site(0).and_then(|i| p.get(i)), total), false)
            })?;
            let rec = rec.ok_or(status::NO_CREDENTIALS)?;
            let n = write_rp(out, &rec, Some(total))?;
            if total > 1 {
                s.cursor = Cursor::Rps {
                    next: 1,
                    total: total as u8,
                    since: now,
                };
            }
            Ok(n)
        }
        sub::ENUMERATE_CREDENTIALS_BEGIN => {
            let rp: [u8; 32] = q
                .rp_id_hash
                .unwrap_or(&[])
                .try_into()
                .map_err(|_| status::INVALID_PARAMETER)?;
            if s.token_rp().is_some_and(|t| *t != rp) {
                return Err(status::PIN_AUTH_INVALID);
            }
            let (rec, total) = env.passkeys(|p| {
                (
                    (
                        p.newest_for(&rp, 0).and_then(|i| p.get(i)),
                        p.count_for(&rp),
                    ),
                    false,
                )
            })?;
            let rec = rec.ok_or(status::NO_CREDENTIALS)?;
            let n = write_credential(out, env, &rec, Some(total))?;
            if total > 1 {
                s.cursor = Cursor::Creds {
                    rp,
                    next: 1,
                    total: total as u8,
                    since: now,
                };
            }
            Ok(n)
        }
        sub::DELETE_CREDENTIAL | sub::UPDATE_USER_INFORMATION => {
            let id = q.credential.unwrap_or(&[]);
            let (index, rec) = find(env, id)?;
            if s.token_rp().is_some_and(|t| *t != rec.rp_id_hash) {
                return Err(status::PIN_AUTH_INVALID);
            }
            if q.sub == sub::DELETE_CREDENTIAL {
                env.passkeys(|p| {
                    p.remove(index);
                    ((), true)
                })?;
            } else {
                let Some((uid, name, display)) = q.user else {
                    return Err(status::MISSING_PARAMETER);
                };
                if uid != rec.user_id.as_bytes() {
                    return Err(status::INVALID_PARAMETER);
                }
                let mut updated = rec.clone();
                updated.set_names(name, display);
                env.passkeys(|p| {
                    p.set(index, &updated);
                    ((), true)
                })?;
            }
            Ok(0)
        }
        _ => Err(status::INVALID_SUBCOMMAND),
    }
}

/// Metadata and the RP enumeration need a token not bound to a site.
fn no_rp_bound(s: &Session) -> R<()> {
    match s.token_rp() {
        Some(_) => Err(status::PIN_AUTH_INVALID),
        None => Ok(()),
    }
}

/// The passkey a credential id names: its place in the list, and the record. The id's
/// MAC is checked, so only this wallet's ids for the stored site match.
fn find<E: Env>(env: &mut E, id: &[u8]) -> R<(usize, Record)> {
    let nonce = id_nonce(id).ok_or(status::NO_CREDENTIALS)?;
    let hit = env.passkeys(|p| {
        let hit = (0..p.len()).find_map(|i| p.get(i).filter(|r| r.nonce == nonce).map(|r| (i, r)));
        (hit, false)
    })?;
    let (i, rec) = hit.ok_or(status::NO_CREDENTIALS)?;
    let ours = env
        .with_master(|m, kw| m.owns(&rec.rp_id_hash, id, kw).is_some())
        .ok_or(status::OPERATION_DENIED)?;
    if !ours {
        return Err(status::NO_CREDENTIALS);
    }
    Ok((i, rec))
}

/// `{3: rp, 4: rpIDHash, 5: totalRPs}`.
fn write_rp(out: &mut [u8], rec: &Record, total: Option<usize>) -> R<usize> {
    let mut w = Writer::new(out);
    w.map(2 + total.is_some() as usize)
        .uint(0x03)
        .map(1)
        .text("id")
        .text(rec.rp_id.as_str())
        .uint(0x04)
        .bytes(&rec.rp_id_hash);
    if let Some(t) = total {
        w.uint(0x05).uint(t as u64);
    }
    w.finish().map_err(|_| status::OTHER)
}

/// `{6: user, 7: credentialID, 8: publicKey, 9: totalCredentials, 10: credProtect}`.
fn write_credential<E: Env>(
    out: &mut [u8],
    env: &mut E,
    rec: &Record,
    total: Option<usize>,
) -> R<usize> {
    let (id, public) = env
        .with_master(|m, kw| {
            let id = m.credential_id(&rec.rp_id_hash, &rec.nonce, kw);
            let key = m.signing_key(&rec.rp_id_hash, &rec.nonce, kw)?;
            Some((id, key.public_sec1(kw)))
        })
        .ok_or(status::OPERATION_DENIED)?
        .ok_or(status::OTHER)?;
    let mut w = Writer::new(out);
    w.map(4 + total.is_some() as usize).uint(0x06);
    write_user(&mut w, rec, true);
    w.uint(0x07)
        .map(2)
        .text("id")
        .bytes(&id)
        .text("type")
        .text("public-key")
        .uint(0x08);
    write_cose_es256(&mut w, &public);
    if let Some(t) = total {
        w.uint(0x09).uint(t as u64);
    }
    w.uint(0x0A).uint(CRED_PROTECT_DEFAULT);
    w.finish().map_err(|_| status::OTHER)
}

fn next_rp<E: Env>(out: &mut [u8], s: &mut Session, env: &mut E, now: u32) -> R<usize> {
    let Cursor::Rps { next, total, since } = s.cursor else {
        return Err(status::NOT_ALLOWED);
    };
    if next >= total || now.wrapping_sub(since) > NEXT_MS {
        s.cursor = Cursor::None;
        return Err(status::NOT_ALLOWED);
    }
    let rec = env
        .passkeys(|p| (p.site(next as usize).and_then(|i| p.get(i)), false))?
        .ok_or(status::NOT_ALLOWED)?;
    s.cursor = Cursor::Rps {
        next: next + 1,
        total,
        since: now,
    };
    write_rp(out, &rec, None)
}

fn next_credential<E: Env>(out: &mut [u8], s: &mut Session, env: &mut E, now: u32) -> R<usize> {
    let Cursor::Creds {
        rp,
        next,
        total,
        since,
    } = s.cursor
    else {
        return Err(status::NOT_ALLOWED);
    };
    if next >= total || now.wrapping_sub(since) > NEXT_MS {
        s.cursor = Cursor::None;
        return Err(status::NOT_ALLOWED);
    }
    let rec = env
        .passkeys(|p| {
            (
                p.newest_for(&rp, next as usize).and_then(|i| p.get(i)),
                false,
            )
        })?
        .ok_or(status::NOT_ALLOWED)?;
    s.cursor = Cursor::Creds {
        rp,
        next: next + 1,
        total,
        since: now,
    };
    write_credential(out, env, &rec, None)
}
