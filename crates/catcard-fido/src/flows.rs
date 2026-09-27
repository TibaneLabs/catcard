//! Whole flows, as a platform drives them: set a PIN, get a token, make a passkey with
//! user verification, find it with no allow list, walk and edit the list through
//! credential management -- and the PIN's retries, blocks and power cycles.
//!
//! The platform side here is written from CTAP 2.1 §6.5.5 (the platform's steps of each
//! subcommand); `tools/fido_check.py --sim` runs the same flows through python-fido2, an
//! independent client.

use purecrypto::ec::ecdh::EcdhPrivateKey;
use purecrypto::ec::ecdsa::EcdsaPublicKey;
use purecrypto::hash::{Digest, Sha256};

use crate::cbor::{Key, Reader, Writer};
use crate::ctap2::tests::{Fake, call, registered};
use crate::ctap2::{ES256, command, flags, status};
use crate::pin::{self, MAX_RETRIES, Session, Shared, perm, sub};

/// A platform that has agreed a shared secret with the device.
struct Platform {
    protocol: u8,
    shared: Shared,
    xy: [u8; 64],
}

fn cbor(f: impl FnOnce(&mut Writer<'_>)) -> Vec<u8> {
    let mut b = vec![0u8; 2048];
    let mut w = Writer::new(&mut b);
    f(&mut w);
    let n = w.finish().unwrap();
    b.truncate(n);
    b
}

fn client_pin(env: &mut Fake, f: impl FnOnce(&mut Writer<'_>)) -> Vec<u8> {
    let mut req = vec![command::CLIENT_PIN];
    req.extend(cbor(f));
    call(env, &req)
}

/// getKeyAgreement, then the platform's half of ECDH. Source: §6.5.5.4 [C]
fn agree(env: &mut Fake, protocol: u8) -> Platform {
    let resp = client_pin(env, |w| {
        w.map(2)
            .uint(1)
            .uint(protocol as u64)
            .uint(2)
            .uint(sub::GET_KEY_AGREEMENT);
    });
    assert_eq!(resp[0], status::OK, "getKeyAgreement");
    let mut r = Reader::new(&resp[1..]);
    let mut m = r.map().unwrap();
    assert_eq!(r.key(&mut m).unwrap(), Some(Key::Int(1)));
    let device = pin::read_cose_key(&mut r).unwrap();
    r.finish().unwrap();
    let d = EcdhPrivateKey::from_bytes(&[0x42 + protocol; 32]).unwrap();
    let mut xy = [0u8; 64];
    xy.copy_from_slice(&d.public_key().to_sec1()[1..]);
    let z = d
        .diffie_hellman(&EcdsaPublicKey::from_sec1(&device).unwrap())
        .unwrap();
    Platform {
        protocol,
        shared: Shared::from_z(protocol, &z),
        xy,
    }
}

impl Platform {
    fn enc(&self, plain: &[u8]) -> Vec<u8> {
        let mut out = vec![0u8; plain.len() + 16];
        let n = self.shared.encrypt(plain, &[0x5C; 16], &mut out).unwrap();
        out.truncate(n);
        out
    }

    fn mac(&self, parts: &[&[u8]]) -> Vec<u8> {
        let (m, n) = self.shared.authenticate(parts);
        m[..n].to_vec()
    }

    fn padded(pin: &str) -> [u8; 64] {
        let mut p = [0u8; 64];
        p[..pin.len()].copy_from_slice(pin.as_bytes());
        p
    }

    fn hash(pin: &str) -> [u8; 16] {
        Sha256::digest(pin.as_bytes())[..16].try_into().unwrap()
    }

    fn set_pin(&self, env: &mut Fake, pin: &str) -> Vec<u8> {
        let enc = self.enc(&Self::padded(pin));
        let auth = self.mac(&[&enc]);
        client_pin(env, |w| {
            w.map(5)
                .uint(1)
                .uint(self.protocol as u64)
                .uint(2)
                .uint(sub::SET_PIN);
            w.uint(3);
            pin::write_cose_key(w, &self.xy);
            w.uint(4).bytes(&auth).uint(5).bytes(&enc);
        })
    }

    fn change_pin(&self, env: &mut Fake, old: &str, new: &str) -> Vec<u8> {
        let new_enc = self.enc(&Self::padded(new));
        let hash_enc = self.enc(&Self::hash(old));
        let auth = self.mac(&[&new_enc, &hash_enc]);
        client_pin(env, |w| {
            w.map(6)
                .uint(1)
                .uint(self.protocol as u64)
                .uint(2)
                .uint(sub::CHANGE_PIN);
            w.uint(3);
            pin::write_cose_key(w, &self.xy);
            w.uint(4)
                .bytes(&auth)
                .uint(5)
                .bytes(&new_enc)
                .uint(6)
                .bytes(&hash_enc);
        })
    }

    /// getPinUvAuthTokenUsingPinWithPermissions; the token, or the error.
    fn token(
        &self,
        env: &mut Fake,
        pin: &str,
        permissions: u8,
        rp: Option<&str>,
    ) -> Result<Vec<u8>, u8> {
        let hash_enc = self.enc(&Self::hash(pin));
        let resp = client_pin(env, |w| {
            w.map(5 + rp.is_some() as usize)
                .uint(1)
                .uint(self.protocol as u64)
                .uint(2)
                .uint(sub::GET_TOKEN_USING_PIN);
            w.uint(3);
            pin::write_cose_key(w, &self.xy);
            w.uint(6).bytes(&hash_enc).uint(9).uint(permissions as u64);
            if let Some(rp) = rp {
                w.uint(0x0A).text(rp);
            }
        });
        if resp[0] != status::OK {
            return Err(resp[0]);
        }
        let mut r = Reader::new(&resp[1..]);
        let mut m = r.map().unwrap();
        assert_eq!(r.key(&mut m).unwrap(), Some(Key::Int(2)));
        let ct = r.bytes().unwrap();
        let mut token = [0u8; 64];
        let n = self.shared.decrypt(ct, &mut token).unwrap();
        assert_eq!(n, 32);
        Ok(token[..32].to_vec())
    }
}

fn retries(env: &mut Fake) -> (u64, bool) {
    let resp = client_pin(env, |w| {
        w.map(2).uint(1).uint(2).uint(2).uint(sub::GET_PIN_RETRIES);
    });
    assert_eq!(resp[0], status::OK);
    let mut r = Reader::new(&resp[1..]);
    let mut m = r.map().unwrap();
    r.key(&mut m).unwrap();
    let n = r.uint().unwrap();
    r.key(&mut m).unwrap();
    (n, r.bool().unwrap())
}

/// MakeCredential with a user, `rk`, and a pinUvAuthParam made with `token`.
fn mc_req(rp: &str, user: &[u8], name: &str, rk: bool, token: Option<(&[u8], u8)>) -> Vec<u8> {
    let cdh = [0xCD; 32];
    let mut req = vec![command::MAKE_CREDENTIAL];
    req.extend(cbor(|w| {
        w.map(4 + rk as usize + 2 * token.is_some() as usize);
        w.uint(1).bytes(&cdh);
        w.uint(2).map(1).text("id").text(rp);
        w.uint(3)
            .map(3)
            .text("id")
            .bytes(user)
            .text("name")
            .text(name)
            .text("displayName")
            .text("Display");
        w.uint(4)
            .array(1)
            .map(2)
            .text("alg")
            .int(ES256)
            .text("type")
            .text("public-key");
        if rk {
            w.uint(7).map(1).text("rk").bool(true);
        }
        if let Some((t, proto)) = token {
            let (m, n) = pin::authenticate(proto, t, &[&cdh]);
            w.uint(8).bytes(&m[..n]).uint(9).uint(proto as u64);
        }
    }));
    req
}

/// GetAssertion without an allow list.
fn ga_req(rp: &str, up: Option<bool>, token: Option<(&[u8], u8)>) -> Vec<u8> {
    let cdh = [0xAB; 32];
    let mut req = vec![command::GET_ASSERTION];
    req.extend(cbor(|w| {
        w.map(2 + up.is_some() as usize + 2 * token.is_some() as usize);
        w.uint(1).text(rp).uint(2).bytes(&cdh);
        if let Some(up) = up {
            w.uint(5).map(1).text("up").bool(up);
        }
        if let Some((t, proto)) = token {
            let (m, n) = pin::authenticate(proto, t, &[&cdh]);
            w.uint(6).bytes(&m[..n]).uint(7).uint(proto as u64);
        }
    }));
    req
}

/// A GetAssertion response: (id, authData flags, user map keys, numberOfCredentials).
fn assertion(resp: &[u8]) -> (Vec<u8>, u8, Vec<String>, Option<u64>) {
    assert_eq!(resp[0], status::OK, "status {:#04x}", resp[0]);
    let mut r = Reader::new(&resp[1..]);
    let mut m = r.map().unwrap();
    let (mut id, mut fl, mut user, mut total) = (Vec::new(), 0, Vec::new(), None);
    while let Some(Key::Int(k)) = r.key(&mut m).unwrap() {
        match k {
            1 => {
                let mut d = r.map().unwrap();
                r.key(&mut d).unwrap();
                id = r.bytes().unwrap().to_vec();
                r.key(&mut d).unwrap();
                r.text().unwrap();
            }
            2 => fl = r.bytes().unwrap()[32],
            3 => {
                r.bytes().unwrap();
            }
            4 => {
                let mut u = r.map().unwrap();
                while let Some(Key::Text(k)) = r.key(&mut u).unwrap() {
                    let v = if k == "id" {
                        format!("id={}", String::from_utf8_lossy(r.bytes().unwrap()))
                    } else {
                        format!("{k}={}", r.text().unwrap())
                    };
                    user.push(v);
                }
            }
            5 => total = Some(r.uint().unwrap()),
            _ => panic!("unexpected key {k}"),
        }
    }
    r.finish().unwrap();
    (id, fl, user, total)
}

#[test]
fn set_pin_then_token_then_a_verified_passkey_found_without_an_allow_list() {
    for protocol in pin::PROTOCOLS {
        let mut env = Fake::new(0);
        let p = agree(&mut env, protocol);
        assert_eq!(p.set_pin(&mut env, "1234"), [status::OK]);
        assert_eq!(env.asked.last().unwrap(), "SetPin");
        assert_eq!(env.pin.as_ref().unwrap().retries, MAX_RETRIES);
        // Setting it again is not allowed: only a change or a reset.
        assert_eq!(p.set_pin(&mut env, "5678"), [status::NOT_ALLOWED]);
        assert_eq!(retries(&mut env), (8, false));

        // A passkey without the PIN, once one is set: the PIN is required.
        assert_eq!(
            call(
                &mut env,
                &mc_req("example.com", b"alice", "alice", true, None)
            ),
            [status::PUAT_REQUIRED]
        );
        // A second-factor registration still needs none (makeCredUvNotRqd).
        let resp = call(&mut env, &mc_req("example.com", b"x", "x", false, None));
        assert_eq!(registered(&resp).2[32] & flags::UV, 0);

        // The token, asked on the device, bound to the site.
        env.asked.clear();
        let t = p
            .token(&mut env, "1234", perm::MC | perm::GA, Some("example.com"))
            .unwrap();
        assert!(env.asked[0].starts_with("UsePin"), "{:?}", env.asked);
        let asked = env.asked.len();
        let resp = call(
            &mut env,
            &mc_req("example.com", b"alice", "alice", true, Some((&t, protocol))),
        );
        let (id, _, auth, _) = registered(&resp);
        assert_eq!(auth[32] & flags::UV, flags::UV);
        assert_eq!(
            env.asked.len(),
            asked,
            "the press for the token was the presence"
        );
        // The token is spent: a second use fails.
        assert_eq!(
            call(
                &mut env,
                &mc_req("example.com", b"bob", "bob", true, Some((&t, protocol)))
            ),
            [status::PIN_AUTH_INVALID]
        );
        // Bound to example.com: not for another site.
        let t = p
            .token(&mut env, "1234", perm::MC, Some("example.com"))
            .unwrap();
        assert_eq!(
            call(
                &mut env,
                &mc_req("other.org", b"bob", "bob", true, Some((&t, protocol)))
            ),
            [status::PIN_AUTH_INVALID]
        );
        // A GetAssertion token cannot make a credential.
        let t = p.token(&mut env, "1234", perm::GA, None).unwrap();
        assert_eq!(
            call(
                &mut env,
                &mc_req("example.com", b"bob", "bob", true, Some((&t, protocol)))
            ),
            [status::PIN_AUTH_INVALID]
        );
        // A second passkey at the same site.
        let t = p.token(&mut env, "1234", perm::MC, None).unwrap();
        let resp = call(
            &mut env,
            &mc_req("example.com", b"bob", "bob", true, Some((&t, protocol))),
        );
        let (id2, ..) = registered(&resp);

        // Discoverable sign-in with UV: the newest first, names shown (more than one),
        // then the other through GetNextAssertion.
        let t = p
            .token(&mut env, "1234", perm::GA, Some("example.com"))
            .unwrap();
        let (got, fl, user, total) = assertion(&call(
            &mut env,
            &ga_req("example.com", None, Some((&t, protocol))),
        ));
        assert_eq!(got, id2);
        assert_eq!(fl, flags::UP | flags::UV);
        assert_eq!(user, ["id=bob", "name=bob", "displayName=Display"]);
        assert_eq!(total, Some(2));
        let (got, fl, user, total) = assertion(&call(&mut env, &[command::GET_NEXT_ASSERTION]));
        assert_eq!(got, id);
        assert_eq!(fl, flags::UP | flags::UV);
        assert_eq!(user, ["id=alice", "name=alice", "displayName=Display"]);
        assert_eq!(total, None);
        assert_eq!(
            call(&mut env, &[command::GET_NEXT_ASSERTION]),
            [status::NOT_ALLOWED],
            "only two"
        );

        // Without UV: asked, ids only, never names.
        env.asked.clear();
        let (_, fl, user, total) = assertion(&call(&mut env, &ga_req("example.com", None, None)));
        assert_eq!(fl, flags::UP);
        assert_eq!(user, ["id=bob"]);
        assert_eq!(total, Some(2));
        assert!(env.asked[0].contains("known: true"));
        // Another command ends the walk.
        call(&mut env, &[command::SELECTION]);
        assert_eq!(
            call(&mut env, &[command::GET_NEXT_ASSERTION]),
            [status::NOT_ALLOWED]
        );
        // The walk also ends 30 s after its last step.
        call(&mut env, &ga_req("example.com", Some(false), None));
        env.now += pin::NEXT_MS + 1;
        assert_eq!(
            call(&mut env, &[command::GET_NEXT_ASSERTION]),
            [status::NOT_ALLOWED]
        );
        // No passkey for a site: asked, then none.
        assert_eq!(
            call(&mut env, &ga_req("nowhere.net", None, None)),
            [status::NO_CREDENTIALS]
        );
        assert!(env.notes.iter().any(|n| n.contains("found: Some(0)")));
        // Same site and user id again: replaced, not added.
        let t = p.token(&mut env, "1234", perm::MC, None).unwrap();
        registered(&call(
            &mut env,
            &mc_req(
                "example.com",
                b"alice",
                "alice2",
                true,
                Some((&t, protocol)),
            ),
        ));
        let n = env.passkeys(|p| (p.len(), false)).unwrap();
        assert_eq!(n, 2);
    }
}

use crate::ctap2::Env as _;

#[test]
fn wrong_pins_count_down_block_after_three_and_for_good_at_zero() {
    let mut env = Fake::new(0);
    let p = agree(&mut env, 2);
    assert_eq!(p.set_pin(&mut env, "correct horse"), [status::OK]);
    env.pin_writes.clear();

    // A wrong PIN: retries written down before the answer, then PIN_INVALID -- and the
    // key agreement is regenerated, so the platform must agree again.
    assert_eq!(
        p.token(&mut env, "wrong", perm::GA, None),
        Err(status::PIN_INVALID)
    );
    assert_eq!(env.pin_writes, [7]);
    assert_eq!(retries(&mut env), (7, false));
    assert!(p.token(&mut env, "correct horse", perm::GA, None).is_err());
    let p = agree(&mut env, 2);
    assert_eq!(
        p.token(&mut env, "wrong", perm::GA, None),
        Err(status::PIN_INVALID)
    );
    let p = agree(&mut env, 2);
    // The third in a row: blocked until a power cycle.
    assert_eq!(
        p.token(&mut env, "wrong", perm::GA, None),
        Err(status::PIN_AUTH_BLOCKED)
    );
    let p = agree(&mut env, 2);
    assert_eq!(retries(&mut env), (5, true));
    env.asked.clear();
    assert_eq!(
        p.token(&mut env, "correct horse", perm::GA, None),
        Err(status::PIN_AUTH_BLOCKED)
    );
    assert!(env.asked.is_empty(), "no retry spent, nobody asked");
    assert_eq!(retries(&mut env), (5, true));

    // A power cycle: a new session. The retries stayed spent.
    env.session = Some(Session::new());
    let p = agree(&mut env, 2);
    assert_eq!(retries(&mut env), (5, false));
    // A right PIN resets them.
    env.pin_writes.clear();
    assert!(p.token(&mut env, "correct horse", perm::GA, None).is_ok());
    assert_eq!(env.pin_writes, [4, 8], "spent first, restored after");
    assert_eq!(retries(&mut env), (8, false));

    // Down to zero across power cycles: blocked for good.
    for i in 0..8 {
        if i % 3 == 0 {
            env.session = Some(Session::new());
        }
        let p = agree(&mut env, 1);
        let e = p.token(&mut env, "nope", perm::GA, None).unwrap_err();
        if i == 7 {
            assert_eq!(e, status::PIN_BLOCKED);
        }
    }
    assert_eq!(env.pin.as_ref().unwrap().retries, 0);
    env.session = Some(Session::new());
    let p = agree(&mut env, 1);
    assert_eq!(
        p.token(&mut env, "correct horse", perm::GA, None),
        Err(status::PIN_BLOCKED)
    );
    assert_eq!(
        p.change_pin(&mut env, "correct horse", "new pin"),
        [status::PIN_BLOCKED]
    );
}

#[test]
fn a_retry_that_cannot_be_written_is_not_tried() {
    let mut env = Fake::new(0);
    let p = agree(&mut env, 2);
    assert_eq!(p.set_pin(&mut env, "1234"), [status::OK]);
    env.pin_save_fails = true;
    assert_eq!(
        p.token(&mut env, "1234", perm::GA, None),
        Err(status::OTHER),
        "even the right PIN is not judged without the retry written"
    );
    assert_eq!(env.pin.as_ref().unwrap().retries, 8);
}

#[test]
fn change_pin_and_the_pin_rules() {
    let mut env = Fake::new(0);
    let p = agree(&mut env, 1);
    // Too short (code points, not bytes), too long, or not UTF-8.
    assert_eq!(p.set_pin(&mut env, "123"), [status::PIN_POLICY_VIOLATION]);
    assert_eq!(p.set_pin(&mut env, "ééé"), [status::PIN_POLICY_VIOLATION]);
    let long = "x".repeat(64);
    let enc = p.enc(long.as_bytes());
    let auth = p.mac(&[&enc]);
    let resp = client_pin(&mut env, |w| {
        w.map(5).uint(1).uint(1).uint(2).uint(sub::SET_PIN);
        w.uint(3);
        pin::write_cose_key(w, &p.xy);
        w.uint(4).bytes(&auth).uint(5).bytes(&enc);
    });
    assert_eq!(resp, [status::PIN_POLICY_VIOLATION]);
    // A bad MAC.
    let enc = p.enc(&Platform::padded("1234"));
    let resp = client_pin(&mut env, |w| {
        w.map(5).uint(1).uint(1).uint(2).uint(sub::SET_PIN);
        w.uint(3);
        pin::write_cose_key(w, &p.xy);
        w.uint(4).bytes(&[0; 16]).uint(5).bytes(&enc);
    });
    assert_eq!(resp, [status::PIN_AUTH_INVALID]);
    assert!(env.pin.is_none());
    // Refused on the device.
    env.answer = crate::ctap2::Presence::Denied;
    assert_eq!(p.set_pin(&mut env, "ééééé"), [status::OPERATION_DENIED]);
    assert!(env.pin.is_none());
    env.answer = crate::ctap2::Presence::Allowed;
    assert_eq!(p.set_pin(&mut env, "ééééé"), [status::OK]);

    // Change: the old one must be right, asked on the device first.
    env.asked.clear();
    assert_eq!(
        p.change_pin(&mut env, "wrong", "9999"),
        [status::PIN_INVALID]
    );
    assert_eq!(env.asked, ["ChangePin"]);
    let p = agree(&mut env, 1);
    let t = p.token(&mut env, "ééééé", perm::GA, None).unwrap();
    assert_eq!(p.change_pin(&mut env, "ééééé", "9999"), [status::OK]);
    assert_eq!(env.pin.as_ref().unwrap().retries, 8);
    // Every token is void after a change.
    assert_eq!(
        call(&mut env, &ga_req("a.com", Some(false), Some((&t, 1)))),
        [status::PIN_AUTH_INVALID]
    );
    assert!(p.token(&mut env, "9999", perm::GA, None).is_ok());
    // A new PIN that breaks the rules leaves the old one, retries restored.
    assert_eq!(
        p.change_pin(&mut env, "9999", "12"),
        [status::PIN_POLICY_VIOLATION]
    );
    assert!(p.token(&mut env, "9999", perm::GA, None).is_ok());
}

#[test]
fn token_requests_are_checked_before_anything_is_spent() {
    let mut env = Fake::new(0);
    let p = agree(&mut env, 2);
    // No PIN yet.
    assert_eq!(
        p.token(&mut env, "1234", perm::GA, None),
        Err(status::PIN_NOT_SET)
    );
    assert_eq!(p.set_pin(&mut env, "1234"), [status::OK]);
    // Permissions: zero, unsupported, and cm on a board without passkeys.
    assert_eq!(
        p.token(&mut env, "1234", 0, None),
        Err(status::INVALID_PARAMETER)
    );
    assert_eq!(
        p.token(&mut env, "1234", perm::LBW, None),
        Err(status::UNAUTHORIZED_PERMISSION)
    );
    env.rk = false;
    assert_eq!(
        p.token(&mut env, "1234", perm::CM, None),
        Err(status::UNAUTHORIZED_PERMISSION)
    );
    env.rk = true;
    assert_eq!(env.pin.as_ref().unwrap().retries, 8, "nothing spent");
    // A protocol this device does not speak, and a missing one.
    let resp = client_pin(&mut env, |w| {
        w.map(2)
            .uint(1)
            .uint(3)
            .uint(2)
            .uint(sub::GET_KEY_AGREEMENT);
    });
    assert_eq!(resp, [status::INVALID_PARAMETER]);
    let resp = client_pin(&mut env, |w| {
        w.map(1).uint(2).uint(sub::GET_KEY_AGREEMENT);
    });
    assert_eq!(resp, [status::MISSING_PARAMETER]);
    // Built-in UV subcommands: there is none.
    let resp = client_pin(&mut env, |w| {
        w.map(2).uint(1).uint(2).uint(2).uint(sub::GET_UV_RETRIES);
    });
    assert_eq!(resp, [status::INVALID_SUBCOMMAND]);
    // Refused on the device: nothing spent.
    env.answer = crate::ctap2::Presence::Denied;
    assert_eq!(
        p.token(&mut env, "1234", perm::GA, None),
        Err(status::OPERATION_DENIED)
    );
    assert_eq!(env.pin.as_ref().unwrap().retries, 8);
    env.answer = crate::ctap2::Presence::Allowed;
    // A token unused for 30 s lapses.
    let t = p.token(&mut env, "1234", perm::GA, None).unwrap();
    env.now += pin::INITIAL_USAGE_MS + 1;
    assert_eq!(
        call(&mut env, &ga_req("a.com", Some(false), Some((&t, 2)))),
        [status::PIN_AUTH_INVALID]
    );
    // The legacy getPinToken: mc and ga, and no permissions parameter allowed.
    let hash_enc = p.enc(&Platform::hash("1234"));
    let resp = client_pin(&mut env, |w| {
        w.map(4).uint(1).uint(2).uint(2).uint(sub::GET_PIN_TOKEN);
        w.uint(3);
        pin::write_cose_key(w, &p.xy);
        w.uint(6).bytes(&hash_enc);
    });
    assert_eq!(resp[0], status::OK);
    // The touch probe with a PIN set.
    let mut req = mc_req("a.com", b"u", "u", false, None);
    let _ = &mut req;
    let mut probe = vec![command::GET_ASSERTION];
    probe.extend(cbor(|w| {
        w.map(4)
            .uint(1)
            .text("a.com")
            .uint(2)
            .bytes(&[0; 32])
            .uint(6)
            .bytes(&[])
            .uint(7)
            .uint(2);
    }));
    assert_eq!(call(&mut env, &probe), [status::PIN_INVALID]);
}

/// A credential management request, MAC'd with `token`.
fn cm(env: &mut Fake, token: &[u8], proto: u8, subc: u8, params: Option<Vec<u8>>) -> Vec<u8> {
    let mut msg = vec![subc];
    if let Some(p) = &params {
        msg.extend_from_slice(p);
    }
    let (m, n) = pin::authenticate(proto, token, &[&msg]);
    let mut req = vec![command::CREDENTIAL_MANAGEMENT];
    req.extend(cbor(|w| {
        w.map(3 + params.is_some() as usize)
            .uint(1)
            .uint(subc as u64);
        if let Some(p) = &params {
            w.uint(2).raw(p);
        }
        w.uint(3).uint(proto as u64).uint(4).bytes(&m[..n]);
    }));
    call(env, &req)
}

fn map_keys(resp: &[u8]) -> Vec<(i64, String)> {
    assert_eq!(resp[0], status::OK, "status {:#04x}", resp[0]);
    let mut r = Reader::new(&resp[1..]);
    let mut m = r.map().unwrap();
    let mut v = Vec::new();
    while let Some(Key::Int(k)) = r.key(&mut m).unwrap() {
        let s = match r.peek_major().unwrap() {
            0 => r.uint().unwrap().to_string(),
            2 => format!("{} bytes", r.bytes().unwrap().len()),
            _ => {
                let at = r.position();
                r.skip(4).unwrap();
                format!("item@{at}")
            }
        };
        v.push((k, s));
    }
    v
}

#[test]
fn credential_management_lists_renames_and_deletes() {
    let mut env = Fake::new(0);
    let p = agree(&mut env, 2);
    assert_eq!(p.set_pin(&mut env, "1234"), [status::OK]);
    let mut ids = Vec::new();
    for (rp, user) in [("a.com", "u1"), ("b.com", "u2"), ("a.com", "u3")] {
        let t = p.token(&mut env, "1234", perm::MC, None).unwrap();
        let resp = call(
            &mut env,
            &mc_req(rp, user.as_bytes(), user, true, Some((&t, 2))),
        );
        ids.push(registered(&resp).0);
    }
    // No cm permission, no token, a site-bound token: refused.
    let t = p.token(&mut env, "1234", perm::GA, None).unwrap();
    assert_eq!(cm(&mut env, &t, 2, 1, None), [status::PIN_AUTH_INVALID]);
    let mut req = vec![command::CREDENTIAL_MANAGEMENT];
    req.extend(cbor(|w| {
        w.map(1).uint(1).uint(1);
    }));
    assert_eq!(call(&mut env, &req), [status::PUAT_REQUIRED]);
    let t = p.token(&mut env, "1234", perm::CM, Some("a.com")).unwrap();
    assert_eq!(cm(&mut env, &t, 2, 1, None), [status::PIN_AUTH_INVALID]);

    let t = p.token(&mut env, "1234", perm::CM, None).unwrap();
    // Metadata.
    let meta = map_keys(&cm(&mut env, &t, 2, 1, None));
    assert_eq!(meta, [(1, "3".into()), (2, "47".into())]);
    // Sites: two, in the order they first appeared.
    let rps = map_keys(&cm(&mut env, &t, 2, 2, None));
    assert_eq!(rps.iter().map(|x| x.0).collect::<Vec<_>>(), [3, 4, 5]);
    assert_eq!(rps[2].1, "2");
    let mut req = vec![command::CREDENTIAL_MANAGEMENT];
    req.extend(cbor(|w| {
        w.map(1).uint(1).uint(3);
    }));
    let next = map_keys(&call(&mut env, &req));
    assert_eq!(next.iter().map(|x| x.0).collect::<Vec<_>>(), [3, 4]);
    assert_eq!(
        call(&mut env, &req),
        [status::NOT_ALLOWED],
        "only two sites"
    );

    // Credentials for a.com: two, newest first, each with its public key.
    let h: [u8; 32] = Sha256::digest(b"a.com");
    let params = cbor(|w| {
        w.map(1).uint(1).bytes(&h);
    });
    let creds = map_keys(&cm(&mut env, &t, 2, 4, Some(params)));
    assert_eq!(
        creds.iter().map(|x| x.0).collect::<Vec<_>>(),
        [6, 7, 8, 9, 10]
    );
    assert_eq!(creds[3].1, "2");
    let mut req = vec![command::CREDENTIAL_MANAGEMENT];
    req.extend(cbor(|w| {
        w.map(1).uint(1).uint(5);
    }));
    let next = map_keys(&call(&mut env, &req));
    assert_eq!(next.iter().map(|x| x.0).collect::<Vec<_>>(), [6, 7, 8, 10]);

    // Rename u1: the user id must match; empty removes the display name.
    let params = cbor(|w| {
        w.map(2);
        w.uint(2)
            .map(2)
            .text("id")
            .bytes(&ids[0])
            .text("type")
            .text("public-key");
        w.uint(3)
            .map(2)
            .text("id")
            .bytes(b"u1")
            .text("name")
            .text("renamed");
    });
    assert_eq!(cm(&mut env, &t, 2, 7, Some(params)), [status::OK]);
    let r = env.passkeys(|p| (p.get(0).unwrap(), false)).unwrap();
    assert_eq!(r.name.as_str(), "renamed");
    assert!(r.display_name.is_empty());
    let params = cbor(|w| {
        w.map(2);
        w.uint(2)
            .map(2)
            .text("id")
            .bytes(&ids[0])
            .text("type")
            .text("public-key");
        w.uint(3).map(1).text("id").bytes(b"someone else");
    });
    assert_eq!(
        cm(&mut env, &t, 2, 7, Some(params)),
        [status::INVALID_PARAMETER]
    );

    // Delete u2 (b.com); then a stranger's id is not found.
    let params = cbor(|w| {
        w.map(1)
            .uint(2)
            .map(2)
            .text("id")
            .bytes(&ids[1])
            .text("type")
            .text("public-key");
    });
    assert_eq!(cm(&mut env, &t, 2, 6, Some(params.clone())), [status::OK]);
    assert_eq!(
        cm(&mut env, &t, 2, 6, Some(params)),
        [status::NO_CREDENTIALS]
    );
    let meta = map_keys(&cm(&mut env, &t, 2, 1, None));
    assert_eq!(meta, [(1, "2".into()), (2, "48".into())]);
    // The deleted passkey is no longer found without an allow list.
    assert_eq!(
        call(&mut env, &ga_req("b.com", Some(false), None)),
        [status::NO_CREDENTIALS]
    );
    // A tampered file opens as nothing: refused, never misread.
    let f = env.file.as_mut().unwrap();
    let last = f.len() - 1;
    f[last] ^= 1;
    assert_eq!(cm(&mut env, &t, 2, 1, None), [status::OTHER]);
}
