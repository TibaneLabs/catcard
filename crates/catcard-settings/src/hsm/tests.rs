//! The policy engine, rule by rule: each key's bounds, each refusal the reference lists,
//! the rules' matching and the velocity clock.

use super::*;

/// A device with users alice, bob and carol, one wallet called `desk-multisig`, two
/// wallets called `twice`, and addresses that start `bc1q` or `1` or `3`.
struct Dev;

impl Env for Dev {
    fn user_exists(&self, name: &str) -> bool {
        ["alice", "bob", "carol"].contains(&name)
    }
    fn wallets_named(&self, name: &str) -> usize {
        match name {
            "desk-multisig" => 1,
            "twice" => 2,
            _ => 0,
        }
    }
    fn address_ok(&self, addr: &str) -> bool {
        (addr.starts_with("bc1q") || addr.starts_with('1') || addr.starts_with('3'))
            && addr.len() >= 26
    }
}

const A1: &str = "bc1qexampleplaceholderaddress00000000000000";
const A2: &str = "bc1qanotherplaceholderaddress0000000000000";
const A3: &str = "3PlaceholderP2shAddress0000000000";

/// Loaded from a copy that lives for the test, so a `format!` can be passed straight in.
fn load(text: &str) -> Result<Policy<'static>, Refusal<'static>> {
    let t: &'static str = Box::leak(text.to_string().into_boxed_str());
    Policy::load(t, &Dev)
}

fn problem(text: &str) -> Problem {
    load(text).expect_err("should be refused").problem
}

/// The reference's worked example, minus the Storage Locker and must_log this firmware
/// refuses.
const EXAMPLE: &str = r#"{
  "notes": "example desk policy",
  "period": 1440,
  "warnings_ok": false,
  "priv_over_ux": false,
  "boot_to_hsm": "123456",
  "msg_paths": ["m/84h/0h/0h/*"],
  "share_xpubs": ["m/84h/0h/0h"],
  "share_addrs": ["m/84h/0h/0h/0/*", "p2sh"],
  "rules": [
    {
      "max_amount": 250000,
      "per_period": 2000000,
      "wallet": "1",
      "whitelist": ["bc1qexampleplaceholderaddress00000000000000"],
      "whitelist_opts": { "mode": "BASIC", "allow_zeroval_outs": false },
      "local_conf": true
    },
    {
      "max_amount": 100000000,
      "wallet": "desk-multisig",
      "users": ["alice", "bob", "carol"],
      "min_users": 2,
      "min_pct_self_transfer": 0.0,
      "patterns": ["EQ_NUM_INS_OUTS"]
    }
  ]
}"#;

#[test]
fn the_worked_example_loads() {
    let p = load(EXAMPLE).unwrap();
    assert_eq!(p.rules.len(), 2);
    assert_eq!(p.period, Some(1440));
    assert!(p.boots_to_hsm());
    assert!(p.boot_code_typeable());
    assert!(p.uses_local_conf());
    assert_eq!(p.rules[0].max_amount, Some(250_000));
    assert_eq!(p.rules[1].min_users, Some(2));
    assert_eq!(p.rules[1].patterns, 1);
    let mut b = [0u8; 4 * WALLET_LEN.1];
    assert_eq!(
        p.rules[1].wallet(&mut b),
        WalletRule::Named("desk-multisig")
    );
}

#[test]
fn the_canonical_form_reloads_to_the_same_form() {
    let p = load(EXAMPLE).unwrap();
    let mut a = [0u8; 4096];
    let n = p.write(&mut a).unwrap();
    let text = core::str::from_utf8(&a[..n]).unwrap();
    let again = Policy::load(text, &Dev).unwrap();
    let mut b = [0u8; 4096];
    let m = again.write(&mut b).unwrap();
    assert_eq!(&a[..n], &b[..m]);
    assert_eq!(Policy::hash(&a[..n]), Policy::hash(&b[..m]));
    // Spelling of paths is normalised.
    assert!(text.contains("\"m/84h/0h/0h/*\""));
    // A trusted reload does not need the device's users or wallets.
    assert!(Policy::load(text, &Trusted).is_ok());
}

#[test]
fn an_empty_object_is_a_policy_that_signs_nothing() {
    let p = load("{}").unwrap();
    assert!(p.rules.is_empty());
    let mut rt = Runtime::new();
    let j = Judge::new(&p);
    let f = facts(1000);
    let mut why = Reasons::new();
    assert_eq!(j.verdict(&f, &mut rt, 0, &mut why), None);
    assert_eq!(why.as_str(), "no txn signing allowed");
}

#[test]
fn not_an_object_or_not_json_is_refused() {
    assert_eq!(problem("[]"), Problem::NotObject);
    assert_eq!(problem("{"), Problem::NotJson);
    assert_eq!(problem("hello"), Problem::NotObject);
}

#[test]
fn unknown_keys_fail_the_whole_policy() {
    let r = load(r#"{"rules": [], "colour": "red"}"#).unwrap_err();
    assert_eq!(r.problem, Problem::UnknownKey);
    assert_eq!(r.key, "colour");
    let r = load(r#"{"rules": [{"max_amount": 1, "speed": 2}]}"#).unwrap_err();
    assert_eq!(
        (r.problem, r.key, r.rule),
        (Problem::UnknownKey, "speed", Some(1))
    );
    let r = load(r#"{"rules": [{"whitelist": ["bc1qexampleplaceholderaddress00000000000000"], "whitelist_opts": {"mode": "BASIC", "x": 1}}]}"#)
        .unwrap_err();
    assert_eq!((r.problem, r.key), (Problem::UnknownKey, "x"));
}

#[test]
fn duplicate_keys_are_refused() {
    assert_eq!(
        problem(r#"{"period": 1, "period": 2}"#),
        Problem::DuplicateKey
    );
}

#[test]
fn period_bounds() {
    assert!(load(r#"{"period": 1}"#).is_ok());
    assert!(load(r#"{"period": 4320}"#).is_ok());
    assert_eq!(problem(r#"{"period": 0}"#), Problem::OutOfRange);
    assert_eq!(problem(r#"{"period": 4321}"#), Problem::OutOfRange);
    assert_eq!(problem(r#"{"period": -5}"#), Problem::OutOfRange);
    assert_eq!(problem(r#"{"period": 1.5}"#), Problem::NotInteger);
    assert_eq!(problem(r#"{"period": "60"}"#), Problem::NotInteger);
    // null is absent.
    assert_eq!(load(r#"{"period": null}"#).unwrap().period, None);
}

#[test]
fn velocity_needs_a_period() {
    let r = load(r#"{"rules": [{"max_amount": 5}, {"per_period": 10}]}"#).unwrap_err();
    assert_eq!((r.problem, r.rule), (Problem::NeedsPeriod, Some(2)));
    assert!(load(r#"{"period": 60, "rules": [{"per_period": 10}]}"#).is_ok());
}

#[test]
fn amounts_are_bounded_by_all_the_bitcoin() {
    assert!(load(r#"{"rules": [{"max_amount": 0}]}"#).is_ok());
    assert!(load(r#"{"rules": [{"max_amount": 2100000000000000}]}"#).is_ok());
    assert_eq!(
        problem(r#"{"rules": [{"max_amount": 2100000000000001}]}"#),
        Problem::OutOfRange
    );
    assert_eq!(
        problem(r#"{"period": 5, "rules": [{"per_period": 2100000000000001}]}"#),
        Problem::OutOfRange
    );
    assert_eq!(
        problem(r#"{"rules": [{"max_amount": 99999999999999999999999}]}"#),
        Problem::OutOfRange
    );
}

#[test]
fn logging_options() {
    assert_eq!(
        problem(r#"{"must_log": true, "never_log": true}"#),
        Problem::LogConflict
    );
    assert_eq!(
        problem(r#"{"must_log": true}"#),
        Problem::MustLogNotSupported
    );
    assert!(load(r#"{"must_log": false}"#).is_ok());
    assert!(load(r#"{"never_log": 1}"#).unwrap().never_log);
    assert_eq!(problem(r#"{"never_log": "yes"}"#), Problem::NotBool);
}

#[test]
fn booleans_take_stocks_spellings() {
    assert!(load(r#"{"warnings_ok": true}"#).unwrap().warnings_ok);
    assert!(load(r#"{"warnings_ok": 1}"#).unwrap().warnings_ok);
    assert!(!load(r#"{"warnings_ok": 0}"#).unwrap().warnings_ok);
    assert!(load(r#"{"priv_over_ux": true}"#).unwrap().priv_over_ux);
    assert_eq!(problem(r#"{"warnings_ok": 2}"#), Problem::NotBool);
}

#[test]
fn string_lengths() {
    assert!(load(r#"{"notes": "x"}"#).is_ok());
    assert_eq!(problem(r#"{"notes": ""}"#), Problem::BadLength);
    let eighty = "n".repeat(80);
    assert!(load(&format!(r#"{{"notes": "{eighty}"}}"#)).is_ok());
    assert_eq!(
        problem(&format!(r#"{{"notes": "{eighty}x"}}"#)),
        Problem::BadLength
    );
    // Length is in characters, as Python counts them.
    let accents = "é".repeat(80);
    assert!(load(&format!(r#"{{"notes": "{accents}"}}"#)).is_ok());
    assert_eq!(problem(r#"{"notes": 5}"#), Problem::NotString);
    assert!(load(r#"{"boot_to_hsm": "1"}"#).is_ok());
    assert!(load(r#"{"boot_to_hsm": "123456"}"#).is_ok());
    assert_eq!(problem(r#"{"boot_to_hsm": ""}"#), Problem::BadLength);
    assert_eq!(problem(r#"{"boot_to_hsm": "1234567"}"#), Problem::BadLength);
}

#[test]
fn a_boot_code_that_is_not_six_digits_can_never_be_typed() {
    assert!(
        load(r#"{"boot_to_hsm": "123456"}"#)
            .unwrap()
            .boot_code_typeable()
    );
    assert!(
        !load(r#"{"boot_to_hsm": "12345"}"#)
            .unwrap()
            .boot_code_typeable()
    );
    assert!(
        !load(r#"{"boot_to_hsm": "abcdef"}"#)
            .unwrap()
            .boot_code_typeable()
    );
    let p = load(r#"{"boot_to_hsm": "abc"}"#).unwrap();
    let mut s = String::new();
    p.explain(&mut s).unwrap();
    assert!(s.contains("IRREVERSIBLE"), "{s}");
    assert!(!load("{}").unwrap().boots_to_hsm());
}

#[test]
fn the_storage_locker_is_refused_with_its_own_bounds_checked_first() {
    assert_eq!(problem(r#"{"allow_sl": 0}"#), Problem::OutOfRange);
    assert_eq!(problem(r#"{"allow_sl": 101}"#), Problem::OutOfRange);
    assert_eq!(
        problem(r#"{"allow_sl": 1}"#),
        Problem::StorageLockerNotSupported
    );
    let sl = "s".repeat(16);
    assert_eq!(
        problem(&format!(r#"{{"set_sl": "{sl}"}}"#)),
        Problem::NeedAllowSl
    );
    assert_eq!(
        problem(&format!(r#"{{"set_sl": "{sl}", "allow_sl": 3}}"#)),
        Problem::StorageLockerNotSupported
    );
    assert_eq!(
        problem(r#"{"set_sl": "short", "allow_sl": 3}"#),
        Problem::BadLength
    );
}

#[test]
fn paths() {
    assert!(load(r#"{"msg_paths": ["any"]}"#).unwrap().msg_paths.any());
    assert!(load(r#"{"msg_paths": ["m/44'/0'/0'/0/*", "84h/1h/0h"]}"#).is_ok());
    assert_eq!(problem(r#"{"msg_paths": ["m/x"]}"#), Problem::BadPath);
    assert_eq!(problem(r#"{"msg_paths": ["m/*h"]}"#), Problem::BadPath);
    assert_eq!(problem(r#"{"msg_paths": ["p2sh"]}"#), Problem::BadPath);
    assert!(
        load(r#"{"share_addrs": ["p2sh"]}"#)
            .unwrap()
            .share_addrs
            .has_literal("p2sh")
    );
    assert_eq!(problem(r#"{"msg_paths": "m/1"}"#), Problem::NotList);
    assert_eq!(problem(r#"{"msg_paths": [5]}"#), Problem::NotString);
    let many: Vec<String> = (0..17).map(|i| format!("\"m/{i}\"")).collect();
    assert_eq!(
        problem(&format!(r#"{{"share_xpubs": [{}]}}"#, many.join(","))),
        Problem::TooManyEntries
    );
    // An empty list is no list.
    assert!(load(r#"{"msg_paths": []}"#).unwrap().msg_paths.is_empty());
}

#[test]
fn path_matching() {
    let p = load(r#"{"msg_paths": ["m/84h/0h/0h/*"], "share_xpubs": ["m/49h/0h/0h"]}"#).unwrap();
    const H: u32 = 0x8000_0000;
    assert!(p.msg_paths.allows(&[84 | H, H, H, 7]));
    assert!(
        !p.msg_paths.allows(&[84 | H, H, H, 7 | H]),
        "a * is unhardened"
    );
    assert!(!p.msg_paths.allows(&[84 | H, H, H]), "same depth only");
    assert!(!p.msg_paths.allows(&[84 | H, H, H, 0, 0]));
    assert!(!p.msg_paths.allows(&[84 | H, H, 1 | H, 0]));
    assert!(p.share_xpubs.allows(&[49 | H, H, H]));
    assert!(
        !p.share_xpubs.allows(&[49, 0, 0]),
        "hardened steps must be hardened"
    );
    let any = load(r#"{"msg_paths": ["any"]}"#).unwrap();
    assert!(any.msg_paths.allows(&[1, 2, 3]));
    assert!(!load("{}").unwrap().msg_paths.allows(&[1]));
}

#[test]
fn rule_wallets() {
    assert!(load(r#"{"rules": [{"wallet": "1"}]}"#).is_ok());
    assert!(load(r#"{"rules": [{"wallet": "desk-multisig"}]}"#).is_ok());
    assert_eq!(
        problem(r#"{"rules": [{"wallet": "nobody"}]}"#),
        Problem::UnknownWallet
    );
    assert_eq!(
        problem(r#"{"rules": [{"wallet": "twice"}]}"#),
        Problem::WalletNotUnique
    );
    assert_eq!(
        problem(r#"{"rules": [{"wallet": ""}]}"#),
        Problem::BadLength
    );
    assert_eq!(
        problem(r#"{"rules": [{"wallet": "abcdefghijklmnopqrstu"}]}"#),
        Problem::BadLength
    );
}

#[test]
fn rule_users() {
    let p = load(r#"{"rules": [{"users": ["alice", "bob"]}]}"#).unwrap();
    assert_eq!(p.rules[0].min_users, Some(2), "all of them unless said");
    let p = load(r#"{"rules": [{"users": ["alice", "bob"], "min_users": 1}]}"#).unwrap();
    assert_eq!(p.rules[0].min_users, Some(1));
    assert_eq!(
        problem(r#"{"rules": [{"users": ["mallory"]}]}"#),
        Problem::UnknownUser
    );
    assert_eq!(
        problem(r#"{"rules": [{"users": ["alice", "alice"]}]}"#),
        Problem::DuplicateUser
    );
    assert_eq!(
        problem(r#"{"rules": [{"users": ["alice"], "min_users": 2}]}"#),
        Problem::BadMinUsers
    );
    assert_eq!(
        problem(r#"{"rules": [{"users": ["alice"], "min_users": 0}]}"#),
        Problem::BadMinUsers
    );
    assert_eq!(
        problem(r#"{"rules": [{"min_users": 1}]}"#),
        Problem::BadMinUsers
    );
    assert_eq!(
        load(r#"{"rules": [{"users": []}]}"#).unwrap().rules[0].min_users,
        None
    );
}

#[test]
fn rule_whitelists() {
    let p = load(&format!(
        r#"{{"rules": [{{"whitelist": ["{}"]}}]}}"#,
        A1.to_uppercase()
    ))
    .unwrap();
    assert!(
        p.rules[0].whitelist.contains(A1),
        "bech32 is case-insensitive"
    );
    assert_eq!(
        problem(r#"{"rules": [{"whitelist": ["nope"]}]}"#),
        Problem::BadAddress
    );
    assert_eq!(
        problem(r#"{"rules": [{"whitelist_opts": {"mode": "BASIC"}}]}"#),
        Problem::OptsWithoutWhitelist
    );
    assert_eq!(
        problem(&format!(
            r#"{{"rules": [{{"whitelist": ["{A1}"], "whitelist_opts": {{"mode": "attest"}}}}]}}"#
        )),
        Problem::AttestNotSupported
    );
    assert_eq!(
        problem(&format!(
            r#"{{"rules": [{{"whitelist": ["{A1}"], "whitelist_opts": {{"mode": "FANCY"}}}}]}}"#
        )),
        Problem::BadMode
    );
    let p = load(&format!(
        r#"{{"rules": [{{"whitelist": ["{A1}"], "whitelist_opts": {{"mode": "basic", "allow_zeroval_outs": true}}}}]}}"#
    ))
    .unwrap();
    assert!(p.rules[0].allow_zeroval_outs);
    let many: Vec<String> = (0..26)
        .map(|i| format!("\"bc1qplaceholder{i:030}\""))
        .collect();
    assert_eq!(
        problem(&format!(
            r#"{{"rules": [{{"whitelist": [{}]}}]}}"#,
            many.join(",")
        )),
        Problem::TooManyEntries
    );
}

#[test]
fn rule_percent_and_patterns() {
    assert!(load(r#"{"rules": [{"min_pct_self_transfer": 100}]}"#).is_ok());
    assert!(load(r#"{"rules": [{"min_pct_self_transfer": 99.5}]}"#).is_ok());
    assert_eq!(
        problem(r#"{"rules": [{"min_pct_self_transfer": 100.1}]}"#),
        Problem::OutOfRange
    );
    assert_eq!(
        problem(r#"{"rules": [{"min_pct_self_transfer": -1}]}"#),
        Problem::OutOfRange
    );
    assert_eq!(
        problem(r#"{"rules": [{"min_pct_self_transfer": "5"}]}"#),
        Problem::NotNumber
    );
    assert_eq!(
        problem(r#"{"rules": [{"patterns": ["EQ_SOMETHING"]}]}"#),
        Problem::BadPattern
    );
    let p =
        load(r#"{"rules": [{"patterns": ["EQ_OUT_AMOUNTS", "EQ_NUM_OWN_INS_OUTS"]}]}"#).unwrap();
    assert_eq!(p.rules[0].patterns, 0b110);
}

#[test]
fn too_many_rules() {
    let rules: Vec<&str> = (0..=MAX_RULES).map(|_| "{}").collect();
    assert_eq!(
        problem(&format!(r#"{{"rules": [{}]}}"#, rules.join(","))),
        Problem::TooManyRules
    );
    assert_eq!(problem(r#"{"rules": [5]}"#), Problem::NotDict);
    assert_eq!(problem(r#"{"rules": {}}"#), Problem::NotList);
}

#[test]
fn refusals_say_where() {
    let r = load(r#"{"rules": [{}, {"max_amount": "lots"}]}"#).unwrap_err();
    assert_eq!(r.to_string(), "rule 2: max_amount: must be a whole number");
    let r = load(r#"{"zzz": 1}"#).unwrap_err();
    assert_eq!(r.to_string(), "unknown key: zzz");
}

// ---- judging ------------------------------------------------------------------------

fn facts(sending: u64) -> Facts<'static> {
    Facts {
        inputs: 1,
        outputs: 2,
        own_inputs: 1,
        own_outputs: 1,
        own_in: 10 * sending.max(1),
        own_out: 9 * sending.max(1) - sending.min(9 * sending.max(1)),
        sending,
        spender: Spender::Single,
        users: &[],
        local_ok: false,
    }
}

fn judge(
    p: &Policy<'_>,
    f: &Facts<'_>,
    outs: &[(u64, bool, &str)],
    rt: &mut Runtime,
    now: u64,
) -> Result<usize, String> {
    let mut j = Judge::new(p);
    for (a, c, addr) in outs {
        j.output(*a, *c, addr);
    }
    let mut why = Reasons::new();
    j.verdict(f, rt, now, &mut why)
        .ok_or_else(|| why.as_str().to_string())
}

#[test]
fn max_amount_is_a_per_transaction_cap() {
    let p = load(r#"{"rules": [{"max_amount": 1000}]}"#).unwrap();
    let mut rt = Runtime::new();
    assert_eq!(
        judge(&p, &facts(1000), &[(1000, false, A1)], &mut rt, 0),
        Ok(0)
    );
    let e = judge(&p, &facts(1001), &[(1001, false, A1)], &mut rt, 0).unwrap_err();
    assert!(e.contains("max_amount"), "{e}");
}

#[test]
fn the_first_matching_rule_wins() {
    let p = load(r#"{"rules": [{"max_amount": 10}, {"max_amount": 1000}]}"#).unwrap();
    let mut rt = Runtime::new();
    assert_eq!(judge(&p, &facts(5), &[], &mut rt, 0), Ok(0));
    assert_eq!(judge(&p, &facts(500), &[], &mut rt, 0), Ok(1));
    let e = judge(&p, &facts(5000), &[], &mut rt, 0).unwrap_err();
    assert!(e.starts_with("rule 1:") && e.contains("; rule 2:"), "{e}");
}

#[test]
fn velocity_accumulates_within_a_period_and_resets_after_it() {
    let p = load(r#"{"period": 60, "rules": [{"per_period": 1000}]}"#).unwrap();
    let mut rt = Runtime::new();
    assert_eq!(rt.time_left(p.period, 100), TimeLeft::NotStarted);
    assert_eq!(judge(&p, &facts(600), &[], &mut rt, 100), Ok(0));
    assert_eq!(rt.period_started, Some(100));
    assert_eq!(rt.time_left(p.period, 160), TimeLeft::Seconds(3540));
    assert_eq!(judge(&p, &facts(400), &[], &mut rt, 200), Ok(0));
    assert!(
        judge(&p, &facts(1), &[], &mut rt, 300).is_err(),
        "the limit is spent"
    );
    // An hour after the first spend, it starts over.
    assert_eq!(judge(&p, &facts(1000), &[], &mut rt, 100 + 3600), Ok(0));
    assert_eq!(rt.period_started, Some(3700));
    assert_eq!(rt.time_left(None, 0), TimeLeft::NoPeriod);
}

#[test]
fn a_refused_spend_is_not_recorded() {
    let p = load(r#"{"period": 60, "rules": [{"per_period": 1000, "max_amount": 100}]}"#).unwrap();
    let mut rt = Runtime::new();
    assert!(judge(&p, &facts(500), &[], &mut rt, 0).is_err());
    assert_eq!(rt.spent[0], 0);
    assert_eq!(rt.period_started, None);
}

#[test]
fn precharge_spends_every_velocity_limit_at_boot() {
    let p = load(r#"{"period": 60, "rules": [{"per_period": 1000}, {"max_amount": 5}]}"#).unwrap();
    let mut rt = Runtime::new();
    rt.precharge(&p, 50);
    assert_eq!(rt.spent[0], 1000);
    assert_eq!(rt.spent[1], 0);
    // Rule 1 has nothing left; rule 2 still lets small ones through.
    assert_eq!(judge(&p, &facts(5), &[], &mut rt, 60), Ok(1));
    assert_eq!(rt.spent[0], 1000);
    // After the period it is all available again.
    let mut rt2 = rt.clone();
    assert_eq!(judge(&p, &facts(900), &[], &mut rt2, 50 + 3600), Ok(0));
}

#[test]
fn whitelist_every_foreign_output() {
    let p = load(&format!(
        r#"{{"rules": [{{"whitelist": ["{A1}", "{A3}"]}}]}}"#
    ))
    .unwrap();
    let mut rt = Runtime::new();
    let f = facts(10);
    assert_eq!(
        judge(
            &p,
            &f,
            &[(5, false, A1), (5, false, A3), (99, true, A2)],
            &mut rt,
            0
        ),
        Ok(0)
    );
    assert!(judge(&p, &f, &[(5, false, A1), (5, false, A2)], &mut rt, 0).is_err());
    // An output with no address (OP_RETURN) is not on any list.
    assert!(judge(&p, &f, &[(0, false, "")], &mut rt, 0).is_err());
    let z = load(&format!(
        r#"{{"rules": [{{"whitelist": ["{A1}"], "whitelist_opts": {{"allow_zeroval_outs": true}}}}]}}"#
    ))
    .unwrap();
    assert_eq!(
        judge(&z, &f, &[(10, false, A1), (0, false, "")], &mut rt, 0),
        Ok(0)
    );
    assert!(judge(&z, &f, &[(10, false, A1), (1, false, "")], &mut rt, 0).is_err());
}

#[test]
fn wallet_rules() {
    let p = load(r#"{"rules": [{"wallet": "1"}, {"wallet": "desk-multisig"}]}"#).unwrap();
    let mut rt = Runtime::new();
    let mut f = facts(1);
    assert_eq!(judge(&p, &f, &[], &mut rt, 0), Ok(0));
    f.spender = Spender::Multi("desk-multisig");
    assert_eq!(judge(&p, &f, &[], &mut rt, 0), Ok(1));
    f.spender = Spender::Multi("other");
    assert!(judge(&p, &f, &[], &mut rt, 0).is_err());
    f.spender = Spender::Other;
    assert!(judge(&p, &f, &[], &mut rt, 0).is_err());
    let any = load(r#"{"rules": [{}]}"#).unwrap();
    assert_eq!(judge(&any, &f, &[], &mut rt, 0), Ok(0));
}

#[test]
fn users_and_min_users() {
    let p = load(r#"{"rules": [{"users": ["alice", "bob", "carol"], "min_users": 2}]}"#).unwrap();
    let mut rt = Runtime::new();
    let mut f = facts(1);
    assert!(
        judge(&p, &f, &[], &mut rt, 0)
            .unwrap_err()
            .contains("more users")
    );
    f.users = &["alice"];
    assert!(judge(&p, &f, &[], &mut rt, 0).is_err());
    f.users = &["alice", "mallory"];
    assert!(
        judge(&p, &f, &[], &mut rt, 0).is_err(),
        "only listed users count"
    );
    f.users = &["alice", "carol"];
    assert_eq!(judge(&p, &f, &[], &mut rt, 0), Ok(0));
}

#[test]
fn local_confirmation() {
    let p = load(r#"{"rules": [{"local_conf": true}]}"#).unwrap();
    let mut rt = Runtime::new();
    let mut f = facts(1);
    assert!(
        judge(&p, &f, &[], &mut rt, 0)
            .unwrap_err()
            .contains("local")
    );
    f.local_ok = true;
    assert_eq!(judge(&p, &f, &[], &mut rt, 0), Ok(0));
}

#[test]
fn self_transfer_percentage() {
    let p = load(r#"{"rules": [{"min_pct_self_transfer": 50}]}"#).unwrap();
    let mut rt = Runtime::new();
    let mut f = facts(1);
    f.own_in = 1000;
    f.own_out = 500;
    assert_eq!(judge(&p, &f, &[], &mut rt, 0), Ok(0));
    f.own_out = 499;
    assert!(judge(&p, &f, &[], &mut rt, 0).is_err());
    f.own_in = 0;
    assert!(judge(&p, &f, &[], &mut rt, 0).is_err());
}

#[test]
fn patterns() {
    let p = load(r#"{"rules": [{"patterns": ["EQ_NUM_INS_OUTS", "EQ_NUM_OWN_INS_OUTS", "EQ_OUT_AMOUNTS"]}]}"#).unwrap();
    let mut rt = Runtime::new();
    let mut f = facts(1);
    f.inputs = 2;
    f.outputs = 2;
    f.own_inputs = 1;
    f.own_outputs = 1;
    assert_eq!(
        judge(&p, &f, &[(5, false, A1), (5, true, A2)], &mut rt, 0),
        Ok(0)
    );
    assert!(
        judge(&p, &f, &[(5, false, A1), (6, true, A2)], &mut rt, 0)
            .unwrap_err()
            .contains("EQ_OUT_AMOUNTS")
    );
    f.outputs = 3;
    assert!(
        judge(&p, &f, &[], &mut rt, 0)
            .unwrap_err()
            .contains("EQ_NUM_INS_OUTS")
    );
    f.outputs = 2;
    f.own_outputs = 0;
    assert!(
        judge(&p, &f, &[], &mut rt, 0)
            .unwrap_err()
            .contains("EQ_NUM_OWN_INS_OUTS")
    );
}

#[test]
fn refusals_count_to_the_shutdown() {
    let mut rt = Runtime::new();
    for _ in 0..MAX_REFUSALS - 1 {
        assert!(!rt.refuse("no"));
    }
    assert!(rt.refuse("the hundredth"));
    assert_eq!(rt.last_refusal.as_str(), "the hundredth");
    rt.approve();
    assert_eq!(rt.approvals, 1);
}

// ---- local code ---------------------------------------------------------------------

#[test]
fn local_code_matches_the_host_tool() {
    // `ckcc local-conf` given next_local_code "AAAAAAAAAAAAAAAAAAAA" (fifteen zero bytes)
    // and a file of `psbt\xff` followed by sixty-four '0' characters said 516993.
    let mut file = b"psbt\xff".to_vec();
    file.extend_from_slice(&[b'0'; 64]);
    let mut sha = [0u8; 32];
    sha.copy_from_slice(&Sha256::digest(&file));
    let key = [0u8; LOCAL_KEY_LEN];
    assert_eq!(local_key_text(&key).as_str(), "AAAAAAAAAAAAAAAAAAAA");
    assert_eq!(local_code(&key, &sha), 516_993);
    assert!(local_code_matches("516993", &key, &sha));
    assert!(!local_code_matches("516994", &key, &sha));
    assert!(!local_code_matches("51699", &key, &sha));
}

#[test]
fn local_key_text_is_base64() {
    let key: [u8; 15] = *b"Many hands make";
    assert_eq!(local_key_text(&key).as_str(), "TWFueSBoYW5kcyBtYWtl");
}

// ---- status -------------------------------------------------------------------------

#[test]
fn status_report_fields() {
    let p = load(EXAMPLE).unwrap();
    let mut rt = Runtime::new();
    rt.approve();
    rt.refuse("rule 1: an output is not whitelisted");
    let st = Status {
        active: true,
        policy_available: true,
        running: Some(Running {
            policy: &p,
            hash: "ab",
            runtime: &rt,
            next_local_code: "AAAAAAAAAAAAAAAAAAAA",
            uptime: 12,
            time_left: TimeLeft::NotStarted,
            users: &["alice", "bob"],
            pending_auth: 1,
        }),
    };
    let mut out = [0u8; 2048];
    let n = st.write(&mut out).unwrap();
    let d = Doc::parse(&out[..n]).unwrap();
    for k in [
        "active",
        "policy_hash",
        "next_local_code",
        "last_refusal",
        "approvals",
        "refusals",
        "summary",
        "sl_reads",
        "period",
        "uptime",
        "period_ends",
        "has_spent",
        "users",
        "pending_auth",
    ] {
        assert!(d.get(k).is_some(), "{k} missing");
    }
    assert_eq!(d.get("approvals"), Some("1"));
    assert_eq!(d.get("has_spent"), Some("[0,null]"));

    // Privacy over UX: counters and the refusal only.
    let quiet = load(r#"{"priv_over_ux": true, "rules": [{"max_amount": 1}]}"#).unwrap();
    let st = Status {
        active: true,
        policy_available: true,
        running: Some(Running {
            policy: &quiet,
            hash: "ab",
            runtime: &rt,
            next_local_code: "AAAAAAAAAAAAAAAAAAAA",
            uptime: 12,
            time_left: TimeLeft::NoPeriod,
            users: &["alice"],
            pending_auth: 0,
        }),
    };
    let mut out2 = [0u8; 2048];
    let n = st.write(&mut out2).unwrap();
    let d = Doc::parse(&out2[..n]).unwrap();
    assert!(d.get("summary").is_none());
    assert!(d.get("users").is_none());
    assert!(d.get("next_local_code").is_none(), "no rule needs it");
    assert!(d.get("refusals").is_some());

    let idle = Status {
        active: false,
        policy_available: false,
        running: None,
    };
    let mut out3 = [0u8; 128];
    let n = idle.write(&mut out3).unwrap();
    assert_eq!(&out3[..n], br#"{"active":false,"policy_available":false}"#);
}

#[test]
fn the_explanation_covers_every_part() {
    let p = load(EXAMPLE).unwrap();
    let mut s = String::new();
    p.explain(&mut s).unwrap();
    for want in [
        "example desk policy",
        "Rule 1:",
        "Rule 2:",
        "0.00250000 BTC",
        "needs 2 of: alice bob carol",
        "local code",
        "1440 minutes",
        "m/84h/0h/0h/*",
        "p2sh",
        "refused",
        "BOOT TO HSM",
    ] {
        assert!(s.contains(want), "{want:?} not in {s}");
    }
}
