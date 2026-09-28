//! NIST CAVP HMAC_DRBG (SHA-256) known-answer tests, SP 800-90A §10.1.2.
//!
//! The cases are every SHA-256 case in the three `HMAC_DRBG.rsp` files of NIST's
//! `drbgtestvectors.zip` (no reseed, reseed without prediction resistance, prediction
//! resistance), extracted into `tests/data/hmac_drbg_sha256.txt` by
//! `tools/reference/cavp_hmac_drbg_extract.py`. The data file's header records the
//! SHA-256 of the zip and of each `.rsp`, and the section headers it took cases from.
//!
//! The CAVP procedure for every mode: instantiate, (reseed), generate `ReturnedBitsLen`
//! bits, generate again, and compare only the second output.
//!
//! Prediction resistance is not a mode of [`HmacDrbg`]; SP 800-90A §9.3.1 defines it as
//! a reseed with fresh entropy (and that request's additional input) immediately before
//! the generate, which then runs with no additional input. That is exactly
//! `reseed(entropy_pr, additional)` followed by `generate`, so those cases run too.

use catcard_entropy::HmacDrbg;

const DATA: &str = include_str!("data/hmac_drbg_sha256.txt");

fn unhex(s: &str) -> Vec<u8> {
    if s == "-" {
        return Vec::new();
    }
    assert!(s.len().is_multiple_of(2), "odd-length hex field");
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).expect("hex"))
        .collect()
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

/// Run one case; returns the second generate's output.
fn run(mode: &str, f: &[Vec<u8>], out_len: usize) -> Vec<u8> {
    let (entropy, nonce, pers) = (&f[0], &f[1], &f[2]);
    let mut d = HmacDrbg::new(entropy, nonce, pers);
    let mut out = vec![0u8; out_len];
    match mode {
        "N" => {
            d.generate_with(&mut out, &f[3]).unwrap();
            d.generate_with(&mut out, &f[4]).unwrap();
        }
        "R" => {
            d.reseed(&f[3], &f[4]);
            d.generate_with(&mut out, &f[5]).unwrap();
            d.generate_with(&mut out, &f[6]).unwrap();
        }
        "P" => {
            // add1, entropy_pr1, add2, entropy_pr2
            d.reseed(&f[4], &f[3]);
            d.generate(&mut out).unwrap();
            d.reseed(&f[6], &f[5]);
            d.generate(&mut out).unwrap();
        }
        other => panic!("unknown mode {other}"),
    }
    out
}

#[test]
fn every_nist_cavp_sha256_case_matches() {
    let mut counts = [0usize; 3];
    let mut failures = Vec::new();
    for (lineno, line) in DATA.lines().enumerate() {
        if line.starts_with('#') || line.trim().is_empty() {
            continue;
        }
        let mut tok = line.split(' ');
        let mode = tok.next().unwrap();
        let fields: Vec<Vec<u8>> = tok.map(unhex).collect();
        let want_fields = match mode {
            "N" => 6,
            "R" | "P" => 8,
            _ => panic!("line {}: unknown mode {mode}", lineno + 1),
        };
        assert_eq!(fields.len(), want_fields, "line {}", lineno + 1);
        let expected = fields.last().unwrap();
        assert_eq!(expected.len(), 128, "SHA-256 cases return 1024 bits");
        let got = run(mode, &fields, expected.len());
        if &got != expected {
            failures.push(format!(
                "line {} ({mode}): got {} want {}",
                lineno + 1,
                hex(&got),
                hex(expected)
            ));
        }
        counts[match mode {
            "N" => 0,
            "R" => 1,
            _ => 2,
        }] += 1;
    }
    assert!(failures.is_empty(), "{}", failures.join("\n"));
    // Every case in every section was run: 16 SHA-256 sections of 15 per file.
    assert_eq!(counts, [240, 240, 240], "cases run per mode");
}

/// The data file is what the extractor wrote from the files named in its header. A
/// changed header means someone regenerated it from different inputs.
#[test]
fn the_data_file_names_its_source() {
    for want in [
        "# drbgtestvectors.zip sha256 5f7e5658ebd5b4e6785a7b12fa32333511d2acc2f2d9c5ae1ffa16b699377769",
        "# drbgvectors_no_reseed.zip/HMAC_DRBG.rsp sha256 9fdd7f11dbbe75e0a7e19c6ae57660008dd4e74672ebb67119cab287c7aa5a79",
        "# drbgvectors_pr_false.zip/HMAC_DRBG.rsp sha256 4b7d03d4fb48c738c76baf09bd67d054514682f4fee36ff8741bec2ccd77b8d4",
        "# drbgvectors_pr_true.zip/HMAC_DRBG.rsp sha256 806f71be8d100702450191d847bbfe3c405f31cdaca219eee6918cb77a7a2f55",
    ] {
        assert!(
            DATA.lines().any(|l| l == want),
            "missing header line: {want}"
        );
    }
}
