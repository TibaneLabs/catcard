//! Bench tool: rewrite a Precursor gateware image.
//!
//!     cargo run -p catcard-bitstream --example rekey -- IN OUT [options]
//!
//! Options: `--src-key HEX` (default zero), `--key HEX` (default zero), `--bbram`,
//! `--iv HEX`, `--hmac HEX`, `--set ADDR=HEX...` (key ROM words from ADDR, hex address).
//! Prints the source key ROM's non-zero words. Never use it with a real device key on
//! a machine you do not trust: the key is on the command line.

use catcard_bitstream::{KeySource, Layout, Target, rewrite};

fn hex<const N: usize>(s: &str) -> [u8; N] {
    let mut out = [0u8; N];
    assert_eq!(s.len(), N * 2, "expected {} hex digits", N * 2);
    for (i, o) in out.iter_mut().enumerate() {
        *o = u8::from_str_radix(&s[i * 2..i * 2 + 2], 16).unwrap();
    }
    out
}

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let (inp, outp) = (&args[0], &args[1]);
    let mut src_key = [0u8; 32];
    let mut t = Target {
        key: [0; 32],
        source: KeySource::Efuse,
        iv: None,
        hmac_key: None,
        keyrom: None,
    };
    let mut sets: Vec<(usize, Vec<u32>)> = Vec::new();
    let mut bbram = false;
    let mut i = 2;
    while i < args.len() {
        match args[i].as_str() {
            "--src-key" => {
                src_key = hex(&args[i + 1]);
                i += 1;
            }
            "--key" => {
                t.key = hex(&args[i + 1]);
                i += 1;
            }
            "--iv" => {
                t.iv = Some(hex(&args[i + 1]));
                i += 1;
            }
            "--hmac" => {
                t.hmac_key = Some(hex(&args[i + 1]));
                i += 1;
            }
            "--bbram" => bbram = true,
            "--set" => {
                let (a, v) = args[i + 1].split_once('=').unwrap();
                let words = v
                    .as_bytes()
                    .chunks(8)
                    .map(|c| u32::from_str_radix(std::str::from_utf8(c).unwrap(), 16).unwrap())
                    .collect();
                sets.push((
                    usize::from_str_radix(a.trim_start_matches("0x"), 16).unwrap(),
                    words,
                ));
                i += 1;
            }
            o => panic!("unknown option {o}"),
        }
        i += 1;
    }
    let img = std::fs::read(inp).unwrap();
    let layout = Layout::parse(&img).unwrap();
    t.source = if bbram {
        KeySource::Bbram
    } else {
        layout.key_source
    };
    let current = catcard_bitstream::read_keyrom(&img, &src_key).expect("source does not verify");
    for (a, w) in current
        .keyrom_in
        .0
        .iter()
        .enumerate()
        .filter(|(_, w)| **w != 0)
    {
        println!("keyrom[{a:#04x}] = {w:08x}");
    }
    if !sets.is_empty() {
        let mut rom = current.keyrom_in.clone();
        for (a, words) in &sets {
            rom.0[*a..*a + words.len()].copy_from_slice(words);
        }
        t.keyrom = Some(rom);
    }
    let mut out = img.clone();
    rewrite(&img, &src_key, t, &mut out).expect("rewrite failed");
    std::fs::write(outp, &out).unwrap();
    println!(
        "wrote {} ({} bytes; first {} rewritten)",
        outp,
        out.len(),
        layout.image_len()
    );
}
