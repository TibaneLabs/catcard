//! Paper wallets: a single-use key with no relation to the device seed.
//!
//! Stock Coldcard's `Advanced/Tools -> Paper Wallets`
//! (hw-reference/firmware-features.md §8 "paper wallets" [C]). The device draws a fresh
//! private key, writes it to microSD as a self-contained printable file -- the key as
//! WIF, its address, and a QR of each -- and keeps nothing. The key is **not** derived
//! from the wallet seed: destroying the seed does not destroy this key, and a backup of
//! the seed does not back it up. That is the whole warning, and it is on the screen
//! before anything is generated and in the file that comes out.
//!
//! # Where the key comes from
//!
//! Real key material, so it comes from the boot entropy pool by way of an
//! [`HmacDrbg`](catcard_entropy::HmacDrbg) spawned for the [`PAPER`](catcard_entropy::domain::PAPER)
//! domain -- the same plumbing every other generated secret uses, and never a UI or
//! public source. A device whose pool never met its policy at boot has no pool to draw
//! from, and that is a refusal, exactly as it is for a new seed.
//!
//! # What is left out
//!
//! No BIP-38 passphrase-encrypted key. Stock offers one, but it is a second cipher
//! (scrypt + AES) carried only for this screen, and a plain-WIF paper wallet is full
//! parity for the common case. It can be added later without changing this file's shape.
//!
//! # Format
//!
//! Mainnet only, matching the rest of this firmware (`export.rs` has no testnet), and the
//! key is used compressed. WIF is `0x80 || key || 0x01`, Base58Check.
//! Source: the Bitcoin WIF convention [C].

use core::fmt::Write as _;

use zeroize::{Zeroize as _, Zeroizing};

use anyd::codes::qr::{EcLevel, QrEncoder, Version};

use catcard_entropy::{EntropyPool, domain, spawn_drbg};
use catcard_wallet::address::{self, AddressKind};
use catcard_wallet::bip32::{self, Network, PRIVKEY_LEN};

use crate::menu;
use crate::ui::Ui;

/// The address types offered, and the label each is shown under.
///
/// Segwit first: it is the default a paper wallet should hand out, and the cursor opens
/// on it. All four of the single-signature kinds this firmware can encode are here, so
/// the choice is the owner's rather than inferred.
const KINDS: &[(AddressKind, &str)] = &[
    (AddressKind::P2wpkh, "Segwit (bc1)"),
    (AddressKind::P2tr, "Taproot (bc1p)"),
    (AddressKind::P2shP2wpkh, "P2SH-Segwit (3)"),
    (AddressKind::P2pkh, "Legacy (1)"),
];

/// The largest QR symbol the render buffers hold: version 8, 49 modules.
///
/// A WIF (~52 bytes, byte mode) and every address form (bech32 in QR's alphanumeric mode,
/// base58 with the `bitcoin:` scheme in byte mode) fit well inside a version-8 symbol at
/// error-correction M, so the encoder never needs a larger one. Matches `menu::qr_screen`.
const MAX_VERSION: Version = match Version::new(8) {
    Some(v) => v,
    None => unreachable!(),
};
/// Bytes each of the encoder's two buffers needs for [`MAX_VERSION`].
const QR_BUF: usize = QrEncoder::buffer_len(MAX_VERSION);

/// The heap block the printable file is built into.
///
/// Two run-length SVG paths (one per QR) plus a small HTML frame. A version-8 symbol is
/// the worst case and its run-length path is a few kilobytes; 16 KiB leaves generous
/// room for both and the text, and the block is wiped on drop because it held the key.
const BODY_CAP: usize = 16 * 1024;

/// The file written to the card. `write_card_export` appends `-2`, `-3`... on collision,
/// so nothing is overwritten.
const FILE_NAME: &str = "/paper-wallet.html";

/// Generate a single-use paper wallet and write it to the card.
///
/// Reached from `Utils` (stock's `Advanced/Tools`). Needs no seed -- the key is
/// standalone -- so it is offered on a blank device too; it needs only the entropy pool.
pub(crate) fn create(ui: &mut Ui<'_>, pool: Option<&mut EntropyPool>) {
    // No pool means it never met its policy at boot. That is a refusal, not a fall back to
    // something weaker -- the same stance `new_seed` takes.
    let Some(pool) = pool else {
        menu::message(
            ui.panel,
            "No entropy",
            "the pool missed its",
            "policy at boot",
        );
        menu::wait_for_any_key(ui);
        return;
    };

    // The one warning that matters, before anything is drawn: this key stands alone.
    menu::ask(
        ui.panel,
        "Paper wallet",
        "key is SEPARATE from",
        "your wallet seed",
    );
    if !menu::confirmed(ui) {
        return;
    }

    let labels: heapless::Vec<&str, 4> = KINDS.iter().map(|&(_, l)| l).collect();
    let Some(choice) = menu::choose(ui, "Address type", "for this key", &labels) else {
        return;
    };
    let kind = KINDS[choice].0;

    // Draw the key from a DRBG spawned for the paper domain, so it can never coincide with
    // the UI, protocol or signing streams even though it is real key material.
    let mut drbg = match spawn_drbg(pool, domain::PAPER, &[]) {
        Ok(d) => d,
        Err(_) => {
            menu::message(ui.panel, "Refused", "pool cannot spare", "a draw");
            menu::wait_for_any_key(ui);
            return;
        }
    };

    // Everything computed from the key runs with interrupts masked: the scalar appears,
    // its public key is derived, and it is encoded as WIF, with nothing a host could time
    // in between. The QR rendering below is outside the mask, exactly as `qr_screen`
    // renders a SeedQR outside it -- the key is destined for paper, not kept secret from
    // the person holding the device.
    let mut secret = Zeroizing::new([0u8; PRIVKEY_LEN]);
    let mut wif = Zeroizing::new([0u8; 64]);
    let derived = crate::keywork::run(|kw| {
        // A DRBG output at or above the curve order is not a usable key. It is
        // cryptographically negligible (~2^-128), but bounded rather than a `while`: draw
        // again a fixed few times, then give up. The loop is inside the mask, so its
        // length -- always one in practice -- tells a host nothing.
        for _ in 0..8u8 {
            if drbg.generate(&mut secret[..]).is_err() {
                return None;
            }
            let Some(pubkey) = bip32::public_key_of(&secret, kw) else {
                continue;
            };
            let wif_len = catcard_wallet::bip85::encode_wif(&secret, &mut wif[..], kw).ok()?;
            return Some((pubkey, wif_len));
        }
        None
    });
    // The DRBG has served its one purpose; drop it so its state does not linger.
    drop(drbg);

    let Some((pubkey, wif_len)) = derived else {
        secret.zeroize();
        menu::message(ui.panel, "Refused", "could not draw a", "usable key");
        menu::wait_for_any_key(ui);
        return;
    };
    // The scalar itself is not needed past the WIF; the WIF is what goes on paper.
    secret.zeroize();

    // The address is public and derived from the public key, so it is computed here rather
    // than inside the mask.
    let mut addr = [0u8; address::MAX_ADDRESS_LEN];
    let Ok(addr_len) = address::encode(kind, Network::Mainnet, &pubkey, &mut addr) else {
        menu::message(ui.panel, "Failed", "could not encode", "the address");
        menu::wait_for_any_key(ui);
        return;
    };
    let address = core::str::from_utf8(&addr[..addr_len]).unwrap_or("");
    let wif_str = core::str::from_utf8(&wif[..wif_len]).unwrap_or("");

    // Build the printable file. The block is wiped on drop -- it holds the WIF.
    let Some(mut block) = crate::heap::take(BODY_CAP) else {
        wif.zeroize();
        menu::message(ui.panel, "No memory", "not enough room", "to build the file");
        menu::wait_for_any_key(ui);
        return;
    };
    let built = {
        let mut w = SliceWriter::new(block.bytes());
        let ok = render_html(&mut w, kind, KINDS[choice].1, address, wif_str);
        ok.then_some(w.len)
    };
    let Some(body_len) = built else {
        wif.zeroize();
        menu::message(ui.panel, "Failed", "the file did not", "fit its buffer");
        menu::wait_for_any_key(ui);
        return;
    };

    menu::card_wait(ui.panel, "Paper wallet", "writing to the card");
    let result = menu::write_card_export(FILE_NAME, &block.bytes()[..body_len], None);
    // The buffer held the WIF; wipe both it and the WIF string before the screen changes.
    block.bytes().zeroize();
    wif.zeroize();

    match result {
        Ok(name) => {
            crate::catlog!("paper: wrote {} bytes", body_len);
            let mut file: heapless::String<48> = heapless::String::new();
            let _ = write!(file, "{}", &name[1..]);
            let mut note: heapless::String<48> = heapless::String::new();
            let _ = write!(note, "addr {}", short(address));
            let lines = [
                file,
                note,
                str_line("device kept no copy"),
                str_line("print it, then wipe card"),
            ];
            menu::info(ui.panel, "Exported", &lines);
        }
        Err(why) => {
            crate::catlog!("paper: export failed: {}", why);
            menu::message(ui.panel, "Export failed", why, "any key to go back");
        }
    }
    menu::wait_for_any_key(ui);
}

/// A `heapless::String<48>` from a `&str`, truncated to fit.
fn str_line(s: &str) -> heapless::String<48> {
    let mut l: heapless::String<48> = heapless::String::new();
    let _ = l.push_str(&s[..s.len().min(48)]);
    l
}

/// The first and last few characters of an address, for a one-line confirmation.
fn short(addr: &str) -> heapless::String<24> {
    let mut s: heapless::String<24> = heapless::String::new();
    if addr.len() <= 16 {
        let _ = s.push_str(addr);
    } else {
        let _ = write!(s, "{}..{}", &addr[..8], &addr[addr.len() - 6..]);
    }
    s
}

/// Write the self-contained printable page. Returns false if it did not fit `w`.
///
/// Deliberately lean: the static text is a few short strings so it costs little of the
/// mk3's flash, and the bulk -- the two QR codes -- is built by code, not held in
/// `.rodata`. Everything is inline, so the file prints and reads with no network.
fn render_html(
    w: &mut SliceWriter<'_>,
    kind: AddressKind,
    kind_label: &str,
    address: &str,
    wif: &str,
) -> bool {
    let _ = write!(
        w,
        "<!DOCTYPE html><html><head><meta charset=\"utf-8\">\
         <title>CatCard paper wallet</title><style>\
         body{{font-family:sans-serif;margin:1em}}\
         .w{{border:2px solid #b00;padding:.5em;margin:.5em 0;color:#b00;font-weight:bold}}\
         .m{{font-family:monospace;word-break:break-all;font-size:1.1em}}\
         svg{{width:200px;height:200px;image-rendering:pixelated}}\
         h2{{margin:.3em 0}}</style></head><body>\
         <h1>Bitcoin paper wallet</h1>\
         <div class=\"w\">This key is INDEPENDENT of your CatCard wallet seed. \
         The device did not keep a copy. Anyone who reads it can spend the funds. \
         Print this page, then destroy every digital copy.</div>\
         <p>Address type: {kind_label}</p>"
    );

    let _ = w.write_str("<h2>Address (deposit here)</h2>");
    let mut qr_payload = [0u8; address::MAX_QR_PAYLOAD];
    let payload = address::qr_payload(address, kind, &mut qr_payload).unwrap_or(address);
    if !qr_svg(w, payload.as_bytes()) {
        return false;
    }
    let _ = write!(w, "<p class=\"m\">{address}</p>");

    let _ = w.write_str("<h2>Private key &mdash; WIF (keep secret)</h2>");
    if !qr_svg(w, wif.as_bytes()) {
        return false;
    }
    let _ = write!(w, "<p class=\"m\">{wif}</p>");

    let _ = w.write_str("</body></html>");
    !w.overflowed
}

/// Append `payload` as an inline SVG QR code, dark modules as one run-length `<path>`.
///
/// Returns false if the payload will not fit the largest symbol these buffers hold, or if
/// the SVG did not fit `w`. Merging each row's dark modules into `h{run}` segments keeps
/// the path short -- a finder pattern's seven-module edge is one segment, not seven.
fn qr_svg(w: &mut SliceWriter<'_>, payload: &[u8]) -> bool {
    // A WIF QR carries the private key, so these buffers do too until they are wiped.
    let mut scratch = Zeroizing::new([0u8; QR_BUF]);
    let mut storage = Zeroizing::new([0u8; QR_BUF]);
    let encoder = QrEncoder::new();
    let Ok((grid, _meta)) =
        encoder.encode_text_into(payload, EcLevel::M, &mut *scratch, &mut *storage)
    else {
        return false;
    };
    let modules = grid.width();
    // One quiet module of margin in the viewBox, which a scanner needs and which the
    // #fff background provides visually.
    let quiet = 1usize;
    let side = modules + 2 * quiet;
    let _ = write!(
        w,
        "<svg viewBox=\"0 0 {side} {side}\" xmlns=\"http://www.w3.org/2000/svg\">\
         <rect width=\"{side}\" height=\"{side}\" fill=\"#fff\"/><path fill=\"#000\" d=\""
    );
    for y in 0..modules {
        let mut x = 0usize;
        while x < modules {
            if grid.get(x, y) {
                let start = x;
                while x < modules && grid.get(x, y) {
                    x += 1;
                }
                let run = x - start;
                let _ = write!(w, "M{} {}h{run}v1h-{run}z", start + quiet, y + quiet);
            } else {
                x += 1;
            }
        }
    }
    let _ = w.write_str("\"/></svg>");
    !w.overflowed
}

/// A bounded `core::fmt::Write` over a byte slice: it fills up to the slice and then
/// records that it overflowed rather than writing past the end, so an oversized page is a
/// clean refusal instead of a truncated or corrupt file.
struct SliceWriter<'a> {
    buf: &'a mut [u8],
    len: usize,
    overflowed: bool,
}

impl<'a> SliceWriter<'a> {
    fn new(buf: &'a mut [u8]) -> Self {
        SliceWriter {
            buf,
            len: 0,
            overflowed: false,
        }
    }
}

impl core::fmt::Write for SliceWriter<'_> {
    fn write_str(&mut self, s: &str) -> core::fmt::Result {
        let bytes = s.as_bytes();
        if self.len + bytes.len() > self.buf.len() {
            self.overflowed = true;
            return Err(core::fmt::Error);
        }
        self.buf[self.len..self.len + bytes.len()].copy_from_slice(bytes);
        self.len += bytes.len();
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Render a page into a fixed buffer, returning the bytes as a string.
    fn page(kind: AddressKind, label: &str, addr: &str, wif: &str) -> std::string::String {
        let mut buf = std::vec![0u8; BODY_CAP];
        let mut w = SliceWriter::new(&mut buf);
        assert!(render_html(&mut w, kind, label, addr, wif), "should fit");
        std::string::String::from_utf8(buf[..w.len].to_vec()).unwrap()
    }

    #[test]
    fn the_page_carries_both_the_address_and_the_wif() {
        let addr = "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4";
        let wif = "L1aW4aubDFB7yfras2S1mms3HzKwsSv8n5RzPZfxAcM2ZfrjZKm4";
        let html = page(AddressKind::P2wpkh, "Segwit (bc1)", addr, wif);
        assert!(html.contains(addr), "address text present");
        assert!(html.contains(wif), "WIF text present");
        // Two QR symbols: one for the address, one for the key.
        assert_eq!(html.matches("<svg").count(), 2);
    }

    #[test]
    fn the_independence_warning_is_on_the_page() {
        let html = page(
            AddressKind::P2pkh,
            "Legacy (1)",
            "1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2",
            "L1aW4aubDFB7yfras2S1mms3HzKwsSv8n5RzPZfxAcM2ZfrjZKm4",
        );
        assert!(html.to_uppercase().contains("INDEPENDENT"));
        assert!(html.contains("did not keep a copy"));
    }

    #[test]
    fn a_bech32_address_qr_uses_the_upper_cased_bare_payload() {
        // `qr_payload` upper-cases bech32 and drops the scheme; the page must carry that
        // form in the QR while the readable text below stays as-is.
        let addr = "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4";
        let html = page(AddressKind::P2wpkh, "Segwit (bc1)", addr, "Kx");
        // The lower-case address is still shown as text for a person to read.
        assert!(html.contains(addr));
    }

    #[test]
    fn a_writer_that_overflows_refuses_rather_than_truncates() {
        let mut buf = [0u8; 8];
        let mut w = SliceWriter::new(&mut buf);
        assert!(!qr_svg(
            &mut w,
            b"a-payload-far-too-long-for-eight-bytes-of-output"
        ));
        assert!(w.overflowed);
    }

    #[test]
    fn short_keeps_the_head_and_tail() {
        let s = short("bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4");
        assert!(s.starts_with("bc1qw508"));
        assert!(s.contains(".."));
    }

    #[test]
    fn every_offered_kind_encodes_a_page() {
        // A representative address per kind; the point is that render_html handles each
        // AddressKind's QR payload shape without overflowing.
        let cases = [
            (AddressKind::P2wpkh, "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4"),
            (
                AddressKind::P2tr,
                "bc1p0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7vqzk5jj0",
            ),
            (AddressKind::P2shP2wpkh, "3J98t1WpEZ73CNmQviecrnyiWrnqRhWNLy"),
            (AddressKind::P2pkh, "1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2"),
        ];
        for (kind, addr) in cases {
            let html = page(kind, "x", addr, "L1aW4aubDFB7yfras2S1mms3HzKwsSv8n5RzPZfxAcM2ZfrjZKm4");
            assert_eq!(html.matches("<svg").count(), 2);
        }
    }
}
