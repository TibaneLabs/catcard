//! Split this wallet into `n` share files (docs/TSS.md, "Export").
//!
//! Each file holds one member's bundle: a Codex32 share of the wallet's words, any `t` of
//! which give the words back, and the core of a DKLs share of one account's key, any `t`
//! of which sign for that account on CatCards -- once the members signing have set up
//! their pairs together (Rebuild setup), which a bundle does not carry. The account's hardened steps are done here first,
//! since a shared key can only derive non-hardened children; the shares then sign for
//! the addresses the wallet already uses under that account.
//!
//! Written one file at a time, so each can go on its own card -- or all to the Virtual
//! Disk, to be taken off it over USB.

use catcard_tss::{AccountKey, ShareBundle};
use catcard_wallet::bip32::{ChildNumber, DerivationPath};
use core::fmt::Write as _;
use zeroize::Zeroize as _;

use super::rand::Fresh;
use super::{Room, Work, approve, card, describe, hex4, say};
use crate::menu::{self, Line, Storage};
use crate::ui::Ui;

const HEAD: &str = "Split this wallet";

/// The address types a share can sign for, as BIP-44's purposes. No Taproot: the
/// threshold key signs ECDSA only (docs/TSS.md, "The scheme and its limits").
const KINDS: [(&str, u32); 3] = [
    ("Native SegWit (84')", 84),
    ("Nested SegWit (49')", 49),
    ("Legacy (44')", 44),
];

#[inline(never)]
pub(super) fn export(
    gate: &catcard_callgate::Callgate,
    login: &mut catcard_pin::Login,
    ui: &mut Ui<'_>,
    pool: Option<&mut catcard_entropy::EntropyPool>,
) {
    let Some(pool) = pool else {
        return say(ui, HEAD, "the pool missed its", "policy at boot");
    };
    if crate::passphrase::is_set() {
        // The shares carry the words, and the words alone are another wallet.
        return say(
            ui,
            HEAD,
            "not with a passphrase:",
            "the shares hold the words",
        );
    }
    // Delta mode: showing the seed erases it instead. See `crate::trickpin`.
    crate::trickpin::seed_reveal(gate);
    let Some(_room) = Room::take(ui, HEAD) else {
        return;
    };
    // Every bundle is in memory while each is encoded (counted in the measured peak).
    let most = Room::most_members(Work::Export, |_| 0);
    if most < 2 {
        return say(ui, HEAD, "not enough memory", "to split a wallet");
    }
    if !approve(
        ui,
        "Split this wallet?",
        "Into share files: any t of them give its words back, and sign for one account.",
        &[
            "Fewer than t tell nothing about the wallet.",
            "Nothing is kept on this device.",
        ],
        "go on",
        "back",
    ) {
        return;
    }
    let Some((n, t)) = ask_shape(ui, most) else {
        return;
    };
    let Some(purpose) = ask_kind(ui) else {
        return;
    };
    let account = match menu::ask_number(ui, HEAD, Some(("account", "empty is 0")), "number", "") {
        Some(a) if a < 0x8000_0000 => a,
        _ => return,
    };
    let Some(storage) = menu::pick_storage(ui, HEAD) else {
        return;
    };
    let Some(protect) = card::ask_protection(ui, HEAD) else {
        return;
    };
    // The split's own randomness, gathered from every chip as for a new wallet, before
    // the words are in memory.
    let Some(mut fresh) = Fresh::gather(gate, ui, pool) else {
        return;
    };

    // The words, and the account key from them, with no passphrase (refused above).
    let (mut entropy, len) = match menu::seed_entropy(gate, login, ui.panel, HEAD) {
        Ok(e) => e,
        Err(why) => return say(ui, HEAD, why, "nothing was split"),
    };
    // The same wallet's master, by the path every other screen takes to it: the words of
    // the wallet in force, stretched with no passphrase (refused above).
    let master = match menu::master_quietly(gate, login, ui.panel, HEAD) {
        Ok(m) => m,
        Err(why) => {
            entropy.zeroize();
            return say(ui, HEAD, why, "nothing was split");
        }
    };
    let coin = crate::prefs::network().coin_type();
    let steps =
        [purpose, coin, account].map(|i| ChildNumber::hardened(i).unwrap_or(ChildNumber(0)));
    let raw = steps.map(|c| c.0);
    let account_key = crate::keywork::run(|kw| {
        let path = DerivationPath::from_slice(&steps).ok()?;
        let acct = master.derive_path(&path, kw).ok()?;
        let fp = master.fingerprint(kw);
        Some(AccountKey::new(
            acct.secret_bytes(),
            &acct.chain_code,
            fp,
            &raw,
        ))
    });
    drop(master);
    let Some(account_key) = account_key else {
        entropy.zeroize();
        return say(ui, HEAD, "cannot derive the account", "nothing was split");
    };

    let mut busy = Some(menu::blocking_screen(ui.panel, HEAD, "making the shares"));
    let made = crate::keywork::run(|kw| {
        let bundles = catcard_tss::export(&entropy[..len], &account_key, n, t, &mut fresh, kw)?;
        // A split is a backup only if it adds back up: the first t give the words.
        let refs: alloc::vec::Vec<&ShareBundle> = bundles.iter().take(usize::from(t)).collect();
        let back = catcard_tss::restore_entropy(&refs, kw)?;
        let same = back.as_slice() == &entropy[..len];
        Ok::<_, catcard_tss::Error>((bundles, same))
    });
    busy.take();
    entropy.zeroize();
    drop(account_key);
    drop(fresh);
    let bundles = match made {
        Ok((b, true)) => b,
        Ok((_, false)) => {
            crate::catlog!("tss: export did not add back up; refused");
            return say(ui, HEAD, "the shares do not", "add back up");
        }
        Err(e) => return say(ui, HEAD, "cannot split:", describe(&e)),
    };
    let fp = hex4(bundles[0].record().fingerprint());
    crate::catlog!("tss: wallet {} split {}-of-{}", fp.as_str(), t, n);

    let mut written = 0u8;
    for b in bundles.iter() {
        if write_one(ui, storage, b, &fp, &protect) {
            written += 1;
        }
    }
    drop(bundles);
    let mut a: Line = Line::new();
    let _ = write!(a, "{written} of {n} files written");
    let mut b: Line = Line::new();
    let _ = write!(b, "any {t} restore it");
    say(ui, HEAD, &a, &b);
}

/// `n` and `t` for an export: any `2 <= t <= n` the memory allows.
#[inline(never)]
fn ask_shape(ui: &mut Ui<'_>, most: u8) -> Option<(u8, u8)> {
    let mut range: heapless::String<16> = heapless::String::new();
    let _ = write!(range, "2 to {most}");
    let n = match menu::ask_number(ui, HEAD, Some(("shares", &range)), "how many", "")? {
        n if (2..=u32::from(most)).contains(&n) => n as u8,
        _ => {
            say(ui, HEAD, "shares must be", &range);
            return None;
        }
    };
    let mut range: heapless::String<16> = heapless::String::new();
    let _ = write!(range, "2 to {n}");
    let t = match menu::ask_number(ui, HEAD, Some(("needed", &range)), "how many", "")? {
        t if (2..=u32::from(n)).contains(&t) => t as u8,
        _ => {
            say(ui, HEAD, "needed must be", &range);
            return None;
        }
    };
    if t == n {
        menu::ask(ui.panel, HEAD, "EVERY share needed:", "lose one, lose all");
        if !menu::confirmed(ui) {
            return None;
        }
    }
    Some((n, t))
}

/// The address type: BIP-44's purpose for it.
#[inline(never)]
fn ask_kind(ui: &mut Ui<'_>) -> Option<u32> {
    const WHY: &str = "Why not Taproot?";
    loop {
        let rows = [KINDS[0].0, KINDS[1].0, KINDS[2].0, WHY];
        let pick = menu::pick_row(ui, HEAD, "the shares sign for", &rows)?;
        if let Some(&(_, purpose)) = KINDS.get(pick) {
            return Some(purpose);
        }
        say(
            ui,
            "No Taproot",
            "shared keys sign ECDSA;",
            "Taproot needs Schnorr",
        );
    }
}

/// Write bundle `b` to the card in the slot, after asking for it. Whether it was written.
#[inline(never)]
fn write_one(
    ui: &mut Ui<'_>,
    storage: Storage,
    b: &ShareBundle,
    fp: &str,
    protect: &card::Protect,
) -> bool {
    let (m, n) = (b.member(), b.n());
    let mut head: heapless::String<24> = heapless::String::new();
    let _ = write!(head, "Share {m} of {n}");
    let mut name: heapless::String<40> = heapless::String::new();
    let _ = write!(name, "tss-{fp}-{m}of{n}.7z");
    let mut inner: heapless::String<24> = heapless::String::new();
    let _ = write!(inner, "share-{m}of{n}.tss");
    loop {
        let note = match storage {
            Storage::Vdisk => "to the Virtual Disk",
            Storage::Sd if m == 1 => "insert the card for it",
            Storage::Sd => "insert its card, or keep this one",
        };
        match menu::pick_row(ui, &head, note, &["Write it", "Skip this share"]) {
            Some(0) => {}
            _ => {
                menu::ask(ui.panel, &head, "skip it? it cannot", "be written later");
                if menu::confirmed(ui) {
                    return false;
                }
                continue;
            }
        }
        let mut busy = Some(menu::blocking_screen(ui.panel, &head, "preparing the file"));
        let bytes = crate::keywork::run(|kw| b.to_bytes(kw));
        busy.take();
        let bytes = match bytes {
            Ok(x) => x,
            Err(e) => {
                say(ui, &head, "cannot write it:", describe(&e));
                return false;
            }
        };
        match card::write_share(ui, storage, &head, &name, &inner, &bytes, protect) {
            Ok(()) => {
                crate::catlog!("tss: share {} of {} written", m, n);
                say(ui, &head, "written as", &name);
                return true;
            }
            Err(why) => say(ui, &head, "not written:", why),
        }
    }
}
