//! BIP-85: children of the seed, shown -- and the ones that are keys, put in force.
//!
//! The seed is backed up once; everything else comes out of it on demand. This screen
//! derives one child, shows it, and for the three that are wallets -- words, an XPRV, a
//! WIF key -- offers to work in it. Nothing is stored: the same seed gives the same child
//! again whenever it is asked for.
//!
//! Every child comes from the **root** without its passphrase ([`menu::bip85_parent`]),
//! whichever wallet is in force when it is asked for. So the child shown here is the one
//! the key menu loads, and the same one again from anywhere.
//!
//! A child is shown, not exported to a card. What is on screen here -- words, a key, a
//! password -- is the whole secret of another wallet or another account, and writing it to
//! removable media is a decision with different consequences from writing a descriptor.
//! Copying it down is the owner's move to make.

use catcard_callgate::Callgate;
use catcard_wallet::bip85;
use core::fmt::Write as _;
use zeroize::{Zeroize, Zeroizing};

use crate::display;
use crate::menu;
use crate::ui::Ui;

const HEAD: &str = "BIP-85";

/// What can be derived.
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
enum Kind {
    /// A BIP-39 phrase of this many words.
    Words(u32),
    Xprv,
    Wif,
    Password,
    Hex32,
}

/// The list, in the order it is shown. Every word count BIP-39 defines: the BIP names 12,
/// 18 and 24, and 15 and 21 derive by the same rule -- fewer wallets will reproduce them.
const ROWS: &[&str] = &[
    "12 words",
    "15 words",
    "18 words",
    "21 words",
    "24 words",
    "XPRV",
    "WIF key",
    "Password",
    "32 bytes hex",
];
const KINDS: [Kind; 9] = [
    Kind::Words(12),
    Kind::Words(15),
    Kind::Words(18),
    Kind::Words(21),
    Kind::Words(24),
    Kind::Xprv,
    Kind::Wif,
    Kind::Password,
    Kind::Hex32,
];
const _: () = assert!(ROWS.len() == KINDS.len());

impl Kind {
    /// The BIP-85 path this uses, for the screen to show.
    fn path(self, index: u32) -> heapless::String<48> {
        let mut s = heapless::String::new();
        let _ = match self {
            Kind::Words(n) => write!(s, "m/83696968h/39h/0h/{n}h/{index}h"),
            Kind::Xprv => write!(s, "m/83696968h/32h/{index}h"),
            Kind::Wif => write!(s, "m/83696968h/2h/{index}h"),
            Kind::Password => write!(s, "m/83696968h/707764h/21h/{index}h"),
            Kind::Hex32 => write!(s, "m/83696968h/128169h/32h/{index}h"),
        };
        s
    }
}

/// A child the owner chose to work in. Wiped when dropped.
pub(crate) enum Chosen {
    /// Words: loaded by their place in the tree, as [`crate::key::Source::Bip85`], and
    /// derived again from the root whenever a screen needs the seed.
    Words { words: u32, index: u32 },
    /// An XPRV: the chain code, then the key.
    Xprv { chain_code: [u8; 32], key: [u8; 32] },
    /// A WIF key.
    Wif { key: [u8; 32] },
}

impl Drop for Chosen {
    fn drop(&mut self) {
        match self {
            Chosen::Words { .. } => {}
            Chosen::Xprv { chain_code, key } => {
                chain_code.zeroize();
                key.zeroize();
            }
            Chosen::Wif { key } => key.zeroize(),
        }
    }
}

/// Characters the longest answer needs: a 24-word phrase.
const MAX_OUT: usize = catcard_wallet::bip39::MAX_PHRASE_LEN;

/// What a child is written as, and the key it is if it is one.
type Derived = (Zeroizing<[u8; MAX_OUT]>, usize, Option<Chosen>);

/// Pick a child, derive it and show it. `Some` if the owner chose to work in it.
pub(crate) fn bip85(
    gate: &Callgate,
    login: &mut catcard_pin::Login,
    ui: &mut Ui<'_>,
) -> Option<Chosen> {
    let (row, index) = loop {
        let row = menu::pick_row(ui, HEAD, "derive a child", ROWS)?;
        // Backing out of the index goes back to the list, not out of BIP-85: they are a
        // pair, and getting the second wrong should not cost the first.
        if let Some(index) = menu::ask_index(ui, HEAD, ROWS[row]) {
            break (row, index);
        }
    };
    let kind = KINDS[row];

    let master = match menu::bip85_parent(gate, login, ui.panel, HEAD) {
        Ok(m) => m,
        Err(why) => {
            menu::message(ui.panel, HEAD, why, "any key to go back");
            menu::wait_for_any_key(ui);
            return None;
        }
    };
    // Derived and written out inside one masked region: what comes out is a secret in its
    // own right, and the derivation is private-key work.
    let derived = crate::keywork::run(|kw| derive(&master, kind, index, kw));
    drop(master);

    let (text, len, chosen) = match derived {
        Ok(d) => d,
        Err(why) => {
            crate::catlog!("bip85: {} at {}: {}", ROWS[row], index, why);
            menu::message(ui.panel, HEAD, why, "any key to go back");
            menu::wait_for_any_key(ui);
            return None;
        }
    };
    crate::catlog!("bip85: {} at index {}", ROWS[row], index);
    let text = core::str::from_utf8(&text[..len]).unwrap_or("");
    let take = show(ui, kind, ROWS[row], index, text, chosen.is_some());
    chosen.filter(|_| take)
}

fn derive(
    master: &catcard_wallet::bip32::ExtendedPrivKey,
    kind: Kind,
    index: u32,
    kw: &catcard_wallet::KeyWork,
) -> Result<Derived, &'static str> {
    const BAD: &str = "could not derive it";
    let mut buf = Zeroizing::new([0u8; MAX_OUT]);
    let out = &mut buf[..];
    let (len, chosen) = match kind {
        Kind::Words(words) => {
            let (entropy, n) = bip85::words_entropy(master, words, index, kw).map_err(|_| BAD)?;
            let mnemonic =
                catcard_wallet::bip39::Mnemonic::from_entropy(&entropy.as_bytes()[..n], kw)
                    .map_err(|_| BAD)?;
            (mnemonic.render(out), Some(Chosen::Words { words, index }))
        }
        Kind::Xprv => {
            let child = bip85::xprv(master, index, kw).map_err(|_| BAD)?;
            let len = child.write_base58(out, kw).map_err(|_| BAD)?;
            let chosen = Chosen::Xprv {
                chain_code: child.chain_code,
                key: *child.secret_bytes(),
            };
            (len, Some(chosen))
        }
        Kind::Wif => {
            let chosen = Chosen::Wif {
                key: bip85::wif_secret(master, index, kw).map_err(|_| BAD)?,
            };
            let Chosen::Wif { key } = &chosen else {
                return Err(BAD);
            };
            (
                bip85::encode_wif(key, out, kw).map_err(|_| BAD)?,
                Some(chosen),
            )
        }
        Kind::Password => (
            bip85::password(master, 21, index, out, kw).map_err(|_| BAD)?,
            None,
        ),
        Kind::Hex32 => (
            bip85::hex(master, 32, index, out, kw).map_err(|_| BAD)?,
            None,
        ),
    };
    Ok((buf, len, chosen))
}

/// Show the child, scrollable. True if the owner chose to work in it -- offered only when
/// `loadable`, since a password or a hex string is not a wallet.
fn show(ui: &mut Ui<'_>, kind: Kind, label: &str, index: u32, text: &str, loadable: bool) -> bool {
    use catcard_ui::scroll::{Line, ScrollView};
    let path = kind.path(index);
    let mut hint = heapless::String::<48>::new();
    if loadable {
        let _ = write!(
            hint,
            "{} work in it   {} back",
            display::CONFIRM_KEY,
            display::CANCEL_KEY
        );
    } else {
        let _ = hint.push_str("write it down; it is not stored");
    }
    let mut doc: heapless::Vec<Line, 8> = heapless::Vec::new();
    let _ = doc.push(Line::title(label));
    let _ = doc.push(Line::body(text).wrapped());
    let _ = doc.push(Line::body(path.as_str()).small().wrapped());
    let _ = doc.push(Line::body(hint.as_str()).small().wrapped());
    let mut view = ScrollView::build(&doc, display::SCREEN_W, display::SCREEN_H, display::FONTS);
    menu::scroll_choice(ui, &mut view) && loadable
}
