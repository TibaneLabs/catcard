//! Which chains the wallet in force shows, and in what order.
//!
//! The list is `"chains"` in **that wallet's own** settings file
//! ([`catcard_settings::chains`]) -- each key its own list, as each key has its own vault:
//! a BIP-85 child kept for one coin should not offer eight others. Read once per key and
//! kept until the key changes ([`forget`]). Absent means every chain the build carries,
//! in the build's order. A ticker this build does not carry is skipped.
//! A list that names none of this build's chains is treated as absent: a picker with
//! nothing in it would be a dead end with no way out but the back key.
//!
//! The mk3 has no settings store, so it shows every chain.

use catcard_wallet::chain::{self, Chain};

use crate::ui::Ui;

/// Chains held at once. More than any build carries.
pub const MAX: usize = 16;

/// The list, once read for the key in force. Foreground only, single core.
static mut ENABLED: Option<heapless::Vec<&'static Chain, MAX>> = None;

/// Forget the list: the key changed, and its list is in a different file.
pub(crate) fn forget() {
    // SAFETY: foreground only, single core.
    unsafe { *core::ptr::addr_of_mut!(ENABLED) = None };
}

/// The chains to offer, in order.
pub(crate) fn enabled(
    gate: &catcard_callgate::Callgate,
    login: &mut catcard_pin::Login,
    ui: &mut Ui<'_>,
) -> heapless::Vec<&'static Chain, MAX> {
    // SAFETY: foreground only; the borrow ends within this statement.
    if let Some(list) = unsafe { (*core::ptr::addr_of!(ENABLED)).clone() } {
        return list;
    }
    let list = read(gate, login, ui).unwrap_or_else(all);
    crate::catlog!("chains: {} offered", list.len());
    // SAFETY: as above.
    unsafe { *core::ptr::addr_of_mut!(ENABLED) = Some(list.clone()) };
    list
}

/// Every chain the build carries.
fn all() -> heapless::Vec<&'static Chain, MAX> {
    chain::SUPPORTED.iter().take(MAX).collect()
}

/// The owner's list, or `None` for "all of them".
#[cfg(not(feature = "board-mk3"))]
fn read(
    gate: &catcard_callgate::Callgate,
    login: &mut catcard_pin::Login,
    ui: &mut Ui<'_>,
) -> Option<heapless::Vec<&'static Chain, MAX>> {
    use catcard_settings::json::Doc;
    use catcard_settings::store::{self, SCRATCH};

    let key = match crate::settings::wallet_key(gate, login, ui.panel, "Addresses") {
        Ok(k) => k,
        Err(why) => {
            crate::catlog!("chains: no settings key: {}", why);
            return None;
        }
    };
    let mut held = crate::heap::take(SCRATCH)?;
    let buf = held.bytes();
    // SAFETY: the region is mapped and readable; nothing is written.
    let mut files = unsafe { crate::settings::Files::mount_read_only() }.ok()?;
    let n = store::read(&mut files, &key, buf).ok()?;
    let doc = Doc::parse(&buf[..n]).ok()?;
    let mut tickers = [""; catcard_settings::chains::MAX];
    let count = catcard_settings::chains::list(&doc, &mut tickers)?;
    let mut out: heapless::Vec<&'static Chain, MAX> = heapless::Vec::new();
    for t in &tickers[..count] {
        match chain::by_ticker(t) {
            Some(c) if !out.iter().any(|o| o.id == c.id) => {
                let _ = out.push(c);
            }
            Some(_) => {}
            None => crate::catlog!("chains: {} is not in this build", t),
        }
    }
    (!out.is_empty()).then_some(out)
}

#[cfg(feature = "board-mk3")]
fn read(
    _gate: &catcard_callgate::Callgate,
    _login: &mut catcard_pin::Login,
    _ui: &mut Ui<'_>,
) -> Option<heapless::Vec<&'static Chain, MAX>> {
    None
}

/// Save the list, and make it the one in force.
///
/// The order is the order shown, and only the enabled chains are written: a list is what
/// a wallet *offers*, so leaving a chain out is how it is turned off. An empty list would
/// read back as "absent" and mean every chain (see the module note), so the one thing
/// this refuses is turning them all off.
#[cfg(all(feature = "multichain", not(feature = "board-mk3")))]
pub(crate) fn save(
    gate: &catcard_callgate::Callgate,
    login: &mut catcard_pin::Login,
    ui: &mut Ui<'_>,
    order: &[(&'static Chain, bool)],
) -> Result<(), &'static str> {
    use catcard_settings::store::SCRATCH;

    let mut tickers: heapless::Vec<&str, MAX> = heapless::Vec::new();
    for (c, _) in order.iter().filter(|(_, on)| *on) {
        let _ = tickers.push(c.ticker);
    }
    if tickers.is_empty() {
        return Err("at least one chain has to stay on");
    }

    let mut json = [0u8; 8 + MAX * 10];
    let n = catcard_settings::chains::render(&tickers, &mut json).ok_or("too many chains")?;
    let raw = core::str::from_utf8(&json[..n]).map_err(|_| "bad list")?;

    crate::menu::blocking_screen(ui.panel, "Chains", "saving");
    let (Some(mut doc), Some(mut seal)) = (crate::heap::take(SCRATCH), crate::heap::take(SCRATCH))
    else {
        return Err("not enough memory to save");
    };
    crate::settings::save_wallet(
        gate,
        login,
        ui,
        "Chains",
        (catcard_settings::chains::KEY, raw),
        doc.bytes(),
        seal.bytes(),
    )?;
    // What is in force now is what was just written, so the cached copy is stale.
    forget();
    Ok(())
}

/// Every chain the build carries, with the ones in force first and in their own order.
///
/// The editor's starting state. The stored list names only what is offered, so anything
/// missing from it is a chain that is off -- and those follow in the registry's order, so
/// turning one on puts it somewhere predictable.
#[cfg(all(feature = "multichain", not(feature = "board-mk3")))]
pub(crate) fn order(
    gate: &catcard_callgate::Callgate,
    login: &mut catcard_pin::Login,
    ui: &mut Ui<'_>,
) -> heapless::Vec<(&'static Chain, bool), MAX> {
    let on = enabled(gate, login, ui);
    let mut out: heapless::Vec<(&'static Chain, bool), MAX> = heapless::Vec::new();
    for c in on.iter() {
        let _ = out.push((c, true));
    }
    for c in chain::SUPPORTED.iter() {
        if !out.iter().any(|(k, _)| k.id == c.id) {
            let _ = out.push((c, false));
        }
    }
    out
}
