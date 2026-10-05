//! Play TSS members from a computer, for testing the device's TSS screens with fewer
//! CatCards than members (docs/TSS.md, "Testing").
//!
//! The members run here read and write the same files a CatCard does (`TSS/<session>/`,
//! `invite.txt`, `r<round>-<from>-<to>.msg`), in a folder: an SD card in a reader, or a
//! CatCard's Virtual Disk mounted over USB. Between visits the tool waits while the card
//! goes to the device and back.
//!
//! **Test wallets only.** A share made here lives on a computer, in the clear in
//! `--keep`: it is no better than the computer. Never put funds on a wallet a member of
//! which ran here.

use anyhow::{Context, Result, anyhow, bail};
use catcard_tss::{
    CacheKey, Entropy, NoEntropy, SESSION_ID_LEN, Session, ShareRecord, Status, file_name,
    session_dir,
};
use catcard_wallet::KeyWork;
use clap::{Parser, Subcommand};
use std::fs;
use std::io::{BufRead, Read, Write};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{Duration, Instant};

const KW: KeyWork = KeyWork::host();
/// What seals the pair caches kept here. A fixed key: these are test wallets.
const HOST_CACHE_ROOT: [u8; 32] = *b"catcard tss-member: test only!!!";

#[derive(Parser)]
#[command(about = "Play TSS members from a computer (test wallets only)")]
struct Cli {
    /// The folder the card or Virtual Disk is mounted at (it holds, or will hold, `TSS/`).
    #[arg(long)]
    dir: PathBuf,
    /// Where the members run here keep their shares and pair caches.
    #[arg(long, default_value = "tss-keep")]
    keep: PathBuf,
    /// Eject the volume before each wait, and wait for it to come back after.
    #[arg(long)]
    eject: bool,
    /// Answer the session-code question with yes (the words are still printed).
    #[arg(long)]
    yes: bool,
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Create a wallet together. Joins the session on the medium, or starts one with
    /// `--start N T` (then member 1 runs here).
    Create {
        /// Member numbers to run here, e.g. `2,3`.
        #[arg(long = "as", value_delimiter = ',', required = true)]
        members: Vec<u8>,
        /// Start a session of N members, T needed, instead of joining one.
        #[arg(long, num_args = 2, value_names = ["N", "T"])]
        start: Option<Vec<u8>>,
    },
    /// Set up every pair between a member kept here and other members again, in one
    /// session (the device's "Rebuild setup").
    Pair {
        /// The member kept here.
        #[arg(long = "as")]
        me: u8,
        /// The other members taking part, e.g. `1,3` -- the same set the starting device
        /// ticked.
        #[arg(long, value_delimiter = ',', required = true)]
        with: Vec<u8>,
        /// Start the session (otherwise join the one on the medium).
        #[arg(long)]
        start: bool,
        /// The wallet, by the first 8 hex digits of its fingerprint as `show` lists it;
        /// optional when only one is kept.
        #[arg(long)]
        wallet: Option<String>,
    },
    /// The wallets and members kept here.
    Show,
}

/// The computer's randomness.
struct Os;

impl Entropy for Os {
    fn fill(&mut self, out: &mut [u8]) -> Result<(), NoEntropy> {
        fs::File::open("/dev/urandom")
            .and_then(|mut f| f.read_exact(out))
            .map_err(|_| NoEntropy)
    }
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    match &cli.cmd {
        Cmd::Create { members, start } => create(&cli, members, start.as_deref()),
        Cmd::Pair {
            me,
            with,
            start,
            wallet,
        } => pair(&cli, *me, with, *start, wallet.as_deref()),
        Cmd::Show => show(&cli),
    }
}

// --- the medium ---------------------------------------------------------------------

fn invite_text(n: u8, t: u8) -> String {
    format!("CatCard TSS session\nmembers {n}\nneeded {t}\n")
}

fn pair_invite_text(wallet: &[u8; 32], members: &[u8]) -> String {
    let list: Vec<String> = members.iter().map(|m| m.to_string()).collect();
    format!(
        "CatCard TSS pair setup\nwallet {}\nmembers {}\n",
        hex::encode(&wallet[..8]),
        list.join(" ")
    )
}

/// The sessions on the medium: (id, invitation text).
fn sessions(dir: &Path) -> Vec<([u8; SESSION_ID_LEN], String)> {
    let mut out = Vec::new();
    let Ok(rd) = fs::read_dir(dir.join("TSS")) else {
        return out;
    };
    for e in rd.flatten() {
        let name = e.file_name().to_string_lossy().to_ascii_lowercase();
        let Ok(bytes) = hex::decode(&name) else {
            continue;
        };
        let Ok(id) = <[u8; SESSION_ID_LEN]>::try_from(bytes.as_slice()) else {
            continue;
        };
        if let Ok(text) = fs::read_to_string(e.path().join("invite.txt")) {
            out.push((id, text.replace("\r\n", "\n")));
        }
    }
    out
}

/// A FAT volume hands names back in whatever case it holds; find `name` regardless.
fn find(dir: &Path, name: &str) -> Option<PathBuf> {
    let p = dir.join(name);
    if p.exists() {
        return Some(p);
    }
    fs::read_dir(dir)
        .ok()?
        .flatten()
        .find(|e| e.file_name().to_string_lossy().eq_ignore_ascii_case(name))
        .map(|e| e.path())
}

fn write_synced(path: &Path, bytes: &[u8]) -> Result<()> {
    let mut f = fs::File::create(path).with_context(|| format!("writing {}", path.display()))?;
    f.write_all(bytes)?;
    f.sync_all()?;
    Ok(())
}

/// Write each hosted session's outbox, read what each waits for, compare codes, until
/// nothing moves. `(moved anything, still waiting for (member, from))`.
fn step(cli: &Cli, sessions: &mut [Session], folder: &Path) -> Result<bool> {
    let mut any = false;
    for _ in 0..64 {
        let mut moved = false;
        for s in sessions.iter_mut() {
            let out = s.take_outbox();
            for o in out {
                let name = o.file_name();
                println!("  member {}: writes {name}", s.me());
                write_synced(&folder.join(&name), &o.bytes)?;
                moved = true;
            }
            match s.status() {
                Status::Failed => bail!(
                    "member {}: the session failed: {}",
                    s.me(),
                    s.failure().unwrap_or("?")
                ),
                Status::Comparing => {
                    let words = s.code().expect("comparing").words().join(" ");
                    println!("\n  member {}: session code\n\n      {words}\n", s.me());
                    if !cli.yes && !ask("  the same words as on the device (or written down)?")? {
                        bail!("the session code differs: stopped");
                    }
                    s.confirm(&KW).map_err(|e| anyhow!("confirm: {e:?}"))?;
                    moved = true;
                    continue;
                }
                _ => {}
            }
            for (r, f, t) in s.awaiting() {
                let name = file_name(r, f, t);
                if let Some(p) = find(folder, &name) {
                    let bytes = fs::read(&p)?;
                    println!("  member {}: reads {name}", s.me());
                    s.receive(&bytes, &KW)
                        .map_err(|e| anyhow!("member {}: {name} refused: {e:?}", s.me()))?;
                    moved = true;
                }
            }
        }
        any |= moved;
        if !moved {
            return Ok(any);
        }
    }
    bail!("sessions did not settle")
}

/// Run `sessions` over the medium to the end, waiting for the device between visits.
fn drive(cli: &Cli, sessions: &mut [Session], id: &[u8; SESSION_ID_LEN]) -> Result<()> {
    let rel = session_dir(id);
    loop {
        let folder = find_rel(&cli.dir, &rel).context("the session's folder is gone")?;
        step(cli, sessions, &folder)?;
        if sessions.iter().all(|s| s.status() == Status::Finished) {
            return Ok(());
        }
        let mut from: Vec<u8> = sessions
            .iter()
            .flat_map(|s| s.awaiting().into_iter().map(|w| w.1))
            .collect();
        from.sort();
        from.dedup();
        println!(
            "\nwaiting for member(s) {from:?}: give the {} to them, and bring it back here.",
            if cli.eject { "card" } else { "files" }
        );
        hand_over(cli)?;
    }
}

/// `rel` (`TSS/<hex>`) under `dir`, matching names in any case.
fn find_rel(dir: &Path, rel: &str) -> Option<PathBuf> {
    let mut p = dir.to_path_buf();
    for part in rel.split('/') {
        p = find(&p, part)?;
    }
    Some(p)
}

/// The medium leaves and comes back.
fn hand_over(cli: &Cli) -> Result<()> {
    if cli.eject {
        let _ = Command::new("sync").status();
        let st = Command::new("diskutil")
            .arg("eject")
            .arg(&cli.dir)
            .status()
            .context("diskutil")?;
        if !st.success() {
            println!("(could not eject {}; eject it by hand)", cli.dir.display());
        }
        println!("press Enter once the card is back in this computer.");
        wait_enter()?;
        let start = Instant::now();
        while !cli.dir.exists() {
            if start.elapsed() > Duration::from_secs(120) {
                bail!("{} did not come back", cli.dir.display());
            }
            std::thread::sleep(Duration::from_millis(500));
        }
        // Let the volume settle before reading it.
        std::thread::sleep(Duration::from_secs(1));
    } else {
        println!("press Enter once the files are back.");
        wait_enter()?;
    }
    Ok(())
}

fn wait_enter() -> Result<()> {
    let mut l = String::new();
    std::io::stdin().lock().read_line(&mut l)?;
    Ok(())
}

fn ask(q: &str) -> Result<bool> {
    print!("{q} [y/N] ");
    std::io::stdout().flush()?;
    let mut l = String::new();
    std::io::stdin().lock().read_line(&mut l)?;
    Ok(matches!(l.trim(), "y" | "Y" | "yes"))
}

// --- what is kept here --------------------------------------------------------------

fn record_path(cli: &Cli, r: &ShareRecord) -> PathBuf {
    cli.keep.join(format!(
        "{}-m{}.share",
        hex::encode(&r.wallet_id()[..8]),
        r.member()
    ))
}

fn save(cli: &Cli, r: &mut ShareRecord) -> Result<()> {
    fs::create_dir_all(&cli.keep)?;
    let key = CacheKey::new(&HOST_CACHE_ROOT, r, &KW);
    let mut iv = [0u8; 16];
    Os.fill(&mut iv).map_err(|_| anyhow!("no randomness"))?;
    let cache = r
        .write_pair_cache(&key, &iv, &KW)
        .map_err(|e| anyhow!("pair cache: {e:?}"))?;
    let path = record_path(cli, r);
    write_synced(&path.with_extension("pairs"), &cache)?;
    let core = r.to_bytes(&KW).map_err(|e| anyhow!("record: {e:?}"))?;
    write_synced(&path, &core)?;
    println!("  kept {}", path.display());
    Ok(())
}

fn load(path: &Path) -> Result<ShareRecord> {
    let core = fs::read(path)?;
    let mut r = ShareRecord::from_bytes(&core, &KW).map_err(|e| anyhow!("{e:?}"))?;
    if let Ok(mut cache) = fs::read(path.with_extension("pairs")) {
        let key = CacheKey::new(&HOST_CACHE_ROOT, &r, &KW);
        r.read_pair_cache(&mut cache, &key, &KW)
            .map_err(|e| anyhow!("pair cache: {e:?}"))?;
    }
    Ok(r)
}

fn kept(cli: &Cli) -> Result<Vec<(PathBuf, ShareRecord)>> {
    let mut out = Vec::new();
    let Ok(rd) = fs::read_dir(&cli.keep) else {
        return Ok(out);
    };
    for e in rd.flatten() {
        let p = e.path();
        if p.extension().is_some_and(|x| x == "share") {
            out.push((p.clone(), load(&p)?));
        }
    }
    out.sort_by(|a, b| a.0.cmp(&b.0));
    Ok(out)
}

fn describe(r: &ShareRecord) -> String {
    format!(
        "wallet {} ({}-of-{}), member {}, pairs with {:?}, key {}",
        hex::encode(r.fingerprint()),
        r.t(),
        r.n(),
        r.member(),
        r.pairs(),
        hex::encode(r.joint_public_key())
    )
}

// --- commands -----------------------------------------------------------------------

fn create(cli: &Cli, members: &[u8], start: Option<&[u8]>) -> Result<()> {
    let (id, n, t) = match start {
        Some(&[n, t]) => {
            if !members.contains(&1) {
                bail!("the member who starts is member 1: add 1 to --as");
            }
            let id = catcard_tss::new_session_id(&mut Os).map_err(|e| anyhow!("{e:?}"))?;
            let folder = cli.dir.join(session_dir(&id));
            fs::create_dir_all(&folder)?;
            write_synced(&folder.join("invite.txt"), invite_text(n, t).as_bytes())?;
            println!("started session {} ({t}-of-{n})", hex::encode(&id[..4]));
            (id, n, t)
        }
        Some(_) => unreachable!("clap takes two values"),
        None => {
            let found: Vec<_> = sessions(&cli.dir)
                .into_iter()
                .filter_map(|(id, text)| {
                    let mut l = text.lines();
                    if l.next()? != "CatCard TSS session" {
                        return None;
                    }
                    let (mut n, mut t) = (None, None);
                    for x in l {
                        if let Some(v) = x.strip_prefix("members ") {
                            n = v.trim().parse::<u8>().ok();
                        } else if let Some(v) = x.strip_prefix("needed ") {
                            t = v.trim().parse::<u8>().ok();
                        }
                    }
                    Some((id, n?, t?))
                })
                .collect();
            match found.as_slice() {
                [one] => {
                    println!(
                        "joining session {} ({}-of-{})",
                        hex::encode(&one.0[..4]),
                        one.2,
                        one.1
                    );
                    *one
                }
                [] => bail!(
                    "no session on {}: start one on the device",
                    cli.dir.display()
                ),
                _ => bail!("several sessions on the medium: remove the old TSS folders"),
            }
        }
    };
    let mut sessions = members
        .iter()
        .map(|&m| {
            Session::keygen(id, n, t, m, &mut Os, &KW).map_err(|e| anyhow!("member {m}: {e:?}"))
        })
        .collect::<Result<Vec<_>>>()?;
    drive(cli, &mut sessions, &id)?;
    println!();
    for s in sessions.iter_mut() {
        let mut r = s.take_share(&KW).context("finished with no share")?;
        println!("member {}: {}", s.me(), describe(&r));
        save(cli, &mut r)?;
    }
    println!("\nthe device shows the same wallet fingerprint and key: compare them.");
    if cli.eject {
        println!("the device(s) still on a step need the card: give it to them.");
    }
    Ok(())
}

fn pair(cli: &Cli, me: u8, with: &[u8], start: bool, wallet: Option<&str>) -> Result<()> {
    let all = kept(cli)?;
    let mut mine: Vec<_> = all
        .into_iter()
        .filter(|(_, r)| r.member() == me)
        .filter(|(_, r)| wallet.is_none_or(|w| hex::encode(r.fingerprint()).starts_with(w)))
        .collect();
    let (_, mut record) = match mine.len() {
        1 => mine.remove(0),
        0 => bail!("no member {me} kept in {}", cli.keep.display()),
        _ => bail!("several wallets kept with member {me}: say which with --wallet"),
    };
    let mut members: Vec<u8> = with.to_vec();
    members.push(me);
    members.sort_unstable();
    members.dedup();
    let wid = record.wallet_id();
    let want = pair_invite_text(&wid, &members);
    let id = if start {
        let id = catcard_tss::new_session_id(&mut Os).map_err(|e| anyhow!("{e:?}"))?;
        let folder = cli.dir.join(session_dir(&id));
        fs::create_dir_all(&folder)?;
        write_synced(&folder.join("invite.txt"), want.as_bytes())?;
        println!(
            "started pair setup {} with members {:?}",
            hex::encode(&id[..4]),
            members
        );
        id
    } else {
        // Several when an earlier try was abandoned: the newest is the one just started.
        let mut found: Vec<_> = sessions(&cli.dir)
            .into_iter()
            .filter(|(_, t)| *t == want)
            .map(|(id, _)| {
                let at = find_rel(&cli.dir, &session_dir(&id))
                    .and_then(|p| fs::metadata(p.join("invite.txt")).ok())
                    .and_then(|m| m.modified().ok());
                (at, id)
            })
            .collect();
        found.sort();
        match found.pop() {
            Some((_, id)) => id,
            None => bail!("no pair setup for members {members:?} on the medium: start one"),
        }
    };
    let mut s =
        [Session::pairs_setup(id, &record, &members, &mut Os, &KW)
            .map_err(|e| anyhow!("{e:?}"))?];
    drive(cli, &mut s, &id)?;
    let peers = s[0]
        .install_pairs(&mut record, &KW)
        .map_err(|e| anyhow!("{e:?}"))?;
    println!(
        "member {me}: pairs with {peers:?} set up again; {}",
        describe(&record)
    );
    save(cli, &mut record)
}

fn show(cli: &Cli) -> Result<()> {
    for (p, r) in kept(cli)? {
        println!("{}: {}", p.display(), describe(&r));
    }
    Ok(())
}
