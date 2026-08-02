//! `catcard-image` — build, sign, verify and package CatCard firmware images.
//!
//! The bootloader below our firmware is unreplaceable and enforces a fixed image
//! format: a 128-byte header at offset 0x3F80, a double-SHA256 digest over the whole
//! image except the signature slot, and a secp256k1 signature from one of six
//! compiled-in keys. This tool is the only thing in the tree that produces images in
//! that format.
//!
//! Typical use:
//!
//! ```text
//! cargo fw-mk4
//! catcard-image build --board mk4 \
//!     target/thumbv7em-none-eabihf/release/catcard-fw \
//!     --version 0.0.1 --dfu out/catcard-mk4.dfu
//! ```

mod dfuse;
mod elf;
mod image;
mod sign;

use anyhow::{bail, Context, Result};
use catcard_board::BoardSpec;
use clap::{Parser, Subcommand};
use std::path::{Path, PathBuf};

#[derive(Parser)]
#[command(name = "catcard-image", version, about, long_about = None)]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Flatten a firmware ELF, add the header, sign it, and optionally wrap as DfuSe.
    Build {
        /// Firmware ELF from `cargo fw-<board>`.
        elf: PathBuf,
        #[arg(long)]
        board: String,
        /// Version string; at most 7 ASCII characters.
        #[arg(long, default_value = "0.0.1")]
        version: String,
        /// Write the raw signed image here.
        #[arg(long)]
        bin: Option<PathBuf>,
        /// Write a DfuSe container here (this is what goes on the microSD card).
        #[arg(long)]
        dfu: Option<PathBuf>,
        /// Signing key PEM. Defaults to the published developer key.
        #[arg(long)]
        key: Option<PathBuf>,
        /// Bootloader key slot. Only 0 (the dev slot) is usable by third parties.
        #[arg(long, default_value_t = 0)]
        pubkey_num: u32,
        /// `YYYY-MM-DDTHH:MM:SS` UTC. Defaults to `SOURCE_DATE_EPOCH` or now.
        #[arg(long)]
        timestamp: Option<String>,
        /// Set the anti-downgrade high-water mark on install.
        ///
        /// IRREVERSIBLE on the device: images with an older timestamp stop being
        /// accepted by the bootloader from then on. Do not use for dev builds.
        #[arg(long)]
        high_water: bool,
        /// Override `hw_compat`. `any` accepts every board.
        #[arg(long)]
        hw_compat: Option<String>,
    },

    /// Sign (or re-sign) an assembled image in place.
    Sign {
        bin: PathBuf,
        #[arg(long)]
        key: Option<PathBuf>,
        #[arg(long, default_value_t = 0)]
        pubkey_num: u32,
        /// Write here instead of modifying the input.
        #[arg(long)]
        out: Option<PathBuf>,
    },

    /// Check an image the way the bootloader would.
    Verify {
        bin: PathBuf,
        /// Also check the image would install on this board.
        #[arg(long)]
        board: Option<String>,
    },

    /// Print the header of a `.bin` or `.dfu`.
    Info { file: PathBuf },

    /// Wrap an already-signed `.bin` as a DfuSe container.
    Dfuse {
        bin: PathBuf,
        #[arg(long)]
        board: String,
        #[arg(long)]
        out: PathBuf,
        /// USB vendor ID for the DFU suffix. Default 0xFFFF = any device.
        #[arg(long)]
        vid: Option<String>,
        #[arg(long)]
        pid: Option<String>,
    },

    /// List the boards this tool knows about.
    Boards,
}

fn main() -> Result<()> {
    match Cli::parse().cmd {
        Cmd::Build {
            elf,
            board,
            version,
            bin,
            dfu,
            key,
            pubkey_num,
            timestamp,
            high_water,
            hw_compat,
        } => cmd_build(
            &elf, &board, &version, bin, dfu, key, pubkey_num, timestamp, high_water, hw_compat,
        ),
        Cmd::Sign {
            bin,
            key,
            pubkey_num,
            out,
        } => cmd_sign(&bin, key, pubkey_num, out),
        Cmd::Verify { bin, board } => cmd_verify(&bin, board.as_deref()),
        Cmd::Info { file } => cmd_info(&file),
        Cmd::Dfuse {
            bin,
            board,
            out,
            vid,
            pid,
        } => cmd_dfuse(&bin, &board, &out, vid, pid),
        Cmd::Boards => cmd_boards(),
    }
}

fn find_board(name: &str) -> Result<&'static BoardSpec> {
    BoardSpec::by_name(name).with_context(|| {
        let known: Vec<&str> = catcard_board::spec::ALL.iter().map(|b| b.name).collect();
        format!("unknown board {name:?}; known boards: {}", known.join(", "))
    })
}

fn read_key(path: Option<PathBuf>) -> Result<String> {
    match path {
        Some(p) => std::fs::read_to_string(&p)
            .with_context(|| format!("reading signing key {}", p.display())),
        None => Ok(sign::DEV_PRIVKEY_PEM.to_string()),
    }
}

fn parse_u16(s: &str) -> Result<u16> {
    let t = s.trim_start_matches("0x").trim_start_matches("0X");
    let radix = if t.len() == s.len() { 10 } else { 16 };
    u16::from_str_radix(t, radix).with_context(|| format!("bad USB id {s:?}"))
}

#[allow(clippy::too_many_arguments)]
fn cmd_build(
    elf_path: &Path,
    board_name: &str,
    version: &str,
    bin: Option<PathBuf>,
    dfu: Option<PathBuf>,
    key: Option<PathBuf>,
    pubkey_num: u32,
    timestamp: Option<String>,
    high_water: bool,
    hw_compat: Option<String>,
) -> Result<()> {
    let board = find_board(board_name)?;
    if bin.is_none() && dfu.is_none() {
        bail!("nothing to do: pass --bin and/or --dfu");
    }

    let raw = std::fs::read(elf_path)
        .with_context(|| format!("reading firmware ELF {}", elf_path.display()))?;
    let segments =
        elf::load_segments(&raw).with_context(|| format!("parsing {}", elf_path.display()))?;
    let flat = elf::flatten(&segments, board.memory.firmware_base, image::FILL)?;

    let hw_compat_override = match hw_compat.as_deref() {
        None => None,
        Some("any") => Some(catcard_fwhdr::hw_compat::ANY),
        Some(s) => Some(
            u32::from_str_radix(
                s.trim_start_matches("0x"),
                if s.starts_with("0x") { 16 } else { 10 },
            )
            .with_context(|| format!("bad --hw-compat value {s:?}"))?,
        ),
    };

    let ts = match timestamp {
        Some(s) => image::parse_timestamp(&s)?,
        None => image::default_timestamp()?,
    };

    let mut img = image::assemble(
        flat,
        &image::BuildOptions {
            board,
            version,
            timestamp: ts,
            high_water,
            hw_compat_override,
        },
    )?;

    let pem = read_key(key)?;
    let digest = image::sign_image(&mut img, &pem, pubkey_num)?;

    println!("board         {} ({:?})", board.name, board.mcu);
    println!("firmware base {:#010x}", board.memory.firmware_base);
    println!("version       {version}");
    println!("timestamp     {} UTC", image::describe_timestamp(&ts));
    println!("length        {} bytes", img.len());
    println!(
        "hw_compat     {}",
        image::describe_hw_compat(
            catcard_fwhdr::FirmwareHeader::from_image(&img)
                .unwrap()
                .hw_compat
        )
    );
    println!("digest        {}", hex::encode(digest));
    println!(
        "pubkey_num    {pubkey_num}{}",
        if pubkey_num == 0 {
            "  (dev key: boots with a 25s warning and a red genuine light)"
        } else {
            ""
        }
    );
    if high_water {
        println!("high_water    SET — installing this makes older builds unloadable");
    }

    if let Some(p) = &bin {
        std::fs::write(p, &img).with_context(|| format!("writing {}", p.display()))?;
        println!("wrote         {}", p.display());
    }
    if let Some(p) = &dfu {
        let file = dfuse::pack(
            &format!("CatCard {}", board.name),
            &[dfuse::Element {
                address: board.memory.firmware_base,
                data: &img,
            }],
            dfuse::VID_ANY,
            dfuse::PID_ANY,
            0,
        )?;
        std::fs::write(p, &file).with_context(|| format!("writing {}", p.display()))?;
        println!("wrote         {} ({} bytes)", p.display(), file.len());
    }

    Ok(())
}

fn cmd_sign(bin: &Path, key: Option<PathBuf>, pubkey_num: u32, out: Option<PathBuf>) -> Result<()> {
    let mut img = std::fs::read(bin).with_context(|| format!("reading {}", bin.display()))?;
    let pem = read_key(key)?;
    let digest = image::sign_image(&mut img, &pem, pubkey_num)?;
    let dest = out.unwrap_or_else(|| bin.to_path_buf());
    std::fs::write(&dest, &img).with_context(|| format!("writing {}", dest.display()))?;
    println!("digest {}", hex::encode(digest));
    println!("wrote  {}", dest.display());
    Ok(())
}

fn cmd_verify(bin: &Path, board: Option<&str>) -> Result<()> {
    let img = std::fs::read(bin).with_context(|| format!("reading {}", bin.display()))?;
    let r = image::verify(&img)?;
    print_header(&r.header);
    println!("digest        {}", hex::encode(r.digest));
    match r.signature_ok {
        Some(true) => println!("signature     OK"),
        Some(false) => {
            println!("signature     BAD");
            bail!("signature does not verify; the device would refuse this image");
        }
        None => println!(
            "signature     not checkable — {}",
            r.signature_note.unwrap_or_default()
        ),
    }
    if let Some(name) = board {
        let b = find_board(name)?;
        image::ensure_installable(b, &img)?;
        println!("installable   yes, on {}", b.name);
    }
    Ok(())
}

fn cmd_info(file: &Path) -> Result<()> {
    let raw = std::fs::read(file).with_context(|| format!("reading {}", file.display()))?;

    let img = if raw.len() > 5 && &raw[0..5] == b"DfuSe" {
        let p = dfuse::unpack(&raw)?;
        println!("container     DfuSe");
        println!("target        {}", p.target_name);
        println!("usb vid:pid   {:04x}:{:04x}", p.vid, p.pid);
        for (addr, data) in &p.elements {
            println!("element       {:#010x}  {} bytes", addr, data.len());
        }
        let (_, data) = p
            .elements
            .into_iter()
            .next()
            .context("DfuSe file has no elements")?;
        data
    } else {
        println!("container     raw .bin");
        raw
    };

    let h = catcard_fwhdr::FirmwareHeader::from_image(&img).map_err(|e| anyhow::anyhow!(e))?;
    print_header(&h);
    match catcard_fwhdr::signed_digest(&img) {
        Ok(d) => println!("digest        {}", hex::encode(d)),
        Err(e) => println!("digest        unavailable: {e}"),
    }
    Ok(())
}

fn print_header(h: &catcard_fwhdr::FirmwareHeader) {
    println!("magic         {:#010x}", h.magic);
    println!("version       {}", h.version_str().unwrap_or("<non-ascii>"));
    println!(
        "timestamp     {} UTC",
        image::describe_timestamp(&h.timestamp)
    );
    println!("length        {} bytes", h.firmware_length);
    println!("hw_compat     {}", image::describe_hw_compat(h.hw_compat));
    println!(
        "install_flags {:#x}{}",
        h.install_flags,
        if h.install_flags & catcard_fwhdr::install_flags::HIGH_WATER != 0 {
            "  (HIGH_WATER)"
        } else {
            ""
        }
    );
    println!(
        "pubkey_num    {}{}",
        h.pubkey_num,
        if h.is_factory_signed() {
            "  (production key)"
        } else {
            "  (dev key)"
        }
    );
}

fn cmd_dfuse(
    bin: &Path,
    board_name: &str,
    out: &Path,
    vid: Option<String>,
    pid: Option<String>,
) -> Result<()> {
    let board = find_board(board_name)?;
    let img = std::fs::read(bin).with_context(|| format!("reading {}", bin.display()))?;

    // Refuse to package something the device will reject; the SD-card round trip is
    // slow enough that catching it here matters.
    let r = image::verify(&img)?;
    if r.signature_ok == Some(false) {
        bail!("{} is not correctly signed; sign it first", bin.display());
    }
    image::ensure_installable(board, &img)?;

    let file = dfuse::pack(
        &format!("CatCard {}", board.name),
        &[dfuse::Element {
            address: board.memory.firmware_base,
            data: &img,
        }],
        vid.as_deref()
            .map(parse_u16)
            .transpose()?
            .unwrap_or(dfuse::VID_ANY),
        pid.as_deref()
            .map(parse_u16)
            .transpose()?
            .unwrap_or(dfuse::PID_ANY),
        0,
    )?;
    std::fs::write(out, &file).with_context(|| format!("writing {}", out.display()))?;
    println!("wrote {} ({} bytes)", out.display(), file.len());
    Ok(())
}

fn cmd_boards() -> Result<()> {
    for b in catcard_board::spec::ALL {
        println!("{:<5} {:?}", b.name, b.mcu);
        println!(
            "      flash {:#010x} + {} KB   ram {:#010x} + {} KB",
            b.memory.firmware_base,
            b.memory.firmware_flash_len / 1024,
            b.memory.sram1_base,
            b.memory.sram1_len / 1024,
        );
        println!(
            "      hw_compat {:#04x}   se2 {}   psram {}   se-rng-callgate {}",
            b.hw_compat_bit, b.has_se2, b.has_psram, b.has_callgate_se_rng
        );
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn usb_id_parsing() {
        assert_eq!(parse_u16("0x1209").unwrap(), 0x1209);
        assert_eq!(parse_u16("4617").unwrap(), 4617);
        assert!(parse_u16("nope").is_err());
    }

    #[test]
    fn unknown_board_lists_the_known_ones() {
        let err = find_board("mk9").unwrap_err().to_string();
        assert!(err.contains("mk3") && err.contains("mk4"), "{err}");
    }

    #[test]
    fn cli_parses() {
        use clap::CommandFactory;
        Cli::command().debug_assert();
    }
}
