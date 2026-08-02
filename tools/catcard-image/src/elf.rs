//! Minimal ELF32 little-endian reader: flattens a firmware ELF into the raw image the
//! bootloader installs.
//!
//! Hand-rolled rather than pulled from a crate for two reasons: the format is fully
//! specified and tiny, and this tool sits on the path that produces signed firmware —
//! fewer moving parts there is worth more than the convenience.
//!
//! # Why sections, not segments
//!
//! The obvious approach — walk `PT_LOAD` program headers and copy each one — produces
//! a corrupt image. The linker emits a `PT_LOAD` covering the ELF header and program
//! header table itself, mapped at the base of the address space. On this hardware that
//! lands at `0x0800_0000`, which is the *bootloader's* flash, so a segment-based
//! flatten prepends 0x154 bytes of ELF metadata and shifts the entire firmware.
//!
//! So this does what `objcopy -O binary` does: take the allocatable, non-`NOBITS`
//! **sections**, and place each at its load address. Sections do not carry an LMA
//! directly, so it is computed from the `PT_LOAD` that contains the section:
//!
//! ```text
//! lma = sh_addr - p_vaddr + p_paddr
//! ```
//!
//! That is what puts `.data` — virtual address in RAM, load address in flash — in the
//! right place, and it naturally drops the header-only segment, which contains no
//! sections at all.

use anyhow::{bail, ensure, Context, Result};

const EI_NIDENT: usize = 16;
const ELFCLASS32: u8 = 1;
const ELFDATA2LSB: u8 = 1;
const ET_EXEC: u16 = 2;
const EM_ARM: u16 = 40;

const PT_LOAD: u32 = 1;
const SHT_NOBITS: u32 = 8;
const SHF_ALLOC: u32 = 0x2;

const PH_ENT_MIN: usize = 32;
const SH_ENT_MIN: usize = 40;

#[derive(Debug, Clone)]
pub struct LoadSection {
    /// Load address: where these bytes land in flash.
    pub lma: u32,
    pub data: Vec<u8>,
}

fn u16le(b: &[u8], at: usize) -> u16 {
    u16::from_le_bytes([b[at], b[at + 1]])
}
fn u32le(b: &[u8], at: usize) -> u32 {
    u32::from_le_bytes([b[at], b[at + 1], b[at + 2], b[at + 3]])
}

struct ProgHeader {
    vaddr: u32,
    paddr: u32,
    memsz: u32,
}

fn check_ident(elf: &[u8]) -> Result<()> {
    ensure!(
        elf.len() >= 52,
        "not an ELF: file is only {} bytes",
        elf.len()
    );
    ensure!(&elf[0..4] == b"\x7fELF", "not an ELF: bad magic");
    ensure!(
        elf[4] == ELFCLASS32,
        "expected a 32-bit ELF (ELFCLASS32), got class {}",
        elf[4]
    );
    ensure!(
        elf[5] == ELFDATA2LSB,
        "expected a little-endian ELF, got data encoding {}",
        elf[5]
    );
    let e_type = u16le(elf, EI_NIDENT);
    let e_machine = u16le(elf, EI_NIDENT + 2);
    ensure!(
        e_type == ET_EXEC,
        "expected an executable ELF (ET_EXEC), got type {e_type}"
    );
    ensure!(
        e_machine == EM_ARM,
        "expected an ARM ELF (EM_ARM), got machine {e_machine}"
    );
    Ok(())
}

fn program_headers(elf: &[u8]) -> Result<Vec<ProgHeader>> {
    let off = u32le(elf, EI_NIDENT + 12) as usize; // e_phoff
    let entsize = u16le(elf, EI_NIDENT + 26) as usize; // e_phentsize
    let num = u16le(elf, EI_NIDENT + 28) as usize; // e_phnum

    ensure!(entsize >= PH_ENT_MIN, "program header entry too small");
    ensure!(num > 0, "ELF has no program headers");

    let mut out = Vec::new();
    for i in 0..num {
        let at = off
            .checked_add(i * entsize)
            .context("program header table offset overflows")?;
        ensure!(
            at + entsize <= elf.len(),
            "program header {i} runs past end of file"
        );
        let ph = &elf[at..at + entsize];
        if u32le(ph, 0) != PT_LOAD {
            continue;
        }
        out.push(ProgHeader {
            vaddr: u32le(ph, 8),
            paddr: u32le(ph, 12),
            memsz: u32le(ph, 20),
        });
    }
    Ok(out)
}

/// The allocatable sections that carry content, each with its load address.
pub fn load_segments(elf: &[u8]) -> Result<Vec<LoadSection>> {
    check_ident(elf)?;
    let phs = program_headers(elf)?;

    let sh_off = u32le(elf, EI_NIDENT + 16) as usize; // e_shoff
    let sh_entsize = u16le(elf, EI_NIDENT + 30) as usize; // e_shentsize
    let sh_num = u16le(elf, EI_NIDENT + 32) as usize; // e_shnum

    ensure!(sh_off != 0 && sh_num > 0, "ELF has no section header table");
    ensure!(sh_entsize >= SH_ENT_MIN, "section header entry too small");

    let mut out = Vec::new();
    for i in 0..sh_num {
        let at = sh_off
            .checked_add(i * sh_entsize)
            .context("section header table offset overflows")?;
        ensure!(
            at + sh_entsize <= elf.len(),
            "section header {i} runs past end of file"
        );
        let sh = &elf[at..at + sh_entsize];

        let sh_type = u32le(sh, 4);
        let sh_flags = u32le(sh, 8);
        let sh_addr = u32le(sh, 12);
        let sh_offset = u32le(sh, 16) as usize;
        let sh_size = u32le(sh, 20) as usize;

        // `.bss` occupies RAM but contributes no bytes; anything not ALLOC (debug
        // info, symbol tables, `.ARM.attributes`) is not part of the image.
        if sh_flags & SHF_ALLOC == 0 || sh_type == SHT_NOBITS || sh_size == 0 {
            continue;
        }
        ensure!(
            sh_offset.saturating_add(sh_size) <= elf.len(),
            "section {i} content runs past end of file"
        );

        // Find the PT_LOAD that maps this section, to translate VMA into LMA.
        let ph = phs
            .iter()
            .find(|p| {
                sh_addr >= p.vaddr
                    && (sh_addr as u64 + sh_size as u64) <= (p.vaddr as u64 + p.memsz as u64)
            })
            .with_context(|| {
                format!(
                    "allocatable section {i} at {sh_addr:#010x} is not covered by any \
                     PT_LOAD segment, so its load address is unknown"
                )
            })?;
        let lma = sh_addr - ph.vaddr + ph.paddr;

        out.push(LoadSection {
            lma,
            data: elf[sh_offset..sh_offset + sh_size].to_vec(),
        });
    }

    ensure!(!out.is_empty(), "ELF contains no loadable content");
    out.sort_by_key(|s| s.lma);
    Ok(out)
}

/// Flatten sections into a contiguous image starting at `base`.
///
/// Gaps are filled with `fill`. Overlaps are an error rather than a last-writer-wins
/// merge — silently discarding part of a firmware image is not a failure mode this
/// tool should have.
pub fn flatten(sections: &[LoadSection], base: u32, fill: u8) -> Result<Vec<u8>> {
    let first = sections.first().context("nothing to flatten")?;
    ensure!(
        first.lma >= base,
        "first loadable section is at {:#010x}, below the firmware base {:#010x} \
         — the linker script and the selected board disagree",
        first.lma,
        base
    );

    let end = sections
        .iter()
        .map(|s| s.lma as u64 + s.data.len() as u64)
        .max()
        .expect("checked non-empty");
    let len = (end - base as u64) as usize;
    ensure!(
        len <= 8 * 1024 * 1024,
        "flattened image would be {len} bytes; refusing"
    );

    let mut image = vec![fill; len];
    let mut covered: Vec<(u32, u32)> = Vec::new();

    for s in sections {
        let off = (s.lma - base) as usize;
        let s_end = s.lma + s.data.len() as u32;
        for (a, b) in &covered {
            if s.lma < *b && *a < s_end {
                bail!(
                    "sections overlap: [{:#010x}..{s_end:#010x}) and [{a:#010x}..{b:#010x})",
                    s.lma
                );
            }
        }
        covered.push((s.lma, s_end));
        image[off..off + s.data.len()].copy_from_slice(&s.data);
    }

    Ok(image)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sec(lma: u32, data: &[u8]) -> LoadSection {
        LoadSection {
            lma,
            data: data.to_vec(),
        }
    }

    #[test]
    fn flatten_places_sections_at_their_load_addresses() {
        let s = vec![sec(0x0800_8000, &[1, 2, 3, 4]), sec(0x0800_8010, &[9, 9])];
        let img = flatten(&s, 0x0800_8000, 0xff).unwrap();
        assert_eq!(img.len(), 0x12);
        assert_eq!(&img[0..4], &[1, 2, 3, 4]);
        assert_eq!(&img[4..0x10], &[0xff; 12]); // gap filled
        assert_eq!(&img[0x10..0x12], &[9, 9]);
    }

    #[test]
    fn flatten_rejects_a_section_below_the_base() {
        let err = flatten(&[sec(0x0800_0000, &[1])], 0x0800_8000, 0xff)
            .unwrap_err()
            .to_string();
        assert!(err.contains("below the firmware base"), "{err}");
    }

    #[test]
    fn flatten_rejects_overlapping_sections() {
        let s = vec![sec(0x0800_8000, &[1, 2, 3, 4]), sec(0x0800_8002, &[5, 6])];
        let err = flatten(&s, 0x0800_8000, 0xff).unwrap_err().to_string();
        assert!(err.contains("overlap"), "{err}");
    }

    #[test]
    fn adjacent_sections_do_not_count_as_overlapping() {
        let s = vec![sec(0x0800_8000, &[1, 2]), sec(0x0800_8002, &[3, 4])];
        assert_eq!(flatten(&s, 0x0800_8000, 0).unwrap(), vec![1, 2, 3, 4]);
    }

    #[test]
    fn rejects_non_elf_input() {
        assert!(load_segments(b"not an elf at all, really quite short").is_err());
        assert!(load_segments(&[0u8; 64]).is_err());
    }

    /// Builds a miniature ELF with the exact shape a real cortex-m-rt link produces:
    /// a header-only `PT_LOAD` at the bootloader's base address, `.text` in flash, and
    /// `.data` whose virtual address is in RAM but whose load address is in flash.
    ///
    /// This is the regression test for the bug that segment-based flattening had.
    struct MiniElf {
        bytes: Vec<u8>,
        sections: Vec<[u32; 6]>, // type, flags, addr, offset, size, _
        progs: Vec<[u32; 4]>,    // offset, vaddr, paddr, memsz
        content: Vec<u8>,
    }

    impl MiniElf {
        fn new() -> Self {
            Self {
                bytes: Vec::new(),
                sections: Vec::new(),
                progs: Vec::new(),
                content: Vec::new(),
            }
        }

        fn add_prog(&mut self, vaddr: u32, paddr: u32, memsz: u32) {
            self.progs.push([0, vaddr, paddr, memsz]);
        }

        /// Returns the file offset the content was placed at.
        fn add_section(&mut self, ty: u32, flags: u32, addr: u32, data: &[u8]) {
            let off = self.content.len();
            self.content.extend_from_slice(data);
            self.sections
                .push([ty, flags, addr, off as u32, data.len() as u32, 0]);
        }

        fn build(mut self) -> Vec<u8> {
            const EHDR: usize = 52;
            let phoff = EHDR;
            let phsize = self.progs.len() * 32;
            let shoff = phoff + phsize;
            let shsize = (self.sections.len() + 1) * 40; // +1 for the null section
            let content_base = shoff + shsize;

            self.bytes.resize(EHDR, 0);
            self.bytes[0..4].copy_from_slice(b"\x7fELF");
            self.bytes[4] = ELFCLASS32;
            self.bytes[5] = ELFDATA2LSB;
            self.bytes[6] = 1;
            self.bytes[16..18].copy_from_slice(&ET_EXEC.to_le_bytes());
            self.bytes[18..20].copy_from_slice(&EM_ARM.to_le_bytes());
            self.bytes[28..32].copy_from_slice(&(phoff as u32).to_le_bytes());
            self.bytes[32..36].copy_from_slice(&(shoff as u32).to_le_bytes());
            self.bytes[42..44].copy_from_slice(&32u16.to_le_bytes());
            self.bytes[44..46].copy_from_slice(&(self.progs.len() as u16).to_le_bytes());
            self.bytes[46..48].copy_from_slice(&40u16.to_le_bytes());
            self.bytes[48..50].copy_from_slice(&((self.sections.len() + 1) as u16).to_le_bytes());

            for p in &self.progs {
                let mut h = vec![0u8; 32];
                h[0..4].copy_from_slice(&PT_LOAD.to_le_bytes());
                h[4..8].copy_from_slice(&p[0].to_le_bytes());
                h[8..12].copy_from_slice(&p[1].to_le_bytes());
                h[12..16].copy_from_slice(&p[2].to_le_bytes());
                h[16..20].copy_from_slice(&p[3].to_le_bytes());
                h[20..24].copy_from_slice(&p[3].to_le_bytes());
                self.bytes.extend(h);
            }

            self.bytes.extend(vec![0u8; 40]); // SHT_NULL
            for s in &self.sections {
                let mut h = vec![0u8; 40];
                h[4..8].copy_from_slice(&s[0].to_le_bytes());
                h[8..12].copy_from_slice(&s[1].to_le_bytes());
                h[12..16].copy_from_slice(&s[2].to_le_bytes());
                h[16..20].copy_from_slice(&(content_base as u32 + s[3]).to_le_bytes());
                h[20..24].copy_from_slice(&s[4].to_le_bytes());
                self.bytes.extend(h);
            }

            self.bytes.extend(self.content);
            self.bytes
        }
    }

    #[test]
    fn ignores_the_header_only_segment_and_uses_load_addresses() {
        const SHT_PROGBITS: u32 = 1;
        let mut e = MiniElf::new();

        // The header-only PT_LOAD the linker emits at the base of flash — the one that
        // must not end up in the image.
        e.add_prog(0x0800_0000, 0x0800_0000, 0x154);
        // .text, identity-mapped in flash.
        e.add_prog(0x0800_8000, 0x0800_8000, 0x10);
        // .data: virtual address in RAM, load address in flash right after .text.
        e.add_prog(0x2000_0000, 0x0800_8010, 0x4);

        e.add_section(SHT_PROGBITS, SHF_ALLOC, 0x0800_8000, &[0xaa; 16]);
        e.add_section(SHT_PROGBITS, SHF_ALLOC, 0x2000_0000, &[0xbb; 4]);
        // .bss: allocatable but NOBITS, so it contributes nothing.
        e.add_section(SHT_NOBITS, SHF_ALLOC, 0x2000_0004, &[]);
        // Debug info: not allocatable.
        e.add_section(SHT_PROGBITS, 0, 0, &[0xcc; 32]);

        let elf = e.build();
        let secs = load_segments(&elf).unwrap();

        assert_eq!(secs.len(), 2, "wrong number of loadable sections");
        assert_eq!(secs[0].lma, 0x0800_8000);
        assert_eq!(secs[1].lma, 0x0800_8010, "flattened .data by VMA, not LMA");

        let img = flatten(&secs, 0x0800_8000, 0xff).unwrap();
        assert_eq!(img.len(), 20);
        assert_eq!(&img[0..16], &[0xaa; 16]);
        assert_eq!(&img[16..20], &[0xbb; 4]);
        assert!(
            !img.windows(4).any(|w| w == [0xcc; 4]),
            "non-allocatable section leaked into the image"
        );
    }
}
