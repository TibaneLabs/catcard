# Hardware open items

Everything the implementation needs that `hw-reference` marks `[?]`, could not answer,
or answers ambiguously. Each entry says what is blocked and how to resolve it.

Ordered by how much they block.

---

## Callgate entry address

**Blocks: every secret operation.** PIN login, seed fetch, seed storage, secure-element
entropy, genuine light, DFU entry, downgrade records. Without this, CatCard can boot but
can never be a wallet.

`hw-reference/bootloader-callgate-abi.md` specifies the ABI completely — method numbers,
argument encodings, the 280-byte `pinAttempt_t`, error codes — but not the address to
branch to.

The bootloader is protected by the **STM32 Firewall** peripheral. Entry into a protected
code segment is only legal through its call gate, at a fixed offset from the code
segment start address. So the address is:

```
callgate_entry = FW_CSSA (firewall code segment start) + <call gate offset>
```

Both parts need confirming:

- `FW_CSSA` / `FW_CSL` are firewall configuration registers, readable on a device.
- The call-gate offset convention is stated in RM0351 §5 (Firewall) — confirm whether
  entry is at `CSSA` or at a fixed offset past it, and what the first words of the
  segment must contain.

**How to resolve.** On an RDP<2 unit, read the firewall registers over SWD and
disassemble the first instructions of the code segment. Alternatively, an existing
running firmware branches there — a single-step at the call site reveals the target.
Either approach reads only the *address*, not the bootloader's source, so it stays
inside the clean-room boundary.

**Where it goes:** `BoardSpec::callgate_entry` in `crates/catcard-board/src/spec.rs`.
A test in `catcard-callgate` fails the moment it is filled in, as a prompt to write
real integration tests for gate 18.

---

## SRAM2 / SRAM3 sizes

**Blocks: using more than SRAM1.** Currently the linker is given SRAM1 only — 256 KB on
mk3, 192 KB on mk4/Q. That is plenty for now.

`hw-reference/platform.md §2` gives SRAM2 as 32 KB on the L496; the ST datasheet for
that part gives 64 KB (256 KB SRAM1 + 64 KB SRAM2 = the documented 320 KB total). The
32 KB figure matches the STM32L475/L476, which is what the stock build targets for its
CMSIS headers even though the die is an L496 — so the reference has likely inherited the
wrong number.

The bootloader reserves `0x1000_6000 .. 0x1000_7C00` (7 KB) in the SRAM2 alias window
either way, and that region is excluded from our linker script already.

**How to resolve.** Read the datasheet for the exact part marking, then confirm by
writing and reading back the top of each bank on hardware.

---

## SPI-NOR chip select and SCK

**Blocks: settings storage, PSBT scratch, and firmware upgrade staging** — i.e. the
whole self-upgrade path.

`hw-reference/gpio-peripherals.md` confirms SPI2 MISO=PC2 and MOSI=PC3 but not SCK or
CS. PB12/PB13, the usual SPI2 NSS/SCK pins, are taken by numpad rows on this board,
which leaves:

- SCK: PB10 or PD1 (PD1 is recorded as the working candidate)
- CS: PB9 or PD0

Also unconfirmed: the NOR part number and total size. The reference says ≥1 MB usable
with settings occupying 896 KB–1 MB, and guesses 2 MB+.

**How to resolve.** Probe the board, or read the JEDEC ID (`RDID`, opcode `0x9F`) once
any candidate SCK/CS pairing produces a response.

**Where it goes:** `SflashPins` in `crates/catcard-board/src/spec.rs`;
`SpiBus::pins_confirmed` flips to `true`.

---

## MSI range, and therefore the PLL configuration

**Blocks: running faster than the reset default.** The core currently runs on the
reset-default MSI clock. Everything works; it is just slow.

`hw-reference/platform.md §1` records the divisors `N=40, M=2, R=2, P=7, Q=4` sourced
from MSI, but not the MSI range. `SYSCLK = MSI / M * N / R` gives **40 MHz at MSI=4 MHz**
and **80 MHz at MSI=8 MHz**. Programming the PLL on the wrong assumption either
underclocks the device or overclocks it past its voltage-scaling limit.

Note the RNG does **not** depend on this: `catcard-hal::clock::enable_hsi48` routes the
independent HSI48 oscillator to the 48 MHz peripheral clock, which is correct on every
generation.

**How to resolve.** Read `RCC_CR.MSIRANGE` on a running device, or measure SYSCLK on the
MCO pin.

**Where it goes:** `crates/catcard-hal/src/clock.rs`, `PLL_DIVISORS` and a new
`init_pll`.

---

## Flash page size and bank configuration

**Blocks: writing to main flash from the firmware** (not needed for the bootloader-driven
upgrade path, which erases on our behalf).

- STM32L4 (L496): 2 KB pages.
- STM32L4+ (L4S5): 8 KB pages single-bank, 4 KB dual-bank — set by the `DBANK` option
  bit, which we cannot know without reading it.

`MemoryMap::flash_page_len` currently assumes the larger (safer) 8 KB on L4S5.

**How to resolve.** Read the option bytes at `0x1FFF_7800`.

---

## SPI-flash staging base

**Blocks: the self-upgrade path.**

`hw-reference/install-and-usb-transport.md §2` says the pending image is staged at
SPI-NOR **offset 0**, sourced from a comment that the entire flash "starting at zero may
be used" — which is weaker than a confirmation that the bootloader reads from exactly
0. It also notes any header or marker the bootloader expects there is unconfirmed.

Getting this wrong means a reboot into a bootloader that installs garbage.

**How to resolve.** Confirm on hardware before the first self-upgrade attempt, by
staging an image and observing what the bootloader installs. Test on a unit you are
willing to recover over DFU.

---

## `install_flags` bits

Only `HIGH_WATER` (`0x01`) is documented, and even that is inferred from behaviour
rather than a bit definition. All other bits must be left clear.

`catcard-image` sets only `HIGH_WATER`, and only when `--high-water` is passed. That
flag is irreversible on the device and is off by default.

---

## Q1 display controller and resolution

**Blocks: any Q1 UI.** `hw-reference` gives the pins (CS=PA4, SCLK=PA5, RESET=PA6,
MOSI=PA7, D/C=PA8, TEAR=PB11) and guesses an ST77xx-class controller at ~320×240. The
board spec records 320×240 as a placeholder.

**How to resolve.** Read the controller ID command response, or read the part marking.

---

## Q1 keyboard topology and QR camera bus

**Blocks: Q1 input and QR scanning.** Neither the keyboard scan topology (matrix vs.
dedicated controller) nor the camera interface (SPI / DCMI / UART) is known.

---

## microSD card-detect polarity

`SD_SW=PA9` is marked `[?]` in the reference, and its active polarity is not stated.
Recorded as `card_detect: Some(pa(9))` but not relied upon.

---

## Secret encoding within the `0x80+` BIP-39 marker range

`hw-reference` says the secret blob's marker is `0x01` for xprv and `0x80`+ for BIP-39
words, but not how word count is encoded in the low bits.

**Blocks: decoding a seed created by stock firmware.** Not needed to create our own,
since CatCard chooses its own encoding for secrets it writes — but needed for any
migration path.

`catcard_callgate::pin::classify_secret` returns the raw marker rather than guessing.

---

## SE1 single-wire UART pin; SE2 I²C pins and addresses

Not needed while all secret operations go through the callgate, which is the design.
Would only matter for direct non-secret SE access (config zone reads, `Random`).
