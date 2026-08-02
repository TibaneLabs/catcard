# Clean-room policy

CatCard is an independent, from-scratch firmware for Coldcard hardware. It is
**not** a fork, port, or derivative of the Coinkite Coldcard firmware.

The original firmware is published under MIT **plus the Commons Clause**, which is
not an OSI-approved open-source license. CatCard is MIT-only. To keep that
defensible, the implementation must be independent of the original *source code*.

## The rule

**Do not read, copy, translate, or consult the original Coldcard firmware source,
its disassembly, or its frozen bytecode while writing CatCard code.**

This applies to:

- `../firmware/` — original firmware images and source in this checkout
- `../work/` — audit artifacts: disassembly (`dis-*`), extracted `.mpy`, vendored
  `micropython-*` / `libngu-*` trees, comparison dumps
- Anything else derived by decompiling or disassembling a shipped image

If you are an AI agent working in this repository: treat those paths as
**off-limits for reads**. Refuse the read rather than "just peeking".

## The permitted input

`../hw-reference/` is the sanctioned specification. It is a deliberate
interface-level description of **hardware and protocol facts** — part numbers, GPIO
assignments, register addresses, bus configuration, the bootloader callgate ABI,
on-flash image layout, and the published developer signing key. Facts about a
device are not the licensed expression of its firmware.

Also permitted:

- Public chip documentation: ST RM0351 (STM32L4), RM0432 (STM32L4+), the
  STM32L496 / STM32L4S5 datasheets, Microchip ATECC608 and Maxim DS28C36
  datasheets, JEDEC SPI-NOR command sets, the SSD1306 and ST77xx command sets.
- Public standards: BIP-32/39/85/174 (PSBT), SLIP-132, secp256k1, DfuSe (ST
  UM0391), USB HID / CDC specifications.
- Independent Rust crates under permissive licenses.

## Boundary cases

**"The two firmwares will look similar."** Where the hardware or a standard fixes
the answer — a register write sequence, a BIP-32 derivation, an SSD1306 init
string — convergence is expected and fine. Independence is about not copying
expression: structure, naming, comments, control flow, and design choices that
were not forced by the spec.

**Formats we must match byte-for-byte.** The firmware header, the signed-region
construction, and the `pinAttempt_t` struct are wire/ABI formats imposed by the
unreplaceable bootloader. They are described in `../hw-reference/` and are
implemented here from that description. Field *names* in our code should be ours.

**Things we deliberately do differently.** The USB application protocol, the
settings store format, the UX, and all wallet logic are unconstrained — see
`docs/ARCHITECTURE.md`. The seed RNG is deliberately redesigned; the original
design is a known defect (see `docs/ENTROPY.md`).

## Provenance discipline

Every module that encodes a hardware or format fact should cite its source in a
comment, using the confidence tags from `hw-reference`:

```rust
// SSD1306 on SPI1: RESET=PA6, DC=PA8, CS=PA4.
// Source: hw-reference/gpio-peripherals.md §Mk3 [C]
```

`[C]` confirmed, `[I]` inferred, `[?]` unconfirmed — carry the tag through. Any
`[?]` that reaches code must also appear in `docs/HARDWARE-OPEN-ITEMS.md`.
