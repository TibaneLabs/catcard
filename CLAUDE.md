# CatCard — working notes for agents

Clean-room Rust firmware for Coldcard hardware. MIT, © Karpeles Lab Inc.

## Read this first

**`CLEANROOM.md` is a hard constraint, not a style guide.**

Never read, and never let a subagent read:

- `../firmware/` — original Coldcard firmware and images
- `../work/` — audit artefacts: disassembly (`dis-*`), extracted `.mpy`, vendored
  `micropython-*` and `libngu-*` trees

If a task seems to need them, it does not. Refuse the read and say why. The one
exception is `../work/FINDINGS-RNG.md` and its siblings, which are our own audit
write-ups about the RNG defect — those are fine, they describe a bug, not an
implementation.

**`../hw-reference/` is the sanctioned input.** Plus public chip documentation
(RM0351 for STM32L4, RM0432 for L4+, part datasheets), public standards (BIP-32/39/85,
PSBT, secp256k1, DfuSe/UM0391, USB), and permissively licensed crates.

## Build and test

```sh
cargo t          # host tests, every crate but catcard-fw
cargo fw-mk3     # or fw-mk4 / fw-q1
cargo clippy --workspace --all-targets
```

`catcard-fw` needs `--target thumbv7em-none-eabihf` and exactly one board feature; the
aliases in `.cargo/config.toml` handle both.

Full pipeline check:

```sh
cargo fw-mk4 && cargo run -p catcard-image -- build \
  target/thumbv7em-none-eabihf/release/catcard-fw \
  --board mk4 --version 0.0.1 --bin out/x.bin --dfu out/x.dfu \
  && cargo run -p catcard-image -- verify out/x.bin --board mk4
```

## Conventions that matter here

**Cite hardware facts.** Every register address, pin, or format constant gets a source
and a confidence tag in a comment:

```rust
// SSD1306 on SPI1: RESET=PA6, DC=PA8, CS=PA4.
// Source: hw-reference/gpio-peripherals.md §Mk3 [C]
```

`[C]` confirmed, `[I]` inferred, `[?]` unconfirmed. Anything `[?]` that reaches code
must also be listed in `docs/HARDWARE-OPEN-ITEMS.md`.

**Do not guess an unknown into a constant.** Unknowns are `Option`, or a `bool` flag
next to the value (`SpiBus::pins_confirmed`), so downstream code has to acknowledge
them. `BoardSpec::callgate_entry` is `None` on every board and that is correct — filling
it in with a plausible address would be worse than not compiling.

**Bound every wait.** No unbounded `while !ready {}`. A dead peripheral must produce an
error, not a hang.

**`unsafe` needs a `SAFETY:` comment.** `unsafe_op_in_unsafe_fn` is denied throughout.

**Secrets are `Zeroize` + `ZeroizeOnDrop`.**

**Irreversible operations are labelled at every layer** — RDP lockdown, `HIGH_WATER`,
brick — and are never a default.

## The entropy code is the point of the project

`crates/catcard-entropy` exists because the stock firmware's seed RNG is broken (see
`docs/ENTROPY.md`). Its tests are written as statements about specific failure modes.
When changing it:

- Never add an API that takes a narrow integer of "entropy".
- Never let `EntropyPool` hand out general-purpose randomness. UI and protocol
  randomness come from `HmacDrbg`, always.
- Never make `draw` infallible. Refusing is the safety property.
- Public or per-device-constant values are credited **zero** bits.

## Where things are

| | |
|---|---|
| board tables, pin maps, memory maps | `crates/catcard-board/src/spec.rs` |
| image header + digest | `crates/catcard-fwhdr` |
| bootloader ABI | `crates/catcard-callgate` |
| entropy, health tests, DRBG | `crates/catcard-entropy` |
| register drivers | `crates/catcard-hal` |
| the binary, boot path | `crates/catcard-fw/src/boot.rs` |
| linker script generation | `crates/catcard-fw/build.rs` |
| sign / verify / package | `tools/catcard-image` |

## Current state

Boot path runs: clock → TRNG → entropy pool → policy check, then parks. No display,
keypad, storage, USB, or wallet logic. `docs/ROADMAP.md` has the order.

**The callgate entry address is unknown**, which blocks every secret operation. It is the
first entry in `docs/HARDWARE-OPEN-ITEMS.md`. Do not work around it by inventing an
address.
