# Architecture

## The one structural fact

The bootloader cannot be replaced. It lives in the first 32 KB (mk3) or 128 KB (mk4/Q)
of flash, is protected by the STM32 Firewall, and at RDP=2 cannot even be read. It owns
the pairing secret, PIN rate-limiting, secure-element authentication, the genuine light,
DFU, and signature verification of *us*.

So CatCard is an application on a fixed platform, and every design decision falls into
one of two piles.

### Fixed — must match exactly

| what | where | source |
|---|---|---|
| Install address, flash layout | `catcard-board::memory` | `platform.md §2` |
| Image header, digest construction, signature | `catcard-fwhdr` | `firmware-signing.md` |
| Callgate entry table, register convention | `catcard-callgate::entry` | `bootloader-callgate-abi.md §0` |
| Callgate ABI, `pinAttempt_t` | `catcard-callgate` | `bootloader-callgate-abi.md`, `gate18-pin-state-machine.md` |
| GPIO assignments | `catcard-board::spec` | `gpio-peripherals.md` |
| DfuSe container | `catcard-image::dfuse` | ST UM0391 |

Getting any of these wrong produces an image that does not boot, or a callgate call the
bootloader rejects. They are implemented from the reference and pinned with tests —
including compile-time assertions where a mismatch would be silent, such as
`size_of::<PinAttempt>() == 280`.

### Ours — no external constraint

USB application protocol, settings storage format, UX, all wallet logic (BIP-32/39/85,
PSBT, descriptors, multisig, and non-Bitcoin chains), and the seed RNG. Only the *secret
storage* (through the callgate) and the *image format* are imposed.

Where we differ deliberately from the stock design, the reason is written down:
[`ENTROPY.md`](ENTROPY.md) for the RNG, [`USB.md`](USB.md) for USB identity.

## Crates

```
                    catcard-fw  (the binary; picks a board by feature)
                     /   |   \   \
        catcard-hal ─┘   |    \   └─ catcard-ui
              │          |     └──── catcard-callgate
       catcard-entropy   |              │
              │          └── catcard-fwhdr
              └──────────────── catcard-board ◄── tools/catcard-image
```

**`catcard-board`** — const data, no MCU dependencies. Memory maps, pin assignments,
peripheral presence, `hw_compat` bits. Used from three places: the firmware, the
firmware's `build.rs` (which turns a `MemoryMap` into a linker script), and the host
image tool. That is why it has no dependencies: the linker script and the host tool's
flattening base cannot drift apart if they read the same constant.

**`catcard-fwhdr`** — the image header and the double-SHA256 digest. `no_std` with an
optional `std` feature, because both the firmware (reading its own header) and the host
tool (writing one) need it.

**`catcard-callgate`** — the bootloader ABI. Typed methods, the 280-byte attempt struct,
buffer range checks that mirror the bootloader's own, and the entry point itself.

Two properties of that interface are worth knowing before touching it, because both fail
in ways that do not look like the cause:

- **The entry address is published, not fixed.** The bootloader writes it to a table at
  `0x0800_0040` so it can move between versions and boards. `entry::validate_entry`
  checks it before we branch, since the failure mode of a wrong target is a CPU reset
  with no diagnostic.
- **It is not an AAPCS call.** `r2` carries the buffer *length*, so an `extern "C"`
  function pointer with three parameters compiles and passes garbage. It is inline asm,
  with interrupts masked — an interrupt inside firewall code resets the CPU.

**`catcard-entropy`** — accumulator, health tests, DRBG. Portable and host-tested; the
firmware only feeds it. See [`ENTROPY.md`](ENTROPY.md).

**`catcard-hal`** — register-level drivers. Deliberately not a PAC: the peripheral
surface is small, and hand-written registers keep every address next to a citation of
the manual section it came from, which is what makes clean-room provenance auditable.

**`catcard-ui`** — framebuffer and panel command sets. Knows nothing about SPI or GPIO,
so it tests on the host.

**`catcard-fw`** — the binary. The only crate that cannot build for the host, and the
only one that needs a board feature.

**`tools/catcard-image`** — flatten, header, sign, verify, package.

## Board abstraction

One board feature selects a `BoardSpec` const:

```
cargo fw-mk3 / fw-mk4 / fw-q1
  → catcard-board/board-mk3 etc.
  → catcard_board::BOARD
  → build.rs generates memory.x from BOARD.memory
```

Host tools enable no board feature and use `spec::ALL` or `BoardSpec::by_name`, so one
`catcard-image` binary handles every board.

Boards carry their unknowns explicitly rather than by omission: `SpiBus::pins_confirmed`,
`SflashPins::cs: Option<Pin>`, `BoardSpec::se2: Option<Se2Pins>`. Code that needs a fact
that is not yet known does not compile against a plausible guess — it has to handle
`None`.

A pin-conflict test asserts no two peripherals claim the same GPIO on a board. That is
what surfaced the mk4 SE2-vs-numpad contradiction in `HARDWARE-OPEN-ITEMS.md`: filling in
a plausible-looking pin fails the build rather than shipping a driver that fights the
keypad for the bus.

## Image assembly

```
cargo fw-mk4
  → ELF, vector table at 0x08020000, _stext at +0x4000
catcard-image build
  → allocatable sections placed at their load addresses  (see elf.rs on why
    sections, not segments — the linker emits a header-only PT_LOAD at the
    bootloader's base address)
  → gaps filled with 0xFF (erased-flash state)
  → 128-byte header written at 0x3F80
  → padded to a 512-byte multiple; firmware_length set
  → digest = SHA256(SHA256(image with only [0x3FC0..0x4000) excised))
  → secp256k1 ECDSA, raw r‖s, into the signature slot
  → DfuSe wrapper
```

The 16 KB below `_stext` is currently mostly fill. Packing `.rodata` into it is a later
optimisation; it costs nothing today.

## Testing

`cargo t` runs every crate except `catcard-fw` on the host. That is not a compromise —
the correctness-critical logic (image format, digest, ABI layout, entropy policy, DRBG,
ELF flattening, DfuSe) is portable by construction, so it is all covered by ordinary
unit tests with no hardware and no emulator.

What that leaves untested until hardware exists: the register writes in `catcard-hal`,
and anything downstream of the callgate. `catcard-hal`'s host tests cover the address
arithmetic (port strides, the AFRL/AFRH split at pin 8, BSRR bit positions) — the parts
that are easy to get silently wrong — but not the writes themselves.

## Conventions

- Every hardware fact cites its source and confidence tag: `[C]` confirmed, `[I]`
  inferred, `[?]` unconfirmed. Any `[?]` reaching code also appears in
  `HARDWARE-OPEN-ITEMS.md`.
- Waits are bounded. An unbounded `while !ready {}` in a wallet's boot path turns a dead
  peripheral into a hang with no diagnosis.
- `unsafe` blocks carry a `SAFETY:` comment; `unsafe_op_in_unsafe_fn` is denied, so an
  `unsafe fn` does not get a free pass on its own body.
- Secrets are `Zeroize` + `ZeroizeOnDrop`.
- Irreversible operations (RDP lockdown, `HIGH_WATER`, brick) are named as such at every
  layer and are never the default.
