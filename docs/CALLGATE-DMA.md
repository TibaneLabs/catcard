# What the bootloader touches during a PIN callgate

Why this exists: during a PIN check the CPU is inside the bootloader, with interrupts
masked, for a second or more. The only way to animate the Q1's screen in that time
without the co-processor is a DMA channel feeding SPI1 on its own
(`catcard-ui::sweep`, `display::start_sweep`). That is only safe if the bootloader
leaves those peripherals alone for the duration -- and above all if it does not use DMA
itself, because a collision behind a PIN check could corrupt a secure-element
transaction.

These are **behavioural facts** about the bootloader, answered by a review of its
source on 2026-09-22. No code from it is reproduced here or anywhere in CatCard.

## Scope

Calls through the published callgate entry (`0x0800_0040`), interrupts masked:

- callgate **16** -- anti-phishing words, after the PIN prefix;
- callgate **18 method 2** (Login) -- the PIN check;
- callgate **18 method 4** (FetchSecret).

## Answers [C]

1. **SPI1** (registers, `APB2ENR.SPI1EN`, `APB2RSTR.SPI1RST`): not touched by gate 16 or
   gate 18 on the normal path. `SPI1EN` is set once at boot.
2. **GPIOA PA4-PA8, GPIOE PE5/PE6, the LCD**: not touched by gate 16 or gate 18 on the
   normal path, including a wrong or trick PIN. The bootloader does drive the LCD in
   other callgates (0 death screen, 3 logout/power-off, 4 genuine light, 23 wipe) and in
   its SE2 hardware-fault handler, which is reachable from gate 18/4. That handler is
   terminal (draws an error and halts) and draws **assuming the bootloader's own SPI1
   configuration**. So anything that reconfigures SPI1 must put it back.
3. **DMA**: the bootloader uses **no DMA channels at all**. SE1 is bit-banged
   single-wire, polled; SE2 is blocking polled I²C; SHA-256 uses the HASH peripheral in
   CPU-fed mode with DMA explicitly off. The only DMA-adjacent act is enabling the
   DMAMUX1 clock at boot. A DMA channel of ours cannot collide with a secure-element
   transaction or the attempt counter.
4. **Clocks and low-power**: no RCC, PLL or prescaler change on the dispatch or PIN path,
   and no WFI/WFE in gate 16 or 18.
5. **SRAM**: the callgate switches to its own 8 KB stack at **`0x2009E000-0x2009FFFF`**
   and wipes it on entry and exit. Keep DMA buffers out of it (and out of the buffer
   passed to the call). The firewall protects only flash -- the bootloader's code and
   its non-volatile data at `0x0801C000` (16 KB); its volatile-data (SRAM) segment is
   unused -- so it does not police a DMA master reading SRAM. The one firewall rule that
   applies is no interrupts while it is open, which a DMA channel with its interrupt
   enables off does not break.

## What this firmware does with it

Before gate 16 and gate 18/2 on the Q1 PIN prompt, before every gate 18/4 seed read
(`menu::reading_seed`), and under every waiting screen (`menu::blocking_screen`): set the
panel window to the bottom 320x5 strip, issue RAMWR, hold CS low and D/C high, slow SPI1
to /128, and start DMA1 channel 7 (DMAMUX1 input 11, SPI1_TX) circular from a heap buffer
outside the range in (5), with no DMA interrupts. Stopping it stops the channel, drains
SPI1 (bounded), restores `CR1`/`CR2` exactly as they were and raises CS -- so a
bootloader screen drawn later still renders.

Who stops it:

- **The waiting screen's guard.** `blocking_screen` and `reading_seed` return a
  `display::Busy`; the caller holds it for the work, and dropping it stops the sweep. A
  lease (`catcard_ui::sweep::Slot`) makes a stale guard -- one whose sweep a later frame
  already stopped -- leave a newer sweep alone.
- **The next frame**, as before, for the PIN check's unowned sweep and anything the guard
  outlived.
- **The backstop, `display::quiesce`, before every callgate that draws** (2, 3, 23; 4/3 is
  never called). A waiting screen's work can be interrupted by the power button (USB
  task), the idle logout, the fatal guard, a trick-PIN wipe or a host's logout, all of
  which end in one of those gates. Every firmware call of them goes through
  `crates/catcard-fw/src/gatecall.rs`, which calls `quiesce` first; `make lint`
  (`tools/gatecall-lint.sh`) refuses a direct call anywhere else. `quiesce` works from
  statics only -- the running sweep's record holds its own SPI1 handle, saved `CR1`/`CR2`
  and the CS pin -- takes that record with interrupts masked so a sweep is stopped exactly
  once, never draws or allocates, and with no sweep running is one atomic load.

What is still not covered: the bootloader's SE2-fault screen, reachable inside gate 18 and
gate 22 while a waiting screen's sweep runs. It is terminal, draws assuming SPI1 as the
bootloader left it, and would come out garbled -- no crypto or fund impact
(hw-reference/bootloader-callgate-abi.md §"Caveat"), the same exposure the seed read has
had since the sweep was introduced.
