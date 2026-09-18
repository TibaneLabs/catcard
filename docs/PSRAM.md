# PSRAM: what a memory-mapped write needs

Measured on a real Q1 on 2026-09-18, chasing a genuine, correctly signed stock firmware
image that failed its signature check after being staged from a microSD card.

The rules come from `hw-reference/storage.md` §PSRAM, which is stock's own discipline
(`mk4-bootloader/psram.c`): the part is an ESP-PSRAM64H on OCTOSPI1, memory-mapped at
`0x9000_0000`, so **every CPU store is an OctoSPI write transaction**.

## 1. Only full 32-bit stores at 4-aligned addresses are issued correctly

`psram.c`'s own header: *"CAUTION: All writes must be word aligned. Unaligned read okay."* A
byte or half-word store, or a word straddling an odd address, is mis-issued — the data lands
at the wrong offset or is dropped. **Reads may be unaligned.**

Confirmed here by the failure it caused. `PsramArea::write` wrote byte by byte, and a run of
byte stores beginning at an **odd** address came back with one byte duplicated and the rest
of the run shifted along by one:

| `poke` start address mod 4 | 2 KB pattern, byte stores |
|---|---|
| 0 | clean |
| 1 | **wrong from the second byte** |
| 2 | clean |
| 3 | **wrong from the second byte** |

`PsramArea::write` and `::read` now use 32-bit accesses only. A partial word at either end of
a span is read, merged and written whole, so bytes outside the span keep their values; every
staging write in practice is 512-aligned and needs no merge. The word plan is a separate
iterator with its own tests, because the addresses PSRAM sees cannot be checked on a host but
the plan that produces them can.

**Why stock never meets this:** its PSRAM writes are always whole 512-byte blocks at
block-aligned offsets, so its `memcpy` stays all-word-store.

## 2. CE# may not stay low for more than 8 us, or the part stops refreshing itself

**This is the rule that explains the rest, and it comes from the datasheet rather than from
us** (`hw-reference/datasheets/ESP-PSRAM64H-espressif.pdf`):

- Table 10-5: **`tCEM`, CE# low pulse width, max 8 us**; `tCPH`, CE# high between bursts,
  min 50 ns.
- §5.5: *"CE# must be pulled high immediately after all read/write operations. Not doing so
  will **block internal refresh operations and cause memory failure**."*

It is a pseudo-SRAM: a DRAM array behind an SRAM interface, and it refreshes itself only
while it is deselected. Hold it selected and it loses data -- **anywhere in the chip**, not
at the address being accessed. That is the piece every earlier theory here was missing,
because it is the only one that explains bytes going wrong in a header that nothing had
written to.

The bus runs quad at 60 MHz, so it moves half a byte per clock: 8 us is 480 clocks, 240
bytes, sixty words. `PsramArea` lets CE# rise every **32 words** -- 128 bytes, which is 256
clocks of data plus about 14 of command and address, so roughly **4.5 us of the 8 us
budget** -- by idling the bus long enough for the controller's timeout (16 clocks, 267 ns as
stock arms it) plus `tCPH`. A megabyte of staging pays that eight thousand times, which is a
few milliseconds.

The budget is a **time**, not an access count, so the figure depends on the bus clock: at 30
MHz those same 128 bytes would take 9 us and be over the limit. Changing the OCTOSPI
prescaler means revisiting `WORDS_PER_BURST`.

## 3. The recovery delay: required by the reference, not reproduced here

`storage.md` also says writes need "a NOP recovery delay after writes", without saying how
long. Guessing invisibly short is how the rest of this bug presented, so it was measured:
**Debug → PSRAM soak** writes 256 KB of a position-derived pattern per pass with word stores,
counting words that did not stick and, separately, words holding their *neighbour's* value —
the mis-issued-store signature.

Result on this Q1: **clean at 0, 1, 2, 4, 8, 16 and 32 NOPs.** At the fault rate seen when
staging (about one 512-byte chunk in thirty-two) a 256 KB pass should have shown around
sixteen faults, so whatever staging was hitting, an uninterrupted run of aligned word stores
is not it.

`RECOVERY_NOPS` is kept at 16 anyway: the reference documents the part as wanting it, our
soak exercises one data pattern at one temperature, and a megabyte of stores costs a few
milliseconds. It is a cost worth paying for a rule we did not establish ourselves — but it is
**not** the fix for what was wrong here, and this file should not be read as saying it was.

## 4. Reads mixed into writes  [C, confirmed]

After the switch to word stores, staging still failed — one word per chunk or so arriving
mis-issued, with the chunk's real data four bytes further on and a word in front of it that
was never written (`05000d90`, which reads as an address rather than image data). Peeking the
region over USB confirmed PSRAM really held it that way, so the write landed wrong rather
than the read returning wrong.

The build that failed this way had a **read-back verification**: it read every 512-byte chunk
immediately after writing it. Memory-mapped reads and writes use different commands (quad
read `0xEB` with 6 dummy cycles, quad write `0x02` with none), so a chunk-by-chunk read-back
makes the controller switch between them thousands of times. Both symptoms seen are
switch symptoms: once a read returned the region's *previous* contents, and at least once a
word was mis-issued.

The verification is gone, and with it the rewrite-on-mismatch retry that was papering over
this. Neither was a fix; the first was an instrument and the second was a workaround.

**Confirmed on the device:** with word stores and no interleaved reads, a stock `v1.5.2Q`
image stages from microSD and installs. Nothing else changed between the failing build and
the working one except the removal of the per-chunk read-back.

Removing it costs nothing in safety. A staged image is digested and its signature checked
before anything installs it -- by this firmware in `Staged::inspect`, and again by the
bootloader at `gate 18/7` -- so corruption is caught either way. What the per-chunk check
added was an earlier, more precise complaint; what it cost was causing the corruption it
was there to find.

## Open

- If a read-back is ever wanted again, it belongs **after** the whole image is staged, not per
  chunk — one switch instead of thousands — and the image is verified by digest anyway.
- We do not configure OCTOSPI at all; the bootloader's setup is inherited, including the
  `TimeOutPeriod=16` that releases CS periodically for the part's refresh. If corruption ever
  returns under sustained access, that setting and the part's `tCEM` limit are where to look
  next: `storage.md` calls it a separate, latent risk.
