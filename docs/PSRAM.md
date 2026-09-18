# PSRAM: byte stores are not reliable, word stores are

Measured on a real Q1 on 2026-09-18, chasing a genuine, correctly signed stock firmware
image that failed its signature check after being read off a microSD card.

## What happens

A run of **byte** stores into memory-mapped PSRAM that begins at an **odd** address comes
back with one byte duplicated and the rest of the run shifted along by one. The span's last
byte is lost off the end. Word-aligned and even-aligned runs of byte stores came back clean
in the same test; 32-bit stores came back clean everywhere.

## The experiment

Through the USB memory monitor (`peek`/`poke`, the `usb-debug-mem` build), a 2 KB
position-dependent pattern was written into unused staging space at `0x9060_0000` in 50-byte
`poke` requests — so each request is a run of 50 byte stores — and read back with 32-bit
`peek`. The only variable is the address the first request starts at:

| start address mod 4 | result |
|---|---|
| 0 | clean |
| 1 | **wrong from the second byte**, 1027 of 2048 bytes differ |
| 2 | clean |
| 3 | **wrong from the second byte**, 1027 of 2048 bytes differ |

and, from a 4-aligned start, in 51-byte requests (so the second request starts at `+51`,
which is 3 mod 4):

| | |
|---|---|
| first difference | byte 52, i.e. the second byte of the second request |
| shape | the byte before it repeated, everything after shifted by one |

A 4 KB pattern written with 32-bit `poke` was byte-for-byte correct in every round.

**Read** accesses are not implicated: the same region read back through 128-word `peek`
requests and through 16-word requests agreed exactly, and the firmware's own byte-wise
digest of staged PSRAM agreed with a host digest of a word-wise dump.

## Why it showed up on the SD path and not over USB

Both paths stage through `PsramArea::write`, which used to write byte by byte. The USB path
writes each frame's payload as it arrives — 56 bytes, then 62 at a time — so its offsets are
always even, which is the case that works. The SD path writes 512-byte chunks, also from an
even offset, and mostly worked: about one 512-byte block in thirty-two came back with a byte
duplicated at a word-aligned position, enough to fail a signature check every time and to
look like "the card read badly".

## What the code does now

`PsramArea::write` and `::read` use **32-bit accesses only** (`crates/catcard-upgrade/src/psram.rs`).
A partial word at either end of a span is read, merged and written whole, so bytes outside
the span keep their values; every staging write in practice is 512-aligned and needs no
merge at all. The word plan is a separate iterator with its own tests, because the addresses
PSRAM sees cannot be checked on a host but the plan that produces them can.

`Staged::write` now also **reads back** what it wrote and returns
`Reject::StorageFault { offset }` at the first byte that differs. A staging medium that
corrupts an image now says so, at the offset where it went wrong, instead of handing on an
image that fails verification for no stated reason.

## Open

- The mechanism is not established. A 16-bit-wide PSRAM whose byte-enables are not honoured
  for an unaligned run would behave this way, as would an OCTOSPI write buffer that pairs
  consecutive byte stores; distinguishing them needs a bus trace, and the fix does not
  depend on which it is.
- Why even-aligned byte runs fail *occasionally* (the one-in-thirty-two blocks on the SD
  path) rather than never is also unexplained. Word stores avoid the question.
