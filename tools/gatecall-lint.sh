#!/bin/sh
# Two rules about the Q1's waiting-screen sweep that the compiler cannot enforce.
#
# 1. Every callgate that draws or does not return -- 2 (DFU/brick), 3 (logout, power
#    off), 4 other than its read (genuine light), 23 (wipe) -- is called through
#    `crates/catcard-fw/src/gatecall.rs`, which stops the sweep first
#    (`display::quiesce`). A direct call could hand the bootloader a panel a DMA channel
#    is still writing. Source: hw-reference/bootloader-callgate-abi.md §"Caveat".
#
# 2. The guard a waiting screen returns (`display::Busy`) is bound for the work it
#    covers. `#[must_use]` catches a bare call; it does not catch `let _ = ...`, which
#    drops the guard -- and stops the bar -- on the spot.
#
# Run from the repository root (`make lint` does). Exits non-zero, listing the lines,
# if either rule is broken.
set -eu

fail=0

direct=$(git grep -nE \
  '\.(logout|fast_wipe|enter_dfu|genuine_light)[[:space:]]*\(|Method::(ShowLogout|EnterDfu|GenuineLight|FastWipe|FastBrick)' \
  -- 'crates/catcard-fw/src' ':!crates/catcard-fw/src/gatecall.rs' || true)
if [ -n "$direct" ]; then
  echo "gatecall-lint: call these callgates through crate::gatecall, which stops the sweep first:"
  echo "$direct"
  fail=1
fi

dropped=$(git grep -nE \
  'let[[:space:]]+_[[:space:]]*(:[^=]*)?=[[:space:]]*.*(blocking_screen|reading_seed|Busy::(start|sweep)|[^_[:alnum:]]working|[^_[:alnum:]]progress)[[:space:]]*\(' \
  -- 'crates/catcard-fw/src' || true)
if [ -n "$dropped" ]; then
  echo "gatecall-lint: 'let _ =' drops the waiting screen's guard at once; bind it ('let _busy = ...'):"
  echo "$dropped"
  fail=1
fi

exit $fail
