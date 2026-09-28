#!/bin/sh
# Who may take material out of the entropy pool. The compiler cannot say it: `EntropyPool`
# is one type, and any code holding `&mut` to it can call its outputs.
#
# The pool is the one place on this device that hands out seed material, so the list of
# places that take from it is short and is kept that way on purpose -- a reader checking
# docs/ENTROPY.md ("Following the bytes: TRNG to seed") should be able to trust it:
#
# 1. `EntropyPool::draw` / `draw_seed` -- bytes that become a key -- only in
#    `crates/catcard-fw/src/newseed.rs` (New wallet, temporary seed, CCC's key C, and
#    Debug -> View TRNG Words) and `crates/catcard-fw/src/seedxor.rs` (the noise parts of
#    a random Seed XOR split, which become phrases of their own).
#
# 2. `spawn_drbg` -- one draw that seeds a DRBG, which cannot write back -- only in
#    `crates/catcard-fw/src/session.rs` (the UI, protocol and USB DRBGs) and
#    `crates/catcard-fw/src/paperwallet.rs` (the paper wallet's own DRBG).
#
# A new consumer is added here deliberately, with docs/ENTROPY.md updated to match, or
# it goes through one of these modules.
#
# Run from the repository root (`make lint` does). Exits non-zero, listing the lines, if
# either rule is broken. `--untracked` so a new file is checked before it is committed.
set -eu

fail=0

draws=$(git grep --untracked -nE \
  '(\.draw_seed[[:space:]]*\(|EntropyPool::draw|[Pp]ool[[:alnum:]_]*[[:space:]]*\)?[[:space:]]*\.draw[[:space:]]*\(|\.draw[[:space:]]*\([[:space:]]*&mut)' \
  -- 'crates/catcard-fw/src' \
  ':!crates/catcard-fw/src/newseed.rs' ':!crates/catcard-fw/src/seedxor.rs' || true)
if [ -n "$draws" ]; then
  echo "pooldraw-lint: seed material is drawn from the pool only in newseed.rs and seedxor.rs:"
  echo "$draws"
  fail=1
fi

drbgs=$(git grep --untracked -nE 'spawn_drbg[[:space:]]*\(' \
  -- 'crates/catcard-fw/src' \
  ':!crates/catcard-fw/src/session.rs' ':!crates/catcard-fw/src/paperwallet.rs' || true)
if [ -n "$drbgs" ]; then
  echo "pooldraw-lint: DRBGs are seeded from the pool only in session.rs and paperwallet.rs:"
  echo "$drbgs"
  fail=1
fi

exit $fail
