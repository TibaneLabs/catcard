# Entropy and random-number generation

This is the part of CatCard that exists because of a specific defect, so it is worth
being precise about what the defect is and what here prevents it.

## The defect being replaced

In the stock Coldcard firmware the BIP-39 wallet seed is not derived from the STM32
hardware TRNG. It comes from two chained software PRNGs XORed together. One is seeded
from a compile-time constant; the other from `UID_word ^ SysTick->VAL` plus two RTC
registers that read zero because the RTC is disabled.

On mk3 that leaves roughly 16–22 bits of real entropy, because the STM32L4 unique ID's
first word encodes wafer die coordinates and is therefore small — and it is public,
since it is the device's USB serial number.

mk4 and later reseed from the two secure-element TRNGs at boot, which helps, but the
reseed is **truncated to 32 bits** and applied to only one of the two generators.

Three mistakes are worth naming separately, because they are what the design below is
shaped around:

1. **A good source was available and unused.** The chip has a TRNG. It was never wired
   into the seed path.
2. **A good source was truncated.** The mk4 mitigation reads 32 bytes from each secure
   element, hashes them, and then keeps 4 bytes.
3. **A public value was treated as entropy.** The unique ID contributed nothing but was
   counted as if it did.

A fourth, subtler one: the numpad's anti-Tempest scan shuffle drew from the *same*
generator as the seed. That coupled the seed's state to the number of key presses, which
is both low-entropy and enumerable — it is what made the state recoverable in practice
rather than only in principle.

## The design

Two components, deliberately unable to substitute for each other, plus a third that can
only ever add to the first.

### `EntropyPool` — seed material only

```rust
let mut pool = EntropyPool::new(Policy::STRICT);
pool.add(Source::Stm32Trng, &bytes);   // whole, never narrowed
pool.add(Source::Se1Trng, &bytes);
let seed = pool.draw_seed()?;          // Result, not a value
```

- **Absorbs whole.** There is no API that takes a `u32`. Mistake 2 has no spelling.
- **Combines cryptographically.** `state ← SHA-512(state ‖ tag ‖ len_be64 ‖ data)`. A
  predictable contribution can fail to help; it cannot cancel a good one, which XOR
  allows. The length prefix makes concatenation unambiguous.
- **Domain-separates every source.** The same bytes arriving as `Se1Trng` and as
  `Stm32Trng` produce different states.
- **Counts what it has.** Public and derived values are `Source::NonSecret` and
  `Source::Auxiliary`, credited **zero** bits. Mistake 3 is representable but
  worthless, which is the correct treatment: mixing the unique ID for per-device domain
  separation is fine, counting it is not.
- **Refuses.** `draw_seed()` returns `Result<_, Insufficient>`. A pool that has not met
  its policy produces nothing at all. This is the property that matters most: mistake 1
  was silent, and the failure mode to design against is *proceeding anyway*.

**Crediting.** Hardware TRNGs are credited 4 bits per byte — half their nominal rate.
The haircut is not a claim about the sources; it is there so a single 32-byte read
cannot satisfy a 256-bit policy on its own.

**Policy.**

| board | policy | means |
|---|---|---|
| mk4, Q1 | `Policy::STRICT` | ≥256 credited bits from ≥2 distinct hardware TRNGs |
| mk3 | `Policy::single_trng()` | ≥256 credited bits, ≥1 TRNG (only the STM32 RNG is reachable) |

mk3 needs 64 bytes from the chip TRNG to clear the bar. mk4 needs two chips to be alive.

**Ratcheting.** Every draw advances the pool, so the state that produced a seed is gone
afterwards and a later compromise cannot reconstruct it.

### `UserSymbols` — dice, coins, a keypad mash

An owner who does not trust the device's silicon can add material it could not have
predicted. Offered as a choice once the hardware collection is done — *this device's
entropy, or this device's combined with yours* — and never a precondition.

```rust
let mut run = UserSymbols::new(Alphabet::Dice);
run.push(b'4')?;                     // ASCII, one die face
// ...
if run.weakness().is_none() {        // long enough, not lopsided
    let bits = pool.add_user(&run);  // 50 rolls -> 129
}
```

**The digest convention is stock's, so a run is checkable.** A run enters the pool as
SHA-256 over the ASCII digits — `printf '%s' 4316... | sha256sum` off the device produces
the same 32 bytes, and the screen shows the first eight of them after mixing, so an owner
can confirm the device used *their* rolls.
Source: <https://coldcard.com/docs/verifying-dice-roll-math/> [C]

**What is deliberately not stock's is the replacement.** There the digest *is* the seed:
`BIP39(sha256(rolls))`, so a wallet made from ten rolls has 26 bits behind it and nothing
else, and an owner who verifies their rolls on a compromised computer has handed over the
wallet. Here it is one more contribution to the same SHA-512 chain the TRNGs went into.
That is why there is no "dice-only seed": it is not a missing feature, it is the property.

**Credited by keyspace, behind a gate.** log2 of the alphabet, truncated to a thousandth
of a bit: 2.584 a d6 face, 1 a coin flip, 3.321 a keypad digit. Three limits:

| | dice | coin | keypad |
|---|---|---|---|
| minimum run | 50 | 128 | 65 |
| max share of one symbol | 30% | 65% | 40% |
| bits per symbol | 2.584 | 1 | 3.321 |

- A run below its minimum, or dominated by one symbol, is **credited nothing** — and
  still mixed, because mixing cannot subtract. A die stuck on one face is a pattern.
  The dice and keypad minimums are stock's own published ones (50 rolls; 65 presses,
  `hw-reference/firmware-features.md` §2), not the 39 presses the keyspace arithmetic
  alone would allow: a mash is the least even of the three inputs, so it gets the
  higher bar. The coin's 128 is the same 128-bit bar in its own alphabet.
- A run is absorbed as one 32-byte digest, so it can never be worth more than **256
  bits** however long it runs.
- None of these is a hardware source, so no amount of typing satisfies the two-TRNG bar.

`Source::UserDice`, `UserCoin` and `UserKeypad` are credited **zero per byte**: a run
counts only through `add_user`, which is where the gate lives, so there is no second path
that could count an ungated one. The cycle counter at each press still goes in through
`UserTiming` regardless of whether the run is ever credited.

### `HmacDrbg` — everything else

Signing nonces, UI randomisation, keypad scan order, padding. HMAC-DRBG (SHA-256) per
NIST SP 800-90A §10.1.2, one instance per purpose with a distinct personalization
string (`domain::UI`, `domain::PROTOCOL`, `domain::SIGNING`), each seeded from an
independent pool draw.

The keypad shuffle draws from `domain::UI`. It cannot move the seed generator, because
`EntropyPool` has no "give me a random number" API at all. There is a test that asserts
exactly this — 500 shuffles, then the pool produces the same seed it would have
produced untouched.

**Two instances run in a session, and what draws from which is decided by whether the
output is shown.** `domain::UI` feeds the keypad scramble, the games and the PRNG-status
screen — values that are on the screen. `domain::PROTOCOL` feeds the microSD 2FA token
and a backup's password words and IV — values that leave the device and must not be
guessable. The firmware carries both in its `Ui` bundle (`drbg` and `protocol`), each
seeded from its own pool draw, so a generator whose outputs anyone can watch never
shares state with one whose outputs are kept. Both are stack locals of the session, not
statics, since the Q1's boot stack is the scarce resource.

**The UI DRBG is topped up from keypress timing.** Every physical keypress reseeds the
`domain::UI` generator with the DWT cycle counter and the three RTC registers sampled at
the moment of the press. To make "the moment of the press" mean the electrical edge
rather than the next 60 Hz scan, the keypad columns carry falling-edge EXTI interrupts
while the matrix idles (all rows driven low): a press raises an interrupt at once and the
handler latches the timers there, at CPU-cycle resolution, independent of the poll
schedule — the same "hard IRQ per press" the stock firmware arms for its seed mash. This
is a top-up of a generator already seeded from the pool, never a precondition; a stopped
RTC (no VBAT — it counts elapsed-since-boot) contributes a constant, which is harmless.
It never touches `EntropyPool`, so it cannot influence a wallet seed. See
`catcard-fw/src/keypad.rs` and `catcard-hal/src/exti.rs`.

`below(n)` uses rejection sampling, never modulo. `shuffle` is Fisher-Yates over it.

### Health testing

Raw TRNG output is checked before absorption, per SP 800-90B §4.4:

- **Repetition count**, cutoff 5 at α=2⁻³⁰ for a full-entropy byte source. Catches a
  stuck output.
- **Adaptive proportion**, 512-byte window, cutoff 13. Catches a biased source that
  never actually repeats.
- **Constant-sample** shortcut, reported separately because all-zero and all-`0xFF` are
  the signatures of "peripheral not enabled" and "dead secure element".

State is kept per source across draws, so a run straddling two reads is still caught.

A failing source is **credited nothing and does not count** toward the hardware-source
requirement — but it does **not** poison the pool. It is still absorbed (it may hold some
unpredictability, and mixing it cannot reduce what the healthy sources contributed), and a
draw is refused only if what the *healthy* sources supplied falls short of the policy. This
is the whole point of combining several sources: any healthy one keeps the draw safe, so a
single failing source must never be able to veto a draw the good ones have already earned.
A pool with two healthy TRNGs and one dead element still draws; a pool left with only one
healthy TRNG under `STRICT` refuses — for lack of a second source, not because it is
"poisoned".

## Boot sequence

`catcard-fw/src/boot.rs`, in order:

1. Unique ID → `NonSecret`, zero credit, domain separation only.
2. STM32 TRNG → 64 bytes, health-tested.
3. SE1 and SE2 TRNGs via callgate 26, where available — 64 bytes each, 32 per call.
   The entry address is read from the table the bootloader publishes at `0x0800_0040`
   and validated before it is branched to. A board whose bootloader publishes no usable
   entry contributes nothing here rather than falling back to something weaker, and the
   policy check in step 5 then decides whether boot continues.
4. 16 DWT cycle-counter samples → `UserTiming`, 1 bit/byte.
5. Policy check.

## Following the bytes: TRNG to seed

This is the path a wallet's entropy takes through the source, step by step, so it can be
read and checked rather than taken on trust. Each step names the file and function to
open. Function names rather than line numbers, because lines move with every edit:
`git grep -n 'fn <name>'` finds each one.

Two things to keep in mind while reading. There is **one** pool, and it is fed at boot and
again when a wallet is made; nothing else ever reads it for seed material. And every place
a seed could be produced from something weaker is a **refusal**, not a fallback: each step
below says where.

### 1. The chip's TRNG, read from its registers

[`crates/catcard-hal/src/rng.rs`](../crates/catcard-hal/src/rng.rs): `Rng::word`, then `Rng::fill`.

`word` reads `RNG_DR` only after `RNG_SR.DRDY`, and checks `SR` again *after* the read. A
clock error (`CECS`/`CEIS`) is an error, never a word; a seed error (`SECS`/`SEIS`) restarts
the generator and retries a bounded number of times, then fails. `DRDY` is waited for a
bounded number of polls. So a dead or unclocked TRNG produces an error here, not zeros.
`fill` packs whole 32-bit words into the caller's buffer, little-endian.

### 2. The secure elements' TRNGs, through the bootloader

[`crates/catcard-fw/src/trng.rs`](../crates/catcard-fw/src/trng.rs): `Trngs::read`, and the `Kind` list from `kinds()`.

- **SE1 and SE2** (mk4, mk5, Q1): callgate 26, `Callgate::se_rng`, 32 bytes per call from
  a 33-byte buffer whose first byte is the length.
- **The bootloader's own read of the chip TRNG**: callgate 17, `Callgate::bootloader_rng`.
- **SE1's raw bus** (mk3): the single-wire driver in [`crates/catcard-hal/src/se1swi.rs`](../crates/catcard-hal/src/se1swi.rs).

`Kind::source` maps each to the pool `Source` it is absorbed as, and that decides its
credit (step 4). Every temporary buffer is zeroized after the copy.

### 3. Boot: the pool is created and fed

[`crates/catcard-fw/src/boot.rs`](../crates/catcard-fw/src/boot.rs): `bring_up`, then `feed_secure_elements`.

In order: the unique ID ([`crates/catcard-hal/src/uid.rs`](../crates/catcard-hal/src/uid.rs), `feed_pool`, as `NonSecret`),
64 bytes of chip TRNG (`Rng::feed_pool`, as `Stm32Trng`), 64 bytes from each secure
element where the board has them (as `Se1Trng` / `Se2Trng`), and 16 cycle-counter samples
(`add_timing`, as `UserTiming`). Then `pool.check()` records whether the policy was met.
The pool travels out of boot in `BootReport::pool`.

### 4. Inside the pool: health test, absorb, credit

[`crates/catcard-entropy/src/pool.rs`](../crates/catcard-entropy/src/pool.rs): `EntropyPool::add`, `absorb`, `bits_per_byte`,
`is_hardware_trng`; the tests themselves in [`crates/catcard-entropy/src/health.rs`](../crates/catcard-entropy/src/health.rs).

- **Health test first**, for the hardware sources only (`is_hardware_trng`: chip, SE1,
  SE2): repetition count and adaptive proportion, with state kept per source across reads.
- **Absorb always**: `state ← SHA-512(state ‖ tag ‖ len_be64 ‖ data)`. The tag is the
  source's (`Source::tag`); the length prefix keeps two short adds from equalling one long
  one. A source that failed its health test is still absorbed, because mixing cannot
  subtract.
- **Credit only if healthy**: `bits_per_byte` is 4 for the chip and both secure elements,
  1 for timing, 0 for everything else -- the bootloader's read, SE1's raw bus, the unique
  ID, typed symbols. `bytes_from` counts which hardware sources have contributed, for the
  "how many chips" half of the policy.

Nothing here returns randomness. The pool's only outputs are `check` and `draw`.

### 5. From boot to the New wallet screen

[`crates/catcard-fw/src/session.rs`](../crates/catcard-fw/src/session.rs): the session takes the pool with `report.pool.take()`,
first spending one independent draw on each DRBG it starts (`spawn_drbg`: `domain::UI`,
`domain::PROTOCOL`, `domain::USB` -- see [`HmacDrbg`](#hmacdrbg--everything-else)), then
hands the pool to the menu task through [`crates/catcard-fw/src/ktest.rs`](../crates/catcard-fw/src/ktest.rs) (`start_menu`).
[`crates/catcard-fw/src/menu.rs`](../crates/catcard-fw/src/menu.rs): the menu reaches it as `Act::pool`; `Screen::NewSeed`
calls `new_seed` with it.

### 6. New wallet: fresh hardware noise on top

[`crates/catcard-fw/src/menu.rs`](../crates/catcard-fw/src/menu.rs): `new_seed`.

The boot pool already met its policy, but a wallet is not made from boot-time noise
alone. `new_seed` reads **512 fresh bytes from every source the board has** (`kinds()`:
both secure elements or SE1's bus, the bootloader's read, and the chip), the same number
of bytes from each, through `Trngs::read` into `pool.add` -- so every byte goes through
step 4's health test and credit again. Bounded at 160 passes, so a silent source ends the
loop instead of hanging it. The per-source byte counts are written to the log
(`seed: SE1 512B/...`), and the screen shows them as they arrive.

### 7. Optional: your own dice, coins or mash

[`crates/catcard-fw/src/menu.rs`](../crates/catcard-fw/src/menu.rs): `add_user_entropy`, `collect_symbols`, `mix_user_run`;
[`crates/catcard-entropy/src/user.rs`](../crates/catcard-entropy/src/user.rs) and `EntropyPool::add_user`.

Your symbols enter as SHA-256 over their ASCII digits -- the published dice convention,
so `printf '%s' <rolls> | sha256sum` reproduces the 32 bytes, and the screen shows the
first eight -- absorbed into the same chain. They can add; they cannot replace or rescue
(see [`UserSymbols`](#usersymbols--dice-coins-a-keypad-mash)). Every keypress also adds
its cycle-counter timestamp.

### 8. The draw

[`crates/catcard-fw/src/menu.rs`](../crates/catcard-fw/src/menu.rs): `new_seed`, the `keywork::run` block;
[`crates/catcard-entropy/src/pool.rs`](../crates/catcard-entropy/src/pool.rs): `EntropyPool::draw`.

`pool.check()` is asked first and its verdict shown and logged (`seed: N bits from M
chips, policy ok`). Then, **with interrupts masked** (`keywork::run`), `draw` refuses unless
the policy holds, otherwise returns `SHA-512(state ‖ "catcard/draw/v1" ‖ counter_be64)`,
truncated to exactly the length the words need -- 16 bytes for 12 words, 32 for 24 -- and
ratchets the pool so that state is gone. A refusal here ends the flow with the reason on
screen; there is no second path to a seed.

### 9. Words, and the slot encoding, from the same bytes

Still inside the masked block:

- [`crates/catcard-callgate/src/pin.rs`](../crates/catcard-callgate/src/pin.rs): `encode_bip39` -- the 72-byte secure-element slot
  image: a marker byte for the length, then the entropy, then zeros.
  Source: `hw-reference/secret-stash-format.md`.
- [`crates/catcard-wallet/src/bip39/mod.rs`](../crates/catcard-wallet/src/bip39/mod.rs): `Mnemonic::from_entropy` keeps the entropy;
  the words are its bits plus the first `ENT/32` bits of SHA-256(entropy) as checksum, in
  11-bit groups, looked up in the BIP-39 English list (`bip39::wordlist`, pinned to the
  reference list's SHA-256). This is BIP-39 exactly, so the words can be checked with any
  BIP-39 tool.

The drawn bytes are zeroized as soon as both exist.

### 10. Shown, confirmed, then stored -- and read back

[`crates/catcard-fw/src/menu.rs`](../crates/catcard-fw/src/menu.rs): `new_seed` (`show_words`, `quiz`, then `set_secret` and
`verify_secret`); [`crates/catcard-pin/src/lib.rs`](../crates/catcard-pin/src/lib.rs): `Login::set_secret`, `verify_secret`.

The words are shown and quizzed **before** anything is written, so a power cut never
leaves a wallet nobody has the words for. Then gate 18 method 3 (`CHANGE_SECRET`) writes
the slot image to the secure element, and the slot is read back and compared before
"Wallet created" appears. A mismatch is reported, not assumed away. The slot image is
zeroized on every path out.

A **temporary seed** and CCC's **key C** take the same path to step 9 and then stop:
the entropy goes into RAM for the session (`key::set_temporary`) or to the caller, not
into the slot.

### Checking that a published binary is this code

Reading the source only helps if the image on the device was built from it. The build is
designed so that a release can be rebuilt and compared byte for byte, with no key and no
trust in whoever ran CI:

- The header timestamp is `SOURCE_DATE_EPOCH`, set to the tagged commit's time and printed
  in the release notes; the version string is in the notes too.
- `Cargo.lock` is committed, and nothing in the build reads the ambient environment (no
  `rustflags` table; the linker script comes from
  [`crates/catcard-fw/build.rs`](../crates/catcard-fw/build.rs)).
- The image is signed with the published developer key using RFC 6979, which is
  deterministic: the same image signs to the same bytes
  ([`tools/catcard-image/src/sign.rs`](../tools/catcard-image/src/sign.rs)).

To rebuild, for example, the all-chains Q1 image of `v7.0.0-alpha3` (the other shapes differ
only in `--features` and `--board`; the release workflow,
[`.github/workflows/release.yml`](../.github/workflows/release.yml), lists all twelve):

```sh
git clone https://github.com/TibaneLabs/catcard && cd catcard
git checkout v7.0.0-alpha3
export SOURCE_DATE_EPOCH=1790503883 CATCARD_VERSION=7.0.0a3   # from the release notes
cargo build --release -p catcard-fw --target thumbv7em-none-eabihf \
  --no-default-features --features board-q1,multichain
cargo run --release -q -p catcard-image -- build \
  target/thumbv7em-none-eabihf/release/catcard-fw \
  --board q1 --version "$CATCARD_VERSION" \
  --bin out/q1.bin --dfu out/catcard-q1-7.0.0-alpha3.dfu
shasum -a 256 out/catcard-q1-7.0.0-alpha3.dfu   # compare with the release's SHA256SUMS
```

The mk4/mk5 image adds `--hw-compat mk4,mk5` and uses `--board mk5`; `-games` images add
`games` to the features; `-bitcoin` images leave out `multichain`.

**Where this stands today -- not yet reproducible across machines.** Rebuilding
`v7.0.0-alpha3` with the recipe above on macOS (arm64), with the same Rust the release used
(1.98.1, 2026-09-01), does **not** reproduce the published digest: the code is the same,
but it is laid out in a different order in the image, so the bytes and the hash differ.
The release was built on GitHub's Linux x86_64 runners, and CI's own check -- two builds
of every push, compared -- runs on one such machine, which is why it has not caught this.
Until it is fixed, a matching digest can only be expected from a rebuild on the same
platform the release used, and even that has not yet been confirmed independently. Making
the image identical across build hosts, and pinning the exact compiler version
(`rust-toolchain.toml` names only the `stable` channel; the version a release used is
printed in its run's toolchain step), are open items in
[`docs/RELEASING.md`](RELEASING.md#reproducible-builds).

### What to check when reading

- Every `pool.add` / `add_user` / `add_timing` call site: `git grep -n 'pool\.add'` in
  `crates/catcard-fw`. Each names its `Source`; none passes a narrowed integer.
- The only calls that take material *out* of the pool: `git grep -n 'draw_seed\|\.draw('`
  -- the New wallet flow, the Debug TRNG-words screen (shown, never stored), and
  `spawn_drbg` at session start.
- `EntropyPool` has no method that returns a random number. The DRBGs are separate types
  seeded by one draw each and cannot write back.
- The log after a wallet is made (`Debug → Logs`, or [`tools/usbclient.py`](../tools/usbclient.py) on a bench
  build) shows the fresh bytes read per source and the policy verdict.

## Testing

The `catcard-entropy` tests are written as statements about the failure modes above
rather than as coverage:

- `a_fresh_pool_refuses_to_produce_a_seed`
- `one_trng_read_is_not_enough_under_the_strict_policy`
- `public_and_auxiliary_values_are_credited_nothing`
- `user_timing_alone_cannot_unlock_a_seed`
- `a_dead_trng_is_not_credited` / `a_dead_trng_does_not_count_toward_the_hardware_requirement`
  / `a_dead_source_does_not_block_a_healthy_pool`
- `a_predictable_source_cannot_cancel_a_good_one`
- `sources_are_domain_separated`, `concatenation_is_unambiguous`
- `ui_randomness_does_not_disturb_the_seed_pool`
- `below_is_not_modulo_biased`

For user-supplied entropy the statement under test is always the same one — *it adds, it
never replaces*:

- `ten_dice_rolls_leave_a_seed_no_weaker_than_none` and
  `no_run_of_any_length_can_weaken_a_pool` — bits, hardware sources and the verdict never
  go backwards, for a run of any length or shape
- `user_input_can_never_replace_the_pool` — 500 rolls into a pool with no healthy
  hardware behind it still refuses
- `typed_symbols_are_only_ever_counted_through_the_gate` — `add` of raw digits credits
  nothing
- `a_dice_run_reaches_the_pool_as_its_published_digest`,
  `the_digest_is_sha256_over_the_ascii_digits` (pinned to `sha256("123456")`)
- `fifty_fair_rolls_are_credited_129_bits`, `a_run_cannot_be_worth_more_than_its_digest`
- `a_die_stuck_on_one_face_is_not_credited`, `a_mash_of_one_key_is_not_counted`

The DRBG is pinned to vectors cross-checked against an independent implementation of
SP 800-90A written separately from the spec text
([`tools/reference/drbg_ref.py`](../tools/reference/drbg_ref.py)). That catches a
refactor changing the generator, but it validates against a second reading of the
standard rather than against the standard itself — importing the NIST CAVP
`HMAC_DRBG.rsp` SHA-256 vectors is still open (`TODO(#1)` in `drbg.rs`).

## Not yet done

- **Entropy accounting is a policy, not a measurement.** The credit rates are chosen
  conservatively; they are not derived from an SP 800-90B entropy estimate of these
  specific sources. Doing that properly needs long raw captures from real hardware.
- **Startup health test.** SP 800-90B also specifies an on-demand test at boot, over a
  larger sample than the continuous tests see.
- **Reseed on wake.** No sleep support yet, so nothing to reseed after.
