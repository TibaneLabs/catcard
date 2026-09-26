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
