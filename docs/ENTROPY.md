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

Two components, deliberately unable to substitute for each other.

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

### `HmacDrbg` — everything else

Signing nonces, UI randomisation, keypad scan order, padding. HMAC-DRBG (SHA-256) per
NIST SP 800-90A §10.1.2, one instance per purpose with a distinct personalization
string (`domain::UI`, `domain::PROTOCOL`, `domain::SIGNING`), each seeded from an
independent pool draw.

The keypad shuffle draws from `domain::UI`. It cannot move the seed generator, because
`EntropyPool` has no "give me a random number" API at all. There is a test that asserts
exactly this — 500 shuffles, then the pool produces the same seed it would have
produced untouched.

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

A failing source **poisons the pool**: it is still absorbed (it may hold some
unpredictability) but it is credited nothing, and `draw` refuses until the pool is
rebuilt. Poisoning is sticky — adding good entropy afterwards does not clear it.

## Boot sequence

`catcard-fw/src/boot.rs`, in order:

1. Unique ID → `NonSecret`, zero credit, domain separation only.
2. STM32 TRNG → 64 bytes, health-tested.
3. SE1 and SE2 TRNGs via callgate 26, where available — 64 bytes each, 32 per call.
   Currently a no-op: the callgate entry address is unknown (see
   `HARDWARE-OPEN-ITEMS.md`).
4. 16 DWT cycle-counter samples → `UserTiming`, 1 bit/byte.
5. Policy check.

## Testing

The `catcard-entropy` tests are written as statements about the failure modes above
rather than as coverage:

- `a_fresh_pool_refuses_to_produce_a_seed`
- `one_trng_read_is_not_enough_under_the_strict_policy`
- `public_and_auxiliary_values_are_credited_nothing`
- `user_timing_alone_cannot_unlock_a_seed`
- `a_dead_trng_poisons_the_pool` / `a_dead_trng_is_not_credited` / `poisoning_is_sticky`
- `a_predictable_source_cannot_cancel_a_good_one`
- `sources_are_domain_separated`, `concatenation_is_unambiguous`
- `ui_randomness_does_not_disturb_the_seed_pool`
- `below_is_not_modulo_biased`

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
- **User-supplied entropy.** Dice rolls and coin flips should be mixable as a first
  class source with its own credit rate.
- **Startup health test.** SP 800-90B also specifies an on-demand test at boot, over a
  larger sample than the continuous tests see.
- **Reseed on wake.** No sleep support yet, so nothing to reseed after.
