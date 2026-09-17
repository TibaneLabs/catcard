# The kernel

A preemptive scheduler: real tasks, real stacks, a real context switch. This document is
the design and, more usefully, the list of things that can go wrong on *this* hardware —
several of which are not in `hw-reference/`, because that tree is peripheral- and
ABI-focused and these are CPU-core and interrupt-model facts.

## Shape

- **SysTick** drives the tick; **PendSV** performs the switch. Tasks run on **PSP**,
  exceptions on **MSP** — the standard Cortex-M split.
- Round-robin over ready tasks. No priorities: a wallet has a handful of jobs and none of
  them is hard-real-time.
- One stack per task, supplied by the caller as a `&'static mut [u32]`, so its size is
  visible where the task is created rather than buried in the kernel.
- No allocator anywhere.

## The five things that must be right

### 1. The callgate is a hard critical section

The bootloader callgate runs behind the STM32 Firewall, and **an interrupt taken inside
firewall code closes the firewall** — the call fails or the CPU resets. Everything
security-critical goes through it: PIN, secret fetch, signing, the genuine light, firmware
install.

So a context switch must **never** preempt `ckcc.gate()`. This is already handled:
`catcard_callgate::Callgate::raw` wraps every call in `entry::with_interrupts_masked`, and
the gate is hand-written assembly regardless (it is not an AAPCS call — `r2` is the buffer
length), so the masking lives in the same stub.

**Consequence for timekeeping:** SysTick is masked for the duration, and the ticks that
fall due collapse into one pending interrupt. Counting interrupts, kernel time ran about
3× slow in the test below. So the SysTick handler does not count interrupts: it measures
the CPU cycles that really passed since the previous tick, from the DWT cycle counter
(which keeps running while interrupts are masked), and adds that many ticks. `ticks()`
therefore tracks real elapsed time, with one limit: CYCCNT wraps every ~35.8 s at 120 MHz
(53.7 s at 80 MHz), so a *single* masked window longer than that undercounts by whole
wraps. Anything that must be right across a longer blackout uses the RTC.

### 2. VTOR is ours to set

The bootloader hands off to the firmware by a **plain jump**, not a reset
(`platform.md` §"Concrete handoff value"). Nothing resets `SCB->VTOR` on that path, and
`cortex-m-rt` only writes it behind its `set-vtor` feature, which we do not enable.

`main` now points it at this image's table explicitly. Relying on the loader to have done
it is a silent failure: exceptions would dispatch through *its* table, and a PendSV we
pend would run something else entirely — indistinguishable from a broken switch.

### 3. A switch must not preempt a driver

The keypad's EXTI handler timestamps a keypress at the electrical edge for entropy, and
the USB transport runs from OTG_FS. Both sit at NVIC priority 0. PendSV is pinned to the
**lowest** priority in the system, so a task swap can never add jitter to an entropy
sample or stall a bulk transfer.

### 4. Interrupts arrive masked

The bootloader hands off with **PRIMASK set**, and nothing on the way in clears it:
`cortex-m-rt`'s reset path does not, `#[entry]` does not, and the callgate's
`with_interrupts_masked` deliberately preserves whatever it found. So until `main` began
calling `cortex_m::interrupt::enable()`, **no interrupt had ever fired on this firmware**.

It went unnoticed because nearly everything is polled — USB, the keypad scan, the display.
The two things that needed an interrupt quietly never worked: the keypad's EXTI edge
timestamp (the fine-grained entropy a keypress contributes, which silently fell back to a
foreground sample every time) and interrupt-mode USB mass storage, whose failure was
recorded as an EP0 servicing problem.

Diagnosed over the debug monitor on the RDP=2 Q1: every EXTI, SYSCFG and NVIC register was
correct and `IMR1` still carried the hardware's own reset bits, yet the edge latch stayed
zero across a boot and many keypresses. Poking a four-instruction `cpsie i; nop…; cpsid i`
routine into RAM and `jsr`-ing it made the pending line fire at once. Enabling interrupts
at boot was checked against every `NVIC_ISER` first — only the keypad's own EXTI lines were
enabled, so there was no stray source to park the CPU in `DefaultHandler`.

For the kernel this is a precondition, not a side issue: SysTick and PendSV are
configurable-priority exceptions and PRIMASK masks both.

### 5. A stack overflow must not be silent

Each stack is painted, with a guard word beneath it, and the high-water mark and guard are
both reportable. This is not tidiness: what lies below a task stack on this device can be
seed material, and a stack that quietly walks into it is the worst failure this design can
produce.

## Floating point

All Coldcard MCUs are Cortex-M4F with the FPU present, and the firmware does use `f32`
(the RNG analysis screens). The switch honours **lazy FPU stacking**: `EXC_RETURN` bit 4
(`FType`) says whether the outgoing task has an extended frame, and `s16-s31` are saved
and restored only when it does. The inline assembler does not inherit the target's FPU, so
the handler carries an explicit `.fpu fpv4-sp-d16`; without it the `vstmdb`/`vldmia` do not
assemble, and the error surfaces confusingly as a complaint about the `IT` block.

## Testing it, on a locked device

**This unit is RDP=2, which removes the usual safety net.**
`install-and-usb-transport.md` §2c: a locked unit running a validly-signed but *broken*
image — "boots, but e.g. no USB" — has **no bootrom recovery**. SD recovery only completes
a *pending* install, which itself needs a working firmware to have authorised it. There is
no BOOT0 or DFU button on mk4/mk5/Q1.

A wrong context switch produces precisely that image: correctly signed, boots, hangs at the
first SysTick, and since our USB is polled from the foreground, a hung foreground never
enumerates.

**So the kernel never starts on the boot path.** It starts only from
*Debug → Kernel test*, which means a failure is cured by a power cycle: the next boot runs
the same firmware and does not start it. The test's own reporting task keeps pumping USB
and writes counters to the log every half second, so the result is read over the existing
debug channel *while the scheduler runs* — `sw` climbing means switching works, `a` and `b`
both climbing means two tasks share the CPU, and `hw`/`ok` cover the stacks.

The same reasoning applies to any later step that puts the kernel on the boot path: it
wants an unlocked unit, an emulator run, or a proven `gate 18/7` SD-upgrade path first.

## Measured on the RDP=2 Q1

Two runs of *Debug → Kernel test*, read over USB.

**Run 1 — preemption.** Three tasks, one of which never yields. After ~4.9 minutes:
`t=294000 sw=882003 a=294001 b=294001`, all stack guards intact. Exactly one round-robin
per tick, and the two yielding tasks ran every tick even though the third never gave up
the CPU — which only SysTick preemption can cause.

**Run 2 — FPU, callgate, device interrupt.**

```
kt t=4501 ms=13398 sw=17648 fp=8824 edge=0xcbf0aca2
kf a=275/0 b=275/0
kg ok=89 err=0  hw fa=78 fb=78 g=67 r=437 ok
```

- **FPU context holds.** Each round carries all of `s16-s31` through sixteen switches —
  confirmed from the disassembly, which saves `d8-d15` and compares after the switch — in
  two disjoint value ranges. 275 rounds per task, zero mismatches, 8 824 FP-state saves.
  An earlier version switched once after building the values and objdump showed the
  optimiser had hoisted the comparisons ahead of the call; that version would have passed
  while testing nothing.
- **Callgate calls work under the scheduler**: 89 SE1 TRNG reads, no errors.
- **A device interrupt preempts a running task**: the keypad edge latch changed mid-run.

### The callgate blackout

`t=4501` ticks against `ms=13398` real milliseconds: kernel time ran about **3× slow**.
Each 500-tick reporting interval took ~1 487 ms and contained 10 gate calls, so each
**SE1 TRNG read held interrupts masked for ~99 ms**.

During that window nothing runs — no other task, no USB, no tick — and a keypress is
pended until the call returns. Consequences:

- The blackout itself cannot be removed, but its effect on the clock can: the tick
  handler catches up from the DWT counter (see §1). PIN key-stretching goes through the
  same masked call and is much longer, so it is the case to check against the 35.8 s wrap.
- **Masking only SysTick and PendSV (BASEPRI) is not an option.** An interrupt taken inside
  firewall code closes the firewall. With the keypad's EXTI now live, a keypress during a
  BASEPRI-only gate call would do exactly that. PRIMASK — everything — is required.
- The host's USB timeouts must cover the longest gate call, since the device cannot answer
  during one.

### The menu as a task (Debug → Kernel UI)

The real menu loop, restarted in a task beside a logging heartbeat, used by hand for
~65 s: `sw` exactly 2 per tick, USB served by the menu task, all guards intact.

**Menu stack high-water: 4 412 of 8 192 words (~54%)**, reached when a heavier screen
opened (it was 2 679 before). That is well above early estimates, and it did not yet
include the seed flow or key derivation, which are the likeliest deep paths. The stack
size is not settled until those have been measured under the kernel.

### USB as its own task (step 3)

Under *Debug → Kernel UI* a third task services USB, the activity light and the power
button every scheduling round. Task-side access to the USB state goes through
`usbtask::with_task`, under the kernel's `without_preemption` scheduler lock; the OTG
interrupt keeps its own accessor. `pump()` becomes a no-op once the service starts.

Verified on the RDP=2 Q1, all under the kernel:

- **Staging**: 266 240 bytes received, written to PSRAM and signature-verified by the USB
  task. The menu-only arrangement of step 2 had refused the same offer twice with
  `StorageFault`; with USB in its own task behind the lock it did not recur.
- **Install approved at the device**, via gate 18/7, while the scheduler ran.
- **Install approved from the host alone** — offer, injected Confirm, reset, running on the
  new image — with no key touched.
- USB task stack peaked at 1 604 of 4 096 words.

**One race this exposed, and fixed by ordering.** The run loop used to check for a pending
offer *before* reading keys. With USB on another task, the offer could become pending in
between, and the host's injected Confirm — sent the moment the offer's reply arrives — was
read with no offer showing and dispatched to the selected menu item, while the install
waited for an OK already spent. Reading keys first closes it: the offer is marked pending
before its reply is sent, and the host injects only after the reply.

## Repeated on the mk5

The mk5 is also RDP=2 and held a (disposable) seed, so the boot-path changes were made
safe by construction before it saw them: every NVIC line is now disabled and un-pended
before the global mask opens, and what the bootloader left is logged. A live read could not
answer that question — the lines enabled on the running mk5 were its own numpad EXTIs,
which our firmware had enabled itself.

- **Boot**: `loader left NVIC 0x00000000 0x00000000 0x00000000` — like the Q1's, the mk5
  bootloader leaves nothing enabled. VTOR had been `0x00000000` and interrupts masked,
  exactly as on the Q1.
- **Numpad edge interrupt** fires with interrupts enabled at boot (latch set during PIN
  entry).
- **Kernel test**: `t=16637` against `ms=16621`; FPU 353/353 rounds per task with zero
  mismatches; 110 SE1 TRNG calls, no errors, ~99 ms of masked time each — the same as the
  Q1, so the blackout looks like a property of the secure element and bootloader rather
  than the board. Stack high-water marks identical to the Q1's.
- **Kernel UI**: menu and USB as tasks on the 128×64 panel; a host-approved upgrade staged,
  verified, installed and came back on the new image with no key pressed.

One host-side artifact, not a firmware fault: a log line read back with bytes missing at a
chunk seam. The log is read in several requests, each at an offset counted from the oldest
byte, and the ring was wrapping during the read, so the oldest byte moved between requests.
A snapshot read would avoid it.

### Address Explorer under the kernel (mk5)

With a seed on the device, Address Explorer ran under *Kernel UI*: the menu stack stayed at
**2 614 of 8 192 words** — BIP-32 derivation and address encoding did not push it deeper.
The deepest menu use measured on either board remains 4 412 (browsing, on the Q1), so 8 192
words has ample headroom across every path measured so far: seed generation, the RNG
screens, key derivation and a firmware upgrade.

The same run recorded the longest masked window yet: `rec` rose by **1 619** in one
heartbeat interval while switches fell short by the same amount — about **1.6 s** with
nothing scheduled, consistent with the secret fetch through gate 18 (PIN key-stretching).
The clock recovered it, and it is well inside CYCCNT's ~35.8 s wrap. It is also the bound
anything host-facing has to tolerate: the USB task cannot answer during it.

## Private-key work is masked

Preemption made one side channel worse than it was. Before the kernel, a screen deriving
keys simply stopped USB from being serviced. With USB in its own task, a host could keep
sending requests *during* a BIP-32 derivation and read the replies' latency as the work
progressed.

So all private-key computation runs inside `keywork::run`, with interrupts masked: no task,
no USB reply and no interrupt handler runs inside it, and a host sees only when it starts
and ends. `catcard-wallet` makes this a compile-time rule — BIP-39 entropy, parsing and
seed stretching; BIP-32 master and child derivation; a private key's public key and
fingerprint; and `xprv` encoding all take a `&KeyWork`, which firmware can only obtain
inside `keywork::run`. Functions on public data (`ExtendedPubKey`, address encoding) do not.

Masking hides the inside of an operation, not its length: the gap in USB service still
shows the total duration. That is covered by the operations being constant-time; the two
are separate defences and neither replaces the other.

The cost is longer blackouts, which the clock already recovers. Address Explorer's
PBKDF2-and-derivation is now masked for about a second, on top of the ~1.6 s secret fetch
through the gate.
