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
