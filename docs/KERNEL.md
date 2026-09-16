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

## The four things that must be right

### 1. The callgate is a hard critical section

The bootloader callgate runs behind the STM32 Firewall, and **an interrupt taken inside
firewall code closes the firewall** — the call fails or the CPU resets. Everything
security-critical goes through it: PIN, secret fetch, signing, the genuine light, firmware
install.

So a context switch must **never** preempt `ckcc.gate()`. This is already handled:
`catcard_callgate::Callgate::raw` wraps every call in `entry::with_interrupts_masked`, and
the gate is hand-written assembly regardless (it is not an AAPCS call — `r2` is the buffer
length), so the masking lives in the same stub.

**Consequence for timekeeping:** SysTick is masked for the duration, and a pending tick
collapses into one. Kernel time is therefore a *scheduling* clock, not a wall clock — it
loses time across a long gate call such as a PIN key-stretch. Anything needing real
elapsed time uses the DWT cycle counter or the RTC, not `ticks()`.

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

### 4. A stack overflow must not be silent

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
