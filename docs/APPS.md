# Apps: a small kernel, and everything else loaded on demand

Status: **design, phase 1 in progress.** Nothing here is on the boot path yet.

## Why

The Q1 image is at 1.40 MB of a 1.44 MB ceiling, and 1.12 MB of that is code. Code
deflates to about half. Built as apps -- compressed in flash, unpacked into RAM when
opened -- most of the firmware would cost half the flash it does today, and each app can be
compiled at the optimisation level that suits it. Flappy Cat at `opt-level = 3`, the
kernel at `"z"`.

The same split buys isolation. Apps run **unprivileged**, under the MPU, and reach the
kernel only through `SVC`. The seed, the PIN path, the entropy pool and settings storage
stay in the kernel. A bug in a parser that runs in an app -- PSBT, Codex32, a QR payload --
can then crash that app, but cannot read a secret.

## The split

**Kernel** (privileged, linked, never compressed):
- the scheduler, the USB stack and its tasks, the drivers (panel, keypad, SD, NFC, QR, flash);
- the callgate, the entropy pool and DRBG, `keywork`, settings storage;
- the services apps call (below);
- the loader and decompressor;
- a **rescue path** that needs no app: enough panel and keypad for a USB or SD install. A
  device whose apps fail their check, or fault, falls back to it instead of bricking.

**Apps** (unprivileged, one at a time, compressed in the image):
- leaf features first: games, HSM screens, Codex32, Paper Wallet, Key Teleport, Notes;
- later the menu, which stays resident across other apps;
- last, login.

## One source, two builds

A feature is written against the `catcard-app` API and nothing else. Per board, the build
either:
- **links it in**, where the API is ordinary function calls into the firmware (mk3, which
  has no spare RAM, and any board that chooses to); or
- **builds it as an app**, where the same API is `SVC` stubs.

The feature cannot tell which. The mk3 keeps getting whatever features fit its flash.

## Execution model

- **Where:** the app area is in the RAM the image does not link, `spare_ram` in
  `catcard-board` (0x2003_0000..0x2009_E000 on mk4/mk5/Q1, 440 KiB). Claimed when an app
  opens, never at boot, for the same reason the heap waits (`heap::claim_spare`).
- **Address:** apps are linked at one fixed address, the start of the app area. One app runs
  at a time, so there is nothing to relocate. The build turns each app's ELF into a flat
  image; the device unpacks it, checks its hash and enters it.
- **MPU while an app runs** (`PRIVDEFENA` set, so privileged code sees the default map
  unchanged):
  - app code read-only + execute;
  - app data and stack read-write, execute-never;
  - nothing else reachable from unprivileged code.
- **Privilege per task:** the UI task runs the app; the USB task stays privileged. The
  context switch saves and restores `CONTROL.nPRIV` per task, behind a flag that is false
  until the first app is entered -- before that, one atomic load per switch is the whole
  change to the boot path.
- **Entering and leaving:** `SVC ENTER` from the launcher saves the launcher's callee-saved
  registers (core and FP), points PSP at the app's stack with a fresh exception frame, sets
  `nPRIV` and returns into the app. `SVC EXIT` from the app, or a MemManage fault taken from
  it, restores the launcher exactly as it was, with the exit code (or the fault) in `r0`.
- **Services run in thread mode, privileged, preemptible.** `SVC` is the highest priority;
  a frame's worth of drawing in the handler would stall USB. So the handler only redirects:
  it drops to a privileged trampoline on the UI task's own stack, the service runs as
  ordinary task code, and a second `SVC` returns to the app with the result.
- **Services are coarse.** An app draws into a canvas in its own RAM and hands the kernel a
  finished frame. One call per frame, not per pixel.

## Images

An app image is a header and the flat binary:
- magic, format version, the **kernel build ID** it was built against (the services are
  `extern "C"`, but Rust has no stable ABI, so an app runs only on the build it was made for);
- load address, code length, data length, BSS length, stack length, entry offset;
- SHA-256 of the binary.

Release images carry their apps after the firmware, covered by the image's digest and
signature, and are never loaded from SD.

**Debug builds** (`usb-debug-mem`, unlocked device) also take an app over USB:
`DebugRunApp` uploads an image into the app area, runs it, and answers with its exit code;
its log lines are in the device log. This is how the platform is proven, and how an app
can be tried without installing a new firmware.

## Phases

1. **Proof, over USB.** Kernel side of ENTER/EXIT/services/fault, the per-task privilege
   bit, the MPU layout, `DebugRunApp`, and a minimal SDK. Test apps from the Mac: log and
   exit; a service call; a read of kernel memory that must fault and return; a long run
   that is switched out mid-way while USB keeps working. Measures unpack speed.
2. **Loader and packaging.** Apps carried in the image, the two-stage build (firmware
   first, then apps against its build ID), Flappy Cat as the first real app.
3. **Leaf features**, one at a time, measuring flash and RAM after each.
4. **Menu** as a resident app.
5. **Login**, last, behind the kernel's rescue path.

## Rules carried over

- Boot-path changes are proven at runtime first (Debug or `DebugRunApp`), never "flash and see".
- Private-key work stays in the kernel, under `keywork::run`; an app asks, it never holds a key.
- Every wait is bounded, including an app that never yields: the kernel can stop it.
