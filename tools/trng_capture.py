#!/usr/bin/env python3
"""Capture raw TRNG output from a bench build, one file per source, for SP 800-90B.

    tools/trng_capture.py hid --list
    tools/trng_capture.py hid                         # every source, 1,000,000 bytes each
    tools/trng_capture.py hid --source se2 --bytes 2000000 --out captures/
    tools/trng_capture.py /dev/hidraw3 --source chip  # a named node (Linux)

On a Mac the transport is hidapi, so run it with a python that has the `hid` module
(see `tools/machid.py`). The device must be unlocked and sitting on a **menu**: it reads
its sources from the main menu loop and nowhere else, so that a capture can never run in
the middle of making a wallet. On any other screen it answers "not now" and this waits.

Each source goes to `<out>/<board>-<source>.bin`, one byte per sample, exactly the bytes
the firmware would have passed to its entropy pool (docs/ENTROPY.md). **Resumable**: an
existing file is appended to until it holds `--bytes`, so an interrupted capture carries on
where it stopped (`--fresh` starts over). The chunks are not consecutive device-side across
a pause, which is also true between any two of them: see docs/USB.md, `DebugTrng`.

Then: `tools/trng_assess.py <out>/*.bin`.

The opcode is `DebugTrng` (0x0035), a bench-only feature (`usb-trng-capture`); a release
build answers `UnknownOpcode`.
"""

import argparse
import os
import struct
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import usbclient as u  # noqa: E402

DEBUG_TRNG = 0x0035

# `catcard_usb::Status`.
OK, UNKNOWN_OPCODE, NOT_NOW, BAD_REQUEST, REFUSED, BUSY = 0, 1, 2, 3, 5, 6

# Wire numbers, `trngcap::wire_id`.
SOURCES = {1: "chip", 2: "se1", 3: "se2", 4: "bootloader", 5: "se1wire"}
BY_NAME = {v: k for k, v in SOURCES.items()}

# Chunk flags, `trngcap::flags`.
SHORT, REFUSED_FLAG = 1 << 0, 1 << 1

# SP 800-90B §3.1.1: the fewest samples a non-IID assessment takes.
DEFAULT_BYTES = 1_000_000

# How long one chunk may keep answering "not now" before we say why.
NOT_NOW_HINT_S = 5.0


def list_sources(sock):
    """(chunk_max, [wire ids]) this board can capture."""
    status, body = u.request(sock, DEBUG_TRNG, b"")
    if status == UNKNOWN_OPCODE:
        raise SystemExit(
            "this build has no raw TRNG capture (usb-trng-capture is a bench feature; "
            "a SHIP=1 image leaves it out)"
        )
    if status != OK or len(body) < 3:
        raise SystemExit(f"listing sources failed: status {status}")
    chunk_max = struct.unpack("<H", body[:2])[0]
    n = body[2]
    return chunk_max, list(body[3 : 3 + n])


def board_name(sock):
    status, body = u.request(sock, u.IDENTIFY)
    told = u.identify(body) if status == OK else None
    if not told:
        return "device"
    _protocol, unlocked, _blank, board, _version = told
    if not unlocked:
        print("note: the device is locked; unlock it and leave it on a menu")
    return board.lower().replace(" ", "")


def one_chunk(sock, source, length):
    """Ask until the chunk is ready. Returns (flags, bytes)."""
    req = struct.pack("<BH", source, length)
    started = time.time()
    hinted = False
    while True:
        status, body = u.request(sock, DEBUG_TRNG, req)
        if status == OK:
            if len(body) < 8 or body[0] != source:
                raise SystemExit(f"malformed chunk reply ({len(body)} bytes)")
            flags = body[1]
            n = struct.unpack("<H", body[2:4])[0]
            data = body[8 : 8 + n]
            if len(data) != n:
                raise SystemExit(f"chunk says {n} bytes, carried {len(data)}")
            return flags, data
        if status in (NOT_NOW, BUSY):
            if not hinted and time.time() - started > NOT_NOW_HINT_S:
                print("\nwaiting: is the device unlocked and on a menu screen?")
                hinted = True
            time.sleep(0.01)
            continue
        if status == REFUSED:
            raise SystemExit(f"this board has no source {SOURCES.get(source, source)}")
        raise SystemExit(f"capture failed: status {status}")


def capture(sock, source, total, path, chunk, fresh=False):
    have = 0 if fresh or not os.path.exists(path) else os.path.getsize(path)
    if have >= total:
        print(f"{path}: already {have} bytes")
        return
    mode = "wb" if fresh else "ab"
    name = SOURCES.get(source, str(source))
    short = refused = 0
    t0 = time.time()
    start = have
    with open(path, mode) as f:
        while have < total:
            want = min(chunk, total - have)
            flags, data = one_chunk(sock, source, want)
            f.write(data)
            f.flush()
            have += len(data)
            short += bool(flags & SHORT)
            if flags & REFUSED_FLAG:
                refused += 1
                print(f"\n{name}: the source refused a read; stopping at {have} bytes")
                break
            rate = (have - start) / max(time.time() - t0, 1e-6)
            left = (total - have) / rate if rate else 0
            print(
                f"\r{name}: {have}/{total} bytes, {rate / 1024:.1f} KB/s, "
                f"~{left / 60:.0f} min left   ",
                end="",
                flush=True,
            )
    print(f"\n{path}: {have} bytes ({short} short chunks)")


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("device", help="hid, usb, /dev/hidrawN, or an emulator socket")
    ap.add_argument(
        "--source",
        default="all",
        help="all, or one of: " + ", ".join(SOURCES.values()),
    )
    ap.add_argument("--bytes", type=int, default=DEFAULT_BYTES, help="per source")
    ap.add_argument("--out", default="captures", help="directory for the .bin files")
    ap.add_argument("--fresh", action="store_true", help="overwrite instead of resuming")
    ap.add_argument("--list", action="store_true", help="list this board's sources")
    a = ap.parse_args(argv)

    sock = u.connect(a.device)
    sock.settimeout(10)
    chunk_max, have = list_sources(sock)
    if a.list:
        print("sources:", ", ".join(SOURCES.get(s, str(s)) for s in have))
        print(f"chunk:   {chunk_max} bytes")
        return 0
    if a.source == "all":
        wanted = have
    else:
        if a.source not in BY_NAME:
            raise SystemExit(f"unknown source {a.source!r}")
        wanted = [BY_NAME[a.source]]
    board = board_name(sock)
    os.makedirs(a.out, exist_ok=True)
    for s in wanted:
        path = os.path.join(a.out, f"{board}-{SOURCES.get(s, s)}.bin")
        capture(sock, s, a.bytes, path, chunk_max, a.fresh)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
