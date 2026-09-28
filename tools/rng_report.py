#!/usr/bin/env python3
"""Ask a paired device how healthy its random sources are (`RngHealth`, sealed).

    tools/rng_report.py hid
    tools/rng_report.py /dev/hidraw3
    tools/rng_report.py hid --json

Any build, release included: the device must be unlocked, and the computer pairs with it
first (the six-digit code is compared on both screens). No question is asked on the
device for the report itself -- it carries verdicts, never a byte a source produced.

What it says, per hardware source, is what the device's entropy pool has judged since
power-up: where the SP 800-90B start-up test stands (pending with how many bytes have
passed, passed, or failed and why), whether the last read passed the continuous tests
(repetition count and adaptive proportion), and how many reads have tripped them. And for
the pool: whether there is one (it met its policy at power-up), whether it meets the
policy now, and whether the start-up test is enforced on it (after a New wallet).

The layout is `catcard_usb::rng::Health`; see docs/USB.md, `RngHealth`.
"""

import argparse
import json
import os
import struct
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

RNG_SAMPLE, RNG_HEALTH = 0x0060, 0x0061

# `catcard_usb::rng::source`.
SOURCES = {1: "chip", 2: "se1", 3: "se2", 5: "se1wire"}
LONG_NAMES = {
    1: "MCU TRNG",
    2: "SE1 (secure element, by the bootloader)",
    3: "SE2 (second secure element)",
    5: "SE1 (its own bus, mk3)",
}

# `catcard_usb::rng::health`.
VERSION = 1
PUBLISHED, POOL, POLICY_MET, STARTUP_ENFORCED = 1, 2, 4, 8
STARTUP = {0: "pending", 1: "passed", 2: "FAILED", 3: "not tested (mixed, credited zero)"}
FAILURE = {0: "", 1: "repetition count", 2: "adaptive proportion",
           3: "constant output", 4: "read too short"}
LAST = {0: "not read yet", 1: "ok", 2: "TRIPPED"}
STARTUP_SAMPLES = 1024


def decode(body):
    """The report as a dict, or raise ValueError."""
    body = bytes(body)
    if len(body) < 4 or body[0] != VERSION:
        raise ValueError(f"not a version-{VERSION} health report ({len(body)} bytes)")
    flags, hw, count = body[1], body[2], body[3]
    if len(body) != 4 + 8 * count:
        raise ValueError(f"report says {count} sources, carries {len(body) - 4} bytes")
    sources = []
    for i in range(count):
        src, startup, failure, last, tested, trips = struct.unpack_from(
            "<BBBBHH", body, 4 + 8 * i)
        sources.append({
            "source": SOURCES.get(src, str(src)),
            "id": src,
            "startup": STARTUP.get(startup, str(startup)),
            "failure": FAILURE.get(failure, str(failure)),
            "tested": tested,
            "last_read": LAST.get(last, str(last)),
            "trips": trips,
        })
    return {
        "published": bool(flags & PUBLISHED),
        "pool": bool(flags & POOL),
        "policy_met": bool(flags & POLICY_MET),
        "startup_enforced": bool(flags & STARTUP_ENFORCED),
        "hardware_sources_counted": hw,
        "sources": sources,
    }


def render(r):
    """The report for a person."""
    if not r["published"]:
        return ("The device has not reached its menu since power-up, so it has no "
                "report yet. Unlock it and try again.")
    yes = lambda b: "yes" if b else "NO"  # noqa: E731
    lines = [
        f"entropy pool at power-up:   {yes(r['pool'])}"
        + ("" if r["pool"] else "  (it missed its policy; no wallet can be made)"),
        f"meets its policy now:       {yes(r['policy_met'])}",
        f"hardware sources counted:   {r['hardware_sources_counted']}",
        "start-up test enforced:     "
        + ("yes (a New wallet has run)" if r["startup_enforced"]
           else "not yet (it is, from the first New wallet)"),
        "",
    ]
    for s in r["sources"]:
        name = LONG_NAMES.get(s["id"], s["source"])
        st = s["startup"]
        if st == "pending":
            st += f" ({s['tested']}/{STARTUP_SAMPLES} bytes so far)"
        elif st == "FAILED":
            st += f": {s['failure']}"
        lines.append(f"{name}")
        lines.append(f"  start-up test:  {st}")
        if s["startup"] != STARTUP[3]:
            lines.append(f"  last read:      {s['last_read']}")
            lines.append(f"  reads tripped:  {s['trips']}")
    return "\n".join(lines)


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("device", help="hid, usb, /dev/hidrawN, or an emulator socket")
    ap.add_argument("--json", action="store_true", help="print the report as JSON")
    a = ap.parse_args(argv)

    import usbclient as u  # the transport; stdlib only

    sock = u.connect(a.device)
    sock.settimeout(10)
    session = u.pair_session(sock)
    st, body = u.ncry_request(sock, session, RNG_HEALTH)
    if st == 1:
        raise SystemExit("this firmware has no RNG health report (older than RngHealth)")
    if st != 0:
        raise SystemExit(f"health report refused: {u.STATUS.get(st, st)}")
    r = decode(body)
    print(json.dumps(r, indent=2) if a.json else render(r))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
