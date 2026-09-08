#!/usr/bin/env python3
"""Speak CatCard's USB protocol over the emulator's HID socket.

`ccemu --usb-hid PATH` hands the device's report pipe to whatever connects: one whole
64-byte report per direction, with no framing of its own. This is the host half of
`catcard-usb` -- the same framing, written independently from the doc comment rather
than shared with the firmware, so agreement between them means something.
"""
import socket, struct, sys, time

REPORT = 64
KIND_START, KIND_CONT = 1, 2
START_PAYLOAD, CONT_PAYLOAD = REPORT - 8, REPORT - 2

PING, IDENTIFY, UPGRADE_OFFER, UPGRADE_COMMIT = 0x0001, 0x0002, 0x0010, 0x0011
STATUS = {0: "Ok", 1: "UnknownOpcode", 2: "NotNow", 3: "BadRequest",
          4: "Declined", 5: "Refused", 6: "Busy"}
REJECT = {1: "Length", 2: "TooBigToStage", 3: "OutOfOrder", 4: "PastEnd",
          5: "Incomplete", 6: "NotAnImage", 7: "BadHeader", 8: "WrongBoard",
          9: "Downgrade", 10: "BadSignature", 11: "StorageFault"}


def frames(opcode, payload):
    seq = 0
    n = min(len(payload), START_PAYLOAD)
    f = bytearray(REPORT)
    f[0] = KIND_START
    f[1] = seq
    f[2:4] = struct.pack("<H", opcode)
    f[4:8] = struct.pack("<I", len(payload))
    f[8:8 + n] = payload[:n]
    yield bytes(f)
    at = n
    while at < len(payload):
        seq = (seq + 1) & 0xFF
        n = min(len(payload) - at, CONT_PAYLOAD)
        f = bytearray(REPORT)
        f[0] = KIND_CONT
        f[1] = seq
        f[2:2 + n] = payload[at:at + n]
        yield bytes(f)
        at += n


def recv_report(sock):
    """One 64-byte report, skipping empty ones.

    An all-zero report is not ours: every frame this protocol emits carries kind 1 or 2
    in its first byte. The port produces them when the device has nothing to send, so
    treating one as a framing error turns "nothing happened yet" into a failed transfer.
    """
    while True:
        buf = b""
        while len(buf) < REPORT:
            b = sock.recv(REPORT - len(buf))
            if not b:
                raise EOFError("device closed the port")
            buf += b
        if buf[0] in (KIND_START, KIND_CONT):
            return buf


def request(sock, opcode, payload=b""):
    for f in frames(opcode, payload):
        sock.sendall(f)
    r = recv_report(sock)
    if r[0] != KIND_START:
        raise ValueError(f"expected a START frame, got kind {r[0]}")
    status = struct.unpack("<H", r[2:4])[0]
    total = struct.unpack("<I", r[4:8])[0]
    body = r[8:8 + min(total, START_PAYLOAD)]
    while len(body) < total:
        c = recv_report(sock)
        body += c[2:2 + min(total - len(body), CONT_PAYLOAD)]
    return status, body


def identify(body):
    """(protocol, unlocked, board, version)."""
    ver = struct.unpack("<H", body[:2])[0]
    unlocked = bool(body[2])
    at = 3
    parts = []
    for _ in range(2):
        n = body[at]
        parts.append(body[at + 1:at + 1 + n].decode())
        at += 1 + n
    return ver, unlocked, parts[0], parts[1]


def connect(path, timeout=300.0):
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            s.connect(path)
            s.settimeout(900.0)
            return s
        except (FileNotFoundError, ConnectionRefusedError):
            time.sleep(0.05)
    raise TimeoutError(f"no socket at {path}")


def main(path, image=None):
    s = connect(path)
    ok = True

    st, body = request(s, PING, b"cat")
    print(f"ping      status={STATUS.get(st, st)} echo={body!r}")
    ok &= st == 0 and body == b"cat"

    st, body = request(s, IDENTIFY)
    if st == 0:
        proto, unlocked, board, ver = identify(body)
        print(f"identify  status=Ok protocol={proto} board={board} version={ver} "
              f"unlocked={unlocked}")
    else:
        print(f"identify  status={STATUS.get(st, st)}")
        ok = False

    if image and "--gate" in sys.argv:
        # The PIN gate: an upgrade must be refused until someone has unlocked the device
        # at the front panel, and accepted afterwards.
        blob = open(image, "rb").read()

        # While locked, send only the first frame of a properly-declared image. The
        # device refuses on that frame and resets its reassembler, so nothing is left
        # half-sent and the next message starts clean.
        first = next(frames(UPGRADE_OFFER, blob))
        s.sendall(first)
        r = recv_report(s)
        st = struct.unpack("<H", r[2:4])[0]
        print(f"offer(locked)     status={STATUS.get(st, st)}")
        ok &= st == 2  # NotNow

        # Wait for the PIN to be entered at the panel. Ask Identify, which reports the
        # state directly -- probing with an offer would leave a message half-open on the
        # device the moment it started being accepted.
        unlocked = False
        for _ in range(120):
            time.sleep(2.0)
            st, body = request(s, IDENTIFY)
            if st == 0 and identify(body)[1]:
                unlocked = True
                break
        print(f"unlocked after wait: {unlocked}")
        ok &= unlocked

        # Now the whole image, for real.
        t0 = time.time()
        st, body = request(s, UPGRADE_OFFER, blob)
        dt = time.time() - t0
        if st == 0:
            print(f"offer(unlocked)   status=Ok verified={bool(body[0])} "
                  f"len={struct.unpack('<I', body[1:5])[0]}  [{len(blob)} B in {dt:.1f}s]")
        else:
            why = REJECT.get(body[0], body[0]) if body else "?"
            print(f"offer(unlocked)   status={STATUS.get(st, st)} reason={why}")
        ok &= st == 0
        print("OK" if ok else "FAILED")
        return 0 if ok else 1

    if image:
        blob = open(image, "rb").read()
        t0 = time.time()
        st, body = request(s, UPGRADE_OFFER, blob)
        dt = time.time() - t0
        if st == 0:
            verified = body[0]
            length = struct.unpack("<I", body[1:5])[0]
            ts = body[5:13].decode(errors="replace")
            ver = body[13:21].split(b"\0")[0].decode(errors="replace")
            slot = body[21]
            older = bool(body[22]) if len(body) > 22 else False
            print(f"offer     status=Ok verified={bool(verified)} len={length} "
                  f"version={ver} key_slot={slot} older={older}"
                  f"  [{len(blob)} B in {dt:.1f}s]")
        else:
            why = REJECT.get(body[0], body[0]) if body else "?"
            print(f"offer     status={STATUS.get(st, st)} reason={why}")
            ok = False

    print("OK" if ok else "FAILED")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main(sys.argv[1], sys.argv[2] if len(sys.argv) > 2 else None))
