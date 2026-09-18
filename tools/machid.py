"""Reach a CatCard from macOS, where neither in-repo port works.

`usbclient.py` carries two transports: `HidRawPort`, which opens a Linux `/dev/hidraw`
node, and `LibUsbPort`, which detaches the kernel HID driver. macOS has neither -- it
gives no hidraw node and will not let a process take the interface from its own HID
driver -- so on a Mac the way in is hidapi, which is what this wraps.

It is duck-typed onto `socket` exactly as the other two are, so every line of protocol
code in `usbclient` is shared and running one really does prove something about the
other. The only wire difference is the report ID: hidapi wants a leading zero byte on
write and consumes it, and does not hand one back on read.

    ../work/ckcc-venv/bin/python tools/machid.py

prints what the device says it is. The ckcc venv's python is used because it has the
`hid` module; the system python3 does not.

See docs/USB.md for the protocol and `usbclient.py` for everything above the wire.
"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import hid  # noqa: E402  -- after the path fix above

import usbclient as u  # noqa: E402


class MacHid:
    """A hidapi device, presented with the three calls a socket offers."""

    def __init__(self, vid=u.VID, pid=u.PID):
        self.h = hid.device()
        self.h.open(vid, pid)
        self.h.set_nonblocking(0)
        # hidapi hands back whole reports; the protocol reads them in pieces.
        self._buf = b""
        self._timeout = 5.0

    def settimeout(self, t):
        # Zero means "poll" to a socket, but zero to hidapi means "block forever", which
        # would turn a quiet device into a hang rather than a timeout.
        self._timeout = t if t else 0.001

    def gettimeout(self):
        return self._timeout

    def sendall(self, data):
        # Report ID 0: hidapi consumes this byte and does not put it on the wire.
        self.h.write(b"\x00" + data)

    def recv(self, n):
        while not self._buf:
            report = self.h.read(u.REPORT, int(self._timeout * 1000))
            if not report:
                raise TimeoutError("no report from the device")
            self._buf = bytes(report)
        out, self._buf = self._buf[:n], self._buf[n:]
        return out

    def close(self):
        self.h.close()


def main():
    try:
        sock = MacHid()
    except OSError as e:
        # The commonest cause by far is a device running *stock*, which is a different
        # VID/PID entirely and answers a different protocol.
        print(f"no CatCard at {u.VID:04x}:{u.PID:04x} ({e})")
        print("a device on stock firmware is d13e:cc10 -- use the ckcc tool for that")
        return 1
    sock.settimeout(10)
    status, body = u.request(sock, u.IDENTIFY)
    told = u.identify(body)
    if status or not told:
        print(f"identify failed: status {status}")
        return 1
    protocol, unlocked, blank, board, version = told
    print(f"board      {board}")
    print(f"version    {version}")
    print(f"protocol   {protocol}")
    print(f"unlocked   {unlocked}")
    print(f"no secret  {blank}")
    print(f"caps       0x{u.capabilities(body):x}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
