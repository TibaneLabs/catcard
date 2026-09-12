#!/usr/bin/env python3
"""Speak CatCard's USB protocol, to the emulator or to a real device.

Two transports, because the protocol is the same either way and the point of this tool
is that what is verified against the emulator is what runs against hardware:

    tools/usbclient.py /tmp/x.sock ...      the emulator's --usb-hid socket
    tools/usbclient.py hid ...              a real device, found by VID:PID
    tools/usbclient.py /dev/hidraw3 ...     a real device, named outright

Reading and writing /dev/hidraw* usually needs root or a udev rule -- see docs/USB.md.

`ccemu --usb-hid PATH` hands the device's report pipe to whatever connects: one whole
64-byte report per direction, with no framing of its own. This is the host half of
`catcard-usb` -- the same framing, written independently from the doc comment rather
than shared with the firmware, so agreement between them means something.
"""
import glob
import os
import zlib
import select
import socket, struct, sys, time

REPORT = 64
KIND_START, KIND_CONT = 1, 2
START_PAYLOAD, CONT_PAYLOAD = REPORT - 8, REPORT - 2

PING, IDENTIFY, UPGRADE_OFFER, UPGRADE_COMMIT = 0x0001, 0x0002, 0x0010, 0x0011
INJECT_KEY = 0x0020
KEY_CANCEL, KEY_CONFIRM = 0x0A, 0x0B


def key_byte(k):
    """`0`..`9`, `x`, `y` as the wire encodes them."""
    if k == "x":
        return KEY_CANCEL
    if k == "y":
        return KEY_CONFIRM
    return int(k)


def press(sock, keys, settle=0.35, expect_reply=True):
    """Press keys one at a time, giving each one time to be read.

    One at a time on purpose: the device queues a single key, so a host that runs ahead
    of the screen it is answering would lose presses -- or worse, land one on a
    confirmation it has not read yet.

    `expect_reply=False` for the press that approves a firmware install. That key makes
    the device stage the image and reboot, so the reply may never arrive -- waiting for
    one hangs the host against a device that is behaving correctly.
    """
    for k in keys:
        if not expect_reply:
            for f in frames(INJECT_KEY, bytes([key_byte(k)])):
                sock.sendall(f)
            time.sleep(settle)
            # Take the acknowledgement if one comes, and throw it away. Not waiting for
            # it is the point -- the device may be rebooting -- but leaving it unread
            # shifts every later reply by one message, and the next thing read is the
            # answer to the previous question. That is how an install diagnostic came
            # back reading `117, 112`: the first two bytes of an earlier ping echo.
            was = sock.gettimeout()
            try:
                sock.settimeout(2.0)
                recv_report(sock)
            except (TimeoutError, EOFError, OSError):
                pass
            finally:
                sock.settimeout(was)
            continue
        try:
            st, _ = request(sock, INJECT_KEY, bytes([key_byte(k)]))
        except TimeoutError:
            raise RuntimeError(f"key {k!r}: device stopped answering USB") from None
        if st != 0:
            raise RuntimeError(f"key {k!r} refused: {STATUS.get(st, st)}")
        time.sleep(settle)
STATUS = {0: "Ok", 1: "UnknownOpcode", 2: "NotNow", 3: "BadRequest",
          4: "Declined", 5: "Refused", 6: "Busy"}
REJECT = {1: "Length", 2: "TooBigToStage", 3: "OutOfOrder", 4: "PastEnd",
          5: "Incomplete", 6: "NotAnImage", 7: "BadHeader", 8: "WrongBoard",
          9: "Downgrade", 10: "BadSignature", 11: "StorageFault",
          12: "NoStagingArea"}

# Capability bits, matching `catcard_usb::caps`.
CAP_KEY_INJECTION = 1 << 0
CAP_UPGRADE = 1 << 1


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


def capabilities(body):
    return body[3] if len(body) > 3 else 0


# Device state bits, matching `catcard_usb::state`.
UNLOCKED = 1 << 0
BLANK = 1 << 1


def identify(body):
    """(protocol, unlocked, blank, board, version), or None if the body is not one."""
    # Layout: protocol[0..2], state[2], caps[3], then two length-prefixed strings.
    # The strings start at 4, after the capability byte -- reading them from 3 takes
    # the caps byte as a length and silently desynchronises board from version.
    if len(body) < 4:
        return None
    ver = struct.unpack("<H", body[:2])[0]
    state = body[2]
    at = 4
    parts = []
    for _ in range(2):
        if at >= len(body):
            return None
        n = body[at]
        parts.append(body[at + 1:at + 1 + n].decode(errors="replace"))
        at += 1 + n
    return ver, bool(state & UNLOCKED), bool(state & BLANK), parts[0], parts[1]


def went_quiet(sock, wait=120.0):
    """True once the device stops answering, which is how a reset looks from here.

    Installing a firmware means rebooting into the bootloader, so the port goes away.
    That silence is the only confirmation the host gets that the approval landed.
    """
    deadline = time.time() + wait
    sock.settimeout(5.0)
    while time.time() < deadline:
        try:
            request(sock, PING, b"up?")
        except (TimeoutError, EOFError, OSError):
            return True
        time.sleep(1.0)
    return False


def came_back(sock, path, wait=900.0):
    """Wait for the device to answer again after a reset, and say what it is running.

    Keeps using the socket it already has. The port is a single accepted connection on
    the emulator side, so dropping it and dialling again is not a reconnect -- it is a
    second client the emulator was never going to serve, which reads as "the device
    never came back" no matter what the device did.
    """
    deadline = time.time() + wait
    sock.settimeout(10.0)
    while time.time() < deadline:
        try:
            st, body = request(sock, IDENTIFY)
            info = identify(body) if st == 0 else None
            if info:
                return info[4]
        except (TimeoutError, ValueError):
            pass
        except (EOFError, OSError):
            # The port really did go away; a fresh connection is the only option left.
            try:
                sock = connect(path, timeout=30.0)
                sock.settimeout(10.0)
            except (TimeoutError, OSError):
                return None
        time.sleep(2.0)
    return None


# Firmware header, from `catcard_fwhdr::FirmwareHeader`: magic u32, timestamp[8], then
# the NUL-padded ASCII version.
HEADER_AT = 0x3F80
VERSION_AT = HEADER_AT + 4 + 8


def image_version(blob):
    """The version string inside a raw signed image, or None."""
    if len(blob) < VERSION_AT + 8:
        return None
    raw = blob[VERSION_AT:VERSION_AT + 8]
    return raw.split(b"\x00")[0].decode(errors="replace") or None


def load_image(path):
    """The raw signed image, unwrapping a DfuSe container if that is what was handed in.

    The device takes a raw image and knows nothing about DfuSe. Keeping it that way is
    deliberate -- the upgrade parser is reachable by anything that can open the port, so
    it should stay as small as it can be, and a container format is the host's problem.

    Doing it here rather than making the caller run `catcard-image extract` means the
    file you flash through stock and the file you offer to CatCard can be the same file.
    """
    raw = open(path, "rb").read()
    if raw[:5] != b"DfuSe":
        return raw

    # Layout, matching tools/catcard-image/src/dfuse.rs:
    #   prefix 11 = "DfuSe" | version | DFUImageSize u32 | targets u8
    #   target 274 = "Target" | alt | named u32 | name[255] | size u32 | elements u32
    #   then per element: address u32 | size u32 | data
    #   suffix 16, ending "UFD" + length + CRC over everything before it
    if len(raw) < 11 + 274 + 16:
        raise ValueError(f"{path}: too short to be a DfuSe container")
    if raw[5] != 1:
        raise ValueError(f"{path}: unsupported DfuSe version {raw[5]}")

    suffix = raw[-16:]
    if suffix[8:11] != b"UFD":
        raise ValueError(f"{path}: missing UFD suffix")
    want = struct.unpack("<I", suffix[12:16])[0]
    got = zlib.crc32(raw[:-4]) ^ 0xFFFFFFFF
    if got != want:
        raise ValueError(f"{path}: DFU suffix CRC mismatch {got:#010x} != {want:#010x}")

    size = struct.unpack("<I", raw[6:10])[0]
    if size != len(raw) - 16:
        raise ValueError(f"{path}: DFUImageSize {size} disagrees with the file length")
    if raw[10] != 1:
        raise ValueError(f"{path}: expected exactly one target, got {raw[10]}")

    t = raw[11:]
    if t[:6] != b"Target":
        raise ValueError(f"{path}: missing Target signature")
    count = struct.unpack("<I", t[270:274])[0]
    if count < 1:
        raise ValueError(f"{path}: container holds no elements")

    addr, esize = struct.unpack("<II", t[274:282])
    data = t[282:282 + esize]
    if len(data) != esize:
        raise ValueError(f"{path}: element data runs past the end of the file")
    print(f"image     unwrapped DfuSe: {esize} bytes for {addr:#010x}"
          + (f" ({count} elements, offering the first)" if count > 1 else ""))
    return data


# CatCard's own VID/PID. Source: docs/USB.md.
VID = 0x39F2
PID = 0x0401


class HidRawPort:
    """A real USB HID device, presented with the three calls a socket offers.

    Duck-typed onto `socket` rather than abstracted behind an interface: every line of
    protocol code above is then shared by the emulator and the hardware, which is the
    only way running one proves anything about the other.
    """

    def __init__(self, path):
        self.fd = os.open(path, os.O_RDWR)
        self.path = path
        # Matches the socket transport: the first reply waits on the whole boot, and
        # `main` tightens this once the device has answered once. Never None, or a
        # device that says nothing hangs the tool with no way to tell.
        self.timeout = 900.0
        self._buf = b""

    def settimeout(self, t):
        self.timeout = t

    def gettimeout(self):
        return self.timeout

    def sendall(self, data):
        # The report descriptor declares no report ID, so hidraw wants a leading 0.
        os.write(self.fd, b"\x00" + data)

    def recv(self, n):
        # hidraw hands over one whole report per read, so a short request cannot be
        # passed through -- it would drop the rest of the report. Buffer instead.
        while not self._buf:
            ready, _, _ = select.select([self.fd], [], [], self.timeout)
            if not ready:
                raise TimeoutError("timed out")
            self._buf = os.read(self.fd, REPORT)
            if not self._buf:
                raise EOFError("device closed the port")
        out, self._buf = self._buf[:n], self._buf[n:]
        return out

    def close(self):
        os.close(self.fd)


def find_hidraw(vid=VID, pid=PID):
    """Every /dev/hidraw node matching a VID/PID, newest first."""
    out = []
    for node in sorted(glob.glob("/sys/class/hidraw/hidraw*")):
        try:
            with open(f"{node}/device/uevent") as f:
                uevent = f.read()
        except OSError:
            continue
        # HID_ID=0003:000039F2:00000401 -- bus:vendor:product, hex, zero-padded.
        for line in uevent.splitlines():
            if line.startswith("HID_ID="):
                parts = line.split("=", 1)[1].split(":")
                if len(parts) == 3 and int(parts[1], 16) == vid and int(parts[2], 16) == pid:
                    out.append("/dev/" + node.rsplit("/", 1)[1])
    return out


READ_LOG = 0x0012
DEBUG_PEEK, DEBUG_POKE, DEBUG_JSR = 0x0030, 0x0031, 0x0032


def fetch_log(s):
    """The device's log, oldest first, as text.

    Paged because a reply is one 64-byte report. The device reports the total and
    whether it wrapped, so a truncated boot log cannot be mistaken for a complete one.
    """
    out = bytearray()
    at = 0
    total, wrapped = None, False
    while True:
        st, body = request(s, READ_LOG, struct.pack("<I", at))
        if st != 0 or len(body) < 5:
            break
        total = struct.unpack("<I", body[:4])[0]
        wrapped = bool(body[4] & 1)
        chunk = body[5:]
        if not chunk:
            break
        out += chunk
        at += len(chunk)
        if total is not None and at >= total:
            break
    return bytes(out), total, wrapped


def print_log(s):
    text, total, wrapped = fetch_log(s)
    if total is None:
        print("log       device does not keep one")
        return
    if wrapped:
        print(f"log       {total} bytes, WRAPPED -- oldest lines were dropped")
    else:
        print(f"log       {total} bytes")
    for line in text.decode(errors="replace").splitlines():
        print(f"  | {line}")


def peek(s, addr, count, width=4):
    """Read `count` words of `width` bytes from `addr`; returns bytes."""
    st, body = request(s, DEBUG_PEEK, struct.pack("<IBB", addr, width, count))
    if st != 0:
        raise RuntimeError(f"peek {addr:#x}: {STATUS.get(st, st)}")
    return body


def poke(s, addr, data, width=4):
    """Write `data` (bytes) to `addr` in `width`-byte units.

    Paged one frame per request: the device reassembles a multi-frame message only for a
    firmware upgrade (it streams that to staging), so an ordinary poke has to fit one
    frame -- 56 bytes minus the 5-byte addr+width header. Longer writes go as several
    requests with the address advancing, which is transparent to the caller.
    """
    data = bytes(data)
    if len(data) % width:
        raise ValueError(f"poke length {len(data)} is not a multiple of width {width}")
    per = ((56 - 5) // width) * width  # whole elements that fit one frame
    at = 0
    while at < len(data):
        chunk = data[at : at + per]
        st, _ = request(s, DEBUG_POKE, struct.pack("<IB", addr + at, width) + chunk)
        if st != 0:
            raise RuntimeError(f"poke {addr + at:#x}: {STATUS.get(st, st)}")
        at += len(chunk)


def jsr(s, addr, arg=0):
    """Call `addr` as fn(u32)->u32; returns the u32 result."""
    st, body = request(s, DEBUG_JSR, struct.pack("<II", addr, arg))
    if st != 0:
        raise RuntimeError(f"jsr {addr:#x}: {STATUS.get(st, st)}")
    return struct.unpack("<I", body[:4])[0]


class LibUsbPort:
    """A real device over libusb, driving its interrupt endpoints directly.

    Same protocol as the hidraw path -- 64-byte frames on EP 0x81 IN / 0x01 OUT -- but
    through usbfs instead of the kernel HID driver, which it detaches first. Needed when
    the hidraw node is root-only but usbfs is reachable (the `usb` group), and it is the
    one wire difference worth noting: **no leading report-ID byte.** hidraw prepends a 0
    the kernel strips; here the 64-byte report goes on the wire as-is.
    """

    EP_IN, EP_OUT, INTF = 0x81, 0x01, 0

    def __init__(self, vid=VID, pid=PID):
        import usb.core

        self.dev = usb.core.find(idVendor=vid, idProduct=pid)
        if self.dev is None:
            raise TimeoutError(f"no USB device {vid:04x}:{pid:04x}")
        # Take the interface from the kernel HID driver so we can drive it.
        if self.dev.is_kernel_driver_active(self.INTF):
            self.dev.detach_kernel_driver(self.INTF)
        self.dev.set_configuration()
        usb.util.claim_interface(self.dev, self.INTF)
        self._timeout_ms = 900_000
        self._buf = b""

    def settimeout(self, t):
        self._timeout_ms = int(t * 1000)

    def gettimeout(self):
        return self._timeout_ms / 1000

    def sendall(self, data):
        # No report-ID byte here, unlike hidraw: the frame is already a whole report.
        self.dev.write(self.EP_OUT, bytes(data), timeout=self._timeout_ms)

    def recv(self, n):
        while not self._buf:
            try:
                r = self.dev.read(self.EP_IN, REPORT, timeout=self._timeout_ms)
            except Exception as e:
                # pyusb raises USBTimeoutError (a subclass of USBError); treat any read
                # failure the framing layer should retry on as a socket timeout.
                if "timeout" in str(e).lower():
                    raise TimeoutError("timed out") from None
                raise
            self._buf = bytes(r)
        out, self._buf = self._buf[:n], self._buf[n:]
        return out

    def close(self):
        import usb.util

        usb.util.release_interface(self.dev, self.INTF)


def connect(path, timeout=300.0):
    """Open the emulator socket, or a real device when asked for one."""
    if path.startswith("/dev/hidraw"):
        return HidRawPort(path)
    if path == "usb":
        # Raw libusb, for when the hidraw node is not readable.
        return LibUsbPort()
    if path in ("hid",):
        deadline = time.time() + timeout
        while True:
            found = find_hidraw()
            if found:
                if len(found) > 1:
                    print(f"note: {len(found)} matching devices; using {found[0]}")
                return HidRawPort(found[0])
            if time.time() >= deadline:
                raise TimeoutError(
                    f"no USB device with VID:PID {VID:04x}:{PID:04x}. "
                    "Is it plugged in, and can you read /dev/hidraw*? See docs/USB.md."
                )
            time.sleep(0.5)
    return connect_unix(path, timeout)


def connect_unix(path, timeout=300.0):
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            s.connect(path)
            # Generous, because the first reply waits on the whole boot: bootloader,
            # signature check, and a 25-second dev-key warning screen, all at emulated
            # speed. `main` tightens this once the device has answered once.
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

    # The device has answered once, so it is booted and pumping. From here a reply that
    # does not come back promptly means it stopped pumping -- a stall, not slow work --
    # and waiting out the boot-sized timeout for that just hides where it stopped.
    s.settimeout(float(next((a.split("=")[1] for a in sys.argv
                             if a.startswith("--timeout=")), 90.0)))

    st, body = request(s, IDENTIFY)
    if st == 0:
        info = identify(body)
        if info is None:
            print(f"identify  status=Ok but body is {len(body)}B: {body[:16].hex()}")
            ok = False
        else:
            proto, unlocked, blank, board, ver = info
            print(f"identify  status=Ok protocol={proto} board={board} version={ver} "
                  f"unlocked={unlocked} blank={blank}")
    else:
        print(f"identify  status={STATUS.get(st, st)}")
        ok = False

    def arg_after(flag):
        i = sys.argv.index(flag)
        return sys.argv[i + 1 :]

    if "--peek" in sys.argv:
        a = arg_after("--peek")
        addr = int(a[0], 0)
        n = int(a[1], 0) if len(a) > 1 else 16
        width = int(a[2], 0) if len(a) > 2 else 4
        data = b""
        # Page across requests. Each request now returns a multi-frame reply, so the page
        # is a few hundred bytes rather than one frame -- `count` is a u8 and the device
        # reply buffer is 512, so up to 128 words or 255 bytes go per request.
        target = n * width
        while len(data) < target:
            remaining = (target - len(data)) // width
            want = min(remaining, 512 // width, 255)
            if want == 0:
                break
            got = peek(s, addr + len(data), want, width)
            if not got:
                break
            data += got
        for off in range(0, len(data), 16):
            row = data[off : off + 16]
            hexs = " ".join(f"{b:02x}" for b in row)
            print(f"{addr + off:08x}  {hexs}")
        return 0

    if "--poke" in sys.argv:
        a = arg_after("--poke")
        addr = int(a[0], 0)
        data = bytes.fromhex(a[1].replace("_", ""))
        width = int(a[2], 0) if len(a) > 2 else 1
        poke(s, addr, data, width)
        print(f"poke      {len(data)} bytes to {addr:#010x}")
        return 0

    if "--jsr" in sys.argv:
        a = arg_after("--jsr")
        addr = int(a[0], 0)
        arg = int(a[1], 0) if len(a) > 1 else 0
        print(f"jsr       {addr:#010x}(arg={arg:#x}) -> {jsr(s, addr, arg):#010x}")
        return 0

    if "--log" in sys.argv:
        # The whole point of the log: a device whose screen cannot be read can still say
        # what happened to it.
        print_log(s)
        return 0

    if "--drive" in sys.argv:
        # The whole device over USB, with nothing touching the keypad: past the selftest
        # screen, through a PIN, and -- if an image was given -- through an upgrade and
        # its approval. This is the escape route for a first run on hardware whose panel
        # and key map are both unconfirmed.
        st, body = request(s, IDENTIFY)
        caps = capabilities(body)
        if not caps & CAP_KEY_INJECTION:
            print("identify  this build does not accept injected keys")
            return 1
        print("identify  key injection available")
        if not caps & CAP_UPGRADE:
            # Say it here rather than letting the offer fail after a long transfer.
            print("identify  device cannot stage an upgrade (no staging area wired up)")

        press(s, "y")                      # leave the selftest screen

        pin = next((a for a in sys.argv if a.startswith("--pin=")), "--pin=12-3456")
        prefix, _, suffix = pin[len("--pin="):].partition("-")

        def enter_pin():
            """Prefix, acknowledge the words, suffix."""
            press(s, prefix + "y")
            press(s, "y")                  # acknowledge the anti-phishing words
            press(s, suffix + "y")

        st, body = request(s, IDENTIFY)
        info = identify(body)
        if info and info[2]:
            # No PIN has ever been set -- a factory-fresh secure element, which is what
            # the emulator gives us. Set one, then log in with it. Without this the
            # drive test just held down `y` against a screen that wanted setup.
            print("setup     device is blank, setting a first PIN")
            press(s, "y")                  # accept the offer to choose a PIN
            enter_pin()
            st, body = request(s, IDENTIFY)
            info = identify(body)
        if info and not info[1]:
            enter_pin()
        st, body = request(s, IDENTIFY)
        info = identify(body)
        if info is None:
            # Printing "?" here told me nothing when it happened. The status and the
            # body are what say whether the device refused, answered something else, or
            # answered nothing at all.
            print(f"unlocked  ? identify status={STATUS.get(st, st)} "
                  f"body={len(body)}B {body[:24].hex()}")
        print(f"unlocked  {info[1] if info else '?'} running={info[4] if info else '?'}")
        ok &= bool(info and info[1])

        if image and ok and not caps & CAP_UPGRADE:
            print("offer     skipped: this board has nowhere to stage an image")
        elif image and ok:
            blob = load_image(image)
            st, body = request(s, UPGRADE_OFFER, blob)
            if st == 0:
                print(f"offer     status=Ok verified={bool(body[0])} "
                      f"len={struct.unpack('<I', body[1:5])[0]}")
                # Approve at the device, over USB. No reply is expected: this key is
                # the one that reboots the device into its installer.
                press(s, "y", expect_reply=False)
                # And confirm it actually happened. Printing "approved" straight after
                # sending the key claimed an outcome from having sent a byte -- the
                # device going quiet is the first evidence that the key landed and the
                # install began.
                if went_quiet(s):
                    print("approved  device stopped answering: it reset to install")
                else:
                    print("approved  but the device is still answering -- no reset")
                    # The device is up, so it can be asked rather than guessed at.
                    print_log(s)
                    ok = False
                # The reset only proves the approval landed. Whether the image was
                # actually installed is a different claim, and the only way to check it
                # from here is to wait for the device to come back and ask what it is
                # now running. Offer a differently-versioned image to make that visible.
                if ok:
                    was = info[4] if info else None
                    offered = image_version(blob)
                    back = came_back(s, path)
                    if back is None:
                        print("install   device did not come back")
                        ok = False
                    elif offered == was:
                        # The offered image carries the same version as the running one,
                        # so coming back as that version proves nothing either way. Say
                        # that, rather than reporting a pass or a failure we cannot tell
                        # apart. Offer a differently-versioned image to make it provable.
                        print(f"install   UNPROVABLE: offered and running are both "
                              f"{back}; version cannot distinguish them")
                    elif was is not None and back == was and "--expect-install" not in sys.argv:
                        # Report it, but do not fail the run: under the emulator this
                        # cannot pass, because PSRAM does not survive the reset. Pass
                        # `--expect-install` on hardware, where it must.
                        print(f"install   NOT VERIFIED: still running {back}")
                        print("install   expected under the emulator, which refills "
                              "PSRAM at reset; check the staging itself with:")
                        print("install     ccemu run ... --no-secure-die --dump-ram r.bin")
                        print("install     tools/emu/psramcheck.py r.bin --image <image>")
                    elif was is not None and back == was:
                        # Coming back is not the same as having installed anything. The
                        # device reboots either way; only the version it reports
                        # afterwards says whether the staged image was taken.
                        print(f"install   FAILED: still running {back}, "
                              f"the staged image was not installed")
                        print("install   if this is the emulator, check the staging "
                              "itself before suspecting the firmware:")
                        print("install     ccemu run ... --no-secure-die --dump-ram r.bin")
                        print("install     tools/emu/psramcheck.py r.bin --image <image>")
                        print("install   the emulator refills PSRAM at reset, so a "
                              "correctly staged image is gone before the bootloader looks")
                        ok = False
                    else:
                        print(f"install   device came back running {back} (was {was})")
            else:
                print(f"offer     status={STATUS.get(st, st)}")
                ok = False
        print("OK" if ok else "FAILED")
        return 0 if ok else 1

    if image and "--gate" in sys.argv:
        # The PIN gate: an upgrade must be refused until someone has unlocked the device
        # at the front panel, and accepted afterwards.
        blob = load_image(image)

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
        for n in range(120):
            time.sleep(2.0)
            st, body = request(s, IDENTIFY)
            info = identify(body) if st == 0 else None
            if info is None:
                print(f"  poll {n}: status={STATUS.get(st, st)} body={len(body)}B "
                      f"{body[:8].hex()}", flush=True)
                continue
            if info[1]:
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
        blob = load_image(image)
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
