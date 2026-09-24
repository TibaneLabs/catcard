#!/usr/bin/env python3
"""Speak CatCard's USB protocol, to the emulator or to a real device.

Two transports, because the protocol is the same either way and the point of this tool
is that what is verified against the emulator is what runs against hardware:

    tools/usbclient.py /tmp/x.sock ...      the emulator's --usb-hid socket
    tools/usbclient.py hid ...              a real device, found by VID:PID
    tools/usbclient.py /dev/hidraw3 ...     a real device, named outright

The microSD bridge, on a bring-up build:

    tools/usbclient.py hid --sd-cid                 the card's identity, decoded
    tools/usbclient.py hid --sd 13 0x1234 --resp=short      one command, by number
    tools/usbclient.py hid --sd 42 0 --write=0001...        one with data to the card

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
SD_RAW = 0x0034
UPGRADE_PACKED = 0x0013
INJECT_KEY = 0x0020
UNLOCK_PIN = 0x0021
KEY_CANCEL, KEY_CONFIRM = 0x0A, 0x0B


def key_byte(k):
    """`0`..`9`, `x`, `y` as the wire encodes them."""
    if k == "x":
        return KEY_CANCEL
    if k == "y":
        return KEY_CONFIRM
    return int(k)


def unlock_with_pin(sock, pin):
    """Submit the whole PIN and wait for the device to report itself unlocked.

    The device applies the PIN asynchronously in its login loop -- the `Ok` to the
    command means only that it was accepted -- so this polls Identify for the UNLOCKED
    state bit rather than trusting the command's own reply. Identify may time out while
    the device is inside a secure-element call, so a timeout is just another poll.
    """
    st, _ = request(sock, UNLOCK_PIN, pin.encode())
    if st != 0:
        raise RuntimeError(f"unlock refused: {STATUS.get(st, st)}")
    for _ in range(40):
        time.sleep(0.25)
        try:
            _st, body = request(sock, IDENTIFY)
        except (TimeoutError, OSError, EOFError):
            continue
        info = identify(body)
        if info and info[1]:
            return True
    return False


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
RETRY_UNCOMPRESSED = 0x0007

STATUS = {0: "Ok", 1: "UnknownOpcode", 2: "NotNow", 3: "BadRequest",
          4: "Declined", 5: "Refused", 6: "Busy",
          7: "RetryUncompressed"}
REJECT = {1: "Length", 2: "TooBigToStage", 3: "OutOfOrder", 4: "PastEnd",
          5: "Incomplete", 6: "NotAnImage", 7: "BadHeader", 8: "WrongBoard",
          9: "Downgrade", 10: "BadSignature", 11: "StorageFault",
          12: "NoStagingArea", 13: "StagingBusy", 14: "RamStoreFailed",
          15: "Unpackable", 16: "Unaligned", 17: "Sealed"}

# Capability bits, matching `catcard_usb::caps`.
CAP_KEY_INJECTION = 1 << 0
CAP_UPGRADE = 1 << 1
CAP_DEBUG_MEM = 1 << 2
CAP_UNLOCK_PIN = 1 << 3
CAP_UPGRADE_PACKED = 1 << 4

# One deflate stream per this many bytes of image.
#
# The device inflates a block into a fixed slab, so a larger one than its slab cannot
# work. It used to be this side's job to know that number, and when the firmware's
# changed and this did not, an upload failed part way through with a frame error and
# no sign of why. So the size now travels in the offer and the device checks it --
# this is a preference, not a shared secret.
PACK_BLOCK = 8 * 1024


def pack_image(blob):
    """The image as the device's packed offer wants it.

    `[u32 uncompressed length][u32 block size][deflate stream]...`, one stream per
    block. Nothing frames the streams: deflate marks its own final block and the device
    splits them on that, so there is one account of where a block ends rather than two.

    The block size is declared rather than assumed. A device whose slab is smaller
    answers `RetryUncompressed` and gets the image the other way, instead of failing
    somewhere in the middle of it.

    The length prefix is the uncompressed one -- what the signature was computed over.
    The device stops there, so a stream that would produce more is refused rather than
    quietly truncated.
    """
    out = [struct.pack("<II", len(blob), PACK_BLOCK)]
    for at in range(0, len(blob), PACK_BLOCK):
        # `wbits=-15`: raw deflate, no zlib or gzip wrapper. The window is the block,
        # which is all a block's matches can reach anyway.
        c = zlib.compressobj(9, zlib.DEFLATED, -15)
        out.append(c.compress(blob[at:at + PACK_BLOCK]) + c.flush())
    return b"".join(out)


def offer(sock, blob, caps):
    """Offer an image, compressed if the device says it can take one that way.

    Returns `(status, body, sent)` -- `sent` being the bytes that actually crossed the
    wire, which is the number worth printing next to the time.
    """
    if caps & CAP_UPGRADE_PACKED:
        packed = pack_image(blob)
        # Only if it is actually smaller. An image that does not compress -- already
        # packed, or encrypted -- would otherwise pay the deflate overhead for nothing.
        if len(packed) < len(blob):
            st, body = request(sock, UPGRADE_PACKED, packed)
            # The device can decline the *compression* without declining the image: it
            # takes a buffer to inflate into and it may not have one to spare. Sending
            # it uncompressed needs no buffer at all, so that is simply what we do --
            # no question for the user, who did not ask about compression either way.
            if st != RETRY_UNCOMPRESSED:
                return st, body, len(packed)
            print("offer     device has no room to decompress; resending uncompressed")
    st, body = request(sock, UPGRADE_OFFER, blob)
    return st, body, len(blob)



# --- the raw SD bridge ---------------------------------------------------------------
#
# One command to the card, and what it said back. The device only serves these on a
# bring-up build (`usb-debug-mem`), because between them these cover the whole card
# protocol -- including erasing it and locking it with a password nobody knows.

SD_NONE, SD_SHORT, SD_LONG = 0, 1, 2


def sd_raw(s, cmd, arg=0, resp=SD_SHORT, read=0, write=None):
    """Send one SD command. Returns (status, [r0, r1, r2, r3], data)."""
    flags = resp & 3
    length = 0
    if read:
        flags |= 4
        length = read
    if write is not None:
        flags |= 8
        length = len(write)
    body = struct.pack("<BBHI", cmd, flags, length, arg)
    if write is not None:
        body += bytes(write)
    st, reply = request(s, SD_RAW, body)
    if st != 0:
        raise SystemExit(f"sd: device refused the request ({STATUS.get(st, st)})")
    status, _, n = struct.unpack("<BBH", reply[:4])
    words = list(struct.unpack("<4I", reply[4:20]))
    return status, words, reply[20:20 + n]


def sd_bits(words):
    """The 128 bits of a long response, most significant first, as bytes.

    A long response holds a CID or a CSD. The controller gives four words with the
    register's low bits in `RESP4`, and the bit numbering in the spec counts from the
    other end -- so this puts them back in the order the tables are written in.
    """
    out = b""
    for w in words:
        out += w.to_bytes(4, "big")
    return out


def sd_cid(s):
    """Read the card's CID, with the card first put back in identification mode.

    `CMD10 SEND_CID` is addressed, so it needs the card's RCA -- which the bridge learned
    at init and does not tell us. `CMD2 ALL_SEND_CID` answers from any card on the bus,
    but only before one is selected. So this deselects first, which is what makes the
    question askable at all without knowing the address.
    """
    sd_raw(s, 7, 0, SD_NONE)  # CMD7 with RCA 0: deselect
    status, words, _ = sd_raw(s, 2, 0, SD_LONG)
    if status != 0:
        raise SystemExit("sd: the card did not answer CMD2")
    return sd_bits(words)


def decode_cid(raw):
    """The CID's fields, as the SD specification lays them out. [C] SD Part 1 §5.2"""
    # The controller drops the register's CRC byte, so the 128 bits here are the
    # register's top 120 with the low byte reading as zero.
    mid = raw[0]
    oid = raw[1:3].decode("ascii", "replace")
    pnm = raw[3:8].decode("ascii", "replace")
    prv = f"{raw[8] >> 4}.{raw[8] & 15}"
    psn = int.from_bytes(raw[9:13], "big")
    mdt = int.from_bytes(raw[13:15], "big") & 0xFFF
    year, month = 2000 + (mdt >> 4), mdt & 15
    return {
        "manufacturer": mid,
        "oem": oid,
        "product": pnm,
        "revision": prv,
        "serial": psn,
        "made": f"{year}-{month:02d}",
    }


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


# --- staging by hand, for when the firmware's own staging path is the broken thing ---
#
# The PSRAM map, from `catcard_board::spec` and hw-reference/storage.md. Only the Q1 and
# mk4/mk5 have PSRAM; mk3 stages into SPI-NOR and none of this applies.
PSRAM_BASE = 0x9000_0000
PSRAM_LEN = 8 * 1024 * 1024
PSRAM_IMAGE = PSRAM_BASE + PSRAM_LEN // 2     # where an image stages: the upper half
PSRAM_HEADER = 0x907F_F800                    # the bootloader's recovery marker
HDR_MAGIC1 = 0xDBCC_8350
HDR_MAGIC2 = 0xBAFC_FBA3


def stage_by_poke(s, blob, progress=True):
    """Write `blob` into PSRAM and publish the recovery header, using the monitor.

    For the case the ordinary paths cannot cover: the firmware's own staging is what is
    broken, so neither the USB offer nor the card can be used to replace it. Poking goes
    straight to the bus and touches none of that code.

    It is also gentler on the part than it looks. Each request carries one frame, so a
    write is a short burst with the bus idle until the next one arrives -- which is far
    more CE#-high time than the 50 ns the part asks for between bursts, without anything
    having to arrange it.

    Returns the region `(start_offset, length)` that `gate 18/7` would be given.
    """
    if len(blob) % 4:
        blob = blob + b"\x00" * (4 - len(blob) % 4)
    per = ((56 - 5) // 4) * 4
    total = len(blob)

    t0 = time.time()
    at = 0
    while at < total:
        chunk = blob[at : at + per]
        st, _ = request(s, DEBUG_POKE, struct.pack("<IB", PSRAM_IMAGE + at, 4) + chunk)
        if st != 0:
            raise RuntimeError(f"poke {PSRAM_IMAGE + at:#x}: {STATUS.get(st, st)}")
        at += len(chunk)
        if progress and (at % (per * 200) == 0 or at >= total):
            done = 100 * at // total
            rate = at / max(time.time() - t0, 1e-6) / 1024
            print(f"\rstage     {at}/{total} ({done}%) {rate:.0f} KB/s", end="", flush=True)
    if progress:
        print()

    # Spot-check what landed. Not a substitute for the bootloader's own verification --
    # it checks the whole image and this checks four places -- but a staging area that
    # dropped a whole run shows up here in a second rather than as `-112` in a minute.
    for off in (0, total // 3, 2 * total // 3, total - 64):
        off &= ~3
        got = peek(s, PSRAM_IMAGE + off, 16, 4)
        if got != blob[off : off + len(got)]:
            raise RuntimeError(f"read-back differs at +{off:#x}: PSRAM did not keep it")
    print("stage     read-back agrees at four points")

    # The header last, and `magic1` last within it: the bootloader requires both magics,
    # so until that final word lands every intermediate state reads as "nothing staged".
    start = PSRAM_IMAGE - PSRAM_BASE
    poke(s, PSRAM_HEADER + 4, struct.pack("<III", start, total, HDR_MAGIC2))
    poke(s, PSRAM_HEADER, struct.pack("<I", HDR_MAGIC1))
    print(f"stage     header published: start={start:#x} len={total}")
    return start, total


# --- triggering the install by hand: gate 18 / 7 -------------------------------------
#
# Staging puts the image in PSRAM; nothing installs it until a logged-in `gate 18/7`
# authorises the region. These are the pieces of that call, taken from
# `catcard-callgate` rather than from the reference, because they are the same numbers
# the firmware itself uses and a disagreement would be silent.
GATE_ENTRY_PTR = 0x0800_0040     # the gate's address is *published* here, never fixed
METHOD_PIN_ATTEMPT = 18
PIN_OP_FIRMWARE_UPGRADE = 7
CHANGE_FIRMWARE = 0x040

PA_MAGIC_V2 = 0x2EAF_6312
PA_SIZE = 280
PA_ATTEMPTS_LEFT = 56
PA_STATE_FLAGS = 60
PA_CHANGE_FLAGS = 100
PA_SECRET = 176
STATE_SUCCESSFUL = 0x01

SRAM_BASE = 0x2000_0000


def gate_entry(s):
    """Where the bootloader's callgate is, read from where it publishes itself."""
    addr = struct.unpack("<I", peek(s, GATE_ENTRY_PTR, 1, 4))[0]
    # It lives in the bootloader, below our firmware, and is a Thumb address.
    if not (0x0800_0000 <= (addr & ~1) < 0x0802_0000):
        raise RuntimeError(f"gate entry {addr:#010x} is not in the bootloader")
    return addr


def find_attempt(s, sram_len=192 * 1024):
    """Find the firmware's live `pinAttempt_t`, by its magic.

    Returns a list of `(addr, state_flags, attempts_left)`, logged-in ones first. The
    struct is not at a fixed place -- it belongs to the login state the session is
    holding -- so it is searched for rather than assumed.
    """
    want = struct.pack("<I", PA_MAGIC_V2)
    per = 64  # words per peek; the reply is one message, so keep it comfortable
    hits = []
    for base in range(SRAM_BASE, SRAM_BASE + sram_len, per * 4):
        try:
            blob = peek(s, base, per, 4)
        except RuntimeError:
            continue
        off = 0
        while True:
            i = blob.find(want, off)
            if i < 0 or i % 4:
                if i < 0:
                    break
                off = i + 1
                continue
            at = base + i
            try:
                tail = peek(s, at + PA_ATTEMPTS_LEFT, 2, 4)
                left, flags = struct.unpack("<II", tail)
                hits.append((at, flags, left))
            except RuntimeError:
                pass
            off = i + 4
    hits.sort(key=lambda h: 0 if h[1] & STATE_SUCCESSFUL else 1)
    return hits


def gate_thunk(method, buf, length, arg2, dest):
    """Machine code to call the gate with its own register convention.

    `DebugJsr` calls `fn(u32) -> u32`, so it can set `r0` and nothing else; the gate
    wants the method in `r0`, the buffer in `r1`, **its length in `r2`** -- not a second
    argument -- and `arg2` in `r3`. So a few instructions load them from a literal pool
    and branch. `r9` and `r10` are saved because the gate clobbers them, exactly as
    `catcard_callgate::entry::invoke` does.

    Hand-assembled Thumb-2. Laid out so the literals sit at fixed offsets from the
    loads, which is the only fiddly part:

        push.w {r4, r9, r10, lr}
        ldr r0, [pc, #12]   ; method
        ldr r1, [pc, #16]   ; buf
        ldr r2, [pc, #16]   ; len
        ldr r3, [pc, #20]   ; arg2
        ldr r4, [pc, #20]   ; dest
        blx r4
        pop.w  {r4, r9, r10, pc}
        .word method, buf, len, arg2, dest

    Checked against a real assembler rather than trusted -- `clang --target=thumbv7em`
    on the listing above produces these exact bytes, and `--selftest` asserts it here so
    an edit cannot quietly change what runs on the device.
    """
    code = struct.pack(
        "<HHHHHHHHHH",
        0xE92D, 0x4610,   # push.w {r4, r9, r10, lr}
        0x4803,           # ldr r0, [pc, #12]
        0x4904,           # ldr r1, [pc, #16]
        0x4A04,           # ldr r2, [pc, #16]
        0x4B05,           # ldr r3, [pc, #20]
        0x4C05,           # ldr r4, [pc, #20]
        0x47A0,           # blx r4
        0xE8BD, 0x8610,   # pop.w {r4, r9, r10, pc}
    )
    return code + struct.pack("<IIIII", method, buf, length, arg2, dest)


# What the listing above assembles to, for `--selftest`. Any change to `gate_thunk`
# that does not also change this is a change nobody looked at.
THUNK_GOLDEN = bytes.fromhex(
    "2de91046" "0348" "0449" "044a" "054b" "054c" "a047" "bde81086"
    "12000000" "34120020" "18010000" "07000000" "05030008"
)


def selftest():
    """Check the things that would be discovered on a device that cannot be recovered."""
    got = gate_thunk(18, 0x2000_1234, 280, 7, 0x0800_0305)
    assert got == THUNK_GOLDEN, f"thunk changed:\n  {got.hex()}\n  {THUNK_GOLDEN.hex()}"
    # The literals have to land where the loads reach, which is the part that is easy
    # to get wrong and impossible to notice until it runs.
    assert struct.unpack_from("<I", got, 20)[0] == 18, "method literal moved"
    assert struct.unpack_from("<I", got, 24)[0] == 0x2000_1234, "buf literal moved"
    assert struct.unpack_from("<I", got, 28)[0] == 280, "len literal moved"
    assert struct.unpack_from("<I", got, 32)[0] == 7, "arg2 literal moved"
    assert struct.unpack_from("<I", got, 36)[0] == 0x0800_0305, "dest literal moved"
    assert PA_SIZE == 280 and PA_SECRET == 176 and PA_CHANGE_FLAGS == 100
    print("selftest  thunk and pinAttempt_t offsets ok")


def gate_install(s, start, length, attempt, thunk_at):
    """Authorise the staged region and install it. **Does not return on success.**

    The device reboots into the bootloader, which verifies the staged image and writes
    it to flash. A return means it refused: -112 is the image failing verification,
    -103 a bad region.
    """
    dest = gate_entry(s)
    print(f"gate      entry {dest:#010x}, attempt {attempt:#010x}")

    # The two fields the caller owns. The bootloader's HMAC covers the struct only up to
    # `hmac` (plus `cached_main_pin`), so these are writable without invalidating it --
    # which is why the firmware's own `set_firmware_region` writes exactly these.
    poke(s, attempt + PA_SECRET, struct.pack("<II", start, length))
    poke(s, attempt + PA_CHANGE_FLAGS, struct.pack("<i", CHANGE_FIRMWARE))
    print(f"gate      region start={start:#x} len={length}, change_flags=FIRMWARE")

    thunk = gate_thunk(METHOD_PIN_ATTEMPT, attempt, PA_SIZE, PIN_OP_FIRMWARE_UPGRADE, dest)
    poke(s, thunk_at, thunk)
    back = peek(s, thunk_at, len(thunk) // 4, 4)
    if back != thunk:
        raise RuntimeError("the thunk did not read back; refusing to call it")
    print(f"gate      thunk at {thunk_at:#010x} ({len(thunk)} bytes), verified")

    try:
        rv = jsr(s, thunk_at)
    except Exception as e:
        print(f"gate      no reply ({type(e).__name__}) -- the device is installing")
        return None
    rv = rv - (1 << 32) if rv >= (1 << 31) else rv
    print(f"gate      returned {rv} -- it refused; nothing was written")
    return rv


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
                # libusb words it "Operation timed out", so match the type as well as
                # the text -- "timeout" alone let a plain timeout escape as a crash.
                msg = str(e).lower()
                if type(e).__name__ == "USBTimeoutError" or "timeout" in msg or "timed out" in msg:
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
        # macOS gives no hidraw node and will not let a process take the interface from
        # its own HID driver, so the way in there is hidapi. Imported here rather than at
        # the top because `machid` imports this module: by the time anyone calls this,
        # both are loaded and the cycle cannot bite.
        if sys.platform == "darwin":
            from machid import MacHid

            return MacHid()
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
    # Read once, here, so every branch below has it. It used to be set only inside the
    # branches that happen to run first, which left the plain "offer an image" path
    # reaching for a name that was never bound.
    caps = capabilities(body) if st == 0 else 0
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

    if "--stage" in sys.argv:
        # Stage an image into PSRAM with the monitor, for when the firmware's own
        # staging is the thing that is broken -- a device that cannot install is
        # otherwise a device that cannot be fixed, because every ordinary route to
        # replacing its firmware runs through the code that is failing.
        #
        # This gets the bytes and the recovery header in place. It does **not** install:
        # that is `gate 18/7`, which is PIN-authenticated and wants the logged-in
        # `pinAttempt_t` the firmware is holding. See the note printed below.
        a = arg_after("--stage")
        if not a:
            print("usage: --stage <image.dfu|image.bin>")
            return 1
        st, body = request(s, IDENTIFY)
        if not capabilities(body) & CAP_DEBUG_MEM:
            print("stage     this build has no memory monitor (needs usb-debug-mem)")
            return 1
        blob = load_image(a[0])
        start, total = stage_by_poke(s, blob)
        print()
        print("staged, but NOT installed. The bootloader only acts on this when a")
        print("logged-in `gate 18/7` authorises the region, or when it recovers a device")
        print(f"whose own firmware fails to verify. Region: start={start:#x} len={total}.")
        return 0

    if "--stage-settings" in sys.argv:
        # Put a state dump's settings region into PSRAM for Debug -> Restore settings.
        # Staging only: the device checks it (length, SHA-256, that it is a volume, that
        # it is *this* device's) and writes the flash only when the owner says yes on the
        # device itself. Nothing this command does touches flash.
        a = arg_after("--stage-settings")
        if not a:
            print("usage: --stage-settings <XXXXXXXX-STATE.BIN>")
            return 1
        st, body = request(s, IDENTIFY)
        if not capabilities(body) & CAP_DEBUG_MEM:
            print("stage     this build has no memory monitor (needs usb-debug-mem)")
            return 1
        import hashlib
        sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
        import statedump
        _manifest, sections = statedump.read(a[0])
        img = sections.get("settings")
        if not img:
            print("stage     that dump has no settings section")
            return 1
        # restore::STAGED_AT: one megabyte into the *lower* half. Never the upper half,
        # where an offered firmware image waits for the owner's yes -- staging over one
        # made the next approval hand the bootloader settings data as firmware.
        at = PSRAM_BASE + 0x0010_0000
        header = 64               # restore::HEADER

        # Unmark first, so a half-finished staging can never look like a finished one.
        poke(s, at, b"\0" * 8)

        t0 = time.time()
        per = ((56 - 5) // 4) * 4
        done = 0
        while done < len(img):
            chunk = img[done : done + per]
            poke(s, at + header + done, chunk)
            done += len(chunk)
            if done % (per * 400) == 0 or done >= len(img):
                rate = done / max(time.time() - t0, 1e-6) / 1024
                print(f"\rstage     {done}/{len(img)} ({100 * done // len(img)}%) "
                      f"{rate:.0f} KB/s", end="", flush=True)
        print()
        for off in (0, len(img) // 3, 2 * len(img) // 3, len(img) - 64):
            off &= ~3
            got = peek(s, at + header + off, 16, 4)
            if got != img[off : off + len(got)]:
                print(f"stage     read-back differs at +{off:#x}; not marked")
                return 1

        # The header, and the magic last within it -- its second word before its first.
        digest = hashlib.sha256(img).digest()
        poke(s, at + 8, struct.pack("<II", len(img), 0) + digest + b"\0" * 16)
        poke(s, at + 4, b"TOR1")
        poke(s, at, b"CCRS")
        print(f"stage     {len(img)} bytes staged, sha256 {digest[:4].hex()}..., marked")
        print("stage     now: Debug -> Restore settings, on the device")
        return 0

    if "--find-attempt" in sys.argv:
        for at, flags, left in find_attempt(s):
            mark = "LOGGED IN" if flags & STATE_SUCCESSFUL else "not logged in"
            print(f"attempt   {at:#010x} state={flags:#x} ({mark}) attempts_left={left}")
        return 0

    if "--rescue" in sys.argv or "--install-staged" in sys.argv:
        # The last resort: stage with the monitor and authorise the region by hand.
        # For a device whose own staging path is what is broken, which is the case
        # where every ordinary route is also the broken one.
        st, body = request(s, IDENTIFY)
        if not capabilities(body) & CAP_DEBUG_MEM:
            print("rescue    this build has no memory monitor (needs usb-debug-mem)")
            return 1
        info = identify(body)
        if not (info and info[1]):
            print("rescue    the device must be unlocked: the gate call is the login's")
            return 1

        thunk_at = PSRAM_BASE
        if "--thunk" in sys.argv:
            thunk_at = int(arg_after("--thunk")[0], 0)

        if "--rescue" in sys.argv:
            a = arg_after("--rescue")
            if not a:
                print("usage: --rescue <image.dfu|image.bin>")
                return 1
            start, total = stage_by_poke(s, load_image(a[0]))
        else:
            # Already staged, by `--stage` or by a previous run that got that far.
            hdr = peek(s, PSRAM_HEADER, 4, 4)
            m1, start, total, m2 = struct.unpack("<IIII", hdr)
            if m1 != HDR_MAGIC1 or m2 != HDR_MAGIC2:
                print(f"rescue    no image staged (magics {m1:#x}/{m2:#x})")
                return 1
            print(f"rescue    using the staged image: start={start:#x} len={total}")

        found = [h for h in find_attempt(s) if h[1] & STATE_SUCCESSFUL]
        if not found:
            print("rescue    no logged-in pinAttempt_t found in SRAM")
            return 1
        attempt = found[0][0]
        if len(found) > 1:
            print(f"rescue    {len(found)} logged-in candidates; using {attempt:#010x}")

        print()
        print("About to authorise the staged image. This is irreversible: the")
        print("bootloader overwrites the running firmware and reboots.")
        if "--yes" not in sys.argv:
            print("Re-run with --yes to go ahead.")
            return 1
        gate_install(s, start, total, attempt, thunk_at)
        return 0

    if "--sd-cid" in sys.argv:
        raw = sd_cid(s)
        print(f"cid       {raw.hex()}")
        for k, v in decode_cid(raw).items():
            print(f"  {k:<13}{v}")
        return 0

    if "--sd" in sys.argv:
        a = arg_after("--sd")
        cmd = int(a[0], 0)
        arg = int(a[1], 0) if len(a) > 1 else 0
        resp = {"none": SD_NONE, "short": SD_SHORT, "long": SD_LONG}[
            next((x.split("=")[1] for x in sys.argv if x.startswith("--resp=")), "short")
        ]
        read = int(next((x.split("=")[1] for x in sys.argv if x.startswith("--read=")), "0"), 0)
        write = next((x.split("=")[1] for x in sys.argv if x.startswith("--write=")), None)
        write = bytes.fromhex(write) if write else None
        status, words, data = sd_raw(s, cmd, arg, resp, read, write)
        answered = "answered" if status == 0 else "did not answer"
        print(f"cmd{cmd:<3}   {answered}")
        if status == 0:
            print("  resp         " + " ".join(f"{w:08x}" for w in words))
            if data:
                print(f"  data         {data.hex()}")
        return 0

    if "--log" in sys.argv:
        # The whole point of the log: a device whose screen cannot be read can still say
        # what happened to it.
        print_log(s)
        return 0

    if "--unlock" in sys.argv:
        # Hand the device the whole PIN instead of driving the keypad blindly. The one
        # key sent here is only to leave the selftest screen -- not the PIN.
        st, body = request(s, IDENTIFY)
        caps = capabilities(body)
        info = identify(body)
        if info and info[1]:
            print("unlock    already unlocked")
            return 0
        if not caps & CAP_UNLOCK_PIN:
            print("unlock    this build does not accept a whole-PIN unlock "
                  "(needs usb-key-injection)")
            return 1
        pin = next((a[len("--pin="):] for a in sys.argv if a.startswith("--pin=")), None)
        if not pin:
            print("unlock    pass --pin=PREFIX-SUFFIX, e.g. --pin=1111-1111")
            return 1
        done = unlock_with_pin(s, pin)
        print(f"unlock    {'unlocked' if done else 'still locked (wrong PIN?)'}")
        return 0 if done else 1

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
            # Prefer the whole-PIN unlock over blind key injection when the build has
            # it -- fewer round trips, and no dependence on the keypad map.
            if caps & CAP_UNLOCK_PIN:
                unlock_with_pin(s, prefix + "-" + suffix)
            else:
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
            st, body, sent = offer(s, blob, caps)
            if st == 0:
                print(f"offer     status=Ok verified={bool(body[0])} "
                      f"len={struct.unpack('<I', body[1:5])[0]} "
                      f"[{sent} B sent of {len(blob)}]")
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
        st, body, sent = offer(s, blob, caps)
        dt = time.time() - t0
        if st == 0:
            print(f"offer(unlocked)   status=Ok verified={bool(body[0])} "
                  f"len={struct.unpack('<I', body[1:5])[0]}  "
                  f"[{sent} B of {len(blob)} in {dt:.1f}s]")
        else:
            why = REJECT.get(body[0], body[0]) if body else "?"
            print(f"offer(unlocked)   status={STATUS.get(st, st)} reason={why}")
        ok &= st == 0
        print("OK" if ok else "FAILED")
        return 0 if ok else 1

    if image:
        blob = load_image(image)
        t0 = time.time()
        st, body, sent = offer(s, blob, caps)
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
                  f"  [{sent} B of {len(blob)} in {dt:.1f}s]")
        else:
            why = REJECT.get(body[0], body[0]) if body else "?"
            print(f"offer     status={STATUS.get(st, st)} reason={why}")
            ok = False

    print("OK" if ok else "FAILED")
    return 0 if ok else 1


if __name__ == "__main__":
    # Checks that need no device, and that matter most when the device cannot be
    # reached: the hand-assembled thunk and the struct offsets it depends on.
    if "--selftest" in sys.argv:
        selftest()
        raise SystemExit(0)
    sys.exit(main(sys.argv[1], sys.argv[2] if len(sys.argv) > 2 else None))
