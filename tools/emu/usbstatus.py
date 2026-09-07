#!/usr/bin/env python3
"""Read CATCARD_USB_STATUS out of an emulator RAM dump.

The screen is the natural place for these numbers, and it works -- but the emulator
emits no screens at all in `--usb-hid` mode, which is the only mode our own host
protocol can be driven in. So the same counters are mirrored into RAM.

They separate three failures that look identical from the host's side: the reports are
not arriving, the firmware is not answering, or it answered and the reply never left.
"""
import struct, sys

MAGIC = 0xCA7C05B0
STATUS = {0: "Ok", 1: "UnknownOpcode", 2: "NotNow", 3: "BadRequest",
          4: "Declined", 5: "Refused", 6: "Busy"}


def main(path):
    data = open(path, "rb").read()
    at = data.find(struct.pack("<I", MAGIC))
    if at < 0:
        sys.exit(f"CATCARD_USB_STATUS not found in {len(data)} bytes — USB never ran")
    (_, configured, rin, rout, pending, ferr, staged, last) = struct.unpack_from("<8I", data, at)
    gintsts, daint, doepctl, doeptsiz, diepctl, dctl = struct.unpack_from("<6I", data, at + 32)
    (rearms,) = struct.unpack_from("<I", data, at + 56)
    print(f"CATCARD_USB_STATUS @ RAM+{at:#x}")
    print(f"  configured     {'yes' if configured else 'NO'}")
    print(f"  reports in     {rin}")
    print(f"  replies out    {rout}")
    print(f"  outbox pending {pending} byte(s)")
    print(f"  frame errors   {ferr}")
    print(f"  staged         {staged} byte(s)")
    print(f"  last status    {STATUS.get(last, last)}")
    print(f"  out re-arms    {rearms}")
    print(f"  GINTSTS        {gintsts:#010x}")
    print(f"  DCTL           {dctl:#010x}  GINSTS={bool(dctl >> 2 & 1)} "
          f"GONSTS={bool(dctl >> 3 & 1)} SDIS={bool(dctl >> 1 & 1)}")
    print(f"  DAINT          {daint:#010x}")
    print(f"  DOEPCTL(out)   {doepctl:#010x}  EPENA={bool(doepctl >> 31 & 1)} "
          f"USBAEP={bool(doepctl >> 15 & 1)} NAKSTS={bool(doepctl >> 17 & 1)} "
          f"MPSIZ={doepctl & 0x7ff}")
    print(f"  DOEPTSIZ(out)  {doeptsiz:#010x}  PKTCNT={doeptsiz >> 19 & 0x3ff} "
          f"XFRSIZ={doeptsiz & 0x7ffff}")
    print(f"  DIEPCTL(in)    {diepctl:#010x}  EPENA={bool(diepctl >> 31 & 1)} "
          f"USBAEP={bool(diepctl >> 15 & 1)}")

    if not configured:
        print("\n  -> the host never finished enumerating us")
    elif rin == 0:
        print("\n  -> reports are not reaching the firmware: the OUT endpoint is not "
              "delivering")
    elif rout == 0 and pending:
        print("\n  -> a reply was built and never left: the IN endpoint or its FIFO")
    elif rout == 0:
        print("\n  -> reports arrive but no reply is even queued: the dispatch path")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1]))
