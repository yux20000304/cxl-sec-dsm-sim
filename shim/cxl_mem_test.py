#!/usr/bin/env python3
"""
Minimal read/write tester for the shared CXL memory region.
Useful for Phase 1 verification (VM1 write, VM2 read).
"""
import argparse
import mmap
import os


def main():
    p = argparse.ArgumentParser(description="CXL shared memory smoke test")
    p.add_argument("--uio", help="Use /dev/uioX instead of a regular file")
    p.add_argument("--path", help="Path to shared file (if not using --uio)")
    p.add_argument("--offset", type=lambda x: int(x, 0), required=True, help="Offset in bytes (hex ok)")
    group = p.add_mutually_exclusive_group(required=True)
    group.add_argument("--write", action="store_true", help="Write mode")
    group.add_argument("--read", action="store_true", help="Read mode")
    p.add_argument("--data", help="String to write")
    p.add_argument("--len", type=int, default=64, help="Bytes to read")
    args = p.parse_args()

    path = args.uio or args.path
    if not path:
        p.error("Specify --uio /dev/uioX or --path <file>")

    fd = os.open(path, os.O_RDWR)
    st = os.fstat(fd)
    mm = mmap.mmap(fd, st.st_size, mmap.MAP_SHARED, mmap.PROT_READ | mmap.PROT_WRITE)

    if args.write:
        if args.data is None:
            p.error("--data required for write")
        data = args.data.encode("utf-8")
        mm[args.offset: args.offset + len(data)] = data
        print(f"[+] wrote {len(data)} bytes at offset {hex(args.offset)}")
    else:
        buf = mm[args.offset: args.offset + args.len]
        print(buf)
    mm.close()
    os.close(fd)


if __name__ == "__main__":
    main()
