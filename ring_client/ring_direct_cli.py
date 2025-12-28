#!/usr/bin/env python3
"""
Direct ring-based client: bypass TCP sockets and talk to Redis over the shared
ivshmem BAR/ring. Useful for measuring pure ring performance without the
cxl_ring_client TCP front-end.
"""
import argparse
import mmap
import os
import struct
import sys
import time
from typing import Iterable, List, Tuple

MAGIC = b"CXLSHM1\0"
VERSION = 1
MSG_DATA = 1
MSG_CLOSE = 2

# Must match redis/src/cxl_ring.c (slot_size is not stored in header)
SLOT_SIZE = 1024
HEADER_FMT = "<8sIIQQQQQ"  # magic, ver, resv, file_size, req_off, req_sz, resp_off, resp_sz
SLOT_HDR_FMT = "<IHHII"    # client_id, msg_type, flags, length, reserved


def load_layout(mm: mmap.mmap) -> Tuple[int, int, int, int]:
    magic, ver, _resv, _fsize, req_off, req_sz, resp_off, resp_sz = struct.unpack_from(HEADER_FMT, mm, 0)
    if magic != MAGIC or ver != VERSION:
        raise RuntimeError("Invalid shared-memory header (magic/version mismatch)")
    return req_off, req_sz, resp_off, resp_sz


def push(mm: mmap.mmap, base_off: int, slots: int, client_id: int, msg_type: int, payload: bytes) -> bool:
    head_off = base_off
    tail_off = base_off + 8
    head = struct.unpack_from("<Q", mm, head_off)[0]
    tail = struct.unpack_from("<Q", mm, tail_off)[0]
    if head - tail >= slots:
        return False  # full
    if len(payload) > SLOT_SIZE - struct.calcsize(SLOT_HDR_FMT):
        raise ValueError("payload too large for slot")
    idx = head % slots
    slot_off = base_off + 16 + idx * SLOT_SIZE
    struct.pack_into(SLOT_HDR_FMT, mm, slot_off, client_id, msg_type, 0, len(payload), 0)
    mm[slot_off + 16 : slot_off + 16 + len(payload)] = payload
    # Zero the rest to avoid stale bytes
    remain = SLOT_SIZE - 16 - len(payload)
    if remain > 0:
        mm[slot_off + 16 + len(payload) : slot_off + SLOT_SIZE] = b"\x00" * remain
    struct.pack_into("<Q", mm, head_off, head + 1)
    return True


def pop(mm: mmap.mmap, base_off: int, slots: int):
    head_off = base_off
    tail_off = base_off + 8
    head = struct.unpack_from("<Q", mm, head_off)[0]
    tail = struct.unpack_from("<Q", mm, tail_off)[0]
    if tail == head:
        return None
    idx = tail % slots
    slot_off = base_off + 16 + idx * SLOT_SIZE
    cid, msg_type, flags, length, _ = struct.unpack_from(SLOT_HDR_FMT, mm, slot_off)
    payload = mm[slot_off + 16 : slot_off + 16 + length]
    struct.pack_into("<Q", mm, tail_off, tail + 1)
    return cid, msg_type, flags, bytes(payload)


def encode_resp(parts: Iterable[str]) -> bytes:
    buf: List[bytes] = []
    parts_list = list(parts)
    buf.append(f"*{len(parts_list)}\r\n".encode())
    for p in parts_list:
        b = p.encode()
        buf.append(f"${len(b)}\r\n".encode())
        buf.append(b + b"\r\n")
    return b"".join(buf)


def parse_resp(payload: bytes) -> str:
    if not payload:
        return ""
    prefix = payload[:1]
    body = payload[1:]
    if prefix == b"+" or prefix == b"-":
        return body.decode(errors="ignore").strip()
    if prefix == b":":
        return body.decode(errors="ignore").strip()
    if prefix == b"$":
        # Bulk string: $len\r\n<data>\r\n
        try:
            parts = body.split(b"\r\n", 2)
            if len(parts) >= 2:
                return parts[1].decode(errors="ignore")
        except Exception:
            pass
    return payload.decode(errors="ignore")


def parse_resp_stream(payload: bytes) -> List[str]:
    """Parse a RESP stream that may contain multiple replies concatenated."""
    out: List[str] = []
    i = 0
    n = len(payload)
    while i < n:
        prefix = payload[i:i+1]
        i += 1
        if prefix == b"":
            break
        if prefix in (b"+", b"-", b":"):
            end = payload.find(b"\r\n", i)
            if end == -1:
                break
            text = payload[i:end].decode(errors="ignore")
            if prefix == b"-":
                text = "ERR " + text
            out.append(text)
            i = end + 2
        elif prefix == b"$":
            end = payload.find(b"\r\n", i)
            if end == -1:
                break
            try:
                length = int(payload[i:end])
            except ValueError:
                break
            i = end + 2
            data = payload[i : i + length]
            out.append(data.decode(errors="ignore"))
            i += length + 2  # skip data + CRLF
        else:
            # Unknown/partial; stop parsing to avoid infinite loop
            break
    return out


def roundtrip(mm: mmap.mmap, req_off: int, resp_off: int, slots: int, commands: List[List[str]], cid: int = 1, serial: bool = True) -> List[str]:
    """Send commands and collect replies.
    If serial=True, push one command then wait for its reply (avoids chunking issues).
    """
    results: List[str] = []
    if serial:
        for cmd in commands:
            payload = encode_resp(cmd)
            while not push(mm, req_off, slots, cid, MSG_DATA, payload):
                time.sleep(0.0005)
            while True:
                msg = pop(mm, resp_off, slots)
                if not msg:
                    time.sleep(0.0005)
                    continue
                _cid, msg_type, _flags, payload = msg
                if msg_type == MSG_DATA:
                    replies = parse_resp_stream(payload) or [parse_resp(payload)]
                    results.extend(replies)
                    break
    else:
        # Pipeline: send all, then drain replies (may pack multiple replies per slot)
        for cmd in commands:
            payload = encode_resp(cmd)
            while not push(mm, req_off, slots, cid, MSG_DATA, payload):
                time.sleep(0.0005)
        remaining = len(commands)
        while remaining > 0:
            msg = pop(mm, resp_off, slots)
            if not msg:
                time.sleep(0.0005)
                continue
            _cid, msg_type, _flags, payload = msg
            if msg_type == MSG_CLOSE:
                results.append("<closed>")
                remaining -= 1
            elif msg_type == MSG_DATA:
                replies = parse_resp_stream(payload) or [parse_resp(payload)]
                results.extend(replies)
                remaining -= len(replies)
    return results


def bench(mm: mmap.mmap, req_off: int, resp_off: int, slots: int, n: int, key_prefix: str = "k", val_prefix: str = "v", serial: bool = True) -> Tuple[float, float]:
    cmds: List[List[str]] = []
    for i in range(n):
        cmds.append(["SET", f"{key_prefix}{i}", f"{val_prefix}{i}"])
    start = time.perf_counter()
    roundtrip(mm, req_off, resp_off, slots, cmds, cid=1, serial=serial)
    mid = time.perf_counter()
    gets = [[ "GET", f"{key_prefix}{i}" ] for i in range(n)]
    roundtrip(mm, req_off, resp_off, slots, gets, cid=2, serial=serial)
    end = time.perf_counter()
    set_rps = n / (mid - start)
    get_rps = n / (end - mid)
    return set_rps, get_rps


def main():
    ap = argparse.ArgumentParser(description="Direct ring Redis client (no TCP)")
    ap.add_argument("--path", default="/sys/bus/pci/devices/0000:00:02.0/resource2", help="Shared BAR/file path")
    ap.add_argument("--map-size", type=int, default=1024 * 1024 * 1024, help="Bytes to mmap (default: 1GB)")
    ap.add_argument("--ping", action="store_true", help="Send a PING and print response")
    ap.add_argument("--bench", type=int, metavar="N", help="Run simple SET/GET benchmark with N ops each")
    ap.add_argument("--pipeline", action="store_true", help="Pipeline all commands before reading replies")
    args = ap.parse_args()

    fd = os.open(args.path, os.O_RDWR)
    mm = mmap.mmap(fd, args.map_size, mmap.MAP_SHARED, mmap.PROT_READ | mmap.PROT_WRITE)
    req_off, req_sz, resp_off, resp_sz = load_layout(mm)
    slots = (req_sz - 16) // SLOT_SIZE
    serial = not args.pipeline

    if args.ping:
        resp = roundtrip(mm, req_off, resp_off, slots, [["PING"]], cid=99, serial=serial)
        print("PING ->", resp)
    if args.bench:
        set_rps, get_rps = bench(mm, req_off, resp_off, slots, args.bench, serial=serial)
        print(f"SET: {set_rps:.2f} req/s")
        print(f"GET: {get_rps:.2f} req/s")
    if not (args.ping or args.bench):
        print("Nothing to do. Use --ping or --bench N.")
    mm.close()
    os.close(fd)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        sys.exit(1)
