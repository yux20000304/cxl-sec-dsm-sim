#!/usr/bin/env python3
"""
CXL shared-memory helpers:
- File/Uio mmap wrapper
- Single-producer/single-consumer ring buffers for request/response

The layout is intentionally simple to keep cross-VM coherence predictable.
"""
import argparse
import mmap
import os
import struct
from dataclasses import dataclass
from typing import Optional, Tuple

MAGIC = b"CXLSHM1\0"
VERSION = 1

# Message types
MSG_DATA = 1
MSG_CLOSE = 2

# Ring defaults (can be overridden via CLI/env)
DEFAULT_SLOT_SIZE = 4096  # bytes per slot including header
DEFAULT_SLOTS = 4096      # ~16 MiB per ring


def align_up(x: int, a: int) -> int:
    return (x + a - 1) // a * a


@dataclass
class RingConfig:
    slot_size: int
    slots: int
    offset: int
    size: int


@dataclass
class Layout:
    req: RingConfig
    resp: RingConfig


class CxlShm:
    """
    Manages mmap of the shared CXL backing file (or /dev/uioX).
    It also initializes the ring headers if magic is absent.
    """

    def __init__(self, path: str, map_size: Optional[int] = None):
        flags = os.O_RDWR
        self.fd = os.open(path, flags)
        st = os.fstat(self.fd)
        self.file_size = st.st_size
        if map_size:
            self.map_size = map_size
        else:
            if self.file_size > 0:
                self.map_size = self.file_size
            else:
                self.map_size = self._detect_uio_size(path)
        if self.map_size <= 0:
            raise ValueError(f"Invalid map_size resolved for {path}")
        self.mm = mmap.mmap(self.fd, self.map_size, mmap.MAP_SHARED, mmap.PROT_READ | mmap.PROT_WRITE)
        self.layout = self._init_or_load_layout()

    def _detect_uio_size(self, path: str) -> int:
        base = os.path.basename(path)
        if not base.startswith("uio") and "uio" not in base:
            raise ValueError("map_size not provided and file size is 0; please pass --map-size")
        # Try /sys/class/uio/uioX/maps/map0/size
        uio = base if base.startswith("uio") else None
        if not uio:
            # maybe /dev/XXXX where XXXX includes uioN
            for part in path.split("/"):
                if part.startswith("uio"):
                    uio = part
                    break
        if not uio:
            raise ValueError("Could not infer UIO device name for size detection")
        sysfs_path = f"/sys/class/uio/{uio}/maps/map0/size"
        try:
            with open(sysfs_path, "r") as f:
                size_str = f.read().strip()
            return int(size_str, 0)
        except Exception as e:
            raise ValueError(f"Failed to read UIO size from {sysfs_path}: {e}")

    def close(self) -> None:
        self.mm.close()
        os.close(self.fd)

    def _init_or_load_layout(self) -> Layout:
        # Header: 8 magic, u32 ver, u32 reserved, u64 file_size,
        #         u64 req_off, u64 req_size, u64 resp_off, u64 resp_size
        header_fmt = "<8sIIQQQQQ"
        header_size = struct.calcsize(header_fmt)
        data = self.mm[:header_size]
        magic, ver, _resv, fsize, req_off, req_sz, resp_off, resp_sz = struct.unpack(header_fmt, data)
        slot_size = DEFAULT_SLOT_SIZE
        slots = DEFAULT_SLOTS
        if magic != MAGIC or ver != VERSION:
            # Initialize layout
            slot_size = DEFAULT_SLOT_SIZE
            slots = DEFAULT_SLOTS
            header_aligned = align_up(header_size, 4096)
            # Shrink slots until both rings fit
            while slots > 1:
                ring_size = align_up(16 + slot_size * slots, 4096)
                total = header_aligned + 2 * ring_size
                if total <= self.map_size:
                    break
                slots //= 2
            else:
                raise RuntimeError("Shared file too small; enlarge or reduce slot size.")
            ring_size = align_up(16 + slot_size * slots, 4096)
            req_off = header_aligned
            req_sz = ring_size
            resp_off = align_up(req_off + req_sz, 4096)
            resp_sz = ring_size
            if resp_off + resp_sz > self.map_size:
                raise RuntimeError("Shared file too small; enlarge or reduce slot size.")
            header = struct.pack(
                header_fmt,
                MAGIC,
                VERSION,
                0,
                self.file_size,
                req_off,
                req_sz,
                resp_off,
                resp_sz,
            )
            self.mm[:header_size] = header
            # Zero ring heads/tails
            for off in (req_off, resp_off):
                self.mm[off:off + 16] = b"\x00" * 16
        req_cfg = RingConfig(slot_size=slot_size, slots=slots, offset=req_off, size=req_sz)
        resp_cfg = RingConfig(slot_size=slot_size, slots=slots, offset=resp_off, size=resp_sz)
        return Layout(req=req_cfg, resp=resp_cfg)


class SpscRing:
    """
    Single-producer / single-consumer ring buffer over shared memory.
    Slot layout:
      u32 client_id
      u16 msg_type
      u16 flags
      u32 length
      u32 reserved
      payload (slot_size - 16 bytes)
    """

    SLOT_HDR_FMT = "<IHHII"
    SLOT_HDR_SIZE = struct.calcsize(SLOT_HDR_FMT)

    def __init__(self, mm: mmap.mmap, cfg: RingConfig):
        self.mm = mm
        self.cfg = cfg
        self.head_off = cfg.offset  # producer writes
        self.tail_off = cfg.offset + 8  # consumer writes
        self.base = cfg.offset + align_up(16, 16)  # leave 16 bytes for head/tail

    def _load_head_tail(self) -> Tuple[int, int]:
        head = struct.unpack_from("<Q", self.mm, self.head_off)[0]
        tail = struct.unpack_from("<Q", self.mm, self.tail_off)[0]
        return head, tail

    def _store_head(self, head: int) -> None:
        struct.pack_into("<Q", self.mm, self.head_off, head)

    def _store_tail(self, tail: int) -> None:
        struct.pack_into("<Q", self.mm, self.tail_off, tail)

    def _slot_addr(self, idx: int) -> int:
        return self.base + (idx % self.cfg.slots) * self.cfg.slot_size

    def push(self, client_id: int, msg_type: int, flags: int, payload: bytes) -> bool:
        head, tail = self._load_head_tail()
        if head - tail >= self.cfg.slots:
            return False  # full
        if len(payload) > self.cfg.slot_size - self.SLOT_HDR_SIZE:
            raise ValueError(f"payload too large ({len(payload)} > {self.cfg.slot_size - self.SLOT_HDR_SIZE})")
        slot_idx = head % self.cfg.slots
        addr = self._slot_addr(slot_idx)
        # Write header & payload
        struct.pack_into(self.SLOT_HDR_FMT, self.mm, addr, client_id, msg_type, flags, len(payload), 0)
        self.mm[addr + self.SLOT_HDR_SIZE: addr + self.SLOT_HDR_SIZE + len(payload)] = payload
        # Zero the rest of the slot payload to avoid leaking stale bytes
        remain = self.cfg.slot_size - self.SLOT_HDR_SIZE - len(payload)
        if remain > 0:
            self.mm[addr + self.SLOT_HDR_SIZE + len(payload): addr + self.cfg.slot_size] = b"\x00" * remain
        # Commit
        self._store_head(head + 1)
        return True

    def pop(self) -> Optional[Tuple[int, int, int, bytes]]:
        head, tail = self._load_head_tail()
        if tail == head:
            return None  # empty
        slot_idx = tail % self.cfg.slots
        addr = self._slot_addr(slot_idx)
        client_id, msg_type, flags, length, _resv = struct.unpack_from(self.SLOT_HDR_FMT, self.mm, addr)
        payload = bytes(self.mm[addr + self.SLOT_HDR_SIZE: addr + self.SLOT_HDR_SIZE + length])
        self._store_tail(tail + 1)
        return client_id, msg_type, flags, payload


def _cli():
    parser = argparse.ArgumentParser(description="Simple CXL shared-memory ring inspector")
    parser.add_argument("--path", required=True, help="Path to shared file or /dev/uioX")
    parser.add_argument("--map-size", type=int, help="Bytes to map (default: whole file)")
    parser.add_argument("--peek", action="store_true", help="Peek at ring heads/tails")
    args = parser.parse_args()

    shm = CxlShm(args.path, args.map_size)
    req_ring = SpscRing(shm.mm, shm.layout.req)
    resp_ring = SpscRing(shm.mm, shm.layout.resp)
    h1, t1 = req_ring._load_head_tail()
    h2, t2 = resp_ring._load_head_tail()
    print(f"REQ head={h1} tail={t1} slots={req_ring.cfg.slots} slot_size={req_ring.cfg.slot_size}")
    print(f"RESP head={h2} tail={t2} slots={resp_ring.cfg.slots} slot_size={resp_ring.cfg.slot_size}")
    shm.close()


if __name__ == "__main__":
    _cli()
