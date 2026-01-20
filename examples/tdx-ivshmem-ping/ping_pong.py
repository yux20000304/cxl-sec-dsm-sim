#!/usr/bin/env python3
"""
Minimal ping-pong over the shared-memory ring used in this repo.

Two roles:
  - server: pops from request ring and replies on response ring
  - client: pushes PINGs on request ring and waits for PONGs on response ring

Intended to run inside two TDX guests that share a QEMU ivshmem-backed region
(/dev/uioX or PCI BAR2 resource file). This demo uses shim/cxl_shm.py.
"""
import argparse
import os
import sys
import time
from typing import Optional

# Add repo root for importing shim.cxl_shm when run from this subdir
REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
if REPO_ROOT not in sys.path:
    sys.path.insert(0, REPO_ROOT)

from shim.cxl_shm import CxlShm, SpscRing, MSG_CLOSE, MSG_DATA  # type: ignore


def parse_args():
    ap = argparse.ArgumentParser(description="TDX ivshmem ping-pong using shared ring")
    src = ap.add_mutually_exclusive_group(required=True)
    src.add_argument("--uio", help="Use /dev/uioX as the shared mapping source")
    src.add_argument("--path", help="Path to shared file or PCI BAR2 resource2")
    ap.add_argument("--map-size", type=int, default=None, help="Bytes to mmap (optional; required for some /dev/uioX)")
    ap.add_argument("--map-offset", type=int, default=0, help="Bytes to offset mmap (page-size aligned; for /dev/uio map index)")
    ap.add_argument("--role", choices=["server", "client"], required=True, help="Which side to run")
    ap.add_argument("--cid", type=int, default=1, help="Client ID used in slot headers")
    ap.add_argument("--count", type=int, default=10, help="Client: number of pings to send")
    ap.add_argument("--timeout-ms", type=int, default=5000, help="Per-op timeout in ms")
    ap.add_argument("--sleep-us", type=int, default=500, help="Spin sleep when ring is empty/full (microseconds)")
    ap.add_argument("--verbose", action="store_true", help="Verbose logging")
    ap.add_argument("--no-close", action="store_true", help="Client: do not send MSG_CLOSE at the end")
    return ap.parse_args()


def micro_sleep(us: int) -> None:
    if us <= 0:
        return
    time.sleep(us / 1_000_000.0)


def run_server(shm: CxlShm, cid_filter: Optional[int], timeout_ms: int, sleep_us: int, verbose: bool) -> int:
    req = SpscRing(shm.mm, shm.layout.req)
    resp = SpscRing(shm.mm, shm.layout.resp)
    deadline = time.monotonic() + (timeout_ms / 1000.0) if timeout_ms > 0 else None
    handled = 0
    if verbose:
        print(f"[server] started: slots={req.cfg.slots} slot_size={req.cfg.slot_size}")
    while True:
        msg = req.pop()
        if not msg:
            if deadline is not None and time.monotonic() > deadline:
                if verbose:
                    print("[server] timeout waiting for requests; exiting")
                break
            micro_sleep(sleep_us)
            continue
        cid, msg_type, flags, payload = msg
        if cid_filter is not None and cid != cid_filter:
            # Ignore other client IDs (demo supports simple filtering)
            continue
        if msg_type == MSG_CLOSE:
            if verbose:
                print("[server] received CLOSE; exiting")
            break
        if msg_type != MSG_DATA:
            if verbose:
                print(f"[server] ignoring unknown msg_type={msg_type}")
            continue
        # echo -> PONG <payload>
        reply = b"PONG " + payload
        # backpressure until a slot is available
        while not resp.push(cid, MSG_DATA, 0, reply):
            micro_sleep(sleep_us)
        handled += 1
        if verbose:
            try:
                preview = payload.decode(errors="ignore")
            except Exception:
                preview = str(payload[:16])
            print(f"[server] handled request #{handled}: {preview}")
    return handled


def run_client(shm: CxlShm, cid: int, count: int, timeout_ms: int, sleep_us: int, verbose: bool, send_close: bool) -> int:
    req = SpscRing(shm.mm, shm.layout.req)
    resp = SpscRing(shm.mm, shm.layout.resp)
    rtt_sum = 0.0
    ok = 0
    for i in range(count):
        payload = f"PING {i}".encode()
        # push
        while not req.push(cid, MSG_DATA, 0, payload):
            micro_sleep(sleep_us)
        start = time.perf_counter()
        # wait for reply
        deadline = time.monotonic() + (timeout_ms / 1000.0) if timeout_ms > 0 else None
        while True:
            msg = resp.pop()
            if msg:
                _cid, msg_type, _flags, data = msg
                if msg_type == MSG_DATA:
                    ok += 1
                    rtt = time.perf_counter() - start
                    rtt_sum += rtt
                    if verbose:
                        try:
                            text = data.decode(errors="ignore")
                        except Exception:
                            text = str(data[:16])
                        print(f"[client] {i}: {text} ({rtt * 1000:.3f} ms)")
                    break
                elif msg_type == MSG_CLOSE:
                    if verbose:
                        print("[client] server closed")
                    break
            if deadline is not None and time.monotonic() > deadline:
                print(f"[client] timeout waiting for PONG {i}")
                break
            micro_sleep(sleep_us)
    # optional close
    if send_close:
        while not req.push(cid, MSG_CLOSE, 0, b""):
            micro_sleep(sleep_us)
    if ok:
        avg_ms = (rtt_sum / ok) * 1000.0
        print(f"[client] {ok}/{count} ok, avg RTT = {avg_ms:.3f} ms")
    else:
        print(f"[client] 0/{count} ok")
    return ok


def main():
    args = parse_args()
    path = args.uio or args.path
    if not path:
        raise SystemExit("Specify --uio /dev/uioX or --path <file>")

    # Map shared region; first side will initialize header/rings if absent
    shm = CxlShm(path, args.map_size, args.map_offset)
    try:
        if args.role == "server":
            handled = run_server(shm, cid_filter=None, timeout_ms=args.timeout_ms, sleep_us=args.sleep_us, verbose=args.verbose)
            print(f"[server] handled {handled} requests")
        else:
            ok = run_client(shm, cid=args.cid, count=args.count, timeout_ms=args.timeout_ms, sleep_us=args.sleep_us, verbose=args.verbose, send_close=not args.no_close)
            if ok != args.count:
                sys.exit(2)
    finally:
        shm.close()


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        sys.exit(130)
