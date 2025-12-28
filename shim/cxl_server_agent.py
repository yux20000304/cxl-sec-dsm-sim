#!/usr/bin/env python3
"""
Server-side shim:
- Consumes request ring from client agent
- For each client_id, opens a dedicated TCP connection to local Redis
- Forwards bytes to Redis; reads responses and writes back via response ring
"""
import argparse
import logging
import selectors
import socket
import time
from typing import Dict, Optional, Tuple

from cxl_shm import CxlShm, MSG_CLOSE, MSG_DATA, SpscRing

LOG = logging.getLogger("cxl_server_agent")


def parse_hostport(hp: str) -> Tuple[str, int]:
    host, port = hp.rsplit(":", 1)
    return host, int(port)


class RedisConn:
    def __init__(self, client_id: int, sock: socket.socket):
        self.client_id = client_id
        self.sock = sock
        self.out_buf = bytearray()  # data to send to Redis


class ServerAgent:
    def __init__(self, shm: CxlShm, redis_addr: Tuple[str, int]):
        self.shm = shm
        self.req_ring = SpscRing(shm.mm, shm.layout.req)   # consumer
        self.resp_ring = SpscRing(shm.mm, shm.layout.resp) # producer
        self.redis_addr = redis_addr
        self.sel = selectors.DefaultSelector()
        self.conns: Dict[int, RedisConn] = {}  # client_id -> RedisConn

    def _push_resp(self, client_id: int, msg_type: int, payload: bytes, max_wait_s: float = 1.0) -> bool:
        start = time.time()
        while True:
            if self.resp_ring.push(client_id, msg_type, 0, payload):
                return True
            if time.time() - start > max_wait_s:
                return False
            time.sleep(0.001)

    def _ensure_conn(self, client_id: int) -> Optional[RedisConn]:
        conn = self.conns.get(client_id)
        if conn:
            return conn
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.setblocking(False)
            s.connect_ex(self.redis_addr)
            rc = RedisConn(client_id, s)
            self.conns[client_id] = rc
            self.sel.register(s, selectors.EVENT_READ, rc)
            LOG.info("Opened Redis connection for client %d", client_id)
            return rc
        except Exception as e:
            LOG.error("Failed to connect to Redis for client %d: %s", client_id, e)
            self._push_resp(client_id, MSG_CLOSE, b"")
            return None

    def _on_redis_read(self, rc: RedisConn):
        sock = rc.sock
        try:
            data = sock.recv(65536)
        except ConnectionResetError:
            data = b""
        if not data:
            LOG.info("Redis closed for client %d", rc.client_id)
            self._cleanup(rc.client_id)
            self._push_resp(rc.client_id, MSG_CLOSE, b"")
            return
        if not self._push_resp(rc.client_id, MSG_DATA, data):
            LOG.error("Resp ring full; dropping client %d", rc.client_id)
            self._cleanup(rc.client_id)

    def _on_redis_write(self, rc: RedisConn):
        sock = rc.sock
        if not rc.out_buf:
            self.sel.modify(sock, selectors.EVENT_READ, rc)
            return
        try:
            sent = sock.send(rc.out_buf)
            if sent > 0:
                del rc.out_buf[:sent]
        except (ConnectionResetError, BrokenPipeError):
            LOG.info("Redis send failed for client %d", rc.client_id)
            self._cleanup(rc.client_id)
            self._push_resp(rc.client_id, MSG_CLOSE, b"")
            return
        if not rc.out_buf:
            self.sel.modify(sock, selectors.EVENT_READ, rc)

    def _cleanup(self, client_id: int):
        rc = self.conns.pop(client_id, None)
        if not rc:
            return
        try:
            self.sel.unregister(rc.sock)
        except Exception:
            pass
        try:
            rc.sock.close()
        except Exception:
            pass
        LOG.info("Closed Redis connection for client %d", client_id)

    def _drain_requests(self):
        while True:
            msg = self.req_ring.pop()
            if msg is None:
                break
            client_id, msg_type, flags, payload = msg
            if msg_type == MSG_CLOSE:
                LOG.info("Client %d requested close", client_id)
                self._cleanup(client_id)
                self._push_resp(client_id, MSG_CLOSE, b"")
                continue
            if msg_type != MSG_DATA:
                LOG.debug("Unknown msg_type %d from client %d", msg_type, client_id)
                continue
            rc = self._ensure_conn(client_id)
            if not rc:
                continue
            rc.out_buf.extend(payload)
            self.sel.modify(rc.sock, selectors.EVENT_READ | selectors.EVENT_WRITE, rc)

    def run(self):
        LOG.info("Server agent connecting to Redis at %s:%d", *self.redis_addr)
        try:
            while True:
                self._drain_requests()
                events = self.sel.select(timeout=0.01)
                for key, mask in events:
                    rc = key.data
                    if mask & selectors.EVENT_READ:
                        self._on_redis_read(rc)
                    if mask & selectors.EVENT_WRITE:
                        self._on_redis_write(rc)
        finally:
            self.sel.close()
            for cid in list(self.conns.keys()):
                self._cleanup(cid)


def main():
    ap = argparse.ArgumentParser(description="Server-side shim to forward Redis over shared memory")
    backend = ap.add_mutually_exclusive_group(required=True)
    backend.add_argument("--uio", help="Path to /dev/uioX")
    backend.add_argument("--path", help="Path to shared memory file")
    ap.add_argument("--map-size", type=int, help="Bytes to mmap (optional)")
    ap.add_argument("--redis", default="127.0.0.1:6379", help="Redis host:port (inside VM1)")
    ap.add_argument("-v", "--verbose", action="store_true")
    args = ap.parse_args()

    logging.basicConfig(level=logging.DEBUG if args.verbose else logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
    shm_path = args.uio or args.path
    shm = CxlShm(shm_path, args.map_size)
    agent = ServerAgent(shm, parse_hostport(args.redis))
    agent.run()


if __name__ == "__main__":
    main()
