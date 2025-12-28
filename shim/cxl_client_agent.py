#!/usr/bin/env python3
"""
Client-side shim:
- Listens on TCP (e.g., 0.0.0.0:6380) for normal Redis clients
- Forwards byte streams into shared memory request ring
- Receives responses from shared memory response ring and writes back to clients
"""
import argparse
import logging
import selectors
import socket
import time
from typing import Dict, Optional, Tuple

from cxl_shm import CxlShm, MSG_CLOSE, MSG_DATA, SpscRing


LOG = logging.getLogger("cxl_client_agent")


def parse_addr(addr: str) -> Tuple[str, int]:
    host, port = addr.rsplit(":", 1)
    return host, int(port)


class Connection:
    def __init__(self, conn_id: int, sock: socket.socket):
        self.conn_id = conn_id
        self.sock = sock
        self.out_buf = bytearray()  # pending data to client


class ClientAgent:
    def __init__(self, shm: CxlShm, listen: str, verbose: bool = False):
        self.shm = shm
        self.req_ring = SpscRing(shm.mm, shm.layout.req)   # producer
        self.resp_ring = SpscRing(shm.mm, shm.layout.resp) # consumer
        self.listen_addr = parse_addr(listen)
        self.sel = selectors.DefaultSelector()
        self.next_id = 1
        self.conns: Dict[socket.socket, Connection] = {}
        self.id_map: Dict[int, Connection] = {}
        self.verbose = verbose

    def _push_with_backoff(self, ring: SpscRing, conn_id: int, msg_type: int, payload: bytes, max_wait_s: float = 1.0) -> bool:
        start = time.time()
        while True:
            ok = ring.push(conn_id, msg_type, 0, payload)
            if ok:
                return True
            if time.time() - start > max_wait_s:
                return False
            time.sleep(0.001)

    def _accept(self, lsock: socket.socket):
        conn, addr = lsock.accept()
        conn.setblocking(False)
        cid = self.next_id
        self.next_id += 1
        c = Connection(cid, conn)
        self.conns[conn] = c
        self.id_map[cid] = c
        self.sel.register(conn, selectors.EVENT_READ, c)
        LOG.info("Accepted client %s id=%d", addr, cid)

    def _on_client_read(self, conn: Connection):
        sock = conn.sock
        try:
            data = sock.recv(65536)
        except ConnectionResetError:
            data = b""
        if not data:
            LOG.info("Client %d closed", conn.conn_id)
            self._push_with_backoff(self.req_ring, conn.conn_id, MSG_CLOSE, b"")
            self._cleanup(sock)
            return
        if not self._push_with_backoff(self.req_ring, conn.conn_id, MSG_DATA, data):
            LOG.error("Req ring full; dropping client %d", conn.conn_id)
            self._cleanup(sock)

    def _on_client_write(self, conn: Connection):
        sock = conn.sock
        if not conn.out_buf:
            self.sel.modify(sock, selectors.EVENT_READ, conn)
            return
        try:
            sent = sock.send(conn.out_buf)
            if sent > 0:
                del conn.out_buf[:sent]
        except (ConnectionResetError, BrokenPipeError):
            self._push_with_backoff(self.req_ring, conn.conn_id, MSG_CLOSE, b"")
            self._cleanup(sock)
            return
        if not conn.out_buf:
            self.sel.modify(sock, selectors.EVENT_READ, conn)

    def _cleanup(self, sock: socket.socket):
        try:
            self.sel.unregister(sock)
        except Exception:
            pass
        conn = self.conns.pop(sock, None)
        if conn:
            self.id_map.pop(conn.conn_id, None)
        try:
            sock.close()
        except Exception:
            pass
        if conn:
            LOG.info("Closed connection id=%d", conn.conn_id)

    def _poll_responses(self):
        while True:
            msg = self.resp_ring.pop()
            if msg is None:
                break
            client_id, msg_type, flags, payload = msg
            target = self.id_map.get(client_id)
            if not target:
                LOG.debug("Response for unknown/closed client %d (type %d)", client_id, msg_type)
                continue
            if msg_type == MSG_DATA:
                target.out_buf.extend(payload)
                self.sel.modify(target.sock, selectors.EVENT_READ | selectors.EVENT_WRITE, target)
            elif msg_type == MSG_CLOSE:
                LOG.info("Server requested close for client %d", client_id)
                self._cleanup(target.sock)

    def run(self):
        lsock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        lsock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        lsock.bind(self.listen_addr)
        lsock.listen()
        lsock.setblocking(False)
        self.sel.register(lsock, selectors.EVENT_READ, "listener")
        LOG.info("Listening on %s:%d", *self.listen_addr)
        try:
            while True:
                self._poll_responses()
                events = self.sel.select(timeout=0.01)
                for key, _mask in events:
                    if key.data == "listener":
                        self._accept(key.fileobj)
                    else:
                        conn = key.data
                        if _mask & selectors.EVENT_READ:
                            self._on_client_read(conn)
                        if _mask & selectors.EVENT_WRITE:
                            self._on_client_write(conn)
        finally:
            self.sel.close()
            for sock in list(self.conns.keys()):
                self._cleanup(sock)


def main():
    ap = argparse.ArgumentParser(description="Client-side shim to forward Redis traffic over shared memory")
    backend = ap.add_mutually_exclusive_group(required=True)
    backend.add_argument("--uio", help="Path to /dev/uioX")
    backend.add_argument("--path", help="Path to shared memory file")
    ap.add_argument("--map-size", type=int, help="Bytes to mmap (optional, useful if backing file is large)")
    ap.add_argument("--listen", default="0.0.0.0:6380", help="Listen address for Redis clients")
    ap.add_argument("-v", "--verbose", action="store_true")
    args = ap.parse_args()

    logging.basicConfig(level=logging.DEBUG if args.verbose else logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
    shm_path = args.uio or args.path
    shm = CxlShm(shm_path, args.map_size)
    agent = ClientAgent(shm, args.listen, verbose=args.verbose)
    agent.run()


if __name__ == "__main__":
    main()
