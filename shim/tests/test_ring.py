import os
import sys
import tempfile
import unittest

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
if ROOT not in sys.path:
  sys.path.insert(0, ROOT)

from shim import cxl_shm


class TestRing(unittest.TestCase):
    def _tmpfile(self, size=4 * 1024 * 1024):
        f = tempfile.NamedTemporaryFile(delete=False)
        f.truncate(size)
        f.close()
        return f.name

    def test_push_pop_single(self):
        path = self._tmpfile()
        shm = cxl_shm.CxlShm(path)
        ring = cxl_shm.SpscRing(shm.mm, shm.layout.req)
        self.assertTrue(ring.push(1, cxl_shm.MSG_DATA, 0, b"hello"))
        msg = ring.pop()
        self.assertEqual(msg, (1, cxl_shm.MSG_DATA, 0, b"hello"))
        shm.close()
        os.remove(path)

    def test_ring_full(self):
        path = self._tmpfile(2 * 1024 * 1024)
        shm = cxl_shm.CxlShm(path)
        ring = cxl_shm.SpscRing(shm.mm, shm.layout.req)
        ring.cfg.slots = 2  # shrink for test
        self.assertTrue(ring.push(1, cxl_shm.MSG_DATA, 0, b"a"))
        self.assertTrue(ring.push(1, cxl_shm.MSG_DATA, 0, b"b"))
        self.assertFalse(ring.push(1, cxl_shm.MSG_DATA, 0, b"c"))
        self.assertIsNotNone(ring.pop())
        self.assertTrue(ring.push(1, cxl_shm.MSG_DATA, 0, b"d"))
        shm.close()
        os.remove(path)

    def test_payload_limit(self):
        path = self._tmpfile(2 * 1024 * 1024)
        shm = cxl_shm.CxlShm(path)
        ring = cxl_shm.SpscRing(shm.mm, shm.layout.req)
        too_big = b"x" * (ring.cfg.slot_size - ring.SLOT_HDR_SIZE + 1)
        with self.assertRaises(ValueError):
            ring.push(1, cxl_shm.MSG_DATA, 0, too_big)
        shm.close()
        os.remove(path)


if __name__ == "__main__":
    unittest.main()
