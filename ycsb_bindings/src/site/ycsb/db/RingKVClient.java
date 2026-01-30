package site.ycsb.db;

import site.ycsb.ByteIterator;
import site.ycsb.DB;
import site.ycsb.DBException;
import site.ycsb.Status;

import java.nio.charset.StandardCharsets;
import java.util.Map;
import java.util.Set;
import java.util.Vector;
import java.util.concurrent.atomic.AtomicInteger;

public class RingKVClient extends DB {
  private static final int STATUS_OK = 0;
  private static final int STATUS_MISS = 1;
  private static final int STATUS_ERR = 2;
  private static final int RING_MAX_PAYLOAD = 4078;

  private static final AtomicInteger NEXT_ID = new AtomicInteger(0);

  private long handle;
  private byte[] readBuf;

  static {
    String lib = System.getenv("RING_KV_NATIVE_LIB");
    if (lib != null && !lib.isEmpty()) {
      System.load(lib);
    } else {
      System.loadLibrary("ringkvjni");
    }
  }

  private static native long nativeOpen(int ringIdx);

  private static native void nativeClose(long handle);

  private static native long nativeSet(long handle, byte[] key, int keyLen, byte[] val, int valLen);

  private static native long nativeGet(long handle, byte[] key, int keyLen, byte[] outBuf);

  private static native long nativeDelete(long handle, byte[] key, int keyLen);

  private static native long nativeScan(long handle, byte[] key, int keyLen, long cursor, int count, byte[] outBuf);

  @Override
  public void init() throws DBException {
    int ringCount = 1;
    String rc = System.getenv("CXL_RING_COUNT");
    if (rc != null && !rc.isEmpty()) {
      try {
        ringCount = Integer.parseInt(rc);
      } catch (NumberFormatException ignored) {
      }
    }
    if (ringCount <= 0) {
      ringCount = 1;
    }
    int idx = Math.floorMod(NEXT_ID.getAndIncrement(), ringCount);
    handle = nativeOpen(idx);
    if (handle == 0) {
      throw new DBException("ringkv nativeOpen failed");
    }
    readBuf = new byte[RING_MAX_PAYLOAD];
  }

  @Override
  public void cleanup() throws DBException {
    if (handle != 0) {
      nativeClose(handle);
      handle = 0;
    }
  }

  private static byte[] keyBytes(String key) {
    return key.getBytes(StandardCharsets.UTF_8);
  }

  private static boolean validateKey(byte[] key) {
    return key != null && key.length > 0 && key.length <= 255;
  }

  private static boolean validateValue(byte[] val, int keyLen) {
    if (val == null) {
      return true;
    }
    if (val.length > 65535) {
      return false;
    }
    int maxVal = RING_MAX_PAYLOAD - 4 - keyLen;
    return val.length <= maxVal;
  }

  @Override
  public Status read(String table, String key, Set<String> fields, Map<String, ByteIterator> result) {
    byte[] k = keyBytes(key);
    if (!validateKey(k)) {
      return Status.BAD_REQUEST;
    }
    long rc = nativeGet(handle, k, k.length, readBuf);
    int status = (int) (rc >> 32);
    int len = (int) rc;
    if (status == STATUS_OK) {
      if (result != null && len > 0) {
        byte[] payload = new byte[len];
        System.arraycopy(readBuf, 0, payload, 0, len);
        KVRecordCodec.decode(payload, fields, result);
      }
      return Status.OK;
    }
    if (status == STATUS_MISS) {
      return Status.NOT_FOUND;
    }
    return Status.ERROR;
  }

  @Override
  public Status insert(String table, String key, Map<String, ByteIterator> values) {
    return update(table, key, values);
  }

  @Override
  public Status update(String table, String key, Map<String, ByteIterator> values) {
    byte[] k = keyBytes(key);
    if (!validateKey(k)) {
      return Status.BAD_REQUEST;
    }
    byte[] payload = KVRecordCodec.encode(values);
    if (!validateValue(payload, k.length)) {
      return Status.BAD_REQUEST;
    }
    long rc = nativeSet(handle, k, k.length, payload, payload.length);
    int status = (int) (rc >> 32);
    return (status == STATUS_OK) ? Status.OK : Status.ERROR;
  }

  @Override
  public Status delete(String table, String key) {
    byte[] k = keyBytes(key);
    if (!validateKey(k)) {
      return Status.BAD_REQUEST;
    }
    long rc = nativeDelete(handle, k, k.length);
    int status = (int) (rc >> 32);
    if (status == STATUS_OK) {
      return Status.OK;
    }
    if (status == STATUS_MISS) {
      return Status.NOT_FOUND;
    }
    return Status.ERROR;
  }

  @Override
  public Status scan(String table, String startkey, int recordcount, Set<String> fields,
                     Vector<java.util.HashMap<String, ByteIterator>> result) {
    if (recordcount <= 0) {
      return Status.OK;
    }
    byte[] k = keyBytes(startkey);
    if (!validateKey(k)) {
      return Status.BAD_REQUEST;
    }
    if (result == null) {
      return Status.OK;
    }

    long cursor = 0;
    int remaining = recordcount;
    while (remaining > 0) {
      long rc = nativeScan(handle, k, k.length, cursor, remaining, readBuf);
      int status = (int) (rc >> 32);
      int len = (int) rc;
      if (status != STATUS_OK && status != STATUS_MISS) {
        return Status.ERROR;
      }
      if (len < 12) {
        return Status.OK;
      }
      int count = (readBuf[1] & 0xff) | ((readBuf[2] & 0xff) << 8);
      long nextCursor = 0;
      for (int i = 0; i < 8; i++) {
        nextCursor |= ((long) readBuf[4 + i] & 0xffL) << (8 * i);
      }
      int off = 12;
      for (int i = 0; i < count && off + 2 <= len; i++) {
        int vlen = (readBuf[off] & 0xff) | ((readBuf[off + 1] & 0xff) << 8);
        off += 2;
        if (off + vlen > len) {
          break;
        }
        byte[] payload = new byte[vlen];
        System.arraycopy(readBuf, off, payload, 0, vlen);
        java.util.HashMap<String, ByteIterator> row = new java.util.HashMap<>();
        KVRecordCodec.decode(payload, fields, row);
        result.add(row);
        off += vlen;
        remaining--;
        if (remaining <= 0) {
          break;
        }
      }
      cursor = nextCursor;
      if (cursor == 0 || count == 0) {
        break;
      }
    }
    return Status.OK;
  }
}
