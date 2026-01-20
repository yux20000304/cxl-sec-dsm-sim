package site.ycsb.db;

import site.ycsb.ByteArrayByteIterator;
import site.ycsb.ByteIterator;
import site.ycsb.DB;
import site.ycsb.DBException;
import site.ycsb.Status;

import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.charset.StandardCharsets;
import java.util.HashMap;
import java.util.Map;
import java.util.Properties;
import java.util.Set;
import java.util.Vector;
import java.util.concurrent.atomic.AtomicInteger;

public class CxlRingClient extends DB {
  // ring protocol v2 status codes
  private static final int CXL_STATUS_OK = 0;
  private static final int CXL_STATUS_MISS = 1;

  private static native long nativeOpen(
      String path,
      long mapSize,
      int ringIdx,
      boolean secure,
      String secMgr,
      int secNodeId,
      int timeoutMs);

  private static native void nativeClose(long handle);

  private static native byte[] nativeGet(long handle, byte[] key, int timeoutMs);

  private static native int nativeSet(long handle, byte[] key, byte[] value, int timeoutMs);

  private static native int nativeDel(long handle, byte[] key, int timeoutMs);

  static {
    String soPath = System.getProperty("cxl.ring.jni.path");
    if (soPath != null && !soPath.isEmpty()) {
      System.load(soPath);
    } else {
      System.loadLibrary("cxlringjni");
    }
  }

  private long handle;
  private int timeoutMs;
  private int ringIdx;

  private static final AtomicInteger NEXT_RING = new AtomicInteger(0);

  @Override
  public void init() throws DBException {
    Properties p = getProperties();

    String path = p.getProperty("cxl.ring.path", "");
    if (path.isEmpty()) {
      throw new DBException("Missing property: cxl.ring.path");
    }
    long mapSize = parseLong(p.getProperty("cxl.ring.map_size", "0"));
    ringIdx = allocateRingIndex(p);
    boolean secure = Boolean.parseBoolean(p.getProperty("cxl.ring.secure", "false"));
    String secMgr = p.getProperty("cxl.sec.mgr", "");
    int secNodeId = (int) parseLong(p.getProperty("cxl.sec.node_id", "2"));
    timeoutMs = (int) parseLong(p.getProperty("cxl.ring.timeout_ms", "5000"));

    if (secure && secMgr.isEmpty()) {
      throw new DBException("cxl.ring.secure=true requires cxl.sec.mgr=<ip:port>");
    }

    handle = nativeOpen(path, mapSize, ringIdx, secure, secMgr, secNodeId, timeoutMs);
    if (handle == 0) {
      throw new DBException("nativeOpen failed");
    }
  }

  @Override
  public void cleanup() throws DBException {
    if (handle != 0) {
      nativeClose(handle);
      handle = 0;
    }
  }

  @Override
  public Status read(String table, String key, Set<String> fields, Map<String, ByteIterator> result) {
    byte[] keyBytes = key.getBytes(StandardCharsets.UTF_8);
    byte[] blob = nativeGet(handle, keyBytes, timeoutMs);
    if (blob == null) {
      return Status.NOT_FOUND;
    }
    try {
      decodeInto(blob, fields, result);
      return Status.OK;
    } catch (RuntimeException e) {
      return Status.ERROR;
    }
  }

  @Override
  public Status insert(String table, String key, Map<String, ByteIterator> values) {
    byte[] keyBytes = key.getBytes(StandardCharsets.UTF_8);
    byte[] encoded = encode(values);
    int st = nativeSet(handle, keyBytes, encoded, timeoutMs);
    return st == CXL_STATUS_OK ? Status.OK : Status.ERROR;
  }

  @Override
  public Status update(String table, String key, Map<String, ByteIterator> values) {
    byte[] keyBytes = key.getBytes(StandardCharsets.UTF_8);
    byte[] cur = nativeGet(handle, keyBytes, timeoutMs);
    Map<String, byte[]> merged = new HashMap<>();
    if (cur != null) {
      try {
        merged.putAll(decodeAll(cur));
      } catch (RuntimeException e) {
        // Treat as missing/corrupt and overwrite with provided values.
        merged.clear();
      }
    }
    for (Map.Entry<String, ByteIterator> e : values.entrySet()) {
      merged.put(e.getKey(), toBytes(e.getValue()));
    }
    int st = nativeSet(handle, keyBytes, encodeBytes(merged), timeoutMs);
    return st == CXL_STATUS_OK ? Status.OK : Status.ERROR;
  }

  @Override
  public Status delete(String table, String key) {
    byte[] keyBytes = key.getBytes(StandardCharsets.UTF_8);
    int st = nativeDel(handle, keyBytes, timeoutMs);
    if (st == CXL_STATUS_OK) return Status.OK;
    if (st == CXL_STATUS_MISS) return Status.NOT_FOUND;
    return Status.ERROR;
  }

  @Override
  public Status scan(
      String table,
      String startkey,
      int recordcount,
      Set<String> fields,
      Vector<HashMap<String, ByteIterator>> result) {
    KeyCursor c = KeyCursor.parse(startkey);
    if (!c.ok) return Status.ERROR;

    for (int i = 0; i < recordcount; i++) {
      String key = c.formatCurrentAndAdvance();
      byte[] blob = nativeGet(handle, key.getBytes(StandardCharsets.UTF_8), timeoutMs);
      if (blob == null) continue;
      HashMap<String, ByteIterator> row = new HashMap<>();
      try {
        decodeInto(blob, fields, row);
      } catch (RuntimeException e) {
        return Status.ERROR;
      }
      result.add(row);
    }
    return Status.OK;
  }

  private static long parseLong(String s) {
    try {
      return Long.parseLong(s.trim());
    } catch (NumberFormatException e) {
      return 0;
    }
  }

  private static int allocateRingIndex(Properties p) throws DBException {
    String explicit = p.getProperty("cxl.ring.idx", "");
    if (!explicit.isEmpty()) {
      return (int) parseLong(explicit);
    }
    int count = (int) parseLong(p.getProperty("cxl.ring.count", "0"));
    int idx = NEXT_RING.getAndIncrement();
    if (count > 0 && idx >= count) {
      throw new DBException("YCSB threads exceed cxl.ring.count (need one ring per thread)");
    }
    return idx;
  }

  private static byte[] toBytes(ByteIterator it) {
    long left = it.bytesLeft();
    if (left < 0 || left > Integer.MAX_VALUE) {
      throw new IllegalArgumentException("value too large: " + left);
    }
    byte[] out = new byte[(int) left];
    int n = it.nextBuf(out, 0);
    if (n != out.length) {
      byte[] trimmed = new byte[n];
      System.arraycopy(out, 0, trimmed, 0, n);
      return trimmed;
    }
    return out;
  }

  // Encoding: u16 field_count, then repeated [u8 name_len][name][u16 value_len][value] (all little-endian).
  private static byte[] encode(Map<String, ByteIterator> values) {
    Map<String, byte[]> m = new HashMap<>();
    for (Map.Entry<String, ByteIterator> e : values.entrySet()) {
      m.put(e.getKey(), toBytes(e.getValue()));
    }
    return encodeBytes(m);
  }

  private static byte[] encodeBytes(Map<String, byte[]> values) {
    int total = 2;
    for (Map.Entry<String, byte[]> e : values.entrySet()) {
      byte[] name = e.getKey().getBytes(StandardCharsets.UTF_8);
      byte[] val = e.getValue();
      total += 1 + name.length + 2 + val.length;
    }
    ByteBuffer b = ByteBuffer.allocate(total).order(ByteOrder.LITTLE_ENDIAN);
    b.putShort((short) values.size());
    for (Map.Entry<String, byte[]> e : values.entrySet()) {
      byte[] name = e.getKey().getBytes(StandardCharsets.UTF_8);
      byte[] val = e.getValue();
      if (name.length > 255) throw new IllegalArgumentException("field name too long");
      if (val.length > 65535) throw new IllegalArgumentException("field value too long");
      b.put((byte) name.length);
      b.put(name);
      b.putShort((short) val.length);
      b.put(val);
    }
    return b.array();
  }

  private static Map<String, byte[]> decodeAll(byte[] blob) {
    ByteBuffer b = ByteBuffer.wrap(blob).order(ByteOrder.LITTLE_ENDIAN);
    int n = Short.toUnsignedInt(b.getShort());
    Map<String, byte[]> out = new HashMap<>(n * 2);
    for (int i = 0; i < n; i++) {
      int nameLen = Byte.toUnsignedInt(b.get());
      byte[] name = new byte[nameLen];
      b.get(name);
      int valLen = Short.toUnsignedInt(b.getShort());
      byte[] val = new byte[valLen];
      b.get(val);
      out.put(new String(name, StandardCharsets.UTF_8), val);
    }
    return out;
  }

  private static void decodeInto(byte[] blob, Set<String> fields, Map<String, ByteIterator> out) {
    boolean all = (fields == null) || fields.isEmpty();
    ByteBuffer b = ByteBuffer.wrap(blob).order(ByteOrder.LITTLE_ENDIAN);
    int n = Short.toUnsignedInt(b.getShort());
    for (int i = 0; i < n; i++) {
      int nameLen = Byte.toUnsignedInt(b.get());
      byte[] nameBytes = new byte[nameLen];
      b.get(nameBytes);
      String name = new String(nameBytes, StandardCharsets.UTF_8);
      int valLen = Short.toUnsignedInt(b.getShort());
      byte[] val = new byte[valLen];
      b.get(val);
      if (all || fields.contains(name)) {
        out.put(name, new ByteArrayByteIterator(val));
      }
    }
  }

  private static final class KeyCursor {
    final boolean ok;
    final String prefix;
    final int width;
    long cur;

    private KeyCursor(boolean ok, String prefix, int width, long cur) {
      this.ok = ok;
      this.prefix = prefix;
      this.width = width;
      this.cur = cur;
    }

    static KeyCursor parse(String key) {
      int end = key.length() - 1;
      while (end >= 0 && Character.isDigit(key.charAt(end))) {
        end--;
      }
      String prefix = key.substring(0, end + 1);
      String digits = key.substring(end + 1);
      if (digits.isEmpty()) return new KeyCursor(false, "", 0, 0);
      long cur;
      try {
        cur = Long.parseLong(digits);
      } catch (NumberFormatException e) {
        return new KeyCursor(false, "", 0, 0);
      }
      return new KeyCursor(true, prefix, digits.length(), cur);
    }

    String formatCurrentAndAdvance() {
      String num = Long.toString(cur++);
      if (num.length() >= width) return prefix + num;
      StringBuilder sb = new StringBuilder(prefix.length() + width);
      sb.append(prefix);
      for (int i = num.length(); i < width; i++) sb.append('0');
      sb.append(num);
      return sb.toString();
    }
  }
}
