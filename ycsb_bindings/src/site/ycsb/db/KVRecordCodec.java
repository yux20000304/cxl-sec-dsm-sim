package site.ycsb.db;

import site.ycsb.ByteArrayByteIterator;
import site.ycsb.ByteIterator;

import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;
import java.util.Map;
import java.util.Set;

final class KVRecordCodec {
  private KVRecordCodec() {
  }

  static byte[] encode(Map<String, ByteIterator> values) {
    if (values == null || values.isEmpty()) {
      return new byte[0];
    }

    List<Map.Entry<String, ByteIterator>> entries = new ArrayList<>(values.entrySet());
    entries.sort(Comparator.comparing(Map.Entry::getKey));

    int total = 4;
    List<byte[]> names = new ArrayList<>(entries.size());
    List<byte[]> vals = new ArrayList<>(entries.size());
    for (Map.Entry<String, ByteIterator> e : entries) {
      byte[] name = e.getKey().getBytes(StandardCharsets.UTF_8);
      byte[] val = e.getValue().toArray();
      names.add(name);
      vals.add(val);
      total += 4 + name.length + 4 + val.length;
    }

    ByteBuffer buf = ByteBuffer.allocate(total).order(ByteOrder.LITTLE_ENDIAN);
    buf.putInt(entries.size());
    for (int i = 0; i < entries.size(); i++) {
      byte[] name = names.get(i);
      byte[] val = vals.get(i);
      buf.putInt(name.length);
      buf.put(name);
      buf.putInt(val.length);
      buf.put(val);
    }
    return buf.array();
  }

  static void decode(byte[] data, Set<String> fields, Map<String, ByteIterator> out) {
    if (data == null || data.length < 4 || out == null) {
      return;
    }
    ByteBuffer buf = ByteBuffer.wrap(data).order(ByteOrder.LITTLE_ENDIAN);
    if (buf.remaining() < 4) {
      return;
    }
    int count = buf.getInt();
    if (count < 0) {
      return;
    }
    for (int i = 0; i < count; i++) {
      if (buf.remaining() < 4) {
        return;
      }
      int nameLen = buf.getInt();
      if (nameLen < 0 || nameLen > buf.remaining()) {
        return;
      }
      byte[] nameBytes = new byte[nameLen];
      buf.get(nameBytes);
      String name = new String(nameBytes, StandardCharsets.UTF_8);

      if (buf.remaining() < 4) {
        return;
      }
      int valLen = buf.getInt();
      if (valLen < 0 || valLen > buf.remaining()) {
        return;
      }
      byte[] val = new byte[valLen];
      buf.get(val);

      if (fields == null || fields.contains(name)) {
        out.put(name, new ByteArrayByteIterator(val));
      }
    }
  }
}
