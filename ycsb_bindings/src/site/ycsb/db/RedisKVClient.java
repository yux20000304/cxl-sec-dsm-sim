package site.ycsb.db;

import site.ycsb.ByteIterator;
import site.ycsb.DB;
import site.ycsb.DBException;
import site.ycsb.Status;
import redis.clients.jedis.BasicCommands;
import redis.clients.jedis.HostAndPort;
import redis.clients.jedis.Jedis;
import redis.clients.jedis.JedisCluster;
import redis.clients.jedis.Protocol;
import redis.clients.jedis.ScanParams;
import redis.clients.jedis.ScanResult;

import java.io.Closeable;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.HashSet;
import java.util.HashMap;
import java.util.Map;
import java.util.Properties;
import java.util.Set;
import java.util.Vector;

public class RedisKVClient extends DB {
  public static final String HOST_PROPERTY = "redis.host";
  public static final String PORT_PROPERTY = "redis.port";
  public static final String PASSWORD_PROPERTY = "redis.password";
  public static final String CLUSTER_PROPERTY = "redis.cluster";
  public static final String TIMEOUT_MS_PROPERTY = "redis.timeout.ms";
  public static final String MAX_ATTEMPTS_PROPERTY = "redis.maxattempts";

  private Jedis jedis;
  private JedisCluster jedisCluster;
  private boolean cluster;

  @Override
  public void init() throws DBException {
    Properties props = getProperties();
    int port = Protocol.DEFAULT_PORT;
    String portString = props.getProperty(PORT_PROPERTY);
    if (portString != null) {
      port = Integer.parseInt(portString);
    }
    String host = props.getProperty(HOST_PROPERTY);
    int timeoutMs = 0;
    String timeoutString = props.getProperty(TIMEOUT_MS_PROPERTY);
    if (timeoutString != null) {
      timeoutMs = Integer.parseInt(timeoutString);
    }
    int maxAttempts = 5;
    String maxAttemptsString = props.getProperty(MAX_ATTEMPTS_PROPERTY);
    if (maxAttemptsString != null) {
      maxAttempts = Integer.parseInt(maxAttemptsString);
    }

    cluster = Boolean.parseBoolean(props.getProperty(CLUSTER_PROPERTY));
    if (cluster) {
      Set<HostAndPort> nodes = new HashSet<>();
      nodes.add(new HostAndPort(host, port));
      if (timeoutMs > 0) {
        jedisCluster = new JedisCluster(nodes, timeoutMs, maxAttempts);
      } else {
        jedisCluster = new JedisCluster(nodes);
      }
    } else {
      jedis = (timeoutMs > 0) ? new Jedis(host, port, timeoutMs) : new Jedis(host, port);
      jedis.connect();
    }

    String password = props.getProperty(PASSWORD_PROPERTY);
    if (password != null) {
      BasicCommands authClient = cluster ? jedisCluster : jedis;
      authClient.auth(password);
    }
  }

  @Override
  public void cleanup() throws DBException {
    try {
      Closeable c = cluster ? jedisCluster : jedis;
      if (c != null) {
        c.close();
      }
    } catch (IOException e) {
      throw new DBException("Closing connection failed.");
    }
  }

  private byte[] keyBytes(String key) {
    return key.getBytes(StandardCharsets.UTF_8);
  }

  @Override
  public Status read(String table, String key, Set<String> fields, Map<String, ByteIterator> result) {
    byte[] k = keyBytes(key);
    byte[] value = cluster ? jedisCluster.get(k) : jedis.get(k);
    if (value == null) {
      return Status.NOT_FOUND;
    }
    if (result != null) {
      KVRecordCodec.decode(value, fields, result);
    }
    return Status.OK;
  }

  @Override
  public Status insert(String table, String key, Map<String, ByteIterator> values) {
    byte[] k = keyBytes(key);
    byte[] payload = KVRecordCodec.encode(values);
    String resp = cluster ? jedisCluster.set(k, payload) : jedis.set(k, payload);
    return "OK".equals(resp) ? Status.OK : Status.ERROR;
  }

  @Override
  public Status update(String table, String key, Map<String, ByteIterator> values) {
    return insert(table, key, values);
  }

  @Override
  public Status delete(String table, String key) {
    byte[] k = keyBytes(key);
    long removed = cluster ? jedisCluster.del(k) : jedis.del(k);
    return removed > 0 ? Status.OK : Status.NOT_FOUND;
  }

  @Override
  public Status scan(String table, String startkey, int recordcount, Set<String> fields,
                     Vector<java.util.HashMap<String, ByteIterator>> result) {
    if (cluster) {
      return Status.NOT_IMPLEMENTED;
    }
    if (recordcount <= 0 || result == null) {
      return Status.OK;
    }

    String cursor = ScanParams.SCAN_POINTER_START;
    ScanParams params = new ScanParams().count(Math.max(1, recordcount));
    int remaining = recordcount;

    while (remaining > 0) {
      ScanResult<String> scan = jedis.scan(cursor, params);
      cursor = String.valueOf(scan.getCursor());
      for (String k : scan.getResult()) {
        byte[] val = jedis.get(k.getBytes(StandardCharsets.UTF_8));
        if (val == null) {
          continue;
        }
        HashMap<String, ByteIterator> row = new HashMap<>();
        KVRecordCodec.decode(val, fields, row);
        result.add(row);
        remaining--;
        if (remaining <= 0) {
          break;
        }
      }
      if ("0".equals(cursor)) {
        break;
      }
    }
    return Status.OK;
  }
}
