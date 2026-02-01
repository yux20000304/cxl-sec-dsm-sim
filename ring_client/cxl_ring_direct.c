#define _GNU_SOURCE

#include "../tdx_shm/tdx_shm_transport.h"

#include <arpa/inet.h>
#include <endian.h>
#include <errno.h>
#include <inttypes.h>
#include <limits.h>
#include <netdb.h>
#include <pthread.h>
#include <signal.h>
#include <sodium.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>
#include <fcntl.h>

/* TDX shared-memory ring client matching Redis shared-memory backend (GET/SET binary protocol).
 *
 * Transport: per-ring TDX SHM region (double-queue layout):
 * - server->client: q12
 * - client->server: q21
 *
 * Each request/response message is stored in a 4KiB slot as:
 *   u16 msg_len (bytes after this length field)
 *   16B header: cid,u16 type,u16 flags,u32 len,u32 reserved
 *   payload (len bytes)
 *
 * Request payload:
 *   u8 op (1=GET,2=SET), u8 key_len, u16 val_len (LE), key, val
 * Response payload:
 *   u8 status (0=OK,1=MISS,2=ERR), u16 val_len (LE), u8 reserved, val
 *
 * Notes:
 * - Keep RESP parsing out of the hot path.
 * - Slot payload budget is limited by the TDX SHM framing:
 *     max_payload = (TDX_SHM_SLOT_SIZE - 2) - 16 = 4078 bytes
 */

#define MSG_DATA 1
#define MSG_CLOSE 2

#define OP_GET  1
#define OP_SET  2
#define OP_DEL  3
#define OP_SCAN 4

#define STATUS_OK 0
#define STATUS_MISS 1
#define STATUS_ERR 2

#define MAX_RINGS 8
#define RING_SLOT_HDR_SIZE 16U
#define RING_MAX_PAYLOAD ((uint32_t)TDX_SHM_MSG_MAX - RING_SLOT_HDR_SIZE)

/* Shared-memory security table (cxl_sec_mgr). */
#define CXL_SEC_TABLE_OFF 512
#define CXL_SEC_MAGIC "CXLSEC1\0"
#define CXL_SEC_VERSION 1
#define CXL_SEC_MAX_ENTRIES (MAX_RINGS * 2)
#define CXL_SEC_MAX_PRINCIPALS 16

#define SEC_PROTO_MAGIC 0x43534543u /* 'CSEC' */
#define SEC_PROTO_VERSION 1
#define SEC_REQ_ACCESS 1

#define SEC_STATUS_OK 0

/* ring_slot_hdr.flags */
#define RING_FLAG_SECURE 0x0001u

#define SEC_DIR_REQ 1u  /* client->server */
#define SEC_DIR_RESP 2u /* server->client */

typedef struct {
    uint64_t start_off;
    uint64_t end_off;
    unsigned char key[crypto_stream_chacha20_ietf_KEYBYTES];
    uint32_t principal_count;
    uint32_t reserved;
    uint64_t principals[CXL_SEC_MAX_PRINCIPALS];
} CxlSecEntry;

typedef struct {
    char magic[8];
    uint32_t version;
    uint32_t entry_count;
    CxlSecEntry entries[CXL_SEC_MAX_ENTRIES];
} CxlSecTable;

struct sec_req {
    uint32_t magic_be;
    uint16_t version_be;
    uint16_t type_be;
    uint64_t principal_be;
    uint64_t offset_be;
    uint32_t length_be;
    uint32_t reserved_be;
};

struct sec_resp {
    uint32_t magic_be;
    uint16_t version_be;
    uint16_t status_be;
    uint32_t reserved_be;
};

static int use_lock = 0;
static pthread_mutex_t req_lock = PTHREAD_MUTEX_INITIALIZER;
static pthread_mutex_t resp_lock = PTHREAD_MUTEX_INITIALIZER;

static uint64_t shm_delay_ns = 0;
static uint64_t shm_pause_iters_per_ns_x1024 = 0;
/* Backoff policy for polling an empty response queue / full request queue.
 * Defaults are tuned for throughput benchmarking (avoid coarse scheduler sleeps)
 * while still allowing the CPU to back off under prolonged emptiness. */
static uint64_t poll_spin_ns = 5000;   /* pause-loop time before sleeping (ns) */
static uint64_t poll_sleep_ns = 50000; /* nanosleep time after spinning (ns) */

static volatile int running = 1;
static void handle_sig(int sig) {
    (void)sig;
    running = 0;
}

struct ring_info {
    struct tdx_shm_queue_view req;  /* q21 (client -> server) */
    struct tdx_shm_queue_view resp; /* q12 (server -> client) */
    uint32_t slots;                 /* capacity - 1 (informational) */
    uint32_t ring_idx;
};

struct layout {
    uint32_t ring_count;
    struct ring_info rings[MAX_RINGS];
};

struct latency_stats {
    double *samples;
    int cap;
    int count;
    double sum;
};

struct cost_stats {
    uint64_t push_retries;
    uint64_t sleep_ns;
};

struct ts_queue {
    uint64_t *buf;
    int cap;
    int head;
    int tail;
};

struct stage_ctx {
    int collect_latency;
    int collect_cost;
    struct ts_queue q;
    struct latency_stats ls;
    struct cost_stats cs;
};

struct bench_result {
    double set_sec;
    double get_sec;
    int n;
    int tid;
    struct latency_stats set_lat;
    struct latency_stats get_lat;
    struct cost_stats set_cost;
    struct cost_stats get_cost;
};

struct agg_latency {
    double avg;
    double p50, p75, p90, p99, p999, p9999;
    int count;
};

struct ring_slot_hdr {
    uint32_t cid;
    uint16_t type;
    uint16_t flags;
    uint32_t len;
    uint32_t reserved;
};

static int g_secure = 0;
static int g_crypto = 0; /* manager-less crypto mode (vm key + common key) */
static const char *g_sec_mgr = NULL;
static uint64_t g_sec_node_id = 0;
static unsigned g_sec_timeout_ms = 10000;
static unsigned char g_sec_key[MAX_RINGS][crypto_aead_chacha20poly1305_ietf_KEYBYTES];
static int g_sec_key_ok[MAX_RINGS];
static atomic_uint_fast64_t g_sec_nonce_ctr_req[MAX_RINGS];

static const char *g_crypto_key_hex = NULL;
static const char *g_crypto_common_hex = NULL;
static unsigned char g_crypto_vm_key[crypto_stream_chacha20_ietf_KEYBYTES];
static unsigned char g_crypto_common_key[crypto_stream_chacha20_ietf_KEYBYTES];
static size_t g_crypto_priv_region_base = 0;
static size_t g_crypto_priv_region_size = 0;
static unsigned char *g_crypto_priv = NULL;
static atomic_uint_fast64_t g_crypto_priv_nonce_ctr[MAX_RINGS];

static size_t g_bench_key_size = 0;
static size_t g_bench_val_size = 0;

struct sec_perm_stats {
    uint64_t table_wait_ns;
    uint64_t principal_sleep_ns;
    uint64_t mgr_calls;
    uint64_t mgr_ns;
};

static const char *g_sec_stats_out = NULL;
static int g_sec_stats_enabled = 0;
static struct sec_perm_stats g_sec_perm = {0};

static inline uint64_t nowns(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000000000ULL + (uint64_t)ts.tv_nsec;
}

static void write_sec_perm_stats_json(const struct layout *lo) {
    if (!g_sec_stats_enabled || !g_sec_stats_out || !g_sec_stats_out[0]) return;
    int fd = open(g_sec_stats_out, O_WRONLY | O_CREAT | O_EXCL, 0644);
    if (fd < 0) {
        if (errno != EEXIST) perror("open CXL_SEC_STATS_OUT");
        return;
    }
    FILE *f = fdopen(fd, "w");
    if (!f) {
        close(fd);
        return;
    }
    uint64_t total_perm_ns = g_sec_perm.table_wait_ns + g_sec_perm.principal_sleep_ns + g_sec_perm.mgr_ns;
    fprintf(f,
            "{\n"
            "  \"mode\": \"%s\",\n"
            "  \"node_id\": %" PRIu64 ",\n"
            "  \"ring_count\": %u,\n"
            "  \"table_wait_ns\": %" PRIu64 ",\n"
            "  \"principal_sleep_ns\": %" PRIu64 ",\n"
            "  \"sec_mgr_calls\": %" PRIu64 ",\n"
            "  \"sec_mgr_ns\": %" PRIu64 ",\n"
            "  \"perm_total_ns\": %" PRIu64 "\n"
            "}\n",
            g_crypto ? "crypto" : (g_secure ? "secure" : "none"),
            (uint64_t)g_sec_node_id,
            lo ? lo->ring_count : 0u,
            g_sec_perm.table_wait_ns,
            g_sec_perm.principal_sleep_ns,
            g_sec_perm.mgr_calls,
            g_sec_perm.mgr_ns,
            total_perm_ns);
    fclose(f);
}

static inline size_t align_up(size_t value, size_t align) {
    return (value + align - 1U) & ~(align - 1U);
}

static size_t env_size(const char *key, size_t def);

static void shm_delay_calibrate(void) {
    if (shm_pause_iters_per_ns_x1024) return;
    const uint64_t iters = 5000000ULL;
    uint64_t start = nowns();
    for (uint64_t i = 0; i < iters; i++) {
        __asm__ __volatile__("pause");
    }
    uint64_t dt = nowns() - start;
    if (dt == 0) dt = 1;
    shm_pause_iters_per_ns_x1024 = (iters * 1024ULL) / dt;
    if (shm_pause_iters_per_ns_x1024 == 0) shm_pause_iters_per_ns_x1024 = 1;
}

static inline void shm_delay(void) {
    uint64_t ns = shm_delay_ns;
    if (!ns) return;
    if (!shm_pause_iters_per_ns_x1024) shm_delay_calibrate();
    uint64_t iters = (ns * shm_pause_iters_per_ns_x1024 + 1023ULL) / 1024ULL;
    if (iters == 0) iters = 1;
    for (uint64_t i = 0; i < iters; i++) {
        __asm__ __volatile__("pause");
    }
}

static int parse_key_hex(const char *hex, unsigned char *out_key, size_t out_len) {
    if (!hex || !hex[0] || !out_key || out_len == 0) return -1;
    size_t bin_len = 0;
    if (sodium_hex2bin(out_key, out_len, hex, strlen(hex), NULL, &bin_len, NULL) != 0) return -1;
    if (bin_len != out_len) return -1;
    return 0;
}

static int crypto_priv_init(unsigned char *mm, size_t map_size, const struct layout *lo) {
    if (!g_crypto) return 0;
    if (!mm || mm == MAP_FAILED || map_size == 0) return -1;
    if (!lo || lo->ring_count == 0 || lo->ring_count > MAX_RINGS) return -1;
    if (g_sec_node_id == 0) {
        fprintf(stderr, "[!] --crypto requires --sec-node-id N (or env CXL_SEC_NODE_ID)\n");
        return -1;
    }

    size_t region_size = env_size("CXL_RING_REGION_SIZE", (size_t)TDX_SHM_DEFAULT_TOTAL_SIZE);
    size_t region_base = env_size("CXL_RING_REGION_BASE", 0);

    const size_t slot_stride = (size_t)TDX_SHM_SLOT_SIZE;
    const size_t need_bytes = align_up((size_t)lo->ring_count * slot_stride, 4096U);
    const size_t def_base = align_up(region_base + (size_t)lo->ring_count * region_size, 4096U);
    const size_t base = env_size("CXL_CRYPTO_PRIV_REGION_BASE", def_base);
    const size_t per_node = env_size("CXL_CRYPTO_PRIV_REGION_SIZE", need_bytes);

    if ((base % 4096) != 0 || (per_node % 4096) != 0) {
        fprintf(stderr, "[!] crypto: CXL_CRYPTO_PRIV_REGION_BASE/SIZE must be 4K-aligned (base=%zu size=%zu)\n",
                base, per_node);
        return -1;
    }
    if (per_node < need_bytes) {
        fprintf(stderr, "[!] crypto: CXL_CRYPTO_PRIV_REGION_SIZE too small (need >= %zu, got %zu)\n",
                need_bytes, per_node);
        return -1;
    }

    uint64_t idx = g_sec_node_id - 1ULL;
    uint64_t off64 = (uint64_t)base + idx * (uint64_t)per_node;
    if (off64 > (uint64_t)map_size || (uint64_t)per_node > (uint64_t)map_size - off64) {
        fprintf(stderr,
                "[!] crypto: private region out of range (map_size=%zu base=%zu node=%" PRIu64 " per_node=%zu)\n",
                map_size, base, g_sec_node_id, per_node);
        return -1;
    }

    g_crypto_priv_region_base = base;
    g_crypto_priv_region_size = per_node;
    g_crypto_priv = mm + (size_t)off64;
    memset(g_crypto_priv, 0, per_node);
    for (uint32_t i = 0; i < lo->ring_count; i++) {
        atomic_store_explicit(&g_crypto_priv_nonce_ctr[i], 0, memory_order_relaxed);
    }
    return 0;
}

static int crypto_priv_encrypt_then_decrypt(uint32_t ring_idx,
                                            unsigned dir,
                                            const unsigned char *payload,
                                            uint32_t payload_len,
                                            unsigned char *out,
                                            uint32_t out_cap,
                                            uint32_t *out_len) {
    if (!out || !out_len || !payload) return -1;
    if (!g_crypto || !g_crypto_priv) return -1;
    if (ring_idx >= MAX_RINGS) return -1;
    if (payload_len > out_cap) return -1;
    const uint32_t nonce_bytes = crypto_stream_chacha20_ietf_NONCEBYTES;
    if ((size_t)payload_len + (size_t)nonce_bytes > (size_t)TDX_SHM_SLOT_SIZE) return -1;

    unsigned char *slot = g_crypto_priv + (size_t)ring_idx * (size_t)TDX_SHM_SLOT_SIZE;
    unsigned char *nonce = slot;
    unsigned char *cipher = slot + nonce_bytes;

    shm_delay();
    memset(nonce, 0, nonce_bytes);
    nonce[0] = (unsigned char)(dir & 0xffu);
    nonce[1] = (unsigned char)(ring_idx & 0xffu);
    uint64_t ctr = atomic_fetch_add_explicit(&g_crypto_priv_nonce_ctr[ring_idx], 1, memory_order_relaxed);
    for (int i = 0; i < 8; i++) {
        nonce[4 + i] = (unsigned char)((ctr >> (8 * i)) & 0xffu);
    }

    memcpy(cipher, payload, payload_len);
    crypto_stream_chacha20_ietf_xor(cipher,
                                    cipher,
                                    (unsigned long long)payload_len,
                                    nonce,
                                    g_crypto_vm_key);

    shm_delay();
    crypto_stream_chacha20_ietf_xor(out,
                                    cipher,
                                    (unsigned long long)payload_len,
                                    nonce,
                                    g_crypto_vm_key);
    *out_len = payload_len;
    return 0;
}

static inline void pause_ns(uint64_t ns) {
    if (!ns) return;
    if (!shm_pause_iters_per_ns_x1024) shm_delay_calibrate();
    uint64_t iters = (ns * shm_pause_iters_per_ns_x1024 + 1023ULL) / 1024ULL;
    if (iters == 0) iters = 1;
    for (uint64_t i = 0; i < iters; i++) {
        __asm__ __volatile__("pause");
    }
}

static inline void bench_sleep_ns(uint64_t ns, struct cost_stats *cs, int collect_cost) {
    if (!ns) return;
    /* Avoid nanosleep() for tiny intervals: on many kernels this rounds up to
     * coarse scheduler ticks (ms) and can dominate tail latency. */
    if (ns <= 100000ULL) {
        pause_ns(ns);
        if (collect_cost && cs) cs->sleep_ns += ns;
        return;
    }
    struct timespec ts;
    ts.tv_sec = (time_t)(ns / 1000000000ULL);
    ts.tv_nsec = (long)(ns % 1000000000ULL);
    nanosleep(&ts, NULL);
    if (collect_cost && cs) cs->sleep_ns += ns;
}

static int parse_size(const char *arg, size_t *out) {
    if (!arg || !out) return -1;
    errno = 0;
    char *end = NULL;
    unsigned long long value = strtoull(arg, &end, 0);
    if (errno != 0) return -1;

    unsigned long long multiplier = 1ULL;
    if (end && *end != '\0') {
        if (end[1] != '\0') return -1;
        switch (*end) {
            case 'K':
            case 'k':
                multiplier = 1024ULL;
                break;
            case 'M':
            case 'm':
                multiplier = 1024ULL * 1024ULL;
                break;
            case 'G':
            case 'g':
                multiplier = 1024ULL * 1024ULL * 1024ULL;
                break;
            default:
                return -1;
        }
    }
    if (multiplier != 0ULL && value > (ULLONG_MAX / multiplier)) return -1;
    unsigned long long bytes = value * multiplier;
    if (bytes > (unsigned long long)SIZE_MAX) return -1;
    *out = (size_t)bytes;
    return 0;
}

static uint32_t env_u32(const char *key, uint32_t def) {
    const char *v = getenv(key);
    if (!v || !v[0]) return def;
    errno = 0;
    unsigned long long x = strtoull(v, NULL, 0);
    if (errno != 0) return def;
    if (x > 0xffffffffULL) return def;
    return (uint32_t)x;
}

static uint64_t env_u64(const char *key, uint64_t def) {
    const char *v = getenv(key);
    if (!v || !v[0]) return def;
    errno = 0;
    unsigned long long x = strtoull(v, NULL, 0);
    if (errno != 0) return def;
    return (uint64_t)x;
}

static size_t env_size(const char *key, size_t def) {
    const char *v = getenv(key);
    if (!v || !v[0]) return def;
    size_t out = 0;
    if (parse_size(v, &out) != 0) return def;
    return out;
}

static int parse_hostport(const char *s, char **host_out, char **port_out) {
    const char *colon = strrchr(s, ':');
    if (!colon || colon == s || *(colon + 1) == '\0') return -1;
    size_t host_len = (size_t)(colon - s);
    char *host = (char *)calloc(host_len + 1, 1);
    char *port = strdup(colon + 1);
    if (!host || !port) {
        free(host);
        free(port);
        return -1;
    }
    memcpy(host, s, host_len);
    host[host_len] = '\0';
    *host_out = host;
    *port_out = port;
    return 0;
}

static ssize_t read_full(int fd, void *buf, size_t n) {
    size_t off = 0;
    while (off < n) {
        ssize_t r = read(fd, (unsigned char *)buf + off, n - off);
        if (r == 0) return (ssize_t)off;
        if (r < 0) {
            if (errno == EINTR) continue;
            return -1;
        }
        off += (size_t)r;
    }
    return (ssize_t)off;
}

static int write_full(int fd, const void *buf, size_t n) {
    size_t off = 0;
    while (off < n) {
        ssize_t w = write(fd, (const unsigned char *)buf + off, n - off);
        if (w < 0) {
            if (errno == EINTR) continue;
            return -1;
        }
        off += (size_t)w;
    }
    return 0;
}

static int socket_connect(const char *host, const char *port) {
    struct addrinfo hints;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;

    struct addrinfo *res = NULL;
    int rc = getaddrinfo(host, port, &hints, &res);
    if (rc != 0) {
        fprintf(stderr, "[!] getaddrinfo(connect %s:%s): %s\n", host, port, gai_strerror(rc));
        return -1;
    }

    int fd = -1;
    for (struct addrinfo *ai = res; ai; ai = ai->ai_next) {
        fd = socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol);
        if (fd < 0) continue;
        if (connect(fd, ai->ai_addr, ai->ai_addrlen) == 0) break;
        close(fd);
        fd = -1;
    }

    freeaddrinfo(res);
    return fd;
}

static void sleep_ms(unsigned ms) {
    struct timespec ts;
    ts.tv_sec = (time_t)(ms / 1000U);
    ts.tv_nsec = (long)(ms % 1000U) * 1000000L;
    while (nanosleep(&ts, &ts) != 0 && errno == EINTR) {
    }
}

static int sec_table_ready(const CxlSecTable *t) {
    if (!t) return 0;
    if (memcmp(t->magic, CXL_SEC_MAGIC, 8) != 0) return 0;
    if (t->version != CXL_SEC_VERSION) return 0;
    if (t->entry_count == 0 || t->entry_count > CXL_SEC_MAX_ENTRIES) return 0;
    return 1;
}

static int sec_table_find(const CxlSecTable *t, uint64_t off, uint64_t len, uint32_t *idx_out) {
    if (!t || !idx_out || !sec_table_ready(t)) return -1;
    if (len == 0) return -1;
    uint64_t end = off + len;
    if (end < off) return -1;
    uint32_t n = t->entry_count;
    if (n > CXL_SEC_MAX_ENTRIES) n = CXL_SEC_MAX_ENTRIES;
    for (uint32_t i = 0; i < n; i++) {
        const CxlSecEntry *e = &t->entries[i];
        if (off >= e->start_off && end <= e->end_off) {
            *idx_out = i;
            return 0;
        }
    }
    return -1;
}

static int sec_entry_has_principal(const CxlSecEntry *e, uint64_t principal) {
    if (!e) return 0;
    uint32_t n = e->principal_count;
    if (n > CXL_SEC_MAX_PRINCIPALS) n = CXL_SEC_MAX_PRINCIPALS;
    for (uint32_t i = 0; i < n; i++) {
        if (e->principals[i] == principal) return 1;
    }
    return 0;
}

static int sec_mgr_request_access(const char *mgr, uint64_t principal, uint64_t off, uint32_t len) {
    char *host = NULL, *port = NULL;
    if (parse_hostport(mgr, &host, &port) != 0) return -1;

    int fd = socket_connect(host, port);
    if (fd < 0) {
        free(host);
        free(port);
        return -1;
    }

    struct sec_req req;
    memset(&req, 0, sizeof(req));
    req.magic_be = htonl(SEC_PROTO_MAGIC);
    req.version_be = htons(SEC_PROTO_VERSION);
    req.type_be = htons(SEC_REQ_ACCESS);
    req.principal_be = htobe64(principal);
    req.offset_be = htobe64(off);
    req.length_be = htonl(len);

    int rc = -1;
    if (write_full(fd, &req, sizeof(req)) != 0) goto out;
    struct sec_resp resp;
    ssize_t r = read_full(fd, &resp, sizeof(resp));
    if (r != (ssize_t)sizeof(resp)) goto out;

    uint32_t magic = ntohl(resp.magic_be);
    uint16_t ver = ntohs(resp.version_be);
    uint16_t status = ntohs(resp.status_be);
    if (magic != SEC_PROTO_MAGIC || ver != SEC_PROTO_VERSION) goto out;
    if (status != SEC_STATUS_OK) goto out;
    rc = 0;
out:
    close(fd);
    free(host);
    free(port);
    return rc;
}

static int secure_init(unsigned char *mm, size_t map_size, const struct layout *lo) {
    if (!g_secure) return 0;
    if (g_sec_node_id == 0) {
        fprintf(stderr, "[!] --secure requires --sec-node-id N\n");
        return -1;
    }
    if (g_sec_stats_enabled) memset(&g_sec_perm, 0, sizeof(g_sec_perm));
    if (sodium_init() < 0) {
        fprintf(stderr, "[!] sodium_init failed\n");
        return -1;
    }

    if (!lo || lo->ring_count == 0 || lo->ring_count > MAX_RINGS) return -1;

    memset(g_sec_key_ok, 0, sizeof(g_sec_key_ok));

    if (g_crypto) {
        if (!g_crypto_key_hex || !g_crypto_key_hex[0]) g_crypto_key_hex = getenv("CXL_SEC_KEY_HEX");
        if (!g_crypto_common_hex || !g_crypto_common_hex[0]) g_crypto_common_hex = getenv("CXL_SEC_COMMON_KEY_HEX");
        if (!g_crypto_key_hex || !g_crypto_key_hex[0] || !g_crypto_common_hex || !g_crypto_common_hex[0]) {
            fprintf(stderr, "[!] --crypto requires CXL_SEC_KEY_HEX and CXL_SEC_COMMON_KEY_HEX (or --sec-key-hex/--sec-common-key-hex)\n");
            return -1;
        }
        if (parse_key_hex(g_crypto_key_hex, g_crypto_vm_key, sizeof(g_crypto_vm_key)) != 0) {
            fprintf(stderr, "[!] invalid CXL_SEC_KEY_HEX (expected %d bytes hex)\n", (int)sizeof(g_crypto_vm_key));
            return -1;
        }
        if (parse_key_hex(g_crypto_common_hex, g_crypto_common_key, sizeof(g_crypto_common_key)) != 0) {
            fprintf(stderr, "[!] invalid CXL_SEC_COMMON_KEY_HEX (expected %d bytes hex)\n", (int)sizeof(g_crypto_common_key));
            return -1;
        }
        for (uint32_t i = 0; i < lo->ring_count; i++) {
            memcpy(g_sec_key[i], g_crypto_common_key, crypto_aead_chacha20poly1305_ietf_KEYBYTES);
            g_sec_key_ok[i] = 1;
            atomic_store_explicit(&g_sec_nonce_ctr_req[i], 0, memory_order_relaxed);
        }
        if (crypto_priv_init(mm, map_size, lo) != 0) return -1;
        return 0;
    }

    if (!g_sec_mgr || !g_sec_mgr[0]) {
        fprintf(stderr, "[!] --secure requires --sec-mgr ip:port\n");
        return -1;
    }

    size_t region_size = env_size("CXL_RING_REGION_SIZE", (size_t)TDX_SHM_DEFAULT_TOTAL_SIZE);
    size_t region_base = env_size("CXL_RING_REGION_BASE", 0);
    if (region_base < 4096) {
        fprintf(stderr, "[!] secure mode requires CXL_RING_REGION_BASE >= 4096 (reserved header page for CXLSEC table)\n");
        return -1;
    }
    if (map_size < CXL_SEC_TABLE_OFF + sizeof(CxlSecTable)) {
        fprintf(stderr, "[!] mapping too small for CXLSEC table\n");
        return -1;
    }

    const CxlSecTable *t = (const CxlSecTable *)(mm + CXL_SEC_TABLE_OFF);
    unsigned waited = 0;
    while (running) {
        if (sec_table_ready(t)) break;
        if (waited >= g_sec_timeout_ms) break;
        uint64_t t0 = 0;
        if (g_sec_stats_enabled) t0 = nowns();
        sleep_ms(10);
        if (g_sec_stats_enabled) g_sec_perm.table_wait_ns += (nowns() - t0);
        waited += 10;
    }
    if (!sec_table_ready(t)) {
        fprintf(stderr, "[!] timeout waiting for CXLSEC table (offset=%u)\n", (unsigned)CXL_SEC_TABLE_OFF);
        return -1;
    }

    for (uint32_t i = 0; i < lo->ring_count; i++) {
        uint64_t off = (uint64_t)region_base + (uint64_t)i * (uint64_t)region_size;
        uint32_t idx = 0;
        if (sec_table_find(t, off, 1, &idx) != 0) {
            fprintf(stderr, "[!] CXLSEC: no entry for ring %u (off=%" PRIu64 ")\n", i, off);
            return -1;
        }

        unsigned waited2 = 0;
        while (running) {
            if (sec_entry_has_principal(&t->entries[idx], g_sec_node_id)) break;
            if (g_sec_stats_enabled) {
                uint64_t m0 = nowns();
                (void)sec_mgr_request_access(g_sec_mgr, g_sec_node_id, off, 1);
                uint64_t m1 = nowns();
                g_sec_perm.mgr_ns += (m1 - m0);
                g_sec_perm.mgr_calls++;
            } else {
                (void)sec_mgr_request_access(g_sec_mgr, g_sec_node_id, off, 1);
            }
            if (waited2 >= g_sec_timeout_ms) break;
            uint64_t s0 = 0;
            if (g_sec_stats_enabled) s0 = nowns();
            sleep_ms(10);
            if (g_sec_stats_enabled) g_sec_perm.principal_sleep_ns += (nowns() - s0);
            waited2 += 10;
        }
        if (!sec_entry_has_principal(&t->entries[idx], g_sec_node_id)) {
            fprintf(stderr, "[!] CXLSEC: principal %" PRIu64 " not granted for ring %u\n", g_sec_node_id, i);
            return -1;
        }

        memcpy(g_sec_key[i], t->entries[idx].key, crypto_aead_chacha20poly1305_ietf_KEYBYTES);
        g_sec_key_ok[i] = 1;
        atomic_store_explicit(&g_sec_nonce_ctr_req[i], 0, memory_order_relaxed);
    }
    return 0;
}

static int secure_encrypt(uint32_t ring_idx,
                          uint32_t cid,
                          uint16_t type,
                          uint16_t flags,
                          uint32_t payload_len,
                          const unsigned char *payload,
                          unsigned dir,
                          unsigned char *out,
                          uint32_t out_cap,
                          uint32_t *out_len) {
    if (!out || !out_len || !payload) return -1;
    if (!g_secure) return -1;
    if (ring_idx >= MAX_RINGS || !g_sec_key_ok[ring_idx]) return -1;
    if (flags & ~RING_FLAG_SECURE) return -1;

    const uint32_t nonce_bytes = crypto_aead_chacha20poly1305_ietf_NPUBBYTES;
    const uint32_t tag_bytes = crypto_aead_chacha20poly1305_ietf_ABYTES;
    if (payload_len > (uint32_t)RING_MAX_PAYLOAD) return -1;
    if (payload_len > (uint32_t)RING_MAX_PAYLOAD - nonce_bytes - tag_bytes) return -1;

    uint32_t clen_total = nonce_bytes + payload_len + tag_bytes;
    if (clen_total > out_cap) return -1;

    struct ring_slot_hdr hdr;
    hdr.cid = cid;
    hdr.type = type;
    hdr.flags = flags;
    hdr.len = clen_total;
    hdr.reserved = 0;

    unsigned char nonce[crypto_aead_chacha20poly1305_ietf_NPUBBYTES];
    memset(nonce, 0, sizeof(nonce));
    nonce[0] = (unsigned char)(dir & 0xffu);
    nonce[1] = (unsigned char)(ring_idx & 0xffu);
    uint64_t ctr = atomic_fetch_add_explicit(&g_sec_nonce_ctr_req[ring_idx], 1, memory_order_relaxed);
    for (int i = 0; i < 8; i++) {
        nonce[4 + i] = (unsigned char)((ctr >> (8 * i)) & 0xffu);
    }

    memcpy(out, nonce, nonce_bytes);
    unsigned long long cbytes = 0;
    if (crypto_aead_chacha20poly1305_ietf_encrypt(out + nonce_bytes,
                                                  &cbytes,
                                                  payload,
                                                  (unsigned long long)payload_len,
                                                  (const unsigned char *)&hdr,
                                                  (unsigned long long)sizeof(hdr),
                                                  NULL,
                                                  nonce,
                                                  g_sec_key[ring_idx]) != 0) {
        return -1;
    }
    if (cbytes != (unsigned long long)(payload_len + tag_bytes)) return -1;
    *out_len = (uint32_t)(nonce_bytes + (uint32_t)cbytes);
    return 0;
}

static int secure_decrypt(uint32_t ring_idx,
                          uint32_t cid,
                          uint16_t type,
                          uint16_t flags,
                          uint32_t payload_len,
                          const unsigned char *payload,
                          unsigned char *out,
                          uint32_t out_cap,
                          uint32_t *out_len) {
    if (!out || !out_len || !payload) return -1;
    if (!g_secure) return -1;
    if (ring_idx >= MAX_RINGS || !g_sec_key_ok[ring_idx]) return -1;

    const uint32_t nonce_bytes = crypto_aead_chacha20poly1305_ietf_NPUBBYTES;
    const uint32_t tag_bytes = crypto_aead_chacha20poly1305_ietf_ABYTES;
    if (payload_len < nonce_bytes + tag_bytes) return -1;
    uint32_t clen = payload_len - nonce_bytes;
    if (clen > (uint32_t)RING_MAX_PAYLOAD) return -1;
    if (clen < tag_bytes) return -1;
    uint32_t pmax = clen - tag_bytes;
    if (pmax > out_cap) return -1;

    struct ring_slot_hdr hdr;
    hdr.cid = cid;
    hdr.type = type;
    hdr.flags = flags;
    hdr.len = payload_len;
    hdr.reserved = 0;

    const unsigned char *nonce = payload;
    const unsigned char *cipher = payload + nonce_bytes;
    unsigned long long pbytes = 0;
    if (crypto_aead_chacha20poly1305_ietf_decrypt(out,
                                                  &pbytes,
                                                  NULL,
                                                  cipher,
                                                  (unsigned long long)clen,
                                                  (const unsigned char *)&hdr,
                                                  (unsigned long long)sizeof(hdr),
                                                  nonce,
                                                  g_sec_key[ring_idx]) != 0) {
        return -1;
    }
    if (pbytes > (unsigned long long)out_cap) return -1;
    *out_len = (uint32_t)pbytes;
    return 0;
}

static int tdx_region_attach(void *base, size_t size, struct tdx_shm_region *out) {
    if (!base || !out) return -1;

    struct tdx_shm_header *hdr = (struct tdx_shm_header *)base;
    if (hdr->magic != TDX_SHM_MAGIC) return -1;
    if (hdr->version != TDX_SHM_VERSION) return -1;
    if (hdr->total_size == 0 || hdr->total_size > (uint64_t)size) return -1;

    if (hdr->q12.slot_size != TDX_SHM_SLOT_SIZE || hdr->q21.slot_size != TDX_SHM_SLOT_SIZE) return -1;
    if (hdr->q12.capacity != TDX_SHM_QUEUE_CAPACITY || hdr->q21.capacity != TDX_SHM_QUEUE_CAPACITY) return -1;

    size_t queue_bytes = (size_t)TDX_SHM_QUEUE_CAPACITY * (size_t)TDX_SHM_SLOT_SIZE;
    if ((size_t)hdr->q12.data_offset + queue_bytes > size) return -1;
    if ((size_t)hdr->q21.data_offset + queue_bytes > size) return -1;

    out->hdr = hdr;
    out->q12.q = &hdr->q12;
    out->q12.data = (uint8_t *)base + hdr->q12.data_offset;
    out->q21.q = &hdr->q21;
    out->q21.data = (uint8_t *)base + hdr->q21.data_offset;
    return 0;
}

static int load_layout(unsigned char *mm, size_t map_size, struct layout *lo) {
    if (!mm || !lo) return -1;

    uint32_t ring_count = env_u32("CXL_RING_COUNT", 1);
    if (ring_count == 0 || ring_count > MAX_RINGS) return -1;

    size_t region_size = env_size("CXL_RING_REGION_SIZE", (size_t)TDX_SHM_DEFAULT_TOTAL_SIZE);
    size_t region_base = env_size("CXL_RING_REGION_BASE", 0);

    if ((region_base % 4096) != 0 || (region_size % 4096) != 0) return -1;
    if (region_size < align_up(sizeof(struct tdx_shm_header), 64U) +
                          2U * (size_t)TDX_SHM_QUEUE_CAPACITY * (size_t)TDX_SHM_SLOT_SIZE) {
        return -1;
    }
    if (region_base > map_size) return -1;
    if ((size_t)ring_count > (map_size - region_base) / region_size) return -1;

    memset(lo, 0, sizeof(*lo));
    lo->ring_count = ring_count;
    for (uint32_t i = 0; i < ring_count; i++) {
        size_t off = region_base + (size_t)i * region_size;
        struct tdx_shm_region region;
        if (tdx_region_attach(mm + off, region_size, &region) != 0) return -1;

        lo->rings[i].req = region.q21;
        lo->rings[i].resp = region.q12;
        lo->rings[i].ring_idx = i;
        lo->rings[i].slots = TDX_SHM_QUEUE_CAPACITY > 0 ? (TDX_SHM_QUEUE_CAPACITY - 1U) : 0U;
    }
    return 0;
}

static uint32_t ring_next(uint32_t v, uint32_t cap) {
    return (v + 1U) % cap;
}

static int ring_push(unsigned char *mm, const struct ring_info *ri, uint32_t cid, uint16_t type, uint16_t flags, const unsigned char *payload, uint32_t len) {
    (void)mm;
    shm_delay();

    if (!ri || !ri->req.q || !ri->req.data || !payload) return -1;
    if (len > RING_MAX_PAYLOAD) return -1;

    struct tdx_shm_queue *q = ri->req.q;
    uint32_t cap = q->capacity;
    uint32_t head = atomic_load_explicit(&q->head, memory_order_acquire);
    uint32_t tail = atomic_load_explicit(&q->tail, memory_order_relaxed);
    uint32_t next = ring_next(tail, cap);
    if (next == head) return 0; /* full */

    uint8_t *slot = ri->req.data + ((size_t)tail * q->slot_size);
    uint16_t msg_len = (uint16_t)(RING_SLOT_HDR_SIZE + len);
    memcpy(slot, &msg_len, sizeof(msg_len));

    struct ring_slot_hdr hdr;
    hdr.cid = cid;
    hdr.type = type;
    hdr.flags = flags;
    hdr.len = len;
    hdr.reserved = 0;
    memcpy(slot + sizeof(msg_len), &hdr, sizeof(hdr));
    if (len) memcpy(slot + sizeof(msg_len) + sizeof(hdr), payload, len);

    atomic_store_explicit(&q->tail, next, memory_order_release);
    return 1;
}

static int ring_pop(unsigned char *mm, const struct ring_info *ri, uint32_t *cid, uint16_t *type, uint16_t *flags, unsigned char **payload, uint32_t *len) {
    (void)mm;
    shm_delay();

    if (!ri || !ri->resp.q || !ri->resp.data || !cid || !type || !flags || !payload || !len) return -1;

    struct tdx_shm_queue *q = ri->resp.q;
    uint32_t cap = q->capacity;
    uint32_t head = atomic_load_explicit(&q->head, memory_order_relaxed);
    uint32_t tail = atomic_load_explicit(&q->tail, memory_order_acquire);
    if (head == tail) return 0; /* empty */

    uint8_t *slot = ri->resp.data + ((size_t)head * q->slot_size);
    uint16_t msg_len = 0;
    memcpy(&msg_len, slot, sizeof(msg_len));
    if (msg_len < sizeof(struct ring_slot_hdr) || msg_len > TDX_SHM_MSG_MAX) return -1;

    struct ring_slot_hdr hdr;
    memcpy(&hdr, slot + sizeof(msg_len), sizeof(hdr));
    if (hdr.len > (uint32_t)(msg_len - sizeof(hdr))) return -1;
    if (hdr.len > RING_MAX_PAYLOAD) return -1;

    *cid = hdr.cid;
    *type = hdr.type;
    *flags = hdr.flags;
    *len = hdr.len;
    *payload = slot + sizeof(msg_len) + sizeof(hdr);

    atomic_store_explicit(&q->head, ring_next(head, cap), memory_order_release);
    return 1;
}

static inline int ring_push_safe(unsigned char *mm, const struct ring_info *ri, uint32_t cid, uint16_t type, uint16_t flags, const unsigned char *payload, uint32_t len) {
    if (!use_lock) return ring_push(mm, ri, cid, type, flags, payload, len);
    int r;
    pthread_mutex_lock(&req_lock);
    r = ring_push(mm, ri, cid, type, flags, payload, len);
    pthread_mutex_unlock(&req_lock);
    return r;
}

static inline int ring_pop_safe(unsigned char *mm, const struct ring_info *ri, uint32_t *cid, uint16_t *type, uint16_t *flags, unsigned char **payload, uint32_t *len) {
    if (!use_lock) return ring_pop(mm, ri, cid, type, flags, payload, len);
    int r;
    pthread_mutex_lock(&resp_lock);
    r = ring_pop(mm, ri, cid, type, flags, payload, len);
    pthread_mutex_unlock(&resp_lock);
    return r;
}

static inline void fill_fixed_key(unsigned char *dst, size_t klen, int idx) {
    if (!dst || klen == 0) return;
    memset(dst, 'k', klen);
    uint32_t v = (uint32_t)idx;
    size_t n = klen < sizeof(v) ? klen : sizeof(v);
    memcpy(dst, &v, n);
}

static inline void fill_fixed_val(unsigned char *dst, size_t vlen, int idx) {
    if (!dst || vlen == 0) return;
    memset(dst, 'v', vlen);
    uint32_t v = (uint32_t)idx;
    size_t n = vlen < sizeof(v) ? vlen : sizeof(v);
    memcpy(dst, &v, n);
}

static int push_set(unsigned char *mm, const struct ring_info *ri, uint32_t cid, int idx) {
    char key_s[32], val_s[32];
    uint8_t klen = 0;
    uint16_t vlen = 0;
    if (g_bench_key_size == 0) {
        snprintf(key_s, sizeof(key_s), "k%d", idx);
        klen = (uint8_t)strlen(key_s);
    } else {
        if (g_bench_key_size > 0xff) return -1;
        klen = (uint8_t)g_bench_key_size;
    }
    if (g_bench_val_size == 0) {
        snprintf(val_s, sizeof(val_s), "v%d", idx);
        vlen = (uint16_t)strlen(val_s);
    } else {
        if (g_bench_val_size > 0xffff) return -1;
        vlen = (uint16_t)g_bench_val_size;
    }

    unsigned char buf[TDX_SHM_SLOT_SIZE];
    size_t need = 4 + klen + vlen;
    if (need > RING_MAX_PAYLOAD) return -1;

    buf[0] = OP_SET;
    buf[1] = klen;
    buf[2] = (uint8_t)(vlen & 0xff);
    buf[3] = (uint8_t)((vlen >> 8) & 0xff);
    if (g_bench_key_size == 0) {
        memcpy(buf + 4, key_s, klen);
    } else {
        fill_fixed_key(buf + 4, klen, idx);
    }
    if (g_bench_val_size == 0) {
        memcpy(buf + 4 + klen, val_s, vlen);
    } else {
        fill_fixed_val(buf + 4 + klen, vlen, idx);
    }
    if (g_secure) {
        unsigned char enc[RING_MAX_PAYLOAD];
        uint32_t enc_len = 0;
        if (!g_crypto) {
            if (secure_encrypt(ri->ring_idx,
                               cid,
                               MSG_DATA,
                               RING_FLAG_SECURE,
                               (uint32_t)need,
                               buf,
                               SEC_DIR_REQ,
                               enc,
                               (uint32_t)sizeof(enc),
                               &enc_len) != 0)
                return -1;
            return ring_push_safe(mm, ri, cid, MSG_DATA, RING_FLAG_SECURE, enc, enc_len);
        }

        const unsigned char *plain = buf;
        uint32_t plain_len = (uint32_t)need;
        unsigned char staged[RING_MAX_PAYLOAD];
        uint32_t staged_len = 0;
        if (use_lock) pthread_mutex_lock(&req_lock);
        if (crypto_priv_encrypt_then_decrypt(ri->ring_idx,
                                             SEC_DIR_REQ,
                                             buf,
                                             (uint32_t)need,
                                             staged,
                                             (uint32_t)sizeof(staged),
                                             &staged_len) != 0) {
            if (use_lock) pthread_mutex_unlock(&req_lock);
            return -1;
        }
        plain = staged;
        plain_len = staged_len;
        int ok = secure_encrypt(ri->ring_idx,
                                cid,
                                MSG_DATA,
                                RING_FLAG_SECURE,
                                plain_len,
                                plain,
                                SEC_DIR_REQ,
                                enc,
                                (uint32_t)sizeof(enc),
                                &enc_len);
        int r = (ok == 0) ? ring_push(mm, ri, cid, MSG_DATA, RING_FLAG_SECURE, enc, enc_len) : -1;
        if (use_lock) pthread_mutex_unlock(&req_lock);
        if (ok != 0) return -1;
        return r;
    }
    return ring_push_safe(mm, ri, cid, MSG_DATA, 0, buf, (uint32_t)need);
}

static int push_get(unsigned char *mm, const struct ring_info *ri, uint32_t cid, int idx) {
    char key_s[32];
    uint8_t klen = 0;
    if (g_bench_key_size == 0) {
        snprintf(key_s, sizeof(key_s), "k%d", idx);
        klen = (uint8_t)strlen(key_s);
    } else {
        if (g_bench_key_size > 0xff) return -1;
        klen = (uint8_t)g_bench_key_size;
    }

    unsigned char buf[TDX_SHM_SLOT_SIZE];
    size_t need = 4 + klen;
    if (need > RING_MAX_PAYLOAD) return -1;

    buf[0] = OP_GET;
    buf[1] = klen;
    buf[2] = 0;
    buf[3] = 0;
    if (g_bench_key_size == 0) {
        memcpy(buf + 4, key_s, klen);
    } else {
        fill_fixed_key(buf + 4, klen, idx);
    }
    if (g_secure) {
        unsigned char enc[RING_MAX_PAYLOAD];
        uint32_t enc_len = 0;
        if (!g_crypto) {
            if (secure_encrypt(ri->ring_idx,
                               cid,
                               MSG_DATA,
                               RING_FLAG_SECURE,
                               (uint32_t)need,
                               buf,
                               SEC_DIR_REQ,
                               enc,
                               (uint32_t)sizeof(enc),
                               &enc_len) != 0)
                return -1;
            return ring_push_safe(mm, ri, cid, MSG_DATA, RING_FLAG_SECURE, enc, enc_len);
        }

        const unsigned char *plain = buf;
        uint32_t plain_len = (uint32_t)need;
        unsigned char staged[RING_MAX_PAYLOAD];
        uint32_t staged_len = 0;
        if (use_lock) pthread_mutex_lock(&req_lock);
        if (crypto_priv_encrypt_then_decrypt(ri->ring_idx,
                                             SEC_DIR_REQ,
                                             buf,
                                             (uint32_t)need,
                                             staged,
                                             (uint32_t)sizeof(staged),
                                             &staged_len) != 0) {
            if (use_lock) pthread_mutex_unlock(&req_lock);
            return -1;
        }
        plain = staged;
        plain_len = staged_len;
        int ok = secure_encrypt(ri->ring_idx,
                                cid,
                                MSG_DATA,
                                RING_FLAG_SECURE,
                                plain_len,
                                plain,
                                SEC_DIR_REQ,
                                enc,
                                (uint32_t)sizeof(enc),
                                &enc_len);
        int r = (ok == 0) ? ring_push(mm, ri, cid, MSG_DATA, RING_FLAG_SECURE, enc, enc_len) : -1;
        if (use_lock) pthread_mutex_unlock(&req_lock);
        if (ok != 0) return -1;
        return r;
    }
    return ring_push_safe(mm, ri, cid, MSG_DATA, 0, buf, (uint32_t)need);
}

/* Delete a key (DEL). Returns >0 on push, 0 if full, <0 on error. */
static int __attribute__((unused)) push_del(unsigned char *mm, const struct ring_info *ri, uint32_t cid, int idx) {
    char key[32];
    snprintf(key, sizeof(key), "k%d", idx);
    uint8_t klen = (uint8_t)strlen(key);

    unsigned char buf[TDX_SHM_SLOT_SIZE];
    size_t need = 4 + klen;
    if (need > RING_MAX_PAYLOAD) return -1;

    buf[0] = OP_DEL;
    buf[1] = klen;
    buf[2] = 0;
    buf[3] = 0;
    memcpy(buf + 4, key, klen);
    if (g_secure) {
        unsigned char enc[RING_MAX_PAYLOAD];
        uint32_t enc_len = 0;
        if (secure_encrypt(ri->ring_idx,
                           cid,
                           MSG_DATA,
                           RING_FLAG_SECURE,
                           (uint32_t)need,
                           buf,
                           SEC_DIR_REQ,
                           enc,
                           (uint32_t)sizeof(enc),
                           &enc_len) != 0)
            return -1;
        return ring_push_safe(mm, ri, cid, MSG_DATA, RING_FLAG_SECURE, enc, enc_len);
    }
    return ring_push_safe(mm, ri, cid, MSG_DATA, 0, buf, (uint32_t)need);
}

/* SCAN request: pattern (key) + extras (val) with [u64 cursor][u16 count] */
static int __attribute__((unused)) push_scan(unsigned char *mm, const struct ring_info *ri, uint32_t cid, const char *pattern, uint64_t cursor, uint16_t count) {
    uint8_t klen = pattern ? (uint8_t)strlen(pattern) : 0;
    unsigned char buf[TDX_SHM_SLOT_SIZE];
    size_t need = 4 + klen + 10;
    if (need > RING_MAX_PAYLOAD) return -1;

    buf[0] = OP_SCAN;
    buf[1] = klen;
    buf[2] = 10; /* val length LE */
    buf[3] = 0;
    if (klen) memcpy(buf + 4, pattern, klen);
    unsigned char *p = buf + 4 + klen;
    p[0] = (uint8_t)(cursor & 0xff);
    p[1] = (uint8_t)((cursor >> 8) & 0xff);
    p[2] = (uint8_t)((cursor >> 16) & 0xff);
    p[3] = (uint8_t)((cursor >> 24) & 0xff);
    p[4] = (uint8_t)((cursor >> 32) & 0xff);
    p[5] = (uint8_t)((cursor >> 40) & 0xff);
    p[6] = (uint8_t)((cursor >> 48) & 0xff);
    p[7] = (uint8_t)((cursor >> 56) & 0xff);
    p[8] = (uint8_t)(count & 0xff);
    p[9] = (uint8_t)((count >> 8) & 0xff);

    if (g_secure) {
        unsigned char enc[RING_MAX_PAYLOAD];
        uint32_t enc_len = 0;
        if (secure_encrypt(ri->ring_idx,
                           cid,
                           MSG_DATA,
                           RING_FLAG_SECURE,
                           (uint32_t)need,
                           buf,
                           SEC_DIR_REQ,
                           enc,
                           (uint32_t)sizeof(enc),
                           &enc_len) != 0)
            return -1;
        return ring_push_safe(mm, ri, cid, MSG_DATA, RING_FLAG_SECURE, enc, enc_len);
    }
    return ring_push_safe(mm, ri, cid, MSG_DATA, 0, buf, (uint32_t)need);
}

static int tsq_init(struct ts_queue *q, int cap) {
    if (!q || cap <= 0) return -1;
    q->buf = (uint64_t *)calloc((size_t)cap, sizeof(uint64_t));
    if (!q->buf) return -1;
    q->cap = cap;
    q->head = q->tail = 0;
    return 0;
}

static void tsq_free(struct ts_queue *q) {
    if (!q) return;
    free(q->buf);
    q->buf = NULL;
    q->cap = q->head = q->tail = 0;
}

static int tsq_push(struct ts_queue *q, uint64_t v) {
    int next = (q->tail + 1) % q->cap;
    if (next == q->head) return -1;
    q->buf[q->tail] = v;
    q->tail = next;
    return 0;
}

static int tsq_pop(struct ts_queue *q, uint64_t *out) {
    if (q->head == q->tail) return -1;
    *out = q->buf[q->head];
    q->head = (q->head + 1) % q->cap;
    return 0;
}

static void lat_init(struct latency_stats *ls, int cap) {
    ls->samples = (double *)malloc(sizeof(double) * (size_t)cap);
    ls->cap = cap;
    ls->count = 0;
    ls->sum = 0.0;
}

static void lat_record(struct latency_stats *ls, double us) {
    if (ls->count < ls->cap) {
        ls->samples[ls->count++] = us;
        ls->sum += us;
    }
}

static int cmp_double(const void *a, const void *b) {
    double x = *(const double *)a;
    double y = *(const double *)b;
    return (x > y) - (x < y);
}

static double percentile(double *a, int n, double p) {
    if (!a || n <= 0) return 0.0;
    double idx = p * (n - 1);
    int i = (int)idx;
    int j = i + 1;
    if (j >= n) return a[n - 1];
    double frac = idx - i;
    return a[i] * (1.0 - frac) + a[j] * frac;
}

static void compute_agg_latency(struct latency_stats *ls, struct agg_latency *out) {
    if (!ls || !out || ls->count <= 0) {
        memset(out, 0, sizeof(*out));
        return;
    }
    qsort(ls->samples, (size_t)ls->count, sizeof(double), cmp_double);
    out->count = ls->count;
    out->avg = ls->sum / (double)ls->count;
    out->p50 = percentile(ls->samples, ls->count, 0.50);
    out->p75 = percentile(ls->samples, ls->count, 0.75);
    out->p90 = percentile(ls->samples, ls->count, 0.90);
    out->p99 = percentile(ls->samples, ls->count, 0.99);
    out->p999 = percentile(ls->samples, ls->count, 0.999);
    out->p9999 = percentile(ls->samples, ls->count, 0.9999);
}

static void stage_init(struct stage_ctx *stage, int collect_latency, int collect_cost, int cap) {
    memset(stage, 0, sizeof(*stage));
    stage->collect_latency = collect_latency;
    stage->collect_cost = collect_cost;
    tsq_init(&stage->q, cap);
    if (collect_latency) lat_init(&stage->ls, cap);
}

static void stage_free(struct stage_ctx *stage) {
    tsq_free(&stage->q);
    /* NOTE: latency samples ownership is moved into bench_result; don't free here. */
}

static int drain_one(unsigned char *mm, const struct ring_info *ri, struct stage_ctx *stage) {
    uint32_t cid, rlen;
    uint16_t type;
    uint16_t flags;
    unsigned char *pl;
    int r = ring_pop_safe(mm, ri, &cid, &type, &flags, &pl, &rlen);
    if (r == 0) return 0;
    if (r < 0) return -1;
    unsigned char dec[RING_MAX_PAYLOAD];
    if ((flags & RING_FLAG_SECURE) != 0) {
        uint32_t dec_len = 0;
        if (secure_decrypt(ri->ring_idx, cid, type, flags, rlen, pl, dec, (uint32_t)sizeof(dec), &dec_len) != 0) {
            return -1;
        }
        pl = dec;
        rlen = dec_len;
    }
    if (type != MSG_DATA || rlen < 3) return 1;
    if (stage && stage->collect_latency) {
        uint64_t t0 = 0;
        if (tsq_pop(&stage->q, &t0) == 0) {
            uint64_t now = nowns();
            double us = (double)(now - t0) / 1000.0;
            lat_record(&stage->ls, us);
        }
    }
    return 1;
}

static void drain_many(unsigned char *mm, const struct ring_info *ri, int *outstanding, int target, struct stage_ctx *stage) {
    while (*outstanding > target && running) {
        int r = drain_one(mm, ri, stage);
        if (r > 0) {
            (*outstanding)--;
        } else if (r < 0) {
            fprintf(stderr, "[!] ring_pop error while draining responses\n");
            running = 0;
            return;
        } else {
            pause_ns(poll_spin_ns);
            int r2 = drain_one(mm, ri, stage);
            if (r2 > 0) {
                (*outstanding)--;
            } else if (r2 < 0) {
                fprintf(stderr, "[!] ring_pop error while draining responses\n");
                running = 0;
                return;
            } else {
                bench_sleep_ns(poll_sleep_ns, stage ? &stage->cs : NULL, stage && stage->collect_cost);
            }
        }
    }
}

static void run_bench_internal(unsigned char *mm, const struct ring_info *ri, int n, int pipeline, int quiet, int tid, struct bench_result *out, int max_inflight, int collect_latency, int collect_cost) {
    struct timespec ts1, ts2, ts3;
    uint32_t cid_set = (uint32_t)(tid * 2 + 1);
    uint32_t cid_get = cid_set + 1;
    int inflight = 0;
    if (max_inflight <= 0) max_inflight = (int)(ri->slots / 4);
    if (max_inflight < 1) max_inflight = 1;

    struct stage_ctx set_stage, get_stage;
    stage_init(&set_stage, collect_latency, collect_cost, n + max_inflight + 64);
    stage_init(&get_stage, collect_latency, collect_cost, n + max_inflight + 64);

    clock_gettime(CLOCK_MONOTONIC, &ts1);
    if (!quiet) fprintf(stderr, "[bench tid=%d] pushing %d SET (pipeline=%d)\n", tid, n, pipeline);
    for (int i = 0; i < n; i++) {
        if (!running) break;
        if (pipeline) drain_many(mm, ri, &inflight, max_inflight, &set_stage);
        int pushed = 0;
        while (running) {
            int pr = push_set(mm, ri, cid_set, i);
            if (pr > 0) {
                pushed = 1;
                break;
            }
            if (pr < 0) {
                fprintf(stderr, "[!] push_set failed (ring write error)\n");
                running = 0;
                break;
            }
            pause_ns(poll_spin_ns);
            pr = push_set(mm, ri, cid_set, i);
            if (pr > 0) {
                pushed = 1;
                break;
            }
            if (pr < 0) {
                fprintf(stderr, "[!] push_set failed (ring write error)\n");
                running = 0;
                break;
            }
            bench_sleep_ns(poll_sleep_ns, &set_stage.cs, collect_cost);
            set_stage.cs.push_retries++;
        }
        if (!running || !pushed) break;
        if (collect_latency) tsq_push(&set_stage.q, nowns());
        if (pipeline) inflight++;
        if (!pipeline) {
            while (running) {
                int dr = drain_one(mm, ri, &set_stage);
                if (dr > 0) break;
                if (dr < 0) {
                    fprintf(stderr, "[!] ring_pop failed while waiting for SET response\n");
                    running = 0;
                    break;
                }
                pause_ns(poll_spin_ns);
                dr = drain_one(mm, ri, &set_stage);
                if (dr > 0) break;
                if (dr < 0) {
                    fprintf(stderr, "[!] ring_pop failed while waiting for SET response\n");
                    running = 0;
                    break;
                }
                bench_sleep_ns(poll_sleep_ns, &set_stage.cs, collect_cost);
            }
        }
    }
    if (pipeline) drain_many(mm, ri, &inflight, 0, &set_stage);
    clock_gettime(CLOCK_MONOTONIC, &ts2);

    if (!quiet) fprintf(stderr, "[bench tid=%d] pushing %d GET\n", tid, n);
    for (int i = 0; i < n; i++) {
        if (!running) break;
        if (pipeline) drain_many(mm, ri, &inflight, max_inflight, &get_stage);
        int pushed = 0;
        while (running) {
            int pr = push_get(mm, ri, cid_get, i);
            if (pr > 0) {
                pushed = 1;
                break;
            }
            if (pr < 0) {
                fprintf(stderr, "[!] push_get failed (ring write error)\n");
                running = 0;
                break;
            }
            pause_ns(poll_spin_ns);
            pr = push_get(mm, ri, cid_get, i);
            if (pr > 0) {
                pushed = 1;
                break;
            }
            if (pr < 0) {
                fprintf(stderr, "[!] push_get failed (ring write error)\n");
                running = 0;
                break;
            }
            bench_sleep_ns(poll_sleep_ns, &get_stage.cs, collect_cost);
            get_stage.cs.push_retries++;
        }
        if (!running || !pushed) break;
        if (collect_latency) tsq_push(&get_stage.q, nowns());
        if (pipeline) inflight++;
        if (!pipeline) {
            while (running) {
                int dr = drain_one(mm, ri, &get_stage);
                if (dr > 0) break;
                if (dr < 0) {
                    fprintf(stderr, "[!] ring_pop failed while waiting for GET response\n");
                    running = 0;
                    break;
                }
                pause_ns(poll_spin_ns);
                dr = drain_one(mm, ri, &get_stage);
                if (dr > 0) break;
                if (dr < 0) {
                    fprintf(stderr, "[!] ring_pop failed while waiting for GET response\n");
                    running = 0;
                    break;
                }
                bench_sleep_ns(poll_sleep_ns, &get_stage.cs, collect_cost);
            }
        }
    }
    if (pipeline) drain_many(mm, ri, &inflight, 0, &get_stage);
    clock_gettime(CLOCK_MONOTONIC, &ts3);

    double set_sec = (ts2.tv_sec - ts1.tv_sec) + (ts2.tv_nsec - ts1.tv_nsec) / 1e9;
    double get_sec = (ts3.tv_sec - ts2.tv_sec) + (ts3.tv_nsec - ts2.tv_nsec) / 1e9;
    if (out) {
        out->set_sec = set_sec;
        out->get_sec = get_sec;
        out->n = n;
        out->tid = tid;
        out->set_lat = set_stage.ls;
        out->get_lat = get_stage.ls;
        out->set_cost = set_stage.cs;
        out->get_cost = get_stage.cs;
    }
    if (!quiet) {
        printf("tid=%d SET: %.2f req/s\n", tid, n / set_sec);
        printf("tid=%d GET: %.2f req/s\n", tid, n / get_sec);
    }
    stage_free(&set_stage);
    stage_free(&get_stage);
}

struct thread_arg {
    unsigned char *mm;
    const struct ring_info *ri;
    int n;
    int pipeline;
    int tid;
    struct bench_result *res;
    int max_inflight;
    int collect_latency;
    int collect_cost;
};

static void *bench_thread(void *p) {
    struct thread_arg *a = (struct thread_arg *)p;
    run_bench_internal(a->mm, a->ri, a->n, a->pipeline, 1, a->tid, a->res, a->max_inflight, a->collect_latency, a->collect_cost);
    return NULL;
}

static void free_thread_results(struct bench_result *res, int threads) {
    if (!res) return;
    for (int i = 0; i < threads; i++) {
        free(res[i].set_lat.samples);
        free(res[i].get_lat.samples);
    }
}

static void aggregate_latency_stats(struct latency_stats *dst, struct bench_result *res, int threads, int is_get) {
    int total = 0;
    for (int i = 0; i < threads; i++) {
        total += is_get ? res[i].get_lat.count : res[i].set_lat.count;
    }
    if (total == 0) {
        dst->samples = NULL;
        dst->cap = dst->count = 0;
        dst->sum = 0.0;
        return;
    }
    dst->samples = (double *)malloc(sizeof(double) * (size_t)total);
    dst->cap = total;
    dst->count = total;
    dst->sum = 0.0;
    int off = 0;
    for (int i = 0; i < threads; i++) {
        struct latency_stats *src = is_get ? &res[i].get_lat : &res[i].set_lat;
        if (src->count == 0) continue;
        memcpy(dst->samples + off, src->samples, sizeof(double) * (size_t)src->count);
        off += src->count;
        dst->sum += src->sum;
    }
    dst->count = off;
}

static void aggregate_cost(struct cost_stats *dst, struct bench_result *res, int threads, int is_get) {
    memset(dst, 0, sizeof(*dst));
    for (int i = 0; i < threads; i++) {
        struct cost_stats *src = is_get ? &res[i].get_cost : &res[i].set_cost;
        dst->push_retries += src->push_retries;
        dst->sleep_ns += src->sleep_ns;
    }
}

static int ensure_dir(const char *path) {
    struct stat st;
    if (stat(path, &st) == 0) {
        if (S_ISDIR(st.st_mode)) return 0;
        return -1;
    }
    if (mkdir(path, 0755) == 0) return 0;
    return -1;
}

static int file_exists(const char *path) {
    struct stat st;
    return stat(path, &st) == 0;
}

static void write_csv_row(FILE *f, const char *label, const char *op, int threads, int rings, int n, int pipeline, int max_inflight, double rps, struct agg_latency *lat, struct cost_stats *cs) {
    fprintf(f, "%s,%s,%d,%d,%d,%d,%d,%.0f,%.3f,%.3f,%.3f,%.3f,%.3f,%.3f,%.3f,%" PRIu64 ",%.3f\n",
            label, op, threads, rings, n, pipeline, max_inflight, rps,
            lat ? lat->avg : 0.0,
            lat ? lat->p50 : 0.0,
            lat ? lat->p75 : 0.0,
            lat ? lat->p90 : 0.0,
            lat ? lat->p99 : 0.0,
            lat ? lat->p999 : 0.0,
            lat ? lat->p9999 : 0.0,
            (uint64_t)(cs ? cs->push_retries : 0),
            cs ? (double)cs->sleep_ns / 1e6 : 0.0);
}

static void run_bench(unsigned char *mm, struct layout *lo, int n, int pipeline, int threads, int max_inflight, int collect_latency, int collect_cost, const char *csv_path, const char *label) {
    int ring_count = lo->ring_count ? (int)lo->ring_count : 1;
    if (threads < 1) threads = 1;
    if (ring_count < threads) use_lock = 1;
    if (collect_latency && use_lock) {
        fprintf(stderr, "warn: latency collection disabled because threads share a ring (lock path)\n");
        collect_latency = 0;
    }

    pthread_t *ths = calloc((size_t)threads, sizeof(pthread_t));
    struct bench_result *res = calloc((size_t)threads, sizeof(struct bench_result));
    struct thread_arg *args = calloc((size_t)threads, sizeof(struct thread_arg));
    if (!ths || !res || !args) {
        fprintf(stderr, "[!] alloc failed\n");
        free(ths);
        free(res);
        free(args);
        return;
    }

    for (int i = 0; i < threads; i++) {
        int ring_idx = i % ring_count;
        args[i].mm = mm;
        args[i].ri = &lo->rings[ring_idx];
        args[i].n = n;
        args[i].pipeline = pipeline;
        args[i].tid = i;
        args[i].res = &res[i];
        args[i].max_inflight = max_inflight;
        args[i].collect_latency = collect_latency;
        args[i].collect_cost = collect_cost;
        int rc = pthread_create(&ths[i], NULL, bench_thread, &args[i]);
        if (rc != 0) fprintf(stderr, "warn: create thread %d failed (%d)\n", i, rc);
    }
    for (int i = 0; i < threads; i++) {
        if (ths[i]) pthread_join(ths[i], NULL);
    }

    double max_set = 0.0, max_get = 0.0;
    for (int i = 0; i < threads; i++) {
        if (res[i].set_sec > max_set) max_set = res[i].set_sec;
        if (res[i].get_sec > max_get) max_get = res[i].get_sec;
    }
    double set_rps = (max_set > 0) ? ((double)threads * n) / max_set : 0.0;
    double get_rps = (max_get > 0) ? ((double)threads * n) / max_get : 0.0;
    printf("[threads=%d rings=%d] SET: %.2f req/s\n", threads, ring_count, set_rps);
    printf("[threads=%d rings=%d] GET: %.2f req/s\n", threads, ring_count, get_rps);

    struct agg_latency set_lat_agg = {0}, get_lat_agg = {0};
    struct latency_stats set_lat = {0}, get_lat = {0};
    struct cost_stats set_cost = {0}, get_cost = {0};
    if (collect_latency) {
        aggregate_latency_stats(&set_lat, res, threads, 0);
        aggregate_latency_stats(&get_lat, res, threads, 1);
        compute_agg_latency(&set_lat, &set_lat_agg);
        compute_agg_latency(&get_lat, &get_lat_agg);
    }
    if (collect_cost) {
        aggregate_cost(&set_cost, res, threads, 0);
        aggregate_cost(&get_cost, res, threads, 1);
    }

    if (csv_path) {
        if (ensure_dir("results") != 0) {
            fprintf(stderr, "warn: cannot create results/ directory for csv\n");
        } else {
            int new_file = !file_exists(csv_path);
            FILE *f = fopen(csv_path, "a");
            if (!f) {
                perror("fopen csv");
            } else {
                if (new_file) {
                    fprintf(f, "label,op,threads,rings,requests,pipeline,max_inflight,throughput_rps,avg_us,p50_us,p75_us,p90_us,p99_us,p99.9_us,p99.99_us,push_retries,sleep_ms\n");
                }
                write_csv_row(f, label, "SET", threads, ring_count, n, pipeline, max_inflight, set_rps, collect_latency ? &set_lat_agg : NULL, collect_cost ? &set_cost : NULL);
                write_csv_row(f, label, "GET", threads, ring_count, n, pipeline, max_inflight, get_rps, collect_latency ? &get_lat_agg : NULL, collect_cost ? &get_cost : NULL);
                fclose(f);
                printf("[+] CSV appended to %s\n", csv_path);
            }
        }
    }

    free(set_lat.samples);
    free(get_lat.samples);
    free_thread_results(res, threads);
    free(ths);
    free(res);
    free(args);
}

int main(int argc, char **argv) {
    const char *path = "/sys/bus/pci/devices/0000:00:02.0/resource2";
    size_t map_size = 1024ULL * 1024 * 1024;
    size_t map_offset = 0;
    int bench_n = 0;
    int pipeline = 0;
    int threads = 1;
    int ring_idx = 0;
    int max_inflight = 0;
    int collect_latency = 0;
    int collect_cost = 0;
    const char *csv_path = "results/ring_metrics.csv";
    const char *label = "ring";
    unsigned ping_timeout_ms = 0;

    const char *delay_env = getenv("CXL_SHM_DELAY_NS");
    if (delay_env && delay_env[0]) {
        errno = 0;
        unsigned long long v = strtoull(delay_env, NULL, 0);
        if (errno == 0) shm_delay_ns = (uint64_t)v;
    }
    poll_spin_ns = env_u64("CXL_RING_POLL_SPIN_NS", poll_spin_ns);
    poll_sleep_ns = env_u64("CXL_RING_POLL_SLEEP_NS", poll_sleep_ns);
    const char *offset_env = getenv("CXL_RING_OFFSET");
    if (!offset_env || !offset_env[0]) offset_env = getenv("CXL_SHM_OFFSET");
    if (offset_env && offset_env[0]) {
        size_t v = 0;
        if (parse_size(offset_env, &v) == 0 && v > 0) map_offset = v;
    }

    for (int i = 1; i < argc; i++) {
        if (!strcmp(argv[i], "--path") && i + 1 < argc) path = argv[++i];
        else if (!strcmp(argv[i], "--map-size") && i + 1 < argc) {
            size_t v = 0;
            if (parse_size(argv[++i], &v) != 0) {
                fprintf(stderr, "[!] Invalid --map-size\n");
                return 2;
            }
            map_size = v;
        }
        else if (!strcmp(argv[i], "--key-size") && i + 1 < argc) {
            size_t v = 0;
            if (parse_size(argv[++i], &v) != 0) {
                fprintf(stderr, "[!] Invalid --key-size\n");
                return 2;
            }
            g_bench_key_size = v;
        }
        else if (!strcmp(argv[i], "--val-size") && i + 1 < argc) {
            size_t v = 0;
            if (parse_size(argv[++i], &v) != 0) {
                fprintf(stderr, "[!] Invalid --val-size\n");
                return 2;
            }
            g_bench_val_size = v;
        }
        else if (!strcmp(argv[i], "--bench") && i + 1 < argc) bench_n = atoi(argv[++i]);
        else if (!strcmp(argv[i], "--map-offset") && i + 1 < argc) {
            size_t v = 0;
            if (parse_size(argv[++i], &v) != 0) {
                fprintf(stderr, "[!] Invalid --map-offset\n");
                return 2;
            }
            map_offset = v;
        }
        else if (!strcmp(argv[i], "--pipeline")) pipeline = 1;
        else if (!strcmp(argv[i], "--threads") && i + 1 < argc) threads = atoi(argv[++i]);
        else if (!strcmp(argv[i], "--ring") && i + 1 < argc) ring_idx = atoi(argv[++i]);
        else if (!strcmp(argv[i], "--max-inflight") && i + 1 < argc) max_inflight = atoi(argv[++i]);
        else if (!strcmp(argv[i], "--latency")) collect_latency = 1;
        else if (!strcmp(argv[i], "--cost")) collect_cost = 1;
        else if (!strcmp(argv[i], "--csv") && i + 1 < argc) csv_path = argv[++i];
        else if (!strcmp(argv[i], "--label") && i + 1 < argc) label = argv[++i];
        else if (!strcmp(argv[i], "--secure")) {
            g_secure = 1;
        } else if (!strcmp(argv[i], "--crypto")) {
            g_secure = 1;
            g_crypto = 1;
        } else if (!strcmp(argv[i], "--sec-mgr") && i + 1 < argc) {
            g_sec_mgr = argv[++i];
        } else if (!strcmp(argv[i], "--sec-node-id") && i + 1 < argc) {
            g_sec_node_id = strtoull(argv[++i], NULL, 0);
        } else if (!strcmp(argv[i], "--sec-timeout-ms") && i + 1 < argc) {
            g_sec_timeout_ms = (unsigned)strtoul(argv[++i], NULL, 0);
        } else if (!strcmp(argv[i], "--sec-key-hex") && i + 1 < argc) {
            g_crypto_key_hex = argv[++i];
        } else if (!strcmp(argv[i], "--sec-common-key-hex") && i + 1 < argc) {
            g_crypto_common_hex = argv[++i];
        } else if (!strcmp(argv[i], "--ping-timeout-ms") && i + 1 < argc) ping_timeout_ms = (unsigned)strtoul(argv[++i], NULL, 0);
        else if (!strcmp(argv[i], "-h") || !strcmp(argv[i], "--help")) {
            printf("Usage: %s [--path <bar2|uio>] [--map-size <bytes>] [--map-offset <bytes>] [--bench N] [--pipeline] [--threads N]\n"
                   "          [--key-size <bytes>] [--val-size <bytes>]\n"
                   "          [--max-inflight N] [--latency] [--cost] [--csv <path>] [--label <name>]\n"
                   "          [--secure --sec-mgr <ip:port> --sec-node-id N [--sec-timeout-ms MS]]\n"
                   "          [--crypto --sec-node-id N [--sec-key-hex HEX] [--sec-common-key-hex HEX]]\n"
                   "          [--ping-timeout-ms <ms>] (ping mode only; 0=wait forever)\n"
                   "Env:\n"
                   "  CXL_RING_COUNT        : number of rings/regions (default: 1)\n"
                   "  CXL_RING_REGION_SIZE  : bytes per ring region (default: 16M)\n"
                   "  CXL_RING_REGION_BASE  : base offset within the mmap (default: 0)\n"
                   "  (bench) --key-size/--val-size accept optional K/M/G suffix.\n"
                   "  CXL_SEC_KEY_HEX       : (crypto) per-node key (32B hex)\n"
                   "  CXL_SEC_COMMON_KEY_HEX: (crypto) common key (32B hex)\n"
                   "  CXL_CRYPTO_PRIV_REGION_BASE: (crypto) private staging base offset (default: after rings)\n"
                   "  CXL_CRYPTO_PRIV_REGION_SIZE: (crypto) per-node private staging size (default: ring_count*4KiB)\n"
                   "  CXL_RING_POLL_SPIN_NS : spin-wait before sleeping when empty/full (default: 5000)\n"
                   "  CXL_RING_POLL_SLEEP_NS: nanosleep after spinning when empty/full (default: 50000)\n",
                   argv[0]);
            return 0;
        }
    }

    if (g_bench_key_size > 0 && g_bench_key_size > 0xff) {
        fprintf(stderr, "[!] --key-size too large (max 255)\n");
        return 2;
    }
    if (g_bench_val_size > 0 && g_bench_val_size > 0xffff) {
        fprintf(stderr, "[!] --val-size too large (max 65535)\n");
        return 2;
    }
    {
        int max_idx = 0;
        if (bench_n > 0) max_idx = bench_n - 1;
        char key_s[32], val_s[32];
        snprintf(key_s, sizeof(key_s), "k%d", max_idx);
        snprintf(val_s, sizeof(val_s), "v%d", max_idx);
        size_t kmax = (g_bench_key_size > 0) ? g_bench_key_size : strlen(key_s);
        size_t vmax = (g_bench_val_size > 0) ? g_bench_val_size : strlen(val_s);
        if (4 + kmax > (size_t)RING_MAX_PAYLOAD) {
            fprintf(stderr, "[!] key size too large for ring payload: need=%zu max=%u\n", 4 + kmax, RING_MAX_PAYLOAD);
            return 2;
        }
        if (bench_n > 0 && 4 + kmax + vmax > (size_t)RING_MAX_PAYLOAD) {
            fprintf(stderr, "[!] key+value too large for ring payload: need=%zu max=%u\n", 4 + kmax + vmax, RING_MAX_PAYLOAD);
            return 2;
        }
    }

    if (g_secure) {
        if (!g_sec_mgr || !g_sec_mgr[0]) g_sec_mgr = getenv("CXL_SEC_MGR");
        if (g_sec_node_id == 0) {
            const char *id_env = getenv("CXL_SEC_NODE_ID");
            if (id_env && id_env[0]) g_sec_node_id = strtoull(id_env, NULL, 0);
        }
    }

    g_sec_stats_out = getenv("CXL_SEC_STATS_OUT");
    if (g_sec_stats_out && g_sec_stats_out[0]) g_sec_stats_enabled = 1;

    signal(SIGINT, handle_sig);
    signal(SIGTERM, handle_sig);

    long page = sysconf(_SC_PAGESIZE);
    if (page > 0 && (map_offset % (size_t)page) != 0) {
        fprintf(stderr, "[!] map offset %zu is not page-aligned\n", map_offset);
        return 1;
    }

    int fd = open(path, O_RDWR);
    if (fd < 0) {
        perror("open");
        return 1;
    }
    struct stat st;
    if (fstat(fd, &st) == 0 && S_ISREG(st.st_mode)) {
        if ((size_t)st.st_size <= map_offset) {
            fprintf(stderr, "[!] map offset %zu exceeds file size %zu\n", map_offset, (size_t)st.st_size);
            close(fd);
            return 1;
        }
        if (map_size > (size_t)st.st_size - map_offset) {
            map_size = (size_t)st.st_size - map_offset;
        }
    }
    if (map_size == 0) {
        fprintf(stderr, "[!] map size is zero after clamping\n");
        close(fd);
        return 1;
    }

    unsigned char *mm = mmap(NULL, map_size, PROT_READ | PROT_WRITE, MAP_SHARED, fd, (off_t)map_offset);
    if (mm == MAP_FAILED) {
        perror("mmap");
        close(fd);
        return 1;
    }

    struct layout lo;
    if (load_layout(mm, map_size, &lo) != 0) {
        fprintf(stderr, "[!] TDX SHM layout not ready.\n");
        fprintf(stderr, "    Start ring-enabled redis-server first, and ensure CXL_RING_COUNT/REGION_SIZE match.\n");
        munmap(mm, map_size);
        close(fd);
        return 1;
    }

    const char *sec_to_env = getenv("CXL_SEC_TIMEOUT_MS");
    if (sec_to_env && sec_to_env[0]) {
        g_sec_timeout_ms = (unsigned)strtoul(sec_to_env, NULL, 0);
    }
    if (secure_init(mm, map_size, &lo) != 0) {
        munmap(mm, map_size);
        close(fd);
        return 1;
    }

    if (ring_idx < 0 || ring_idx >= (int)lo.ring_count) ring_idx = 0;
    size_t region_size = env_size("CXL_RING_REGION_SIZE", (size_t)TDX_SHM_DEFAULT_TOTAL_SIZE);
    size_t region_base = env_size("CXL_RING_REGION_BASE", 0);

    printf("[*] tdx shm ring direct: path=%s map=%zu offset=%zu ring_count=%u region_base=%zu region_size=%zu slots=%u shm_delay_ns=%" PRIu64 " poll_spin_ns=%" PRIu64 " poll_sleep_ns=%" PRIu64 " crypto=%d priv_base=%zu priv_size=%zu\n",
           path, map_size, map_offset, lo.ring_count, region_base, region_size, lo.rings[ring_idx].slots, shm_delay_ns, poll_spin_ns, poll_sleep_ns,
           g_crypto, g_crypto_priv_region_base, g_crypto_priv_region_size);

    if (bench_n > 0) {
        run_bench(mm, &lo, bench_n, pipeline, threads, max_inflight, collect_latency, collect_cost, csv_path, label);
    } else {
        uint64_t start_ns = nowns();
        int pushed = 0;
        int ok = 0;
        while (running) {
            if (!pushed) {
                int pr = push_get(mm, &lo.rings[ring_idx], 99, 0);
                if (pr > 0) {
                    pushed = 1;
                } else if (pr < 0) {
                    fprintf(stderr, "[!] push_get failed (ring write error)\n");
                    break;
                }
            }

            if (pushed) {
                int dr = drain_one(mm, &lo.rings[ring_idx], NULL);
                if (dr > 0) {
                    ok = 1;
                    break;
                }
                if (dr < 0) {
                    fprintf(stderr, "[!] ring_pop failed while waiting for ping response\n");
                    break;
                }
            }

            if (ping_timeout_ms > 0) {
                uint64_t now_ns = nowns();
                uint64_t waited_ms = (now_ns - start_ns) / 1000000ULL;
                if (waited_ms >= ping_timeout_ms) {
                    fprintf(stderr, "[!] ping timeout after %u ms\n", ping_timeout_ms);
                    break;
                }
            }

            struct timespec ts = {0, 1000000};
            nanosleep(&ts, NULL);
        }

        if (ok) printf("PING done\n");
        else {
            munmap(mm, map_size);
            close(fd);
            return 1;
        }
    }

    write_sec_perm_stats_json(&lo);

    munmap(mm, map_size);
    close(fd);
    return 0;
}
