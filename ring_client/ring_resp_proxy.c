#define _GNU_SOURCE

#include "../tdx_shm/tdx_shm_transport.h"

#include <arpa/inet.h>
#include <endian.h>
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <limits.h>
#include <netdb.h>
#include <signal.h>
#include <sodium.h>
#include <stdatomic.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/epoll.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

/* RESP-over-ring stream proxy.
 *
 * Listens on TCP (for redis clients like YCSB Jedis) and forwards raw RESP bytes
 * over the TDX shared-memory ring transport to the Redis ring backend.
 *
 * This keeps protocol/command behavior identical to native TCP Redis (fair YCSB),
 * and avoids any proxy-side RESP parsing/translation overhead.
 */

#define MSG_DATA  1
#define MSG_CLOSE 2

#define MAX_RINGS 8
#define RING_SLOT_HDR_SIZE 16U
#define RING_MAX_PAYLOAD ((uint32_t)TDX_SHM_MSG_MAX - RING_SLOT_HDR_SIZE)

/* ring_slot_hdr.flags */
#define RING_FLAG_SECURE 0x0001u
#define RING_FLAG_RESP   0x0002u

#define SEC_DIR_REQ 1u  /* client->server */
#define SEC_DIR_RESP 2u /* server->client */

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

struct ring_slot_hdr {
    uint32_t cid;
    uint16_t type;
    uint16_t flags;
    uint32_t len;
    uint32_t reserved;
};

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

static volatile sig_atomic_t running = 1;

static int g_secure = 0;
static const char *g_sec_mgr = NULL;
static uint64_t g_sec_node_id = 0;
static unsigned g_sec_timeout_ms = 10000;
static unsigned char g_sec_key[MAX_RINGS][crypto_aead_chacha20poly1305_ietf_KEYBYTES];
static int g_sec_key_ok[MAX_RINGS];
static atomic_uint_fast64_t g_sec_nonce_ctr_req[MAX_RINGS];

static uint64_t shm_delay_ns = 0;
static uint64_t shm_pause_iters_per_ns_x1024 = 0;

static void handle_sig(int sig) {
    (void)sig;
    running = 0;
}

static inline uint64_t nowns(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000000000ULL + (uint64_t)ts.tv_nsec;
}

static void cxl_shm_delay_calibrate(void) {
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

static inline void cxl_shm_delay(void) {
    uint64_t ns = shm_delay_ns;
    if (!ns) return;
    if (!shm_pause_iters_per_ns_x1024) cxl_shm_delay_calibrate();
    uint64_t iters = (ns * shm_pause_iters_per_ns_x1024 + 1023ULL) / 1024ULL;
    if (iters == 0) iters = 1;
    for (uint64_t i = 0; i < iters; i++) {
        __asm__ __volatile__("pause");
    }
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

static size_t env_size(const char *key, size_t def) {
    const char *v = getenv(key);
    if (!v || !v[0]) return def;
    size_t out = 0;
    if (parse_size(v, &out) != 0) return def;
    return out;
}

static int fd_set_nonblock(int fd) {
    int flags = fcntl(fd, F_GETFL, 0);
    if (flags < 0) return -1;
    if (fcntl(fd, F_SETFL, flags | O_NONBLOCK) != 0) return -1;
    return 0;
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

static int socket_listen(const char *host, const char *port) {
    struct addrinfo hints;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_flags = AI_PASSIVE;

    struct addrinfo *res = NULL;
    int rc = getaddrinfo(host, port, &hints, &res);
    if (rc != 0) {
        fprintf(stderr, "[!] getaddrinfo(listen %s:%s): %s\n", host, port, gai_strerror(rc));
        return -1;
    }

    int fd = -1;
    for (struct addrinfo *ai = res; ai; ai = ai->ai_next) {
        fd = socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol);
        if (fd < 0) continue;
        int one = 1;
        (void)setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
        if (bind(fd, ai->ai_addr, ai->ai_addrlen) != 0) {
            close(fd);
            fd = -1;
            continue;
        }
        if (listen(fd, 256) != 0) {
            close(fd);
            fd = -1;
            continue;
        }
        break;
    }

    freeaddrinfo(res);
    if (fd >= 0) (void)fd_set_nonblock(fd);
    return fd;
}

struct ring_info {
    struct tdx_shm_queue_view req;
    struct tdx_shm_queue_view resp;
    uint32_t ring_idx;
};

struct layout {
    uint32_t ring_count;
    struct ring_info rings[MAX_RINGS];
};

static size_t align_up(size_t v, size_t a) {
    return (v + a - 1U) & ~(a - 1U);
}

static int load_layout(unsigned char *mm, size_t map_size, struct layout *lo) {
    if (!mm || !lo) return -1;

    uint32_t ring_count = env_u32("CXL_RING_COUNT", 1);
    if (ring_count == 0 || ring_count > MAX_RINGS) return -1;
    size_t region_size = env_size("CXL_RING_REGION_SIZE", (size_t)TDX_SHM_DEFAULT_TOTAL_SIZE);
    size_t region_base = env_size("CXL_RING_REGION_BASE", 0);

    if ((region_base % 4096) != 0 || (region_size % 4096) != 0) return -1;
    size_t header_size = align_up(sizeof(struct tdx_shm_header), 64U);
    size_t queue_bytes = (size_t)TDX_SHM_QUEUE_CAPACITY * (size_t)TDX_SHM_SLOT_SIZE;
    size_t needed = header_size + (2U * queue_bytes);
    if (region_size < needed) return -1;
    if (region_base > map_size) return -1;
    if ((size_t)ring_count > (map_size - region_base) / region_size) return -1;

    memset(lo, 0, sizeof(*lo));
    lo->ring_count = ring_count;
    for (uint32_t i = 0; i < ring_count; i++) {
        size_t off = region_base + (size_t)i * region_size;
        struct tdx_shm_region region;
        if (tdx_shm_region_attach(mm + off, region_size, &region) != 0) return -1;
        lo->rings[i].req = region.q21;
        lo->rings[i].resp = region.q12;
        lo->rings[i].ring_idx = i;
    }
    return 0;
}

static int ring_push(struct ring_info *ri, uint32_t cid, uint16_t type, uint16_t flags, const unsigned char *payload, uint32_t len) {
    if (!ri || !payload) return -1;
    if (len > RING_MAX_PAYLOAD) return -1;

    unsigned char slot[TDX_SHM_SLOT_SIZE];
    struct ring_slot_hdr hdr = {.cid = cid, .type = type, .flags = flags, .len = len, .reserved = 0};
    memcpy(slot, &hdr, sizeof(hdr));
    if (len) memcpy(slot + sizeof(hdr), payload, len);
    uint32_t total = (uint32_t)(sizeof(hdr) + len);

    cxl_shm_delay();
    int rc = tdx_shm_queue_send(&ri->req, slot, total);
    if (rc == 0) return 1;
    if (rc == -EAGAIN) return 0;
    return -1;
}

static int ring_pop(struct ring_info *ri, uint32_t *cid, uint16_t *type, uint16_t *flags, unsigned char **payload, uint32_t *len) {
    if (!ri || !cid || !type || !flags || !payload || !len) return -1;
    static __thread unsigned char slot[TDX_SHM_SLOT_SIZE];
    size_t rlen = 0;

    cxl_shm_delay();
    int rc = tdx_shm_queue_recv(&ri->resp, slot, sizeof(slot), &rlen);
    if (rc == -EAGAIN) return 0;
    if (rc != 0) return -1;
    if (rlen < sizeof(struct ring_slot_hdr)) return -1;

    struct ring_slot_hdr hdr;
    memcpy(&hdr, slot, sizeof(hdr));
    if (hdr.len > RING_MAX_PAYLOAD) return -1;
    if (sizeof(hdr) + (size_t)hdr.len > rlen) return -1;
    *cid = hdr.cid;
    *type = hdr.type;
    *flags = hdr.flags;
    *len = hdr.len;
    *payload = slot + sizeof(hdr);
    return 1;
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

static void sleep_ms(unsigned ms) {
    struct timespec ts;
    ts.tv_sec = (time_t)(ms / 1000U);
    ts.tv_nsec = (long)(ms % 1000U) * 1000000L;
    while (nanosleep(&ts, &ts) != 0 && errno == EINTR) {
    }
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
    if (!g_sec_mgr || !g_sec_mgr[0]) {
        fprintf(stderr, "[!] --secure requires --sec-mgr ip:port (or env CXL_SEC_MGR)\n");
        return -1;
    }
    if (g_sec_node_id == 0) {
        fprintf(stderr, "[!] --secure requires --sec-node-id N (or env CXL_SEC_NODE_ID)\n");
        return -1;
    }
    if (sodium_init() < 0) {
        fprintf(stderr, "[!] sodium_init failed\n");
        return -1;
    }

    size_t region_size = env_size("CXL_RING_REGION_SIZE", (size_t)TDX_SHM_DEFAULT_TOTAL_SIZE);
    size_t region_base = env_size("CXL_RING_REGION_BASE", 0);
    if (region_base < 4096) {
        fprintf(stderr, "[!] secure mode requires CXL_RING_REGION_BASE >= 4096 (reserved page for CXLSEC)\n");
        return -1;
    }
    if (!lo || lo->ring_count == 0 || lo->ring_count > MAX_RINGS) return -1;
    if (map_size < CXL_SEC_TABLE_OFF + sizeof(CxlSecTable)) {
        fprintf(stderr, "[!] mapping too small for CXLSEC table\n");
        return -1;
    }

    const CxlSecTable *t = (const CxlSecTable *)(mm + CXL_SEC_TABLE_OFF);
    unsigned waited = 0;
    while (running) {
        if (sec_table_ready(t)) break;
        if (waited >= g_sec_timeout_ms) break;
        sleep_ms(10);
        waited += 10;
    }
    if (!sec_table_ready(t)) {
        fprintf(stderr, "[!] timeout waiting for CXLSEC table (offset=%u)\n", (unsigned)CXL_SEC_TABLE_OFF);
        return -1;
    }

    memset(g_sec_key_ok, 0, sizeof(g_sec_key_ok));
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
            (void)sec_mgr_request_access(g_sec_mgr, g_sec_node_id, off, 1);
            if (waited2 >= g_sec_timeout_ms) break;
            sleep_ms(10);
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
    if (flags & ~(RING_FLAG_SECURE | RING_FLAG_RESP)) return -1;

    const uint32_t nonce_bytes = crypto_aead_chacha20poly1305_ietf_NPUBBYTES;
    const uint32_t tag_bytes = crypto_aead_chacha20poly1305_ietf_ABYTES;
    if (payload_len > RING_MAX_PAYLOAD) return -1;
    if (payload_len > RING_MAX_PAYLOAD - nonce_bytes - tag_bytes) return -1;

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
    if (clen > RING_MAX_PAYLOAD) return -1;
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

typedef struct Conn {
    int fd;
    uint32_t cid;
    uint32_t ring_idx;
    struct ring_info *ri;

    int server_close;
    int closing; /* local close pending ring MSG_CLOSE */

    unsigned char *ring_buf;
    size_t ring_len;
    size_t ring_off;

    unsigned char *sock_buf;
    size_t sock_len;
    size_t sock_off;

    int in_pending_ring;
    struct Conn *pending_prev;
    struct Conn *pending_next;
} Conn;

static Conn *pending_ring_head = NULL;

static void pending_ring_add(Conn *c) {
    if (!c || c->in_pending_ring) return;
    c->in_pending_ring = 1;
    c->pending_prev = NULL;
    c->pending_next = pending_ring_head;
    if (pending_ring_head) pending_ring_head->pending_prev = c;
    pending_ring_head = c;
}

static void pending_ring_remove(Conn *c) {
    if (!c || !c->in_pending_ring) return;
    if (c->pending_prev) c->pending_prev->pending_next = c->pending_next;
    else pending_ring_head = c->pending_next;
    if (c->pending_next) c->pending_next->pending_prev = c->pending_prev;
    c->pending_prev = NULL;
    c->pending_next = NULL;
    c->in_pending_ring = 0;
}

static void conn_buf_free(unsigned char **buf, size_t *len, size_t *off) {
    free(*buf);
    *buf = NULL;
    *len = 0;
    *off = 0;
}

static void conn_close_fd(Conn *c, int epfd) {
    if (!c) return;
    if (c->fd >= 0) {
        (void)epoll_ctl(epfd, EPOLL_CTL_DEL, c->fd, NULL);
        close(c->fd);
        c->fd = -1;
    }
}

static void conn_free(Conn *c) {
    if (!c) return;
    conn_buf_free(&c->ring_buf, &c->ring_len, &c->ring_off);
    conn_buf_free(&c->sock_buf, &c->sock_len, &c->sock_off);
    free(c);
}

static int epoll_set_events(int epfd, Conn *c, uint32_t events) {
    if (!c || c->fd < 0) return -1;
    struct epoll_event ev;
    memset(&ev, 0, sizeof(ev));
    ev.events = events;
    ev.data.ptr = c;
    return epoll_ctl(epfd, EPOLL_CTL_MOD, c->fd, &ev);
}

static int epoll_add_conn(int epfd, Conn *c) {
    if (!c || c->fd < 0) return -1;
    struct epoll_event ev;
    memset(&ev, 0, sizeof(ev));
    ev.events = EPOLLIN | EPOLLRDHUP;
    ev.data.ptr = c;
    return epoll_ctl(epfd, EPOLL_CTL_ADD, c->fd, &ev);
}

static int conn_sock_flush(Conn *c, int epfd) {
    if (!c || c->fd < 0) return -1;
    while (c->sock_off < c->sock_len) {
        ssize_t w = send(c->fd, c->sock_buf + c->sock_off, c->sock_len - c->sock_off, 0);
        if (w > 0) {
            c->sock_off += (size_t)w;
            continue;
        }
        if (w < 0 && (errno == EINTR)) continue;
        if (w < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) break;
        return -1;
    }
    if (c->sock_off >= c->sock_len) {
        conn_buf_free(&c->sock_buf, &c->sock_len, &c->sock_off);
        (void)epoll_set_events(epfd, c, EPOLLIN | EPOLLRDHUP);
        if (c->server_close) return 1; /* drained + close requested */
    } else {
        (void)epoll_set_events(epfd, c, EPOLLIN | EPOLLOUT | EPOLLRDHUP);
    }
    return 0;
}

static int conn_sock_write(Conn *c, int epfd, const unsigned char *buf, size_t len) {
    if (!c || c->fd < 0) return -1;
    if (!buf || len == 0) return 0;

    if (!c->sock_buf) {
        ssize_t w = send(c->fd, buf, len, 0);
        if (w == (ssize_t)len) return 0;
        if (w < 0 && (errno != EAGAIN && errno != EWOULDBLOCK && errno != EINTR)) return -1;
        size_t off = 0;
        if (w > 0) off = (size_t)w;

        c->sock_buf = (unsigned char *)malloc(len - off);
        if (!c->sock_buf) return -1;
        memcpy(c->sock_buf, buf + off, len - off);
        c->sock_len = len - off;
        c->sock_off = 0;
        (void)epoll_set_events(epfd, c, EPOLLIN | EPOLLOUT | EPOLLRDHUP);
        return 0;
    }

    size_t pending = c->sock_len - c->sock_off;
    unsigned char *nb = (unsigned char *)malloc(pending + len);
    if (!nb) return -1;
    memcpy(nb, c->sock_buf + c->sock_off, pending);
    memcpy(nb + pending, buf, len);
    free(c->sock_buf);
    c->sock_buf = nb;
    c->sock_len = pending + len;
    c->sock_off = 0;
    (void)epoll_set_events(epfd, c, EPOLLIN | EPOLLOUT | EPOLLRDHUP);
    return 0;
}

static int conn_send_close(struct ring_info *ri, Conn *c, uint16_t flags) {
    unsigned char dummy = 0;
    return ring_push(ri, c->cid, MSG_CLOSE, flags, &dummy, 1);
}

static int conn_ring_flush_one(struct ring_info *ri, Conn *c, uint16_t flags, uint32_t ring_idx) {
    if (!c || !ri) return -1;
    if (!c->ring_buf || c->ring_off >= c->ring_len) return 1;

    const uint32_t nonce_bytes = crypto_aead_chacha20poly1305_ietf_NPUBBYTES;
    const uint32_t tag_bytes = crypto_aead_chacha20poly1305_ietf_ABYTES;
    uint32_t chunk_max = RING_MAX_PAYLOAD;
    if (g_secure) chunk_max = RING_MAX_PAYLOAD - nonce_bytes - tag_bytes;

    while (c->ring_off < c->ring_len) {
        size_t avail = c->ring_len - c->ring_off;
        uint32_t plain_len = (uint32_t)((avail > chunk_max) ? chunk_max : avail);
        const unsigned char *plain = c->ring_buf + c->ring_off;

        const unsigned char *send_ptr = plain;
        uint32_t send_len = plain_len;
        unsigned char enc[RING_MAX_PAYLOAD];
        if (g_secure) {
            uint32_t enc_len = 0;
            if (secure_encrypt(ring_idx, c->cid, MSG_DATA, flags, plain_len, plain, SEC_DIR_REQ, enc, (uint32_t)sizeof(enc), &enc_len) != 0) {
                return -1;
            }
            send_ptr = enc;
            send_len = enc_len;
        }

        int sr = ring_push(ri, c->cid, MSG_DATA, flags, send_ptr, send_len);
        if (sr == 0) return 0; /* ring full */
        if (sr < 0) return -1;
        c->ring_off += plain_len;
    }

    conn_buf_free(&c->ring_buf, &c->ring_len, &c->ring_off);
    return 1;
}

static int conn_ring_send_bytes(struct ring_info *ri, Conn *c, uint16_t flags, uint32_t ring_idx, const unsigned char *buf, size_t len) {
    if (!ri || !c || !buf || len == 0) return 0;
    if (c->ring_buf) return -1; /* caller must flush first */

    const uint32_t nonce_bytes = crypto_aead_chacha20poly1305_ietf_NPUBBYTES;
    const uint32_t tag_bytes = crypto_aead_chacha20poly1305_ietf_ABYTES;
    uint32_t chunk_max = RING_MAX_PAYLOAD;
    if (g_secure) chunk_max = RING_MAX_PAYLOAD - nonce_bytes - tag_bytes;

    size_t off = 0;
    while (off < len) {
        uint32_t plain_len = (uint32_t)(((len - off) > chunk_max) ? chunk_max : (len - off));
        const unsigned char *plain = buf + off;

        const unsigned char *send_ptr = plain;
        uint32_t send_len = plain_len;
        unsigned char enc[RING_MAX_PAYLOAD];
        if (g_secure) {
            uint32_t enc_len = 0;
            if (secure_encrypt(ring_idx, c->cid, MSG_DATA, flags, plain_len, plain, SEC_DIR_REQ, enc, (uint32_t)sizeof(enc), &enc_len) != 0) {
                return -1;
            }
            send_ptr = enc;
            send_len = enc_len;
        }

        int sr = ring_push(ri, c->cid, MSG_DATA, flags, send_ptr, send_len);
        if (sr == 0) {
            size_t remaining = len - off;
            c->ring_buf = (unsigned char *)malloc(remaining);
            if (!c->ring_buf) return -1;
            memcpy(c->ring_buf, buf + off, remaining);
            c->ring_len = remaining;
            c->ring_off = 0;
            pending_ring_add(c);
            return 0;
        }
        if (sr < 0) return -1;
        off += plain_len;
    }
    return 0;
}

static int ensure_map_slot(Conn ***map, size_t *cap, uint32_t cid) {
    if (!map || !cap) return -1;
    if (cid < *cap) return 0;
    size_t ncap = (*cap == 0) ? 1024 : *cap;
    while (cid >= ncap) ncap *= 2;
    Conn **nm = (Conn **)realloc(*map, ncap * sizeof((*map)[0]));
    if (!nm) return -1;
    for (size_t i = *cap; i < ncap; i++) nm[i] = NULL;
    *map = nm;
    *cap = ncap;
    return 0;
}

static uint32_t next_cid = 100;

static uint32_t alloc_cid(void) {
    return next_cid++;
}

static void conn_begin_close_local(Conn *c, int epfd, uint16_t close_flags, Conn ***cid_map, size_t *cid_cap) {
    if (!c || !cid_map || !cid_cap) return;
    if (c->closing) return;

    c->closing = 1;
    c->server_close = 0;

    conn_close_fd(c, epfd);
    conn_buf_free(&c->sock_buf, &c->sock_len, &c->sock_off);
    conn_buf_free(&c->ring_buf, &c->ring_len, &c->ring_off);

    pending_ring_add(c);
    int sr = conn_send_close(c->ri, c, close_flags);
    if (sr == 1) {
        pending_ring_remove(c);
        if (c->cid < *cid_cap) (*cid_map)[c->cid] = NULL;
        conn_free(c);
    }
}

static void conn_finish_close_server(Conn *c, int epfd, Conn ***cid_map, size_t *cid_cap) {
    if (!c || !cid_map || !cid_cap) return;
    conn_close_fd(c, epfd);
    pending_ring_remove(c);
    if (c->cid < *cid_cap) (*cid_map)[c->cid] = NULL;
    conn_free(c);
}

static void flush_pending_ring(int epfd, uint16_t flags, uint16_t close_flags, Conn ***cid_map, size_t *cid_cap) {
    Conn *c = pending_ring_head;
    while (c) {
        Conn *next = c->pending_next;
        if (c->closing) {
            int sr = conn_send_close(c->ri, c, close_flags);
            if (sr == 1) {
                pending_ring_remove(c);
                if (c->cid < *cid_cap) (*cid_map)[c->cid] = NULL;
                conn_free(c);
            }
            c = next;
            continue;
        }

        int fr = conn_ring_flush_one(c->ri, c, flags, c->ring_idx);
        if (fr == 1) pending_ring_remove(c);
        else if (fr < 0) {
            conn_begin_close_local(c, epfd, close_flags, cid_map, cid_cap);
        }
        c = next;
    }
}

static void usage(const char *argv0) {
    printf("Usage: %s [--path <bar2|uio>] [--map-size <bytes>] [--map-offset <bytes>]\n"
           "          [--listen <ip:port>] [--ring <base-idx>]\n"
           "          [--secure --sec-mgr <ip:port> --sec-node-id N [--sec-timeout-ms MS]]\n"
           "Env:\n"
           "  CXL_RING_COUNT        : number of rings/regions (default: 1)\n"
           "  CXL_RING_REGION_SIZE  : bytes per ring region (default: 16M)\n"
           "  CXL_RING_REGION_BASE  : base offset within the mmap (default: 0)\n"
           "  CXL_SHM_DELAY_NS      : simulated shm access delay (ns)\n",
           argv0);
}

int main(int argc, char **argv) {
    const char *path = "/sys/bus/pci/devices/0000:00:02.0/resource2";
    size_t map_size = 1024ULL * 1024ULL * 1024ULL;
    size_t map_offset = 0;
    const char *listen_addr = "127.0.0.1:6381";
    int ring_idx = 0;

    const char *delay_env = getenv("CXL_SHM_DELAY_NS");
    if (delay_env && delay_env[0]) {
        errno = 0;
        unsigned long long v = strtoull(delay_env, NULL, 0);
        if (errno == 0) shm_delay_ns = (uint64_t)v;
    }
    const char *offset_env = getenv("CXL_RING_OFFSET");
    if (!offset_env || !offset_env[0]) offset_env = getenv("CXL_SHM_OFFSET");
    if (offset_env && offset_env[0]) {
        unsigned long long v = strtoull(offset_env, NULL, 0);
        if (v > 0) map_offset = (size_t)v;
    }

    for (int i = 1; i < argc; i++) {
        if (!strcmp(argv[i], "--path") && i + 1 < argc) path = argv[++i];
        else if (!strcmp(argv[i], "--map-size") && i + 1 < argc) map_size = strtoull(argv[++i], NULL, 0);
        else if (!strcmp(argv[i], "--map-offset") && i + 1 < argc) map_offset = strtoull(argv[++i], NULL, 0);
        else if (!strcmp(argv[i], "--listen") && i + 1 < argc) listen_addr = argv[++i];
        else if (!strcmp(argv[i], "--ring") && i + 1 < argc) ring_idx = atoi(argv[++i]);
        else if (!strcmp(argv[i], "--secure")) g_secure = 1;
        else if (!strcmp(argv[i], "--sec-mgr") && i + 1 < argc) g_sec_mgr = argv[++i];
        else if (!strcmp(argv[i], "--sec-node-id") && i + 1 < argc) g_sec_node_id = strtoull(argv[++i], NULL, 0);
        else if (!strcmp(argv[i], "--sec-timeout-ms") && i + 1 < argc) g_sec_timeout_ms = (unsigned)strtoul(argv[++i], NULL, 0);
        else if (!strcmp(argv[i], "-h") || !strcmp(argv[i], "--help")) {
            usage(argv[0]);
            return 0;
        } else {
            fprintf(stderr, "[!] unknown arg: %s\n", argv[i]);
            usage(argv[0]);
            return 1;
        }
    }

    if (g_secure) {
        if (!g_sec_mgr || !g_sec_mgr[0]) g_sec_mgr = getenv("CXL_SEC_MGR");
        if (g_sec_node_id == 0) {
            const char *id_env = getenv("CXL_SEC_NODE_ID");
            if (id_env && id_env[0]) g_sec_node_id = strtoull(id_env, NULL, 0);
        }
        const char *to_env = getenv("CXL_SEC_TIMEOUT_MS");
        if (to_env && to_env[0]) g_sec_timeout_ms = (unsigned)strtoul(to_env, NULL, 0);
    }

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
        if (map_size > (size_t)st.st_size - map_offset) map_size = (size_t)st.st_size - map_offset;
    }
    unsigned char *mm = mmap(NULL, map_size, PROT_READ | PROT_WRITE, MAP_SHARED, fd, (off_t)map_offset);
    if (mm == MAP_FAILED) {
        perror("mmap");
        close(fd);
        return 1;
    }

    struct layout lo;
    if (load_layout(mm, map_size, &lo) != 0) {
        fprintf(stderr, "[!] TDX SHM layout not ready (CXL_RING_COUNT/REGION_* mismatch?)\n");
        munmap(mm, map_size);
        close(fd);
        return 1;
    }
    if (ring_idx < 0 || ring_idx >= (int)lo.ring_count) ring_idx = 0;

    if (g_secure) {
        if (secure_init(mm, map_size, &lo) != 0) {
            fprintf(stderr, "[!] secure init failed\n");
            munmap(mm, map_size);
            close(fd);
            return 1;
        }
    }

    char *listen_host = NULL;
    char *listen_port = NULL;
    if (parse_hostport(listen_addr, &listen_host, &listen_port) != 0) {
        fprintf(stderr, "[!] --listen must be host:port\n");
        munmap(mm, map_size);
        close(fd);
        return 1;
    }
    int lfd = socket_listen(listen_host, listen_port);
    if (lfd < 0) {
        perror("listen");
        free(listen_host);
        free(listen_port);
        munmap(mm, map_size);
        close(fd);
        return 1;
    }

    int epfd = epoll_create1(0);
    if (epfd < 0) {
        perror("epoll_create1");
        close(lfd);
        free(listen_host);
        free(listen_port);
        munmap(mm, map_size);
        close(fd);
        return 1;
    }

    int listen_tag = 0;
    struct epoll_event lev;
    memset(&lev, 0, sizeof(lev));
    lev.events = EPOLLIN;
    lev.data.ptr = &listen_tag;
    if (epoll_ctl(epfd, EPOLL_CTL_ADD, lfd, &lev) != 0) {
        perror("epoll_ctl(listen)");
        close(epfd);
        close(lfd);
        free(listen_host);
        free(listen_port);
        munmap(mm, map_size);
        close(fd);
        return 1;
    }

    Conn **cid_map = NULL;
    size_t cid_cap = 0;

    uint16_t data_flags = RING_FLAG_RESP | (g_secure ? RING_FLAG_SECURE : 0);
    uint16_t close_flags = RING_FLAG_RESP | (g_secure ? RING_FLAG_SECURE : 0);

    printf("[*] ring RESP stream proxy listening on %s:%s (rings=%u base=%d secure=%d)\n",
           listen_host,
           listen_port,
           lo.ring_count,
           ring_idx,
           g_secure ? 1 : 0);
    fflush(stdout);

    uint32_t base_ring = (uint32_t)ring_idx;
    uint32_t accept_rr = 0;
    uint32_t drain_rr = 0;
    struct epoll_event events[256];
    unsigned char iobuf[8192];

    while (running) {
        /* Drain ring responses (bounded burst). */
        int budget = 4096;
        for (uint32_t r = 0; r < lo.ring_count && budget > 0; r++) {
            uint32_t idx = (drain_rr + r) % lo.ring_count;
            struct ring_info *ri = &lo.rings[idx];
            for (int iter = 0; iter < 256 && budget > 0; iter++, budget--) {
                uint32_t cid = 0;
                uint16_t type = 0, flags = 0;
                unsigned char *payload = NULL;
                uint32_t len = 0;
                int rr = ring_pop(ri, &cid, &type, &flags, &payload, &len);
                if (rr == 0) break; /* ring empty */
                if (rr < 0) break;  /* ring error */

                if ((flags & RING_FLAG_RESP) == 0) continue;

                if (ensure_map_slot(&cid_map, &cid_cap, cid) != 0) continue;
                Conn *c = cid_map[cid];
                if (!c) continue;

                if (type == MSG_CLOSE) {
                    c->server_close = 1;
                    if (!c->sock_buf) {
                        conn_finish_close_server(c, epfd, &cid_map, &cid_cap);
                    }
                    continue;
                }
                if (type != MSG_DATA) continue;

                unsigned char dec[RING_MAX_PAYLOAD];
                unsigned char *plain = payload;
                uint32_t plain_len = len;
                if (g_secure) {
                    if (!(flags & RING_FLAG_SECURE)) continue;
                    uint32_t dl = 0;
                    if (secure_decrypt(idx, cid, type, flags, len, payload, dec, (uint32_t)sizeof(dec), &dl) != 0) {
                        conn_begin_close_local(c, epfd, close_flags, &cid_map, &cid_cap);
                        continue;
                    }
                    plain = dec;
                    plain_len = dl;
                }

                if (conn_sock_write(c, epfd, plain, (size_t)plain_len) != 0) {
                    conn_begin_close_local(c, epfd, close_flags, &cid_map, &cid_cap);
                }
            }
        }
        if (lo.ring_count) drain_rr = (drain_rr + 1U) % lo.ring_count;

        /* Flush pending ring sends (data + closes). */
        flush_pending_ring(epfd, data_flags, close_flags, &cid_map, &cid_cap);

        int n = epoll_wait(epfd, events, (int)(sizeof(events) / sizeof(events[0])), 5);
        if (n < 0) {
            if (errno == EINTR) continue;
            break;
        }

        for (int i = 0; i < n; i++) {
            void *tag = events[i].data.ptr;
            uint32_t ev = events[i].events;

            if (tag == &listen_tag) {
                for (;;) {
                    struct sockaddr_storage ss;
                    socklen_t sl = sizeof(ss);
                    int cfd = accept(lfd, (struct sockaddr *)&ss, &sl);
                    if (cfd < 0) {
                        if (errno == EAGAIN || errno == EWOULDBLOCK) break;
                        break;
                    }
                    (void)fd_set_nonblock(cfd);

                    Conn *c = (Conn *)calloc(1, sizeof(*c));
                    if (!c) {
                        close(cfd);
                        continue;
                    }
                    c->fd = cfd;
                    c->cid = alloc_cid();
                    c->ring_idx = (lo.ring_count == 0) ? 0U : (base_ring + (accept_rr++ % lo.ring_count)) % lo.ring_count;
                    c->ri = &lo.rings[c->ring_idx];

                    if (ensure_map_slot(&cid_map, &cid_cap, c->cid) != 0) {
                        close(cfd);
                        conn_free(c);
                        continue;
                    }
                    cid_map[c->cid] = c;

                    if (epoll_add_conn(epfd, c) != 0) {
                        cid_map[c->cid] = NULL;
                        close(cfd);
                        conn_free(c);
                        continue;
                    }
                }
                continue;
            }

            Conn *c = (Conn *)tag;
            if (!c) continue;

            if (ev & (EPOLLERR | EPOLLHUP | EPOLLRDHUP)) {
                conn_begin_close_local(c, epfd, close_flags, &cid_map, &cid_cap);
                continue;
            }

            if ((ev & EPOLLOUT) && c->sock_buf) {
                int fr = conn_sock_flush(c, epfd);
                if (fr < 0) {
                    conn_begin_close_local(c, epfd, close_flags, &cid_map, &cid_cap);
                    continue;
                }
                if (fr == 1) { /* drained + server_close */
                    conn_finish_close_server(c, epfd, &cid_map, &cid_cap);
                    continue;
                }
            }

            if (ev & EPOLLIN) {
                if (c->ring_buf) {
                    int fr = conn_ring_flush_one(c->ri, c, data_flags, c->ring_idx);
                    if (fr == 1) {
                        pending_ring_remove(c);
                    } else if (fr == 0) {
                        pending_ring_add(c);
                        continue;
                    } else {
                        conn_begin_close_local(c, epfd, close_flags, &cid_map, &cid_cap);
                        continue;
                    }
                }

                for (;;) {
                    ssize_t r = recv(c->fd, iobuf, sizeof(iobuf), 0);
                    if (r == 0) {
                        conn_begin_close_local(c, epfd, close_flags, &cid_map, &cid_cap);
                        break;
                    }
                    if (r < 0) {
                        if (errno == EINTR) continue;
                        if (errno == EAGAIN || errno == EWOULDBLOCK) break;
                        conn_begin_close_local(c, epfd, close_flags, &cid_map, &cid_cap);
                        break;
                    }

                    int sr = conn_ring_send_bytes(c->ri, c, data_flags, c->ring_idx, iobuf, (size_t)r);
                    if (sr != 0) {
                        conn_begin_close_local(c, epfd, close_flags, &cid_map, &cid_cap);
                        break;
                    }
                    if (c->ring_buf) break; /* ring full; backpressure */
                }
            }
        }
    }

    /* Best-effort cleanup: close all conns without blocking. */
    if (cid_map) {
        for (size_t i = 0; i < cid_cap; i++) {
            Conn *c = cid_map[i];
            if (!c) continue;
            conn_close_fd(c, epfd);
            conn_free(c);
        }
    }
    free(cid_map);
    close(epfd);
    close(lfd);
    free(listen_host);
    free(listen_port);
    munmap(mm, map_size);
    close(fd);
    return 0;
}
